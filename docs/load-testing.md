# Load testing

Two instruments, two jobs. `throughput_baseline` (and its `throughput_push`
and `throughput_outbound` siblings in `server/tests/e2e.rs`) times one stream
through a fixed method and stays the regression baseline for optimization
work. `concurrent_load`, in the same file, is the concurrency instrument: it
drives N upload sessions and M grant downloads at once so contention (the
store lock, the session registry, spawn_blocking hops) shows up as p95 spread
and error counts, and so `VOTPORT_MAX_TOTAL_SESSIONS` can be sized from
evidence instead of guesswork.

## Running the rig

Locally, against an in-process server with defaults (16 sessions, 8 download
streams, 64 MiB per file):

```sh
cd server
cargo test --release --test e2e -- --ignored --nocapture concurrent_load
```

Against a deployed box:

```sh
VOTPORT_LOAD_TARGET=https://drop.example.com \
VOTPORT_LOAD_ADMIN_PASSWORD='the admin password' \
cargo test --release --test e2e -- --ignored --nocapture concurrent_load
```

Knobs, all environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `VOTPORT_LOAD_TARGET` | unset | Base URL of the server under test. Unset runs an in-process server with caps sized for the run. |
| `VOTPORT_LOAD_ADMIN_PASSWORD` | unset | Admin password for the target. Required with `VOTPORT_LOAD_TARGET`. |
| `VOTPORT_LOAD_SESSIONS` | 16 | Concurrent upload sessions per upload phase. |
| `VOTPORT_LOAD_DOWNLOADS` | 8 | Concurrent grant downloads per download phase. |
| `VOTPORT_LOAD_FILE_MIB` | 64 | Size of every transferred file, in MiB. |
| `VOTPORT_LOAD_TIMEOUT_SECS` | 600 | Per-phase deadline. A phase that blows it fails the test with a count of who finished. |

The run has three phases: uploads alone, downloads alone, then both at once.
Every uploaded file carries a per-run salt so dedupe-at-begin can never skip
the transfer, and each worker sends through the full protocol (session, seal,
pages, begin, proven ranges with eight in flight, finish), matching the real
sender. Workers use distinct file names: concurrent uploads of the same name
with different content race on the collision suffix and fail with 409, which
is real server behavior but not the contention this rig is pointed at. Downloads stream one admin outbound file through one grant per
stream. On a real target the rig cleans up after itself, best effort, and
the cleanup also runs when setup fails partway or a phase stalls: grants
revoked, outbound file, received copies, and every seeded link deleted. A
hard kill of the rig process skips it and leaves the seeded links and
outbound file behind.

Mind the rig's own appetite: it holds `SESSIONS x FILE_MIB` of prepared bytes
in memory during each upload phase, and hashing them front-loads a burst of
CPU before the clock starts.

## Ceilings you will hit before the interesting ones

The server throttles by design, and the throttles fire before the contention
you came to measure. Know them so a 429 in the report reads as the right kind
of data:

- **Session creation: 20 per client IP per 10 minutes.** The rig stamps each
  worker with a synthetic `X-Forwarded-For` address, which the server honors
  when the connection arrives from a loopback or RFC 1918 peer with no proxy
  in between (in-process and LAN runs). Behind a reverse proxy the proxy
  appends the rig's real address and the synthetic ones are ignored, so a
  three-phase run through a proxy is capped at 20 session creations total:
  keep `SESSIONS` at 10 or below there, or run from inside the network.
  Synthetic addresses appear in link events and the audit log on a real box.
- **Upload sessions: 8 concurrent per link (`MAX_SESSIONS_PER_LINK`).** The
  rig seeds one link per eight upload workers and spreads sessions across
  them, so runs reach the process-wide cap instead of this one. A single
  real link still refuses its ninth concurrent sender.
- **`VOTPORT_MAX_TOTAL_SESSIONS` (default 32).** The process-wide session
  cap; this is the knob the rig exists to size. Runs with `SESSIONS` above it
  report the overflow as 429 errors, which is the measurement working.
- **Downloads: 32 concurrent process-wide, 16 per grant.** The rig uses one
  grant per stream, so `DOWNLOADS` above 32 reports 429s from the global
  ceiling.
- **`VOTPORT_MAX_UPLOAD_BYTES`** on the target must cover `FILE_MIB`, for
  the upload sessions and for the outbound library file both.

## Reading the report

One line per phase:

```text
upload          16 x 64 MiB: 12.45s wall, 82.3 MiB/s aggregate, first-response p50 48.2ms p95 210.4ms, complete p50 9.81s p95 12.10s, 0/16 errors
```

- **Aggregate MiB/s** counts completed workers only; it is the number to
  compare across runs and against `throughput_baseline` times the worker
  count.
- **First-response p50/p95** is time to the first server response (session
  create for uploads, response headers for downloads). Widening p95 here
  under load is the store lock and session registry queueing.
- **Complete p50/p95** is full-transfer time per worker. A p95 far above p50
  means some workers starve while others run; compare the mixed phase against
  the isolated ones to see whether uploads and downloads steal from each
  other.
- **Errors** are counted and sampled, not fatal. The test fails only when a
  phase stalls past its deadline (a wedged server, reported with how many
  workers finished) or every worker in a phase fails.

Watch the run from the outside too: `votport_sessions_active` against the
cap, `votport_http_requests_in_flight`, and the request-duration histogram on
the dashboard below tell you what the server thought was happening.

## Scraping /metrics into Prometheus

`GET /metrics` is Prometheus text format. Set `VOTPORT_METRICS_TOKEN` on the
server and give Prometheus the same value as a bearer token:

```yaml
scrape_configs:
  - job_name: votport
    metrics_path: /metrics
    scheme: https
    authorization:
      type: Bearer
      credentials: <VOTPORT_METRICS_TOKEN value>
    static_configs:
      - targets: ["drop.example.com:443"]
```

Scrape over an internal interface where you can; the token gates the route
but the metrics are still counts you may not want on the public path. A 15s
scrape interval is plenty; the histogram buckets are fixed and cheap.

## The Grafana dashboard

`ops/grafana-votport.json` covers the whole `/metrics` surface: traffic by
status class and 5xx ratio, latency percentiles from the request-duration
histogram, active sessions against the configured cap, native-push activity
and refusals, per-tenant links and received bytes, and audit health.

Import it with Dashboards, then Import, then Upload JSON file (or `curl` it
at `/api/dashboards/import`), and pick the Prometheus datasource when asked.
Set the `session_cap` dashboard variable to the target's
`VOTPORT_MAX_TOTAL_SESSIONS` so the capacity panel draws the real ceiling;
it defaults to 32 like the server does. The audit insert failures panel is
the one to alert on: any non-zero value means audit events are being
dropped.
