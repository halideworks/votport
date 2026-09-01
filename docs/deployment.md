# Deployment guide

votport is one container behind a TLS-terminating proxy. This guide covers a
production deployment end to end: layout, Caddy, SSO with worked examples,
backups, metrics, and content lifecycle.

## Layout

```text
docker-compose.yml          service definition (ports, env, volumes)
data/                       votport state (directory 0700, keep private)
  votport.db                SQLite store (links, tenants, audit log) (0600)
  votport.db-wal / -shm     SQLite write-ahead log and shared-memory files (0600)
  secret                    cookie-signing key        (0600)
  receipt.key               ed25519 receipt signer    (0600)
  push-issuer.key           native-push capability issuer, always here (0600)
  push.crt / push.key       generated native-push certificate and key (0600)
  backups/                  automatic and manual snapshots (directory 0700, files 0600)
/received                   received files, published per tenant/link
/outbound                   Deliver library files and rendered projects
  .vot-tenants.stage/<tenant> tenant-scoped library subtree
Caddyfile.example           reverse-proxy template
```

The container runs as uid 1000; all three mounted volumes must be writable by
it.

## Quick start

```sh
cp Caddyfile.example /etc/caddy/sites/votport   # adjust host + port
# edit docker-compose.yml: VOTPORT_ADMIN_PASSWORD, VOTPORT_PUBLIC_URL, volumes
docker compose up -d --build
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:<debug-port>/r/x   # expect 200
```

`VOTPORT_PUBLIC_URL` must be an `https://` URL for a deployed site. Plain
`http://` is accepted only when its host is loopback (`localhost`, `127.0.0.1`,
or `::1`), and invalid values stop startup.

For a customer release, use the GHCR image reference and digest recorded in the
GitHub release notes and workflow summary instead of rebuilding from source:

```yaml
services:
  votport:
    image: ghcr.io/halideworks/votport:vX.Y.Z@sha256:<published-digest>
    # remove build: .
```

The workflow also publishes `sha-<commit>` as a diagnostic tag. Do not use a
floating tag such as `latest` for a deployment.

## Admin pages and deliveries

The admin UI has separate **Receive** and **Deliver** pages. Receive issues
request links; each link can opt in to notification when a receive completes.
Deliver issues links for one or more outbound files; each delivery link can opt
in to notification on its first download and when the delivery completes.

Multi-file deliveries offer a payload-only ZIP or separate-file bulk streaming.
Receipts remain optional individual downloads. `max_downloads` applies per file
and per full-delivery round. Separate streaming uses bounded concurrency.

Per-tenant branding (name, accent color, logo) restyles the recipient pages,
but serving a tenant under its own hostname is Caddy configuration, not
votport: point the extra domain at the same upstream in the `Caddyfile` and
Caddy provisions its certificate. votport sees only the request path, so links
issued for any tenant work on every domain that reaches the instance.

## Native push

Native push is disabled unless `VOTPORT_PUSH_BIND` is set. It is a QUIC/UDP
listener separate from the HTTP listener, so keep the browser site behind
Caddy and expose the push port directly to senders. For a container listening
on UDP 8322, the deployment-specific compose service needs a mapping such as:

```yaml
ports:
  - "127.0.0.1:8103:8080"
  - "8322:8322/udp"
environment:
  VOTPORT_PUSH_BIND: "0.0.0.0:8322"
  VOTPORT_PUSH_ADVERTISE: "203.0.113.10:8322"
```

Replace the example address with the numeric public address reachable by the
sender, and allow that UDP port in the host and cloud firewalls. Do not put
the UDP mapping behind the normal Caddy `reverse_proxy`: it proxies HTTP/TCP,
not the VOT QUIC listener. The HTTPS `VOTPORT_PUBLIC_URL` remains the address
used for the link and native-push preflight.

If `VOTPORT_PUSH_CERT` and `VOTPORT_PUSH_KEY` are both unset, votport creates
and retains a self-signed certificate in `data/` and exposes its digest from
`GET /api/push-identity`. Pin that digest in each sender. To supply a
certificate instead, set both variables to readable PEM paths; votport uses
those files in place and does not obtain an ACME certificate for the UDP
listener. Back up the generated `push.crt` and `push.key` with the data
directory, or back up and rotate configured external files separately. The
`push-issuer.key` is always in the data directory and must be backed up there.
Rotating the certificate changes the identity and requires senders to pin the
new digest.

The sender presents the link password only to the HTTPS preflight,
`POST /api/r/{token}/push`, which admits the exact package root and length and
returns a capability, advertised address, certificate digest, and expiry. The
receiver checks the manifest entry count later against `MAX_ENTRIES`. Native
pushes then use the UDP listener. They share tenant/link
quotas, sessions, upload history, receipts, retention, and the admin UI with
browser uploads. A native package is staged and published after the complete
package verifies; a failed or cancelled native push does not leave partial
destination files.

The VOT b14 CLI requires a numeric IPv4 or bracketed IPv6 `SocketAddr` for
`vot push`; it does not resolve the advertised DNS name. Use a numeric
`VOTPORT_PUSH_ADVERTISE` when supporting that CLI. Library senders may resolve
DNS before calling the VOT push API.

## Backups

Three stores, two clocks. The System page can run scheduled backups to a local
target and/or an S3-compatible bucket. Litestream (or an equivalent WAL
replica) remains the database RPO for deployments that need continuous
replication. `/received` and `/outbound` stay on existing file backups.

Automatic archives contain the SQLite database and VOTPort-managed identity
files only: the cookie secret, receipt signer, native-push issuer, and
VOTPort-generated push certificate pair. They exclude WAL/SHM files,
`data/backups/`, staging data, and everything under `/received` and
`/outbound`. Configured external certificate files are not copied. The local
path is interpreted inside the service filesystem and must be writable by the
container user; blank uses `<data_dir>/backups` (normally `/data/backups`). A
custom path must already exist with no symlink or group/other-writable ancestor.
A dedicated host directory must be mounted at that container path. S3 uploads
use the configured bucket and prefix. The UI reports credential and passphrase
configured flags, never their values.

Pruning is owned by VOTPort for snapshots it created under the configured
local path and for generated `votport-backup-v1-*` objects under the configured
S3 prefix. It does not delete unrelated local files or bucket objects. Keep an
external recovery copy of the encryption passphrase. An
encrypted archive is unrecoverable without it, and storing that passphrase in
the same deployment backup defeats recovery isolation.

| Store | Mechanism | RPO | RTO |
| --- | --- | --- | --- |
| `data/votport.db` | Litestream (or equivalent WAL replica) continuous | seconds (Litestream's default interval is about 1s of WAL) | minutes: stop container, `litestream restore`, start |
| `data/votport.db` | `GET /api/admin/backup` (`VACUUM INTO`) | last time someone clicked Download (not the DR clock) | same stop-replace-start |
| `/received` | existing file backup (restic, borg, zfs send, rsync) | that job's interval | restore files, start |
| `/outbound` (including `.vot-tenants.stage/<tenant>`) | existing file backup (restic, borg, zfs send, rsync) | that job's interval | restore files, start |

### Database copy-home

`GET /api/admin/backup` (admin session) streams a consistent snapshot produced
by SQLite's `VACUUM INTO`, with `Content-Length`. Snapshots land under
`data/backups/` and are swept after 30 days. Manually:

```sh
sqlite3 data/votport.db ".backup data/backups/manual.db"
```

The legacy Download snapshot action remains database-only. It is useful for a
quick copy home, but it is not a replacement for the scheduled archive or the
external `/received` and `/outbound` backups.

### Litestream

Replicate on; restore before the container starts. Keep the recipe
operator-owned (do not add a sidecar to `docker-compose.yml`).

```yaml
# litestream.yml (operator-owned)
dbs:
  - path: /data/votport.db
    replicas:
      - type: s3
        bucket: example-votport
        path: votport
```

Postgres is not on the table.

### Persistent files

Plain files under `/received` and `/outbound`. Any file-level backup tool works
(restic, borg, zfs send, rsync); include the named-tenant subtree
`/outbound/.vot-tenants.stage/<tenant>`. Back both volumes up together with a
database snapshot so records and bytes stay consistent with each other.

### Restore

The System page's Restore action validates the selected archive, stages it,
and asks the supervised service to restart. At boot, VOTPort moves the current
managed files into a private `.votport-restore-rollback-<token>/` directory
under `data/`, installs the staged database and identity files, then removes
the restore stage and marker after the file installation and integrity checks
finish. Later database migration, receipt signer, or push initialization can
still fail; the private rollback directory remains for operator recovery and
can be removed after the restored deployment is accepted. The archive still
does not restore `/received` or `/outbound`; use the matching operator-owned
file backups for those volumes.

With the default compose restart policy, the process restart request is
observed by the supervisor and the service comes back. Without a supervisor,
the action only stages the restore: stop the container or process, then start
it manually so boot can apply the pending restore. Never copy a live `-wal`
over a restored database. The install clears the restored backup destination
and leaves automatic backups disabled, preventing historical S3 targets from
receiving data with current credentials. Re-save and re-enable backup settings
after verifying the deployment.

Restoring the managed cookie secret rotates the admin cookie signing key and
signs out every existing admin session. Plan to sign in again after restart.

For a manual restore, use the System action or place a validated archive in
the pending restore workflow; do not copy archive members directly over a live
database. Verify `/healthz` and a known Receive and Deliver link. A
database-only restore cannot serve Deliver files whose source remains absent
from `/outbound`.

For an upgrade or rollback, record the complete image reference, including its
digest, with the point-in-time backup set. Restore the database and both file
volumes from that set, set the compose service to the selected digest, and
start it without rebuilding. Verify `/healthz` and a known Receive and Deliver
link; a database-only restore cannot serve Deliver files whose source remains
absent from `/outbound`.

## Single sign-on

Register an OIDC application at your identity provider with redirect URI
`https://YOUR-HOST/api/admin/callback`, then set:

```yaml
VOTPORT_OIDC_ISSUER: "https://idp.example.com"
VOTPORT_OIDC_CLIENT_ID: "..."
VOTPORT_OIDC_CLIENT_SECRET: "..."
VOTPORT_OIDC_ADMIN_GROUP: "votport-admins"   # omit = every principal is admin
VOTPORT_OIDC_AUDITOR_GROUP: "votport-auditors" # optional audit-only role
```

Roles come from the provider's `groups` claim: members of the admin group are
administrators, members of the auditor group (when configured) get an
audit-only session that can read and export the audit trail but sees no
links, files, grants, or settings, and everyone else is a read-only viewer.
Admin membership outranks auditor membership. The local password always
remains available as break-glass access. `POST /api/admin/login` is never
disabled. System can collapse the password form behind a "Use local password"
disclosure when SSO is configured; the form stays in the page. Without SSO
the form stays expanded even if `VOTPORT_PUBLIC_PASSWORD_LOGIN=0`. An
unreachable IdP may mute the SSO button, never the password form.

A single `VOTPORT_OIDC_CLIENT_ID` is the supported shape. When an id token
carries `azp`, it must equal that client id. The crate already checks issuer,
audience, and nonce. A second client or a hosted-domain (`hd`) allow-list is
not supported.

Discovery runs on first SSO use, not at process start. Failed discovery cools
down for 30 seconds and then retries. A successful discovery stays loaded
until process restart, so rotating IdP metadata still needs a restart.

SSO sessions last `VOTPORT_SSO_SESSION_SECS` (default 604800, 7 days), and a
platform admin can adjust the value live from System > Sign-in; the stored
setting overrides the environment. The local break-glass session keeps a
fixed 7 days. The session cookie freezes the principal's tenants and roles at
login, so removing a user's IdP group takes effect at their next login,
bounded by this lifetime; shorten it when offboarding latency matters. To cut
access immediately, also revoke the principal in the Tenants page;
offboarding is a two-step action across the IdP and votport.

### Authentik

1. Applications > Applications > Create: choose *Authorization code with PKCE*.
2. Redirect URI: `https://YOUR-HOST/api/admin/callback`.
3. Copy the client id and secret; issuer is `https://auth.example.com/application/o/<slug>/`.
4. In the provider's *Advanced protocol settings*, add the groups you want in
   the `groups` claim (Authentik includes groups by default for OAuth2 sources).

### Entra ID (Azure AD)

1. App registrations > New registration > Web, redirect URI as above.
2. Certificates & secrets > New client secret.
3. Issuer: `https://login.microsoftonline.com/<tenant-id>/v2.0`.
4. Token configuration > Add groups claim (security groups, emitted as group
   IDs); use the object ID of your admin group as `VOTPORT_OIDC_ADMIN_GROUP`,
   or expose group names via directory roles/attributes as your policy allows.

### Tenants

Create namespaces from an admin session (default-tenant admin only):

```sh
curl -b cookies.txt -X POST -H 'Content-Type: application/json' \
     -H 'X-Votport: 1' https://YOUR-HOST/api/admin/tenants \
     -d '{"key":"acme","label":"Acme Corp","admin_group":"acme-admins",
          "max_total_bytes":107374182400,"max_links":50,"max_sessions":4}'
```

SSO principals whose groups include `acme-admins` may switch into `acme`
from the dashboard switcher. Named tenants publish into the reserved
`/received/.vot-tenants.stage/acme/...` subtree; the default tenant keeps the
receive root and cannot upload a path that names the reserved subtree.

Update quotas, label, or admin group without recreating the namespace
(JSON `null` clears a quota back to unlimited; `0` is rejected):

```sh
curl -b cookies.txt -X PATCH -H 'Content-Type: application/json' \
     -H 'X-Votport: 1' https://YOUR-HOST/api/admin/tenants/acme \
     -d '{"max_total_bytes":214748364800,"max_links":100}'
```

`DELETE /api/admin/tenants/{key}` drops the namespace row and purges both
`<receive>/.vot-tenants.stage/<key>/` and
`<outbound>/.vot-tenants.stage/<key>/`. Point-in-time snapshots under
`data/backups/` (30-day sweep in the session sweeper) and Litestream replicas
still contain the tenant's rows until they rotate. File backups of
`/received` and `/outbound` retain bytes until they rotate. GDPR-style erasure
of backups is an operator job, not an API.

Retry DELETE if purge fails (the row is already gone; leftover retry removes
the reserved directory). An unknown key with no leftover directory is 404
and does not touch disk. A default-tenant path with the same name is separate
and is never purged.

The first start after upgrading moves each existing named tenant from
`<receive>/<key>/` into the reserved subtree. The move is same-filesystem and
resumable. If both old and new paths exist for a tenant, startup refuses so an
operator can move one aside instead of guessing which data owns the name.
Startup also refuses when a default-tenant link or live record uses the legacy
prefix, or when a legacy tenant key falls outside `[a-z0-9_-]`. Reconcile those
names and records before retrying the upgrade.

The local platform password is break-glass for every namespace; named
tenants have no separate password.

### Principals

SSO sign-in records the principal on `/tenants`. Kick someone (current
sessions die; further SSO is refused until you unblock):

```sh
curl -b cookies.txt -X POST -H 'Content-Type: application/json' \
     -H 'X-Votport: 1' https://YOUR-HOST/api/admin/principals/revoke \
     -d '{"subject":"user@example.com"}'
```

Unblock does not restore old cookies; they must sign in again. Lasting
revoke is removing the IdP group.

```sh
curl -b cookies.txt -X POST -H 'Content-Type: application/json' \
     -H 'X-Votport: 1' https://YOUR-HOST/api/admin/principals/unblock \
     -d '{"subject":"user@example.com"}'
```

## Settings

Default-tenant admins edit notification URLs, SMTP, retention days, default
quotas, and the sign-in disclosure from the System page. Those values
overlay environment variables via `GET`/`PUT /api/admin/settings`
(`X-Votport` on PUT). Env remains the boot default; a written key wins;
`""` disables a URL or token; JSON `null` ("Use environment") deletes the
row so env applies again. See [`enterprise-ops.md`](enterprise-ops.md).

## Admin password minimum

`VOTPORT_ADMIN_PASSWORD` must be at least 12 characters, and votport exits at
startup when it is shorter. Throttling bounds how fast a guess is checked and
cannot make a short password safe, and this is the credential that still works
when the identity provider does not.

Upgrading a deployment whose password is shorter will fail to start. Either
set a longer one, or switch to `VOTPORT_ADMIN_PASSWORD_HASH`, which is exempt
because a PHC string says nothing about the length of the password behind it.
A password already changed through the System page lives in the database and
takes precedence over both, so rotating the environment value does not sign
anyone out.

## Client addresses

Throttles and audit rows need to know which client made a request. Behind a
reverse proxy the socket peer is the proxy, so votport reads the rightmost
`X-Forwarded-For` entry, the one the proxy appended. Earlier entries are
whatever the client sent and are ignored.

That header is only believed from a peer that could be the proxy. With
`VOTPORT_TRUSTED_PROXIES` unset the rule is "any loopback or private address",
which is broad enough to matter: on a shared container network, or with the
default `0.0.0.0` bind reachable from a LAN, anything else that can open a
connection can send a different `X-Forwarded-For` per request and give itself
a fresh throttle bucket every time.

Set the variable to the address your proxy actually connects from:

```yaml
environment:
  VOTPORT_TRUSTED_PROXIES: "10.1.2.3/32"      # example only
```

Do not copy an address out of this document, and do not assume a container
bridge gateway is stable, because Docker assigns those when it creates the
network. Determine it for your own deployment: send one request **through the
proxy** with a deliberately wrong admin password, then read what votport
logged.

```sh
curl -sk --resolve receive.example.com:443:127.0.0.1 \
  -X POST https://receive.example.com/api/admin/login \
  -H 'content-type: application/json' -d '{"password":"wrong"}'
docker logs --since 30s votport | grep admin_login_failed
```

That line carries two addresses, and the difference between them is the whole
point:

- `peer` is the socket address votport accepted the connection from. Behind a
  proxy this is the proxy. **This is the value to name in the variable.**
- `ip` is the address votport decided the client has, which is the forwarded
  header when it was believed. Naming this one would trust a client rather
  than the proxy, and leave the proxy untrusted.

Send the request through the proxy, not straight to the published port: a
direct request makes both fields the same and tells you nothing about which
is which.

Recheck after recreating the network. Naming an address the proxy does not
connect from collapses every client into one bucket, so confirm afterwards
that failed sign-ins from two different clients still log two different `ip`
values.

## Metrics

`GET /metrics` serves Prometheus-format counters and gauges (tenants, links,
received bytes, active sessions, audit rows), plus native-push active sessions,
received bytes, and refusals by bounded reason (`rate`, `capability`, `expired`,
or `spent`). It also exposes fixed-cardinality HTTP request totals by status
class, in-flight handlers, and a time-to-response-headers histogram with 10ms
through 5s and `+Inf` buckets; streamed body transfer time is excluded. Outbound
library uploads also have a fixed-cardinality
`votport_http_outbound_upload_duration_seconds` histogram with no route labels.
Request metrics never include paths, tenants, addresses,
methods, or tokens. Set `VOTPORT_METRICS_TOKEN` to require a bearer token, and
scrape it over an internal interface only.
Platform admins can fetch the same per-tenant link and live-byte totals as JSON
from `GET /api/admin/holdings`.

## Content lifecycle

Set `VOTPORT_UPLOAD_RETENTION_DAYS` to delete received files (and their
records' live status) older than N days, swept daily with audit events.
`VOTPORT_AUDIT_RETENTION_DAYS` (default 400) prunes audit rows the same way.
Upload retention defaults to keeping everything; audit rows default to
400 days. A link's **Legal hold** action excludes all of that link's uploads
from the automatic content sweep and records the change in the audit log.
Explicit file, upload-record, link, and tenant deletion remain available.

## Performance

Range size is 8 MiB, set by VOT, advertised as `chunk_bytes` on session
create. The sender keeps eight range PUTs in flight. The upload worker
drains the in-flight window as one batch and verifies and writes those
ranges in parallel (VOT's `accept` takes shared access since ADR-0046),
so a single fast upload is no longer bottlenecked on one-at-a-time verify.
Measured single-stream upload rose about a quarter (256 MiB baseline,
1258 to 1580 MiB/s median on the same rig). The native-push receive path
still verifies serially and is the next candidate.

Do not raise `CHUNK_BYTES` in votport until VOT changes its server verify
path to support larger ranges; the `aba35a0` pin does not. Any VOT re-pin
moves the VOT dependencies and Dockerfile `ARG` together, then relocks
Cargo.lock. Measure with:

```sh
cargo test --test e2e -- --ignored --nocapture throughput_baseline
```

`VOTPORT_MAX_TOTAL_SESSIONS` (default 32) caps concurrent upload sessions
process-wide; the 33rd sender gets a 429 until one finishes. Worst-case
queued-body memory rises linearly with it: sessions x 8 in-flight chunks x
~9 MiB, so 32 sessions bound roughly 2.3 GiB. Size it against available RAM
before raising it for a busy facility.

Static assets under `/assets` are served `no-cache` and answer conditional
GETs with 304s, so a redeploy takes effect on the next page load. The heavy
leaf assets (fonts, the hero image and ship mark, the wasm verification
binary) are referenced with a `?v=<content hash>` stamp and those responses
are `immutable`, cached for a year without revalidation. Stamps maintain
themselves: `scripts/build-wasm.sh` and `scripts/fetch-fonts.sh` restamp
what they generate, and `npm test` fails if a stamp goes stale.

## Logs

Operational logs use a human-readable format by default. Set
`VOTPORT_LOG_FORMAT=json` to emit one JSON object per line for log pipelines.
`RUST_LOG` controls the filter either way; the audit trail is separate and
exports as JSONL from the Audit page regardless of this setting.

## Scaling and availability

votport is a single-replica service by design: SQLite is the one writer, and
upload sessions, throttles, and rate state live in process memory. Running two
replicas behind one hostname is unsupported; scale up (CPU, RAM, faster disk),
not out. This is the deliberate trade for atomic verified publication with no
external dependencies; see docs/multi-tenancy.md non-goals.

A restart discards in-flight upload sessions: staged partials are swept at
boot, and senders start those files over (files already published from a
multi-file session survive and dedupe on re-send). Long streaming downloads
die with the process too. For a planned upgrade, drain first: stop handing out
new links or wait for a quiet window, watch `votport_sessions_active` on
/metrics reach 0, then restart. The compose file sets `stop_grace_period: 5m`
so in-flight downloads get a window to finish; no grace period covers a
multi-hundred-GiB upload, which is what the drain is for.
