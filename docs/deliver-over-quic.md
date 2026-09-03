# Deliver over QUIC, the replication agent, and the road to votdock

Status: V1 and V2 landed upstream (VOT #401, #402) and P1 in votport,
2026-09-02; votport pins VOT at `d3c18a46ba5c9108091c9639151c40cd34d95fd3`.
P2, P3, the agent, and phase W remain.

| Field | Value |
| --- | --- |
| Status | V1 and V2 merged upstream (VOT #401, #402); P1 implemented in votport |
| Date | 2026-09-02 |
| Continues | `docs/native-push.md` (the receive direction of the same carrier) |
| Audience | David, and the next session |

## Overview

votport receives over VOT QUIC (native push, `docs/native-push.md`) and
delivers over HTTP. This design adds the other direction: votport serves
Deliver grants and received uploads over VOT QUIC, so a recipient with a VOT
client fetches multi-rail, resumable, verified per range, at the rates
measured upstream (2.10 Gbit/s Helsinki to Singapore at 191 ms RTT, 1.08
Gbit/s at 5% loss, 9.21 Gbit/s on a 10 GbE LAN). The same serve path feeds a
standalone replication agent that copies published uploads to a second
store, a facility's directory or S3-compatible object storage such as
Cloudflare R2. That agent's core is the transport half of votdock, the
hosted product, and later of the desktop apps.

The order is deliberate. Deliver over QUIC is the urgent need and the serve
seam it requires is also what the agent fetches from, so the seam lands
first, then serving grants, then the feed and the agent, then the S3 target.

## Goals

- A recipient holding a Deliver link can fetch it over VOT QUIC with the VOT
  CLI (`vot fetch` or `vot pull`), the agent, or later the desktop app, and
  get every byte proven to its object root on arrival.
- The same serve path exposes received uploads (by upload record) to an
  agent that holds a tenant-scoped credential.
- The agent replicates every published upload to a directory or an S3
  bucket, ordered by a durable feed with acks and tombstones, and reports
  its state back so the admin sees per-file replica status.
- One issuer key and one audience cover push and fetch, so the existing
  `push-issuer.key` and `/api/push-identity` are reused.

## Non-goals

- Replacing the recipient web page in version one. Browsers cannot open a
  raw QUIC connection with VOT's ALPN; `/s/{token}` stays on HTTP with
  server-side verification. Browser QUIC arrives through WebTransport as a
  later phase (see "Browsers over WebTransport"), not by dropping HTTP.
- One UDP port for both directions. Version one binds a second port for
  serving. Role detection at admission (a push token carries Publish, a
  fetch token carries ReadManifest and ReadRanges) is a follow-on.
- Rendezvous, relay, or hole punching. votport is the fixed end; recipients
  and agents dial it.
- Fetching one file out of a pack. The unit of transfer, resume, and
  completion is the stored object; a pack moves whole.
- The multi-box control plane, billing, or signup for votdock. This design
  builds the transport and replication half and names the rest.

## What VOT provides today, and what it does not

From the pinned revision and the current VOT main:

- Serving is `serve_bundle(bundle_dir, address, credentials, sessions,
  listening)`. It binds its own socket, takes one bundle directory
  (`manifest/` pages plus `seal`, `objects/<root-hex>`), builds its
  capability requirement from process environment variables, sets no
  stateless retry, has no per-peer cap, no completion callback, and no
  byte counters. One `BundleServer` is one package root. `CONCURRENT_SESSIONS`
  is a global 8 with backpressure, so one client at eight rails fills it.
- Receiving has the seam votport already uses: `bind_push_listener` (retry
  on) plus `receive_push_on(listener, policy)` where the policy sees a
  `PushPresentation` (peer, challenge, open, channel binding, now) and
  returns `Option<PushAdmission>`. Nothing equivalent exists for serving;
  the pieces (`BundleServer::open`, `ServeSession::begin`, `drive`) are
  public but the accept loop, stance, and limits are crate-private.
- `BundleServer::open` reads and hashes every object at open, about 1.4 s
  per GiB single-threaded, unless a `<root>.leaves` cache sits next to the
  object. Only `vot send` writes that cache and the writer is crate-private.
  A bundle received by push has none.
- Fetching is `fetch_bundle(address, bundle_dir, pin)` with every knob a
  process-global environment variable (`VOT_FETCH_CAPABILITY`,
  `VOT_FETCH_HOLDER_KEY`, `VOT_FETCH_SERVE_IDENTITY`, `VOT_FETCH_RAILS`,
  `VOT_FETCH_STATS`). Capability, rails, and resume come together only in
  that shape; the seams constructor is one rail, no capability, no resume.
- Capabilities: `vot_cli::authz::issue(issuer, audience, key, holder, root,
  now, seconds)` mints exactly what a serve accepts (ReadManifest plus
  ReadRanges over the package root, suite 1, no length, no ranges). Tokens
  are not single use; lifetime is the validity window; the serve refuses
  with one constant detail for every reason. The proof of possession binds
  to the TLS exporter (ADR-0037), so a middle cannot replay it.
- Mutation: the serve takes a length-plus-mtime witness at open and hashes
  covers it cannot vouch for; a changed source closes the session with
  `SOURCE_MUTATED`.
- Proof catalogs (`vot-proof-catalog`) are for dumb storage and are not on
  the serve path. votport's `outbound.proofs` catalogs stay for HTTP and are
  irrelevant to QUIC serving.

## VOT changes

Each mirrors something the push path already has, which is the argument for
the review. Land as separate VOT PRs, gated on mutants and the public API
snapshot, then repin votport (eleven sync points, `scripts` note in memory).

1. `bind_serve_listener(address, &Credentials) -> Result<(Listener, [u8; 32]), Error>`
   with `stateless_retry` on, returning the certificate digest, exactly as
   `bind_push_listener` does.
2. `serve_on(listener, policy)` where
   `policy: Fn(ServePresentation<'_>) -> Option<ServeAdmission> + Sync`,
   `ServePresentation { peer, challenge, open, channel_binding, now }`, and
   `ServeAdmission { server: Arc<BundleServer>, scope: Vec<u8>, observer:
   Option<Box<dyn ServeObserver>> }`. The observer receives the session's
   served byte count and its GOAWAY cursor (objects finished) at session
   end. The accept loop enforces the ten-second authorization deadline
   ADR-0045 already requires of receivers and reaps as `serve_sessions`
   does. The policy decides the root from the token's scope, so one socket
   serves every package.
3. `BundleServer::assemble(manifest_root, sources)` (landed, ADR-0049):
   `manifest_root` holds `manifest/` with pages and seal, and `sources`
   maps each stored root to `ServedSource { path, leaves }`. With leaves
   supplied the server samples the file instead of reading it. This
   removes the per-grant bundle directory and, once leaves are handed in,
   the 1.4 s/GiB open cost.
4. `proof_cache::write` made public, and `NativeFile::publish` given a way
   to emit `<root>.leaves` next to a published file, so received uploads
   carry leaves like sent bundles.
5. `fetch_bundle_with(FetchOptions)` where the options struct carries what
   the environment variables carry today (capability bytes, holder key,
   serve identity, rails, provers, stats sink), so a long-running agent can
   run two fetches with two capabilities at once.
6. Per-peer session cap in the serve accept loop, or at least a policy
   refusal by peer that the loop honours before the handshake completes.

## votport: serving grants

### Listener and identity

`VOTPORT_SERVE_BIND` (UDP, default off) and `VOTPORT_SERVE_ADVERTISE`. The
listener uses the push certificate and key from `data/push.crt` and
`data/push.key`, the same issuer key `data/push-issuer.key`, the issuer name
`votport`, and the same audience as push. `/api/push-identity` grows a
`serve_address` field. The serve thread mirrors `start_push_receiver`: an OS
thread that locks the listener for the process lifetime and calls
`serve_on` with `admit_fetch` as the policy.

### Admission

A package root is a function of the files, so two grants over one file set
share a root; what names a grant is the fetch ticket recorded at mint
(`outbound_fetch_tickets`, keyed by the capability's token id). `admit_fetch`
runs per session, which is what gives early revocation:

1. Rate limit by peer (its own `serve_rate`).
2. Read the token id and root from the presented capability before
   authenticating it, only to find the ticket and pick the requirement;
   the seam re-checks the granted scope against the server it answers
   from. No ticket, or a ticket for another root: refuse.
3. Load the grant by id. Revoked, expired, or exhausted: refuse.
4. `Requirement::new` for that root and `decide`; a refusal is the constant
   reason and detail.
5. Claim the fetch's download slot (one per capability, however many
   rails) and return the registry's `Arc<BundleServer>` with an observer
   that credits the session's bytes to the token.

### Serve registry

`ServeRegistry` in `server/src/api/serve.rs`: root to `Arc<BundleServer>`,
built at mint (and warmed at start for every live ticket, so a restart
honours capabilities minted before it), plus the bytes each token's
sessions have taken and the slot each fetch holds. `BundleServer::service`
is `&self`, so one server answers every session for that root. The session
sweeper keeps servers for grants still open, drops byte counts of expired
tickets unless a session of that fetch is still running, and deletes tickets
expired for more than a day. A slot is released by its sessions: the
observer owns a hold that releases on drop, so an admission the seam
discards before serving releases too.

### Bundle shape for a grant

A grant needs a manifest and a package root. Library grants store an empty
`package_root` today; received-file grants inherit the upload's. So:

- At the first mint for a grant, build the manifest with `vot_sdk`
  `PackageBuilder` from the grant's files (path, object id) in canonical
  order, write the pages and seal under `data/outbound.manifests/<grant>/`
  (vot-cli's layout: `manifest/{index:016}.cbor` and `manifest/seal.cbor`,
  names upstream keeps crate-private), and record the package root in a
  new `outbound_grant_manifests` table keyed by grant id. Schema 21.
  Building lazily means grants from before are servable without a
  backfill, and a received-file grant gets a one-entry package whose root
  differs from the upload's.
- Objects resolve through the code that already resolves downloads:
  `source_info_indexed_with_file` for library files and received files.
- Leaves (P2, not yet landed): `hash_library_file` reads every byte at
  grant time; emit leaves with `proof_leaves_at` there and store them in
  `outbound.proofs` as `<suite>-<root>-<length>.leaves`. Received files get
  leaves lazily at first serve until VOT change 4 lands, cached the same
  way. The registry hands the leaves to `BundleServer::assemble` as each
  `ServedSource`. P1 passes no leaves and reads the files at assembly.
- The mutation rule: a library file under an active grant must not be
  replaced. Deletion already refuses with 409 on an active grant; the
  library upload path needs the same guard.

### Recipient protocol

`POST /api/s/{token}/fetch` with `{ holder_key }` after the password gate.
The server mints `issue(...)` for the grant's package root with a TTL of
`min(grant expiry, 1 hour)`, records the mint as intent, and returns
`{ capability (base64), address, certificate_digest, package_root,
expires_at }`. The recipient runs:

```
VOT_FETCH_CAPABILITY=token.cbor VOT_FETCH_HOLDER_KEY=env:HOLDER_SECRET \
VOT_FETCH_SERVE_IDENTITY=<digest> VOT_FETCH_RAILS=8 \
vot pull <address> ./bundle ./delivered receipt.cbor <key> <observed_at> <package_root>
```

or `vot fetch` for a bundle directory. The web recipient page shows the
command with the token filled in, next to the HTTP buttons, when
`serve_address` is set.

### Download accounting

`max_downloads` is a client-delivery control: it applies to outside-facing
grants (`/s/{token}`), never to an agent fetching the tenant's own uploads.
The HTTP path counts a download per request. Over QUIC a completed fetch
sends no GOAWAY (the cursor is only sent on a cancel), and every rail is its
own session, so the registry sums each capability's served bytes across its
sessions and counts one delivery when the sum reaches the package's logical
length, once per fetch (the count stays until the fetch's last session
ends, so pages and proofs running past the length cannot count again);
served bytes include pages and proofs, so this trips a little early, which
errs toward counting a delivery that happened. `max_downloads` is enforced
twice: a mint reserves a delivery in the same statement that records its
ticket, refusing when deliveries plus live undelivered tickets leave no
room, and admission refuses an exhausted grant. Minting is recorded as an
audit row (`outbound_fetch_minted`) so an operator can see fetches that
never completed. Agent fetches are admitted by token scope and recorded as
replication, not as deliveries. Bytes served feed `votport_serve_bytes_total`
and a `votport_serve_sessions_active` gauge. Recording is per session end,
not per range, so it costs nothing on the data path.

### Failure webhook and audit

`serve_admitted` and `serve_completed` audit rows and tracing events, and
`serve_refused{reason}` as a tracing event only (a refusal is unauthenticated
and attacker-controllable, as with push), mirroring the push vocabulary. A
completed QUIC delivery sends the same `outbound_download_started` and
`outbound_delivery_complete` notifications the HTTP path sends.

## votport: the publication feed and replicas

### Why not the audit log

The audit log is best effort (a failed insert is counted and dropped),
prunes by time, carries no download event, and its cursor is the implicit
rowid. A replication feed needs its own table.

### Schema (part of the same version bump)

```
publications (
  id INTEGER PRIMARY KEY,
  at INTEGER NOT NULL,
  tenant TEXT NOT NULL,
  kind TEXT NOT NULL,            -- published | deleted
  link_id TEXT NOT NULL,
  upload_id TEXT NOT NULL,
  file_index INTEGER NOT NULL,
  root TEXT NOT NULL,
  suite TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  stored_as TEXT NOT NULL
)
replicas (
  target TEXT NOT NULL,          -- agent id
  link_id, upload_id, file_index,
  state TEXT NOT NULL,           -- pending | stored | failed | deleted
  at INTEGER NOT NULL,
  error TEXT,
  PRIMARY KEY (target, link_id, upload_index, file_index)
)
```

`upload_completed` inserts one `published` row per file inside the same
transaction that appends the upload record, so the feed cannot lag the
record. Admin delete and the retention sweep insert `deleted` rows. On first
enable for a target, the sweep backfills `pending` replicas for every live
file so existing holdings replicate too.

### Endpoints

- `GET /api/agent/feed?after=<id>&limit=` returns rows in id order. Bearer:
  an automation token carrying the `replicate` scope. Tenant-scoped.
- `POST /api/agent/ack` with `{ target, rows: [{ id, state, error }] }`.
- `POST /api/agent/fetch` with `{ upload_id, holder_key }` mints a fetch
  capability for that upload's package root and returns the same shape as
  the recipient endpoint. Received uploads are served through the same
  registry, assembled from the upload record's files.
- The admin Receive page shows per-file replica state from `replicas`, and
  `votport_replicas{target,state}` gauges join `/metrics`.

## The agent

A new crate `agent/` in the votport workspace, binary `votport-agent`,
depending on `vot-cli` (wire) and `object_store` (aws). Config is a TOML
file plus environment for secrets: portal URL, automation token, agent id,
target (`dir:/path` or `s3://bucket/prefix` with endpoint and region),
rails, concurrency.

Loop:

1. Poll the feed from the persisted cursor; batch `published` rows by
   upload id.
2. For each upload, call `/api/agent/fetch`, then `fetch_bundle_with` into
   a staging bundle directory with the capability, the pinned identity, and
   rails. Resume comes for free from `resume.vot`.
3. Publish: `receive_bundle` into a staging directory, then for a directory
   target rename each file into place under `tenant_prefix/stored_as` with
   its receipt sidecar; for S3 put each file with `object_store` multipart
   (the same code `backup.rs` uses) under `prefix/tenant_prefix/stored_as`
   plus the `.vot-receipt` sibling.
4. Ack `stored` after the store confirms, never before. A failed store acks
   `failed` with the error and retries on the next pass with backoff.
5. `deleted` rows remove the replica and ack `deleted`.
6. Serve `/metrics` with fetched bytes, sessions, store latency, and the
   cursor lag.

The agent's identity is its automation token; it has no key file of its
own. If a later version gives it one, it goes in `backup::MANAGED_FILES`.

### Automation token scopes

Automation tokens gain a `scopes` column (schema 21, default `share` for
existing rows). Scopes: `share` (today's `POST /api/automation/share`),
`replicate` (feed, ack, and agent fetch of the tenant's uploads), and
`fetch` (mint a fetch capability for a named grant, for scripted client
pulls). The create endpoint takes a scope list; the admin page shows it; a
refusal audits `automation_refused` with the missing scope. The optional
`directory` confinement keeps applying to `share`.

## Browsers over WebTransport

Browsers cannot dial VOT's ALPN, but every current engine ships
WebTransport over HTTP/3 (Chrome 97, Edge 97, Firefox 114 for streams,
Safari 26), and `serverCertificateHashes` lets a page connect to a
self-signed certificate it pins by hash, exactly the pin VOT already uses.
The feasible path is a WebTransport carrier for VOT:

- VOT side: a `vot-transport-webtransport` adapter implementing
  `TransportAdapter` over an HTTP/3 extended CONNECT session on the same
  quiche stack (quiche ships H3), carrying VOT records on bidirectional
  streams and datagrams. A browser adapter in `vot-wasm` over the
  `WebTransport` API, so the recipient page runs the real fetch engine:
  multi-rail (one WebTransport session per rail), range proofs verified in
  the tab, resume from a local store.
- Channel binding: a page cannot read the TLS exporter, so ADR-0037's
  possession proof cannot bind to the channel. The browser session binds
  the proof to the pinned certificate hash plus the nonce instead; the pin
  is what defeats a middle, and the serve marks such sessions as
  hash-bound in the observer so policy can treat them separately.
- Caddy cannot proxy WebTransport; the page connects straight to the serve
  port, so the certificate in use must be the one whose hash the page was
  given (the 14-day validity rule for hash-pinned certificates means votport
  rotates the serve certificate on a schedule and publishes the current
  hash).
- Sender direction later: the same carrier under the PUSH extension lets
  the browser sender push instead of posting chunks through Caddy.

This is phase W, after P1, and is its own design once V1 is in.

## Sequencing

| PR | Repo | Content |
| --- | --- | --- |
| V1 | VOT | `bind_serve_listener`, `serve_on`, `ServePresentation`, `ServeAdmission`, observer, auth deadline |
| V2 | VOT | `BundleServer::assemble` with prepared objects |
| V3 | VOT | `proof_cache::write` public; leaves on publish |
| V4 | VOT | `fetch_bundle_with(FetchOptions)`; per-peer cap |
| P1 | votport | Repin to V1 plus V2; serve listener, registry, admission, manifest at grant creation, schema 21, `/api/s/{token}/fetch`, accounting, audit, metrics, recipient page command |
| P2 | votport | Leaves at grant hashing and lazy leaves for received files; library upload guard on active grants |
| P3 | votport | Publications and replicas tables, feed and ack endpoints, `replicate` token scope, admin replica state, backfill |
| A1 | votport | `agent/` crate with the directory target; run on loopback against the live box |
| A2 | votport | S3 and R2 target; run one agent on a VM near an R2 bucket against erebus |
| W1 | VOT | WebTransport carrier (server adapter on quiche H3, browser adapter in vot-wasm), hash-bound possession proof |
| W2 | votport | Recipient page fetches over WebTransport with HTTP fallback; serve certificate rotation and hash publication |
| D1 | votdock | Fork; control plane; presigned R2 downloads; fleet config |

V1 and V2 can be one VOT PR if the review prefers; P1 is the first user
visible result and the one to measure.

## Measurements to take, before and after

- Deliver of a 20 GiB grant over HTTP versus `vot fetch` at 8 rails, on the
  LAN and over the tr-desktop link, same box and method.
- `BundleServer::assemble` with prepared objects versus `open` on a 100 GiB
  grant: time to first byte after boot.
- Agent replication of one day's uploads to a directory on loopback and to
  R2 from Hetzner: wall time, cursor lag, and store latency.

## Risks

- Facility firewalls: a client behind a corporate network may not get UDP
  out. HTTP remains, and the page shows both paths.
- The serve seam's shape is a guess until the upstream review; the fallback
  bundle directory keeps P1 possible without V2.
- Two UDP ports and one certificate: rotating the cert re-pins both.
- A large open grant set with lazy leaves means the first fetch of a
  received upload pays the hash; the leaves-on-publish change removes it.
- The agent holds W rails of receiver budget (up to about 1.7 GB at eight)
  per fetch; concurrency defaults to one fetch at a time until measured.

## Decisions taken 2026-09-02

- `max_downloads` applies only to outside-facing client deliveries; agent
  replication of a tenant's own uploads is never counted against it.
- Browsers get QUIC through WebTransport as phase W; HTTP stays as the
  fallback rather than being replaced.
- Agent credentials are automation tokens with a new scopes column, not a
  separate table.
