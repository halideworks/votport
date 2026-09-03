# Native push: VOT QUIC receive path

Status: Native push and its operator surface are implemented, 2026-08-29. VOT ADR-0045 (push, the holder dials)
landed upstream in PR #391 at `8789fc974e6ecc1237dcaed68c4e4bd9b6c77c34`.

## Overview

votport gains a second way in. Today every upload is a browser session:
vot-wasm hashes and proves in the tab, chunks travel as HTTP POSTs through
Caddy, and `session.rs` verifies each range and commits it. This design adds
a native path for senders that embed VOT (the CLI, a desktop app, a
server-to-server agent): the sender dials votport's UDP port, presents a
capability votport minted for that link and that package, and pushes the
bundle over VOT's own carrier. votport fetches it into staging with the VOT
wire engine, then hands the complete objects to the same commit, receipt,
dedupe, quota, and retention machinery the browser path uses.

The browser path does not change. The two paths share one session table, one
admission decision, one commit path, and one `UploadRecord` shape.

## Background & Motivation

### Current state (verified in code)

- The browser path still uses HTTP through Caddy. It admits sessions through
  the shared quota and session checks, verifies proven ranges, and publishes
  files with receipts.
- When `VOTPORT_PUSH_BIND` is set, votport also binds a QUIC/UDP listener,
  serves `/api/push-identity`, and accepts the capability returned by
  `POST /api/r/{token}/push`. The bind is off by default.
- Native push uses the same tenant/link quotas, session table, upload history,
  receipts, retention, and admin views as browser uploads. It stages and
  verifies the complete package before publication, so a failed native
  transfer does not publish partial destination files.
- The browser uses the link token plus optional password (argon2, throttled
  per /64) and a signed cookie. Native senders authenticate the HTTPS
  preflight with that link authorization, then present its scoped capability
  and holder proof over QUIC.
- `server/Cargo.toml` embeds VOT's wire engine behind the `wire` feature,
  including the live QUIC transport and the proof dependencies used by the
  native receive seams.

### What native push addresses

- Without native push, a CLI or desktop sender must drive the HTTP chunk
  protocol by hand and gets nothing from VOT's carrier: no multi-rail, no
  datagram FEC, no pacing, no resume below the 8 MiB chunk.
- The HTTP path verifies ranges serially in one worker thread per session
  (`handle_chunk`). The VOT fetch engine already parallelizes proof workers
  (`VOT_FETCH_PROVERS`) and rails (`VOT_FETCH_RAILS`).
- Server-to-server (VOTDock) needs an endpoint a process can authenticate
  to without a cookie jar.

## Goals & Non-Goals

### Goals

1. A sender that embeds VOT can push a package into a link with one HTTPS
   call and one VOT transfer, authenticated by a capability votport
   mints, and the result is indistinguishable in the admin UI, receipts,
   dedupe, quotas, retention, legal hold, and audit from a browser upload.
2. Admission happens once, before any byte moves, under the same
   `Sessions` lock the browser path uses, with the package length taken
   from the capability scope.
3. votport owns its UDP listener and certificate. Caddy is untouched.
4. The fetched bundle publishes through `NativeFile` and `ReceiptSigner`
   with no second commit path.
5. Tests: an e2e that pushes a bundle with the VOT library and asserts the
   same on-disk and store state the HTTP e2e asserts; policy tests for every
   refusal (bad capability, wrong root, over quota, expired ticket).

### Non-goals

- Browser over WebTransport. Separate design after ADR-0045 lands.
- Rendezvous, relay, or hole punching. votport is the fixed end; senders
  dial it. `VOT_RENDEZVOUS` settings on the sender are the sender's affair.
- Replacing the HTTP path or changing `CHUNK_BYTES`.
- A general API-token system for admin operations. The capability minted
  here is scoped to one link, one package root, one length, one window.
- ACME. The certificate is a file the operator provides or a self-signed
  one votport generates; senders pin the digest, which votport publishes.
- Packed entries. `handle_begin` refuses them today and the push path
  refuses them at the same place.

## Key Decisions

1. **The capability is the ticket.** ADR-0036's format, minted by votport's
   own issuer key, scoped to `(suite 1, package root, exact length)` with
   operation `PUBLISH` (the existing `0x0001`), audience
   `votport:<public_url>`, holder key supplied by the sender, validity equal
   to the session idle window. No new token format.
2. **Preflight over HTTPS, transfer over QUIC.** The sender calls
   `POST /api/r/{token}/push` with the link password, its holder public
   key, and the package root and length. votport admits the session there,
   mints the capability, and returns it with the UDP address and the
   certificate digest. The QUIC connection carries only VOT frames.
3. **One session table.** The push session is a row in `Sessions` with the
   same reserved bytes and delete pins. `SessionHandle` gains a `kind`
   field that `insert_admitted` (`session.rs:1061-1070`) sets from a new
   `SessionAdmission` field; `remove` and tenant delete pins work
   unchanged; `sweep` and abort call the cancellation handle for a push
   session instead of dropping or sending on the `Cmd` channel.
4. **Fetch into staging, then publish through `NativeFile` after package verification.**
   The VOT engine writes each object to
   `<dest_dir>/.vot-push-<sid>/objects/<root>` through its own `RangeSink`,
   root-verified on arrival. The engine consumes the `PROOF_BUNDLE`s and
   hands the sink bare bytes, and `VerifiedSlice` has no public constructor
   other than `verify_range`, so the worker cannot replay the wire proofs.
   On object completion it re-proves the staged file locally into an
   unpublished `NativeFile`: one
   streaming pass with `vot_proof_blake3::GroupCvs::push` per 64 KiB group
   and `seal`, then `prove_with(&cvs, offset, length)` per
   `RANGE_UNIT_BYTES`-aligned range of at most `MAX_PROOF_RANGE_BYTES`
   (4,259,840 bytes in the pinned VOT revision), each fed through
   `NativeFile::accept`. After all unique objects finish, it publishes every
   destination and writes sidecars. One hash pass
   per object and about 512 KiB of chaining-value state per GiB, next to a
   network transfer. `vot_proof_blake3::prove` is not used: it takes the
   whole object as one slice and rehashes it per range. `NativeFile::publish`,
   `write_sidecar`, and `FileRecord` are identical for both paths.
5. **The engine is embedded, not shelled.** `vot-cli` with the `wire`
   feature is a dependency; `receive_push_on(listener, policy)` from
   ADR-0045 item 9 takes a `Listener` votport binds at startup and
   votport's admission policy. The engine owns the accept loop. The policy
   runs per `SESSION_OPEN` and returns the grant with that session's
   `ReceiveSeams` (ADR-0045 item 8): manifest hook, sink factory with
   per-object skip, per-object completion, cancellation handle.

## Proposed Design

### 1. Listener and identity

- `VOTPORT_PUSH_BIND` (default unset, feature off). When set, `app::build`
  binds a `vot_transport_quiche::Listener` on that UDP address with
  `VOTPORT_PUSH_CERT` and `VOTPORT_PUSH_KEY` (PEM). If both are unset,
  votport generates a self-signed pair at first boot into
  `<data_dir>/push.crt` and `<data_dir>/push.key` with `auth::write_private`,
  the pattern `ReceiptSigner::load_or_create` uses, and logs the digest.
  When both are set, those certificate and key paths are used in place.
- `VOTPORT_PUSH_ADVERTISE` (default: host of `VOTPORT_PUBLIC_URL` plus the
  bind port) is what the preflight returns to senders. Docker publishes it
  as `<port>/udp`.
- The issuer key for capabilities is a second Ed25519 key,
  `<data_dir>/push-issuer.key`, generated the same way. It is not the
  receipt key; receipts are public attestations and the issuer key is an
  authorization secret.
- `GET /api/push-identity` (public, no cookies) returns
  `{"address", "certificate_digest", "issuer_public_key"}`. Senders pin the
  digest before connecting, the mirror of `VOT_FETCH_SERVE_IDENTITY`.

### 2. Preflight: `POST /api/r/{token}/push`

Request:

```json
{
  "password": "...",
  "holder_key": "<64 hex>",
  "package": { "suite": 1, "root": "<64 hex>", "length": 123456789,
               "entries": 3 }
}
```

The announced suite, root, and length are bound at admission. The announced
`entries` value is accepted for the request shape but is not an admission
check; the received manifest is checked later against `MAX_ENTRIES`.

- Runs the same checks as `create_session` in the same order: link usable,
  per-IP rate, password or link cookie, tenant resolve, `effective_cap`
  against `package.length`.
- Calls `Sessions::insert_admitted` with `reserved_bytes = package.length`
  and a `SessionAdmission` whose kind is `Push`. Over quota, over session
  caps, and pinned tenants fail here with the same status codes the browser
  path returns.
- Mints the capability: issuer votport, audience `votport:<public_url>`,
  holder `holder_key`, operations `[PUBLISH]`, scope
  `(1, root, length, [])`, not-before now, expiry now plus
  `VOTPORT_SESSION_IDLE_SECS`, fresh `id128`. Signs with the issuer key.
- Spawns the push worker and returns:

```json
{
  "session": "<sid>",
  "capability": "<base64 signed-capability>",
  "address": "drop.example.com:8322",
  "certificate_digest": "<64 hex>",
  "expires_at": 1724800000
}
```

- The sender then runs `vot push BUNDLE_DIR <address> CAPABILITY KEY` with
  `VOT_PUSH_IDENTITY=<certificate_digest>`, or the library equivalent.

### 3. Accepting the connection

- `app::build` calls `receive_push_on(listener, policy)` on its own thread;
  the engine owns the accept loop. The policy is votport's: verify the
  capability against the issuer key, check audience and validity, look up
  `id128` in a `push_tickets` map keyed to the session id, and refuse if
  unknown, expired, cancelled, or the session is gone. The first accepted
  `SESSION_OPEN` builds that transfer's `ReceiveSeams`; concurrent VOT rails
  presenting the same capability join those seams. Completion removes the
  ticket, so a later replay is refused. The cancellation handle is shared
  with the `SessionHandle`.
- The grant binds the session to the scope root and length. When
  `PACKAGE_DESCRIPTOR` arrives, the engine compares; a mismatch ends the
  session and the worker records an `interrupted` event exactly as the
  HTTP worker does on channel close.
- Connection rate: the listener runs QUIC stateless retry (ADR-0045 item
  9 adds it to `Listener`; the carrier today creates connection state for
  any source), so a source address is validated before any connection
  state exists and before votport counts anything. Counting uses a separate
  small limiter keyed by
  validated peer address, not `app.session_rate`: that table is the
  per-sender upload quota for HTTP, capped at 4096 buckets with eviction
  (`server/src/api/session_rate.rs:16,40-58`), and feeding it unvalidated
  UDP sources would let an off-path spoofer evict browser senders' buckets.
  The capability check is the first application frame after `AUTH_CONTEXT`,
  so a flood is bounded by retry cost, the limiter, and the `MAX_SESSIONS`
  table, not by disk.
- Push sessions count against `MAX_SESSIONS` and `MAX_SESSIONS_PER_LINK`
  from preflight, so a sender that preflights and never dials holds a slot
  until the idle sweep, the same as a browser that creates a session and
  closes the tab. `last_active` is written only by `touch` and the lease
  drop (`session.rs:1126`, `:821`), which a push session never calls, and
  `sweep` evicts on `last_active` alone when `in_flight` is zero
  (`session.rs:1158-1174`). The sink votport hands the engine wraps
  `FileSink` and stamps `last_active` through `Sessions::mark_active(sid)`
  from `write_at`, throttled to once a second, so a single large object
  keeps refreshing it and only a stalled transfer is swept.

### 4. Push worker

`SessionHandle` (`session.rs:795`) gains a `kind` field, `Http` or
`Push { cancel }`; `Phase` is the HTTP worker's private state and a push
session has none. The engine drives the session and calls votport through
the seams:

1. There is no per-session worker thread driving the engine; the engine
   drives the session and calls votport through the seams. votport's
   per-session state (`files`, the dedupe index, the staging root
   `<dest_dir>/.vot-push-<sid>/`) lives in the `ReceiveSeams` closures,
   `tighten_dir` applied to every directory they create (umask 022 is
   already pinned in `app::build`).
2. The manifest hook runs the entry validation `handle_page` and
   `handle_begin` run today, before any range is requested: entry count
   against `MAX_ENTRIES` (`session.rs:327`), packed entries refused,
   `paths::admit_component` per path component (`session.rs:371`), and the
   dedupe index over prior uploads. A refusal ends the session with
   `ADMISSION_DENIED` and no byte transferred, matching the HTTP path.
3. The sink factory answers per object: an entry the dedupe index already
   has with its stored file intact returns the skip decision, so the engine
   issues no `RANGE_REQUEST` for that object; this is the `find_delivered`
   outcome of the browser path (`session.rs:469-507`) at the same point in
   the flow. Otherwise it returns a `FileSink` under the staging root.
   `HAVE` is not involved: it carries verified 64 KiB group coverage within
   one object (`spec/object.md` section 10), not a package-level skip, and
   has no implementation outside the codec.
4. Each object's completion callback creates its `NativeFile` destinations
   and runs the local re-prove loop of Key Decision 4 (`GroupCvs`,
   `prove_with` per aligned range, `verify_range`, `accept`). Publication is
   deferred until every unique object has completed, so aborting or rejecting
   a later object cannot leave a partial package in the destination.
5. On the last unique object, cancellation is checked before publication and
   again before recording. The worker publishes every `NativeFile`, writes
   sidecars, and runs the record-building half of `handle_finish`
   (`session.rs:642-692`) runs. Today that function destructures
   `Phase::Receiving { files }` and takes the chunk `replays` and `rejected`
   counters (`session.rs:645-650`); the `UploadRecord` construction and
   `store.append_upload` call are extracted into a function both phases
   call, with the counters zero for a push. The `upload_completed` audit
   row, `notify::uploaded`, and `Sessions::remove` run today in the axum
   handler `upload_finish` (`upload.rs:530-572`) after `dispatch` returns;
   for a push they run from the completion path on the engine's thread,
   which has no tokio context, so `App` keeps a `tokio::runtime::Handle`
   for the notify spawn. Audit rows are written the same way for both
   paths. A process-wide publication namespace lock spans
   `NativeFile::publish`, sidecar publication, guard capture, and rollback.
   Same-filesystem hard links guard the identity of newly published files and
   sidecars until `store.append_upload` succeeds; rollback opens one guard at
   a time and removes only that exact destination, keeping file descriptor use
   constant even at the entry cap.
   The pinned VOT revision has no public whole-session terminal callback.
   Therefore the last unique per-object completion commits the record; a
   later transport-level workspace sync or acknowledgement failure cannot
   revoke an already published upload.
6. On any failure, cancel unpublished `NativeFile`s, roll back guarded final
   files, and remove
   `.vot-push-<sid>/`, record the event, `Sessions::remove`.
   `paths::clean_staging` at boot also removes only the generated
   `.vot-push-<32 lowercase hex>` shape.
7. Abort and the `Cmd` routes. Nothing consumes a push session's `Cmd`
   channel, and `dispatch` awaits a oneshot with no timeout
   (`upload.rs:415-434`), so every HTTP session route (`seal`, `page`,
   `begin`, `chunk`, `finish`, `abort`) would hang on a push session id.
   The guard goes in `Sessions::touch` (`session.rs:1121`), the one place
   all six routes obtain a `SessionCommand`. `touch` returns
   `Option<SessionCommand>` and `dispatch` maps `None` to 404
   (`upload.rs:421-423`), so it becomes `Result<SessionCommand,
   TouchError>` with `NotFound` and `WrongKind`, and `dispatch` maps
   `WrongKind` to 409. `upload_abort` handles a push session before
   `dispatch`: `Sessions::cancel_push(sid)` clones the cancellation handle
   out of `SessionHandle::kind` and triggers it. The engine sends `GOAWAY`,
   the fetch loop returns, and step 6 runs. `Sessions::sweep` does the same
   on idle eviction, since dropping the `mpsc::Sender` does not interrupt
   the engine.

### 5. Engine dependency

- `server/Cargo.toml` adds `vot-cli = { git, rev, default-features = false,
  features = ["wire"] }`, `vot-transport-quiche` for `Listener`,
  `vot-capability` for minting, `vot-scheduler` for the `RangeSink` and
  `FileSink` types the seams are typed on (`vot-cli` re-exports neither),
  and `vot-proof-blake3` for the re-prove (`vot-sdk` does not re-export a
  range prover; `vot_sdk::proof` is the catalog encoder). Package entries
  may use either suite 1 (BLAKE3) or suite 2 (SHA-256), so the same loop uses
  `vot-proof-sha256` for suite 2. The
  Dockerfile build stage gains `cmake` and `clang` for BoringSSL. CI's
  server job builds it once; the cache key already hashes `Cargo.lock`.
- The pin moves in one PR with the ADR-0045 implementation upstream, the
  same six sites as any repin.
- Sender-side knobs (`VOT_FETCH_RAILS`, `VOT_DATAGRAM_FEC`, `VOT_INITIAL_CWND`,
  `VOT_PREFIX_DUP`) are the sender's. Receiver-side, VOT b14 supplies the
  `VOT_FETCH_PROVERS` default; votport does not set or re-expose it. The
  remaining receiver settings stay at VOT defaults until a measurement asks.

## API / Interface Changes

New, all under the existing link authorization:

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/push-identity` | none | address, certificate digest, issuer key, and `serve_address` when Deliver over QUIC is bound |
| `POST` | `/api/r/{token}/push` | link password or cookie | admit, mint capability, start session |
| `POST` | `/api/session/{sid}/abort` | existing | for a push session, triggers the engine cancellation handle |

`GET /api/r/{token}` gains `"push": true` when `VOTPORT_PUSH_BIND` is set so a
CLI can discover the path before asking for a password.

The stored `UploadRecord` carries `transport: "push"`; new browser uploads
record `"http"`. The operator surface exposes it through `list_links` and
upload history.
There is no schema bump: `UploadRecord` is JSON in `links.uploads_json`, and
an absent value on an older record means `"http"`.

## Data Model Changes

- `UploadRecord.transport: Option<String>` (`Some("http")` or `Some("push")`
  for new records; serde default `None`, read as `http`, for legacy rows). No
  migration.
- In-memory `push_tickets: Mutex<HashMap<[u8; 16], PushTicket>>` on `App`,
  swept with sessions. Not persisted: a restart invalidates in-flight
  pushes the same way it invalidates HTTP sessions today.
- `push-issuer.key` is always under `data_dir`. `push.key` and `push.crt` are
  generated there unless the operator supplies certificate and key paths,
  which are used in place.

## Alternatives Considered

### 1. votport fetches from a serving sender

Works today with no upstream change, but every sender must be reachable or
punch through a rendezvous votport would have to run. ADR-0045's context
section is the argument; the receive portal is the fixed end and should be
the one that listens.

### 2. Shell out to the `vot` binary

No cmake in votport's build, and the binary would own the socket and the
certificate. But the admission decision and the capability check would
have to be expressed as files and exit codes, and a failed session could
not be tied to a `SessionHandle` under the same lock. The library seam
ADR-0045 specifies is the smaller change.

### 3. A new ticket format instead of VOT capabilities

A signed JSON ticket would be simpler to mint. It would also be a second
authorization format on a wire that already has one with proof of
possession, scope, audience, and expiry, and `vot-session` already routes
it to policy. Reusing it costs a dependency on `vot-capability` and saves a
parser, a signature scheme, and a spec section.

### 4. Publish straight from the engine's `FileSink`

The engine could write final files in place. That bypasses `NativeFile`'s
same-directory staging and journal, `publish_observation`, and the
receipt's incarnation and sequence. The extra copy from `.vot-push-<sid>/`
to the destination is a rename on the same filesystem; the design keeps
the commit contract instead of the copy.

### 5. Terminate QUIC in Caddy

Caddy's `reverse_proxy` speaks TCP to backends and cannot forward a raw
QUIC connection with VOT's ALPN. The `layer4` plugin can forward UDP
datagrams, which would let Caddy own the port but not the TLS identity,
since the QUIC handshake is end to end. It is an option for operators who
want one public port, and changes nothing in votport.

## Security & Privacy Considerations

- The capability is single use, scoped to one root and length, bound to a
  holder key the sender proves possession of, and expires with the session.
  Concurrent rails may join one live transfer. Replay after completion and
  ticket removal is refused; expiry is refused by the validity window.
- The link password is presented once, over HTTPS, at preflight. It never
  crosses the QUIC connection.
- The QUIC listener accepts any handshake; authorization is the first
  application frame. Handshake cost per validated address is the exposure,
  bounded by stateless retry, the push limiter, and `MAX_SESSIONS` for
  anything that gets as far as a session row.
- The issuer key never leaves `data_dir`. The certificate digest is public
  by design.
- Root and length in the capability are what the sender claimed at
  preflight. Admission reserves that length; the manifest must match both
  exactly or it is refused before any range is requested.
- Staged bytes under `.vot-push-<sid>/` are root-verified on arrival by the
  engine and re-verified before `NativeFile::accept`; nothing unverified
  reaches a destination path.

## Observability

- Events: `push_admitted`, `push_connected`, and `push_refused` with a bounded
  reason (`rate`, `capability`, `expired`, or `spent`), plus the existing
  `uploaded`, `cancelled`, and `interrupted`
  lifecycle events. A package root mismatch is recorded as an interrupted
  push rather than a `push_refused` reason: VOT b14 checks the package pin
  before calling votport's manifest hook and exposes no terminal reason hook.
- Metrics: `votport_push_sessions_active`, `votport_push_bytes_total`,
  `votport_push_refused_total{reason}`.
- `VOT_FETCH_STATS` is for VOT's fetch path only, not a native push sender
  setting. The b14 receiver has no whole-session terminal statistics callback,
  so votport does not claim to emit that setting's fetch-statistics line; use
  the metrics and audit events above for receiver-side observability.
- Link cards show transport and the same duration and rate telemetry the
  HTTP path records.

## Rollout Plan

1. Keep `VOTPORT_PUSH_BIND` unset unless native push is needed.
2. When enabling it, choose a reachable UDP port, set a numeric
   `VOTPORT_PUSH_ADVERTISE` for the b14 CLI, map the UDP port, open the
   firewall, and verify `/api/push-identity`.
3. Pin the returned certificate digest, perform the HTTPS preflight, decode
   its capability into the VOT CLI's capability file, and run `vot push`.
   Library senders may resolve DNS before dialing.

## Upstream limitations

- Cloudflare in front of VOTDock: raw QUIC needs Spectrum UDP or a direct
  address. Decide before VOTDock's topology is fixed.
- VOT `d3c18a4` parses the CLI push address as a numeric `SocketAddr`. DNS
  resolution remains the library caller's responsibility until upstream adds
  hostname resolution to the CLI.

## Risks

| Severity | Risk | Mitigation |
|---|---|---|
| High | BoringSSL build in the image and CI adds minutes and a toolchain | Build once per lock change; the docker job already runs vot-wasm from source. Measure the first CI run and record it. |
| High | A second commit path drifts from the first | There is no second path: publication is `NativeFile` plus `write_sidecar` for both. Test asserts `FileRecord` equality between an HTTP and a push upload of the same package. |
| Medium | UDP port exposed to unauthenticated handshakes | Stateless retry before any state, a separate limiter on validated addresses, capability before any session row, `MAX_SESSIONS` ceiling. |
| Medium | Self-signed certificate digest changes on data loss | Digest is published and pinned per transfer at preflight, so a rotation invalidates only sessions started before it. |
| Low | `.vot-push-*` staging orphaned by a crash | `clean_staging` at boot sweeps the prefix. |

## References

- VOT ADR-0045 push, the holder dials (this design's prerequisite)
- VOT ADR-0030 serve and fetch, ADR-0036 who may fetch a package,
  ADR-0037 the proof binds to the channel, ADR-0041 the server answers HELLO
- `server/src/session.rs`, `server/src/api/upload.rs`, `server/src/receipt.rs`,
  `server/src/paths.rs`
- `docs/sender-identity.md` for the receipt and object-card contract this
  path must satisfy

## PR Plan

### PR 1: Push identity and listener (feature off)

- `config.rs`: `VOTPORT_PUSH_BIND`, `VOTPORT_PUSH_CERT`, `VOTPORT_PUSH_KEY`,
  `VOTPORT_PUSH_ADVERTISE`.
- `app.rs`: bind `Listener` when set; issuer and certificate key files;
  `GET /api/push-identity`.
- `Cargo.toml`: `vot-cli` with `wire` and `rcgen`; the worker's direct
  capability, scheduler, proof, and transport dependencies wait for PR 3.
  Dockerfile: cmake, clang.
- Tests: identity endpoint, key generation idempotent across restarts,
  digest stable.

### PR 2: Preflight and admission

- `api/upload.rs`: `POST /api/r/{token}/push`; `SessionAdmission::kind`;
  `push_tickets` on `App`.
- `session.rs`: `SessionHandle::kind`, `Sessions::touch` guard for the HTTP
  routes, idle timeout like any session.
- Tests: every refusal path returns the browser path's status; quota is
  reserved and released; capability verifies under the issuer key and
  fails under another.

### PR 3: Accept loop and push worker

- `session.rs`: `ReceiveSeams` construction, manifest hook validation,
  sink factory with dedupe skip, per-object re-prove and publish,
  cancellation on abort and sweep, `handle_finish` record-building split.
- `paths.rs`: `.vot-push-*` in `clean_staging`.
- `store.rs`: `UploadRecord.transport`.
- Tests: e2e push of a multi-file package with the VOT library against a
  `TestServer` that also binds a push listener; on-disk and store state
  equal to the HTTP e2e; root mismatch, spent capability, and mid-transfer
  abort leave no partial destination file; throughput benchmark variant
  `throughput_push` beside `throughput_baseline`.

### PR 4: Operator surface (implemented)

- Link cards and upload history show transport; metrics; events; docs
  (`deployment.md` port and certificate, `README.md` sender section).
