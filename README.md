# votport

A small, self-hosted **file transfer portal** built on
[VOT (Verified Object Transfer)](https://github.com/halideworks/VOT).

You sign in to the admin UI (`/receive`, `/deliver`, `/tenants`, `/audit`,
`/system`), create
a unique request link (with an optional password), and send it to someone. They
open it in a browser, drop files on the page, and the files land, cryptographically
verified, atomically published, never overwriting anything, in a folder you
chose on your server.

```
you (admin)                    them (any modern browser)
    │                                   │
    │  create request link              │
    │  https://drop.example/r/9f2c…     │
    ├──────────── send link ───────────▶│
    │                                   │  vot-wasm hashes the files locally,
    │                                   │  builds a VOT package (manifest+seal),
    │                                   │  streams up to eight proven 8 MiB ranges
    │                                   ▼
    │                       votport server (this repo)
    │                       verifies every range against the announced
    │                       package root before a byte is accepted;
    │                       publishes atomically via vot-sdk-file
    ▼
/your/folder/…      ← files appear here, listed in the admin UI
```

Received files use **Send** beside a file on **Receive**. For the outbound
library, use **Deliver** to choose one or more files. Server-rendered projects
may populate nested project subdirectories under the outbound directory, and
admin uploads land there too. VOTPort issues one expiring bearer URL for the
selection, shown once and revocable by an admin.
Before an individual file download starts, the server verifies the source's
VOT object identity and signed receipt against a cached proof catalog (built
once per object), then streams verified ranges directly from the source. ZIP
and grouped batch downloads copy each source into private staging and verify
it per request. Individual files support RFC 9110 single-byte-range requests for
resumable downloads; each logical file download is counted once and a short-lived
secure lease permits subsequent ranges. For multi-file deliveries, recipients may download a payload-only
ZIP or stream the files separately in bulk; signed receipts remain optional
individual downloads. Optional link passwords gate metadata, files, receipts,
and the ZIP.

## Why VOT instead of a plain upload form?

* **End-to-end integrity.** The browser computes each file's VOT object
  identity (BLAKE3 merkle root) and a package manifest before anything is
  sent. The server accepts a byte range only with a valid proof against the
  announced root — a flipped bit in transit, a truncated body, or a buggy
  proxy is refused, not stored.
* **Authenticated names.** File names arrive inside the sealed manifest, so
  the listing you see is the listing that was hashed.
* **Atomic, no-overwrite publication.** Files are staged and published by
  `vot-sdk-file`: a file either appears complete and verified, or not at
  all. Existing files are never overwritten — repeats get `name-1.ext`.
* **Interrupted uploads leave nothing behind.** Abandoned sessions are swept
  and their staging files removed.

## Quick start (Docker + Caddy)

Requirements: Docker with the compose plugin, and Caddy on the host.

```sh
git clone https://github.com/halideworks/votport
cd votport
# edit docker-compose.yml:
#   - set VOTPORT_ADMIN_PASSWORD
#   - set VOTPORT_PUBLIC_URL to the https URL Caddy will serve
#   - point the /received volume at the folder that should receive files
#   - point the /outbound volume at the folder for outbound library files
docker compose up -d --build
```

The first build takes a while: it compiles the VOT SDK to WebAssembly for the
browser and builds the server. Then add the site to your Caddyfile (see
[`Caddyfile.example`](Caddyfile.example)):

```caddy
drop.example.com {
 reverse_proxy 127.0.0.1:8321
}
```

Reload Caddy, open `https://drop.example.com`, sign in with your admin
password, create a link, and send it to someone.

Default-tenant files appear under the host folder mounted at `/received`.
Named tenants use `/received/.vot-tenants.stage/<tenant>/`; per-link
subfolders are configurable when you create a link.

### Released images

The release workflow publishes semver tags and commit tags to GHCR, never
`latest`. Pin a customer deployment to the digest recorded in the GitHub
release notes and workflow summary:

```yaml
services:
  votport:
    image: ghcr.io/halideworks/votport:vX.Y.Z@sha256:<published-digest>
    # remove build: .
```

Keep the complete image reference, including its digest, with the matching
database and `/received` and `/outbound` backup set. System-page automatic
archives cover the database and VOTPort-managed identity files only; the two
content volumes still need operator-owned file backups.

## Configuration

Environment variables are the boot defaults (see `docker-compose.yml`). A
default-tenant admin can overlay notify channels, retention, and default
quotas from **System** without SSH (`GET`/`PUT /api/admin/settings`). The same
page configures automatic local and S3-compatible backups, reports redacted
status, and stages restores for the service supervisor. Backup archives include
the database and VOTPort-managed identity files only; a blank local path uses
`<data_dir>/backups` (normally `/data/backups`), while a custom path must be a
writable service-filesystem path mounted by the operator. S3 prefix settings
cover VOTPort backup objects only, and `/received` and `/outbound` remain
operator backups.
Optional backup secrets are unchanged when left blank and never returned by
GET. A restore rotates the cookie secret and signs out existing sessions. A
written settings key wins; `""` disables a URL or token; JSON `null` deletes
the row so env applies again. Details: [`docs/deployment.md`](docs/deployment.md).

| Variable | Default | Meaning |
| --- | --- | --- |
| `VOTPORT_ADMIN_PASSWORD` | — | Admin password (hashed with argon2id at startup). Required unless the hash is set. At least 12 characters; a shorter one refuses to start, because this is the credential that still works when the identity provider does not. |
| `VOTPORT_ADMIN_PASSWORD_HASH` | — | Argon2 PHC string; takes precedence over the plain password. |
| `VOTPORT_PUBLIC_URL` | — | Public https URL; used for generated links and to mark cookies `Secure`. |
| `VOTPORT_BIND` | `0.0.0.0:8080` | Listen address inside the container. |
| `VOTPORT_PUSH_BIND` | off | UDP address for native VOT pushes. Setting it enables the listener; leave unset to keep native push disabled. |
| `VOTPORT_PUSH_ADVERTISE` | derived | `host:port` that native senders dial. Defaults to the host in `VOTPORT_PUBLIC_URL` and the push bind port. Set it when the public UDP address differs. |
| `VOTPORT_SERVE_BIND` | unset | UDP address for serving Deliver grants to VOT clients over QUIC; off when unset. Same certificate and issuer key as push. |
| `VOTPORT_SERVE_ADVERTISE` | derived | `host:port` that VOT fetch clients dial, on the same rules as `VOTPORT_PUSH_ADVERTISE`. |
| `VOTPORT_PUSH_CERT` / `VOTPORT_PUSH_KEY` | generated | PEM certificate and private key for native push. Set both together to use those paths in place, or leave both unset for a persistent self-signed pair under `VOTPORT_DATA_DIR`. |
| `VOTPORT_DATA_DIR` | `/data` | State: `votport.db` (links, upload records; legacy `state.json` is imported once) and the cookie secret. |
| `VOTPORT_RECEIVE_DIR` | `/received` | Root folder received files are published into. |
| `VOTPORT_OUTBOUND_DIR` | `/outbound` | Root folder for server-rendered projects and files uploaded by admins for outbound links. Nested project subdirectories are allowed. |
| `VOTPORT_MAX_UPLOAD_BYTES` | 50 GiB | Hard cap per upload session (per-link caps can be lower). Accepts plain bytes or a `K/KiB/KB`, `M/MiB/MB`, `G/GiB/GB`, `T/TiB/TB` suffix, e.g. `500G`. |
| `VOTPORT_ALLOW_HIDDEN` | off | Set `1` to accept dot-file names from uploaders. |
| `VOTPORT_SESSION_IDLE_SECS` | `1800` | Idle time before an unfinished upload session is discarded. |
| `VOTPORT_WEB_ROOT` | `./web` | Static assets directory (`/app/web` in Docker). |
| `VOTPORT_NOTIFY_WEBHOOK_URL` | — | POSTed a JSON summary (`event`, `label`, `upload_id`, `total_bytes`, `files`) when an upload completes. |
| `VOTPORT_NOTIFY_NTFY_URL` | — | Full ntfy topic URL (e.g. `https://ntfy.sh/mytopic`) sent a message per completed upload. |
| `VOTPORT_NOTIFY_NTFY_TOKEN` | — | Bearer token for the ntfy topic, if it needs one. |
| `VOTPORT_NOTIFY_PUSHOVER_TOKEN` | — | Pushover application token (set together with the user key). |
| `VOTPORT_NOTIFY_PUSHOVER_USER` | — | Pushover application token (set together with the user key). |
| `VOTPORT_NOTIFY_SMTP_HOST` | — | SMTP host. The channel is inert unless host, from, and at least one `to` all resolve. |
| `VOTPORT_NOTIFY_SMTP_PORT` | `587` | SMTP port. Port 465 uses implicit TLS. |
| `VOTPORT_NOTIFY_SMTP_STARTTLS` | on | SMTP STARTTLS. Off only when `0`. Port 465 uses implicit TLS regardless. |
| `VOTPORT_NOTIFY_SMTP_USERNAME` | — | Optional SMTP AUTH username. |
| `VOTPORT_NOTIFY_SMTP_PASSWORD` | — | Optional SMTP AUTH password. |
| `VOTPORT_NOTIFY_SMTP_FROM` | — | SMTP From address (required with host and `to`). |
| `VOTPORT_NOTIFY_SMTP_TO` | — | Comma-separated SMTP recipients (at least one required with host and from). |
| `VOTPORT_AUDIT_RETENTION_DAYS` | `400` | Days to keep queryable audit rows; `0` disables pruning. Overridable via `PUT /api/admin/settings`. |
| `VOTPORT_UPLOAD_RETENTION_DAYS` | off | Days to keep received files and their records; a daily sweep deletes expired content and audits it. `0` (default) keeps everything. Overridable via `PUT /api/admin/settings`. |
| `VOTPORT_DEFAULT_MAX_TOTAL_BYTES` | unlimited | Fills a new tenant's byte quota when the request omits it, and caps received bytes on the unnamed default tenant. Named tenants keep the quota on their row. |
| `VOTPORT_DEFAULT_MAX_LINKS` | unlimited | Same overlay for max links (new tenants when omitted, and the unnamed default tenant). |
| `VOTPORT_DEFAULT_MAX_SESSIONS` | unlimited | Same overlay for max concurrent sessions. |
| `VOTPORT_PUBLIC_PASSWORD_LOGIN` | on | Set `0` to prefer collapsing the local password form when SSO is offered (login API stays available). |
| `VOTPORT_METRICS_TOKEN` | — | When set, `GET /metrics` requires this bearer token. Counts only; scrape over an internal interface. |
| `VOTPORT_TRUSTED_PROXIES` | loopback + private ranges | Comma-separated CIDR blocks (or bare addresses) whose `X-Forwarded-For` is believed. Anything else is keyed on its socket address. The default trusts any loopback or RFC1918/ULA peer, which is broad: on a shared container network or a LAN bind, anything that can reach the port can pick its own throttle bucket. Name your reverse proxy to close that; see [Client addresses](docs/deployment.md#client-addresses). |
| `VOTPORT_OIDC_ISSUER` | — | OIDC issuer URL for admin single sign-on. Requires the client id/secret and `VOTPORT_PUBLIC_URL`; see [Single sign-on](#single-sign-on). |
| `VOTPORT_OIDC_CLIENT_ID` | — | OAuth client id at the identity provider. |
| `VOTPORT_OIDC_CLIENT_SECRET` | — | OAuth client secret at the identity provider. |
| `VOTPORT_OIDC_ADMIN_GROUP` | — | Group whose members sign in as admins. Unset means every principal your provider authenticates gets admin. |

Notifications are best-effort: a delivery failure is logged and never affects
the upload.

Production setup beyond the quick start - SSO walkthroughs (Authentik,
Entra ID), backups and restore, metrics scraping, tenant provisioning, and
content lifecycle - lives in [`docs/deployment.md`](docs/deployment.md).

## Single sign-on

Set `VOTPORT_OIDC_ISSUER`, `VOTPORT_OIDC_CLIENT_ID` and
`VOTPORT_OIDC_CLIENT_SECRET` (plus `VOTPORT_PUBLIC_URL`, which builds the
redirect URI `<public-url>/api/admin/callback`) and the login page gains a
**Sign in with SSO** button alongside the local password form. The flow is
authorization-code with PKCE; the id token is verified against the provider's
JWKS, with issuer, audience and nonce checks.

Roles come from the provider's `groups` claim: members of
`VOTPORT_OIDC_ADMIN_GROUP` sign in as administrators, everyone else as
viewers with read-only dashboard access. When the group is unset, every
principal your provider authenticates is an administrator — votport warns
loudly at startup.

Local password sign-in always remains available as the break-glass path,
including when SSO is configured. `POST /api/admin/login` is never disabled.
System can collapse the password form behind a disclosure when SSO is offered;
the form stays in the page. SSO principals appear on `/tenants` and can be
revoked (current sessions die; further SSO is refused until unblock). Lasting
revoke is removing the IdP group.

## Audit trail

Every administrative and transfer event — sign-ins (with client IP),
link lifecycle, received-file deletions, upload completions and failures — is
written both to the structured log (`RUSTLOG=audit=info`) and to an
append-only table in the database. Export it as JSONL for a SIEM:

```sh
curl -b cookies.txt 'https://drop.example.com/api/admin/audit?since=0&limit=1000'
```

Rows are never modified or deleted through the API; retention prunes them
after `VOTPORT_AUDIT_RETENTION_DAYS` (default 400).

Platform admins can read current link and live-byte totals for every tenant at
`GET /api/admin/holdings`. Quota checks, holdings, and `/metrics` use the
schema-v7 SQL file projection rather than loading upload-history JSON.

## Receipts

Every published file gets a sidecar, `<name>.vot-receipt`: a canonical
[vot-receipt](https://github.com/halideworks/VOT) CBOR envelope, ed25519-signed
with a key votport generates in the data directory (`receipt.key`), attesting
that exactly that object (suite, BLAKE3 root, length) reached **Published**
assurance under the Balanced commit profile, with the session, provider
incarnation, sequence, and UTC timestamp of the observation. The verifying
public key is shown on **System** (and returned by `GET /api/admin/links` as
`receipt_key`); the receipt's embedded key id is the same 32-byte public key.
Anyone can check a sidecar without an account: open `/verify`, drop the file
and its sidecar (the file is hashed in your browser and never uploaded), or
post the sidecar bytes to `POST /api/verify` after fetching the key from
`GET /api/receipt-key`. Programmatically, verify with the `vot-receipt`
crate: `decode_authenticated(bytes)` then `verify_ed25519(&decoded, &key)`.

## Security model

* Request links are unguessable 128-bit URLs; add a per-link password for a
  second factor (argon2id-hashed, verified before any upload state exists).
* The admin session is a signed, expiring cookie (`HttpOnly`, `SameSite=Lax`,
  `Secure` behind https); mutating admin calls also require a custom header,
  which closes cross-site request forgery.
* Password guessing is throttled per client bucket, and each password path
  holds its own small budget of concurrent argon2 verifications. Nothing
  refuses a correct password, so no one can lock the administrator out of the
  break-glass credential. A sustained flood can still make sign-in wait behind
  the queue for that budget; the wait is bounded by the queue and ends with
  the flood, and rate limiting at the reverse proxy is the answer to it.
  Guessing buckets group an IPv6 client by
  /64, since a client holding a routed prefix would otherwise get a fresh
  budget per address; the cost is that neighbours in one prefix share a
  lockout. Upload-session creation and receipt checks are quotas rather than
  guessing throttles, so they key on the full address and colleagues in one
  office do not share a budget.
* Optional SSO sign-in maps your identity provider's groups to admin or
  read-only viewer access; session cookies bind the role and are invalidated
  by password changes or role changes. Platform admins can revoke an SSO
  principal from `/tenants`.
* Uploaded names pass VOT's portable-path profile (no traversal, no control
  characters, no Windows-reserved names) **and** a server-side re-check; files
  cannot land outside the receive folder.
* Per-link expiry, per-link size caps, a global session cap, and bounded
  request bodies keep resource use predictable.
* votport itself speaks plain HTTP and expects to sit behind Caddy (or any
  TLS-terminating proxy) — don't expose the container port publicly.

Threat-model honesty: TLS (Caddy) protects confidentiality in transit. VOT
adds integrity — what lands on disk is exactly what the sender's browser
hashed, verified range by range, independent of every proxy in between.

## Admin flow

1. Open the site, sign in (password and, if configured, SSO).
2. **Receive:** issue a request (label, optional destination, password, expiry,
   size cap). Enable its optional notification policy to be notified when a
   receive completes or fails. Copy the URL or show a QR code.
3. When files arrive, **Receive** lists uploads as object cards: stored path,
   size, and a click-to-copy identity line (`suite:64-hex root`) per file,
   plus whether the file is still on disk and whether its receipt sidecar
   was written. Delete a file (and its receipt) or clear a
   transfer from history. Deactivate or delete links when done (files stay
   until you delete them or retention sweeps them).
4. **Deliver:** browse nested project directories and admin-uploaded files,
   select one or more files and issue one expiring, revocable download link,
   or share a project folder directly and issue one expiring, revocable
   download link. Manual mixed selection is limited to 64 files; direct folder
   shares can include up to 50,000 files.
   Delivery links have an optional notification policy for the first download
   and completed delivery. Issued links show aggregate and per-file download
   starts with first and most recent timestamps. For multi-file links,
   `max_downloads` applies per file and per full-delivery round.
5. **Tenants** (platform admin): namespaces, quotas, principals, revoke.
6. **Audit:** queryable event log and JSONL export.
7. **System:** password, automatic backup configuration/status/restore,
   database snapshot download, receipt public key, notify/SMTP, retention,
   default quotas.

Senders can drop folders as well as files; browser support requires
WebAssembly SIMD and module workers (Safari 16.4, Chrome 91, Firefox 114 or
newer).

### Automation shares

Create a tenant-scoped automation token on **Deliver**. The raw token is shown
once, so copy it immediately; revoke it and create another if it is lost.
Use the token to share a server-relative outbound directory from the CLI (up
to 50,000 files per share):

```sh
export VOTPORT_URL=https://drop.example.com
export VOTPORT_AUTOMATION_TOKEN='<token from Deliver>'
# Optional password for the outbound link:
export VOTPORT_SHARE_PASSWORD='use-a-separate-secret'
votport share project/render --expires 7d --label "Client delivery" --max-downloads 1
```

The command prints the expiring share URL. `VOTPORT_URL` must be the HTTPS
server URL (HTTP is allowed for loopback); `VOTPORT_SHARE_PASSWORD` is optional.
`--max-downloads` is optional. For a multi-file delivery it applies per file
and per full-delivery round; `1` allows one download of each file or one full
delivery.

## Performance

The wire unit is an 8 MiB proven range (`CHUNK_BYTES` in `session.rs`). That
ceiling is protocol-level in VOT, not a votport knob. The browser keeps up to
eight range PUTs in flight and hashes ahead in module workers. The server
worker verifies ranges serially against the announced merkle root, then
publishes each file the moment its coverage is complete.

That serial verify is what leaves headroom on a fast NIC. Raising the range
size or verifying in parallel needs VOT changes on the server verify path;
the VOT pin at `5e287be` does not include them. Do not raise `CHUNK_BYTES`
in votport ahead of that work.

Measure on this box:

```sh
cargo test --test e2e -- --ignored --nocapture throughput_baseline
```

Latest run (2026-08-23, this host, 256 MiB single file): hashing and
packaging 3012 MiB/s, loopback upload 1203 MiB/s.

SQLite is one writer. That is the scale story. Litestream is the documented
database RPO; `/received` and `/outbound` are file backups. See [`docs/deployment.md`](docs/deployment.md).

## Development

Browser tooling requires Node.js 20.19+, 22.13+, or 24+.

```sh
# server (needs Rust ≥ 1.97)
(cd server && cargo test) # unit + full-protocol integration tests
(cd server && cargo run)  # needs VOTPORT_ADMIN_PASSWORD, VOTPORT_DATA_DIR, etc.

# browser JS
npm ci
for f in web/assets/*.js; do node --check "$f"; done
npm run lint
npm test

# browser wasm bundle (needs wasm32 target + wasm-bindgen-cli 0.2.126)
scripts/build-wasm.sh /path/to/VOT-checkout
```

The server pins `vot-sdk` / `vot-sdk-file` to an exact VOT commit in
`server/Cargo.toml`; the Dockerfile builds `vot-wasm` from the same commit so
browser and server always agree on the wire artifacts.

### Layout

```
server/   axum server: admin API, upload protocol, VOT verify + publish
web/      static frontend: admin pages and the uploader (vot-wasm in browser)
scripts/  wasm build helper, login-disclosure tests
docs/     deployment, multi-tenancy design, enterprise-ops
```

### Upload protocol (what the browser does)

```
POST /api/r/{link}/session     announce package root (+ link password)
POST /api/session/{s}/seal     manifest seal bytes
POST /api/session/{s}/page     manifest pages, in order
POST /api/session/{s}/begin    server verifies manifest, stages files
POST /api/session/{s}/chunk    proof ‖ data for one 8 MiB range   (repeat)
POST /api/session/{s}/finish   all files verified → recorded
```

Each file is published the moment its coverage is complete, so a session that
dies halfway still delivers the files that finished.

### Native push sender

Native push is optional. It is enabled only when `VOTPORT_PUSH_BIND` is set;
the UDP port must be reachable from the sender and `VOTPORT_PUSH_ADVERTISE`
must name the address it can dial. The issuer key is always kept in
`VOTPORT_DATA_DIR`; an automatically generated listener certificate pair is
kept there too, while configured certificate and key paths are used in place.
`/api/push-identity` is public so a sender can obtain and pin the certificate
digest.

The sender first calls `POST /api/r/{token}/push` over HTTPS with the link
password (or its existing link cookie), holder public key, and the exact VOT
package root and length. The receiver checks the manifest entry count later
against its built-in `MAX_ENTRIES` limit. The response contains a one-session capability,
the advertised UDP address, certificate digest, and expiry. Pass the
capability and its holder key to the VOT CLI or equivalent VOT library:

```sh
CAPABILITY_B64='<capability from the preflight JSON>'
printf '%s' "$CAPABILITY_B64" | base64 -d > push-token.cbor
export VOT_PUSH_IDENTITY=<certificate_digest>
export HOLDER_SECRET='ed25519-secret:<64 hex characters for the holder secret>'
vot push BUNDLE_DIR <host>:<udp-port> push-token.cbor env:HOLDER_SECRET
```

The b14 CLI accepts a numeric IPv4 or bracketed IPv6 `SocketAddr`, not a DNS
hostname. Use a numeric address in `VOTPORT_PUSH_ADVERTISE` for that CLI; VOT
library callers may resolve names themselves. The link password never crosses
the UDP connection.

Native and browser uploads share link and tenant quotas, upload history,
receipts, retention, and the admin UI. Browser uploads continue to use HTTP
through the reverse proxy. Native push stages the complete package first and
publishes it as one package after verification; an interrupted native push
does not publish partial files.

## Roadmap

VOT is pinned at `5e287bea4edda0d4dca0af85b20992bc0e50eda1` (includes upstream PR #391, plus ADR-0046 parallel range acceptance, ADR-0047 receiver re-attach, and ADR-0051, the fetch window of up to sixteen objects).
That pin adds the holder-dialed push engine, and votport's native push receive
path is shipped but disabled unless `VOTPORT_PUSH_BIND` is set. Browser uploads
still travel over HTTP through the reverse proxy. Native push does not change
`CHUNK_BYTES` or enable parallel HTTP verification.

Product next, each as its own design first:

* Content dedup when two entries share an object root
* Automation tokens beyond `POST /api/automation/share` (tokens are per
  tenant, expiring, revocable, rate limited, optionally confined to a library
  folder, with use and refusal audited)
* Legal hold versus upload retention (a do-not-sweep flag)

Not on the table: Postgres, a second store backend, horizontal replicas, SAML.

## Splitting this out into its own repository

votport is self-contained (it consumes VOT only as pinned git dependencies),
so if it currently lives as `votport/` inside the VOT repository you can
extract it with full history:

```sh
cd VOT
git subtree split --prefix=votport -b votport-standalone
# create an empty repo (e.g. halideworks/votport) on GitHub, then:
git push git@github.com:halideworks/votport.git votport-standalone:main
```

Nothing in the project references its location inside the VOT tree.

## License

Votport is proprietary commercial software. Use requires a separate paid
written agreement from the repository owner. See [LICENSE](LICENSE) and
contact the repository owner for commercial terms.

VOT remains separately available under its own license, but bundled VOT use
with Votport follows the Votport commercial agreement. Third-party component
licenses and notices are unaffected.
