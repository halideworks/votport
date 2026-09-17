# Deployment guide

votport is one container behind a TLS-terminating proxy. This guide covers a
production deployment end to end: layout, Caddy, SSO with worked examples,
backups, metrics, and content lifecycle.

## Layout

```text
docker-compose.yml          deployment-specific service definition
docker-compose.example.yml  portable Docker quick-start service definition
.env.example                tracked quick-start environment template
.env                        local environment file (0600, ignored)
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

### Build identity

`votport --version` prints the version and source revision compiled into the
server without loading configuration or opening data files. Primary and standby
processes also log those fields at startup. Release images carry the same values
in their OCI labels.

For a local build from a clean checkout, stamp the revision explicitly:

```sh
VOTPORT_REVISION="$(git rev-parse HEAD)" cargo build --release --locked --manifest-path server/Cargo.toml
```

The portable Compose file accepts `VOTPORT_VERSION` and `VOTPORT_REVISION` as build
arguments. Export the revision before building; the version defaults to `dev`:

```sh
export VOTPORT_REVISION="$(git rev-parse HEAD)"
docker compose -f docker-compose.example.yml build
```

For a deployment-specific Compose file, pass `--build-arg
VOTPORT_REVISION="$VOTPORT_REVISION"` and `--build-arg VOTPORT_VERSION=dev` to its
build command. Unstamped local binaries report the package version and an
`unknown` revision. Build identity is diagnostic metadata; verify the image digest
and provenance when checking authenticity.

### Network filesystems

Linux NFS and SMB/CIFS can receive directly with Balanced publication after a
platform administrator qualifies the exact mounted share in **Storage > Receiving
storage**. A new or changed NAS stays paused; administration remains available.
Votport never silently falls back to a local directory when a qualified mount is
missing. Local receiving continues to use Balanced.

The server must honor stable SMB FLUSH or NFS COMMIT acknowledgments, enforce the
private receiving namespace and ancestor permissions, and support hard links,
stable file identity, and coordinated file locks. The UI requires explicit
confirmation of the storage server's durability and permissions. Its operation
probe checks file and namespace operations; it cannot prove power-loss behavior.
Client-side `uid`, `gid`, and mode presentation alone do not qualify server ACLs.
Unsupported mount options are refused. See [Direct receiving](direct-receiving.md)
for the supported mount contract and deployment checks.

Files are verified as they arrive into Votport's private `.vot-stage` folder on
the destination filesystem. Publication gives the same inode its final name;
there is no second payload allocation or final copy. The application creates this
folder itself without changing the selected shared directory's permissions.
Native push carries verified ranges directly into the same receiver. Reception
workflows keep and verify the original received files instead of taking another
payload snapshot.

File and folder components ending in `.vot-receipt` are reserved for signed
receipts, including portable case and Unicode aliases. Uploads, receive
destinations and shared payload names reject them before new transfer work.
Generated receipt downloads and verification remain available. Recovery reuses
an existing receipt only when its signature, object and publication identity
match. Existing damaged payload/receipt pairs require separate recovery.

Payload filenames may use at most 242 UTF-8 bytes so the `.vot-<name>.journal`
and signed receipt sidecars fit the filesystem's 255-byte component limit.
Parent directories may still use 255 bytes. A collision that would exceed the
filename budget is refused with a shorten-name error; names are never truncated.

HTTP and native uploads reserve final filenames together when their manifests
are admitted. Reservations include unfinished sessions retained across restart
and overlapping link destinations within a tenant. Conflicting filenames get a
suffix; a file reserved as a parent folder causes admission to refuse. Existing
verified files can still be reused without creating the requested path.

Admission serializes staging metadata allocation and its database transaction.
Very large manifests or slow NAS metadata operations can delay other admissions;
payload verification and transfer run outside that lock. Temporary memory scales
with filename keys and directory prefixes, not payload size.

NAS receipts identify provider `POSIX_NAS` (`0x0005`) and Balanced publication.
They distinguish verified content and server-acknowledged durability from
independent server-side readback. Strict is not offered for NAS. macOS SMB and
Windows receiving are not qualified by this Linux server implementation; desktop
senders can transfer to a qualified Linux port using either transport.

Keep SQLite and control data on local storage. Sharing existing `/outbound`
library files verifies their content without creating publication receipts.
Received files retain their original publication receipts when shared.

## Quick start

```sh
cp Caddyfile.example /etc/caddy/sites/votport   # adjust host + port
install -m 600 .env.example .env
# edit .env: VOTPORT_ADMIN_PASSWORD and VOTPORT_PUBLIC_URL
sudo install -d -o 1000 -g 1000 -m 0700 data received outbound
docker compose --env-file .env -f docker-compose.example.yml up -d --build
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8103/r/x   # expect 200
```

The three bind roots must be writable by uid/gid 1000, the user inside the
container. If they already exist, grant that uid/gid access without
recursively changing unrelated content. The tracked `docker-compose.yml` is
deployment-specific; use `docker-compose.example.yml` for this portable quick
start.

`VOTPORT_PUBLIC_URL` must be an `https://` URL for a deployed site. Plain
`http://` is accepted only when its host is loopback (`localhost`, `127.0.0.1`,
or `::1`), and invalid values stop startup.

`VOTPORT_SESSION_IDLE_SECS` defaults to 1800 seconds. Choose a value longer
than the longest sender or network pause when preserving interrupted
transfers; the portable Compose example uses 172800 seconds (48 hours). Keep
this environment setting the same on a promoted failover host. Active requests
remain retained while in flight.

HTTP connections are bounded on both sides. The server itself caps how long a
connection may spend sending request headers (30 seconds per connection,
enforced by the HTTP/1 listener); there are no server-side limits on transfer
duration. The Caddy examples add the outer bounds: header reads 30 seconds,
read and write windows of 1 hour (reset as data flows), and 5-minute idle
keep-alives. Large uploads and downloads ride chunked multi-MiB requests, so
per-request windows stay well inside these limits.

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
request links; each link can opt in to notification when a receive completes
or fails (a refused request, or a transfer that stopped after bytes arrived; a
sender's cancel does not notify).
Deliver issues links for one or more outbound files; each delivery link can opt
in to notification when its first file is requested and when every file is
requested. These request counters record transport handoff and do not prove
recipient-side verification or acceptance; signed Verify/Accept evidence is
separate.

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

Replace the example address with the numeric public address reachable by
the sender. Because the port is published, Docker DNATs push packets before
the host INPUT chain: no `ufw allow` is needed for UDP 8322, and an INPUT
rule cannot restrict it either. Restrict sender sources in the `DOCKER-USER`
chain instead, using the original destination port, for example:

```sh
sudo iptables -I DOCKER-USER -m conntrack --ctorigdstport 8322 \
  ! -s 203.0.113.0/24 -j DROP
```

Cloud-level firewalls that sit in front of the host still apply normally. Do
not put the UDP mapping behind the normal Caddy `reverse_proxy`: it proxies
HTTP/TCP, not the VOT QUIC listener. The HTTPS `VOTPORT_PUBLIC_URL` remains
the address used for the link and native-push preflight.

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

### Deliver over VOT QUIC

Set `VOTPORT_SERVE_BIND` (and `VOTPORT_SERVE_ADVERTISE`, on the same rules as
the push pair) to serve Deliver grants to VOT clients over QUIC. The serve
listener is a second UDP port that presents the same certificate and signs
capabilities with the same `push-issuer.key`, so one digest pins both
directions; map and allow the port exactly as for push. A recipient page for
a grant then shows a "Fetch with the VOT client" block, `GET /api/s/{token}`
carries a `fetch` object (address, certificate digest, mint URL), and
`POST /api/s/{token}/fetch` with the recipient's ed25519 public key mints a
capability for the grant's package good for an hour or until the grant
expires. Each minted capability reserves one delivery against
`max_downloads` until it is delivered or expires, so the cap bounds copies
rather than counting them after the fact; a fetch session is refused when
the grant is revoked, expired, or exhausted, and a completed fetch counts
as one delivery however many rails carried it. A fetch holds one download
slot for all its rails, under the same per-grant and global caps as HTTP
downloads, and the VOT listener itself answers at most eight sessions at
once, so one eight-rail fetch fills it and a second waits. The first mint
for a grant builds its VOT package under `data/outbound.manifests/<grant>/`
and reads every byte of its files once to prepare the server, so the first
mint of a large grant takes about 1.4 seconds per gigabyte; later sessions
cost nothing extra, and a restart rebuilds the servers for every live
capability before it accepts.

The sender presents the link password only to the HTTPS preflight,
`POST /api/r/{token}/push`, which admits the exact package root and length and
returns a capability, advertised address, certificate digest, and expiry. The
receiver checks the manifest entry count later against `MAX_ENTRIES`. Native
pushes then use the UDP listener. They share tenant/link
quotas, sessions, upload history, receipts, retention, and the admin UI with
browser uploads. Each completed object publishes its destination files before
the rest of the package finishes. A failed or cancelled native push can leave
completed files at their final names and retain incomplete files for retry;
publication is not atomic across the package. See [direct receiving](direct-receiving.md).

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
files only: the receipt signer, native-push issuer, and VOTPort-generated
push certificate pair. They exclude the live cookie-signing secret, WAL/SHM files,
`data/backups/`, staging data, and everything under `/received` and
`/outbound`. Configured external certificate files are not copied. The local
path is interpreted inside the service filesystem and must be writable by the
container user; blank uses `<data_dir>/backups` (normally `/data/backups`). A
custom path must already exist with no symlink or group/other-writable ancestor.
A dedicated host directory must be mounted at that container path. S3 uploads
use the configured bucket and prefix. The UI reports credential and passphrase
configured flags, never their values. A pending restore or an unreadable restore
marker pauses scheduled backups. The System page shows the current reason
without replacing the last backup result. The scheduler checks again each
minute and resumes when the blocker clears; applying a restore still requires
a restart.

Backup and restore work retains its ownership locks if the requesting client
disconnects. At startup, VOTPort removes owned scratch files under the data or
backup directory lock. It preserves pending restore inputs, rollback files,
and older scratch names whose writers do not use the backup directory lock.

Pruning is owned by VOTPort for snapshots it created under the configured
local path and for generated `votport-backup-v2-*` objects under the configured
S3 prefix. It does not delete unrelated local files or bucket objects. S3
inventory and retention listings allow five minutes and 100,000 returned
objects, including unrelated objects under that prefix. Use a dedicated backup
prefix. A failed or oversized listing deletes no remote snapshots. If other
maintenance repeatedly blocks the scheduler for a configured backup interval,
it logs a warning, at most once per interval, while continuing to wait.
Keep an external recovery copy of the encryption passphrase. An
encrypted archive is unrecoverable without it, and storing that passphrase in
the same deployment backup defeats recovery isolation.

Any single archive can also be discarded on demand: `DELETE
/api/admin/backups/{source}/{id}` (platform admin; `source` is `local` or
`s3`, matching the inventory) removes that copy only. Retention days or count
of `0` keeps every archive until one is deleted this way. The backup window is
the erasure floor: content removed on the server by retention or deletion
stays restorable from every archive that still contains it, until each copy is
deleted or ages out.

| Store | Mechanism | RPO | RTO |
| --- | --- | --- | --- |
| `data/votport.db` | Litestream (or equivalent WAL replica) continuous | seconds (Litestream's default interval is about 1s of WAL) | minutes: stop container, `litestream restore`, start |
| `data/votport.db` | `GET /api/admin/backup` (`VACUUM INTO`) | last time someone clicked Download (not the DR clock) | same stop-replace-start |
| `/received` | existing file backup (restic, borg, zfs send, rsync) | that job's interval | restore files, start |
| `/outbound` (including `.vot-tenants.stage/<tenant>`) | existing file backup (restic, borg, zfs send, rsync) | that job's interval | restore files, start |

### Database copy-home

`GET /api/admin/backup` (admin session plus the `X-Votport: 1` header) streams a consistent snapshot produced
by SQLite's `VACUUM INTO`, with `Content-Length`. Snapshots land under
`data/backups/` and are swept after 30 days. Use this endpoint or the scheduled
archive service for a live snapshot. Never open the running container's database
with a host SQLite client, including a read-only query or `.backup`: closing that
connection can invalidate the live WAL and lose acknowledged writes. Inspect an
exported snapshot instead. Stop the service before opening its database directly.

The Download snapshot action remains database-only. It is useful for a
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

### ZFS receive and download volumes

Measured on erebus (OpenZFS 2.2.2, mirrored NVMe, `recordsize=128K`,
`compression=lz4`, `sync=standard`, `zfs_dirty_data_max` 4 GiB): one buffered
writer into one file lands 0.86 GiB/s, eight concurrent writers into one file
3.19 GiB/s, one writer with `O_DIRECT` 2.37 GiB/s, and an fsync every 64 MiB
costs nothing for a single stream. VOT writes each verified bundle with one
`pwrite` per prover and syncs each object once at completion (plus every
64 MiB during a large object), so the eight-writer figure is the one a fetch
can reach and the fsync pattern is what the volume has to absorb.

Three settings decide the number on a media volume:

- `zfs_dirty_data_max` (module parameter, default 10% of RAM capped at 4 GiB).
  Once dirty data reaches it the write throttle engages and an fsync issued at
  that moment waits for a transaction group to drain; on the test pool that
  showed as single reps of 13 to 50 seconds for a 4 GiB object. Raise it above
  the largest object the volume receives, or expect that wait once per object
  of that size.
- `compression` on a dataset that holds compressed media and EXR: lz4 tries
  every record and stores an incompressible one unchanged, so it buys nothing
  there; measure a fetch with it off before deciding, since the test pool
  above ran with it on.
- `sync=disabled` removes every wait for the ZIL and also removes the
  durability VOT's receipts promise: a receipt says the bytes were synced,
  and under `sync=disabled` they were not. Do not use it on a volume that
  holds the only copy. Whether a SLOG device helps this write pattern was not
  measured; measure before buying one.

### Restore

The System page's Restore action validates the selected archive, stages it,
and asks the supervised service to restart. At boot, VOTPort moves the current
managed files into a private `.votport-restore-rollback-<token>/` directory
under `data/`, installs the staged database and identity files, then removes
the restore stage and marker after the file installation and integrity checks
finish. Later database validation, receipt signer, or push initialization can
still fail; the private rollback directory remains for operator recovery and
can be removed after the restored deployment is accepted. The archive still
does not restore `/received` or `/outbound`; use the matching operator-owned
file backups for those volumes.

With the default compose restart policy, the process restart request is
observed by the supervisor and the service comes back. Without a supervisor,
the action only stages the restore: stop the container or process, then start
it manually so boot can apply the pending restore. Never copy a live `-wal`
over a restored database. Historical restore disables request links, revokes
download links and automation tokens, and disables SCIM and replica tokens.
Trade connections require new invitations. Delivery jobs remain visible as
**Held after restore** and require new submissions; their files and signed
evidence remain. Pending transfers and route-control messages do not resume.

Automatic backups, received-file retention, storage exports, notifications and
webhooks stay disabled until an administrator reviews and re-enables them.
Backup schedule, destination and encryption settings are preserved from the
snapshot. Backup credentials, the encryption passphrase and previous run status
are cleared during activation; re-enter secrets before running encrypted or
remote backups. Keep the external recovery copy of the old passphrase to read
existing encrypted archives. Staging alone does not change these settings.
Disabled storage and notification destinations retain their saved credentials.
Restore still loads the archived users, roles and administrator password;
review access and reconcile the file volumes before enabling links or retention.

Restore creates a fresh cookie-signing key and signs out existing sessions.
Plan to sign in again after restart. Archives use format version 2; older
archives containing a cookie-signing secret are refused. Create a new backup
after upgrading, and keep older archives private until they can be discarded.
Finish any pending restore with its existing binary before upgrading. The
pending marker records whether installation is historical restore or replica
promotion; markers without that purpose are refused.

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

Groups from the verified ID token and matching-subject UserInfo response are
combined with SCIM group memberships before roles are assigned. Direct group
claims must be arrays of strings; malformed claims refuse sign-in.

SSO start and callback requests share a limit of 200 per ten minutes for each
client address (IPv6 addresses share a /64 bucket). A normal sign-in uses two
requests. Excess requests return HTTP 429 with `Retry-After: 600` before provider
calls or failure audit writes. This budget is separate from local password
sign-in and uses the same `VOTPORT_TRUSTED_PROXIES` rules.

The macOS and Windows apps use the same provider configuration. In Settings,
enter the port address and choose **Sign in with SSO**. Finish sign-in in the
default browser and allow it to open Votport. The app receives a one-use code
valid for 60 seconds, bound to a secret kept by the app that started sign-in;
the URL contains no session cookie. Cancel in the app to abandon the attempt.
A server restart invalidates an unfinished handoff, so start again if needed.

A single `VOTPORT_OIDC_CLIENT_ID` is the supported shape. When an id token
carries `azp`, it must equal that client id. The crate already checks issuer,
audience, and nonce. A second client or a hosted-domain (`hd`) allow-list is
not supported.

Discovery runs on first SSO use, not at process start. Failed discovery cools
down for 30 seconds and then retries. A successful discovery stays loaded, but
an id-token verification failure (typically an identity provider that rolled
its signing key, leaving the cached key set stale) drops it into the same
cooldown, so key rolls recover automatically on the next sign-in without a
restart.

SSO sessions last `VOTPORT_SSO_SESSION_SECS` (default 604800, 7 days). The
environment and settings API accept 1 through 31536000 seconds (365 days),
and a platform admin can adjust the value live from System > Sign-in in whole
hours from 1 through 8760. The stored setting overrides the environment; an
invalid persisted value falls back to the environment value. Values outside
the seconds range refuse startup or the settings write. The local break-glass
session keeps a fixed 7 days. The session cookie freezes the principal's
tenants and roles at login, so removing a user's IdP group takes effect at
their next login, bounded by this lifetime; shorten it when offboarding
latency matters. To cut access immediately, also revoke the principal in the
Tenants page; offboarding is a two-step action across the IdP and votport.

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

Entra supplies these groups in the ID token; its UserInfo endpoint does not
return groups. Tokens with group overage (`hasgroups`) or distributed groups
(`_claim_names.groups`) refuse sign-in with a group-verification error. Votport
does not fetch external claim sources. Configure a complete direct group list,
or disable OIDC group emission and provision memberships through SCIM instead,
using SCIM group display names in Votport's group settings.

### SCIM provisioning

votport serves SCIM 2.0 Users and Groups at `/scim/v2` (RFC 7643 and RFC 7644): `ServiceProviderConfig`, `Schemas`, `ResourceTypes`, `GET`, `POST` `/Groups` with the filters `displayName eq "value"` and `externalId eq "value"`, `GET`, `PUT`, `PATCH`, `DELETE /Groups/{id}` (members by user id; PATCH takes the Okta and Entra shapes: add or replace with a member list, remove by `members[value eq "id"]` or by list, and a pathless replace with a value object), `GET /Users` with the filters `userName eq "value"` and `externalId eq "value"` and `startIndex`/`count` paging, `POST /Users`, and `GET`, `PUT`, `PATCH`, `DELETE /Users/{id}`. The bearer token is `VOTPORT_SCIM_TOKEN` or the value saved under System > Sign-in (the stored value wins; clear it to disable the endpoint). Every route answers 401 until a token is set. A saved token is stored as a SHA-256 digest, never in clear; the env value is compared as given. Saving a new token moves the old digest to a previous slot that stays accepted, while a current token exists, until **Clear previous token** is pressed, so the provider can be switched over without a gap; clearing the current token turns the endpoint off whatever the previous slot holds; a request with the previous token is logged as `scim_previous_token_used`. Failed bearers count against the client address the way failed admin passwords do and lock that address out for a minute after a burst; every SCIM mutation is audited with the client address (`ip` in the detail, honoring `VOTPORT_TRUSTED_PROXIES`).

A user's `userName` is the principal subject, so it must equal the claim the OIDC sign-in uses as the subject: that is the row the sign-in path looks up and the row SCIM deactivates. Subjects are matched and stored case-insensitively: `userName` and the sign-in subject are folded to lowercase, so the provider may send any case, and the stored (displayed) form is lowercase because no separate display column is kept. Rows stored with mixed case by earlier versions still resolve by any case and converge to the folded form the next time that row is written; until then two rows differing only by case can coexist, and a delete by either spelling revokes both. `VOTPORT_OIDC_SUBJECT_CLAIM` chooses that claim: `sub` (the default), `email`, or `preferred_username`, read from the id token and then from userinfo. The userinfo `sub` is still checked against the verified id token whichever claim is chosen. `email` trusts the provider's email attribute: an id token or userinfo document that says `email_verified: false` is refused, one that omits the flag (Entra) is accepted, so where users can edit their own email at the provider, choose `preferred_username` or `sub`. Okta and Entra both send the user's login as SCIM `userName` and as `preferred_username` (Entra: the UPN) or `email`, so set the claim to match the provisioning app's `userName` mapping. Authentik emits `preferred_username` and `email` as well. `externalId` is stored and searchable (`filter=externalId eq "..."`) so a provider can reconcile by its own id.

`VOTPORT_SCIM_REQUIRE_PROVISIONING=1`, or the **Require SCIM provisioning** toggle under System > Sign-in, refuses SSO sign-in for a subject with no principal row, which makes the provisioning system the source of truth for who may enter. Rows created by earlier sign-ins count as provisioned. The local password is unaffected.

Deactivating (`active: false`) or deleting a user revokes the principal: its live sessions die on the next request and further SSO sign-ins are refused until it is set active again. Delete keeps a blocked row rather than removing it, because an absent principal is treated as a first sign-in. A replacement (`PUT`) without `active` preserves that state; reactivation requires an explicit `active: true`. Reactivation does not restore previously revoked sessions. Creating a user pre-provisions an unblocked row; the role at sign-in still comes from the group claims. A group's `displayName` joins the provider's `groups` claim at sign-in, so `VOTPORT_OIDC_ADMIN_GROUP`, `VOTPORT_OIDC_AUDITOR_GROUP`, and a tenant's admin group match a SCIM group as well as a claim; pushing groups over SCIM therefore works with a provider that emits no group claims, and a membership change takes effect at the member's next sign-in like a claim change. An unprovisioned user can still sign in through SSO unless **Require SCIM provisioning** is on.

```sh
curl -H 'Authorization: Bearer YOUR-TOKEN' -H 'Content-Type: application/scim+json' \
     -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"user@example.com","active":true}' \
     https://YOUR-HOST/scim/v2/Users
```

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

Once scheduled, the purge continues if the request is cancelled. The tenant key
stays reserved for the whole purge, covering receive files, library files and
logo cleanup. Recreating the key cannot overlap that purge.

Retry DELETE if purge fails (the row is already gone; leftover retry removes
the reserved directory). An unknown key with no leftover directory is 404
and does not touch disk. A default-tenant path with the same name is separate
and is never purged.

An empty database is initialized directly with the current schema and reserved
tenant storage layout. Startup and archive restore require the exact schema
version supported by the binary. Older databases, newer databases, missing or
unsupported storage-layout markers, and `state.json` imports are refused.
Existing receiving directories are never relocated automatically. Preserve the
database and payload directories and use a matching release to export data
before an intentional schema or storage-layout transition.

Schema 37 binds named-tenant session grants to an immutable tenant identity and
records upload completion atomically with history and workflow creation.
Deleting and recreating a tenant key does not restore its previous users' access.
Deletion is refused while that tenant has admitted operations. Completed uploads
awaiting journal cleanup are never resumed or charged as retained transfers.
A transition from schema 35 or 36 requires draining all upload sessions,
stopping VOTPort and making a verified cold backup before
an explicit offline database conversion with fresh identities for existing
tenants. Existing named-tenant SSO grants require a fresh sign-in. Do not infer
completion from published file flags or discard unresolved session rows. Older
archives require a matching binary; take fresh backups after the transition
and upgrade replicas together.

Schema 38 additionally stores an independent random bearer for each workflow job.
An offline conversion must replace existing workflow bearers and their matching
grant hashes together; distribute the replacement links to recipients. Do not
derive these values from `receipt.key` or retain the old deterministic links.
Use a matching binary for older archives, take fresh backups after conversion,
and upgrade replicas together.

The explicit `votport convert-schema35` command converts a disposable schema-35
copy to schema 46 without starting the application. Follow the
[offline conversion procedure](schema35-conversion.md); startup never runs it.

Schemas 41, 42, and 43 upgrade to 44 during startup under the data-directory
ownership lock, before workers start. Schemas 41 and 42 add the tenant quota
aggregate and its live-file accounting indexes and triggers. Schema 41 also gains
private storage for ordinary download addresses. Every upgrade seeds the
transactional audit-row counter before workers start; its insert and delete
triggers keep the counter current. Existing files, grants, passwords, expiry and
download counts are unchanged.
Older ordinary addresses remain valid but cannot be reconstructed if no copy was
saved. New addresses can be reopened from Deliver. Workflow addresses retain their
existing private token storage. The database and its backups contain credentials
and must remain private. Upgrade replicas to the same release.

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

Platform admins edit SMTP relay, retention, default quotas and sign-in settings
on System. These settings overlay environment values through
`GET`/`PUT /api/admin/settings` (`X-Votport` on PUT). An absent row uses the
environment; JSON `null` ("Use environment") removes the override. Empty text
clears optional values. See the [configuration reference](../README.md#configuration).
Named destinations and recipient lists are managed separately under
[Notifications](notifications.md).

Primary and standby startup warn once about each unrecognized `VOTPORT_*`
environment name. Warnings include the name only; unknown settings are ignored.

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

The tracked `docker-compose.yml` sets `172.16.0.0/12` because its reverse
proxy is the Caddy container on the same compose network, and every
Docker-created user bridge draws from that range. Change it when that trust
assumption changes: name the proxy's exact address (found as below) when
other containers on the host are not trusted, and replace it when the proxy
moves off the compose network.

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

Public port discovery (`GET /api/port`) shares the recipient authentication
budget of 6,000 requests per ten minutes for each client address. Exhaustion
returns HTTP 429 with `Retry-After: 600` before settings reads or signing.

## Metrics

`GET /metrics` serves Prometheus-format counters and gauges (tenants, links,
received bytes, active sessions, audit rows), plus native-push active sessions,
received bytes, and refusals by bounded reason (`rate`, `capability`, `expired`,
or `spent`). It also exposes fixed-cardinality HTTP request totals by status
class, in-flight handlers, and a time-to-response-headers histogram with 10ms
through 5s and `+Inf` buckets; streamed body transfer time is excluded. Outbound
library uploads also have a fixed-cardinality
`votport_http_outbound_upload_duration_seconds` histogram with no route labels.
Transfers are covered by `votport_upload_sessions_ended_total` with a fixed
`outcome` label (`published`, `rejected`, `cancelled`, `interrupted`), the
`votport_upload_bytes` and `votport_upload_duration_seconds` histograms over
published uploads (1 MiB through 16 GiB, and 1s through 6h), the
`votport_upload_bytes_in_flight` gauge, and `votport_disk_free_bytes` and
`votport_disk_total_bytes` per `volume` (`receive`, `outbound`). Alert on
`votport_disk_free_bytes` for either `volume`: session admission refuses new
sessions whose declared total would not fit above a 1 GiB reserve on the
receiving volume, and outbound staging keeps the same reserve.
Ownership and admission state use the `votport_draining`, `votport_lease_held`
and diagnostic `votport_lease_age_seconds` gauges. QUIC delivery exports
`votport_serve_sessions_active`, `votport_serve_bytes_total`,
`votport_serve_deliveries_total` and `votport_serve_refused_total{reason}`
(`rate`, `capability`, `unknown`, `closed`, `busy`). Served bytes update when
sessions end; completions count successfully recorded fetch acknowledgements.
`votport_delivery_event_chain_failures_total` counts stored delivery-history
signature, issuer, hash and chain verification failures. It resets on restart;
invalid client cursors and unrelated database errors do not increment it.
[The Grafana dashboard](../ops/grafana-votport.json) includes these series.
Request metrics never include paths, tenants, addresses,
methods, or tokens. Set `VOTPORT_METRICS_TOKEN` to require a bearer token, and
scrape the private upstream directly. The public Caddy examples return 404 for
`/metrics` and `/readyz`, including requests with a bearer token: metrics
expose tenant keys and `/readyz` reports lease ownership, so both stay on the
private upstream. See the
[Prometheus example](load-testing.md#scraping-metrics-into-prometheus).
Platform admins can fetch the same per-tenant link and live-byte totals as JSON
from `GET /api/admin/holdings`.

## Content lifecycle

Set `VOTPORT_UPLOAD_RETENTION_DAYS` to delete received files (and their
records' live status) older than N days, swept daily with audit events.
`VOTPORT_AUDIT_RETENTION_DAYS` (default 400) prunes audit rows the same way.
Upload retention defaults to keeping everything; audit rows default to
400 days. A link's **Legal hold** action excludes all of that link's uploads
from the automatic content sweep and records the change in the audit log.
Explicit file, upload-record, and link deletion require releasing the hold
first. Tenant deletion requires removing its links first.

Automatic age cleanup uses a saved time anchor plus server uptime, so a
forward clock correction cannot suddenly age stored data. Existing installations
without an anchor pause age cleanup until a platform admin confirms the displayed
server time under **System > Retention**. Cleanup stays conservative across
restarts and downtime; confirm the current time there if it falls behind.
Backup count limits and explicit deletions continue independently.

Idle-session and staging cleanup waits one minute between passes. Daily
retention waits 24 hours after startup and after each completed pass, so it
never runs immediately at boot. The two schedules run independently. Restarting
resets these delays; a service restarted more often than daily will postpone
daily retention until it stays up long enough.
If receiving storage becomes unavailable, upload retention stops the current
pass and logs one error. It retries on the next daily pass.

## Performance

Range size is 8 MiB, set by VOT, advertised as `chunk_bytes` on session
create. The sender keeps eight range PUTs in flight. The upload worker
drains the in-flight window as one batch and verifies and writes those
ranges in parallel (VOT's `accept` takes shared access since ADR-0046),
so a single fast upload is no longer bottlenecked on one-at-a-time verify.
Measured single-stream upload rose about a quarter (256 MiB baseline,
1258 to 1580 MiB/s median on the same rig).

Do not raise `CHUNK_BYTES` in votport until VOT changes its server verify
path to support larger ranges; the `de66d413` pin does not. Any VOT re-pin
moves the VOT dependencies and Dockerfile `ARG` together, then relocks
Cargo.lock. Measure with:

```sh
cargo test --test e2e -- --ignored --nocapture throughput_baseline
```

### UDP socket buffers (QUIC push and deliver)

The VOT QUIC paths (native-push receive, deliver-over-QUIC serve) ask the
kernel for a 16 MiB receive and 8 MiB send socket buffer. Linux caps those at
`net.core.rmem_max` / `net.core.wmem_max`, which default to about 208 KiB; VOT
logs a warning and runs with the smaller buffer, which drops packets at
multi-Gbps rates. These limits are host-global, not per-container, so raise
them on the Docker host rather than in the container:

```sh
# /etc/sysctl.d/99-votport-quic.conf
net.core.rmem_max = 16777216
net.core.wmem_max = 8388608
# apply: sudo sysctl --system
```

Only needed when `VOTPORT_PUSH_BIND` or `VOTPORT_SERVE_BIND` is set; the HTTP
upload and download paths do not use these sockets.

`VOTPORT_MAX_TOTAL_SESSIONS` (default 32) caps concurrent upload sessions
process-wide; the 33rd sender gets a 429 until one finishes. Worst-case
queued-body memory rises linearly with it: sessions x 8 in-flight chunks x
~9 MiB, so 32 sessions bound roughly 2.3 GiB. `VOTPORT_MAX_LINK_SESSIONS`
(default 8) caps sessions per request link the same way: the 9th concurrent
sender on one link gets a 429. Size both against available RAM
before raising it for a busy facility.

Static assets under `/assets` are served `no-cache` and answer conditional
GETs with 304s, so a redeploy takes effect on the next page load. The heavy
leaf assets (fonts, the hero image and ship mark, the wasm verification
binary) are referenced with a `?v=<content hash>` stamp and those responses
are `immutable`, cached for a year without revalidation. Stamps maintain
themselves: `scripts/build-wasm.sh` and `scripts/fetch-fonts.sh` restamp
what they generate, and `npm test` fails if a stamp goes stale.

## High availability (active-passive)

One live instance, one stopped standby, the same three volumes and application
environment. Mounting `data/`, `/received`, and `/outbound` at the same paths
and starting the same image preserves stored state, but does not copy the
primary's environment settings. Match those before promotion.
It sees the same links, tenants, settings, cookie secret, receipt key, and
push certificate (all under `data/`), and it re-attaches the uploads the
previous instance suspended: staging and journal files sit in a private
`.vot-stage` child of their destination directory under `/received`, and the
resume record in SQLite names them by path, not by host.

In both topologies, copy the primary's complete application environment into
the promoted service. In particular, `VOTPORT_MAX_UPLOAD_BYTES`,
`VOTPORT_ALLOW_HIDDEN`, and `VOTPORT_SESSION_IDLE_SECS` have no database
override. A smaller cap or resume window can reject an unfinished transfer;
changing the hidden-file policy can prevent its staged files from reopening.
Keep the public URL, authentication, retention, quotas, workflow capacity,
session limits and enabled transports consistent too. Host bind addresses,
advertised endpoints and mount sources may differ, but must preserve client
reachability and the same container paths. Saved System settings override
only the settings described in [Settings](#settings); they do not replace
the deployment environment. See the [standby configuration example](../ops/failover/README.md#matching-the-primary).

Layout:

- `/received` and `/outbound` on the NFS export both hosts mount, under the
  rules in [Network filesystems](#network-filesystems).
- `data/` on storage exactly one host writes at a time: a block device or ZFS
  dataset that fails over with the service, or a DRBD volume. SQLite over NFS
  is not supported (its locking is unreliable there), and two hosts writing
  one `data/` is corruption. votport takes an exclusive `flock` on
  `data/lock` at boot and refuses to start while another process holds it,
  which catches a standby started too early on shared block storage but not
  on NFS, where `flock` semantics vary by server.
- `/received/.vot-stage/writer.lock` is a permanent inode holding an exclusive
  kernel lock. NAS must coordinate that lock at the server; client-local locks
  are refused. A second instance cannot take ownership because a heartbeat is
  old or its wall clock differs. `.vot-stage/.votport-lease` records the holder
  and renewal time for diagnostics, refreshed every 30 seconds. Never unlink
  the lock file to force takeover: that would create independent lock inodes.
  Stop or fence the old host and let the filesystem release its lock first.
  `/readyz` and lease metrics expose ownership. Loss of ownership stops writes,
  preserves recovery state and ends the instance. Both data and receiving
  locks remain held until process exit, including while storage work is blocked.
  A retained heartbeat record does not prevent the next holder from acquiring
  the released kernel lock; crash takeover follows the NAS's lock recovery rules.
- Where the data volume cannot move, run the standby in replica mode:
  `votport standby` with `VOTPORT_STANDBY_SOURCE` (the live instance's
  https URL), `VOTPORT_REPLICA_TOKEN` (the token saved under System >
  Standby replica, or the live instance's `VOTPORT_REPLICA_TOKEN`),
  `VOTPORT_DATA_DIR`, and optionally `VOTPORT_STANDBY_INTERVAL_SECS`
  (default 60). On each interval it pulls `GET /api/replica`, a fresh
  archive of the database and identity files, validates it, and stages it
  as the pending restore that its next normal boot applies; the standby
  holds the same `data/lock` as a live instance and never opens the live
  database or touches the receive root. A replacement keeps the previous
  replica until the new marker is durable. Its `/healthz` is
  200 while pulls land within two intervals and its `/readyz` is always
  503 with `replica_lag_secs`, so a failover script can see how fresh the
  copy is. A replica-mode standby serves nothing else, so it is not a proxy
  upstream until it has been promoted: the Caddy pair below is for the
  shared-volume topology, and its `/healthz` exists for the container
  runtime's health check. Promotion is stopping the standby process and
  starting `votport` normally over the same data directory. Promotion requires
  an initialized, compatible database. A fresh standby must first receive a
  valid replica; an interrupted first pull cannot create an empty live
  instance. Like any restore, promotion rotates the cookie secret, so every admin signs in
  again; receipt and push identities carry over. Replica promotion preserves
  the snapshot's links, credentials, jobs and resume records. Historical-restore
  suspension does not apply to promotion. Backup schedule settings are retained,
  but backup credentials, encryption passphrase and run status are cleared.
  Automatic backups remain disabled until their secrets are re-entered and
  scheduling is re-enabled. Upgrade the standby binary
  alongside the live one: replica pulls require matching archive formats and database schemas.
  If a promotion boot is interrupted mid-restore, run `votport` normally to
  finish it before returning the directory to standby mode. The RPO is the
  interval: links, settings, and resume records written on the live
  instance after the last pull are lost, and uploads in that window start
  over. Litestream (see [Litestream](#litestream)) remains an option for a
  tighter RPO with an operator-owned restore step. Plain `http://` sources
  are accepted only for loopback.
- Caddy in front of both hosts with a health-checked upstream pair
  (shared-volume topology; a replica-mode standby joins the pool only after
  promotion). The check is `/healthz`, so a drained live instance keeps
  serving downloads and admin until it is stopped, and the standby takes
  over once it is up:

```caddyfile
drop.example.com {
	respond /metrics 404
	respond /readyz 404
	reverse_proxy live:8321 standby:8321 {
		lb_policy first
		health_uri /healthz
		health_interval 5s
	}
}
```

Native push and deliver-over-QUIC listeners bind a UDP port on the live host;
`VOTPORT_PUSH_ADVERTISE` and `VOTPORT_SERVE_ADVERTISE` must name an address
that follows the failover (a floating IP, or a DNS name with a short TTL), and
the generated `push.crt` under `data/` moves with the volume so pinned
senders keep matching.

Planned failover: turn on **Drain for restart** so new upload sessions are
refused and `/readyz` goes 503, poll `/readyz` on the live host directly (not
through the proxy) until `sessions_active` reaches 0, stop the live container
(a clean stop yields the lease), move or restore `data/`, start the standby,
turn drain off. Unplanned failover
skips the drain: in-flight uploads whose worker checkpointed resume from that
offset once the standby is up, uploads killed before a checkpoint start over,
and QUIC sessions die with the process and are retried by the client. Browser
downloads that stream to disk (Chromium's save-to-folder path) keep resuming
by byte range for ten minutes, long enough for a failover; when the cookie
secret was rotated by a promotion, a password-gated delivery asks for the
password again and then continues from the same offset; on a capped
delivery that resume consumes another count, and a delivery whose cap was
already spent cannot resume after a promotion. Browsers on the plain download
fallback (Firefox, Safari) need a click to retry, and the desktop client
resumes on its own. Per-IP throttles and session rate windows reset. Nothing
is lost that had been published.

`ops/failover/` holds the automation: `planned.sh` drains, waits, stops,
promotes, and clears the drain on the new live; `watch.sh` probes the live
instance's `/healthz` and, after a run of misses, fences and promotes, then
exits for a person to re-arm; `docker-compose.standby.yml` is the standby
host's compose file with `standby` and `live` profiles over one data volume.
Both scripts take the stop and promote steps as commands and end by waiting
for the promoted instance to report the lease as its own. See
`ops/failover/README.md`.

Drill both topologies against the real binary before relying on either:

```sh
cargo build --release --manifest-path server/Cargo.toml
scripts/build-wasm.sh /path/to/VOT            # the browser uploader's wasm bundle
npm ci && npx playwright install chromium
MODE=shared  node scripts/restart-e2e.mjs   # SIGTERM mid-upload, same directories
MODE=replica node scripts/restart-e2e.mjs   # standby pulls, live stops, standby promoted
```

Each run uploads a 16 MiB file through Chromium and holds later chunk
requests until the live process has stopped. It checks the suspended payload
and journal, the retained lease lock inode, and the next instance's ownership.
The same session must resume verified progress, publish the retained payload
inode byte-identical, and produce a receipt authenticated by the original key.
Payload hashes use streaming reads. The replica run starts with an empty
standby data directory, stages a copy after the first progress checkpoint,
promotes the standby, and checks that the pending restore was consumed.

What this does not give: two live instances. The single SQLite writer, the
process-wide publication lock, and the in-memory session registry are the
items that a multi-node design has to replace, and that is a separate
architecture, not a configuration.

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
external dependencies; see docs/multi-tenancy.md non-goals. Availability
comes from a stopped standby instead, described under
[High availability](#high-availability-active-passive) below.

Receiving currentness checks take a snapshot of ownership before filesystem
work, so a stalled check does not hold the ownership mutex or delay the lease
worker through that mutex. HTTP and native session admission allow eight checks
at once; further requests wait asynchronously. Cancelling a request does not
release its slot until the blocking check finishes. File preparation keeps its
existing concurrency. Lease renewal waits for one blocking job at a time.

`GET /healthz` answers 200 when the database and both storage roots answer,
and is what a proxy health check should poll. `GET /readyz` additionally
answers 503 while **Drain for restart** is on, with a JSON body
containing `ready`, `draining`, `sessions_active`, and
`lease: {holder, mine, age_secs, lost}` for failover scripts and orchestrators.
The two endpoints share a storage probe cached for up to five seconds. Only
one probe runs at a time; a missing or stale result reports unavailable after
at most a one-second wait. Concurrent requests without a fresh result return
503 immediately. Draining changes and detected ownership loss take
effect without waiting for that cache to expire. If a probe remains blocked
at shutdown, storage ownership is retained until process exit.
`holder` and `age_secs` are null when the lease record is unavailable; its age
is diagnostic and never authorizes takeover. Do not point a single-upstream
proxy at `/readyz`: drain keeps downloads and the admin pages up on purpose,
and a proxy that drops the upstream on 503 would take them down.

In-flight upload sessions survive a restart. SIGTERM and API restart close new
transfer admission and make `/readyz` return 503. Existing HTTP and native
transfers share a 240-second drain window, followed by up to 30 seconds for
upload checkpoints. Each upload worker records how far its file is contiguously
verified and leaves its staging on disk; at boot those sessions are re-attached
under the same session id and the sender continues from that offset (the
browser pauses while the server is down, then re-begins on its own). Ranges
that had landed beyond the contiguous prefix are re-sent, at most the sender's
in-flight window. A partial that cannot be re-attached (a link deleted while
down, staging missing or shorter than its checkpoint, or the process killed
before the checkpoint) retains its files, journals and database record for
recovery. The link receives an interruption event, and already published files
are recorded as a partial upload so they remain visible and can be deduplicated.
Before a re-attached file is published, the staged bytes are re-hashed against the
announced object, so a partial altered while the server was down cannot
publish. Long streaming downloads die with the
process. The compose file sets `stop_grace_period: 5m` so in-flight downloads
get a window to finish.

For a zero-surprise upgrade you can still drain first: turn on **Drain for
restart** on the System page (or set the `draining` setting), which refuses new
upload sessions with a transient 503 while leaving downloads, deliveries, and
admin available. Watch `votport_sessions_active` on /metrics reach 0
(`votport_draining` reads 1 while draining), then restart, then turn drain back
off.
