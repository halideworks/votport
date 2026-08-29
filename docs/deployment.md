# Deployment guide

votport is one container behind a TLS-terminating proxy. This guide covers a
production deployment end to end: layout, Caddy, SSO with worked examples,
backups, metrics, and content lifecycle.

## Layout

```text
docker-compose.yml          service definition (ports, env, volumes)
data/                       votport state - keep private
  votport.db                SQLite store (links, tenants, audit log)
  secret                    cookie-signing key        (0600)
  receipt.key               ed25519 receipt signer    (0600)
  backups/                  snapshots written by /api/admin/backup
/received                   received files, published per tenant/link
Caddyfile.example           reverse-proxy template
```

The container runs as uid 1000; both mounted volumes must be writable by it.

## Quick start

```sh
cp Caddyfile.example /etc/caddy/sites/votport   # adjust host + port
# edit docker-compose.yml: VOTPORT_ADMIN_PASSWORD, VOTPORT_PUBLIC_URL, volumes
docker compose up -d --build
curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:<debug-port>/r/x   # expect 200
```

## Backups

Two stores, two clocks. Litestream (or an equivalent WAL replica) is the
database RPO. `/received` stays on the existing file backup. `GET
/api/admin/backup` is a consistent copy-home button, not the HA story.

| Store | Mechanism | RPO | RTO |
| --- | --- | --- | --- |
| `data/votport.db` | Litestream (or equivalent WAL replica) continuous | seconds (Litestream's default interval is about 1s of WAL) | minutes: stop container, `litestream restore`, start |
| `data/votport.db` | `GET /api/admin/backup` (`VACUUM INTO`) | last time someone clicked Download (not the DR clock) | same stop-replace-start |
| `/received` | existing file backup (restic, borg, zfs send, rsync) | that job's interval | restore files, start |

### Database copy-home

`GET /api/admin/backup` (admin session) streams a consistent snapshot produced
by SQLite's `VACUUM INTO`, with `Content-Length`. Snapshots land under
`data/backups/` and are swept after 30 days. Manually:

```sh
sqlite3 data/votport.db ".backup data/backups/manual.db"
```

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

### Received files

Plain files under `/received`. Any file-level backup tool works (restic, borg,
zfs send, rsync). Back them up together with a database snapshot so records
and bytes stay consistent with each other.

### Restore

1. Stop the container.
2. Replace `data/votport.db` with the Litestream restore or a `VACUUM INTO`
   snapshot. Do not copy a live `-wal` over a restored file.
3. Restore `/received` from the file backup taken nearest that snapshot.
4. Start. Staging leftovers are removed by `paths::clean_staging` at boot.

## Single sign-on

Register an OIDC application at your identity provider with redirect URI
`https://YOUR-HOST/api/admin/callback`, then set:

```yaml
VOTPORT_OIDC_ISSUER: "https://idp.example.com"
VOTPORT_OIDC_CLIENT_ID: "..."
VOTPORT_OIDC_CLIENT_SECRET: "..."
VOTPORT_OIDC_ADMIN_GROUP: "votport-admins"   # omit = every principal is admin
```

Roles come from the provider's `groups` claim: members of the admin group are
administrators, everyone else read-only viewers. The local password always
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

`DELETE /api/admin/tenants/{key}` drops the namespace row and purges
`<receive>/.vot-tenants.stage/<key>/`. Point-in-time snapshots under
`data/backups/` (30-day
sweep in the session sweeper) and Litestream replicas still contain the
tenant's rows and, for file backups of `/received`, the bytes until those
backups rotate. GDPR-style erasure of backups is an operator job, not an
API.

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
received bytes, active sessions, audit rows). Set `VOTPORT_METRICS_TOKEN` to
require a bearer token, and scrape it over an internal interface only.
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
verifies those ranges one at a time. That serial verify, not SQLite, is
what leaves the NIC idle on a fast path.

Do not raise `CHUNK_BYTES` in votport until VOT changes its server verify
path to support larger ranges; the `b14cc41` pin does not. Any VOT re-pin
moves the VOT dependencies and Dockerfile `ARG` together, then relocks
Cargo.lock. Measure with:

```sh
cargo test --test e2e -- --ignored --nocapture throughput_baseline
```
