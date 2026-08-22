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
from the dashboard switcher. Named tenants publish into
`/received/acme/...`; the default tenant keeps the receive root.

Update quotas, label, or admin group without recreating the namespace
(JSON `null` clears a quota back to unlimited; `0` is rejected):

```sh
curl -b cookies.txt -X PATCH -H 'Content-Type: application/json' \
     -H 'X-Votport: 1' https://YOUR-HOST/api/admin/tenants/acme \
     -d '{"max_total_bytes":214748364800,"max_links":100}'
```

`DELETE /api/admin/tenants/{key}` drops the namespace row and purges
`<receive>/<key>/`. Point-in-time snapshots under `data/backups/` (30-day
sweep in the session sweeper) and Litestream replicas still contain the
tenant's rows and, for file backups of `/received`, the bytes until those
backups rotate. GDPR-style erasure of backups is an operator job, not an
API.

Retry DELETE if purge fails (the row is already gone; leftover retry
removes the directory). An unknown key with no leftover directory is 404
and does not touch disk. A leftover directory is retried only when no
default-tenant link has `dest` equal to that key or prefixed by `key/`;
otherwise DELETE returns 409 and leaves the folder (a default-tenant dest
of the same name lives at the receive root).

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

Default-tenant admins edit notification URLs, retention days, default
quotas, and the sign-in disclosure from the System page. Those values
overlay environment variables via `GET`/`PUT /api/admin/settings`
(`X-Votport` on PUT). Env remains the boot default; a written key wins;
`""` disables a URL or token; JSON `null` ("Use environment") deletes the
row so env applies again. See [`enterprise-ops.md`](enterprise-ops.md).

## Metrics

`GET /metrics` serves Prometheus-format counters and gauges (tenants, links,
received bytes, active sessions, audit rows). Set `VOTPORT_METRICS_TOKEN` to
require a bearer token, and scrape it over an internal interface only.

## Content lifecycle

Set `VOTPORT_UPLOAD_RETENTION_DAYS` to delete received files (and their
records' live status) older than N days, swept daily with audit events.
`VOTPORT_AUDIT_RETENTION_DAYS` (default 400) prunes audit rows the same way.
Upload retention defaults to keeping everything; audit rows default to
400 days.
