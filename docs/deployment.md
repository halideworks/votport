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

Two pieces to back up, on different schedules:

1. **Database**: `GET /api/admin/backup` (admin session) streams a consistent
   snapshot produced by SQLite's `VACUUM INTO`. Manually:

   ```sh
   sqlite3 data/votport.db ".backup data/backups/manual.db"
   ```

2. **Received files**: plain files under `/received` — any file-level backup
   tool works. Back them up together with a database snapshot so records and
   bytes stay consistent with each other.

Restore: stop the container, replace `data/votport.db` with the snapshot,
restore the files, start. A [litestream](https://litestream.io) recipe works as
-is against `data/votport.db` (replicate on, restore before container start).

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
remains available as break-glass access.

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

## Metrics

`GET /metrics` serves Prometheus-format counters and gauges (tenants, links,
received bytes, active sessions, audit rows). Set `VOTPORT_METRICS_TOKEN` to
require a bearer token, and scrape it over an internal interface only.

## Content lifecycle

Set `VOTPORT_UPLOAD_RETENTION_DAYS` to delete received files (and their
records' live status) older than N days, swept daily with audit events.
`VOTPORT_AUDIT_RETENTION_DAYS` (default 400) prunes audit rows the same way.
Both default to keeping everything.
