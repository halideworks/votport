# Multi-tenancy design

Status: phases 1-3 shipped (#23 SQLite store, #24 audit log, #25 OIDC SSO);
phases 4-5 designed below. Each phase lands as its own PR with the
standard gate (fmt, clippy -D warnings, tests, e2e, docker build) and review.

## Goal

One votport instance, many isolated tenants: an enterprise deploys once, gives each
team its own admins, request links, receive folder, and quotas, and gets an audit
trail its security department accepts. Homelab users run exactly one tenant and see
no new required configuration.

## What a tenant is

A tenant is an isolated namespace:

- its own admins (via SSO group/claim mapping),
- its own request links, upload history, and session events,
- its own receive subtree `<receive_dir>/<tenant>/...`,
- its own byte quota and concurrent-session cap.

Tenants never share links, files, history, or quota. There is no cross-tenant
sharing feature; if two teams need the same drop folder, that is one tenant.

## Phase 1: SQLite store (no behavior change)

`state.json` is one mutex-guarded JSON document rewritten per mutation. It cannot
carry per-tenant rows, an append-only audit log, or concurrent writers. Replace the
implementation, not the API.

- rusqlite (bundled SQLite, WAL mode), one database file `data/votport.db`.
- `Store` keeps its current method set; signatures gain no tenant concept yet.
- Schema: `links`, `uploads`, `files`, `meta` (schema version), plus an
  `audit_log` table created now but written only from phase 2. Session events
  stay embedded in the `links` row exactly as today (`Link.events`, capped) —
  splitting them into a table changes the read API, so that moves to phase 2
  with the audit work. Foreign keys on, `busy_timeout` set.
- Migration: if `state.json` exists and the DB is absent, import and rename the
  JSON to `state.json.imported`. The importer runs before the listener binds; a
  failed import refuses startup rather than silently dropping links.
- `persist()`'s temp-file-plus-fsync dance disappears; SQLite WAL + `synchronous
  FULL` gives the same durability with less code.

Why not later: every subsequent phase (audit log, tenancy, quotas) needs rows, and
retrofitting tenancy onto the JSON document twice is wasted work.

## Phase 2: Queryable audit log

The tracing `audit` target stays (operators grep logs), and every audit event is
also inserted into `audit_log(at, tenant, actor, event, subject, detail_json)`.

- Retention: `VOTPORT_AUDIT_RETENTION_DAYS` (default 400), swept daily.
- Export: admin endpoint `GET /api/admin/audit?since=...` streams JSONL, the format
  SIEMs ingest without conversion.
- Login attempts, link lifecycle, file deletions, password changes, and upload
  completions all land here with the client IP already captured by `client_ip`.

## Phase 3: OIDC admin auth (local auth stays)

- Config: `VOTPORT_OIDC_ISSUER`, `VOTPORT_OIDC_CLIENT_ID`, secret file ref.
  Authorization-code flow with PKCE; discovery document fetched at boot.
- The admin session cookie stays a stateless HMAC token, but its MAC now covers
  `(subject, tenant, role, credential_version)` instead of the password hash.
  `credential_version` bumps on a local password change (preserving today's
  guarantee that changing the break-glass password evicts every session) and on
  role or tenant-mapping changes, reusing the existing binding trick.
- Tenant mapping: the `tenant` claim if present, else group-to-tenant mapping in
  the DB, else the single default tenant. Role: `admin` or `viewer` from claims;
  `viewer` gets read-only admin routes (enforced where `require_admin_write`
  sits today); finer roles are deferred until someone asks with a use case.
  SAML is out of scope: OIDC covers every provider named above, and SAML-in-front
  of an OIDC bridge is the standard enterprise answer.
- Local password auth remains the zero-config default and the break-glass path;
  it maps to the default tenant. When OIDC is configured, the login page offers
  SSO first.
- CSRF posture unchanged (custom header on mutations).

## Phase 4: Tenant scoping and quotas

- Every `Link` gains `tenant`. Every store query takes the tenant from the
  authenticated context; the store API makes unscoped queries unrepresentable
  (methods take `tenant: &str`, no method lists all tenants' links).
- Path layout: published files land under `<receive_dir>/<tenant>/<dest>/...`.
  The existing `admit_dest` + `join_under` guards apply unchanged below the
  tenant prefix, so the traversal story is: tenant prefix is server-chosen,
  everything under it already proven safe.
- Quotas per tenant: `max_total_bytes` (sum of live uploads), `max_sessions`
  (concurrent, enforced next to `MAX_SESSIONS_PER_LINK`), `max_links`. Enforced
  in `create_session`/`create_link` alongside the existing per-link caps and the
  per-IP `SessionRate`. Known bounded race: concurrent sessions each pass the
  byte-quota check before uploading, so the total can overshoot by up to
  (max_sessions - 1) x per-session cap mid-transfer; chunks are merkle-verified
  against the announced size, so a lying announcement fails verification rather
  than consuming quota.
- Admin UI: tenant switcher for admins with multiple tenant roles; otherwise the
  UI is unchanged. Senders see nothing new.

## Phase 5: Operations polish

- Backup story documented and tested: `VACUUM INTO` snapshot endpoint or documented
  sqlite3 command; received files are plain files, already backup-friendly.
- Optional: litestream recipe in the deployment guide.
- Per-tenant metrics lines on a plain-text `/metrics` (counts only, no new framework).
- Deployment guide: single instance behind Caddy, volume layout, SSO setup with
  two worked examples (Authentik, Entra ID).
- Upload-content lifecycle: `VOTPORT_UPLOAD_RETENTION_DAYS` (off by default) with
  a daily sweep deleting expired received files and their records, emitting audit
  events; audit retention alone does not answer "how long does received data
  live", which every security review asks.

## Threat-model deltas

| Change | Mitigation |
| --- | --- |
| Cross-tenant path escape | Tenant prefix is server-chosen; `join_under` guard already rejects traversal components; stored records remain server-generated |
| Cross-tenant data read | Tenant is in every store query signature, not remembered by callers; token MAC binds tenant |
| Tenant admin confusion | Cookie MAC covers `(subject, tenant, role)`; switching tenant re-issues the cookie |
| Audit tampering | Audit rows are insert-only from the request path; no admin route deletes them; retention prune is the only writer |
| Cross-tenant noisy-neighbor DoS | Today's `IpThrottle`, `SessionRate`, and session caps are shared buckets; phase 4 adds per-tenant throttle buckets and per-tenant session caps alongside them |
| Tenant offboarding and erasure | Tenant deletion purges store rows and the receive subtree, emits an audit tombstone; backup docs cover per-tenant restore (GDPR-style erasure is a standard security-review ask) |
| OIDC provider outage | Local break-glass account per tenant, created at first boot, password rotated on first login |

## Non-goals

- Per-tenant encryption keys (files at rest are the operator's volume concern).
- Tenant self-registration; tenants are provisioned by mapping, not signup.
- Cross-tenant sharing, public API tokens, per-tenant custom domains.
- Horizontal scaling: one writer (SQLite) is a feature at this scale; if a deploy
  ever outgrows one node, the `Store` struct is the seam (a trait gets introduced
  only when a second backend actually exists).
- Public API tokens: automation integration is a real enterprise ask, but tokens
  that can create links bypass the human-rate assumptions of every throttle here;
  they deserve their own design with scoped grants, not a phase-4 leftover.

## Deliberately unchanged

The single-binary, env-configured, Caddy-fronted deployment. An enterprise should be
able to `docker compose up` this behind their SSO and pass a security review, and a
homelabber should never learn the word "tenant".
