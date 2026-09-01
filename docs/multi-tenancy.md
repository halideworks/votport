# Multi-tenancy design

Status: phases 1-5 shipped (#23 store, #24 audit, #25 SSO, #26 tenants,
#27 ops polish) plus the multi-page admin (#28). Phases 6+ shipped (settings
overlay, SMTP, SSO discovery retry, principals/revoke, tenant purge, backup
streaming). Design: [`enterprise-ops.md`](enterprise-ops.md). Per-link legal
hold is also shipped. Automation tokens shipped for one route, optionally confined to a library folder.
Each phase landed as its own PR with the standard gate (fmt, clippy -D
warnings, tests, e2e, docker build) and review.

## Goal

One votport instance, many isolated tenants: an enterprise deploys once, gives each
team its own admins, request links, receive folder, and quotas, and gets an audit
trail its security department accepts. Homelab users run exactly one tenant and see
no new required configuration.

## What a tenant is

A tenant is an isolated namespace:

- its own admins (via SSO group/claim mapping),
- its own request links, upload history, and session events,
- its own receive subtree `<receive_dir>/.vot-tenants.stage/<tenant>/...`,
- its own byte quota and concurrent-session cap.

Tenants never share links, files, history, or quota. There is no cross-tenant
sharing feature; if two teams need the same drop folder, that is one tenant.

## Phase 1: SQLite store (no behavior change)

`state.json` is one mutex-guarded JSON document rewritten per mutation. It cannot
carry per-tenant rows, an append-only audit log, or concurrent writers. Replace the
implementation, not the API.

- rusqlite (bundled SQLite, WAL mode), one database file `data/votport.db`.
- `Store` keeps its current method set; signatures gain no tenant concept yet.
- Schema began with `links`, `meta` (schema version), and an `audit_log` table
  written from phase 2. Completed uploads and capped session events remain
  embedded in each link row; schema v7 adds an exact-byte `files` projection
  for quota and holdings accounting, updated atomically by upload append and
  file deletion. Full history normalization remains deferred until the
  embedded representation measurably limits a deployment.
- Migration: whenever legacy `state.json` remains, import it with idempotent
  inserts and rename it to `state.json.imported`. This safely resumes a crash
  after the database commit but before the rename. The importer runs before the
  listener binds; a failed import refuses startup rather than dropping links.
- `persist()`'s temp-file-plus-fsync dance disappears; SQLite WAL + `synchronous
  FULL` gives the same durability with less code.

Why not later: every subsequent phase (audit log, tenancy, quotas) needs rows, and
retrofitting tenancy onto the JSON document twice is wasted work.

## Phase 2: Queryable audit log

The tracing `audit` target stays as the operational record. Core security and
lifecycle request paths also insert best-effort rows into
`audit_log(at, tenant, actor, event, subject, detail)`; a database failure can
still leave only the tracing event.

- Retention: `VOTPORT_AUDIT_RETENTION_DAYS` (default 400), swept daily.
- Export: `GET /api/admin/audit?since=...&after_rowid=...&limit=...` returns a
  capped, buffered JSONL page with a stable cursor, a format SIEMs ingest
  without conversion.
- Login, link lifecycle, file deletion, password-change, and upload-completion
  request paths persist rows alongside their tracing events.

## Phase 3: OIDC admin auth (local auth stays)

- Config: `VOTPORT_OIDC_ISSUER`, `VOTPORT_OIDC_CLIENT_ID`, and
  `VOTPORT_OIDC_CLIENT_SECRET`. Authorization-code flow uses PKCE; discovery is
  lazy and retries after a cooldown when the provider is unavailable.
- SSO session cookies are stateless HMAC tokens containing the subject, grants,
  and `credential_version`. Explicit principal revoke bumps that version and
  blocks new sessions. Group changes apply on the next login; revoke existing
  sessions when a grant must disappear immediately.
- Tenant mapping uses the OIDC `groups` claim against configured platform groups
  and each tenant's `admin_group`. `viewer` gets read-only admin routes (enforced
  by `require_admin_write`); `auditor` (VOTPORT_OIDC_AUDITOR_GROUP) sees only
  the audit trail, enforced by `require_operator` on every other read route.
  Finer roles stay deferred until a concrete use case.
  SAML is out of scope: OIDC covers every provider named above, and SAML-in-front
  of an OIDC bridge is the standard enterprise answer.
- Local password auth remains the zero-config default and the break-glass path;
  it grants platform access, and changing the password invalidates its existing
  cookies. When OIDC is configured, the login page offers SSO first.
- CSRF posture unchanged (custom header on mutations).

## Phase 4: Tenant scoping and quotas

- Every `Link` gains `tenant`. Named-tenant link and audit reads use the tenant
  from the authenticated context; authorized platform administration,
  retention, and metrics may span tenants explicitly. Public link metadata uses
  the unguessable link id as a capability, while any configured link password
  gates authorization and session creation.
- Path layout: named tenants publish under the reserved
  `<receive_dir>/.vot-tenants.stage/<tenant>/<dest>/...` subtree; the default
  tenant retains the receive root layout. The existing `admit_dest` +
  `join_under` guards apply unchanged below the server-chosen tenant prefix.
- Quotas per tenant: `max_total_bytes` (sum of live uploads), `max_sessions`
  (concurrent, enforced next to `MAX_SESSIONS_PER_LINK`), `max_links`. Session
  admission atomically combines SQL-accounted live bytes with every in-flight
  session's announced-byte reservation under the same lock that enforces
  tenant, link, and global session caps. Cancellation-safe leases retain those
  reservations until queued worker commands actually finish.
- Admin UI: tenant switcher for admins with multiple tenant roles; otherwise the
  UI is unchanged. Senders see nothing new.

## Phase 5: Operations polish

- Backup story documented and tested: `VACUUM INTO` snapshot endpoint or documented
  sqlite3 command; received files are plain files, already backup-friendly.
- Optional: litestream recipe in the deployment guide.
- Per-tenant metrics lines on a plain-text `/metrics` (counts only, no new framework).
- Platform-admin `GET /api/admin/holdings` returns grouped link and live-byte
  totals from the schema-v7 SQL file projection.
- Deployment guide: single instance behind Caddy, volume layout, SSO setup with
  two worked examples (Authentik, Entra ID).
- Upload-content lifecycle: `VOTPORT_UPLOAD_RETENTION_DAYS` (off by default) with
  a daily sweep deleting expired received files and tombstoning their file
  records, emitting audit events; audit retention alone does not answer "how
  long does received data live", which every security review asks.

## Per-tenant branding

Recipient-facing surfaces can carry a tenant's identity instead of the stock
VOTPort look. Branding is a display name, an accent color (`#rrggbb`), and an
optional logo (PNG, JPEG, or SVG, 512 KiB cap) stored per tenant; the default
tenant is branded from the System page, named tenants from their card on the
Tenants page (tenant admins may also set their own via
`/api/admin/branding/<key>`). The request/upload page, the download page, and
notification titles use the brand name, falling back to the tenant label,
falling back to today's appearance; logos are served on token-scoped public
routes that expose exactly what the link or grant metadata already exposes,
including password gating. Branding covers presentation only: it changes no
paths, quotas, tokens, or verification behavior, and custom domains remain out
of scope (see `docs/deployment.md`).

## Threat-model deltas

| Change | Mitigation |
| --- | --- |
| Cross-tenant path escape | Tenant prefix is server-chosen below the reserved `.vot-tenants.stage` subtree; `join_under` rejects traversal components; stored records remain server-generated |
| Cross-tenant data read | Named-tenant link and audit reads are scoped; authorized platform admins may aggregate across tenants. The capability id exposes public link metadata, while any configured link password gates session creation |
| Tenant admin confusion | SSO cookie MAC covers the embedded grants; group changes apply on next login, while explicit revoke invalidates existing sessions |
| Audit tampering | Audit rows are insert-only from the request path; no admin route deletes them; retention prune is the only writer |
| Cross-tenant noisy-neighbor DoS | `IpThrottle` and `SessionRate` remain shared IP-keyed controls; per-tenant session caps and atomic byte reservations bound each tenant's admitted work |
| Tenant offboarding and erasure | Pin on the Sessions mutex so `insert` and named-tenant outbound operations fail; register then spawn; drop the tenant row and its outbound grants and automation tokens atomically; purge `<receive>/.vot-tenants.stage/<tenant>/` and `<outbound>/.vot-tenants.stage/<tenant>/` via `join_under`; emit `tenant_deleted` with `purged_receive` and `purged_outbound`. DELETE on an absent key is leftover retry only when either directory exists and no default-tenant dest collides; unknown key with no directories is 404. Snapshots under `data/backups/` (30-day sweep) and Litestream replicas retain rows until they rotate; received and outbound file backups retain bytes until they rotate. See `docs/deployment.md`. |
| OIDC provider outage | One platform local password (`AdminIdentity::local_admin`). `require_admin` expands its grants to every named tenant. Named tenants have no separate password. |

## Non-goals

- Per-tenant encryption keys (files at rest are the operator's volume concern).
- Tenant self-registration; tenants are provisioned by mapping, not signup.
- Cross-tenant sharing, public API tokens, per-tenant custom domains.
- Horizontal scaling: one writer (SQLite) is a feature at this scale; if a deploy
  ever outgrows one node, the `Store` struct is the seam (a trait gets introduced
  only when a second backend actually exists).
- Public API tokens: `POST /api/automation/share` accepts per-tenant bearer
  tokens with expiry, revocation, a per-IP rate limit, an optional folder
  scope, and audit rows for use and token refusal.

## Deliberately unchanged

The single-binary, Caddy-fronted deployment. Env remains the boot default;
System overlays notify, retention, and default quotas. An enterprise should be
able to `docker compose up` this behind their SSO and pass a security review, and a
homelabber should never learn the word "tenant".
