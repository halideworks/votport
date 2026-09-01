//! Admin management API: sign-in, request links, received-file management.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::io::ReaderStream;

use crate::app::App;
use crate::auth;
use crate::paths;
use crate::store::{now_unix, AuditFilters, Link, LinkCursor};

use super::{cookie_attributes, ApiError, ApiResult};

const ADMIN_COOKIE: &str = "votport_admin";
const MAX_PASSWORD_BYTES: usize = 256;
const PRINCIPAL_PAGE_DEFAULT: usize = 50;
const PRINCIPAL_PAGE_MAX: usize = 100;

/// Signed admin cookie for a test identity; the shared body behind each
/// test module's `cookie_for`.
#[cfg(test)]
fn test_admin_cookie(app: &App, identity: &auth::AdminIdentity) -> String {
    format!(
        "votport_admin={}; Path=/",
        auth::issue_admin_token(&app.secret, identity, &admin_token_phc(app).unwrap())
    )
}

/// Credential tag bound into admin token MACs: the stored hash when the
/// UI has set one, else the stable tag derived from the environment
/// credential. Either way, rotating the credential evicts sessions and a
/// plain restart does not.
fn admin_token_phc(app: &App) -> ApiResult<String> {
    Ok(app
        .store
        .admin_password_hash()
        .map_err(super::store_unavailable)?
        .unwrap_or_else(|| app.config.admin_token_tag.clone()))
}

/// Returns the authenticated principal, or unauthorized.
pub(crate) fn require_admin(app: &App, headers: &HeaderMap) -> ApiResult<auth::AdminIdentity> {
    let token = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| auth::cookie_value(cookies, ADMIN_COOKIE));
    let mut identity = auth::verify_admin_token(
        &app.secret,
        &admin_token_phc(app)?,
        token.unwrap_or_default(),
    )
    .ok_or_else(ApiError::unauthorized)?;
    if identity.subject != "local"
        && !app
            .store
            .principal_allows(&identity.subject, identity.credential_version)
    {
        return Err(ApiError::unauthorized());
    }
    if identity.subject == "local" {
        identity.grants = local_admin_grants(app).map_err(super::store_unavailable)?;
        if !identity
            .grants
            .iter()
            .any(|grant| grant.tenant == identity.tenant)
        {
            identity.tenant = String::new();
            identity.role = "admin".to_owned();
        }
    }
    Ok(identity)
}

/// Read routes for operators: admins and viewers pass, auditors do not.
/// The auditor role sees only its own session and the audit trail; every
/// link, file, grant, and settings route goes through this gate instead of
/// bare `require_admin`.
pub(crate) fn require_operator(app: &App, headers: &HeaderMap) -> ApiResult<auth::AdminIdentity> {
    let identity = require_admin(app, headers)?;
    if identity.role == "auditor" {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "audit-only session"));
    }
    Ok(identity)
}

fn local_admin_grants(app: &App) -> Result<Vec<auth::TenantGrant>, String> {
    let mut grants = vec![auth::TenantGrant {
        tenant: String::new(),
        role: "admin".to_owned(),
    }];
    grants.extend(
        app.store
            .tenants()?
            .into_iter()
            .map(|tenant| auth::TenantGrant {
                tenant: tenant.key,
                role: "admin".to_owned(),
            }),
    );
    Ok(grants)
}

/// Default-tenant admin only. Same gate as database backup: viewers and
/// named-tenant admins cannot read platform configuration.
fn require_platform_admin(app: &App, headers: &HeaderMap) -> ApiResult<auth::AdminIdentity> {
    let identity = require_admin(app, headers)?;
    if !identity.tenant.is_empty() || identity.role != "admin" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "default-tenant admin required",
        ));
    }
    Ok(identity)
}

/// Mutating admin routes require the admin role AND a custom header;
/// cross-site forms cannot set one, which closes CSRF without token
/// bookkeeping. Viewers (SSO principals outside the admin group) get
/// read-only access.
pub(crate) fn require_admin_write(
    headers: &HeaderMap,
    identity: &auth::AdminIdentity,
) -> ApiResult<()> {
    if identity.role != "admin" {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "read-only session"));
    }
    if !headers.contains_key("x-votport") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "missing X-Votport header",
        ));
    }
    Ok(())
}

/// The admin password in force: a hash stored by "change password" wins over
/// the one derived from the environment at startup, so a restart does not roll
/// the password back to VOTPORT_ADMIN_PASSWORD.
fn admin_hash(app: &App) -> ApiResult<String> {
    Ok(app
        .store
        .admin_password_hash()
        .map_err(super::store_unavailable)?
        .unwrap_or_else(|| app.config.admin_password_hash.clone()))
}

/// Builds the signed admin session cookie value for `identity`. The local
/// break-glass subject keeps the fixed 7-day lifetime; SSO identities use
/// the adjustable one (VOTPORT_SSO_SESSION_SECS, overridable live from the
/// System page) so IdP-side offboarding latency is a policy knob.
pub(crate) fn issue_admin_cookie(app: &App, identity: &auth::AdminIdentity) -> ApiResult<String> {
    let ttl = if identity.subject == "local" {
        7 * 24 * 3600
    } else {
        app.store
            .overlay(&app.config)
            .map_err(super::store_unavailable)?
            .resolved
            .sso_session_secs
    };
    let token =
        auth::issue_admin_token_with_ttl(&app.secret, identity, &admin_token_phc(app)?, ttl);
    Ok(format!(
        "{ADMIN_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={ttl}{}",
        cookie_attributes(app)
    ))
}

/// Cookie attributes for non-admin cookies too (Secure behind https).
pub(crate) fn sso_cookie_attributes(app: &App) -> &'static str {
    cookie_attributes(app)
}

#[derive(Deserialize)]
pub struct LoginRequest {
    password: String,
}

pub async fn admin_login(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Response> {
    // Per IP first, because it is precise: a wrong password locks out the
    // address that typed it and nobody else. It cannot be the only bound,
    // because the key comes from a header a caller behind a private peer can
    // choose, and because one IPv6 client holds a whole prefix.
    let ip = super::client_ip(&headers, &peer, &app.config.trusted_proxies);
    let bucket = super::throttle_key(&ip);
    // Counted before the verify, not after: checking and then recording lets
    // any number of concurrent attempts pass the check together, which turns
    // five per window into five per connection the caller opens.
    if !app.login_throttle.claim(&bucket) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; wait a minute",
        ));
    }
    // Sign-in's own argon2 budget, and nothing global that can refuse or
    // delay a correct password. The permit moves into the blocking task, so
    // it is held for exactly as long as the verification runs: a client that
    // disconnects mid-verify would otherwise release it while the work, and
    // its memory, carried on.
    let permit = Arc::clone(&app.login_permits)
        .acquire_owned()
        .await
        .map_err(|_| ApiError::internal("login semaphore closed"))?;
    let ok = tokio::task::spawn_blocking({
        let hash = admin_hash(&app)?;
        move || {
            let _permit = permit;
            auth::verify_password(&request.password, &hash)
        }
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?;
    if ok {
        app.login_throttle.succeeded(&bucket);
    }
    if !ok {
        // peer is the socket address; ip is what the forwarded header named,
        // when it was believed. VOTPORT_TRUSTED_PROXIES wants the peer.
        tracing::warn!(target: "audit", event = "admin_login_failed", %ip, peer = %peer.ip(), "admin login refused");
        app.store
            .audit("", "", "admin_login_failed", &ip, &serde_json::json!({}));
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "wrong password"));
    }
    tracing::info!(target: "audit", event = "admin_login", %ip, "admin signed in");
    app.store
        .audit("", "", "admin_login", &ip, &serde_json::json!({}));
    let cookie = issue_admin_cookie(&app, &auth::AdminIdentity::local_admin())?;
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

pub async fn admin_logout(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Response> {
    // A cross-site form POST can force a logout (denial of convenience, not
    // of security); the CSRF header closes even that.
    let _identity = require_admin(&app, &headers)?;
    if !headers.contains_key("x-votport") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "missing X-Votport header",
        ));
    }
    let cookie = format!(
        "{ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        cookie_attributes(&app)
    );
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

/// Streams audit rows as JSONL. The legacy `since`/`after_rowid` mode is
/// oldest-first; `before_rowid` opts into recent-first pagination.
pub async fn admin_audit_export(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Response> {
    let identity = require_admin(&app, &headers)?;
    if query.before_rowid.is_some() && (query.since.is_some() || query.after_rowid.is_some()) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "before_rowid cannot be combined with since or after_rowid",
        ));
    }
    // Named-tenant principals see only their namespace's rows; the default
    // tenant (platform admin) sees everything.
    let tenant_filter = identity.tenant.clone();
    let limit = query.limit.unwrap_or(1000).min(10_000);
    let event = validate_audit_filter(query.event, "event")?;
    let search = validate_audit_filter(query.q, "q")?;
    let since = query.since;
    let after_rowid = query.after_rowid;
    let before_rowid = query.before_rowid;
    let store = Arc::clone(&app.store);
    let rows = tokio::task::spawn_blocking(move || {
        let filters = AuditFilters {
            event: event.as_deref(),
            query: search.as_deref(),
        };
        if let Some(before_rowid) = before_rowid {
            store.audit_recent_filtered(&tenant_filter, before_rowid, limit, filters)
        } else {
            store.audit_export_filtered(
                &tenant_filter,
                since.unwrap_or(0),
                after_rowid.unwrap_or(0),
                limit,
                filters,
            )
        }
    })
    .await
    .map_err(|_| ApiError::internal("audit query worker failed"))?
    .map_err(ApiError::internal)?;
    use std::fmt::Write as _;
    let mut body = String::new();
    for row in rows {
        let detail = row.detail;
        writeln!(
            body,
            "{}",
            serde_json::json!({
                "rowid": row.rowid,
                "at": row.at,
                "tenant": row.tenant,
                "actor": row.actor,
                "event": row.event,
                "subject": row.subject,
                "detail": detail,
            })
        )
        .map_err(|error| ApiError::internal(error.to_string()))?;
    }
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "application/x-ndjson; charset=utf-8",
        )],
        body,
    )
        .into_response())
}

/// Platform-wide link and live-byte totals without loading upload history.
pub async fn holdings(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    require_platform_admin(&app, &headers)?;
    let holdings = app.store.tenant_usage().map_err(ApiError::internal)?;
    Ok(Json(json!({ "holdings": holdings })))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    since: Option<u64>,
    /// Cursor for rows sharing `since`'s second (from the previous page's
    /// final `rowid`).
    after_rowid: Option<u64>,
    before_rowid: Option<u64>,
    limit: Option<u64>,
    event: Option<String>,
    q: Option<String>,
}

fn validate_audit_filter(value: Option<String>, name: &str) -> ApiResult<Option<String>> {
    let Some(value) = value else { return Ok(None) };
    if value.chars().count() > 100 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{name} must be at most 100 characters"),
        ));
    }
    let value = value.trim().to_owned();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

pub async fn admin_session(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_admin(&app, &headers)?;
    // Which dashboard pages this principal may open. Named tenants get their
    // own links plus a tenant-filtered audit view; platform administration
    // (tenants, system) is default-tenant admin only.
    let mut pages = if identity.role == "auditor" {
        vec!["audit"]
    } else {
        vec!["receive", "deliver", "audit"]
    };
    if identity.tenant.is_empty() && identity.role == "admin" {
        pages.push("tenants");
        pages.push("system");
    }
    Ok(Json(json!({
        "ok": true,
        "tenant": identity.tenant,
        "grants": identity.grants,
        "pages": pages,
    })))
}

#[derive(Deserialize)]
pub struct CreateTenantRequest {
    key: String,
    label: String,
    #[serde(default)]
    admin_group: Option<String>,
    #[serde(default)]
    max_total_bytes: Option<u64>,
    #[serde(default)]
    max_links: Option<u64>,
    #[serde(default)]
    max_sessions: Option<u64>,
}

/// Admits a tenant key for lookup: destination rules plus the reserved names.
/// Multi-segment keys pass here so a namespace stored before
/// [`admit_tenant_key`] existed can still be deleted.
fn admit_tenant_ref(key: &str) -> ApiResult<String> {
    let key = paths::admit_dest(key)
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    if key.is_empty() || key == "default" {
        // "default" would collide with the hard-coded metrics series for the
        // built-in namespace.
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "that tenant key is reserved",
        ));
    }
    Ok(key)
}

/// Admits a portable tenant key for creation. Legacy keys remain addressable
/// through `admit_tenant_ref`, but new on-disk namespaces are lowercase ASCII
/// so case-insensitive and normalization-insensitive filesystems agree.
fn admit_tenant_key(key: &str) -> ApiResult<String> {
    let key = admit_tenant_ref(key)?;
    if !paths::portable_tenant_key(&key) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "tenant key must use lowercase ASCII letters, digits, '-' or '_'",
        ));
    }
    Ok(key)
}

/// Creates a tenant namespace. Admins only; the key becomes a folder name in
/// the reserved tenant-storage subtree.
pub async fn create_tenant(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<CreateTenantRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let key = admit_tenant_key(&request.key)?;
    if app.sessions.tenant_pinned(&key) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "tenant delete already in progress",
        ));
    }
    let defaults = app
        .store
        .resolved_settings(&app.config)
        .map_err(super::store_unavailable)?;
    let tenant = crate::store::Tenant {
        key: key.clone(),
        label: request.label.trim().to_owned(),
        admin_group: request.admin_group.filter(|group| !group.trim().is_empty()),
        max_total_bytes: request
            .max_total_bytes
            .or(defaults.default_max_total_bytes)
            .filter(|&bytes| bytes > 0),
        max_links: request
            .max_links
            .or(defaults.default_max_links)
            .filter(|&links| links > 0),
        max_sessions: request
            .max_sessions
            .or(defaults.default_max_sessions)
            .filter(|&sessions| sessions > 0),
        created_at: now_unix(),
    };
    app.store
        .insert_tenant(tenant)
        .map_err(|error| match error {
            crate::store::InsertTenantError::AlreadyExists => {
                ApiError::new(StatusCode::CONFLICT, "tenant already exists")
            }
            crate::store::InsertTenantError::Store(message) => ApiError::internal(message),
        })?;
    tracing::info!(target: "audit", event = "tenant_created", key = %key, "tenant namespace created");
    app.store
        .audit("", &identity.subject, "tenant_created", &key, &json!({}));
    Ok(Json(json!({ "key": key })))
}

pub async fn list_tenants(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let _identity = require_platform_admin(&app, &headers)?;
    let (principals, total) = app
        .store
        .principals_page(PRINCIPAL_PAGE_DEFAULT, 0, None)
        .map_err(super::store_unavailable)?;
    Ok(Json(json!({
        "tenants": app.store.tenants().map_err(super::store_unavailable)?,
        "principals": principals,
        "principals_truncated": total > PRINCIPAL_PAGE_DEFAULT as u64,
    })))
}

#[derive(Deserialize)]
pub struct PrincipalsQuery {
    limit: Option<String>,
    offset: Option<String>,
    q: Option<String>,
}

pub async fn list_principals(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<PrincipalsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let _identity = require_platform_admin(&app, &headers)?;
    let limit = query
        .limit
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "limit must be an integer between 1 and 100",
            )
        })?
        .unwrap_or(PRINCIPAL_PAGE_DEFAULT);
    if !(1..=PRINCIPAL_PAGE_MAX).contains(&limit) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "limit must be between 1 and 100",
        ));
    }
    let offset = query
        .offset
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "offset must be a non-negative integer",
            )
        })?
        .unwrap_or(0usize);
    if i64::try_from(offset).is_err() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "offset is too large",
        ));
    }
    let query = query.q.filter(|value| !value.is_empty());
    if query
        .as_ref()
        .is_some_and(|value| value.chars().count() > 100)
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "q must be at most 100 characters",
        ));
    }
    let (principals, total) = app
        .store
        .principals_page(limit, offset, query.as_deref())
        .map_err(super::store_unavailable)?;
    let has_more = u64::try_from(offset)
        .unwrap_or(u64::MAX)
        .saturating_add(principals.len() as u64)
        < total;
    Ok(Json(json!({
        "principals": principals,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
    })))
}

#[derive(Deserialize)]
pub struct PrincipalSubjectRequest {
    subject: String,
}

pub async fn revoke_principal(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<PrincipalSubjectRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    mutate_principal(&app, &identity.subject, &request.subject, true)
}

pub async fn unblock_principal(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<PrincipalSubjectRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    mutate_principal(&app, &identity.subject, &request.subject, false)
}

fn mutate_principal(
    app: &App,
    actor: &str,
    subject: &str,
    revoke: bool,
) -> ApiResult<Json<serde_json::Value>> {
    let subject = subject.trim();
    if subject.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "subject is required",
        ));
    }
    if subject == "local" {
        let action = if revoke { "revoke" } else { "unblock" };
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("cannot {action} the local administrator"),
        ));
    }
    let changed = if revoke {
        app.store.revoke_principal(subject)
    } else {
        app.store.unblock_principal(subject)
    }
    .map_err(ApiError::internal)?;
    if !changed {
        return Err(ApiError::not_found());
    }
    let event = if revoke {
        "principal_revoked"
    } else {
        "principal_unblocked"
    };
    tracing::info!(target: "audit", event, subject = %subject, "principal updated");
    app.store.audit("", actor, event, subject, &json!({}));
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_tenant(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let key = admit_tenant_ref(&key)?;
    if !app.sessions.pin_tenant_for_delete(&key) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "tenant delete already in progress",
        ));
    }
    let count = match app.store.tenant_link_count(&key) {
        Ok(count) => count,
        Err(error) => {
            app.sessions.unpin_tenant(&key);
            return Err(super::store_unavailable(error));
        }
    };
    if count > 0 {
        app.sessions.unpin_tenant(&key);
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("{count} link(s) still reference this tenant; delete them first"),
        ));
    }
    let active = app.sessions.active_for_tenant(&key);
    let outbound_active = app.sessions.active_outbound_for_tenant(&key);
    if active > 0 || outbound_active > 0 {
        app.sessions.unpin_tenant(&key);
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!(
                "{} operation(s) are in flight; try again when they finish",
                active + outbound_active
            ),
        ));
    }
    // The subtrees this delete would purge, if there are any. A key with a
    // separator was never usable as a namespace, and neither root is valid.
    let purge_targets = if purges_tenant_subtrees(&key) {
        let receive = match tenant_receive_dir(&app.config.receive_dir, &key) {
            Ok(path) if path.is_dir() => Some(path),
            Ok(_) => None,
            Err(error) => {
                app.sessions.unpin_tenant(&key);
                return Err(ApiError::internal(error));
            }
        };
        let outbound = match tenant_outbound_dir(&app.config.outbound_dir, &key) {
            Ok(path) if path.is_dir() => Some(path),
            Ok(_) => None,
            Err(error) => {
                app.sessions.unpin_tenant(&key);
                return Err(ApiError::internal(error));
            }
        };
        (receive, outbound)
    } else {
        (None, None)
    };
    // Read before the row delete cascades the branding row away.
    let logo_ext = app
        .store
        .branding(&key)
        .ok()
        .flatten()
        .map(|branding| branding.logo_ext)
        .filter(|ext| !ext.is_empty());
    use crate::store::TenantRemoval;
    let row_deleted = match app.store.remove_tenant(&key) {
        Ok(TenantRemoval::Deleted) => true,
        Ok(TenantRemoval::HasLinks) => {
            app.sessions.unpin_tenant(&key);
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "a link was created concurrently; delete them first",
            ));
        }
        Ok(TenantRemoval::Absent) => {
            if purge_targets.0.is_none() && purge_targets.1.is_none() {
                app.sessions.unpin_tenant(&key);
                return Err(ApiError::not_found());
            }
            false
        }
        Err(error) => {
            app.sessions.unpin_tenant(&key);
            return Err(ApiError::internal(error));
        }
    };
    let purged_receive = purge_targets.0.is_some();
    let purged_outbound = purge_targets.1.is_some();
    for (name, path) in [("receive", purge_targets.0), ("outbound", purge_targets.1)].into_iter() {
        let Some(path) = path else { continue };
        #[cfg(test)]
        if name == "receive" {
            app.sessions.wait_delete_stall().await;
        }
        let purge = tokio::fs::remove_dir_all(&path).await;
        match purge {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && row_deleted => {}
            Err(error) => {
                tracing::error!(
                    key = %key,
                    subtree = name,
                    error = %error,
                    "tenant subtree purge failed"
                );
                app.sessions.unpin_tenant(&key);
                return Err(ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "tenant subtree purge failed; retry DELETE",
                ));
            }
        }
    }
    if row_deleted {
        if let Some(ext) = logo_ext {
            let stale = paths::branding_logo_path(&app.config.data_dir, &key, &ext);
            let _ = tokio::fs::remove_file(stale).await;
        }
    }
    app.sessions.unpin_tenant(&key);
    tracing::info!(target: "audit", event = "tenant_deleted", key = %key, "tenant namespace deleted");
    app.store.audit(
        "",
        &identity.subject,
        "tenant_deleted",
        &key,
        &json!({
            "purged_receive": purged_receive,
            "purged_outbound": purged_outbound,
            "row_deleted": row_deleted
        }),
    );
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct PatchTenantRequest {
    #[serde(default)]
    label: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    admin_group: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    max_total_bytes: Option<Option<u64>>,
    #[serde(default, deserialize_with = "double_option")]
    max_links: Option<Option<u64>>,
    #[serde(default, deserialize_with = "double_option")]
    max_sessions: Option<Option<u64>>,
}

fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(deserializer)?))
}

fn patch_quota(field: &str, value: Option<u64>) -> ApiResult<Option<u64>> {
    match value {
        None => Ok(None),
        Some(0) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{field} must be greater than zero"),
        )),
        Some(n) => Ok(Some(n)),
    }
}

/// Updates label, admin group, or quotas on an existing tenant. The key is
/// a folder name and cannot be renamed here.
pub async fn update_tenant(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PatchTenantRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let Some(mut tenant) = app.store.tenant(&key).map_err(super::store_unavailable)? else {
        return Err(ApiError::not_found());
    };
    if let Some(label) = request.label {
        tenant.label = label.trim().to_owned();
    }
    if let Some(group) = request.admin_group {
        tenant.admin_group = group
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_owned());
    }
    if let Some(bytes) = request.max_total_bytes {
        tenant.max_total_bytes = patch_quota("max_total_bytes", bytes)?;
    }
    if let Some(links) = request.max_links {
        tenant.max_links = patch_quota("max_links", links)?;
    }
    if let Some(sessions) = request.max_sessions {
        tenant.max_sessions = patch_quota("max_sessions", sessions)?;
    }
    if !app
        .store
        .update_tenant(&tenant)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "tenant_updated", key = %key, "tenant namespace updated");
    app.store.audit(
        "",
        &identity.subject,
        "tenant_updated",
        &key,
        &json!({
            "label": tenant.label,
            "admin_group": tenant.admin_group,
            "max_total_bytes": tenant.max_total_bytes,
            "max_links": tenant.max_links,
            "max_sessions": tenant.max_sessions,
        }),
    );
    Ok(Json(json!({ "ok": true })))
}

/// Hard cap on stored logo bytes; the route body limit adds header slack.
pub(crate) const MAX_LOGO_BYTES: usize = 512 * 1024;

/// Maps the branding path key to a stored tenant: "default" is the default
/// tenant (""), anything else must name an existing tenant row.
fn branding_tenant(app: &App, key: &str, identity: &auth::AdminIdentity) -> ApiResult<String> {
    let tenant = if key == "default" {
        String::new()
    } else {
        admit_tenant_ref(key)?
    };
    // Grant check before the store lookup: a foreign admin learns nothing
    // about which tenant keys exist.
    if !identity
        .grants
        .iter()
        .any(|grant| grant.role == "admin" && (grant.tenant == tenant || grant.tenant.is_empty()))
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "no admin access to that tenant",
        ));
    }
    if !tenant.is_empty()
        && app
            .store
            .tenant(&tenant)
            .map_err(super::store_unavailable)?
            .is_none()
    {
        return Err(ApiError::not_found());
    }
    Ok(tenant)
}

fn admit_brand_color(color: &str) -> ApiResult<()> {
    let valid = color.is_empty()
        || (color.len() == 7
            && color.starts_with('#')
            && color.bytes().skip(1).all(|byte| byte.is_ascii_hexdigit()));
    if valid {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "color must be empty or #rrggbb",
        ))
    }
}

/// Audit subject for branding events; the default tenant has no key to name.
fn branding_subject(tenant: &str) -> &str {
    if tenant.is_empty() {
        "default"
    } else {
        tenant
    }
}

/// Current branding for the admin form. Empty fields when no row exists.
pub async fn get_branding(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    let tenant = branding_tenant(&app, &key, &identity)?;
    let branding = app
        .store
        .branding(&tenant)
        .map_err(super::store_unavailable)?;
    Ok(Json(match branding {
        Some(branding) => json!({
            "name": branding.name,
            "color": branding.color,
            "has_logo": !branding.logo_ext.is_empty(),
        }),
        None => json!({ "name": "", "color": "", "has_logo": false }),
    }))
}

#[derive(Deserialize)]
pub struct PutBrandingRequest {
    name: String,
    #[serde(default)]
    color: String,
}

/// Sets a tenant's recipient-facing name and accent color. The logo has its
/// own PUT; its stored extension survives this write.
pub async fn put_branding(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PutBrandingRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let tenant = branding_tenant(&app, &key, &identity)?;
    admit_brand_color(&request.color)?;
    let logo_ext = app
        .store
        .branding(&tenant)
        .map_err(super::store_unavailable)?
        .map(|branding| branding.logo_ext)
        .unwrap_or_default();
    let branding = crate::store::Branding {
        tenant: tenant.clone(),
        name: request.name.trim().to_owned(),
        color: request.color,
        logo_ext,
        updated_at: now_unix(),
    };
    app.store
        .set_branding(&branding)
        .map_err(ApiError::internal)?;
    tracing::info!(target: "audit", event = "branding_updated", tenant = %tenant, "tenant branding updated");
    app.store.audit(
        &tenant,
        &identity.subject,
        "branding_updated",
        branding_subject(&tenant),
        &json!({ "name": branding.name, "color": branding.color }),
    );
    Ok(Json(json!({ "ok": true })))
}

/// Removes a tenant's branding row and any stored logo file.
pub async fn delete_branding(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let tenant = branding_tenant(&app, &key, &identity)?;
    let logo_ext = app
        .store
        .branding(&tenant)
        .map_err(super::store_unavailable)?
        .map(|branding| branding.logo_ext)
        .ok_or_else(ApiError::not_found)?;
    app.store
        .delete_branding(&tenant)
        .map_err(ApiError::internal)?;
    if !logo_ext.is_empty() {
        let path = paths::branding_logo_path(&app.config.data_dir, &tenant, &logo_ext);
        let _ = tokio::fs::remove_file(path).await;
    }
    tracing::info!(target: "audit", event = "branding_deleted", tenant = %tenant, "tenant branding removed");
    app.store.audit(
        &tenant,
        &identity.subject,
        "branding_deleted",
        branding_subject(&tenant),
        &json!({}),
    );
    Ok(Json(json!({ "ok": true })))
}

/// Declared logo type checked against the leading bytes. SVG has no magic
/// and is stored as declared; the serving CSP is what keeps it inert.
fn admit_logo(headers: &HeaderMap, bytes: &[u8]) -> ApiResult<&'static str> {
    let declared = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).trim().to_owned())
        .unwrap_or_default();
    let (ext, sniffed) = match declared.as_str() {
        "image/png" => ("png", bytes.starts_with(b"\x89PNG\r\n\x1a\n")),
        "image/jpeg" => ("jpg", bytes.starts_with(b"\xff\xd8\xff")),
        "image/svg+xml" => ("svg", true),
        _ => {
            return Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "logo must be image/png, image/jpeg, or image/svg+xml",
            ));
        }
    };
    if !sniffed {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "logo bytes do not match the declared type",
        ));
    }
    Ok(ext)
}

/// Stores a tenant logo, replacing any previous one atomically.
pub async fn put_branding_logo(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let tenant = branding_tenant(&app, &key, &identity)?;
    if body.len() > MAX_LOGO_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "logo exceeds 512 KiB",
        ));
    }
    if body.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "logo body is empty",
        ));
    }
    let ext = admit_logo(&headers, &body)?;
    let target = paths::branding_logo_path(&app.config.data_dir, &tenant, ext);
    let directory = target.parent().expect("logo path has a parent").to_owned();
    let staged = target.with_extension(format!("{ext}.tmp"));
    let bytes = body.to_vec();
    let written: Result<(), String> = tokio::task::spawn_blocking({
        let target = target.clone();
        move || {
            std::fs::create_dir_all(&directory)
                .map_err(|error| format!("create {}: {error}", directory.display()))?;
            paths::tighten_private_dir(&directory)?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options
                .open(&staged)
                .map_err(|error| format!("create {}: {error}", staged.display()))?;
            use std::io::Write as _;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("write {}: {error}", staged.display()))?;
            drop(file);
            paths::tighten_private_file(&staged)?;
            std::fs::rename(&staged, &target)
                .map_err(|error| format!("publish {}: {error}", target.display()))
        }
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?;
    written.map_err(ApiError::internal)?;
    let previous = app
        .store
        .branding(&tenant)
        .map_err(super::store_unavailable)?;
    let previous_ext = previous
        .as_ref()
        .map(|branding| branding.logo_ext.clone())
        .unwrap_or_default();
    let branding = crate::store::Branding {
        tenant: tenant.clone(),
        name: previous
            .as_ref()
            .map(|b| b.name.clone())
            .unwrap_or_default(),
        color: previous.map(|b| b.color).unwrap_or_default(),
        logo_ext: ext.to_owned(),
        updated_at: now_unix(),
    };
    app.store
        .set_branding(&branding)
        .map_err(ApiError::internal)?;
    if !previous_ext.is_empty() && previous_ext != ext {
        let stale = paths::branding_logo_path(&app.config.data_dir, &tenant, &previous_ext);
        let _ = tokio::fs::remove_file(stale).await;
    }
    tracing::info!(target: "audit", event = "branding_logo_updated", tenant = %tenant, "tenant logo stored");
    app.store.audit(
        &tenant,
        &identity.subject,
        "branding_logo_updated",
        branding_subject(&tenant),
        &json!({ "ext": ext, "bytes": body.len() }),
    );
    Ok(Json(json!({ "ok": true })))
}

/// Removes a tenant logo; the name and color survive.
pub async fn delete_branding_logo(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let tenant = branding_tenant(&app, &key, &identity)?;
    let branding = app
        .store
        .branding(&tenant)
        .map_err(super::store_unavailable)?
        .filter(|branding| !branding.logo_ext.is_empty())
        .ok_or_else(ApiError::not_found)?;
    let path = paths::branding_logo_path(&app.config.data_dir, &tenant, &branding.logo_ext);
    app.store
        .set_branding(&crate::store::Branding {
            logo_ext: String::new(),
            updated_at: now_unix(),
            ..branding
        })
        .map_err(ApiError::internal)?;
    let _ = tokio::fs::remove_file(path).await;
    tracing::info!(target: "audit", event = "branding_logo_deleted", tenant = %tenant, "tenant logo removed");
    app.store.audit(
        &tenant,
        &identity.subject,
        "branding_logo_deleted",
        branding_subject(&tenant),
        &json!({}),
    );
    Ok(Json(json!({ "ok": true })))
}

/// Whether deleting `key` may remove tenant subtrees. A key with a
/// separator was never usable as a namespace: `Tenant::path_prefix` hands the
/// whole key to `join_under` as one component, so no upload ever published
/// beneath it, and anything at that path belongs to a default-tenant link
/// whose dest is that string.
fn purges_tenant_subtrees(key: &str) -> bool {
    !key.contains('/')
}

fn tenant_receive_dir(
    receive_dir: &std::path::Path,
    key: &str,
) -> Result<std::path::PathBuf, String> {
    let path = paths::join_under(receive_dir, &paths::tenant_prefix(key))?;
    if path == *receive_dir {
        return Err("refusing to purge the receive root".to_owned());
    }
    Ok(path)
}

fn tenant_outbound_dir(
    outbound_dir: &std::path::Path,
    key: &str,
) -> Result<std::path::PathBuf, String> {
    let path = paths::join_under(outbound_dir, &paths::tenant_prefix(key))?;
    if path == *outbound_dir {
        return Err("refusing to purge the outbound root".to_owned());
    }
    Ok(path)
}

/// Streams a consistent SQLite snapshot as a download. Read-only operation:
/// admin session required, CSRF header not (nothing mutates).
pub async fn backup_database(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let _identity = require_platform_admin(&app, &headers)?;
    let _guard = app
        .backup_lock
        .try_lock()
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "backup already running"))?;
    let backups = app.config.data_dir.join("backups");
    tokio::fs::create_dir_all(&backups)
        .await
        .map_err(|error| ApiError::internal(format!("create backups dir: {error}")))?;
    paths::tighten_private_dir(&backups).map_err(ApiError::internal)?;
    let name = crate::backup::legacy_snapshot_filename();
    let destination = backups.join(&name);
    let store = Arc::clone(&app.store);
    let destination_clone = destination.clone();
    tokio::task::spawn_blocking(move || store.backup_into(&destination_clone))
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .map_err(ApiError::internal)?;
    let file = tokio::fs::File::open(&destination)
        .await
        .map_err(|error| ApiError::internal(format!("open snapshot: {error}")))?;
    let len = file
        .metadata()
        .await
        .map_err(|error| ApiError::internal(format!("snapshot metadata: {error}")))?
        .len();
    tracing::info!(target: "audit", event = "backup_created", file = %name, bytes = len, "database snapshot exported");
    app.store
        .audit("", "", "backup_created", &name, &json!({ "bytes": len }));
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
            (header::CONTENT_LENGTH, len.to_string()),
        ],
        Body::from_stream(ReaderStream::new(file)),
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupConfigRequest {
    #[serde(flatten)]
    pub config: crate::backup::BackupConfig,
    #[serde(default, deserialize_with = "double_option")]
    pub access_key_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub secret_access_key: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub passphrase: Option<Option<String>>,
}

pub async fn get_backups(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let _identity = require_platform_admin(&app, &headers)?;
    let guard = app.backup_lock.try_lock().ok();
    let busy = guard.is_none();
    let config = crate::backup::decode_config(
        app.store
            .setting(crate::backup::SETTING_KEY)
            .map_err(super::store_unavailable)?,
    )
    .map_err(ApiError::internal)?;
    let secrets = crate::backup::read_secrets(&app.config.data_dir).map_err(ApiError::internal)?;
    let local_root = config
        .local_root(&app.config.data_dir)
        .map_err(ApiError::internal)?;
    let (mut inventory, mut inventory_error) =
        match crate::backup::inventory_local_root(&local_root) {
            Ok(inventory) => (inventory, None),
            Err(error) => (Vec::new(), Some(error)),
        };
    if !busy
        && matches!(
            config.destination,
            crate::backup::Destination::S3 | crate::backup::Destination::Both
        )
        && secrets.access_key_id.is_some()
        && secrets.secret_access_key.is_some()
    {
        match crate::backup::inventory_s3(&config, &secrets).await {
            Ok(remote) => inventory.extend(remote),
            Err(error) => inventory_error = Some(error),
        }
    }
    let mut status =
        crate::backup::read_status(&app.config.data_dir).map_err(ApiError::internal)?;
    status.running = busy;
    Ok(Json(json!({
        "config": config.public(&secrets),
        "inventory": inventory,
        "inventory_error": inventory_error.map(|error| error.chars().take(512).collect::<String>()),
        "status": status
    })))
}

pub async fn put_backups_config(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(mut body): Json<BackupConfigRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    for value in [
        &mut body.config.local_path,
        &mut body.config.s3_endpoint,
        &mut body.config.s3_region,
        &mut body.config.s3_bucket,
        &mut body.config.s3_prefix,
    ] {
        if value.as_deref().is_some_and(str::is_empty) {
            *value = None;
        }
    }
    for value in [
        body.access_key_id.as_ref().and_then(Option::as_ref),
        body.secret_access_key.as_ref().and_then(Option::as_ref),
        body.passphrase.as_ref().and_then(Option::as_ref),
    ] {
        if value.is_some_and(|value| value.is_empty()) {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "backup secrets must not be empty",
            ));
        }
        if value.is_some_and(|value| value.len() > 4096) {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "backup secret is too long",
            ));
        }
    }
    body.config
        .validate(&app.config.data_dir)
        .map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let _guard = app
        .backup_lock
        .try_lock()
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "backup already running"))?;
    let mut secrets =
        crate::backup::read_secrets(&app.config.data_dir).map_err(ApiError::internal)?;
    if let Some(value) = body.access_key_id {
        secrets.access_key_id = value;
    }
    if let Some(value) = body.secret_access_key {
        secrets.secret_access_key = value;
    }
    if let Some(value) = body.passphrase {
        secrets.passphrase = value;
    }
    secrets
        .validate()
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    if matches!(
        body.config.destination,
        crate::backup::Destination::S3 | crate::backup::Destination::Both
    ) && (secrets.access_key_id.is_none() || secrets.secret_access_key.is_none())
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "S3 credentials are required",
        ));
    }
    if body.config.encrypt && secrets.passphrase.is_none() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "encryption passphrase is required",
        ));
    }
    let mut disabled = body.config.clone();
    disabled.enabled = false;
    let disabled_value =
        serde_json::to_string(&disabled).map_err(|error| ApiError::internal(error.to_string()))?;
    app.store
        .put_settings(
            &identity.subject,
            &[(
                crate::backup::SETTING_KEY.to_owned(),
                crate::store::SettingWrite::Set(disabled_value),
            )],
        )
        .map_err(ApiError::internal)?;
    crate::backup::write_secrets(&app.config.data_dir, &secrets).map_err(ApiError::internal)?;
    if body.config.enabled {
        let value = serde_json::to_string(&body.config)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        app.store
            .put_settings(
                &identity.subject,
                &[(
                    crate::backup::SETTING_KEY.to_owned(),
                    crate::store::SettingWrite::Set(value),
                )],
            )
            .map_err(ApiError::internal)?;
    }
    app.store
        .audit("", &identity.subject, "backups_configured", "", &json!({}));
    Ok(Json(json!({ "config": body.config.public(&secrets) })))
}

pub async fn create_backup(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let _guard = app
        .backup_lock
        .try_lock()
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "backup already running"))?;
    crate::backup::ensure_no_pending_restore(&app.config.data_dir)
        .map_err(|error| ApiError::new(StatusCode::CONFLICT, error))?;
    let config = crate::backup::parse_config(
        app.store
            .setting(crate::backup::SETTING_KEY)
            .map_err(super::store_unavailable)?,
        &app.config.data_dir,
    )
    .map_err(ApiError::internal)?;
    let secrets = crate::backup::read_secrets(&app.config.data_dir).map_err(ApiError::internal)?;
    let id = crate::backup::run(Arc::clone(&app), config, secrets)
        .await
        .map_err(ApiError::internal)?;
    app.store
        .audit("", &identity.subject, "backup_created", &id, &json!({}));
    Ok(Json(json!({ "id": id })))
}

pub async fn restore_backup(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<crate::backup::RestoreRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    crate::backup::validate_id(&body.id)
        .map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let _guard = app
        .backup_lock
        .try_lock()
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "backup already running"))?;
    crate::backup::ensure_no_pending_restore(&app.config.data_dir)
        .map_err(|error| ApiError::new(StatusCode::CONFLICT, error))?;
    let config = crate::backup::parse_config(
        app.store
            .setting(crate::backup::SETTING_KEY)
            .map_err(super::store_unavailable)?,
        &app.config.data_dir,
    )
    .map_err(ApiError::internal)?;
    let secrets = crate::backup::read_secrets(&app.config.data_dir).map_err(ApiError::internal)?;
    let stage = app.config.data_dir.join(format!(
        ".votport-restore-stage-{}",
        crate::auth::random_token()
    ));
    std::fs::create_dir(&stage).map_err(|e| ApiError::internal(e.to_string()))?;
    paths::tighten_private_dir(&stage).map_err(ApiError::internal)?;
    let mut stage_cleanup = crate::backup::CleanupPath::directory(stage.clone());
    let incoming = app.config.data_dir.join(format!(
        ".votport-restore-{}.download",
        crate::auth::random_token()
    ));
    let _incoming_cleanup = crate::backup::CleanupPath::new(incoming.clone());
    if body.source == "local" {
        let local_root = config
            .local_root(&app.config.data_dir)
            .map_err(ApiError::internal)?;
        let source = local_root.join(&body.id);
        let source_meta = std::fs::symlink_metadata(&source)
            .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "backup not found"))?;
        if source_meta.file_type().is_symlink() || !source_meta.file_type().is_file() {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "backup not found"));
        }
        let output = incoming.clone();
        tokio::task::spawn_blocking(move || crate::backup::copy_private_file(&source, &output))
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
            .map_err(ApiError::internal)?;
    } else if body.source == "s3" {
        crate::backup::download_s3(&config, &secrets, &body.id, &incoming)
            .await
            .map_err(ApiError::internal)?;
    } else {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "source must be local or s3",
        ));
    }
    let tar_path = app.config.data_dir.join(format!(
        ".votport-restore-{}.tar",
        crate::auth::random_token()
    ));
    let _tar_cleanup = crate::backup::CleanupPath::new(tar_path.clone());
    if body.id.ends_with(".age") {
        let pass = secrets
            .passphrase
            .as_deref()
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "encryption passphrase is not configured",
                )
            })?
            .to_owned();
        let input = incoming.clone();
        let output = tar_path.clone();
        tokio::task::spawn_blocking(move || crate::backup::decrypt_file(&input, &output, &pass))
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
            .map_err(ApiError::internal)?;
    } else {
        tokio::fs::rename(&incoming, &tar_path)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    }
    let extracted = stage.clone();
    let tar_for_extract = tar_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        crate::backup::validate_and_extract(
            &tar_for_extract,
            &extracted,
            crate::store::SCHEMA_VERSION,
        )
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(ApiError::internal)?;
    crate::backup::write_pending_restore(&app.config.data_dir, &stage, result.clone())
        .map_err(ApiError::internal)?;
    stage_cleanup.keep();
    app.store.audit(
        "",
        &identity.subject,
        "backup_restore_pending",
        &body.id,
        &json!({ "version": result.version }),
    );
    tracing::info!(
        target: "audit",
        event = "backup_restore_pending",
        id = %body.id,
        source = %body.source,
        version = result.version,
        "backup restore staged"
    );
    app.request_shutdown();
    Ok(Json(json!({ "pending": true, "restart_required": true })))
}

const SETTINGS_KEYS: &[&str] = &[
    "notify_webhook",
    "notify_ntfy",
    "notify_ntfy_token",
    "notify_pushover_token",
    "notify_pushover_user",
    "smtp_host",
    "smtp_port",
    "smtp_starttls",
    "smtp_username",
    "smtp_password",
    "smtp_from",
    "smtp_to",
    "audit_retention_days",
    "upload_retention_days",
    "default_max_total_bytes",
    "default_max_links",
    "default_max_sessions",
    "public_password_login",
    "sso_session_secs",
    "draining",
];

pub async fn get_settings(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let _identity = require_platform_admin(&app, &headers)?;
    Ok(Json(settings_json(&app)?))
}

pub async fn test_notifications(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let identity = require_platform_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let report = crate::notify::test_saved(Arc::clone(&app))
        .await
        .map_err(ApiError::internal)?;
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "notification_test",
        "",
        &json!({ "configured": report.configured, "delivered": report.delivered }),
    );
    if report.configured == 0 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "no notification channels are configured",
        ));
    }
    let status = if report.delivered == report.configured {
        StatusCode::OK
    } else {
        StatusCode::BAD_GATEWAY
    };
    let error = (status != StatusCode::OK).then(|| {
        format!(
            "Delivered {} of {} configured notification channels",
            report.delivered, report.configured
        )
    });
    Ok((
        status,
        Json(json!({
            "error": error,
            "configured": report.configured,
            "delivered": report.delivered,
            "failed": report.configured.saturating_sub(report.delivered),
        })),
    )
        .into_response())
}

fn settings_json(app: &App) -> ApiResult<serde_json::Value> {
    let overlay = app
        .store
        .overlay(&app.config)
        .map_err(super::store_unavailable)?;
    let resolved = &overlay.resolved;
    let oidc = app.config.oidc.as_ref();
    let deployment = json!({
        // Deployment values are intentionally read-only. Secret-bearing
        // values are represented by a configured flag, never their contents.
        "bind": app.config.bind.to_string(),
        "public_url": app.config.public_url,
        "data_dir": app.config.data_dir,
        "receive_dir": app.config.receive_dir,
        "outbound_dir": app.config.outbound_dir,
        "web_root": app.config.web_root,
        "max_upload_bytes": app.config.max_upload_bytes,
        "allow_hidden": app.config.allow_hidden,
        "session_idle_secs": app.config.session_idle_secs,
        "trusted_proxies": app.config.trusted_proxies.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "metrics_configured": app.config.metrics_token.is_some(),
        "push_bind": app.config.push_bind.map(|value| value.to_string()),
        "push_advertise": app.config.push_advertise,
        "push_certificate": app.config.push_certificate,
        "push_certificate_configured": app.config.push_certificate.is_some(),
        "push_private_key_configured": app.config.push_private_key.is_some(),
        "push_configured": app.config.push_bind.is_some(),
        "oidc_issuer": oidc.map(|value| value.issuer.clone()),
        "oidc_client_id": oidc.map(|value| value.client_id.clone()),
        "oidc_admin_group": oidc.and_then(|value| value.admin_group.clone()),
        "oidc_client_secret_configured": oidc.is_some_and(|value| !value.client_secret.is_empty()),
        "oidc_configured": oidc.is_some(),
    });
    Ok(json!({
        "notify_webhook": resolved.notify_webhook,
        "notify_webhook_source": overlay.notify_webhook_source,
        "notify_ntfy": resolved.notify_ntfy,
        "notify_ntfy_source": overlay.notify_ntfy_source,
        "notify_ntfy_token_set": resolved.notify_ntfy_token.is_some(),
        "notify_ntfy_token_source": overlay.notify_ntfy_token_source,
        "notify_pushover_set": resolved.notify_pushover.is_some(),
        "notify_pushover_token_set": overlay.notify_pushover_token_set,
        "notify_pushover_token_source": overlay.notify_pushover_token_source,
        "notify_pushover_user_set": overlay.notify_pushover_user_set,
        "notify_pushover_user_source": overlay.notify_pushover_user_source,
        "smtp_host": overlay.smtp_host,
        "smtp_host_source": overlay.smtp_host_source,
        "smtp_port": overlay.smtp_port,
        "smtp_port_source": overlay.smtp_port_source,
        "smtp_starttls": overlay.smtp_starttls,
        "smtp_starttls_source": overlay.smtp_starttls_source,
        "smtp_username": overlay.smtp_username,
        "smtp_username_source": overlay.smtp_username_source,
        "smtp_password_set": overlay.smtp_password_set,
        "smtp_password_source": overlay.smtp_password_source,
        "smtp_from": overlay.smtp_from,
        "smtp_from_source": overlay.smtp_from_source,
        "smtp_to": overlay.smtp_to,
        "smtp_to_source": overlay.smtp_to_source,
        "audit_retention_days": resolved.audit_retention_days,
        "audit_retention_days_source": overlay.audit_retention_days_source,
        "upload_retention_days": resolved.upload_retention_days,
        "upload_retention_days_source": overlay.upload_retention_days_source,
        "default_max_total_bytes": resolved.default_max_total_bytes,
        "default_max_total_bytes_source": overlay.default_max_total_bytes_source,
        "default_max_links": resolved.default_max_links,
        "default_max_links_source": overlay.default_max_links_source,
        "default_max_sessions": resolved.default_max_sessions,
        "default_max_sessions_source": overlay.default_max_sessions_source,
        "public_password_login": resolved.public_password_login,
        "public_password_login_source": overlay.public_password_login_source,
        "sso_session_secs": resolved.sso_session_secs,
        "sso_session_secs_source": overlay.sso_session_secs_source,
        "draining": resolved.draining,
        "draining_source": overlay.draining_source,
        "sso_configured": app.sso_config.is_some(),
        "deployment": deployment,
    }))
}

fn write_url(key: &str, value: &serde_json::Value) -> ApiResult<crate::store::SettingWrite> {
    match value {
        serde_json::Value::Null => Ok(crate::store::SettingWrite::Reset),
        serde_json::Value::String(text) if text.is_empty() => {
            Ok(crate::store::SettingWrite::Set(String::new()))
        }
        serde_json::Value::String(text)
            if text.starts_with("http://") || text.starts_with("https://") =>
        {
            Ok(crate::store::SettingWrite::Set(text.clone()))
        }
        serde_json::Value::String(_) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be an http:// or https:// URL"),
        )),
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be a string or null"),
        )),
    }
}

fn write_secret(key: &str, value: &serde_json::Value) -> ApiResult<crate::store::SettingWrite> {
    match value {
        serde_json::Value::Null => Ok(crate::store::SettingWrite::Reset),
        serde_json::Value::String(text) => Ok(crate::store::SettingWrite::Set(text.clone())),
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be a string or null"),
        )),
    }
}

fn write_u64(
    key: &str,
    value: &serde_json::Value,
    allow_zero: bool,
) -> ApiResult<crate::store::SettingWrite> {
    match value {
        serde_json::Value::Null => Ok(crate::store::SettingWrite::Reset),
        serde_json::Value::Number(number) => {
            let Some(parsed) = number.as_u64() else {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("{key} must be a non-negative integer"),
                ));
            };
            if !allow_zero && parsed == 0 {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("{key} must be greater than zero"),
                ));
            }
            Ok(crate::store::SettingWrite::Set(parsed.to_string()))
        }
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be a number or null"),
        )),
    }
}

fn write_smtp_port(key: &str, value: &serde_json::Value) -> ApiResult<crate::store::SettingWrite> {
    match value {
        serde_json::Value::Null => Ok(crate::store::SettingWrite::Reset),
        serde_json::Value::Number(number) => {
            let Some(parsed) = number.as_u64() else {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("{key} must be a non-negative integer"),
                ));
            };
            if !(1..=65535).contains(&parsed) {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("{key} must be 1..=65535"),
                ));
            }
            Ok(crate::store::SettingWrite::Set(parsed.to_string()))
        }
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be a number or null"),
        )),
    }
}

fn write_bool(key: &str, value: &serde_json::Value) -> ApiResult<crate::store::SettingWrite> {
    match value {
        serde_json::Value::Null => Ok(crate::store::SettingWrite::Reset),
        serde_json::Value::Bool(true) => Ok(crate::store::SettingWrite::Set("1".to_owned())),
        serde_json::Value::Bool(false) => Ok(crate::store::SettingWrite::Set("0".to_owned())),
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be a boolean or null"),
        )),
    }
}

pub async fn put_settings(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let object = body
        .as_object()
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "expected a JSON object"))?;
    for key in object.keys() {
        if !SETTINGS_KEYS.contains(&key.as_str()) {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("unknown setting {key}"),
            ));
        }
    }
    let mut writes = Vec::new();
    let mut keys = Vec::new();
    let mut reset = Vec::new();
    for key in SETTINGS_KEYS {
        let Some(value) = object.get(*key) else {
            continue;
        };
        let write = match *key {
            "notify_webhook" | "notify_ntfy" => write_url(key, value)?,
            "notify_ntfy_token"
            | "notify_pushover_token"
            | "notify_pushover_user"
            | "smtp_host"
            | "smtp_username"
            | "smtp_password"
            | "smtp_from"
            | "smtp_to" => write_secret(key, value)?,
            "audit_retention_days" | "upload_retention_days" => write_u64(key, value, true)?,
            "default_max_total_bytes"
            | "default_max_links"
            | "default_max_sessions"
            | "sso_session_secs" => write_u64(key, value, false)?,
            "public_password_login" | "smtp_starttls" | "draining" => write_bool(key, value)?,
            "smtp_port" => write_smtp_port(key, value)?,
            _ => unreachable!(),
        };
        match &write {
            crate::store::SettingWrite::Reset => reset.push((*key).to_owned()),
            crate::store::SettingWrite::Set(_) => keys.push((*key).to_owned()),
        }
        writes.push(((*key).to_owned(), write));
    }
    if !writes.is_empty() {
        app.store
            .put_settings(&identity.subject, &writes)
            .map_err(ApiError::internal)?;
        tracing::info!(
            target: "audit",
            event = "settings_updated",
            keys = keys.len(),
            reset = reset.len(),
            "admin settings updated"
        );
        app.store.audit(
            "",
            &identity.subject,
            "settings_updated",
            "",
            &json!({ "keys": keys, "reset": reset }),
        );
    }
    Ok(Json(settings_json(&app)?))
}

#[derive(Deserialize)]
pub struct SwitchTenantRequest {
    tenant: String,
}

/// Switches the active tenant, reissuing the session cookie. SSO sessions
/// honor grants already in the cookie; local sessions use live grants from
/// `store.tenants()`.
pub async fn switch_tenant(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<SwitchTenantRequest>,
) -> ApiResult<Response> {
    let identity = require_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let Some(grant) = identity
        .grants
        .iter()
        .find(|grant| grant.tenant == request.tenant)
    else {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "no access to that tenant",
        ));
    };
    let switched = auth::AdminIdentity {
        tenant: grant.tenant.clone(),
        role: grant.role.clone(),
        credential_version: identity.credential_version,
        grants: identity.grants.clone(),
        subject: identity.subject.clone(),
    };
    tracing::info!(
        target: "audit", event = "tenant_switched",
        subject = %identity.subject, from = %identity.tenant, to = %switched.tenant,
        "admin switched active tenant"
    );
    app.store.audit(
        &switched.tenant,
        &identity.subject,
        "tenant_switched",
        &switched.tenant,
        &json!({ "from": identity.tenant }),
    );
    let cookie = issue_admin_cookie(&app, &switched)?;
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    current: String,
    new: String,
}

/// Replaces the admin password. The new hash is persisted in the store, which
/// from then on takes precedence over the environment. Token MACs cover that
/// hash, so every outstanding admin session is invalidated by the change; the
/// response reissues a cookie under the new hash so the acting admin stays
/// signed in.
pub async fn admin_change_password(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> ApiResult<Response> {
    let identity = require_operator(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    // The local password is the break-glass credential for the platform;
    // SSO tenant admins rotate access at their identity provider instead.
    if !identity.tenant.is_empty() || identity.role != "admin" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "the local administrator password is managed by the default-tenant admin",
        ));
    }
    // Validate before claiming. A request rejected on its own shape never
    // reaches a password, so charging it against the guess budget would let a
    // script with a too-short new password lock every admin out of rotation.
    if request.new.chars().count() < crate::config::MIN_ADMIN_PASSWORD_CHARS {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "new password must be at least {} characters",
                crate::config::MIN_ADMIN_PASSWORD_CHARS
            ),
        ));
    }
    // Claimed before the verify, like sign-in: a caller holding a session
    // could otherwise fire many concurrent guesses that all pass the check
    // together, making this the oracle the throttle exists to prevent.
    if !app.change_password_throttle.claim() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; wait a minute",
        ));
    }
    // Its own budget, not the sign-in one: rotating the password is what an
    // operator does while under attack, so an anonymous sign-in flood must
    // not queue ahead of it.
    let permit = Arc::clone(&app.change_password_permits)
        .acquire_owned()
        .await
        .map_err(|_| ApiError::internal("login semaphore closed"))?;
    let current_ok = tokio::task::spawn_blocking({
        let hash = admin_hash(&app)?;
        let current = request.current.clone();
        move || {
            let _permit = permit;
            auth::verify_password(&current, &hash)
        }
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?;
    // Its own counter: sharing the sign-in one let anonymous login failures
    // keep an operator from rotating the password.
    if current_ok {
        app.change_password_throttle.succeeded();
    }
    if !current_ok {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "current password is wrong",
        ));
    }
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&request.new))
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .map_err(ApiError::internal)?;
    app.store
        .set_admin_password_hash(hash)
        .map_err(ApiError::internal)?;
    tracing::info!(target: "audit", event = "admin_password_changed", "admin password changed; outstanding sessions invalidated");
    app.store.audit(
        "",
        "local",
        "admin_password_changed",
        "",
        &serde_json::json!({}),
    );
    let cookie = issue_admin_cookie(&app, &auth::AdminIdentity::local_admin())?;
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

// ------------------------------------------------------------ link management

#[derive(Serialize)]
struct LinkView {
    id: String,
    label: String,
    dest: String,
    url: String,
    has_password: bool,
    created_at: u64,
    expires_at: Option<u64>,
    max_bytes: Option<u64>,
    active: bool,
    legal_hold: bool,
    notify_on_upload: bool,
    usable: bool,
    uploads: Vec<UploadView>,
    events: Vec<crate::store::SessionEvent>,
}

#[derive(Serialize)]
struct UploadView {
    id: String,
    started_at: u64,
    completed_at: u64,
    transport: String,
    replayed_chunks: u64,
    rejected_chunks: u64,
    package_root: String,
    total_bytes: u64,
    files: Vec<FileView>,
}

#[derive(Serialize)]
struct FileView {
    path: String,
    stored_as: String,
    bytes: u64,
    suite: String,
    root: String,
    receipt: bool,
    /// Whether the stored file is still on disk right now.
    exists: bool,
}

#[derive(Deserialize)]
pub struct LinkQuery {
    limit: Option<u64>,
    search: Option<String>,
    status: Option<String>,
    before_created_at: Option<u64>,
    before_id: Option<String>,
}

pub(crate) fn base_url(app: &App, headers: &HeaderMap) -> String {
    if let Some(url) = &app.config.public_url {
        return url.clone();
    }
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("http");
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    format!("{proto}://{host}")
}

/// The on-disk path a file record points at, from server-recorded components
/// only; client input never reaches this. None when a stored record fails the
/// join guard (a corrupted record), which the display treats as "missing".
pub(crate) fn stored_path(app: &App, tenant: &str, stored_as: &str) -> Option<std::path::PathBuf> {
    // stored_as is relative to the tenant's own subtree: the session builds
    // it from the link dest, while the tenant prefix is added separately when
    // the destination directory is assembled. Joining it straight under the
    // receive root resolves a tenant's file to the default tenant's path,
    // which is one namespace reading and deleting another's bytes.
    let mut components = paths::tenant_prefix(tenant);
    components.extend(
        stored_as
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned),
    );
    paths::join_under(&app.config.receive_dir, &components).ok()
}

fn link_view(app: &App, link: Link, base: &str) -> LinkView {
    let usable = link.usable_now();
    let tenant = link.tenant.clone();
    let uploads = link
        .uploads
        .into_iter()
        .map(|upload| UploadView {
            files: upload
                .files
                .into_iter()
                .map(|file| FileView {
                    exists: stored_path(app, &tenant, &file.stored_as)
                        .is_some_and(|path| path.is_file()),
                    path: file.path,
                    stored_as: file.stored_as,
                    bytes: file.bytes,
                    suite: file.suite,
                    root: file.root,
                    receipt: file.receipt,
                })
                .collect(),
            id: upload.id,
            started_at: upload.started_at,
            completed_at: upload.completed_at,
            transport: upload.transport.unwrap_or_else(|| "http".to_owned()),
            replayed_chunks: upload.replayed_chunks,
            rejected_chunks: upload.rejected_chunks,
            package_root: upload.package_root,
            total_bytes: upload.total_bytes,
        })
        .collect();
    LinkView {
        url: format!("{base}/r/{}", link.id),
        usable,
        id: link.id,
        label: link.label,
        dest: link.dest,
        has_password: link.password_hash.is_some(),
        created_at: link.created_at,
        expires_at: link.expires_at,
        max_bytes: link.max_bytes,
        active: link.active,
        legal_hold: link.legal_hold,
        notify_on_upload: link.notify_on_upload,
        uploads,
        events: link.events,
    }
}

pub async fn list_links(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<LinkQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    let base = base_url(&app, &headers);
    let paged = query.limit.is_some()
        || query.search.is_some()
        || query.status.is_some()
        || query.before_created_at.is_some()
        || query.before_id.is_some();
    if paged {
        let limit = query.limit.unwrap_or(100);
        if !(1..=100).contains(&limit) {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "limit must be between 1 and 100",
            ));
        }
        let status = query
            .status
            .as_deref()
            .unwrap_or("all")
            .to_ascii_lowercase();
        if !matches!(status.as_str(), "all" | "open" | "closed") {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "status must be all, open, or closed",
            ));
        }
        let cursor = match (query.before_created_at, query.before_id) {
            (Some(created_at), Some(id)) => Some(LinkCursor { created_at, id }),
            (None, None) => None,
            _ => {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "before_created_at and before_id must be supplied together",
                ));
            }
        };
        let page = app
            .store
            .links_page(
                &identity.tenant,
                limit,
                cursor.as_ref(),
                query.search.as_deref().unwrap_or(""),
                &status,
                now_unix(),
            )
            .map_err(super::store_unavailable)?;
        let links: Vec<LinkView> = page
            .links
            .into_iter()
            .map(|link| link_view(&app, link, &base))
            .collect();
        return Ok(Json(json!({
            "links": links,
            "receive_dir": app.config.receive_dir,
            "receipt_key": app.signer.public_hex,
            "next_cursor": page.next_cursor,
        })));
    }
    let links: Vec<LinkView> = app
        .store
        .links(&identity.tenant)
        .map_err(super::store_unavailable)?
        .into_iter()
        .map(|link| link_view(&app, link, &base))
        .collect();
    Ok(Json(json!({
        "links": links,
        "receive_dir": app.config.receive_dir,
        "receipt_key": app.signer.public_hex,
    })))
}

#[derive(Deserialize)]
pub struct CreateLinkRequest {
    label: String,
    #[serde(default)]
    dest: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    expires_days: Option<u32>,
    #[serde(default)]
    max_bytes: Option<u64>,
    #[serde(default)]
    notify_on_upload: bool,
}

pub async fn create_link(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<CreateLinkRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let label = request.label.trim().to_owned();
    if label.is_empty() || label.len() > 200 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "label must be 1..=200 characters",
        ));
    }
    let dest = paths::admit_dest(&request.dest)
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    if let Some(max_bytes) = request.max_bytes {
        if max_bytes == 0 || max_bytes > app.config.max_upload_bytes {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "max_bytes must be between 1 and {} bytes",
                    app.config.max_upload_bytes
                ),
            ));
        }
    }
    let password_hash = match request.password.as_deref().filter(|p| !p.is_empty()) {
        Some(password) if password.len() <= MAX_PASSWORD_BYTES => {
            Some(auth::hash_password(password).map_err(ApiError::internal)?)
        }
        Some(_) => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "password must be at most 256 bytes",
            ));
        }
        None => None,
    };
    let tenant = identity.tenant.clone();
    // A cookie can outlive its tenant's deletion; without this check the
    // link would be created under a namespace nothing manages anymore.
    if !tenant.is_empty()
        && app
            .store
            .tenant(&tenant)
            .map_err(super::store_unavailable)?
            .is_none()
    {
        return Err(ApiError::new(
            StatusCode::GONE,
            "this session's tenant no longer exists; sign in again",
        ));
    }
    let (_, max_links, _) = app
        .store
        .quotas_for(&tenant, &app.config)
        .map_err(super::store_unavailable)?;
    if let Some(max_links) = max_links {
        let count = u64::try_from(
            app.store
                .links(&tenant)
                .map_err(super::store_unavailable)?
                .len(),
        )
        .unwrap_or(u64::MAX);
        if count >= max_links {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("this tenant allows at most {max_links} request links"),
            ));
        }
    }
    let link = Link {
        id: auth::random_token(),
        tenant,
        label,
        dest,
        password_hash,
        created_at: now_unix(),
        expires_at: request
            .expires_days
            .map(|days| now_unix() + u64::from(days) * 86_400),
        max_bytes: request.max_bytes,
        active: true,
        legal_hold: false,
        notify_on_upload: request.notify_on_upload,
        uploads: Vec::new(),
        events: Vec::new(),
    };
    let base = base_url(&app, &headers);
    let view = link_view(&app, link.clone(), &base);
    app.store.insert_link(link).map_err(|error| match error {
        crate::store::InsertLinkError::NamedTenantGone => ApiError::new(
            StatusCode::GONE,
            "this session's tenant no longer exists; sign in again",
        ),
        crate::store::InsertLinkError::Store(message) => ApiError::internal(message),
    })?;
    tracing::info!(target: "audit", event = "link_created", id = %view.id, label = %view.label, dest = %view.dest, "request link created");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "link_created",
        &view.id,
        &serde_json::json!({ "label": view.label, "dest": view.dest, "tenant": identity.tenant, "notify_on_upload": view.notify_on_upload }),
    );
    Ok(Json(json!({ "link": view })))
}

#[derive(Deserialize)]
pub struct UpdateLinkRequest {
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    legal_hold: Option<bool>,
    #[serde(default)]
    notify_on_upload: Option<bool>,
}

pub async fn update_link(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateLinkRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let fields = [
        request.active.is_some(),
        request.legal_hold.is_some(),
        request.notify_on_upload.is_some(),
    ];
    if fields.iter().filter(|field| **field).count() != 1 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "exactly one link lifecycle or policy field is required",
        ));
    }
    if let Some(legal_hold) = request.legal_hold {
        if app
            .store
            .link(&identity.tenant, &id)
            .map_err(ApiError::internal)?
            .is_none()
        {
            return Err(ApiError::not_found());
        }
        let _pin = app.sessions.try_pin_link(&id).ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "link lifecycle update in progress; try again",
            )
        })?;
        let found = app
            .store
            .set_link_legal_hold(&identity.tenant, &id, legal_hold, &identity.subject)
            .map_err(ApiError::internal)?;
        if !found {
            return Err(ApiError::not_found());
        }
        tracing::info!(target: "audit", event = "link_legal_hold_changed", id = %id, legal_hold, "request link legal hold changed");
        return Ok(Json(json!({ "ok": true })));
    }

    if let Some(notify_on_upload) = request.notify_on_upload {
        let found = app
            .store
            .update_link(&identity.tenant, &id, |link| {
                link.notify_on_upload = notify_on_upload
            })
            .map_err(ApiError::internal)?;
        if !found {
            return Err(ApiError::not_found());
        }
        app.store.audit(
            &identity.tenant,
            &identity.subject,
            "link_notify_on_upload_changed",
            &id,
            &serde_json::json!({ "notify_on_upload": notify_on_upload }),
        );
        return Ok(Json(json!({ "ok": true })));
    }

    let active = request.active.expect("validated above");
    let found = app
        .store
        .update_link(&identity.tenant, &id, |link| link.active = active)
        .map_err(ApiError::internal)?;
    if !found {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "link_active_changed", id = %id, active, "request link toggled");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "link_active_changed",
        &id,
        &serde_json::json!({ "active": active }),
    );
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_link(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    if app
        .store
        .link(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .is_none()
    {
        return Err(ApiError::not_found());
    }
    let _pin = app
        .sessions
        .try_pin_link(&id)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "link delete already in progress"))?;
    let link = app
        .store
        .link(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if link.legal_hold {
        return Err(ApiError::new(StatusCode::CONFLICT, "link is on legal hold"));
    }
    if app.sessions.active_for_link(&id) > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "uploads are in flight; try again when they finish",
        ));
    }
    if app
        .store
        .link_has_active_outbound_grants(&identity.tenant, &id, now_unix())
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "active download links must be revoked first",
        ));
    }
    let removed = app
        .store
        .remove_link(&identity.tenant, &id)
        .map_err(ApiError::internal)?;
    if !removed {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "link_deleted", id = %id, "request link deleted");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "link_deleted",
        &id,
        &serde_json::json!({}),
    );
    Ok(Json(json!({ "ok": true })))
}

/// The request link as a scannable SVG, for senders on phones.
pub async fn link_qr(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let identity = require_operator(&app, &headers)?;
    let link = app
        .store
        .link(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let url = format!("{}/r/{}", base_url(&app, &headers), link.id);
    let code = qrcode::QrCode::new(url.as_bytes())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(([(header::CONTENT_TYPE, "image/svg+xml")], svg).into_response())
}

/// Removes one upload from a link's history. Files on disk are untouched.
pub async fn delete_upload_record(
    State(app): State<Arc<App>>,
    Path((id, upload)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    if app
        .store
        .link(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .is_none()
    {
        return Err(ApiError::not_found());
    }
    let _pin = app
        .sessions
        .try_pin_link(&id)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "link update already in progress"))?;
    if app.sessions.active_for_link(&id) > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "uploads are in flight; try again when they finish",
        ));
    }
    let link = app
        .store
        .link(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if link.legal_hold {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "received records cannot be deleted while the link is on legal hold",
        ));
    }
    let record = link
        .uploads
        .iter()
        .find(|entry| entry.id == upload)
        .ok_or_else(ApiError::not_found)?;
    for index in 0..record.files.len() {
        if app
            .store
            .has_active_outbound_grant(&identity.tenant, &id, &upload, index, now_unix())
            .map_err(ApiError::internal)?
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "active download links must be revoked first",
            ));
        }
    }
    let found = app
        .store
        .update_link_uploads(&identity.tenant, &id, |link| {
            link.uploads.retain(|entry| entry.id != upload)
        })
        .map_err(ApiError::internal)?;
    if !found {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "upload_record_cleared", link = %id, upload = %upload, "upload record cleared from history");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "upload_record_cleared",
        &id,
        &serde_json::json!({ "upload": upload }),
    );
    Ok(Json(json!({ "ok": true })))
}

/// Deletes one received file (and its receipt sidecar) from disk. The path
/// comes from the stored record, never from the client. Already-gone files
/// succeed: the record's existence flag is the display of truth.
pub async fn delete_received_file(
    State(app): State<Arc<App>>,
    Path((id, upload, index)): Path<(String, String, usize)>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    if app
        .store
        .link(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .is_none()
    {
        return Err(ApiError::not_found());
    }
    let _pin = app
        .sessions
        .try_pin_link(&id)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "file deletion already in progress"))?;
    if app.sessions.active_for_link(&id) > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "uploads are in flight; try again when they finish",
        ));
    }
    let link = app
        .store
        .link(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if link.legal_hold {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "received files cannot be deleted while the link is on legal hold",
        ));
    }
    let record = link
        .uploads
        .iter()
        .find(|entry| entry.id == upload)
        .and_then(|entry| entry.files.get(index))
        .ok_or_else(ApiError::not_found)?;
    let path = stored_path(&app, &identity.tenant, &record.stored_as)
        .ok_or_else(|| ApiError::internal("stored path failed the join guard"))?;
    if app
        .store
        .has_active_outbound_grant(&identity.tenant, &id, &upload, index, now_unix())
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "active download links must be revoked first",
        ));
    }
    for target in [path.clone(), {
        let mut sidecar = path.into_os_string();
        sidecar.push(".vot-receipt");
        sidecar.into()
    }] {
        match std::fs::remove_file(&target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ApiError::internal(format!(
                    "delete {}: {error}",
                    target.display()
                )));
            }
        }
    }
    // Tombstone every record naming this path, not just the one deleted
    // through: the freed name can be reused by different content, and any
    // record still pointing there must never satisfy dedupe again.
    let stored_as = record.stored_as.clone();
    app.store
        .tombstone_files(&identity.tenant, &id, |file| file.stored_as == stored_as)
        .map_err(ApiError::internal)?;
    tracing::info!(target: "audit", event = "received_file_deleted", link = %id, stored_as = %stored_as, "received file deleted from disk");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "received_file_deleted",
        &id,
        &serde_json::json!({ "stored_as": stored_as }),
    );
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod audit_filter_tests {
    use super::*;

    #[test]
    fn audit_filters_are_bounded_and_blank_values_are_absent() {
        assert_eq!(validate_audit_filter(None, "q").unwrap(), None);
        assert_eq!(
            validate_audit_filter(Some(String::new()), "q").unwrap(),
            None
        );
        assert_eq!(
            validate_audit_filter(Some(" \t".to_owned()), "q").unwrap(),
            None
        );
        assert!(validate_audit_filter(Some("🙂".repeat(100)), "q").is_ok());
        assert!(validate_audit_filter(Some("🙂".repeat(101)), "q").is_err());
        assert_eq!(
            validate_audit_filter(Some("  actor  ".to_owned()), "q").unwrap(),
            Some("actor".to_owned())
        );
    }
}

#[cfg(test)]
mod handler_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::store::UploadRecord;

    async fn login_attempt(
        application: Arc<App>,
        peer: [u8; 4],
        password: &str,
    ) -> axum::http::Response<axum::body::Body> {
        app::router(application)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/login")
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((peer, 1234))))
                    .body(Body::from(format!("{{\"password\":\"{password}\"}}")))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_flood_of_attempts_does_not_refuse_the_operator() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // Every attempt from a different bucket, so none is refused by the
        // per-IP throttle. The operator must still sign in while they are in
        // flight.
        let mut flood = Vec::new();
        for index in 0..20u8 {
            let application = application.clone();
            flood.push(tokio::spawn(async move {
                login_attempt(application, [10, 0, 0, index], "wrong").await;
            }));
        }
        // Bounded so a regression fails with a diagnosis rather than hanging.
        // This checks that the operator is not refused, not that the wait is
        // short: queue latency under a flood is an accepted residual, and the
        // semaphore is FIFO.
        let operator = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            login_attempt(
                application.clone(),
                [198, 51, 100, 4],
                testing::TEST_PASSWORD,
            ),
        )
        .await
        .expect("the operator never completed sign-in during a flood");
        assert_eq!(
            operator.status(),
            StatusCode::OK,
            "the operator signs in while the flood is in flight"
        );
        for task in flood {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(60), task).await;
        }
    }

    #[tokio::test]
    async fn a_rejected_new_password_costs_no_guess_budget() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login_cookie(app::router(application.clone())).await;
        // Six requests whose new password is too short. None of them reaches
        // a verification, so none may spend the budget that guards the
        // current password, or a script could lock every admin out of
        // rotation without guessing anything.
        for _ in 0..6 {
            let response = change_password_req(
                application.clone(),
                &cookie,
                testing::TEST_PASSWORD,
                "short",
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let response = change_password_req(
            application.clone(),
            &cookie,
            testing::TEST_PASSWORD,
            "a-much-longer-passphrase",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn change_password_req(
        application: Arc<App>,
        cookie: &str,
        current: &str,
        new: &str,
    ) -> axum::http::Response<axum::body::Body> {
        app::router(application)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/password")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"current":"{current}","new":"{new}"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn sign_in_failures_do_not_block_a_password_change() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login_cookie(app::router(application.clone())).await;
        // Sign-in failures must not reach the counter that guards password
        // rotation: an operator holding a session has to be able to rotate.
        for index in 0..6u8 {
            login_attempt(application.clone(), [203, 0, 113, index], "wrong").await;
        }
        let response = app::router(application.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/password")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"current":"{}","new":"a-much-longer-passphrase"}}"#,
                        testing::TEST_PASSWORD
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn spread_out_failures_never_reach_a_fresh_address() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // Twelve failures, spread four per address so no single address
        // locks itself, and well past the five that used to trip a global
        // counter. Nothing may accumulate across addresses, or an attacker
        // who spreads guesses denies the operator the break-glass credential.
        // Kept small on purpose: every one of these runs a real argon2.
        for index in 0..3u8 {
            for _ in 0..4 {
                assert_eq!(
                    login_attempt(application.clone(), [203, 0, 113, index], "wrong")
                        .await
                        .status(),
                    StatusCode::UNAUTHORIZED
                );
            }
        }
        assert_eq!(
            login_attempt(
                application.clone(),
                [198, 51, 100, 4],
                testing::TEST_PASSWORD
            )
            .await
            .status(),
            StatusCode::OK,
            "a fresh address signs in normally"
        );
    }

    #[tokio::test]
    async fn a_link_password_flood_cannot_queue_the_operator_out() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // Every permit of the public link budget held: that path is the one
        // an unauthenticated caller can flood. Sign-in has its own budget, so
        // it must not wait on this one.
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(
                Arc::clone(&application.link_verify_permits)
                    .acquire_owned()
                    .await
                    .unwrap(),
            );
        }
        let signed_in = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            login_attempt(
                application.clone(),
                [198, 51, 100, 4],
                testing::TEST_PASSWORD,
            ),
        )
        .await
        .expect("sign-in waited on the link password budget");
        assert_eq!(signed_in.status(), StatusCode::OK);
        drop(held);
    }

    #[tokio::test]
    async fn a_guessing_address_cannot_lock_out_the_operator() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // Well past the five-failure lockout: a global throttle here would
        // deny the break-glass credential to everyone, which is exactly what
        // an operator needs during an identity-provider outage.
        for _ in 0..15 {
            let response = login_attempt(application.clone(), [203, 0, 113, 9], "wrong").await;
            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status() == StatusCode::TOO_MANY_REQUESTS
            );
        }
        assert_eq!(
            login_attempt(application.clone(), [203, 0, 113, 9], "wrong")
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the guessing address is locked"
        );
        assert_eq!(
            login_attempt(
                application.clone(),
                [198, 51, 100, 4],
                testing::TEST_PASSWORD
            )
            .await
            .status(),
            StatusCode::OK,
            "another address still signs in"
        );
    }

    async fn login_cookie(router: axum::Router) -> String {
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/login")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                1234,
            ))))
            .body(Body::from(format!(
                "{{\"password\":\"{}\"}}",
                testing::TEST_PASSWORD
            )))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response
            .headers()
            .get(header::SET_COOKIE)
            .expect("login sets a cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn admin_api_rejects_the_unauthenticated() {
        let directory = tempfile::tempdir().unwrap();
        let router = app::router(testing::build(directory.path()));
        let response = router
            .oneshot(
                Request::get("/api/admin/links")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn legal_hold_refuses_all_received_data_deletions() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(crate::store::Link {
                id: "held".to_owned(),
                label: "held".to_owned(),
                tenant: String::new(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: true,
                notify_on_upload: false,
                uploads: Vec::new(),
                events: Vec::new(),
            })
            .unwrap();
        let cookie = login_cookie(app::router(application.clone())).await;
        for uri in [
            "/api/admin/links/held",
            "/api/admin/links/held/uploads/upload",
            "/api/admin/links/held/uploads/upload/files/0",
        ] {
            let response = app::router(application.clone())
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(uri)
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CONFLICT, "{uri}");
        }
        assert!(application.store.link("", "held").unwrap().is_some());
    }

    #[tokio::test]
    async fn paged_links_return_a_stable_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        for id in ["z-link", "m-link", "a-link"] {
            application
                .store
                .insert_link(crate::store::Link {
                    id: id.to_owned(),
                    label: id.to_owned(),
                    tenant: String::new(),
                    dest: String::new(),
                    password_hash: None,
                    created_at: 10,
                    expires_at: None,
                    max_bytes: None,
                    active: true,
                    legal_hold: false,
                    notify_on_upload: false,
                    uploads: Vec::new(),
                    events: Vec::new(),
                })
                .unwrap();
        }
        let cookie = login_cookie(app::router(application.clone())).await;
        let response = app::router(application.clone())
            .oneshot(
                Request::get("/api/admin/links?limit=2")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let links = json["links"].as_array().unwrap();
        assert_eq!(links[0]["id"], "z-link");
        assert_eq!(links[1]["id"], "m-link");
        assert_eq!(
            json["next_cursor"],
            serde_json::json!({"created_at": 10, "id": "m-link"})
        );

        let response = app::router(application)
            .oneshot(
                Request::get("/api/admin/links?limit=2&before_created_at=10&before_id=m-link")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["links"].as_array().unwrap()[0]["id"], "a-link");
        assert!(json["next_cursor"].is_null());
    }

    #[test]
    fn link_view_maps_legacy_upload_transport_to_http() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let view = link_view(
            &application,
            Link {
                id: "link".to_owned(),
                label: "link".to_owned(),
                tenant: String::new(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,
                notify_on_upload: false,
                uploads: vec![UploadRecord {
                    id: "upload".to_owned(),
                    started_at: 0,
                    completed_at: 1,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: None,
                    package_root: "root".to_owned(),
                    total_bytes: 0,
                    files: Vec::new(),
                }],
                events: Vec::new(),
            },
            "http://localhost",
        );
        let json = serde_json::to_value(view).unwrap();
        assert_eq!(json["uploads"][0]["transport"], "http");
    }

    #[test]
    fn patch_tenant_null_clears_and_omission_preserves() {
        let cleared: PatchTenantRequest = serde_json::from_str(
            r#"{"admin_group":null,"max_total_bytes":null,"max_links":null,"max_sessions":null}"#,
        )
        .unwrap();
        assert_eq!(cleared.admin_group, Some(None));
        assert_eq!(cleared.max_total_bytes, Some(None));
        assert_eq!(cleared.max_links, Some(None));
        assert_eq!(cleared.max_sessions, Some(None));

        let omitted: PatchTenantRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(omitted.admin_group, None);
        assert_eq!(omitted.max_total_bytes, None);
        assert_eq!(omitted.max_links, None);
        assert_eq!(omitted.max_sessions, None);
    }

    #[tokio::test]
    async fn mutating_admin_routes_require_the_csrf_header() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;

        // Valid session, no X-Votport header: cross-site forms must fail.
        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"label":"no header"}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // The same request with the header succeeds.
        let router = app::router(application);
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"label":"with header"}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn audit_export_requires_sign_in_and_emits_jsonl() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application.store.audit(
            "",
            "",
            "link_created",
            "l-1",
            &serde_json::json!({ "label": "x" }),
        );

        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/audit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let router = app::router(application);
        let request = Request::builder()
            .uri("/api/admin/audit?limit=100")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(line["event"], "link_created");
        assert_eq!(line["subject"], "l-1");
        assert_eq!(line["detail"]["label"], "x");
    }

    #[tokio::test]
    async fn audit_recent_cursor_returns_newest_rows_and_rejects_mixed_cursors() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login_cookie(app::router(application.clone())).await;
        application
            .store
            .audit("", "", "oldest", "a", &serde_json::json!({}));
        application
            .store
            .audit("", "", "middle", "b", &serde_json::json!({}));
        application
            .store
            .audit("", "", "newest", "c", &serde_json::json!({}));

        let response = app::router(application.clone())
            .oneshot(
                Request::get("/api/admin/audit?before_rowid=0&limit=2")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let events: Vec<_> = String::from_utf8(body.to_vec())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
            .collect();
        assert_eq!(events, vec!["newest", "middle"]);

        let response = app::router(application)
            .oneshot(
                Request::get("/api/admin/audit?before_rowid=3&since=0")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn holdings_reports_platform_usage() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login_cookie(app::router(application.clone())).await;
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"label":"holdings"}"#))
            .unwrap();
        assert_eq!(
            app::router(application.clone())
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let response = app::router(application)
            .oneshot(
                Request::get("/api/admin/holdings")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["holdings"][0]["tenant"], "");
        assert_eq!(json["holdings"][0]["links"], 1);
        assert_eq!(json["holdings"][0]["received_bytes"], 0);
    }

    #[tokio::test]
    async fn received_file_delete_refuses_an_active_session() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let path = application.config.receive_dir.join("received.bin");
        std::fs::write(&path, b"keep").unwrap();
        application
            .store
            .insert_link(crate::store::Link {
                id: "link".to_owned(),
                label: "link".to_owned(),
                tenant: String::new(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,
                notify_on_upload: false,
                uploads: vec![crate::store::UploadRecord {
                    id: "upload".to_owned(),
                    started_at: 0,
                    completed_at: 1,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: Some("http".to_owned()),
                    package_root: "root".to_owned(),
                    total_bytes: 4,
                    files: vec![crate::store::FileRecord {
                        path: "received.bin".to_owned(),
                        stored_as: "received.bin".to_owned(),
                        bytes: 4,
                        suite: "blake3".to_owned(),
                        root: "root".to_owned(),
                        receipt: false,
                        deleted: false,
                    }],
                }],
                events: Vec::new(),
            })
            .unwrap();
        application
            .sessions
            .insert(
                "session".to_owned(),
                "link".to_owned(),
                String::new(),
                tokio::sync::mpsc::channel(1).0,
            )
            .unwrap();

        let cookie = login_cookie(app::router(application.clone())).await;
        let response = app::router(application.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/admin/links/link/uploads/upload/files/0")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        let link = application.store.link("", "link").unwrap().unwrap();
        assert!(!link.uploads[0].files[0].deleted);
        let pin = application
            .sessions
            .try_pin_link("link")
            .expect("file delete released its link pin");
        drop(pin);
    }

    #[tokio::test]
    async fn https_public_url_marks_cookies_secure() {
        let directory = tempfile::tempdir().unwrap();
        let router = app::router(testing::build(directory.path()));
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/login")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                1234,
            ))))
            .body(Body::from(format!(
                "{{\"password\":\"{}\"}}",
                testing::TEST_PASSWORD
            )))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(cookie.contains("; Secure"), "cookie was {cookie}");
    }
}

#[cfg(test)]
mod tenant_authz_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::auth::{self, TenantGrant};

    /// Mints an admin session cookie for an arbitrary identity, exactly as
    /// the SSO callback would after verifying a provider response.
    fn cookie_for(app: &App, tenant: &str, role: &str) -> String {
        let identity = auth::AdminIdentity {
            subject: format!("sso:{tenant}"),
            tenant: tenant.to_owned(),
            role: role.to_owned(),
            grants: vec![TenantGrant {
                tenant: tenant.to_owned(),
                role: role.to_owned(),
            }],
            credential_version: 1,
        };
        super::test_admin_cookie(app, &identity)
    }

    /// A new handler that calls bare `require_admin` silently reopens the
    /// audit-only surface; the allow-list below is every function that may
    /// serve an auditor. Extend it deliberately or use `require_operator`.
    #[test]
    fn bare_require_admin_stays_on_the_allow_list() {
        let allowed = [
            "require_operator",
            "require_platform_admin",
            "admin_logout",
            "admin_audit_export",
            "admin_session",
            "switch_tenant",
        ];
        for file in [
            "src/api/admin.rs",
            "src/api/outbound.rs",
            "src/api/sso.rs",
            "src/api/upload.rs",
            "src/api/verify.rs",
            "src/api/mod.rs",
            "src/api/session_rate.rs",
            "src/app.rs",
        ] {
            let text = std::fs::read_to_string(file).unwrap();
            let mut current_fn = String::new();
            // Test modules exercise require_admin directly; skip them by
            // brace-tracking from each #[cfg(test)] marker. Approximate
            // (string literals with braces would confuse it) but the lint
            // only needs to be right about handler code.
            let mut test_depth = 0usize;
            let mut pending_test_mod = false;
            for (number, line) in text.lines().enumerate() {
                if test_depth == 0 && line.trim_start().starts_with("#[cfg(test)]") {
                    pending_test_mod = true;
                }
                if test_depth > 0 || pending_test_mod {
                    let opens = line.matches('{').count();
                    let closes = line.matches('}').count();
                    if pending_test_mod && opens > 0 {
                        pending_test_mod = false;
                        test_depth = 1 + opens.saturating_sub(1);
                    } else if test_depth > 0 {
                        test_depth += opens;
                    }
                    test_depth = test_depth.saturating_sub(closes);
                    continue;
                }
                if let Some(rest) = line.trim_start().strip_prefix("pub async fn ").or_else(|| {
                    line.trim_start()
                        .strip_prefix("async fn ")
                        .or_else(|| line.trim_start().strip_prefix("pub(crate) fn "))
                        .or_else(|| line.trim_start().strip_prefix("pub fn "))
                        .or_else(|| line.trim_start().strip_prefix("fn "))
                }) {
                    current_fn = rest.split(['(', '<']).next().unwrap_or_default().to_owned();
                }
                // Split so this test's own source cannot match the needle.
                let needle = ["require_admin", "("].concat();
                let bare = line.contains(&needle)
                    && !line.contains("fn require_admin")
                    && !line.contains("require_admin_write");
                if bare && current_fn != "require_admin" {
                    assert!(
                        allowed.contains(&current_fn.as_str()),
                        "{file}:{}: bare require_admin in fn {current_fn}; \
                         use require_operator or extend the allow-list",
                        number + 1
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn auditor_sees_the_audit_trail_and_nothing_else() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "auditor");
        let get = |path: &'static str| {
            let cookie = cookie.clone();
            let application = application.clone();
            async move {
                app::router(application)
                    .oneshot(
                        Request::get(path)
                            .header("cookie", cookie)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            }
        };
        let session = get("/api/admin/session").await;
        assert_eq!(session.status(), StatusCode::OK);
        let session: serde_json::Value = serde_json::from_slice(
            &http_body_util::BodyExt::collect(session.into_body())
                .await
                .unwrap()
                .to_bytes(),
        )
        .unwrap();
        assert_eq!(session["pages"], serde_json::json!(["audit"]));
        assert_eq!(get("/api/admin/audit").await.status(), StatusCode::OK);
        for denied in [
            "/api/admin/links",
            "/api/admin/outbound-files",
            "/api/admin/outbound-grants",
            "/api/admin/automation-tokens",
        ] {
            assert_eq!(
                get(denied).await.status(),
                StatusCode::FORBIDDEN,
                "{denied} must refuse the auditor role"
            );
        }
        // Platform routes already demand the admin role.
        assert_eq!(
            get("/api/admin/holdings").await.status(),
            StatusCode::FORBIDDEN
        );
        // Writes fail on the role check even with the CSRF header present.
        let write = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/links")
                    .header("cookie", cookie.clone())
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"label":"x","dest":"d"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(write.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn tenant_admins_cannot_reach_other_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::Tenant {
                key: "acme".to_owned(),
                label: String::new(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        application
            .store
            .insert_link(crate::store::Link {
                tenant: "acme".to_owned(),
                ..crate::store::Link {
                    id: "acme-link".to_owned(),
                    tenant: "acme".to_owned(),
                    label: "acme".to_owned(),
                    dest: String::new(),
                    password_hash: None,
                    created_at: 0,
                    expires_at: None,
                    max_bytes: None,
                    active: true,
                    legal_hold: false,
                    notify_on_upload: false,
                    uploads: Vec::new(),
                    events: Vec::new(),
                }
            })
            .unwrap();

        // An admin whose only grant is the default tenant: acme's link is
        // invisible, and switching without the grant is refused.
        let outsider = cookie_for(&application, "", "admin");
        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/links")
                    .header("cookie", &outsider)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["links"].as_array().unwrap().len(), 0);

        // Foreign IDs are rejected before touching the global lifecycle pin.
        assert!(application.sessions.pin_link_for_delete("acme-link"));
        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &outsider)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"legal_hold":true}"#))
            .unwrap();
        assert_eq!(
            router.oneshot(request).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let router = app::router(application.clone());
        let request = Request::builder()
            .method("DELETE")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &outsider)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.oneshot(request).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        application.sessions.unpin_link("acme-link");

        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/tenant")
            .header("cookie", &outsider)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"tenant":"acme"}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // An acme admin sees exactly their own link and can toggle it.
        let acme_admin = cookie_for(&application, "acme", "admin");
        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/links")
                    .header("cookie", &acme_admin)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let links = json["links"].as_array().unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["id"], "acme-link");

        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &acme_admin)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"active":false}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &acme_admin)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"legal_hold":true}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            application
                .store
                .link("acme", "acme-link")
                .unwrap()
                .unwrap()
                .legal_hold
        );
        assert!(application
            .store
            .audit_export("acme", 0, 0, 100)
            .unwrap()
            .iter()
            .any(|row| row.event == "link_legal_hold_changed"));

        assert!(application.sessions.pin_link_for_delete("acme-link"));
        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &acme_admin)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"legal_hold":false}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        application.sessions.unpin_link("acme-link");
        assert!(
            application
                .store
                .link("acme", "acme-link")
                .unwrap()
                .unwrap()
                .legal_hold
        );

        // A viewer gets read-only access: reads pass, writes are 403.
        let viewer = cookie_for(&application, "acme", "viewer");
        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/links")
                    .header("cookie", &viewer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let router = app::router(application);
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &viewer)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"active":true}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

#[cfg(test)]
mod branding_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::auth::{self, TenantGrant};

    fn cookie_for(app: &App, tenant: &str, role: &str) -> String {
        let identity = auth::AdminIdentity {
            subject: format!("sso:{tenant}:{role}"),
            tenant: tenant.to_owned(),
            role: role.to_owned(),
            grants: vec![TenantGrant {
                tenant: tenant.to_owned(),
                role: role.to_owned(),
            }],
            credential_version: 1,
        };
        super::test_admin_cookie(app, &identity)
    }

    fn insert_tenant(app: &App, key: &str) {
        app.store
            .insert_tenant(crate::store::Tenant {
                key: key.to_owned(),
                label: String::new(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
    }

    async fn put_branding(app: &Arc<App>, cookie: &str, key: &str, body: &str) -> StatusCode {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/admin/branding/{key}"))
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(body.to_owned()))
            .unwrap();
        app::router(app.clone())
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    async fn put_logo(
        app: &Arc<App>,
        cookie: &str,
        key: &str,
        content_type: &str,
        bytes: Vec<u8>,
    ) -> StatusCode {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/admin/branding/{key}/logo"))
            .header("cookie", cookie)
            .header("content-type", content_type)
            .header("x-votport", "1")
            .body(Body::from(bytes))
            .unwrap();
        app::router(app.clone())
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn put_branding_validates_color_and_stores_the_row() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let platform = cookie_for(&application, "", "admin");

        for bad in ["#12zz99", "12ab99", "#12ab9", "#12ab999", "red"] {
            let body = format!(r#"{{"name":"Acme","color":"{bad}"}}"#);
            assert_eq!(
                put_branding(&application, &platform, "default", &body).await,
                StatusCode::UNPROCESSABLE_ENTITY,
                "color {bad:?} was admitted"
            );
        }
        assert!(application.store.branding("").unwrap().is_none());

        assert_eq!(
            put_branding(
                &application,
                &platform,
                "default",
                r##"{"name":"  Acme Corp  ","color":"#12Ab99"}"##
            )
            .await,
            StatusCode::OK
        );
        let row = application.store.branding("").unwrap().unwrap();
        assert_eq!(row.name, "Acme Corp");
        assert_eq!(row.color, "#12Ab99");
        assert_eq!(row.logo_ext, "");

        // Empty color clears the accent; DELETE removes the row entirely.
        assert_eq!(
            put_branding(
                &application,
                &platform,
                "default",
                r#"{"name":"Acme Corp","color":""}"#
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(application.store.branding("").unwrap().unwrap().color, "");
        let request = Request::builder()
            .method("DELETE")
            .uri("/api/admin/branding/default")
            .header("cookie", &platform)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app::router(application.clone())
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(application.store.branding("").unwrap().is_none());
    }

    #[tokio::test]
    async fn wrong_tenant_admin_cannot_brand_other_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        insert_tenant(&application, "acme");
        insert_tenant(&application, "beta");
        let acme = cookie_for(&application, "acme", "admin");

        for foreign in ["default", "beta", "missing"] {
            assert_eq!(
                put_branding(
                    &application,
                    &acme,
                    foreign,
                    r#"{"name":"Acme","color":""}"#
                )
                .await,
                StatusCode::FORBIDDEN,
                "{foreign} accepted a foreign admin"
            );
        }
        assert_eq!(
            put_branding(&application, &acme, "acme", r#"{"name":"Acme","color":""}"#).await,
            StatusCode::OK
        );
        assert_eq!(
            application.store.branding("acme").unwrap().unwrap().name,
            "Acme"
        );

        // A platform admin brands any tenant; an unknown one is 404.
        let platform = cookie_for(&application, "", "admin");
        assert_eq!(
            put_branding(
                &application,
                &platform,
                "beta",
                r#"{"name":"Beta","color":""}"#
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            put_branding(
                &application,
                &platform,
                "missing",
                r#"{"name":"X","color":""}"#
            )
            .await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn logo_upload_enforces_type_magic_and_size() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let platform = cookie_for(&application, "", "admin");
        let png = b"\x89PNG\r\n\x1a\npixels".to_vec();

        assert_eq!(
            put_logo(&application, &platform, "default", "image/gif", png.clone()).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            put_logo(
                &application,
                &platform,
                "default",
                "image/png",
                b"\xff\xd8\xffjpeg".to_vec()
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut oversized = png.clone();
        oversized.resize(MAX_LOGO_BYTES + 1, 0);
        assert_eq!(
            put_logo(&application, &platform, "default", "image/png", oversized).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(application.store.branding("").unwrap().is_none());

        assert_eq!(
            put_logo(&application, &platform, "default", "image/png", png).await,
            StatusCode::OK
        );
        let row = application.store.branding("").unwrap().unwrap();
        assert_eq!(row.logo_ext, "png");
        let stored = paths::branding_logo_path(&application.config.data_dir, "", "png");
        assert!(stored.is_file());

        // Replacing with another type removes the stale file.
        assert_eq!(
            put_logo(
                &application,
                &platform,
                "default",
                "image/svg+xml",
                b"<svg xmlns='http://www.w3.org/2000/svg'/>".to_vec()
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            application.store.branding("").unwrap().unwrap().logo_ext,
            "svg"
        );
        assert!(!stored.exists());

        // DELETE clears the extension and the file; name and color survive.
        let request = Request::builder()
            .method("DELETE")
            .uri("/api/admin/branding/default/logo")
            .header("cookie", &platform)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app::router(application.clone())
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            application.store.branding("").unwrap().unwrap().logo_ext,
            ""
        );
        assert!(!paths::branding_logo_path(&application.config.data_dir, "", "svg").exists());
    }

    #[tokio::test]
    async fn tenant_delete_removes_the_branding_row_and_logo_file() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        insert_tenant(&application, "acme");
        let platform = cookie_for(&application, "", "admin");
        assert_eq!(
            put_logo(
                &application,
                &platform,
                "acme",
                "image/png",
                b"\x89PNG\r\n\x1a\npixels".to_vec()
            )
            .await,
            StatusCode::OK
        );
        let logo = paths::branding_logo_path(&application.config.data_dir, "acme", "png");
        assert!(logo.is_file());

        let request = Request::builder()
            .method("DELETE")
            .uri("/api/admin/tenants/acme")
            .header("cookie", &platform)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app::router(application.clone())
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(application.store.branding("acme").unwrap().is_none());
        assert!(!logo.exists());
    }

    #[tokio::test]
    async fn branding_mutations_require_the_csrf_header() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let platform = cookie_for(&application, "", "admin");
        let request = Request::builder()
            .method("PUT")
            .uri("/api/admin/branding/default")
            .header("cookie", &platform)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"Acme","color":""}"#))
            .unwrap();
        let response = app::router(application.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "missing X-Votport header");
    }
}

#[cfg(test)]
mod tenant_offboard_tests {
    use super::*;

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use std::sync::Arc;

    use crate::api::testing;
    use crate::app;
    use crate::session::InsertError;
    use crate::store::{Link, Tenant};

    async fn login_cookie(router: axum::Router) -> String {
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/login")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                1234,
            ))))
            .body(Body::from(format!(
                "{{\"password\":\"{}\"}}",
                testing::TEST_PASSWORD
            )))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response
            .headers()
            .get(header::SET_COOKIE)
            .expect("login sets a cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    fn named_tenant(key: &str) -> Tenant {
        Tenant {
            key: key.to_owned(),
            label: key.to_owned(),
            admin_group: None,
            max_total_bytes: None,
            max_links: None,
            max_sessions: None,
            created_at: 0,
        }
    }

    fn default_link(id: &str, dest: &str) -> Link {
        Link {
            id: id.to_owned(),
            tenant: String::new(),
            label: id.to_owned(),
            dest: dest.to_owned(),
            password_hash: None,
            created_at: 0,
            expires_at: None,
            max_bytes: None,
            active: true,
            legal_hold: false,
            notify_on_upload: false,
            uploads: Vec::new(),
            events: Vec::new(),
        }
    }

    fn named_link(tenant: &str, id: &str) -> Link {
        Link {
            tenant: tenant.to_owned(),
            ..default_link(id, "")
        }
    }

    fn write_dummy(receive_dir: &std::path::Path, key: &str) -> std::path::PathBuf {
        let dir = receive_dir.join(crate::paths::TENANT_STORAGE_DIR).join(key);
        std::fs::create_dir_all(&dir).unwrap();
        crate::paths::tighten_dir(&dir);
        std::fs::write(dir.join("x.bin"), b"hello").unwrap();
        dir
    }

    fn write_outbound_dummy(outbound_dir: &std::path::Path, key: &str) -> std::path::PathBuf {
        let dir = outbound_dir
            .join(crate::paths::TENANT_STORAGE_DIR)
            .join(key);
        std::fs::create_dir_all(&dir).unwrap();
        crate::paths::tighten_dir(&dir);
        std::fs::write(dir.join("x.bin"), b"hello").unwrap();
        dir
    }

    async fn create_tenant_req(
        application: Arc<App>,
        cookie: &str,
        key: &str,
    ) -> axum::http::Response<axum::body::Body> {
        let router = app::router(application);
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/tenants")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"key":"{key}","label":"{key}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn delete_tenant_req(
        application: Arc<App>,
        cookie: &str,
        key: &str,
    ) -> axum::http::Response<axum::body::Body> {
        let router = app::router(application);
        router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/admin/tenants/{key}"))
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn delete_purges_the_receive_subtree() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");
        assert!(tenant_dir.join("x.bin").exists());

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!tenant_dir.exists());

        let rows = application.store.audit_export("", 0, 0, 100).unwrap();
        let deleted = rows
            .iter()
            .find(|row| row.event == "tenant_deleted")
            .expect("tenant_deleted audit");
        assert_eq!(deleted.detail["purged_receive"], true);
        assert_eq!(deleted.detail["row_deleted"], true);
        assert!(application.store.tenant("acme").unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_purges_the_outbound_subtree_without_receive_files() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let outbound_dir = write_outbound_dummy(&application.config.outbound_dir, "acme");
        let default_file = application.config.outbound_dir.join("default.bin");
        std::fs::write(&default_file, b"keep").unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!outbound_dir.exists());
        assert!(!application
            .config
            .receive_dir
            .join(crate::paths::TENANT_STORAGE_DIR)
            .join("acme")
            .exists());
        assert!(default_file.exists());
        let rows = application.store.audit_export("", 0, 0, 100).unwrap();
        let deleted = rows
            .iter()
            .find(|row| row.event == "tenant_deleted")
            .expect("tenant_deleted audit");
        assert_eq!(deleted.detail["purged_receive"], false);
        assert_eq!(deleted.detail["purged_outbound"], true);
    }

    #[tokio::test]
    async fn absent_tenant_retry_purges_leftover_outbound_subtree() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let outbound_dir = write_outbound_dummy(&application.config.outbound_dir, "acme");

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!outbound_dir.exists());
        assert!(application.store.tenant("acme").unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_refuses_an_active_outbound_operation() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let operation = application.sessions.try_begin_outbound("acme").unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(application.store.tenant("acme").unwrap().is_some());
        drop(operation);
    }

    #[tokio::test]
    async fn live_link_refuses_delete_and_unpins() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        application
            .store
            .insert_link(named_link("acme", "still-live"))
            .unwrap();
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(tenant_dir.join("x.bin").exists());
        assert!(!application.sessions.tenant_pinned("acme"));
        application
            .sessions
            .insert(
                "s1".to_owned(),
                "still-live".to_owned(),
                "acme".to_owned(),
                tokio::sync::mpsc::channel(1).0,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn store_read_failure_during_delete_unpins_the_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        rusqlite::Connection::open(application.config.data_dir.join("votport.db"))
            .unwrap()
            .execute_batch("DROP TABLE links")
            .unwrap();

        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!application.sessions.tenant_pinned("acme"));
    }

    #[tokio::test]
    async fn link_delete_refuses_an_active_session_then_unpins() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(default_link("busy", ""))
            .unwrap();
        application
            .sessions
            .insert(
                "session".to_owned(),
                "busy".to_owned(),
                String::new(),
                tokio::sync::mpsc::channel(1).0,
            )
            .unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let request = || {
            Request::builder()
                .method("DELETE")
                .uri("/api/admin/links/busy")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap()
        };
        let response = app::router(application.clone())
            .oneshot(request())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(application.store.link("", "busy").unwrap().is_some());

        application.sessions.remove("session");
        let response = app::router(application.clone())
            .oneshot(request())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(application.store.link("", "busy").unwrap().is_none());
    }

    #[tokio::test]
    async fn live_session_refuses_delete_and_leaves_files() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");
        application
            .sessions
            .insert(
                "live".to_owned(),
                "link".to_owned(),
                "acme".to_owned(),
                tokio::sync::mpsc::channel(1).0,
            )
            .unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(tenant_dir.join("x.bin").exists());
        assert!(!application.sessions.tenant_pinned("acme"));
        assert!(application.store.tenant("acme").unwrap().is_some());
    }

    #[tokio::test]
    async fn unknown_key_without_a_directory_is_404() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let keep = application.config.receive_dir.join("keep.bin");
        std::fs::write(&keep, b"root").unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "ghost").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(keep.exists());
        let mut entries: Vec<_> = std::fs::read_dir(&application.config.receive_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        assert_eq!(entries, vec![std::ffi::OsString::from("keep.bin")]);
        assert!(!application.sessions.tenant_pinned("ghost"));
    }

    #[tokio::test]
    async fn leftover_retry_ignores_a_same_named_default_destination() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");
        application
            .store
            .insert_link(default_link("root-dest", "acme"))
            .unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!tenant_dir.exists());
        assert!(application.store.link("", "root-dest").unwrap().is_some());
        assert!(!application.sessions.tenant_pinned("acme"));
    }

    #[tokio::test]
    async fn leftover_retry_purges_an_orphaned_directory() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");
        assert!(application.store.tenant("acme").unwrap().is_none());

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!tenant_dir.exists());
        let rows = application.store.audit_export("", 0, 0, 100).unwrap();
        let deleted = rows
            .iter()
            .find(|row| row.event == "tenant_deleted")
            .expect("tenant_deleted audit");
        assert_eq!(deleted.detail["purged_receive"], true);
        assert_eq!(deleted.detail["row_deleted"], false);
    }

    #[tokio::test]
    async fn overlapping_delete_does_not_unpin_until_owner_finishes() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let (entered, release) = application.sessions.arm_delete_stall();
        let first_app = application.clone();
        let first_cookie = cookie.clone();
        let first =
            tokio::spawn(async move { delete_tenant_req(first_app, &first_cookie, "acme").await });
        entered.await.unwrap();
        assert!(application.sessions.tenant_pinned("acme"));
        assert!(application.store.tenant("acme").unwrap().is_none());

        let second = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let body = second.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"]
                .as_str()
                .unwrap_or_default()
                .contains("already in progress"),
            "error was {json}"
        );
        assert!(application.sessions.tenant_pinned("acme"));
        assert!(tenant_dir.join("x.bin").exists());

        let created = create_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(created.status(), StatusCode::CONFLICT);
        assert!(application.sessions.tenant_pinned("acme"));
        assert!(application.store.tenant("acme").unwrap().is_none());

        release.send(()).unwrap();
        let first_resp = first.await.unwrap();
        assert_eq!(first_resp.status(), StatusCode::OK);
        assert!(!application.sessions.tenant_pinned("acme"));
        assert!(!tenant_dir.exists());
    }

    #[tokio::test]
    async fn create_tenant_refuses_a_pinned_key() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        assert!(application.sessions.pin_tenant_for_delete("acme"));

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = create_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"]
                .as_str()
                .unwrap_or_default()
                .contains("already in progress"),
            "error was {json}"
        );
        assert!(application.store.tenant("acme").unwrap().is_none());
        assert!(application.sessions.tenant_pinned("acme"));
    }

    #[tokio::test]
    async fn create_tenant_refuses_a_multi_segment_key() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        // A key with a separator passes admit_dest but would be unreachable:
        // DELETE matches one path segment and join_under refuses the
        // component, so uploads into it fail too.
        let response = create_tenant_req(application.clone(), &cookie, "a/b").await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(application.store.tenants().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_removes_a_legacy_multi_segment_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // A row of the shape create_tenant used to accept. Deleting it must
        // drop the row without touching disk: no upload ever published under
        // such a key, so that path can only hold a default-tenant link's
        // files.
        application
            .store
            .insert_tenant(crate::store::Tenant {
                key: "clients/acme".to_owned(),
                label: "legacy".to_owned(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        // What a default-tenant link with dest "clients/acme" would have
        // received. The delete must not reach it.
        let bystander = application.config.receive_dir.join("clients").join("acme");
        std::fs::create_dir_all(&bystander).unwrap();
        std::fs::write(bystander.join("statement.pdf"), b"kept").unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "clients%2Facme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(application.store.tenants().unwrap().is_empty());
        assert!(bystander.join("statement.pdf").exists());
    }

    #[tokio::test]
    async fn delete_purges_only_the_reserved_tenant_subtree() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::Tenant {
                key: "acme".to_owned(),
                label: "acme".to_owned(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        application
            .store
            .insert_link(default_link("default-link", "acme"))
            .unwrap();
        let default_dir = application.config.receive_dir.join("acme");
        std::fs::create_dir_all(&default_dir).unwrap();
        std::fs::write(default_dir.join("invoice.pdf"), b"kept").unwrap();
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(application.store.tenant("acme").unwrap().is_none());
        assert!(!tenant_dir.exists());
        assert!(default_dir.join("invoice.pdf").exists());
        assert!(!application.sessions.tenant_pinned("acme"));
    }

    #[tokio::test]
    async fn unknown_key_with_a_colliding_link_but_no_directory_is_404() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // A colliding link exists, but there is no tenant row and nothing on
        // disk, so there is no purge to conflict with: this is a 404, not the
        // purge refusal.
        application
            .store
            .insert_link(default_link("root-dest", "acme"))
            .unwrap();
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_tenant_does_not_claim_the_same_named_default_folder() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let occupied = application.config.receive_dir.join("acme");
        std::fs::create_dir_all(&occupied).unwrap();
        std::fs::write(occupied.join("invoice.pdf"), b"someone else's").unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = create_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(application.store.tenants().unwrap().len(), 1);
        assert!(occupied.join("invoice.pdf").exists());
    }

    #[test]
    fn stored_paths_resolve_inside_the_owning_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let root = &application.config.receive_dir;
        // stored_as is relative to the tenant's own subtree, because the
        // session builds it from the link dest while the tenant prefix is
        // added separately when the destination directory is assembled.
        assert_eq!(
            stored_path(&application, "acme", "inbox/a.txt").unwrap(),
            root.join(crate::paths::TENANT_STORAGE_DIR)
                .join("acme")
                .join("inbox")
                .join("a.txt")
        );
        // The default tenant has no prefix.
        assert_eq!(
            stored_path(&application, "", "inbox/a.txt").unwrap(),
            root.join("inbox").join("a.txt")
        );
        // The two must never resolve to the same file: that is one namespace
        // deleting another's bytes.
        assert_ne!(
            stored_path(&application, "acme", "inbox/a.txt").unwrap(),
            stored_path(&application, "", "inbox/a.txt").unwrap()
        );
    }

    #[tokio::test]
    async fn create_tenant_accepts_an_empty_folder() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // An empty directory holds nobody's files, so it is not a collision.
        std::fs::create_dir_all(application.config.receive_dir.join("acme")).unwrap();
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = create_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_tenant_allows_a_same_named_default_link_destination() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(default_link("root-dest", "acme"))
            .unwrap();
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = create_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(application.store.tenants().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn create_link_allows_a_dest_named_after_a_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        assert_eq!(
            create_tenant_req(application.clone(), &cookie, "acme")
                .await
                .status(),
            StatusCode::OK
        );
        for dest in ["acme", "acme/invoices"] {
            let response = app::router(application.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/admin/links")
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"label":"invoices","dest":"{dest}"}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "dest {dest}");
        }
        assert_eq!(application.store.links("").unwrap().len(), 2);
    }

    #[test]
    fn tenant_keys_are_single_segments() {
        assert_eq!(admit_tenant_key("acme").ok().as_deref(), Some("acme"));
        assert_eq!(admit_tenant_key("/acme/").ok().as_deref(), Some("acme"));
        assert_eq!(
            admit_tenant_key("acme-1_ok").ok().as_deref(),
            Some("acme-1_ok")
        );
        for bad in [
            "a/b",
            "",
            "default",
            "..",
            "clients/acme",
            "Acme",
            "café",
            "acme.inc",
            "acme corp",
        ] {
            assert!(admit_tenant_key(bad).is_err(), "{bad} was admitted");
        }
        // Delete admits a multi-segment key so legacy rows stay removable.
        assert_eq!(
            admit_tenant_ref("clients/acme").ok().as_deref(),
            Some("clients/acme")
        );
        for bad in ["", "default", ".."] {
            assert!(admit_tenant_ref(bad).is_err(), "{bad} was admitted");
        }
    }

    #[test]
    fn insert_returns_pinned_while_delete_holds_the_pin() {
        let sessions = crate::session::Sessions::new();
        assert!(sessions.pin_tenant_for_delete("acme"));
        let err = sessions
            .insert(
                "s".to_owned(),
                "l".to_owned(),
                "acme".to_owned(),
                tokio::sync::mpsc::channel(1).0,
            )
            .unwrap_err();
        assert_eq!(err, InsertError::TenantPinned);
    }
}

#[cfg(test)]
mod ops_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;

    #[tokio::test]
    async fn metrics_refuse_a_bad_token_and_serve_counts() {
        let directory = tempfile::tempdir().unwrap();
        let mut config_source = testing_config_with_token(directory.path(), Some("secret-token"));
        let application = build_with(config_source.take().unwrap());
        let router = app::router(application.clone());

        let response = router
            .oneshot(
                Request::get("/metrics")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/metrics")
                    .header("authorization", "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("votport_tenants"));
        assert!(text.contains("votport_received_bytes{tenant=\"default\"} 0"));
        assert!(text.contains("votport_sessions_active"));
    }

    fn testing_config_with_token(
        _directory: &std::path::Path,
        token: Option<&str>,
    ) -> Option<crate::config::Config> {
        let mut config = testing_config_snapshot();
        config.metrics_token = token.map(str::to_owned);
        Some(config)
    }

    fn testing_config_snapshot() -> crate::config::Config {
        // testing::build owns its tempdirs; this variant re-derives the same
        // config with a metrics token so /metrics authz can be exercised.
        let directory = std::env::temp_dir().join(format!(
            "votport-metrics-test-{}",
            crate::auth::random_token()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let mut config = testing_config_public();
        config.data_dir = directory.join("data");
        config.receive_dir = directory.join("received");
        config.outbound_dir = directory.join("outbound");
        config
    }

    fn testing_config_public() -> crate::config::Config {
        crate::config::Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            push_bind: None,
            push_certificate: None,
            push_private_key: None,
            push_advertise: None,
            data_dir: std::path::PathBuf::from("/nonexistent"),
            receive_dir: std::path::PathBuf::from("/nonexistent"),
            outbound_dir: std::path::PathBuf::from("/nonexistent"),
            web_root: std::path::PathBuf::from("../web"),
            admin_password_hash: crate::auth::hash_password(testing::TEST_PASSWORD).unwrap(),
            admin_token_tag: "tag".to_owned(),
            notify_webhook: None,
            notify_ntfy: None,
            notify_ntfy_token: None,
            notify_pushover: None,
            smtp_host: None,
            smtp_port: 587,
            smtp_starttls: true,
            smtp_username: None,
            smtp_password: None,
            smtp_from: None,
            smtp_to: None,
            public_url: None,
            max_upload_bytes: 1024 * 1024,
            allow_hidden: false,
            session_idle_secs: 60,
            audit_retention_days: 400,
            upload_retention_days: 0,
            default_max_total_bytes: None,
            default_max_links: None,
            default_max_sessions: None,
            public_password_login: true,
            metrics_token: None,
            max_total_sessions: 32,
            sso_session_secs: 7 * 24 * 3600,
            trusted_proxies: Vec::new(),
            oidc: None,
        }
    }

    fn build_with(config: crate::config::Config) -> std::sync::Arc<App> {
        app::build(config).unwrap()
    }
}

#[cfg(test)]
mod backup_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;

    async fn login(application: Arc<App>) -> String {
        let response = app::router(application)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/login")
                    .header("content-type", "application/json")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        1234,
                    ))))
                    .body(Body::from(format!(
                        "{{\"password\":\"{}\"}}",
                        testing::TEST_PASSWORD
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn backup_route_serves_a_snapshot_and_requires_sign_in() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .audit("", "", "probe", "", &serde_json::json!({}));

        // Unauthenticated requests are refused.
        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/backup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Signed in, the route serves a non-empty SQLite snapshot.
        let cookie = login(application.clone()).await;

        let router = app::router(application);
        let response = router
            .oneshot(
                Request::get("/api/admin/backup")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_length = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!body.is_empty());
        // SQLite databases begin with the magic string.
        assert!(body.starts_with(b"SQLite format 3\0"));
        assert_eq!(content_length, Some(body.len()));
    }

    #[tokio::test]
    async fn backup_settings_match_the_browser_contract_and_redact_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login(application.clone()).await;
        let local_path = application.config.data_dir.join("custom-backups");
        std::fs::create_dir(&local_path).unwrap();
        let body = serde_json::json!({
            "enabled": true,
            "interval_secs": 3600,
            "retention_days": 7,
            "retention_count": 5,
            "destination": "local",
            "local_path": local_path,
            "s3_endpoint": null,
            "s3_region": null,
            "s3_bucket": null,
            "s3_prefix": null,
            "s3_path_style": false,
            "encrypt": true,
            "access_key_id": "visible-only-on-write",
            "secret_access_key": "never-return-this",
            "passphrase": "correct horse battery staple"
        });

        let response = app::router(application.clone())
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let guard = application.backup_lock.lock().await;
        let response = app::router(application.clone())
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let error = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{}",
            String::from_utf8_lossy(&error)
        );
        drop(guard);

        let response = app::router(application.clone())
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app::router(application.clone())
            .oneshot(
                Request::get("/api/admin/backups")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("never-return-this"));
        assert!(!text.contains("correct horse battery staple"));
        let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["config"]["interval_secs"], 3600);
        assert_eq!(response["config"]["passphrase_configured"], true);

        let mut unknown = body;
        unknown["unexpected"] = serde_json::json!(true);
        let response = app::router(application.clone())
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(unknown.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/backups")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let id = created["id"].as_str().unwrap();
        let shutdown = Arc::clone(&application.shutdown);
        let shutdown_waiter = tokio::spawn(async move { shutdown.notified().await });
        tokio::task::yield_now().await;
        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/backups/restore")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(
                        serde_json::json!({ "source": "local", "id": id }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let restored: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(restored["pending"], true);
        tokio::time::timeout(std::time::Duration::from_secs(1), shutdown_waiter)
            .await
            .unwrap()
            .unwrap();

        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/backups")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            crate::backup::scheduler(application),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn missing_backup_mount_can_be_repaired_in_app() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login(application.clone()).await;
        let missing = application.config.data_dir.join("detached-backups");
        std::fs::create_dir(&missing).unwrap();
        let mut body = serde_json::json!({
            "enabled": false,
            "interval_secs": 3600,
            "retention_days": 7,
            "retention_count": 5,
            "destination": "local",
            "local_path": missing,
            "s3_endpoint": null,
            "s3_region": null,
            "s3_bucket": null,
            "s3_prefix": null,
            "s3_path_style": false,
            "encrypt": false
        });
        let response = app::router(application.clone())
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        std::fs::remove_dir(&missing).unwrap();

        let response = app::router(application.clone())
            .oneshot(
                Request::get("/api/admin/backups")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert!(response["inventory_error"].is_string());
        assert_eq!(response["config"]["local_path"], body["local_path"]);

        body["local_path"] = serde_json::Value::Null;
        let response = app::router(application)
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[cfg(test)]
mod settings_api_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::auth::{self, TenantGrant};
    use crate::store::SettingWrite;

    #[tokio::test]
    async fn sso_session_lifetime_follows_the_settings_overlay() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let sso = auth::AdminIdentity {
            subject: "sso:user".to_owned(),
            tenant: String::new(),
            role: "admin".to_owned(),
            grants: vec![TenantGrant {
                tenant: String::new(),
                role: "admin".to_owned(),
            }],
            credential_version: 1,
        };
        // Env default: 7 days for both SSO and break-glass.
        let cookie = issue_admin_cookie(&application, &sso).unwrap();
        assert!(cookie.contains("Max-Age=604800"), "{cookie}");
        application
            .store
            .put_settings(
                "sso:admin",
                &[(
                    "sso_session_secs".to_owned(),
                    SettingWrite::Set("3600".to_owned()),
                )],
            )
            .unwrap();
        let cookie = issue_admin_cookie(&application, &sso).unwrap();
        assert!(cookie.contains("Max-Age=3600"), "{cookie}");
        // Break-glass keeps its fixed lifetime regardless of the setting.
        let local = issue_admin_cookie(&application, &auth::AdminIdentity::local_admin()).unwrap();
        assert!(local.contains("Max-Age=604800"), "{local}");
    }

    fn cookie_for(app: &App, tenant: &str, role: &str) -> String {
        let identity = auth::AdminIdentity {
            subject: format!("sso:{tenant}:{role}"),
            tenant: tenant.to_owned(),
            role: role.to_owned(),
            grants: vec![TenantGrant {
                tenant: tenant.to_owned(),
                role: role.to_owned(),
            }],
            credential_version: 1,
        };
        super::test_admin_cookie(app, &identity)
    }

    async fn send(
        application: Arc<App>,
        request: Request<Body>,
    ) -> (StatusCode, serde_json::Value) {
        let response = app::router(application).oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
        (status, json)
    }

    #[tokio::test]
    async fn draining_round_trips_through_the_settings_route() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application.clone(),
            Request::get("/api/admin/settings")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["draining"], false);

        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"draining":true}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // The JSON bool is stored and resolves back to draining.
        assert!(
            application
                .store
                .resolved_settings(&application.config)
                .unwrap()
                .draining
        );
        let (_, json) = send(
            application,
            Request::get("/api/admin/settings")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(json["draining"], true);
        assert_eq!(json["draining_source"], "db");
    }

    #[tokio::test]
    async fn get_settings_returns_env_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application,
            Request::get("/api/admin/settings")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["audit_retention_days"], 400);
        assert_eq!(json["audit_retention_days_source"], "env");
        assert_eq!(json["upload_retention_days"], 0);
        assert_eq!(json["upload_retention_days_source"], "env");
        assert_eq!(json["notify_webhook"], serde_json::Value::Null);
        assert_eq!(json["notify_webhook_source"], "env");
        assert_eq!(json["notify_ntfy_token_set"], false);
        assert_eq!(json["default_max_total_bytes"], serde_json::Value::Null);
        assert_eq!(json["public_password_login"], true);
        assert_eq!(json["sso_configured"], false);
        assert_eq!(json["smtp_host"], serde_json::Value::Null);
        assert_eq!(json["smtp_port"], 587);
        assert_eq!(json["smtp_starttls"], true);
        assert_eq!(json["smtp_password_set"], false);
        assert_eq!(json["smtp_password_source"], "env");
        assert!(json.get("smtp_password").is_none());
        let deployment = &json["deployment"];
        assert_eq!(deployment["bind"], "127.0.0.1:0");
        assert_eq!(deployment["public_url"], "https://drop.example.com");
        assert_eq!(
            deployment["data_dir"],
            directory.path().join("data").to_string_lossy().as_ref()
        );
        assert_eq!(
            deployment["receive_dir"],
            directory.path().join("received").to_string_lossy().as_ref()
        );
        assert_eq!(
            deployment["outbound_dir"],
            directory.path().join("outbound").to_string_lossy().as_ref()
        );
        assert_eq!(deployment["max_upload_bytes"], 1024 * 1024);
        assert_eq!(deployment["allow_hidden"], false);
        assert_eq!(deployment["session_idle_secs"], 60);
        assert_eq!(deployment["trusted_proxies"], json!([]));
        assert_eq!(deployment["metrics_configured"], false);
        assert_eq!(deployment["push_configured"], false);
        assert_eq!(deployment["push_private_key_configured"], false);
        assert_eq!(deployment["oidc_configured"], false);
        assert_eq!(deployment["oidc_client_secret_configured"], false);
        // Config::admin_password_hash is represented by the existing
        // password form. Config::admin_token_tag is internal session state,
        // so neither belongs in this API payload.
        for field in [
            "notify_webhook",
            "notify_webhook_source",
            "notify_ntfy",
            "notify_ntfy_source",
            "notify_ntfy_token_set",
            "notify_ntfy_token_source",
            "notify_pushover_set",
            "notify_pushover_token_set",
            "notify_pushover_token_source",
            "notify_pushover_user_set",
            "notify_pushover_user_source",
            "smtp_host",
            "smtp_host_source",
            "smtp_port",
            "smtp_port_source",
            "smtp_starttls",
            "smtp_starttls_source",
            "smtp_username",
            "smtp_username_source",
            "smtp_password_set",
            "smtp_password_source",
            "smtp_from",
            "smtp_from_source",
            "smtp_to",
            "smtp_to_source",
            "audit_retention_days",
            "audit_retention_days_source",
            "upload_retention_days",
            "upload_retention_days_source",
            "default_max_total_bytes",
            "default_max_total_bytes_source",
            "default_max_links",
            "default_max_links_source",
            "default_max_sessions",
            "default_max_sessions_source",
            "public_password_login",
            "public_password_login_source",
            "sso_session_secs",
            "sso_session_secs_source",
            "sso_configured",
        ] {
            assert!(json.get(field).is_some(), "missing settings field {field}");
        }
        for field in [
            "bind",
            "public_url",
            "data_dir",
            "receive_dir",
            "outbound_dir",
            "web_root",
            "max_upload_bytes",
            "allow_hidden",
            "session_idle_secs",
            "trusted_proxies",
            "metrics_configured",
            "push_bind",
            "push_advertise",
            "push_certificate",
            "push_certificate_configured",
            "push_private_key_configured",
            "push_configured",
            "oidc_issuer",
            "oidc_client_id",
            "oidc_admin_group",
            "oidc_client_secret_configured",
            "oidc_configured",
        ] {
            assert!(
                deployment.get(field).is_some(),
                "missing deployment field {field}"
            );
        }
        for secret in [
            "admin_password_hash",
            "admin_token_tag",
            "metrics_token",
            "push_private_key",
            "oidc_client_secret",
            "notify_ntfy_token",
            "notify_pushover_token",
            "notify_pushover_user",
            "smtp_password",
        ] {
            assert!(
                json.get(secret).is_none() && deployment.get(secret).is_none(),
                "secret leaked as {secret}"
            );
        }
    }

    #[tokio::test]
    async fn get_settings_redacts_smtp_password() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application,
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"smtp_host":"smtp.example.com","smtp_from":"votport@example.com","smtp_to":"ops@example.com","smtp_password":"s3cret"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["smtp_host"], "smtp.example.com");
        assert_eq!(json["smtp_password_set"], true);
        assert_eq!(json["smtp_password_source"], "db");
        assert!(json.get("smtp_password").is_none());
    }

    #[tokio::test]
    async fn put_then_get_shows_db_source() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"audit_retention_days":7,"notify_webhook":"https://db.example/hook"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["audit_retention_days"], 7);
        assert_eq!(json["audit_retention_days_source"], "db");
        assert_eq!(json["notify_webhook"], "https://db.example/hook");
        assert_eq!(json["notify_webhook_source"], "db");
        assert_eq!(json["upload_retention_days_source"], "env");
    }

    #[tokio::test]
    async fn put_omitting_a_secret_leaves_the_previous_value() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"notify_ntfy_token":"secret-token"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, json) = send(
            application,
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"audit_retention_days":10}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["notify_ntfy_token_set"], true);
        assert_eq!(json["notify_ntfy_token_source"], "db");
        assert!(json.get("notify_ntfy_token").is_none());
        assert_eq!(json["audit_retention_days"], 10);
    }

    #[tokio::test]
    async fn put_empty_url_disables_env_webhook() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = testing::config(directory.path());
        config.notify_webhook = Some("https://env.example/hook".to_owned());
        let application = app::build(config).unwrap();
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"notify_webhook":""}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["notify_webhook"], serde_json::Value::Null);
        assert_eq!(json["notify_webhook_source"], "db");

        let (status, json) = send(
            application,
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"notify_webhook":null}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["notify_webhook"], "https://env.example/hook");
        assert_eq!(json["notify_webhook_source"], "env");
    }

    #[tokio::test]
    async fn put_rejects_zero_default_quota_and_non_http_url() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"default_max_total_bytes":0}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, json) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"audit_retention_days":0}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["audit_retention_days"], 0);

        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"notify_webhook":"ftp://nope"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, _) = send(
            application,
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"smtp_port":0}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn viewer_and_named_admin_cannot_read_settings_or_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let viewer = cookie_for(&application, "", "viewer");
        let named = cookie_for(&application, "acme", "admin");

        for cookie in [&viewer, &named] {
            let (status, _) = send(
                application.clone(),
                Request::get("/api/admin/settings")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let (status, _) = send(
                application.clone(),
                Request::get("/api/admin/tenants")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn put_settings_requires_csrf_header() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application,
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"audit_retention_days":1}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json["error"], "missing X-Votport header");
    }

    #[tokio::test]
    async fn patch_tenant_quota_then_create_session_hits_the_cap() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::Tenant {
                key: "acme".to_owned(),
                label: String::new(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        application
            .store
            .insert_link(crate::store::Link {
                id: "acme-link".to_owned(),
                tenant: "acme".to_owned(),
                label: "open".to_owned(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,
                notify_on_upload: false,
                uploads: Vec::new(),
                events: Vec::new(),
            })
            .unwrap();
        let cookie = cookie_for(&application, "", "admin");
        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PATCH")
                .uri("/api/admin/tenants/acme")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"max_total_bytes":100}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let router = app::router(application);
        let request = Request::builder()
            .method("POST")
            .uri("/api/r/acme-link/session")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
            .body(Body::from(
                r#"{"package":{"suite":"blake3","root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","length":200}}"#,
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn create_tenant_fills_omitted_quotas_from_overlay() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"default_max_total_bytes":100}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, json) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/tenants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"key":"acme","label":"Acme"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["key"], "acme");
        let tenant = application
            .store
            .tenant("acme")
            .unwrap()
            .expect("tenant stored");
        assert_eq!(tenant.max_total_bytes, Some(100));
        assert_eq!(tenant.max_links, None);
        assert_eq!(tenant.max_sessions, None);
    }

    #[tokio::test]
    async fn tenant_api_round_trips_full_u64_quotas() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/tenants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"key":"acme","label":"Acme","max_total_bytes":18446744073709551615,"max_links":18446744073709551615,"max_sessions":18446744073709551615}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["key"], "acme");
        let tenant = application.store.tenant("acme").unwrap().unwrap();
        assert_eq!(tenant.max_total_bytes, Some(u64::MAX));
        assert_eq!(tenant.max_links, Some(u64::MAX));
        assert_eq!(tenant.max_sessions, Some(u64::MAX));

        let (status, json) = send(
            application.clone(),
            Request::builder()
                .method("PATCH")
                .uri("/api/admin/tenants/acme")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"max_total_bytes":18446744073709551614,"max_links":18446744073709551614,"max_sessions":18446744073709551614}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["ok"], true);
        let tenant = application.store.tenant("acme").unwrap().unwrap();
        assert_eq!(tenant.max_total_bytes, Some(u64::MAX - 1));
        assert_eq!(tenant.max_links, Some(u64::MAX - 1));
        assert_eq!(tenant.max_sessions, Some(u64::MAX - 1));
    }

    #[tokio::test]
    async fn default_tenant_create_session_hits_overlay_byte_cap() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(crate::store::Link {
                id: "default-link".to_owned(),
                tenant: String::new(),
                label: "open".to_owned(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,
                notify_on_upload: false,
                uploads: Vec::new(),
                events: Vec::new(),
            })
            .unwrap();
        let cookie = cookie_for(&application, "", "admin");
        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"default_max_total_bytes":100}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let router = app::router(application);
        let request = Request::builder()
            .method("POST")
            .uri("/api/r/default-link/session")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
            .body(Body::from(
                r#"{"package":{"suite":"blake3","root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","length":200}}"#,
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn overlay_skips_invalid_text_without_panic() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .put_settings(
                "local",
                &[(
                    "audit_retention_days".to_owned(),
                    SettingWrite::Set("nope".to_owned()),
                )],
            )
            .unwrap();
        let resolved = application
            .store
            .resolved_settings(&application.config)
            .unwrap();
        assert_eq!(resolved.audit_retention_days, 400);
    }
}

#[cfg(test)]
mod principals_api_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::auth::{self, TenantGrant};

    fn cookie_for(app: &App, identity: auth::AdminIdentity) -> String {
        super::test_admin_cookie(app, &identity)
    }

    fn sso_identity(subject: &str, cv: u64) -> auth::AdminIdentity {
        auth::AdminIdentity {
            subject: subject.to_owned(),
            tenant: String::new(),
            role: "admin".to_owned(),
            grants: vec![TenantGrant {
                tenant: String::new(),
                role: "admin".to_owned(),
            }],
            credential_version: cv,
        }
    }

    fn cookie_without_cv(app: &App, subject: &str) -> String {
        let payload = serde_json::json!({
            "subject": subject,
            "tenant": "",
            "role": "admin",
            "grants": []
        })
        .to_string();
        format!(
            "votport_admin={}; Path=/",
            auth::issue_admin_token_from_payload(
                &app.secret,
                &payload,
                &admin_token_phc(app).unwrap()
            )
        )
    }

    fn platform_cookie(app: &App) -> String {
        cookie_for(app, auth::AdminIdentity::local_admin())
    }

    fn cookie_token(set_cookie: &str) -> &str {
        set_cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("votport_admin=")
            .unwrap()
    }

    fn payload_cv(set_cookie: &str) -> u64 {
        let token = cookie_token(set_cookie);
        let payload_hex = token.split('.').nth(1).unwrap();
        let payload = hex::decode(payload_hex).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        json["cv"].as_u64().unwrap()
    }

    async fn send(
        application: Arc<App>,
        request: Request<Body>,
    ) -> (StatusCode, serde_json::Value, Option<String>) {
        let response = app::router(application).oneshot(request).await.unwrap();
        let status = response.status();
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
        (status, json, cookie)
    }

    fn insert_acme(application: &App) {
        application
            .store
            .insert_tenant(crate::store::Tenant {
                key: "acme".to_owned(),
                label: String::new(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
    }

    #[tokio::test]
    async fn payload_without_cv_still_verifies_when_no_row() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_without_cv(&application, "user@example.com");
        let (status, json, _) = send(
            application,
            Request::get("/api/admin/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["ok"], true);
    }

    #[tokio::test]
    async fn missing_row_with_cv_2_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, sso_identity("user@example.com", 2));
        let (status, _, _) = send(
            application,
            Request::get("/api/admin/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cv_1_against_row_2_fails_require_admin() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        application
            .store
            .revoke_principal("user@example.com")
            .unwrap();
        let cookie = cookie_for(&application, sso_identity("user@example.com", 1));
        let (status, _, _) = send(
            application,
            Request::get("/api/admin/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_then_unblock_then_live_version_passes() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        let platform = platform_cookie(&application);
        let (status, _, _) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/revoke")
                .header("cookie", &platform)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"user@example.com"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let stale = cookie_for(&application, sso_identity("user@example.com", 1));
        let (status, _, _) = send(
            application.clone(),
            Request::get("/api/admin/session")
                .header("cookie", &stale)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _, _) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/unblock")
                .header("cookie", &platform)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"user@example.com"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, _) = send(
            application.clone(),
            Request::get("/api/admin/session")
                .header("cookie", &stale)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let live = application
            .store
            .principal("user@example.com")
            .unwrap()
            .unwrap()
            .credential_version;
        assert_eq!(live, 2);
        let cookie = cookie_for(&application, sso_identity("user@example.com", live));
        let (status, json, _) = send(
            application,
            Request::get("/api/admin/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["ok"], true);
    }

    #[tokio::test]
    async fn switch_tenant_reissues_the_same_cv() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        insert_acme(&application);
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        application
            .store
            .revoke_principal("user@example.com")
            .unwrap();
        application
            .store
            .unblock_principal("user@example.com")
            .unwrap();
        let mut identity = sso_identity("user@example.com", 2);
        identity.grants.push(TenantGrant {
            tenant: "acme".to_owned(),
            role: "admin".to_owned(),
        });
        let cookie = cookie_for(&application, identity);
        let (status, _, set_cookie) = send(
            application,
            Request::builder()
                .method("POST")
                .uri("/api/admin/tenant")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"tenant":"acme"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let set_cookie = set_cookie.expect("switch reissues a cookie");
        assert_eq!(payload_cv(&set_cookie), 2);
    }

    #[tokio::test]
    async fn local_identity_sees_named_tenant_grants() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        insert_acme(&application);
        let cookie = platform_cookie(&application);
        let (status, json, _) = send(
            application.clone(),
            Request::get("/api/admin/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let grants = json["grants"].as_array().unwrap();
        assert!(
            grants
                .iter()
                .any(|grant| grant["tenant"] == "acme" && grant["role"] == "admin"),
            "grants were {grants:?}"
        );
        let (status, _, _) = send(
            application,
            Request::builder()
                .method("POST")
                .uri("/api/admin/tenant")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"tenant":"acme"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn upsert_then_list_tenants_contains_the_subject() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal(
                "user@example.com",
                &["employees".to_owned()],
                &json!([{"tenant":"","role":"viewer"}]),
            )
            .unwrap();
        let cookie = platform_cookie(&application);
        let (status, json, _) = send(
            application,
            Request::get("/api/admin/tenants")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let principals = json["principals"].as_array().unwrap();
        assert_eq!(principals.len(), 1);
        assert_eq!(principals[0]["subject"], "user@example.com");
        assert_eq!(principals[0]["blocked"], false);
        assert_eq!(principals[0]["credential_version"], 1);
        assert_eq!(principals[0]["last_groups"][0], "employees");
        assert_eq!(principals[0]["source"], "sso");
    }

    #[tokio::test]
    async fn principal_page_is_platform_only_and_validates_bounds() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("Alice%literal", &[], &json!([]))
            .unwrap();
        let named = cookie_for(
            &application,
            auth::AdminIdentity {
                subject: "named-admin".to_owned(),
                tenant: "acme".to_owned(),
                role: "admin".to_owned(),
                grants: vec![TenantGrant {
                    tenant: "acme".to_owned(),
                    role: "admin".to_owned(),
                }],
                credential_version: 1,
            },
        );
        let (status, _, _) = send(
            application.clone(),
            Request::get("/api/admin/principals")
                .header("cookie", &named)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let platform = platform_cookie(&application);
        let (status, json, _) = send(
            application.clone(),
            Request::get("/api/admin/principals?limit=1&q=%25literal")
                .header("cookie", &platform)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["total"], 1);
        assert_eq!(json["principals"][0]["subject"], "Alice%literal");

        for uri in [
            "/api/admin/principals?limit=0",
            "/api/admin/principals?limit=101",
            "/api/admin/principals?offset=-1",
        ] {
            let (status, _, _) = send(
                application.clone(),
                Request::get(uri)
                    .header("cookie", &platform)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{uri}");
        }
        let long_query = "a".repeat(101);
        let (status, _, _) = send(
            application,
            Request::get(format!("/api/admin/principals?q={long_query}"))
                .header("cookie", &platform)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn legacy_tenant_principals_are_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        for index in 0..51 {
            application
                .store
                .upsert_sso_principal(&format!("user-{index:02}"), &[], &json!([]))
                .unwrap();
        }
        let platform = platform_cookie(&application);
        let (status, json, _) = send(
            application,
            Request::get("/api/admin/tenants")
                .header("cookie", &platform)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["principals"].as_array().unwrap().len(), 50);
        assert_eq!(json["principals_truncated"], true);
    }

    #[tokio::test]
    async fn named_tenant_admin_cannot_revoke() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        let cookie = cookie_for(
            &application,
            auth::AdminIdentity {
                subject: "sso:acme".to_owned(),
                tenant: "acme".to_owned(),
                role: "admin".to_owned(),
                grants: vec![TenantGrant {
                    tenant: "acme".to_owned(),
                    role: "admin".to_owned(),
                }],
                credential_version: 1,
            },
        );
        let (status, _, _) = send(
            application,
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/revoke")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"user@example.com"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn viewer_cannot_list_principals() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        let cookie = cookie_for(
            &application,
            auth::AdminIdentity {
                subject: "sso:viewer".to_owned(),
                tenant: String::new(),
                role: "viewer".to_owned(),
                grants: vec![TenantGrant {
                    tenant: String::new(),
                    role: "viewer".to_owned(),
                }],
                credential_version: 1,
            },
        );
        let (status, json, _) = send(
            application,
            Request::get("/api/admin/tenants")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(json.get("principals").is_none());
    }

    #[tokio::test]
    async fn revoke_refuses_local_and_unknown() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = platform_cookie(&application);
        let (status, _, _) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/revoke")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"local"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, _, _) = send(
            application,
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/revoke")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"missing@example.com"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn revoke_requires_csrf_header() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        let cookie = platform_cookie(&application);
        let (status, _, _) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/revoke")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"user@example.com"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let row = application
            .store
            .principal("user@example.com")
            .unwrap()
            .unwrap();
        assert!(!row.blocked);
        assert_eq!(row.credential_version, 1);
    }
}

#[cfg(test)]
mod notification_and_limit_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use crate::api::testing;
    use crate::app;

    fn admin_cookie(application: &App) -> String {
        let token = auth::issue_admin_token(
            &application.secret,
            &auth::AdminIdentity::local_admin(),
            &application.config.admin_token_tag,
        );
        format!("votport_admin={token}")
    }

    async fn create_link(application: Arc<App>, max_bytes: Option<u64>) -> StatusCode {
        let cookie = admin_cookie(&application);
        app::router(application)
            .oneshot(
                Request::post("/api/admin/links")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "label": "test", "max_bytes": max_bytes }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn explicit_link_max_bytes_must_be_within_configured_bounds() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        assert_eq!(
            create_link(application.clone(), Some(0)).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            create_link(
                application.clone(),
                Some(application.config.max_upload_bytes.saturating_add(1)),
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(create_link(application.clone(), None).await, StatusCode::OK);
        assert_eq!(
            create_link(application.clone(), Some(123)).await,
            StatusCode::OK
        );
        assert!(application
            .store
            .links("")
            .unwrap()
            .iter()
            .any(|link| link.max_bytes == Some(123)));
        assert_eq!(application.store.links("").unwrap()[0].max_bytes, None);
    }

    #[tokio::test]
    async fn receive_link_passwords_are_limited_to_256_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = admin_cookie(&application);
        let create = |password: String| {
            let application = application.clone();
            let cookie = cookie.clone();
            async move {
                app::router(application.clone())
                    .oneshot(
                        Request::post("/api/admin/links")
                            .header("cookie", &cookie)
                            .header("x-votport", "1")
                            .header("content-type", "application/json")
                            .body(Body::from(
                                json!({ "label": "test", "password": password }).to_string(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
                    .status()
            }
        };

        assert_eq!(create("a".repeat(256)).await, StatusCode::OK);
        assert_eq!(create("é".repeat(128)).await, StatusCode::OK);
        assert_eq!(
            create("a".repeat(257)).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            create("é".repeat(129)).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn switch_tenant_requires_csrf_header() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = admin_cookie(&application);
        let response = app::router(application)
            .oneshot(
                Request::post("/api/admin/tenant")
                    .header("cookie", cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tenant":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn notification_test_requires_a_saved_channel() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/notifications/test")
                    .header("cookie", admin_cookie(&application))
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn notification_test_reports_saved_channel_failures() {
        let directory = tempfile::tempdir().unwrap();
        let mut application = testing::build(directory.path());
        Arc::get_mut(&mut application)
            .unwrap()
            .config
            .notify_webhook = Some("http://127.0.0.1:9/notification-test".to_owned());
        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/notifications/test")
                    .header("cookie", admin_cookie(&application))
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["configured"], 1);
        assert_eq!(body["delivered"], 0);
        assert_eq!(
            body["error"],
            "Delivered 0 of 1 configured notification channels"
        );
    }
}
