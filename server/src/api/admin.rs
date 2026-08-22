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
use crate::store::{now_unix, Link};

use super::{cookie_attributes, ApiError, ApiResult};

const ADMIN_COOKIE: &str = "votport_admin";

/// Credential tag bound into admin token MACs: the stored hash when the
/// UI has set one, else the stable tag derived from the environment
/// credential. Either way, rotating the credential evicts sessions and a
/// plain restart does not.
fn admin_token_phc(app: &App) -> String {
    app.store
        .admin_password_hash()
        .unwrap_or_else(|| app.config.admin_token_tag.clone())
}

/// Returns the authenticated principal, or unauthorized.
fn require_admin(app: &App, headers: &HeaderMap) -> ApiResult<auth::AdminIdentity> {
    let token = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| auth::cookie_value(cookies, ADMIN_COOKIE));
    let mut identity = auth::verify_admin_token(
        &app.secret,
        &admin_token_phc(app),
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
        identity.grants = local_admin_grants(app);
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

fn local_admin_grants(app: &App) -> Vec<auth::TenantGrant> {
    let mut grants = vec![auth::TenantGrant {
        tenant: String::new(),
        role: "admin".to_owned(),
    }];
    grants.extend(
        app.store
            .tenants()
            .into_iter()
            .map(|tenant| auth::TenantGrant {
                tenant: tenant.key,
                role: "admin".to_owned(),
            }),
    );
    grants
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
fn require_admin_write(headers: &HeaderMap, identity: &auth::AdminIdentity) -> ApiResult<()> {
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
fn admin_hash(app: &App) -> String {
    app.store
        .admin_password_hash()
        .unwrap_or_else(|| app.config.admin_password_hash.clone())
}

/// Builds the signed admin session cookie value for `identity`.
pub(crate) fn issue_admin_cookie(app: &App, identity: &auth::AdminIdentity) -> String {
    let token = auth::issue_admin_token(&app.secret, identity, &admin_token_phc(app));
    format!(
        "{ADMIN_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800{}",
        cookie_attributes(app)
    )
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
    if app.throttle.locked() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; wait a minute",
        ));
    }
    let ok = tokio::task::spawn_blocking({
        let hash = admin_hash(&app);
        move || auth::verify_password(&request.password, &hash)
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?;
    app.throttle.record(ok);
    let ip = super::client_ip(&headers, &peer);
    if !ok {
        tracing::warn!(target: "audit", event = "admin_login_failed", %ip, "admin login refused");
        app.store
            .audit("", "", "admin_login_failed", &ip, &serde_json::json!({}));
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "wrong password"));
    }
    tracing::info!(target: "audit", event = "admin_login", %ip, "admin signed in");
    app.store
        .audit("", "", "admin_login", &ip, &serde_json::json!({}));
    let cookie = issue_admin_cookie(&app, &auth::AdminIdentity::local_admin());
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

/// Streams audit rows after `since` as JSONL, oldest first. Caps at 10_000
/// rows per call; callers paginate with `since`.
pub async fn admin_audit_export(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Response> {
    let identity = require_admin(&app, &headers)?;
    // Named-tenant principals see only their namespace's rows; the default
    // tenant (platform admin) sees everything.
    let tenant_filter = identity.tenant.clone();
    let limit = query.limit.unwrap_or(1000).min(10_000);
    let rows = app
        .store
        .audit_export(
            &tenant_filter,
            query.since.unwrap_or(0),
            query.after_rowid.unwrap_or(0),
            limit,
        )
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

#[derive(Deserialize)]
pub struct AuditQuery {
    since: Option<u64>,
    /// Cursor for rows sharing `since`'s second (from the previous page's
    /// final `rowid`).
    after_rowid: Option<u64>,
    limit: Option<u64>,
}

pub async fn admin_session(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_admin(&app, &headers)?;
    // Which dashboard pages this principal may open. Named tenants get their
    // own links plus a tenant-filtered audit view; platform administration
    // (tenants, system) is default-tenant admin only.
    let mut pages = vec!["links", "audit"];
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

/// Creates a tenant namespace. Admins only; the key must pass the same
/// component rules as a link destination (it becomes a folder name).
pub async fn create_tenant(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<CreateTenantRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let key = paths::admit_dest(&request.key)
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    if key.is_empty() || key == "default" {
        // "default" would collide with the hard-coded metrics series for the
        // built-in namespace.
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "that tenant key is reserved",
        ));
    }
    if app.store.tenant(&key).is_some() {
        return Err(ApiError::new(StatusCode::CONFLICT, "tenant already exists"));
    }
    if app.sessions.tenant_pinned(&key) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "tenant delete already in progress",
        ));
    }
    let defaults = app.store.resolved_settings(&app.config);
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
        .map_err(ApiError::internal)?;
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
    Ok(Json(json!({
        "tenants": app.store.tenants(),
        "principals": app.store.principals(),
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
    let key = paths::admit_dest(&key)
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    if key.is_empty() || key == "default" {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "that tenant key is reserved",
        ));
    }
    if !app.sessions.pin_tenant_for_delete(&key) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "tenant delete already in progress",
        ));
    }
    let count = app.store.tenant_link_count(&key);
    if count > 0 {
        app.sessions.unpin_tenant(&key);
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("{count} link(s) still reference this tenant; delete them first"),
        ));
    }
    let active = app.sessions.active_for_tenant(&key);
    if active > 0 {
        app.sessions.unpin_tenant(&key);
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("{active} upload(s) are in flight; try again when they finish"),
        ));
    }
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
            let path = match tenant_receive_dir(&app.config.receive_dir, &key) {
                Ok(path) => path,
                Err(error) => {
                    app.sessions.unpin_tenant(&key);
                    return Err(ApiError::internal(error));
                }
            };
            if !path.is_dir() {
                app.sessions.unpin_tenant(&key);
                return Err(ApiError::not_found());
            }
            if default_tenant_dest_collides(&app.store, &key) {
                app.sessions.unpin_tenant(&key);
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "refusing leftover purge: default-tenant dest uses that path",
                ));
            }
            false
        }
        Err(error) => {
            app.sessions.unpin_tenant(&key);
            return Err(ApiError::internal(error));
        }
    };
    let path = match tenant_receive_dir(&app.config.receive_dir, &key) {
        Ok(path) => path,
        Err(error) => {
            app.sessions.unpin_tenant(&key);
            return Err(ApiError::internal(error));
        }
    };
    #[cfg(test)]
    app.sessions.wait_delete_stall().await;
    let purge = tokio::fs::remove_dir_all(&path).await;
    app.sessions.unpin_tenant(&key);
    match purge {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && row_deleted => {}
        Err(error) => {
            tracing::error!(
                key = %key,
                error = %error,
                "receive subtree purge failed"
            );
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "receive subtree purge failed; retry DELETE",
            ));
        }
    }
    tracing::info!(target: "audit", event = "tenant_deleted", key = %key, "tenant namespace deleted");
    app.store.audit(
        "",
        &identity.subject,
        "tenant_deleted",
        &key,
        &json!({ "purged_receive": true, "row_deleted": row_deleted }),
    );
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct PatchTenantRequest {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    admin_group: Option<Option<String>>,
    #[serde(default)]
    max_total_bytes: Option<Option<u64>>,
    #[serde(default)]
    max_links: Option<Option<u64>>,
    #[serde(default)]
    max_sessions: Option<Option<u64>>,
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
    let Some(mut tenant) = app.store.tenant(&key) else {
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

fn tenant_receive_dir(
    receive_dir: &std::path::Path,
    key: &str,
) -> Result<std::path::PathBuf, String> {
    let path = paths::join_under(receive_dir, &[key.to_owned()])?;
    if path == *receive_dir {
        return Err("refusing to purge the receive root".to_owned());
    }
    Ok(path)
}

fn default_tenant_dest_collides(store: &crate::store::Store, key: &str) -> bool {
    let prefix = format!("{key}/");
    store
        .links("")
        .iter()
        .any(|link| link.dest == key || link.dest.starts_with(&prefix))
}

/// Streams a consistent SQLite snapshot as a download. Read-only operation:
/// admin session required, CSRF header not (nothing mutates).
pub async fn backup_database(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let _identity = require_platform_admin(&app, &headers)?;
    let backups = app.config.data_dir.join("backups");
    tokio::fs::create_dir_all(&backups)
        .await
        .map_err(|error| ApiError::internal(format!("create backups dir: {error}")))?;
    let name = format!("votport-{}-{}.db", now_unix(), &auth::random_token()[..8]);
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

const SETTINGS_KEYS: &[&str] = &[
    "notify_webhook",
    "notify_ntfy",
    "notify_ntfy_token",
    "notify_pushover_token",
    "notify_pushover_user",
    "audit_retention_days",
    "upload_retention_days",
    "default_max_total_bytes",
    "default_max_links",
    "default_max_sessions",
    "public_password_login",
];

pub async fn get_settings(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let _identity = require_platform_admin(&app, &headers)?;
    Ok(Json(settings_json(&app)))
}

fn settings_json(app: &App) -> serde_json::Value {
    let overlay = app.store.overlay(&app.config);
    let resolved = &overlay.resolved;
    json!({
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
        "sso_configured": app.sso_config.is_some(),
    })
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
            "notify_ntfy_token" | "notify_pushover_token" | "notify_pushover_user" => {
                write_secret(key, value)?
            }
            "audit_retention_days" | "upload_retention_days" => write_u64(key, value, true)?,
            "default_max_total_bytes" | "default_max_links" | "default_max_sessions" => {
                write_u64(key, value, false)?
            }
            "public_password_login" => write_bool(key, value)?,
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
    Ok(Json(settings_json(&app)))
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
    let cookie = issue_admin_cookie(&app, &switched);
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
    let identity = require_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    // The local password is the break-glass credential for the platform;
    // SSO tenant admins rotate access at their identity provider instead.
    if !identity.tenant.is_empty() || identity.role != "admin" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "the local administrator password is managed by the default-tenant admin",
        ));
    }
    if app.throttle.locked() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; wait a minute",
        ));
    }
    if request.new.chars().count() < 12 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "new password must be at least 12 characters",
        ));
    }
    let current_ok = tokio::task::spawn_blocking({
        let hash = admin_hash(&app);
        let current = request.current.clone();
        move || auth::verify_password(&current, &hash)
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?;
    // Throttled like login: this endpoint verifies a password too, so it would
    // otherwise be an unthrottled oracle for an attacker holding a session.
    app.throttle.record(current_ok);
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
    let cookie = issue_admin_cookie(&app, &auth::AdminIdentity::local_admin());
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
    usable: bool,
    uploads: Vec<UploadView>,
    events: Vec<crate::store::SessionEvent>,
}

#[derive(Serialize)]
struct UploadView {
    id: String,
    started_at: u64,
    completed_at: u64,
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

fn base_url(app: &App, headers: &HeaderMap) -> String {
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
fn stored_path(app: &App, stored_as: &str) -> Option<std::path::PathBuf> {
    let components: Vec<String> = stored_as
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect();
    paths::join_under(&app.config.receive_dir, &components).ok()
}

fn link_view(app: &App, link: Link, base: &str) -> LinkView {
    let usable = link.usable_now();
    let uploads = link
        .uploads
        .into_iter()
        .map(|upload| UploadView {
            files: upload
                .files
                .into_iter()
                .map(|file| FileView {
                    exists: stored_path(app, &file.stored_as).is_some_and(|path| path.is_file()),
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
        uploads,
        events: link.events,
    }
}

pub async fn list_links(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_admin(&app, &headers)?;
    let base = base_url(&app, &headers);
    let links: Vec<LinkView> = app
        .store
        .links(&identity.tenant)
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
}

pub async fn create_link(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<CreateLinkRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_admin(&app, &headers)?;
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
    let password_hash = match request.password.as_deref().filter(|p| !p.is_empty()) {
        Some(password) => Some(auth::hash_password(password).map_err(ApiError::internal)?),
        None => None,
    };
    let tenant = identity.tenant.clone();
    // A cookie can outlive its tenant's deletion; without this check the
    // link would be created under a namespace nothing manages anymore.
    if !tenant.is_empty() && app.store.tenant(&tenant).is_none() {
        return Err(ApiError::new(
            StatusCode::GONE,
            "this session's tenant no longer exists; sign in again",
        ));
    }
    let (_, max_links, _) = app.store.quotas_for(&tenant, &app.config);
    if let Some(max_links) = max_links {
        let count = u64::try_from(app.store.links(&tenant).len()).unwrap_or(u64::MAX);
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
        max_bytes: request.max_bytes.filter(|&bytes| bytes > 0),
        active: true,
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
        &serde_json::json!({ "label": view.label, "dest": view.dest, "tenant": identity.tenant }),
    );
    Ok(Json(json!({ "link": view })))
}

#[derive(Deserialize)]
pub struct UpdateLinkRequest {
    active: bool,
}

pub async fn update_link(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateLinkRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let found = app
        .store
        .update_link(&identity.tenant, &id, |link| link.active = request.active)
        .map_err(ApiError::internal)?;
    if !found {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "link_active_changed", id = %id, active = request.active, "request link toggled");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "link_active_changed",
        &id,
        &serde_json::json!({ "active": request.active }),
    );
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_link(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    if !app
        .store
        .remove_link(&identity.tenant, &id)
        .map_err(ApiError::internal)?
    {
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
    let identity = require_admin(&app, &headers)?;
    let link = app
        .store
        .link(&identity.tenant, &id)
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
    let identity = require_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let found = app
        .store
        .update_link(&identity.tenant, &id, |link| {
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
    let identity = require_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    let link = app
        .store
        .link(&identity.tenant, &id)
        .ok_or_else(ApiError::not_found)?;
    let record = link
        .uploads
        .iter()
        .find(|entry| entry.id == upload)
        .and_then(|entry| entry.files.get(index))
        .ok_or_else(ApiError::not_found)?;
    let path = stored_path(&app, &record.stored_as)
        .ok_or_else(|| ApiError::internal("stored path failed the join guard"))?;
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
        .update_link(&identity.tenant, &id, |link| {
            for upload in &mut link.uploads {
                for file in &mut upload.files {
                    if file.stored_as == stored_as {
                        file.deleted = true;
                    }
                }
            }
        })
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
mod handler_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;

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
        format!(
            "votport_admin={}; Path=/",
            auth::issue_admin_token(&app.secret, &identity, &admin_token_phc(app))
        )
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
        let dir = receive_dir.join(key);
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
        assert!(application.store.tenant("acme").is_none());
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
        assert!(application.store.tenant("acme").is_some());
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
    async fn leftover_retry_refuses_a_default_tenant_dest() {
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
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"]
                .as_str()
                .unwrap_or_default()
                .contains("default-tenant dest"),
            "error was {json}"
        );
        assert!(tenant_dir.join("x.bin").exists());
        assert!(!application.sessions.tenant_pinned("acme"));
    }

    #[tokio::test]
    async fn leftover_retry_purges_an_orphaned_directory() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");
        assert!(application.store.tenant("acme").is_none());

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
        assert!(application.store.tenant("acme").is_none());

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
        assert!(application.store.tenant("acme").is_none());

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
        assert!(application.store.tenant("acme").is_none());
        assert!(application.sessions.tenant_pinned("acme"));
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
        assert_eq!(err, InsertError::Pinned);
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
        config
    }

    fn testing_config_public() -> crate::config::Config {
        crate::config::Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: std::path::PathBuf::from("/nonexistent"),
            receive_dir: std::path::PathBuf::from("/nonexistent"),
            web_root: std::path::PathBuf::from("../web"),
            admin_password_hash: crate::auth::hash_password(testing::TEST_PASSWORD).unwrap(),
            admin_token_tag: "tag".to_owned(),
            notify_webhook: None,
            notify_ntfy: None,
            notify_ntfy_token: None,
            notify_pushover: None,
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
        let router = app::router(application.clone());
        let login = Request::builder()
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
            .unwrap();
        let response = router.oneshot(login).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

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
        format!(
            "votport_admin={}; Path=/",
            auth::issue_admin_token(&app.secret, &identity, &admin_token_phc(app))
        )
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
            application,
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
        let tenant = application.store.tenant("acme").expect("tenant stored");
        assert_eq!(tenant.max_total_bytes, Some(100));
        assert_eq!(tenant.max_links, None);
        assert_eq!(tenant.max_sessions, None);
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
        let resolved = application.store.resolved_settings(&application.config);
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
        format!(
            "votport_admin={}; Path=/",
            auth::issue_admin_token(&app.secret, &identity, &admin_token_phc(app))
        )
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
            auth::issue_admin_token_from_payload(&app.secret, &payload, &admin_token_phc(app))
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
        let row = application.store.principal("user@example.com").unwrap();
        assert!(!row.blocked);
        assert_eq!(row.credential_version, 1);
    }
}
