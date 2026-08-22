//! Admin management API: sign-in, request links, received-file management.

use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

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
    auth::verify_admin_token(
        &app.secret,
        &admin_token_phc(app),
        token.unwrap_or_default(),
    )
    .ok_or_else(ApiError::unauthorized)
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
            .audit("admin_login_failed", &ip, &serde_json::json!({}));
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "wrong password"));
    }
    tracing::info!(target: "audit", event = "admin_login", %ip, "admin signed in");
    app.store.audit("admin_login", &ip, &serde_json::json!({}));
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
    let _identity = require_admin(&app, &headers)?;
    let limit = query.limit.unwrap_or(1000).min(10_000);
    let rows = app
        .store
        .audit_export(query.since.unwrap_or(0), limit)
        .map_err(ApiError::internal)?;
    use std::fmt::Write as _;
    let mut body = String::new();
    for row in rows {
        let detail = row.detail;
        writeln!(
            body,
            "{}",
            serde_json::json!({
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
    limit: Option<u64>,
}

pub async fn admin_session(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_admin(&app, &headers)?;
    Ok(Json(json!({
        "ok": true,
        "tenant": identity.tenant,
        "grants": identity.grants,
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
    let identity = require_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    // Tenant lifecycle is a platform operation: only the default tenant's
    // admin holds it, so an SSO principal scoped to "acme" cannot mint or
    // destroy other namespaces.
    if !identity.tenant.is_empty() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "tenant administration requires the default-tenant admin",
        ));
    }
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
    let tenant = crate::store::Tenant {
        key: key.clone(),
        label: request.label.trim().to_owned(),
        admin_group: request.admin_group.filter(|group| !group.trim().is_empty()),
        max_total_bytes: request.max_total_bytes.filter(|&bytes| bytes > 0),
        max_links: request.max_links.filter(|&links| links > 0),
        max_sessions: request.max_sessions.filter(|&sessions| sessions > 0),
        created_at: now_unix(),
    };
    app.store
        .insert_tenant(tenant)
        .map_err(ApiError::internal)?;
    tracing::info!(target: "audit", event = "tenant_created", key = %key, "tenant namespace created");
    app.store.audit("tenant_created", &key, &json!({}));
    Ok(Json(json!({ "key": key })))
}

pub async fn list_tenants(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let _ = require_admin(&app, &headers)?;
    Ok(Json(json!({ "tenants": app.store.tenants() })))
}

pub async fn delete_tenant(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_admin(&app, &headers)?;
    require_admin_write(&headers, &identity)?;
    if !identity.tenant.is_empty() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "tenant administration requires the default-tenant admin",
        ));
    }
    let count = app.store.tenant_link_count(&key);
    if count > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("{count} link(s) still reference this tenant; delete them first"),
        ));
    }
    // In-flight uploads would keep writing into the deleted namespace and
    // their records would silently vanish.
    let active = app.sessions.active_for_tenant(&key);
    if active > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("{active} upload(s) are in flight; try again when they finish"),
        ));
    }
    if !app.store.remove_tenant(&key).map_err(ApiError::internal)? {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "tenant_deleted", key = %key, "tenant namespace deleted");
    app.store.audit("tenant_deleted", &key, &json!({}));
    Ok(Json(json!({ "ok": true })))
}

/// Streams a consistent SQLite snapshot as a download. Read-only operation:
/// admin session required, CSRF header not (nothing mutates).
pub async fn backup_database(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let _ = require_admin(&app, &headers)?;
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
    let bytes = tokio::fs::read(&destination)
        .await
        .map_err(|error| ApiError::internal(format!("read snapshot: {error}")))?;
    tracing::info!(target: "audit", event = "backup_created", file = %name, bytes = bytes.len(), "database snapshot exported");
    app.store
        .audit("backup_created", &name, &json!({ "bytes": bytes.len() }));
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        bytes,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct SwitchTenantRequest {
    tenant: String,
}

/// Switches the active tenant, reissuing the session cookie. Only grants
/// already carried by the session are honored, so this cannot escalate.
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
        grants: identity.grants.clone(),
        subject: identity.subject.clone(),
    };
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
    app.store
        .audit("admin_password_changed", "", &serde_json::json!({}));
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
    if let Some(max_links) = app.store.tenant(&tenant).and_then(|t| t.max_links) {
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
    app.store.insert_link(link).map_err(ApiError::internal)?;
    tracing::info!(target: "audit", event = "link_created", id = %view.id, label = %view.label, dest = %view.dest, "request link created");
    app.store.audit(
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
    app.store.audit("link_deleted", &id, &serde_json::json!({}));
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
        application
            .store
            .audit("link_created", "l-1", &serde_json::json!({ "label": "x" }));

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
        application.store.audit("probe", "", &serde_json::json!({}));

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
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!body.is_empty());
        // SQLite databases begin with the magic string.
        assert!(body.starts_with(b"SQLite format 3\0"));
    }
}
