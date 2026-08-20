//! HTTP API: admin management plus the public upload protocol.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::oneshot;

use vot_sdk::object::{ObjectId, Suite};

use crate::app::App;
use crate::auth;
use crate::paths;
use crate::session::{self, Cmd, SessionError};
use crate::store::{now_unix, Link};

const ADMIN_COOKIE: &str = "votport_admin";
const MAX_SESSIONS: usize = 32;
const MAX_SESSIONS_PER_LINK: usize = 8;

pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "not signed in")
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not found")
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl From<SessionError> for ApiError {
    fn from(error: SessionError) -> Self {
        Self::new(
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            error.message,
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

// ---------------------------------------------------------------- admin auth

/// Credential tag bound into admin token MACs: the state.json hash when the
/// UI has set one, else the stable tag derived from the environment
/// credential. Either way, rotating the credential evicts sessions and a
/// plain restart does not.
fn admin_token_phc(app: &App) -> String {
    app.store
        .admin_password_hash()
        .unwrap_or_else(|| app.config.admin_token_tag.clone())
}

fn is_admin(app: &App, headers: &HeaderMap) -> bool {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| auth::cookie_value(cookies, ADMIN_COOKIE))
        .is_some_and(|token| auth::verify_admin_token(&app.secret, &admin_token_phc(app), token))
}

/// Client address for per-IP throttling: the rightmost X-Forwarded-For entry
/// (the one the reverse proxy appended; earlier entries are client-supplied),
/// else the socket peer.
fn client_ip(headers: &HeaderMap, peer: &std::net::SocketAddr) -> String {
    // X-Forwarded-For is honored only from a peer that can be the reverse
    // proxy (loopback or a private/ULA address). A caller reaching the port
    // directly from elsewhere would otherwise mint a fresh throttle bucket
    // per request by spoofing the header.
    if !proxy_peer(&peer.ip()) {
        return peer.ip().to_string();
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|list| list.rsplit(',').next())
        .map(|ip| ip.trim().to_owned())
        .filter(|ip| !ip.is_empty())
        .unwrap_or_else(|| peer.ip().to_string())
}

fn proxy_peer(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        // fc00::/7 unique-local, the v6 analogue of RFC 1918.
        std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

fn require_admin(app: &App, headers: &HeaderMap) -> ApiResult<()> {
    if is_admin(app, headers) {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

/// Mutating admin routes also require a custom header; cross-site forms
/// cannot set one, which closes CSRF without token bookkeeping.
fn require_admin_write(app: &App, headers: &HeaderMap) -> ApiResult<()> {
    require_admin(app, headers)?;
    if headers.contains_key("x-votport") {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "missing X-Votport header",
        ))
    }
}

/// The admin password in force: a hash stored by "change password" wins over
/// the one derived from the environment at startup, so a restart does not roll
/// the password back to VOTPORT_ADMIN_PASSWORD.
fn admin_hash(app: &App) -> String {
    app.store
        .admin_password_hash()
        .unwrap_or_else(|| app.config.admin_password_hash.clone())
}

fn cookie_attributes(app: &App) -> &'static str {
    let secure = app
        .config
        .public_url
        .as_deref()
        .is_none_or(|url| url.starts_with("https://"));
    if secure {
        "; Secure"
    } else {
        ""
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    password: String,
}

pub async fn admin_login(
    State(app): State<Arc<App>>,
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
    if !ok {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "wrong password"));
    }
    let token = auth::issue_admin_token(&app.secret, &admin_token_phc(&app));
    let cookie = format!(
        "{ADMIN_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800{}",
        cookie_attributes(&app)
    );
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

pub async fn admin_logout(State(app): State<Arc<App>>) -> Response {
    let cookie = format!(
        "{ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        cookie_attributes(&app)
    );
    ([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response()
}

pub async fn admin_session(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(&app, &headers)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    current: String,
    new: String,
}

/// Replaces the admin password. The new hash is persisted in state.json, which
/// from then on takes precedence over the environment. Token MACs cover that
/// hash, so every outstanding admin session is invalidated by the change; the
/// response reissues a cookie under the new hash so the acting admin stays
/// signed in.
pub async fn admin_change_password(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> ApiResult<Response> {
    require_admin_write(&app, &headers)?;
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
    let token = auth::issue_admin_token(&app.secret, &admin_token_phc(&app));
    let cookie = format!(
        "{ADMIN_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800{}",
        cookie_attributes(&app)
    );
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
}

#[derive(Serialize)]
struct UploadView {
    id: String,
    completed_at: u64,
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
/// only; client input never reaches this.
fn stored_path(app: &App, stored_as: &str) -> std::path::PathBuf {
    let components: Vec<String> = stored_as
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect();
    paths::join_under(&app.config.receive_dir, &components)
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
                    exists: stored_path(app, &file.stored_as).is_file(),
                    path: file.path,
                    stored_as: file.stored_as,
                    bytes: file.bytes,
                    suite: file.suite,
                    root: file.root,
                    receipt: file.receipt,
                })
                .collect(),
            id: upload.id,
            completed_at: upload.completed_at,
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
    }
}

pub async fn list_links(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(&app, &headers)?;
    let base = base_url(&app, &headers);
    let links: Vec<LinkView> = app
        .store
        .links()
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
    require_admin_write(&app, &headers)?;
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
    let link = Link {
        id: auth::random_token(),
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
    };
    let base = base_url(&app, &headers);
    let view = link_view(&app, link.clone(), &base);
    app.store.insert_link(link).map_err(ApiError::internal)?;
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
    require_admin_write(&app, &headers)?;
    let found = app
        .store
        .update_link(&id, |link| link.active = request.active)
        .map_err(ApiError::internal)?;
    if !found {
        return Err(ApiError::not_found());
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_link(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin_write(&app, &headers)?;
    if !app.store.remove_link(&id).map_err(ApiError::internal)? {
        return Err(ApiError::not_found());
    }
    Ok(Json(json!({ "ok": true })))
}

/// The request link as a scannable SVG, for senders on phones.
pub async fn link_qr(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    require_admin(&app, &headers)?;
    let link = app.store.link(&id).ok_or_else(ApiError::not_found)?;
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
    require_admin_write(&app, &headers)?;
    let found = app
        .store
        .update_link(&id, |link| link.uploads.retain(|entry| entry.id != upload))
        .map_err(ApiError::internal)?;
    if !found {
        return Err(ApiError::not_found());
    }
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
    require_admin_write(&app, &headers)?;
    let link = app.store.link(&id).ok_or_else(ApiError::not_found)?;
    let record = link
        .uploads
        .iter()
        .find(|entry| entry.id == upload)
        .and_then(|entry| entry.files.get(index))
        .ok_or_else(ApiError::not_found)?;
    let path = stored_path(&app, &record.stored_as);
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
    Ok(Json(json!({ "ok": true })))
}

// ------------------------------------------------------------- upload protocol

/// Cookie carrying proof that this link's password was verified once.
fn link_cookie_name(link_id: &str) -> String {
    format!("votport_r_{link_id}")
}

fn link_authorized(app: &App, link: &Link, headers: &HeaderMap) -> bool {
    let phc = link.password_hash.as_deref().unwrap_or_default();
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| auth::cookie_value(cookies, &link_cookie_name(&link.id)))
        .is_some_and(|token| auth::verify_link_token(&app.secret, &link.id, phc, token))
}

pub async fn link_info(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let link = app.store.link(&token).ok_or_else(ApiError::not_found)?;
    let usable = link.usable_now();
    Ok(Json(json!({
        // The label leaks nothing new to an authorized sender, but an old URL
        // for a closed request should not keep revealing what it was for.
        "label": if usable { Some(&link.label) } else { None },
        "needs_password": link.password_hash.is_some(),
        "authorized": link_authorized(&app, &link, &headers),
        "usable": usable,
        "max_bytes": effective_cap(&app, &link),
        "chunk_bytes": session::CHUNK_BYTES,
    })))
}

fn effective_cap(app: &App, link: &Link) -> u64 {
    link.max_bytes.map_or(app.config.max_upload_bytes, |cap| {
        cap.min(app.config.max_upload_bytes)
    })
}

#[derive(Deserialize)]
pub struct PackageAnnouncement {
    /// "blake3" or "sha256" — package roots are blake3 today, but the wire
    /// format carries the suite so the client stays authoritative.
    suite: String,
    root: String,
    length: u64,
}

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    #[serde(default)]
    password: Option<String>,
    package: PackageAnnouncement,
}

fn parse_object(package: &PackageAnnouncement) -> ApiResult<ObjectId> {
    let suite = match package.suite.as_str() {
        "blake3" => Suite::Blake3Bao64,
        "sha256" => Suite::Sha256Bep52,
        other => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("unknown suite {other:?}"),
            ));
        }
    };
    let bytes = hex::decode(&package.root)
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "root must be hex"))?;
    let root: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "root must be 32 bytes"))?;
    Ok(ObjectId {
        suite: suite.identifier(),
        root,
        length: package.length,
    })
}

/// Verifies a link password, throttled per client IP: this is the only
/// unauthenticated password check in the service, so without a throttle it
/// would be an oracle, and with a global one anyone holding a link URL could
/// lock the admin out. A link with no password accepts anything.
async fn check_link_password(
    app: &Arc<App>,
    link: &crate::store::Link,
    password: Option<&str>,
    ip: &str,
) -> ApiResult<()> {
    let Some(hash) = &link.password_hash else {
        return Ok(());
    };
    if app.link_throttle.locked(ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; wait a minute",
        ));
    }
    let password = password.unwrap_or_default().to_owned();
    let hash = hash.clone();
    let ok = tokio::task::spawn_blocking(move || auth::verify_password(&password, &hash))
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    app.link_throttle.record(ip, ok);
    if !ok {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "wrong link password",
        ));
    }
    Ok(())
}

/// Checks a link password without creating any upload state, so the uploader
/// can gate its drop zone behind the password instead of letting someone hash
/// a hundred gigabytes and only then discover they typed it wrong. Success
/// sets a signed cookie so a return visit skips the gate.
pub async fn verify_link_password(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<VerifyRequest>,
) -> ApiResult<Response> {
    let link = app.store.link(&token).ok_or_else(ApiError::not_found)?;
    if !link.usable_now() {
        return Err(ApiError::new(
            StatusCode::GONE,
            "this link is no longer accepting uploads",
        ));
    }
    let ip = client_ip(&headers, &peer);
    check_link_password(&app, &link, request.password.as_deref(), &ip).await?;
    let phc = link.password_hash.as_deref().unwrap_or_default();
    let value = auth::issue_link_token(&app.secret, &link.id, phc);
    let cookie = format!(
        "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{}",
        link_cookie_name(&link.id),
        cookie_attributes(&app)
    );
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    password: Option<String>,
}

pub async fn create_session(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CreateSessionRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let link = app.store.link(&token).ok_or_else(ApiError::not_found)?;
    if !link.usable_now() {
        return Err(ApiError::new(
            StatusCode::GONE,
            "this link is no longer accepting uploads",
        ));
    }
    if !link_authorized(&app, &link, &headers) {
        let ip = client_ip(&headers, &peer);
        check_link_password(&app, &link, request.password.as_deref(), &ip).await?;
    }
    if app.sessions.active_for_link(&link.id) >= MAX_SESSIONS_PER_LINK
        || app.sessions.total() >= MAX_SESSIONS
    {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many uploads in progress; try again shortly",
        ));
    }
    let expected = parse_object(&request.package)?;
    let cap = effective_cap(&app, &link);
    if expected.length > cap {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("upload exceeds the {cap} byte limit for this link"),
        ));
    }
    let dest_components: Vec<String> = link
        .dest
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect();
    let session_id = auth::random_token();
    let session_bytes: [u8; 16] = hex::decode(&session_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ApiError::internal("session id shape"))?;
    let setup = session::WorkerSetup {
        store: Arc::clone(&app.store),
        link_id: link.id.clone(),
        dest_dir: paths::join_under(&app.config.receive_dir, &dest_components),
        dest_rel: link.dest.clone(),
        expected_package: expected,
        max_total_bytes: cap,
        allow_hidden: app.config.allow_hidden,
        signer: Arc::clone(&app.signer),
        session_id: session_bytes,
    };
    let sender = session::spawn_worker(setup);
    app.sessions.insert(session_id.clone(), link.id, sender);
    Ok(Json(json!({
        "session": session_id,
        "chunk_bytes": session::CHUNK_BYTES,
    })))
}

async fn dispatch<T>(
    app: &App,
    session_id: &str,
    build: impl FnOnce(oneshot::Sender<Result<T, SessionError>>) -> Cmd,
) -> ApiResult<T> {
    let sender = app
        .sessions
        .touch(session_id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "unknown or expired session"))?;
    let (reply, receive) = oneshot::channel();
    sender
        .send(build(reply))
        .await
        .map_err(|_| ApiError::new(StatusCode::GONE, "upload session ended"))?;
    receive
        .await
        .map_err(|_| ApiError::new(StatusCode::GONE, "upload session ended"))?
        .map_err(ApiError::from)
}

pub async fn upload_seal(
    State(app): State<Arc<App>>,
    Path(sid): Path<String>,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    if body.len() > session::MAX_SEAL_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "seal too large",
        ));
    }
    let pages = dispatch(&app, &sid, |reply| Cmd::Seal { bytes: body, reply }).await?;
    Ok(Json(json!({ "pages": pages })))
}

pub async fn upload_page(
    State(app): State<Arc<App>>,
    Path(sid): Path<String>,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    if body.len() > session::MAX_PAGE_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "page too large",
        ));
    }
    let remaining = dispatch(&app, &sid, |reply| Cmd::Page { bytes: body, reply }).await?;
    Ok(Json(json!({ "remaining_pages": remaining })))
}

pub async fn upload_begin(
    State(app): State<Arc<App>>,
    Path(sid): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let entries = dispatch(&app, &sid, |reply| Cmd::Begin { reply }).await?;
    Ok(Json(json!({ "entries": entries })))
}

#[derive(Deserialize)]
pub struct ChunkQuery {
    entry: usize,
    offset: u64,
}

pub async fn upload_chunk(
    State(app): State<Arc<App>>,
    Path(sid): Path<String>,
    Query(query): Query<ChunkQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<session::ChunkProgress>> {
    let proof_len: usize = headers
        .get("x-votport-proof")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "X-Votport-Proof header must carry the proof length",
            )
        })?;
    if proof_len > body.len() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "proof length exceeds the body",
        ));
    }
    // Bytes::slice is a refcount bump, not a copy; the session worker holds
    // the same buffers the request body arrived in.
    let proof = body.slice(..proof_len);
    let data = body.slice(proof_len..);
    let progress = dispatch(&app, &sid, |reply| Cmd::Chunk {
        entry: query.entry,
        offset: query.offset,
        proof,
        data,
        reply,
    })
    .await?;
    Ok(Json(progress))
}

pub async fn upload_finish(
    State(app): State<Arc<App>>,
    Path(sid): Path<String>,
) -> ApiResult<Json<session::FinishReport>> {
    let link_id = app.sessions.link_id(&sid);
    let report = dispatch(&app, &sid, |reply| Cmd::Finish { reply }).await?;
    app.sessions.remove(&sid);
    if let Some(link) = link_id.and_then(|id| app.store.link(&id)) {
        tokio::spawn(crate::notify::uploaded(
            Arc::clone(&app),
            link.label,
            report.clone(),
        ));
    }
    Ok(Json(report))
}

pub async fn upload_abort(
    State(app): State<Arc<App>>,
    Path(sid): Path<String>,
) -> Json<serde_json::Value> {
    app.sessions.remove(&sid);
    Json(json!({ "ok": true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_for_is_trusted_only_from_proxy_peers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());
        let proxy: std::net::SocketAddr = "127.0.0.1:80".parse().unwrap();
        let private: std::net::SocketAddr = "172.18.0.2:80".parse().unwrap();
        let public: std::net::SocketAddr = "203.0.113.9:80".parse().unwrap();
        assert_eq!(client_ip(&headers, &proxy), "5.6.7.8");
        assert_eq!(client_ip(&headers, &private), "5.6.7.8");
        assert_eq!(client_ip(&headers, &public), "203.0.113.9");
        assert_eq!(client_ip(&HeaderMap::new(), &proxy), "127.0.0.1");
    }
}
