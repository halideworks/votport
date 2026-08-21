//! Admin management API: sign-in, request links, received-file management.

use std::sync::Arc;

use axum::extract::{Path, State};
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
        events: Vec::new(),
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
        .update_link(&id, |link| {
            for upload in &mut link.uploads {
                for file in &mut upload.files {
                    if file.stored_as == stored_as {
                        file.deleted = true;
                    }
                }
            }
        })
        .map_err(ApiError::internal)?;
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
    async fn https_public_url_marks_cookies_secure() {
        let directory = tempfile::tempdir().unwrap();
        let router = app::router(testing::build(directory.path()));
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/login")
            .header("content-type", "application/json")
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
