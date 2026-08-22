//! Public upload protocol: link info, sessions, proven chunk transfer.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::oneshot;

use vot_sdk::object::{ObjectId, Suite};

use crate::app::App;
use crate::auth;
use crate::paths;
use crate::session::{self, Cmd, SessionError};
use crate::store::{now_unix, Link};

use super::{client_ip, cookie_attributes, ApiError, ApiResult};

// Worst case memory: MAX_SESSIONS x 8 in-flight chunks x ~9 MiB of queued
// request bodies, plus each worker's pinned merkle trees. Raising these caps
// raises that ceiling linearly.
const MAX_SESSIONS: usize = 32;
const MAX_SESSIONS_PER_LINK: usize = 8;

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
    let link = app
        .store
        .link_by_id(&token)
        .ok_or_else(ApiError::not_found)?;
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
    let link = app
        .store
        .link_by_id(&token)
        .ok_or_else(ApiError::not_found)?;
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

/// Audit helper for rejected session-creation attempts (abuse-probe signals).
fn audit_session_rejected(app: &App, tenant: &str, reason: &str) {
    tracing::warn!(target: "audit", event = "session_rejected", %tenant, reason);
    app.store.audit(
        tenant,
        "",
        "session_rejected",
        "",
        &json!({ "reason": reason }),
    );
}

pub async fn create_session(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CreateSessionRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let link = app
        .store
        .link_by_id(&token)
        .ok_or_else(ApiError::not_found)?;
    if !link.usable_now() {
        return Err(ApiError::new(
            StatusCode::GONE,
            "this link is no longer accepting uploads",
        ));
    }
    // Every create-session request consumes rate budget, whatever the
    // outcome: without this, holders of a no-password link could churn
    // sessions into the global cap and evict legitimate senders' uploads.
    let ip = client_ip(&headers, &peer);
    if !app.session_rate.allow(&ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many uploads started from your address; try again later",
        ));
    }
    if !link_authorized(&app, &link, &headers) {
        check_link_password(&app, &link, request.password.as_deref(), &ip).await?;
    }
    // Fail closed when a named tenant row has vanished: publishing into the
    // receive root unprefixed and quota-free would cross a tenant boundary.
    if !link.tenant.is_empty() && app.store.tenant(&link.tenant).is_none() {
        audit_session_rejected(&app, &link.tenant, "link tenant missing");
        return Err(ApiError::new(
            StatusCode::GONE,
            "this link's tenant no longer exists",
        ));
    }
    if app.sessions.active_for_link(&link.id) >= MAX_SESSIONS_PER_LINK
        || app.sessions.total() >= MAX_SESSIONS
    {
        audit_session_rejected(&app, &link.tenant, "global or per-link session cap");
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many uploads in progress; try again shortly",
        ));
    }
    let expected = parse_object(&request.package)?;
    let announced_bytes = expected.length;
    let cap = effective_cap(&app, &link);
    if expected.length > cap {
        audit_session_rejected(&app, &link.tenant, "per-link size cap");
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("upload exceeds the {cap} byte limit for this link"),
        ));
    }
    // Quotas: the tenant's received-but-not-deleted bytes plus this upload
    // must stay under max_total_bytes, and its concurrent sessions under
    // max_sessions.
    let (max_total, _, max_sessions) = app.store.quotas_for(&link.tenant, &app.config);
    if let Some(max_total) = max_total {
        let received = app.store.tenant_received_bytes(&link.tenant);
        if received + expected.length > max_total {
            audit_session_rejected(&app, &link.tenant, "byte quota exhausted");
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "this tenant's storage quota is exhausted ({received} of {max_total} bytes used)"
                ),
            ));
        }
    }
    if let Some(max_sessions) = max_sessions {
        if app.sessions.active_for_tenant(&link.tenant) >= max_sessions as usize {
            audit_session_rejected(&app, &link.tenant, "tenant session cap reached");
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too many concurrent uploads for this tenant",
            ));
        }
    }

    // Named tenants publish into <receive>/<tenant-key>/...; the default
    // tenant keeps today's layout.
    let mut dest_components = app
        .store
        .tenant(&link.tenant)
        .map(|tenant| tenant.path_prefix())
        .unwrap_or_default();
    dest_components.extend(
        link.dest
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned),
    );
    // admit_dest already vetted these; join_under re-checks as defense.
    let dest_dir =
        paths::join_under(&app.config.receive_dir, &dest_components).map_err(ApiError::internal)?;
    let session_id = auth::random_token();
    let session_bytes: [u8; 16] = hex::decode(&session_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ApiError::internal("session id shape"))?;
    let setup = session::WorkerSetup {
        store: Arc::clone(&app.store),
        link_id: link.id.clone(),
        tenant: link.tenant.clone(),
        dest_dir,
        dest_rel: link.dest.clone(),
        expected_package: expected,
        max_total_bytes: cap,
        allow_hidden: app.config.allow_hidden,
        signer: Arc::clone(&app.signer),
        session_id: session_bytes,
        started_at: now_unix(),
    };
    let sender = session::spawn_worker(setup);
    tracing::info!(
        target: "audit", event = "upload_session_created", link = %link.id,
        session_tag = %session_id.get(..8).unwrap_or(&session_id),
        bytes = announced_bytes, "upload session started"
    );
    app.store.audit(
        &link.tenant,
        "",
        "upload_session_created",
        &link.id,
        &serde_json::json!({ "session_tag": &session_id[..8.min(session_id.len())], "bytes": announced_bytes }),
    );
    app.sessions
        .insert(session_id.clone(), link.id, link.tenant.clone(), sender);
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
    tracing::info!(
        target: "audit", event = "upload_completed", session = %sid,
        files = report.files.len(), bytes = report.files.iter().map(|f| f.bytes).sum::<u64>(),
        "upload finished and recorded"
    );
    let completed_tenant = link_id
        .clone()
        .and_then(|id| app.store.link_by_id(&id))
        .map(|link| link.tenant)
        .unwrap_or_default();
    app.store.audit(
        &completed_tenant,
        "",
        "upload_completed",
        &sid[..8.min(sid.len())],
        &serde_json::json!({
            "files": report.files.len(),
            "bytes": report.files.iter().map(|f| f.bytes).sum::<u64>()
        }),
    );
    if let Some(link) = link_id.and_then(|id| app.store.link_by_id(&id)) {
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
    // Best effort: lets the worker record a "cancelled" event; an unknown or
    // already-dead session still answers ok.
    let _ = dispatch(&app, &sid, |reply| Cmd::Abort { reply }).await;
    app.sessions.remove(&sid);
    Json(json!({ "ok": true }))
}

#[cfg(test)]
mod session_rate_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::store::Link;

    #[tokio::test]
    async fn session_creation_is_rate_limited_per_ip() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let link = Link {
            id: "rate-limited-link".to_owned(),
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
        };
        application.store.insert_link(link).unwrap();

        let router = app::router(application);
        // Invalid packages fail 422 but still consume rate budget, so the
        // 21st attempt from one address is refused outright.
        for _ in 0..20 {
            let request = Request::builder()
                .method("POST")
                .uri("/api/r/rate-limited-link/session")
                .header("content-type", "application/json")
                .extension(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    1234,
                ))))
                .body(Body::from(
                    r#"{"package":{"suite":"blake3","root":"00","length":1}}"#,
                ))
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
        let request = Request::builder()
            .method("POST")
            .uri("/api/r/rate-limited-link/session")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                1234,
            ))))
            .body(Body::from(
                r#"{"package":{"suite":"blake3","root":"00","length":1}}"#,
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
