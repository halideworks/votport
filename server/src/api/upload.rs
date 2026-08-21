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
    } else {
        let ip = client_ip(&headers, &peer);
        if !app.session_rate.allow(&ip) {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too many uploads started from your address; try again later",
            ));
        }
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
    let announced_bytes = expected.length;
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
        session = %session_id, bytes = announced_bytes, "upload session started"
    );
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
    tracing::info!(
        target: "audit", event = "upload_completed", session = %sid,
        files = report.files.len(), bytes = report.files.iter().map(|f| f.bytes).sum::<u64>(),
        "upload finished and recorded"
    );
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
    // Best effort: lets the worker record a "cancelled" event; an unknown or
    // already-dead session still answers ok.
    let _ = dispatch(&app, &sid, |reply| Cmd::Abort { reply }).await;
    app.sessions.remove(&sid);
    Json(json!({ "ok": true }))
}
