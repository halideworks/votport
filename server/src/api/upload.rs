//! Public upload protocol: link info, sessions, proven chunk transfer.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{mpsc, oneshot};

use vot_sdk::object::{ObjectId, Suite};

use crate::app::{App, PushTicket};
use crate::auth;
use crate::paths;
use crate::session::{self, Cmd, SessionError};
use crate::store::{now_unix, Link};

use super::{client_ip, cookie_attributes, ApiError, ApiResult};

/// Cookie carrying proof that this link's password was verified once.
pub(crate) fn link_cookie_name(link_id: &str) -> String {
    format!("votport_r_{link_id}")
}

pub(crate) fn cookie_authorized(
    app: &App,
    id: &str,
    password_hash: Option<&str>,
    cookie_name: &str,
    headers: &HeaderMap,
) -> bool {
    let phc = password_hash.unwrap_or_default();
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| auth::cookie_value(cookies, cookie_name))
        .is_some_and(|token| auth::verify_link_token(&app.secret, id, phc, token))
}

fn link_authorized(app: &App, link: &Link, headers: &HeaderMap) -> bool {
    cookie_authorized(
        app,
        &link.id,
        link.password_hash.as_deref(),
        &link_cookie_name(&link.id),
        headers,
    )
}

pub async fn link_info(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let link = app
        .store
        .upload_link(&token)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let usable = link.usable_now();
    let max_bytes = effective_cap(&app, &link);
    let branding = if usable {
        super::public_branding(&app, &link.tenant).map_err(super::store_unavailable)?
    } else {
        None
    };
    Ok((
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::VARY, "Cookie"),
        ],
        Json(json!({
        // The label leaks nothing new to an authorized sender, but an old URL
        // for a closed request should not keep revealing what it was for.
        "label": if usable { Some(&link.label) } else { None },
        // Same exposure as the label: shown pre-password, hidden once closed.
        "branding": branding,
        "needs_password": link.password_hash.is_some(),
        "authorized": link_authorized(&app, &link, &headers),
        "usable": usable,
        "max_bytes": max_bytes,
        "chunk_bytes": session::CHUNK_BYTES,
        // The sender refuses dotfiles before hashing when this is off; the
        // server re-checks at begin.
        "allow_hidden": app.config.allow_hidden,
        "max_entries": session::max_entries_for_bytes(max_bytes),
        "push": app.push.is_some(),
        "web_build": app.web_build,
        })),
    )
        .into_response())
}

/// Tenant logo for a request link. Ungated like the link label: the metadata
/// endpoint reveals the label pre-password, so the logo matches that level.
pub async fn link_logo(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
) -> ApiResult<axum::response::Response> {
    let link = app
        .store
        .upload_link(&token)
        .map_err(super::store_unavailable)?
        .filter(Link::usable_now)
        .ok_or_else(ApiError::not_found)?;
    super::serve_branding_logo(&app, &link.tenant).await
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
    pub(crate) suite: String,
    pub(crate) root: String,
    pub(crate) length: u64,
}

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    route: Option<String>,
    #[serde(default)]
    password: Option<String>,
    package: PackageAnnouncement,
}

pub(crate) fn parse_object(package: &PackageAnnouncement) -> ApiResult<ObjectId> {
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

#[derive(Deserialize)]
pub struct PushPackageAnnouncement {
    suite: u64,
    root: String,
    length: u64,
    entries: usize,
}

#[derive(Deserialize)]
pub struct CreatePushRequest {
    route: Option<String>,
    #[serde(default)]
    password: Option<String>,
    holder_key: String,
    package: PushPackageAnnouncement,
}

fn parse_push_object(package: &PushPackageAnnouncement) -> ApiResult<ObjectId> {
    if package.suite != 1 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "native push requires suite 1",
        ));
    }
    let bytes = hex::decode(&package.root)
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "root must be hex"))?;
    let root: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "root must be 32 bytes"))?;
    Ok(ObjectId {
        suite: Suite::Blake3Bao64.identifier(),
        root,
        length: package.length,
    })
}

#[derive(Clone, Copy)]
pub(crate) enum PasswordResourceKind {
    Receive,
    Delivery,
}

impl PasswordResourceKind {
    fn label(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::Delivery => "delivery",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PasswordResource<'a> {
    pub(crate) tenant: &'a str,
    pub(crate) id: &'a str,
    pub(crate) kind: PasswordResourceKind,
}

/// Verifies a public-resource password, throttled per client IP. These are
/// unauthenticated password checks, so without a throttle they would be an
/// oracle, and with a global one anyone holding a URL could lock the admin
/// out. A resource with no password accepts anything.
pub(crate) async fn check_password(
    app: &Arc<App>,
    resource: PasswordResource<'_>,
    password_hash: Option<&str>,
    password: Option<&str>,
    ip: &str,
    error_message: &'static str,
) -> ApiResult<()> {
    let Some(hash) = password_hash else {
        return Ok(());
    };
    // One bucket per v4 address and per IPv6 /64: a client holding a routed
    // prefix would otherwise get a fresh five-guess budget per address.
    let bucket = super::throttle_key(ip);
    // Claimed before the verify; see admin_login for why checking and then
    // recording is not enough.
    if !app.link_throttle.claim(&bucket) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; wait a minute",
        )
        .with_retry_after(60));
    }
    let password = password.unwrap_or_default().to_owned();
    let hash = hash.to_owned();
    // This path's own argon2 budget, separate from sign-in so a flood of
    // link guesses cannot queue ahead of the operator. The permit moves into
    // the blocking task so a disconnect cannot release it early.
    let permit = Arc::clone(&app.link_verify_permits)
        .acquire_owned()
        .await
        .map_err(|_| ApiError::internal("verify semaphore closed"))?;
    let app = Arc::clone(app);
    let store = Arc::clone(&app.store);
    let tenant = resource.tenant.to_owned();
    let subject = resource.id.to_owned();
    let kind = resource.kind.label();
    let client_ip = ip.to_owned();
    let ok = tokio::task::spawn_blocking(move || {
        let ok = auth::verify_password(&password, &hash);
        drop(permit);
        if ok {
            app.link_throttle.succeeded(&bucket);
        }
        let event = if ok {
            tracing::info!(
                target: "audit",
                event = "link_unlocked",
                tenant = %tenant,
                subject = %subject,
                kind,
                client_ip = %client_ip,
                "public link password accepted"
            );
            "link_unlocked"
        } else {
            tracing::warn!(
                target: "audit",
                event = "link_password_failed",
                tenant = %tenant,
                subject = %subject,
                kind,
                client_ip = %client_ip,
                "public link password rejected"
            );
            "link_password_failed"
        };
        store.audit(
            &tenant,
            "",
            event,
            &subject,
            &json!({"kind": kind, "client_ip": client_ip}),
        );
        ok
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?;
    if !ok {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, error_message));
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
        .upload_link(&token)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if !link.usable_now() {
        return Err(ApiError::new(
            StatusCode::GONE,
            "this link is no longer accepting uploads",
        ));
    }
    let ip = client_ip(&headers, &peer, &app.config.trusted_proxies);
    check_password(
        &app,
        PasswordResource {
            tenant: &link.tenant,
            id: &link.id,
            kind: PasswordResourceKind::Receive,
        },
        link.password_hash.as_deref(),
        request.password.as_deref(),
        &ip,
        "wrong link password",
    )
    .await?;
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

struct PreparedSession {
    link: Link,
    expected: ObjectId,
    dest_dir: std::path::PathBuf,
    destinations: Arc<crate::receiving::Destinations>,
    cap: u64,
    max_total: Option<u64>,
    max_sessions: Option<u64>,
}

async fn prepare_session(
    app: &Arc<App>,
    token: &str,
    headers: &HeaderMap,
    password: Option<&str>,
    peer: &std::net::SocketAddr,
    parse: impl FnOnce() -> ApiResult<ObjectId>,
) -> ApiResult<PreparedSession> {
    if app.is_stopping() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "the server is shutting down; retry after restart",
        ));
    }
    // Refuse new sessions while draining so active uploads finish before a
    // restart. 503 is transient to the sender, which pauses and resumes.
    if app
        .store
        .resolved_settings(&app.config)
        .map_err(super::store_unavailable)?
        .draining
    {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "the server is draining for maintenance; your upload will resume shortly",
        ));
    }
    let link = app
        .store
        .upload_link(token)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if !link.usable_now() {
        return Err(ApiError::new(
            StatusCode::GONE,
            "this link is no longer accepting uploads",
        ));
    }
    // Every attempt consumes rate budget, whatever the outcome. Otherwise a
    // no-password link can churn sessions into the shared capacity limit.
    let ip = client_ip(headers, peer, &app.config.trusted_proxies);
    if !app.session_rate.allow(&ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many uploads started from your address; try again later",
        )
        .with_retry_after(600));
    }
    if !link_authorized(app, &link, headers) {
        check_password(
            app,
            PasswordResource {
                tenant: &link.tenant,
                id: &link.id,
                kind: PasswordResourceKind::Receive,
            },
            link.password_hash.as_deref(),
            password,
            &ip,
            "wrong link password",
        )
        .await?;
    }
    let tenant = if link.tenant.is_empty() {
        None
    } else {
        match app
            .store
            .tenant(&link.tenant)
            .map_err(super::store_unavailable)?
        {
            Some(tenant) => Some(tenant),
            None => {
                audit_session_rejected(app, &link.tenant, "link tenant missing");
                return Err(ApiError::new(
                    StatusCode::GONE,
                    "this link's tenant no longer exists",
                ));
            }
        }
    };
    let expected = parse()?;
    let cap = effective_cap(app, &link);
    if expected.length > cap {
        audit_session_rejected(app, &link.tenant, "per-link size cap");
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("upload exceeds the {cap} byte limit for this link"),
        ));
    }
    let (max_total, _, max_sessions) = if let Some(tenant) = &tenant {
        (
            tenant.max_total_bytes,
            tenant.max_links,
            tenant.max_sessions,
        )
    } else {
        app.store
            .quotas_for("", &app.config)
            .map_err(super::store_unavailable)?
    };
    if link
        .dest
        .split('/')
        .any(crate::protocol_paths::is_receipt_name)
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "receiving destination uses a name reserved for signed receipts",
        ));
    }
    // Compute the destination before either transport reserves capacity. Link
    // creation already vets these components; join_under repeats the boundary
    // check so native push and HTTP fail admission in the same place.
    let mut dest_components = tenant
        .as_ref()
        .map_or_else(Vec::new, |tenant| tenant.path_prefix());
    dest_components.extend(
        link.dest
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned),
    );
    let dest_dir =
        paths::join_under(&app.config.receive_dir, &dest_components).map_err(ApiError::internal)?;
    let destinations = app.receiving_destinations_async().await.map_err(|error| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("receiving storage is unavailable: {error}"),
        )
    })?;
    Ok(PreparedSession {
        destinations,
        link,
        expected,
        dest_dir,
        cap,
        max_total,
        max_sessions,
    })
}

async fn register_session(
    app: &Arc<App>,
    prepared: &PreparedSession,
    id: &str,
    sender: mpsc::Sender<Cmd>,
    kind: session::SessionKind,
    route: Option<&crate::store::InboundRoute>,
    admission_guard: session::AdmissionGuard,
) -> ApiResult<session::AdmissionGuard> {
    #[cfg(test)]
    app.sessions.wait_session_create_stall().await;
    let transport = if matches!(kind, session::SessionKind::Http) {
        "http"
    } else {
        "push"
    };
    let admission = session::SessionAdmission {
        id: id.to_owned(),
        link_id: prepared.link.id.clone(),
        tenant: prepared.link.tenant.clone(),
        reserved_bytes: prepared.expected.length,
        max_total_bytes: prepared.max_total,
        max_tenant_sessions: prepared.max_sessions,
        max_link_sessions: app.config.max_link_sessions,
        max_sessions: app.config.max_total_sessions,
        kind,
    };
    // Off the runtime thread: admission's quota check reads the store.
    let admit_app = Arc::clone(app);
    let admit_tenant = prepared.link.tenant.clone();
    let admission_guard = tokio::task::spawn_blocking(move || {
        admit_app.sessions.insert_admitted_with_guard(
            admission,
            sender,
            || admit_app.store.tenant_admission_usage(&admit_tenant),
            admission_guard,
        )
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?
    .map_err(|error| session_insert_error(app, &prepared.link.tenant, error))?;
    match app.store.upload_link(&prepared.link.id) {
        Ok(Some(current)) if current.tenant == prepared.link.tenant && current.usable_now() => {
            if route.is_none() {
                match app.store.is_trade_endpoint(&prepared.link.id) {
                    Ok(false) => {}
                    result => {
                        app.sessions.remove(id);
                        return Err(match result {
                            Err(error) => super::store_unavailable(error),
                            _ => ApiError::new(
                                StatusCode::CONFLICT,
                                "This receiving endpoint requires an enrolled trade route",
                            ),
                        });
                    }
                }
            }
            if let Some(route) = route {
                if let Err(error) = app.store.bind_route_session(route, id, transport) {
                    app.sessions.remove(id);
                    return Err(ApiError::new(StatusCode::CONFLICT, error));
                }
            }
            Ok(admission_guard)
        }
        Ok(_) => {
            app.sessions.remove(id);
            audit_session_rejected(
                app,
                &prepared.link.tenant,
                "link deleted during session creation",
            );
            Err(ApiError::new(
                StatusCode::GONE,
                "this link is no longer accepting uploads",
            ))
        }
        Err(error) => {
            app.sessions.remove(id);
            Err(super::store_unavailable(error))
        }
    }
}

fn session_insert_error(app: &App, tenant: &str, error: session::InsertError) -> ApiError {
    match error {
        session::InsertError::ShuttingDown => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "the server is shutting down; retry after restart",
        ),
        session::InsertError::TenantPinned => {
            audit_session_rejected(app, tenant, "tenant pinned for delete");
            ApiError::new(StatusCode::GONE, "this link's tenant no longer exists")
        }
        session::InsertError::LinkPinned => {
            audit_session_rejected(app, tenant, "link pinned for delete");
            ApiError::new(StatusCode::GONE, "this link no longer exists")
        }
        session::InsertError::ByteQuota => {
            audit_session_rejected(app, tenant, "byte quota exhausted");
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "this tenant's storage quota is exhausted",
            )
        }
        session::InsertError::TenantSessionLimit => {
            audit_session_rejected(app, tenant, "tenant session cap reached");
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too many concurrent uploads for this tenant",
            )
            .with_retry_after(1)
        }
        session::InsertError::Capacity => {
            audit_session_rejected(app, tenant, "global or per-link session cap");
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too many uploads in progress; try again shortly",
            )
            .with_retry_after(1)
        }
        session::InsertError::Store(error) => super::store_unavailable(error),
    }
}

pub async fn create_session(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CreateSessionRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let prepared = prepare_session(
        &app,
        &token,
        &headers,
        request.password.as_deref(),
        &peer,
        || parse_object(&request.package),
    )
    .await?;
    let route = super::outbound::workflows::routes::admission(
        &app,
        request.route.as_deref(),
        &prepared.link.id,
    )?;
    if let Some(existing) = route
        .as_ref()
        .and_then(|route| route.session_id.as_ref())
        .filter(|id| app.sessions.link_id(id).is_some())
    {
        if app.sessions.contains_push(existing) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "route has an active native transfer",
            ));
        }
        return Ok(Json(
            json!({"session":existing,"chunk_bytes":session::CHUNK_BYTES,"resume":true}),
        ));
    }
    let announced_bytes = prepared.expected.length;

    let session_id = auth::random_token();
    let session_bytes: [u8; 16] = hex::decode(&session_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ApiError::internal("session id shape"))?;
    let setup = session::WorkerSetup {
        store: Arc::clone(&app.store),
        link_id: prepared.link.id.clone(),
        tenant: prepared.link.tenant.clone(),
        dest_dir: prepared.dest_dir.clone(),
        destinations: Arc::clone(&prepared.destinations),
        dest_rel: prepared.link.dest.clone(),
        expected_package: prepared.expected.clone(),
        max_total_bytes: prepared.cap,
        allow_hidden: app.config.allow_hidden,
        signer: Arc::clone(&app.signer),
        session_id: session_bytes,
        started_at: now_unix(),
        quiet_after_secs: session::quiet_after_secs(app.config.session_idle_secs),
        ended: app.session_ended.clone(),
    };
    // Depth matches the client's chunk concurrency so handlers rarely block
    // on send. Register the sender before the worker can create_dir_all.
    let (sender, receiver) = mpsc::channel(8);
    let admission_guard = app.sessions.try_admit().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "the server is shutting down; retry after restart",
        )
    })?;
    let _admission_guard = register_session(
        &app,
        &prepared,
        &session_id,
        sender,
        session::SessionKind::Http,
        route.as_ref(),
        admission_guard,
    )
    .await?;
    session::spawn_worker(setup, receiver);
    tracing::info!(
        target: "audit", event = "upload_session_created", link = %prepared.link.id,
        session_tag = %session_id.get(..8).unwrap_or(&session_id),
        bytes = announced_bytes, "upload session started"
    );
    // Off the runtime thread: the audit insert takes the store lock and an
    // fsync'd commit, and this is the hottest write path in the app.
    let store = Arc::clone(&app.store);
    let tenant = prepared.link.tenant.clone();
    let link_id = prepared.link.id.clone();
    let detail = serde_json::json!({ "session_tag": &session_id[..8.min(session_id.len())], "bytes": announced_bytes });
    tokio::task::spawn_blocking(move || {
        store.audit(&tenant, "", "upload_session_created", &link_id, &detail)
    })
    .await
    .ok();
    Ok(Json(json!({
        "session": session_id,
        "chunk_bytes": session::CHUNK_BYTES,
    })))
}

pub async fn create_push_session(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CreatePushRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let Some(push) = app.push.as_ref() else {
        return Err(ApiError::not_found());
    };
    let prepared = prepare_session(
        &app,
        &token,
        &headers,
        request.password.as_deref(),
        &peer,
        || parse_push_object(&request.package),
    )
    .await?;
    let max_entries = session::max_entries_for_bytes(prepared.cap);
    if request.package.entries == 0 || request.package.entries > max_entries {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("package entry count is outside 1..={max_entries}"),
        ));
    }
    let route = super::outbound::workflows::routes::admission(
        &app,
        request.route.as_deref(),
        &prepared.link.id,
    )?;
    if route
        .as_ref()
        .and_then(|route| route.session_id.as_ref())
        .is_some_and(|id| app.sessions.link_id(id).is_some())
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "route transfer is already active",
        ));
    }
    let holder: [u8; 32] = hex::decode(&request.holder_key)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "holder_key must be 32 bytes of hex",
            )
        })?;
    let holder = ed25519_dalek::VerifyingKey::from_bytes(&holder)
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid holder_key"))?
        .to_bytes();
    let admission_guard = app.sessions.try_admit().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "the server is shutting down; retry after restart",
        )
    })?;
    let session_id = auth::random_token();
    let session_bytes: [u8; 16] = hex::decode(&session_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ApiError::internal("session id shape"))?;
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"votport push resume v1");
    hash.update((prepared.link.id.len() as u64).to_be_bytes());
    hash.update(prepared.link.id.as_bytes());
    hash.update(prepared.expected.suite.to_be_bytes());
    hash.update(prepared.expected.root);
    hash.update(prepared.expected.length.to_be_bytes());
    hash.update(holder);
    let key = hex::encode(&hash.finalize()[..16]);
    let components = prepared
        .dest_dir
        .strip_prefix(&app.config.receive_dir)
        .map_err(|_| ApiError::internal("destination is outside receiving storage"))?
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let store = Arc::clone(&app.store);
    let root = Arc::clone(&prepared.destinations);
    let tenant = prepared.link.tenant.clone();
    let destination = prepared.link.dest.clone();
    let destinations = tokio::task::spawn_blocking(move || -> ApiResult<_> {
        let _allocation = store
            .upload_allocation
            .lock()
            .map_err(|_| ApiError::internal("upload allocation poisoned"))?;
        session::check_upload_directory(&store, &tenant, &destination).map_err(ApiError::from)?;
        root.child(&components)
            .map(Arc::new)
            .map_err(ApiError::internal)
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))??;
    let directory = destinations
        .push_directory(&key)
        .map_err(ApiError::internal)?;
    let lock = session::lock_push_directory(&directory, prepared.destinations.contract())
        .map_err(|error| ApiError::new(StatusCode::CONFLICT, error.to_string()))?;
    let control_directory = destinations
        .clear_push_directory(&directory, &lock)
        .map_err(ApiError::internal)?;
    lock.set_modified(std::time::SystemTime::now())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    control_directory
        .private_child(std::ffi::OsStr::new("engine"))
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let engine = control_directory
        .entry(std::ffi::OsStr::new("engine"))
        .map_err(|error| ApiError::internal(error.to_string()))?
        .path();
    let control = session::PushControl::resumable(key.clone(), Some(lock));
    let setup = session::WorkerSetup {
        store: Arc::clone(&app.store),
        link_id: prepared.link.id.clone(),
        tenant: prepared.link.tenant.clone(),
        dest_dir: prepared.dest_dir.clone(),
        destinations,
        dest_rel: prepared.link.dest.clone(),
        expected_package: prepared.expected.clone(),
        max_total_bytes: prepared.cap,
        allow_hidden: app.config.allow_hidden,
        signer: Arc::clone(&app.signer),
        session_id: session_bytes,
        started_at: now_unix(),
        quiet_after_secs: session::quiet_after_secs(app.config.session_idle_secs),
        ended: app.session_ended.clone(),
    };
    let (sender, _receiver) = mpsc::channel(1);
    let admission_guard = match register_session(
        &app,
        &prepared,
        &session_id,
        sender,
        session::SessionKind::Push(control.clone()),
        route.as_ref(),
        admission_guard,
    )
    .await
    {
        Ok(guard) => guard,
        Err(error) => {
            let _ = std::fs::remove_dir(&directory);
            return Err(error);
        }
    };

    if let Err(error) = session::persist_push(&setup, key) {
        app.sessions.remove(&session_id);
        control.park();
        return Err(ApiError::internal(format!("persist push session: {error}")));
    }
    let issued = (|| -> ApiResult<(Vec<u8>, [u8; 16], u64)> {
        let now = now_unix();
        let token = vot_cli::authz::issue_push(
            "votport",
            &push.audience,
            &push.issuer,
            holder,
            prepared.expected.root,
            prepared.expected.length,
            now,
            app.config.session_idle_secs,
        )
        .map_err(|error| ApiError::internal(format!("issue native push capability: {error:?}")))?;
        let signed = vot_capability::decode(&token).map_err(|error| {
            ApiError::internal(format!("decode issued native push capability: {error:?}"))
        })?;
        let capability = vot_capability::Capability::from_canonical_bytes(&signed.capability)
            .map_err(|error| {
                ApiError::internal(format!("decode issued native push claims: {error:?}"))
            })?;
        Ok((token, capability.token_id, capability.expiry))
    })();
    let (capability, token_id, expires_at) = match issued {
        Ok(issued) => issued,
        Err(error) => {
            control.park();
            return Err(error);
        }
    };
    let ticket = PushTicket {
        session_id: session_id.clone(),
        expires_at,
        expected_package: setup.expected_package.clone(),
        directory: engine,
        setup: Some(setup),
        seams: None,
        control: control.clone(),
    };
    let inserted = match app
        .push_tickets
        .lock()
        .expect("push tickets poisoned")
        .entry(token_id)
    {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(ticket);
            true
        }
        std::collections::hash_map::Entry::Occupied(_) => false,
    };
    if !inserted {
        control.park();
        return Err(ApiError::internal("native push token id collision"));
    }
    tracing::info!(
        target: "audit", event = "push_admitted", link = %prepared.link.id,
        session_tag = %session_id.get(..8).unwrap_or(&session_id),
        bytes = prepared.expected.length, "native push session started"
    );
    app.store.audit(
        &prepared.link.tenant,
        "",
        "push_admitted",
        &prepared.link.id,
        &json!({
            "session_tag": &session_id[..8.min(session_id.len())],
            "bytes": prepared.expected.length
        }),
    );
    drop(admission_guard);
    Ok(Json(json!({
        "session": session_id,
        "capability": base64::engine::general_purpose::STANDARD.encode(capability),
        "address": push.address,
        "certificate_digest": hex::encode(push.certificate_digest),
        "expires_at": expires_at,
    })))
}

async fn dispatch<T>(
    app: &App,
    session_id: &str,
    build: impl FnOnce(oneshot::Sender<Result<T, SessionError>>, session::SessionLease) -> Cmd,
) -> ApiResult<T> {
    let command = app
        .sessions
        .touch(session_id)
        .map_err(|error| match error {
            session::TouchError::NotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "unknown or expired session")
            }
            session::TouchError::WrongKind => ApiError::new(
                StatusCode::CONFLICT,
                "native push sessions cannot use the HTTP upload protocol",
            ),
        })?;
    let (reply, receive) = oneshot::channel();
    let command_to_send = build(reply, command.lease);
    #[cfg(test)]
    let finish_dispatch = matches!(&command_to_send, Cmd::Finish { .. });
    command
        .sender
        .send(command_to_send)
        .await
        .map_err(|_| ApiError::new(StatusCode::GONE, "upload session ended"))?;
    #[cfg(test)]
    if finish_dispatch {
        app.sessions.wait_finish_dispatch_stall().await;
    }
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
    let pages = dispatch(&app, &sid, |reply, _lease| Cmd::Seal {
        bytes: body,
        reply,
        _lease,
    })
    .await?;
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
    let remaining = dispatch(&app, &sid, |reply, _lease| Cmd::Page {
        bytes: body,
        reply,
        _lease,
    })
    .await?;
    Ok(Json(json!({ "remaining_pages": remaining })))
}

pub async fn upload_begin(
    State(app): State<Arc<App>>,
    Path(sid): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let stopping = Arc::clone(&app.stopping);
    let entries = dispatch(&app, &sid, |reply, _lease| Cmd::Begin {
        reply,
        _lease,
        stopping,
    })
    .await?;
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
    let progress = dispatch(&app, &sid, |reply, _lease| Cmd::Chunk {
        entry: query.entry,
        offset: query.offset,
        proof,
        data,
        reply,
        _lease,
    })
    .await?;
    app.sessions.set_received(&sid, progress.received);
    Ok(Json(progress))
}

pub async fn upload_finish(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Path(sid): Path<String>,
) -> ApiResult<Json<session::FinishReport>> {
    let runtime = tokio::runtime::Handle::current();
    let ip = client_ip(&headers, &peer, &app.config.trusted_proxies);
    // Off the runtime thread: completion does a link read plus an fsync'd
    // audit insert, once per finished file. The push path calls this from
    // its own OS thread and needs no wrapper.
    let application = Arc::clone(&app);
    let session_id = sid.clone();
    let session_tag = sid.get(..8).unwrap_or(&sid).to_owned();
    let task_session_tag = session_tag.clone();
    let finish = tokio::spawn(async move {
        let link_id = application.sessions.link_id(&session_id);
        let report = dispatch(&application, &session_id, |reply, _lease| Cmd::Finish {
            reply,
            _lease,
        })
        .await?;
        #[cfg(test)]
        application.sessions.wait_finish_stall().await;
        let report_for_completion = report.clone();
        let app_for_completion = Arc::clone(&application);
        if let Err(error) = tokio::task::spawn_blocking(move || {
            crate::app::upload_completed(
                &app_for_completion,
                &session_id,
                link_id,
                &report_for_completion,
                &runtime,
            )
        })
        .await
        {
            // A panic here loses the completion audit row and notification for
            // good; the session slot itself is reclaimed by the idle sweep.
            tracing::error!(%error, session = %task_session_tag, "upload completion bookkeeping failed");
        }
        // A finished session that moved bytes is not churn: a sender shipping
        // many drops in a row would otherwise stall on the per-address creation
        // limit after twenty of them. Refund after the slot is released above,
        // and never for a session that finished on already-delivered files,
        // which costs the sender nothing.
        if report.received > 0 {
            application.session_rate.refund(&ip);
        }
        Ok::<_, ApiError>(report)
    });
    match finish.await {
        Ok(result) => result.map(Json),
        Err(error) => {
            tracing::error!(%error, session = %session_tag, "upload finish task failed");
            Err(ApiError::internal("upload finish task failed"))
        }
    }
}

pub async fn upload_abort(
    State(app): State<Arc<App>>,
    Path(sid): Path<String>,
) -> Json<serde_json::Value> {
    if app.sessions.contains_push(&sid) {
        let mut ticket_found = false;
        let setup = {
            let mut tickets = app.push_tickets.lock().expect("push tickets poisoned");
            let key = tickets
                .iter()
                .find(|(_, ticket)| ticket.session_id == sid)
                .map(|(key, _)| *key);
            if let Some(key) = key {
                ticket_found = true;
                if let Some(ticket) = tickets.get(&key) {
                    ticket.control.abort();
                }
                if tickets
                    .get(&key)
                    .is_some_and(|ticket| ticket.setup.is_some())
                {
                    tickets.remove(&key).and_then(|ticket| {
                        let parked = ticket.control.park();
                        ticket.setup.map(|setup| (setup, parked))
                    })
                } else {
                    None
                }
            } else {
                None
            }
        };
        if !ticket_found {
            app.sessions.abort_push(&sid);
        }
        if let Some((setup, parked)) = setup {
            if !parked {
                app.sessions.remove(&sid);
            }
            session::record_unconnected_push(setup, true);
        }
        return Json(json!({ "ok": true }));
    }
    // Best effort: lets the worker record a "cancelled" event; an unknown or
    // already-dead session still answers ok.
    let _ = dispatch(&app, &sid, |reply, _lease| Cmd::Abort { reply, _lease }).await;
    app.sessions.remove(&sid);
    Json(json!({ "ok": true }))
}

#[cfg(test)]
mod session_rate_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use vot_sdk::object::{InMemoryObjectBuilder, Suite};
    use vot_sdk::package::{PackageBuilder, PackageEntry};

    use crate::api::testing;
    use crate::app;
    use crate::store::Link;

    fn open_link(id: &str) -> Link {
        Link {
            id: id.to_owned(),
            tenant: String::new(),
            label: "open".to_owned(),
            dest: String::new(),
            password_hash: None,
            created_at: 0,
            expires_at: None,
            max_bytes: None,
            active: true,
            legal_hold: false,

            notifications: None,
            uploads: Vec::new(),
            events: Vec::new(),
        }
    }

    async fn create_received_session(application: &Arc<App>, link_id: &str) -> String {
        let bytes = b"finished";
        let mut object = InMemoryObjectBuilder::new(
            Suite::Blake3Bao64,
            Some(bytes.len() as u64),
            bytes.len() as u64,
        )
        .unwrap();
        object.update(bytes).unwrap();
        let prepared = object.finish().unwrap();
        let mut package = PackageBuilder::new().unwrap();
        let entry =
            PackageEntry::direct(vec!["file.bin".to_owned()], prepared.object_id()).unwrap();
        assert!(package.push(&entry).unwrap().is_none());
        let (summary, page, mut finalizer) = package.finish().unwrap().into_parts();
        let page = finalizer.push(page).unwrap().into_bytes();
        let seal = finalizer.finish().unwrap().into_bytes();
        let package_id = summary.object_id();
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], 4000));
        let create = Request::post(format!("/api/r/{link_id}/session"))
            .header("content-type", "application/json")
            .extension(ConnectInfo(address))
            .body(Body::from(
                json!({
                    "package": {
                        "suite": "blake3",
                        "root": hex::encode(package_id.root),
                        "length": package_id.length
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let response = app::router(application.clone())
            .oneshot(create)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let session = serde_json::from_slice::<serde_json::Value>(
            &response.into_body().collect().await.unwrap().to_bytes(),
        )
        .unwrap()["session"]
            .as_str()
            .unwrap()
            .to_owned();

        for (path, body) in [
            (format!("/api/session/{session}/seal"), seal),
            (format!("/api/session/{session}/page"), page),
        ] {
            assert_eq!(
                app::router(application.clone())
                    .oneshot(Request::post(path).body(Body::from(body)).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        assert_eq!(
            app::router(application.clone())
                .oneshot(
                    Request::post(format!("/api/session/{session}/begin"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let proof = prepared.prove(0, bytes.len() as u64).unwrap();
        let mut body = proof.proof().to_vec();
        let proof_len = body.len();
        body.extend_from_slice(bytes);
        assert_eq!(
            app::router(application.clone())
                .oneshot(
                    Request::post(format!("/api/session/{session}/chunk?entry=0&offset=0"))
                        .header("x-votport-proof", proof_len.to_string())
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        session
    }

    async fn assert_completed(application: &Arc<App>, link_id: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while application.sessions.active_for_link(link_id) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled finish did not release the session");
        assert_eq!(application.sessions.total(), 0);
        assert!(application.store.load_upload_sessions().unwrap().is_empty());
        let uploads = application.store.uploads_by_id(link_id).unwrap().unwrap();
        assert_eq!(uploads.len(), 1);
        assert!(application
            .store
            .audit_export(Some(""), 0, 0, 100)
            .unwrap()
            .iter()
            .any(|row| row.event == "upload_completed"));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !application.session_rate.allow("127.0.0.1") {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled finish did not refund the session rate budget");
    }

    #[tokio::test]
    async fn finish_with_unicode_session_id_returns_an_error_without_panicking() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let response = app::router(application)
            .oneshot(
                Request::post("/api/session/aaaaaaa%C3%A9/finish")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        4000,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn draining_refuses_new_sessions_with_a_transient_status() {
        use crate::store::SettingWrite;
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(open_link("drain-link"))
            .unwrap();
        let session_request = || {
            Request::builder()
                .method("POST")
                .uri("/api/r/drain-link/session")
                .header("content-type", "application/json")
                .extension(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    5000,
                ))))
                .body(Body::from(
                    r#"{"package":{"suite":"blake3","root":"00","length":1}}"#,
                ))
                .unwrap()
        };
        // Not draining: admission proceeds far enough to reject the bad
        // package (422), not the drain 503.
        let router = app::router(Arc::clone(&application));
        let response = router.oneshot(session_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        application
            .store
            .put_settings(
                "admin",
                &[("draining".to_owned(), SettingWrite::Set("1".to_owned()))],
            )
            .unwrap();
        // Draining: refused before the package is parsed, with a transient
        // status the sender retries.
        let router = app::router(Arc::clone(&application));
        let response = router.oneshot(session_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn session_creation_is_rate_limited_per_ip() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(open_link("rate-limited-link"))
            .unwrap();

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
        assert_eq!(response.headers()[header::RETRY_AFTER], "600");
    }

    #[tokio::test]
    async fn session_creation_uses_the_atomic_link_cap() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(open_link("full-link"))
            .unwrap();
        let mut receivers = Vec::new();
        for index in 0..application.config.max_link_sessions {
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            application
                .sessions
                .insert(
                    format!("session-{index}"),
                    "full-link".to_owned(),
                    String::new(),
                    sender,
                )
                .unwrap();
            receivers.push(receiver);
        }

        let response = app::router(application.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/r/full-link/session")
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        1234,
                    ))))
                    .body(Body::from(
                        r#"{"package":{"suite":"blake3","root":"0000000000000000000000000000000000000000000000000000000000000000","length":1}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        assert_eq!(
            application.sessions.total(),
            application.config.max_link_sessions
        );
    }

    #[tokio::test]
    async fn session_creation_rechecks_a_link_deleted_before_registration() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(open_link("delete-race"))
            .unwrap();
        let (entered, release) = application.sessions.arm_session_create_stall();
        let router = app::router(application.clone());
        let create = tokio::spawn(async move {
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/r/delete-race/session")
                        .header("content-type", "application/json")
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            1234,
                        ))))
                        .body(Body::from(
                            r#"{"package":{"suite":"blake3","root":"0000000000000000000000000000000000000000000000000000000000000000","length":1}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        entered.await.unwrap();
        assert!(application.store.remove_link("", "delete-race").unwrap());
        release.send(()).unwrap();

        assert_eq!(create.await.unwrap().status(), StatusCode::GONE);
        assert_eq!(application.sessions.total(), 0);
    }

    #[tokio::test]
    async fn session_creation_stopped_while_registration_is_waiting_has_no_late_worker() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(open_link("shutdown-race"))
            .unwrap();
        let (entered, release) = application.sessions.arm_session_create_stall();
        let router = app::router(application.clone());
        let mut create = tokio::spawn(async move {
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/r/shutdown-race/session")
                        .header("content-type", "application/json")
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            1234,
                        ))))
                        .body(Body::from(
                            r#"{"package":{"suite":"blake3","root":"0000000000000000000000000000000000000000000000000000000000000000","length":1}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        if tokio::time::timeout(std::time::Duration::from_secs(1), entered)
            .await
            .is_err()
        {
            let _ = release.send(());
            create.abort();
            let _ = create.await;
            panic!("session creation did not reach the admission barrier");
        }
        application.request_shutdown();
        let _ = application.sessions.take_http();
        release.send(()).unwrap();

        let response =
            match tokio::time::timeout(std::time::Duration::from_secs(1), &mut create).await {
                Ok(result) => result.unwrap(),
                Err(_) => {
                    create.abort();
                    let _ = create.await;
                    panic!("session creation did not finish after admission release");
                }
            };
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(application.sessions.total(), 0);
    }

    #[tokio::test]
    async fn session_creation_rechecks_endpoint_pairing_before_registration() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(open_link("pair-race"))
            .unwrap();
        let (entered, release) = application.sessions.arm_session_create_stall();
        let router = app::router(application.clone());
        let create = tokio::spawn(async move {
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/r/pair-race/session")
                        .header("content-type", "application/json")
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            1234,
                        ))))
                        .body(Body::from(
                            r#"{"package":{"suite":"blake3","root":"0000000000000000000000000000000000000000000000000000000000000000","length":1}}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        entered.await.unwrap();
        application
            .store
            .create_trade_endpoint(
                "",
                &crate::store::TradeEndpoint {
                    id: "pair-race".into(),
                    name: "Paired".into(),
                    category: "external".into(),
                    forwarding: false,
                    metadata_keys: vec![],
                    notifications: crate::store::NotificationPolicy::default(),
                },
            )
            .unwrap();
        release.send(()).unwrap();

        assert_eq!(create.await.unwrap().status(), StatusCode::CONFLICT);
        assert_eq!(application.sessions.total(), 0);
    }

    #[tokio::test]
    async fn finish_keeps_the_session_registered_through_metadata_reads() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(open_link("finishing"))
            .unwrap();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        application
            .sessions
            .insert(
                "session".to_owned(),
                "finishing".to_owned(),
                String::new(),
                sender,
            )
            .unwrap();
        tokio::spawn(async move {
            let Some(Cmd::Finish { reply, _lease }) = receiver.recv().await else {
                panic!("finish command");
            };
            reply
                .send(Ok(session::FinishReport {
                    received: 0,
                    upload_id: "upload".to_owned(),
                    files: Vec::new(),
                }))
                .unwrap();
        });
        let (entered, release) = application.sessions.arm_finish_stall();
        let router = app::router(application.clone());
        let finish = tokio::spawn(async move {
            router
                .oneshot(
                    Request::post("/api/session/session/finish")
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            4000,
                        ))))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        entered.await.unwrap();
        assert_eq!(application.sessions.active_for_link("finishing"), 1);
        release.send(()).unwrap();

        assert_eq!(finish.await.unwrap().status(), StatusCode::OK);
        assert_eq!(application.sessions.active_for_link("finishing"), 0);
    }

    #[tokio::test]
    async fn cancelled_finish_completes_bookkeeping_and_refunds_rate_budget() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(open_link("cancel-finish"))
            .unwrap();

        let session = create_received_session(&application, "cancel-finish").await;
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], 4000));
        // The session creation already consumed one slot. Fill the bucket so
        // the completion task's refund is observable.
        for _ in 0..19 {
            assert!(application.session_rate.allow("127.0.0.1"));
        }
        let (entered, release) = application.sessions.arm_finish_stall();
        let router = app::router(application.clone());
        let finish = tokio::spawn(async move {
            router
                .oneshot(
                    Request::post(format!("/api/session/{session}/finish"))
                        .extension(ConnectInfo(address))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered)
            .await
            .unwrap()
            .unwrap();
        finish.abort();
        assert!(finish.await.unwrap_err().is_cancelled());
        let _ = release.send(());

        assert_completed(&application, "cancel-finish").await;
    }

    #[tokio::test]
    async fn cancelled_finish_before_reply_completes_bookkeeping_and_refunds_rate_budget() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(open_link("cancel-before-reply"))
            .unwrap();
        let session = create_received_session(&application, "cancel-before-reply").await;
        for _ in 0..19 {
            assert!(application.session_rate.allow("127.0.0.1"));
        }

        let (entered, release) = application.sessions.arm_finish_dispatch_stall();
        let router = app::router(application.clone());
        let finish = tokio::spawn(async move {
            router
                .oneshot(
                    Request::post(format!("/api/session/{session}/finish"))
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            4000,
                        ))))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered)
            .await
            .unwrap()
            .unwrap();
        finish.abort();
        assert!(finish.await.unwrap_err().is_cancelled());
        let _ = release.send(());

        assert_completed(&application, "cancel-before-reply").await;
    }
}

#[cfg(test)]
mod push_preflight_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use crate::api::testing;
    use crate::app;
    use crate::store::{Link, Tenant};

    fn push_app(directory: &std::path::Path) -> Arc<App> {
        let mut config = testing::config(directory);
        config.push_bind = Some("127.0.0.1:0".parse().unwrap());
        config.push_advertise = Some("push.example.test:8322".to_owned());
        app::build(config).unwrap()
    }

    #[tokio::test]
    async fn receiving_checks_do_not_block_session_creation_runtime() {
        use std::time::{Duration, Instant};
        let mut timings = Vec::new();
        for native in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let app = push_app(directory.path());
            app.store.insert_link(open_link("paused")).unwrap();
            let destinations = app.receiving_destinations().unwrap();
            let pause = crate::receiving::CheckPause::new(&destinations, 1);
            let holder = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
            let body = if native {
                request_body(&holder, 1)
            } else {
                json!({"package":{"suite":"blake3","root":hex::encode([7;32]),"length":1}})
            };
            let path = if native { "push" } else { "session" };
            let request = Request::post(format!("/api/r/paused/{path}"))
                .header("content-type", "application/json")
                .extension(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    1234,
                ))))
                .body(Body::from(body.to_string()))
                .unwrap();
            let started = Instant::now();
            let (response, timer) =
                tokio::join!(app::router(app.clone()).oneshot(request), async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let elapsed = started.elapsed();
                    pause.release();
                    elapsed
                });
            app::suspend_sessions(&app).await;
            assert_eq!(response.unwrap().status(), StatusCode::OK);
            timings.push((path, timer));
        }
        assert!(
            timings
                .iter()
                .all(|(_, timer)| *timer < Duration::from_millis(500)),
            "admission blocked async timers: {timings:?}"
        );
    }

    #[tokio::test]
    async fn receiving_checks_allow_concurrent_http_and_native_admissions() {
        use std::time::Duration;
        let directory = tempfile::tempdir().unwrap();
        let app = push_app(directory.path());
        let destinations = app.receiving_destinations().unwrap();
        let pause = crate::receiving::CheckPause::new(&destinations, 8);
        let mut requests = Vec::new();
        for index in 0..24_u8 {
            let link = format!("concurrent-{index}");
            app.store.insert_link(open_link(&link)).unwrap();
            let native = index % 2 == 0;
            let holder = ed25519_dalek::SigningKey::from_bytes(&[index; 32]);
            let body = if native {
                request_body(&holder, 1)
            } else {
                json!({"package":{"suite":"blake3","root":hex::encode([index;32]),"length":1}})
            };
            let path = if native { "push" } else { "session" };
            let request = Request::post(format!("/api/r/{link}/{path}"))
                .header("content-type", "application/json")
                .extension(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, index + 1],
                    1234,
                ))))
                .body(Body::from(body.to_string()))
                .unwrap();
            requests.push(tokio::spawn(app::router(app.clone()).oneshot(request)));
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while pause.entered() < 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(pause.entered(), 8);
        pause.release();
        let mut statuses = Vec::new();
        for request in requests {
            statuses.push(
                tokio::time::timeout(Duration::from_secs(3), request)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .status(),
            );
        }
        app::suspend_sessions(&app).await;
        assert!(
            statuses.iter().all(|status| *status == StatusCode::OK),
            "{statuses:?}"
        );
        assert_eq!(pause.entered(), 24);
    }

    fn open_link(id: &str) -> Link {
        Link {
            id: id.to_owned(),
            tenant: String::new(),
            label: "open".to_owned(),
            dest: String::new(),
            password_hash: None,
            created_at: 0,
            expires_at: None,
            max_bytes: None,
            active: true,
            legal_hold: false,

            notifications: None,
            uploads: Vec::new(),
            events: Vec::new(),
        }
    }

    #[tokio::test]
    async fn expired_receive_links_close_metadata_and_admission() {
        let directory = tempfile::tempdir().unwrap();
        let application = push_app(directory.path());
        let now = crate::store::now_unix();
        let mut expired = open_link("expired");
        expired.expires_at = Some(now.saturating_sub(3600));
        application.store.insert_link(expired).unwrap();
        let mut future = open_link("future");
        future.expires_at = Some(now + 3600);
        application.store.insert_link(future).unwrap();
        let router = app::router(application.clone());

        let info = router
            .clone()
            .oneshot(Request::get("/api/r/expired").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(info.status(), StatusCode::OK);
        let info = response_json(info).await;
        assert_eq!(info["usable"], false);
        assert!(info["label"].is_null());

        let peer = ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1234)));
        let verify = router
            .clone()
            .oneshot(
                Request::post("/api/r/expired/verify")
                    .header("content-type", "application/json")
                    .extension(peer)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify.status(), StatusCode::GONE);

        let session = router
            .clone()
            .oneshot(
                Request::post("/api/r/expired/session")
                    .header("content-type", "application/json")
                    .extension(peer)
                    .body(Body::from(
                        json!({
                            "package": {
                                "suite": "blake3",
                                "root": hex::encode([7_u8; 32]),
                                "length": 1
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::GONE);

        let holder = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        assert_eq!(
            post_push(application.clone(), "expired", request_body(&holder, 1))
                .await
                .status(),
            StatusCode::GONE
        );

        let info = router
            .clone()
            .oneshot(Request::get("/api/r/future").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(info.status(), StatusCode::OK);
        let info = response_json(info).await;
        assert_eq!(info["usable"], true);
        assert_eq!(info["label"], "open");

        let session = router
            .clone()
            .oneshot(
                Request::post("/api/r/future/session")
                    .header("content-type", "application/json")
                    .extension(peer)
                    .body(Body::from(
                        json!({
                            "package": {
                                "suite": "blake3",
                                "root": hex::encode([8_u8; 32]),
                                "length": 1
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::OK);

        assert_eq!(
            post_push(application.clone(), "future", request_body(&holder, 1))
                .await
                .status(),
            StatusCode::OK
        );
        app::suspend_sessions(&application).await;
    }

    #[tokio::test]
    async fn protected_link_password_failure_is_audited() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::tests::test_tenant("acme"))
            .unwrap();
        let mut link = open_link("password-audit");
        link.tenant = "acme".to_owned();
        link.password_hash = Some(auth::hash_password("correct password").unwrap());
        application.store.insert_link(link).unwrap();

        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/r/password-audit/session")
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [192, 0, 2, 8],
                        4444,
                    ))))
                    .body(Body::from(
                        r#"{"password":"wrong password","package":{"suite":"blake3","root":"0000000000000000000000000000000000000000000000000000000000000000","length":1}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/r/password-audit/verify")
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [192, 0, 2, 9],
                        4444,
                    ))))
                    .body(Body::from(r#"{"password":"wrong password"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let audits = application
            .store
            .audit_export(Some("acme"), 0, 0, 100)
            .unwrap();
        assert!(audits.iter().any(|row| {
            row.event == "link_password_failed"
                && row.subject == "password-audit"
                && row.detail["kind"] == "receive"
                && row.detail["client_ip"] == "192.0.2.9"
        }));

        let verified = app::router(application.clone())
            .oneshot(
                Request::post("/api/r/password-audit/verify")
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [192, 0, 2, 10],
                        4444,
                    ))))
                    .body(Body::from(r#"{"password":"correct password"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verified.status(), StatusCode::OK);
        let cookie = verified
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let session = app::router(application.clone())
            .oneshot(
                Request::post("/api/r/password-audit/session")
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [192, 0, 2, 10],
                        4444,
                    ))))
                    .body(Body::from(
                        r#"{"package":{"suite":"blake3","root":"0000000000000000000000000000000000000000000000000000000000000000","length":1}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::OK);
        app::suspend_sessions(&application).await;

        let audits = application
            .store
            .audit_export(Some("acme"), 0, 0, 100)
            .unwrap();
        let verdicts: Vec<_> = audits
            .iter()
            .filter(|row| {
                row.subject == "password-audit"
                    && matches!(row.event.as_str(), "link_password_failed" | "link_unlocked")
            })
            .collect();
        assert_eq!(
            verdicts.len(),
            3,
            "cookie authorization must not audit again"
        );
        assert!(verdicts.iter().any(|row| {
            row.event == "link_unlocked"
                && row.detail["kind"] == "receive"
                && row.detail["client_ip"] == "192.0.2.10"
        }));
        assert!(verdicts.iter().all(
            |row| row.actor.is_empty() && !row.detail.to_string().contains("correct password")
        ));

        application
            .store
            .insert_link(open_link("unprotected"))
            .unwrap();
        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/r/unprotected/verify")
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [192, 0, 2, 11],
                        4444,
                    ))))
                    .body(Body::from(r#"{"password":"anything"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!application
            .store
            .audit_export(None, 0, 0, 100)
            .unwrap()
            .iter()
            .any(|row| row.subject == "unprotected"));
    }

    #[tokio::test]
    async fn password_throttle_refusal_is_not_a_verdict() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let hash = auth::hash_password("correct password").unwrap();
        let resource = PasswordResource {
            tenant: "acme",
            id: "password-throttle",
            kind: PasswordResourceKind::Receive,
        };
        for _ in 0..5 {
            assert!(check_password(
                &application,
                resource,
                Some(&hash),
                Some("wrong password"),
                "192.0.2.12",
                "wrong link password",
            )
            .await
            .is_err());
        }
        let before = application.store.audit_export(None, 0, 0, 100).unwrap();
        assert_eq!(before.len(), 5);
        assert!(check_password(
            &application,
            resource,
            Some(&hash),
            Some("wrong password"),
            "192.0.2.12",
            "wrong link password",
        )
        .await
        .is_err());
        assert_eq!(
            application
                .store
                .audit_export(None, 0, 0, 100)
                .unwrap()
                .len(),
            before.len(),
            "a throttle refusal did not run password verification"
        );
    }

    #[tokio::test]
    async fn successful_password_clears_throttle_before_blocking_audit() {
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let hash = auth::hash_password("correct password").unwrap();
        let ip = "192.0.2.13";
        let permits = Arc::clone(&application.link_verify_permits)
            .acquire_many_owned(2)
            .await
            .unwrap();
        for _ in 0..4 {
            assert!(application.link_throttle.claim(ip));
        }
        assert!(!application.link_throttle.locked(ip));

        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let store = Arc::clone(&application.store);
        let holder = std::thread::spawn(move || {
            store
                .with(|_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    Ok(())
                })
                .unwrap();
        });
        if entered_rx.recv_timeout(Duration::from_secs(1)).is_err() {
            let _ = release_tx.send(());
            let _ = holder.join();
            panic!("store contention fixture did not acquire the store");
        }

        let app_for_check = Arc::clone(&application);
        let hash_for_check = hash.clone();
        let check = tokio::spawn(async move {
            check_password(
                &app_for_check,
                PasswordResource {
                    tenant: "acme",
                    id: "password-order",
                    kind: PasswordResourceKind::Receive,
                },
                Some(&hash_for_check),
                Some("correct password"),
                ip,
                "wrong link password",
            )
            .await
        });
        let locked = tokio::time::timeout(Duration::from_secs(5), async {
            while !application.link_throttle.locked(ip) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();
        if !locked {
            drop(permits);
            let _ = release_tx.send(());
            let _ = holder.join();
            let _ = tokio::time::timeout(Duration::from_secs(5), check).await;
            panic!("password check did not claim the locked bucket");
        }
        drop(permits);
        let cleared = tokio::time::timeout(Duration::from_secs(5), async {
            while application.link_throttle.locked(ip) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();
        if !cleared {
            let _ = release_tx.send(());
            let _ = holder.join();
            let _ = tokio::time::timeout(Duration::from_secs(5), check).await;
            panic!("successful verification stayed throttled");
        }
        let audit_blocked = !check.is_finished();
        let _ = release_tx.send(());
        holder.join().unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), check)
            .await
            .expect("password check did not finish after audit release")
            .unwrap();
        assert!(audit_blocked, "audit was not held by store contention");
        assert!(result.is_ok());
    }

    fn request_body(holder: &ed25519_dalek::SigningKey, length: u64) -> serde_json::Value {
        request_body_with_entries(holder, length, 3)
    }

    fn request_body_with_entries(
        holder: &ed25519_dalek::SigningKey,
        length: u64,
        entries: usize,
    ) -> serde_json::Value {
        json!({
            "holder_key": hex::encode(holder.verifying_key().to_bytes()),
            "package": {
                "suite": 1,
                "root": hex::encode([7_u8; 32]),
                "length": length,
                "entries": entries
            }
        })
    }

    async fn post_push(application: Arc<App>, link: &str, body: serde_json::Value) -> Response {
        app::router(application)
            .oneshot(
                Request::post(format!("/api/r/{link}/push"))
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        1234,
                    ))))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn stored_receipt_destinations_refuse_both_transports_before_reserving() {
        let directory = tempfile::tempdir().unwrap();
        let application = push_app(directory.path());
        let mut link = open_link("old-destination");
        link.dest = "deliveries/report.vot-receI\u{307}pt/child".into();
        application.store.insert_link(link.clone()).unwrap();
        let holder = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        for transport in ["session", "push"] {
            let mut body = request_body(&holder, 7);
            if transport == "session" {
                body.as_object_mut().unwrap().remove("holder_key");
                body["package"]["suite"] = json!("blake3");
            }
            let response = app::router(application.clone())
                .oneshot(
                    Request::post(format!("/api/r/{}/{transport}", link.id))
                        .header("content-type", "application/json")
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            1234,
                        ))))
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{transport}"
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(
                String::from_utf8_lossy(&body).contains("reserved for signed receipts"),
                "{transport}: {}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(application.sessions.active_for_link(&link.id), 0);
            assert!(application.push_tickets.lock().unwrap().is_empty());
            assert!(!application.config.receive_dir.join("deliveries").exists());
        }
    }

    async fn response_json(response: Response) -> serde_json::Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    #[tokio::test]
    async fn disabled_push_is_not_advertised_or_admitted() {
        let directory = tempfile::tempdir().unwrap();
        let assets = directory.path().join("web/assets");
        std::fs::create_dir_all(&assets).unwrap();
        std::fs::write(assets.join("fixture.js"), b"").unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(open_link("disabled"))
            .unwrap();
        let info = app::router(application.clone())
            .oneshot(Request::get("/api/r/disabled").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let info = response_json(info).await;
        assert_eq!(info["push"], false);
        // The web build hash lets a stale tab notice a deploy and reload.
        assert_eq!(info["web_build"], application.web_build);
        assert_eq!(application.web_build.len(), 16);
        assert!(application.web_build.chars().all(|c| c.is_ascii_hexdigit()));

        let holder = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        assert_eq!(
            post_push(application, "disabled", request_body(&holder, 7))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn link_info_advertises_the_byte_bound_entry_limit() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let mut link = open_link("small-cap");
        link.max_bytes = Some(1024 * 1024);
        application.store.insert_link(link).unwrap();

        let info = app::router(application)
            .oneshot(
                Request::get("/api/r/small-cap")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let info = response_json(info).await;
        assert_eq!(info["max_bytes"], 1024 * 1024);
        assert_eq!(
            info["max_entries"],
            crate::session::max_entries_for_bytes(1024 * 1024)
        );
    }

    #[tokio::test]
    async fn link_info_varies_and_is_not_cached_across_password_authorization() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let mut link = open_link("cache-headers");
        link.password_hash = Some(auth::hash_password("correct password").unwrap());
        application.store.insert_link(link).unwrap();

        let response = app::router(application.clone())
            .oneshot(
                Request::get("/api/r/cache-headers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::VARY], "Cookie");
        assert_eq!(response_json(response).await["authorized"], false);

        let verified = app::router(application.clone())
            .oneshot(
                Request::post("/api/r/cache-headers/verify")
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        1234,
                    ))))
                    .body(Body::from(r#"{"password":"correct password"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verified.status(), StatusCode::OK);
        let cookie = verified
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        let response = app::router(application)
            .oneshot(
                Request::get("/api/r/cache-headers")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::VARY], "Cookie");
        assert_eq!(response_json(response).await["authorized"], true);
    }

    #[tokio::test]
    async fn native_entry_count_is_checked_at_the_route_before_admission_history() {
        let cap = 1024 * 1024;
        let limit = crate::session::max_entries_for_bytes(cap);
        let holder = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        for (entries, status, admitted) in [
            (0, StatusCode::UNPROCESSABLE_ENTITY, false),
            (limit, StatusCode::OK, true),
            (limit + 1, StatusCode::UNPROCESSABLE_ENTITY, false),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let application = push_app(directory.path());
            let mut link = open_link("native-count");
            link.max_bytes = Some(cap);
            application.store.insert_link(link).unwrap();

            let response = post_push(
                application.clone(),
                "native-count",
                request_body_with_entries(&holder, 7, entries),
            )
            .await;
            assert_eq!(response.status(), status, "entries={entries}");
            assert_eq!(application.sessions.total(), usize::from(admitted));
            assert_eq!(
                application.push_tickets.lock().unwrap().len(),
                usize::from(admitted)
            );
            assert_eq!(
                application.store.load_push_sessions().unwrap().len(),
                usize::from(admitted)
            );
            if !admitted {
                let stage = application.config.receive_dir.join(".vot-stage");
                assert!(!std::fs::read_dir(stage).unwrap().any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".vot-push-")));
            }
            if admitted {
                let session = response_json(response).await["session"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let _ = upload_abort(State(application.clone()), Path(session)).await;
            }
        }
    }

    #[tokio::test]
    async fn native_admission_refuses_a_folder_reserved_by_an_upload() {
        let directory = tempfile::tempdir().unwrap();
        let application = push_app(directory.path());
        application.store.insert_link(open_link("root")).unwrap();
        let mut nested = open_link("nested");
        nested.dest = "folder/child".into();
        application.store.insert_link(nested).unwrap();
        let holder = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        assert!(
            post_push(application.clone(), "root", request_body(&holder, 7))
                .await
                .status()
                .is_success()
        );
        let mut saved = application.store.load_push_sessions().unwrap().remove(0);
        saved.files.push(crate::store::PersistedUploadFile {
            entry: 0,
            display_path: "folder".into(),
            stored_components: vec!["folder".into()],
            object: saved.package.clone(),
            staging_path: Default::default(),
            journal_path: Default::default(),
            incarnation: [0; 16],
            profile: vot_sdk_file::CommitProfile::Balanced,
            nas_contract: vot_sdk_file::NasContract::Unqualified,
            prefix_bytes: 0,
            published: false,
            receipt: false,
        });
        application.store.insert_upload_session(&saved).unwrap();
        let before = application.sessions.total();
        let response = post_push(application.clone(), "nested", request_body(&holder, 7)).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(!application.config.receive_dir.join("folder").exists());
        assert_eq!(application.sessions.total(), before);
        assert_eq!(application.store.load_push_sessions().unwrap(), [saved]);
        application
            .store
            .with(|connection| {
                connection.execute_batch(
                    "UPDATE upload_session_files SET stored_components='invalid json';",
                )
            })
            .unwrap();
        let response = post_push(application.clone(), "nested", request_body(&holder, 7)).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!application.config.receive_dir.join("folder").exists());
        assert_eq!(application.sessions.total(), before);
    }

    #[tokio::test]
    async fn completed_push_refusal_releases_runtime_admission() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = testing::config(directory.path());
        config.push_bind = Some("127.0.0.1:0".parse().unwrap());
        config.push_advertise = Some("push.example.test:8322".into());
        let application = app::build(config).unwrap();
        application.store.insert_link(open_link("retry")).unwrap();
        let holder = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let first = post_push(application.clone(), "retry", request_body(&holder, 7)).await;
        assert!(first.status().is_success());
        let id = response_json(first).await["session"]
            .as_str()
            .unwrap()
            .to_owned();
        let _ = upload_abort(State(application.clone()), Path(id.clone())).await;
        application.sessions.remove(&id);
        application
            .store
            .with(|connection| {
                connection.execute(
                    "UPDATE upload_sessions SET committed_upload_id='committed' WHERE id=?1",
                    [&id],
                )
            })
            .unwrap();
        let saved = application.store.load_push_sessions().unwrap();
        let usage = application.store.tenant_admission_usage("").unwrap().0;
        for _ in 0..2 {
            let response = post_push(application.clone(), "retry", request_body(&holder, 7)).await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(
                application.sessions.total(),
                0,
                "refusal must release runtime reservation"
            );
            assert_eq!(application.store.load_push_sessions().unwrap(), saved);
            assert_eq!(
                application.store.tenant_admission_usage("").unwrap().0,
                usage
            );
        }
    }

    #[tokio::test]
    async fn push_retry_replaces_parked_quota_and_old_abort_cannot_cancel_it() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = testing::config(directory.path());
        config.push_bind = Some("127.0.0.1:0".parse().unwrap());
        config.push_advertise = Some("push.example.test:8322".to_owned());
        config.max_total_sessions = 1;
        config.max_link_sessions = 1;
        let application = app::build(config).unwrap();
        application.store.insert_link(open_link("retry")).unwrap();
        let holder = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let first = post_push(application.clone(), "retry", request_body(&holder, 7)).await;
        assert!(first.status().is_success());
        let first = response_json(first).await["session"]
            .as_str()
            .unwrap()
            .to_owned();
        let busy = post_push(application.clone(), "retry", request_body(&holder, 7)).await;
        assert_eq!(busy.status(), StatusCode::CONFLICT);
        let before = application.store.load_push_sessions().unwrap();
        assert_eq!(before.len(), 1);
        let stage = before[0].dest_dir.join(format!(
            ".vot-stage/.vot-push-{}",
            before[0].push_key.as_ref().unwrap()
        ));
        let retained = stage.parent().unwrap().join("retained.stage");
        std::fs::write(&retained, b"verified bytes").unwrap();
        let _ = upload_abort(State(application.clone()), Path(first.clone())).await;
        assert!(application.sessions.contains_push(&first));
        let second = post_push(application.clone(), "retry", request_body(&holder, 7)).await;
        assert!(second.status().is_success());
        let second = response_json(second).await["session"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(first, second);
        assert!(!application.sessions.contains_push(&first));
        assert!(application.sessions.contains_push(&second));
        assert_eq!(std::fs::read(&retained).unwrap(), b"verified bytes");
        let after = application.store.load_push_sessions().unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, second);
        assert_eq!(after[0].push_key, before[0].push_key);
        let _ = upload_abort(State(application.clone()), Path(first)).await;
        assert!(!application
            .push_tickets
            .lock()
            .unwrap()
            .values()
            .find(|ticket| ticket.session_id == second)
            .unwrap()
            .control
            .is_cancelled());
        let foreign = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        assert!(
            !post_push(application.clone(), "retry", request_body(&foreign, 7))
                .await
                .status()
                .is_success()
        );
    }

    #[tokio::test]
    async fn preflight_issues_an_exact_capability_and_blocks_http_dispatch() {
        let directory = tempfile::tempdir().unwrap();
        let application = push_app(directory.path());
        application.store.insert_link(open_link("native")).unwrap();
        let holder = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);

        let info = app::router(application.clone())
            .oneshot(Request::get("/api/r/native").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response_json(info).await["push"], true);

        let response = post_push(application.clone(), "native", request_body(&holder, 7)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = response_json(response).await;
        assert_eq!(response["address"], "push.example.test:8322");
        assert_eq!(response["certificate_digest"].as_str().unwrap().len(), 64);
        let token = base64::engine::general_purpose::STANDARD
            .decode(response["capability"].as_str().unwrap())
            .unwrap();
        let signed = vot_capability::decode(&token).unwrap();
        let push = application.push.as_ref().unwrap();
        assert!(vot_capability::verify_signature(&signed, &push.issuer.verifying_key()).is_ok());
        let another = ed25519_dalek::SigningKey::from_bytes(&[6; 32]);
        assert!(vot_capability::verify_signature(&signed, &another.verifying_key()).is_err());
        let claims = vot_capability::Capability::from_canonical_bytes(&signed.capability).unwrap();
        assert_eq!(claims.issuer, "votport");
        assert_eq!(claims.audience, push.audience);
        assert_eq!(claims.holder_key, holder.verifying_key().to_bytes());
        assert_eq!(response["expires_at"], claims.expiry);
        assert_eq!(
            claims.expiry - claims.not_before,
            application.config.session_idle_secs
        );
        assert_eq!(
            claims.operations,
            [vot_capability::Operation::Publish.identifier()]
        );
        assert_eq!(claims.scope, vot_cli::authz::push_scope([7; 32], 7));
        assert!(application
            .push_tickets
            .lock()
            .unwrap()
            .contains_key(&claims.token_id));

        let session = response["session"].as_str().unwrap();
        let http = app::router(application.clone())
            .oneshot(
                Request::post(format!("/api/session/{session}/seal"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(http.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn push_specific_refusals_and_shared_admission_errors_keep_their_statuses() {
        let directory = tempfile::tempdir().unwrap();
        let application = push_app(directory.path());
        application.store.insert_link(open_link("open")).unwrap();
        let holder = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut malformed = request_body(&holder, 1);
        malformed["package"]["suite"] = json!(2);
        let mut bad_root = request_body(&holder, 1);
        bad_root["package"]["root"] = json!("00");
        let mut bad_holder = request_body(&holder, 1);
        bad_holder["holder_key"] = json!("00");
        for body in [malformed, bad_root, bad_holder] {
            assert_eq!(
                post_push(application.clone(), "open", body).await.status(),
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        assert_eq!(
            post_push(application.clone(), "missing", request_body(&holder, 1))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );

        let mut closed = open_link("closed");
        closed.active = false;
        application.store.insert_link(closed).unwrap();
        assert_eq!(
            post_push(application.clone(), "closed", request_body(&holder, 1))
                .await
                .status(),
            StatusCode::GONE
        );

        application
            .store
            .insert_tenant(Tenant {
                incarnation: String::new(),
                key: "gone".to_owned(),
                label: "gone".to_owned(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        let mut orphaned = open_link("orphaned");
        orphaned.tenant = "gone".to_owned();
        application.store.insert_link(orphaned).unwrap();
        // Public deletion preserves this invariant; simulate a damaged or
        // externally edited database to prove admission still fails closed.
        rusqlite::Connection::open(directory.path().join("data/votport.db"))
            .unwrap()
            .execute("DELETE FROM tenants WHERE key = 'gone'", [])
            .unwrap();
        assert_eq!(
            post_push(application.clone(), "orphaned", request_body(&holder, 1))
                .await
                .status(),
            StatusCode::GONE
        );

        let mut protected = open_link("protected");
        protected.password_hash = Some(auth::hash_password("right password").unwrap());
        application.store.insert_link(protected).unwrap();
        let mut wrong_password = request_body(&holder, 1);
        wrong_password["password"] = json!("wrong password");
        assert_eq!(
            post_push(application.clone(), "protected", wrong_password)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let mut capped = open_link("capped");
        capped.max_bytes = Some(0);
        application.store.insert_link(capped).unwrap();
        assert_eq!(
            post_push(application.clone(), "capped", request_body(&holder, 1))
                .await
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );

        application
            .store
            .insert_tenant(Tenant {
                incarnation: String::new(),
                key: "no-sessions".to_owned(),
                label: "no sessions".to_owned(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: Some(0),
                created_at: 0,
            })
            .unwrap();
        let mut limited = open_link("session-limited");
        limited.tenant = "no-sessions".to_owned();
        application.store.insert_link(limited).unwrap();
        assert_eq!(
            post_push(
                application.clone(),
                "session-limited",
                request_body(&holder, 1)
            )
            .await
            .status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        application
            .store
            .insert_link(open_link("link-limited"))
            .unwrap();
        let mut receivers = Vec::new();
        for index in 0..application.config.max_link_sessions {
            let (sender, receiver) = mpsc::channel(1);
            application
                .sessions
                .insert(
                    format!("occupied-{index}"),
                    "link-limited".to_owned(),
                    String::new(),
                    sender,
                )
                .unwrap();
            receivers.push(receiver);
        }
        assert_eq!(
            post_push(
                application.clone(),
                "link-limited",
                request_body(&holder, 1)
            )
            .await
            .status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        for (error, expected) in [
            (session::InsertError::TenantPinned, StatusCode::GONE),
            (session::InsertError::LinkPinned, StatusCode::GONE),
            (
                session::InsertError::ByteQuota,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                session::InsertError::TenantSessionLimit,
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                session::InsertError::Capacity,
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                session::InsertError::Store("offline".to_owned()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            assert_eq!(
                session_insert_error(&application, "", error).status,
                expected
            );
        }
    }

    #[tokio::test]
    async fn push_admission_reserves_tenant_bytes_until_idle_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let application = push_app(directory.path());
        application
            .store
            .insert_tenant(Tenant {
                incarnation: String::new(),
                key: "tenant".to_owned(),
                label: "tenant".to_owned(),
                admin_group: None,
                max_total_bytes: Some(10),
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        let mut link = open_link("quota");
        link.tenant = "tenant".to_owned();
        application.store.insert_link(link).unwrap();
        let holder = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);

        let first = post_push(application.clone(), "quota", request_body(&holder, 7)).await;
        assert_eq!(first.status(), StatusCode::OK);
        let session = response_json(first).await["session"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            post_push(application.clone(), "quota", request_body(&holder, 4))
                .await
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let abort = app::router(application.clone())
            .oneshot(
                Request::post(format!("/api/session/{session}/abort"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(abort.status(), StatusCode::OK);
        assert_eq!(application.sessions.total(), 1);
        assert!(application.push_tickets.lock().unwrap().is_empty());
        assert_eq!(
            post_push(application.clone(), "quota", request_body(&holder, 4))
                .await
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        application.sessions.sweep(0);
        assert_eq!(application.sessions.total(), 0);
        assert_eq!(
            application
                .store
                .link_by_id("quota")
                .unwrap()
                .unwrap()
                .events[0]
                .outcome,
            "cancelled"
        );
        let ended = application
            .session_ended_rx
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .try_recv()
            .unwrap();
        assert_eq!(
            (ended.link_id.as_str(), ended.event.outcome.as_str()),
            ("quota", "cancelled")
        );
        assert_eq!(ended.event.expected_bytes, 7);
        assert_eq!(
            post_push(application, "quota", request_body(&holder, 4))
                .await
                .status(),
            StatusCode::OK
        );
    }
}
