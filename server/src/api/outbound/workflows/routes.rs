use super::*;
use crate::route_protocol::SignedRoute;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRequest {
    source: SignedRoute,
    password: Option<String>,
    #[serde(default)]
    ancestry: Vec<crate::route_protocol::RouteReceipt>,
}

pub async fn receive(
    State(app): State<Arc<App>>,
    AxumPath(token): AxumPath<String>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<RouteRequest>,
) -> ApiResult<Response> {
    if !headers.contains_key("x-votport") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "missing X-Votport header",
        ));
    }
    recipient_rate(&app, &headers, &peer)?;
    let link = app
        .store
        .upload_link(&token)
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let ip = crate::api::client_ip(&headers, &peer, &app.config.trusted_proxies);
    crate::api::upload::check_password(
        &app,
        link.password_hash.as_deref(),
        request.password.as_deref(),
        &ip,
        "wrong link password",
    )
    .await?;
    let route = app
        .store
        .receive_route(&link.tenant, &link.id, &request.source, &request.ancestry)
        .map_err(conflict)?;
    let session = route
        .session_id
        .as_ref()
        .filter(|id| app.sessions.link_id(id).is_some());
    Ok(([(header::CACHE_CONTROL,"no-store")], Json(json!({"route":route.id,"receipt_key":app.signer.public_hex,"receipt":route.receipt,"revoked_at":route.revoked_at,"session":session,"transport":route.transport}))).into_response())
}

pub(crate) fn admission(
    app: &App,
    token: Option<&str>,
    link_id: &str,
) -> ApiResult<Option<crate::store::InboundRoute>> {
    let Some(token) = token else {
        return Ok(None);
    };
    if !valid_token(token) {
        return Err(ApiError::not_found());
    }
    let route = app
        .store
        .inbound_route(token)
        .map_err(crate::api::store_unavailable)?
        .filter(|route| route.link_id == link_id)
        .ok_or_else(ApiError::not_found)?;
    if route.receipt.is_some() || route.revoked_at.is_some() {
        return Err(conflict(
            "route is already complete or revoked; refresh its status".into(),
        ));
    }
    Ok(Some(route))
}

#[derive(Deserialize)]
struct RemoteRoute {
    route: String,
    receipt_key: String,
    receipt: Option<crate::route_protocol::RouteReceipt>,
    revoked_at: Option<u64>,
    session: Option<String>,
    transport: Option<String>,
}

async fn command(
    app: &App,
    origin: &str,
    token: &str,
    password: Option<&str>,
    source: &SignedRoute,
    ancestry: &[crate::route_protocol::RouteReceipt],
) -> ApiResult<RemoteRoute> {
    let response = app
        .http
        .post(format!("{origin}/api/r/{token}/route"))
        .header("X-Votport", "1")
        .json(&json!({"password":password,"source":source,"ancestry":ancestry}))
        .send()
        .await
        .map_err(|_| conflict("could not reach the destination port".into()))?;
    if !response.status().is_success() {
        return Err(conflict(format!("destination refused route admission (HTTP {}); check its receive request and software version",response.status().as_u16())));
    }
    read_response(response).await
}

async fn read_response<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> ApiResult<T> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| conflict("destination response was interrupted".into()))?
    {
        if bytes.len().saturating_add(chunk.len()) > 2 * 1024 * 1024 {
            return Err(conflict(
                "destination route response exceeds its limit".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| conflict("destination returned an invalid route response".into()))
}

struct Progress {
    app: Arc<App>,
    job: Job,
    destination: String,
    reported: std::time::Instant,
    moved: u64,
    checked: std::cell::Cell<std::time::Instant>,
    cancelled: std::cell::Cell<bool>,
}

impl votport_client_core::progress::Observer for Progress {
    fn event(&mut self, event: votport_client_core::progress::Event) {
        match event {
            votport_client_core::progress::Event::Bytes { moved, .. } => self.moved = moved,
            votport_client_core::progress::Event::Transferred { bytes } => {
                self.moved = self.moved.saturating_add(bytes)
            }
            _ => return,
        }
        if self.reported.elapsed() >= std::time::Duration::from_secs(5) {
            self.reported = std::time::Instant::now();
            let _ = self
                .app
                .store
                .route_progress(&self.job, &self.destination, self.moved);
        }
    }
    fn cancelled(&self) -> bool {
        if self.checked.get().elapsed() >= std::time::Duration::from_millis(250) {
            self.checked.set(std::time::Instant::now());
            self.cancelled.set(
                self.app
                    .lease_lost
                    .load(std::sync::atomic::Ordering::Relaxed)
                    || self
                        .app
                        .store
                        .require_delivery_export(&self.job.id, self.job.attempts)
                        .is_err(),
            );
        }
        self.cancelled.get()
    }
}

pub(super) async fn export(app: &Arc<App>, job: &Job, config: &storage::Storage) -> ApiResult<()> {
    let Some(storage::Credentials::Votport {
        request_url,
        password,
    }) = app
        .store
        .delivery_storage_credentials(&config.id, config.revision)
        .map_err(conflict)?
    else {
        return Err(conflict(
            "destination receive credentials are missing".into(),
        ));
    };
    let (origin, token) = storage::receive_url(&request_url).map_err(conflict)?;
    let parent: Option<crate::route_protocol::RouteReceipt> = job
        .checks
        .get("source_receipt")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .map_err(|_| conflict("incoming custody receipt is invalid".into()))?;
    if parent
        .as_ref()
        .is_some_and(|receipt| !receipt.verify(&app.signer.public_hex))
    {
        return Err(conflict("incoming custody signature is invalid".into()));
    }
    let mut ancestry: Vec<crate::route_protocol::RouteReceipt> = job
        .checks
        .get("source_ancestry")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .map_err(|_| conflict("incoming custody chain is invalid".into()))?
        .unwrap_or_default();
    if let Some(receipt) = &parent {
        ancestry.push(receipt.clone());
    }
    let mut visited = parent
        .as_ref()
        .map(|receipt| receipt.document.source.document.visited.clone())
        .unwrap_or_default();
    visited.push(app.signer.public_hex.clone());
    let source = app.signer.sign_route(crate::route_protocol::RouteDocument {
        issuer: app.signer.public_hex.clone(),
        operation_id: job.id.clone(),
        manifest: job
            .manifest
            .clone()
            .ok_or_else(|| conflict("frozen manifest missing".into()))?,
        label: job.request.label.clone(),
        metadata: job.request.metadata.clone(),
        parent_receipt: parent.as_ref().map(|receipt| receipt.digest()),
        visited,
    });
    if !crate::route_protocol::verify_ancestry(&source, &ancestry) {
        return Err(conflict("route exceeds its forwarding limit".into()));
    }
    let mut remote = command(
        app,
        &origin,
        &token,
        password.as_deref(),
        &source,
        &ancestry,
    )
    .await?;
    if !valid_token(&remote.route)
        || !source.admits(&remote.receipt_key)
        || remote.revoked_at.is_some()
    {
        return Err(conflict(
            "destination identity creates a forwarding loop or route is revoked".into(),
        ));
    }
    app.store
        .bind_outbound_route(
            job,
            &config.id,
            &origin,
            &remote.route,
            &remote.receipt_key,
            &source,
        )
        .map_err(conflict)?;
    let peer_key = remote.receipt_key.clone();
    if remote.receipt.is_none() {
        let application = Arc::clone(app);
        let owned_job = job.clone();
        let base = origin.clone();
        let receive_token = token.clone();
        let secret = password.clone();
        let route_id = remote.route.clone();
        let previous_session = remote.session.clone();
        let previous_transport = remote.transport.clone();
        let destination = config.id.clone();
        let outcome = tokio::task::spawn_blocking(move || -> Result<(),votport_client_core::Error> {
            let grant = application.store.outbound_grant_by_id(&owned_job.id).map_err(votport_client_core::Error::Other)?.ok_or_else(||votport_client_core::Error::Other("delivery missing".into()))?;
            let prepared = crate::api::serve::prepare_route_package(&application,&grant).map_err(|_|votport_client_core::Error::Other("prepare peer delivery failed".into()))?;
            let client = votport_client_core::api::Client::for_route(base,route_id)?;
            let mut progress = Progress {app:Arc::clone(&application),job:owned_job,destination,moved:0,reported:std::time::Instant::now()-std::time::Duration::from_secs(5),checked:std::cell::Cell::new(std::time::Instant::now()-std::time::Duration::from_secs(1)),cancelled:std::cell::Cell::new(false)};
            use votport_client_core::progress::Observer;
            if progress.cancelled() { return Err(votport_client_core::Error::Cancelled); }
            if previous_transport.as_deref() == Some("push") {
                if let Some(session) = &previous_session { client.abort(session); }
            }
            if previous_session.is_none() || previous_transport.as_deref() == Some("push") {
                let device = application.signer.route_device();
                if matches!(votport_client_core::send_push::try_push(&client,&receive_token,secret.as_deref(),&device,&prepared,&mut progress)?,votport_client_core::send_push::Outcome::Pushed) { return Ok(()); }
            }
            let result = votport_client_core::send_http::send(&client,&receive_token,secret.as_deref(),&prepared,&mut progress);
            if matches!(&result,Err(votport_client_core::Error::Server {status:409|422,what,..}) if what == "begin") {
                if let Some(session) = &previous_session {
                    client.abort(session);
                    return votport_client_core::send_http::send(&client,&receive_token,secret.as_deref(),&prepared,&mut progress).map(|_|());
                }
            }
            result.map(|_|())
        }).await.map_err(|_|ApiError::internal("peer sender stopped unexpectedly"))?;
        // A lost finish response does not turn a verified remote receipt into a second upload.
        remote = command(
            app,
            &origin,
            &token,
            password.as_deref(),
            &source,
            &ancestry,
        )
        .await?;
        if remote.receipt.is_none() {
            return Err(conflict(match outcome {
                Err(votport_client_core::Error::Server {status,..}) => format!("destination refused the transfer (HTTP {status}); check its limits and permissions"),
                Err(votport_client_core::Error::Cancelled) => "peer delivery was cancelled".into(),
                _ => "peer transfer was interrupted; its verified checkpoint will be retried".into(),
            }));
        }
    }
    let receipt = remote
        .receipt
        .ok_or_else(|| conflict("destination has not issued a custody receipt".into()))?;
    if remote.revoked_at.is_some()
        || remote.receipt_key != peer_key
        || !receipt.verify(&peer_key)
        || receipt.document.source != source
    {
        return Err(conflict(
            "destination custody receipt does not match this delivery".into(),
        ));
    }
    app.store
        .record_route_receipt(job, &config.id, &receipt)
        .map_err(conflict)?;
    app.store
        .complete_delivery_export(
            &job.id,
            job.attempts,
            &config.id,
            &format!("receipt:{}", receipt.digest()),
        )
        .map_err(conflict)
}

pub async fn revoke(
    State(app): State<Arc<App>>,
    AxumPath(id): AxumPath<String>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<crate::route_protocol::RouteRevocation>,
) -> ApiResult<Response> {
    if !headers.contains_key("x-votport") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "missing X-Votport header",
        ));
    }
    recipient_rate(&app, &headers, &peer)?;
    if !valid_token(&id) {
        return Err(ApiError::not_found());
    }
    let route = app
        .store
        .revoke_inbound_route(&id, &request)
        .map_err(conflict)?;
    if let Some(session) = route.as_ref().and_then(|route| route.session_id.as_ref()) {
        let _ =
            crate::api::upload::upload_abort(State(Arc::clone(&app)), AxumPath(session.clone()))
                .await;
    }
    let ack = app.signer.route_revoked(
        request,
        route
            .and_then(|route| route.revoked_at)
            .unwrap_or_else(now_unix),
    );
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(ack)).into_response())
}

async fn revoke_remote(
    app: &App,
    control: &crate::store::OutboundControl,
) -> ApiResult<crate::route_protocol::RouteRevoked> {
    let response = app
        .http
        .post(format!(
            "{}/api/route/{}/revoke",
            control.origin, control.route_id
        ))
        .header("X-Votport", "1")
        .json(&control.request)
        .send()
        .await
        .map_err(|_| conflict("destination has not acknowledged revocation".into()))?;
    if !response.status().is_success() {
        return Err(conflict(
            "destination has not acknowledged revocation".into(),
        ));
    }
    let ack: crate::route_protocol::RouteRevoked = read_response(response).await?;
    if !ack.verify(&control.request) {
        return Err(conflict(
            "invalid destination revocation acknowledgement".into(),
        ));
    }
    Ok(ack)
}

pub async fn control_worker(app: Arc<App>) {
    loop {
        if app.lease_lost.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if let Ok(_operation) = begin_outbound_operation(&app, "") {
            match app.store.claim_route_revocation(now_unix()) {
                Ok(Some(control)) => {
                    let ack = revoke_remote(&app, &control).await.ok();
                    if let Err(error) =
                        app.store
                            .finish_route_revocation(&control, ack.as_ref(), now_unix())
                    {
                        tracing::error!(%error,"record route revocation status");
                    }
                    continue;
                }
                Err(error) => tracing::error!(%error,"claim route revocation"),
                Ok(None) => {}
            }
        }
        tokio::select! { _ = app.shutdown.notified() => return, _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {} }
    }
}

pub async fn evidence(
    State(app): State<Arc<App>>,
    AxumPath((link, upload)): AxumPath<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    let route = app
        .store
        .received_route(&identity.tenant, &upload)
        .map_err(crate::api::store_unavailable)?
        .filter(|route| route.link_id == link)
        .ok_or_else(ApiError::not_found)?;
    Ok(([(header::CACHE_CONTROL,"no-store")],Json(json!({"receipt":route.receipt,"ancestors":route.ancestry,"revoked_at":route.revoked_at}))).into_response())
}
