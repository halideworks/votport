use super::*;
use crate::route_protocol::SignedPortMessage;
use crate::store::{TradeEndpoint, TradeRoute, TRADE_EVENTS};
use axum::extract::{ConnectInfo, Path, Query, State};
use serde::Deserialize;
use std::sync::Arc;

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, message)
}
fn unprocessable(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, message)
}
fn unauthorized(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, message)
}
/// Notification delivery waits on remote webhooks; a peer's request or an
/// admin's save must not.
fn notify_later(app: &Arc<App>, route: &TradeRoute, event: &'static str) {
    let (app, route) = (Arc::clone(app), route.clone());
    tokio::spawn(async move {
        crate::notify::trade_event(&app, &route, &route.notifications, event).await;
    });
}
fn write(app: &App, headers: &HeaderMap) -> ApiResult<crate::auth::AdminIdentity> {
    let identity = admin::require_operator(app, headers)?;
    admin::require_admin_write(headers, &identity)?;
    Ok(identity)
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn private(value: impl serde::Serialize) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

pub fn address(value: &str) -> Result<String, String> {
    if value.len() > 2048 || value.chars().any(char::is_control) {
        return Err("invalid port address".into());
    }
    let url = reqwest::Url::parse(value).map_err(|_| "enter the port's HTTP or HTTPS address")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err("use a port origin such as https://port.example".into());
    }
    Ok(url.origin().ascii_serialization())
}
fn identity(app: &App) -> ApiResult<serde_json::Value> {
    Ok(
        json!({"name":app.store.setting("port_name").map_err(store_unavailable)?.unwrap_or_else(||"VOTPort".into()),"address":app.store.setting("port_address").map_err(store_unavailable)?.or_else(||app.config.public_url.clone()).unwrap_or_default(),"key":app.signer.public_hex,"protocols":[1]}),
    )
}
#[derive(Deserialize)]
pub struct DiscoveryQuery {
    challenge: String,
}
pub async fn discover(
    State(app): State<Arc<App>>,
    Query(query): Query<DiscoveryQuery>,
) -> ApiResult<Response> {
    if !crate::workflow::valid_id(&query.challenge) {
        return Err(invalid("invalid discovery challenge"));
    }
    Ok(private(app.signer.port_message(
        "discovery",
        "",
        query.challenge,
        now() + 300,
        identity(&app)?,
    )))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortSettings {
    name: String,
    address: String,
}
pub async fn settings(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<PortSettings>,
) -> ApiResult<Response> {
    let actor = write(&app, &headers)?;
    if !actor.tenant.is_empty() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "platform administrator required",
        ));
    }
    if body.name.trim().is_empty()
        || body.name.len() > 200
        || body.name.chars().any(char::is_control)
    {
        return Err(unprocessable("enter a port name of at most 200 characters"));
    }
    let origin = address(&body.address).map_err(unprocessable)?;
    app.store
        .put_settings(
            &actor.subject,
            &[
                (
                    "port_name".into(),
                    crate::store::SettingWrite::Set(body.name),
                ),
                (
                    "port_address".into(),
                    crate::store::SettingWrite::Set(origin),
                ),
            ],
        )
        .map_err(store_unavailable)?;
    Ok(private(identity(&app)?))
}
pub async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Response> {
    let actor = admin::require_operator(&app, &headers)?;
    let routes = app
        .store
        .trade_routes(Some(&actor.tenant))
        .map_err(store_unavailable)?;
    let mut deliveries = serde_json::Map::new();
    for route in &routes {
        deliveries.insert(
            route.id.clone(),
            app.store
                .trade_deliveries(route)
                .map_err(store_unavailable)?,
        );
    }
    Ok(private(
        json!({"port":identity(&app)?,"routes":routes,"endpoints":app.store.trade_endpoints(&actor.tenant).map_err(store_unavailable)?,"deliveries":deliveries}),
    ))
}
pub async fn endpoint(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<TradeEndpoint>,
) -> ApiResult<Response> {
    let actor = write(&app, &headers)?;
    super::notifications::validate_policy(&app, &actor.tenant, &body.notifications, &TRADE_EVENTS)?;
    let _pin = app
        .sessions
        .try_pin_link(&body.id)
        .ok_or_else(|| invalid("request is being changed; retry"))?;
    if app.sessions.active_for_link(&body.id) > 0 {
        return Err(invalid(
            "wait for active uploads before converting this request",
        ));
    }
    app.store
        .create_trade_endpoint(&actor.tenant, &body)
        .map_err(invalid)?;
    app.store.audit(
        &actor.tenant,
        &actor.subject,
        "trade_endpoint_created",
        &body.id,
        &json!({"name":body.name}),
    );
    Ok(private(body))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRequest {
    endpoint: String,
    #[serde(default)]
    expected_key: String,
    expires_in: u64,
}
pub async fn invite(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<InviteRequest>,
) -> ApiResult<Response> {
    let actor = write(&app, &headers)?;
    let port = identity(&app)?;
    let origin = address(port["address"].as_str().unwrap_or_default())
        .map_err(|_| invalid("set this port's advertised address first"))?;
    let mut endpoint = app
        .store
        .trade_endpoints(&actor.tenant)
        .map_err(store_unavailable)?
        .into_iter()
        .find(|e| e.id == body.endpoint)
        .ok_or_else(ApiError::not_found)?;
    if !matches!(body.expires_in, 3600 | 86400 | 604800) {
        return Err(unprocessable(
            "choose an invitation expiry of one hour, one day or seven days",
        ));
    }
    let expires = now() + body.expires_in;
    let (id, secret) = app
        .store
        .create_trade_invitation(&actor.tenant, &body.endpoint, &body.expected_key, expires)
        .map_err(invalid)?;
    app.store.audit(
        &actor.tenant,
        &actor.subject,
        "trade_invitation_created",
        &body.endpoint,
        &json!({"invitation":id,"expires_at":expires,"expected_key":body.expected_key}),
    );
    endpoint.notifications = crate::store::NotificationPolicy::default();
    let invitation=app.signer.port_message("invitation","",id,expires,json!({"address":origin,"name":port["name"],"endpoint":endpoint,"secret":secret,"expected_key":body.expected_key}));
    Ok(private(json!({"invitation":invitation})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectRequest {
    address: Option<String>,
    invitation: Option<SignedPortMessage>,
}
async fn remote_json(
    app: &App,
    origin: &str,
    path: &str,
    body: Option<&impl serde::Serialize>,
) -> ApiResult<SignedPortMessage> {
    let request = if let Some(body) = body {
        app.http
            .post(format!("{origin}{path}"))
            .header("X-Votport", "1")
            .json(body)
    } else {
        app.http.get(format!("{origin}{path}"))
    };
    let mut response = request
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|_| invalid("port could not be reached"))?;
    if !response.status().is_success() {
        return Err(invalid(format!(
            "port refused the request (HTTP {})",
            response.status().as_u16()
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| invalid("port response interrupted"))?
    {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err(invalid("port response too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid("port returned an invalid signed response"))
}
pub async fn probe(
    app: &App,
    origin: &str,
    expected: Option<&str>,
) -> ApiResult<SignedPortMessage> {
    let challenge = crate::auth::random_token();
    let response = remote_json(
        app,
        origin,
        &format!("/api/port?challenge={challenge}"),
        None::<&serde_json::Value>,
    )
    .await?;
    if !response.verify("discovery", "", now())
        || response.document.nonce != challenge
        || expected.is_some_and(|key| key != response.document.issuer)
        || !response.document.body["protocols"]
            .as_array()
            .is_some_and(|v| v.contains(&json!(1)))
    {
        return Err(invalid("Port identity mismatch or unsupported protocol. Confirm the fingerprint; a replaced key requires a new invitation."));
    }
    Ok(response)
}
fn invitation(value: &SignedPortMessage) -> ApiResult<(String, TradeEndpoint)> {
    if !value.verify("invitation", "", now()) || value.document.expires_at > now() + 7 * 86400 {
        return Err(invalid("invitation expired or signature is invalid"));
    }
    let origin =
        address(value.document.body["address"].as_str().unwrap_or_default()).map_err(invalid)?;
    let endpoint: TradeEndpoint = serde_json::from_value(value.document.body["endpoint"].clone())
        .map_err(|_| invalid("invalid invitation endpoint"))?;
    endpoint.validate().map_err(invalid)?;
    Ok((origin, endpoint))
}
pub async fn inspect(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<InspectRequest>,
) -> ApiResult<Response> {
    write(&app, &headers)?;
    let (origin, key) = if let Some(invite) = &body.invitation {
        let (origin, _) = invitation(invite)?;
        (origin, Some(invite.document.issuer.as_str()))
    } else {
        (
            address(body.address.as_deref().unwrap_or_default()).map_err(unprocessable)?,
            None,
        )
    };
    // The address is admin-chosen and unverified; the reply says whether a
    // Votport port answered, not how the host failed.
    let port = probe(&app, &origin, key).await.map_err(|error| {
        if error.message.contains("identity mismatch") {
            error
        } else {
            invalid("no Votport port answered at that address")
        }
    })?;
    Ok(private(port))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptRequest {
    invitation: SignedPortMessage,
    name: String,
    notifications: crate::store::NotificationPolicy,
}
pub async fn accept(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<AcceptRequest>,
) -> ApiResult<Response> {
    let actor = write(&app, &headers)?;
    let (origin, endpoint) = invitation(&body.invitation)?;
    if body.name.trim().is_empty() || body.name.len() > 200 {
        return Err(unprocessable("enter a route name"));
    }
    super::notifications::validate_policy(&app, &actor.tenant, &body.notifications, &TRADE_EVENTS)?;
    let peer = probe(&app, &origin, Some(&body.invitation.document.issuer)).await?;
    if peer.document.issuer == app.signer.public_hex {
        return Err(invalid("cannot pair a port with itself"));
    }
    let expected = body.invitation.document.body["expected_key"]
        .as_str()
        .unwrap_or_default();
    if !expected.is_empty() && expected != app.signer.public_hex {
        return Err(invalid("invitation was issued to a different sending port"));
    }
    let route = TradeRoute {
        id: crate::auth::random_token(),
        revision: 1,
        tenant: actor.tenant,
        direction: "outgoing".into(),
        name: body.name,
        peer_name: peer.document.body["name"]
            .as_str()
            .unwrap_or("VOTPort")
            .into(),
        peer_key: peer.document.issuer,
        address: origin,
        endpoint: endpoint.id,
        endpoint_name: endpoint.name,
        category: endpoint.category,
        forwarding: endpoint.forwarding,
        metadata_keys: endpoint.metadata_keys,
        state: "pending_approval".into(),
        notifications: body.notifications,
        last_contact: None,
        error: None,
        remote_grant: String::new(),
        remote_state: "enrolling".into(),
        cancel_active: false,
    };
    app.store
        .save_outgoing_trade(&route, &crate::auth::random_token(), &body.invitation)
        .map_err(invalid)?;
    app.store.audit(
        &route.tenant,
        &actor.subject,
        "trade_route_accepted",
        &route.id,
        &json!({"name":route.name,"peer":route.peer_key,"address":route.address,"endpoint":route.endpoint}),
    );
    let outcome = enroll_outgoing(&app, &route).await;
    if let Err(error) = outcome {
        app.store
            .trade_contact(
                &route.tenant,
                &route.id,
                "unreachable",
                Some(&error.message),
            )
            .map_err(store_unavailable)?;
    }
    Ok(private(
        app.store
            .trade_route(&route.tenant, &route.id)
            .map_err(store_unavailable)?,
    ))
}
pub(crate) async fn enroll_outgoing(app: &App, route: &TradeRoute) -> ApiResult<()> {
    let invitation = app
        .store
        .trade_enrollment(&route.tenant, &route.id)
        .map_err(store_unavailable)?
        .ok_or_else(|| invalid("enrollment is already complete"))?;
    probe(app, &route.address, Some(&route.peer_key)).await?;
    let credential = app
        .store
        .trade_credential(&route.tenant, &route.id)
        .map_err(store_unavailable)?;
    let request=app.signer.port_message("enroll",&route.peer_key,invitation.document.nonce.clone(),now()+300,json!({"secret":invitation.document.body["secret"],"credential":credential,"name":identity(app)?["name"],"address":identity(app)?["address"]}));
    let response = remote_json(app, &route.address, "/api/port/enroll", Some(&request)).await?;
    verify_response(app, route, &request, &response, "enrolled")?;
    let grant = response.document.body["grant"]
        .as_str()
        .filter(|s| crate::workflow::valid_id(s))
        .ok_or_else(|| invalid("invalid granted endpoint"))?;
    let state = response.document.body["state"]
        .as_str()
        .filter(|s| matches!(*s, "active" | "pending_approval" | "paused" | "revoked"))
        .ok_or_else(|| invalid("invalid permission status"))?;
    if response.document.body["endpoint"] != route.endpoint {
        return Err(invalid("receiver granted a different endpoint"));
    }
    app.store
        .finish_trade_enrollment(&route.tenant, &route.id, grant, state)
        .map_err(store_unavailable)
}
fn verify_response(
    app: &App,
    route: &TradeRoute,
    request: &SignedPortMessage,
    response: &SignedPortMessage,
    purpose: &str,
) -> ApiResult<()> {
    if response.document.issuer != route.peer_key
        || !response.verify(purpose, &app.signer.public_hex, now())
        || response.document.nonce != request.document.nonce
    {
        return Err(invalid("Port identity mismatch in signed reply"));
    }
    Ok(())
}
fn public_guard(app: &App, headers: &HeaderMap, peer: std::net::SocketAddr) -> ApiResult<()> {
    if !headers.contains_key("x-votport") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "missing X-Votport header",
        ));
    }
    super::outbound::workflows::recipient_rate(app, headers, &peer)
}
pub async fn enroll(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SignedPortMessage>,
) -> ApiResult<Response> {
    public_guard(&app, &headers, peer)?;
    let (route, created) = app
        .store
        .redeem_trade_invitation(&request)
        .map_err(unauthorized)?;
    let event = if route.state == "active" {
        "route_approved"
    } else {
        "route_approval_requested"
    };
    if created {
        notify_later(&app, &route, event);
    }
    Ok(private(app.signer.port_message(
        "enrolled",
        &route.peer_key,
        request.document.nonce,
        now() + 300,
        json!({"grant":route.id,"endpoint":route.endpoint,"state":route.state}),
    )))
}
pub async fn status(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SignedPortMessage>,
) -> ApiResult<Response> {
    public_guard(&app, &headers, peer)?;
    let route = app
        .store
        .authenticate_trade(&request, "status")
        .map_err(unauthorized)?;
    let link = app
        .store
        .upload_link(&route.endpoint)
        .map_err(store_unavailable)?;
    let state = if route.state == "revoked" || link.as_ref().is_none_or(|l| !l.usable_now()) {
        "revoked"
    } else {
        route.state.as_str()
    };
    // A revoked peer learns only that it is revoked: no contact refresh and
    // no delivery listing.
    let deliveries = if state == "revoked" {
        json!([])
    } else {
        app.store
            .trade_contact(&route.tenant, &route.id, "active", None)
            .map_err(store_unavailable)?;
        app.store
            .trade_deliveries(&route)
            .map_err(store_unavailable)?
    };
    Ok(private(app.signer.port_message(
        "status",
        &route.peer_key,
        request.document.nonce,
        now() + 300,
        json!({"grant":route.id,"state":state,"endpoint":route.endpoint,"deliveries":deliveries}),
    )))
}
async fn refresh_route_inner(app: &Arc<App>, route: &TradeRoute) -> ApiResult<()> {
    if route.remote_grant.is_empty() {
        return enroll_outgoing(app, route).await;
    }
    probe(app, &route.address, Some(&route.peer_key)).await?;
    let request=app.signer.port_message("status",&route.peer_key,crate::auth::random_token(),now()+300,json!({"grant":route.remote_grant,"credential":app.store.trade_credential(&route.tenant,&route.id).map_err(store_unavailable)?}));
    let response = remote_json(app, &route.address, "/api/port/status", Some(&request)).await?;
    verify_response(app, route, &request, &response, "status")?;
    let state = response.document.body["state"]
        .as_str()
        .filter(|v| matches!(*v, "active" | "paused" | "pending_approval" | "revoked"))
        .ok_or_else(|| invalid("invalid permission state"))?;
    if response.document.body["grant"] != route.remote_grant
        || response.document.body["endpoint"] != route.endpoint
    {
        return Err(invalid("peer status names a different permission"));
    }
    let changed = app
        .store
        .trade_contact(&route.tenant, &route.id, state, None)
        .map_err(store_unavailable)?;
    app.store
        .record_trade_status(route, &response.document.body["deliveries"])
        .map_err(store_unavailable)?;
    if changed && state == "active" {
        notify_later(
            app,
            route,
            if route.remote_state == "pending_approval" {
                "route_approved"
            } else {
                "route_recovered"
            },
        );
    }
    Ok(())
}
pub async fn test(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let actor = write(&app, &headers)?;
    let route = app
        .store
        .trade_route(&actor.tenant, &id)
        .map_err(|_| ApiError::not_found())?;
    if route.direction != "outgoing" {
        return Err(invalid("test connections from the sending port"));
    }
    refresh_route(&app, &route).await?;
    Ok(private(
        app.store
            .trade_route(&actor.tenant, &id)
            .map_err(store_unavailable)?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRequest {
    revision: u64,
    state: String,
    cancel_active: bool,
    notifications: crate::store::NotificationPolicy,
}
pub async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateRequest>,
) -> ApiResult<Response> {
    let actor = write(&app, &headers)?;
    super::notifications::validate_policy(&app, &actor.tenant, &body.notifications, &TRADE_EVENTS)?;
    let previous = app
        .store
        .trade_route(&actor.tenant, &id)
        .map_err(|_| ApiError::not_found())?;
    let route = app
        .store
        .update_trade_route(
            &actor.tenant,
            &id,
            body.revision,
            &body.state,
            body.cancel_active,
            &body.notifications,
        )
        .map_err(invalid)?;
    if route.direction == "incoming" && body.state != "active" && body.cancel_active {
        for session in app.store.trade_sessions(&id).map_err(store_unavailable)? {
            let _ = crate::api::upload::upload_abort(State(Arc::clone(&app)), Path(session)).await;
        }
    }
    if previous.state == "pending_approval" && route.state == "active" {
        notify_later(&app, &route, "route_approved");
    }
    Ok(private(route))
}
pub async fn rotate_remote(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SignedPortMessage>,
) -> ApiResult<Response> {
    public_guard(&app, &headers, peer)?;
    let route = app
        .store
        .authenticate_trade(&request, "rotate")
        .map_err(unauthorized)?;
    if route.state == "revoked" {
        return Err(invalid("route revoked"));
    }
    let old = request.document.body["credential"]
        .as_str()
        .unwrap_or_default();
    let next = request.document.body["next"].as_str().unwrap_or_default();
    app.store
        .rotate_trade_credential(&route.id, old, next, true)
        .map_err(invalid)?;
    Ok(private(app.signer.port_message(
        "rotated",
        &route.peer_key,
        request.document.nonce,
        now() + 300,
        json!({"grant":route.id}),
    )))
}
pub async fn rotate(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let actor = write(&app, &headers)?;
    let route = app
        .store
        .trade_route(&actor.tenant, &id)
        .map_err(|_| ApiError::not_found())?;
    if route.direction != "outgoing" || route.remote_grant.is_empty() || route.state == "revoked" {
        return Err(invalid(
            "only an enrolled outgoing route can rotate its credential",
        ));
    }
    probe(&app, &route.address, Some(&route.peer_key)).await?;
    let old = app
        .store
        .trade_credential(&actor.tenant, &id)
        .map_err(store_unavailable)?;
    let next = app
        .store
        .pending_trade_rotation(&actor.tenant, &id)
        .map_err(store_unavailable)?;
    let request = app.signer.port_message(
        "rotate",
        &route.peer_key,
        crate::auth::random_token(),
        now() + 300,
        json!({"grant":route.remote_grant,"credential":old,"next":next}),
    );
    let response = remote_json(&app, &route.address, "/api/port/rotate", Some(&request)).await?;
    verify_response(&app, &route, &request, &response, "rotated")?;
    app.store
        .rotate_trade_credential(&id, &old, &next, false)
        .map_err(invalid)?;
    app.store
        .clear_trade_rotation(&id, &next)
        .map_err(store_unavailable)?;
    app.store.audit(
        &actor.tenant,
        &actor.subject,
        "trade_credential_rotated",
        &id,
        &json!({"peer":route.peer_key}),
    );
    Ok(private(json!({"ok":true})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressRequest {
    address: String,
    revision: u64,
}
pub async fn change_address(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AddressRequest>,
) -> ApiResult<Response> {
    let actor = write(&app, &headers)?;
    let route = app
        .store
        .trade_route(&actor.tenant, &id)
        .map_err(|_| ApiError::not_found())?;
    let origin = address(&body.address).map_err(unprocessable)?;
    probe(&app, &origin, Some(&route.peer_key)).await?;
    app.store
        .change_trade_address(&actor.tenant, &id, body.revision, &origin)
        .map_err(invalid)?;
    Ok(private(json!({"ok":true})))
}

pub async fn worker(app: Arc<App>) {
    use futures_util::{stream, StreamExt};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    // A dead peer costs two 15 s timeouts per probe; back off per route so a
    // pass stays near a minute and known-dead peers are not hammered.
    let backoff: std::sync::Mutex<HashMap<String, (u32, Instant)>> = Default::default();
    loop {
        tokio::select! {_=app.shutdown.notified()=>return,_=tokio::time::sleep(std::time::Duration::from_secs(60))=>{}}
        if app.lease_lost.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if app
            .store
            .resolved_settings(&app.config)
            .map_or(true, |s| s.draining)
        {
            continue;
        }
        if let Err(error) = app.store.prune_trade_invitations() {
            tracing::warn!(%error, "cannot prune expired trade invitations");
        }
        match app.store.trade_routes(None) {
            Ok(routes) => {
                let now = Instant::now();
                let due: Vec<TradeRoute> = {
                    let mut waiting = backoff.lock().expect("backoff poisoned");
                    waiting.retain(|id, _| routes.iter().any(|r| &r.id == id));
                    routes
                        .into_iter()
                        .filter(|r| {
                            r.direction == "outgoing"
                                && r.state != "revoked"
                                && !r.remote_grant.is_empty()
                                && waiting.get(&r.id).is_none_or(|(_, next)| *next <= now)
                        })
                        .collect()
                };
                stream::iter(due)
                    .for_each_concurrent(4, |route| {
                        let app = Arc::clone(&app);
                        let backoff = &backoff;
                        async move {
                            let outcome = refresh_route(&app, &route).await;
                            let mut waiting = backoff.lock().expect("backoff poisoned");
                            match outcome {
                                Ok(()) => {
                                    waiting.remove(&route.id);
                                }
                                Err(_) => {
                                    let failures = waiting.get(&route.id).map_or(1, |(n, _)| n + 1);
                                    let wait = Duration::from_secs(60 << failures.min(6));
                                    waiting.insert(
                                        route.id.clone(),
                                        (failures, Instant::now() + wait),
                                    );
                                }
                            }
                        }
                    })
                    .await
            }
            Err(error) => tracing::warn!(%error,"cannot monitor trade routes"),
        }
    }
}

pub async fn refresh_route(app: &Arc<App>, route: &TradeRoute) -> ApiResult<()> {
    let result = refresh_route_inner(app, route).await;
    if let Err(error) = &result {
        let mismatch = error
            .message
            .to_ascii_lowercase()
            .contains("identity mismatch");
        let state = if mismatch {
            "identity_mismatch"
        } else {
            "unreachable"
        };
        if app
            .store
            .trade_contact(&route.tenant, &route.id, state, Some(&error.message))
            .map_err(store_unavailable)?
        {
            notify_later(
                app,
                route,
                if mismatch {
                    "route_identity_changed"
                } else {
                    "route_failed"
                },
            );
        }
    }
    result
}
