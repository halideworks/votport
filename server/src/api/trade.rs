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
fn notify_later(app: &Arc<App>, route: &TradeRoute, event: &'static str, detail: Option<String>) {
    let (app, route) = (Arc::clone(app), route.clone());
    tokio::spawn(async move {
        crate::notify::trade_event(&app, &route, &route.notifications, event, detail.as_deref())
            .await;
    });
}
fn write(app: &App, headers: &HeaderMap) -> ApiResult<admin::AdminSession> {
    let identity = admin::require_operator_write(app, headers)?;
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
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<DiscoveryQuery>,
) -> ApiResult<Response> {
    super::outbound::workflows::recipient_rate(&app, &headers, &peer)?;
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
    // The same settings_updated emission admin settings changes use, so
    // audit subscribers see a port rename or address move.
    tracing::info!(
        target: "audit",
        event = "settings_updated",
        keys = 2,
        reset = 0,
        "port settings updated"
    );
    app.store.audit(
        "",
        &actor.subject,
        "settings_updated",
        "",
        &json!({ "keys": ["port_name", "port_address"], "reset": [] }),
    );
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
    let actor = write(&app, &headers)?;
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
    let probed = probe(&app, &origin, key).await;
    app.store.audit(
        &actor.tenant,
        &actor.subject,
        "trade_port_probed",
        &origin,
        &json!({"outcome": if probed.is_ok() { "success" } else { "failure" }}),
    );
    let port = probed.map_err(|error| {
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
    let probed = probe(&app, &origin, Some(&body.invitation.document.issuer)).await;
    app.store.audit(
        &actor.tenant,
        &actor.subject,
        "trade_invitation_probed",
        &origin,
        &json!({"outcome": if probed.is_ok() { "success" } else { "failure" }}),
    );
    let peer = probed?;
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
        tenant: actor.tenant.clone(),
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
            .map_err(store_unavailable)?
            .ok_or_else(ApiError::not_found)?,
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
        notify_later(&app, &route, event, None);
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
            None,
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
        .map_err(store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if route.direction != "outgoing" {
        return Err(invalid("test connections from the sending port"));
    }
    refresh_route(&app, &route).await?;
    Ok(private(
        app.store
            .trade_route(&actor.tenant, &id)
            .map_err(store_unavailable)?
            .ok_or_else(ApiError::not_found)?,
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
        .map_err(store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let route = app
        .store
        .update_trade_route(
            &actor.tenant,
            &id,
            body.revision,
            &body.state,
            body.cancel_active,
            &body.notifications,
            &actor.subject,
        )
        .map_err(invalid)?;
    if route.direction == "incoming" && body.state != "active" && body.cancel_active {
        for session in app.store.trade_sessions(&id).map_err(store_unavailable)? {
            let _ = crate::api::upload::upload_abort(State(Arc::clone(&app)), Path(session)).await;
        }
    }
    if previous.state == "pending_approval" && route.state == "active" {
        notify_later(&app, &route, "route_approved", None);
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
    let actor = format!("peer:{}", route.peer_key);
    app.store
        .rotate_trade_credential(&route.id, old, next, &actor)
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
        .map_err(store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
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
        .rotate_trade_credential(&id, &old, &next, &actor.subject)
        .map_err(invalid)?;
    app.store
        .clear_trade_rotation(&id, &next)
        .map_err(store_unavailable)?;
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
        .map_err(store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let origin = address(&body.address).map_err(unprocessable)?;
    probe(&app, &origin, Some(&route.peer_key)).await?;
    app.store
        .change_trade_address(&actor.tenant, &id, body.revision, &origin, &actor.subject)
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
    let mut settings_error_reported = false;
    loop {
        tokio::select! {_=app.wait_for_shutdown()=>return,_=tokio::time::sleep(std::time::Duration::from_secs(60))=>{}}
        if app.lease_lost.load(std::sync::atomic::Ordering::Relaxed) || app.is_stopping() {
            return;
        }
        if trade_monitoring_is_draining(&app, &mut settings_error_reported) {
            continue;
        }
        if let Err(error) = app.store.prune_trade_invitations() {
            tracing::warn!(%error, "cannot prune expired trade invitations");
        }
        match app.store.trade_routes_to_monitor() {
            Ok(routes) => {
                let now = Instant::now();
                let due: Vec<TradeRoute> = {
                    let mut waiting = backoff.lock().expect("backoff poisoned");
                    waiting.retain(|id, _| routes.iter().any(|r| &r.id == id));
                    routes
                        .into_iter()
                        .filter(|r| waiting.get(&r.id).is_none_or(|(_, next)| *next <= now))
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

fn trade_monitoring_is_draining(app: &App, settings_error_reported: &mut bool) -> bool {
    match app.store.resolved_settings(&app.config) {
        Ok(settings) => {
            *settings_error_reported = false;
            settings.draining
        }
        Err(error) => {
            if !*settings_error_reported {
                tracing::warn!(%error, "cannot read trade monitoring settings");
                *settings_error_reported = true;
            }
            true
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
                Some(error.message.clone()),
            );
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    fn admin_cookie(app: &crate::app::App) -> String {
        format!(
            "votport_admin={}",
            crate::auth::issue_admin_token(
                &app.secret,
                &crate::auth::AdminIdentity::local_admin(),
                &app.config.admin_token_tag,
            )
        )
    }

    #[test]
    fn trade_monitoring_reports_settings_outage_once_per_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let mut settings_error_reported = false;
        assert!(!trade_monitoring_is_draining(
            &app,
            &mut settings_error_reported
        ));
        app.store
            .put_settings(
                "test",
                &[(
                    "draining".to_owned(),
                    crate::store::SettingWrite::Set("0".to_owned()),
                )],
            )
            .unwrap();
        app.store
            .with(|connection| connection.execute_batch("DROP TABLE settings"))
            .unwrap();
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            assert!(trade_monitoring_is_draining(
                &app,
                &mut settings_error_reported
            ));
            assert!(settings_error_reported);
            assert!(trade_monitoring_is_draining(
                &app,
                &mut settings_error_reported
            ));
            assert!(settings_error_reported);
            app.store
                .with(|connection| {
                    connection.execute_batch(
                        "CREATE TABLE settings (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL,
                            updated_at INTEGER NOT NULL,
                            updated_by TEXT NOT NULL DEFAULT ''
                        )",
                    )
                })
                .unwrap();
            app.store
                .put_settings(
                    "test",
                    &[(
                        "draining".to_owned(),
                        crate::store::SettingWrite::Set("1".to_owned()),
                    )],
                )
                .unwrap();
            let warnings_after_outage =
                std::fs::read_to_string(log.path()).unwrap().lines().count();
            assert!(trade_monitoring_is_draining(
                &app,
                &mut settings_error_reported
            ));
            assert!(!settings_error_reported);
            assert_eq!(
                std::fs::read_to_string(log.path()).unwrap().lines().count(),
                warnings_after_outage
            );
            app.store
                .put_settings(
                    "test",
                    &[(
                        "draining".to_owned(),
                        crate::store::SettingWrite::Set("0".to_owned()),
                    )],
                )
                .unwrap();
            app.store
                .with(|connection| connection.execute_batch("DROP TABLE settings"))
                .unwrap();
            assert!(trade_monitoring_is_draining(
                &app,
                &mut settings_error_reported
            ));
            assert!(settings_error_reported);
        });
        let records = std::fs::read_to_string(log.path()).unwrap().lines().count();
        assert_eq!(records, 2);
    }

    #[derive(Clone)]
    struct RotationPeer {
        app: Arc<crate::app::App>,
        route_id: String,
        remote_grant: String,
        replacement: String,
        signer: Arc<crate::receipt::ReceiptSigner>,
        mutated: Arc<std::sync::atomic::AtomicBool>,
    }

    async fn rotation_peer_discovery(
        axum::extract::State(peer): axum::extract::State<RotationPeer>,
        axum::extract::Query(query): axum::extract::Query<DiscoveryQuery>,
    ) -> axum::response::Response {
        super::private(peer.signer.port_message(
            "discovery",
            "",
            query.challenge,
            super::now() + 300,
            serde_json::json!({"protocols":[1]}),
        ))
    }

    async fn rotation_peer_rotate(
        axum::extract::State(peer): axum::extract::State<RotationPeer>,
        axum::Json(request): axum::Json<SignedPortMessage>,
    ) -> axum::response::Response {
        peer.app
            .store
            .with(|connection| {
                connection.execute(
                    "UPDATE trade_routes SET credential=?2 WHERE id=?1",
                    rusqlite::params![&peer.route_id, &peer.replacement,],
                )
            })
            .unwrap();
        peer.mutated
            .store(true, std::sync::atomic::Ordering::SeqCst);
        super::private(peer.signer.port_message(
            "rotated",
            &request.document.issuer,
            request.document.nonce,
            super::now() + 300,
            serde_json::json!({"grant":peer.remote_grant}),
        ))
    }

    fn invitation_fixture() -> (
        tempfile::TempDir,
        Arc<crate::app::App>,
        String,
        TradeEndpoint,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let endpoint = TradeEndpoint {
            id: "trade-endpoint".into(),
            name: "Trade endpoint".into(),
            category: "external".into(),
            forwarding: false,
            metadata_keys: vec![],
            notifications: crate::store::NotificationPolicy::default(),
        };
        app.store
            .insert_link(crate::store::tests::test_link(&endpoint.id))
            .unwrap();
        app.store.create_trade_endpoint("", &endpoint).unwrap();
        app.store
            .put_settings(
                "test",
                &[(
                    "port_address".into(),
                    crate::store::SettingWrite::Set("http://127.0.0.1".into()),
                )],
            )
            .unwrap();
        let cookie = admin_cookie(&app);
        (directory, app, cookie, endpoint)
    }

    fn invitation_count(app: &crate::app::App) -> i64 {
        app.store
            .with(|connection| {
                connection.query_row("SELECT COUNT(*) FROM trade_invitations", [], |row| {
                    row.get(0)
                })
            })
            .unwrap()
    }

    #[tokio::test]
    async fn inspect_rejects_an_invalid_address_before_contacting_a_peer() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/trade-routes/inspect")
                    .header("X-Votport", "1")
                    .header(header::COOKIE, admin_cookie(&app))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"address":"file:///tmp"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(
            body["error"],
            "use a port origin such as https://port.example"
        );
        assert_eq!(app.store.audit_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn port_settings_rewrite_emits_settings_updated() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::put("/api/trade-routes/port")
                    .header("X-Votport", "1")
                    .header(header::COOKIE, admin_cookie(&app))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"name":"Port name","address":"https://port.example"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let updated = app
            .store
            .audit_export(Some(""), 0, 0, 100)
            .unwrap()
            .into_iter()
            .filter(|row| row.event == "settings_updated")
            .collect::<Vec<_>>();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].actor, "local");
        assert_eq!(
            updated[0].detail["keys"],
            serde_json::json!(["port_name", "port_address"])
        );
        assert_eq!(updated[0].detail["reset"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn route_update_and_address_change_events_carry_the_acting_principal() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let cookie = admin_cookie(&app);
        let sender_directory = tempfile::tempdir().unwrap();
        let sender =
            crate::receipt::ReceiptSigner::load_or_create(sender_directory.path()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let route_id = "routed-actor".to_owned();
        let route = TradeRoute {
            id: route_id.clone(),
            revision: 1,
            tenant: String::new(),
            direction: "outgoing".into(),
            name: "Remote".into(),
            peer_name: "Remote".into(),
            peer_key: sender.public_hex.clone(),
            address: format!("http://{address}"),
            endpoint: "endpoint".into(),
            endpoint_name: "Endpoint".into(),
            category: "external".into(),
            forwarding: false,
            metadata_keys: vec![],
            state: "active".into(),
            notifications: crate::store::NotificationPolicy::default(),
            last_contact: None,
            error: None,
            remote_grant: "remote-grant".into(),
            remote_state: "active".into(),
            cancel_active: false,
        };
        app.store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO trade_routes(id,tenant,direction,peer_key,endpoint,document,credential) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    rusqlite::params![
                        &route.id,
                        &route.tenant,
                        &route.direction,
                        &route.peer_key,
                        route.endpoint,
                        serde_json::to_string(&route).unwrap(),
                        &crate::auth::random_token(),
                    ],
                )
            })
            .unwrap();
        let peer = RotationPeer {
            app: Arc::clone(&app),
            route_id: route_id.clone(),
            remote_grant: route.remote_grant.clone(),
            replacement: String::new(),
            signer: Arc::new(sender),
            mutated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let peer_router = axum::Router::new()
            .route("/api/port", axum::routing::get(rotation_peer_discovery))
            .with_state(peer);
        let server = tokio::spawn(async move {
            axum::serve(listener, peer_router).await.unwrap();
        });

        let router = crate::app::router(Arc::clone(&app));
        let response = router
            .clone()
            .oneshot(
                Request::put(format!("/api/trade-routes/{route_id}"))
                    .header("X-Votport", "1")
                    .header(header::COOKIE, &cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"revision":1,"state":"paused","cancel_active":false,"notifications":crate::store::NotificationPolicy::default()})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = router
            .oneshot(
                Request::put(format!("/api/trade-routes/{route_id}/address"))
                    .header("X-Votport", "1")
                    .header(header::COOKIE, cookie)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"address": format!("http://{address}"), "revision": 2}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        server.abort();
        let _ = server.await;

        let events = app.store.delivery_events("", 0, 100).unwrap();
        let permission = events
            .iter()
            .find(|event| event.kind == "route_permission_changed")
            .unwrap();
        assert_eq!(permission.payload["actor"], "local");
        assert_eq!(permission.payload["state"], "paused");
        let moved = events
            .iter()
            .find(|event| event.kind == "route_address_changed")
            .unwrap();
        assert_eq!(moved.payload["actor"], "local");
        assert_eq!(moved.payload["address"], format!("http://{address}"));
    }

    #[tokio::test]
    async fn invitation_expiry_accepts_only_documented_bounds() {
        let (_directory, app, cookie, endpoint) = invitation_fixture();
        let router = crate::app::router(Arc::clone(&app));
        let request = |expires_in| {
            Request::post("/api/trade-routes/invitations")
                .header("X-Votport", "1")
                .header(header::COOKIE, &cookie)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "endpoint": endpoint.id,
                        "expires_in": expires_in,
                    })
                    .to_string(),
                ))
                .unwrap()
        };

        for expires_in in [3600, 86400, 604800] {
            let before = now();
            let invitations_before = invitation_count(&app);
            let audits_before = app.store.audit_count().unwrap();
            let response = router.clone().oneshot(request(expires_in)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let response_body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap_or_else(|_| panic!("invitation response was not JSON"));
            let issued: SignedPortMessage =
                serde_json::from_value(response_body["invitation"].clone())
                    .expect("invitation response field");
            assert!(issued.verify("invitation", "", now()));
            assert!(issued.document.expires_at >= before + expires_in);
            assert!(issued.document.expires_at <= now() + expires_in);
            assert_eq!(invitation_count(&app), invitations_before + 1);
            assert_eq!(app.store.audit_count().unwrap(), audits_before + 1);
        }

        for expires_in in [3599, 3601, 86399, 86401, 604799, 604801] {
            let invitations_before = invitation_count(&app);
            let audits_before = app.store.audit_count().unwrap();
            let response = router.clone().oneshot(request(expires_in)).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(invitation_count(&app), invitations_before);
            assert_eq!(app.store.audit_count().unwrap(), audits_before);
        }
    }

    #[tokio::test]
    async fn local_rotation_refuses_a_credential_changed_during_remote_reply() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let cookie = admin_cookie(&app);
        let sender_directory = tempfile::tempdir().unwrap();
        let sender = Arc::new(
            crate::receipt::ReceiptSigner::load_or_create(sender_directory.path()).unwrap(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let route_id = "local-rotation".to_owned();
        let old = crate::auth::random_token();
        let replacement = crate::auth::random_token();
        let route = TradeRoute {
            id: route_id.clone(),
            revision: 1,
            tenant: String::new(),
            direction: "outgoing".into(),
            name: "Remote".into(),
            peer_name: "Remote".into(),
            peer_key: sender.public_hex.clone(),
            address: format!("http://{address}"),
            endpoint: "endpoint".into(),
            endpoint_name: "Endpoint".into(),
            category: "external".into(),
            forwarding: false,
            metadata_keys: vec![],
            state: "active".into(),
            notifications: crate::store::NotificationPolicy::default(),
            last_contact: None,
            error: None,
            remote_grant: "remote-grant".into(),
            remote_state: "active".into(),
            cancel_active: false,
        };
        let route_document = serde_json::to_string(&route).unwrap();
        app.store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO trade_routes(id,tenant,direction,peer_key,endpoint,document,credential) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    rusqlite::params![
                        &route.id,
                        &route.tenant,
                        &route.direction,
                        &route.peer_key,
                        route.endpoint,
                        route_document,
                        &old,
                    ],
                )
            })
            .unwrap();
        let mutated = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let peer = RotationPeer {
            app: Arc::clone(&app),
            route_id: route_id.clone(),
            remote_grant: route.remote_grant.clone(),
            replacement: replacement.clone(),
            signer: sender,
            mutated: Arc::clone(&mutated),
        };
        let peer_router = axum::Router::new()
            .route("/api/port", axum::routing::get(rotation_peer_discovery))
            .route(
                "/api/port/rotate",
                axum::routing::post(rotation_peer_rotate),
            )
            .with_state(peer);
        let server = tokio::spawn(async move {
            axum::serve(listener, peer_router).await.unwrap();
        });

        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post(format!("/api/trade-routes/{route_id}/rotate"))
                    .header("X-Votport", "1")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        server.abort();
        let _ = server.await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body["error"],
            "credential changed; retry with current credentials"
        );
        assert!(mutated.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            app.store.trade_credential("", &route_id).unwrap(),
            replacement
        );
        assert!(app
            .store
            .audit_export(Some(""), 0, 0, 100)
            .unwrap()
            .iter()
            .all(|row| row.event != "trade_credential_rotated"));
    }

    #[tokio::test]
    async fn trade_test_route_distinguishes_missing_foreign_and_store_failure() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let cookie = admin_cookie(&app);
        let request = |id: &str| {
            Request::post(format!("/api/trade-routes/{id}/test"))
                .extension(ConnectInfo(
                    "127.0.0.1:34567".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .header("X-Votport", "1")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap()
        };
        let response = crate::app::router(Arc::clone(&app))
            .oneshot(request("missing"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let foreign = TradeRoute {
            id: "foreign".into(),
            revision: 1,
            tenant: "other".into(),
            direction: "outgoing".into(),
            name: "Foreign".into(),
            peer_name: "Foreign".into(),
            peer_key: "peer".into(),
            address: "http://127.0.0.1".into(),
            endpoint: "endpoint".into(),
            endpoint_name: "Endpoint".into(),
            category: "external".into(),
            forwarding: false,
            metadata_keys: vec![],
            state: "active".into(),
            notifications: crate::store::NotificationPolicy::default(),
            last_contact: None,
            error: None,
            remote_grant: "grant".into(),
            remote_state: "active".into(),
            cancel_active: false,
        };
        app.store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO trade_routes(id,tenant,direction,peer_key,endpoint,document,credential) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                    rusqlite::params![
                        foreign.id,
                        foreign.tenant,
                        foreign.direction,
                        foreign.peer_key,
                        foreign.endpoint,
                        serde_json::to_string(&foreign).unwrap(),
                        "credential",
                    ],
                )
            })
            .unwrap();
        let response = crate::app::router(Arc::clone(&app))
            .oneshot(request("foreign"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        app.store
            .with(|connection| connection.execute_batch("DROP TABLE trade_routes"))
            .unwrap();
        let response = crate::app::router(app)
            .oneshot(request("backend"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "database unavailable; try again");
    }

    #[tokio::test]
    async fn discovery_limits_requests_before_identity_reads_and_signing() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.trusted_proxies = vec![crate::config::IpCidr::parse("10.0.0.1/32").unwrap()];
        let mut app = crate::app::build(config).unwrap();
        Arc::get_mut(&mut app).unwrap().automation_read_rate =
            super::super::session_rate::SessionRate::with_limit(2);
        let router = crate::app::router(Arc::clone(&app));
        for (peer, forwarded, denied) in [
            ("198.51.100.1:1", "203.0.113.1", false),
            ("198.51.100.1:2", "203.0.113.2", false),
            ("198.51.100.1:3", "203.0.113.3", true),
            ("198.51.100.2:1", "203.0.113.3", false),
            ("10.0.0.1:1", "192.0.2.1, 203.0.113.1", false),
            ("10.0.0.1:2", "192.0.2.2, 203.0.113.1", false),
            ("10.0.0.1:3", "192.0.2.3, 203.0.113.1", true),
            ("10.0.0.1:4", "192.0.2.3, 203.0.113.2", false),
        ] {
            let challenge = crate::auth::random_token();
            let response = router
                .clone()
                .oneshot(
                    Request::get(format!("/api/port?challenge={challenge}"))
                        .extension(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()))
                        .header("x-forwarded-for", forwarded)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if denied {
                    StatusCode::TOO_MANY_REQUESTS
                } else {
                    StatusCode::OK
                },
                "{peer}, {forwarded}"
            );
            if denied {
                assert_eq!(response.headers()[header::RETRY_AFTER], "600");
            } else {
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                let message: SignedPortMessage = serde_json::from_slice(&bytes).unwrap();
                assert!(message.verify("discovery", "", now()));
                assert_eq!(message.document.issuer, app.signer.public_hex);
                assert_eq!(message.document.nonce, challenge);
            }
        }
        let peer = ConnectInfo("198.51.100.1:1".parse::<std::net::SocketAddr>().unwrap());
        let request = app.signer.port_message(
            "status",
            "",
            crate::auth::random_token(),
            now() + 300,
            json!({}),
        );
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/port/status")
                    .extension(peer)
                    .header("x-votport", "1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let response = router
            .clone()
            .oneshot(
                Request::get("/api/admin/callback")
                    .extension(peer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        app.store
            .with(|connection| connection.execute_batch("DROP TABLE settings"))
            .unwrap();
        for (peer, status) in [
            ("198.51.100.1:1", StatusCode::TOO_MANY_REQUESTS),
            ("198.51.100.3:1", StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::get(format!(
                        "/api/port?challenge={}",
                        crate::auth::random_token()
                    ))
                    .extension(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()))
                    .body(Body::empty())
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
        }
    }

    #[tokio::test]
    async fn remote_rotation_replay_mirrors_once() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        let sender_directory = tempfile::tempdir().unwrap();
        let sender =
            crate::receipt::ReceiptSigner::load_or_create(sender_directory.path()).unwrap();
        let route = TradeRoute {
            id: crate::auth::random_token(),
            revision: 1,
            tenant: String::new(),
            direction: "incoming".into(),
            name: "Sender".into(),
            peer_name: "Sender".into(),
            peer_key: sender.public_hex.clone(),
            address: String::new(),
            endpoint: "endpoint".into(),
            endpoint_name: "Endpoint".into(),
            category: "external".into(),
            forwarding: false,
            metadata_keys: vec![],
            state: "active".into(),
            notifications: crate::store::NotificationPolicy::default(),
            last_contact: Some(crate::store::now_unix()),
            error: None,
            remote_grant: String::new(),
            remote_state: String::new(),
            cancel_active: false,
        };
        let old = crate::auth::random_token();
        let next = crate::auth::random_token();
        application
            .store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO trade_routes(id,tenant,direction,peer_key,endpoint,document,credential) VALUES (?1,'','incoming',?2,?3,?4,?5)",
                    rusqlite::params![
                        route.id,
                        route.peer_key,
                        route.endpoint,
                        serde_json::to_string(&route).unwrap(),
                        crate::store::trade_secret_hash(&old),
                    ],
                )
            })
            .unwrap();
        let request = sender.port_message(
            "rotate",
            &application.signer.public_hex,
            crate::auth::random_token(),
            now() + 300,
            json!({"grant":route.id,"credential":old,"next":next}),
        );
        let router = crate::app::router(application.clone());
        for _ in 0..2 {
            let response = router
                .clone()
                .oneshot(
                    Request::post("/api/port/rotate")
                        .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                        .header("x-votport", "1")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(serde_json::to_vec(&request).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let events = application.store.delivery_events("", 0, 100).unwrap();
        let rotated = events
            .iter()
            .filter(|event| event.kind == "trade_credential_rotated")
            .collect::<Vec<_>>();
        assert_eq!(rotated.len(), 1);
        assert!(rotated[0].verify());
        let audits = application.store.audit_export(Some(""), 0, 0, 100).unwrap();
        let mirrored = audits
            .iter()
            .filter(|row| row.event == "trade_credential_rotated")
            .collect::<Vec<_>>();
        assert_eq!(mirrored.len(), 1);
        assert_eq!(mirrored[0].actor, format!("peer:{}", sender.public_hex));
        assert_eq!(mirrored[0].detail["delivery_event_id"], rotated[0].id);
        assert_eq!(mirrored[0].detail["summary"]["route"], route.id);
        assert_eq!(mirrored[0].detail["summary"]["direction"], "incoming");
        assert_eq!(mirrored[0].detail["summary"]["peer_id"], sender.public_hex);
        let text = serde_json::to_string(&mirrored[0]).unwrap();
        assert!(!text.contains(&old));
        assert!(!text.contains(&next));
    }
    #[tokio::test]
    async fn probe_handlers_record_origin_only_outcome_rows() {
        let (_directory, app, cookie, _endpoint) = invitation_fixture();

        // Inspect a dead address: the probe is audited even though it fails.
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/trade-routes/inspect")
                    .header("X-Votport", "1")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"address":"http://127.0.0.1:1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // Accepting an invitation that points at a dead port audits the probe
        // with the invitation address.
        let invitation = app.signer.port_message(
            "invitation",
            "",
            crate::auth::random_token(),
            super::now() + 300,
            json!({
                "address": "http://127.0.0.1:1",
                "name": "Dead Port",
                "endpoint": {
                    "id": "trade-endpoint",
                    "name": "Trade endpoint",
                    "category": "external",
                    "forwarding": false,
                    "metadata_keys": [],
                    "notifications": {"mode": "off", "rules": []}
                },
            }),
        );
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/trade-routes")
                    .header("X-Votport", "1")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "invitation": invitation,
                            "name": "Dead Route",
                            "notifications": {"mode": "off", "rules": []}
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!response.status().is_success());

        // Storage test against an unreadable shared folder: recorded as a
        // failure with the folder path as the address.
        let storage_body = |revision: u64, directory: &str| {
            json!({
                "storage": {
                    "id": "probe_storage",
                    "revision": revision,
                    "label": "Probe",
                    "kind": "folder",
                    "directory": directory,
                    "endpoint": "",
                    "bucket": "",
                    "region": "",
                    "prefix": "",
                    "path_style": false,
                    "kms_key_id": null,
                    "tenants": [""],
                    "enabled": true
                },
                "credentials": null
            })
        };
        let save = |revision: u64, directory: &str| {
            crate::app::router(app.clone()).oneshot(
                Request::put("/api/workflows/storage")
                    .header("X-Votport", "1")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(storage_body(revision, directory).to_string()))
                    .unwrap(),
            )
        };
        let missing = std::env::temp_dir().join("votport-audit-probe-missing/shared");
        let response = save(0, missing.to_str().unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/workflows/storage/probe_storage/test")
                    .header("X-Votport", "1")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/json")
                    // The save above bumped the storage to revision 1.
                    .body(Body::from(json!({"revision": 1}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // Notification test against a live webhook: success with the URL
        // reduced to its origin.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let hook_port = listener.local_addr().unwrap().port();
        let stub = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 2048];
            let _ = std::io::Read::read(&mut stream, &mut buffer);
            let _ = std::io::Write::write_all(
                &mut stream,
                b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            );
        });
        let mut destination: crate::store::NotificationDestination =
            serde_json::from_value(json!({
                "id": "probe_hook",
                "label": "Probe hook",
                "channel": "webhook",
                "target": "Audit probe",
                "enabled": true,
                "url": format!("http://127.0.0.1:{hook_port}/hook?token=sekret")
            }))
            .unwrap();
        app.store
            .save_notification_destination("", &mut destination)
            .unwrap();
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/notifications/probe_hook/test")
                    .header("X-Votport", "1")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        stub.join().unwrap();

        let rows = app.store.audit_export(Some(""), 0, 0, 100).unwrap();
        let inspected = rows
            .iter()
            .find(|row| row.event == "trade_port_probed")
            .expect("inspect probe is audited");
        assert_eq!(inspected.subject, "http://127.0.0.1:1");
        assert_eq!(inspected.detail["outcome"], json!("failure"));
        let accepted = rows
            .iter()
            .find(|row| row.event == "trade_invitation_probed")
            .expect("accept probe is audited");
        assert_eq!(accepted.subject, "http://127.0.0.1:1");
        assert_eq!(accepted.detail["outcome"], json!("failure"));
        let storage_row = rows
            .iter()
            .find(|row| row.event == "storage_connection_tested")
            .expect("storage test is audited");
        assert_eq!(storage_row.subject, "probe_storage");
        assert_eq!(storage_row.detail["kind"], json!("folder"));
        assert_eq!(
            storage_row.detail["address"],
            json!(missing.to_str().unwrap())
        );
        assert_eq!(storage_row.detail["outcome"], json!("failure"));
        let tested = rows
            .iter()
            .find(|row| row.event == "notification_tested")
            .expect("notification test is audited");
        assert_eq!(tested.subject, "probe_hook");
        assert_eq!(tested.detail["outcome"], json!("success"));
        assert_eq!(
            tested.detail["url"],
            json!(format!("http://127.0.0.1:{hook_port}"))
        );
        assert!(!tested.detail.to_string().contains("sekret"));
    }
}
