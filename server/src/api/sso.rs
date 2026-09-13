//! OIDC single sign-in for the admin dashboard (phase 3 of
//! docs/multi-tenancy.md): discovery at first use, authorization-code flow
//! with PKCE, id-token verification by the openidconnect crate, and role
//! mapping from the provider's `groups` claim.
//!
//! Local password sign-in remains the zero-config default and the
//! break-glass path; this module only exists when VOTPORT_OIDC_* is set.
//!
//! A single `client_id` is the supported shape. The crate checks issuer,
//! audience, and nonce; when an id token carries `azp` it must equal that
//! client id. Hosted-domain (`hd`) checks are not implemented.

use std::fmt::Write as _;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use hmac::Mac as _;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, RedirectUrl, Scope,
};
use openidconnect::{OAuth2TokenResponse as _, TokenResponse as _};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Digest as _;

use crate::app::App;
use crate::auth;

/// The discovered provider plus the client bound to our redirect URI.
/// The generic states come from `from_provider_metadata`: the authorization
/// endpoint is always set, the rest are MaybeSet because discovery cannot
/// guarantee them.
pub struct SsoClient {
    client: CoreClient<
        openidconnect::EndpointSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointMaybeSet,
        openidconnect::EndpointMaybeSet,
    >,
    /// A no-redirect client owned by this crate's dependency graph; OIDC
    /// endpoints must be contacted directly, never through follower redirects.
    http: reqwest::Client,
    userinfo_url: Option<String>,
}

impl SsoClient {
    pub async fn discover(
        issuer: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> Result<Self, String> {
        let http = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            // Every IdP call runs inside a browser redirect; without this a
            // hung endpoint holds the callback open indefinitely.
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|error| format!("oidc http client: {error}"))?;
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer.to_owned()).map_err(|error| error.to_string())?,
            &http,
        )
        .await
        .map_err(|error| format!("oidc discovery: {error}"))?;
        let userinfo_url = metadata.userinfo_endpoint().map(|url| url.to_string());
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(client_id.to_owned()),
            Some(ClientSecret::new(client_secret.to_owned())),
        );
        let client = client.set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_owned()).map_err(|error| error.to_string())?,
        );
        Ok(Self {
            client,
            http,
            userinfo_url,
        })
    }
}

// Present azp must match client_id so a second client at this issuer cannot act as us.
fn azp_ok(azp: Option<&str>, client_id: &str) -> bool {
    match azp {
        None => true,
        Some(party) => party == client_id,
    }
}

/// Error string for a blocked SSO principal.
fn blocked_principal_error(blocked: bool) -> Option<&'static str> {
    blocked.then_some("this account is blocked")
}

/// Role from the optional required groups: no admin requirement means every
/// authenticated principal is an admin; otherwise admin membership wins,
/// then auditor membership, and everyone else is a read-only viewer.
fn sso_role(
    admin_group: Option<&str>,
    auditor_group: Option<&str>,
    groups: &[String],
) -> &'static str {
    match admin_group {
        None => "admin",
        Some(required) if groups.iter().any(|group| group == required) => "admin",
        Some(_) => match auditor_group {
            Some(required) if groups.iter().any(|group| group == required) => "auditor",
            _ => "viewer",
        },
    }
}

/// Builds the SSO session identity. Refuses the reserved break-glass subject
/// and blocked principals. Records `sso_login` only after those checks pass.
/// SCIM group names join the provider's group claims, so the admin,
/// auditor, and tenant admin group settings match either source. A read
/// failure fails the sign-in rather than silently dropping a role.
fn merge_scim_groups(
    store: &crate::store::Store,
    subject: &str,
    groups: &mut Vec<String>,
) -> Result<(), &'static str> {
    let scim = store.scim_groups_of(subject).map_err(|error| {
        tracing::error!(%error, "scim group read failed during sign-in");
        "could not verify group membership"
    })?;
    for name in scim {
        if !groups.contains(&name) {
            groups.push(name);
        }
    }
    Ok(())
}

/// The principal subject for the configured claim, or None when the claim
/// is absent so the caller can retry with the userinfo document. An empty
/// value counts as absent. An email the provider marks unverified is
/// refused outright: a self-asserted address must not select a principal.
/// Providers that omit email_verified (Entra) are accepted as is.
fn select_subject(
    claim: crate::config::SubjectClaim,
    sub: &str,
    email: Option<&str>,
    email_verified: Option<bool>,
    preferred_username: Option<&str>,
) -> Result<Option<String>, &'static str> {
    use crate::config::SubjectClaim;
    let chosen = match claim {
        SubjectClaim::Sub => Some(sub),
        SubjectClaim::Email if email_verified == Some(false) => {
            return Err("the provider marks this email unverified")
        }
        SubjectClaim::Email => email,
        SubjectClaim::PreferredUsername => preferred_username,
    };
    Ok(chosen
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned))
}

fn finish_sso_login(
    store: &crate::store::Store,
    subject: &str,
    role: String,
    groups: &[String],
    require_provisioning: bool,
) -> Result<auth::AdminIdentity, &'static str> {
    if subject == "local" {
        return Err("identity could not be verified");
    }
    // With provisioning required, an absent row is a refusal before any
    // upsert could create one; a read failure denies for the same reason
    // principal_allows does.
    if require_provisioning {
        match store.principal(subject) {
            Ok(Some(_)) => {}
            Ok(None) => {
                tracing::warn!(target: "audit", event = "sso_failed", subject = %subject, "subject is not provisioned");
                return Err("this account is not provisioned");
            }
            Err(error) => {
                tracing::error!(%error, "principal read failed during sign-in");
                return Err("could not complete sign-in");
            }
        }
    }
    let mut grants = vec![auth::TenantGrant {
        incarnation: None,
        tenant: String::new(),
        role: role.clone(),
    }];
    let tenants = store.tenants().map_err(|error| {
        tracing::error!(%error, "tenant read failed during sign-in");
        "could not complete sign-in"
    })?;
    for tenant in tenants {
        let Some(required) = &tenant.admin_group else {
            continue;
        };
        if groups.iter().any(|group| group == required) {
            grants.push(auth::TenantGrant {
                incarnation: Some(tenant.incarnation.clone()),
                tenant: tenant.key.clone(),
                role: "admin".to_owned(),
            });
        }
    }
    let grants_json = serde_json::to_value(&grants).unwrap_or_else(|_| json!([]));
    let mut identity = auth::AdminIdentity {
        subject: subject.to_owned(),
        tenant: String::new(),
        role: role.clone(),
        grants,
        credential_version: 1,
    };
    let row = match store.upsert_sso_principal(subject, groups, &grants_json) {
        Ok(row) => row,
        Err(error) => {
            tracing::error!(
                target: "audit",
                error = %error,
                "principal upsert failed"
            );
            return Err("could not complete sign-in");
        }
    };
    if let Some(message) = blocked_principal_error(row.blocked) {
        return Err(message);
    }
    identity.credential_version = row.credential_version;
    tracing::info!(
        target: "audit", event = "sso_login", subject = %subject, %role,
        "SSO sign-in succeeded"
    );
    store.audit("", subject, "sso_login", subject, &json!({ "role": role }));
    Ok(identity)
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Whether SSO sign-in is configured (drives the login-page button).
/// Does not start discovery; `sso_healthy` is true only for a Ready slot.
/// `public_password_login` comes from the settings overlay (env if unwritten).
pub async fn sso_available(State(app): State<std::sync::Arc<App>>) -> Response {
    let available = app.sso_config.is_some();
    let sso_healthy = app.sso_client.health_peek();
    // A read failure must not answer "password sign-in is off": the login
    // page would hide the break-glass form. Fall back to the env default.
    let public_password_login = match app.store.resolved_settings(&app.config) {
        Ok(settings) => settings.public_password_login,
        Err(error) => {
            tracing::error!(%error, "settings read failed; using the environment default");
            app.config.public_password_login
        }
    };
    (
        [(header::CONTENT_TYPE, "application/json")],
        axum::Json(json!({
            "available": available,
            "sso_healthy": sso_healthy,
            "public_password_login": public_password_login,
        })),
    )
        .into_response()
}

#[derive(Deserialize, Default)]
pub struct StartParams {
    desktop_challenge: Option<String>,
    desktop_state: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct DesktopFlow {
    challenge: [u8; 32],
    state: String,
}

impl StartParams {
    fn desktop(self) -> Result<Option<DesktopFlow>, &'static str> {
        match (self.desktop_challenge, self.desktop_state) {
            (None, None) => Ok(None),
            (Some(challenge), Some(state)) => {
                if challenge.len() != 64 {
                    return Err("invalid desktop challenge");
                }
                let challenge = hex::decode(challenge)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or("invalid desktop challenge")?;
                if state.len() != 32 || !state.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err("invalid desktop state");
                }
                Ok(Some(DesktopFlow { challenge, state }))
            }
            _ => Err("desktop challenge and state are both required"),
        }
    }
}

struct DesktopHandoff {
    flow: DesktopFlow,
    identity: auth::AdminIdentity,
    expires: u64,
}

#[derive(Default)]
pub struct DesktopSignIns(std::sync::Mutex<std::collections::HashMap<String, DesktopHandoff>>);

impl DesktopSignIns {
    fn issue(&self, flow: DesktopFlow, identity: auth::AdminIdentity, now: u64) -> Option<String> {
        let mut pending = self.0.lock().expect("desktop sign-ins poisoned");
        pending.retain(|_, login| login.expires > now);
        if pending.len() >= 1024 {
            return None;
        }
        let code = auth::random_token();
        let target = format!("votport://signin/{code}?state={}", flow.state);
        pending.insert(
            code,
            DesktopHandoff {
                flow,
                identity,
                expires: now + 60,
            },
        );
        Some(target)
    }

    fn exchange(&self, code: &str, verifier: &str, now: u64) -> Option<auth::AdminIdentity> {
        if code.len() != 32 || verifier.len() != 64 {
            return None;
        }
        let digest = sha2::Sha256::digest(verifier.as_bytes());
        let mut pending = self.0.lock().expect("desktop sign-ins poisoned");
        pending.retain(|_, login| login.expires > now);
        let login = pending.get(code)?;
        if !auth::constant_time_eq(&login.flow.challenge, &digest) {
            return None;
        }
        pending.remove(code).map(|login| login.identity)
    }
}

#[derive(Deserialize)]
pub struct ExchangeParams {
    code: String,
    verifier: String,
}

pub async fn sso_exchange(
    State(app): State<std::sync::Arc<App>>,
    axum::Json(params): axum::Json<ExchangeParams>,
) -> super::ApiResult<Response> {
    let identity = app
        .desktop_sign_ins
        .exchange(&params.code, &params.verifier, crate::store::now_unix())
        .ok_or_else(|| {
            super::ApiError::new(
                StatusCode::UNAUTHORIZED,
                "sign-in expired or was already used; start again",
            )
        })?;
    let cookie = super::admin::issue_admin_cookie(&app, &identity, None)?;
    let cookie = cookie.split(';').next().unwrap_or_default();
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({ "cookie": cookie })),
    )
        .into_response())
}

const STATE_COOKIE: &str = "votport_sso_x";
const STATE_SECS: u64 = 600;

fn clear_state_cookie(app: &App) -> String {
    format!(
        "{STATE_COOKIE}=; Path=/api/admin; HttpOnly; SameSite=Lax; Max-Age=0{}",
        super::admin::sso_cookie_attributes(app)
    )
}

fn sign_payload(secret: &[u8; 32], expires: u64, payload: &str) -> String {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(secret)
        .expect("hmac accepts any key length");
    mac.update(b"votport-sso-x\0");
    mac.update(expires.to_le_bytes().as_slice());
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Starts the flow: PKCE pair, signed state cookie, redirect to the IdP.
async fn start_flow(
    app: &std::sync::Arc<App>,
    config: crate::config::OidcConfig,
    desktop: Option<DesktopFlow>,
) -> Result<Response, Response> {
    let public_url = app.config.public_url.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "SSO needs VOTPORT_PUBLIC_URL set",
        )
            .into_response()
    })?;
    let client = app
        .sso_client
        .get_or_discover(&config, &public_url)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "SSO discovery failed; try again shortly",
            )
                .into_response()
        })?;

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state, nonce) = client
        .client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_owned()))
        .add_scope(Scope::new("email".to_owned()))
        .add_scope(Scope::new("profile".to_owned()))
        .set_pkce_challenge(challenge)
        .url();

    let payload = json!({
        "state": state.secret(),
        "nonce": nonce.secret(),
        "verifier": verifier.secret(),
        "desktop": desktop,
    })
    .to_string();
    let expires = crate::store::now_unix() + STATE_SECS;
    let mut cookie_value = String::new();
    write!(
        cookie_value,
        "{expires}.{}",
        hex::encode(payload.as_bytes())
    )
    .expect("writing to a string cannot fail");
    write!(
        cookie_value,
        ".{}",
        sign_payload(&app.secret, expires, &payload)
    )
    .expect("writing to a string cannot fail");

    let cookie = format!(
        "{STATE_COOKIE}={cookie_value}; Path=/api/admin; HttpOnly; SameSite=Lax; Max-Age={STATE_SECS}{}",
        super::admin::sso_cookie_attributes(app)
    );
    Ok((
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, url.to_string()),
        ],
        StatusCode::FOUND,
    )
        .into_response())
}

fn sso_rate(app: &App, headers: &HeaderMap, peer: &std::net::SocketAddr) -> super::ApiResult<()> {
    let ip = super::client_ip(headers, peer, &app.config.trusted_proxies);
    if app.sso_rate.allow(&super::throttle_key(&ip)) {
        Ok(())
    } else {
        Err(super::ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many SSO sign-in requests; wait ten minutes, then start sign-in again",
        )
        .with_retry_after(600))
    }
}

pub async fn sso_start(
    State(app): State<std::sync::Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<StartParams>,
) -> Response {
    if let Err(error) = sso_rate(&app, &headers, &peer) {
        return error.into_response();
    }
    let desktop = match params.desktop() {
        Ok(desktop) => desktop,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    match app.sso_config.clone() {
        Some(config) => start_flow(&app, config, desktop)
            .await
            .unwrap_or_else(|response| response),
        None => (StatusCode::NOT_FOUND, "SSO is not configured").into_response(),
    }
}

fn sso_error_code(message: &str) -> &'static str {
    match message {
        "the identity provider refused the sign-in" => "provider_refused",
        "missing code or state"
        | "stale or missing sign-in state"
        | "stale sign-in state"
        | "sign-in timed out; try again"
        | "invalid sign-in state"
        | "invalid desktop sign-in state" => "state_invalid",
        "SSO is not configured" => "not_configured",
        "SSO is unavailable"
        | "token exchange failed"
        | "too many pending desktop sign-ins; try again shortly" => "unavailable",
        "the identity provider is misconfigured" | "no id token in response" => {
            "provider_misconfigured"
        }
        "identity could not be verified" => "identity_unverified",
        "could not verify group membership" => "groups_unverified",
        "this account is blocked" => "account_blocked",
        "this account is not provisioned" => "not_provisioned",
        _ => "failed",
    }
}

/// Finishes the flow: validates state, exchanges the code with the PKCE
/// verifier, maps groups to a role, issues the admin cookie, and returns to
/// the dashboard. Admitted failures redirect home with ?sso_error=...
pub async fn sso_callback(
    State(app): State<std::sync::Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    if let Err(error) = sso_rate(&app, &headers, &peer) {
        return error.into_response();
    }
    let app_for_home = std::sync::Arc::clone(&app);
    let home = move |message: &str| {
        if !message.is_empty() {
            // Failures are SIEM-relevant; the generic message goes to the
            // browser, the specific one to the audit trail.
            tracing::warn!(target: "audit", event = "sso_failed", reason = message, "SSO sign-in failed");
            app_for_home
                .store
                .audit("", "", "sso_failed", "", &json!({ "reason": message }));
        }
        let clear_state = clear_state_cookie(&app_for_home);
        let target = if message.is_empty() {
            "/".to_owned()
        } else {
            format!("/?sso_error={}", sso_error_code(message))
        };
        (
            [
                (header::SET_COOKIE, clear_state),
                (header::LOCATION, target),
            ],
            StatusCode::FOUND,
        )
            .into_response()
    };
    if let Some(error) = params.error {
        tracing::warn!(target: "audit", event = "sso_failed", %error, "provider returned an error");
        return home("the identity provider refused the sign-in");
    }
    let (Some(code), Some(state)) = (params.code, params.state) else {
        return home("missing code or state");
    };

    // Recover and validate the signed flow state.
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| auth::cookie_value(cookies, STATE_COOKIE))
        .unwrap_or_default();
    let parts: Vec<&str> = cookie.split('.').collect();
    let [expires_s, payload_hex, mac] = parts.as_slice() else {
        return home("stale or missing sign-in state");
    };
    let Ok(expires) = expires_s.parse::<u64>() else {
        return home("stale sign-in state");
    };
    if crate::store::now_unix() >= expires {
        return home("sign-in timed out; try again");
    }
    let payload = match hex::decode(payload_hex)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
    {
        Some(payload) => payload,
        None => return home("invalid sign-in state"),
    };
    let expected = sign_payload(&app.secret, expires, &payload);
    if !auth::constant_time_eq(expected.as_bytes(), mac.as_bytes()) {
        return home("invalid sign-in state");
    }
    let flow: serde_json::Value = serde_json::from_str(&payload).unwrap_or(json!({}));
    if flow["state"].as_str() != Some(state.as_str()) {
        return home("invalid sign-in state");
    }
    let (Some(nonce), Some(verifier)) = (flow["nonce"].as_str(), flow["verifier"].as_str()) else {
        return home("invalid sign-in state");
    };

    let sso_config = match (&app.sso_config, app.config.public_url.clone()) {
        (Some(config), Some(public_url)) => (config, public_url),
        _ => return home("SSO is not configured"),
    };
    let client = match app
        .sso_client
        .get_or_discover(sso_config.0, &sso_config.1)
        .await
    {
        Ok(client) => client,
        Err(()) => return home("SSO is unavailable"),
    };

    // The token endpoint is MaybeSet under discovery; a missing URL is a
    // provider configuration problem, not a runtime condition.
    let exchange = match client.client.exchange_code(AuthorizationCode::new(code)) {
        Ok(exchange) => exchange,
        Err(error) => {
            tracing::warn!(target: "audit", event = "sso_failed", error = %error, "provider lacks a token endpoint");
            return home("the identity provider is misconfigured");
        }
    };
    let token_response = match exchange
        .set_pkce_verifier(openidconnect::PkceCodeVerifier::new(verifier.to_owned()))
        .request_async(&client.http)
        .await
    {
        Ok(token) => token,
        Err(error) => {
            tracing::warn!(target: "audit", event = "sso_failed", error = %error, "token exchange failed");
            return home("token exchange failed");
        }
    };
    let id_token = token_response
        .id_token()
        .ok_or_else(|| home("no id token in response"))
        .ok();
    let Some(id_token) = id_token else {
        return home("no id token in response");
    };
    let expected_nonce = nonce;
    let claims = match id_token.claims(
        &client.client.id_token_verifier(),
        move |actual: Option<&Nonce>| {
            actual
                .map(|nonce| nonce.secret() == expected_nonce)
                .unwrap_or(false)
                .then_some(())
                .ok_or_else(|| "nonce mismatch".to_owned())
        },
    ) {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(target: "audit", event = "sso_failed", error = %error, "id token verification failed");
            return home("identity could not be verified");
        }
    };
    if !azp_ok(
        claims.authorized_party().map(|party| party.as_str()),
        &sso_config.0.client_id,
    ) {
        tracing::warn!(
            target: "audit",
            event = "sso_failed",
            "authorized party does not match client id"
        );
        return home("identity could not be verified");
    }
    // The verified sub anchors the userinfo check; the principal subject may
    // be a different claim and is chosen once userinfo has been read.
    let sub = claims.subject().to_string();
    let mut subject = match select_subject(
        sso_config.0.subject_claim,
        &sub,
        claims.email().map(|value| value.as_str()),
        claims.email_verified(),
        claims.preferred_username().map(|value| value.as_str()),
    ) {
        Ok(subject) => subject,
        Err(reason) => {
            tracing::warn!(target: "audit", event = "sso_failed", reason, "subject claim refused");
            return home("identity could not be verified");
        }
    };

    // Groups come from the userinfo endpoint; the id token may not carry them.
    let mut groups: Vec<String> = Vec::new();
    if let Some(url) = client.userinfo_url.clone() {
        let token = token_response.access_token().secret();
        // A userinfo failure must not silently downgrade an admin to viewer:
        // fail the sign-in loudly instead.
        // The client's own no-redirect transport, not app.http: a redirecting
        // userinfo endpoint must not carry the access token onward.
        let value = match client.http.get(url).bearer_auth(token).send().await {
            // A redirect answers here rather than being followed, so the
            // status has to be named or the failure is undiagnosable.
            Ok(response) if !response.status().is_success() => {
                tracing::warn!(target: "audit", event = "sso_failed", status = %response.status(), "userinfo returned a non-success status");
                return home("could not verify group membership");
            }
            Ok(response) => match response.json::<serde_json::Value>().await {
                Ok(value) => value,
                Err(error) => {
                    tracing::warn!(target: "audit", event = "sso_failed", error = %error, "userinfo parse failed");
                    return home("could not verify group membership");
                }
            },
            Err(error) => {
                tracing::warn!(target: "audit", event = "sso_failed", error = %error, "userinfo request failed");
                return home("could not verify group membership");
            }
        };
        // OIDC Core 5.3.2: the userinfo sub must match the verified id-token
        // subject, or the response is not about this user.
        if value["sub"].as_str() != Some(sub.as_str()) {
            tracing::warn!(target: "audit", event = "sso_failed", "userinfo sub mismatch");
            return home("identity could not be verified");
        }
        if subject.is_none() {
            subject = match select_subject(
                sso_config.0.subject_claim,
                &sub,
                value["email"].as_str(),
                value["email_verified"].as_bool(),
                value["preferred_username"].as_str(),
            ) {
                Ok(subject) => subject,
                Err(reason) => {
                    tracing::warn!(target: "audit", event = "sso_failed", reason, "userinfo subject claim refused");
                    return home("identity could not be verified");
                }
            };
        }
        if let Some(list) = value["groups"].as_array() {
            groups.extend(
                list.iter()
                    .filter_map(|entry| entry.as_str().map(str::to_owned)),
            );
        }
    }

    let Some(subject) = subject else {
        tracing::warn!(
            target: "audit",
            event = "sso_failed",
            claim = ?sso_config.0.subject_claim,
            "the configured subject claim is absent from the id token and userinfo"
        );
        return home("identity could not be verified");
    };
    let require_provisioning = match app.store.resolved_settings(&app.config) {
        Ok(settings) => settings.require_provisioning,
        Err(error) => {
            tracing::error!(%error, "settings read failed during sign-in");
            return home("could not complete sign-in");
        }
    };

    if let Err(message) = merge_scim_groups(&app.store, &subject, &mut groups) {
        return home(message);
    }
    let role = sso_role(
        sso_config.0.admin_group.as_deref(),
        sso_config.0.auditor_group.as_deref(),
        &groups,
    )
    .to_owned();
    let identity = match finish_sso_login(&app.store, &subject, role, &groups, require_provisioning)
    {
        Ok(identity) => identity,
        Err(message) => return home(message),
    };
    if !flow["desktop"].is_null() {
        let desktop = match serde_json::from_value::<DesktopFlow>(flow["desktop"].clone()) {
            Ok(desktop) => desktop,
            Err(_) => return home("invalid desktop sign-in state"),
        };
        let Some(target) = app
            .desktop_sign_ins
            .issue(desktop, identity, crate::store::now_unix())
        else {
            return home("too many pending desktop sign-ins; try again shortly");
        };
        return (
            StatusCode::FOUND,
            [
                (header::SET_COOKIE, clear_state_cookie(&app)),
                (header::LOCATION, target),
                (header::CACHE_CONTROL, "no-store".to_owned()),
            ],
        )
            .into_response();
    }
    let admin_cookie = match super::admin::issue_admin_cookie(&app, &identity, None) {
        Ok(cookie) => cookie,
        Err(_) => return home("could not complete sign-in"),
    };
    browser_login_response(&app, admin_cookie)
}

fn browser_login_response(app: &App, admin_cookie: String) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, "/"), (header::CACHE_CONTROL, "no-store")],
        axum::response::AppendHeaders([
            (header::SET_COOKIE, admin_cookie),
            (header::SET_COOKIE, clear_state_cookie(app)),
        ]),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AdminIdentity;

    #[test]
    fn desktop_handoffs_bind_proof_expire_and_are_single_use() {
        let verifier = "ab".repeat(32);
        let flow = DesktopFlow {
            challenge: sha2::Sha256::digest(verifier.as_bytes()).into(),
            state: "cd".repeat(16),
        };
        let handoffs = std::sync::Arc::new(DesktopSignIns::default());
        let target = handoffs
            .issue(flow.clone(), AdminIdentity::local_admin(), 100)
            .unwrap();
        let code = target
            .strip_prefix("votport://signin/")
            .unwrap()
            .split('?')
            .next()
            .unwrap();
        assert!(target.ends_with(&format!("?state={}", flow.state)));
        assert!(handoffs.exchange(code, "short", 101).is_none());
        assert!(handoffs.exchange("short", &verifier, 101).is_none());
        assert!(handoffs.exchange(code, &"ef".repeat(32), 101).is_none());
        let successes = std::thread::scope(|scope| {
            let first = scope.spawn(|| handoffs.exchange(code, &verifier, 159));
            let second = scope.spawn(|| handoffs.exchange(code, &verifier, 159));
            usize::from(first.join().unwrap().is_some())
                + usize::from(second.join().unwrap().is_some())
        });
        assert_eq!(successes, 1);
        assert!(handoffs.exchange(code, &verifier, 159).is_none());
        let target = handoffs
            .issue(flow.clone(), AdminIdentity::local_admin(), 100)
            .unwrap();
        let code = target
            .strip_prefix("votport://signin/")
            .unwrap()
            .split('?')
            .next()
            .unwrap();
        assert!(handoffs.exchange(code, &verifier, 160).is_none());
        for _ in 0..1024 {
            assert!(handoffs
                .issue(flow.clone(), AdminIdentity::local_admin(), 200)
                .is_some());
        }
        assert!(handoffs
            .issue(flow.clone(), AdminIdentity::local_admin(), 259)
            .is_none());
        assert!(handoffs
            .issue(flow, AdminIdentity::local_admin(), 260)
            .is_some());
    }

    #[tokio::test]
    async fn desktop_handoff_does_not_refresh_recreated_tenant_grants() {
        use axum::body::Body;
        use axum::http::Request;
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;

        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        let mut tenant = crate::store::tests::test_tenant("acme");
        tenant.admin_group = Some("editors".into());
        application.store.insert_tenant(tenant.clone()).unwrap();
        let identity = finish_sso_login(
            &application.store,
            "editor",
            "viewer".into(),
            &["editors".into()],
            false,
        )
        .unwrap();
        let original = application
            .store
            .tenant("acme")
            .unwrap()
            .unwrap()
            .incarnation;
        assert_eq!(
            identity.grants[1].incarnation.as_deref(),
            Some(original.as_str())
        );
        let verifier = "ab".repeat(32);
        let target = application
            .desktop_sign_ins
            .issue(
                DesktopFlow {
                    challenge: sha2::Sha256::digest(verifier.as_bytes()).into(),
                    state: "cd".repeat(16),
                },
                identity,
                crate::store::now_unix(),
            )
            .unwrap();
        let code = target
            .strip_prefix("votport://signin/")
            .unwrap()
            .split('?')
            .next()
            .unwrap()
            .to_owned();
        application.store.remove_tenant("acme").unwrap();
        application.store.insert_tenant(tenant).unwrap();
        assert_ne!(
            application
                .store
                .tenant("acme")
                .unwrap()
                .unwrap()
                .incarnation,
            original
        );
        let response = sso_exchange(
            State(application.clone()),
            axum::Json(ExchangeParams { code, verifier }),
        )
        .await
        .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let cookie = payload["cookie"].as_str().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookie.parse().unwrap());
        let session = super::super::admin::require_admin(&application, &headers).unwrap();
        assert_eq!(session.tenant, "");
        assert_eq!(session.role, "viewer");
        assert_eq!(session.grants.len(), 1);
        assert_eq!(session.grants[0].tenant, "");
        for (method, uri, body) in [
            ("POST", "/api/admin/tenant", r#"{"tenant":"acme"}"#),
            ("GET", "/api/admin/branding/acme", ""),
        ] {
            let response = crate::app::router(application.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header(header::COOKIE, cookie)
                        .header("x-votport", "1")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {uri}");
        }
    }

    #[test]
    fn desktop_start_requires_a_complete_valid_binding() {
        assert!(StartParams::default().desktop().unwrap().is_none());
        let challenge = "ab".repeat(32);
        let state = "cd".repeat(16);
        assert!(StartParams {
            desktop_challenge: Some(challenge.clone()),
            desktop_state: Some(state.clone())
        }
        .desktop()
        .unwrap()
        .is_some());
        for (desktop_challenge, desktop_state) in [
            (Some(challenge.clone()), None),
            (None, Some(state.clone())),
            (Some("x".repeat(64)), Some(state.clone())),
            (Some("00".into()), Some(state.clone())),
            (Some(challenge.clone()), Some("x".repeat(32))),
            (Some(challenge), Some("00".into())),
        ] {
            assert!(StartParams {
                desktop_challenge,
                desktop_state
            }
            .desktop()
            .is_err());
        }
    }

    #[test]
    fn browser_login_keeps_both_session_and_state_cookies() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let response = browser_login_response(&app, "votport_admin=test-session".into());
        let cookies: Vec<_> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(
            cookies,
            ["votport_admin=test-session", &clear_state_cookie(&app)]
        );
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(response.headers()[header::LOCATION], "/");
    }

    #[test]
    fn callback_errors_use_fixed_codes() {
        for (reason, code) in [
            (
                "the identity provider refused the sign-in",
                "provider_refused",
            ),
            ("missing code or state", "state_invalid"),
            ("stale or missing sign-in state", "state_invalid"),
            ("stale sign-in state", "state_invalid"),
            ("sign-in timed out; try again", "state_invalid"),
            ("invalid sign-in state", "state_invalid"),
            ("invalid desktop sign-in state", "state_invalid"),
            ("SSO is not configured", "not_configured"),
            ("SSO is unavailable", "unavailable"),
            ("token exchange failed", "unavailable"),
            (
                "too many pending desktop sign-ins; try again shortly",
                "unavailable",
            ),
            (
                "the identity provider is misconfigured",
                "provider_misconfigured",
            ),
            ("no id token in response", "provider_misconfigured"),
            ("identity could not be verified", "identity_unverified"),
            ("could not verify group membership", "groups_unverified"),
            ("this account is blocked", "account_blocked"),
            ("this account is not provisioned", "not_provisioned"),
            ("could not complete sign-in", "failed"),
            ("Contact attacker.invalid", "failed"),
        ] {
            assert_eq!(sso_error_code(reason), code, "{reason}");
        }
    }

    #[tokio::test]
    async fn sso_routes_share_a_budget_before_provider_calls_and_audit() {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::Request;
        use http_body_util::BodyExt as _;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tower::ServiceExt as _;

        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let metadata = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        });
        let provider = axum::Router::new().fallback(move |uri: axum::http::Uri| {
            seen.fetch_add(1, Ordering::Relaxed);
            let metadata = metadata.clone();
            async move {
                match uri.path() {
                    "/.well-known/openid-configuration" => axum::Json(metadata).into_response(),
                    "/jwks" => axum::Json(json!({"keys": []})).into_response(),
                    "/token" => (
                        StatusCode::BAD_REQUEST,
                        axum::Json(json!({"error": "invalid_grant"})),
                    )
                        .into_response(),
                    _ => panic!("unexpected provider request: {uri}"),
                }
            }
        });
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move { axum::serve(listener, provider).await.unwrap() });
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.oidc = Some(crate::config::OidcConfig {
            issuer,
            client_id: "votport".into(),
            client_secret: "secret".into(),
            admin_group: None,
            auditor_group: None,
            subject_claim: crate::config::SubjectClaim::Sub,
        });
        let app = crate::app::build(config).unwrap();
        let router = crate::app::router(Arc::clone(&app));
        let peer: std::net::SocketAddr = "198.51.100.1:1234".parse().unwrap();
        let mut callback = String::new();
        let mut cookie = String::new();
        for flow in 0..100 {
            let start = if flow % 2 == 0 {
                "/api/admin/sso/start".to_owned()
            } else {
                format!(
                    "/api/admin/sso/start?desktop_challenge={}&desktop_state={}",
                    "ab".repeat(32),
                    "cd".repeat(16)
                )
            };
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                router.clone().oneshot(
                    Request::get(start)
                        .extension(ConnectInfo(peer))
                        .body(Body::empty())
                        .unwrap(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status(), StatusCode::FOUND, "start {flow}");
            cookie = response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            let redirect =
                reqwest::Url::parse(response.headers()[header::LOCATION].to_str().unwrap())
                    .unwrap();
            let state = redirect
                .query_pairs()
                .find(|(name, _)| name == "state")
                .unwrap()
                .1;
            callback = format!("/api/admin/callback?code=junk&state={state}");
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                router.clone().oneshot(
                    Request::get(&callback)
                        .extension(ConnectInfo(peer))
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status(), StatusCode::FOUND, "callback {flow}");
            assert_eq!(
                response.headers()[header::LOCATION],
                "/?sso_error=unavailable"
            );
        }
        assert_eq!(calls.load(Ordering::Relaxed), 102);
        assert_eq!(app.store.audit_recent(None, 0, 1000).unwrap().len(), 100);
        for path in [
            &callback,
            "/api/admin/sso/start",
            "/api/admin/callback?error=refused",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::get(path)
                        .extension(ConnectInfo(peer))
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
            assert_eq!(response.headers()[header::RETRY_AFTER], "600");
        }
        assert_eq!(calls.load(Ordering::Relaxed), 102);
        assert_eq!(app.store.audit_recent(None, 0, 1000).unwrap().len(), 100);
        let response = router
            .oneshot(
                Request::post("/api/admin/login")
                    .extension(ConnectInfo(peer))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("x-votport", "1")
                    .body(Body::from(
                        json!({"password": crate::api::testing::TEST_PASSWORD}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["ok"]
                .as_bool()
                .unwrap()
        );
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn sso_budget_uses_trusted_client_addresses_before_discovery() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.trusted_proxies = vec![crate::config::IpCidr::parse("10.0.0.1/32").unwrap()];
        config.oidc = Some(crate::config::OidcConfig {
            issuer: "invalid issuer".into(),
            client_id: "votport".into(),
            client_secret: "secret".into(),
            admin_group: None,
            auditor_group: None,
            subject_claim: crate::config::SubjectClaim::Sub,
        });
        let mut app = crate::app::build(config).unwrap();
        std::sync::Arc::get_mut(&mut app).unwrap().sso_rate =
            super::super::session_rate::SessionRate::with_limit(2);
        let router = crate::app::router(std::sync::Arc::clone(&app));
        for (peer, forwarded, denied) in [
            ("198.51.100.1:1", "203.0.113.1", false),
            ("198.51.100.1:2", "203.0.113.2", false),
            ("198.51.100.1:3", "203.0.113.3", true),
            ("198.51.100.2:1", "203.0.113.3", false),
            ("10.0.0.2:1", "203.0.113.1", false),
            ("10.0.0.2:2", "203.0.113.2", false),
            ("10.0.0.2:3", "203.0.113.3", true),
            ("10.0.0.1:1", "192.0.2.1, 203.0.113.1", false),
            ("10.0.0.1:2", "192.0.2.2, 203.0.113.1", false),
            ("10.0.0.1:3", "192.0.2.3, 203.0.113.1", true),
            ("10.0.0.1:4", "192.0.2.3, 203.0.113.2", false),
            ("[2001:db8:1::1]:1", "", false),
            ("[2001:db8:1::2]:2", "", false),
            ("[2001:db8:1::3]:3", "", true),
            ("[2001:db8:2::1]:1", "", false),
        ] {
            let path = if denied {
                "/api/admin/sso/start"
            } else {
                "/api/admin/callback"
            };
            let response = router
                .clone()
                .oneshot(
                    Request::get(path)
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
                    StatusCode::FOUND
                },
                "{peer}, {forwarded}"
            );
        }
        let attempted = std::sync::atomic::AtomicBool::new(false);
        let _ = app
            .sso_client
            .get_or_discover_with(|| async {
                attempted.store(true, std::sync::atomic::Ordering::Relaxed);
                Err("test discovery".into())
            })
            .await;
        assert!(
            attempted.load(std::sync::atomic::Ordering::Relaxed),
            "a refused start must leave discovery unattempted, outside its failure cooldown"
        );
        assert_eq!(app.store.audit_recent(None, 0, 1000).unwrap().len(), 11);
    }

    #[tokio::test]
    async fn callback_failure_redirects_with_a_code_and_clears_state() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let clear_state = clear_state_cookie(&app);
        let payload = r#"{"state":"test","nonce":"nonce","verifier":"verifier"}"#;
        let expired = format!(
            "{STATE_COOKIE}=0.{}.{}",
            hex::encode(payload),
            sign_payload(&app.secret, 0, payload)
        );
        let router = crate::app::router(app);
        for (query, cookie, code) in [
            ("?error=Contact%20attacker.invalid", "", "provider_refused"),
            ("", "", "state_invalid"),
            ("?code=test&state=test", "", "state_invalid"),
            ("?code=test&state=test", expired.as_str(), "state_invalid"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::get(format!("/api/admin/callback{query}"))
                        .extension(ConnectInfo(
                            "198.51.100.1:1234".parse::<std::net::SocketAddr>().unwrap(),
                        ))
                        .header(header::COOKIE, cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FOUND);
            assert_eq!(
                response.headers()[header::LOCATION],
                format!("/?sso_error={code}")
            );
            let cookies: Vec<_> = response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect();
            assert_eq!(cookies, [clear_state.as_str()]);
        }
    }

    #[test]
    fn azp_ok_when_absent_or_matching() {
        assert!(azp_ok(None, "votport"));
        assert!(azp_ok(Some("votport"), "votport"));
        assert!(!azp_ok(Some("other-client"), "votport"));
        assert!(!azp_ok(Some(""), "votport"));
    }

    #[test]
    fn state_cookie_clearing_matches_the_configured_transport() {
        let directory = tempfile::tempdir().unwrap();
        let https = crate::api::testing::build(directory.path());
        assert!(clear_state_cookie(&https).ends_with("; Secure"));

        let mut config = crate::api::testing::config(directory.path());
        config.data_dir = directory.path().join("http-data");
        config.receive_dir = directory.path().join("http-received");
        config.outbound_dir = directory.path().join("http-outbound");
        config.public_url = Some("http://127.0.0.1:8080".to_owned());
        let http = crate::app::build(config).unwrap();
        assert!(!clear_state_cookie(&http).ends_with("; Secure"));
    }

    #[tokio::test]
    async fn sso_available_reports_configured_and_health_without_discovering() {
        use axum::body::Body;
        use axum::http::Request;
        use http_body_util::BodyExt as _;
        use tower::ServiceExt;

        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        assert!(!application.sso_client.health_peek());
        let router = crate::app::router(application);
        let response = router
            .oneshot(Request::get("/api/admin/sso").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["available"], false);
        assert_eq!(json["sso_healthy"], false);
        assert_eq!(json["public_password_login"], true);
    }

    #[tokio::test]
    async fn sso_available_is_true_when_oidc_is_configured_even_if_unhealthy() {
        use axum::body::Body;
        use axum::http::Request;
        use http_body_util::BodyExt as _;
        use tower::ServiceExt;

        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::build(directory.path()).config.clone();
        config.data_dir = directory.path().join("data-oidc");
        config.receive_dir = directory.path().join("received-oidc");
        config.oidc = Some(crate::config::OidcConfig {
            issuer: "https://idp.example.com".to_owned(),
            client_id: "votport".to_owned(),
            client_secret: "secret".to_owned(),
            admin_group: None,
            auditor_group: None,
            subject_claim: crate::config::SubjectClaim::Sub,
        });
        let application = crate::app::build(config).unwrap();
        assert!(!application.sso_client.health_peek());
        let router = crate::app::router(application);
        let response = router
            .oneshot(Request::get("/api/admin/sso").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["available"], true);
        assert_eq!(json["sso_healthy"], false);
        assert_eq!(json["public_password_login"], true);
    }

    #[tokio::test]
    async fn sso_available_reads_public_password_login_from_the_overlay() {
        use axum::body::Body;
        use axum::http::Request;
        use http_body_util::BodyExt as _;
        use tower::ServiceExt;

        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        application
            .store
            .put_settings(
                "test",
                &[(
                    "public_password_login".to_owned(),
                    crate::store::SettingWrite::Set("0".to_owned()),
                )],
            )
            .unwrap();
        let router = crate::app::router(application);
        let response = router
            .oneshot(Request::get("/api/admin/sso").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["available"], false);
        assert_eq!(json["public_password_login"], false);
    }

    #[tokio::test]
    async fn local_password_login_works_when_public_password_login_is_false() {
        use axum::body::Body;
        use axum::extract::ConnectInfo;
        use axum::http::Request;
        use tower::ServiceExt;

        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        application
            .store
            .put_settings(
                "test",
                &[(
                    "public_password_login".to_owned(),
                    crate::store::SettingWrite::Set("0".to_owned()),
                )],
            )
            .unwrap();
        let router = crate::app::router(application);
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/login")
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        1234,
                    ))))
                    .body(Body::from(format!(
                        "{{\"password\":\"{}\"}}",
                        crate::api::testing::TEST_PASSWORD
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn role_mapping_follows_the_group_requirement() {
        let groups = ["employees".to_owned(), "platform-admins".to_owned()];
        // No required group: every principal is an admin.
        assert_eq!(sso_role(None, None, &groups), "admin");
        // auditor_group alone never demotes when admin_group is unset.
        assert_eq!(
            sso_role(None, Some("auditors"), &["auditors".to_owned()]),
            "admin"
        );
        assert_eq!(sso_role(None, None, &[]), "admin");
        assert_eq!(sso_role(Some("platform-admins"), None, &groups), "admin");
        assert_eq!(sso_role(Some("missing"), None, &groups), "viewer");
        assert_eq!(
            sso_role(Some("missing"), Some("auditors"), &["auditors".to_owned()],),
            "auditor"
        );
        // Admin membership outranks auditor membership.
        assert_eq!(
            sso_role(Some("platform-admins"), Some("platform-admins"), &groups,),
            "admin"
        );
        assert_eq!(
            sso_role(Some("platform-admins"), Some("aud"), &[]),
            "viewer"
        );
    }

    #[test]
    fn admin_tokens_bind_identity_and_version() {
        let secret = [7u8; 32];
        let identity = AdminIdentity {
            grants: vec![crate::auth::TenantGrant {
                incarnation: None,
                tenant: "acme".to_owned(),
                role: "viewer".to_owned(),
            }],
            subject: "user@example.com".to_owned(),
            tenant: "acme".to_owned(),
            role: "viewer".to_owned(),
            credential_version: 1,
        };
        let token = auth::issue_admin_token(&secret, &identity, "version-1");
        let (verified, _) = auth::verify_admin_token(&secret, "version-1", &token).unwrap();
        assert_eq!(verified.subject, identity.subject);
        assert_eq!(verified.tenant, identity.tenant);
        assert_eq!(verified.role, identity.role);
        // A credential rotation or role change evicts every token.
        assert!(auth::verify_admin_token(&secret, "version-2", &token).is_none());
        // Tokens for other identities do not verify under this one's MAC.
        let other = AdminIdentity {
            subject: "other".into(),
            ..identity.clone()
        };
        let token_b = auth::issue_admin_token(&secret, &other, "version-1");
        let swapped = token.replace(&hex::encode("user@example.com"), &hex::encode("other"));
        assert!(auth::verify_admin_token(&secret, "version-1", &swapped).is_none());
        drop(token_b);
    }

    #[test]
    fn blocked_subject_helper_matches_callback() {
        assert_eq!(blocked_principal_error(false), None);
        assert_eq!(
            blocked_principal_error(true),
            Some("this account is blocked")
        );
    }

    fn test_store() -> (tempfile::TempDir, crate::store::Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(directory.path()).unwrap();
        (directory, store)
    }

    fn sso_login_events(store: &crate::store::Store) -> Vec<String> {
        store
            .audit_export(None, 0, 0, 100)
            .unwrap()
            .into_iter()
            .filter(|row| row.event == "sso_login")
            .map(|row| row.subject)
            .collect()
    }

    #[test]
    fn reserved_sub_is_not_issued() {
        let (_directory, store) = test_store();
        let error = finish_sso_login(&store, "local", "admin".to_owned(), &[], false).unwrap_err();
        assert_eq!(error, "identity could not be verified");
        assert!(store.principal("local").unwrap().is_none());
        assert!(sso_login_events(&store).is_empty());
    }

    #[test]
    fn blocked_sign_in_is_not_audited_as_sso_login() {
        let (_directory, store) = test_store();
        store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        store.revoke_principal("user@example.com").unwrap();
        let error = finish_sso_login(&store, "user@example.com", "admin".to_owned(), &[], false)
            .unwrap_err();
        assert_eq!(error, "this account is blocked");
        assert_eq!(sso_error_code(error), "account_blocked");
        assert!(sso_login_events(&store).is_empty());
        let issued =
            finish_sso_login(&store, "ok@example.com", "viewer".to_owned(), &[], false).unwrap();
        assert_eq!(issued.subject, "ok@example.com");
        assert_eq!(sso_login_events(&store), vec!["ok@example.com".to_owned()]);
    }

    #[test]
    fn required_provisioning_refuses_unknown_subjects_and_admits_provisioned_ones() {
        let (_directory, store) = test_store();
        let error =
            finish_sso_login(&store, "new@example.com", "admin".to_owned(), &[], true).unwrap_err();
        assert_eq!(error, "this account is not provisioned");
        assert_eq!(sso_error_code(error), "not_provisioned");
        assert!(store.principal("new@example.com").unwrap().is_none());
        assert!(sso_login_events(&store).is_empty());

        assert!(store
            .provision_principal("new@example.com", Some("00u1"))
            .unwrap());
        let issued =
            finish_sso_login(&store, "new@example.com", "viewer".to_owned(), &[], true).unwrap();
        assert_eq!(issued.subject, "new@example.com");
        let row = store.principal("new@example.com").unwrap().unwrap();
        assert_eq!(row.source, "scim", "sign-in keeps the provisioning source");
        assert_eq!(row.external_id.as_deref(), Some("00u1"));
        assert!(row.created_at > 0);
        assert!(row.last_login_at >= row.created_at);

        // A blocked provisioned row is still refused as blocked.
        store.revoke_principal("new@example.com").unwrap();
        let error = finish_sso_login(&store, "new@example.com", "viewer".to_owned(), &[], true)
            .unwrap_err();
        assert_eq!(error, "this account is blocked");
    }

    #[test]
    fn scim_groups_join_the_claim_groups_without_duplicates() {
        let (_directory, store) = test_store();
        store
            .create_scim_group("votport-admins", None, &["u@example.com".to_owned()])
            .unwrap()
            .unwrap();
        store
            .create_scim_group("shared", None, &["u@example.com".to_owned()])
            .unwrap()
            .unwrap();
        let mut groups = vec!["shared".to_owned(), "idp-only".to_owned()];
        merge_scim_groups(&store, "u@example.com", &mut groups).unwrap();
        assert_eq!(groups, ["shared", "idp-only", "votport-admins"]);
        assert_eq!(
            sso_role(Some("votport-admins"), None, &groups),
            "admin",
            "a SCIM-only group grants the role"
        );
        let mut none = Vec::new();
        merge_scim_groups(&store, "other@example.com", &mut none).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn subject_selection_follows_the_configured_claim() {
        use crate::config::SubjectClaim;
        let pick = |claim, email: Option<&str>, username: Option<&str>| {
            select_subject(claim, "abc123", email, None, username).unwrap()
        };
        assert_eq!(
            pick(SubjectClaim::Sub, None, None).as_deref(),
            Some("abc123")
        );
        assert_eq!(
            pick(SubjectClaim::Sub, Some("e@x"), Some("u")).as_deref(),
            Some("abc123")
        );
        assert_eq!(
            pick(SubjectClaim::Email, Some(" e@x "), None).as_deref(),
            Some("e@x")
        );
        assert_eq!(pick(SubjectClaim::Email, None, Some("u")), None);
        assert_eq!(pick(SubjectClaim::Email, Some(""), None), None);
        assert_eq!(
            pick(SubjectClaim::PreferredUsername, Some("e@x"), Some("u")).as_deref(),
            Some("u")
        );
        assert_eq!(
            pick(SubjectClaim::PreferredUsername, Some("e@x"), None),
            None
        );

        // email_verified: false refuses; true or absent is accepted; other
        // claims ignore it.
        assert!(select_subject(SubjectClaim::Email, "s", Some("e@x"), Some(false), None).is_err());
        assert_eq!(
            select_subject(SubjectClaim::Email, "s", Some("e@x"), Some(true), None)
                .unwrap()
                .as_deref(),
            Some("e@x")
        );
        assert_eq!(
            select_subject(SubjectClaim::Sub, "s", Some("e@x"), Some(false), None)
                .unwrap()
                .as_deref(),
            Some("s")
        );
        assert_eq!(
            select_subject(
                SubjectClaim::PreferredUsername,
                "s",
                None,
                Some(false),
                Some("u")
            )
            .unwrap()
            .as_deref(),
            Some("u")
        );
    }
}
