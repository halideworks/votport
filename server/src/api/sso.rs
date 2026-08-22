//! OIDC single sign-in for the admin dashboard (phase 3 of
//! docs/multi-tenancy.md): discovery at first use, authorization-code flow
//! with PKCE, id-token verification by the openidconnect crate, and role
//! mapping from the provider's `groups` claim.
//!
//! Local password sign-in remains the zero-config default and the
//! break-glass path; this module only exists when VOTPORT_OIDC_* is set.
//!
//! Multi-client providers (Entra ID and friends) may require additional
//! per-client claims checks (azp, hd); with a single client_id configured,
//! the openidconnect crate's issuer/audience/nonce verification covers the
//! standard cases.

use std::fmt::Write as _;

use axum::extract::{Query, State};
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
use serde::Deserialize;
use serde_json::json;

use crate::app::{self, App};
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

/// Role from an optional required-group: no requirement means every
/// authenticated principal is an admin; otherwise membership decides.
fn sso_role(admin_group: Option<&str>, groups: &[String]) -> &'static str {
    match admin_group {
        None => "admin",
        Some(required) if groups.iter().any(|group| group == required) => "admin",
        Some(_) => "viewer",
    }
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Whether SSO sign-in is configured (drives the login-page button).
pub async fn sso_available(State(app): State<std::sync::Arc<App>>) -> Response {
    let available = app.sso_config.is_some();
    (
        [(header::CONTENT_TYPE, "application/json")],
        axum::Json(json!({ "available": available })),
    )
        .into_response()
}

const STATE_COOKIE: &str = "votport_sso_x";
const STATE_SECS: u64 = 600;

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
        .get_or_init(|| async move { app::discover_sso(&config, &public_url).await })
        .await;
    let client = client.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "SSO discovery failed at startup; check the logs",
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

pub async fn sso_start(State(app): State<std::sync::Arc<App>>) -> Response {
    match app.sso_config.clone() {
        Some(config) => start_flow(&app, config)
            .await
            .unwrap_or_else(|response| response),
        None => (StatusCode::NOT_FOUND, "SSO is not configured").into_response(),
    }
}

/// Finishes the flow: validates state, exchanges the code with the PKCE
/// verifier, maps groups to a role, issues the admin cookie, and returns to
/// the dashboard. Any failure redirects home with ?sso_error=...
pub async fn sso_callback(
    State(app): State<std::sync::Arc<App>>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
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
        let clear_state =
            format!("{STATE_COOKIE}=; Path=/api/admin; HttpOnly; SameSite=Lax; Max-Age=0");
        let target = if message.is_empty() {
            "/".to_owned()
        } else {
            format!("/?sso_error={}", hex::encode(message.as_bytes()))
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
    let payload =
        match auth::hex_decode(payload_hex).and_then(|bytes| String::from_utf8(bytes).ok()) {
            Some(payload) => payload,
            None => return home("invalid sign-in state"),
        };
    let expected = sign_payload(&app.secret, expires, &payload);
    if !auth::ct_eq(expected.as_bytes(), mac.as_bytes()) {
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
    let client = app
        .sso_client
        .get_or_init(|| async move { app::discover_sso(sso_config.0, &sso_config.1).await })
        .await;
    let Some(client) = client.as_ref() else {
        return home("SSO is unavailable");
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
    let subject = claims.subject().to_string();

    // Groups come from the userinfo endpoint; the id token may not carry them.
    let mut groups: Vec<String> = Vec::new();
    if let Some(url) = client.userinfo_url.clone() {
        let token = token_response.access_token().secret();
        if let Ok(response) = app.http.get(url).bearer_auth(token).send().await {
            if let Ok(value) = response.json::<serde_json::Value>().await {
                // OIDC Core 5.3.2: the userinfo sub must match the verified
                // id-token subject, or the response is not about this user.
                if value["sub"].as_str() != Some(subject.as_str()) {
                    tracing::warn!(target: "audit", event = "sso_failed", "userinfo sub mismatch");
                    return home("identity could not be verified");
                }
                if let Some(list) = value["groups"].as_array() {
                    groups.extend(
                        list.iter()
                            .filter_map(|entry| entry.as_str().map(str::to_owned)),
                    );
                }
            }
        }
    }

    let role = sso_role(sso_config.0.admin_group.as_deref(), &groups).to_owned();
    tracing::info!(
        target: "audit", event = "sso_login", subject = %subject, %role,
        "SSO sign-in succeeded"
    );
    // Login lands in the default tenant; switching happens post-login.
    app.store.audit(
        "",
        &subject,
        "sso_login",
        &subject,
        &json!({ "role": role }),
    );

    // Grant set: the default tenant (role from the global admin group),
    // plus every named tenant whose admin group the principal belongs to.
    let mut grants = vec![auth::TenantGrant {
        tenant: String::new(),
        role: role.clone(),
    }];
    for tenant in app.store.tenants() {
        let Some(required) = &tenant.admin_group else {
            continue;
        };
        if groups.iter().any(|group| group == required) {
            grants.push(auth::TenantGrant {
                tenant: tenant.key.clone(),
                role: "admin".to_owned(),
            });
        }
    }
    let identity = auth::AdminIdentity {
        subject,
        tenant: String::new(),
        role,
        grants,
    };
    let admin_cookie = super::admin::issue_admin_cookie(&app, &identity);
    let clear_state =
        format!("{STATE_COOKIE}=; Path=/api/admin; HttpOnly; SameSite=Lax; Max-Age=0");
    (
        [
            (header::SET_COOKIE, admin_cookie),
            (header::SET_COOKIE, clear_state),
            (header::LOCATION, "/".to_owned()),
        ],
        StatusCode::FOUND,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AdminIdentity;

    #[test]
    fn role_mapping_follows_the_group_requirement() {
        let groups = ["employees".to_owned(), "platform-admins".to_owned()];
        // No required group: every principal is an admin.
        assert_eq!(sso_role(None, &groups), "admin");
        assert_eq!(sso_role(None, &[]), "admin");
        assert_eq!(sso_role(Some("platform-admins"), &groups), "admin");
        assert_eq!(sso_role(Some("missing"), &groups), "viewer");
        assert_eq!(sso_role(Some("platform-admins"), &[]), "viewer");
    }

    #[test]
    fn admin_tokens_bind_identity_and_version() {
        let secret = [7u8; 32];
        let identity = AdminIdentity {
            grants: vec![crate::auth::TenantGrant {
                tenant: "acme".to_owned(),
                role: "viewer".to_owned(),
            }],
            subject: "user@example.com".to_owned(),
            tenant: "acme".to_owned(),
            role: "viewer".to_owned(),
        };
        let token = auth::issue_admin_token(&secret, &identity, "version-1");
        let verified = auth::verify_admin_token(&secret, "version-1", &token).unwrap();
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
}
