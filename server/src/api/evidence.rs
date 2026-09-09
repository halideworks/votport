//! Recipient statements authenticate a device, not the behavior of arbitrary software.

use super::{admin, outbound, ApiError, ApiResult};
use crate::app::App;
use crate::delivery_protocol::{Challenge, Evidence};
use crate::store::now_unix;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    holder: String,
}

pub(crate) fn metadata_authorization(
    app: &App,
    grant: &crate::store::OutboundGrant,
    headers: &HeaderMap,
    manifest: &str,
    recipient: Option<&str>,
) -> ApiResult<Option<crate::delivery_protocol::SignedChallenge>> {
    let Some(holder) = headers
        .get("x-votport-device")
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(None);
    };
    if !crate::workflow::valid_holder(holder)
        || recipient.is_some_and(|recipient| recipient != holder)
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "metadata device must match the authorized recipient",
        ));
    }
    let now = now_unix();
    Ok(Some(app.signer.evidence_challenge(Challenge {
        origin: admin::base_url(app, headers),
        grant_id: grant.id.clone(),
        manifest: manifest.into(),
        holder: holder.into(),
        nonce: crate::auth::random_token(),
        issued_at: now,
        expires_at: now.saturating_add(7 * 86_400),
    })))
}

pub async fn challenge(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ChallengeRequest>,
) -> ApiResult<Response> {
    rate(&app, &headers, &peer)?;
    let key = hex::decode(&request.holder)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .and_then(|v| ed25519_dalek::VerifyingKey::from_bytes(&v).ok());
    if key.is_none() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid device public key",
        ));
    }
    let grant = outbound::readable_grant(&app, &token)?;
    outbound::require_grant_access(&app, &grant, &headers)?;
    if outbound::workflows::require_recipient(&app, &grant, &headers)?
        .is_some_and(|holder| holder != request.holder)
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "evidence holder must be the authenticated recipient",
        ));
    }
    let now = now_unix();
    let authorization = app.signer.evidence_challenge(Challenge {
        origin: admin::base_url(&app, &headers),
        grant_id: grant.id.clone(),
        manifest: app
            .store
            .delivery_manifest(&grant.id)
            .map_err(super::store_unavailable)?,
        holder: request.holder,
        nonce: crate::auth::random_token(),
        issued_at: now,
        expires_at: now.saturating_add(7 * 86_400),
    });
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(authorization)).into_response())
}

pub async fn submit(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(evidence): Json<Evidence>,
) -> ApiResult<Response> {
    rate(&app, &headers, &peer)?;
    let challenge = &evidence.authorization.challenge;
    let now = now_unix();
    if !evidence.verify(&app.signer.public_hex)
        || challenge.issued_at > now
        || (challenge.expires_at <= now
            && !app
                .store
                .delivery_evidence_recorded(&evidence.id())
                .map_err(super::store_unavailable)?)
        || challenge.expires_at.saturating_sub(challenge.issued_at) > 7 * 86_400
        || challenge.origin != admin::base_url(&app, &headers)
    {
        return Err(ApiError::unauthorized());
    }
    // A statement can arrive after expiry or revocation; it grants no file access.
    let inserted = app
        .store
        .record_delivery_evidence(&evidence, now)
        .map_err(|e| ApiError::new(StatusCode::CONFLICT, e))?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"id": evidence.id(), "recorded": true, "duplicate": !inserted})),
    )
        .into_response())
}

fn rate(app: &App, headers: &HeaderMap, peer: &std::net::SocketAddr) -> ApiResult<()> {
    let ip = super::client_ip(headers, peer, &app.config.trusted_proxies);
    if !app.automation_read_rate.allow(&ip) {
        return Err(
            ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too many evidence requests")
                .with_retry_after(600),
        );
    }
    Ok(())
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    after: Option<u64>,
    limit: Option<usize>,
}

pub async fn list(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    let grant = app
        .store
        .outbound_grant_by_id(&id)
        .map_err(super::store_unavailable)?
        .filter(|g| g.tenant == identity.tenant)
        .ok_or_else(ApiError::not_found)?;
    if let Some(job) = app
        .store
        .delivery_job(&id)
        .map_err(super::store_unavailable)?
    {
        let project = app
            .store
            .delivery_project(&identity.tenant, &job.project.id)
            .map_err(super::store_unavailable)?
            .ok_or_else(ApiError::not_found)?;
        if !project.allows(&identity.subject, "viewer", identity.role == "admin") {
            return Err(ApiError::not_found());
        }
    }
    let limit = page.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) || page.after.unwrap_or(0) > i64::MAX as u64 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid evidence page",
        ));
    }
    let evidence = app
        .store
        .delivery_evidence(&grant.id, page.after.unwrap_or(0), limit)
        .map_err(super::store_unavailable)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(json!({"manifest": app.store.delivery_manifest(&id).map_err(super::store_unavailable)?, "evidence": evidence}))).into_response())
}
