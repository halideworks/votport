//! Public receipt verification: publish the signing key and check sidecar
//! bytes against this server's key. No cookies, no admin role, no payload
//! upload; the browser hashes any payload file itself.

use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::json;
use vot_receipt::{AssuranceLevel, CommitProfile, SubjectKind};

use crate::api::{client_ip, ApiError, ApiResult};
use crate::app::App;

pub async fn receipt_key(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    Json(json!({ "receipt_key": app.signer.public_hex }))
}

pub async fn verify_receipt(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    // Every POST consumes rate budget, including ones that will 422, same as
    // create_session. A folder of sidecars is not a batch API.
    let ip = client_ip(&headers, &peer, &app.config.trusted_proxies);
    // Full address: a quota, not a guessing throttle. See create_session.
    if !app.verify_rate.allow(&ip) {
        return Err(super::rate_limited("checks from your address", 600));
    }
    if body.is_empty() {
        return Err(not_a_receipt());
    }
    let decoded = match vot_receipt::decode_authenticated(&body) {
        Ok(decoded) => decoded,
        Err(
            vot_receipt::Error::TooLarge
            | vot_receipt::Error::InvalidEncoding
            | vot_receipt::Error::NonCanonical,
        ) => return Err(not_a_receipt()),
        Err(_) => return Err(uncheckable()),
    };
    let verified = match vot_receipt::verify_ed25519(&decoded, &app.signer.verifying_key()) {
        Ok(verified) => verified,
        Err(
            vot_receipt::Error::Authentication
            | vot_receipt::Error::UnexpectedScheme
            | vot_receipt::Error::InvalidKey,
        ) => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "This receipt was not issued by this server.",
            ))
        }
        Err(_) => return Err(uncheckable()),
    };
    let receipt = verified.receipt();
    let Some(subject_kind) = subject_kind_name(receipt.subject_kind) else {
        return Err(uncheckable());
    };
    let Some(assurance) = assurance_name(receipt.assurance) else {
        return Err(uncheckable());
    };
    let Some(profile) = profile_name(receipt.profile) else {
        return Err(uncheckable());
    };
    let suite = crate::session::suite_name(receipt.suite_id);
    tracing::info!(
        target: "audit",
        event = "receipt_checked",
        ok = true,
        suite = %suite,
        length = receipt.subject_length,
    );
    Ok(Json(json!({
        "ok": true,
        "suite": suite,
        "root": hex::encode(receipt.subject_digest),
        "length": receipt.subject_length,
        "subject_kind": subject_kind,
        "assurance": assurance,
        "profile": profile,
        "observed_at": receipt.observed_at,
    })))
}

fn not_a_receipt() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "This is not a vot-receipt.",
    )
}

fn uncheckable() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "This receipt could not be checked.",
    )
}

// Explicit lowercase names: the enums are repr(u8) with no Display, and
// Debug casing must never leak into the JSON. Unknown numerics cannot be
// named, so the caller treats them as uncheckable.
fn subject_kind_name(kind: SubjectKind) -> Option<&'static str> {
    match kind {
        SubjectKind::Object => Some("object"),
        SubjectKind::Package => Some("package"),
    }
}

fn assurance_name(level: AssuranceLevel) -> Option<&'static str> {
    match level {
        AssuranceLevel::Admitted => Some("admitted"),
        AssuranceLevel::TransitVerified => Some("transit_verified"),
        AssuranceLevel::Durable => Some("durable"),
        AssuranceLevel::AtRestVerified => Some("at_rest_verified"),
        AssuranceLevel::Published => Some("published"),
    }
}

fn profile_name(profile: CommitProfile) -> Option<&'static str> {
    match profile {
        CommitProfile::Fast => Some("fast"),
        CommitProfile::Balanced => Some("balanced"),
        CommitProfile::Strict => Some("strict"),
    }
}
