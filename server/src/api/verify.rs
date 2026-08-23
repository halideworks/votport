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
    let ip = client_ip(&headers, &peer);
    if !app.verify_rate.allow(&crate::api::throttle_key(&ip)) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many checks from your address; try again later",
        ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_names_are_lowercase_json_strings() {
        assert_eq!(subject_kind_name(SubjectKind::Object), Some("object"));
        assert_eq!(subject_kind_name(SubjectKind::Package), Some("package"));
        for (level, name) in [
            (AssuranceLevel::Admitted, "admitted"),
            (AssuranceLevel::TransitVerified, "transit_verified"),
            (AssuranceLevel::Durable, "durable"),
            (AssuranceLevel::AtRestVerified, "at_rest_verified"),
            (AssuranceLevel::Published, "published"),
        ] {
            assert_eq!(assurance_name(level), Some(name));
        }
        for (profile, name) in [
            (CommitProfile::Fast, "fast"),
            (CommitProfile::Balanced, "balanced"),
            (CommitProfile::Strict, "strict"),
        ] {
            assert_eq!(profile_name(profile), Some(name));
        }
    }

    #[test]
    fn error_mapping_sentences() {
        assert_eq!(not_a_receipt().message, "This is not a vot-receipt.");
        assert_eq!(uncheckable().message, "This receipt could not be checked.");
    }
}
