//! SCIM 2.0 Users (RFC 7643, RFC 7644) over the principals table.
//!
//! One resource type, User, keyed by `userName`, which must equal the OIDC
//! `sub` claim the identity provider issues at sign-in: the row a SCIM client
//! deactivates has to be the row `finish_sso_login` looks up. Deactivate and
//! delete both revoke (credential version bump plus blocked); a row is never
//! deleted, because `principal_allows` accepts a missing row at version 1
//! and a deleted subject could sign in again. Groups are not served: roles
//! come from the group claims at login.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::app::App;
use crate::auth;
use crate::store::Principal;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const CONTENT_TYPE: &str = "application/scim+json";
const MAX_PAGE: usize = 200;
const MAX_SUBJECT_BYTES: usize = 256;

#[derive(Debug)]
pub struct ScimError {
    status: StatusCode,
    detail: String,
}

impl ScimError {
    fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }

    fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail)
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "no such user")
    }

    fn store(error: String) -> Self {
        tracing::error!(target: "audit", event = "scim_store_failed", %error, "scim store call failed");
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "store unavailable")
    }
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        scim_json(
            self.status,
            json!({
                "schemas": [ERROR_SCHEMA],
                "status": self.status.as_u16().to_string(),
                "detail": self.detail,
            }),
        )
    }
}

type ScimResult<T> = Result<T, ScimError>;

fn scim_json(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    response
}

/// Every SCIM route is refused unless the stored (or env) token is set and
/// the bearer matches it byte for byte.
fn authorize(app: &App, headers: &HeaderMap) -> ScimResult<()> {
    let expected = app
        .store
        .resolved_settings(&app.config)
        .map_err(ScimError::store)?
        .scim_token;
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    match (expected, presented) {
        (Some(expected), Some(presented))
            if auth::constant_time_eq(expected.as_bytes(), presented.as_bytes()) =>
        {
            Ok(())
        }
        _ => {
            tracing::warn!(target: "audit", event = "scim_unauthorized", "scim bearer refused");
            Err(ScimError::new(StatusCode::UNAUTHORIZED, "invalid bearer"))
        }
    }
}

/// A userName usable as a principal subject. Refuses the break-glass
/// subject, which never comes from an identity provider.
fn admit_subject(value: Option<&Value>) -> ScimResult<String> {
    let subject = value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| ScimError::bad_request("userName is required"))?;
    // Interior whitespace means a display name was mapped, not a subject.
    if subject.len() > MAX_SUBJECT_BYTES
        || subject
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(ScimError::bad_request("userName is not acceptable"));
    }
    if subject == "local" {
        return Err(ScimError::bad_request(
            "the local administrator is not provisionable",
        ));
    }
    Ok(subject.to_owned())
}

/// SCIM `active` arrives as a bool from most clients and as the strings
/// "True"/"False" from Entra.
fn parse_active(value: &Value) -> ScimResult<bool> {
    match value {
        Value::Bool(active) => Ok(*active),
        Value::String(text) if text.eq_ignore_ascii_case("true") => Ok(true),
        Value::String(text) if text.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(ScimError::bad_request("active must be a boolean")),
    }
}

fn resource(principal: &Principal) -> Value {
    json!({
        "schemas": [USER_SCHEMA],
        "id": principal.subject,
        "userName": principal.subject,
        "active": !principal.blocked,
        "meta": { "resourceType": "User" },
    })
}

fn load(app: &App, subject: &str) -> ScimResult<Principal> {
    app.store
        .principal(subject)
        .map_err(ScimError::store)?
        .ok_or_else(ScimError::not_found)
}

/// Deactivate revokes: version bump plus blocked, so live sessions die and
/// a later SSO sign-in is refused. Activate unblocks. Returns whether the
/// row existed.
fn set_active(app: &App, subject: &str, active: bool) -> ScimResult<bool> {
    let (changed, event) = if active {
        (app.store.unblock_principal(subject), "principal_unblocked")
    } else {
        (app.store.revoke_principal(subject), "principal_revoked")
    };
    let changed = changed.map_err(ScimError::store)?;
    if changed {
        tracing::info!(target: "audit", event, subject = %subject, "principal updated by scim");
        app.store
            .audit("", "scim", event, subject, &json!({ "via": "scim" }));
    }
    Ok(changed)
}

pub async fn service_provider_config(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ScimResult<Response> {
    authorize(&app, &headers)?;
    Ok(scim_json(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_PAGE },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "Bearer token",
                "description": "The token set under System > Sign-in",
            }],
        }),
    ))
}

#[derive(Deserialize)]
pub struct ListQuery {
    filter: Option<String>,
    #[serde(rename = "startIndex")]
    start_index: Option<usize>,
    count: Option<usize>,
}

/// The one filter provisioning clients send: `userName eq "value"`.
fn filter_subject(filter: &str) -> ScimResult<String> {
    let rest = filter
        .trim()
        .get(..8)
        .filter(|head| head.eq_ignore_ascii_case("userName"))
        .and_then(|_| filter.trim().get(8..))
        .map(str::trim_start)
        .and_then(|rest| rest.strip_prefix("eq").or_else(|| rest.strip_prefix("EQ")))
        .map(str::trim)
        .and_then(|rest| rest.strip_prefix('"'))
        .and_then(|rest| rest.strip_suffix('"'))
        .filter(|value| !value.contains('"'))
        .ok_or_else(|| {
            ScimError::bad_request("only the filter userName eq \"value\" is supported")
        })?;
    Ok(rest.to_owned())
}

pub async fn list_users(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    authorize(&app, &headers)?;
    let start_index = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(MAX_PAGE).min(MAX_PAGE);
    let (rows, total) = match query.filter.as_deref() {
        Some(filter) => {
            let subject = filter_subject(filter)?;
            let rows: Vec<_> = app
                .store
                .principal(&subject)
                .map_err(ScimError::store)?
                .into_iter()
                .collect();
            let total = rows.len() as u64;
            (rows, total)
        }
        None => app
            .store
            .principals_page(count, start_index - 1, None)
            .map_err(ScimError::store)?,
    };
    let resources: Vec<_> = rows.iter().map(resource).collect();
    Ok(scim_json(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start_index,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    ))
}

pub async fn create_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ScimResult<Response> {
    authorize(&app, &headers)?;
    let subject = admit_subject(body.get("userName"))?;
    let active = body
        .get("active")
        .map(parse_active)
        .transpose()?
        .unwrap_or(true);
    if !app
        .store
        .provision_principal(&subject)
        .map_err(ScimError::store)?
    {
        return Err(ScimError::new(
            StatusCode::CONFLICT,
            "userName already exists",
        ));
    }
    tracing::info!(target: "audit", event = "principal_provisioned", subject = %subject, "principal created by scim");
    app.store.audit(
        "",
        "scim",
        "principal_provisioned",
        &subject,
        &json!({ "via": "scim" }),
    );
    if !active {
        set_active(&app, &subject, false)?;
    }
    Ok(scim_json(
        StatusCode::CREATED,
        resource(&load(&app, &subject)?),
    ))
}

pub async fn get_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    authorize(&app, &headers)?;
    Ok(scim_json(StatusCode::OK, resource(&load(&app, &id)?)))
}

/// PUT replaces the whole resource. userName is immutable here (it is the
/// identity the sign-in path keys on), so only `active` can change.
pub async fn replace_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ScimResult<Response> {
    authorize(&app, &headers)?;
    load(&app, &id)?;
    if admit_subject(body.get("userName"))? != id {
        return Err(ScimError::bad_request("userName cannot change"));
    }
    let active = body
        .get("active")
        .map(parse_active)
        .transpose()?
        .unwrap_or(true);
    set_active(&app, &id, active)?;
    Ok(scim_json(StatusCode::OK, resource(&load(&app, &id)?)))
}

/// Reads the `active` value out of one PatchOp operation: either
/// `{"op":"replace","path":"active","value":false}` or a pathless
/// `{"op":"replace","value":{"active":false}}`. None when the operation
/// touches attributes this server does not store.
fn patched_active(operation: &Value) -> ScimResult<Option<bool>> {
    let op = operation.get("op").and_then(Value::as_str).unwrap_or("");
    if !(op.eq_ignore_ascii_case("replace") || op.eq_ignore_ascii_case("add")) {
        return Ok(None);
    }
    let path = operation.get("path").and_then(Value::as_str);
    if path.is_some_and(|path| path.eq_ignore_ascii_case("userName")) {
        return Err(ScimError::bad_request("userName cannot change"));
    }
    let value = match path {
        Some(path) if path.eq_ignore_ascii_case("active") => operation.get("value"),
        Some(_) => None,
        None => operation.get("value").and_then(|value| value.get("active")),
    };
    value.map(parse_active).transpose()
}

pub async fn patch_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ScimResult<Response> {
    authorize(&app, &headers)?;
    load(&app, &id)?;
    let operations = body
        .get("Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| ScimError::bad_request("Operations is required"))?;
    let mut active = None;
    for operation in operations {
        if let Some(value) = patched_active(operation)? {
            active = Some(value);
        }
    }
    if let Some(active) = active {
        set_active(&app, &id, active)?;
    }
    Ok(scim_json(StatusCode::OK, resource(&load(&app, &id)?)))
}

pub async fn delete_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    authorize(&app, &headers)?;
    // Already-revoked rows answer 404 so a retried delete is idempotent to
    // the client while the tombstone stays in place.
    let principal = load(&app, &id)?;
    if principal.blocked {
        return Err(ScimError::not_found());
    }
    set_active(&app, &id, false)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use crate::api::testing;
    use crate::app;
    use crate::store::SettingWrite;

    const TOKEN: &str = "scim-secret-token";

    fn build(directory: &std::path::Path) -> Arc<App> {
        let application = testing::build(directory);
        application
            .store
            .put_settings(
                "test",
                &[("scim_token".to_owned(), SettingWrite::Set(TOKEN.to_owned()))],
            )
            .unwrap();
        application
    }

    async fn call(
        application: &Arc<App>,
        method: &str,
        uri: &str,
        bearer: Option<&str>,
        body: Option<(&str, &str)>,
    ) -> (StatusCode, Value, Option<String>) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(bearer) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        let request = match body {
            Some((content_type, text)) => request
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(text.to_owned())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = app::router(Arc::clone(application))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| value.to_str().unwrap().to_owned());
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json, content_type)
    }

    async fn scim(
        application: &Arc<App>,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> (StatusCode, Value) {
        let (status, json, _) = call(
            application,
            method,
            uri,
            Some(TOKEN),
            body.map(|text| ("application/scim+json", text)),
        )
        .await;
        (status, json)
    }

    #[tokio::test]
    async fn every_route_needs_the_configured_bearer() {
        let directory = tempfile::tempdir().unwrap();
        let unset = testing::build(directory.path());
        let (status, json, content_type) =
            call(&unset, "GET", "/scim/v2/Users", Some(TOKEN), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["schemas"][0], ERROR_SCHEMA);
        assert_eq!(json["status"], "401");
        assert_eq!(content_type.as_deref(), Some(CONTENT_TYPE));

        let application = build(directory.path());
        let user = Some(("application/scim+json", r#"{"userName":"a"}"#));
        let patch = Some((
            "application/scim+json",
            r#"{"Operations":[{"op":"replace","path":"active","value":false}]}"#,
        ));
        for (bearer, uri, method, body) in [
            (None, "/scim/v2/Users", "GET", None),
            (Some("wrong"), "/scim/v2/Users", "GET", None),
            (Some("scim-secret-toke"), "/scim/v2/Users", "GET", None),
            (Some("wrong"), "/scim/v2/ServiceProviderConfig", "GET", None),
            (None, "/scim/v2/Users", "POST", user),
            (Some("wrong"), "/scim/v2/Users/a", "GET", None),
            (Some("wrong"), "/scim/v2/Users/a", "PUT", user),
            (None, "/scim/v2/Users/a", "PATCH", patch),
            (Some("wrong"), "/scim/v2/Users/a", "DELETE", None),
        ] {
            let (status, _, _) = call(&application, method, uri, bearer, body).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {uri} {bearer:?}"
            );
        }
        assert!(application.store.principal("a").unwrap().is_none());
        let (status, json) =
            scim(&application, "GET", "/scim/v2/ServiceProviderConfig", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["patch"]["supported"], true);
    }

    #[tokio::test]
    async fn create_get_filter_and_conflict() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        let (status, json) = scim(
            &application,
            "POST",
            "/scim/v2/Users",
            Some(r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ok@example.com","externalId":"00u1","active":true}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
        assert_eq!(json["id"], "ok@example.com");
        assert_eq!(json["userName"], "ok@example.com");
        assert_eq!(json["active"], true);
        let row = application
            .store
            .principal("ok@example.com")
            .unwrap()
            .unwrap();
        assert_eq!(row.source, "scim");
        assert!(!row.blocked);
        assert!(application.store.principal_allows("ok@example.com", 1));

        let (status, json) = scim(&application, "GET", "/scim/v2/Users/ok@example.com", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["active"], true);

        let (status, json) = scim(
            &application,
            "GET",
            "/scim/v2/Users?filter=userName%20eq%20%22ok%40example.com%22&startIndex=1&count=100",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["schemas"][0], LIST_SCHEMA);
        assert_eq!(json["totalResults"], 1);
        assert_eq!(json["Resources"][0]["id"], "ok@example.com");

        let (status, json) = scim(
            &application,
            "GET",
            "/scim/v2/Users?filter=userName%20eq%20%22nobody%22",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["totalResults"], 0);
        assert_eq!(json["Resources"].as_array().unwrap().len(), 0);

        let (status, _) = scim(
            &application,
            "GET",
            "/scim/v2/Users?filter=emails%20co%20%22x%22",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, json) = scim(&application, "GET", "/scim/v2/Users", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["totalResults"], 1);
        assert_eq!(json["itemsPerPage"], 1);

        let (status, _) = scim(
            &application,
            "POST",
            "/scim/v2/Users",
            Some(r#"{"userName":"ok@example.com"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, _) = scim(&application, "GET", "/scim/v2/Users/missing", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn refuses_local_blank_and_renames() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        for body in [
            r#"{"userName":"local"}"#,
            r#"{"userName":"  "}"#,
            r#"{}"#,
            r#"{"userName":"Jane Doe"}"#,
            r#"{"userName":"ok","active":"maybe"}"#,
        ] {
            let (status, json) = scim(&application, "POST", "/scim/v2/Users", Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body} {json}");
        }
        assert!(application.store.principal("ok").unwrap().is_none());
        scim(
            &application,
            "POST",
            "/scim/v2/Users",
            Some(r#"{"userName":"ok"}"#),
        )
        .await;
        let (status, _) = scim(
            &application,
            "PUT",
            "/scim/v2/Users/ok",
            Some(r#"{"userName":"renamed","active":true}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = scim(
            &application,
            "PATCH",
            "/scim/v2/Users/ok",
            Some(r#"{"Operations":[{"op":"replace","path":"userName","value":"renamed"}]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(application.store.principal("renamed").unwrap().is_none());
        assert!(!application.store.principal("ok").unwrap().unwrap().blocked);
    }

    #[tokio::test]
    async fn deactivate_revokes_sessions_and_reactivate_unblocks() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        scim(
            &application,
            "POST",
            "/scim/v2/Users",
            Some(r#"{"userName":"u@example.com"}"#),
        )
        .await;
        // Okta shape: a path and a boolean.
        let (status, json) = scim(
            &application,
            "PATCH",
            "/scim/v2/Users/u@example.com",
            Some(r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["active"], false);
        let row = application
            .store
            .principal("u@example.com")
            .unwrap()
            .unwrap();
        assert!(row.blocked);
        assert_eq!(row.credential_version, 2);
        assert!(!application.store.principal_allows("u@example.com", 1));
        assert!(!application.store.principal_allows("u@example.com", 2));

        // Entra shape: no path, a value object, and the string "True".
        let (status, json) = scim(
            &application,
            "PATCH",
            "/scim/v2/Users/u@example.com",
            Some(
                r#"{"Operations":[{"op":"Replace","value":{"active":"True","displayName":"U"}}]}"#,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["active"], true);
        assert!(application.store.principal_allows("u@example.com", 2));

        // An operation on an attribute this server does not store is a no-op.
        let (status, json) = scim(
            &application,
            "PATCH",
            "/scim/v2/Users/u@example.com",
            Some(r#"{"Operations":[{"op":"replace","path":"displayName","value":"X"}]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["active"], true);
        let (status, _) = scim(
            &application,
            "PATCH",
            "/scim/v2/Users/u@example.com",
            Some(r#"{"nope":1}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // PUT with active false revokes again.
        let (status, json) = scim(
            &application,
            "PUT",
            "/scim/v2/Users/u@example.com",
            Some(r#"{"userName":"u@example.com","active":"false"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["active"], false);
        assert!(!application.store.principal_allows("u@example.com", 2));

        let (status, _) = scim(
            &application,
            "PATCH",
            "/scim/v2/Users/nobody",
            Some(r#"{"Operations":[]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_keeps_a_blocked_tombstone() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        let (status, _) = scim(
            &application,
            "POST",
            "/scim/v2/Users",
            Some(r#"{"userName":"gone@example.com","active":false}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(
            application
                .store
                .principal("gone@example.com")
                .unwrap()
                .unwrap()
                .blocked
        );
        scim(
            &application,
            "PATCH",
            "/scim/v2/Users/gone@example.com",
            Some(r#"{"Operations":[{"op":"replace","path":"active","value":true}]}"#),
        )
        .await;

        let (status, _) = scim(
            &application,
            "DELETE",
            "/scim/v2/Users/gone@example.com",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let row = application
            .store
            .principal("gone@example.com")
            .unwrap()
            .unwrap();
        assert!(
            row.blocked,
            "delete must leave a blocked row, not remove it"
        );
        assert!(!application.store.principal_allows("gone@example.com", 1));

        let (status, _) = scim(
            &application,
            "DELETE",
            "/scim/v2/Users/gone@example.com",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = scim(&application, "DELETE", "/scim/v2/Users/never", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Re-provisioning a deleted subject conflicts; the tombstone stays.
        let (status, _) = scim(
            &application,
            "POST",
            "/scim/v2/Users",
            Some(r#"{"userName":"gone@example.com"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(!application.store.principal_allows("gone@example.com", 1));
    }

    #[tokio::test]
    async fn plain_json_content_type_is_accepted_too() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        let (status, _, _) = call(
            &application,
            "POST",
            "/scim/v2/Users",
            Some(TOKEN),
            Some(("application/json", r#"{"userName":"j@example.com"}"#)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    #[test]
    fn filter_parser_accepts_the_one_shape() {
        assert_eq!(filter_subject(r#"userName eq "a b""#).unwrap(), "a b");
        assert_eq!(filter_subject(r#"  username EQ "x"  "#).unwrap(), "x");
        for bad in [
            r#"userName co "a""#,
            r#"userName eq a"#,
            r#"userName eq "a" and active eq true"#,
            r#"emails eq "a""#,
            r#"userName eq "a"b""#,
            "",
        ] {
            assert!(filter_subject(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn active_parser_handles_bools_and_entra_strings() {
        assert!(parse_active(&json!(true)).unwrap());
        assert!(!parse_active(&json!(false)).unwrap());
        assert!(parse_active(&json!("True")).unwrap());
        assert!(!parse_active(&json!("FALSE")).unwrap());
        assert!(parse_active(&json!(1)).is_err());
        assert!(parse_active(&json!("yes")).is_err());
    }
}
