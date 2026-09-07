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

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::app::App;
use crate::auth;
use crate::store::{Principal, ScimGroup};

use sha2::{Digest, Sha256};

type Peer = ConnectInfo<std::net::SocketAddr>;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SPC_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const RESOURCE_TYPE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
const SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const CONTENT_TYPE: &str = "application/scim+json";
const MAX_PAGE: usize = 200;
const MAX_SUBJECT_BYTES: usize = 256;

#[derive(Debug)]
pub struct ScimError {
    status: StatusCode,
    detail: String,
    /// RFC 7644 3.12 scimType, set for the 400 and 409 classes it names.
    scim_type: Option<&'static str>,
}

impl ScimError {
    fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
            scim_type: None,
        }
    }

    fn typed(status: StatusCode, scim_type: &'static str, detail: impl Into<String>) -> Self {
        Self {
            scim_type: Some(scim_type),
            ..Self::new(status, detail)
        }
    }

    fn invalid_value(detail: impl Into<String>) -> Self {
        Self::typed(StatusCode::BAD_REQUEST, "invalidValue", detail)
    }

    fn mutability(detail: impl Into<String>) -> Self {
        Self::typed(StatusCode::BAD_REQUEST, "mutability", detail)
    }

    fn not_found(what: &str) -> Self {
        Self::new(StatusCode::NOT_FOUND, format!("no such {what}"))
    }

    fn store(error: String) -> Self {
        tracing::error!(target: "audit", event = "scim_store_failed", %error, "scim store call failed");
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "store unavailable")
    }
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let mut body = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.as_u16().to_string(),
            "detail": self.detail,
        });
        if let Some(scim_type) = self.scim_type {
            body["scimType"] = json!(scim_type);
        }
        scim_json(self.status, body)
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

const HASH_PREFIX: &str = "sha256:";

/// The stored form of a bearer: the settings row never holds the token.
pub(crate) fn hash_bearer(token: &str) -> String {
    format!(
        "{HASH_PREFIX}{}",
        hex::encode(Sha256::digest(token.as_bytes()))
    )
}

/// A stored hash matches by digest; an env value (never hashed) matches
/// byte for byte. Both comparisons are constant time.
fn bearer_matches(stored: &str, presented: &str) -> bool {
    if stored.is_empty() || presented.is_empty() {
        return false;
    }
    match stored.strip_prefix(HASH_PREFIX) {
        Some(digest) => {
            let presented = hex::encode(Sha256::digest(presented.as_bytes()));
            auth::constant_time_eq(digest.as_bytes(), presented.as_bytes())
        }
        None => auth::constant_time_eq(stored.as_bytes(), presented.as_bytes()),
    }
}

/// The client address the audit rows and the throttle key on.
fn client_ip(app: &App, headers: &HeaderMap, peer: &Peer) -> String {
    super::client_ip(headers, &peer.0, &app.config.trusted_proxies)
}

/// Every SCIM route is refused unless a current token is set and the bearer
/// matches it or the previous one. Only failures count against the client's
/// throttle bucket (a bearer is checked, not verified, so a correct
/// concurrent burst must never trip it); a match clears the bucket.
fn authorize(app: &App, headers: &HeaderMap, ip: &str) -> ScimResult<()> {
    let bucket = super::throttle_key(ip);
    let settings = app
        .store
        .resolved_settings(&app.config)
        .map_err(ScimError::store)?;
    // Checked after the settings read so the check-then-record window
    // holds a digest, not the store mutex: a wrong-bearer flood that queues
    // on the store cannot pass the gate together.
    if app.scim_throttle.locked(&bucket) {
        tracing::warn!(target: "audit", event = "scim_throttled", %ip, "scim bearer attempts throttled");
        return Err(ScimError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; wait a minute",
        ));
    }
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let refused = |what: &str| {
        // Counted only now, so a wrong or missing bearer is a failure and a
        // right one never is, however many are in flight.
        app.scim_throttle.claim(&bucket);
        tracing::warn!(target: "audit", event = "scim_unauthorized", %ip, "scim bearer {what}");
        ScimError::new(StatusCode::UNAUTHORIZED, "invalid bearer")
    };
    let Some(presented) = presented else {
        return Err(refused("missing"));
    };
    let current = settings
        .scim_token
        .as_deref()
        .is_some_and(|stored| bearer_matches(stored, presented));
    // The previous slot only bridges a rotation: with no current token the
    // endpoint is off, whatever the slot still holds.
    let previous = !current
        && settings.scim_token.is_some()
        && settings
            .scim_token_previous
            .as_deref()
            .is_some_and(|stored| bearer_matches(stored, presented));
    if !(current || previous) {
        return Err(refused("refused"));
    }
    app.scim_throttle.succeeded(&bucket);
    if previous {
        // Visible so the operator knows the client has not moved yet.
        tracing::info!(target: "audit", event = "scim_previous_token_used", %ip, "scim client authenticated with the previous token");
    }
    Ok(())
}

/// A userName usable as a principal subject. Refuses the break-glass
/// subject, which never comes from an identity provider.
fn admit_subject(value: Option<&Value>) -> ScimResult<String> {
    let subject = value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| ScimError::invalid_value("userName is required"))?;
    // Interior whitespace means a display name was mapped, not a subject.
    if subject.len() > MAX_SUBJECT_BYTES
        || subject
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(ScimError::invalid_value("userName is not acceptable"));
    }
    if subject == "local" {
        return Err(ScimError::invalid_value(
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
        _ => Err(ScimError::invalid_value("active must be a boolean")),
    }
}

/// Percent-encodes one path segment (RFC 3986 unreserved characters pass).
fn encode_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The absolute base for meta.location; the request path when no public
/// URL is configured (loopback deployments).
fn location(app: &App, path: &str) -> String {
    match app.config.public_url.as_deref() {
        Some(base) => format!("{}{path}", base.trim_end_matches('/')),
        None => path.to_owned(),
    }
}

fn resource(app: &App, principal: &Principal) -> Value {
    let mut meta = json!({
        "resourceType": "User",
        "location": location(app, &format!("/scim/v2/Users/{}", encode_segment(&principal.subject))),
    });
    if principal.created_at > 0 {
        meta["created"] = json!(crate::receipt::rfc3339(principal.created_at));
    }
    let mut resource = json!({
        "schemas": [USER_SCHEMA],
        "id": principal.subject,
        "userName": principal.subject,
        "active": !principal.blocked,
        "meta": meta,
    });
    if let Some(external_id) = &principal.external_id {
        resource["externalId"] = json!(external_id);
    }
    resource
}

/// externalId is optional and opaque; refuse only what could not be a
/// provider id.
fn admit_external_id(value: Option<&Value>) -> ScimResult<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => {
            let text = text.trim();
            if text.is_empty() {
                return Ok(None);
            }
            if text.len() > MAX_SUBJECT_BYTES || text.chars().any(char::is_control) {
                return Err(ScimError::invalid_value("externalId is not acceptable"));
            }
            Ok(Some(text.to_owned()))
        }
        Some(_) => Err(ScimError::invalid_value("externalId must be a string")),
    }
}

fn load(app: &App, subject: &str) -> ScimResult<Principal> {
    app.store
        .principal(subject)
        .map_err(ScimError::store)?
        .ok_or_else(|| ScimError::not_found("user"))
}

/// Deactivate revokes: version bump plus blocked, so live sessions die and
/// a later SSO sign-in is refused. Activate unblocks. Returns whether the
/// row existed.
fn set_active(app: &App, subject: &str, active: bool, ip: &str) -> ScimResult<bool> {
    let (changed, event) = if active {
        (app.store.unblock_principal(subject), "principal_unblocked")
    } else {
        (app.store.revoke_principal(subject), "principal_revoked")
    };
    let changed = changed.map_err(ScimError::store)?;
    if changed {
        tracing::info!(target: "audit", event, subject = %subject, %ip, "principal updated by scim");
        app.store.audit(
            "",
            "scim",
            event,
            subject,
            &json!({ "via": "scim", "ip": ip }),
        );
    }
    Ok(changed)
}

pub async fn service_provider_config(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
) -> ScimResult<Response> {
    authorize(&app, &headers, &client_ip(&app, &headers, &peer))?;
    Ok(scim_json(
        StatusCode::OK,
        json!({
            "schemas": [SPC_SCHEMA],
            "meta": {
                "resourceType": "ServiceProviderConfig",
                "location": location(&app, "/scim/v2/ServiceProviderConfig"),
            },
            "documentationUri": "https://github.com/halideworks/votport/blob/main/docs/deployment.md",
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

fn user_resource_type(app: &App) -> Value {
    json!({
        "schemas": [RESOURCE_TYPE_SCHEMA],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "description": "A principal that may sign in through the identity provider",
        "schema": USER_SCHEMA,
        "schemaExtensions": [],
        "meta": {
            "resourceType": "ResourceType",
            "location": location(app, "/scim/v2/ResourceTypes/User"),
        },
    })
}

fn user_schema(app: &App) -> Value {
    let attribute = |name: &str,
                     kind: &str,
                     mutability: &str,
                     uniqueness: &str,
                     required: bool,
                     description: &str| {
        json!({
            "name": name,
            "type": kind,
            "multiValued": false,
            "description": description,
            "required": required,
            "caseExact": true,
            "mutability": mutability,
            "returned": "default",
            "uniqueness": uniqueness,
        })
    };
    json!({
        "schemas": [SCHEMA_SCHEMA],
        "id": USER_SCHEMA,
        "name": "User",
        "description": "User account",
        "attributes": [
            attribute("userName", "string", "immutable", "server", true,
                "The principal subject; must equal the identity provider's configured subject claim"),
            attribute("externalId", "string", "readWrite", "none", false,
                "The provisioning system's identifier for the user"),
            attribute("active", "boolean", "readWrite", "none", false,
                "false revokes the principal: live sessions end and sign-in is refused"),
        ],
        "meta": {
            "resourceType": "Schema",
            "location": location(app, &format!("/scim/v2/Schemas/{USER_SCHEMA}")),
        },
    })
}

fn group_resource_type(app: &App) -> Value {
    json!({
        "schemas": [RESOURCE_TYPE_SCHEMA],
        "id": "Group",
        "name": "Group",
        "endpoint": "/Groups",
        "description": "A named set of principals; the name feeds the sign-in role mapping",
        "schema": GROUP_SCHEMA,
        "schemaExtensions": [],
        "meta": {
            "resourceType": "ResourceType",
            "location": location(app, "/scim/v2/ResourceTypes/Group"),
        },
    })
}

fn group_schema(app: &App) -> Value {
    json!({
        "schemas": [SCHEMA_SCHEMA],
        "id": GROUP_SCHEMA,
        "name": "Group",
        "description": "Group",
        "attributes": [
            {
                "name": "displayName",
                "type": "string",
                "multiValued": false,
                "description": "The group name; matched against the admin, auditor, and tenant admin group settings at sign-in",
                "required": true,
                "caseExact": true,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "server",
            },
            {
                "name": "externalId",
                "type": "string",
                "multiValued": false,
                "description": "The provisioning system's identifier for the group",
                "required": false,
                "caseExact": true,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
            },
            {
                "name": "members",
                "type": "complex",
                "multiValued": true,
                "description": "Member users, by id",
                "required": false,
                "mutability": "readWrite",
                "returned": "default",
                "subAttributes": [{
                    "name": "value",
                    "type": "string",
                    "multiValued": false,
                    "description": "The member user's id",
                    "required": true,
                    "caseExact": true,
                    "mutability": "immutable",
                    "returned": "default",
                    "uniqueness": "none",
                }],
            },
        ],
        "meta": {
            "resourceType": "Schema",
            "location": location(app, &format!("/scim/v2/Schemas/{GROUP_SCHEMA}")),
        },
    })
}

fn list_response(resources: Vec<Value>) -> Value {
    json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": resources.len(),
        "startIndex": 1,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

pub async fn resource_types(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
) -> ScimResult<Response> {
    authorize(&app, &headers, &client_ip(&app, &headers, &peer))?;
    Ok(scim_json(
        StatusCode::OK,
        list_response(vec![user_resource_type(&app), group_resource_type(&app)]),
    ))
}

pub async fn resource_type(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    match id.as_str() {
        "User" => Ok(scim_json(StatusCode::OK, user_resource_type(&app))),
        "Group" => Ok(scim_json(StatusCode::OK, group_resource_type(&app))),
        _ => Err(ScimError::not_found("resource type")),
    }
}

pub async fn schemas(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
) -> ScimResult<Response> {
    authorize(&app, &headers, &client_ip(&app, &headers, &peer))?;
    Ok(scim_json(
        StatusCode::OK,
        list_response(vec![user_schema(&app), group_schema(&app)]),
    ))
}

pub async fn schema(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    match id.as_str() {
        USER_SCHEMA => Ok(scim_json(StatusCode::OK, user_schema(&app))),
        GROUP_SCHEMA => Ok(scim_json(StatusCode::OK, group_schema(&app))),
        _ => Err(ScimError::not_found("schema")),
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    filter: Option<String>,
    #[serde(rename = "startIndex")]
    start_index: Option<usize>,
    count: Option<usize>,
}

/// Which attribute an equality filter names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FilterKey {
    UserName,
    ExternalId,
}

/// The filters provisioning clients send: `userName eq "value"` and
/// `externalId eq "value"`.
fn filter_subject(filter: &str) -> ScimResult<(FilterKey, String)> {
    let filter = filter.trim();
    let (key, rest) = if filter
        .get(..8)
        .is_some_and(|head| head.eq_ignore_ascii_case("userName"))
    {
        (FilterKey::UserName, filter.get(8..))
    } else if filter
        .get(..10)
        .is_some_and(|head| head.eq_ignore_ascii_case("externalId"))
    {
        (FilterKey::ExternalId, filter.get(10..))
    } else {
        (FilterKey::UserName, None)
    };
    let rest = rest
        .map(str::trim_start)
        .and_then(|rest| rest.strip_prefix("eq").or_else(|| rest.strip_prefix("EQ")))
        .map(str::trim)
        .and_then(|rest| rest.strip_prefix('"'))
        .and_then(|rest| rest.strip_suffix('"'))
        .filter(|value| !value.contains('"'))
        .ok_or_else(|| {
            ScimError::typed(
                StatusCode::BAD_REQUEST,
                "invalidFilter",
                "only the filters userName eq \"value\" and externalId eq \"value\" are supported",
            )
        })?;
    Ok((key, rest.to_owned()))
}

pub async fn list_users(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    authorize(&app, &headers, &client_ip(&app, &headers, &peer))?;
    let start_index = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(MAX_PAGE).min(MAX_PAGE);
    let (rows, total) = match query.filter.as_deref() {
        Some(filter) => {
            let (key, value) = filter_subject(filter)?;
            let found = match key {
                FilterKey::UserName => app.store.principal(&value),
                FilterKey::ExternalId => app.store.principal_by_external_id(&value),
            };
            let rows: Vec<_> = found.map_err(ScimError::store)?.into_iter().collect();
            let total = rows.len() as u64;
            (rows, total)
        }
        None => app
            .store
            .principals_page(count, start_index - 1, None)
            .map_err(ScimError::store)?,
    };
    let resources: Vec<_> = rows.iter().map(|row| resource(&app, row)).collect();
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
    peer: Peer,
    Json(body): Json<Value>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    let subject = admit_subject(body.get("userName"))?;
    let external_id = admit_external_id(body.get("externalId"))?;
    let active = body
        .get("active")
        .map(parse_active)
        .transpose()?
        .unwrap_or(true);
    if !app
        .store
        .provision_principal(&subject, external_id.as_deref())
        .map_err(ScimError::store)?
    {
        return Err(ScimError::typed(
            StatusCode::CONFLICT,
            "uniqueness",
            "userName already exists",
        ));
    }
    tracing::info!(target: "audit", event = "principal_provisioned", subject = %subject, %ip, "principal created by scim");
    app.store.audit(
        "",
        "scim",
        "principal_provisioned",
        &subject,
        &json!({ "via": "scim", "ip": ip }),
    );
    if !active {
        set_active(&app, &subject, false, &ip)?;
    }
    Ok(scim_json(
        StatusCode::CREATED,
        resource(&app, &load(&app, &subject)?),
    ))
}

pub async fn get_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    Ok(scim_json(StatusCode::OK, resource(&app, &load(&app, &id)?)))
}

/// PUT replaces the whole resource. userName is immutable here (it is the
/// identity the sign-in path keys on), so only `active` can change.
pub async fn replace_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    load(&app, &id)?;
    if admit_subject(body.get("userName"))? != id {
        return Err(ScimError::mutability("userName cannot change"));
    }
    let active = body
        .get("active")
        .map(parse_active)
        .transpose()?
        .unwrap_or(true);
    set_active(&app, &id, active, &ip)?;
    Ok(scim_json(StatusCode::OK, resource(&app, &load(&app, &id)?)))
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
        return Err(ScimError::mutability("userName cannot change"));
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
    peer: Peer,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    load(&app, &id)?;
    let operations = body
        .get("Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ScimError::typed(
                StatusCode::BAD_REQUEST,
                "invalidSyntax",
                "Operations is required",
            )
        })?;
    let mut active = None;
    for operation in operations {
        if let Some(value) = patched_active(operation)? {
            active = Some(value);
        }
    }
    if let Some(active) = active {
        set_active(&app, &id, active, &ip)?;
    }
    Ok(scim_json(StatusCode::OK, resource(&app, &load(&app, &id)?)))
}

pub async fn delete_user(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    // Already-revoked rows answer 404 so a retried delete is idempotent to
    // the client while the tombstone stays in place.
    let principal = load(&app, &id)?;
    if principal.blocked {
        return Err(ScimError::not_found("user"));
    }
    set_active(&app, &id, false, &ip)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ----------------------------------------------------------------- Groups

fn group_resource(app: &App, group: &ScimGroup) -> Value {
    let members: Vec<_> = group
        .members
        .iter()
        .map(|subject| {
            json!({
                "value": subject,
                "$ref": location(app, &format!("/scim/v2/Users/{}", encode_segment(subject))),
            })
        })
        .collect();
    let mut resource = json!({
        "schemas": [GROUP_SCHEMA],
        "id": group.id,
        "displayName": group.display_name,
        "members": members,
        "meta": {
            "resourceType": "Group",
            "location": location(app, &format!("/scim/v2/Groups/{}", group.id)),
            "created": crate::receipt::rfc3339(group.created_at),
        },
    });
    if let Some(external_id) = &group.external_id {
        resource["externalId"] = json!(external_id);
    }
    resource
}

fn admit_display_name(value: Option<&Value>) -> ScimResult<String> {
    let name = value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| ScimError::invalid_value("displayName is required"))?;
    if name.len() > MAX_SUBJECT_BYTES || name.chars().any(char::is_control) {
        return Err(ScimError::invalid_value("displayName is not acceptable"));
    }
    Ok(name.to_owned())
}

/// Member entries are `{"value": "<user id>"}`; the id is the subject.
fn admit_members(value: Option<&Value>) -> ScimResult<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_array()
        .ok_or_else(|| ScimError::invalid_value("members must be a list"))?;
    let mut members = Vec::with_capacity(entries.len());
    for entry in entries {
        let subject = entry
            .get("value")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|subject| !subject.is_empty())
            .ok_or_else(|| ScimError::invalid_value("each member needs a value"))?;
        if subject.len() > MAX_SUBJECT_BYTES || subject.chars().any(char::is_control) {
            return Err(ScimError::invalid_value("member value is not acceptable"));
        }
        members.push(subject.to_owned());
    }
    Ok(members)
}

fn load_group(app: &App, id: &str) -> ScimResult<ScimGroup> {
    app.store
        .scim_group(id)
        .map_err(ScimError::store)?
        .ok_or_else(|| ScimError::not_found("group"))
}

fn audit_group(app: &App, event: &str, group: &ScimGroup, ip: &str) {
    tracing::info!(target: "audit", event, group = %group.display_name, %ip, "scim group changed");
    app.store.audit(
        "",
        "scim",
        event,
        &group.display_name,
        &json!({ "via": "scim", "ip": ip, "id": group.id, "members": group.members.len() }),
    );
}

fn name_taken(error: String) -> ScimError {
    if error == crate::store::SCIM_GROUP_NAME_TAKEN {
        ScimError::typed(
            StatusCode::CONFLICT,
            "uniqueness",
            "displayName already exists",
        )
    } else {
        ScimError::store(error)
    }
}

/// The filter provisioning clients send for groups: `displayName eq "x"`.
fn filter_group_name(filter: &str) -> ScimResult<String> {
    let filter = filter.trim();
    filter
        .get(..11)
        .filter(|head| head.eq_ignore_ascii_case("displayName"))
        .and_then(|_| filter.get(11..))
        .map(str::trim_start)
        .and_then(|rest| rest.strip_prefix("eq").or_else(|| rest.strip_prefix("EQ")))
        .map(str::trim)
        .and_then(|rest| rest.strip_prefix('"'))
        .and_then(|rest| rest.strip_suffix('"'))
        .filter(|value| !value.contains('"'))
        .map(str::to_owned)
        .ok_or_else(|| {
            ScimError::typed(
                StatusCode::BAD_REQUEST,
                "invalidFilter",
                "only the filter displayName eq \"value\" is supported",
            )
        })
}

pub async fn list_groups(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    authorize(&app, &headers, &client_ip(&app, &headers, &peer))?;
    let start_index = query.start_index.unwrap_or(1).max(1);
    let count = query.count.unwrap_or(MAX_PAGE).min(MAX_PAGE);
    let (rows, total) = match query.filter.as_deref() {
        Some(filter) => {
            let name = filter_group_name(filter)?;
            let rows: Vec<_> = app
                .store
                .scim_group_by_name(&name)
                .map_err(ScimError::store)?
                .into_iter()
                .collect();
            let total = rows.len() as u64;
            (rows, total)
        }
        None => app
            .store
            .scim_groups_page(count, start_index - 1)
            .map_err(ScimError::store)?,
    };
    let resources: Vec<_> = rows.iter().map(|row| group_resource(&app, row)).collect();
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

pub async fn create_group(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Json(body): Json<Value>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    let display_name = admit_display_name(body.get("displayName"))?;
    let external_id = admit_external_id(body.get("externalId"))?;
    let members = admit_members(body.get("members"))?;
    let group = app
        .store
        .create_scim_group(&display_name, external_id.as_deref(), &members)
        .map_err(ScimError::store)?
        .ok_or_else(|| {
            ScimError::typed(
                StatusCode::CONFLICT,
                "uniqueness",
                "displayName already exists",
            )
        })?;
    audit_group(&app, "scim_group_created", &group, &ip);
    Ok(scim_json(StatusCode::CREATED, group_resource(&app, &group)))
}

pub async fn get_group(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    Ok(scim_json(
        StatusCode::OK,
        group_resource(&app, &load_group(&app, &id)?),
    ))
}

/// PUT replaces the name and the whole member list.
pub async fn replace_group(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    load_group(&app, &id)?;
    let display_name = admit_display_name(body.get("displayName"))?;
    let members = admit_members(body.get("members"))?;
    if !app
        .store
        .replace_scim_group(&id, Some(&display_name), Some(&members))
        .map_err(name_taken)?
    {
        return Err(ScimError::not_found("group"));
    }
    let group = load_group(&app, &id)?;
    audit_group(&app, "scim_group_replaced", &group, &ip);
    Ok(scim_json(StatusCode::OK, group_resource(&app, &group)))
}

/// One PatchOp operation on a group, reduced to what the store applies.
#[derive(Debug, Default, PartialEq, Eq)]
struct GroupPatch {
    display_name: Option<String>,
    add: Vec<String>,
    remove: Vec<String>,
    replace_members: Option<Vec<String>>,
}

/// Okta and Entra shapes: `replace` with a value object holding displayName
/// or members; `add`/`replace` with path "members" and a member list;
/// `remove` with path `members[value eq "id"]` or path "members" plus a
/// member list.
fn patch_group_operation(patch: &mut GroupPatch, operation: &Value) -> ScimResult<()> {
    let op = operation
        .get("op")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let path = operation.get("path").and_then(Value::as_str).map(str::trim);
    let value = operation.get("value");
    match (op.as_str(), path) {
        ("replace" | "add", None) => {
            if !value.is_some_and(Value::is_object) {
                return Err(ScimError::typed(
                    StatusCode::BAD_REQUEST,
                    "invalidValue",
                    "a pathless operation needs a value object",
                ));
            }
            if let Some(name) = value.and_then(|value| value.get("displayName")) {
                patch.display_name = Some(admit_display_name(Some(name))?);
            }
            if let Some(members) = value.and_then(|value| value.get("members")) {
                let members = admit_members(Some(members))?;
                if op == "replace" {
                    patch.replace_members = Some(members);
                } else {
                    patch.add.extend(members);
                }
            }
            Ok(())
        }
        ("replace" | "add", Some(path)) if path.eq_ignore_ascii_case("displayName") => {
            patch.display_name = Some(admit_display_name(value)?);
            Ok(())
        }
        ("replace", Some(path)) if path.eq_ignore_ascii_case("members") => {
            patch.replace_members = Some(admit_members(value)?);
            Ok(())
        }
        ("add", Some(path)) if path.eq_ignore_ascii_case("members") => {
            patch.add.extend(admit_members(value)?);
            Ok(())
        }
        ("remove", Some(path)) if path.eq_ignore_ascii_case("members") => {
            // No value removes every member (RFC 7644 3.5.2.2); a list
            // removes those members.
            match value {
                None => patch.replace_members = Some(Vec::new()),
                Some(_) => patch.remove.extend(admit_members(value)?),
            }
            Ok(())
        }
        ("remove", Some(path)) => {
            let subject = path
                .strip_prefix("members[")
                .and_then(|rest| rest.strip_suffix(']'))
                .map(str::trim)
                .and_then(|rest| rest.strip_prefix("value"))
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix("eq"))
                .map(str::trim)
                .and_then(|rest| rest.strip_prefix('"'))
                .and_then(|rest| rest.strip_suffix('"'))
                .filter(|subject| !subject.is_empty() && !subject.contains('"'))
                .ok_or_else(|| {
                    ScimError::typed(
                        StatusCode::BAD_REQUEST,
                        "invalidPath",
                        "remove supports members or members[value eq \"id\"]",
                    )
                })?;
            patch.remove.push(subject.to_owned());
            Ok(())
        }
        _ => Err(ScimError::typed(
            StatusCode::BAD_REQUEST,
            "invalidSyntax",
            "unsupported operation",
        )),
    }
}

pub async fn patch_group(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    load_group(&app, &id)?;
    let operations = body
        .get("Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ScimError::typed(
                StatusCode::BAD_REQUEST,
                "invalidSyntax",
                "Operations is required",
            )
        })?;
    let mut patch = GroupPatch::default();
    for operation in operations {
        patch_group_operation(&mut patch, operation)?;
    }
    if patch.display_name.is_some() || patch.replace_members.is_some() {
        app.store
            .replace_scim_group(
                &id,
                patch.display_name.as_deref(),
                patch.replace_members.as_deref(),
            )
            .map_err(name_taken)?;
    }
    if !(patch.add.is_empty() && patch.remove.is_empty()) {
        app.store
            .change_scim_group_members(&id, &patch.add, &patch.remove)
            .map_err(ScimError::store)?;
    }
    let group = load_group(&app, &id)?;
    audit_group(&app, "scim_group_patched", &group, &ip);
    Ok(scim_json(StatusCode::OK, group_resource(&app, &group)))
}

pub async fn delete_group(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    peer: Peer,
    Path(id): Path<String>,
) -> ScimResult<Response> {
    let ip = client_ip(&app, &headers, &peer);
    authorize(&app, &headers, &ip)?;
    let group = load_group(&app, &id)?;
    app.store.delete_scim_group(&id).map_err(ScimError::store)?;
    audit_group(&app, "scim_group_deleted", &group, &ip);
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
    const PEER: [u8; 4] = [127, 0, 0, 1];

    fn build(directory: &std::path::Path) -> Arc<App> {
        let application = testing::build(directory);
        application
            .store
            .put_settings(
                "test",
                &[(
                    "scim_token".to_owned(),
                    SettingWrite::Set(hash_bearer(TOKEN)),
                )],
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
        call_from(application, PEER, method, uri, bearer, body).await
    }

    async fn call_from(
        application: &Arc<App>,
        peer: [u8; 4],
        method: &str,
        uri: &str,
        bearer: Option<&str>,
        body: Option<(&str, &str)>,
    ) -> (StatusCode, Value, Option<String>) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .extension(ConnectInfo(std::net::SocketAddr::from((peer, 1234))));
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
        // One instance per data directory: a rebuild needs the first one's
        // clean-shutdown release, as a real restart would have done.
        crate::app::release_data_lock(&unset);
        drop(unset);

        let application = build(directory.path());
        let user = Some(("application/scim+json", r#"{"userName":"a"}"#));
        let patch = Some((
            "application/scim+json",
            r#"{"Operations":[{"op":"replace","path":"active","value":false}]}"#,
        ));
        // Each case from its own client, so the failure throttle (covered by
        // its own test) does not turn a later 401 into a 429 here.
        for (index, (bearer, uri, method, body)) in [
            (None, "/scim/v2/Users", "GET", None),
            (Some("wrong"), "/scim/v2/Users", "GET", None),
            (Some("scim-secret-toke"), "/scim/v2/Users", "GET", None),
            (Some("wrong"), "/scim/v2/ServiceProviderConfig", "GET", None),
            (None, "/scim/v2/Users", "POST", user),
            (Some("wrong"), "/scim/v2/Users/a", "GET", None),
            (Some("wrong"), "/scim/v2/Users/a", "PUT", user),
            (None, "/scim/v2/Users/a", "PATCH", patch),
            (Some("wrong"), "/scim/v2/Users/a", "DELETE", None),
        ]
        .into_iter()
        .enumerate()
        {
            let peer = [10, 1, 0, index as u8];
            let (status, _, _) = call_from(&application, peer, method, uri, bearer, body).await;
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
        assert_eq!(json["externalId"], "00u1");
        let row = application
            .store
            .principal("ok@example.com")
            .unwrap()
            .unwrap();
        assert_eq!(row.source, "scim");
        assert!(!row.blocked);
        assert_eq!(row.external_id.as_deref(), Some("00u1"));
        assert!(row.created_at > 0);
        assert!(application.store.principal_allows("ok@example.com", 1));
        let (status, json) = scim(
            &application,
            "GET",
            "/scim/v2/Users?filter=externalId%20eq%20%2200u1%22",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["totalResults"], 1);
        assert_eq!(json["Resources"][0]["userName"], "ok@example.com");
        let (status, _) = scim(
            &application,
            "POST",
            "/scim/v2/Users",
            Some(r#"{"userName":"bad","externalId":7}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

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
    fn filter_parser_accepts_username_and_external_id_only() {
        assert_eq!(
            filter_subject(r#"userName eq "a b""#).unwrap(),
            (FilterKey::UserName, "a b".to_owned())
        );
        assert_eq!(
            filter_subject(r#"  username EQ "x"  "#).unwrap(),
            (FilterKey::UserName, "x".to_owned())
        );
        assert_eq!(
            filter_subject(r#"externalId eq "00u1""#).unwrap(),
            (FilterKey::ExternalId, "00u1".to_owned())
        );
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

    #[tokio::test]
    async fn discovery_resources_and_meta_are_served() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        for uri in [
            "/scim/v2/ResourceTypes",
            "/scim/v2/ResourceTypes/User",
            "/scim/v2/Schemas",
            "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
        ] {
            let (status, _, _) = call(&application, "GET", uri, None, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
            let (status, json) = scim(&application, "GET", uri, None).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert!(json["schemas"][0].is_string(), "{uri}");
        }
        let (status, json) = scim(&application, "GET", "/scim/v2/Schemas", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["Resources"][0]["id"], USER_SCHEMA);
        assert_eq!(json["totalResults"], 2);
        assert_eq!(json["Resources"][1]["id"], GROUP_SCHEMA);
        let names: Vec<_> = json["Resources"][0]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|attribute| attribute["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["userName", "externalId", "active"]);
        let (status, json) = scim(&application, "GET", "/scim/v2/ResourceTypes/User", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["endpoint"], "/Users");
        assert_eq!(
            json["meta"]["location"],
            "https://drop.example.com/scim/v2/ResourceTypes/User"
        );
        let (status, json) = scim(&application, "GET", "/scim/v2/ResourceTypes/Group", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["endpoint"], "/Groups");
        let (status, _) = scim(&application, "GET", "/scim/v2/ResourceTypes/Nope", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = scim(&application, "GET", "/scim/v2/Schemas/nope", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, json) =
            scim(&application, "GET", "/scim/v2/ServiceProviderConfig", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["meta"]["resourceType"], "ServiceProviderConfig");

        let (status, json) = scim(
            &application,
            "POST",
            "/scim/v2/Users",
            Some(r#"{"userName":"a/b@example.com"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            json["meta"]["location"],
            "https://drop.example.com/scim/v2/Users/a%2Fb%40example.com"
        );
        let created = json["meta"]["created"].as_str().unwrap();
        assert!(created.ends_with('Z') && created.len() == 20, "{created}");
        let (status, json) = scim(
            &application,
            "GET",
            "/scim/v2/Users/a%2Fb@example.com",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["userName"], "a/b@example.com");
    }

    #[tokio::test]
    async fn errors_carry_scim_types() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        scim(
            &application,
            "POST",
            "/scim/v2/Users",
            Some(r#"{"userName":"t"}"#),
        )
        .await;
        let cases: [(&str, &str, Option<&str>, &str); 5] = [
            (
                "POST",
                "/scim/v2/Users",
                Some(r#"{"userName":"t"}"#),
                "uniqueness",
            ),
            (
                "POST",
                "/scim/v2/Users",
                Some(r#"{"userName":"local"}"#),
                "invalidValue",
            ),
            (
                "GET",
                "/scim/v2/Users?filter=emails%20co%20%22x%22",
                None,
                "invalidFilter",
            ),
            (
                "PUT",
                "/scim/v2/Users/t",
                Some(r#"{"userName":"u"}"#),
                "mutability",
            ),
            ("PATCH", "/scim/v2/Users/t", Some(r#"{}"#), "invalidSyntax"),
        ];
        for (method, uri, body, scim_type) in cases {
            let (status, json) = scim(&application, method, uri, body).await;
            assert!(status.is_client_error(), "{method} {uri}");
            assert_eq!(json["scimType"], scim_type, "{method} {uri} {json}");
        }
        let (_, json) = scim(&application, "GET", "/scim/v2/Users/missing", None).await;
        assert!(json.get("scimType").is_none(), "404 carries no scimType");
    }

    #[tokio::test]
    async fn failed_bearers_are_throttled_per_client_and_a_match_resets() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        let mut seen_429 = false;
        for _ in 0..20 {
            let (status, _, _) = call_from(
                &application,
                [10, 0, 0, 1],
                "GET",
                "/scim/v2/Users",
                Some("wrong"),
                None,
            )
            .await;
            if status == StatusCode::TOO_MANY_REQUESTS {
                seen_429 = true;
                break;
            }
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        assert!(seen_429, "repeated bad bearers never reached the throttle");
        // The locked bucket refuses even the right bearer; another client
        // is unaffected, and its correct bearer keeps its bucket clean.
        let (status, _, _) = call_from(
            &application,
            [10, 0, 0, 1],
            "GET",
            "/scim/v2/Users",
            Some(TOKEN),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        for _ in 0..20 {
            let (status, _, _) = call_from(
                &application,
                [10, 0, 0, 2],
                "GET",
                "/scim/v2/Users",
                Some(TOKEN),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn previous_token_stays_valid_until_cleared_and_env_token_is_plain() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        application
            .store
            .put_settings(
                "test",
                &[
                    (
                        "scim_token".to_owned(),
                        SettingWrite::Set(hash_bearer("new-token")),
                    ),
                    (
                        "scim_token_previous".to_owned(),
                        SettingWrite::Set(hash_bearer(TOKEN)),
                    ),
                ],
            )
            .unwrap();
        for bearer in [TOKEN, "new-token"] {
            let (status, _, _) =
                call(&application, "GET", "/scim/v2/Users", Some(bearer), None).await;
            assert_eq!(status, StatusCode::OK, "{bearer}");
        }
        application
            .store
            .put_settings(
                "test",
                &[(
                    "scim_token_previous".to_owned(),
                    SettingWrite::Set(String::new()),
                )],
            )
            .unwrap();
        let (status, _, _) = call(&application, "GET", "/scim/v2/Users", Some(TOKEN), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "cleared previous token");
        let (status, _, _) = call(
            &application,
            "GET",
            "/scim/v2/Users",
            Some("new-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // An env token is compared as given, and its hash is not a bearer.
        let mut config = testing::config(&directory.path().join("env"));
        config.scim_token = Some("env-token".to_owned());
        let env_app = app::build(config).unwrap();
        let (status, _, _) = call(&env_app, "GET", "/scim/v2/Users", Some("env-token"), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = call(
            &env_app,
            "GET",
            "/scim/v2/Users",
            Some(&hash_bearer("env-token")),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "the hash is not a bearer");

        // Clearing the current token turns the endpoint off even while the
        // previous slot still holds a digest.
        application
            .store
            .put_settings(
                "test",
                &[
                    ("scim_token".to_owned(), SettingWrite::Set(String::new())),
                    (
                        "scim_token_previous".to_owned(),
                        SettingWrite::Set(hash_bearer("new-token")),
                    ),
                ],
            )
            .unwrap();
        let (status, _, _) = call(
            &application,
            "GET",
            "/scim/v2/Users",
            Some("new-token"),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "no current token, no access"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_concurrent_burst_of_correct_bearers_is_never_throttled() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        let mut tasks = Vec::new();
        for _ in 0..24 {
            let application = Arc::clone(&application);
            tasks.push(tokio::spawn(async move {
                call_from(
                    &application,
                    [10, 0, 0, 9],
                    "GET",
                    "/scim/v2/Users",
                    Some(TOKEN),
                    None,
                )
                .await
                .0
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), StatusCode::OK);
        }
        // A wrong bearer afterwards is the first failure, not the sixth.
        let (status, _, _) = call_from(
            &application,
            [10, 0, 0, 9],
            "GET",
            "/scim/v2/Users",
            Some("wrong"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mutations_audit_the_client_address() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        let (status, _, _) = call_from(
            &application,
            [198, 51, 100, 7],
            "POST",
            "/scim/v2/Users",
            Some(TOKEN),
            Some((
                "application/scim+json",
                r#"{"userName":"audited","active":false}"#,
            )),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let rows = application.store.audit_export("", 0, 0, 100).unwrap();
        let events: Vec<_> = rows
            .iter()
            .filter(|row| row.subject == "audited")
            .map(|row| {
                (
                    row.event.clone(),
                    row.detail["ip"].as_str().map(str::to_owned),
                )
            })
            .collect();
        assert_eq!(
            events,
            [
                (
                    "principal_provisioned".to_owned(),
                    Some("198.51.100.7".to_owned())
                ),
                (
                    "principal_revoked".to_owned(),
                    Some("198.51.100.7".to_owned())
                ),
            ]
        );
    }

    #[test]
    fn bearer_matching_covers_hashed_and_plain_forms() {
        let hashed = hash_bearer("abc");
        assert!(hashed.starts_with("sha256:") && hashed.len() == 7 + 64);
        assert!(bearer_matches(&hashed, "abc"));
        assert!(!bearer_matches(&hashed, "abd"));
        assert!(!bearer_matches(&hashed, &hashed));
        assert!(bearer_matches("plain", "plain"));
        assert!(!bearer_matches("plain", "plain "));
        assert!(
            !bearer_matches("", ""),
            "an empty stored token matches nothing"
        );
    }

    #[tokio::test]
    async fn groups_are_created_listed_patched_and_feed_sign_in_groups() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(directory.path());
        let body = Some((
            "application/scim+json",
            r#"{"displayName":"g","Operations":[]}"#,
        ));
        // One client per case: the sixth failure from one address is a 429.
        for (index, (method, uri, body)) in [
            ("GET", "/scim/v2/Groups", None),
            ("POST", "/scim/v2/Groups", body),
            ("GET", "/scim/v2/Groups/x", None),
            ("PUT", "/scim/v2/Groups/x", body),
            ("PATCH", "/scim/v2/Groups/x", body),
            ("DELETE", "/scim/v2/Groups/x", None),
        ]
        .into_iter()
        .enumerate()
        {
            let (status, _, _) = call_from(
                &application,
                [10, 2, 0, index as u8],
                method,
                uri,
                None,
                body,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        }
        assert!(application
            .store
            .scim_groups_page(10, 0)
            .unwrap()
            .0
            .is_empty());

        let (status, json) = scim(
            &application,
            "POST",
            "/scim/v2/Groups",
            Some(r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"votport-admins","externalId":"00g1","members":[{"value":"a@example.com"},{"value":"b@example.com","display":"B"}]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
        let id = json["id"].as_str().unwrap().to_owned();
        assert_eq!(json["displayName"], "votport-admins");
        assert_eq!(json["externalId"], "00g1");
        assert_eq!(json["members"].as_array().unwrap().len(), 2);
        assert_eq!(json["members"][0]["value"], "a@example.com");
        assert_eq!(
            json["members"][0]["$ref"],
            "https://drop.example.com/scim/v2/Users/a%40example.com"
        );
        assert_eq!(
            json["meta"]["location"],
            format!("https://drop.example.com/scim/v2/Groups/{id}")
        );
        assert_eq!(
            application.store.scim_groups_of("a@example.com").unwrap(),
            ["votport-admins"]
        );

        let (status, json) = scim(
            &application,
            "POST",
            "/scim/v2/Groups",
            Some(r#"{"displayName":"votport-admins"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json["scimType"], "uniqueness");
        for body in [
            r#"{}"#,
            r#"{"displayName":"x","members":"no"}"#,
            r#"{"displayName":"x","members":[{"display":"only"}]}"#,
        ] {
            let (status, json) = scim(&application, "POST", "/scim/v2/Groups", Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(json["scimType"], "invalidValue", "{body}");
        }

        let (status, json) = scim(
            &application,
            "GET",
            "/scim/v2/Groups?filter=displayName%20eq%20%22votport-admins%22",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["totalResults"], 1);
        assert_eq!(json["Resources"][0]["id"], id);
        let (status, json) = scim(
            &application,
            "GET",
            "/scim/v2/Groups?filter=id%20eq%20%22x%22",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["scimType"], "invalidFilter");
        let (status, json) = scim(
            &application,
            "GET",
            "/scim/v2/Groups?startIndex=1&count=10",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["totalResults"], 1);

        // Okta: add members by path; remove one by filter path.
        let (status, json) = scim(
            &application,
            "PATCH",
            &format!("/scim/v2/Groups/{id}"),
            Some(r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"c@example.com"}]},{"op":"remove","path":"members[value eq \"a@example.com\"]"}]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let members: Vec<_> = json["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["value"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(members, ["b@example.com", "c@example.com"]);

        // Entra: pathless replace with a value object; remove with a list.
        let (status, json) = scim(
            &application,
            "PATCH",
            &format!("/scim/v2/Groups/{id}"),
            Some(r#"{"Operations":[{"op":"Replace","value":{"displayName":"admins"}},{"op":"Remove","path":"members","value":[{"value":"b@example.com"}]}]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["displayName"], "admins");
        assert_eq!(json["members"].as_array().unwrap().len(), 1);
        assert_eq!(json["members"][0]["value"], "c@example.com");

        // Replace the member list wholesale, then an unsupported op.
        let (status, json) = scim(
            &application,
            "PATCH",
            &format!("/scim/v2/Groups/{id}"),
            Some(r#"{"Operations":[{"op":"replace","path":"members","value":[{"value":"d@example.com"}]}]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["members"][0]["value"], "d@example.com");
        assert_eq!(json["members"].as_array().unwrap().len(), 1);
        for body in [
            r#"{"Operations":[{"op":"remove","path":"displayName"}]}"#,
            r#"{"Operations":[{"op":"move","path":"members"}]}"#,
            r#"{"nope":1}"#,
        ] {
            let (status, json) = scim(
                &application,
                "PATCH",
                &format!("/scim/v2/Groups/{id}"),
                Some(body),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(json["scimType"].is_string(), "{body} {json}");
        }

        // PUT replaces everything; a rename onto another group conflicts.
        scim(
            &application,
            "POST",
            "/scim/v2/Groups",
            Some(r#"{"displayName":"other"}"#),
        )
        .await;
        let (status, json) = scim(
            &application,
            "PUT",
            &format!("/scim/v2/Groups/{id}"),
            Some(r#"{"displayName":"other","members":[]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{json}");
        let (status, json) = scim(
            &application,
            "PUT",
            &format!("/scim/v2/Groups/{id}"),
            Some(r#"{"displayName":"renamed","members":[{"value":"e@example.com"}]}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["displayName"], "renamed");
        assert_eq!(
            application.store.scim_groups_of("e@example.com").unwrap(),
            ["renamed"]
        );
        assert!(application
            .store
            .scim_groups_of("d@example.com")
            .unwrap()
            .is_empty());

        let (status, _) = scim(
            &application,
            "DELETE",
            &format!("/scim/v2/Groups/{id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = scim(
            &application,
            "DELETE",
            &format!("/scim/v2/Groups/{id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = scim(&application, "GET", &format!("/scim/v2/Groups/{id}"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(application
            .store
            .scim_groups_of("e@example.com")
            .unwrap()
            .is_empty());

        let events: Vec<_> = application
            .store
            .audit_export("", 0, 0, 100)
            .unwrap()
            .into_iter()
            .filter(|row| row.event.starts_with("scim_group_"))
            .map(|row| row.event)
            .collect();
        assert_eq!(
            events.first().map(String::as_str),
            Some("scim_group_created")
        );
        assert_eq!(
            events.last().map(String::as_str),
            Some("scim_group_deleted")
        );
        assert!(events.iter().any(|event| event == "scim_group_patched"));
        assert!(events.iter().any(|event| event == "scim_group_replaced"));
    }

    #[test]
    fn group_patch_operations_reduce_to_store_changes() {
        let mut patch = GroupPatch::default();
        patch_group_operation(
            &mut patch,
            &json!({"op":"add","path":"members","value":[{"value":"a"}]}),
        )
        .unwrap();
        patch_group_operation(
            &mut patch,
            &json!({"op":"remove","path":"members[value eq \"b\"]"}),
        )
        .unwrap();
        patch_group_operation(
            &mut patch,
            &json!({"op":"replace","path":"displayName","value":"n"}),
        )
        .unwrap();
        assert_eq!(
            patch,
            GroupPatch {
                display_name: Some("n".to_owned()),
                add: vec!["a".to_owned()],
                remove: vec!["b".to_owned()],
                replace_members: None,
            }
        );
        let mut patch = GroupPatch::default();
        patch_group_operation(&mut patch, &json!({"op":"remove","path":"members"})).unwrap();
        assert_eq!(
            patch.replace_members,
            Some(Vec::new()),
            "remove-all clears the list"
        );
        let mut patch = GroupPatch::default();
        patch_group_operation(
            &mut patch,
            &json!({"op":"replace","value":{"members":[{"value":"z"}],"displayName":"m"}}),
        )
        .unwrap();
        assert_eq!(patch.replace_members, Some(vec!["z".to_owned()]));
        assert_eq!(patch.display_name.as_deref(), Some("m"));
        for bad in [
            json!({"op":"remove","path":"members[value co \"b\"]"}),
            json!({"op":"remove","path":"members[value eq b]"}),
            json!({"op":"add","path":"members","value":[{"value":""}]}),
            json!({"op":"replace","path":"displayName","value":""}),
            json!({"op":"add"}),
        ] {
            let mut patch = GroupPatch::default();
            assert!(patch_group_operation(&mut patch, &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn segment_encoding_keeps_unreserved_bytes_only() {
        assert_eq!(encode_segment("a-b_c.d~E9"), "a-b_c.d~E9");
        assert_eq!(encode_segment("a/b@x y"), "a%2Fb%40x%20y");
        assert_eq!(encode_segment("é"), "%C3%A9");
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
