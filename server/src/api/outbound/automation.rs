//! Folder-scoped automation over the same library and delivery records as the apps.

use super::*;
use crate::store::AutomationOperation;
use hmac::{Hmac, Mac};
use serde::Serialize;

pub const PERMISSIONS: [&str; 4] = [
    "library:read",
    "deliveries:create",
    "deliveries:read",
    "deliveries:revoke",
];

// A cursor includes the admitted directory and its child filename.
const MAX_FILE_CURSOR_BYTES: usize = 4096;

pub(super) fn default_permissions() -> Vec<String> {
    vec!["deliveries:create".to_owned()]
}

pub(super) fn validate_permissions(mut permissions: Vec<String>) -> ApiResult<Vec<String>> {
    if permissions.is_empty()
        || permissions.len() > PERMISSIONS.len()
        || permissions
            .iter()
            .any(|p| !PERMISSIONS.contains(&p.as_str()))
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "choose one or more supported permissions",
        ));
    }
    permissions.sort();
    permissions.dedup();
    Ok(permissions)
}

fn authenticate(
    app: &App,
    headers: &HeaderMap,
    peer: std::net::SocketAddr,
    permission: Option<&str>,
) -> ApiResult<(AutomationToken, String)> {
    let ip = crate::api::client_ip(headers, &peer, &app.config.trusted_proxies);
    let rate = if permission == Some("deliveries:create") {
        &app.automation_rate
    } else {
        &app.automation_read_rate
    };
    if !rate.allow(&ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many automation requests; try again later",
        )
        .with_retry_after(600));
    }
    let refused = |reason: &str| {
        app.store.audit(
            "",
            "",
            "automation_refused",
            &ip,
            &json!({"reason": reason}),
        )
    };
    let bearer =
        automation_bearer(headers).inspect_err(|_| refused("missing or malformed bearer"))?;
    let token = app
        .store
        .authenticate_automation_token(&hash_token(&bearer), now_unix())
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(|| {
            refused("unknown, expired, or revoked token");
            ApiError::unauthorized()
        })?;
    if permission.is_some_and(|p| !token.permissions.iter().any(|allowed| allowed == p)) {
        app.store.audit(
            &token.tenant,
            &format!("automation:{}", token.id),
            "automation_refused",
            "",
            &json!({"reason": "permission denied", "permission": permission}),
        );
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "this token does not allow this operation",
        ));
    }
    Ok((token, bearer))
}

fn check_directory(app: &App, token: &AutomationToken, directory: &str) -> ApiResult<()> {
    if directory.len() > MAX_LIBRARY_DIRECTORY_INPUT_BYTES {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "directory is too long",
        ));
    }
    if let Some(scope) = &token.directory {
        if !within_scope(scope, directory) {
            app.store.audit(
                &token.tenant,
                &format!("automation:{}", token.id),
                "automation_refused",
                directory,
                &json!({"reason": "directory outside token scope", "scope": scope}),
            );
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "directory is outside this token's scope",
            ));
        }
    }
    Ok(())
}

pub async fn session(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let (token, _) = authenticate(&app, &headers, peer, None)?;
    Ok(Json(
        json!({"api_version": 1, "automation_token": public_automation_token(&token), "supported_permissions": PERMISSIONS, "max_page_size": 100}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesQuery {
    directory: Option<String>,
    after: Option<String>,
    limit: Option<usize>,
}

fn page_limit(limit: Option<usize>) -> ApiResult<usize> {
    let limit = limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "limit must be between 1 and 100",
        ));
    }
    Ok(limit)
}

pub async fn files(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<FilesQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let (token, _) = authenticate(&app, &headers, peer, Some("library:read"))?;
    let _operation = begin_outbound_operation(&app, &token.tenant)?;
    let directory = query
        .directory
        .unwrap_or_else(|| token.directory.clone().unwrap_or_default());
    check_directory(&app, &token, &directory)?;
    let limit = page_limit(query.limit)?;
    let after = query.after.unwrap_or_default();
    if after.len() > MAX_FILE_CURSOR_BYTES {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "cursor is too long",
        ));
    }
    let root = library_root(&app, &token.tenant);
    let path = if directory.is_empty() {
        root.clone()
    } else {
        automation_directory(&app, &token.tenant, &directory)?
    };
    if !library_root_safe(&root) || !library_directory_safe(&root, &path) {
        return Err(ApiError::not_found());
    }
    let (directories, files, has_more) = tokio::task::spawn_blocking(move || {
        direct_library_entries_page(&root, &path, &after, limit)
    })
    .await
    .map_err(|_| ApiError::internal("list outbound files failed"))?
    .map_err(|_| ApiError::internal("cannot read this library directory"))?;
    let next_cursor = has_more.then(|| {
        directories
            .iter()
            .map(String::as_str)
            .chain(files.iter().filter_map(|f| f["path"].as_str()))
            .max()
            .unwrap_or_default()
            .to_owned()
    });
    Ok(Json(
        json!({"directory": directory, "directories": directories, "files": files, "has_more": has_more, "next_cursor": next_cursor}),
    ))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationShareRequest {
    directory: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    max_downloads: Option<u64>,
    #[serde(default)]
    notify_on_download: bool,
    expires_days: u64,
    #[serde(default)]
    operation_id: Option<String>,
}

fn valid_operation_id(id: &str) -> bool {
    !id.is_empty()
        && !matches!(id, "." | "..")
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn keyed_hash(bearer: &str, purpose: &[u8], data: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(bearer.as_bytes()).expect("HMAC accepts any key length");
    mac.update(purpose);
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

fn delivery_token(bearer: &str, operation_id: &str) -> String {
    keyed_hash(bearer, b"votport-delivery-v1\0", operation_id.as_bytes())[..32].to_owned()
}

// ponytail: 64 stripes bound lock memory; unrelated operations can wait on a collision.
static SHARE_LOCKS: std::sync::LazyLock<[tokio::sync::Mutex<()>; 64]> =
    std::sync::LazyLock::new(|| std::array::from_fn(|_| tokio::sync::Mutex::new(())));

pub async fn automation_share(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(mut request): Json<AutomationShareRequest>,
) -> ApiResult<Response> {
    let (token, bearer) = authenticate(&app, &headers, peer, Some("deliveries:create"))?;
    let _operation = begin_outbound_operation(&app, &token.tenant)?;
    check_directory(&app, &token, &request.directory)?;
    if !(1..=30).contains(&request.expires_days) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "expires_days must be 1..=30",
        ));
    }
    validate_max_downloads(request.max_downloads)?;
    let operation_id = request
        .operation_id
        .get_or_insert_with(auth::random_token)
        .clone();
    if !valid_operation_id(&operation_id) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "operation_id must contain 1..=128 letters, digits, dots, hyphens or underscores",
        ));
    }
    let request_hash = keyed_hash(
        &bearer,
        b"votport-request-v1\0",
        &serde_json::to_vec(&request)
            .map_err(|_| ApiError::internal("encode automation request failed"))?,
    );
    let raw = delivery_token(&bearer, &operation_id);
    let stripe = usize::from(Sha256::digest(raw.as_bytes())[0]) % SHARE_LOCKS.len();
    let _lock = SHARE_LOCKS[stripe].lock().await;
    let token = app
        .store
        .authenticate_automation_token(&hash_token(&bearer), now_unix())
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::unauthorized)?;
    if let Some(previous) = app
        .store
        .automation_operation(&token.id, &operation_id)
        .map_err(crate::api::store_unavailable)?
    {
        if previous.request_hash != request_hash {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "operation_id was already used with different parameters",
            )
            .with_code("operation_conflict"));
        }
        return recover_response(&app, &headers, &token, &bearer, &previous);
    }
    let _grant_permit = app.outbound_grant_permits.try_acquire().map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many deliveries are being prepared; retry with the same operation_id",
        )
        .with_retry_after(1)
    })?;
    let directory = automation_directory(&app, &token.tenant, &request.directory)?;
    let root = library_root(&app, &token.tenant);
    let paths = tokio::task::spawn_blocking(move || {
        enumerate_automation_files(&root, &directory, MAX_LIBRARY_PROJECT_FILES)
    })
    .await
    .map_err(|_| ApiError::internal("enumerate outbound files failed"))??;
    let identity = auth::AdminIdentity {
        subject: format!("automation:{}", token.id),
        tenant: token.tenant.clone(),
        role: "admin".to_owned(),
        grants: Vec::new(),
        credential_version: 1,
    };
    let operation = AutomationOperation {
        token_id: token.id,
        operation_id,
        request_hash,
        grant_id: auth::random_token(),
    };
    create_library_grant(
        &app,
        &headers,
        &identity,
        &paths,
        MAX_LIBRARY_PROJECT_FILES,
        GrantOptions {
            automation: Some((operation, raw)),
            label: request
                .label
                .filter(|label| !label.trim().is_empty())
                .or_else(|| Some(library_directory_label(&request.directory))),
            password_hash: hash_optional_password(request.password.as_deref())?,
            expires_days: request.expires_days,
            max_downloads: request.max_downloads,
            notify_on_download: request.notify_on_download,
        },
    )
    .await
}

fn recover_response(
    app: &Arc<App>,
    headers: &HeaderMap,
    token: &AutomationToken,
    bearer: &str,
    operation: &AutomationOperation,
) -> ApiResult<Response> {
    let (_, current_hash) = owned_delivery(app, token, &operation.grant_id)?;
    let raw = delivery_token(bearer, &operation.operation_id);
    if current_hash != hash_token(&raw) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "the delivery link was rotated by an administrator",
        )
        .with_code("delivery_changed"));
    }
    let page = delivery_page(app, &current_hash, 0, OUTBOUND_GRANT_PREVIEW_FILES)?;
    let base = admin::base_url(app, headers);
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(json!({"operation_id": operation.operation_id, "grant": page["grant"], "url": format!("{base}/s/{raw}")}))).into_response())
}

pub async fn recover(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> ApiResult<Response> {
    let (token, bearer) = authenticate(&app, &headers, peer, Some("deliveries:create"))?;
    let _operation = begin_outbound_operation(&app, &token.tenant)?;
    let operation = app
        .store
        .automation_operation(&token.id, &id)
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    recover_response(&app, &headers, &token, &bearer, &operation)
}

fn owned_delivery(app: &App, token: &AutomationToken, id: &str) -> ApiResult<(String, String)> {
    app.store
        .automation_delivery(&token.id, id)
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::not_found)
}

fn delivery_page(
    app: &App,
    hash: &str,
    offset: usize,
    limit: usize,
) -> ApiResult<serde_json::Value> {
    let mut page = app
        .store
        .outbound_grant_files_page_by_token_hash(hash, offset, limit)
        .map_err(crate::api::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if offset == 0
        && page.file_count <= OUTBOUND_GRANT_PREVIEW_FILES
        && page.files.len() == page.file_count
    {
        page.grant.files = page.files.iter().map(|(_, file)| file.clone()).collect();
    }
    let has_more = offset.saturating_add(page.files.len()) < page.file_count;
    let state = if page.grant.revoked_at.is_some() {
        "revoked"
    } else if page.grant.expires_at <= now_unix() {
        "expired"
    } else {
        "active"
    };
    let files = page.files.iter().map(|(index, file)| json!({"index": index, "name": file.name, "suite": file.suite, "root": file.root, "bytes": file.bytes, "receipt_b64": file.receipt_b64, "download_starts": file.downloads, "first_download_at": file.first_download_at, "last_download_at": file.last_download_at})).collect::<Vec<_>>();
    Ok(
        json!({"grant": public_grant_with_file_count(page.grant, page.file_count), "state": state, "total_bytes": page.total_bytes, "files": files, "offset": offset, "has_more": has_more, "next_offset": has_more.then_some(offset + files.len())}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveriesQuery {
    after: Option<i64>,
    limit: Option<usize>,
}

pub async fn deliveries(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<DeliveriesQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let (token, _) = authenticate(&app, &headers, peer, Some("deliveries:read"))?;
    let _operation = begin_outbound_operation(&app, &token.tenant)?;
    let limit = page_limit(query.limit)?;
    let after = query.after.unwrap_or_default();
    if after < 0 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "after must be non-negative",
        ));
    }
    let mut rows = app
        .store
        .automation_deliveries(&token.id, after, limit + 1)
        .map_err(crate::api::store_unavailable)?;
    let has_more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = has_more.then(|| rows.last().map(|r| r.0)).flatten();
    let grants = rows.iter().map(|(_, _, hash)| delivery_page(&app, hash, 0, 0).map(|page| json!({"grant": page["grant"], "state": page["state"], "total_bytes": page["total_bytes"]}))).collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(
        json!({"deliveries": grants, "has_more": has_more, "next_cursor": next_cursor}),
    ))
}

pub async fn delivery(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<OutboundGrantsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let (token, _) = authenticate(&app, &headers, peer, Some("deliveries:read"))?;
    let _operation = begin_outbound_operation(&app, &token.tenant)?;
    let (limit, offset) = outbound_grants_paging(query)?;
    let (operation_id, hash) = owned_delivery(&app, &token, &id)?;
    let mut page = delivery_page(&app, &hash, offset, limit)?;
    page["operation_id"] = json!(operation_id);
    Ok(Json(page))
}

pub async fn revoke(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let (token, _) = authenticate(&app, &headers, peer, Some("deliveries:revoke"))?;
    let _operation = begin_outbound_operation(&app, &token.tenant)?;
    owned_delivery(&app, &token, &id)?;
    if app
        .store
        .revoke_outbound_grant(&token.tenant, &id, now_unix())
        .map_err(crate::api::store_unavailable)?
    {
        app.store.audit(
            &token.tenant,
            &format!("automation:{}", token.id),
            "outbound_grant_revoked",
            &id,
            &json!({}),
        );
    }
    Ok(Json(json!({"ok": true, "id": id, "state": "revoked"})))
}

pub async fn normalize_response(response: Response) -> Response {
    if response.status().is_client_error()
        && !response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|value| value.as_bytes().starts_with(b"application/json"))
    {
        return ApiError::new(
            response.status(),
            "request does not match the API; check the path, JSON body and query parameters",
        )
        .into_response();
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn request(
        app: &Arc<App>,
        method: &str,
        path: &str,
        token: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        8080,
                    ))))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes)})),
        )
    }

    fn token(app: &App, permissions: &[&str]) -> String {
        let raw = auth::random_token();
        app.store
            .insert_automation_token(AutomationToken {
                id: auth::random_token(),
                token_hash: hash_token(&raw),
                tenant: String::new(),
                label: "agent".to_owned(),
                directory: Some("project".to_owned()),
                permissions: permissions.iter().map(|s| s.to_string()).collect(),
                created_at: now_unix(),
                expires_at: now_unix() + 3600,
                revoked_at: None,
                last_used_at: None,
            })
            .unwrap();
        raw
    }

    #[tokio::test]
    async fn scoped_delivery_workflow_recovers_and_tracks_the_same_objects() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        std::fs::create_dir_all(app.config.outbound_dir.join("project/sub")).unwrap();
        std::fs::create_dir_all(app.config.outbound_dir.join("other")).unwrap();
        std::fs::write(app.config.outbound_dir.join("project/a.txt"), b"alpha").unwrap();
        std::fs::write(app.config.outbound_dir.join("project/sub/b.txt"), b"beta").unwrap();
        let raw = token(&app, &PERMISSIONS);
        let read_only = token(&app, &["library:read", "deliveries:read"]);
        let foreign = token(&app, &PERMISSIONS);
        let legacy = token(&app, &["deliveries:create"]);
        let (status, access) =
            request(&app, "GET", "/api/automation/session", &raw, json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(access["automation_token"]["directory"], "project");
        let (status, first) = request(
            &app,
            "GET",
            "/api/automation/files?limit=1",
            &raw,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["files"][0]["path"], "project/a.txt");
        assert_eq!(first["next_cursor"], "project/a.txt");
        let (_, second) = request(
            &app,
            "GET",
            "/api/automation/files?limit=1&after=project/a.txt",
            &raw,
            json!({}),
        )
        .await;
        assert_eq!(second["directories"], json!(["project/sub"]));
        assert_eq!(second["has_more"], false);
        for path in [
            "/api/automation/files?directory=other",
            "/api/automation/files?directory=project/../other",
            "/api/automation/files?directory=project-old",
        ] {
            assert!(!request(&app, "GET", path, &raw, json!({}))
                .await
                .0
                .is_success());
        }
        assert_eq!(
            request(&app, "GET", "/api/automation/files", &legacy, json!({}))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        for (method, path, payload) in [
            ("GET", "/api/automation/files?limit=nope", json!({})),
            (
                "POST",
                "/api/automation/share",
                json!({"directory": "project", "expires_days": 7, "unknown": true}),
            ),
        ] {
            let (status, error) = request(&app, method, path, &raw, payload).await;
            assert!(status.is_client_error());
            assert_eq!(error["code"], "invalid_request");
            assert_eq!(error["retryable"], false);
        }
        let spec = json!({"directory": "project", "expires_days": 7, "operation_id": "render-1"});
        assert_eq!(
            request(
                &app,
                "POST",
                "/api/automation/share",
                &read_only,
                spec.clone()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        let (first, replay) = tokio::join!(
            request(&app, "POST", "/api/automation/share", &raw, spec.clone()),
            request(&app, "POST", "/api/automation/share", &raw, spec.clone())
        );
        assert_eq!(first.0, StatusCode::OK, "{}", first.1);
        assert_eq!(replay.0, StatusCode::OK, "{}", replay.1);
        assert_eq!(first.1, replay.1);
        assert_eq!(app.store.outbound_grants("").unwrap().len(), 1);
        let created = first.1;
        let id = created["grant"]["id"].as_str().unwrap();
        let path = format!("/api/automation/deliveries/{id}");
        let (_, detail) = request(&app, "GET", &format!("{path}?limit=1"), &raw, json!({})).await;
        assert_eq!(detail["total_bytes"], 9);
        assert_eq!(detail["files"][0]["name"], "project/a.txt");
        assert_eq!(detail["files"][0]["root"].as_str().unwrap().len(), 64);
        assert!(!detail["files"][0]["receipt_b64"]
            .as_str()
            .unwrap()
            .is_empty());
        assert_eq!(detail["next_offset"], 1);
        for method in ["GET", "DELETE"] {
            assert_eq!(
                request(&app, method, &path, &foreign, json!({})).await.0,
                StatusCode::NOT_FOUND
            );
        }
        let (_, listing) = request(
            &app,
            "GET",
            "/api/automation/deliveries?limit=1",
            &raw,
            json!({}),
        )
        .await;
        assert_eq!(listing["deliveries"][0]["grant"]["id"], id);
        let (_, listing) = request(
            &app,
            "GET",
            "/api/automation/deliveries",
            &foreign,
            json!({}),
        )
        .await;
        assert_eq!(listing["deliveries"], json!([]));
        let mut changed = spec.clone();
        changed["expires_days"] = json!(1);
        let (status, conflict) =
            request(&app, "POST", "/api/automation/share", &raw, changed).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(conflict["code"], "operation_conflict");
        // Recovery reads committed state even when the source folder is gone.
        std::fs::remove_dir_all(app.config.outbound_dir.join("project")).unwrap();
        let (_, recovered) = request(
            &app,
            "GET",
            "/api/automation/operations/render-1",
            &raw,
            json!({}),
        )
        .await;
        assert_eq!(created, recovered);
        let store = crate::store::Store::open(&app.config.data_dir).unwrap();
        let token_id = access["automation_token"]["id"].as_str().unwrap();
        assert_eq!(
            store
                .automation_operation(token_id, "render-1")
                .unwrap()
                .unwrap()
                .grant_id,
            id
        );
        let bytes = std::fs::read(app.config.data_dir.join("votport.db")).unwrap();
        assert!(!bytes
            .windows(raw.len())
            .any(|window| window == raw.as_bytes()));
        for _ in 0..2 {
            assert_eq!(
                request(&app, "DELETE", &path, &raw, json!({})).await.0,
                StatusCode::OK
            );
        }
        assert_eq!(
            request(&app, "GET", &path, &raw, json!({})).await.1["state"],
            "revoked"
        );
        app.store
            .revoke_automation_token("", token_id, now_unix())
            .unwrap();
        for path in [
            "/api/automation/session",
            "/api/automation/operations/render-1",
        ] {
            assert_eq!(
                request(&app, "GET", path, &raw, json!({})).await.0,
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[test]
    fn permissions_and_operation_ids_reject_unsupported_values() {
        assert!(validate_permissions(vec![]).is_err());
        assert!(validate_permissions(vec!["admin".into()]).is_err());
        assert_eq!(default_permissions(), vec!["deliveries:create"]);
        for id in ["", ".", "..", "bad/id", "a?b", "💾"] {
            assert!(!valid_operation_id(id));
        }
        assert!(valid_operation_id("render-1"));
        assert_ne!(
            delivery_token("token-a", "op"),
            delivery_token("token-b", "op")
        );
    }
    #[tokio::test]
    async fn queued_recovery_rechecks_revocation_before_returning_the_url() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        std::fs::create_dir_all(app.config.outbound_dir.join("project")).unwrap();
        std::fs::write(app.config.outbound_dir.join("project/a"), b"a").unwrap();
        let raw = token(&app, &PERMISSIONS);
        let spec = json!({"directory": "project", "expires_days": 1, "operation_id": "queued"});
        assert_eq!(
            request(&app, "POST", "/api/automation/share", &raw, spec.clone())
                .await
                .0,
            StatusCode::OK
        );
        let token_id = app.store.automation_tokens("").unwrap()[0].id.clone();
        let db = rusqlite::Connection::open(app.config.data_dir.join("votport.db")).unwrap();
        db.execute("UPDATE automation_tokens SET last_used_at = NULL", [])
            .unwrap();
        let raw_delivery = delivery_token(&raw, "queued");
        let stripe = usize::from(Sha256::digest(raw_delivery.as_bytes())[0]) % SHARE_LOCKS.len();
        let lock = SHARE_LOCKS[stripe].lock().await;
        let waiting_app = app.clone();
        let waiter = tokio::spawn(async move {
            request(&waiting_app, "POST", "/api/automation/share", &raw, spec).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while app.store.automation_tokens("").unwrap()[0]
                .last_used_at
                .is_none()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        app.store
            .revoke_automation_token("", &token_id, now_unix())
            .unwrap();
        drop(lock);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
                .await
                .unwrap()
                .unwrap()
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn unreadable_directory_is_an_error_instead_of_an_empty_listing() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file");
        std::fs::write(&file, b"not a directory").unwrap();
        assert!(direct_library_entries_page(directory.path(), &file, "", 10).is_err());
    }

    #[tokio::test]
    async fn file_cursors_cover_children_of_the_longest_admitted_directories() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let component = "d".repeat(200);
        let relative = format!("project/{}", [component.as_str(); 5].join("/"));
        assert!(relative.len() <= MAX_LIBRARY_DIRECTORY_INPUT_BYTES);
        let folder = app.config.outbound_dir.join(&relative);
        std::fs::create_dir_all(&folder).unwrap();
        let first_name = "a".repeat(255);
        let second_name = "b".repeat(255);
        std::fs::write(folder.join(&first_name), b"a").unwrap();
        std::fs::write(folder.join(&second_name), b"b").unwrap();
        let raw = token(&app, &["library:read"]);
        let path = format!("/api/automation/files?directory={relative}&limit=1");
        let (status, first) = request(&app, "GET", &path, &raw, json!({})).await;
        assert_eq!(status, StatusCode::OK);
        let cursor = first["next_cursor"].as_str().unwrap();
        assert!(cursor.len() > MAX_LIBRARY_DIRECTORY_INPUT_BYTES);
        let (status, second) = request(
            &app,
            "GET",
            &format!("{path}&after={cursor}"),
            &raw,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            second["files"][0]["path"],
            format!("{relative}/{second_name}")
        );
        assert_eq!(second["has_more"], false);
        let (status, _) = request(
            &app,
            "GET",
            &format!("{path}&after={}", "x".repeat(MAX_FILE_CURSOR_BYTES + 1)),
            &raw,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
}
