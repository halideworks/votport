//! Verified, administrator-selected outbound files.

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::{ConnectInfo, Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use futures_util::StreamExt as _;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, ReadBuf};
use tokio_util::io::ReaderStream;
use vot_receipt::SubjectKind;
use vot_sdk::object::{InMemoryObjectBuilder, ObjectId, Suite};

use super::{ApiError, ApiResult};
use crate::api::admin;
use crate::app::App;
use crate::auth;
use crate::store::{now_unix, OutboundGrant, OutboundGrantFile};

const MAX_ACTIVE: usize = 8;
const CHUNK: usize = 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_PASSWORD_BYTES: usize = 256;

#[derive(Deserialize)]
pub struct OutboundPathQuery {
    path: String,
}

pub async fn list_outbound_files(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_admin(&app, &headers)?;
    let root = library_root(&app, &identity.tenant);
    let mut files = Vec::new();
    if let Ok(meta) = std::fs::symlink_metadata(&root) {
        if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
            list_library_dir(&root, &root, &mut files);
        }
    }
    files.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    Ok(Json(json!({ "files": files })))
}

pub async fn upload_outbound_file(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<OutboundPathQuery>,
    body: Body,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_admin(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let path = safe_library_path(&app, &identity.tenant, &query.path)?;
    let parent = path
        .parent()
        .ok_or_else(|| ApiError::internal("outbound path has no parent"))?;
    create_library_dirs(parent)?;
    let temporary = parent.join(format!(".vot-outbound-{}.stage", auth::random_token()));
    let temporary_guard = UploadTemporary(temporary.clone());
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            ApiError::new(StatusCode::CONFLICT, "outbound file already exists")
        } else {
            ApiError::internal("create outbound file failed")
        }
    })?;
    let mut bytes = 0u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid upload body"))?;
        bytes = bytes.checked_add(chunk.len() as u64).ok_or_else(|| {
            ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "file exceeds upload limit")
        })?;
        if bytes > app.config.max_upload_bytes {
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "file exceeds upload limit",
            ));
        }
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
            .await
            .map_err(|_| ApiError::internal("write outbound file failed"))?;
    }
    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .map_err(|_| ApiError::internal("write outbound file failed"))?;
    file.sync_all()
        .await
        .map_err(|_| ApiError::internal("sync outbound file failed"))?;
    drop(file);
    if let Err(error) = std::fs::hard_link(&temporary, &path) {
        return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
            ApiError::new(StatusCode::CONFLICT, "outbound file already exists")
        } else {
            ApiError::internal("publish outbound file failed")
        });
    }
    let _ = std::fs::remove_file(&temporary);
    drop(temporary_guard);
    let relative_path = query.path.trim_matches('/').replace('\\', "/");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "outbound_file_uploaded",
        &relative_path,
        &json!({ "path": relative_path, "bytes": bytes }),
    );
    Ok(Json(json!({ "path": query.path, "bytes": bytes })))
}

struct UploadTemporary(PathBuf);
impl Drop for UploadTemporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn library_root(app: &App, tenant: &str) -> PathBuf {
    if tenant.is_empty() {
        app.config.outbound_dir.clone()
    } else {
        app.config
            .outbound_dir
            .join(crate::paths::TENANT_STORAGE_DIR)
            .join(tenant)
    }
}

fn list_library_dir(root: &Path, dir: &Path, files: &mut Vec<serde_json::Value>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let is_stage = name
            .to_str()
            .is_some_and(|name| name.starts_with(".vot-") && name.ends_with(".stage"));
        if dir == root && name == crate::paths::TENANT_STORAGE_DIR {
            continue;
        }
        if meta.file_type().is_dir() {
            list_library_dir(root, &path, files);
        } else if meta.file_type().is_file() && !is_stage {
            if let Ok(relative) = path.strip_prefix(root) {
                files.push(json!({ "path": relative.to_string_lossy().replace('\\', "/"), "bytes": meta.len() }));
            }
        }
    }
}

fn library_components_safe(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let mut current = root.to_owned();
    let Ok(meta) = std::fs::symlink_metadata(&current) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return false;
    }
    for component in relative.components() {
        current.push(component);
        let Ok(meta) = std::fs::symlink_metadata(&current) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            return false;
        }
    }
    true
}

fn safe_library_path(app: &App, tenant: &str, input: &str) -> ApiResult<PathBuf> {
    let input = input.trim_matches('/');
    if input.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "path is required",
        ));
    }
    let mut path = library_root(app, tenant);
    for component in input.split('/') {
        crate::paths::admit_component(component, app.config.allow_hidden)
            .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
        path.push(component);
    }
    Ok(path)
}

fn create_library_dirs(path: &Path) -> ApiResult<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_dir() && !meta.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "outbound path component is not a directory",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)
                    .map_err(|_| ApiError::internal("create outbound directory failed"))?;
            }
            Err(_) => return Err(ApiError::internal("inspect outbound directory failed")),
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct CreateOutboundRequest {
    #[serde(default)]
    link_id: Option<String>,
    #[serde(default)]
    upload_id: Option<String>,
    #[serde(default)]
    file_index: Option<usize>,
    #[serde(default)]
    paths: Option<Vec<String>>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default = "default_expiry")]
    expires_days: u64,
}

const fn default_expiry() -> u64 {
    7
}

pub async fn list_outbound_grants(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_admin(&app, &headers)?;
    let grants = app
        .store
        .outbound_grants(&identity.tenant)
        .map_err(super::store_unavailable)?;
    Ok(Json(
        json!({ "grants": grants.into_iter().map(public_grant).collect::<Vec<_>>() }),
    ))
}

pub async fn create_outbound_grant(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<CreateOutboundRequest>,
) -> ApiResult<Response> {
    let identity = admin::require_admin(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    if !(1..=30).contains(&request.expires_days) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "expires_days must be 1..=30",
        ));
    }
    let password_hash = hash_optional_password(request.password.as_deref())?;
    if let Some(paths) = request.paths.as_deref() {
        return create_library_grant(
            &app,
            &headers,
            &identity,
            paths,
            request.label,
            password_hash,
            request.expires_days,
        )
        .await;
    }
    let link_id = request
        .link_id
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "link_id is required"))?;
    let upload_id = request
        .upload_id
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "upload_id is required"))?;
    let file_index = request
        .file_index
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "file_index is required"))?;
    let _pin = app
        .sessions
        .try_pin_link(&link_id)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "link lifecycle update in progress"))?;
    let link = app
        .store
        .link(&identity.tenant, &link_id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let upload = link
        .uploads
        .iter()
        .find(|upload| upload.id == upload_id)
        .ok_or_else(ApiError::not_found)?;
    let file = upload
        .files
        .get(file_index)
        .ok_or_else(ApiError::not_found)?;
    if upload.completed_at == 0 || file.deleted || !file.receipt {
        return Err(ApiError::not_found());
    }
    let source = admin::stored_path(&app, &identity.tenant, &file.stored_as)
        .ok_or_else(ApiError::not_found)?;
    if !source.is_file() || !receipt_path(&source).is_file() {
        return Err(ApiError::not_found());
    }
    let label = request
        .label
        .unwrap_or_else(|| file.path.clone())
        .trim()
        .to_owned();
    if label.is_empty() || label.len() > 200 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "label must be 1..=200 characters",
        ));
    }
    let token = auth::random_token();
    let token_hash = hash_token(&token);
    let created_at = now_unix();
    let grant = OutboundGrant {
        id: auth::random_token(),
        tenant: identity.tenant.clone(),
        link_id,
        upload_id,
        package_root: upload.package_root.clone(),
        name: file.path.clone(),
        suite: file.suite.clone(),
        root: file.root.clone(),
        file_index,
        bytes: file.bytes,
        label,
        password_hash,
        token_hash,
        created_at,
        expires_at: created_at.saturating_add(request.expires_days * 86_400),
        revoked_at: None,
        downloads: 0,
        files: Vec::new(),
    };
    app.store
        .insert_outbound_grant(grant.clone())
        .map_err(ApiError::internal)?;
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "outbound_grant_created",
        &grant.id,
        &json!({ "link": grant.link_id, "upload": grant.upload_id, "file_index": grant.file_index }),
    );
    let base = admin::base_url(&app, &headers);
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "grant": public_grant(grant), "url": format!("{base}/s/{token}") })),
    )
        .into_response())
}

async fn create_library_grant(
    app: &Arc<App>,
    headers: &HeaderMap,
    identity: &auth::AdminIdentity,
    requested: &[String],
    label: Option<String>,
    password_hash: Option<String>,
    expires_days: u64,
) -> ApiResult<Response> {
    if requested.is_empty() || requested.len() > 64 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "paths must contain 1..=64 files",
        ));
    }
    let root = library_root(app, &identity.tenant);
    let mut selections = Vec::with_capacity(requested.len());
    for name in requested {
        let path = safe_library_path(app, &identity.tenant, name)?;
        if !library_components_safe(&root, &path) {
            return Err(ApiError::not_found());
        }
        let meta = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            return Err(ApiError::not_found());
        }
        selections.push((name.trim_matches('/').to_owned(), path));
    }
    let max = app.config.max_upload_bytes;
    let hashed = tokio::task::spawn_blocking(move || {
        selections
            .into_iter()
            .map(|(name, path)| hash_library_file(&root, &name, &path, max))
            .collect::<Result<Vec<_>, _>>()
    })
    .await
    .map_err(|_| ApiError::internal("hash outbound files failed"))?
    .map_err(|_| ApiError::not_found())?;
    let files = hashed
        .into_iter()
        .map(|file| {
            let object = ObjectId {
                suite: 1,
                root: hex::decode(&file.root)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .unwrap_or([0; 32]),
                length: file.bytes,
            };
            let session_id: [u8; 16] = hex::decode(auth::random_token())
                .unwrap()
                .try_into()
                .unwrap();
            let incarnation_id: [u8; 16] = hex::decode(auth::random_token())
                .unwrap()
                .try_into()
                .unwrap();
            let receipt = app
                .signer
                .encode(
                    &object,
                    session_id,
                    vot_sdk_file::PublishObservation {
                        incarnation: incarnation_id,
                        sequence: 1,
                    },
                )
                .map_err(ApiError::internal)?;
            Ok(OutboundGrantFile {
                receipt_b64: base64::prelude::BASE64_STANDARD.encode(receipt),
                ..file
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let first = files.first().cloned().ok_or_else(ApiError::not_found)?;
    let created_at = now_unix();
    let token = auth::random_token();
    let label = label
        .unwrap_or_else(|| first.name.clone())
        .trim()
        .to_owned();
    let grant = OutboundGrant {
        id: auth::random_token(),
        token_hash: hash_token(&token),
        tenant: identity.tenant.clone(),
        link_id: String::new(),
        upload_id: String::new(),
        package_root: String::new(),
        name: first.name.clone(),
        suite: first.suite.clone(),
        root: first.root.clone(),
        file_index: 0,
        bytes: first.bytes,
        label,
        password_hash,
        created_at,
        expires_at: created_at.saturating_add(expires_days * 86_400),
        revoked_at: None,
        downloads: 0,
        files,
    };
    if grant.label.trim().is_empty() || grant.label.len() > 200 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "label must be 1..=200 characters",
        ));
    }
    app.store
        .insert_outbound_grant(grant.clone())
        .map_err(ApiError::internal)?;
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "outbound_grant_created",
        &grant.id,
        &json!({ "files": grant.files.len() }),
    );
    let base = admin::base_url(app, headers);
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "grant": public_grant(grant), "url": format!("{base}/s/{token}") })),
    )
        .into_response())
}

fn hash_library_file(
    root: &Path,
    name: &str,
    path: &Path,
    max: u64,
) -> io::Result<OutboundGrantFile> {
    use std::io::Read as _;
    let mut input = std::fs::File::open(path)?;
    let mut builder = InMemoryObjectBuilder::new(
        Suite::try_from(1).map_err(|_| io::Error::other("suite"))?,
        None,
        max,
    )
    .map_err(|_| io::Error::other("builder"))?;
    let mut buf = vec![0u8; CHUNK];
    let mut bytes = 0u64;
    loop {
        let count = input.read(&mut buf)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("size"))?;
        builder
            .update(&buf[..count])
            .map_err(|_| io::Error::other("object"))?;
    }
    let object = builder
        .finish()
        .map_err(|_| io::Error::other("object"))?
        .object_id()
        .clone();
    Ok(OutboundGrantFile {
        source: path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/"),
        name: name.to_owned(),
        suite: "blake3".to_owned(),
        root: hex::encode(object.root),
        bytes,
        receipt_b64: String::new(),
    })
}

pub async fn delete_outbound_grant(
    State(app): State<Arc<App>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_admin(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    if !app
        .store
        .revoke_outbound_grant(&identity.tenant, &id, now_unix())
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found());
    }
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "outbound_grant_revoked",
        &id,
        &json!({}),
    );
    Ok(Json(json!({ "ok": true })))
}

pub async fn outbound_metadata(
    State(app): State<Arc<App>>,
    AxumPath(token): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let grant = active_grant(&app, &token)?;
    let authorized = grant_authorized(&app, &grant, &headers);
    if grant.password_hash.is_some() && !authorized {
        return Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({ "has_password": true, "authorized": false })),
        )
            .into_response());
    }
    let files = if grant.files.is_empty() {
        vec![json!({
            "name": grant.name,
            "suite": grant.suite,
            "root": grant.root,
            "bytes": grant.bytes,
            "receipt_url": format!("/api/s/{token}/receipt"),
            "download_url": format!("/api/s/{token}/file")
        })]
    } else {
        grant
            .files
            .iter()
            .enumerate()
            .map(|(index, file)| {
                json!({
                    "name": file.name,
                    "suite": file.suite,
                    "root": file.root,
                    "bytes": file.bytes,
                    "receipt_url": format!("/api/s/{token}/receipts/{index}"),
                    "download_url": format!("/api/s/{token}/files/{index}")
                })
            })
            .collect()
    };
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "has_password": grant.password_hash.is_some(),
            "authorized": authorized,
            "label": grant.label,
            "name": grant.name,
            "suite": grant.suite,
            "root": grant.root,
            "bytes": grant.bytes,
            "length": grant.bytes,
            "package_root": grant.package_root,
            "expires_at": grant.expires_at,
            "downloads": grant.downloads,
            "receipt_key": app.signer.public_hex,
            "receipt_url": format!("/api/s/{token}/receipt"),
            "download_url": format!("/api/s/{token}/file")
            ,"files": files
        })),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct VerifyOutboundRequest {
    password: Option<String>,
}

pub async fn verify_outbound_password(
    State(app): State<Arc<App>>,
    AxumPath(token): AxumPath<String>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<VerifyOutboundRequest>,
) -> ApiResult<Response> {
    let grant = active_grant(&app, &token)?;
    let ip = super::client_ip(&headers, &peer, &app.config.trusted_proxies);
    super::upload::check_password(
        &app,
        grant.password_hash.as_deref(),
        request.password.as_deref(),
        &ip,
        "wrong outbound grant password",
    )
    .await?;
    let phc = grant.password_hash.as_deref().unwrap_or_default();
    let value = auth::issue_link_token(&app.secret, &grant.id, phc);
    let cookie = format!(
        "{}={value}; Path=/api/s/{token}; HttpOnly; SameSite=Lax; Max-Age=2592000{}",
        grant_cookie_name(&grant.id),
        super::cookie_attributes(&app)
    );
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

pub async fn outbound_receipt(
    State(app): State<Arc<App>>,
    AxumPath(token): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    outbound_receipt_indexed(State(app), AxumPath((token, 0)), headers).await
}

pub async fn outbound_receipt_indexed(
    State(app): State<Arc<App>>,
    AxumPath((token, index)): AxumPath<(String, usize)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let grant = active_grant(&app, &token)?;
    require_grant_access(&app, &grant, &headers)?;
    let source = source_info_indexed(&app, &grant, index)?;
    let bytes = if let Some(bytes) = source.receipt.clone() {
        bytes
    } else {
        tokio::fs::read(receipt_path(&source.path))
            .await
            .map_err(|_| ApiError::not_found())?
    };
    if bytes.len() as u64 > MAX_RECEIPT_BYTES
        || verify_receipt(&app, &bytes, &source.object).is_err()
    {
        return Err(ApiError::not_found());
    }
    let filename = format!("{}.vot-receipt", safe_filename(&source.name));
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/cbor"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::try_from(format!("attachment; filename=\"{filename}\""))
            .map_err(|_| ApiError::internal("receipt filename invalid"))?,
    );
    Ok(response)
}

pub async fn outbound_file(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
) -> ApiResult<Response> {
    outbound_file_inner(app, peer, headers, token, 0).await
}

pub async fn outbound_file_indexed(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AxumPath((token, index)): AxumPath<(String, usize)>,
) -> ApiResult<Response> {
    outbound_file_inner(app, peer, headers, token, index).await
}

async fn outbound_file_inner(
    app: Arc<App>,
    peer: std::net::SocketAddr,
    headers: HeaderMap,
    token: String,
    index: usize,
) -> ApiResult<Response> {
    let grant = active_grant(&app, &token)?;
    require_grant_access(&app, &grant, &headers)?;
    let ip = super::client_ip(&headers, &peer, &app.config.trusted_proxies);
    if !app.outbound_rate.allow(&ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many downloads; try again later",
        ));
    }
    let active = ActiveDownload::claim(Arc::clone(&app), &format!("{}:{index}", grant.token_hash))?;
    let (stage, source) = prepare(&app, &grant, index).await?;
    let file = tokio::fs::File::open(&stage.path)
        .await
        .map_err(|_| ApiError::internal("open staged file failed"))?;
    if app.store.record_outbound_download(&grant.id).is_err() {
        return Err(ApiError::internal("record download failed"));
    }
    let stream = ReaderStream::new(OutboundReader {
        file,
        _stage: stage,
        _active: active,
    });
    let filename = safe_filename(&source.name);
    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("none"));
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(source.object.length),
    );
    let disposition = format!("attachment; filename=\"{filename}\"");
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::try_from(disposition)
            .map_err(|_| ApiError::internal("download filename invalid"))?,
    );
    Ok(response)
}

fn active_grant(app: &App, token: &str) -> ApiResult<OutboundGrant> {
    if !valid_token(token) {
        return Err(ApiError::not_found());
    }
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(token))
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if grant.revoked_at.is_some() || grant.expires_at <= now_unix() {
        return Err(ApiError::not_found());
    }
    Ok(grant)
}

fn grant_cookie_name(grant_id: &str) -> String {
    format!("votport_s_{grant_id}")
}

fn grant_authorized(app: &App, grant: &OutboundGrant, headers: &HeaderMap) -> bool {
    grant.password_hash.is_none()
        || super::upload::cookie_authorized(
            app,
            &grant.id,
            grant.password_hash.as_deref(),
            &grant_cookie_name(&grant.id),
            headers,
        )
}

fn require_grant_access(app: &App, grant: &OutboundGrant, headers: &HeaderMap) -> ApiResult<()> {
    if grant_authorized(app, grant, headers) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "outbound grant password required",
        ))
    }
}

fn hash_optional_password(password: Option<&str>) -> ApiResult<Option<String>> {
    let Some(password) = password.filter(|password| !password.is_empty()) else {
        return Ok(None);
    };
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "password must be at most 256 bytes",
        ));
    }
    auth::hash_password(password)
        .map(Some)
        .map_err(ApiError::internal)
}

struct Source {
    path: PathBuf,
    object: ObjectId,
    name: String,
    receipt: Option<Vec<u8>>,
}

fn source_info_indexed(app: &App, grant: &OutboundGrant, index: usize) -> ApiResult<Source> {
    if !grant.files.is_empty() {
        let file = grant.files.get(index).ok_or_else(ApiError::not_found)?;
        let path = safe_library_path(app, &grant.tenant, &file.source)?;
        if !library_components_safe(&library_root(app, &grant.tenant), &path) {
            return Err(ApiError::not_found());
        }
        let root: [u8; 32] = hex::decode(&file.root)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(ApiError::not_found)?;
        let suite = match file.suite.as_str() {
            "blake3" => 1,
            _ => return Err(ApiError::not_found()),
        };
        let receipt = base64::prelude::BASE64_STANDARD
            .decode(&file.receipt_b64)
            .map_err(|_| ApiError::not_found())?;
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(ApiError::not_found());
        }
        return Ok(Source {
            path,
            object: ObjectId {
                suite,
                root,
                length: file.bytes,
            },
            name: file.name.clone(),
            receipt: Some(receipt),
        });
    }
    if index != 0 {
        return Err(ApiError::not_found());
    }
    let link = app
        .store
        .link(&grant.tenant, &grant.link_id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let upload = link
        .uploads
        .iter()
        .find(|upload| upload.id == grant.upload_id)
        .ok_or_else(ApiError::not_found)?;
    let file = upload
        .files
        .get(grant.file_index)
        .ok_or_else(ApiError::not_found)?;
    if upload.completed_at == 0
        || file.deleted
        || upload.package_root != grant.package_root
        || file.path != grant.name
        || file.suite != grant.suite
        || file.root != grant.root
        || file.bytes != grant.bytes
    {
        return Err(ApiError::not_found());
    }
    let root: [u8; 32] = hex::decode(&file.root)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(ApiError::not_found)?;
    let suite = match file.suite.as_str() {
        "blake3" => 1,
        "sha256" => 2,
        _ => return Err(ApiError::not_found()),
    };
    let path =
        admin::stored_path(app, &grant.tenant, &file.stored_as).ok_or_else(ApiError::not_found)?;
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ApiError::not_found());
    }
    Ok(Source {
        path,
        object: ObjectId {
            suite,
            root,
            length: file.bytes,
        },
        name: file.path.clone(),
        receipt: None,
    })
}

async fn prepare(
    app: &Arc<App>,
    grant: &OutboundGrant,
    index: usize,
) -> ApiResult<(StagedFile, Source)> {
    let _pin = if grant.files.is_empty() {
        let pin = app.sessions.try_pin_link(&grant.link_id).ok_or_else(|| {
            ApiError::new(StatusCode::CONFLICT, "link lifecycle update in progress")
        })?;
        if app.sessions.active_for_link(&grant.link_id) > 0 {
            return Err(ApiError::new(StatusCode::CONFLICT, "uploads are in flight"));
        }
        Some(pin)
    } else {
        None
    };
    let source = source_info_indexed(app, grant, index)?;
    let stage_dir = app
        .config
        .data_dir
        .join("outbound.stage")
        .join(format!(".vot-outbound-{}", auth::random_token()));
    std::fs::create_dir_all(&stage_dir)
        .map_err(|_| ApiError::internal("create outbound stage failed"))?;
    let stage = StagedFile {
        path: stage_dir.join("file"),
    };
    let source_path = source.path.clone();
    let expected = source.object.clone();
    let source_receipt = source.receipt.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        let receipt = copy_verify(&source_path, &stage.path, expected, source_receipt)?;
        Ok::<_, io::Error>((stage, receipt))
    })
    .await
    .map_err(|_| ApiError::internal("outbound preparation failed"))?
    .map_err(|error| {
        tracing::warn!(%error, "outbound source verification failed");
        ApiError::not_found()
    })?;
    let (stage, receipt) = prepared;
    if verify_receipt(app, &receipt, &source.object).is_err() {
        return Err(ApiError::not_found());
    }
    Ok((stage, source))
}

fn copy_verify(
    source: &Path,
    stage: &Path,
    expected: ObjectId,
    receipt_bytes: Option<Vec<u8>>,
) -> io::Result<Vec<u8>> {
    use std::io::{Read, Write};
    let mut input = std::fs::File::open(source)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options.open(stage)?;
    let suite = Suite::try_from(expected.suite).map_err(|_| io::Error::other("suite"))?;
    let mut builder = InMemoryObjectBuilder::new(suite, Some(expected.length), expected.length)
        .map_err(|_| io::Error::other("builder"))?;
    let mut buf = vec![0u8; CHUNK];
    let mut receipt = Vec::new();
    loop {
        let count = input.read(&mut buf)?;
        if count == 0 {
            break;
        }
        builder
            .update(&buf[..count])
            .map_err(|_| io::Error::other("object"))?;
        output.write_all(&buf[..count])?;
    }
    let actual = builder.finish().map_err(|_| io::Error::other("object"))?;
    if actual.object_id() != &expected {
        return Err(io::Error::other("source mismatch"));
    }
    if let Some(bytes) = receipt_bytes {
        receipt = bytes;
    } else {
        let mut sidecar = source.as_os_str().to_os_string();
        sidecar.push(".vot-receipt");
        std::fs::File::open(sidecar)?
            .take(MAX_RECEIPT_BYTES + 1)
            .read_to_end(&mut receipt)?;
    }
    if receipt.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(io::Error::other("receipt too large"));
    }
    Ok(receipt)
}

fn verify_receipt(app: &App, bytes: &[u8], object: &ObjectId) -> Result<(), ()> {
    let decoded = vot_receipt::decode_authenticated(bytes).map_err(|_| ())?;
    let verified =
        vot_receipt::verify_ed25519(&decoded, &app.signer.verifying_key()).map_err(|_| ())?;
    let receipt = verified.receipt();
    if receipt.subject_kind != SubjectKind::Object
        || receipt.suite_id != object.suite
        || receipt.subject_digest != object.root
        || receipt.subject_length != object.length
    {
        return Err(());
    }
    Ok(())
}

fn receipt_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".vot-receipt");
    value.into()
}
fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
fn valid_token(token: &str) -> bool {
    token.len() == 32 && token.as_bytes().iter().all(u8::is_ascii_hexdigit)
}
fn safe_filename(name: &str) -> String {
    let name = name.rsplit('/').next().unwrap_or(name);
    let mut value: String = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ' ') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if value.is_empty() || value == "." || value == ".." {
        value = "download.bin".to_owned();
    }
    value.chars().take(180).collect()
}
fn public_grant(grant: OutboundGrant) -> serde_json::Value {
    json!({ "id": grant.id, "tenant": grant.tenant, "link_id": grant.link_id, "upload_id": grant.upload_id, "file_index": grant.file_index, "name": grant.name, "label": grant.label, "has_password": grant.password_hash.is_some(), "created_at": grant.created_at, "expires_at": grant.expires_at, "revoked_at": grant.revoked_at, "downloads": grant.downloads, "files": grant.files.iter().map(|file| json!({ "name": file.name, "suite": file.suite, "root": file.root, "bytes": file.bytes })).collect::<Vec<_>>() })
}

struct ActiveDownload {
    app: Arc<App>,
    key: String,
}
impl ActiveDownload {
    fn claim(app: Arc<App>, key: &str) -> ApiResult<Self> {
        let mut active = app
            .outbound_active
            .lock()
            .expect("outbound active poisoned");
        if active.contains(key) || active.len() >= MAX_ACTIVE {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too many downloads in progress",
            ));
        }
        active.insert(key.to_owned());
        drop(active);
        Ok(Self {
            app,
            key: key.to_owned(),
        })
    }
}
impl Drop for ActiveDownload {
    fn drop(&mut self) {
        self.app
            .outbound_active
            .lock()
            .expect("outbound active poisoned")
            .remove(&self.key);
    }
}

struct StagedFile {
    path: PathBuf,
}
impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

struct OutboundReader {
    file: tokio::fs::File,
    _stage: StagedFile,
    _active: ActiveDownload,
}
impl AsyncRead for OutboundReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    use vot_sdk_file::PublishObservation;

    fn admin_cookie(app: &App) -> String {
        let token = auth::issue_admin_token(
            &app.secret,
            &auth::AdminIdentity::local_admin(),
            &app.config.admin_token_tag,
        );
        format!("votport_admin={token}")
    }

    async fn body(response: Response) -> serde_json::Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    async fn fixture() -> (tempfile::TempDir, Arc<App>, String, Vec<u8>) {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let bytes = b"outbound fixture".to_vec();
        let mut builder = InMemoryObjectBuilder::new(
            Suite::try_from(1).unwrap(),
            Some(bytes.len() as u64),
            bytes.len() as u64,
        )
        .unwrap();
        builder.update(&bytes).unwrap();
        let object = builder.finish().unwrap().object_id().clone();
        let source = app.config.receive_dir.join("received.bin");
        std::fs::write(&source, &bytes).unwrap();
        app.signer
            .write_sidecar(
                &source,
                &object,
                [1; 16],
                PublishObservation {
                    incarnation: [2; 16],
                    sequence: 1,
                },
            )
            .unwrap();
        app.store
            .insert_link(crate::store::Link {
                id: "link".to_owned(),
                label: "link".to_owned(),
                tenant: String::new(),
                dest: String::new(),
                password_hash: None,
                created_at: 1,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,
                uploads: vec![crate::store::UploadRecord {
                    id: "upload".to_owned(),
                    started_at: 1,
                    completed_at: 2,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: Some("http".to_owned()),
                    package_root: "package-root".to_owned(),
                    total_bytes: bytes.len() as u64,
                    files: vec![crate::store::FileRecord {
                        path: "received.bin".to_owned(),
                        stored_as: "received.bin".to_owned(),
                        bytes: object.length,
                        suite: "blake3".to_owned(),
                        root: hex::encode(object.root),
                        receipt: true,
                        deleted: false,
                    }],
                }],
                events: Vec::new(),
            })
            .unwrap();
        (directory, app.clone(), admin_cookie(&app), bytes)
    }

    #[test]
    fn tokens_are_strict() {
        assert!(valid_token(&"a".repeat(32)));
        assert!(!valid_token("x"));
        assert!(!valid_token(&"g".repeat(32)));
    }
    #[test]
    fn hashes_are_not_raw_tokens() {
        assert_ne!(hash_token("a"), "a");
    }
    #[test]
    fn filenames_are_single_safe_components() {
        assert_eq!(safe_filename("../a/b?.txt"), "b_.txt");
    }
    #[test]
    fn source_identity_mismatch_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let stage = directory.path().join("stage");
        std::fs::write(&source, b"payload").unwrap();
        let expected = ObjectId {
            suite: 1,
            root: [0; 32],
            length: 7,
        };
        assert!(copy_verify(&source, &stage, expected, None).is_err());
    }
    #[test]
    fn drop_guards_remove_stage_and_active_grant() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let stage = directory.path().join("stage").join("file");
        std::fs::create_dir_all(stage.parent().unwrap()).unwrap();
        std::fs::write(&stage, b"payload").unwrap();
        let staged = StagedFile {
            path: stage.clone(),
        };
        let active = ActiveDownload::claim(Arc::clone(&app), "grant").unwrap();
        drop((staged, active));
        assert!(!stage.exists());
        assert!(!app.outbound_active.lock().unwrap().contains("grant"));
    }

    #[tokio::test]
    async fn grant_flow_serves_verified_file_and_receipt_then_revokes() {
        let (_directory, app, cookie, expected_bytes) = fixture().await;
        let create = Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"link_id":"link","upload_id":"upload","file_index":0,"label":"fixture","expires_days":7}"#,
            ))
            .unwrap();
        let response = crate::app::router(app.clone())
            .oneshot(create)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let created = body(response).await;
        assert_eq!(created["grant"]["file_index"], 0);
        assert!(created["grant"].get("token_hash").is_none());
        let url = created["url"].as_str().unwrap();
        let token = url.rsplit('/').next().unwrap();
        assert_eq!(url, format!("https://drop.example.com/s/{token}"));
        let id = created["grant"]["id"].as_str().unwrap().to_owned();

        let metadata = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metadata.status(), StatusCode::OK);
        assert_eq!(metadata.headers()[header::CACHE_CONTROL], "no-store");
        let metadata = body(metadata).await;
        assert_eq!(metadata["bytes"], expected_bytes.len());
        assert_eq!(metadata["length"], expected_bytes.len());
        assert_eq!(metadata["suite"], "blake3");
        assert_eq!(metadata["name"], "received.bin");
        assert_eq!(metadata["root"].as_str().unwrap().len(), 64);
        assert_eq!(metadata["receipt_key"], app.signer.public_hex);
        assert_eq!(metadata["receipt_url"], format!("/api/s/{token}/receipt"));
        assert_eq!(metadata["download_url"], format!("/api/s/{token}/file"));

        let receipt = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/receipt"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt.status(), StatusCode::OK);
        assert_eq!(
            receipt.into_body().collect().await.unwrap().to_bytes(),
            std::fs::read(app.config.receive_dir.join("received.bin.vot-receipt")).unwrap()
        );

        let file = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(file.status(), StatusCode::OK);
        assert_eq!(
            file.headers()[header::CONTENT_LENGTH],
            expected_bytes.len().to_string()
        );
        assert_eq!(
            file.into_body().collect().await.unwrap().to_bytes(),
            expected_bytes
        );

        std::fs::write(
            app.config.receive_dir.join("received.bin"),
            b"tampered fixture",
        )
        .unwrap();
        let tampered = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tampered.status(), StatusCode::NOT_FOUND);
        assert!(app.outbound_active.lock().unwrap().is_empty());

        let conflict = crate::app::router(app.clone())
            .oneshot(
                Request::delete("/api/admin/links/link/uploads/upload/files/0")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

        let revoke = Request::delete(format!("/api/admin/outbound-grants/{id}"))
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            crate::app::router(app.clone())
                .oneshot(revoke)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        for suffix in ["", "/receipt", "/file"] {
            let mut request = Request::get(format!("/api/s/{token}{suffix}"));
            if suffix == "/file" {
                request =
                    request.extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))));
            }
            assert_eq!(
                crate::app::router(app.clone())
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
    }

    #[tokio::test]
    async fn password_grant_gates_metadata_file_and_receipt() {
        let (_directory, app, cookie, expected_bytes) = fixture().await;
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"link_id":"link","upload_id":"upload","file_index":0,"password":"correct horse","expires_days":7}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created = body(response).await;
        assert_eq!(created["grant"]["has_password"], true);
        assert!(created["grant"].get("password_hash").is_none());
        let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();

        let metadata = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metadata.status(), StatusCode::OK);
        let metadata = body(metadata).await;
        assert_eq!(
            metadata,
            json!({ "has_password": true, "authorized": false })
        );

        let peer = ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1)));
        for suffix in ["/file", "/receipt"] {
            let mut request = Request::get(format!("/api/s/{token}{suffix}"));
            if suffix == "/file" {
                request = request.extension(peer);
            }
            assert_eq!(
                crate::app::router(app.clone())
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }

        let wrong = crate::app::router(app.clone())
            .oneshot(
                Request::post(format!("/api/s/{token}/verify"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"password":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let verified = crate::app::router(app.clone())
            .oneshot(
                Request::post(format!("/api/s/{token}/verify"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"password":"correct horse"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verified.status(), StatusCode::OK);
        let set_cookie = verified.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(set_cookie.starts_with("votport_s_"));
        assert!(set_cookie.contains(&format!("; Path=/api/s/{token}; HttpOnly; SameSite=Lax;")));
        let grant_cookie = set_cookie.split(';').next().unwrap().to_owned();

        let metadata = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}"))
                    .header("cookie", &grant_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metadata.status(), StatusCode::OK);
        assert_eq!(body(metadata).await["label"], "received.bin");

        let file = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .header("cookie", &grant_cookie)
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(file.status(), StatusCode::OK);
        assert_eq!(
            file.into_body().collect().await.unwrap().to_bytes(),
            expected_bytes
        );

        let receipt = crate::app::router(app)
            .oneshot(
                Request::get(format!("/api/s/{token}/receipt"))
                    .header("cookie", &grant_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn library_upload_list_multi_file_grant_and_mutation_failure() {
        let (_directory, app, cookie, first) = fixture().await;
        let upload = |path: &str, bytes: &[u8]| {
            let request = Request::post(format!("/api/admin/outbound-files?path={path}"))
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::from(bytes.to_vec()))
                .unwrap();
            async {
                crate::app::router(app.clone())
                    .oneshot(request)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            upload("project/one.bin", &first).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            upload("project/two.bin", b"second file").await.status(),
            StatusCode::OK
        );
        let audits = app.store.audit_export("", 0, 0, 100).unwrap();
        assert!(audits.iter().any(|row| {
            row.event == "outbound_file_uploaded"
                && row.actor == "local"
                && row.subject == "project/one.bin"
                && row.detail["path"] == "project/one.bin"
                && row.detail["bytes"] == first.len()
        }));

        let listed = crate::app::router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let listed = body(listed).await;
        assert_eq!(listed["files"].as_array().unwrap().len(), 2);
        assert!(listed["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "project/one.bin"));

        for path in ["../escape", "project/../escape", "project//escape"] {
            assert_eq!(
                upload(path, b"bad").await.status(),
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                app.config.outbound_dir.join("project"),
                app.config.outbound_dir.join("link"),
            )
            .unwrap();
            assert_eq!(
                upload("link/escape", b"bad").await.status(),
                StatusCode::CONFLICT
            );
        }
        assert_eq!(
            upload("project/one.bin", b"overwrite").await.status(),
            StatusCode::CONFLICT
        );

        let create = Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"paths":["project/one.bin","project/two.bin"],"label":"project"}"#,
            ))
            .unwrap();
        let response = crate::app::router(app.clone())
            .oneshot(create)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created = body(response).await;
        let token = created["url"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        let metadata = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let metadata = body(metadata).await;
        assert_eq!(metadata["files"].as_array().unwrap().len(), 2);
        for (index, expected) in [first, b"second file".to_vec()].into_iter().enumerate() {
            let file = crate::app::router(app.clone())
                .oneshot(
                    Request::get(format!("/api/s/{token}/files/{index}"))
                        .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(file.status(), StatusCode::OK);
            assert_eq!(
                file.into_body().collect().await.unwrap().to_bytes(),
                expected
            );
            let receipt = crate::app::router(app.clone())
                .oneshot(
                    Request::get(format!("/api/s/{token}/receipts/{index}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(receipt.status(), StatusCode::OK);
            let receipt = receipt.into_body().collect().await.unwrap().to_bytes();
            let decoded = vot_receipt::decode_authenticated(&receipt).unwrap();
            let verified =
                vot_receipt::verify_ed25519(&decoded, &app.signer.verifying_key()).unwrap();
            assert_eq!(
                verified.receipt().subject_kind,
                vot_receipt::SubjectKind::Object
            );
            assert_eq!(verified.receipt().subject_length, expected.len() as u64);
        }
        std::fs::write(app.config.outbound_dir.join("project/one.bin"), b"mutated").unwrap();
        let mutated = crate::app::router(app)
            .oneshot(
                Request::get(format!("/api/s/{token}/files/0"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 4))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mutated.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn library_upload_limit_cleans_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let mut app = crate::api::testing::build(directory.path());
        Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 3;
        let cookie = admin_cookie(&app);
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-files?path=too-large.bin")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .body(Body::from("four"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!app.config.outbound_dir.join("too-large.bin").exists());
        assert!(std::fs::read_dir(&app.config.outbound_dir)
            .map(|entries| entries
                .flatten()
                .all(|entry| !entry.file_name().to_string_lossy().ends_with(".stage")))
            .unwrap_or(true));
    }

    #[tokio::test]
    async fn default_library_listing_excludes_tenants_and_stages_and_is_sorted() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        std::fs::write(app.config.outbound_dir.join("z.bin"), b"z").unwrap();
        std::fs::write(app.config.outbound_dir.join("a.bin"), b"a").unwrap();
        std::fs::create_dir_all(
            app.config
                .outbound_dir
                .join(crate::paths::TENANT_STORAGE_DIR)
                .join("named"),
        )
        .unwrap();
        std::fs::write(
            app.config
                .outbound_dir
                .join(crate::paths::TENANT_STORAGE_DIR)
                .join("named/secret.bin"),
            b"secret",
        )
        .unwrap();
        std::fs::write(app.config.outbound_dir.join(".vot-crash.stage"), b"staged").unwrap();

        let response = crate::app::router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files")
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = body(response).await;
        assert_eq!(listed["files"][0]["path"], "a.bin");
        assert_eq!(listed["files"][1]["path"], "z.bin");
        assert_eq!(listed["files"].as_array().unwrap().len(), 2);
    }
}
