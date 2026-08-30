//! Verified, administrator-selected outbound files.

use std::collections::BinaryHeap;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
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
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _, ReadBuf, SeekFrom,
};
use tokio::sync::Semaphore;
use tokio_util::io::ReaderStream;
use vot_receipt::SubjectKind;
use vot_sdk::object::{InMemoryObjectBuilder, ObjectId, Suite};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

use super::{ApiError, ApiResult};
use crate::api::admin;
use crate::app::App;
use crate::auth;
use crate::session::OutboundOperation;
use crate::store::{
    now_unix, AutomationToken, OutboundDownloadResult, OutboundGrant, OutboundGrantFile,
    OUTBOUND_DOWNLOAD_LIMIT_REACHED,
};

const MAX_ACTIVE: usize = 32;
const MAX_ACTIVE_PER_GRANT: usize = 4;
const CHUNK: usize = 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_PASSWORD_BYTES: usize = 256;
const MAX_AUTOMATION_LABEL_CHARS: usize = 100;
const DOWNLOAD_LEASE_SECS: u64 = 24 * 60 * 60;
const OUTBOUND_UPLOAD_ID: &str = "x-votport-upload-id";
const MAX_OUTBOUND_CHUNK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LIBRARY_DIRECTORY_INPUT_BYTES: usize = 1024;
const MAX_LIBRARY_DIRECTORY_ENTRIES: usize = 1000;
const MAX_LIBRARY_SELECTION_FILES: usize = 64;
const MAX_LIBRARY_PROJECT_FILES: usize = 10_000;
const MAX_LIBRARY_SEARCH_CHARS: usize = 100;
const MAX_LIBRARY_SEARCH_RESULTS: usize = 200;
const RETAINED_LIBRARY_SEARCH_RESULTS: usize = MAX_LIBRARY_SEARCH_RESULTS + 1;
const LIBRARY_HASH_CONCURRENCY: usize = 4;

// ponytail: one tiny global critical section; use per-tenant locks only if contention is measured.
static LIBRARY_MUTATION_LOCK: Mutex<()> = Mutex::new(());
static LIBRARY_HASH_PERMITS: Semaphore = Semaphore::const_new(LIBRARY_HASH_CONCURRENCY);

#[derive(Deserialize)]
pub struct OutboundPathQuery {
    path: String,
}

#[derive(Deserialize)]
pub struct OutboundListQuery {
    directory: Option<String>,
    q: Option<String>,
    selection: Option<String>,
}

pub async fn list_outbound_files(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<OutboundListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_admin(&app, &headers)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    let root = library_root(&app, &identity.tenant);
    if [
        query.directory.is_some(),
        query.q.is_some(),
        query.selection.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count()
        > 1
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "library listing modes cannot be combined",
        ));
    }
    if let Some(selection) = query.selection {
        if selection.len() > MAX_LIBRARY_DIRECTORY_INPUT_BYTES {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "selection is too long",
            ));
        }
        let tenant = identity.tenant;
        let app_for_selection = Arc::clone(&app);
        let result = tokio::task::spawn_blocking(move || {
            let directory = automation_directory(&app_for_selection, &tenant, &selection)?;
            let root = library_root(&app_for_selection, &tenant);
            enumerate_library_selection(&root, &directory)
        })
        .await
        .map_err(|_| ApiError::internal("list outbound files failed"))??;
        return Ok(Json(json!({ "files": result })));
    }
    if let Some(query) = query.q {
        let query = query.trim();
        if query.chars().count() > MAX_LIBRARY_SEARCH_CHARS || query.is_empty() {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "q must be between 1 and 100 characters",
            ));
        }
        let query = query.to_lowercase();
        let result = tokio::task::spawn_blocking(move || list_library_search(&root, &query))
            .await
            .map_err(|_| ApiError::internal("list outbound files failed"))?;
        return Ok(Json(json!({
            "files": result.0,
            "truncated": result.1,
        })));
    }
    if let Some(directory) = query.directory {
        if directory.len() > MAX_LIBRARY_DIRECTORY_INPUT_BYTES {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "directory is too long",
            ));
        }
        let directory = directory.trim_matches('/').to_owned();
        if identity.tenant.is_empty()
            && directory
                .split('/')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case(crate::paths::TENANT_STORAGE_DIR))
        {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "directory is reserved",
            ));
        }
        let path = if directory.is_empty() {
            root.clone()
        } else {
            safe_library_path(&app, &identity.tenant, &directory)?
        };
        let result = tokio::task::spawn_blocking(move || list_library_directory(&root, &path))
            .await
            .map_err(|_| ApiError::internal("list outbound files failed"))?
            .map_err(|_| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "directory must contain only directories",
                )
            })?;
        return Ok(Json(json!({
            "directory": directory,
            "directories": result.0,
            "files": result.1,
            "truncated": result.2,
        })));
    }
    let files = tokio::task::spawn_blocking(move || {
        let mut files = Vec::new();
        if let Ok(meta) = std::fs::symlink_metadata(&root) {
            if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
                list_library_dir(&root, &root, &mut files);
            }
        }
        files.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
        files
    })
    .await
    .map_err(|_| ApiError::internal("list outbound files failed"))?;
    Ok(Json(json!({ "files": files })))
}

pub async fn upload_outbound_file(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<OutboundPathQuery>,
    body: Body,
) -> ApiResult<Response> {
    let identity = admin::require_admin(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    if headers.contains_key(header::CONTENT_RANGE) || headers.contains_key(OUTBOUND_UPLOAD_ID) {
        return upload_outbound_chunk(Arc::clone(&app), identity, headers, query.path, body).await;
    }
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
    Ok(Json(json!({ "path": query.path, "bytes": bytes })).into_response())
}

async fn upload_outbound_chunk(
    app: Arc<App>,
    identity: auth::AdminIdentity,
    headers: HeaderMap,
    requested_path: String,
    body: Body,
) -> ApiResult<Response> {
    let upload_id = headers
        .get(OUTBOUND_UPLOAD_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_outbound_upload_id(value))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "X-Votport-Upload-Id must be 64 hexadecimal characters",
            )
        })?
        .to_owned();
    let (start, end, total) = parse_outbound_content_range(&headers)?;
    let chunk_len = end
        .checked_sub(start)
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid Content-Range"))?;
    if chunk_len > MAX_OUTBOUND_CHUNK_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "outbound chunk exceeds 16 MiB",
        ));
    }
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "Content-Length must match the requested range",
            )
        })?;
    if declared != chunk_len {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Content-Length must match the requested range",
        ));
    }
    if total > app.config.max_upload_bytes {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "file exceeds upload limit",
        ));
    }
    if end >= total {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Content-Range exceeds the declared file size",
        ));
    }

    let path = safe_library_path(&app, &identity.tenant, &requested_path)?;
    let stripe = outbound_upload_stripe(&path);
    let _lock = app.outbound_upload_locks[stripe].lock().await;
    let parent = path
        .parent()
        .ok_or_else(|| ApiError::internal("outbound path has no parent"))?;
    create_library_dirs(parent)?;
    let stage = parent.join(outbound_stage_name(&path, &upload_id));
    if std::fs::symlink_metadata(&path).is_ok() {
        let _ = std::fs::remove_file(&stage);
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "outbound file already exists",
        ));
    }
    match std::fs::symlink_metadata(&stage) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.file_type().is_file() => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "outbound staging path is not a regular file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ApiError::internal("inspect outbound staging file failed")),
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options
        .open(&stage)
        .await
        .map_err(|_| ApiError::internal("open outbound staging file failed"))?;
    let stage_len = file
        .metadata()
        .await
        .map_err(|_| ApiError::internal("inspect outbound staging file failed"))?
        .len();
    if stage_len != start {
        return Ok(outbound_upload_conflict(&requested_path, stage_len, total));
    }
    file.seek(SeekFrom::Start(start))
        .await
        .map_err(|_| ApiError::internal("seek outbound staging file failed"))?;
    let mut stream = body.into_data_stream();
    let mut received = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => {
                let _ = file.set_len(start).await;
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid upload body",
                ));
            }
        };
        let next = received.checked_add(chunk.len() as u64).ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "upload body exceeds Content-Length",
            )
        });
        let Ok(next) = next else {
            let _ = file.set_len(start).await;
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "upload body exceeds Content-Length",
            ));
        };
        if next > chunk_len {
            let _ = file.set_len(start).await;
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "upload body exceeds Content-Length",
            ));
        }
        if file.write_all(&chunk).await.is_err() {
            let _ = file.set_len(start).await;
            return Err(ApiError::internal("write outbound staging file failed"));
        }
        received = next;
    }
    if received != chunk_len {
        let _ = file.set_len(start).await;
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "upload body does not match Content-Length",
        ));
    }
    let offset = end + 1;
    if offset < total {
        if file.flush().await.is_err() {
            let _ = file.set_len(start).await;
            return Err(ApiError::internal("write outbound staging file failed"));
        }
        return Ok(Json(json!({
            "complete": false,
            "offset": offset,
            "bytes": total,
            "path": requested_path,
        }))
        .into_response());
    }
    if file.flush().await.is_err() {
        let _ = file.set_len(start).await;
        return Err(ApiError::internal("write outbound staging file failed"));
    }
    if file.sync_all().await.is_err() {
        let _ = file.set_len(start).await;
        return Err(ApiError::internal("sync outbound file failed"));
    }
    drop(file);
    if let Err(error) = std::fs::hard_link(&stage, &path) {
        return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
            let _ = std::fs::remove_file(&stage);
            ApiError::new(StatusCode::CONFLICT, "outbound file already exists")
        } else {
            ApiError::internal("publish outbound file failed")
        });
    }
    let _ = std::fs::remove_file(&stage);
    let relative_path = requested_path.trim_matches('/').replace('\\', "/");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "outbound_file_uploaded",
        &relative_path,
        &json!({ "path": relative_path, "bytes": total }),
    );
    Ok(Json(json!({
        "complete": true,
        "offset": total,
        "bytes": total,
        "path": requested_path,
    }))
    .into_response())
}

fn outbound_upload_stripe(path: &Path) -> usize {
    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    usize::from(u16::from_be_bytes([digest[0], digest[1]])) % 64
}

fn outbound_stage_name(path: &Path, upload_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update([0]);
    hasher.update(upload_id.as_bytes());
    format!(".vot-outbound-{}.stage", hex::encode(hasher.finalize()))
}

fn valid_outbound_upload_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_outbound_content_range(headers: &HeaderMap) -> ApiResult<(u64, u64, u64)> {
    let value = headers
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Content-Range is required",
            )
        })?;
    let value = value
        .strip_prefix("bytes ")
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid Content-Range"))?;
    let (range, total) = value
        .split_once('/')
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid Content-Range"))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid Content-Range"))?;
    let start = start
        .parse::<u64>()
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid Content-Range"))?;
    let end = end
        .parse::<u64>()
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid Content-Range"))?;
    let total = total
        .parse::<u64>()
        .map_err(|_| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid Content-Range"))?;
    if end < start || total == 0 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid Content-Range",
        ));
    }
    Ok((start, end, total))
}

fn outbound_upload_conflict(path: &str, offset: u64, total: u64) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({ "complete": false, "offset": offset, "bytes": total, "path": path })),
    )
        .into_response()
}

pub async fn delete_outbound_file(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<OutboundPathQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_admin(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    let relative_path = query.path.trim_matches('/').to_owned();
    let path = safe_library_path(&app, &identity.tenant, &relative_path)?;
    let bytes = {
        let _lock = LIBRARY_MUTATION_LOCK
            .lock()
            .expect("library mutation lock poisoned");
        let root = library_root(&app, &identity.tenant);
        if !library_components_safe(&root, &path) {
            return Err(ApiError::not_found());
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(ApiError::not_found());
        }
        if app
            .store
            .has_active_library_grant(&identity.tenant, &relative_path, now_unix())
            .map_err(super::store_unavailable)?
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "outbound file is referenced by an active grant",
            ));
        }
        std::fs::remove_file(&path)
            .map_err(|_| ApiError::internal("delete outbound file failed"))?;
        metadata.len()
    };
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "outbound_file_deleted",
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

fn begin_outbound_operation<'a>(app: &'a App, tenant: &str) -> ApiResult<OutboundOperation<'a>> {
    let operation = app
        .sessions
        .try_begin_outbound(tenant)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "tenant deletion in progress"))?;
    if !tenant.is_empty()
        && app
            .store
            .tenant(tenant)
            .map_err(super::store_unavailable)?
            .is_none()
    {
        return Err(ApiError::not_found());
    }
    Ok(operation)
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

fn is_library_stage_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.starts_with(".vot-") && name.ends_with(".stage"))
}

fn library_root_safe(root: &Path) -> bool {
    std::fs::symlink_metadata(root)
        .is_ok_and(|meta| meta.file_type().is_dir() && !meta.file_type().is_symlink())
}

fn library_directory_safe(root: &Path, directory: &Path) -> bool {
    if !library_root_safe(root) || !library_directory_components_safe(root, directory) {
        return false;
    }
    std::fs::symlink_metadata(directory)
        .is_ok_and(|meta| meta.file_type().is_dir() && !meta.file_type().is_symlink())
}

fn library_directory_components_safe(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let mut current = root.to_owned();
    for component in relative.components() {
        current.push(component);
        let Ok(meta) = std::fs::symlink_metadata(&current) else {
            return true;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return false;
        }
    }
    true
}

fn direct_library_entries(
    root: &Path,
    directory: &Path,
) -> (Vec<String>, Vec<serde_json::Value>, bool) {
    let mut entries = BinaryHeap::new();
    let Ok(read_dir) = std::fs::read_dir(directory) else {
        return (Vec::new(), Vec::new(), false);
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        let name = entry.file_name();
        if directory == root
            && name
                .to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(crate::paths::TENANT_STORAGE_DIR))
        {
            continue;
        }
        if is_library_stage_name(&name) {
            continue;
        }
        let Some(relative) = path.strip_prefix(root).ok() else {
            continue;
        };
        let is_directory = meta.file_type().is_dir();
        if !is_directory && !meta.file_type().is_file() {
            continue;
        }
        entries.push((
            relative.to_string_lossy().replace('\\', "/"),
            is_directory,
            meta.len(),
        ));
        if entries.len() > MAX_LIBRARY_DIRECTORY_ENTRIES + 1 {
            entries.pop();
        }
    }
    let truncated = entries.len() > MAX_LIBRARY_DIRECTORY_ENTRIES;
    let mut entries = entries.into_sorted_vec();
    entries.truncate(MAX_LIBRARY_DIRECTORY_ENTRIES);
    let mut directories = Vec::new();
    let mut files = Vec::new();
    for (path, is_directory, bytes) in entries {
        if is_directory {
            directories.push(path);
        } else {
            files.push(json!({ "path": path, "bytes": bytes }));
        }
    }
    (directories, files, truncated)
}

fn list_library_directory(
    root: &Path,
    directory: &Path,
) -> Result<(Vec<String>, Vec<serde_json::Value>, bool), ()> {
    if !library_root_safe(root) {
        return Ok((Vec::new(), Vec::new(), false));
    }
    if !library_directory_safe(root, directory) {
        if std::fs::symlink_metadata(directory).is_err() {
            return Ok((Vec::new(), Vec::new(), false));
        }
        return Err(());
    }
    Ok(direct_library_entries(root, directory))
}

fn search_library_dir(
    root: &Path,
    directory: &Path,
    query: &str,
    matches: &mut BinaryHeap<(String, String, u64)>,
) {
    let Ok(entries) = std::fs::read_dir(directory) else {
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
        if directory == root
            && name
                .to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(crate::paths::TENANT_STORAGE_DIR))
        {
            continue;
        }
        if is_library_stage_name(&name) {
            continue;
        }
        if meta.file_type().is_dir() {
            search_library_dir(root, &path, query, matches);
        } else if meta.file_type().is_file() {
            let Some(relative) = path.strip_prefix(root).ok() else {
                continue;
            };
            let relative = relative.to_string_lossy().replace('\\', "/");
            let lowercase = relative.to_lowercase();
            if !lowercase.contains(query) {
                continue;
            }
            matches.push((lowercase, relative, meta.len()));
            if matches.len() > RETAINED_LIBRARY_SEARCH_RESULTS {
                matches.pop();
            }
        }
    }
}

fn list_library_search(root: &Path, query: &str) -> (Vec<serde_json::Value>, bool) {
    if !library_root_safe(root) {
        return (Vec::new(), false);
    }
    let mut matches = BinaryHeap::new();
    search_library_dir(root, root, query, &mut matches);
    let truncated = matches.len() > MAX_LIBRARY_SEARCH_RESULTS;
    let mut matches = matches.into_sorted_vec();
    matches.truncate(MAX_LIBRARY_SEARCH_RESULTS);
    (
        matches
            .into_iter()
            .map(|(_, path, bytes)| json!({ "path": path, "bytes": bytes }))
            .collect(),
        truncated,
    )
}

fn enumerate_library_selection(root: &Path, directory: &Path) -> ApiResult<Vec<serde_json::Value>> {
    enumerate_automation_files(root, directory, MAX_LIBRARY_SELECTION_FILES)?
        .into_iter()
        .map(|relative| {
            let path = root.join(&relative);
            let metadata = std::fs::symlink_metadata(path).map_err(|_| ApiError::not_found())?;
            Ok(json!({ "path": relative, "bytes": metadata.len() }))
        })
        .collect()
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
                match std::fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        match std::fs::symlink_metadata(&current) {
                            Ok(meta)
                                if meta.file_type().is_dir() && !meta.file_type().is_symlink() => {}
                            Ok(_) => {
                                return Err(ApiError::new(
                                    StatusCode::CONFLICT,
                                    "outbound path component is not a directory",
                                ))
                            }
                            Err(_) => {
                                return Err(ApiError::internal("inspect outbound directory failed"))
                            }
                        }
                    }
                    Err(_) => return Err(ApiError::internal("create outbound directory failed")),
                }
            }
            Err(_) => return Err(ApiError::internal("inspect outbound directory failed")),
        }
    }
    Ok(())
}

fn library_sources_match(
    root: &Path,
    selections: &[(String, PathBuf)],
    files: &[OutboundGrantFile],
) -> bool {
    selections.len() == files.len()
        && selections.iter().zip(files).all(|((_, path), file)| {
            if !library_components_safe(root, path) {
                return false;
            }
            let Ok(metadata) = std::fs::symlink_metadata(path) else {
                return false;
            };
            !metadata.file_type().is_symlink()
                && metadata.file_type().is_file()
                && metadata.len() == file.bytes
        })
}

#[derive(Deserialize)]
pub struct CreateOutboundRequest {
    #[serde(default)]
    directory: Option<String>,
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
    #[serde(default)]
    max_downloads: Option<u64>,
    #[serde(default)]
    notify_on_download: bool,
    #[serde(default = "default_expiry")]
    expires_days: u64,
}

const fn default_expiry() -> u64 {
    7
}

#[derive(Deserialize)]
pub struct OutboundGrantsQuery {
    limit: Option<String>,
    offset: Option<String>,
}

fn outbound_grants_paging(query: OutboundGrantsQuery) -> ApiResult<(usize, usize)> {
    let limit = query
        .limit
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "limit must be an integer between 1 and 100",
            )
        })?
        .unwrap_or(50usize);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "limit must be between 1 and 100",
        ));
    }
    let offset = query
        .offset
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "offset must be a non-negative integer",
            )
        })?
        .unwrap_or(0usize);
    if i64::try_from(offset).is_err() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "offset is too large",
        ));
    }
    Ok((limit, offset))
}

pub async fn list_outbound_grants(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<OutboundGrantsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_admin(&app, &headers)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    let (limit, offset) = outbound_grants_paging(query)?;
    let (grants, total) = app
        .store
        .outbound_grants_page(&identity.tenant, limit, offset, MAX_LIBRARY_SELECTION_FILES)
        .map_err(super::store_unavailable)?;
    let has_more = u64::try_from(offset)
        .unwrap_or(u64::MAX)
        .saturating_add(grants.len() as u64)
        < total;
    Ok(Json(json!({
        "grants": grants
            .into_iter()
            .map(|(grant, file_count)| public_grant_with_file_count(grant, file_count))
            .collect::<Vec<_>>(),
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
    })))
}

#[derive(Deserialize)]
pub struct AutomationTokenRequest {
    label: String,
    expires_days: u64,
}

pub async fn list_automation_tokens(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_automation_admin(&app, &headers)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    let tokens = app
        .store
        .automation_tokens(&identity.tenant)
        .map_err(super::store_unavailable)?;
    Ok(Json(json!({
        "tokens": tokens.iter().map(public_automation_token).collect::<Vec<_>>()
    })))
}

pub async fn create_automation_token(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<AutomationTokenRequest>,
) -> ApiResult<Response> {
    let identity = require_automation_admin(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    let label = request.label.trim().to_owned();
    if label.is_empty() || label.chars().count() > MAX_AUTOMATION_LABEL_CHARS {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "label must be 1..=100 characters",
        ));
    }
    if !(1..=365).contains(&request.expires_days) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "expires_days must be 1..=365",
        ));
    }
    let raw = auth::random_token();
    let created_at = now_unix();
    let token = AutomationToken {
        id: auth::random_token(),
        token_hash: hash_token(&raw),
        tenant: identity.tenant.clone(),
        label,
        created_at,
        expires_at: created_at.saturating_add(request.expires_days * 86_400),
        revoked_at: None,
        last_used_at: None,
    };
    app.store
        .insert_automation_token(token.clone())
        .map_err(ApiError::internal)?;
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "automation_token_created",
        &token.id,
        &json!({ "label": token.label, "expires_at": token.expires_at }),
    );
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "token": raw,
            "automation_token": public_automation_token(&token),
        })),
    )
        .into_response())
}

pub async fn delete_automation_token(
    State(app): State<Arc<App>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_automation_admin(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    if !app
        .store
        .revoke_automation_token(&identity.tenant, &id, now_unix())
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found());
    }
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "automation_token_revoked",
        &id,
        &json!({}),
    );
    Ok(Json(json!({ "ok": true })))
}

fn require_automation_admin(app: &App, headers: &HeaderMap) -> ApiResult<auth::AdminIdentity> {
    let identity = admin::require_admin(app, headers)?;
    if identity.role != "admin" {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "admin role required"));
    }
    Ok(identity)
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
    validate_max_downloads(request.max_downloads)?;
    let password_hash = hash_optional_password(request.password.as_deref())?;
    let has_legacy_fields =
        request.link_id.is_some() || request.upload_id.is_some() || request.file_index.is_some();
    if let Some(directory_name) = request.directory {
        if request.paths.is_some() || has_legacy_fields {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "directory cannot be combined with paths, link_id, upload_id, or file_index",
            ));
        }
        let directory_label = library_directory_label(&directory_name);
        let directory = automation_directory(&app, &identity.tenant, &directory_name)?;
        let root = library_root(&app, &identity.tenant);
        let paths = tokio::task::spawn_blocking(move || {
            enumerate_automation_files(&root, &directory, MAX_LIBRARY_PROJECT_FILES)
        })
        .await
        .map_err(|_| ApiError::internal("enumerate outbound files failed"))??;
        return create_library_grant(
            &app,
            &headers,
            &identity,
            &paths,
            MAX_LIBRARY_PROJECT_FILES,
            GrantOptions {
                label: request
                    .label
                    .filter(|label| !label.trim().is_empty())
                    .or(Some(directory_label)),
                password_hash,
                expires_days: request.expires_days,
                max_downloads: request.max_downloads,
                notify_on_download: request.notify_on_download,
            },
        )
        .await;
    }
    if let Some(paths) = request.paths.as_deref() {
        if has_legacy_fields {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "paths cannot be combined with link_id, upload_id, or file_index",
            ));
        }
        return create_library_grant(
            &app,
            &headers,
            &identity,
            paths,
            MAX_LIBRARY_SELECTION_FILES,
            GrantOptions {
                label: request.label,
                password_hash,
                expires_days: request.expires_days,
                max_downloads: request.max_downloads,
                notify_on_download: request.notify_on_download,
            },
        )
        .await;
    }
    if !has_legacy_fields {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "paths, directory, or link_id, upload_id, and file_index are required",
        ));
    }
    let link_id = request
        .link_id
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "link_id is required"))?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
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
        max_downloads: request.max_downloads,
        notify_on_download: request.notify_on_download,
        revoked_at: None,
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
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
        &json!({ "link": grant.link_id, "upload": grant.upload_id, "file_index": grant.file_index, "notify_on_download": grant.notify_on_download }),
    );
    let base = admin::base_url(&app, &headers);
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "grant": public_grant(grant), "url": format!("{base}/s/{token}") })),
    )
        .into_response())
}

#[derive(Deserialize)]
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
}

pub async fn automation_share(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<AutomationShareRequest>,
) -> ApiResult<Response> {
    let ip = super::client_ip(&headers, &peer, &app.config.trusted_proxies);
    if !app.automation_rate.allow(&ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many automation shares; try again later",
        ));
    }
    let bearer = automation_bearer(&headers)?;
    let token = app
        .store
        .authenticate_automation_token(&hash_token(&bearer), now_unix())
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::unauthorized)?;
    let _operation = begin_outbound_operation(&app, &token.tenant)?;
    if !(1..=30).contains(&request.expires_days) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "expires_days must be 1..=30",
        ));
    }
    validate_max_downloads(request.max_downloads)?;
    let directory_label = library_directory_label(&request.directory);
    let directory = automation_directory(&app, &token.tenant, &request.directory)?;
    let root = library_root(&app, &token.tenant);
    let paths = tokio::task::spawn_blocking(move || {
        enumerate_automation_files(&root, &directory, MAX_LIBRARY_PROJECT_FILES)
    })
    .await
    .map_err(|_| ApiError::internal("enumerate outbound files failed"))??;
    let identity = auth::AdminIdentity {
        subject: format!("automation:{}", token.id),
        tenant: token.tenant,
        role: "admin".to_owned(),
        grants: Vec::new(),
        credential_version: 1,
    };
    create_library_grant(
        &app,
        &headers,
        &identity,
        &paths,
        MAX_LIBRARY_PROJECT_FILES,
        GrantOptions {
            label: request
                .label
                .filter(|label| !label.trim().is_empty())
                .or(Some(directory_label)),
            password_hash: hash_optional_password(request.password.as_deref())?,
            expires_days: request.expires_days,
            max_downloads: request.max_downloads,
            notify_on_download: request.notify_on_download,
        },
    )
    .await
}

fn automation_bearer(headers: &HeaderMap) -> ApiResult<String> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| valid_token(token))
        .ok_or_else(ApiError::unauthorized)?;
    Ok(value.to_owned())
}

fn automation_directory(app: &App, tenant: &str, directory: &str) -> ApiResult<PathBuf> {
    if directory.len() > MAX_LIBRARY_DIRECTORY_INPUT_BYTES {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "directory is too long",
        ));
    }
    if directory.is_empty() || Path::new(directory).is_absolute() || directory.contains('\\') {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "directory must be a relative path",
        ));
    }
    let root = library_root(app, tenant);
    let path = safe_library_path(app, tenant, directory)?;
    if !library_components_safe(&root, &path) {
        return Err(ApiError::not_found());
    }
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ApiError::not_found());
    }
    Ok(path)
}

fn library_directory_label(directory: &str) -> String {
    directory
        .trim_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(directory)
        .to_owned()
}

fn enumerate_automation_files(
    root: &Path,
    directory: &Path,
    max_files: usize,
) -> ApiResult<Vec<String>> {
    fn visit(
        root: &Path,
        directory: &Path,
        paths: &mut Vec<String>,
        max_files: usize,
    ) -> ApiResult<()> {
        let entries = std::fs::read_dir(directory).map_err(|_| ApiError::not_found())?;
        for entry in entries {
            let entry = entry.map_err(|_| ApiError::not_found())?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
            if metadata.file_type().is_symlink() {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "directory contains a symlink",
                ));
            }
            if metadata.file_type().is_dir() {
                let name = entry.file_name();
                if is_library_stage_name(&name) {
                    continue;
                }
                visit(root, &path, paths, max_files)?;
            } else if metadata.file_type().is_file() {
                let name = entry.file_name();
                if is_library_stage_name(&name) {
                    continue;
                }
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| ApiError::not_found())?
                    .to_str()
                    .ok_or_else(ApiError::not_found)?
                    .replace('\\', "/");
                paths.push(relative);
                if paths.len() > max_files {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("directory contains too many files (maximum {max_files})"),
                    ));
                }
            }
        }
        Ok(())
    }

    let mut paths = Vec::new();
    visit(root, directory, &mut paths, max_files)?;
    paths.sort();
    if paths.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "directory contains no files",
        ));
    }
    Ok(paths)
}

struct GrantOptions {
    label: Option<String>,
    password_hash: Option<String>,
    expires_days: u64,
    max_downloads: Option<u64>,
    notify_on_download: bool,
}

async fn create_library_grant(
    app: &Arc<App>,
    headers: &HeaderMap,
    identity: &auth::AdminIdentity,
    requested: &[String],
    max_files: usize,
    options: GrantOptions,
) -> ApiResult<Response> {
    let _operation = begin_outbound_operation(app, &identity.tenant)?;
    if requested.is_empty() || requested.len() > max_files {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("paths must contain 1..={max_files} files"),
        ));
    }
    let root = library_root(app, &identity.tenant);
    let mut selections = Vec::with_capacity(requested.len());
    let mut selected = std::collections::HashSet::with_capacity(requested.len());
    let mut total_bytes = 0u64;
    for name in requested {
        let path = safe_library_path(app, &identity.tenant, name)?;
        if !library_components_safe(&root, &path) {
            return Err(ApiError::not_found());
        }
        let meta = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            return Err(ApiError::not_found());
        }
        let name = name.trim_matches('/').to_owned();
        if !selected.insert(name.clone()) {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "paths must not contain duplicates",
            ));
        }
        total_bytes = total_bytes
            .checked_add(meta.len())
            .filter(|total| *total <= app.config.max_upload_bytes)
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "selected files exceed total size limit",
                )
            })?;
        selections.push((name, path));
    }
    let max = app.config.max_upload_bytes;
    let revalidation = selections.clone();
    let hash_root = root.clone();
    let hashed = futures_util::stream::iter(selections.into_iter().map(|(name, path)| {
        let hash_root = hash_root.clone();
        async move {
            let _permit = LIBRARY_HASH_PERMITS
                .acquire()
                .await
                .map_err(|_| ApiError::internal("hash outbound files failed"))?;
            tokio::task::spawn_blocking(move || hash_library_file(&hash_root, &name, &path, max))
                .await
                .map_err(|_| ApiError::internal("hash outbound files failed"))?
                .map_err(|_| ApiError::not_found())
        }
    }))
    .buffered(LIBRARY_HASH_CONCURRENCY)
    .collect::<Vec<_>>()
    .await
    .into_iter()
    .collect::<ApiResult<Vec<_>>>()?;
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
    let label = options
        .label
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
        password_hash: options.password_hash,
        created_at,
        expires_at: created_at.saturating_add(options.expires_days * 86_400),
        max_downloads: options.max_downloads,
        notify_on_download: options.notify_on_download,
        revoked_at: None,
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
        files,
    };
    if grant.label.trim().is_empty() || grant.label.len() > 200 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "label must be 1..=200 characters",
        ));
    }
    {
        let _lock = LIBRARY_MUTATION_LOCK
            .lock()
            .expect("library mutation lock poisoned");
        if !library_sources_match(&root, &revalidation, &grant.files) {
            return Err(ApiError::not_found());
        }
        app.store
            .insert_outbound_grant(grant.clone())
            .map_err(ApiError::internal)?;
    }
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "outbound_grant_created",
        &grant.id,
        &json!({ "files": grant.files.len(), "notify_on_download": grant.notify_on_download }),
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
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
    })
}

pub async fn delete_outbound_grant(
    State(app): State<Arc<App>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_admin(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
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

#[derive(Deserialize)]
pub struct UpdateOutboundGrantRequest {
    #[serde(default)]
    rotate: Option<bool>,
    #[serde(default)]
    extend_days: Option<u64>,
    #[serde(default)]
    notify_on_download: Option<bool>,
}

pub async fn update_outbound_grant(
    State(app): State<Arc<App>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateOutboundGrantRequest>,
) -> ApiResult<Response> {
    let identity = admin::require_admin(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    let fields = [
        request.rotate.is_some(),
        request.extend_days.is_some(),
        request.notify_on_download.is_some(),
    ];
    if fields.iter().filter(|field| **field).count() != 1 || request.rotate == Some(false) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "choose exactly one grant lifecycle or policy action",
        ));
    }
    if let Some(notify_on_download) = request.notify_on_download {
        if !app
            .store
            .set_outbound_notify_on_download(&identity.tenant, &id, notify_on_download)
            .map_err(ApiError::internal)?
        {
            return Err(ApiError::not_found());
        }
        app.store.audit(
            &identity.tenant,
            &identity.subject,
            "outbound_grant_notify_on_download_changed",
            &id,
            &json!({ "notify_on_download": notify_on_download }),
        );
        return Ok(Json(json!({ "ok": true })).into_response());
    }
    if request.rotate == Some(true) {
        let token = auth::random_token();
        if !app
            .store
            .rotate_outbound_grant_token(&identity.tenant, &id, &hash_token(&token))
            .map_err(ApiError::internal)?
        {
            return Err(ApiError::not_found());
        }
        app.store.audit(
            &identity.tenant,
            &identity.subject,
            "outbound_grant_token_rotated",
            &id,
            &json!({}),
        );
        let base = admin::base_url(&app, &headers);
        return Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({ "url": format!("{base}/s/{token}") })),
        )
            .into_response());
    }
    let days = request.extend_days.expect("validated extend_days");
    if !(1..=30).contains(&days) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "extend_days must be 1..=30",
        ));
    }
    let expires_at = app
        .store
        .extend_outbound_grant(&identity.tenant, &id, days * 86_400, now_unix())
        .map_err(ApiError::internal)?
        .ok_or_else(ApiError::not_found)?;
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "outbound_grant_extended",
        &id,
        &json!({ "expires_at": expires_at, "days": days }),
    );
    Ok(Json(json!({ "expires_at": expires_at })).into_response())
}

pub async fn outbound_metadata(
    State(app): State<Arc<App>>,
    AxumPath(token): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let grant = active_grant(&app, &token)?;
    let _operation = begin_outbound_operation(&app, &grant.tenant)?;
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
            "max_downloads": grant.max_downloads,
            "receipt_key": app.signer.public_hex,
            "receipt_url": format!("/api/s/{token}/receipt"),
            "download_url": format!("/api/s/{token}/file"),
            "bundle_url": format!("/api/s/{token}/bundle"),
            "files": files,
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
    let _operation = begin_outbound_operation(&app, &grant.tenant)?;
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
    let _operation = begin_outbound_operation(&app, &grant.tenant)?;
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
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
) -> ApiResult<Response> {
    outbound_file_inner(app, headers, token, 0).await
}

pub async fn outbound_file_head(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
) -> ApiResult<Response> {
    outbound_file_head_inner(app, headers, token, 0).await
}

pub async fn outbound_file_indexed(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath((token, index)): AxumPath<(String, usize)>,
) -> ApiResult<Response> {
    outbound_file_inner(app, headers, token, index).await
}

pub async fn outbound_file_indexed_head(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath((token, index)): AxumPath<(String, usize)>,
) -> ApiResult<Response> {
    outbound_file_head_inner(app, headers, token, index).await
}

async fn outbound_file_inner(
    app: Arc<App>,
    headers: HeaderMap,
    token: String,
    index: usize,
) -> ApiResult<Response> {
    let (grant, leased, file) = active_download_grant(&app, &token, index, &headers)?;
    let _operation = begin_outbound_operation(&app, &grant.tenant)?;
    require_grant_access(&app, &grant, &headers)?;
    if !app.outbound_rate.allow(&grant.token_hash) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many downloads; try again later",
        ));
    }
    let source = source_info_indexed_with_file(&app, &grant, index, file.as_ref())?;
    let range = requested_range(&headers, &source.object)?;
    let active = if leased {
        ActiveDownload::claim_with_grant(
            Arc::clone(&app),
            &format!("{}:{index}:{}", grant.token_hash, auth::random_token()),
            &grant.token_hash,
        )?
    } else {
        ActiveDownload::claim(Arc::clone(&app), &format!("{}:{index}", grant.token_hash))?
    };
    let (stage, source, _receipt) = prepare(&app, &grant, index, range, file.as_ref()).await?;
    let file = tokio::fs::File::open(&stage.path)
        .await
        .map_err(|_| ApiError::internal("open staged file failed"))?;
    if !leased {
        record_download(&app, &grant, &[index])?;
    }
    let length = range.map_or(source.object.length, |(start, end)| end - start + 1);
    let file = file.take(length);
    let stream = ReaderStream::with_capacity(
        OutboundReader {
            file,
            _stage: stage,
            _active: active,
        },
        CHUNK,
    );
    let filename = safe_filename(&source.name);
    let mut response = Body::from_stream(stream).into_response();
    add_file_headers(&mut response, &source, filename, length, range)?;
    if range.is_some() {
        *response.status_mut() = StatusCode::PARTIAL_CONTENT;
    }
    if !leased {
        issue_download_lease(&app, &grant, &token, index, &mut response);
    }
    Ok(response)
}

async fn outbound_file_head_inner(
    app: Arc<App>,
    headers: HeaderMap,
    token: String,
    index: usize,
) -> ApiResult<Response> {
    let (grant, _leased, file) = active_download_grant(&app, &token, index, &headers)?;
    let _operation = begin_outbound_operation(&app, &grant.tenant)?;
    require_grant_access(&app, &grant, &headers)?;
    if !app.outbound_rate.allow(&grant.token_hash) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many downloads; try again later",
        ));
    }
    let source = source_info_indexed_with_file(&app, &grant, index, file.as_ref())?;
    let mut response = Body::empty().into_response();
    add_file_headers(
        &mut response,
        &source,
        safe_filename(&source.name),
        source.object.length,
        None,
    )?;
    Ok(response)
}

fn add_file_headers(
    response: &mut Response,
    source: &Source,
    filename: String,
    length: u64,
    range: Option<(u64, u64)>,
) -> ApiResult<()> {
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::try_from(etag(&source.object))
            .map_err(|_| ApiError::internal("download etag invalid"))?,
    );
    if let Some((start, end)) = range {
        response.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::try_from(format!("bytes {start}-{end}/{}", source.object.length))
                .map_err(|_| ApiError::internal("download range invalid"))?,
        );
    }
    let disposition = format!("attachment; filename=\"{filename}\"");
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::try_from(disposition)
            .map_err(|_| ApiError::internal("download filename invalid"))?,
    );
    Ok(())
}

fn requested_range(headers: &HeaderMap, object: &ObjectId) -> ApiResult<Option<(u64, u64)>> {
    let mut values = headers.get_all(header::RANGE).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(range_not_satisfiable(object.length));
    }
    let etag = etag(object);
    if let Some(value) = headers.get(header::IF_RANGE) {
        if value.to_str().ok() != Some(etag.as_str()) {
            return Ok(None);
        }
    }
    let value = value
        .to_str()
        .map_err(|_| range_not_satisfiable(object.length))?;
    let range =
        parse_range(value, object.length).ok_or_else(|| range_not_satisfiable(object.length))?;
    Ok(Some(range))
}

fn parse_range(value: &str, length: u64) -> Option<(u64, u64)> {
    let (unit, spec) = value.split_once('=')?;
    if !unit.eq_ignore_ascii_case("bytes") || spec.is_empty() || spec.contains(',') || length == 0 {
        return None;
    }
    let (start, end) = spec.split_once('-')?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().ok()?;
        if suffix == 0 {
            return None;
        }
        let first = length.saturating_sub(suffix);
        return Some((first, length - 1));
    }
    let first = start.parse::<u64>().ok()?;
    if first >= length {
        return None;
    }
    if end.is_empty() {
        return Some((first, length - 1));
    }
    let last = end.parse::<u64>().ok()?;
    if last < first {
        return None;
    }
    Some((first, last.min(length - 1)))
}

fn range_not_satisfiable(length: u64) -> ApiError {
    let mut error = ApiError::new(
        StatusCode::RANGE_NOT_SATISFIABLE,
        format!("bytes */{length}"),
    );
    error.content_range = Some(format!("bytes */{length}"));
    error
}

fn etag(object: &ObjectId) -> String {
    format!(
        "\"votport-{}-{}-{}\"",
        object.suite,
        hex::encode(object.root),
        object.length
    )
}

fn issue_download_lease(
    app: &App,
    grant: &OutboundGrant,
    token: &str,
    index: usize,
    response: &mut Response,
) {
    let lifetime = grant
        .expires_at
        .saturating_sub(now_unix())
        .min(DOWNLOAD_LEASE_SECS);
    if lifetime == 0 {
        return;
    }
    let value =
        auth::issue_download_lease(&app.secret, &grant.id, &grant.token_hash, index, lifetime);
    let cookie = format!(
        "{}={value}; Path=/api/s/{token}; HttpOnly; SameSite=Lax; Max-Age={lifetime}{}",
        download_lease_cookie_name(&grant.id, index),
        super::cookie_attributes(app)
    );
    if let Ok(value) = HeaderValue::try_from(cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
}

pub async fn outbound_bundle(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
) -> ApiResult<Response> {
    let grant = active_grant(&app, &token)?;
    let _operation = begin_outbound_operation(&app, &grant.tenant)?;
    require_grant_access(&app, &grant, &headers)?;
    if !app.outbound_rate.allow(&grant.token_hash) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many downloads; try again later",
        ));
    }
    let count = if grant.files.is_empty() {
        1
    } else {
        grant.files.len()
    };
    let total_bytes = if grant.files.is_empty() {
        Some(grant.bytes)
    } else {
        grant
            .files
            .iter()
            .try_fold(0u64, |total, file| total.checked_add(file.bytes))
    };
    if total_bytes.is_none_or(|bytes| bytes > app.config.max_upload_bytes) {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "bundle exceeds total size limit",
        ));
    }
    let active = ActiveDownload::claim(Arc::clone(&app), &format!("{}:bundle", grant.token_hash))?;
    let mut files = Vec::with_capacity(count);
    let mut names = std::collections::HashSet::with_capacity(count);
    for index in 0..count {
        let (stage, source, _receipt) = prepare(&app, &grant, index, None, None).await?;
        let relative = bundle_path(&source.name).ok_or_else(ApiError::not_found)?;
        if !names.insert(bundle_collision_key(&relative)) {
            return Err(ApiError::not_found());
        }
        files.push(PreparedBundleFile {
            stage,
            name: relative,
            bytes: source.object.length,
        });
    }
    let (archive, stages) = build_bundle(&app, files).await?;
    let length = tokio::fs::metadata(&archive.path)
        .await
        .map_err(|_| ApiError::internal("inspect bundle failed"))?
        .len();
    let file = tokio::fs::File::open(&archive.path)
        .await
        .map_err(|_| ApiError::internal("open bundle failed"))?;
    let indexes: Vec<usize> = (0..count).collect();
    record_download(&app, &grant, &indexes)?;
    let stream = ReaderStream::with_capacity(
        BundleReader {
            file,
            _archive: archive,
            _stages: stages,
            _active: active,
        },
        CHUNK,
    );
    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"deliverables.zip\""),
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
    if grant.revoked_at.is_some()
        || grant.expires_at <= now_unix()
        || grant
            .max_downloads
            .is_some_and(|max| grant.downloads >= max)
    {
        return Err(ApiError::not_found());
    }
    Ok(grant)
}

fn active_download_grant(
    app: &App,
    token: &str,
    index: usize,
    headers: &HeaderMap,
) -> ApiResult<(OutboundGrant, bool, Option<OutboundGrantFile>)> {
    if !valid_token(token) {
        return Err(ApiError::not_found());
    }
    let (grant, file) = app
        .store
        .outbound_grant_file_by_token_hash(&hash_token(token), index)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if grant.revoked_at.is_some() || grant.expires_at <= now_unix() {
        return Err(ApiError::not_found());
    }
    let leased = download_lease_authorized(app, &grant, index, headers);
    if !leased && grant_is_exhausted(&grant, index, file.as_ref()) {
        return Err(ApiError::not_found());
    }
    Ok((grant, leased, file))
}

fn grant_is_exhausted(
    grant: &OutboundGrant,
    index: usize,
    indexed_file: Option<&OutboundGrantFile>,
) -> bool {
    let Some(max) = grant.max_downloads else {
        return false;
    };
    indexed_file
        .or_else(|| grant.files.get(index))
        .map_or(grant.files.is_empty() && grant.downloads >= max, |file| {
            file.downloads >= max
        })
}

fn record_download(
    app: &Arc<App>,
    grant: &OutboundGrant,
    indexes: &[usize],
) -> ApiResult<OutboundDownloadResult> {
    match app
        .store
        .record_outbound_download(&grant.id, indexes, now_unix())
    {
        Ok(result) => {
            if grant.notify_on_download && (result.first_download || result.completed_delivery) {
                match app.store.outbound_grant_by_token_hash(&grant.token_hash) {
                    Ok(Some(full_grant)) => {
                        tokio::spawn(crate::notify::outbound_downloaded(
                            Arc::clone(app),
                            full_grant,
                            result,
                        ));
                    }
                    Ok(None) => {
                        tracing::warn!(grant_id = %grant.id, "download notification grant reload found no grant");
                    }
                    Err(error) => {
                        tracing::warn!(grant_id = %grant.id, %error, "download notification grant reload failed");
                    }
                }
            }
            Ok(result)
        }
        Err(error) if error == OUTBOUND_DOWNLOAD_LIMIT_REACHED => Err(ApiError::not_found()),
        Err(_) => Err(ApiError::internal("record download failed")),
    }
}

fn grant_cookie_name(grant_id: &str) -> String {
    format!("votport_s_{grant_id}")
}

fn download_lease_cookie_name(grant_id: &str, index: usize) -> String {
    format!("votport_d_{grant_id}_{index}")
}

fn download_lease_authorized(
    app: &App,
    grant: &OutboundGrant,
    index: usize,
    headers: &HeaderMap,
) -> bool {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            auth::cookie_value(cookies, &download_lease_cookie_name(&grant.id, index))
        })
        .is_some_and(|value| {
            auth::verify_download_lease(&app.secret, &grant.id, &grant.token_hash, index, value)
        })
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

struct PreparedBundleFile {
    stage: StagedFile,
    name: String,
    bytes: u64,
}

fn bundle_path(name: &str) -> Option<String> {
    let normalized = name.replace('\\', "/");
    let mut components = Vec::new();
    for component in Path::new(&normalized).components() {
        let std::path::Component::Normal(component) = component else {
            return None;
        };
        components.push(component.to_str()?.to_owned());
    }
    (!components.is_empty()).then(|| components.join("/"))
}

fn bundle_collision_key(name: &str) -> String {
    name.to_lowercase()
}

async fn build_bundle(
    app: &App,
    files: Vec<PreparedBundleFile>,
) -> ApiResult<(StagedFile, Vec<StagedFile>)> {
    let stage_dir = app
        .config
        .data_dir
        .join("outbound.stage")
        .join(format!(".vot-outbound-{}", auth::random_token()));
    std::fs::create_dir_all(&stage_dir)
        .map_err(|_| ApiError::internal("create bundle stage failed"))?;
    let archive_path = stage_dir.join(format!("{}.zip", auth::random_token()));
    let archive = StagedFile {
        path: archive_path.clone(),
    };
    let prepared = tokio::task::spawn_blocking(move || {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let output = options.open(&archive_path)?;
        let mut builder = ZipWriter::new(output);
        for file in &files {
            let mut input = std::fs::File::open(&file.stage.path)?;
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .large_file(file.bytes >= u32::MAX as u64);
            builder.start_file(&file.name, options)?;
            io::copy(&mut input, &mut builder)?;
        }
        let output = builder.finish()?;
        output.sync_all()?;
        Ok::<_, io::Error>(files.into_iter().map(|file| file.stage).collect())
    })
    .await
    .map_err(|_| ApiError::internal("bundle preparation failed"))?
    .map_err(|_| ApiError::internal("build bundle failed"))?;
    Ok((archive, prepared))
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

fn validate_max_downloads(max_downloads: Option<u64>) -> ApiResult<()> {
    if max_downloads.is_some_and(|max| !(1..=10_000).contains(&max)) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "max_downloads must be 1..=10000",
        ));
    }
    Ok(())
}

struct Source {
    path: PathBuf,
    object: ObjectId,
    name: String,
    receipt: Option<Vec<u8>>,
}

fn source_info_indexed(app: &App, grant: &OutboundGrant, index: usize) -> ApiResult<Source> {
    source_info_indexed_with_file(app, grant, index, None)
}

fn source_info_indexed_with_file(
    app: &App,
    grant: &OutboundGrant,
    index: usize,
    indexed_file: Option<&OutboundGrantFile>,
) -> ApiResult<Source> {
    if let Some(file) = indexed_file.or_else(|| grant.files.get(index)) {
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
    range: Option<(u64, u64)>,
    indexed_file: Option<&OutboundGrantFile>,
) -> ApiResult<(StagedFile, Source, Vec<u8>)> {
    let _pin = if grant.files.is_empty() && indexed_file.is_none() {
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
    let source = source_info_indexed_with_file(app, grant, index, indexed_file)?;
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
        let receipt = copy_verify(&source_path, &stage.path, expected, source_receipt, range)?;
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
    Ok((stage, source, receipt))
}

fn copy_verify(
    source: &Path,
    stage: &Path,
    expected: ObjectId,
    receipt_bytes: Option<Vec<u8>>,
    range: Option<(u64, u64)>,
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
    let mut offset = 0u64;
    loop {
        let count = input.read(&mut buf)?;
        if count == 0 {
            break;
        }
        builder
            .update(&buf[..count])
            .map_err(|_| io::Error::other("object"))?;
        if let Some((start, end)) = range {
            let chunk_end = offset
                .checked_add(count as u64)
                .and_then(|end| end.checked_sub(1))
                .ok_or_else(|| io::Error::other("source too large"))?;
            let write_start = start.max(offset);
            let write_end = end.min(chunk_end);
            if write_start <= write_end {
                let begin = usize::try_from(write_start - offset)
                    .map_err(|_| io::Error::other("range offset"))?;
                let finish = usize::try_from(write_end - offset + 1)
                    .map_err(|_| io::Error::other("range offset"))?;
                output.write_all(&buf[begin..finish])?;
            }
        } else {
            output.write_all(&buf[..count])?;
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("source too large"))?;
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
    let file_count = if grant.files.is_empty() {
        1
    } else {
        grant.files.len()
    };
    public_grant_with_file_count(grant, file_count)
}

fn public_grant_with_file_count(grant: OutboundGrant, file_count: usize) -> serde_json::Value {
    let files_truncated = file_count > MAX_LIBRARY_SELECTION_FILES;
    let files = if files_truncated {
        Vec::new()
    } else {
        grant
            .files
            .iter()
            .map(|file| {
                json!({ "name": file.name, "suite": file.suite, "root": file.root, "bytes": file.bytes, "downloads": file.downloads, "first_download_at": file.first_download_at, "last_download_at": file.last_download_at })
            })
            .collect()
    };
    json!({ "id": grant.id, "tenant": grant.tenant, "link_id": grant.link_id, "upload_id": grant.upload_id, "file_index": grant.file_index, "name": grant.name, "label": grant.label, "has_password": grant.password_hash.is_some(), "created_at": grant.created_at, "expires_at": grant.expires_at, "revoked_at": grant.revoked_at, "max_downloads": grant.max_downloads, "downloads": grant.downloads, "first_download_at": grant.first_download_at, "last_download_at": grant.last_download_at, "notify_on_download": grant.notify_on_download, "file_count": file_count, "files_truncated": files_truncated, "files": files })
}

fn public_automation_token(token: &AutomationToken) -> serde_json::Value {
    json!({
        "id": token.id,
        "tenant": token.tenant,
        "label": token.label,
        "created_at": token.created_at,
        "expires_at": token.expires_at,
        "revoked_at": token.revoked_at,
        "last_used_at": token.last_used_at,
    })
}

struct ActiveDownload {
    app: Arc<App>,
    key: String,
}
impl ActiveDownload {
    fn claim(app: Arc<App>, key: &str) -> ApiResult<Self> {
        let grant = key.rsplit_once(':').map_or(key, |(grant, _)| grant);
        Self::claim_with_grant(app, key, grant)
    }

    fn claim_with_grant(app: Arc<App>, key: &str, grant: &str) -> ApiResult<Self> {
        let mut active = app
            .outbound_active
            .lock()
            .expect("outbound active poisoned");
        if active.contains(key)
            || active.len() >= MAX_ACTIVE
            || active
                .iter()
                .filter(|other| {
                    other
                        .strip_prefix(grant)
                        .is_some_and(|suffix| suffix.starts_with(':'))
                })
                .count()
                >= MAX_ACTIVE_PER_GRANT
        {
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

struct OutboundReader<R> {
    file: R,
    _stage: StagedFile,
    _active: ActiveDownload,
}
impl<R: AsyncRead + Unpin> AsyncRead for OutboundReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}

struct BundleReader {
    file: tokio::fs::File,
    _archive: StagedFile,
    _stages: Vec<StagedFile>,
    _active: ActiveDownload,
}

impl AsyncRead for BundleReader {
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

    fn zip_entries(bytes: &[u8]) -> std::collections::HashMap<String, Vec<u8>> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let mut entries = std::collections::HashMap::new();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).unwrap();
            let name = entry.name().to_owned();
            let mut contents = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut contents).unwrap();
            entries.insert(name, contents);
        }
        entries
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
                notify_on_upload: false,
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
    fn concurrent_library_dir_creation_accepts_same_parent() {
        let directory = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles = (0..8)
            .map(|index| {
                let barrier = std::sync::Arc::clone(&barrier);
                let path = directory
                    .path()
                    .join("shared")
                    .join(format!("nested-{index}"));
                std::thread::spawn(move || {
                    barrier.wait();
                    create_library_dirs(&path)
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        assert!(directory.path().join("shared").is_dir());
    }

    #[test]
    fn hashes_are_not_raw_tokens() {
        assert_ne!(hash_token("a"), "a");
    }
    #[test]
    fn byte_ranges_support_all_single_range_forms() {
        assert_eq!(parse_range("bytes=2-4", 10), Some((2, 4)));
        assert_eq!(parse_range("bytes=2-", 10), Some((2, 9)));
        assert_eq!(parse_range("bytes=-3", 10), Some((7, 9)));
        assert_eq!(parse_range("bytes=-99", 10), Some((0, 9)));
        assert_eq!(parse_range("BYTES=0-99", 10), Some((0, 9)));
    }
    #[test]
    fn byte_ranges_reject_malformed_and_unsatisfiable_values() {
        for value in [
            "bytes=",
            "bytes=1-2,4-5",
            "bytes=abc-2",
            "bytes=2-1",
            "bytes=10-",
            "bytes=-0",
        ] {
            assert_eq!(parse_range(value, 10), None, "{value}");
        }
        assert_eq!(parse_range("bytes=0-", 0), None);
    }
    #[test]
    fn automation_share_rate_is_bounded_per_ip() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        for _ in 0..60 {
            assert!(app.automation_rate.allow("127.0.0.1"));
        }
        assert!(!app.automation_rate.allow("127.0.0.1"));
        assert!(app.automation_rate.allow("127.0.0.2"));
    }

    #[test]
    fn outbound_grants_paging_rejects_invalid_bounds_and_overflow() {
        assert_eq!(
            outbound_grants_paging(OutboundGrantsQuery {
                limit: None,
                offset: None,
            })
            .unwrap(),
            (50, 0)
        );
        for limit in ["0", "101", "nope"] {
            assert_eq!(
                outbound_grants_paging(OutboundGrantsQuery {
                    limit: Some(limit.to_owned()),
                    offset: None,
                })
                .unwrap_err()
                .status,
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        for offset in ["-1", "18446744073709551616"] {
            assert_eq!(
                outbound_grants_paging(OutboundGrantsQuery {
                    limit: None,
                    offset: Some(offset.to_owned()),
                })
                .unwrap_err()
                .status,
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
    }

    #[tokio::test]
    async fn outbound_grants_handler_returns_default_page_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        for index in 0..51 {
            app.store
                .insert_outbound_grant(OutboundGrant {
                    id: format!("grant-{index}"),
                    token_hash: format!("hash-{index}"),
                    password_hash: None,
                    tenant: String::new(),
                    link_id: String::new(),
                    upload_id: String::new(),
                    package_root: String::new(),
                    name: "file.bin".to_owned(),
                    suite: "blake3".to_owned(),
                    root: String::new(),
                    file_index: 0,
                    bytes: 0,
                    label: format!("grant-{index}"),
                    created_at: 1,
                    expires_at: 2,
                    revoked_at: None,
                    downloads: 0,
                    max_downloads: None,
                    notify_on_download: false,
                    first_download_at: None,
                    last_download_at: None,
                    files: Vec::new(),
                })
                .unwrap();
        }

        let response = crate::app::router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-grants")
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = body(response).await;
        assert_eq!(listed["limit"], 50);
        assert_eq!(listed["offset"], 0);
        assert_eq!(listed["total"], 51);
        assert_eq!(listed["has_more"], true);
        assert_eq!(listed["grants"].as_array().unwrap().len(), 50);
        assert_eq!(listed["grants"][0]["file_count"], 1);
        assert_eq!(listed["grants"][0]["files_truncated"], false);
        assert_eq!(listed["grants"][0]["files"], json!([]));
        assert_eq!(listed["grants"][0]["id"], "grant-50");
    }

    #[tokio::test]
    async fn deleting_library_files_checks_safety_and_active_grants() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        std::fs::create_dir_all(&app.config.outbound_dir).unwrap();
        let path = app.config.outbound_dir.join("delete.bin");
        std::fs::write(&path, b"payload").unwrap();
        let request_app = app.clone();
        let request = |path: &str| {
            Request::delete(format!("/api/admin/outbound-files?path={path}"))
                .header("cookie", admin_cookie(&request_app))
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap()
        };

        let response = crate::app::router(app.clone())
            .oneshot(request("../outside"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let mut grant = OutboundGrant {
            id: "active".to_owned(),
            token_hash: "active-hash".to_owned(),
            password_hash: None,
            tenant: String::new(),
            link_id: String::new(),
            upload_id: String::new(),
            package_root: String::new(),
            name: "delete.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: String::new(),
            file_index: 0,
            bytes: 7,
            label: "delete.bin".to_owned(),
            created_at: now_unix(),
            expires_at: now_unix().saturating_add(60),
            revoked_at: None,
            downloads: 0,
            max_downloads: Some(1),
            notify_on_download: false,
            first_download_at: None,
            last_download_at: None,
            files: Vec::new(),
        };
        grant.files = vec![OutboundGrantFile {
            source: "delete.bin".to_owned(),
            name: "delete.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: 7,
            receipt_b64: "receipt".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        app.store.insert_outbound_grant(grant).unwrap();
        let response = crate::app::router(app.clone())
            .oneshot(request("delete.bin"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(path.exists());

        app.store
            .revoke_outbound_grant("", "active", now_unix())
            .unwrap();
        let response = crate::app::router(app)
            .oneshot(request("delete.bin"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!path.exists());
    }

    #[test]
    fn library_grant_revalidation_rejects_changed_sources() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("outbound");
        std::fs::create_dir(&root).unwrap();
        let path = root.join("file.bin");
        std::fs::write(&path, b"payload").unwrap();
        let selections = vec![("file.bin".to_owned(), path.clone())];
        let file = OutboundGrantFile {
            source: "file.bin".to_owned(),
            name: "file.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: 7,
            receipt_b64: "receipt".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        };
        assert!(library_sources_match(
            &root,
            &selections,
            std::slice::from_ref(&file)
        ));
        std::fs::write(&path, b"changed length").unwrap();
        assert!(!library_sources_match(&root, &selections, &[file]));
    }

    #[test]
    fn filenames_are_single_safe_components() {
        assert_eq!(safe_filename("../a/b?.txt"), "b_.txt");
    }
    #[test]
    fn bundle_paths_are_relative_and_normalized() {
        assert_eq!(
            bundle_path("project/file.bin").as_deref(),
            Some("project/file.bin")
        );
        assert!(bundle_path("../file.bin").is_none());
        assert!(bundle_path("/file.bin").is_none());
        assert!(bundle_path("project/../file.bin").is_none());
        assert!(bundle_path("").is_none());
        assert_eq!(
            bundle_collision_key("Project/FINAL.MOV"),
            bundle_collision_key("project/final.mov")
        );
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
        assert!(copy_verify(&source, &stage, expected, None, Some((1, 3))).is_err());
    }

    #[test]
    fn copy_verify_stages_exact_range_and_full_source() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let range_stage = directory.path().join("range-stage");
        let full_stage = directory.path().join("full-stage");
        let payload = b"0123456789";
        std::fs::write(&source, payload).unwrap();

        let mut builder = InMemoryObjectBuilder::new(
            Suite::try_from(1).unwrap(),
            Some(payload.len() as u64),
            payload.len() as u64,
        )
        .unwrap();
        builder.update(payload).unwrap();
        let expected = builder.finish().unwrap().object_id().clone();

        copy_verify(
            &source,
            &range_stage,
            expected.clone(),
            Some(Vec::new()),
            Some((2, 6)),
        )
        .unwrap();
        assert_eq!(std::fs::read(&range_stage).unwrap(), b"23456");

        copy_verify(&source, &full_stage, expected, Some(Vec::new()), None).unwrap();
        assert_eq!(std::fs::read(&full_stage).unwrap(), payload);

        let boundary_source = directory.path().join("boundary-source");
        let boundary_stage = directory.path().join("boundary-stage");
        let mut boundary_payload = vec![0u8; CHUNK + 3];
        boundary_payload[CHUNK - 2..].copy_from_slice(b"abcde");
        std::fs::write(&boundary_source, &boundary_payload).unwrap();
        let mut boundary_builder = InMemoryObjectBuilder::new(
            Suite::try_from(1).unwrap(),
            Some(boundary_payload.len() as u64),
            boundary_payload.len() as u64,
        )
        .unwrap();
        boundary_builder.update(&boundary_payload).unwrap();
        let boundary_expected = boundary_builder.finish().unwrap().object_id().clone();
        copy_verify(
            &boundary_source,
            &boundary_stage,
            boundary_expected,
            Some(Vec::new()),
            Some((CHUNK as u64 - 2, CHUNK as u64 + 2)),
        )
        .unwrap();
        assert_eq!(std::fs::read(&boundary_stage).unwrap(), b"abcde");
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

    #[test]
    fn active_downloads_allow_four_distinct_files_per_grant() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let active: Vec<_> = (0..MAX_ACTIVE_PER_GRANT)
            .map(|index| ActiveDownload::claim(Arc::clone(&app), &format!("grant:{index}")))
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(ActiveDownload::claim(Arc::clone(&app), "grant:4").is_err());
        assert!(ActiveDownload::claim(Arc::clone(&app), "grant:0").is_err());
        drop(active);
        assert!(ActiveDownload::claim(Arc::clone(&app), "grant:4").is_ok());
    }

    #[test]
    fn leased_ranges_can_run_alongside_one_unleased_file_download() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let first = ActiveDownload::claim(Arc::clone(&app), "grant:0").unwrap();
        let leased =
            ActiveDownload::claim_with_grant(Arc::clone(&app), "grant:0:lease-unique", "grant")
                .unwrap();
        assert!(ActiveDownload::claim(Arc::clone(&app), "grant:0").is_err());
        drop((first, leased));
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
        assert_eq!(metadata["bundle_url"], format!("/api/s/{token}/bundle"));

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
    async fn resumable_downloads_count_once_and_head_does_not_stage() {
        let (_directory, app, cookie, expected_bytes) = fixture().await;
        let created = body(
            crate::app::router(app.clone())
                .oneshot(
                    Request::post("/api/admin/outbound-grants")
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7,"max_downloads":1}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
        let head = crate::app::router(app.clone())
            .oneshot(
                Request::head(format!("/api/s/{token}/file"))
                    .header(header::RANGE, "bytes=0-6")
                    .header(header::IF_RANGE, "\"not-the-etag\"")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers()[header::CONTENT_LENGTH],
            expected_bytes.len().to_string()
        );
        assert!(head.headers().get(header::SET_COOKIE).is_none());
        assert!(!app.config.data_dir.join("outbound.stage").exists());

        let first = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .header(header::RANGE, "bytes=0-6")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(first.headers()[header::CONTENT_RANGE], "bytes 0-6/16");
        assert_eq!(first.headers()[header::CONTENT_LENGTH], "7");
        assert_eq!(first.headers()[header::ACCEPT_RANGES], "bytes");
        let etag = first.headers()[header::ETAG].to_str().unwrap().to_owned();
        let lease = first.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert!(first.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("HttpOnly"));
        assert!(first.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("SameSite=Lax"));
        assert!(first.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Secure"));
        assert_eq!(
            first.into_body().collect().await.unwrap().to_bytes(),
            &expected_bytes[..7]
        );

        let second = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .header(header::RANGE, "bytes=7-")
                    .header(header::IF_RANGE, etag)
                    .header(header::COOKIE, &lease)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(second.headers()[header::CONTENT_RANGE], "bytes 7-15/16");
        assert_eq!(
            second.into_body().collect().await.unwrap().to_bytes(),
            &expected_bytes[7..]
        );

        let exhausted = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .header(header::RANGE, "bytes=7-15")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exhausted.status(), StatusCode::NOT_FOUND);
        let invalid_lease = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .header(header::COOKIE, "votport_d_invalid=forged")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_lease.status(), StatusCode::NOT_FOUND);

        let id = created["grant"]["id"].as_str().unwrap();
        let rotated = crate::app::router(app.clone())
            .oneshot(
                Request::patch(format!("/api/admin/outbound-grants/{id}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rotate":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rotated.status(), StatusCode::OK);
        let old_lease_after_rotation = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .header(header::COOKIE, &lease)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_lease_after_rotation.status(), StatusCode::NOT_FOUND);

        let created = body(
            crate::app::router(app.clone())
                .oneshot(
                    Request::post("/api/admin/outbound-grants")
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        let revoke_token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
        let first = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{revoke_token}/file"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let revoke_lease = first.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let revoke_id = created["grant"]["id"].as_str().unwrap();
        let revoke = crate::app::router(app.clone())
            .oneshot(
                Request::delete(format!("/api/admin/outbound-grants/{revoke_id}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke.status(), StatusCode::OK);
        let old_lease_after_revoke = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{revoke_token}/file"))
                    .header(header::COOKIE, revoke_lease)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_lease_after_revoke.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn range_errors_and_if_range_mismatch_are_safe() {
        let (_directory, app, cookie, expected_bytes) = fixture().await;
        let created = body(
            crate::app::router(app.clone())
                .oneshot(
                    Request::post("/api/admin/outbound-grants")
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7}"#,
                        ))
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
        for value in ["bytes=0-1,2-3", "bytes=99-", "bytes=3-2"] {
            let response = crate::app::router(app.clone())
                .oneshot(
                    Request::get(format!("/api/s/{token}/file"))
                        .header(header::RANGE, value)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
            assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes */16");
        }
        let mut multiple = Request::get(format!("/api/s/{token}/file"))
            .body(Body::empty())
            .unwrap();
        multiple
            .headers_mut()
            .append(header::RANGE, HeaderValue::from_static("bytes=0-1"));
        multiple
            .headers_mut()
            .append(header::RANGE, HeaderValue::from_static("bytes=2-3"));
        let multiple = crate::app::router(app.clone())
            .oneshot(multiple)
            .await
            .unwrap();
        assert_eq!(multiple.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(multiple.headers()[header::CONTENT_RANGE], "bytes */16");
        let full = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .header(header::RANGE, "bytes=0-1")
                    .header(header::IF_RANGE, "\"wrong\"")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(full.status(), StatusCode::OK);
        assert_eq!(full.headers()[header::CONTENT_LENGTH], "16");
        assert!(full.headers().get(header::CONTENT_RANGE).is_none());
        assert_eq!(
            full.into_body().collect().await.unwrap().to_bytes(),
            expected_bytes
        );
    }

    #[tokio::test]
    async fn grant_lifecycle_rotation_and_extension_are_scoped() {
        let (_directory, app, cookie, _expected_bytes) = fixture().await;
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let created = body(response).await;
        let old_url = created["url"].as_str().unwrap().to_owned();
        let old_token = old_url.rsplit('/').next().unwrap().to_owned();
        let id = created["grant"]["id"].as_str().unwrap();
        let invalid = crate::app::router(app.clone())
            .oneshot(
                Request::patch(format!("/api/admin/outbound-grants/{id}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rotate":true,"extend_days":7}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let rotated = crate::app::router(app.clone())
            .oneshot(
                Request::patch(format!("/api/admin/outbound-grants/{id}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"rotate":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rotated.status(), StatusCode::OK);
        let rotated = body(rotated).await;
        let new_url = rotated["url"].as_str().unwrap();
        assert_ne!(new_url, old_url);
        assert_eq!(
            crate::app::router(app.clone())
                .oneshot(
                    Request::get(format!("/api/s/{old_token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let extended = crate::app::router(app.clone())
            .oneshot(
                Request::patch(format!("/api/admin/outbound-grants/{id}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"extend_days":7}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(extended.status(), StatusCode::OK);
        assert!(body(extended).await["expires_at"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn exhausted_grant_is_not_available_for_a_second_download() {
        let (_directory, app, cookie, expected_bytes) = fixture().await;
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7,"max_downloads":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let created = body(response).await;
        assert_eq!(created["grant"]["max_downloads"], 1);
        let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
        let first = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(
            first.into_body().collect().await.unwrap().to_bytes(),
            expected_bytes
        );
        let second = crate::app::router(app)
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::NOT_FOUND);
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

        for suffix in ["/file", "/receipt", "/bundle"] {
            let mut request = Request::get(format!("/api/s/{token}{suffix}"));
            if matches!(suffix, "/file" | "/bundle") {
                request =
                    request.extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))));
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

        let bundle = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/bundle"))
                    .header("cookie", &grant_cookie)
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bundle.status(), StatusCode::OK);
        assert_eq!(bundle.headers()[header::CONTENT_TYPE], "application/zip");
        assert_eq!(
            bundle.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"deliverables.zip\""
        );
        assert!(bundle.headers().get(header::ACCEPT_RANGES).is_none());
        let bundle = bundle.into_body().collect().await.unwrap().to_bytes();
        let entries = zip_entries(&bundle);
        assert_eq!(
            entries
                .keys()
                .map(String::as_str)
                .collect::<std::collections::HashSet<_>>(),
            ["received.bin"].into_iter().collect()
        );
        assert_eq!(entries["received.bin"], expected_bytes);
        assert!(!entries.keys().any(|name| name.contains("receipt")));
        assert!(!entries.contains_key("manifest.json"));
        assert!(app.outbound_active.lock().unwrap().is_empty());

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

        let duplicate = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"paths":["project/one.bin","project/one.bin"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::UNPROCESSABLE_ENTITY);

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
        assert_eq!(created["grant"]["file_count"], 2);
        assert_eq!(created["grant"]["files_truncated"], false);
        assert_eq!(created["grant"]["files"].as_array().unwrap().len(), 2);
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
        let bundle = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/bundle"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bundle.status(), StatusCode::OK);
        let bundle = bundle.into_body().collect().await.unwrap().to_bytes();
        let entries = zip_entries(&bundle);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries["project/one.bin"], first);
        assert_eq!(entries["project/two.bin"], b"second file");
        assert!(!entries.keys().any(|name| name.contains("receipt")));
        assert!(!entries.contains_key("manifest.json"));
        assert!(app.outbound_active.lock().unwrap().is_empty());
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
        let mutated = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/files/0"))
                    .header(header::RANGE, "bytes=0-1")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 4))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mutated.status(), StatusCode::NOT_FOUND);
        let bundle = crate::app::router(app)
            .oneshot(
                Request::get(format!("/api/s/{token}/bundle"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 6))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bundle.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn library_grant_restore_requires_outbound_volume() {
        let (directory, app, cookie, expected) = fixture().await;
        let source = app.config.outbound_dir.join("restore.bin");
        std::fs::write(&source, &expected).unwrap();
        let created = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"paths":["restore.bin"],"label":"restore"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let token = body(created).await["url"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();

        let snapshot = directory.path().join("backup.db");
        app.store.backup_into(&snapshot).unwrap();
        let restored_directory = tempfile::tempdir().unwrap();
        let restored_data = restored_directory.path().join("data");
        std::fs::create_dir_all(&restored_data).unwrap();
        std::fs::copy(&snapshot, restored_data.join("votport.db")).unwrap();
        std::fs::copy(
            directory.path().join("data/receipt.key"),
            restored_data.join("receipt.key"),
        )
        .unwrap();
        let restored = crate::api::testing::build(restored_directory.path());

        let unavailable = crate::app::router(restored.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/files/0"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::NOT_FOUND);

        std::fs::create_dir_all(&restored.config.outbound_dir).unwrap();
        std::fs::copy(&source, restored.config.outbound_dir.join("restore.bin")).unwrap();
        let available = crate::app::router(restored)
            .oneshot(
                Request::get(format!("/api/s/{token}/files/0"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(available.status(), StatusCode::OK);
        assert_eq!(
            available.into_body().collect().await.unwrap().to_bytes(),
            expected
        );
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
    async fn library_grant_caps_the_aggregate_selection_size() {
        let directory = tempfile::tempdir().unwrap();
        let mut app = crate::api::testing::build(directory.path());
        Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 5;
        std::fs::write(app.config.outbound_dir.join("one.bin"), b"one").unwrap();
        std::fs::write(app.config.outbound_dir.join("two.bin"), b"two").unwrap();
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", admin_cookie(&app))
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"paths":["one.bin","two.bin"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    fn chunk_request(
        cookie: &str,
        path: &str,
        upload_id: &str,
        start: u64,
        end: u64,
        total: u64,
        bytes: &[u8],
    ) -> Request<Body> {
        Request::post(format!("/api/admin/outbound-files?path={path}"))
            .header("cookie", cookie)
            .header("x-votport", "1")
            .header(OUTBOUND_UPLOAD_ID, upload_id)
            .header(
                header::CONTENT_RANGE,
                format!("bytes {start}-{end}/{total}"),
            )
            .header(header::CONTENT_LENGTH, bytes.len())
            .body(Body::from(bytes.to_vec()))
            .unwrap()
    }

    #[tokio::test]
    async fn resumable_library_upload_keeps_partial_files_unpublished() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "a".repeat(64);
        let response = crate::app::router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "partial.bin",
                &upload_id,
                0,
                2,
                6,
                b"abc",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let progress = body(response).await;
        assert_eq!(progress["complete"], false);
        assert_eq!(progress["offset"], 3);
        assert_eq!(progress["bytes"], 6);
        assert!(!app.config.outbound_dir.join("partial.bin").exists());
        assert_eq!(
            std::fs::read(app.config.outbound_dir.join(outbound_stage_name(
                &app.config.outbound_dir.join("partial.bin"),
                &upload_id,
            )))
            .unwrap(),
            b"abc"
        );
        assert!(app.store.audit_export("", 0, 0, 100).unwrap().is_empty());
    }

    #[tokio::test]
    async fn resumable_library_upload_resynchronizes_and_audits_completion() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "b".repeat(64);
        let first = crate::app::router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "resume.bin",
                &upload_id,
                0,
                2,
                6,
                b"abc",
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let mismatch = crate::app::router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "resume.bin",
                &upload_id,
                0,
                2,
                6,
                b"abc",
            ))
            .await
            .unwrap();
        assert_eq!(mismatch.status(), StatusCode::CONFLICT);
        assert_eq!(body(mismatch).await["offset"], 3);

        let complete = crate::app::router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "resume.bin",
                &upload_id,
                3,
                5,
                6,
                b"def",
            ))
            .await
            .unwrap();
        assert_eq!(complete.status(), StatusCode::OK);
        let complete = body(complete).await;
        assert_eq!(complete["complete"], true);
        assert_eq!(complete["offset"], 6);
        assert_eq!(
            std::fs::read(app.config.outbound_dir.join("resume.bin")).unwrap(),
            b"abcdef"
        );
        assert!(!app
            .config
            .outbound_dir
            .join(outbound_stage_name(
                &app.config.outbound_dir.join("resume.bin"),
                &upload_id,
            ))
            .exists());
        let audits = app.store.audit_export("", 0, 0, 100).unwrap();
        assert_eq!(
            audits
                .iter()
                .filter(|row| row.event == "outbound_file_uploaded")
                .count(),
            1
        );
        assert_eq!(audits[0].detail["bytes"], 6);
    }

    #[tokio::test]
    async fn resumable_library_upload_rolls_back_an_invalid_chunk() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "e".repeat(64);
        let first = crate::app::router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "rollback.bin",
                &upload_id,
                0,
                2,
                6,
                b"abc",
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let invalid = Request::post("/api/admin/outbound-files?path=rollback.bin")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header(OUTBOUND_UPLOAD_ID, &upload_id)
            .header(header::CONTENT_RANGE, "bytes 3-5/6")
            .header(header::CONTENT_LENGTH, 3)
            .body(Body::from("defg"))
            .unwrap();
        let invalid = crate::app::router(app.clone())
            .oneshot(invalid)
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert!(!app.config.outbound_dir.join("rollback.bin").exists());
        let stage = app.config.outbound_dir.join(outbound_stage_name(
            &app.config.outbound_dir.join("rollback.bin"),
            &upload_id,
        ));
        assert_eq!(std::fs::read(stage).unwrap(), b"abc");
    }

    #[tokio::test]
    async fn resumable_library_upload_separates_sibling_stages_with_same_id() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "f".repeat(64);
        for (path, bytes) in [("sibling-a.bin", b"abc"), ("sibling-b.bin", b"xyz")] {
            let response = crate::app::router(app.clone())
                .oneshot(chunk_request(&cookie, path, &upload_id, 0, 2, 6, bytes))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let first = app.config.outbound_dir.join(outbound_stage_name(
            &app.config.outbound_dir.join("sibling-a.bin"),
            &upload_id,
        ));
        let second = app.config.outbound_dir.join(outbound_stage_name(
            &app.config.outbound_dir.join("sibling-b.bin"),
            &upload_id,
        ));
        assert_ne!(first, second);
        assert_eq!(std::fs::read(first).unwrap(), b"abc");
        assert_eq!(std::fs::read(second).unwrap(), b"xyz");
    }

    #[tokio::test]
    async fn resumable_library_upload_rejects_limits_before_staging() {
        let directory = tempfile::tempdir().unwrap();
        let mut app = crate::api::testing::build(directory.path());
        Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 5;
        let cookie = admin_cookie(&app);
        let upload_id = "c".repeat(64);
        let response = crate::app::router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "limited.bin",
                &upload_id,
                0,
                5,
                6,
                b"abcdef",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!app.config.outbound_dir.join("limited.bin").exists());
        assert!(!app
            .config
            .outbound_dir
            .join(outbound_stage_name(
                &app.config.outbound_dir.join("limited.bin"),
                &upload_id,
            ))
            .exists());
        let mut headers = HeaderMap::new();
        headers.insert(OUTBOUND_UPLOAD_ID, HeaderValue::from_static("bad"));
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_static("bytes 0-16777216/16777217"),
        );
        assert_eq!(
            parse_outbound_content_range(&headers).unwrap(),
            (0, 16_777_216, 16_777_217)
        );
    }

    #[tokio::test]
    async fn resumable_library_upload_serializes_duplicate_chunks() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "d".repeat(64);
        let first = chunk_request(&cookie, "concurrent.bin", &upload_id, 0, 2, 6, b"abc");
        let second = chunk_request(&cookie, "concurrent.bin", &upload_id, 0, 2, 6, b"xyz");
        let (first, second) = tokio::join!(
            crate::app::router(app.clone()).oneshot(first),
            crate::app::router(app.clone()).oneshot(second),
        );
        let statuses = [first.unwrap().status(), second.unwrap().status()];
        assert!(statuses.contains(&StatusCode::OK));
        assert!(statuses.contains(&StatusCode::CONFLICT));
        assert_eq!(
            std::fs::metadata(app.config.outbound_dir.join(outbound_stage_name(
                &app.config.outbound_dir.join("concurrent.bin"),
                &upload_id,
            )))
            .unwrap()
            .len(),
            3
        );
        assert!(app
            .outbound_upload_locks
            .iter()
            .all(|lock| lock.try_lock().is_ok()));
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

    #[tokio::test]
    async fn scoped_library_directory_lists_sorted_direct_entries() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let root = &app.config.outbound_dir;
        std::fs::write(root.join("z.bin"), b"z").unwrap();
        std::fs::write(root.join("a.bin"), b"a").unwrap();
        std::fs::create_dir_all(root.join("zdir/nested")).unwrap();
        std::fs::create_dir_all(root.join("adir")).unwrap();
        std::fs::create_dir_all(root.join(".vot-dir.stage")).unwrap();
        std::fs::write(root.join("adir/nested.bin"), b"nested").unwrap();
        std::fs::write(root.join(".vot-upload.stage"), b"stage").unwrap();
        std::fs::create_dir_all(root.join(crate::paths::TENANT_STORAGE_DIR).join("named")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("adir"), root.join("link")).unwrap();

        let response = crate::app::router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?directory=")
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = body(response).await;
        assert_eq!(listed["directory"], "");
        assert_eq!(listed["directories"], json!(["adir", "zdir"]));
        assert_eq!(listed["files"][0]["path"], "a.bin");
        assert_eq!(listed["files"][1]["path"], "z.bin");
        assert_eq!(listed["truncated"], false);

        let response = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!(
                    "/api/admin/outbound-files?directory={}",
                    crate::paths::TENANT_STORAGE_DIR
                ))
                .header("cookie", admin_cookie(&app))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let response = crate::app::router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?directory=adir")
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = body(response).await;
        assert_eq!(listed["directory"], "adir");
        assert_eq!(listed["directories"], json!([]));
        assert_eq!(listed["files"][0]["path"], "adir/nested.bin");

        let response = crate::app::router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?selection=adir")
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let selected = body(response).await;
        assert_eq!(
            selected["files"],
            json!([{ "path": "adir/nested.bin", "bytes": 6 }])
        );

        std::fs::create_dir_all(root.join("large")).unwrap();
        for index in 0..65 {
            std::fs::write(root.join(format!("large/file-{index:02}.bin")), b"x").unwrap();
        }
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?selection=large")
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        #[cfg(unix)]
        {
            let response = crate::app::router(app.clone())
                .oneshot(
                    Request::get("/api/admin/outbound-files?selection=link")
                        .header("cookie", admin_cookie(&app))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[test]
    fn scoped_library_directory_caps_direct_entries() {
        let directory = tempfile::tempdir().unwrap();
        for index in 0..=MAX_LIBRARY_DIRECTORY_ENTRIES {
            std::fs::write(directory.path().join(format!("file-{index:04}.bin")), b"x").unwrap();
        }
        let (directories, files, truncated) =
            direct_library_entries(directory.path(), directory.path());
        assert!(directories.is_empty());
        assert_eq!(files.len(), MAX_LIBRARY_DIRECTORY_ENTRIES);
        assert!(truncated);
        assert_eq!(files[0]["path"], "file-0000.bin");
        assert_eq!(
            files[MAX_LIBRARY_DIRECTORY_ENTRIES - 1]["path"],
            "file-0999.bin"
        );
    }

    #[tokio::test]
    async fn admin_directory_grant_supports_large_projects_and_public_metadata() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let project = app.config.outbound_dir.join("project");
        std::fs::create_dir(&project).unwrap();
        for index in 0..=1000 {
            std::fs::write(project.join(format!("file-{index:02}.bin")), b"x").unwrap();
        }
        for payload in [
            json!({ "directory": "project", "paths": ["project/file-00.bin"] }),
            json!({ "directory": "x".repeat(MAX_LIBRARY_DIRECTORY_INPUT_BYTES + 1) }),
        ] {
            let response = crate::app::router(app.clone())
                .oneshot(
                    Request::post("/api/admin/outbound-grants")
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({ "expires_days": 1, "directory": payload["directory"], "paths": payload["paths"] }).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
        let response = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "directory": "project", "expires_days": 1 }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created = body(response).await;
        assert_eq!(created["grant"]["file_count"], 1001);
        assert_eq!(created["grant"]["files_truncated"], true);
        assert_eq!(created["grant"]["files"], json!([]));
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
        let files = metadata["files"].as_array().unwrap();
        assert_eq!(files.len(), 1001);
        assert!(files.windows(2).all(|pair| {
            pair[0]["name"].as_str().unwrap() <= pair[1]["name"].as_str().unwrap()
        }));

        let history = crate::app::router(app)
            .oneshot(
                Request::get("/api/admin/outbound-grants")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(history.status(), StatusCode::OK);
        let history = body(history).await;
        assert_eq!(history["grants"][0]["file_count"], 1001);
        assert_eq!(history["grants"][0]["files_truncated"], true);
        assert_eq!(history["grants"][0]["files"], json!([]));
    }

    #[test]
    fn recursive_library_enumerator_rejects_more_than_project_limit() {
        let directory = tempfile::tempdir().unwrap();
        for index in 0..=MAX_LIBRARY_PROJECT_FILES {
            std::fs::write(directory.path().join(format!("file-{index:04}.bin")), b"x").unwrap();
        }
        let error = enumerate_automation_files(
            directory.path(),
            directory.path(),
            MAX_LIBRARY_PROJECT_FILES,
        )
        .unwrap_err();
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error.message.contains("maximum 10000"));
    }

    #[tokio::test]
    async fn scoped_library_search_is_literal_case_insensitive_and_capped() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        for index in 0..205 {
            std::fs::write(
                app.config
                    .outbound_dir
                    .join(format!("match-{index:03}.bin")),
                b"x",
            )
            .unwrap();
        }
        std::fs::create_dir_all(app.config.outbound_dir.join("nested")).unwrap();
        std::fs::write(app.config.outbound_dir.join("nested/noise.bin"), b"match").unwrap();
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
                .join("named/match-reserved.bin"),
            b"x",
        )
        .unwrap();
        std::fs::write(app.config.outbound_dir.join(".vot-match.stage"), b"x").unwrap();
        #[cfg(unix)]
        {
            std::fs::create_dir_all(directory.path().join("outside")).unwrap();
            std::fs::write(directory.path().join("outside/match-outside.bin"), b"x").unwrap();
            std::os::unix::fs::symlink(
                directory.path().join("outside"),
                app.config.outbound_dir.join("000-match-link"),
            )
            .unwrap();
        }

        let response = crate::app::router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?q=MaTcH")
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = body(response).await;
        assert_eq!(
            listed["files"].as_array().unwrap().len(),
            MAX_LIBRARY_SEARCH_RESULTS
        );
        assert_eq!(listed["files"][0]["path"], "match-000.bin");
        assert_eq!(listed["files"][199]["path"], "match-199.bin");
        assert_eq!(listed["truncated"], true);
        let paths = listed["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file["path"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(!paths.iter().any(|path| path.contains("reserved")));
        assert!(!paths.iter().any(|path| path.ends_with(".stage")));
        assert!(!paths.iter().any(|path| path.contains("outside")));
    }

    #[tokio::test]
    async fn scoped_library_listing_rejects_invalid_queries() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        for uri in [
            "/api/admin/outbound-files?directory=one&q=two".to_owned(),
            "/api/admin/outbound-files?directory=one&selection=two".to_owned(),
            "/api/admin/outbound-files?selection=".to_owned(),
            "/api/admin/outbound-files?q=".to_owned(),
            format!("/api/admin/outbound-files?q={}", "x".repeat(101)),
            format!("/api/admin/outbound-files?directory={}", "x".repeat(1025)),
        ] {
            let response = crate::app::router(app.clone())
                .oneshot(
                    Request::get(uri)
                        .header("cookie", admin_cookie(&app))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    #[tokio::test]
    async fn automation_token_shares_recursive_library_without_leaking_token() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        std::fs::create_dir_all(app.config.outbound_dir.join("project/sub")).unwrap();
        std::fs::write(app.config.outbound_dir.join("project/a.txt"), b"a").unwrap();
        std::fs::write(app.config.outbound_dir.join("project/sub/b.txt"), b"b").unwrap();
        let create = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/admin/automation-tokens")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"label":"CI","expires_days":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::OK);
        assert_eq!(
            create.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let created = body(create).await;
        let raw = created["token"].as_str().unwrap().to_owned();
        assert!(valid_token(&raw));
        assert!(created["automation_token"].get("token_hash").is_none());

        let listed = crate::app::router(app.clone())
            .oneshot(
                Request::get("/api/admin/automation-tokens")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let listed = body(listed).await;
        assert!(listed["tokens"][0].get("token_hash").is_none());
        assert!(listed["tokens"][0].get("token").is_none());

        for authorization in [None, Some("Bearer nope")] {
            let mut request = Request::post("/api/automation/share")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"directory":"project","expires_days":1}"#))
                .unwrap();
            if let Some(value) = authorization {
                request
                    .headers_mut()
                    .insert(header::AUTHORIZATION, HeaderValue::from_static(value));
            }
            request
                .extensions_mut()
                .insert(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    10,
                ))));
            assert_eq!(
                crate::app::router(app.clone())
                    .oneshot(request)
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }

        let share = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/automation/share")
                    .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        11,
                    ))))
                    .body(Body::from(r#"{"directory":"project","expires_days":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(share.status(), StatusCode::OK);
        let share = body(share).await;
        assert_eq!(share["grant"]["label"], "project");
        assert_eq!(share["grant"]["files"][0]["name"], "project/a.txt");
        assert_eq!(share["grant"]["files"][1]["name"], "project/sub/b.txt");
        assert_eq!(share["grant"]["has_password"], false);

        let large = app.config.outbound_dir.join("automation-large");
        std::fs::create_dir(&large).unwrap();
        for index in 0..=1000 {
            std::fs::write(large.join(format!("file-{index:02}.bin")), b"x").unwrap();
        }
        let large_share = crate::app::router(app.clone())
            .oneshot(
                Request::post("/api/automation/share")
                    .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        15,
                    ))))
                    .body(Body::from(
                        r#"{"directory":"automation-large","expires_days":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(large_share.status(), StatusCode::OK);
        let large_share = body(large_share).await;
        assert_eq!(large_share["grant"]["file_count"], 1001);
        assert_eq!(large_share["grant"]["files_truncated"], true);
        assert_eq!(large_share["grant"]["label"], "automation-large");

        for directory in ["/project", "../project", "project/../project"] {
            let response = crate::app::router(app.clone())
                .oneshot(
                    Request::post("/api/automation/share")
                        .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                        .header("content-type", "application/json")
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            12,
                        ))))
                        .body(Body::from(format!(
                            r#"{{"directory":"{directory}","expires_days":1}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                app.config.outbound_dir.join("project/a.txt"),
                app.config.outbound_dir.join("project/link"),
            )
            .unwrap();
            let response = crate::app::router(app.clone())
                .oneshot(
                    Request::post("/api/automation/share")
                        .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                        .header("content-type", "application/json")
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            13,
                        ))))
                        .body(Body::from(r#"{"directory":"project","expires_days":1}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }

        let id = created["automation_token"]["id"].as_str().unwrap();
        let revoke = crate::app::router(app.clone())
            .oneshot(
                Request::delete(format!("/api/admin/automation-tokens/{id}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke.status(), StatusCode::OK);
        let denied = crate::app::router(app)
            .oneshot(
                Request::post("/api/automation/share")
                    .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        14,
                    ))))
                    .body(Body::from(r#"{"directory":"project","expires_days":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    }
}
