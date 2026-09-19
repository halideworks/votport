//! Verified, administrator-selected outbound files.

use std::collections::BinaryHeap;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, FromRequest, Path as AxumPath, Query, RawQuery, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use futures_util::{Stream, StreamExt as _};
use serde::Deserialize;

pub mod automation;
pub mod workflows;
use crate::receipt::verify_receipt_with_key;
pub use automation::automation_share;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncSeekExt as _, AsyncWriteExt as _, ReadBuf, SeekFrom};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;
use vot_sdk::object::{InMemoryObjectBuilder, ObjectId, Suite};
use vot_sdk::proof::{self, CatalogHeader};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

use super::{ApiError, ApiResult};
use crate::api::admin;
use crate::app::App;
use crate::auth;
use crate::auth::hash_token;
use crate::session::{OutboundOperation, OwnedOutboundOperation};
use crate::store::{
    now_unix, AutomationToken, OutboundDownloadResult, OutboundGrant, OutboundGrantFile, Store,
    OUTBOUND_DOWNLOAD_LIMIT_REACHED,
};

const MAX_ACTIVE: usize = 32;
const MAX_ACTIVE_PER_GRANT: usize = 16;
const CHUNK: usize = 1024 * 1024;
const BATCH_STAGE_BYTES: u64 = 1024 * 1024 * 1024;
const BATCH_STAGE_FILES: usize = 5_000;
// Batch chunks ramp from the lead size, doubling per chunk up to the caps,
// so the first byte waits on a small stage while later chunks are large
// enough to stage efficiently. BATCH_LOOKAHEAD chunks stage concurrently
// ahead of the one streaming; each holds a stage-budget reservation. A
// single file above BATCH_CHUNK_BYTES but below BATCH_STAGE_BYTES is its own
// chunk at full size, so live reservations can reach (1 + BATCH_LOOKAHEAD) x
// BATCH_STAGE_BYTES; many-small-file batches stay near (1 + BATCH_LOOKAHEAD)
// x BATCH_CHUNK_BYTES.
const BATCH_LEAD_FILES: usize = 64;
const BATCH_LEAD_BYTES: u64 = 16 * 1024 * 1024;
const BATCH_CHUNK_BYTES: u64 = 256 * 1024 * 1024;
const BATCH_LOOKAHEAD: usize = 2;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_PASSWORD_BYTES: usize = 256;
const MAX_AUTOMATION_LABEL_CHARS: usize = 100;
const DOWNLOAD_LEASE_SECS: u64 = 24 * 60 * 60;
// No valid file index reaches usize::MAX; this signed index represents the
// already-admitted logical bundle and can recover any of its member files.
const BUNDLE_DOWNLOAD_LEASE_INDEX: usize = usize::MAX;
const OUTBOUND_UPLOAD_ID: &str = "x-votport-upload-id";
const MAX_OUTBOUND_CHUNK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LIBRARY_DIRECTORY_INPUT_BYTES: usize = 1024;
const MAX_LIBRARY_DIRECTORY_ENTRIES: usize = 1000;
pub(super) const MAX_LIBRARY_CURSOR_BYTES: usize = 4096;
const MAX_LIBRARY_PROJECT_FILES: usize = 1_000_000;
const MAX_LIBRARY_SELECTION_FILES: usize = 100_000;
const MAX_LIBRARY_PATHS_FILES: usize = 1_000_000;
const OUTBOUND_GRANT_PREVIEW_FILES: usize = 64;
pub const MAX_GRANT_REQUEST_BYTES: usize = 256 * 1024 * 1024;
const MAX_LIBRARY_SEARCH_CHARS: usize = 100;
const MAX_LIBRARY_SEARCH_RESULTS: usize = 200;
// ponytail: bounded at 100,000 entries and 128 levels per query; add a search
// cursor if larger libraries need full coverage.
const MAX_LIBRARY_SEARCH_NODES: usize = 100_000;
const MAX_LIBRARY_SEARCH_DEPTH: usize = 128;
const RETAINED_LIBRARY_SEARCH_RESULTS: usize = MAX_LIBRARY_SEARCH_RESULTS + 1;
const LIBRARY_HASH_CONCURRENCY: usize = 4;
pub(crate) const LIBRARY_GRANT_CONCURRENCY: usize = 4;
const MIN_STAGE_FREE_BYTES: u64 = 1024 * 1024 * 1024;
const ZIP_LOCAL_HEADER_BYTES: u64 = 30;
const ZIP_CENTRAL_HEADER_BYTES: u64 = 46;
const ZIP_ENTRY_EXTRA_BYTES: u64 = 64;
const ZIP_END_BYTES: u64 = 98;

// ponytail: one JSON response; reuse the search budget and refuse over-limit
// folders instead of returning partial data. Add a cursor for full coverage.
#[derive(Clone, Copy)]
struct LibraryEnumerationBudget {
    max_entries: usize,
    max_depth: usize,
    max_path_bytes: usize,
}

const LIBRARY_SELECTION_BUDGET: LibraryEnumerationBudget = LibraryEnumerationBudget {
    max_entries: MAX_LIBRARY_SEARCH_NODES,
    max_depth: MAX_LIBRARY_SEARCH_DEPTH,
    max_path_bytes: 16 * 1024 * 1024,
};

// ponytail: one tiny global critical section; use per-tenant locks only if contention is measured.
static LIBRARY_MUTATION_LOCK: Mutex<()> = Mutex::new(());

// Serialization contract for LIBRARY_MUTATION_LOCK: it must stay impossible
// for delete_outbound_file to remove a library source that a concurrent grant
// creation validated and inserted. Grant creation validates its sources by
// statting every selected file, which on a stalled library mount can block
// forever, so the walk runs WITHOUT the lock and the lock guards only the
// grant insert. Closing the validation-to-insert window against deletes is
// the generation below: delete_outbound_file is the only in-process mutator
// that removes sources under the lock, and it bumps the count after removing.
// A creation that saw generation G before validating re-reads it under the
// lock (the mutex hand-off makes that re-read authoritative over every
// completed bump) and, when it moved, revalidates before inserting. So a
// delete and a validated insert are strictly ordered: either the delete
// completes first and the insert revalidates and fails, or the insert lands
// first and the delete observes the active grant and refuses.
static LIBRARY_MUTATION_GENERATION: AtomicU64 = AtomicU64::new(0);

static LIBRARY_HASH_PERMITS: Semaphore = Semaphore::const_new(LIBRARY_HASH_CONCURRENCY);

fn library_mutation_generation() -> u64 {
    // Relaxed is enough: only the lock-held re-read decides, and the mutex
    // gives that read happens-after every bump from earlier critical
    // sections. A stale unlocked read can only cause a redundant recheck.
    LIBRARY_MUTATION_GENERATION.load(Ordering::Relaxed)
}

#[cfg(test)]
struct LibraryMutationStall {
    root: PathBuf,
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
static LIBRARY_MUTATION_STALL: Mutex<Option<LibraryMutationStall>> = Mutex::new(None);

#[cfg(test)]
fn wait_library_mutation_stall(root: &Path) {
    let stall = {
        let mut pending = LIBRARY_MUTATION_STALL
            .lock()
            .expect("library mutation stall poisoned");
        if pending.as_ref().is_some_and(|stall| stall.root == root) {
            pending.take()
        } else {
            None
        }
    };
    if let Some(stall) = stall {
        let _ = stall.entered.send(());
        stall
            .release
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("library mutation stall was not released");
    }
}

pub(crate) static OUTBOUND_INTEGRITY_FAILURES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct IntegrityContext {
    store: Arc<Store>,
    tenant: String,
    grant_id: String,
    index: usize,
    component: &'static str,
    path: PathBuf,
}

impl IntegrityContext {
    fn for_source(
        app: &App,
        grant: &OutboundGrant,
        index: usize,
        component: &'static str,
        source: &Source,
    ) -> Self {
        Self::for_path(app, grant, index, component, &source.path)
    }

    fn for_path(
        app: &App,
        grant: &OutboundGrant,
        index: usize,
        component: &'static str,
        path: &Path,
    ) -> Self {
        Self {
            store: Arc::clone(&app.store),
            tenant: grant.tenant.clone(),
            grant_id: grant.id.clone(),
            index,
            component,
            path: path.to_owned(),
        }
    }
}

fn report_integrity_failure(context: &IntegrityContext, error: &io::Error) {
    OUTBOUND_INTEGRITY_FAILURES.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(
        target: "audit",
        event = "outbound_integrity_failure",
        grant_id = %context.grant_id,
        file_index = context.index,
        component = context.component,
        path = %context.path.display(),
        error = %error,
        "outbound source integrity verification failed"
    );
    context.store.audit(
        &context.tenant,
        "",
        "outbound_integrity_failure",
        &context.grant_id,
        &json!({
            "file_index": context.index,
            "component": context.component,
            "path": context.path.to_string_lossy(),
            "error": error.to_string(),
        }),
    );
}
// Batch staging copies, hashes, and receipt-checks files on the blocking
// pool; every batch stream keeps up to BATCH_LOOKAHEAD stages running (the
// streaming chunk's stage is done), so MAX_ACTIVE streams could run 64
// multi-hundred-MiB copies at once. The stage budget caps bytes, not task
// count, so this caps the concurrent staging I/O against the disk. A permit
// from App::staging_permits is taken before the stage-budget reservation and
// released when the stage finishes;
// streaming the staged file needs none.
pub(crate) const STAGING_CONCURRENCY: usize = 8;

/// Admission control for temporary outbound files. One free-space epoch is
/// shared by all active preparations so concurrent requests cannot each pass
/// the same statvfs check.
pub struct StageBudget {
    state: Mutex<StageBudgetState>,
}

struct StageBudgetState {
    epoch_capacity: Option<u64>,
    reserved: u64,
    active: usize,
}

impl StageBudget {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(StageBudgetState {
                epoch_capacity: None,
                reserved: 0,
                active: 0,
            }),
        }
    }

    fn reserve(
        self: &Arc<Self>,
        filesystem: &Path,
        bytes: u64,
    ) -> Result<StageReservation, StageReserveError> {
        let mut state = self.state.lock().expect("outbound stage budget poisoned");
        if state.active == 0 {
            let stats = rustix::fs::statvfs(filesystem)
                .map_err(|error| StageReserveError::Probe(error.into()))?;
            let free = stats
                .f_bavail
                .checked_mul(stats.f_frsize)
                .ok_or(StageReserveError::Overflow)?;
            Self::start_epoch(&mut state, free);
        }
        self.try_reserve(&mut state, bytes)
    }

    #[cfg(test)]
    fn reserve_with_free_space(
        self: &Arc<Self>,
        free: u64,
        bytes: u64,
    ) -> Result<StageReservation, StageReserveError> {
        let mut state = self.state.lock().expect("outbound stage budget poisoned");
        if state.active == 0 {
            Self::start_epoch(&mut state, free);
        }
        self.try_reserve(&mut state, bytes)
    }

    fn start_epoch(state: &mut StageBudgetState, free: u64) {
        state.epoch_capacity = Some(free.saturating_sub(MIN_STAGE_FREE_BYTES));
        state.reserved = 0;
    }

    fn try_reserve(
        self: &Arc<Self>,
        state: &mut StageBudgetState,
        bytes: u64,
    ) -> Result<StageReservation, StageReserveError> {
        let capacity = state.epoch_capacity.expect("stage capacity initialized");
        let next = state
            .reserved
            .checked_add(bytes)
            .ok_or(StageReserveError::Overflow)?;
        if next > capacity {
            return Err(StageReserveError::Insufficient);
        }
        state.reserved = next;
        state.active += 1;
        Ok(StageReservation {
            budget: Arc::clone(self),
            bytes,
        })
    }
}

impl Default for StageBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
enum StageReserveError {
    Insufficient,
    Overflow,
    Probe(io::Error),
}

struct StageReservation {
    budget: Arc<StageBudget>,
    bytes: u64,
}

impl Drop for StageReservation {
    fn drop(&mut self) {
        let mut state = self
            .budget
            .state
            .lock()
            .expect("outbound stage budget poisoned");
        state.reserved = state.reserved.saturating_sub(self.bytes);
        state.active = state.active.saturating_sub(1);
        if state.active == 0 {
            state.epoch_capacity = None;
            state.reserved = 0;
        }
    }
}

#[derive(Deserialize)]
pub struct OutboundPathQuery {
    path: String,
}

#[derive(Deserialize)]
pub struct OutboundListQuery {
    directory: Option<String>,
    q: Option<String>,
    selection: Option<String>,
    after: Option<String>,
    limit: Option<String>,
}

pub async fn list_outbound_files(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<OutboundListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_operator(&app, &headers)?;
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
    if (query.after.is_some() || query.limit.is_some())
        && (query.q.is_some() || query.selection.is_some())
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "pagination is only supported for directory listings",
        ));
    }
    if let Some(selection) = query.selection {
        if selection.len() > MAX_LIBRARY_DIRECTORY_INPUT_BYTES {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "selection is too long",
            ));
        }
        let tenant = identity.tenant.clone();
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
        let (after, limit) =
            library_directory_paging(&directory, query.after.as_deref(), query.limit.as_deref())?;
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
        let result = tokio::task::spawn_blocking(move || {
            list_library_directory(&root, &path, &after, limit)
        })
        .await
        .map_err(|_| ApiError::internal("list outbound files failed"))?
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "directory must contain only directories",
            )
        })?;
        let next_cursor = result.2.then(|| next_library_cursor(&result.0, &result.1));
        return Ok(Json(json!({
            "directory": directory,
            "directories": result.0,
            "files": result.1,
            "truncated": result.2,
            "next_cursor": next_cursor,
        })));
    }
    Err(ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "directory, q or selection is required",
    ))
}

pub async fn upload_outbound_file(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<OutboundPathQuery>,
    body: Body,
) -> ApiResult<Response> {
    // Every refusal of a chunk before its body is read drains it first, so
    // a client still writing reads the status (a session that ended
    // mid-upload must arrive as the 401 it is, not a reset connection).
    let admitted = admin::require_operator_write(&app, &headers).and_then(|identity| {
        let operation = begin_outbound_operation(&app, &identity.tenant)?;
        Ok((identity, operation))
    });
    let (identity, _operation) = match admitted {
        Ok(admitted) => admitted,
        Err(refused) => {
            drain(body).await;
            return Err(refused);
        }
    };
    // A file under an active grant is being served; replacing it would make
    // that grant's VOT package fail to assemble. Refuse both paths as delete
    // does.
    let relative = query.path.trim_matches('/').replace('\\', "/");
    match app
        .store
        .has_active_library_grant(&identity.tenant, &relative)
    {
        Ok(false) => {}
        Ok(true) => {
            drain(body).await;
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "outbound file is referenced by an active grant",
            ));
        }
        Err(error) => {
            drain(body).await;
            return Err(super::store_unavailable(error));
        }
    }
    if headers.contains_key(header::CONTENT_RANGE) || headers.contains_key(OUTBOUND_UPLOAD_ID) {
        return upload_outbound_chunk(Arc::clone(&app), identity, headers, query.path, body).await;
    }
    let path = safe_library_path(&app, &identity.tenant, &query.path)?;
    let stripe = outbound_upload_stripe(&path);
    let _lock = app.outbound_upload_locks[stripe].lock().await;
    let parent = path
        .parent()
        .ok_or_else(|| ApiError::internal("outbound path has no parent"))?;
    create_library_dirs(parent)?;
    let upload_id = auth::random_token();
    let temporary = parent.join(outbound_stage_name(&path, &upload_id));
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

/// A chunk's stage, opened and locked, with the request's range checked
/// against it: everything an upload settles before it reads the body.
struct ChunkStage<'a> {
    _lock: tokio::sync::MutexGuard<'a, ()>,
    file: tokio::fs::File,
    path: PathBuf,
    stage: PathBuf,
    start: u64,
    end: u64,
    total: u64,
    chunk_len: u64,
}

/// Checks a chunk request and opens its stage. A refusal comes back as the
/// response to send, so the caller can drain the body first: a client still
/// writing an 8 MiB chunk otherwise sees a reset connection instead of the
/// 409, 413, or 422, and reqwest reports that as a network failure.
async fn prepare_outbound_chunk<'a>(
    app: &'a App,
    identity: &auth::AdminIdentity,
    headers: &HeaderMap,
    requested_path: &str,
) -> Result<ChunkStage<'a>, ApiResult<Response>> {
    let upload_id = headers
        .get(OUTBOUND_UPLOAD_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_outbound_upload_id(value))
        .ok_or_else(|| {
            Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "X-Votport-Upload-Id must be 64 hexadecimal characters",
            ))
        })?
        .to_owned();
    let (start, end, total) = parse_outbound_content_range(headers).map_err(Err)?;
    let chunk_len = end
        .checked_sub(start)
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| {
            Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid Content-Range",
            ))
        })?;
    if chunk_len > MAX_OUTBOUND_CHUNK_BYTES {
        return Err(Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "outbound chunk exceeds 16 MiB",
        )));
    }
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Content-Length must match the requested range",
            ))
        })?;
    if declared != chunk_len {
        return Err(Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Content-Length must match the requested range",
        )));
    }
    if total > app.config.max_upload_bytes {
        return Err(Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "file exceeds upload limit",
        )));
    }
    if end >= total {
        return Err(Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Content-Range exceeds the declared file size",
        )));
    }

    let path = safe_library_path(app, &identity.tenant, requested_path).map_err(Err)?;
    let stripe = outbound_upload_stripe(&path);
    let lock = app.outbound_upload_locks[stripe].lock().await;
    let parent = path
        .parent()
        .ok_or_else(|| Err(ApiError::internal("outbound path has no parent")))?;
    create_library_dirs(parent).map_err(Err)?;
    let stage = parent.join(outbound_stage_name(&path, &upload_id));
    match std::fs::symlink_metadata(&path) {
        Ok(destination) => {
            if destination.file_type().is_file()
                && destination.len() == total
                && vot_platform_fs::same_file_regular(&stage, &path).is_ok_and(|same| same)
            {
                return Err(Ok(Json(json!({
                    "complete": true,
                    "offset": total,
                    "bytes": total,
                    "path": requested_path,
                }))
                .into_response()));
            }
            return Err(Err(ApiError::new(
                StatusCode::CONFLICT,
                "outbound file already exists",
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(Err(ApiError::internal(
                "inspect outbound destination failed",
            )));
        }
    }
    match std::fs::symlink_metadata(&stage) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.file_type().is_file() => {
            return Err(Err(ApiError::new(
                StatusCode::CONFLICT,
                "outbound staging path is not a regular file",
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(Err(ApiError::internal(
                "inspect outbound staging file failed",
            )))
        }
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
        .map_err(|_| Err(ApiError::internal("open outbound staging file failed")))?;
    let stage_len = file
        .metadata()
        .await
        .map_err(|_| Err(ApiError::internal("inspect outbound staging file failed")))?
        .len();
    if stage_len < start {
        sync_outbound_chunk(&mut file).await.map_err(Err)?;
        return Err(Ok(outbound_upload_conflict(
            requested_path,
            stage_len,
            total,
        )));
    }
    if stage_len > start {
        // Only the caller's acknowledged offset proves a safe prefix. A
        // longer stage may contain unsynced bytes from an interrupted request.
        file.set_len(start)
            .await
            .map_err(|_| Err(ApiError::internal("truncate outbound staging file failed")))?;
    }
    file.seek(SeekFrom::Start(start))
        .await
        .map_err(|_| Err(ApiError::internal("seek outbound staging file failed")))?;
    Ok(ChunkStage {
        _lock: lock,
        file,
        path,
        stage,
        start,
        end,
        total,
        chunk_len,
    })
}

async fn upload_outbound_chunk(
    app: Arc<App>,
    identity: admin::AdminSession,
    headers: HeaderMap,
    requested_path: String,
    body: Body,
) -> ApiResult<Response> {
    let ChunkStage {
        _lock,
        mut file,
        path,
        stage,
        start,
        end,
        total,
        chunk_len,
    } = match prepare_outbound_chunk(&app, &identity, &headers, &requested_path).await {
        Ok(stage) => stage,
        Err(refusal) => {
            drain(body).await;
            return refusal;
        }
    };
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
        if let Err(error) = sync_outbound_chunk(&mut file).await {
            let _ = file.set_len(start).await;
            return Err(error);
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
    publish_outbound_stage(&app, &identity, &stage, &path, &requested_path, total)
}

async fn sync_outbound_chunk(file: &mut tokio::fs::File) -> ApiResult<()> {
    file.flush()
        .await
        .map_err(|_| ApiError::internal("write outbound staging file failed"))?;
    file.sync_data()
        .await
        .map_err(|_| ApiError::internal("sync outbound staging file failed"))
}

/// Links a complete stage into the library under `path`, and audits the
/// upload. The stage hardlink remains as a bounded replay witness until the
/// idle stage sweep removes it.
fn publish_outbound_stage(
    app: &App,
    identity: &auth::AdminIdentity,
    stage: &Path,
    path: &Path,
    requested_path: &str,
    total: u64,
) -> ApiResult<Response> {
    if let Err(error) = std::fs::File::open(stage).and_then(|file| {
        file.set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::now()))
            .and_then(|()| file.sync_all())
    }) {
        tracing::warn!(%error, path = %stage.file_name().unwrap_or_default().to_string_lossy(), "persisting outbound stage expiry failed");
        return Err(ApiError::internal("persist outbound stage expiry failed"));
    }
    if let Err(error) = std::fs::hard_link(stage, path) {
        return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
            let _ = std::fs::remove_file(stage);
            ApiError::new(StatusCode::CONFLICT, "outbound file already exists")
        } else {
            ApiError::internal("publish outbound file failed")
        });
    }
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
    // Older stages acknowledged bytes before syncing and cannot prove a prefix.
    hasher.update(b"durable-chunks-v1\0");
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update([0]);
    hasher.update(upload_id.as_bytes());
    format!(
        ".vot-outbound-{:02x}-{}.stage",
        outbound_upload_stripe(path),
        hex::encode(hasher.finalize())
    )
}

pub(crate) fn sweep_upload_stages(app: &App, now: std::time::SystemTime) {
    #[cfg(not(unix))]
    let _ = (app, now);
    #[cfg(unix)]
    {
        let Some(cutoff) =
            now.checked_sub(std::time::Duration::from_secs(app.config.session_idle_secs))
        else {
            return;
        };
        crate::paths::walk(&app.config.outbound_dir, &mut |path, name, is_dir| {
            if is_dir {
                return true;
            }
            let Some((stripe, digest)) = name
                .strip_prefix(".vot-outbound-")
                .and_then(|name| name.strip_suffix(".stage"))
                .and_then(|name| name.split_once('-'))
            else {
                return true;
            };
            if stripe.len() != 2
                || !stripe.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !valid_outbound_upload_id(digest)
            {
                return true;
            }
            let Some(lock) = usize::from_str_radix(stripe, 16)
                .ok()
                .and_then(|stripe| app.outbound_upload_locks.get(stripe))
            else {
                return true;
            };
            // The stage name carries the destination's lock stripe; a slow
            // request owns it even when its last write is older than the cutoff.
            let Ok(_guard) = lock.try_lock() else {
                return true;
            };
            let expired = std::fs::symlink_metadata(path)
                .ok()
                .filter(|metadata| metadata.is_file())
                .and_then(|metadata| metadata.modified().ok())
                .is_some_and(|modified| modified <= cutoff);
            if expired {
                if let Err(error) = std::fs::remove_file(path) {
                    tracing::warn!(
                        %error,
                        path = %path.file_name().unwrap_or_default().to_string_lossy(),
                        "expired library upload cleanup failed"
                    );
                }
            }
            true
        });
    }
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

/// Reads and discards a refused upload's body, up to one chunk, so a client
/// still writing it finishes and reads the status instead of a reset
/// connection (which reqwest reports as a network failure, never as the
/// 409, 413, or 422 it was). A body past the chunk cap is cut off as before.
async fn drain(body: Body) {
    let mut stream = body.into_data_stream();
    let mut seen = 0u64;
    while let Some(Ok(chunk)) = stream.next().await {
        seen = seen.saturating_add(chunk.len() as u64);
        if seen > MAX_OUTBOUND_CHUNK_BYTES {
            break;
        }
    }
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
    let identity = admin::require_operator_write(&app, &headers)?;
    let operation = begin_outbound_operation_owned(&app, &identity.tenant)?;
    let relative_path = query.path.trim_matches('/').to_owned();
    let path = safe_library_path(&app, &identity.tenant, &relative_path)?;
    let worker = Arc::clone(&app);
    let tenant = identity.tenant.clone();
    let subject = identity.subject.clone();
    let relative_path_for_worker = relative_path.clone();
    let bytes = tokio::task::spawn_blocking(move || {
        let _operation = operation;
        let _lock = LIBRARY_MUTATION_LOCK
            .lock()
            .expect("library mutation lock poisoned");
        let root = library_root(&worker, &tenant);
        #[cfg(test)]
        wait_library_mutation_stall(&root);
        if !library_components_safe(&root, &path) {
            return Err(ApiError::not_found());
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(ApiError::not_found());
        }
        if worker
            .store
            .has_active_library_grant(&tenant, &relative_path_for_worker)
            .map_err(super::store_unavailable)?
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "outbound file is referenced by an active grant",
            ));
        }
        std::fs::remove_file(&path)
            .map_err(|_| ApiError::internal("delete outbound file failed"))?;
        LIBRARY_MUTATION_GENERATION.fetch_add(1, Ordering::Relaxed);
        drop(_lock);
        worker.store.audit(
            &tenant,
            &subject,
            "outbound_file_deleted",
            &relative_path_for_worker,
            &json!({ "path": relative_path_for_worker, "bytes": metadata.len() }),
        );
        Ok::<_, ApiError>(metadata.len())
    })
    .await
    .map_err(|_| ApiError::internal("delete outbound file failed"))??;
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

/// Cadence bound shared by the worker log hygiene helpers: repeat
/// observations of one condition log at most this often.
pub(crate) const WORKER_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Bounds recurring worker error logs: an unchanged error from one site
/// logs at most once per [`WORKER_LOG_INTERVAL`], a changed error logs
/// immediately, and a cleared condition yields one recovery line. Without
/// this a stuck two-second loop produces about 43000 error lines per day.
pub(crate) struct ErrorDeduper {
    site: &'static str,
    last_error: Option<String>,
    last_logged: Option<std::time::Instant>,
}

impl ErrorDeduper {
    pub(crate) fn new(site: &'static str) -> Self {
        Self {
            site,
            last_error: None,
            last_logged: None,
        }
    }

    /// True when `error` must be logged now: immediately when it differs
    /// from the previous error of this site, otherwise at most once per
    /// [`WORKER_LOG_INTERVAL`]. `now` is injected so tests can pin the
    /// decision without a clock.
    pub(crate) fn observe(&mut self, error: &str, now: std::time::Instant) -> bool {
        let due = self.last_error.as_deref() != Some(error)
            || self
                .last_logged
                .is_none_or(|last| now.duration_since(last) >= WORKER_LOG_INTERVAL);
        self.last_error = Some(error.to_owned());
        if due {
            self.last_logged = Some(now);
        }
        due
    }

    /// Test-only clearing of observed state: statics shared by production
    /// code must not carry pacing state between tests in one process.
    #[cfg(test)]
    pub(crate) fn reset(&mut self) {
        self.last_error = None;
        self.last_logged = None;
    }

    /// Logs one info line naming the site when a previously observed error
    /// has cleared. Call on every iteration the condition did not fire.
    /// Returns whether a recovery line was due, so tests can pin the
    /// exactly-once decision.
    pub(crate) fn recovered(&mut self) -> bool {
        let cleared = self.last_error.take().is_some();
        if cleared {
            tracing::info!("{} recovered", self.site);
        }
        cleared
    }
}

/// How loudly a worker should report a skipped iteration.
pub(crate) enum SkipLevel {
    /// First occurrence: log at info.
    First,
    /// Repeat: log at debug, at most once per [`WORKER_LOG_INTERVAL`].
    Repeat,
    /// Suppress entirely.
    Silent,
}

/// Bounds the skipped-iteration notice for a worker whose platform-tenant
/// gate refuses while a tenant deletion is pinned: the first occurrence
/// logs at info, repeats at most once per [`WORKER_LOG_INTERVAL`] at debug,
/// so a blocked worker stays visible without joining the log-flood class it
/// is warning about.
pub(crate) struct SkipNotice {
    first: bool,
    last_logged: Option<std::time::Instant>,
}

impl SkipNotice {
    pub(crate) fn new() -> Self {
        Self {
            first: true,
            last_logged: None,
        }
    }

    /// Classifies whether a skipped iteration at `now` should log. `now` is
    /// injected so tests can pin the pacing decision without a clock.
    pub(crate) fn due(&mut self, now: std::time::Instant) -> SkipLevel {
        if self.first {
            self.first = false;
            self.last_logged = Some(now);
            return SkipLevel::First;
        }
        if self
            .last_logged
            .is_none_or(|last| now.duration_since(last) >= WORKER_LOG_INTERVAL)
        {
            self.last_logged = Some(now);
            return SkipLevel::Repeat;
        }
        SkipLevel::Silent
    }
}

pub(crate) fn begin_outbound_operation<'a>(
    app: &'a App,
    tenant: &str,
) -> ApiResult<OutboundOperation<'a>> {
    let operation = app.sessions.try_begin_outbound(tenant).ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant deletion in progress",
        )
        .with_retry_after(1)
    })?;
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

fn begin_outbound_operation_owned(app: &App, tenant: &str) -> ApiResult<OwnedOutboundOperation> {
    let operation = app
        .sessions
        .try_begin_outbound_owned(tenant)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant deletion in progress",
            )
            .with_retry_after(1)
        })?;
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

fn is_private_library_name(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|name| {
        name.eq_ignore_ascii_case(".votport-workflows")
            || (name.starts_with(".vot-") && name.ends_with(".stage"))
    })
}

fn library_root_safe(root: &Path) -> bool {
    std::fs::symlink_metadata(root)
        .is_ok_and(|meta| meta.file_type().is_dir() && !meta.file_type().is_symlink())
}

fn library_directory_safe(root: &Path, directory: &Path) -> bool {
    if !library_components_safe(root, directory) {
        return false;
    }
    std::fs::symlink_metadata(directory)
        .is_ok_and(|meta| meta.file_type().is_dir() && !meta.file_type().is_symlink())
}

fn direct_library_entries_page(
    root: &Path,
    directory: &Path,
    after: &str,
    limit: usize,
) -> io::Result<(Vec<String>, Vec<serde_json::Value>, bool)> {
    let mut entries = BinaryHeap::new();
    let read_dir = std::fs::read_dir(directory)?;
    for entry in read_dir {
        let entry = entry?;
        let name = entry.file_name();
        if is_private_library_name(&name) {
            continue;
        }
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.contains('\\') {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if directory == root && name.eq_ignore_ascii_case(crate::paths::TENANT_STORAGE_DIR) {
            continue;
        }
        let Some(relative) = path.strip_prefix(root).ok() else {
            continue;
        };
        let is_directory = meta.file_type().is_dir();
        if !is_directory && !meta.file_type().is_file() {
            continue;
        }
        let relative = relative.to_string_lossy().replace('\\', "/");
        if relative.as_str() <= after {
            continue;
        }
        entries.push((relative, is_directory, meta.len()));
        if entries.len() > limit + 1 {
            entries.pop();
        }
    }
    let truncated = entries.len() > limit;
    let mut entries = entries.into_sorted_vec();
    entries.truncate(limit);
    let mut directories = Vec::new();
    let mut files = Vec::new();
    for (path, is_directory, bytes) in entries {
        if is_directory {
            directories.push(path);
        } else {
            files.push(json!({ "path": path, "bytes": bytes }));
        }
    }
    Ok((directories, files, truncated))
}

fn next_library_cursor(directories: &[String], files: &[serde_json::Value]) -> String {
    directories
        .iter()
        .map(String::as_str)
        .chain(files.iter().filter_map(|file| file["path"].as_str()))
        .max()
        .unwrap_or_default()
        .to_owned()
}

fn library_cursor_matches_directory(directory: &str, after: &str) -> bool {
    if after.is_empty()
        || after.contains('\\')
        || after
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return after.is_empty();
    }
    after
        .rsplit_once('/')
        .map_or(directory.is_empty(), |(parent, _)| parent == directory)
}

fn library_directory_paging(
    directory: &str,
    after: Option<&str>,
    raw_limit: Option<&str>,
) -> ApiResult<(String, usize)> {
    let after = after.unwrap_or_default();
    if after.len() > MAX_LIBRARY_CURSOR_BYTES {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "cursor is too long",
        ));
    }
    if !library_cursor_matches_directory(directory, after) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "cursor does not belong to this directory",
        ));
    }
    let limit = raw_limit
        .map(str::parse)
        .transpose()
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "limit must be an integer between 1 and 1000",
            )
        })?
        .unwrap_or(MAX_LIBRARY_DIRECTORY_ENTRIES);
    if !(1..=MAX_LIBRARY_DIRECTORY_ENTRIES).contains(&limit) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "limit must be between 1 and 1000",
        ));
    }
    Ok((after.to_owned(), limit))
}

fn list_library_directory(
    root: &Path,
    directory: &Path,
    after: &str,
    limit: usize,
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
    direct_library_entries_page(root, directory, after, limit).map_err(|_| ())
}

fn search_library_dir(
    root: &Path,
    directory: &Path,
    query: &str,
    matches: &mut BinaryHeap<(String, String, u64)>,
    visited: &mut usize,
    max_nodes: usize,
    depth: usize,
) -> bool {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return true;
    };
    for entry in entries {
        if *visited >= max_nodes {
            return true;
        }
        *visited += 1;
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        if is_private_library_name(&name) {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if directory == root
            && name
                .to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(crate::paths::TENANT_STORAGE_DIR))
        {
            continue;
        }
        if meta.file_type().is_dir() {
            if depth >= MAX_LIBRARY_SEARCH_DEPTH
                || search_library_dir(root, &path, query, matches, visited, max_nodes, depth + 1)
            {
                return true;
            }
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
    false
}

fn list_library_search(root: &Path, query: &str) -> (Vec<serde_json::Value>, bool) {
    list_library_search_with_budget(root, query, MAX_LIBRARY_SEARCH_NODES)
}

fn list_library_search_with_budget(
    root: &Path,
    query: &str,
    max_nodes: usize,
) -> (Vec<serde_json::Value>, bool) {
    if !library_root_safe(root) {
        return (Vec::new(), false);
    }
    let mut matches = BinaryHeap::new();
    let mut visited = 0;
    let budget_exhausted =
        search_library_dir(root, root, query, &mut matches, &mut visited, max_nodes, 0);
    let truncated = budget_exhausted || matches.len() > MAX_LIBRARY_SEARCH_RESULTS;
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
    enumerate_automation_files_with_budget(
        root,
        directory,
        MAX_LIBRARY_SELECTION_FILES,
        Some(LIBRARY_SELECTION_BUDGET),
    )?
    .into_iter()
    .map(|relative| {
        let path = root.join(&relative);
        let metadata = std::fs::symlink_metadata(path).map_err(|_| ApiError::not_found())?;
        Ok(json!({ "path": relative, "bytes": metadata.len() }))
    })
    .collect()
}

fn library_selection_limit_error() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "library selection is too large; choose a narrower folder or select individual files",
    )
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

pub(crate) fn safe_library_path(app: &App, tenant: &str, input: &str) -> ApiResult<PathBuf> {
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
    crate::paths::admit_portable_path(input)
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
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
    notifications: Option<crate::store::NotificationPolicy>,
    #[serde(default = "default_expiry")]
    expires_days: u64,
}

const fn default_expiry() -> u64 {
    7
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    let identity = admin::require_operator(&app, &headers)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    let (limit, offset) = outbound_grants_paging(query)?;
    let (grants, total) = app
        .store
        .outbound_grants_page(
            &identity.tenant,
            limit,
            offset,
            OUTBOUND_GRANT_PREVIEW_FILES,
        )
        .map_err(super::store_unavailable)?;
    let has_more = u64::try_from(offset)
        .unwrap_or(u64::MAX)
        .saturating_add(grants.len() as u64)
        < total;
    Ok(Json(json!({
        "grants": grants
            .into_iter()
            .map(|(grant, file_count)| public_grant_with_file_count(&grant, file_count))
            .collect::<Vec<_>>(),
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
    })))
}

pub async fn outbound_grant_url(
    State(app): State<Arc<App>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    let token = app.store.outbound_share_token(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND,
            "This saved address is unavailable. For a link created before saved addresses were supported, use your original copy or choose New address to replace it."))?;
    app.store
        .delivery_access(&id, &hash_token(&token))
        .map_err(|error| {
            ApiError::new(StatusCode::FORBIDDEN, error).with_code("delivery_pending")
        })?;
    let base = admin::base_url(&app, &headers);
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"url": format!("{base}/s/{token}")})),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct AutomationTokenRequest {
    label: String,
    expires_days: u64,
    /// Optional library directory the token is confined to.
    #[serde(default)]
    directory: Option<String>,
    #[serde(default = "automation::default_permissions")]
    permissions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationTokenPage {
    after: Option<String>,
    limit: Option<usize>,
}

// Page size follows the jobs and principals convention: 50 default, 100 max.
const AUTOMATION_TOKEN_PAGE_DEFAULT: usize = 50;
const AUTOMATION_TOKEN_PAGE_MAX: usize = 100;
// Creation cap per tenant, in the style of the workflows project limit: it
// keeps the token table and its listing finite even under automation that
// mints tokens on a schedule.
const MAX_AUTOMATION_TOKENS_PER_TENANT: u64 = 100;

pub async fn list_automation_tokens(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(page): Query<AutomationTokenPage>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_automation_admin(&app, &headers)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    let limit = page.limit.unwrap_or(AUTOMATION_TOKEN_PAGE_DEFAULT);
    if !(1..=AUTOMATION_TOKEN_PAGE_MAX).contains(&limit)
        || page.after.as_ref().is_some_and(|after| after.len() > 100)
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid token page",
        ));
    }
    let mut tokens = app
        .store
        .automation_tokens(
            &identity.tenant,
            page.after.as_deref().unwrap_or(""),
            limit + 1,
        )
        .map_err(super::store_unavailable)?;
    let more = tokens.len() > limit;
    tokens.truncate(limit);
    let next = more
        .then(|| tokens.last().map(|token| token.id.clone()))
        .flatten();
    Ok(Json(json!({
        "tokens": tokens.iter().map(public_automation_token).collect::<Vec<_>>(),
        "next": next,
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
    let count = app
        .store
        .automation_token_count(&identity.tenant)
        .map_err(super::store_unavailable)?;
    if count >= MAX_AUTOMATION_TOKENS_PER_TENANT {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("this tenant allows at most {MAX_AUTOMATION_TOKENS_PER_TENANT} automation tokens; revoke one first"),
        ));
    }
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
    // Shape only: the folder may not exist yet when the token is issued.
    let directory = match request.directory.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(directory) => {
            if directory.len() > MAX_LIBRARY_DIRECTORY_INPUT_BYTES {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "directory is too long",
                ));
            }
            if Path::new(directory).is_absolute() || directory.contains('\\') {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "directory must be a relative path",
                ));
            }
            safe_library_path(&app, &identity.tenant, directory)?;
            Some(directory.trim_matches('/').to_owned())
        }
    };
    let permissions = automation::validate_permissions(request.permissions)?;
    let raw = auth::random_token();
    let created_at = now_unix();
    let token = AutomationToken {
        id: auth::random_token(),
        token_hash: hash_token(&raw),
        tenant: identity.tenant.clone(),
        label,
        directory,
        permissions,
        created_by: identity.subject.clone(),
        created_at,
        expires_at: created_at.saturating_add(request.expires_days * 86_400),
        revoked_at: None,
        last_used_at: None,
    };
    app.store
        .insert_automation_token(token.clone())
        .map_err(super::store_unavailable)?;
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "automation_token_created",
        &token.id,
        &json!({ "label": token.label, "expires_at": token.expires_at, "directory": token.directory, "permissions": token.permissions }),
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
    // Idempotent like the automation delivery revoke: a repeat delete of a
    // row this tenant owns answers 200 again; only an unknown id 404s.
    if !app
        .store
        .revoke_automation_token(&identity.tenant, &id, now_unix())
        .map_err(ApiError::internal)?
        && !app
            .store
            .automation_token_exists(&identity.tenant, &id)
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

fn require_automation_admin(app: &App, headers: &HeaderMap) -> ApiResult<admin::AdminSession> {
    let identity = admin::require_operator(app, headers)?;
    if identity.role != "admin" {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "admin role required"));
    }
    Ok(identity)
}

pub async fn create_outbound_grant(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    request: Request,
) -> ApiResult<Response> {
    let identity = admin::require_operator_write(&app, &headers)?;
    let _grant_permit = app.outbound_grant_permits.try_acquire().map_err(|_| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many grant preparations; try again later",
        )
        .with_retry_after(1)
    })?;
    let Json(request) = Json::<CreateOutboundRequest>::from_request(request, &app)
        .await
        .map_err(|error| ApiError::new(error.status(), error.body_text()))?;
    let notifications = super::notifications::creation_policy(
        &app,
        &identity.tenant,
        request.notifications.clone(),
        &super::notifications::DOWNLOAD_EVENTS,
    )?;
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
                workflow: None,
                automation: None,
                label: request
                    .label
                    .filter(|label| !label.trim().is_empty())
                    .or(Some(directory_label)),
                password_hash,
                expires_days: request.expires_days,
                max_downloads: request.max_downloads,

                notifications: notifications.clone(),
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
            MAX_LIBRARY_PATHS_FILES,
            GrantOptions {
                workflow: None,
                automation: None,
                label: request.label,
                password_hash,
                expires_days: request.expires_days,
                max_downloads: request.max_downloads,

                notifications: notifications.clone(),
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
    let upload = app
        .store
        .link_upload(&identity.tenant, &link_id, &upload_id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let file = upload
        .files
        .get(file_index)
        .ok_or_else(ApiError::not_found)?;
    if upload.completed_at == 0 || file.deleted || !file.receipt {
        return Err(ApiError::not_found());
    }
    crate::paths::admit_portable_paths([file.path.as_str()])
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    let source = admin::stored_path(&app, &identity.tenant, &file.stored_as)
        .ok_or_else(ApiError::not_found)?;
    if !source.is_file() || !receipt_path(&source).is_file() {
        return Err(ApiError::not_found());
    }
    if file.bytes >= BATCH_STAGE_BYTES {
        let root: [u8; 32] = hex::decode(&file.root)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(ApiError::not_found)?;
        let suite = match file.suite.as_str() {
            "blake3" => 1,
            "sha256" => 2,
            _ => return Err(ApiError::not_found()),
        };
        let expected = ObjectId {
            suite,
            root,
            length: file.bytes,
        };
        read_verified_receipt(&app, &source, &expected, None)?;
        let proof_root = app.config.data_dir.join("outbound.proofs");
        let source_for_catalog = source.clone();
        tokio::task::spawn_blocking(move || {
            ensure_catalog(&proof_root, &source_for_catalog, &expected)
        })
        .await
        .map_err(|_| ApiError::internal("catalog generation failed"))?
        .map_err(|_| ApiError::not_found())?;
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

        notifications,
        revoked_at: None,
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
        files: Vec::new(),
    };
    app.store
        .insert_workflow_grant(grant.clone(), None, None, Some(&token))
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
        Json(json!({ "grant": public_grant(&grant), "url": format!("{base}/s/{token}") })),
    )
        .into_response())
}

/// True when `directory` is `scope` or a path below it, comparing whole
/// components so "project" does not admit "project-old".
fn within_scope(scope: &str, directory: &str) -> bool {
    let scope: Vec<&str> = scope.trim_matches('/').split('/').collect();
    let mut directory = directory.trim_matches('/').split('/');
    scope
        .iter()
        .all(|component| directory.next() == Some(*component))
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
    enumerate_automation_files_with_budget(root, directory, max_files, None)
}

fn enumerate_automation_files_with_budget(
    root: &Path,
    directory: &Path,
    max_files: usize,
    budget: Option<LibraryEnumerationBudget>,
) -> ApiResult<Vec<String>> {
    struct TraversalState {
        entries_seen: usize,
        path_bytes: usize,
    }

    fn visit(
        root: &Path,
        directory: &Path,
        paths: &mut Vec<String>,
        max_files: usize,
        budget: Option<LibraryEnumerationBudget>,
        state: &mut TraversalState,
        depth: usize,
    ) -> ApiResult<()> {
        if budget.is_some_and(|budget| depth > budget.max_depth) {
            return Err(library_selection_limit_error());
        }
        let entries = std::fs::read_dir(directory).map_err(|_| ApiError::not_found())?;
        for entry in entries {
            if let Some(budget) = budget {
                state.entries_seen = state
                    .entries_seen
                    .checked_add(1)
                    .ok_or_else(library_selection_limit_error)?;
                if state.entries_seen > budget.max_entries {
                    return Err(library_selection_limit_error());
                }
            }
            let entry = entry.map_err(|_| ApiError::not_found())?;
            if is_private_library_name(&entry.file_name()) {
                continue;
            }
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
            if metadata.file_type().is_symlink() {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "directory contains a symlink",
                ));
            }
            if metadata.file_type().is_dir() {
                visit(root, &path, paths, max_files, budget, state, depth + 1)?;
            } else if metadata.file_type().is_file() {
                if paths.len() >= max_files {
                    return Err(if budget.is_some() {
                        library_selection_limit_error()
                    } else {
                        ApiError::new(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            format!("directory contains too many files (maximum {max_files})"),
                        )
                    });
                }
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| ApiError::not_found())?
                    .to_str()
                    .ok_or_else(ApiError::not_found)?
                    .replace('\\', "/");
                if let Some(budget) = budget {
                    state.path_bytes = state
                        .path_bytes
                        .checked_add(relative.len())
                        .ok_or_else(library_selection_limit_error)?;
                    if state.path_bytes > budget.max_path_bytes {
                        return Err(library_selection_limit_error());
                    }
                }
                paths.push(relative);
            }
        }
        Ok(())
    }

    let mut paths = Vec::new();
    let mut state = TraversalState {
        entries_seen: 0,
        path_bytes: 0,
    };
    visit(
        root, directory, &mut paths, max_files, budget, &mut state, 0,
    )?;
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
    workflow: Option<crate::workflow::Job>,
    automation: Option<(crate::store::AutomationOperation, String)>,
    label: Option<String>,
    password_hash: Option<String>,
    expires_days: u64,
    max_downloads: Option<u64>,

    notifications: Option<crate::store::NotificationPolicy>,
}

async fn create_library_grant(
    app: &Arc<App>,
    headers: &HeaderMap,
    identity: &auth::AdminIdentity,
    requested: &[String],
    max_files: usize,
    options: GrantOptions,
) -> ApiResult<Response> {
    let operation = begin_outbound_operation_owned(app, &identity.tenant)?;
    if requested.is_empty() || requested.len() > max_files {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("paths must contain 1..={max_files} files"),
        ));
    }
    let received = if let Some(job) = options
        .workflow
        .as_ref()
        .filter(|job| job.received.is_some())
    {
        Some(workflows::received_files(app, job).await?)
    } else {
        None
    };
    let root = if received.is_some() {
        crate::paths::join_under(
            &app.config.receive_dir,
            &crate::paths::tenant_prefix(&identity.tenant),
        )
        .map_err(ApiError::internal)?
    } else {
        options
            .workflow
            .as_ref()
            .filter(|job| job.uses_snapshot())
            .map(|job| workflows::payload_root(app, &identity.tenant, &job.id))
            .unwrap_or_else(|| library_root(app, &identity.tenant))
    };
    let source_prefix = options
        .workflow
        .as_ref()
        .filter(|job| job.received.is_none() && !job.uses_snapshot())
        .map(|job| format!("{}/", job.project.directory));
    crate::paths::admit_portable_paths(requested.iter().map(|name| {
        let name = name.trim_matches('/');
        source_prefix
            .as_deref()
            .and_then(|prefix| name.strip_prefix(prefix))
            .unwrap_or(name)
    }))
    .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    let mut selections = Vec::with_capacity(requested.len());
    let mut total_bytes = 0u64;
    for name in requested {
        let path = if let Some(received) = &received {
            let file = received.get(name).ok_or_else(ApiError::not_found)?;
            admin::stored_path(app, &identity.tenant, &file.stored_as)
                .ok_or_else(ApiError::not_found)?
        } else if let Some(job) = options.workflow.as_ref().filter(|job| job.uses_snapshot()) {
            workflows::payload_path(app, &identity.tenant, &job.id, name)?
        } else {
            safe_library_path(app, &identity.tenant, name)?
        };
        if !library_components_safe(&root, &path) {
            return Err(ApiError::not_found());
        }
        let meta = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            return Err(ApiError::not_found());
        }
        let name = name.trim_matches('/').to_owned();
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
    let proof_root = app.config.data_dir.join("outbound.proofs");
    let hashed = futures_util::stream::iter(selections.into_iter().map(|(name, path)| {
        let hash_root = hash_root.clone();
        let proof_root = proof_root.clone();
        async move {
            let _permit = LIBRARY_HASH_PERMITS
                .acquire()
                .await
                .map_err(|_| ApiError::internal("hash outbound files failed"))?;
            tokio::task::spawn_blocking(move || {
                hash_library_file(&hash_root, &name, &path, &proof_root, max)
            })
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
    if let Some(expected) = &received {
        if expected.len() != hashed.len() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "incoming inventory changed",
            ));
        }
        for file in &hashed {
            let original = expected
                .get(file.name.as_str())
                .filter(|original| !original.deleted && original.bytes == file.bytes)
                .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "incoming file changed"))?;
            match original.suite.as_str() {
                "blake3" if original.root == file.root => {}
                "sha256" => {
                    let object = ObjectId {
                        suite: 2,
                        root: hex::decode(&original.root)
                            .ok()
                            .and_then(|bytes| bytes.try_into().ok())
                            .ok_or_else(ApiError::not_found)?,
                        length: original.bytes,
                    };
                    let path = admin::stored_path(app, &identity.tenant, &original.stored_as)
                        .ok_or_else(ApiError::not_found)?;
                    let proof_root = proof_root.clone();
                    tokio::task::spawn_blocking(move || build_catalog(&proof_root, &path, &object))
                        .await
                        .map_err(|_| ApiError::internal("verify incoming file failed"))?
                        .map_err(|_| {
                            ApiError::new(
                                StatusCode::CONFLICT,
                                "incoming content changed since verification",
                            )
                        })?;
                }
                _ => {
                    return Err(ApiError::new(
                        StatusCode::CONFLICT,
                        "incoming content changed since verification",
                    ))
                }
            }
        }
    }
    let files = hashed
        .into_iter()
        .map(|mut file| {
            if let Some(received) = &received {
                let original = received.get(&file.name).ok_or_else(ApiError::not_found)?;
                file.suite.clone_from(&original.suite);
                file.root.clone_from(&original.root);
                let object = ObjectId {
                    suite: match file.suite.as_str() {
                        "blake3" => 1,
                        "sha256" => 2,
                        _ => return Err(ApiError::not_found()),
                    },
                    root: hex::decode(&file.root)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                        .ok_or_else(ApiError::not_found)?,
                    length: file.bytes,
                };
                let path = admin::stored_path(app, &identity.tenant, &original.stored_as)
                    .ok_or_else(ApiError::not_found)?;
                file.receipt_b64 = base64::prelude::BASE64_STANDARD
                    .encode(read_verified_receipt(app, &path, &object, None)?);
            }
            let name = source_prefix
                .as_deref()
                .and_then(|prefix| file.name.strip_prefix(prefix))
                .unwrap_or(&file.name)
                .to_owned();
            Ok(OutboundGrantFile {
                name,
                source: if let Some(received) = &received {
                    format!(
                        "received:{}",
                        received
                            .get(&file.name)
                            .ok_or_else(ApiError::not_found)?
                            .stored_as
                    )
                } else {
                    options
                        .workflow
                        .as_ref()
                        .filter(|job| job.uses_snapshot())
                        .map(|job| format!("workflow:{}/{}", job.id, file.name))
                        .unwrap_or_else(|| file.source.clone())
                },
                ..file
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let first = files.first().cloned().ok_or_else(ApiError::not_found)?;
    let created_at = now_unix();
    let token = if let Some(job) = &options.workflow {
        app.store
            .delivery_job_token(&job.tenant, &job.id)
            .map_err(super::store_unavailable)?
    } else {
        options
            .automation
            .as_ref()
            .map(|(_, token)| token.clone())
            .unwrap_or_else(auth::random_token)
    };
    let label = options
        .label
        .unwrap_or_else(|| first.name.clone())
        .trim()
        .to_owned();
    let grant = OutboundGrant {
        id: options
            .workflow
            .as_ref()
            .map(|job| job.id.clone())
            .or_else(|| {
                options
                    .automation
                    .as_ref()
                    .map(|(op, _)| op.grant_id.clone())
            })
            .unwrap_or_else(auth::random_token),
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

        notifications: options.notifications.clone(),
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
    let public = public_grant(&grant);
    let grant_id = grant.id.clone();
    let grant_file_count = grant.files.len();
    let operation_id = options
        .automation
        .as_ref()
        .map(|(operation, _)| operation.operation_id.clone());
    let automation = options.automation;
    let workflow = options.workflow;
    let worker = Arc::clone(app);
    let token_for_worker = token.clone();
    let tenant = identity.tenant.clone();
    let subject = identity.subject.clone();
    let audit_detail = json!({ "files": grant_file_count, "operation_id": operation_id });
    tokio::task::spawn_blocking(move || {
        let _operation = operation;
        // Validate without the lock: the walk stats every selected file and
        // a stalled library mount would otherwise hold the lock forever.
        #[cfg(test)]
        wait_library_mutation_stall(&root);
        let generation = library_mutation_generation();
        if !library_sources_match(&root, &revalidation, &grant.files) {
            return Err(ApiError::not_found());
        }
        // Test seam marking the start of the validation-to-insert window:
        // arming with a marker key pins a validated creation right here, so
        // a delete can be run through the window deterministically.
        #[cfg(test)]
        wait_library_mutation_stall(&root.join(".validated"));
        let _lock = LIBRARY_MUTATION_LOCK
            .lock()
            .expect("library mutation lock poisoned");
        // The lock covers only the store transaction plus this recheck, so a
        // stalled mount delays only the request doing the walking. A delete
        // that completed while we validated moved the generation; redo the
        // walk under the lock so it cannot win the validation-to-insert
        // window.
        if library_mutation_generation() != generation
            && !library_sources_match(&root, &revalidation, &grant.files)
        {
            return Err(ApiError::not_found());
        }
        worker
            .store
            .insert_workflow_grant(
                grant,
                automation.as_ref().map(|(operation, _)| operation),
                workflow.as_ref(),
                Some(&token_for_worker),
            )
            .map_err(super::store_unavailable)?;
        drop(_lock);
        worker.store.audit(
            &tenant,
            &subject,
            "outbound_grant_created",
            &grant_id,
            &audit_detail,
        );
        Ok::<_, ApiError>(())
    })
    .await
    .map_err(|_| ApiError::internal("create outbound grant failed"))??;
    let base = admin::base_url(app, headers);
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "grant": public, "url": format!("{base}/s/{token}"), "operation_id": operation_id })),
    )
        .into_response())
}

fn valid_preparation_length(length: u64, expected: Option<u64>, max: u64) -> bool {
    max <= vot_sdk::object::MAX_OBJECT_LENGTH
        && length <= max
        && expected.is_none_or(|expected| expected == length)
}

fn prepare_library_file(
    path: &Path,
    suite: Suite,
    expected_length: Option<u64>,
    max: u64,
) -> io::Result<vot_sdk::object::InMemoryPreparedObject> {
    use std::io::Read as _;
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "source");
    let mut input = std::fs::File::open(path)?;
    let length = input.metadata()?.len();
    if !valid_preparation_length(length, expected_length, max) {
        return Err(invalid());
    }
    if length > vot_sdk::object::PROOF_LEAF_SIZE {
        let leaves =
            vot_cli::file_proof_leaves(&mut input, suite, length).map_err(|error| match error {
                vot_cli::Error::Io(error) => error,
                _ => invalid(),
            })?;
        return vot_sdk::object::InMemoryPreparedObject::from_proof_leaves(
            suite, length, leaves, max,
        )
        .map_err(|_| invalid());
    }
    let mut builder =
        InMemoryObjectBuilder::new(suite, Some(length), max).map_err(|_| invalid())?;
    let mut buffer = vec![0; CHUNK];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        builder.update(&buffer[..count]).map_err(|_| invalid())?;
    }
    builder.finish().map_err(|_| invalid())
}

fn hash_library_file(
    root: &Path,
    name: &str,
    path: &Path,
    proof_root: &Path,
    max: u64,
) -> io::Result<OutboundGrantFile> {
    let prepared = prepare_library_file(path, Suite::Blake3Bao64, None, max)?;
    let bytes = prepared.object_id().length;
    let object = prepared.object_id().clone();
    if bytes >= BATCH_STAGE_BYTES {
        ensure_catalog_from_prepared(proof_root, &prepared)?;
    }
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

fn catalog_path(root: &Path, object: &ObjectId) -> PathBuf {
    root.join(format!(
        "{}-{}-{}.vot-catalog",
        object.suite,
        hex::encode(object.root),
        object.length
    ))
}

fn catalog_header(file: &mut std::fs::File, expected: &ObjectId) -> io::Result<CatalogHeader> {
    use std::io::{Read as _, Seek as _};
    let mut bytes = [0u8; proof::HEADER_LENGTH];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut bytes)?;
    let header = proof::decode_header(&bytes, expected)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "catalog header"))?;
    let physical = file.metadata()?.len();
    if physical != header.catalog_length() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "catalog length"));
    }
    Ok(header)
}

fn ensure_catalog_from_prepared(
    root: &Path,
    prepared: &vot_sdk::object::InMemoryPreparedObject,
) -> io::Result<PathBuf> {
    let expected = prepared.object_id();
    std::fs::create_dir_all(root)?;
    let path = catalog_path(root, expected);
    if let Ok(mut file) = std::fs::File::open(&path) {
        if catalog_header(&mut file, expected).is_ok() {
            return Ok(path);
        }
    }
    let mut stage = root.to_path_buf();
    stage.push(format!(
        ".{}.stage-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("catalog"),
        auth::random_token()
    ));
    let result = (|| {
        use std::io::{Seek as _, Write as _};
        let mut options = std::fs::OpenOptions::new();
        options.write(true).read(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&stage)?;
        file.write_all(&[0; proof::HEADER_LENGTH])?;
        let mut encoder = proof::CatalogEncoder::new(prepared)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "catalog encoder"))?;
        while let Some(record) = encoder
            .next_record()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "catalog record"))?
        {
            file.seek(SeekFrom::Start(record.index_offset()))?;
            file.write_all(record.index_entry())?;
            file.seek(SeekFrom::Start(record.proof_offset()))?;
            file.write_all(record.proof())?;
        }
        let finished = encoder
            .finish()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "catalog finish"))?;
        file.set_len(finished.catalog_length())?;
        file.sync_all()?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(finished.header())?;
        file.sync_all()?;
        std::fs::rename(&stage, &path)?;
        Ok(path.clone())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&stage);
    }
    result
}

/// One in-flight catalog build per object: N cold requests for the same
/// file wait on a single full read+hash instead of each paying it.
static CATALOG_BUILDS: std::sync::LazyLock<
    Mutex<std::collections::HashMap<PathBuf, Arc<Mutex<()>>>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

fn ensure_catalog(root: &Path, source: &Path, expected: &ObjectId) -> io::Result<PathBuf> {
    std::fs::create_dir_all(root)?;
    let path = catalog_path(root, expected);
    if let Ok(mut file) = std::fs::File::open(&path) {
        if catalog_header(&mut file, expected).is_ok() {
            return Ok(path);
        }
    }
    let build_lock = Arc::clone(
        CATALOG_BUILDS
            .lock()
            .expect("catalog builds poisoned")
            .entry(path.clone())
            .or_default(),
    );
    let _building = build_lock.lock().expect("catalog build poisoned");
    // A racer may have finished the build while this thread waited.
    if let Ok(mut file) = std::fs::File::open(&path) {
        if catalog_header(&mut file, expected).is_ok() {
            drop(_building);
            CATALOG_BUILDS
                .lock()
                .expect("catalog builds poisoned")
                .remove(&path);
            return Ok(path);
        }
    }
    let result = build_catalog(root, source, expected);
    drop(_building);
    // Waiters still hold their Arc; a later request re-creates the entry
    // and finds the finished catalog on the recheck above.
    CATALOG_BUILDS
        .lock()
        .expect("catalog builds poisoned")
        .remove(&path);
    result
}

fn build_catalog(root: &Path, source: &Path, expected: &ObjectId) -> io::Result<PathBuf> {
    let suite = Suite::try_from(expected.suite).map_err(|_| io::Error::other("suite"))?;
    let prepared = prepare_library_file(source, suite, Some(expected.length), expected.length)?;
    if prepared.object_id() != expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "source"));
    }
    ensure_catalog_from_prepared(root, &prepared)
}

pub async fn delete_outbound_grant(
    State(app): State<Arc<App>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_operator_write(&app, &headers)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    // Idempotent like the automation delivery revoke documents: a repeat
    // delete of a row this tenant owns answers 200 again; only an unknown id
    // 404s.
    if !app
        .store
        .revoke_outbound_grant(&identity.tenant, &id, now_unix())
        .map_err(ApiError::internal)?
        && !app
            .store
            .outbound_grant_exists(&identity.tenant, &id)
            .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found());
    }
    // A stream already admitted before the revocation stops at its next
    // frame instead of delivering the rest of the body.
    if let Ok(Some(grant)) = app.store.outbound_grant_by_id(&id) {
        cancel_grant_streams(&app, &grant.token_hash);
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
    notifications: Option<crate::store::NotificationPolicy>,
}

pub async fn update_outbound_grant(
    State(app): State<Arc<App>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateOutboundGrantRequest>,
) -> ApiResult<Response> {
    let identity = admin::require_operator_write(&app, &headers)?;
    let _operation = begin_outbound_operation(&app, &identity.tenant)?;
    let fields = [
        request.rotate.is_some(),
        request.extend_days.is_some(),
        request.notifications.is_some(),
    ];
    if fields.iter().filter(|field| **field).count() != 1 || request.rotate == Some(false) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "choose exactly one grant lifecycle or policy action",
        ));
    }
    if let Some(policy) = request.notifications {
        super::notifications::validate_policy(
            &app,
            &identity.tenant,
            &policy,
            &super::notifications::DOWNLOAD_EVENTS,
        )?;
        if !app
            .store
            .set_outbound_notifications(&identity.tenant, &id, &policy)
            .map_err(ApiError::internal)?
        {
            return Err(ApiError::not_found());
        }
        app.store.audit(
            &identity.tenant,
            &identity.subject,
            "outbound_notifications_changed",
            &id,
            &json!({}),
        );
        return Ok(Json(json!({"ok":true})).into_response());
    }
    if request.rotate == Some(true) {
        let job = app
            .store
            .delivery_job(&id)
            .map_err(super::store_unavailable)?
            .filter(|job| job.tenant == identity.tenant);
        let token = auth::random_token();
        let changed = if let Some(job) = job {
            app.store
                .rotate_delivery_job_token(&identity.tenant, &id, job.token_generation, &token)
        } else {
            app.store
                .rotate_outbound_grant_token(&identity.tenant, &id, &token)
        }
        .map_err(ApiError::internal)?;
        if !changed {
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
    Query(query): Query<OutboundMetadataQuery>,
) -> ApiResult<Response> {
    let paging = outbound_metadata_paging(query)?;
    if let Some((offset, limit)) = paging {
        if !valid_token(&token) {
            return Err(ApiError::not_found());
        }
        let page = app
            .store
            .outbound_grant_files_page_by_token_hash(&hash_token(&token), offset, limit)
            .map_err(super::store_unavailable)?
            .ok_or_else(ApiError::not_found)?;
        let grant = page.grant;
        let files_total = page.file_count;
        if grant.revoked_at.is_some() || grant.expires_at <= now_unix() {
            return Err(ApiError::not_found());
        }
        let _operation = begin_outbound_operation(&app, &grant.tenant)?;
        let recipient = workflows::require_recipient(&app, &grant, &headers)?;
        let authorized = grant_authorized(&app, &grant, &headers);
        if grant.password_hash.is_some() && !authorized {
            return Ok((
                [(header::CACHE_CONTROL, "no-store")],
                Json(json!({ "has_password": true, "authorized": false })),
            )
                .into_response());
        }
        let manifest = app
            .store
            .delivery_manifest(&grant.id)
            .map_err(super::store_unavailable)?;
        let evidence_authorization = super::evidence::metadata_authorization(
            &app,
            &grant,
            &headers,
            &manifest,
            recipient.as_deref(),
        )?;
        let receipt_url = (!grant.link_id.is_empty()
            || page
                .files
                .iter()
                .any(|(index, file)| *index == 0 && file.source.starts_with("received:")))
        .then(|| format!("/api/s/{token}/receipt"));
        let files = page
            .files
            .into_iter()
            .map(|(index, file)| outbound_metadata_file(&token, index, &file))
            .collect::<Vec<_>>();
        let has_more = offset.saturating_add(files.len()) < files_total;
        let branding =
            super::public_branding(&app, &grant.tenant).map_err(super::store_unavailable)?;
        return Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({
                "has_password": grant.password_hash.is_some(),
                "authorized": authorized,
                "branding": branding,
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
                "grant_id": grant.id,
                "delivery_manifest": manifest,
                "evidence_authorization": evidence_authorization,
                "receipt_url": receipt_url,
                "download_url": format!("/api/s/{token}/file"),
                "bundle_url": format!("/api/s/{token}/bundle"),
                "batch_url": format!("/api/s/{token}/batch"),
                "files": files,
                "files_total": files_total,
                "total_bytes": page.total_bytes,
                "offset": offset,
                "limit": limit,
                "has_more": has_more,
            })),
        )
            .into_response());
    }
    let grant = readable_grant(&app, &token)?;
    let _operation = begin_outbound_operation(&app, &grant.tenant)?;
    let recipient = workflows::require_recipient(&app, &grant, &headers)?;
    let authorized = grant_authorized(&app, &grant, &headers);
    if grant.password_hash.is_some() && !authorized {
        return Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({ "has_password": true, "authorized": false })),
        )
            .into_response());
    }
    let manifest = app
        .store
        .delivery_manifest(&grant.id)
        .map_err(super::store_unavailable)?;
    let evidence_authorization = super::evidence::metadata_authorization(
        &app,
        &grant,
        &headers,
        &manifest,
        recipient.as_deref(),
    )?;
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
            .map(|(index, file)| outbound_metadata_file(&token, index, file))
            .collect()
    };
    let branding = super::public_branding(&app, &grant.tenant).map_err(super::store_unavailable)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "has_password": grant.password_hash.is_some(),
            "authorized": authorized,
            "branding": branding,
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
                "grant_id": grant.id,
                "delivery_manifest": manifest,
                "evidence_authorization": evidence_authorization,
            "receipt_url": (grant.files.is_empty() || grant.files[0].source.starts_with("received:")).then(|| format!("/api/s/{token}/receipt")),
            "download_url": format!("/api/s/{token}/file"),
            "bundle_url": format!("/api/s/{token}/bundle"),
            "batch_url": format!("/api/s/{token}/batch"),
            // Present only when the VOT serve listener is bound: where a VOT
            // client dials and where it mints its capability.
            "fetch": app.serve.as_ref().filter(|_| !grant.max_downloads.is_some_and(|max| grant.downloads >= max)).map(|serve| json!({
                "address": serve.address,
                "certificate_digest": hex::encode(serve.certificate_digest),
                "mint_url": format!("/api/s/{token}/fetch"),
            })),
            "total_bytes": if grant.files.is_empty() {
                grant.bytes
            } else {
                grant.files.iter().fold(0u64, |total, file| total.saturating_add(file.bytes))
            },
            "files": files,
        })),
    )
        .into_response())
}

/// Tenant logo for a delivery. Password-gated like the metadata: the
/// pre-password response reveals nothing, so the logo hides with it.
pub async fn outbound_logo(
    State(app): State<Arc<App>>,
    AxumPath(token): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let grant = active_grant(&app, &token)?;
    require_grant_access(&app, &grant, &headers)?;
    super::serve_branding_logo(&app, &grant.tenant).await
}

#[derive(Deserialize)]
pub struct OutboundMetadataQuery {
    offset: Option<String>,
    limit: Option<String>,
}

fn outbound_metadata_paging(query: OutboundMetadataQuery) -> ApiResult<Option<(usize, usize)>> {
    if query.offset.is_none() && query.limit.is_none() {
        return Ok(None);
    }
    let limit = query
        .limit
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "limit must be an integer between 1 and 500",
            )
        })?
        .unwrap_or(100usize);
    if !(1..=500).contains(&limit) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "limit must be between 1 and 500",
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
    Ok(Some((offset, limit)))
}

fn outbound_metadata_file(
    token: &str,
    index: usize,
    file: &OutboundGrantFile,
) -> serde_json::Value {
    json!({
        "name": file.name,
        "suite": file.suite,
        "root": file.root,
        "bytes": file.bytes,
        "receipt_url": (file.source.is_empty() || file.source.starts_with("received:")).then(|| format!("/api/s/{token}/receipts/{index}")),
        "download_url": format!("/api/s/{token}/files/{index}"),
    })
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
    let grant = readable_grant(&app, &token)?;
    let _operation = begin_outbound_operation(&app, &grant.tenant)?;
    let ip = super::client_ip(&headers, &peer, &app.config.trusted_proxies);
    super::upload::check_password(
        &app,
        super::upload::PasswordResource {
            tenant: &grant.tenant,
            id: &grant.id,
            kind: super::upload::PasswordResourceKind::Delivery,
        },
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
    let grant = Arc::new(active_grant(&app, &token)?);
    let operation = begin_outbound_operation_owned(&app, &grant.tenant)?;
    require_grant_access(&app, &grant, &headers)?;
    let (source, _operation) = source_info_async(&app, grant, index, None, operation, None).await?;
    let bytes = source.receipt.ok_or_else(ApiError::not_found)?;
    let filename = format!("{}.vot-receipt", source.name);
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/cbor"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::CONTENT_DISPOSITION, attachment_filename(&filename)?);
    Ok(response)
}

pub async fn outbound_file(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
    query: RawQuery,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
) -> ApiResult<Response> {
    let route_path = format!("/api/s/{token}/file");
    outbound_file_inner(app, headers, token, 0, peer, route_path, query.0.as_deref()).await
}

pub async fn outbound_file_head(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
    query: RawQuery,
) -> ApiResult<Response> {
    outbound_file_head_inner(app, headers, token, 0, query.0.as_deref()).await
}

pub async fn outbound_file_indexed(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath((token, index)): AxumPath<(String, usize)>,
    query: RawQuery,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
) -> ApiResult<Response> {
    let route_path = format!("/api/s/{token}/files/{index}");
    outbound_file_inner(
        app,
        headers,
        token,
        index,
        peer,
        route_path,
        query.0.as_deref(),
    )
    .await
}

pub async fn outbound_file_indexed_head(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath((token, index)): AxumPath<(String, usize)>,
    query: RawQuery,
) -> ApiResult<Response> {
    outbound_file_head_inner(app, headers, token, index, query.0.as_deref()).await
}

pub async fn outbound_batch(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    request: Request,
) -> ApiResult<Response> {
    let is_head = request.method() == Method::HEAD;
    let grant = Arc::new(active_grant(&app, &token)?);
    let operation = begin_outbound_operation_owned(&app, &grant.tenant)?;
    require_grant_access(&app, &grant, &headers)?;
    if !app.outbound_rate.allow(&grant.token_hash) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many downloads; try again later",
        )
        .with_retry_after(600));
    }
    let count = if grant.files.is_empty() {
        1
    } else {
        grant.files.len()
    };
    let total_bytes = (0..count)
        .map(|index| {
            grant
                .files
                .get(index)
                .map_or(grant.bytes, |file| file.bytes)
        })
        .try_fold(0u64, u64::checked_add)
        .ok_or_else(|| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "batch size overflow"))?;
    if total_bytes > app.config.max_upload_bytes {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "batch exceeds total size limit",
        ));
    }
    // Refuse an exhausted file before any staging or payload preparation.
    for index in 0..count {
        if grant_is_exhausted(&grant, index, None) {
            return Err(ApiError::not_found());
        }
    }
    if is_head {
        let mut response = Body::empty().into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.votport.batch"),
        );
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(total_bytes));
        return Ok(response);
    }
    if total_bytes == 0 {
        let validation_app = Arc::clone(&app);
        let validation_grant = Arc::clone(&grant);
        tokio::task::spawn_blocking(move || {
            validate_batch_sources(&validation_app, &validation_grant, count)
        })
        .await
        .map_err(|_| ApiError::internal("batch source validation failed"))??;
        let indexes: Vec<usize> = (0..count).collect();
        record_download(&app, &grant, &indexes).await?;
        audit_download_request(&app, &grant, &headers, peer, "batch", None, false).await?;
        let mut response = Body::empty().into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.votport.batch"),
        );
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(0u64));
        return Ok(response);
    }
    let active = ActiveDownload::claim(Arc::clone(&app), &format!("{}:batch", grant.token_hash))?;
    let gate = StreamGate::for_grant(&app, &grant);
    let chunks = batch_chunks(&grant, count);
    let permit = staging_permit(&app, &chunks[0]).await;
    let first_file = await_batch_chunk(start_batch_chunk(
        Arc::clone(&app),
        Arc::clone(&grant),
        chunks[0].clone(),
        permit,
    )?)
    .await?;
    let file = first_file;
    let validated_end = chunks[0].end;
    // Downloads are recorded per file as its last byte is handed to the
    // transport, not all up front: an interrupted batch must leave the
    // files it never sent still downloadable individually. The per-file
    // record enforces max_downloads atomically, so two racing batch streams
    // can both start but only one records each capped file.
    let boundaries: Vec<u64> = (0..count)
        .scan(0u64, |total, index| {
            *total += grant
                .files
                .get(index)
                .map_or(grant.bytes, |file| file.bytes);
            Some(*total)
        })
        .collect();
    let mut state = BatchStream {
        app: Arc::clone(&app),
        grant,
        _operation: operation,
        _active: active,
        gate,
        chunks,
        chunk_index: 0,
        file: Some(file),
        lookahead: std::collections::VecDeque::new(),
        boundaries,
        validated_end,
        sent_bytes: 0,
        recorded: 0,
    };
    state.fill_lookahead();
    audit_download_request(&app, &state.grant, &headers, peer, "batch", None, false).await?;
    let stream = futures_util::stream::try_unfold(state, |mut state| async move {
        // Normal polls record only files whose bytes a previous poll handed
        // to the transport. The final frame is validated and admitted before
        // it is returned because a known-length body may skip terminal None.
        // A drop or failure before that frame leaves its files retryable.
        state.record_delivered(false).await.map_err(api_error_io)?;
        loop {
            // A stream admitted before its grant was revoked or expired stops
            // at the next frame; bytes already handed off stay recorded.
            if state.gate.stopped() {
                return Ok(None);
            }
            let item = match state.file.as_mut() {
                Some(file) => file.next().await,
                None => None,
            };
            if let Some(item) = item {
                match item {
                    Ok(bytes) => {
                        state.sent_bytes += bytes.len() as u64;
                        // A known-length body may be dropped immediately after
                        // its last frame, without polling terminal None. Record
                        // the boundary before handing that frame to the body.
                        if state.sent_bytes >= state.boundaries.last().copied().unwrap_or(0) {
                            state
                                .validate_trailing_chunks()
                                .await
                                .map_err(api_error_io)?;
                            state.record_delivered(true).await.map_err(api_error_io)?;
                            state.file = None;
                            state.chunk_index = state.chunks.len() - 1;
                        }
                        return Ok(Some((bytes, state)));
                    }
                    Err(error) => return Err(error),
                }
            }
            state.file = None;
            state.chunk_index += 1;
            if state.chunk_index >= state.chunks.len() {
                // End of stream: record the coalesced tail.
                state.record_delivered(true).await.map_err(api_error_io)?;
                return Ok(None);
            }
            let handle = if let Some(handle) = state.lookahead.pop_front() {
                handle
            } else {
                let chunk = state.chunks[state.chunk_index].clone();
                let permit = staging_permit(&state.app, &chunk).await;
                match start_batch_chunk(Arc::clone(&state.app), state.grant.clone(), chunk, permit)
                {
                    Ok(handle) => handle,
                    Err(error) => return Err(api_error_io(error)),
                }
            };
            let file = await_batch_chunk(handle).await.map_err(api_error_io)?;
            state.file = Some(file);
            state.validated_end = state.chunks[state.chunk_index].end;
            state.fill_lookahead();
        }
    });
    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.votport.batch"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(total_bytes));
    Ok(response)
}

enum BatchFile {
    Staged(ReaderStream<StagedReader>),
    Verified(VerifiedStream),
}

impl Stream for BatchFile {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match &mut *self {
            Self::Staged(stream) => Pin::new(stream).poll_next(cx),
            Self::Verified(stream) => Pin::new(stream).poll_next(cx),
        }
    }
}

#[derive(Clone)]
struct BatchChunk {
    start: usize,
    end: usize,
    bytes: u64,
    oversized: bool,
}

fn batch_chunks(grant: &OutboundGrant, count: usize) -> Vec<BatchChunk> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut bytes = 0;
    let mut file_cap = BATCH_LEAD_FILES;
    let mut byte_cap = BATCH_LEAD_BYTES;
    for index in 0..count {
        let length = grant
            .files
            .get(index)
            .map_or(grant.bytes, |file| file.bytes);
        if length >= BATCH_STAGE_BYTES {
            if start < index {
                chunks.push(BatchChunk {
                    start,
                    end: index,
                    bytes,
                    oversized: false,
                });
            }
            chunks.push(BatchChunk {
                start: index,
                end: index + 1,
                bytes: length,
                oversized: true,
            });
            start = index + 1;
            bytes = 0;
            continue;
        }
        if start < index && (index - start >= file_cap || bytes.saturating_add(length) > byte_cap) {
            chunks.push(BatchChunk {
                start,
                end: index,
                bytes,
                oversized: false,
            });
            file_cap = (file_cap * 2).min(BATCH_STAGE_FILES);
            byte_cap = (byte_cap * 2).min(BATCH_CHUNK_BYTES);
            start = index;
            bytes = 0;
        }
        bytes = bytes.saturating_add(length);
    }
    if start < count {
        chunks.push(BatchChunk {
            start,
            end: count,
            bytes,
            oversized: false,
        });
    }
    chunks
}

/// Waits for a staging permit; oversized chunks stream from source without
/// staging and take none.
async fn staging_permit(
    app: &Arc<App>,
    chunk: &BatchChunk,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    if chunk.oversized {
        return None;
    }
    // The semaphore is never closed, so acquire only fails if it were.
    Arc::clone(&app.staging_permits).acquire_owned().await.ok()
}

fn validate_batch_sources(app: &App, grant: &OutboundGrant, count: usize) -> ApiResult<()> {
    let _pin = legacy_link_pin(app, grant, grant.files.is_empty())?;
    let verifying_key = app.signer.verifying_key();
    let mut output = io::sink();
    let mut buf = vec![0u8; CHUNK];
    for index in 0..count {
        let source = source_info_indexed_for_delivery(app, grant, index, "batch")?;
        let context = IntegrityContext::for_source(app, grant, index, "batch", &source);
        write_verified_source(&mut output, source, &verifying_key, &mut buf, &context)
            .map_err(map_batch_error)?;
    }
    Ok(())
}

fn start_batch_chunk(
    app: Arc<App>,
    grant: Arc<OutboundGrant>,
    chunk: BatchChunk,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> ApiResult<tokio::task::JoinHandle<io::Result<BatchFile>>> {
    let operation = begin_outbound_operation_owned(&app, &grant.tenant)?;
    if chunk.oversized {
        drop(permit);
        return Ok(tokio::spawn(async move {
            let worker = Arc::clone(&app);
            let (source, catalog, pin, operation, integrity) =
                tokio::task::spawn_blocking(move || {
                    let pin = legacy_link_pin(&worker, &grant, grant.files.is_empty())
                        .map_err(api_error_io)?;
                    let source =
                        source_info_indexed_for_delivery(&worker, &grant, chunk.start, "batch")
                            .map_err(api_error_io)?;
                    let integrity = IntegrityContext::for_source(
                        &worker,
                        &grant,
                        chunk.start,
                        "batch",
                        &source,
                    );
                    let catalog = ensure_catalog(
                        &worker.config.data_dir.join("outbound.proofs"),
                        &source.path,
                        &source.object,
                    )
                    .map_err(|error| report_io_integrity(&integrity, error))?;
                    Ok::<_, io::Error>((source, catalog, pin, operation, integrity))
                })
                .await
                .map_err(|_| io::Error::other("catalog generation failed"))??;
            let stream = start_verified_stream(
                source.path.clone(),
                source.object.clone(),
                catalog,
                None,
                integrity,
                Some(operation),
                None,
                None,
            )
            .await?;
            drop(pin);
            Ok(BatchFile::Verified(stream))
        }));
    }
    let stage_root = app.config.data_dir.join("outbound.stage");
    std::fs::create_dir_all(&stage_root)
        .map_err(|_| ApiError::internal("create outbound stage failed"))?;
    let reservation = app
        .outbound_stage_budget
        .reserve(&stage_root, chunk.bytes)
        .map_err(map_stage_reserve_error)?;
    let stage_dir = stage_root.join(format!(".vot-outbound-{}", auth::random_token()));
    std::fs::create_dir_all(&stage_dir)
        .map_err(|_| ApiError::internal("create outbound stage failed"))?;
    let stage = StagedFile {
        path: stage_dir.join("file"),
        reservation: Some(reservation),
    };
    let verifying_key = app.signer.verifying_key();
    // ponytail: every request re-copies and re-verifies each source into a
    // throwaway stage. Measured 2026-09-01 (throughput_outbound_batch, 1024 x
    // 256 KiB, VOTPORT_BENCH_STREAMS, sources page-cached, client in the same
    // process): one stream 1160 to 1310 MiB/s; four streams over four grants
    // 760 to 1010 MiB/s each, 2760 to 3660 MiB/s aggregate. Four streams is the
    // most that fit STAGING_CONCURRENCY = 8 at BATCH_LOOKAHEAD = 2 without
    // queueing, so up to that point staging is not the ceiling under parallel
    // clients. A second batch of the same grant is refused while the first
    // streams (ActiveDownload), so a staged-chunk cache could only serve
    // sequential re-fetches of one grant; add one keyed by grant id and file
    // range if that pattern shows.
    Ok(tokio::task::spawn_blocking(move || {
        let (_operation, _permit) = (operation, permit);
        let _pin = legacy_link_pin(&app, &grant, grant.files.is_empty()).map_err(api_error_io)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut output = options.open(&stage.path)?;
        let mut buf = vec![0u8; CHUNK];
        for index in chunk.start..chunk.end {
            let source = source_info_indexed_for_delivery(&app, &grant, index, "batch")
                .map_err(api_error_io)?;
            let context = IntegrityContext::for_source(&app, &grant, index, "batch", &source);
            write_verified_source(&mut output, source, &verifying_key, &mut buf, &context)?;
        }
        Ok(BatchFile::Staged(open_staged_reader(stage)?))
    }))
}

fn open_staged_reader(stage: StagedFile) -> io::Result<ReaderStream<StagedReader>> {
    let file = std::fs::File::open(&stage.path)?;
    let file = tokio::fs::File::from_std(file);
    Ok(ReaderStream::with_capacity(
        StagedReader {
            file,
            _stage: stage,
        },
        CHUNK,
    ))
}

async fn await_batch_chunk(
    handle: tokio::task::JoinHandle<io::Result<BatchFile>>,
) -> ApiResult<BatchFile> {
    handle
        .await
        .map_err(|_| ApiError::internal("outbound batch preparation failed"))?
        .map_err(map_batch_error)
}

fn api_error_io(error: ApiError) -> io::Error {
    if error.status == StatusCode::NOT_FOUND {
        io::Error::new(io::ErrorKind::NotFound, error.message)
    } else {
        io::Error::other(error.message)
    }
}

fn map_batch_error(error: io::Error) -> ApiError {
    match error.kind() {
        io::ErrorKind::InvalidData => ApiError::not_found(),
        io::ErrorKind::NotFound => ApiError::not_found(),
        _ => {
            tracing::error!(%error, "outbound batch build failed");
            ApiError::internal("build outbound batch failed")
        }
    }
}

async fn outbound_file_inner(
    app: Arc<App>,
    headers: HeaderMap,
    token: String,
    index: usize,
    peer: std::net::SocketAddr,
    route_path: String,
    query: Option<&str>,
) -> ApiResult<Response> {
    let (grant, leased, file) = active_download_grant(&app, &token, index, &headers, query)?;
    let grant = Arc::new(grant);
    let operation = begin_outbound_operation_owned(&app, &grant.tenant)?;
    // A verified lease was minted only after a full access check, so the
    // redirected request streams on the MAC alone: it carries no grant
    // cookie for a password gated grant.
    if !leased {
        require_grant_access(&app, &grant, &headers)?;
    }
    let allowed = app
        .outbound_rate
        .allow_individual(&grant.token_hash, || {
            app.store
                .outbound_grant_files_page_by_token_hash(&grant.token_hash, index, 0)
                .map(|page| page.map_or(1, |page| page.file_count.max(1)))
        })
        .map_err(super::store_unavailable)?;
    if !allowed {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many downloads; try again later",
        )
        .with_retry_after(600));
    }
    let legacy = grant.files.is_empty() && file.is_none();
    let (source, operation) = source_info_async(
        &app,
        Arc::clone(&grant),
        index,
        file,
        operation,
        Some("file"),
    )
    .await?;
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
    {
        let pin = legacy_link_pin(&app, &grant, legacy)?;
        let proof_root = app.config.data_dir.join("outbound.proofs");
        let source_path = source.path.clone();
        let expected = source.object.clone();
        let integrity = IntegrityContext::for_source(&app, &grant, index, "file", &source);
        let catalog_integrity = integrity.clone();
        let (catalog, pin, operation) = tokio::task::spawn_blocking(move || {
            let catalog =
                ensure_catalog(&proof_root, &source_path, &expected).map_err(|error| {
                    if error.kind() == io::ErrorKind::InvalidData {
                        report_integrity_failure(&catalog_integrity, &error);
                    }
                    ApiError::not_found()
                })?;
            Ok::<_, ApiError>((catalog, pin, operation))
        })
        .await
        .map_err(|_| ApiError::internal("catalog generation failed"))??;
        // The catalog is only rebuilt when its reuse key changes, so a
        // stale cached catalog would otherwise admit a corrupt source. The
        // unleased request therefore verifies the first chunk of the
        // requested range against the catalog before anything is counted,
        // exactly the eager check the streamed response used to make, so
        // an absent or corrupt source still consumes no download. The
        // probe drops its stream: the redirected request reopens and
        // streams the body.
        if !leased {
            let probe = start_verified_stream(
                source.path.clone(),
                source.object.clone(),
                catalog.clone(),
                range,
                integrity.clone(),
                None,
                None,
                None,
            )
            .await
            .map_err(|_| ApiError::not_found())?;
            drop(probe);
            audit_download_request(&app, &grant, &headers, peer, "file", Some(index), leased)
                .await?;
            let lifetime = grant
                .expires_at
                .saturating_sub(now_unix())
                .min(DOWNLOAD_LEASE_SECS);
            if lifetime > 0 {
                let lease = auth::issue_download_lease(
                    &app.secret,
                    &grant.id,
                    &grant.token_hash,
                    index,
                    lifetime,
                );
                return Ok(download_lease_redirect(&route_path, &lease));
            }
            // At the expiry edge there is no lease left to hand out, so
            // this request streams with no lease, exactly as the old
            // cookie path did.
        }
        let stream = start_verified_stream(
            source.path.clone(),
            source.object.clone(),
            catalog,
            range,
            integrity,
            Some(operation),
            Some(active),
            Some(StreamGate::for_grant(&app, &grant)),
        )
        .await
        .map_err(|_| ApiError::not_found())?;
        drop(pin);
        let length = range.map_or(source.object.length, |(start, end)| end - start + 1);
        // The batch route records each file as its last byte is handed to the
        // transport; this route now applies the same completion rule (audit
        // finding 490): only a response covering the whole object records,
        // once its last frame has passed through, so an interrupted download
        // burns no quota and range resumes on the leased URL never recount.
        let whole_object =
            range.is_none_or(|(start, end)| start == 0 && end + 1 == source.object.length);
        let remaining = if length == 0 {
            // An empty body has no last frame to carry the record, so it
            // lands before the response, the way the empty batch records.
            record_download(&app, &grant, &[index]).await?;
            None
        } else if whole_object {
            Some(length)
        } else {
            None
        };
        let stream = RecordingStream {
            inner: stream,
            remaining,
            app: Arc::clone(&app),
            grant: Arc::clone(&grant),
            index,
        };
        let mut response = Body::from_stream(stream).into_response();
        add_file_headers(&mut response, &source, length, range)?;
        if range.is_some() {
            *response.status_mut() = StatusCode::PARTIAL_CONTENT;
        }
        audit_download_request(&app, &grant, &headers, peer, "file", Some(index), leased).await?;
        Ok(response)
    }
}

async fn outbound_file_head_inner(
    app: Arc<App>,
    headers: HeaderMap,
    token: String,
    index: usize,
    query: Option<&str>,
) -> ApiResult<Response> {
    let (grant, leased, file) = active_download_grant(&app, &token, index, &headers, query)?;
    let grant = Arc::new(grant);
    let operation = begin_outbound_operation_owned(&app, &grant.tenant)?;
    // Same as the streaming path: a verified lease stands in for the
    // grant access recheck.
    if !leased {
        require_grant_access(&app, &grant, &headers)?;
    }
    if !app.outbound_rate.allow(&grant.token_hash) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many downloads; try again later",
        )
        .with_retry_after(600));
    }
    let (source, _operation) =
        source_info_async(&app, Arc::clone(&grant), index, file, operation, None).await?;
    let mut response = Body::empty().into_response();
    add_file_headers(&mut response, &source, source.object.length, None)?;
    Ok(response)
}

fn add_file_headers(
    response: &mut Response,
    source: &Source,
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
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        attachment_filename(&source.name)?,
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
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
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// Builds the same-origin redirect that hands a counted file request its
/// per-file lease in the URL query. The location mirrors the route the
/// request came in on, so the final URL is the same file route and any
/// old lease parameter is gone by construction. The lease value is
/// digits, dots and lowercase hex, so it needs no percent-encoding.
fn download_lease_redirect(route_path: &str, lease: &str) -> Response {
    let mut response = StatusCode::TEMPORARY_REDIRECT.into_response();
    if let Ok(value) = HeaderValue::from_str(&format!("{route_path}?download_lease={lease}")) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

pub async fn outbound_bundle(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    request: Request,
) -> ApiResult<Response> {
    let is_head = request.method() == Method::HEAD;
    let grant = active_grant(&app, &token)?;
    let operation = begin_outbound_operation_owned(&app, &grant.tenant)?;
    require_grant_access(&app, &grant, &headers)?;
    if !app.outbound_rate.allow(&grant.token_hash) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many downloads; try again later",
        )
        .with_retry_after(600));
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
    for index in 0..count {
        if grant_is_exhausted(&grant, index, None) {
            return Err(ApiError::not_found());
        }
    }
    if is_head {
        let mut response = Body::empty().into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/zip"),
        );
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"deliverables.zip\""),
        );
        return Ok(response);
    }
    let active = ActiveDownload::claim(Arc::clone(&app), &format!("{}:bundle", grant.token_hash))?;
    let gate = StreamGate::for_grant(&app, &grant);
    let worker = Arc::clone(&app);
    let (grant, archive, _operation, active, _pin) = tokio::task::spawn_blocking(move || {
        let _pin = legacy_link_pin(&worker, &grant, grant.files.is_empty())?;
        let mut files = Vec::with_capacity(count);
        for index in 0..count {
            let source = source_info_indexed_for_delivery(&worker, &grant, index, "bundle")?;
            let relative = bundle_path(&source.name).ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "invalid filename in delivery",
                )
            })?;
            files.push((source, relative));
        }
        let archive = build_bundle(&worker, &grant, files)?;
        Ok::<_, ApiError>((grant, archive, operation, active, _pin))
    })
    .await
    .map_err(|_| ApiError::internal("bundle preparation failed"))??;
    let length = tokio::fs::metadata(&archive.path)
        .await
        .map_err(|_| ApiError::internal("inspect bundle failed"))?
        .len();
    let file = tokio::fs::File::open(&archive.path)
        .await
        .map_err(|_| ApiError::internal("open bundle failed"))?;
    // The ZIP is one opaque response with no per-file boundaries a client
    // commits against, so the bundle keeps up-front recording; the batch
    // endpoint records per delivered file instead. The bundle lease lets an
    // interrupted bundle recover each file through the existing range path.
    let indexes: Vec<usize> = (0..count).collect();
    record_download(&app, &grant, &indexes).await?;
    let stream = ReaderStream::with_capacity(
        BundleReader {
            file,
            _archive: archive,
            _active: active,
            gate,
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
    issue_download_lease(
        &app,
        &grant,
        &token,
        BUNDLE_DOWNLOAD_LEASE_INDEX,
        &mut response,
    );
    audit_download_request(&app, &grant, &headers, peer, "bundle", None, false).await?;
    Ok(response)
}

pub(crate) fn readable_grant(app: &App, token: &str) -> ApiResult<OutboundGrant> {
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
    workflows::release(app, &grant)?;
    Ok(grant)
}

pub(crate) fn active_grant(app: &App, token: &str) -> ApiResult<OutboundGrant> {
    let grant = readable_grant(app, token)?;
    if grant
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
    query: Option<&str>,
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
    let leased = download_lease_authorized(app, &grant, index, headers, query);
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

/// Audits a download response. `leased` marks a request whose per-file
/// URL lease already proved grant access at admission, so the closure
/// records the audit event without re-running the password and recipient
/// checks that the redirected request can no longer answer.
async fn audit_download_request(
    app: &Arc<App>,
    grant: &OutboundGrant,
    headers: &HeaderMap,
    peer: std::net::SocketAddr,
    mode: &'static str,
    index: Option<usize>,
    leased: bool,
) -> ApiResult<()> {
    let client_ip = super::client_ip(headers, &peer, &app.config.trusted_proxies);
    let tenant = grant.tenant.clone();
    let subject = grant.id.clone();
    let token_hash = grant.token_hash.clone();
    let password_hash = grant.password_hash.clone();
    let secret = app.secret;
    let headers = headers.clone();
    let detail = match index {
        Some(index) => json!({
            "client_ip": client_ip,
            "mode": mode,
            "file_index": index,
        }),
        None => json!({
            "client_ip": client_ip,
            "mode": mode,
        }),
    };
    let store = Arc::clone(&app.store);
    let app = Arc::clone(app);
    tokio::task::spawn_blocking(move || {
        store.delivery_access_with_audit(&subject, &token_hash, &tenant, &detail, |access| {
            let job = access.map_err(|error| {
                if error == "delivery link is inactive" {
                    ApiError::not_found()
                } else {
                    ApiError::new(StatusCode::FORBIDDEN, error).with_code("delivery_pending")
                }
            })?;
            if !leased {
                if password_hash.is_some()
                    && !super::upload::cookie_authorized(
                        &app,
                        &subject,
                        password_hash.as_deref(),
                        &grant_cookie_name(&subject),
                        &headers,
                    )
                {
                    return Err(ApiError::new(
                        StatusCode::UNAUTHORIZED,
                        "delivery password required",
                    ));
                }
                workflows::require_recipient_for_job(
                    &secret,
                    &subject,
                    &token_hash,
                    &headers,
                    job.as_ref(),
                )?;
            }
            tracing::info!(
                target: "audit",
                event = "outbound_downloaded",
                grant_id = %subject,
                %client_ip,
                mode,
                file_index = ?index,
                "outbound HTTP payload request started"
            );
            Ok(())
        })
    })
    .await
    .map_err(|_| ApiError::internal("download authorization failed"))?
}

async fn record_download(
    app: &Arc<App>,
    grant: &OutboundGrant,
    indexes: &[usize],
) -> ApiResult<OutboundDownloadResult> {
    // Store writes and the grant reload run off the runtime thread; this
    // sits ahead of every download response.
    let store = Arc::clone(&app.store);
    let grant_id = grant.id.clone();
    let token_hash = grant.token_hash.clone();
    let notify = grant.notifications.as_ref().is_some_and(|p| p.enabled());
    let indexes = indexes.to_vec();
    let recorded = tokio::task::spawn_blocking(move || {
        let result = store.record_outbound_download(&grant_id, &indexes, now_unix())?;
        let reload = if notify && (result.first_download || result.completed_delivery) {
            Some(store.outbound_grant_by_token_hash(&token_hash))
        } else {
            None
        };
        Ok::<_, String>((result, reload))
    })
    .await
    .map_err(|error| {
        tracing::warn!(grant_id = %grant.id, %error, "record download task failed");
        ApiError::internal("record download failed")
    })?;
    match recorded {
        Ok((result, reload)) => {
            match reload {
                Some(Ok(Some(full_grant))) => {
                    tokio::spawn(crate::notify::outbound_downloaded(
                        Arc::clone(app),
                        full_grant,
                        result,
                    ));
                }
                Some(Ok(None)) => {
                    tracing::warn!(grant_id = %grant.id, "download notification grant reload found no grant");
                }
                Some(Err(error)) => {
                    tracing::warn!(grant_id = %grant.id, %error, "download notification grant reload failed");
                }
                None => {}
            }
            Ok(result)
        }
        Err(error) if error == OUTBOUND_DOWNLOAD_LIMIT_REACHED => Err(ApiError::not_found()),
        Err(error) => {
            tracing::warn!(grant_id = %grant.id, %error, "record download failed");
            Err(ApiError::internal("record download failed"))
        }
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
    query: Option<&str>,
) -> bool {
    if let Some(value) = download_lease_query(query) {
        if auth::verify_download_lease(&app.secret, &grant.id, &grant.token_hash, index, value) {
            return true;
        }
    }
    // The bundle sentinel stays a cookie: it is issued once after every
    // bundle index has been recorded, so its size does not grow with the
    // file list the way one per-file cookie did.
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|cookies| {
            auth::cookie_value(
                cookies,
                &download_lease_cookie_name(&grant.id, BUNDLE_DOWNLOAD_LEASE_INDEX),
            )
            .is_some_and(|value| {
                auth::verify_download_lease(
                    &app.secret,
                    &grant.id,
                    &grant.token_hash,
                    BUNDLE_DOWNLOAD_LEASE_INDEX,
                    value,
                )
            })
        })
}

/// The raw value of the `download_lease` query parameter, when present.
/// The value is compared as issued, so percent-encoded junk fails the
/// MAC check and counts as absent.
fn download_lease_query(query: Option<&str>) -> Option<&str> {
    query?.split('&').find_map(|pair| {
        pair.split_once('=')
            .filter(|(name, _)| *name == "download_lease")
            .map(|(_, value)| value)
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

pub(crate) fn require_grant_access(
    app: &App,
    grant: &OutboundGrant,
    headers: &HeaderMap,
) -> ApiResult<()> {
    workflows::require_recipient(app, grant, headers)?;
    if grant_authorized(app, grant, headers) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "delivery password required",
        ))
    }
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

// ponytail: every request re-copies and re-verifies each source; cache the
// built archive keyed by grant id + file set if concurrent same-ZIP fetches
// are ever measured as a pattern.
fn build_bundle(
    app: &App,
    grant: &OutboundGrant,
    files: Vec<(Source, String)>,
) -> ApiResult<StagedFile> {
    crate::paths::admit_portable_paths(files.iter().map(|(_, name)| name.as_str()))
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    let bound = archive_size_bound(&files).ok_or_else(stage_capacity_error)?;
    let stage_root = app.config.data_dir.join("outbound.stage");
    std::fs::create_dir_all(&stage_root)
        .map_err(|_| ApiError::internal("create bundle stage failed"))?;
    let reservation = app
        .outbound_stage_budget
        .reserve(&stage_root, bound)
        .map_err(map_stage_reserve_error)?;
    let stage_dir = stage_root.join(format!(".vot-outbound-{}", auth::random_token()));
    std::fs::create_dir_all(&stage_dir)
        .map_err(|_| ApiError::internal("create bundle stage failed"))?;
    let archive_path = stage_dir.join(format!("{}.zip", auth::random_token()));
    let archive = StagedFile {
        path: archive_path.clone(),
        reservation: Some(reservation),
    };
    let verifying_key = app.signer.verifying_key();
    (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let output = options.open(&archive_path)?;
        let mut builder = ZipWriter::new(output);
        let mut buf = vec![0u8; CHUNK];
        for (index, (source, name)) in files.into_iter().enumerate() {
            let integrity = IntegrityContext::for_source(app, grant, index, "bundle", &source);
            let expected = source.object.clone();
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .large_file(expected.length >= u32::MAX as u64);
            builder.start_file(name, options)?;
            write_verified_source(&mut builder, source, &verifying_key, &mut buf, &integrity)?;
        }
        let output = builder.finish()?;
        output.sync_all()?;
        Ok::<_, io::Error>(())
    })()
    .map_err(map_bundle_error)?;
    Ok(archive)
}

fn write_verified_source<W: io::Write>(
    output: &mut W,
    source: Source,
    verifying_key: &ed25519_dalek::VerifyingKey,
    buf: &mut [u8],
    context: &IntegrityContext,
) -> io::Result<()> {
    use std::io::Read;

    let expected = source.object;
    let suite = Suite::try_from(expected.suite).map_err(|_| invalid_integrity(context, "suite"))?;
    let mut input = std::fs::File::open(&source.path)?;
    let mut object = InMemoryObjectBuilder::new(suite, Some(expected.length), expected.length)
        .map_err(|_| invalid_integrity(context, "builder"))?;
    loop {
        let count = input.read(buf)?;
        if count == 0 {
            break;
        }
        object
            .update(&buf[..count])
            .map_err(|_| invalid_integrity(context, "object"))?;
        output.write_all(&buf[..count])?;
    }
    let actual = object
        .finish()
        .map_err(|_| invalid_integrity(context, "object"))?;
    if actual.object_id() != &expected {
        return Err(invalid_integrity(context, "source mismatch"));
    }
    if let Some(receipt) = source.receipt {
        if receipt.len() as u64 > MAX_RECEIPT_BYTES
            || verify_receipt_with_key(verifying_key, &receipt, &expected).is_err()
        {
            return Err(invalid_integrity(context, "receipt verification failed"));
        }
    }
    Ok(())
}

fn invalid_integrity(context: &IntegrityContext, message: &'static str) -> io::Error {
    let error = io::Error::new(io::ErrorKind::InvalidData, message);
    report_integrity_failure(context, &error);
    error
}

fn report_io_integrity(context: &IntegrityContext, error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::InvalidData {
        report_integrity_failure(context, &error);
    }
    error
}

fn classify_integrity_eof(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "verified outbound proof truncated",
        )
    } else {
        error
    }
}

fn archive_size_bound(files: &[(Source, String)]) -> Option<u64> {
    let total_bytes = files.iter().try_fold(0u64, |total, (source, _)| {
        total.checked_add(source.object.length)
    })?;
    let entry_count = u64::try_from(files.len()).ok()?;
    let path_bytes = files.iter().try_fold(0u64, |total, (_, name)| {
        total.checked_add(u64::try_from(name.len()).ok()?)
    })?;
    let entry_overhead = entry_count.checked_mul(
        ZIP_LOCAL_HEADER_BYTES
            .checked_add(ZIP_CENTRAL_HEADER_BYTES)?
            .checked_add(ZIP_ENTRY_EXTRA_BYTES)?,
    )?;
    total_bytes
        .checked_add(entry_overhead)?
        .checked_add(path_bytes.checked_mul(2)?)?
        .checked_add(ZIP_END_BYTES)
}

fn stage_capacity_error() -> ApiError {
    ApiError::new(
        StatusCode::INSUFFICIENT_STORAGE,
        "not enough temporary disk space to prepare this download; free space and retry",
    )
}

fn map_stage_reserve_error(error: StageReserveError) -> ApiError {
    match error {
        StageReserveError::Insufficient | StageReserveError::Overflow => stage_capacity_error(),
        StageReserveError::Probe(error) => {
            tracing::error!(%error, "inspect outbound staging filesystem failed");
            ApiError::internal("inspect outbound staging filesystem failed")
        }
    }
}

fn map_bundle_error(error: io::Error) -> ApiError {
    match error.kind() {
        io::ErrorKind::InvalidData => ApiError::not_found(),
        io::ErrorKind::NotFound => ApiError::not_found(),
        _ => {
            tracing::error!(%error, "outbound bundle build failed");
            ApiError::internal("build bundle failed")
        }
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

fn validate_max_downloads(max_downloads: Option<u64>) -> ApiResult<()> {
    if max_downloads.is_some_and(|max| !(1..=10_000).contains(&max)) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "max_downloads must be 1..=10000",
        ));
    }
    Ok(())
}

pub(crate) struct Source {
    pub(crate) path: PathBuf,
    pub(crate) object: ObjectId,
    pub(crate) name: String,
    pub(crate) receipt: Option<Vec<u8>>,
}

fn read_verified_receipt(
    app: &App,
    path: &Path,
    object: &ObjectId,
    integrity: Option<&IntegrityContext>,
) -> ApiResult<Vec<u8>> {
    use std::io::Read as _;
    let mut receipt = Vec::new();
    std::fs::File::open(receipt_path(path))
        .map_err(|_| ApiError::not_found())?
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut receipt)
        .map_err(|_| ApiError::not_found())?;
    if receipt.len() as u64 > MAX_RECEIPT_BYTES || verify_receipt(app, &receipt, object).is_err() {
        if let Some(integrity) = integrity {
            let error = io::Error::new(io::ErrorKind::InvalidData, "receipt verification failed");
            report_integrity_failure(integrity, &error);
        }
        return Err(ApiError::not_found());
    }
    Ok(receipt)
}

struct VerifiedStream {
    first: Option<Result<Bytes, io::Error>>,
    receiver: mpsc::Receiver<Result<Bytes, io::Error>>,
    _operation: Option<OwnedOutboundOperation>,
    _active: Option<ActiveDownload>,
    /// Set only on the body stream, never on the preparation probe or the
    /// batch chunks (the batch loop checks its own gate per frame).
    gate: Option<StreamGate>,
}

/// Wraps the file route's body stream to record the download the way the
/// batch stream records each file: when the response's last byte is handed
/// to the transport (audit finding 490). `remaining` counts down the bytes
/// of a whole-object response and fires the record on the frame that reaches
/// zero, before that frame is returned, because a known-length body may
/// never be polled again. A dropped stream before that frame leaves the
/// download unrecorded and retryable. The record is spawned rather than
/// awaited so the final frame is not held back; a crash in that window
/// leaves the file downloadable, the safe direction.
struct RecordingStream {
    inner: VerifiedStream,
    /// Bytes still to hand off before the count lands. `None` never records:
    /// a partial range response (resumes stay free under the download lease)
    /// and the empty body, which recorded before the response.
    remaining: Option<u64>,
    app: Arc<App>,
    grant: Arc<OutboundGrant>,
    index: usize,
}

impl Stream for RecordingStream {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let frame = match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(frame) => frame,
            Poll::Pending => return Poll::Pending,
        };
        if let (Some(Ok(bytes)), Some(remaining)) = (&frame, &mut this.remaining) {
            *remaining = remaining.saturating_sub(bytes.len() as u64);
            if *remaining == 0 {
                this.remaining = None;
                let app = Arc::clone(&this.app);
                let grant = Arc::clone(&this.grant);
                let index = this.index;
                let grant_id = this.grant.id.clone();
                tokio::spawn(async move {
                    // The body is already gone, so a refusal (a racing stream
                    // took the last allowed download) can only be logged.
                    if let Err(error) = record_download(&app, &grant, &[index]).await {
                        tracing::debug!(%grant_id, ?error, "download record after delivery refused");
                    }
                });
            }
        }
        Poll::Ready(frame)
    }
}

impl Stream for VerifiedStream {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(item) = self.first.take() {
            return Poll::Ready(Some(item));
        }
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(_)) if self.gate.as_ref().is_some_and(StreamGate::stopped) => {
                Poll::Ready(Some(Err(io::Error::other(
                    "download revoked or expired mid-stream",
                ))))
            }
            item => item,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_verified_stream(
    source: PathBuf,
    expected: ObjectId,
    catalog: PathBuf,
    range: Option<(u64, u64)>,
    integrity: IntegrityContext,
    operation: Option<OwnedOutboundOperation>,
    active: Option<ActiveDownload>,
    gate: Option<StreamGate>,
) -> io::Result<VerifiedStream> {
    let (first_tx, first_rx) = oneshot::channel();
    let (sender, receiver) = mpsc::channel(1);
    tokio::task::spawn_blocking(move || {
        let result = produce_verified_stream(
            source, expected, catalog, range, integrity, first_tx, sender,
        );
        if let Err(error) = result {
            tracing::debug!(%error, "verified outbound stream stopped");
        }
    });
    let first = first_rx
        .await
        .map_err(|_| io::Error::other("verified stream stopped"))??;
    Ok(VerifiedStream {
        first: Some(Ok(first)),
        receiver,
        _operation: operation,
        _active: active,
        gate,
    })
}

fn produce_verified_stream(
    source: PathBuf,
    expected: ObjectId,
    catalog: PathBuf,
    range: Option<(u64, u64)>,
    integrity: IntegrityContext,
    first: oneshot::Sender<io::Result<Bytes>>,
    sender: mpsc::Sender<io::Result<Bytes>>,
) -> io::Result<()> {
    use std::io::{Read as _, Seek as _};
    let mut first = Some(first);
    let mut first_sent = false;
    let result: io::Result<()> = (|| {
        let mut input = std::fs::File::open(&source)?;
        let mut catalog_file = std::fs::File::open(&catalog)?;
        let header =
            catalog_header(&mut catalog_file, &expected).map_err(classify_integrity_eof)?;
        if header.record_count() == 0 {
            first
                .take()
                .expect("first result sender")
                .send(Ok(Bytes::new()))
                .map_err(|_| io::Error::other("stream cancelled"))?;
            first_sent = true;
            return Ok(());
        }
        let first_ordinal = range.map_or(0, |(start, _)| start / proof::RANGE_LENGTH);
        let last_ordinal = range.map_or(header.record_count() - 1, |(_, end)| {
            end / proof::RANGE_LENGTH
        });
        for ordinal in first_ordinal..=last_ordinal {
            let index_offset = header
                .index_entry_offset(ordinal)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "catalog entry"))?;
            let mut index = [0u8; proof::INDEX_ENTRY_LENGTH];
            catalog_file.seek(SeekFrom::Start(index_offset))?;
            catalog_file
                .read_exact(&mut index)
                .map_err(classify_integrity_eof)?;
            let entry = header
                .decode_entry(ordinal, &index)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "catalog entry"))?;
            let proof_length = usize::try_from(entry.proof_length())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proof length"))?;
            let mut proof_bytes = vec![0u8; proof_length];
            catalog_file.seek(SeekFrom::Start(entry.proof_offset()))?;
            catalog_file
                .read_exact(&mut proof_bytes)
                .map_err(classify_integrity_eof)?;
            let data_length = usize::try_from(entry.data_length())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "data length"))?;
            let mut data = vec![0u8; data_length];
            input.seek(SeekFrom::Start(entry.data_offset()))?;
            input
                .read_exact(&mut data)
                .map_err(classify_integrity_eof)?;
            entry
                .verify(&data, &proof_bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "source proof"))?;
            let (begin, end) = if let Some((start, end)) = range {
                let begin = usize::try_from(start.saturating_sub(entry.data_offset()))
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "range start"))?;
                let end = usize::try_from(
                    end.saturating_add(1)
                        .saturating_sub(entry.data_offset())
                        .min(entry.data_length()),
                )
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "range end"))?;
                (begin, end)
            } else {
                (0, data.len())
            };
            let output = Bytes::from(data).slice(begin..end);
            if !first_sent {
                first
                    .take()
                    .expect("first result sender")
                    .send(Ok(output))
                    .map_err(|_| io::Error::other("stream cancelled"))?;
                first_sent = true;
            } else if sender.blocking_send(Ok(output)).is_err() {
                return Ok(());
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        if error.kind() == io::ErrorKind::InvalidData {
            report_integrity_failure(&integrity, &error);
        }
        if first_sent {
            let _ = sender.blocking_send(Err(error));
        } else if let Some(first) = first.take() {
            let _ = first.send(Err(error));
        }
    }
    Ok(())
}

async fn source_info_async(
    app: &Arc<App>,
    grant: Arc<OutboundGrant>,
    index: usize,
    file: Option<OutboundGrantFile>,
    operation: OwnedOutboundOperation,
    component: Option<&'static str>,
) -> ApiResult<(Source, OwnedOutboundOperation)> {
    let app = Arc::clone(app);
    tokio::task::spawn_blocking(move || {
        let source =
            source_info_indexed_with_component(&app, &grant, index, file.as_ref(), component)?;
        Ok((source, operation))
    })
    .await
    .map_err(|_| ApiError::internal("inspect delivery source failed"))?
}

fn source_info_indexed_for_delivery(
    app: &App,
    grant: &OutboundGrant,
    index: usize,
    component: &'static str,
) -> ApiResult<Source> {
    source_info_indexed_with_component(app, grant, index, None, Some(component))
}

pub(crate) fn source_info_indexed_with_file(
    app: &App,
    grant: &OutboundGrant,
    index: usize,
    indexed_file: Option<&OutboundGrantFile>,
) -> ApiResult<Source> {
    source_info_indexed_with_component(app, grant, index, indexed_file, None)
}

fn source_info_indexed_with_component(
    app: &App,
    grant: &OutboundGrant,
    index: usize,
    indexed_file: Option<&OutboundGrantFile>,
    component: Option<&'static str>,
) -> ApiResult<Source> {
    if let Some(file) = indexed_file.or_else(|| grant.files.get(index)) {
        let (root, path) = if let Some(stored_as) = file.source.strip_prefix("received:") {
            app.receiving_destinations()
                .map_err(|e| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, e))?;
            (
                app.config.receive_dir.clone(),
                admin::stored_path(app, &grant.tenant, stored_as)
                    .ok_or_else(ApiError::not_found)?,
            )
        } else {
            let path = if let Some(relative) =
                file.source.strip_prefix(&format!("workflow:{}/", grant.id))
            {
                workflows::payload_path(app, &grant.tenant, &grant.id, relative)?
            } else {
                safe_library_path(app, &grant.tenant, &file.source)?
            };
            (library_root(app, &grant.tenant), path)
        };
        if !library_components_safe(&root, &path) {
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
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| ApiError::not_found())?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(ApiError::not_found());
        }
        let object = ObjectId {
            suite,
            root,
            length: file.bytes,
        };
        let integrity = component
            .filter(|_| file.source.starts_with("received:"))
            .map(|component| IntegrityContext::for_path(app, grant, index, component, &path));
        let receipt = if file.source.starts_with("received:") {
            Some(read_verified_receipt(
                app,
                &path,
                &object,
                integrity.as_ref(),
            )?)
        } else {
            None
        };
        return Ok(Source {
            path,
            object,
            name: file.name.clone(),
            receipt,
        });
    }
    if index != 0 {
        return Err(ApiError::not_found());
    }
    let upload = app
        .store
        .link_upload(&grant.tenant, &grant.link_id, &grant.upload_id)
        .map_err(super::store_unavailable)?
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
    let object = ObjectId {
        suite,
        root,
        length: file.bytes,
    };
    let integrity =
        component.map(|component| IntegrityContext::for_path(app, grant, index, component, &path));
    let receipt = Some(read_verified_receipt(
        app,
        &path,
        &object,
        integrity.as_ref(),
    )?);
    Ok(Source {
        path,
        object,
        name: file.path.clone(),
        receipt,
    })
}

fn legacy_link_pin(
    app: &App,
    grant: &OutboundGrant,
    should_pin: bool,
) -> ApiResult<Option<crate::session::LinkPin>> {
    if !should_pin {
        return Ok(None);
    }
    let pin = app
        .sessions
        .try_pin_link(&grant.link_id)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "link lifecycle update in progress"))?;
    if app.sessions.active_for_link(&grant.link_id) > 0 {
        return Err(ApiError::new(StatusCode::CONFLICT, "uploads are in flight"));
    }
    Ok(Some(pin))
}

fn verify_receipt(app: &App, bytes: &[u8], object: &ObjectId) -> Result<(), ()> {
    verify_receipt_with_key(&app.signer.verifying_key(), bytes, object)
}

fn receipt_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".vot-receipt");
    value.into()
}
fn valid_token(token: &str) -> bool {
    token.len() == 32 && token.as_bytes().iter().all(u8::is_ascii_hexdigit)
}
pub(super) fn attachment_filename(name: &str) -> ApiResult<HeaderValue> {
    use std::fmt::Write as _;

    let name = name
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !matches!(*name, "" | "." | ".."))
        .unwrap_or("download.bin");
    let fallback: String = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ' ') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let mut value = format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''");
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~') {
            value.push(char::from(byte));
        } else {
            write!(value, "%{byte:02X}").expect("writing to a string cannot fail");
        }
    }
    HeaderValue::try_from(value).map_err(|_| ApiError::internal("download filename invalid"))
}
fn public_grant(grant: &OutboundGrant) -> serde_json::Value {
    let file_count = if grant.files.is_empty() {
        1
    } else {
        grant.files.len()
    };
    public_grant_with_file_count(grant, file_count)
}

fn public_grant_with_file_count(grant: &OutboundGrant, file_count: usize) -> serde_json::Value {
    let files_truncated = file_count > OUTBOUND_GRANT_PREVIEW_FILES
        || (file_count > 1 && grant.files.len() < file_count);
    // Per-file counters are named download_starts (docs/agents.md): a count
    // of transport handoffs, the same counter the automation deliveries
    // response reports as files[].download_starts. The grant-wide pair
    // downloads/max_downloads is a different counter and keeps its name.
    let files = if files_truncated {
        Vec::new()
    } else {
        grant
            .files
            .iter()
            .map(|file| {
                json!({ "name": file.name, "suite": file.suite, "root": file.root, "bytes": file.bytes, "download_starts": file.downloads, "first_download_at": file.first_download_at, "last_download_at": file.last_download_at })
            })
            .collect()
    };
    json!({ "id": grant.id, "tenant": grant.tenant, "link_id": grant.link_id, "upload_id": grant.upload_id, "file_index": grant.file_index, "name": grant.name, "label": grant.label, "has_password": grant.password_hash.is_some(), "created_at": grant.created_at, "expires_at": grant.expires_at, "revoked_at": grant.revoked_at, "max_downloads": grant.max_downloads, "downloads": grant.downloads, "first_download_at": grant.first_download_at, "last_download_at": grant.last_download_at, "notifications":grant.notifications, "file_count": file_count, "files_truncated": files_truncated, "files": files })
}

fn public_automation_token(token: &AutomationToken) -> serde_json::Value {
    json!({
        "id": token.id,
        "tenant": token.tenant,
        "label": token.label,
        "directory": token.directory,
        "permissions": token.permissions,
        "created_by": token.created_by,
        "created_at": token.created_at,
        "expires_at": token.expires_at,
        "revoked_at": token.revoked_at,
        "last_used_at": token.last_used_at,
    })
}

pub(crate) struct ActiveDownload {
    app: Arc<App>,
    key: String,
}

/// Stops a live download when its grant is revoked or expires. Revocation
/// cancels the grant's token (see [`cancel_grant_streams`]); expiry is a
/// clock compare against the grant's own deadline, checked at the same frame
/// boundaries. Admission-only checks would otherwise let a stream verified
/// before the revocation deliver the whole body.
#[derive(Clone)]
struct StreamGate {
    cancel: CancellationToken,
    expires_at: u64,
}

impl StreamGate {
    fn for_grant(app: &App, grant: &OutboundGrant) -> Self {
        Self {
            cancel: stream_cancel_token(app, &grant.token_hash),
            expires_at: grant.expires_at,
        }
    }

    fn stopped(&self) -> bool {
        self.cancel.is_cancelled() || self.expires_at <= now_unix()
    }
}

/// The cancellation token every live download stream of the grant holds.
/// Created on first claim; dropped when the grant's last stream ends
/// ([`ActiveDownload::drop`]) or when a revocation cancels it.
fn stream_cancel_token(app: &App, token_hash: &str) -> CancellationToken {
    let mut cancels = app
        .outbound_stream_cancels
        .lock()
        .expect("outbound stream cancels poisoned");
    cancels.entry(token_hash.to_owned()).or_default().clone()
}

/// Cancels every live download stream of a grant. Called by the revoke
/// handlers once the store records the revocation.
pub(crate) fn cancel_grant_streams(app: &App, token_hash: &str) {
    let token = app
        .outbound_stream_cancels
        .lock()
        .expect("outbound stream cancels poisoned")
        .remove(token_hash);
    if let Some(token) = token {
        token.cancel();
    }
}

impl ActiveDownload {
    fn claim(app: Arc<App>, key: &str) -> ApiResult<Self> {
        let grant = key.rsplit_once(':').map_or(key, |(grant, _)| grant);
        Self::claim_with_grant(app, key, grant)
    }

    pub(crate) fn claim_with_grant(app: Arc<App>, key: &str, grant: &str) -> ApiResult<Self> {
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
            )
            .with_retry_after(1));
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
        // Keys start with the grant's token hash, which holds no colon:
        // "{hash}:{index}", "{hash}:{index}:{random}", "{hash}:batch",
        // "{hash}:bundle".
        let grant = self.key.split(':').next().unwrap_or(&self.key);
        let mut active = self
            .app
            .outbound_active
            .lock()
            .expect("outbound active poisoned");
        active.remove(&self.key);
        // The grant's last live download ended, so its cancellation token has
        // no listener left and the map must not keep it.
        if !active.iter().any(|other| {
            other
                .strip_prefix(grant)
                .is_some_and(|rest| rest.starts_with(':'))
        }) {
            self.app
                .outbound_stream_cancels
                .lock()
                .expect("outbound stream cancels poisoned")
                .remove(grant);
        }
    }
}

struct StagedFile {
    path: PathBuf,
    reservation: Option<StageReservation>,
}
impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
        drop(self.reservation.take());
    }
}

struct BundleReader {
    file: tokio::fs::File,
    _archive: StagedFile,
    _active: ActiveDownload,
    gate: StreamGate,
}

struct StagedReader {
    file: tokio::fs::File,
    _stage: StagedFile,
}

impl AsyncRead for StagedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}

struct BatchStream {
    app: Arc<App>,
    grant: Arc<OutboundGrant>,
    _operation: OwnedOutboundOperation,
    _active: ActiveDownload,
    gate: StreamGate,
    chunks: Vec<BatchChunk>,
    chunk_index: usize,
    file: Option<BatchFile>,
    /// Staging tasks for the chunks after `chunk_index`, in order: entry i
    /// is chunk `chunk_index + 1 + i`.
    lookahead: std::collections::VecDeque<tokio::task::JoinHandle<io::Result<BatchFile>>>,
    /// Cumulative end offset of each file in the concatenated body; a file is
    /// recorded once a poll covers its boundary. The final frame flushes
    /// before it is returned because a known-length body need not poll
    /// terminal None. This records transport handoff, not recipient receipt.
    boundaries: Vec<u64>,
    /// End of the chunk whose source bytes and receipts have been validated.
    validated_end: usize,
    sent_bytes: u64,
    recorded: usize,
}

/// Delivered files are recorded in one store transaction per this many
/// delivered bytes, not one per file: every commit is an fsync inside the
/// stream, and a batch of small files paid one per file (1024 x 256 KiB
/// measured 320 MiB/s against 867 MiB/s for one file of the same size).
/// A dropped stream can now leave fully delivered files unrecorded up to
/// this many bytes plus the file that crosses the window, instead of one
/// file, still the safe direction: those files stay downloadable and a later
/// per-file fetch records them. Per-file download counts are one per stream
/// either way, and the grant count is the minimum over its files, so the
/// window changes when files are recorded, never how many times.
const RECORD_COALESCE_BYTES: u64 = 16 * 1024 * 1024;

/// The files to record now: those past `recorded` whose boundary `sent_bytes`
/// has covered, once they span the coalesce window, or all of them on
/// `flush`.
fn record_range(
    boundaries: &[u64],
    recorded: usize,
    sent_bytes: u64,
    flush: bool,
) -> Option<std::ops::Range<usize>> {
    let mut end = recorded;
    while end < boundaries.len() && sent_bytes >= boundaries[end] {
        end += 1;
    }
    if end == recorded {
        return None;
    }
    let recorded_end = recorded.checked_sub(1).map_or(0, |last| boundaries[last]);
    (flush || boundaries[end - 1] - recorded_end >= RECORD_COALESCE_BYTES).then_some(recorded..end)
}

impl BatchStream {
    /// Keeps BATCH_LOOKAHEAD chunks staging ahead of the streaming one. An
    /// oversized chunk streams straight from its source with its own
    /// blocking producer, so staging stops at the first one and never runs
    /// beside one.
    fn fill_lookahead(&mut self) {
        if self.chunks[self.chunk_index].oversized {
            return;
        }
        while self.lookahead.len() < BATCH_LOOKAHEAD {
            let next = self.chunk_index + 1 + self.lookahead.len();
            let Some(chunk) = self.chunks.get(next) else {
                break;
            };
            if chunk.oversized {
                break;
            }
            // No free permit: stage this chunk inline when its turn comes.
            let Ok(permit) = Arc::clone(&self.app.staging_permits).try_acquire_owned() else {
                break;
            };
            match start_batch_chunk(
                Arc::clone(&self.app),
                Arc::clone(&self.grant),
                chunk.clone(),
                Some(permit),
            ) {
                Ok(handle) => self.lookahead.push_back(handle),
                // The stream loop retries inline and surfaces the error.
                Err(_) => break,
            }
        }
    }

    async fn validate_trailing_chunks(&mut self) -> ApiResult<()> {
        let mut chunk_index = self.chunk_index + 1;
        while let Some(chunk) = self.chunks.get(chunk_index).cloned() {
            let handle = if let Some(handle) = self.lookahead.pop_front() {
                handle
            } else {
                let permit = staging_permit(&self.app, &chunk).await;
                start_batch_chunk(
                    Arc::clone(&self.app),
                    self.grant.clone(),
                    chunk.clone(),
                    permit,
                )?
            };
            drop(await_batch_chunk(handle).await?);
            self.validated_end = self.chunks[chunk_index].end;
            chunk_index += 1;
        }
        Ok(())
    }

    /// Records every file whose boundary has been covered, once enough of
    /// them have accumulated or when `flush` ends the stream.
    async fn record_delivered(&mut self, flush: bool) -> ApiResult<()> {
        let Some(range) = record_range(
            &self.boundaries[..self.validated_end],
            self.recorded,
            self.sent_bytes,
            flush,
        ) else {
            return Ok(());
        };
        let indexes: Vec<usize> = range.clone().collect();
        record_download(&self.app, &self.grant, &indexes).await?;
        self.recorded = range.end;
        Ok(())
    }
}

impl Drop for BatchStream {
    fn drop(&mut self) {
        // A running spawn_blocking stage finishes anyway and its StagedFile
        // drop removes the stage; abort only stops ones not yet started.
        for handle in self.lookahead.drain(..) {
            handle.abort();
        }
    }
}

impl AsyncRead for BundleReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // A stream admitted before its grant was revoked or expired stops at
        // the next read instead of delivering the rest of the archive.
        if self.gate.stopped() {
            return Poll::Ready(Err(io::Error::other(
                "download revoked or expired mid-stream",
            )));
        }
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
    use std::time::Duration;
    use tower::ServiceExt as _;
    use vot_sdk_file::PublishObservation;

    #[test]
    fn error_deduper_suppresses_unchanged_errors_and_fires_recovery_once() {
        let start = std::time::Instant::now();
        let mut dedupe = ErrorDeduper::new("test site");
        // First occurrence logs immediately.
        assert!(dedupe.observe("store locked", start));
        // An unchanged repeat inside the interval stays quiet.
        assert!(!dedupe.observe("store locked", start + Duration::from_secs(30)));
        // A changed error logs immediately.
        assert!(dedupe.observe("disk full", start + Duration::from_secs(31)));
        // The new error's own cadence suppresses its immediate repeat.
        assert!(!dedupe.observe("disk full", start + Duration::from_secs(40)));
        // After the interval the unchanged error is visible again.
        assert!(dedupe.observe(
            "disk full",
            start + Duration::from_secs(31) + WORKER_LOG_INTERVAL
        ));
        // Recovery is due exactly once, and only after an error.
        assert!(dedupe.recovered());
        assert!(!dedupe.recovered());
    }

    /// Audit finding 225: a download whose store write fails keeps its 500
    /// response but now warns with the grant id and store error instead of
    /// vanishing into the generic message.
    #[tokio::test]
    async fn record_download_warns_when_the_store_write_fails() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .with(|connection| connection.execute_batch("DROP TABLE outbound_grants"))
            .unwrap();
        let grant = crate::notify::tests::test_grant(vec![]);
        let (log, _guard) = crate::logging::captured(crate::logging::stdout_filter(None, false));
        let error = record_download(&app, &grant, &[0]).await.unwrap_err();
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        let text = std::fs::read_to_string(log.path()).unwrap();
        let warn = text
            .lines()
            .find(|line| line.contains("record download failed"))
            .expect("the failed store write warns");
        assert!(warn.contains("grant-id"), "{warn}");
    }

    #[test]
    fn skip_notice_logs_first_occurrence_then_paces() {
        let start = std::time::Instant::now();
        let mut notice = SkipNotice::new();
        // The first skipped iteration logs at info.
        assert!(matches!(notice.due(start), SkipLevel::First));
        // Repeats inside the interval stay silent.
        assert!(matches!(
            notice.due(start + Duration::from_secs(1)),
            SkipLevel::Silent
        ));
        assert!(matches!(
            notice.due(start + Duration::from_secs(59)),
            SkipLevel::Silent
        ));
        // After the interval a debug reminder is due, then quiet again.
        assert!(matches!(
            notice.due(start + Duration::from_secs(60)),
            SkipLevel::Repeat
        ));
        assert!(matches!(
            notice.due(start + Duration::from_secs(61)),
            SkipLevel::Silent
        ));
    }

    /// Wraps the router so tests observe the streamed response the file
    /// download admission redirect produces: the one same-origin 307 is
    /// replayed with the same method, headers and peer against its lease
    /// location, exactly what a real download client does.
    fn router(app: std::sync::Arc<App>) -> RedirectFollowing {
        RedirectFollowing { app }
    }

    struct RedirectFollowing {
        app: std::sync::Arc<App>,
    }

    impl tower::Service<Request<Body>> for RedirectFollowing {
        type Response = Response;
        type Error = std::convert::Infallible;
        type Future = std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Response, std::convert::Infallible>> + Send,
            >,
        >;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::convert::Infallible>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<Body>) -> Self::Future {
            let app = self.app.clone();
            Box::pin(async move {
                let (parts, body) = request.into_parts();
                let headers = parts.headers.clone();
                let peer = parts
                    .extensions
                    .get::<ConnectInfo<std::net::SocketAddr>>()
                    .map(|info| info.0);
                let mut response = crate::app::router(app.clone())
                    .oneshot(Request::from_parts(parts, body))
                    .await
                    .unwrap();
                for _ in 0..3 {
                    if response.status() != StatusCode::TEMPORARY_REDIRECT
                        && response.status() != StatusCode::PERMANENT_REDIRECT
                    {
                        break;
                    }
                    let Some(location) = response
                        .headers()
                        .get(axum::http::header::LOCATION)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned)
                    else {
                        break;
                    };
                    let mut replayed = Request::builder()
                        .method(axum::http::Method::GET)
                        .uri(&location);
                    *replayed.headers_mut().unwrap() = headers.clone();
                    if let Some(address) = peer {
                        replayed = replayed.extension(ConnectInfo(address));
                    }
                    let replayed = replayed.body(Body::empty()).unwrap();
                    response = crate::app::router(app.clone())
                        .oneshot(replayed)
                        .await
                        .unwrap();
                }
                Ok(response)
            })
        }
    }

    fn admin_cookie(app: &App) -> String {
        let token = auth::issue_admin_token(
            &app.secret,
            &auth::AdminIdentity::local_admin(),
            &app.config.admin_token_tag,
        );
        format!("votport_admin={token}")
    }

    fn admin_headers(app: &App) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, admin_cookie(app).parse().unwrap());
        headers.insert("x-votport", "1".parse().unwrap());
        headers
    }

    /// Idempotent deletes: a repeat delete of an owned automation token
    /// answers 200 again; only an unknown id 404s.
    #[tokio::test]
    async fn automation_token_deletes_are_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let auth = admin_headers(&app);
        app.store
            .insert_automation_token(AutomationToken {
                id: "tok-id".into(),
                token_hash: hash_token("a".repeat(32).as_str()),
                tenant: String::new(),
                label: "jobs".into(),
                directory: None,
                permissions: vec!["jobs:read".into()],
                created_by: String::new(),
                created_at: now_unix(),
                expires_at: now_unix() + 3600,
                revoked_at: None,
                last_used_at: None,
            })
            .unwrap();
        let first = delete_automation_token(
            State(app.clone()),
            AxumPath("tok-id".to_owned()),
            auth.clone(),
        )
        .await
        .unwrap();
        assert_eq!(first.0, json!({"ok": true}));
        assert_eq!(
            delete_automation_token(
                State(app.clone()),
                AxumPath("tok-id".to_owned()),
                auth.clone()
            )
            .await
            .unwrap()
            .0,
            json!({"ok": true})
        );
        assert_eq!(
            delete_automation_token(State(app.clone()), AxumPath("unknown".to_owned()), auth)
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
    }

    /// Idempotent deletes: a repeat delete of an owned admin outbound grant
    /// answers 200 again; only an unknown id 404s.
    #[tokio::test]
    async fn outbound_grant_deletes_are_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let auth = admin_headers(&app);
        app.store
            .insert_outbound_grant(crate::notify::tests::test_grant(vec![]))
            .unwrap();
        let first = delete_outbound_grant(
            State(app.clone()),
            AxumPath("grant-id".to_owned()),
            auth.clone(),
        )
        .await
        .unwrap();
        assert_eq!(first.0, json!({"ok": true}));
        assert_eq!(
            delete_outbound_grant(
                State(app.clone()),
                AxumPath("grant-id".to_owned()),
                auth.clone(),
            )
            .await
            .unwrap()
            .0,
            json!({"ok": true})
        );
        assert_eq!(
            delete_outbound_grant(State(app.clone()), AxumPath("unknown".to_owned()), auth)
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
    }

    fn named_admin_cookie(app: &App, tenant: &str) -> String {
        let identity = auth::AdminIdentity {
            subject: "local".to_owned(),
            tenant: tenant.to_owned(),
            role: "admin".to_owned(),
            grants: vec![auth::TenantGrant {
                incarnation: None,
                tenant: tenant.to_owned(),
                role: "admin".to_owned(),
            }],
            credential_version: 1,
        };
        let token = auth::issue_admin_token(&app.secret, &identity, &app.config.admin_token_tag);
        format!("votport_admin={token}")
    }

    /// One process-wide stall, so armed tests serialize on `SERIAL` and the
    /// guard disarms on drop; concurrent tests must never see the stall.
    static LIBRARY_MUTATION_STALL_SERIAL: Mutex<()> = Mutex::new(());

    struct ArmedLibraryMutationStall {
        _serial: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for ArmedLibraryMutationStall {
        fn drop(&mut self) {
            LIBRARY_MUTATION_STALL
                .lock()
                .expect("library mutation stall poisoned")
                .take();
        }
    }

    fn arm_library_mutation_stall(
        root: &Path,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        ArmedLibraryMutationStall,
    ) {
        let _serial = LIBRARY_MUTATION_STALL_SERIAL
            .lock()
            .expect("library mutation stall serializer poisoned");
        let (entered_rx, release_tx) = rearm_library_mutation_stall(root);
        (
            entered_rx,
            release_tx,
            ArmedLibraryMutationStall { _serial },
        )
    }

    /// Arms another stall while the caller already holds the serializer
    /// guard, e.g. to pin the validation-to-insert window separately from
    /// the walk-start stall.
    fn rearm_library_mutation_stall(
        root: &Path,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        assert!(LIBRARY_MUTATION_STALL
            .lock()
            .expect("library mutation stall poisoned")
            .replace(LibraryMutationStall {
                root: root.to_owned(),
                entered: entered_tx,
                release: release_rx,
            })
            .is_none());
        (entered_rx, release_tx)
    }

    #[test]
    fn outbound_operation_refusal_is_retryable_during_tenant_purge() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let operation = app.sessions.try_begin_outbound("acme").unwrap();
        let _pin = app.sessions.try_pin_tenant("acme").unwrap();
        let error = match begin_outbound_operation(&app, "acme") {
            Err(error) => error,
            Ok(_) => panic!("tenant purge did not block a second outbound operation"),
        };
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.retry_after_seconds, Some(1));
        assert_eq!(error.code, "unavailable");
        drop(operation);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_library_mutation_keeps_admission_until_worker_finishes() {
        use std::time::{Duration, Instant};

        for deleting in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let app = crate::api::testing::build(directory.path());
            app.store
                .insert_tenant(crate::store::tests::test_tenant("acme"))
                .unwrap();
            let root = library_root(&app, "acme");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join("held.bin"), b"library fixture").unwrap();
            let cookie = named_admin_cookie(&app, "acme");

            let (entered, release, _stall) = arm_library_mutation_stall(&root);
            let (cancel_watchdog, watchdog_wait) = std::sync::mpsc::channel();
            let watchdog_release = release.clone();
            let watchdog = std::thread::spawn(move || {
                if watchdog_wait.recv_timeout(Duration::from_secs(5)).is_err() {
                    let _ = watchdog_release.send(());
                }
            });
            let request = if deleting {
                Request::delete("/api/admin/outbound-files?path=held.bin")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap()
            } else {
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"paths":["held.bin"],"expires_days":1}"#))
                    .unwrap()
            };
            let serving = tokio::spawn(router(app.clone()).oneshot(request));

            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if entered.try_recv().is_ok() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("library mutation worker did not enter its critical section");
            let heartbeat_started = Instant::now();
            let heartbeat = tokio::spawn(async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Instant::now()
            });
            let heartbeat_at = heartbeat.await.unwrap();
            assert!(
                !serving.is_finished(),
                "mutation must still be held by the barrier"
            );
            assert!(
                heartbeat_at.duration_since(heartbeat_started) < Duration::from_secs(1),
                "the runtime stalled in the library mutation critical section"
            );
            serving.abort();
            assert!(matches!(
                serving.await,
                Err(error) if error.is_cancelled()
            ));
            assert_eq!(app.sessions.active_outbound_for_tenant("acme"), 1);

            release.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while app.sessions.active_outbound_for_tenant("acme") != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("cancelled mutation did not release admission after worker completion");
            let _ = cancel_watchdog.send(());
            watchdog.join().unwrap();
            let grants = app.store.outbound_grants("acme").unwrap();
            assert_eq!(grants.len(), usize::from(!deleting));
            assert_eq!(root.join("held.bin").exists(), !deleting);
            let audit = app.store.audit_recent(Some("acme"), 0, 10).unwrap();
            let event = if deleting {
                "outbound_file_deleted"
            } else {
                "outbound_grant_created"
            };
            assert_eq!(audit.iter().filter(|row| row.event == event).count(), 1);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stalled_library_validation_does_not_block_outbound_deletion() {
        use std::time::Duration;

        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_tenant(crate::store::tests::test_tenant("acme"))
            .unwrap();
        let root = library_root(&app, "acme");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("held.bin"), b"library fixture").unwrap();
        let cookie = named_admin_cookie(&app, "acme");

        let (entered, release, _stall) = arm_library_mutation_stall(&root);
        let create = tokio::spawn(
            router(app.clone()).oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"paths":["held.bin"],"expires_days":1}"#))
                    .unwrap(),
            ),
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if entered.try_recv().is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("grant creation never reached its validation walk");
        assert!(!create.is_finished());

        // The stalled walk runs without the mutation lock, so the delete must
        // finish while the walk is still stuck instead of queueing behind it.
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            router(app.clone()).oneshot(
                Request::delete("/api/admin/outbound-files?path=held.bin")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("stalled library validation blocked outbound deletion")
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!root.join("held.bin").exists());

        release.send(()).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), create)
            .await
            .expect("grant creation never finished after its stall was released")
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(app.store.outbound_grants("acme").unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn library_deletion_and_validated_insert_are_strictly_ordered() {
        use std::time::Duration;

        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_tenant(crate::store::tests::test_tenant("acme"))
            .unwrap();
        let root = library_root(&app, "acme");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("held.bin"), b"library fixture").unwrap();
        let cookie = named_admin_cookie(&app, "acme");
        let create_request = || {
            Request::post("/api/admin/outbound-grants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"paths":["held.bin"],"expires_days":1}"#))
                .unwrap()
        };
        let delete_request = || {
            Request::delete("/api/admin/outbound-files?path=held.bin")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap()
        };

        // Delete first: pin a creation inside the validation-to-insert
        // window (validated, not yet inserted), then run the delete through
        // that window. The delete wins, so the insert must revalidate under
        // the lock and refuse instead of landing a grant for a source that
        // no longer exists.
        let (validated, validated_release, _stall) =
            arm_library_mutation_stall(&root.join(".validated"));
        let create = tokio::spawn(router(app.clone()).oneshot(create_request()));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if validated.try_recv().is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("grant creation never reached the validation-to-insert window");
        let (entered, release) = rearm_library_mutation_stall(&root);
        let delete = tokio::spawn(router(app.clone()).oneshot(delete_request()));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if entered.try_recv().is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("deletion never entered its critical section");
        validated_release.send(()).unwrap();
        release.send(()).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), delete)
            .await
            .expect("deletion never finished after its stall was released")
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = tokio::time::timeout(Duration::from_secs(2), create)
            .await
            .expect("grant creation never finished after the delete released the lock")
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(app.store.outbound_grants("acme").unwrap().is_empty());
        assert!(!root.join("held.bin").exists());
        let audit = app.store.audit_recent(Some("acme"), 0, 10).unwrap();
        assert_eq!(
            audit
                .iter()
                .filter(|row| row.event == "outbound_grant_created")
                .count(),
            0
        );

        // Insert first: with the grant landed, the delete must observe the
        // active grant and refuse instead of removing the validated source.
        std::fs::write(root.join("held.bin"), b"library fixture").unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            router(app.clone()).oneshot(create_request()),
        )
        .await
        .expect("grant creation stalled outside the mutation lock")
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            router(app.clone()).oneshot(delete_request()),
        )
        .await
        .expect("deletion stalled")
        .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(app.store.outbound_grants("acme").unwrap().len(), 1);
        assert!(root.join("held.bin").exists());
    }

    async fn body(response: Response) -> serde_json::Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    fn branding_grant(token: &str, password_hash: Option<String>) -> OutboundGrant {
        OutboundGrant {
            id: format!("grant-{token}"),
            token_hash: hash_token(token),
            password_hash,
            tenant: String::new(),
            link_id: String::new(),
            upload_id: String::new(),
            package_root: String::new(),
            name: "file.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: String::new(),
            file_index: 0,
            bytes: 3,
            label: "delivery".to_owned(),
            created_at: 1,
            expires_at: now_unix() + 600,
            revoked_at: None,
            downloads: 0,
            max_downloads: None,

            notifications: None,
            first_download_at: None,
            last_download_at: None,
            files: Vec::new(),
        }
    }

    #[tokio::test]
    async fn receiving_source_check_retains_its_operation_when_cancelled() {
        use std::time::Duration;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_tenant(crate::store::tests::test_tenant("acme"))
            .unwrap();
        let mut grant = branding_grant(&"a".repeat(32), None);
        grant.tenant = "acme".into();
        grant.files.push(OutboundGrantFile {
            source: "received:missing.bin".into(),
            name: "file.bin".into(),
            suite: "blake3".into(),
            root: hex::encode([7; 32]),
            bytes: 3,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        });
        let destinations = app.receiving_destinations().unwrap();
        let grant = Arc::new(grant);
        for oversized in [None, Some(false), Some(true)] {
            let pause = crate::receiving::CheckPause::new(&destinations, 1);
            let worker = app.clone();
            let grant = Arc::clone(&grant);
            let serving = tokio::spawn(async move {
                if let Some(oversized) = oversized {
                    let chunk = BatchChunk {
                        start: 0,
                        end: 1,
                        bytes: 3,
                        oversized,
                    };
                    await_batch_chunk(start_batch_chunk(worker, grant, chunk, None)?)
                        .await
                        .map(|_| ())
                } else {
                    let operation = begin_outbound_operation_owned(&worker, "acme")?;
                    source_info_async(&worker, grant, 0, None, operation, None)
                        .await
                        .map(|_| ())
                }
            });
            tokio::time::timeout(Duration::from_secs(1), async {
                while pause.entered() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(app.receiving.try_lock().is_ok());
            assert_eq!(app.receiving_permits.available_permits(), 8);
            assert_eq!(app.sessions.active_outbound_for_tenant("acme"), 1);
            serving.abort();
            assert!(matches!(serving.await, Err(error) if error.is_cancelled()));
            assert_eq!(app.sessions.active_outbound_for_tenant("acme"), 1);
            pause.release();
            tokio::time::timeout(Duration::from_secs(2), async {
                while app.sessions.active_outbound_for_tenant("acme") != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn metadata_branding_and_logo_hide_behind_the_password() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .set_branding(&crate::store::Branding {
                tenant: String::new(),
                name: "Acme Corp".to_owned(),
                color: "#12ab99".to_owned(),
                logo_ext: "png".to_owned(),
                updated_at: 0,
                ..Default::default()
            })
            .unwrap();
        let logo = crate::paths::branding_logo_path(&app.config.data_dir, "", "png");
        std::fs::create_dir_all(logo.parent().unwrap()).unwrap();
        std::fs::write(&logo, b"\x89PNG\r\n\x1a\npixels").unwrap();
        let gated = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let open = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        app.store
            .insert_outbound_grant(branding_grant(
                gated,
                Some(auth::hash_password("pw").unwrap()),
            ))
            .unwrap();
        app.store
            .insert_outbound_grant(branding_grant(open, None))
            .unwrap();

        // Pre-password metadata reveals nothing, branding included.
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{gated}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body(response).await;
        assert_eq!(json["has_password"], true);
        assert_eq!(json["authorized"], false);
        assert!(json.get("branding").is_none(), "{json}");
        // ... so the logo hides with it.
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{gated}/logo"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // The password cookie unlocks branding and the logo together.
        let response = router(app.clone())
            .oneshot(
                Request::post(format!("/api/s/{gated}/verify"))
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::from(r#"{"password":"pw"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{gated}"))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body(response).await;
        assert_eq!(json["authorized"], true);
        assert_eq!(json["branding"]["name"], "Acme Corp");
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{gated}/logo"))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Without a password, metadata (plain and paged) carries branding
        // and the logo streams.
        for uri in [
            format!("/api/s/{open}"),
            format!("/api/s/{open}?offset=0&limit=10"),
        ] {
            let response = router(app.clone())
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let json = body(response).await;
            assert_eq!(json["branding"]["name"], "Acme Corp", "{uri}");
            assert_eq!(json["branding"]["color"], "#12ab99", "{uri}");
            assert_eq!(json["branding"]["has_logo"], true, "{uri}");
        }
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{open}/logo"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/png"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
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

    fn object_id(bytes: &[u8]) -> ObjectId {
        let mut builder = InMemoryObjectBuilder::new(
            Suite::try_from(1).unwrap(),
            Some(bytes.len() as u64),
            bytes.len() as u64,
        )
        .unwrap();
        builder.update(bytes).unwrap();
        builder.finish().unwrap().object_id().clone()
    }

    #[test]
    fn library_preparation_preserves_identity_and_enforces_source_bounds() {
        let limit = vot_sdk::object::MAX_OBJECT_LENGTH;
        for (length, expected, max, valid) in [
            (0, None, 0, true),
            (1, None, 0, false),
            (1, None, 1, true),
            (1, Some(0), 1, false),
            (1, Some(2), 2, false),
            (1, Some(1), 1, true),
            (limit, Some(limit), limit, true),
            (0, None, limit + 1, false),
        ] {
            assert_eq!(valid_preparation_length(length, expected, max), valid);
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.bin");
        for length in [0, 31, vot_sdk::object::PROOF_LEAF_SIZE as usize + 17] {
            let bytes = vec![7; length];
            std::fs::write(&path, &bytes).unwrap();
            let prepared =
                prepare_library_file(&path, Suite::Blake3Bao64, None, length as u64).unwrap();
            assert_eq!(prepared.object_id(), &object_id(&bytes));
            assert!(prepare_library_file(
                &path,
                Suite::Blake3Bao64,
                None,
                vot_sdk::object::MAX_OBJECT_LENGTH + 1
            )
            .is_err());
            assert!(prepare_library_file(
                &path,
                Suite::Blake3Bao64,
                Some(length as u64 + 1),
                length as u64 + 1
            )
            .is_err());
            if length != 0 {
                assert!(
                    prepare_library_file(&path, Suite::Blake3Bao64, None, length as u64 - 1)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn proof_catalog_round_trip_rejects_tampered_header() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = vec![7u8; 32 * 1024];
        let mut builder = InMemoryObjectBuilder::new(
            Suite::try_from(1).unwrap(),
            Some(bytes.len() as u64),
            bytes.len() as u64,
        )
        .unwrap();
        builder.update(&bytes).unwrap();
        let prepared = builder.finish().unwrap();
        let path = ensure_catalog_from_prepared(directory.path(), &prepared).unwrap();
        let encoded = std::fs::read(&path).unwrap();
        assert!(proof::validate_catalog(&encoded, prepared.object_id()).is_ok());
        let mut tampered = encoded;
        tampered[24] ^= 1;
        std::fs::write(&path, tampered).unwrap();
        assert!(ensure_catalog_from_prepared(directory.path(), &prepared).is_ok());
        let repaired = std::fs::read(path).unwrap();
        assert!(proof::validate_catalog(&repaired, prepared.object_id()).is_ok());
    }

    #[test]
    fn concurrent_cold_catalog_requests_share_one_build() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = vec![9u8; 64 * 1024];
        let source = directory.path().join("source.bin");
        std::fs::write(&source, &bytes).unwrap();
        let expected = object_id(&bytes);
        let root = directory.path().join("proofs");
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| ensure_catalog(&root, &source, &expected).unwrap()))
                .collect();
            for worker in workers {
                let path = worker.join().unwrap();
                let mut file = std::fs::File::open(&path).unwrap();
                assert!(catalog_header(&mut file, &expected).is_ok());
            }
        });
        // Other tests share the static map; only this object's entry matters.
        assert!(!CATALOG_BUILDS
            .lock()
            .unwrap()
            .contains_key(&catalog_path(&root, &expected)));
    }

    #[tokio::test]
    async fn revocation_stops_a_batch_stream_mid_body() {
        let (_directory, mut app, cookie, _first) = fixture().await;
        Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 64 * 1024 * 1024;
        let count = 8usize;
        let part_bytes = 512 * 1024;
        let total = count * part_bytes;
        for index in 0..count {
            let path = format!("cap/part-{index}.bin");
            let response = router(app.clone())
                .oneshot(
                    Request::post(format!("/api/admin/outbound-files?path={path}"))
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .body(Body::from(vec![b'a' + index as u8; part_bytes]))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let paths = (0..count)
            .map(|index| format!("\"cap/part-{index}.bin\""))
            .collect::<Vec<_>>()
            .join(",");
        let created = router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        "{{\"paths\":[{paths}],\"max_downloads\":1}}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let created = body(created).await;
        let token = created["url"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        let id = created["grant"]["id"].as_str().unwrap().to_owned();
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/batch"))
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        12,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body().into_data_stream();
        let first = stream.next().await.unwrap().unwrap();
        assert!(
            first.len() < total,
            "the batch must have frames left to deliver"
        );
        // Paused: the recipient holds the stream open without polling while
        // the grant is revoked through the admin handler.
        let revoke = Request::delete(format!("/api/admin/outbound-grants/{id}"))
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router(app.clone()).oneshot(revoke).await.unwrap().status(),
            StatusCode::OK
        );
        // Resuming must stop at the next frame, not deliver the rest of the
        // body the old admission-only checks let through.
        let mut delivered = first.len();
        while let Some(item) = stream.next().await {
            delivered += item.map(|bytes| bytes.len()).unwrap_or(0);
        }
        assert!(
            delivered < total,
            "a revoked stream must not deliver the whole body ({delivered} of {total})"
        );
        // The grant's last live stream ended, so its cancellation token is
        // gone from the map instead of leaking per streamed grant.
        assert!(app.outbound_stream_cancels.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn interrupted_batch_leaves_unsent_files_downloadable() {
        let (_directory, app, cookie, _first) = fixture().await;
        for (path, bytes) in [
            ("cap/a.bin", b"file a".as_slice()),
            ("cap/b.bin", b"file b"),
        ] {
            let response = router(app.clone())
                .oneshot(
                    Request::post(format!("/api/admin/outbound-files?path={path}"))
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .body(Body::from(bytes.to_vec()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let created = router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"paths":["cap/a.bin","cap/b.bin"],"max_downloads":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let created = body(created).await;
        let token = created["url"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        let peer = |port| ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], port)));

        let head_batch = router(app.clone())
            .oneshot(
                Request::head(format!("/api/s/{token}/batch"))
                    .extension(peer(10))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head_batch.status(), StatusCode::OK);
        drop(head_batch);
        assert!(!app.config.data_dir.join("outbound.stage").exists());
        let grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&token))
            .unwrap()
            .unwrap();
        assert!(grant.files.iter().all(|file| file.downloads == 0));

        let head_bundle = router(app.clone())
            .oneshot(
                Request::head(format!("/api/s/{token}/bundle"))
                    .extension(peer(11))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head_bundle.status(), StatusCode::OK);
        drop(head_bundle);
        assert!(!app.config.data_dir.join("outbound.stage").exists());
        let grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&token))
            .unwrap()
            .unwrap();
        assert!(grant.files.iter().all(|file| file.downloads == 0));

        // A batch response dropped before any body frame is polled records
        // nothing: the old up-front recording burned every file's single
        // download here.
        let aborted = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/batch"))
                    .extension(peer(11))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(aborted.status(), StatusCode::OK);
        drop(aborted);
        let grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&token))
            .unwrap()
            .unwrap();
        assert!(grant.files.iter().all(|file| file.downloads == 0));

        // Full consumption records each file exactly once.
        let batch = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/batch"))
                    .extension(peer(12))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(batch.status(), StatusCode::OK);
        let expected_length = batch.headers()[header::CONTENT_LENGTH]
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let mut stream = batch.into_body().into_data_stream();
        let mut bytes = Vec::with_capacity(expected_length);
        while bytes.len() < expected_length {
            bytes.extend_from_slice(&stream.next().await.unwrap().unwrap());
        }
        drop(stream);
        assert_eq!(bytes.len(), expected_length);
        assert_eq!(bytes, b"file afile b");
        let grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&token))
            .unwrap()
            .unwrap();
        assert!(grant.files.iter().all(|file| file.downloads == 1));

        // The cap is now spent: another batch is refused before any bytes.
        let refused = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/batch"))
                    .extension(peer(13))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::NOT_FOUND);

        for path in ["empty/a.bin", "empty/b.bin"] {
            let response = router(app.clone())
                .oneshot(
                    Request::post(format!("/api/admin/outbound-files?path={path}"))
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let empty_created = router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"paths":["empty/a.bin","empty/b.bin"],"max_downloads":1}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(empty_created.status(), StatusCode::OK);
        let empty_token = body(empty_created).await["url"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        let empty_batch = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{empty_token}/batch"))
                    .extension(peer(14))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(empty_batch.status(), StatusCode::OK);
        assert_eq!(empty_batch.headers()[header::CONTENT_LENGTH], "0");
        drop(empty_batch);
        let empty_grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&empty_token))
            .unwrap()
            .unwrap();
        assert!(empty_grant.files.iter().all(|file| file.downloads == 1));
    }

    #[tokio::test]
    async fn zero_byte_batch_validates_sources_before_counting() {
        let (_directory, app, _cookie, _expected) = fixture().await;
        let empty = object_id(&[]);
        let make_grant = |id: &str, token: &str, source: &str| {
            let mut grant = crate::store::tests::test_outbound_grant(id, "", 0);
            grant.token_hash = hash_token(token);
            grant.expires_at = now_unix() + 600;
            grant.max_downloads = Some(1);
            grant.name = "empty.bin".to_owned();
            grant.suite = "blake3".to_owned();
            grant.root = hex::encode(empty.root);
            grant.bytes = 0;
            grant.files = vec![OutboundGrantFile {
                source: source.to_owned(),
                name: "empty.bin".to_owned(),
                suite: "blake3".to_owned(),
                root: hex::encode(empty.root),
                bytes: 0,
                receipt_b64: String::new(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            }];
            grant
        };
        let missing_token = "a".repeat(32);
        let missing = make_grant("missing-zero", &missing_token, "missing-zero.bin");
        app.store.insert_outbound_grant(missing).unwrap();
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{missing_token}/batch"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            app.store
                .outbound_grant_by_token_hash(&hash_token(&missing_token))
                .unwrap()
                .unwrap()
                .files[0]
                .downloads,
            0
        );

        let tampered_path = app.config.outbound_dir.join("tampered-zero.bin");
        std::fs::write(&tampered_path, b"x").unwrap();
        let tampered_token = "b".repeat(32);
        let tampered = make_grant("tampered-zero", &tampered_token, "tampered-zero.bin");
        app.store.insert_outbound_grant(tampered).unwrap();
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{tampered_token}/batch"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            app.store
                .outbound_grant_by_token_hash(&hash_token(&tampered_token))
                .unwrap()
                .unwrap()
                .files[0]
                .downloads,
            0
        );
    }

    #[tokio::test]
    async fn batch_integrity_failure_reports_the_corrupt_file() {
        let (_directory, app, cookie, _expected) = fixture().await;
        for (path, bytes) in [
            ("batch/first.bin", b"first".as_slice()),
            ("batch/second.bin", b"second".as_slice()),
        ] {
            let response = router(app.clone())
                .oneshot(
                    Request::post(format!("/api/admin/outbound-files?path={path}"))
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .body(Body::from(bytes.to_vec()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let created = router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"paths":["batch/first.bin","batch/second.bin"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let created = body(created).await;
        let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
        let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
        let corrupt_path = app.config.outbound_dir.join("batch/second.bin");
        std::fs::write(&corrupt_path, b"tampered").unwrap();
        let failures_before = OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed);
        let audits_before = app.store.audit_count().unwrap();
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/batch"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed) > failures_before,
            "integrity metric did not increment"
        );
        assert_eq!(app.store.audit_count().unwrap(), audits_before + 1);
        let audit = app
            .store
            .audit_recent(Some(""), 0, 100)
            .unwrap()
            .into_iter()
            .find(|row| row.event == "outbound_integrity_failure" && row.subject == grant_id)
            .expect("integrity audit row");
        assert_eq!(audit.detail["file_index"], 1);
        assert_eq!(audit.detail["component"], "batch");
        assert_eq!(
            audit.detail["path"],
            corrupt_path.to_string_lossy().as_ref()
        );
    }

    #[tokio::test]
    async fn corrupt_received_receipt_reports_file_context() {
        let (_directory, app, cookie, _expected) = fixture().await;
        let created = body(
            router(app.clone())
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
        let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
        let source_path = app.config.receive_dir.join("received.bin");
        std::fs::write(receipt_path(&source_path), b"invalid receipt").unwrap();
        let failures_before = OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed);
        let audits_before = app.store.audit_count().unwrap();
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/files/0"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed) > failures_before,
            "integrity metric did not increment"
        );
        assert_eq!(app.store.audit_count().unwrap(), audits_before + 1);
        let audit = app
            .store
            .audit_recent(Some(""), 0, 100)
            .unwrap()
            .into_iter()
            .find(|row| row.event == "outbound_integrity_failure" && row.subject == grant_id)
            .expect("integrity audit row");
        assert_eq!(audit.detail["file_index"], 0);
        assert_eq!(audit.detail["component"], "file");
        assert_eq!(audit.detail["path"], source_path.to_string_lossy().as_ref());
        assert_eq!(audit.detail["error"], "receipt verification failed");
    }

    #[tokio::test]
    async fn truncated_cached_catalog_source_reports_integrity_failure() {
        let (_directory, app, cookie, expected) = fixture().await;
        let created = body(
            router(app.clone())
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
        let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
        let source_path = app.config.receive_dir.join("received.bin");
        let expected_object = object_id(&expected);
        let catalog = ensure_catalog(
            &app.config.data_dir.join("outbound.proofs"),
            &source_path,
            &expected_object,
        )
        .unwrap();
        assert!(catalog.is_file());
        std::fs::write(&source_path, &expected[..expected.len() - 1]).unwrap();
        let failures_before = OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed);
        let audits_before = app.store.audit_count().unwrap();
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/files/0"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed) > failures_before,
            "integrity metric did not increment"
        );
        assert_eq!(app.store.audit_count().unwrap(), audits_before + 1);
        let audit = app
            .store
            .audit_recent(Some(""), 0, 100)
            .unwrap()
            .into_iter()
            .find(|row| row.event == "outbound_integrity_failure" && row.subject == grant_id)
            .expect("integrity audit row");
        assert_eq!(audit.detail["file_index"], 0);
        assert_eq!(audit.detail["component"], "file");
        assert_eq!(audit.detail["path"], source_path.to_string_lossy().as_ref());
        assert_eq!(audit.detail["error"], "verified outbound proof truncated");
    }

    #[tokio::test]
    async fn an_interrupted_file_download_records_nothing_until_completion() {
        // One recorded download must mean one delivered download (audit
        // finding 490): admission and mid-stream drops burn no quota, and
        // only a whole-object response that finished counts once.
        let (_directory, app, _cookie, _expected) = fixture().await;
        let contents = vec![0xa5u8; 9 * 1024 * 1024];
        std::fs::write(app.config.outbound_dir.join("large.bin"), &contents).unwrap();
        let object = object_id(&contents);
        let token = "d".repeat(32);
        let mut grant = crate::store::tests::test_outbound_grant("file-once", "", 0);
        grant.token_hash = hash_token(&token);
        grant.expires_at = now_unix() + 600;
        grant.max_downloads = Some(1);
        grant.bytes = contents.len() as u64;
        grant.files = vec![OutboundGrantFile {
            source: "large.bin".to_owned(),
            name: "large.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: hex::encode(object.root),
            bytes: contents.len() as u64,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        app.store.insert_outbound_grant(grant).unwrap();

        // Admission redirects and records nothing.
        let admission = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admission.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = admission.headers()[header::LOCATION].to_str().unwrap();
        let lease = location
            .strip_prefix(&format!("/api/s/{token}/file?download_lease="))
            .unwrap_or_else(|| panic!("unexpected redirect location {location}"))
            .to_owned();
        let grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&token))
            .unwrap()
            .unwrap();
        assert_eq!(grant.files[0].downloads, 0);

        // The final URL streams frame by frame; dropping after the first
        // frame leaves the download unrecorded and the quota unspent.
        let first_url = format!("/api/s/{token}/file?download_lease={lease}");
        let aborted = router(app.clone())
            .oneshot(
                Request::get(&first_url)
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(aborted.status(), StatusCode::OK);
        let mut stream = aborted.into_body().into_data_stream();
        let frame = stream.next().await.unwrap().unwrap();
        assert!(!frame.is_empty());
        drop(stream);
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        let grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&token))
            .unwrap()
            .unwrap();
        assert_eq!(grant.files[0].downloads, 0);

        // A fresh request is still admitted, and finishing the delivery
        // records the download exactly once.
        let completed = router(app.clone())
            .oneshot(
                Request::get(&first_url)
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(completed.status(), StatusCode::OK);
        let body = completed.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.len(), contents.len());
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let downloads = app
                    .store
                    .outbound_grant_by_token_hash(&hash_token(&token))
                    .unwrap()
                    .unwrap()
                    .files[0]
                    .downloads;
                if downloads == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the completed download was not recorded");

        // The single download is spent, so a tokenless retry is refused.
        let exhausted = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exhausted.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn batch_defers_trailing_empty_file_until_its_chunk_is_validated() {
        let (_directory, app, _cookie, expected) = fixture().await;
        let expected_object = object_id(&expected);
        let empty_object = object_id(&[]);
        std::fs::write(app.config.outbound_dir.join("source.bin"), &expected).unwrap();
        std::fs::write(app.config.outbound_dir.join("trailing-empty.bin"), b"x").unwrap();
        let token = "c".repeat(32);
        let mut grant = crate::store::tests::test_outbound_grant("mixed-empty", "", 0);
        grant.token_hash = hash_token(&token);
        grant.expires_at = now_unix() + 600;
        grant.max_downloads = Some(1);
        grant.bytes = expected.len() as u64;
        grant.files = (0..64)
            .map(|index| OutboundGrantFile {
                source: "source.bin".to_owned(),
                name: format!("file-{index}.bin"),
                suite: "blake3".to_owned(),
                root: hex::encode(expected_object.root),
                bytes: expected.len() as u64,
                receipt_b64: String::new(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .chain(std::iter::once(OutboundGrantFile {
                source: "trailing-empty.bin".to_owned(),
                name: "trailing-empty.bin".to_owned(),
                suite: "blake3".to_owned(),
                root: hex::encode(empty_object.root),
                bytes: 0,
                receipt_b64: String::new(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            }))
            .collect();
        app.store.insert_outbound_grant(grant).unwrap();
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/batch"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body().into_data_stream();
        assert!(stream.next().await.unwrap().is_err());
        drop(stream);
        let grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&token))
            .unwrap()
            .unwrap();
        assert!(grant.files.iter().all(|file| file.downloads == 0));
        assert_eq!(grant.files[64].downloads, 0);
    }

    #[tokio::test]
    async fn batch_does_not_record_zero_file_before_next_chunk_validation() {
        let (_directory, mut app, _cookie, _expected) = fixture().await;
        Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 64 * 1024 * 1024;
        let large = vec![b'a'; BATCH_LEAD_BYTES as usize / BATCH_LEAD_FILES];
        let large_object = object_id(&large);
        let empty_object = object_id(&[]);
        std::fs::write(app.config.outbound_dir.join("large.bin"), &large).unwrap();
        std::fs::write(app.config.outbound_dir.join("invalid-empty.bin"), b"x").unwrap();
        let token = "e".repeat(32);
        let mut grant = crate::store::tests::test_outbound_grant("mixed-boundary", "", 0);
        grant.token_hash = hash_token(&token);
        grant.expires_at = now_unix() + 600;
        grant.max_downloads = Some(1);
        grant.bytes = large.len() as u64;
        grant.files = (0..BATCH_LEAD_FILES)
            .map(|index| OutboundGrantFile {
                source: "large.bin".to_owned(),
                name: format!("large-{index}.bin"),
                suite: "blake3".to_owned(),
                root: hex::encode(large_object.root),
                bytes: large.len() as u64,
                receipt_b64: String::new(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .chain([
                OutboundGrantFile {
                    source: "invalid-empty.bin".to_owned(),
                    name: "invalid-empty.bin".to_owned(),
                    suite: "blake3".to_owned(),
                    root: hex::encode(empty_object.root),
                    bytes: 0,
                    receipt_b64: String::new(),
                    downloads: 0,
                    first_download_at: None,
                    last_download_at: None,
                },
                OutboundGrantFile {
                    source: "large.bin".to_owned(),
                    name: "after-empty.bin".to_owned(),
                    suite: "blake3".to_owned(),
                    root: hex::encode(large_object.root),
                    bytes: large.len() as u64,
                    receipt_b64: String::new(),
                    downloads: 0,
                    first_download_at: None,
                    last_download_at: None,
                },
            ])
            .collect();
        app.store.insert_outbound_grant(grant).unwrap();
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/batch"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 4))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body().into_data_stream();
        let mut saw_error = false;
        while let Some(item) = stream.next().await {
            if item.is_err() {
                saw_error = true;
                break;
            }
        }
        assert!(saw_error);
        drop(stream);
        let grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&token))
            .unwrap()
            .unwrap();
        assert!(grant.files[..BATCH_LEAD_FILES]
            .iter()
            .all(|file| file.downloads == 1));
        assert_eq!(grant.files[BATCH_LEAD_FILES].downloads, 0);
        assert_eq!(grant.files[BATCH_LEAD_FILES + 1].downloads, 0);
    }

    #[tokio::test]
    async fn interrupted_bundle_issues_logical_lease_for_file_recovery() {
        let (_directory, app, _cookie, expected) = fixture().await;
        let object = object_id(&expected);
        std::fs::write(app.config.outbound_dir.join("source.bin"), &expected).unwrap();
        let token = "d".repeat(32);
        let mut grant = crate::store::tests::test_outbound_grant("bundle-resume", "", 0);
        grant.token_hash = hash_token(&token);
        grant.expires_at = now_unix() + 600;
        grant.max_downloads = Some(1);
        grant.bytes = expected.len() as u64;
        grant.files = ["one.bin", "two.bin"]
            .into_iter()
            .map(|name| OutboundGrantFile {
                source: "source.bin".to_owned(),
                name: name.to_owned(),
                suite: "blake3".to_owned(),
                root: hex::encode(object.root),
                bytes: expected.len() as u64,
                receipt_b64: String::new(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .collect();
        app.store.insert_outbound_grant(grant).unwrap();
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/bundle"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 1);
        let cookie = cookies[0].split(';').next().unwrap();
        drop(response);
        let grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&token))
            .unwrap()
            .unwrap();
        assert!(grant.files.iter().all(|file| file.downloads == 1));
        let refused = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/files/0"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 6))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::NOT_FOUND);
        for index in 0..2 {
            let response = router(app.clone())
                .oneshot(
                    Request::get(format!("/api/s/{token}/files/{index}"))
                        .header(header::COOKIE, cookie)
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            7 + index as u16,
                        ))))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                expected
            );
        }
    }

    /// Mid-stream recording (a flush inside the window) and the end flush
    /// count each file once and the grant once, the same as per-file
    /// recording did.
    #[tokio::test]
    async fn batch_over_the_window_records_each_file_once() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.max_upload_bytes = 64 * 1024 * 1024;
        let app = crate::app::build(config).unwrap();
        let cookie = admin_cookie(&app);
        let mib = 1024 * 1024;
        // 9 + 9 MiB crosses the 16 MiB window after the second file, so the
        // third is recorded by the end-of-stream flush in a second call.
        for (path, size) in [
            ("win/a.bin", 9 * mib),
            ("win/b.bin", 9 * mib),
            ("win/c.bin", 1),
        ] {
            let bytes: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
            let response = router(app.clone())
                .oneshot(
                    Request::post(format!("/api/admin/outbound-files?path={path}"))
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .body(Body::from(bytes))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let created = router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"paths":["win/a.bin","win/b.bin","win/c.bin"],"max_downloads":2}"#,
                    ))
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
        let batch = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/batch"))
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        21,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(batch.status(), StatusCode::OK);
        let bytes = batch.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), 18 * mib + 1);
        let grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&token))
            .unwrap()
            .unwrap();
        assert_eq!(
            grant
                .files
                .iter()
                .map(|file| file.downloads)
                .collect::<Vec<_>>(),
            vec![1, 1, 1]
        );
        assert_eq!(grant.downloads, 1);
        // Every staging permit is returned once the stream has drained.
        assert_eq!(
            app.staging_permits.available_permits(),
            STAGING_CONCURRENCY,
            "a staging permit leaked"
        );
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
                &vot_platform_fs::FileLocation::from_path(&source).unwrap(),
                &object,
                [1; 16],
                PublishObservation {
                    incarnation: [2; 16],
                    sequence: 1,
                },
                vot_sdk_file::CommitProfile::Balanced,
            )
            .unwrap();
        app.store
            .insert_link(crate::store::Link {
                retention_days: None,
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

                notifications: None,
                uploads: vec![crate::store::UploadRecord {
                    partial: false,
                    log: Vec::new(),
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

    #[tokio::test]
    async fn payload_gets_write_one_audit_row_per_request() {
        let (_directory, app, cookie, first) = fixture().await;
        for (path, bytes) in [
            ("audit/one.bin", first.as_slice()),
            ("audit/two.bin", b"second file".as_slice()),
        ] {
            let response = router(app.clone())
                .oneshot(
                    Request::post(format!("/api/admin/outbound-files?path={path}"))
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .body(Body::from(bytes.to_vec()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let created = router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"paths":["audit/one.bin","audit/two.bin"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let created = body(created).await;
        let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
        let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
        let audit_rows = || {
            app.store
                .audit_export(None, 0, 0, 100)
                .unwrap()
                .into_iter()
                .filter(|row| row.event == "outbound_downloaded" && row.subject == grant_id)
                .collect::<Vec<_>>()
        };

        // Metadata, HEAD and receipts do not represent a payload request.
        let metadata = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metadata.status(), StatusCode::OK);
        let head = router(app.clone())
            .oneshot(
                Request::head(format!("/api/s/{token}/files/0"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        let receipt = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/receipts/0"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt.status(), StatusCode::NOT_FOUND);
        for (path, port) in [("batch", 6), ("bundle", 7)] {
            let head = router(app.clone())
                .oneshot(
                    Request::head(format!("/api/s/{token}/{path}"))
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            port,
                        ))))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(head.status(), StatusCode::OK, "{path}");
            head.into_body().collect().await.unwrap();
        }
        assert!(audit_rows().is_empty());

        // The tokenless GET is admitted with a same-origin redirect that
        // writes its own row; the redirected request streams and writes
        // the payload row. No lease cookie is set anywhere.
        let admission = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/files/0"))
                    .header("x-forwarded-for", "198.51.100.7")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admission.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(admission.headers().get(header::SET_COOKIE).is_none());
        let location = admission.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned();
        let lease = location
            .strip_prefix(&format!("/api/s/{token}/files/0?download_lease="))
            .unwrap_or_else(|| panic!("unexpected redirect location {location}"))
            .to_owned();
        let final_url = format!("/api/s/{token}/files/0?download_lease={lease}");
        let file = router(app.clone())
            .oneshot(
                Request::get(&final_url)
                    .header("x-forwarded-for", "198.51.100.7")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(file.status(), StatusCode::OK);
        assert_eq!(file.into_body().collect().await.unwrap().to_bytes(), first);

        let range = router(app.clone())
            .oneshot(
                Request::get(&final_url)
                    .header(header::RANGE, "bytes=0-1")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            range.into_body().collect().await.unwrap().to_bytes(),
            &first[..2]
        );

        let batch = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/batch"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(batch.status(), StatusCode::OK);
        assert_eq!(
            batch.into_body().collect().await.unwrap().to_bytes(),
            [first.clone(), b"second file".to_vec()].concat()
        );

        let bundle = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/bundle"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 4))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bundle.status(), StatusCode::OK);
        bundle.into_body().collect().await.unwrap();

        // A source failure happens before the request-start boundary.
        std::fs::write(app.config.outbound_dir.join("audit/two.bin"), b"tampered").unwrap();
        let failed = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/files/1"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(failed.status(), StatusCode::NOT_FOUND);

        let rows = audit_rows();
        assert_eq!(rows.len(), 5);
        let mut modes = rows
            .iter()
            .map(|row| row.detail["mode"].as_str().unwrap())
            .collect::<Vec<_>>();
        modes.sort_unstable();
        assert_eq!(modes, ["batch", "bundle", "file", "file", "file"]);
        assert!(rows.iter().all(|row| {
            row.actor.is_empty() && row.tenant.is_empty() && row.detail.get("token").is_none()
        }));
        let file_rows = rows
            .iter()
            .filter(|row| row.detail["mode"] == "file")
            .collect::<Vec<_>>();
        assert_eq!(file_rows.len(), 3);
        assert!(file_rows.iter().all(|row| row.detail["file_index"] == 0));
        assert!(file_rows
            .iter()
            .any(|row| row.detail["client_ip"] == "198.51.100.7"));
        assert!(rows
            .iter()
            .filter(|row| row.detail["mode"] != "file")
            .all(|row| row.detail.get("file_index").is_none()));
    }

    #[test]
    fn tokens_are_strict() {
        assert!(valid_token(&"a".repeat(32)));
        assert!(!valid_token("x"));
        assert!(!valid_token(&"g".repeat(32)));
    }

    #[test]
    fn record_range_coalesces_delivered_files() {
        let mib = 1024 * 1024;
        // Forty 1 MiB files.
        let boundaries: Vec<u64> = (1..=40).map(|index| index * mib).collect();
        // Nothing delivered yet, and a partial first file, record nothing.
        assert_eq!(record_range(&boundaries, 0, 0, false), None);
        assert_eq!(record_range(&boundaries, 0, mib - 1, false), None);
        // Under the window: wait, unless the stream is ending.
        assert_eq!(record_range(&boundaries, 0, 15 * mib, false), None);
        assert_eq!(record_range(&boundaries, 0, 15 * mib, true), Some(0..15));
        // At the window: record exactly the covered files.
        assert_eq!(
            record_range(&boundaries, 0, 16 * mib + 7, false),
            Some(0..16)
        );
        // The window is measured from the last recorded boundary.
        assert_eq!(record_range(&boundaries, 16, 31 * mib, false), None);
        assert_eq!(record_range(&boundaries, 16, 32 * mib, false), Some(16..32));
        // Everything recorded: a flush has nothing to do.
        assert_eq!(record_range(&boundaries, 40, 40 * mib, true), None);
    }

    #[test]
    fn batch_chunks_bound_file_count_bytes_and_oversized_files() {
        let file = |bytes| OutboundGrantFile {
            source: String::new(),
            name: String::new(),
            suite: "blake3".to_owned(),
            root: String::new(),
            bytes,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        };
        let mut grant = OutboundGrant {
            id: String::new(),
            token_hash: String::new(),
            password_hash: None,
            tenant: String::new(),
            link_id: String::new(),
            upload_id: String::new(),
            package_root: String::new(),
            name: String::new(),
            suite: String::new(),
            root: String::new(),
            file_index: 0,
            bytes: 0,
            label: String::new(),
            created_at: 0,
            expires_at: 0,
            revoked_at: None,
            downloads: 0,
            max_downloads: None,

            notifications: None,
            first_download_at: None,
            last_download_at: None,
            files: (0..5_001).map(|_| file(1)).collect(),
        };
        // File counts ramp from the lead size, doubling per chunk.
        let chunks = batch_chunks(&grant, grant.files.len());
        let spans: Vec<(usize, usize)> = chunks.iter().map(|c| (c.start, c.end)).collect();
        assert_eq!(
            spans,
            [
                (0, 64),
                (64, 192),
                (192, 448),
                (448, 960),
                (960, 1_984),
                (1_984, 4_032),
                (4_032, 5_001),
            ]
        );
        assert!(chunks.iter().all(|c| !c.oversized));
        assert_eq!(chunks[6].bytes, 969);

        // Byte caps ramp the same way and never exceed BATCH_CHUNK_BYTES.
        grant.files = (0..12).map(|_| file(64 * 1024 * 1024)).collect();
        let chunks = batch_chunks(&grant, grant.files.len());
        let spans: Vec<(usize, usize)> = chunks.iter().map(|c| (c.start, c.end)).collect();
        assert_eq!(spans, [(0, 1), (1, 2), (2, 3), (3, 5), (5, 9), (9, 12)]);
        assert!(chunks.iter().all(|c| c.bytes <= BATCH_CHUNK_BYTES));

        grant.files = vec![file(BATCH_STAGE_BYTES), file(1)];
        let chunks = batch_chunks(&grant, grant.files.len());
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].oversized);
        assert!(!chunks[1].oversized);
        assert_eq!((chunks[0].bytes, chunks[1].bytes), (BATCH_STAGE_BYTES, 1));

        grant.files = vec![file(BATCH_STAGE_BYTES + 1), file(1)];
        let chunks = batch_chunks(&grant, grant.files.len());
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].oversized);
        assert_eq!(
            (chunks[0].start, chunks[0].end, chunks[0].bytes),
            (0, 1, BATCH_STAGE_BYTES + 1)
        );
        assert!(!chunks[1].oversized);
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

    #[test]
    fn outbound_metadata_paging_defaults_and_rejects_invalid_bounds() {
        assert_eq!(
            outbound_metadata_paging(OutboundMetadataQuery {
                limit: None,
                offset: None,
            })
            .unwrap(),
            None
        );
        assert_eq!(
            outbound_metadata_paging(OutboundMetadataQuery {
                limit: None,
                offset: Some("4".to_owned()),
            })
            .unwrap(),
            Some((4, 100))
        );
        for limit in ["0", "501", "nope"] {
            assert_eq!(
                outbound_metadata_paging(OutboundMetadataQuery {
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
                outbound_metadata_paging(OutboundMetadataQuery {
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

                    notifications: None,
                    first_download_at: None,
                    last_download_at: None,
                    files: Vec::new(),
                })
                .unwrap();
        }

        let response = router(app.clone())
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

        let response = router(app.clone())
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

            notifications: None,
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
        let response = router(app.clone())
            .oneshot(request("delete.bin"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(path.exists());

        app.store
            .revoke_outbound_grant("", "active", now_unix())
            .unwrap();
        let response = router(app).oneshot(request("delete.bin")).await.unwrap();
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
        for (name, fallback, encoded) in [
            ("../a/b?.txt", "b_.txt", "b%3F.txt"),
            ("a\\file.txt", "file.txt", "file.txt"),
            ("a-z_1~. txt", "a-z_1_. txt", "a-z_1~.%20txt"),
            ("x\";\r\n*.txt", "x_____.txt", "x%22%3B%0D%0A%2A.txt"),
            ("100% prêt.txt", "100_ pr_t.txt", "100%25%20pr%C3%AAt.txt"),
            ("", "download.bin", "download.bin"),
            (".", "download.bin", "download.bin"),
            ("..", "download.bin", "download.bin"),
        ] {
            assert_eq!(
                attachment_filename(name).unwrap(),
                format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
            );
        }
        let name = format!("{}.mov.vot-receipt", "a".repeat(239));
        let header = attachment_filename(&name).unwrap();
        assert!(header
            .to_str()
            .unwrap()
            .starts_with(&format!("attachment; filename=\"{name}\";")));
        assert!(header
            .to_str()
            .unwrap()
            .ends_with(&format!("filename*=UTF-8''{name}")));
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
    }
    #[test]
    fn drop_guards_remove_stage_and_active_grant() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let stage = directory.path().join("stage").join("file");
        std::fs::create_dir_all(stage.parent().unwrap()).unwrap();
        std::fs::write(&stage, b"payload").unwrap();
        let budget = Arc::new(StageBudget::new());
        let reservation = budget
            .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 1, 1)
            .unwrap();
        assert!(budget
            .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 1, 1)
            .is_err());
        let staged = StagedFile {
            path: stage.clone(),
            reservation: Some(reservation),
        };
        let active = ActiveDownload::claim(Arc::clone(&app), "grant").unwrap();
        drop((staged, active));
        assert!(!stage.exists());
        assert!(!app.outbound_active.lock().unwrap().contains("grant"));
        assert!(budget
            .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 1, 1)
            .is_ok());
    }

    #[test]
    fn build_bundle_verifies_sources_and_keeps_archive_readable() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let first_path = directory.path().join("first");
        let second_path = directory.path().join("second");
        let first_bytes = b"first payload";
        let second_bytes = b"second payload";
        std::fs::write(&first_path, first_bytes).unwrap();
        std::fs::write(&second_path, second_bytes).unwrap();
        let first_object = object_id(first_bytes);
        let second_object = object_id(second_bytes);
        let first_receipt = app
            .signer
            .encode(
                &first_object,
                [1; 16],
                PublishObservation {
                    incarnation: [2; 16],
                    sequence: 1,
                },
                vot_sdk_file::CommitProfile::Balanced,
                vot_sdk_file::NasContract::Unqualified,
            )
            .unwrap();
        let second_receipt = app
            .signer
            .encode(
                &second_object,
                [3; 16],
                PublishObservation {
                    incarnation: [4; 16],
                    sequence: 2,
                },
                vot_sdk_file::CommitProfile::Balanced,
                vot_sdk_file::NasContract::Unqualified,
            )
            .unwrap();

        let grant = branding_grant("bundle-test", None);
        let archive = build_bundle(
            &app,
            &grant,
            vec![
                (
                    Source {
                        path: first_path,
                        object: first_object,
                        name: "first.txt".to_owned(),
                        receipt: Some(first_receipt),
                    },
                    "first.txt".to_owned(),
                ),
                (
                    Source {
                        path: second_path,
                        object: second_object,
                        name: "second.txt".to_owned(),
                        receipt: Some(second_receipt),
                    },
                    "second.txt".to_owned(),
                ),
            ],
        )
        .unwrap();

        let entries = zip_entries(&std::fs::read(&archive.path).unwrap());
        assert_eq!(entries["first.txt"], b"first payload");
        assert_eq!(entries["second.txt"], b"second payload");
        drop(archive);
    }

    #[test]
    fn build_bundle_rejects_ambiguous_names_before_staging() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let grant = branding_grant("bundle-test", None);
        for names in [
            ["Café.mov", "Cafe\u{301}.mov"],
            ["folder", "FOLDER/clip.mov"],
        ] {
            let files = names
                .into_iter()
                .map(|name| {
                    (
                        Source {
                            path: directory.path().join(name),
                            object: ObjectId {
                                suite: 1,
                                root: [0; 32],
                                length: 1,
                            },
                            name: name.into(),
                            receipt: None,
                        },
                        bundle_path(name).unwrap(),
                    )
                })
                .collect();
            let error = build_bundle(&app, &grant, files).err().unwrap();
            assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
            assert!(error.message.contains("collide"));
            assert!(!app.config.data_dir.join("outbound.stage").exists());
        }
    }

    #[test]
    fn build_bundle_rejects_source_mismatch_without_archive() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let grant = branding_grant("integrity-test", None);
        let source_path = directory.path().join("source");
        let source_for_assert = source_path.clone();
        std::fs::write(&source_path, b"actual payload").unwrap();
        let expected = object_id(b"expected payload");
        let failures_before = OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed);
        let audits_before = app.store.audit_count().unwrap();

        assert!(build_bundle(
            &app,
            &grant,
            vec![(
                Source {
                    path: source_path,
                    object: expected,
                    name: "source.txt".to_owned(),
                    receipt: Some(Vec::new()),
                },
                "source.txt".to_owned(),
            )],
        )
        .is_err());
        assert!(
            OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed) > failures_before,
            "integrity metric did not increment"
        );
        assert_eq!(app.store.audit_count().unwrap(), audits_before + 1);
        let audit = app
            .store
            .audit_recent(Some(&grant.tenant), 0, 10)
            .unwrap()
            .into_iter()
            .find(|row| row.event == "outbound_integrity_failure")
            .expect("integrity audit row");
        assert_eq!(audit.subject, grant.id);
        assert_eq!(audit.detail["file_index"], 0);
        assert_eq!(audit.detail["component"], "bundle");
        assert_eq!(
            audit.detail["path"],
            source_for_assert.to_string_lossy().as_ref()
        );
        assert!(app
            .config
            .data_dir
            .join("outbound.stage")
            .read_dir()
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn bundle_error_mapping_keeps_io_failures_internal() {
        assert_eq!(
            map_bundle_error(io::Error::new(io::ErrorKind::InvalidData, "mismatch")).status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            map_bundle_error(io::Error::other("disk full")).status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            map_bundle_error(io::Error::new(io::ErrorKind::NotFound, "gone")).status,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn archive_size_bound_checks_payload_and_zip_overhead() {
        let source = Source {
            path: PathBuf::new(),
            object: ObjectId {
                suite: 1,
                root: [0; 32],
                length: 10,
            },
            name: "unused".to_owned(),
            receipt: None,
        };
        let files = vec![(source, "project/file.exr".to_owned())];
        assert_eq!(
            archive_size_bound(&files),
            Some(10 + 30 + 46 + 64 + 2 * "project/file.exr".len() as u64 + 98)
        );
        assert!(archive_size_bound(&[(
            Source {
                path: PathBuf::new(),
                object: ObjectId {
                    suite: 1,
                    root: [0; 32],
                    length: u64::MAX,
                },
                name: "unused".to_owned(),
                receipt: None,
            },
            "file".to_owned(),
        )])
        .is_none());
    }

    #[test]
    fn stage_budget_reserves_concurrently_and_resets_after_last_drop() {
        let budget = Arc::new(StageBudget::new());
        let first = budget
            .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 10, 10)
            .unwrap();
        assert!(matches!(
            budget.reserve_with_free_space(MIN_STAGE_FREE_BYTES + 10, 1),
            Err(StageReserveError::Insufficient)
        ));
        drop(first);
        let second = budget
            .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 20, 20)
            .unwrap();
        drop(second);
        assert!(budget
            .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 1, 1)
            .is_ok());
    }

    #[test]
    fn stage_capacity_errors_are_507() {
        assert_eq!(
            stage_capacity_error().status,
            StatusCode::INSUFFICIENT_STORAGE
        );
        assert_eq!(
            map_stage_reserve_error(StageReserveError::Overflow).status,
            StatusCode::INSUFFICIENT_STORAGE
        );
    }

    #[test]
    fn active_downloads_allow_sixteen_distinct_files_per_grant() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let active: Vec<_> = (0..MAX_ACTIVE_PER_GRANT)
            .map(|index| ActiveDownload::claim(Arc::clone(&app), &format!("grant:{index}")))
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(ActiveDownload::claim(Arc::clone(&app), "grant:16").is_err());
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
    async fn download_headers_preserve_unicode_file_and_receipt_names() {
        let (_directory, app, cookie, _) = fixture().await;
        app.store
            .with(|connection| {
                connection.execute(
                    "UPDATE files SET path=?1 WHERE link_id='link' AND file_index=0",
                    ["folder/納品 café.mov"],
                )
            })
            .unwrap();
        let response = router(app.clone())
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
        assert_eq!(response.status(), StatusCode::OK);
        let created = body(response).await;
        let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
        for (path, extension) in [
            ("file", ""),
            ("files/0", ""),
            ("receipt", ".vot-receipt"),
            ("receipts/0", ".vot-receipt"),
        ] {
            for method in [axum::http::Method::GET, axum::http::Method::HEAD] {
                let response = router(app.clone())
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(format!("/api/s/{token}/{path}"))
                            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK, "{path}");
                assert_eq!(
                    response.headers()[header::CONTENT_DISPOSITION],
                    format!("attachment; filename=\"__ caf_.mov{extension}\"; filename*=UTF-8''%E7%B4%8D%E5%93%81%20caf%C3%A9.mov{extension}"),
                    "{path}"
                );
                response.into_body().collect().await.unwrap();
            }
        }
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
        let response = router(app.clone()).oneshot(create).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let created = body(response).await;
        assert_eq!(created["grant"]["file_index"], 0);
        assert!(created["grant"].get("token_hash").is_none());
        let url = created["url"].as_str().unwrap();
        let token = url.rsplit('/').next().unwrap();
        assert_eq!(url, format!("https://drop.example.com/s/{token}"));
        let id = created["grant"]["id"].as_str().unwrap().to_owned();
        for _ in 0..2 {
            let response = router(app.clone())
                .oneshot(
                    Request::get(format!("/api/admin/outbound-grants/{id}/url"))
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(body(response).await["url"], url);
        }
        let refused = router(app.clone())
            .oneshot(
                Request::get(format!("/api/admin/outbound-grants/{id}/url"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        let listing = router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!body(listing).await.to_string().contains(token));

        let metadata = router(app.clone())
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

        let paged = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}?limit=1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(paged.status(), StatusCode::OK);
        let paged = body(paged).await;
        assert_eq!(paged["files_total"], 1);
        assert_eq!(paged["offset"], 0);
        assert_eq!(paged["limit"], 1);
        assert_eq!(paged["has_more"], false);
        assert_eq!(paged["files"].as_array().unwrap().len(), 1);
        assert_eq!(
            paged["files"][0]["download_url"],
            format!("/api/s/{token}/files/0")
        );

        let receipt = router(app.clone())
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

        let file = router(app.clone())
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
        let catalog = app.config.data_dir.join("outbound.proofs").join(format!(
            "1-{}-{}.vot-catalog",
            metadata["root"].as_str().unwrap(),
            expected_bytes.len()
        ));
        assert!(catalog.is_file());
        let catalog_bytes = std::fs::read(&catalog).unwrap();
        assert!(!app.config.data_dir.join("outbound.stage").exists());
        let second = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(
            second.into_body().collect().await.unwrap().to_bytes(),
            expected_bytes
        );
        assert_eq!(std::fs::read(catalog).unwrap(), catalog_bytes);
        std::fs::write(
            app.config.receive_dir.join("received.bin"),
            b"tampered fixture",
        )
        .unwrap();
        let tampered = router(app.clone())
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

        let conflict = router(app.clone())
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
            router(app.clone()).oneshot(revoke).await.unwrap().status(),
            StatusCode::OK
        );
        let refused = router(app.clone())
            .oneshot(
                Request::get(format!("/api/admin/outbound-grants/{id}/url"))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::NOT_FOUND);
        for suffix in ["", "/receipt", "/file"] {
            let mut request = Request::get(format!("/api/s/{token}{suffix}"));
            if suffix == "/file" {
                request =
                    request.extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))));
            }
            assert_eq!(
                router(app.clone())
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
            router(app.clone())
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
        let head = router(app.clone())
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
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(first.headers().get(header::SET_COOKIE).is_none());
        assert_eq!(first.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(first.headers()[header::REFERRER_POLICY], "no-referrer");
        let location = first.headers()[header::LOCATION].to_str().unwrap();
        let lease = location
            .strip_prefix(&format!("/api/s/{token}/file?download_lease="))
            .unwrap_or_else(|| panic!("unexpected redirect location {location}"));
        assert!(
            !lease.is_empty()
                && lease
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'.'),
            "lease {lease} is not an issued token"
        );
        // Admission does not record: an aborted delivery must burn no quota
        // (audit finding 490).
        let grant = app
            .store
            .outbound_grant_by_id(created["grant"]["id"].as_str().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(grant.downloads, 0);

        // The redirected request streams the range and hands out no lease
        // cookie. A partial range response records nothing (audit finding
        // 490): only a whole-object delivery counts, so resumes stay free.
        let final_url = format!("/api/s/{token}/file?download_lease={lease}");
        let second = router(app.clone())
            .oneshot(
                Request::get(&final_url)
                    .header(header::RANGE, "bytes=0-6")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(second.headers()[header::CONTENT_RANGE], "bytes 0-6/16");
        assert_eq!(second.headers()[header::CONTENT_LENGTH], "7");
        assert_eq!(second.headers()[header::ACCEPT_RANGES], "bytes");
        assert!(second.headers().get(header::SET_COOKIE).is_none());
        let etag = second.headers()[header::ETAG].to_str().unwrap().to_owned();
        assert_eq!(
            second.into_body().collect().await.unwrap().to_bytes(),
            &expected_bytes[..7]
        );

        // A Range resume on the final URL neither redirects nor counts.
        let resume = router(app.clone())
            .oneshot(
                Request::get(&final_url)
                    .header(header::RANGE, "bytes=7-")
                    .header(header::IF_RANGE, etag)
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resume.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(resume.headers()[header::CONTENT_RANGE], "bytes 7-15/16");
        assert_eq!(
            resume.into_body().collect().await.unwrap().to_bytes(),
            &expected_bytes[7..]
        );
        let grant = app
            .store
            .outbound_grant_by_id(created["grant"]["id"].as_str().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(grant.downloads, 0);

        // The abandoned ranges spent nothing, so a tokenless retry is
        // admitted again instead of refused. The plain router (no redirect
        // replay) observes the admission alone.
        let retry = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = retry.headers()[header::LOCATION].to_str().unwrap();
        let fresh = location
            .strip_prefix(&format!("/api/s/{token}/file?download_lease="))
            .unwrap_or_else(|| panic!("unexpected redirect location {location}"))
            .to_owned();

        // A full delivery records once, after its last frame is handed to
        // the transport (audit finding 490).
        let full = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file?download_lease={fresh}"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(full.status(), StatusCode::OK);
        assert_eq!(
            full.headers()[header::CONTENT_LENGTH],
            expected_bytes.len().to_string()
        );
        assert_eq!(
            full.into_body().collect().await.unwrap().to_bytes(),
            &expected_bytes[..]
        );
        let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let downloads = app
                    .store
                    .outbound_grant_by_id(&grant_id)
                    .unwrap()
                    .unwrap()
                    .downloads;
                if downloads == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the completed download was not recorded");

        // The single download is spent, so a tokenless retry is refused.
        let exhausted = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .header(header::RANGE, "bytes=7-15")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exhausted.status(), StatusCode::NOT_FOUND);

        // A forged lease and a lease minted for another index both count as
        // absent and land on the same refusal.
        let grant = app
            .store
            .outbound_grant_by_id(created["grant"]["id"].as_str().unwrap())
            .unwrap()
            .unwrap();
        let wrong_index =
            auth::issue_download_lease(&app.secret, &grant.id, &grant.token_hash, 1, 60);
        for absent in ["forged.deadbeef.deadbeef".to_owned(), wrong_index] {
            let refused = router(app.clone())
                .oneshot(
                    Request::get(format!("/api/s/{token}/file?download_lease={absent}"))
                        .header(header::RANGE, "bytes=7-15")
                        .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(refused.status(), StatusCode::NOT_FOUND, "{absent}");
        }

        let id = created["grant"]["id"].as_str().unwrap();
        let rotated = router(app.clone())
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
        let old_lease_after_rotation = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file?download_lease={lease}"))
                    .header(header::RANGE, "bytes=7-15")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(old_lease_after_rotation.status(), StatusCode::NOT_FOUND);

        let created = body(
            router(app.clone())
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
        let admission = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{revoke_token}/file"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admission.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(admission.headers().get(header::SET_COOKIE).is_none());
        let location = admission.headers()[header::LOCATION].to_str().unwrap();
        let revoke_lease = location
            .strip_prefix(&format!("/api/s/{revoke_token}/file?download_lease="))
            .unwrap_or_else(|| panic!("unexpected redirect location {location}"))
            .to_owned();
        let revoke_id = created["grant"]["id"].as_str().unwrap();
        let revoke = router(app.clone())
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
        let old_lease_after_revoke = router(app.clone())
            .oneshot(
                Request::get(format!(
                    "/api/s/{revoke_token}/file?download_lease={revoke_lease}"
                ))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
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
            router(app.clone())
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
            let response = router(app.clone())
                .oneshot(
                    Request::get(format!("/api/s/{token}/file"))
                        .header(header::RANGE, value)
                        .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
            assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes */16");
        }
        let mut multiple = Request::get(format!("/api/s/{token}/file"))
            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
            .body(Body::empty())
            .unwrap();
        multiple
            .headers_mut()
            .append(header::RANGE, HeaderValue::from_static("bytes=0-1"));
        multiple
            .headers_mut()
            .append(header::RANGE, HeaderValue::from_static("bytes=2-3"));
        let multiple = router(app.clone()).oneshot(multiple).await.unwrap();
        assert_eq!(multiple.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(multiple.headers()[header::CONTENT_RANGE], "bytes */16");
        let full = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .header(header::RANGE, "bytes=0-1")
                    .header(header::IF_RANGE, "\"wrong\"")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
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
        let response = router(app.clone())
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
        let invalid = router(app.clone())
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

        let rotated = router(app.clone())
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
            router(app.clone())
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
        let extended = router(app.clone())
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
        let response = router(app.clone())
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
        let first = router(app.clone())
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
        // The record lands after the body's last frame is handed off, on a
        // spawned task; a second admission must observe it (finding 490).
        let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let downloads = app
                    .store
                    .outbound_grant_by_id(&grant_id)
                    .unwrap()
                    .unwrap()
                    .downloads;
                if downloads == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the completed download was not recorded");
        let second = router(app)
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
    async fn password_grant_gates_metadata_file_receipt_and_evidence() {
        let (_directory, app, cookie, expected_bytes) = fixture().await;
        let response = router(app.clone())
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
        let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
        let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();

        let metadata = router(app.clone())
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
        let paged = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}?offset=0&limit=1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(paged.status(), StatusCode::OK);
        assert_eq!(
            body(paged).await,
            json!({ "has_password": true, "authorized": false })
        );

        for suffix in ["/file", "/receipt", "/bundle", "/batch"] {
            let mut request = Request::get(format!("/api/s/{token}{suffix}"));
            if matches!(suffix, "/file" | "/bundle" | "/batch") {
                request =
                    request.extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))));
            }
            assert_eq!(
                router(app.clone())
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }

        let wrong = router(app.clone())
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

        let verified = router(app.clone())
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

        let verdicts: Vec<_> = app
            .store
            .audit_export(Some(""), 0, 0, 100)
            .unwrap()
            .into_iter()
            .filter(|row| {
                row.subject == grant_id
                    && matches!(row.event.as_str(), "link_password_failed" | "link_unlocked")
            })
            .collect();
        assert_eq!(
            verdicts
                .iter()
                .map(|row| row.event.as_str())
                .collect::<Vec<_>>(),
            ["link_password_failed", "link_unlocked"]
        );
        assert!(verdicts.iter().all(|row| {
            row.actor.is_empty()
                && row.detail["kind"] == "delivery"
                && row.detail["client_ip"] == "127.0.0.1"
                && !row.detail.to_string().contains("correct horse")
                && !row.detail.to_string().contains(token)
                && !row.detail.to_string().contains("$argon2")
        }));
        assert_ne!(grant_id, token);

        let holder = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes(),
        );
        let challenge_request = |cookie: &str| {
            Request::post(format!("/api/s/{token}/evidence-challenge"))
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 4))))
                .body(Body::from(json!({"holder": holder}).to_string()))
                .unwrap()
        };
        let forged_cookie = format!("{}=forged", grant_cookie_name(&grant_id));
        for denied_cookie in ["", cookie.as_str(), forged_cookie.as_str()] {
            let response = router(app.clone())
                .oneshot(challenge_request(denied_cookie))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(body(response).await["error"], "delivery password required");
        }
        let response = router(app.clone())
            .oneshot(challenge_request(&grant_cookie))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let signed: crate::delivery_protocol::SignedChallenge =
            serde_json::from_value(body(response).await).unwrap();
        assert!(signed.verify(&app.signer.public_hex));
        assert_eq!(signed.challenge.grant_id, grant_id);
        assert_eq!(signed.challenge.holder, holder);
        assert_eq!(signed.challenge.origin, "https://drop.example.com");
        assert_eq!(
            signed.challenge.manifest,
            app.store.delivery_manifest(&grant_id).unwrap()
        );

        let metadata = router(app.clone())
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
        let paged = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}?offset=0&limit=1"))
                    .header("cookie", &grant_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(paged.status(), StatusCode::OK);
        assert_eq!(body(paged).await["files_total"], 1);

        let file = router(app.clone())
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

        let bundle = router(app.clone())
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

        let receipt = router(app)
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
    async fn indexed_file_downloads_charge_fractional_grant_units() {
        let (_directory, app, cookie, first) = fixture().await;
        for (path, bytes) in [
            ("rate/one.bin", first.as_slice()),
            ("rate/two.bin", b"second file".as_slice()),
        ] {
            let response = router(app.clone())
                .oneshot(
                    Request::post(format!("/api/admin/outbound-files?path={path}"))
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .body(Body::from(bytes.to_vec()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let created = router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"paths":["rate/one.bin","rate/two.bin"]}"#))
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

        // Leave two full units. Each indexed download is answered by two
        // requests, the admission and the redirected stream, and each
        // request must cost half a unit; a full-unit endpoint wiring would
        // refuse the second download's replay.
        let key = hash_token(&token);
        for _ in 0..1_998 {
            assert!(app.outbound_rate.allow(&key));
        }
        for (index, expected) in [first, b"second file".to_vec()].into_iter().enumerate() {
            let response = router(app.clone())
                .oneshot(
                    Request::get(format!("/api/s/{token}/files/{index}"))
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            31,
                        ))))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn library_grants_reject_nonportable_names_before_source_access() {
        let (_directory, app, cookie, _) = fixture().await;
        let library = library_root(&app, "");
        std::fs::create_dir_all(&library).unwrap();
        for names in [
            vec!["Café.mov", "Cafe\u{301}.mov"],
            vec!["ΣΊΣΥΦΟΣ.mov", "σίσυφος.mov"],
            vec!["ſtraße.mov", "strasse.mov"],
            vec!["I.mov", "ı.mov"],
            vec!["XML:EDL/clip.mov"],
            vec!["clip.mov."],
        ] {
            for materialized in [false, true] {
                if materialized {
                    for (index, name) in names.iter().enumerate() {
                        let path = library.join(name);
                        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                        std::fs::write(path, [index as u8]).unwrap();
                    }
                }
                let response = router(app.clone())
                    .oneshot(
                        Request::post("/api/admin/outbound-grants")
                            .header("cookie", &cookie)
                            .header("x-votport", "1")
                            .header("content-type", "application/json")
                            .body(Body::from(json!({"paths":names}).to_string()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{names:?}"
                );
                assert!(app.store.outbound_grants("").unwrap().is_empty());
            }
        }
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
            async { router(app.clone()).oneshot(request).await.unwrap() }
        };
        assert_eq!(
            upload("project/one.bin", &first).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            upload("project/two.bin", b"second file").await.status(),
            StatusCode::OK
        );
        let audits = app.store.audit_export(None, 0, 0, 100).unwrap();
        assert!(audits.iter().any(|row| {
            row.event == "outbound_file_uploaded"
                && row.actor == "local"
                && row.subject == "project/one.bin"
                && row.detail["path"] == "project/one.bin"
                && row.detail["bytes"] == first.len()
        }));

        let listed = router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?directory=project")
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

        let duplicate = router(app.clone())
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
        let response = router(app.clone()).oneshot(create).await.unwrap();
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
        let metadata = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let metadata = body(metadata).await;
        assert_eq!(metadata["files"].as_array().unwrap().len(), 2);
        assert!(metadata["receipt_url"].is_null());
        assert!(metadata["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|file| file["receipt_url"].is_null()));
        // The unpaged shape sums every file too, not the first file's bytes.
        let expected: u64 = metadata["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file["bytes"].as_u64().unwrap())
            .sum();
        assert_eq!(metadata["total_bytes"].as_u64().unwrap(), expected);
        for (offset, expected_name, expected_url, has_more) in [
            (
                0,
                "project/one.bin",
                format!("/api/s/{token}/files/0"),
                true,
            ),
            (
                1,
                "project/two.bin",
                format!("/api/s/{token}/files/1"),
                false,
            ),
        ] {
            let response = router(app.clone())
                .oneshot(
                    Request::get(format!("/api/s/{token}?offset={offset}&limit=1"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let page = body(response).await;
            assert_eq!(page["files_total"], 2);
            // The byte total covers the whole grant, not only this page.
            assert_eq!(page["total_bytes"].as_u64().unwrap(), expected);
            assert_eq!(page["offset"], offset);
            assert_eq!(page["limit"], 1);
            assert_eq!(page["has_more"], has_more);
            assert_eq!(page["files"].as_array().unwrap().len(), 1);
            assert_eq!(page["files"][0]["name"], expected_name);
            assert_eq!(page["files"][0]["download_url"], expected_url);
            assert!(page["receipt_url"].is_null());
            assert!(page["files"][0]["receipt_url"].is_null());
        }
        let end = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}?offset=2&limit=1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(end.status(), StatusCode::OK);
        let end = body(end).await;
        assert_eq!(end["files_total"], 2);
        assert_eq!(end["offset"], 2);
        assert_eq!(end["files"], json!([]));
        assert_eq!(end["has_more"], false);
        assert_eq!(metadata["batch_url"], format!("/api/s/{token}/batch"));
        let batch = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/batch"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(batch.status(), StatusCode::OK);
        assert_eq!(
            batch.headers()[header::CONTENT_TYPE],
            "application/vnd.votport.batch"
        );
        assert_eq!(batch.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            batch.headers()[header::CONTENT_LENGTH],
            (first.len() + 11).to_string()
        );
        assert_eq!(
            batch.into_body().collect().await.unwrap().to_bytes(),
            [first.clone(), b"second file".to_vec()].concat()
        );
        assert!(app.outbound_active.lock().unwrap().is_empty());
        let bundle = router(app.clone())
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
            let file = router(app.clone())
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
            let receipt = router(app.clone())
                .oneshot(
                    Request::get(format!("/api/s/{token}/receipts/{index}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(receipt.status(), StatusCode::NOT_FOUND);
        }
        std::fs::write(app.config.outbound_dir.join("project/one.bin"), b"mutated").unwrap();
        let batch = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/batch"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 7))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(batch.status(), StatusCode::NOT_FOUND);
        assert!(
            std::fs::read_dir(app.config.data_dir.join("outbound.stage"))
                .unwrap()
                .next()
                .is_none()
        );
        let mutated = router(app.clone())
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
        let bundle = router(app)
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

    fn outbound_query(pairs: &[(&str, &str)]) -> String {
        let mut url = reqwest::Url::parse("http://localhost/api/admin/outbound-files").unwrap();
        {
            let mut query = url.query_pairs_mut();
            for (key, value) in pairs {
                query.append_pair(key, value);
            }
        }
        format!("{}?{}", url.path(), url.query().unwrap())
    }

    fn outbound_file_path(path: &str) -> String {
        outbound_query(&[("path", path)])
    }

    #[tokio::test]
    async fn library_uploads_refuse_nonportable_names_before_staging() {
        let (_directory, app, cookie, _) = fixture().await;
        let portable = "unicode/Café.mov";
        let response = router(app.clone())
            .oneshot(
                Request::post(outbound_file_path(portable))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from("portable"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            std::fs::read(app.config.outbound_dir.join(portable)).unwrap(),
            b"portable"
        );

        let invalid = [
            "XML:EDL/clip.mov",
            "trailing.",
            "trailing ",
            "CON.txt",
            "a<b>.mov",
            "\u{ff0e}/clip.mov",
            "\u{202e}fdp.exe",
        ];
        for (index, path) in invalid.iter().enumerate() {
            let response = router(app.clone())
                .oneshot(
                    Request::post(outbound_file_path(path))
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .body(Body::from("rejected"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{path}"
            );
            let destination = app.config.outbound_dir.join(path);
            assert!(!destination.exists(), "{path}");
            let upload_id = format!("{index:064x}");
            let stage = outbound_stage_name(&destination, &upload_id);
            assert!(
                !destination.parent().unwrap().join(stage).exists(),
                "{path}"
            );
        }

        for (index, path) in invalid.iter().enumerate() {
            let upload_id = format!("{:064x}", index + invalid.len());
            let response = router(app.clone())
                .oneshot(chunk_request(
                    &cookie,
                    path,
                    &upload_id,
                    0,
                    7,
                    8,
                    b"rejected",
                ))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{path}"
            );
            let destination = app.config.outbound_dir.join(path);
            assert!(!destination.exists(), "{path}");
            let stage = outbound_stage_name(&destination, &upload_id);
            assert!(
                !destination.parent().unwrap().join(stage).exists(),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn library_255_byte_directory_remains_browseable_and_selectable() {
        let (_directory, app, cookie, _) = fixture().await;
        let directory = "d".repeat(255);
        let file = format!("{directory}/clip.mov");
        let response = router(app.clone())
            .oneshot(
                Request::post(outbound_file_path(&file))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from("portable"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let listed = router(app.clone())
            .oneshot(
                Request::get(outbound_query(&[("directory", &directory)]))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        assert_eq!(body(listed).await["files"][0]["path"], file);

        let paged = router(app.clone())
            .oneshot(
                Request::get(outbound_query(&[("directory", &directory), ("limit", "1")]))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(paged.status(), StatusCode::OK);
        let paged = body(paged).await;
        assert_eq!(paged["files"][0]["path"], file);
        assert_eq!(paged["truncated"], false);

        let selected = router(app.clone())
            .oneshot(
                Request::get(outbound_query(&[("selection", &directory)]))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(selected.status(), StatusCode::OK);
        assert_eq!(body(selected).await["files"][0]["path"], file);

        let grant = router(app)
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "directory": directory,
                            "label": "long directory",
                            "expires_days": 1
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(grant.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn library_grant_restore_requires_outbound_volume() {
        let (directory, app, cookie, expected) = fixture().await;
        let source = app.config.outbound_dir.join("restore.bin");
        std::fs::write(&source, &expected).unwrap();
        let created = router(app.clone())
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

        let grant = app
            .store
            .outbound_grant_by_token_hash(&hash_token(&token))
            .unwrap()
            .unwrap();
        assert!(grant.files[0].receipt_b64.is_empty());
        let mut cached = grant.files[0].clone();
        cached.receipt_b64 = base64::prelude::BASE64_STANDARD.encode(
            app.signer
                .encode(
                    &object_id(&expected),
                    [61; 16],
                    PublishObservation {
                        incarnation: [62; 16],
                        sequence: 1,
                    },
                    vot_sdk_file::CommitProfile::Fast,
                    vot_sdk_file::NasContract::Unqualified,
                )
                .unwrap(),
        );
        assert!(
            source_info_indexed_with_file(&app, &grant, 0, Some(&cached))
                .unwrap()
                .receipt
                .is_none()
        );

        let receipt = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/receipts/0"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt.status(), StatusCode::NOT_FOUND);

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

        let unavailable = router(restored.clone())
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
        let available = router(restored)
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
        let response = router(app.clone())
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

    #[cfg(unix)]
    #[tokio::test]
    async fn whole_file_upload_stage_is_owned_while_a_slow_body_is_active() {
        use std::time::{Duration, SystemTime};

        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let cookie = admin_cookie(&app);
        let (sender, receiver) = mpsc::channel::<Result<Bytes, std::io::Error>>(2);
        let stream = futures_util::stream::unfold(receiver, |mut receiver| async {
            receiver.recv().await.map(|chunk| (chunk, receiver))
        });
        let request = Request::post("/api/admin/outbound-files?path=slow.bin")
            .header("cookie", cookie)
            .header("x-votport", "1")
            .body(Body::from_stream(stream))
            .unwrap();
        let upload = tokio::spawn(router(app.clone()).oneshot(request));

        sender.send(Ok(Bytes::from_static(b"first"))).await.unwrap();
        let stage = tokio::time::timeout(Duration::from_secs(2), async {
            for _ in 0..200 {
                if let Some(stage) = std::fs::read_dir(&app.config.outbound_dir)
                    .unwrap()
                    .flatten()
                    .map(|entry| entry.path())
                    .find(|path| {
                        path.file_name()
                            .and_then(|name| name.to_str())
                            .is_some_and(|name| {
                                name.starts_with(".vot-outbound-") && name.ends_with(".stage")
                            })
                    })
                    .filter(|stage| {
                        std::fs::read(stage).is_ok_and(|contents| contents.as_slice() == b"first")
                    })
                {
                    return stage;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("whole-file upload did not write its first chunk");
        })
        .await
        .expect("whole-file upload did not create its stage");
        let name = stage.file_name().unwrap().to_str().unwrap();
        let (stripe, digest) = name
            .strip_prefix(".vot-outbound-")
            .and_then(|name| name.strip_suffix(".stage"))
            .and_then(|name| name.split_once('-'))
            .expect("whole-file upload used an unowned stage name");
        assert_eq!(
            stripe,
            format!(
                "{:02x}",
                outbound_upload_stripe(&app.config.outbound_dir.join("slow.bin"))
            )
        );
        assert!(stripe.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(valid_outbound_upload_id(digest));

        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let now = old + Duration::from_secs(app.config.session_idle_secs);
        std::fs::File::open(&stage)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();
        sweep_upload_stages(&app, now);
        assert!(stage.exists(), "sweeper removed an active upload stage");

        sender
            .send(Ok(Bytes::from_static(b"second")))
            .await
            .unwrap();
        drop(sender);
        let response = tokio::time::timeout(Duration::from_secs(2), upload)
            .await
            .expect("whole-file upload did not finish")
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            std::fs::read(app.config.outbound_dir.join("slow.bin")).unwrap(),
            b"firstsecond"
        );
        assert!(!stage.exists());
    }

    #[tokio::test]
    async fn library_grant_caps_the_aggregate_selection_size() {
        let directory = tempfile::tempdir().unwrap();
        let mut app = crate::api::testing::build(directory.path());
        Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 5;
        std::fs::write(app.config.outbound_dir.join("one.bin"), b"one").unwrap();
        std::fs::write(app.config.outbound_dir.join("two.bin"), b"two").unwrap();
        let response = router(app.clone())
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
        Request::post(outbound_file_path(path))
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn chunk_checkpoint_refuses_a_file_that_cannot_sync() {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .await
            .unwrap();
        file.write_all(b"chunk").await.unwrap();
        let response = sync_outbound_chunk(&mut file)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn resumable_library_upload_keeps_partial_files_unpublished() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "a".repeat(64);
        let response = router(app.clone())
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
        assert!(app.store.audit_export(None, 0, 0, 100).unwrap().is_empty());
    }

    #[tokio::test]
    async fn resumable_library_upload_resynchronizes_and_audits_completion() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "b".repeat(64);
        let first = router(app.clone())
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

        let mismatch = router(app.clone())
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
        assert_eq!(mismatch.status(), StatusCode::OK);
        assert_eq!(body(mismatch).await["offset"], 3);

        let complete = router(app.clone())
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
        let stage = app.config.outbound_dir.join(outbound_stage_name(
            &app.config.outbound_dir.join("resume.bin"),
            &upload_id,
        ));
        assert!(vot_platform_fs::same_file_regular(
            &stage,
            &app.config.outbound_dir.join("resume.bin")
        )
        .unwrap());
        let audits = app.store.audit_export(None, 0, 0, 100).unwrap();
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
    async fn resumable_library_upload_replays_only_its_published_witness() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "1".repeat(64);
        for (start, end, bytes) in [(0, 2, b"abc".as_slice()), (3, 5, b"def".as_slice())] {
            let response = router(app.clone())
                .oneshot(chunk_request(
                    &cookie,
                    "replay.bin",
                    &upload_id,
                    start,
                    end,
                    6,
                    bytes,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let destination = app.config.outbound_dir.join("replay.bin");
        let stage = app
            .config
            .outbound_dir
            .join(outbound_stage_name(&destination, &upload_id));
        let uploaded = || {
            app.store
                .audit_export(None, 0, 0, 100)
                .unwrap()
                .into_iter()
                .filter(|row| row.event == "outbound_file_uploaded")
                .count()
        };
        assert!(vot_platform_fs::same_file_regular(&stage, &destination).unwrap());
        let audits_before = uploaded();

        // The final response may be lost after publication. The same upload
        // id and hardlink witness make the retry an idempotent completion.
        let replay = router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "replay.bin",
                &upload_id,
                3,
                5,
                6,
                b"def",
            ))
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::OK);
        assert_eq!(body(replay).await["complete"], true);
        assert_eq!(uploaded(), audits_before);
        assert_eq!(std::fs::read(&destination).unwrap(), b"abcdef");

        // A different upload id has no witness and cannot claim the name.
        let foreign = "2".repeat(64);
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "replay.bin",
                &foreign,
                0,
                5,
                6,
                b"abcdef",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(!app
            .config
            .outbound_dir
            .join(outbound_stage_name(&destination, &foreign))
            .exists());

        // Matching bytes are still rejected when the caller's declared total
        // differs from the published file.
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "replay.bin",
                &upload_id,
                0,
                6,
                7,
                b"abcdefg",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // Replacing the destination breaks the hardlink witness, even at the
        // same size, so a stale final reply cannot bless a new file.
        std::fs::remove_file(&destination).unwrap();
        std::fs::write(&destination, b"ghijkl").unwrap();
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "replay.bin",
                &upload_id,
                3,
                5,
                6,
                b"def",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(stage.exists());
        assert_eq!(uploaded(), audits_before);
    }

    #[cfg(unix)]
    #[test]
    fn completed_stage_expiry_starts_at_publication() {
        use std::time::{Duration, SystemTime};

        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let identity = auth::AdminIdentity::local_admin();
        let upload_id = "4".repeat(64);
        let destination = app.config.outbound_dir.join("completion-time.bin");
        let stage = app
            .config
            .outbound_dir
            .join(outbound_stage_name(&destination, &upload_id));
        std::fs::write(&stage, b"abcdef").unwrap();
        std::fs::File::open(&stage).unwrap().sync_all().unwrap();
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        std::fs::File::open(&stage)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old))
            .unwrap();

        let complete = publish_outbound_stage(
            &app,
            &identity,
            &stage,
            &destination,
            "completion-time.bin",
            6,
        )
        .unwrap();
        assert_eq!(complete.status(), StatusCode::OK);
        let published_at = std::fs::metadata(&stage).unwrap().modified().unwrap();
        assert!(published_at > old);

        let before_expiry = published_at
            .checked_add(Duration::from_secs(
                app.config.session_idle_secs.saturating_sub(1),
            ))
            .unwrap();
        sweep_upload_stages(&app, before_expiry);
        assert!(stage.exists());
        sweep_upload_stages(
            &app,
            published_at
                .checked_add(Duration::from_secs(app.config.session_idle_secs))
                .unwrap(),
        );
        assert!(!stage.exists());
        assert_eq!(std::fs::read(destination).unwrap(), b"abcdef");
    }

    #[cfg(unix)]
    #[test]
    fn publication_refresh_failure_keeps_destination_unpublished() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let identity = auth::AdminIdentity::local_admin();
        let destination = app.config.outbound_dir.join("refresh-failure.bin");
        let stage = app
            .config
            .outbound_dir
            .join(outbound_stage_name(&destination, &"5".repeat(64)));
        std::os::unix::fs::symlink(app.config.outbound_dir.join("missing-stage-target"), &stage)
            .unwrap();

        assert!(publish_outbound_stage(
            &app,
            &identity,
            &stage,
            &destination,
            "refresh-failure.bin",
            0,
        )
        .is_err());
        assert!(matches!(
            std::fs::symlink_metadata(&destination),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
        assert!(std::fs::symlink_metadata(&stage)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn resumable_library_upload_rejects_symlink_witnesses() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "3".repeat(64);
        for (start, end, bytes) in [(0, 2, b"abc".as_slice()), (3, 5, b"def".as_slice())] {
            let response = router(app.clone())
                .oneshot(chunk_request(
                    &cookie,
                    "symlink.bin",
                    &upload_id,
                    start,
                    end,
                    6,
                    bytes,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let destination = app.config.outbound_dir.join("symlink.bin");
        let stage = app
            .config
            .outbound_dir
            .join(outbound_stage_name(&destination, &upload_id));
        let external = app.config.outbound_dir.join("symlink-target.bin");
        std::fs::remove_file(&destination).unwrap();
        std::fs::write(&external, b"abcdef").unwrap();
        std::os::unix::fs::symlink(&external, &destination).unwrap();
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "symlink.bin",
                &upload_id,
                3,
                5,
                6,
                b"def",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(stage.exists());
        std::fs::remove_file(&destination).unwrap();
        std::fs::write(&destination, b"abcdef").unwrap();
        std::fs::remove_file(&stage).unwrap();
        std::os::unix::fs::symlink(&destination, &stage).unwrap();
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "symlink.bin",
                &upload_id,
                3,
                5,
                6,
                b"def",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(std::fs::symlink_metadata(&stage)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[tokio::test]
    async fn resumable_library_upload_rolls_back_an_invalid_chunk() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "e".repeat(64);
        let first = router(app.clone())
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
        let invalid = router(app.clone()).oneshot(invalid).await.unwrap();
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
            let response = router(app.clone())
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
    async fn an_unacknowledged_stage_tail_is_replayed_instead_of_trusted() {
        for stale in [b"wrong".as_slice(), b"wrong data"] {
            let (_directory, app, cookie, _bytes) = fixture().await;
            let upload_id = "e".repeat(64);
            let path = app.config.outbound_dir.join("late.bin");
            let stage = app
                .config
                .outbound_dir
                .join(outbound_stage_name(&path, &upload_id));
            std::fs::write(&stage, stale).unwrap();
            let response = router(app.clone())
                .oneshot(chunk_request(
                    &cookie, "late.bin", &upload_id, 0, 4, 10, b"whole",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let progress = body(response).await;
            assert_eq!(progress["complete"], false);
            assert_eq!(progress["offset"], 5);
            assert!(!path.exists());
            assert_eq!(std::fs::read(&stage).unwrap(), b"whole");
            let response = router(app.clone())
                .oneshot(chunk_request(
                    &cookie, "late.bin", &upload_id, 5, 9, 10, b" file",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body(response).await["complete"], true);
            assert_eq!(std::fs::read(&path).unwrap(), b"whole file");
            assert!(vot_platform_fs::same_file_regular(&stage, &path).unwrap());
        }
    }

    #[tokio::test]
    async fn chunk_replay_preserves_the_acknowledged_prefix_and_rewinds_missing_bytes() {
        for (stale, expected_status, expected_offset) in [
            (b"wholewrong".as_slice(), StatusCode::OK, 10),
            (b"who".as_slice(), StatusCode::CONFLICT, 3),
        ] {
            let (_directory, app, cookie, _bytes) = fixture().await;
            let upload_id = "e".repeat(64);
            let path = app.config.outbound_dir.join("prefix.bin");
            let stage = path
                .parent()
                .unwrap()
                .join(outbound_stage_name(&path, &upload_id));
            std::fs::write(&stage, stale).unwrap();
            let response = router(app.clone())
                .oneshot(chunk_request(
                    &cookie,
                    "prefix.bin",
                    &upload_id,
                    5,
                    9,
                    10,
                    b" file",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status);
            assert_eq!(body(response).await["offset"], expected_offset);
            if expected_status == StatusCode::CONFLICT {
                assert_eq!(std::fs::read(&stage).unwrap(), b"who");
                let response = router(app.clone())
                    .oneshot(chunk_request(
                        &cookie,
                        "prefix.bin",
                        &upload_id,
                        3,
                        9,
                        10,
                        b"le file",
                    ))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(body(response).await["complete"], true);
            }
            assert_eq!(std::fs::read(&path).unwrap(), b"whole file");
        }
    }

    #[tokio::test]
    async fn stages_from_before_durable_acknowledgements_are_not_resumed() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "e".repeat(64);
        let path = app.config.outbound_dir.join("older.bin");
        let mut old_hash = Sha256::new();
        old_hash.update(path.to_string_lossy().as_bytes());
        old_hash.update([0]);
        old_hash.update(upload_id.as_bytes());
        let old_stage = path.parent().unwrap().join(format!(
            ".vot-outbound-{:02x}-{}.stage",
            outbound_upload_stripe(&path),
            hex::encode(old_hash.finalize()),
        ));
        std::fs::write(&old_stage, b"wrong").unwrap();
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "older.bin",
                &upload_id,
                5,
                9,
                10,
                b" file",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(body(response).await["offset"], 0);
        assert!(!path.exists());
        assert_eq!(std::fs::read(&old_stage).unwrap(), b"wrong");
    }

    #[tokio::test]
    async fn a_refused_chunk_body_is_read_through_before_the_answer() {
        // The body arrives in pieces and the handler must pull every one
        // before answering, or a client mid-write sees a reset connection
        // instead of the 422 (here: a path the library refuses).
        let (_directory, app, cookie, _bytes) = fixture().await;
        let pulled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&pulled);
        let pieces: Vec<Result<Bytes, std::io::Error>> =
            (0..8).map(|_| Ok(Bytes::from(vec![7u8; 1024]))).collect();
        let body = Body::from_stream(futures_util::stream::iter(pieces).inspect(move |_| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        let response = router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-files?path=../escape.bin")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header(OUTBOUND_UPLOAD_ID, "d".repeat(64))
                    .header(header::CONTENT_RANGE, "bytes 0-8191/16384")
                    .header(header::CONTENT_LENGTH, 8192)
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(pulled.load(std::sync::atomic::Ordering::SeqCst), 8);
    }

    #[tokio::test]
    async fn resumable_library_upload_rejects_limits_before_staging() {
        let directory = tempfile::tempdir().unwrap();
        let mut app = crate::api::testing::build(directory.path());
        Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 5;
        let cookie = admin_cookie(&app);
        let upload_id = "c".repeat(64);
        let response = router(app.clone())
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
            router(app.clone()).oneshot(first),
            router(app.clone()).oneshot(second),
        );
        let statuses = [first.unwrap().status(), second.unwrap().status()];
        assert_eq!(statuses, [StatusCode::OK, StatusCode::OK]);
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

    #[cfg(unix)]
    #[test]
    fn expired_upload_stages_are_removed_without_touching_active_or_unowned_files() {
        use std::time::{Duration, SystemTime};

        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let root = &app.config.outbound_dir;
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let now = old + Duration::from_secs(app.config.session_idle_secs);
        let write = |path: &Path, modified| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"partial").unwrap();
            std::fs::File::open(path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(modified))
                .unwrap();
        };
        let stage =
            |path: &Path, id: &str| path.parent().unwrap().join(outbound_stage_name(path, id));
        let destination = root.join("project/expired.bin");
        let completed_destination = root.join("project/completed.bin");
        let completed_stage = stage(&completed_destination, &"0".repeat(64));
        write(&completed_stage, old);
        std::fs::hard_link(&completed_stage, &completed_destination).unwrap();
        let expired = stage(&destination, &"a".repeat(64));
        let abandoned = stage(&destination, &"b".repeat(64));
        let recent = stage(&destination, &"c".repeat(64));
        write(&expired, old);
        write(&abandoned, old);
        write(&recent, old + Duration::from_secs(1));
        let completed_stripe = outbound_upload_stripe(&completed_destination);
        let active_destination = (0..1000)
            .map(|i| root.join(format!("active-{i}.bin")))
            .find(|path| {
                let stripe = outbound_upload_stripe(path);
                stripe > 1
                    && stripe != outbound_upload_stripe(&destination)
                    && stripe != completed_stripe
            })
            .unwrap();
        let active = stage(&active_destination, &"d".repeat(64));
        write(&active, old);
        let guard = app.outbound_upload_locks[outbound_upload_stripe(&active_destination)]
            .try_lock()
            .unwrap();

        let digest = "e".repeat(64);
        let preserved: Vec<_> = [
            "operator.bin".to_owned(),
            format!(".vot-outbound-{digest}.stage"),
            format!(".vot-outbound-0-{digest}.stage"),
            format!(".vot-outbound-+1-{digest}.stage"),
            format!(".vot-outbound-ff-{digest}.stage"),
            format!(".vot-outbound-zz-{digest}.stage"),
            ".vot-outbound-00-short.stage".to_owned(),
            format!(".vot-outbound-00-{}.stage", "g".repeat(64)),
            format!(".vot-outbound-00-{digest}.journal"),
        ]
        .into_iter()
        .map(|name| root.join(name))
        .collect();
        for path in &preserved {
            write(path, old);
        }
        let external = directory.path().join("external");
        let external_stage = stage(&external.join("file.bin"), &digest);
        write(&external_stage, old);
        std::os::unix::fs::symlink(&external, root.join("linked-directory")).unwrap();
        let linked_stage = stage(&destination, &digest);
        std::os::unix::fs::symlink(&external_stage, &linked_stage).unwrap();
        let stamp = rustix::fs::Timespec {
            tv_sec: 1000,
            tv_nsec: 0,
        };
        rustix::fs::utimensat(
            rustix::fs::CWD,
            &linked_stage,
            &rustix::fs::Timestamps {
                last_access: stamp,
                last_modification: stamp,
            },
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();

        sweep_upload_stages(&app, now - Duration::from_secs(1));
        assert!(
            expired.exists(),
            "a stage younger than the idle limit stays"
        );
        sweep_upload_stages(&app, now);
        assert!(!expired.exists() && !abandoned.exists());
        assert!(!completed_stage.exists() && completed_destination.exists());
        assert!(recent.exists() && active.exists());
        assert!(preserved.iter().all(|path| path.exists()));
        assert!(external_stage.exists() && linked_stage.exists());
        drop(guard);
        sweep_upload_stages(&app, now);
        assert!(
            !active.exists(),
            "an expired stage is removed once its request ends"
        );
    }

    #[tokio::test]
    async fn root_library_listing_excludes_tenants_and_stages_and_is_sorted() {
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

        let response = router(app.clone())
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

        let response = router(app.clone())
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

        let response = router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?directory=&limit=2")
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let first_page = body(response).await;
        assert_eq!(first_page["directories"], json!(["adir"]));
        assert_eq!(
            first_page["files"],
            json!([{ "path": "a.bin", "bytes": 1 }])
        );
        assert_eq!(first_page["truncated"], true);
        assert_eq!(first_page["next_cursor"], "adir");

        let response = router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?directory=&limit=2&after=adir")
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let second_page = body(response).await;
        assert_eq!(second_page["directories"], json!(["zdir"]));
        assert_eq!(
            second_page["files"],
            json!([{ "path": "z.bin", "bytes": 1 }])
        );
        assert_eq!(second_page["truncated"], false);
        assert!(second_page["next_cursor"].is_null());

        for query in [
            "?directory=adir&limit=2&after=z.bin",
            "?q=adir&after=adir",
            "?directory=&limit=0",
            "?directory=&limit=1001",
            "?directory=&limit=nope",
        ] {
            let response = router(app.clone())
                .oneshot(
                    Request::get(format!("/api/admin/outbound-files{query}"))
                        .header("cookie", admin_cookie(&app))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{query}"
            );
        }

        let response = router(app.clone())
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

        let response = router(app.clone())
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

        let response = router(app.clone())
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
        let response = router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?selection=large")
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body(response).await["files"].as_array().unwrap().len(), 65);

        #[cfg(unix)]
        {
            let response = router(app.clone())
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

    #[cfg(unix)]
    #[test]
    fn library_pages_skip_literal_backslash_direct_filenames() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("a\\b"), b"skip").unwrap();
        std::fs::write(directory.path().join("portable"), b"keep").unwrap();
        let (directories, files, truncated) =
            direct_library_entries_page(directory.path(), directory.path(), "", 1).unwrap();
        assert!(directories.is_empty());
        assert_eq!(files, [json!({ "path": "portable", "bytes": 4 })]);
        assert!(!truncated);
    }

    #[tokio::test]
    async fn library_views_exclude_private_workflow_storage() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let root = &app.config.outbound_dir;
        for name in [
            ".votport-workflows/job/secret.bin",
            ".VOTPORT-WORKFLOWS/job/secret.bin",
            "public/.votport-workflows/job/secret.bin",
            "public/.VOTPORT-WORKFLOWS/job/secret.bin",
            ".vot-hidden.stage/secret.bin",
            "public/.vot-hidden.stage/secret.bin",
            "public/visible.bin",
            "public/.notes",
            "public/.vot-workflows.txt",
        ] {
            let path = root.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"x").unwrap();
        }
        let expected = json!([
            {"path":"public/.notes","bytes":1},
            {"path":"public/.vot-workflows.txt","bytes":1},
            {"path":"public/visible.bin","bytes":1},
        ]);
        for query in ["?directory=public", "?selection=public"] {
            let response = router(app.clone())
                .oneshot(
                    Request::get(format!("/api/admin/outbound-files{query}"))
                        .header("cookie", admin_cookie(&app))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{query}");
            let listed = body(response).await;
            assert_eq!(listed["files"], expected, "{query}: {listed}");
            if query.contains("directory") {
                assert_eq!(listed["directories"], json!([]));
                assert_eq!(listed["truncated"], false);
            }
        }
        let (matches, truncated) = list_library_search(root, "secret");
        assert!(matches.is_empty() && !truncated);
        let (matches, truncated) = list_library_search(root, "visible");
        assert_eq!(
            matches,
            vec![json!({"path":"public/visible.bin","bytes":1})]
        );
        assert!(!truncated);
        let (directories, files, has_more) =
            direct_library_entries_page(root, root, "", 1).unwrap();
        assert_eq!(directories, ["public"]);
        assert!(files.is_empty() && !has_more);
    }

    #[test]
    fn library_directory_safety_checks_root_and_every_component() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("library");
        std::fs::create_dir_all(root.join("nested/child")).unwrap();
        std::fs::write(root.join("file"), b"x").unwrap();
        for (path, expected) in [
            (root.clone(), true),
            (root.join("nested/child"), true),
            (root.join("missing"), false),
            (root.join("file"), false),
            (root.join("file/child"), false),
            (directory.path().to_owned(), false),
        ] {
            assert_eq!(library_directory_safe(&root, &path), expected, "{path:?}");
        }
        assert!(!library_directory_safe(
            &root.join("file"),
            &root.join("file")
        ));
        #[cfg(unix)]
        {
            let link = directory.path().join("link");
            std::os::unix::fs::symlink(&root, &link).unwrap();
            assert!(!library_directory_safe(&link, &link.join("nested")));
            std::os::unix::fs::symlink(root.join("nested"), root.join("link")).unwrap();
            assert!(!library_directory_safe(&root, &root.join("link")));
            assert!(!library_directory_safe(&root, &root.join("link/child")));
        }
    }

    #[test]
    fn scoped_library_directory_caps_direct_entries() {
        let directory = tempfile::tempdir().unwrap();
        for index in 0..=MAX_LIBRARY_DIRECTORY_ENTRIES {
            std::fs::write(directory.path().join(format!("file-{index:04}.bin")), b"x").unwrap();
        }
        let (directories, files, truncated) = direct_library_entries_page(
            directory.path(),
            directory.path(),
            "",
            MAX_LIBRARY_DIRECTORY_ENTRIES,
        )
        .unwrap();
        assert!(directories.is_empty());
        assert_eq!(files.len(), MAX_LIBRARY_DIRECTORY_ENTRIES);
        assert!(truncated);
        assert_eq!(files[0]["path"], "file-0000.bin");
        assert_eq!(
            files[MAX_LIBRARY_DIRECTORY_ENTRIES - 1]["path"],
            "file-0999.bin"
        );
    }

    #[test]
    fn library_search_stops_at_node_budget() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("missed-match.bin"), b"x").unwrap();
        let (matches, truncated) = list_library_search_with_budget(directory.path(), "match", 1);
        assert!(matches.is_empty());
        assert!(truncated);
    }

    #[test]
    fn library_search_stops_at_depth_budget() {
        let directory = tempfile::tempdir().unwrap();
        let mut nested = directory.path().to_owned();
        for index in 0..=MAX_LIBRARY_SEARCH_DEPTH {
            nested.push(format!("nested-{index:03}"));
            std::fs::create_dir(&nested).unwrap();
        }
        std::fs::write(nested.join("missed-match.bin"), b"x").unwrap();

        let (matches, truncated) = list_library_search(directory.path(), "match");

        assert!(matches.is_empty());
        assert!(truncated);
    }

    #[test]
    fn library_search_reports_missing_directory_as_truncated() {
        let directory = tempfile::tempdir().unwrap();
        let mut matches = BinaryHeap::new();
        let mut visited = 0;

        assert!(search_library_dir(
            directory.path(),
            &directory.path().join("missing"),
            "match",
            &mut matches,
            &mut visited,
            1,
            0,
        ));
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
            json!({ "directory": "a/".repeat(MAX_LIBRARY_DIRECTORY_INPUT_BYTES / 2 + 1) }),
        ] {
            let response = router(app.clone())
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
        let response = router(app.clone())
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

        let metadata = router(app.clone())
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

        let history = router(app)
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

    #[tokio::test]
    async fn grant_admission_bounds_request_bodies_and_releases_for_valid_grants() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let held = app
            .outbound_grant_permits
            .clone()
            .try_acquire_many_owned(LIBRARY_GRANT_CONCURRENCY as u32)
            .unwrap();
        let pending =
            Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
        let refused = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            router(app.clone()).oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(pending)
                    .unwrap(),
            ),
        )
        .await
        .expect("grant admission attempted to read a refused body")
        .unwrap();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        drop(held);

        let root = app.config.outbound_dir.join("admitted");
        std::fs::create_dir_all(&root).unwrap();
        let paths = (0..65)
            .map(|index| {
                let path = root.join(format!("file-{index:02}.bin"));
                std::fs::write(&path, b"x").unwrap();
                format!("admitted/file-{index:02}.bin")
            })
            .collect::<Vec<_>>();
        let accepted = router(app)
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "paths": paths, "expires_days": 1 }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(body(accepted).await["grant"]["file_count"], 65);
    }

    #[tokio::test]
    async fn grant_admission_permit_survives_parsing_while_hashers_wait() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        std::fs::write(app.config.outbound_dir.join("held.bin"), b"x").unwrap();
        let hash_held = LIBRARY_HASH_PERMITS
            .acquire_many(LIBRARY_HASH_CONCURRENCY as u32)
            .await
            .unwrap();
        let request = Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"paths":["held.bin"],"expires_days":1}"#))
            .unwrap();
        let mut response = Box::pin(router(app.clone()).oneshot(request));
        let waker = futures_util::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        assert!(matches!(
            std::future::Future::poll(response.as_mut(), &mut context),
            std::task::Poll::Pending
        ));
        assert_eq!(
            app.outbound_grant_permits.available_permits(),
            LIBRARY_GRANT_CONCURRENCY - 1
        );
        drop(hash_held);
        let response = tokio::time::timeout(std::time::Duration::from_secs(1), response)
            .await
            .expect("grant hashing did not resume")
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            app.outbound_grant_permits.available_permits(),
            LIBRARY_GRANT_CONCURRENCY
        );
    }

    #[tokio::test]
    async fn large_selection_bodies_require_authentication_before_reading() {
        let (_directory, app, cookie, _first) = fixture().await;
        let pending =
            Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            router(app.clone()).oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("content-type", "application/json")
                    .body(pending)
                    .unwrap(),
            ),
        )
        .await
        .expect("unauthenticated request attempted to read its body")
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let paths = (0..100_001)
            .map(|index| format!("sequence/frame-{index:06}.exr"))
            .collect::<Vec<_>>();
        let response = router(app)
            .oneshot(
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "paths": paths,
                            "expires_days": 1,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        // The selection passes count/body limits and reaches file validation.
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{}",
            body(response).await
        );
    }

    #[test]
    fn recursive_library_enumerator_rejects_more_than_project_limit() {
        let directory = tempfile::tempdir().unwrap();
        let limit = 3;
        for index in 0..=limit {
            std::fs::write(directory.path().join(format!("file-{index:04}.bin")), b"x").unwrap();
        }
        let error =
            enumerate_automation_files(directory.path(), directory.path(), limit).unwrap_err();
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error.message.contains(&format!("maximum {limit}")));
    }

    #[test]
    fn library_selection_refuses_file_entry_depth_and_path_budgets() {
        let boundary_root = tempfile::tempdir().unwrap();
        std::fs::write(boundary_root.path().join("x"), b"x").unwrap();
        let paths = enumerate_automation_files_with_budget(
            boundary_root.path(),
            boundary_root.path(),
            1,
            Some(LibraryEnumerationBudget {
                max_entries: 1,
                max_depth: 0,
                max_path_bytes: 1,
            }),
        )
        .unwrap();
        assert_eq!(paths, vec!["x"]);

        let directory = tempfile::tempdir().unwrap();
        for index in 0..=3 {
            std::fs::write(directory.path().join(format!("file-{index}.bin")), b"x").unwrap();
        }
        let error = enumerate_automation_files_with_budget(
            directory.path(),
            directory.path(),
            3,
            Some(LibraryEnumerationBudget {
                max_entries: 10,
                max_depth: 10,
                max_path_bytes: 1000,
            }),
        )
        .unwrap_err();
        assert_eq!(
            error.message,
            "library selection is too large; choose a narrower folder or select individual files"
        );

        let nested = directory.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("nested.bin"), b"x").unwrap();
        let error = enumerate_automation_files_with_budget(
            directory.path(),
            directory.path(),
            10,
            Some(LibraryEnumerationBudget {
                max_entries: 1,
                max_depth: 10,
                max_path_bytes: 1000,
            }),
        )
        .unwrap_err();
        assert_eq!(
            error.message,
            "library selection is too large; choose a narrower folder or select individual files"
        );

        let depth_root = tempfile::tempdir().unwrap();
        let mut deep = depth_root.path().to_owned();
        for index in 0..=2 {
            deep.push(format!("nested-{index}"));
            std::fs::create_dir(&deep).unwrap();
        }
        std::fs::write(deep.join("deep.bin"), b"x").unwrap();
        let error = enumerate_automation_files_with_budget(
            depth_root.path(),
            depth_root.path(),
            10,
            Some(LibraryEnumerationBudget {
                max_entries: 10,
                max_depth: 1,
                max_path_bytes: 1000,
            }),
        )
        .unwrap_err();
        assert_eq!(
            error.message,
            "library selection is too large; choose a narrower folder or select individual files"
        );

        let path_root = tempfile::tempdir().unwrap();
        std::fs::write(path_root.path().join("long-name.bin"), b"x").unwrap();
        let error = enumerate_automation_files_with_budget(
            path_root.path(),
            path_root.path(),
            10,
            Some(LibraryEnumerationBudget {
                max_entries: 10,
                max_depth: 10,
                max_path_bytes: 4,
            }),
        )
        .unwrap_err();
        assert_eq!(
            error.message,
            "library selection is too large; choose a narrower folder or select individual files"
        );
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

        let response = router(app.clone())
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
            "/api/admin/outbound-files".to_owned(),
            "/api/admin/outbound-files?directory=one&q=two".to_owned(),
            "/api/admin/outbound-files?directory=one&selection=two".to_owned(),
            "/api/admin/outbound-files?selection=".to_owned(),
            "/api/admin/outbound-files?q=".to_owned(),
            format!("/api/admin/outbound-files?q={}", "x".repeat(101)),
            format!("/api/admin/outbound-files?directory={}", "x".repeat(1025)),
        ] {
            let response = router(app.clone())
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

    #[test]
    fn scope_matches_whole_components() {
        assert!(within_scope("project", "project"));
        assert!(within_scope("project", "project/sub"));
        assert!(within_scope("/project/", "project/sub/deeper"));
        assert!(!within_scope("project", "project-old"));
        assert!(!within_scope("project", "other"));
        assert!(!within_scope("project/sub", "project"));
    }

    /// A token confined to a directory shares that directory and its
    /// children only; anything else is refused and audited.
    #[tokio::test]
    async fn scoped_automation_token_shares_only_its_directory() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        for path in ["project/sub", "project-old", "other"] {
            std::fs::create_dir_all(app.config.outbound_dir.join(path)).unwrap();
            std::fs::write(app.config.outbound_dir.join(path).join("f.txt"), b"f").unwrap();
        }
        let create = router(app.clone())
            .oneshot(
                Request::post("/api/admin/automation-tokens")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"label":"Nightly","expires_days":1,"directory":"project/"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = create.status();
        let created = body(create).await;
        assert_eq!(status, StatusCode::OK, "{created}");
        assert_eq!(created["automation_token"]["directory"], json!("project"));
        let raw = created["token"].as_str().unwrap().to_owned();
        // A traversal, absolute, or over-long directory is refused at issue time.
        let long = format!("\"{}\"", "a/".repeat(600));
        for bad in [r#""../x""#, r#""/abs""#, long.as_str()] {
            let create = router(app.clone())
                .oneshot(
                    Request::post("/api/admin/automation-tokens")
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"label":"bad","expires_days":1,"directory":{bad}}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(create.status(), StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
        }
        let share = |directory: &'static str| {
            let app = app.clone();
            let raw = raw.clone();
            async move {
                router(app)
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
                    .unwrap()
                    .status()
            }
        };
        assert_eq!(share("project").await, StatusCode::OK);
        assert_eq!(share("project/sub").await, StatusCode::OK);
        assert_eq!(share("project-old").await, StatusCode::FORBIDDEN);
        assert_eq!(share("other").await, StatusCode::FORBIDDEN);
        let refusals: Vec<String> = app
            .store
            .audit_export(None, 0, 0, 100)
            .unwrap()
            .into_iter()
            .filter(|row| row.event == "automation_refused")
            .map(|row| format!("{} {}", row.actor, row.subject))
            .collect();
        assert_eq!(refusals.len(), 2, "{refusals:?}");
        assert!(refusals.iter().all(|row| row.starts_with("automation:")));
        assert!(refusals.iter().any(|row| row.ends_with(" project-old")));
        let listed = router(app.clone())
            .oneshot(
                Request::get("/api/admin/automation-tokens")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            body(listed).await["tokens"][0]["directory"],
            json!("project")
        );
    }

    #[tokio::test]
    async fn automation_token_shares_recursive_library_without_leaking_token() {
        let (_directory, app, cookie, _bytes) = fixture().await;
        std::fs::create_dir_all(app.config.outbound_dir.join("project/sub")).unwrap();
        std::fs::write(app.config.outbound_dir.join("project/a.txt"), b"a").unwrap();
        std::fs::write(app.config.outbound_dir.join("project/sub/b.txt"), b"b").unwrap();
        let create = router(app.clone())
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

        let listed = router(app.clone())
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

        for authorization in [
            None,
            Some("Bearer nope"),
            Some("Bearer 00000000000000000000000000000000"),
        ] {
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
                router(app.clone()).oneshot(request).await.unwrap().status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let refusals = app
            .store
            .audit_export(None, 0, 0, 100)
            .unwrap()
            .into_iter()
            .filter(|row| row.event == "automation_refused")
            .map(|row| row.detail["reason"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            refusals,
            [
                "missing or malformed bearer",
                "missing or malformed bearer",
                "unknown, expired, or revoked token"
            ]
        );

        let share = router(app.clone())
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
        let large_share = router(app.clone())
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
            let response = router(app.clone())
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
            let response = router(app.clone())
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
        let revoke = router(app.clone())
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
        let denied = router(app)
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
