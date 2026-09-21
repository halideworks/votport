//! Verified, administrator-selected outbound files.

use std::collections::{BinaryHeap, HashMap};
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
pub mod root_cache;
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

use self::root_cache::mtime_nanos;
pub(crate) use self::root_cache::RootCache;
use super::{ApiError, ApiResult};
use crate::api::admin;
use crate::app::App;
use crate::auth;
use crate::auth::{hash_token, valid_hex};
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

// The deliver page's create-share used to block the POST on hashing every
// selected file, so a multi-gigabyte folder froze the page with no feedback.
// Grant creation for paths/directory now answers 202 with a preparation id
// and hashes in a detached job; the handles below carry live progress
// (files/bytes done) and the terminal outcome. State is in-memory by design:
// a restart loses pending preparations and the progress endpoint answers
// with a clear retry error (PREPARATION_LOST_MESSAGE).
const PREPARATION_PREPARING: u8 = 0;
const PREPARATION_COMPLETE: u8 = 1;
const PREPARATION_FAILED: u8 = 2;
// Terminal preparations stay queryable for a few minutes so a page reload or
// a slow poll still finds the finished link, then the sweep drops them.
const PREPARATION_TTL_SECS: u64 = 15 * 60;
// A preparation that never settles (a hash walk hung on dead NAS I/O, say)
// would otherwise pin its registry entry and the session's one-in-flight 409
// slot forever; past this age the sweep drops it and the session can retry.
const PREPARATION_STALE_SECS: u64 = 60 * 60;
const PREPARATION_LOST_MESSAGE: &str =
    "This preparation is no longer available; the server may have restarted. Create the link again.";

pub(crate) struct GrantPreparation {
    id: String,
    tenant: String,
    status: std::sync::atomic::AtomicU8,
    files_total: std::sync::atomic::AtomicU64,
    files_done: std::sync::atomic::AtomicU64,
    bytes_total: std::sync::atomic::AtomicU64,
    bytes_done: std::sync::atomic::AtomicU64,
    finished_at: std::sync::atomic::AtomicU64,
    created_at: std::sync::atomic::AtomicU64,
    outcome: Mutex<Option<Result<CreatedGrant, (u16, String)>>>,
}

/// Totals are unknown until the per-file stat pass finishes; u64::MAX stands
/// in for "not yet known" and serializes as null so the page can shimmer.
const PREPARATION_UNKNOWN: u64 = u64::MAX;

impl GrantPreparation {
    fn new(identity: &auth::AdminIdentity) -> Self {
        Self {
            id: auth::random_token(),
            tenant: identity.tenant.clone(),
            status: std::sync::atomic::AtomicU8::new(PREPARATION_PREPARING),
            files_total: std::sync::atomic::AtomicU64::new(PREPARATION_UNKNOWN),
            files_done: std::sync::atomic::AtomicU64::new(0),
            bytes_total: std::sync::atomic::AtomicU64::new(PREPARATION_UNKNOWN),
            bytes_done: std::sync::atomic::AtomicU64::new(0),
            finished_at: std::sync::atomic::AtomicU64::new(0),
            created_at: std::sync::atomic::AtomicU64::new(now_unix()),
            outcome: Mutex::new(None),
        }
    }

    fn is_terminal(&self) -> bool {
        self.status.load(Ordering::Relaxed) != PREPARATION_PREPARING
    }

    /// One hashed file left the pipeline; bytes are unknown when the file
    /// itself failed, which fails the whole preparation right after.
    fn record_file_done(&self, bytes: Option<u64>) {
        self.files_done.fetch_add(1, Ordering::Relaxed);
        if let Some(bytes) = bytes {
            self.bytes_done.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn set_totals(&self, files: u64, bytes: u64) {
        self.files_total.store(files, Ordering::Relaxed);
        self.bytes_total.store(bytes, Ordering::Relaxed);
    }

    fn complete(&self, created: CreatedGrant) {
        let mut outcome = self.outcome.lock().expect("grant preparation poisoned");
        *outcome = Some(Ok(created));
        drop(outcome);
        self.finish(PREPARATION_COMPLETE);
    }

    fn fail(&self, status: u16, message: String) {
        let mut outcome = self.outcome.lock().expect("grant preparation poisoned");
        *outcome = Some(Err((status, message)));
        drop(outcome);
        self.finish(PREPARATION_FAILED);
    }

    fn finish(&self, status: u8) {
        self.finished_at.store(now_unix(), Ordering::Relaxed);
        self.status.store(status, Ordering::Relaxed);
    }

    fn snapshot(&self) -> serde_json::Value {
        let known = |value: u64| (value != PREPARATION_UNKNOWN).then_some(value);
        let outcome = self.outcome.lock().expect("grant preparation poisoned");
        let (url, grant, error, error_status) = match &*outcome {
            Some(Ok(created)) => (
                Some(created.url.clone()),
                Some(created.grant.clone()),
                None,
                None,
            ),
            Some(Err((status, message))) => (None, None, Some(message.clone()), Some(*status)),
            None => (None, None, None, None),
        };
        json!({
            "id": self.id,
            "status": match self.status.load(Ordering::Relaxed) {
                PREPARATION_COMPLETE => "complete",
                PREPARATION_FAILED => "failed",
                _ => "preparing",
            },
            "files_total": known(self.files_total.load(Ordering::Relaxed)),
            "files_done": self.files_done.load(Ordering::Relaxed),
            "bytes_total": known(self.bytes_total.load(Ordering::Relaxed)),
            "bytes_done": self.bytes_done.load(Ordering::Relaxed),
            "url": url,
            "grant": grant,
            "error": error,
            "error_status": error_status,
        })
    }
}

/// Per-App preparation state; lives and dies with the process, so a restart
/// loses pending preparations by design.
#[derive(Default)]
pub(crate) struct GrantPreparationRegistry {
    by_id: HashMap<String, Arc<GrantPreparation>>,
    /// One in-flight preparation per (tenant, admin subject): a second
    /// create-share from the same session answers 409 instead of doubling
    /// the hashing work.
    in_flight: HashMap<(String, String), String>,
}

fn sweep_preparations(registry: &mut GrantPreparationRegistry) {
    let now = now_unix();
    let finished_cutoff = now.saturating_sub(PREPARATION_TTL_SECS);
    let stale_cutoff = now.saturating_sub(PREPARATION_STALE_SECS);
    registry.by_id.retain(|_, preparation| {
        if preparation.is_terminal() {
            preparation.finished_at.load(Ordering::Relaxed) > finished_cutoff
        } else {
            preparation.created_at.load(Ordering::Relaxed) > stale_cutoff
        }
    });
    registry
        .in_flight
        .retain(|_, id| registry.by_id.contains_key(id));
}

/// Frees a settled job's one-in-flight slot, but only while it is still that
/// job's own: the stale sweep can drop a hung preparation and let the session
/// start a new one, and the zombie's late cleanup must not delete the new
/// preparation's slot with it.
fn release_preparation_slot(
    registry: &mut GrantPreparationRegistry,
    key: &(String, String),
    id: &str,
) {
    if registry.in_flight.get(key).is_some_and(|slot| slot == id) {
        registry.in_flight.remove(key);
    }
}

fn begin_grant_preparation(
    app: &App,
    identity: &auth::AdminIdentity,
) -> ApiResult<Arc<GrantPreparation>> {
    let mut registry = app
        .grant_preparations
        .lock()
        .expect("grant preparations poisoned");
    sweep_preparations(&mut registry);
    let key = (identity.tenant.clone(), identity.subject.clone());
    if let Some(id) = registry.in_flight.get(&key) {
        let live = registry
            .by_id
            .get(id)
            .is_some_and(|preparation| !preparation.is_terminal());
        if live {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "a link preparation is already running for this session; wait for it to finish",
            ));
        }
        registry.in_flight.remove(&key);
    }
    let preparation = Arc::new(GrantPreparation::new(identity));
    registry.in_flight.insert(key, preparation.id.clone());
    registry
        .by_id
        .insert(preparation.id.clone(), Arc::clone(&preparation));
    Ok(preparation)
}

/// Everything `create_library_grant` needs, parked for the detached job.
struct PreparationJob {
    directory: Option<String>,
    requested: Vec<String>,
    max_files: usize,
    options: GrantOptions,
}

/// The detached half of an async grant creation: same permit, same operation
/// guard, same insert pipeline as the old synchronous request path.
async fn run_grant_preparation(
    app: Arc<App>,
    preparation: Arc<GrantPreparation>,
    identity: auth::AdminIdentity,
    base: String,
    job: PreparationJob,
) {
    let tenant = identity.tenant.clone();
    let subject = identity.subject.clone();
    let future = prepare_grant_files(&app, &preparation, &identity, &base, job);
    // A panic in the pipeline must not strand the page on "preparing".
    let outcome = futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(future)).await;
    match outcome {
        Ok(Ok(created)) => preparation.complete(created),
        Ok(Err(error)) => preparation.fail(error.0, error.1),
        Err(_) => preparation.fail(
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            "preparing this link failed unexpectedly".to_owned(),
        ),
    }
    let mut registry = app
        .grant_preparations
        .lock()
        .expect("grant preparations poisoned");
    release_preparation_slot(&mut registry, &(tenant, subject), &preparation.id);
    sweep_preparations(&mut registry);
}

async fn prepare_grant_files(
    app: &Arc<App>,
    preparation: &Arc<GrantPreparation>,
    identity: &auth::AdminIdentity,
    base: &str,
    job: PreparationJob,
) -> Result<CreatedGrant, (u16, String)> {
    let failure = |error: ApiError| (error.status.as_u16(), error.message);
    let _grant_permit = app.outbound_grant_permits.try_acquire().map_err(|_| {
        (
            StatusCode::TOO_MANY_REQUESTS.as_u16(),
            "too many grant preparations; try again later".to_owned(),
        )
    })?;
    let PreparationJob {
        directory,
        requested,
        max_files,
        options,
    } = job;
    let paths = match directory {
        Some(directory) => {
            let root = library_root(app, &identity.tenant);
            let directory =
                automation_directory(app, &identity.tenant, &directory).map_err(failure)?;
            tokio::task::spawn_blocking(move || {
                enumerate_automation_files(&root, &directory, MAX_LIBRARY_PROJECT_FILES)
            })
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    "enumerate outbound files failed".to_owned(),
                )
            })?
            .map_err(failure)?
        }
        None => requested,
    };
    create_library_grant(
        app,
        base,
        identity,
        &paths,
        max_files,
        options,
        Some(preparation),
    )
    .await
    .map_err(failure)
}

pub async fn outbound_grant_preparation(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_operator(&app, &headers)?;
    let preparation = {
        let mut registry = app
            .grant_preparations
            .lock()
            .expect("grant preparations poisoned");
        sweep_preparations(&mut registry);
        registry.by_id.get(&id).cloned()
    };
    let preparation = preparation
        .filter(|preparation| preparation.tenant == identity.tenant)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, PREPARATION_LOST_MESSAGE))?;
    Ok(Json(preparation.snapshot()))
}

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
            if !valid_hex(stripe, 2) || !valid_outbound_upload_id(digest) {
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
    valid_hex(value, 64)
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

/// Shared prologue of both grant creation routes: parse the body and run the
/// request-scoped validation. The synchronous route is a pinned contract
/// (the CLI decodes its 200 body), so both routes must agree on it.
async fn validated_grant_create(
    app: &Arc<App>,
    identity: &auth::AdminIdentity,
    request: Request,
) -> ApiResult<(
    CreateOutboundRequest,
    Option<crate::store::NotificationPolicy>,
    Option<String>,
)> {
    let Json(request) = Json::<CreateOutboundRequest>::from_request(request, app)
        .await
        .map_err(|error| ApiError::new(error.status(), error.body_text()))?;
    let notifications = super::notifications::creation_policy(
        app,
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
    Ok((request, notifications, password_hash))
}

/// The synchronous 200 body the CLI and scripts decode once a grant lands.
fn grant_created_response(created: CreatedGrant) -> Response {
    let CreatedGrant {
        grant,
        url,
        operation_id,
    } = created;
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "grant": grant, "url": url, "operation_id": operation_id })),
    )
        .into_response()
}

/// Answers 202 with a preparation handle and detaches hashing for the web
/// page, which polls `outbound_grant_preparation` for live progress. The
/// pinned CLI keeps using the synchronous `create_outbound_grant`.
pub async fn create_outbound_grant_preparation(
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
    let (request, notifications, password_hash) =
        validated_grant_create(&app, &identity, request).await?;
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
        // Cheap shape and mount sanity check before answering 202; the real
        // walk runs in the preparation job.
        automation_directory(&app, &identity.tenant, &directory_name)?;
        return start_preparation(
            &app,
            &headers,
            &identity,
            PreparationJob {
                directory: Some(directory_name),
                requested: Vec::new(),
                max_files: MAX_LIBRARY_PROJECT_FILES,
                options: GrantOptions {
                    workflow: None,
                    automation: None,
                    label: request
                        .label
                        .filter(|label| !label.trim().is_empty())
                        .or(Some(directory_label)),
                    password_hash,
                    expires_days: request.expires_days,
                    max_downloads: request.max_downloads,

                    notifications,
                },
            },
        );
    }
    if let Some(paths) = request.paths.as_deref() {
        if has_legacy_fields {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "paths cannot be combined with link_id, upload_id, or file_index",
            ));
        }
        return start_preparation(
            &app,
            &headers,
            &identity,
            PreparationJob {
                directory: None,
                requested: paths.to_vec(),
                max_files: MAX_LIBRARY_PATHS_FILES,
                options: GrantOptions {
                    workflow: None,
                    automation: None,
                    label: request.label,
                    password_hash,
                    expires_days: request.expires_days,
                    max_downloads: request.max_downloads,

                    notifications,
                },
            },
        );
    }
    Err(ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "paths or directory is required",
    ))
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
    let (request, notifications, password_hash) =
        validated_grant_create(&app, &identity, request).await?;
    let has_legacy_fields =
        request.link_id.is_some() || request.upload_id.is_some() || request.file_index.is_some();
    if let Some(directory_name) = request.directory {
        if request.paths.is_some() || has_legacy_fields {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "directory cannot be combined with paths, link_id, upload_id, or file_index",
            ));
        }
        let base = admin::base_url(&app, &headers);
        let directory_label = library_directory_label(&directory_name);
        let directory = automation_directory(&app, &identity.tenant, &directory_name)?;
        let root = library_root(&app, &identity.tenant);
        let paths = tokio::task::spawn_blocking(move || {
            enumerate_automation_files(&root, &directory, MAX_LIBRARY_PROJECT_FILES)
        })
        .await
        .map_err(|_| ApiError::internal("enumerate outbound files failed"))??;
        let created = create_library_grant(
            &app,
            &base,
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
            None,
        )
        .await?;
        return Ok(grant_created_response(created));
    }
    if let Some(paths) = request.paths.as_deref() {
        if has_legacy_fields {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "paths cannot be combined with link_id, upload_id, or file_index",
            ));
        }
        let base = admin::base_url(&app, &headers);
        let created = create_library_grant(
            &app,
            &base,
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
            None,
        )
        .await?;
        return Ok(grant_created_response(created));
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

/// Answers 202 with a preparation handle and detaches the hashing job; the
/// page polls `outbound_grant_preparation` for live progress and the link.
fn start_preparation(
    app: &Arc<App>,
    headers: &HeaderMap,
    identity: &auth::AdminIdentity,
    job: PreparationJob,
) -> ApiResult<Response> {
    let preparation = begin_grant_preparation(app, identity)?;
    let base = admin::base_url(app, headers);
    tokio::task::spawn(run_grant_preparation(
        Arc::clone(app),
        Arc::clone(&preparation),
        identity.clone(),
        base,
        job,
    ));
    let mut response = Json(json!({
        "preparation_id": preparation.id,
        "preparation": preparation.snapshot(),
    }))
    .into_response();
    *response.status_mut() = StatusCode::ACCEPTED;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

struct CreatedGrant {
    grant: serde_json::Value,
    url: String,
    operation_id: Option<String>,
}

async fn create_library_grant(
    app: &Arc<App>,
    base: &str,
    identity: &auth::AdminIdentity,
    requested: &[String],
    max_files: usize,
    options: GrantOptions,
    progress: Option<&GrantPreparation>,
) -> ApiResult<CreatedGrant> {
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
    let tenant = identity.tenant.clone();
    let cache_app = Arc::clone(app);
    if let Some(progress) = progress {
        progress.set_totals(selections.len() as u64, total_bytes);
    }
    let hashed = futures_util::stream::iter(selections.into_iter().map(|(name, path)| {
        let hash_root = hash_root.clone();
        let proof_root = proof_root.clone();
        let tenant = tenant.clone();
        let cache_app = Arc::clone(&cache_app);
        async move {
            let _permit = LIBRARY_HASH_PERMITS
                .acquire()
                .await
                .map_err(|_| ApiError::internal("hash outbound files failed"))?;
            let hashed = tokio::task::spawn_blocking(move || {
                hash_library_file(
                    &hash_root,
                    &name,
                    &path,
                    &proof_root,
                    max,
                    &tenant,
                    &cache_app.root_cache,
                )
            })
            .await
            .map_err(|_| ApiError::internal("hash outbound files failed"))?
            .map_err(|_| ApiError::not_found());
            if let Some(progress) = progress {
                progress.record_file_done(hashed.as_ref().ok().map(|file| file.bytes));
            }
            hashed
        }
    }))
    .buffered(LIBRARY_HASH_CONCURRENCY)
    .collect::<Vec<_>>()
    .await
    .into_iter()
    .collect::<ApiResult<Vec<_>>>()?;
    app.root_cache.persist();
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
    let base_url = base;
    Ok(CreatedGrant {
        grant: public,
        url: format!("{base_url}/s/{token}"),
        operation_id,
    })
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
    tenant: &str,
    cache: &RootCache,
) -> io::Result<OutboundGrantFile> {
    let grant_file = |object: &ObjectId| -> io::Result<OutboundGrantFile> {
        Ok(OutboundGrantFile {
            source: path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/"),
            name: name.to_owned(),
            suite: "blake3".to_owned(),
            root: hex::encode(object.root),
            bytes: object.length,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        })
    };
    // Cache first: an unchanged source (same size and mtime) re-shares
    // without the full re-read. Large files still need their range-proof
    // catalog; if the cached root cannot produce one, fall through to the
    // honest full hash.
    let stat = std::fs::symlink_metadata(path)?;
    let (size, mtime) = (stat.len(), mtime_nanos(&stat));
    if let Some(hex_root) = cache.lookup(tenant, path, size, mtime) {
        let object = hex::decode(&hex_root)
            .ok()
            .and_then(|bytes| TryInto::<[u8; 32]>::try_into(bytes).ok())
            .map(|root| ObjectId {
                suite: 1,
                root,
                length: size,
            });
        if let Some(object) = object {
            let usable =
                size < BATCH_STAGE_BYTES || ensure_catalog(proof_root, path, &object).is_ok();
            if usable {
                return grant_file(&object);
            }
        }
    }
    let prepared = prepare_library_file(path, Suite::Blake3Bao64, None, max)?;
    let bytes = prepared.object_id().length;
    let object = prepared.object_id().clone();
    if bytes >= BATCH_STAGE_BYTES {
        ensure_catalog_from_prepared(proof_root, &prepared)?;
    }
    if bytes == size {
        cache.insert(tenant, path, size, mtime, hex::encode(object.root));
    }
    grant_file(&object)
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
    valid_hex(token, 32)
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
pub(crate) mod tests;
