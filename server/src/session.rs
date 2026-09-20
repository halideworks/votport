//! Upload sessions: one worker thread per session owns all VOT state.
//!
//! The VOT SDK objects (`PackageIngest`, `NativeFile`) are kept on a single
//! dedicated thread per session; async handlers talk to it over a bounded
//! channel. That serializes disk writes per session and keeps the SDK types
//! off the async executor entirely.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read as _;
#[cfg(test)]
use std::io::{Seek as _, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

use vot_sdk::coverage::ObjectCoverage;
use vot_sdk::object::{InMemoryObjectBuilder, ObjectId, Suite};
use vot_sdk::package::{EntryStorage, PackageEntry, PackageIngest};
use vot_sdk::verify::verify_range;
use vot_sdk_file::{CommitProfile, NativeFile, RangeStatus};

use crate::paths;
use crate::store::{
    now_unix, FileRecord, LogEvent, PersistedUploadFile, PersistedUploadSession, Store,
    UploadRecord,
};

pub const MAX_SEAL_BYTES: usize = 1024 * 1024;
pub const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PAGES: u64 = 4096;
pub const MAX_ENTRIES: usize = 2_000_000;
/// Per-session bound on stored entries: every entry's state stays resident
/// for the session's whole life, so the count is capped regardless of the
/// link byte budget. The browser UI fixture handles 100k files, leaving
/// 2.6x headroom.
pub const MAX_SESSION_ENTRIES: usize = 262_144;
// Reserve room for one file, its journal, and metadata when bytes are zero.
const ENTRY_ADMISSION_BYTES: u64 = 4096;
const ENTRY_ADMISSION_FLOOR: u64 = 256;
/// Covered bytes the client sends per chunk request.
pub const CHUNK_BYTES: u64 = 8 * 1024 * 1024;
/// Body cap for one chunk request (data + proof + slack).
pub const MAX_CHUNK_BODY_BYTES: usize = 9 * 1024 * 1024;
const MAX_NAME_ATTEMPTS: u32 = 100;

#[derive(Clone, Debug)]
pub struct SessionError {
    pub status: u16,
    pub message: String,
}

impl SessionError {
    fn bad(message: impl Into<String>) -> Self {
        Self {
            status: 422,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: 409,
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: 503,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: 500,
            message: message.into(),
        }
    }
}

type Reply<T> = oneshot::Sender<Result<T, SessionError>>;

pub enum Cmd {
    Seal {
        bytes: Bytes,
        reply: Reply<u64>,
        _lease: SessionLease,
    },
    Page {
        bytes: Bytes,
        reply: Reply<u64>,
        _lease: SessionLease,
    },
    Begin {
        reply: Reply<Vec<EntryInfo>>,
        _lease: SessionLease,
        stopping: Arc<AtomicBool>,
    },
    Chunk {
        entry: usize,
        offset: u64,
        proof: Bytes,
        data: Bytes,
        reply: Reply<ChunkProgress>,
        _lease: SessionLease,
    },
    Finish {
        reply: Reply<FinishReport>,
        _lease: SessionLease,
    },
    /// Sender gave up; lets the worker record a "cancelled" event before it
    /// exits, instead of the generic "interrupted" the drop path records.
    Abort {
        reply: Reply<()>,
        _lease: SessionLease,
    },
    /// Process shutdown: checkpoint, keep staging on disk for boot
    /// re-attach, and exit. The reply reports whether the checkpoint
    /// persisted; an error means the resume point stopped advancing.
    Suspend {
        reply: oneshot::Sender<Result<(), String>>,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct EntryInfo {
    pub index: usize,
    pub path: String,
    pub stored_as: String,
    pub bytes: u64,
    pub complete: bool,
    /// Bytes verified and written contiguously from offset zero. Chunks land
    /// out of order, so this is the offset a resuming sender restarts from;
    /// the total accepted count would make it skip holes.
    pub covered_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChunkProgress {
    pub accepted: bool,
    pub replay: bool,
    pub covered_bytes: u64,
    pub total_bytes: u64,
    pub complete: bool,
    /// Bytes the whole session has accepted so far, for the admin's live view.
    pub received: u64,
    /// The session was re-attached after a restart and its coverage restarted
    /// from the checkpointed prefix: the sender must call begin again to
    /// learn where to resume. Cleared by the next begin.
    pub rebegin: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct FinishReport {
    pub upload_id: String,
    pub files: Vec<FileRecord>,
    /// Bytes this session accepted, for the creation-limit refund: a session
    /// that finished on already-delivered files hands nothing back.
    #[serde(skip)]
    pub received: u64,
}

/// Everything a worker needs that outlives one request.
pub struct WorkerSetup {
    pub store: Arc<Store>,
    pub link_id: String,
    pub tenant: String,
    /// Client address taken at session creation; empty on resume after a
    /// restart, where no request supplied it.
    pub client_ip: String,
    /// Absolute directory this session publishes into.
    pub dest_dir: PathBuf,
    pub destinations: Arc<crate::receiving::Destinations>,
    /// Prefix of `dest_dir` relative to the receive root, for records.
    pub dest_rel: String,
    pub expected_package: ObjectId,
    pub max_total_bytes: u64,
    pub allow_hidden: bool,
    pub signer: Arc<crate::receipt::ReceiptSigner>,
    /// The session id bytes, carried into issued receipts.
    pub session_id: [u8; 16],
    /// When the session was created, for duration/rate feedback.
    pub started_at: u64,
    /// A gap between sender commands at least this long is logged as quiet.
    pub quiet_after_secs: u64,
    /// Where an ended session reports for the failure notification.
    pub ended: mpsc::UnboundedSender<SessionEnded>,
    /// Paces checkpoint-failure warnings so a persistently failing
    /// checkpoint stays visible without flooding the log.
    pub checkpoint_warn: CheckpointWarnPacer,
}

/// A session that ended without publishing, as handed to the notifier.
#[derive(Clone, Debug)]
pub struct SessionEnded {
    pub notifications: Option<crate::store::NotificationPolicy>,
    pub tenant: String,
    pub link_id: String,
    pub label: String,
    pub event: crate::store::SessionEvent,
}

/// The transfer log grows one event per file; a huge package would otherwise
/// write thousands of entries into the link's JSON.
const LOG_CAP: usize = 200;

/// Quiet threshold from the idle timeout: a tenth of it, at least five
/// seconds, so a test with a short timeout can provoke one.
pub fn quiet_after_secs(session_idle_secs: u64) -> u64 {
    if session_idle_secs == 0 {
        return 60;
    }
    (session_idle_secs / 10).max(5)
}

#[derive(Default)]
struct TransferLog {
    events: Vec<LogEvent>,
    elided: u64,
}

impl TransferLog {
    fn push(&mut self, event: LogEvent) {
        if self.events.len() >= LOG_CAP {
            self.elided += 1;
            return;
        }
        self.events.push(event);
    }

    fn plain(at: u64, kind: &str, count: Option<u64>) -> LogEvent {
        LogEvent {
            at,
            kind: kind.to_owned(),
            path: None,
            bytes: None,
            secs: None,
            count,
        }
    }

    /// The outcome survives the cap: a record must not end on "published"
    /// when the session finished.
    fn terminal(&mut self, at: u64, kind: &str, count: Option<u64>) {
        self.events.push(Self::plain(at, kind, count));
    }

    /// The events with the elided tail, for a record. Not consuming: a
    /// failed commit retries with the same log.
    fn snapshot(&self) -> Vec<LogEvent> {
        let mut events = self.events.clone();
        if self.elided > 0 {
            events.push(Self::plain(now_unix(), "elided", Some(self.elided)));
        }
        events
    }
}

/// Shared control for one native-push admission and its eventual connection.
#[derive(Clone, Default)]
pub struct PushControl {
    pub(crate) resume_key: Option<String>,
    directory_lock: Arc<Mutex<Option<fs::File>>>,
    parked: Arc<AtomicBool>,
    cancellation: vot_cli::CancellationHandle,
    connected: Arc<AtomicBool>,
    aborted: Arc<AtomicBool>,
}

impl std::fmt::Debug for PushControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PushControl")
            .field("connected", &self.is_connected())
            .field("aborted", &self.is_aborted())
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish()
    }
}

impl PushControl {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn resumable(key: String, lock: Option<fs::File>) -> Self {
        let parked = lock.is_none();
        Self {
            resume_key: Some(key),
            directory_lock: Arc::new(Mutex::new(lock)),
            parked: Arc::new(AtomicBool::new(parked)),
            ..Self::default()
        }
    }

    pub(crate) fn staging_dir(&self, setup: &WorkerSetup) -> PathBuf {
        self.resume_key.as_ref().map_or_else(
            || push_staging_dir(setup),
            |key| {
                setup
                    .dest_dir
                    .join(".vot-stage")
                    .join(format!(".vot-push-{key}"))
            },
        )
    }

    pub(crate) fn park(&self) -> bool {
        if self.resume_key.is_none() {
            return false;
        }
        self.parked.store(true, Ordering::Release);
        self.connected.store(false, Ordering::Release);
        self.directory_lock
            .lock()
            .expect("push directory poisoned")
            .take();
        true
    }

    /// Claims creation of the shared receive state; later rails join it.
    pub fn connect(&self) -> bool {
        self.connected
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    #[must_use]
    pub fn cancellation(&self) -> vot_cli::CancellationHandle {
        self.cancellation.clone()
    }

    pub fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        self.cancel();
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

// Staging identity and verified coverage outlive the bounded set of open sinks.
struct StagedFile {
    destinations: Arc<crate::receiving::Destinations>,
    destination: PathBuf,
    staging: PathBuf,
    journal: PathBuf,
    incarnation: [u8; 16],
    profile: CommitProfile,
    nas_contract: vot_sdk_file::NasContract,
    coverage: Mutex<ObjectCoverage>,
    active: Option<NativeFile>,
    active_directory: Option<vot_sdk_file::ReceiveDirectory>,
    reopened: bool,
    parked_metadata: Option<(u64, u64, u64, i64, i64, i64, i64)>,
    preserve: bool,
}

impl StagedFile {
    fn new(
        native: NativeFile,
        destination: PathBuf,
        coverage: ObjectCoverage,
        profile: CommitProfile,
        destinations: Arc<crate::receiving::Destinations>,
    ) -> Self {
        let mut staged = Self {
            nas_contract: destinations.contract(),
            destinations,
            destination,
            staging: native.staging_path().to_path_buf(),
            journal: native.journal_path().to_path_buf(),
            incarnation: native.incarnation(),
            profile,
            coverage: Mutex::new(coverage),
            active: Some(native),
            active_directory: None,
            reopened: false,
            parked_metadata: None,
            preserve: false,
        };
        staged.park();
        staged
    }

    fn reopen(&mut self) -> Result<(), SessionError> {
        self.destinations
            .check_live()
            .map_err(SessionError::internal)?;
        if self.active.is_none() {
            let state = self.resume_state();
            let directory = self.directory()?;
            let native = directory
                .resume(
                    self.coverage
                        .get_mut()
                        .expect("staging coverage poisoned")
                        .object_id(),
                    self.destination
                        .file_name()
                        .ok_or_else(|| SessionError::internal("missing destination name"))?,
                    &state,
                )
                .map_err(|error| SessionError::internal(format!("reopen staging: {error}")))?;
            self.reopened |=
                self.parked_metadata.is_none() || self.parked_metadata != Self::metadata(&native);
            self.active = Some(native);
            self.active_directory = Some(directory);
        }
        Ok(())
    }

    fn native(&self) -> Result<&NativeFile, SessionError> {
        self.destinations
            .check_live()
            .map_err(SessionError::internal)?;
        self.active
            .as_ref()
            .ok_or_else(|| SessionError::internal("staging is not open"))
    }

    fn directory(&self) -> Result<vot_sdk_file::ReceiveDirectory, SessionError> {
        self.destinations
            .check_live()
            .map_err(SessionError::internal)?;
        if let Some(directory) = &self.active_directory {
            return Ok(directory.clone());
        }
        self.destinations
            .directory(
                self.destination
                    .parent()
                    .ok_or_else(|| SessionError::internal("missing destination parent"))?,
                false,
            )
            .map_err(SessionError::internal)
    }

    fn resume_state(&self) -> vot_sdk_file::ResumeState {
        vot_sdk_file::ResumeState {
            staging_name: self.staging.file_name().unwrap_or_default().to_owned(),
            journal_name: self.journal.file_name().unwrap_or_default().to_owned(),
            incarnation: self.incarnation,
            profile: self.profile,
            nas_contract: self.nas_contract,
            runs: self
                .coverage
                .lock()
                .expect("staging coverage poisoned")
                .runs()
                .collect(),
        }
    }

    fn metadata(native: &NativeFile) -> Option<(u64, u64, u64, i64, i64, i64, i64)> {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = native.read_staging().ok()?.metadata().ok()?;
        Some((
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ))
    }

    fn record(&self, verified: &vot_sdk::verify::VerifiedSlice<'_>) -> Result<(), SessionError> {
        self.coverage
            .lock()
            .expect("staging coverage poisoned")
            .accept(verified)
            .map_err(|error| {
                SessionError::internal(format!("record verified coverage: {error:?}"))
            })?;
        Ok(())
    }

    fn park(&mut self) {
        if let Some(native) = self.active.take() {
            self.preserve |= native.recovery_required();
            self.parked_metadata = Self::metadata(&native);
            native.abandon();
        }
        self.active_directory = None;
    }

    fn abandon(mut self) {
        self.preserve = true;
        self.park();
    }

    fn staging_path(&self) -> &std::path::Path {
        &self.staging
    }
    fn journal_path(&self) -> &std::path::Path {
        &self.journal
    }
    fn incarnation(&self) -> [u8; 16] {
        self.incarnation
    }

    fn progress(&self) -> vot_sdk_file::Progress {
        let coverage = self.coverage.lock().expect("staging coverage poisoned");
        vot_sdk_file::Progress {
            covered_bytes: coverage.covered_bytes(),
            prefix_bytes: coverage.contiguous_prefix(),
            total_bytes: coverage.object_id().length,
            fragments: coverage.fragment_count(),
        }
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if self.preserve || self.destinations.check_live().is_err() {
            self.park();
            return;
        }
        if self.active.is_none() {
            // Reacquire the journal identity before the SDK removes its files.
            if self.reopen().is_err() {
                warn_once_per_interval(
                    "staged file drop reopen",
                    &STAGED_DROP_REOPEN_WARN,
                    "reopen failed",
                    "staging could not be reopened on drop; it stays on disk for recovery",
                );
            }
        }
    }
}

struct FileState {
    display_path: String,
    /// Admitted path components joined by NUL; component names can never
    /// contain NUL, so one String replaces a Vec of per-component heaps.
    stored_components: String,
    object: ObjectId,
    native: Option<StagedFile>,
    published: bool,
    receipt: bool,
    checkpointed: Mutex<Option<(u64, bool, bool)>>,
    /// When this file's first range was accepted, for the publish timing.
    first_range_at: Option<u64>,
    /// Re-attached after a restart: the staged bytes are re-hashed against
    /// the announced object before publish, since the resumed coverage is
    /// trusted bookkeeping rather than verified ranges.
    rehash: bool,
}

// One Phase exists per session; the variant size gap is irrelevant here.
#[allow(clippy::large_enum_variant)]
enum Phase {
    AwaitSeal,
    Pages {
        ingest: PackageIngest,
        entries: Vec<PackageEntry>,
        pages_pushed: u64,
        max_entries: usize,
    },
    Receiving {
        files: Vec<FileState>,
    },
    Done,
}

/// Runs the per-session worker. The caller creates the channel, registers the
/// sender, then passes the receiver here so the thread cannot touch disk
/// before the session is in the map.
pub fn spawn_worker(setup: WorkerSetup, receiver: mpsc::Receiver<Cmd>) {
    spawn_worker_from(setup, receiver, Phase::AwaitSeal, false, 0, Vec::new());
}

/// `already` is what a re-attached session had covered before the restart,
/// so the byte count reported to the admin spans the whole transfer.
/// `recovered` carries per-file events for publications the resume itself
/// completed (audit finding 499), replayed into the log after "reattached".
fn spawn_worker_from(
    setup: WorkerSetup,
    mut receiver: mpsc::Receiver<Cmd>,
    mut phase: Phase,
    resumed: bool,
    already: u64,
    recovered: Vec<LogEvent>,
) {
    std::thread::spawn(move || {
        // Feedback for the admin: bytes newly accepted this session and the
        // last error handed to the sender, recorded if the session dies.
        let mut received: u64 = 0;
        let mut persist = PersistTracker::new();
        let mut rebegin = resumed;
        let mut suspended = false;
        // Consecutive mid-transfer checkpoints that failed to persist. The
        // rate-limited warning keeps the failure visible; this counter lets
        // the accept path report when the resume point recovers.
        let mut checkpoint_failures: u64 = 0;
        let mut replays: u64 = 0;
        let mut rejected: u64 = 0;
        let mut last_error: Option<String> = None;
        // When the sender was last heard from. The worker only exits long
        // after that (the idle sweep), so stamping the event with now_unix()
        // there would date a five-minute failure two days late.
        let mut last_seen = now_unix();
        let mut log = TransferLog::default();
        if resumed {
            let published = match &phase {
                Phase::Receiving { files } => files.iter().filter(|f| f.published).count(),
                _ => 0,
            };
            log.push(TransferLog::plain(
                now_unix(),
                "reattached",
                Some(published as u64),
            ));
        }
        // Publications completed by the resume itself (audit finding 499);
        // empty for a fresh worker.
        for event in recovered {
            log.push(event);
        }
        // A resumed worker's first wait measures uptime, not sender silence.
        let mut heard = !resumed;
        let mut opened = resumed;
        // Remembers the error message, then hands the result to the sender.
        macro_rules! send_noted {
            ($reply:expr, $result:expr) => {{
                let result = $result;
                if let Err(error) = &result {
                    last_error = Some(error.message.clone());
                }
                let _ = $reply.send(result);
            }};
        }
        // A non-chunk command drained while batching chunks waits here for
        // the next iteration instead of going back on the channel.
        let mut pending: Option<Cmd> = None;
        loop {
            // Quiet is measured only across a real wait on the channel; a
            // command carried over from a batch drain waited on the server.
            // The pause itself comes from the monotonic clock: two wall-clock
            // reads would let a forward step mid-transfer fabricate a long
            // quiet event that evicts a real one from the kept log (audit
            // finding 406). `arrived` stays the wall stamp for the event.
            let waiting_since = Instant::now();
            let (cmd, waited) = match pending.take() {
                Some(cmd) => (cmd, false),
                None => match receiver.blocking_recv() {
                    Some(cmd) => (cmd, true),
                    None => {
                        break;
                    }
                },
            };
            let arrived = now_unix();
            let silent = waiting_since.elapsed().as_secs();
            if waited && heard && silent >= setup.quiet_after_secs {
                log.push(LogEvent {
                    at: arrived,
                    kind: "quiet".to_owned(),
                    path: None,
                    bytes: None,
                    secs: Some(silent),
                    count: None,
                });
            }
            heard = true;
            last_seen = arrived;
            match cmd {
                Cmd::Seal {
                    bytes,
                    reply,
                    _lease,
                } => {
                    send_noted!(reply, handle_seal(&setup, &mut phase, &bytes));
                }
                Cmd::Page {
                    bytes,
                    reply,
                    _lease,
                } => {
                    send_noted!(reply, handle_page(&mut phase, &bytes));
                }
                Cmd::Begin {
                    reply,
                    _lease,
                    stopping,
                } => {
                    let result = if stopping.load(Ordering::Acquire) {
                        Err(SessionError::unavailable(
                            "the server is shutting down; retry after restart",
                        ))
                    } else {
                        handle_begin(&setup, &mut phase)
                    };
                    if result.is_ok() && !opened {
                        log.push(TransferLog::plain(now_unix(), "opened", None));
                        opened = true;
                    }
                    rebegin = false;
                    // A failed begin has consumed the pages: the phase is
                    // already Done, the worker exits below, and the exit-time
                    // "interrupted" fall-through is skipped. Record it here.
                    if let Err(error) = &result {
                        if matches!(phase, Phase::Done) {
                            record_event(
                                &setup,
                                already + received,
                                last_seen,
                                "rejected",
                                error.message.clone(),
                                replays,
                                rejected,
                            );
                        }
                    }
                    send_noted!(reply, result);
                }
                Cmd::Chunk {
                    entry,
                    offset,
                    proof,
                    data,
                    reply,
                    _lease,
                } => {
                    // Drain the rest of the in-flight window so the batch
                    // verifies and writes in parallel. The first non-chunk
                    // command ends the batch and runs on the next iteration.
                    let mut batch = vec![BatchChunk {
                        entry,
                        offset,
                        proof,
                        data,
                        reply,
                        _lease,
                    }];
                    while batch.len() < MAX_CHUNK_BATCH {
                        match receiver.try_recv() {
                            Ok(Cmd::Chunk {
                                entry,
                                offset,
                                proof,
                                data,
                                reply,
                                _lease,
                            }) => batch.push(BatchChunk {
                                entry,
                                offset,
                                proof,
                                data,
                                reply,
                                _lease,
                            }),
                            Ok(other) => {
                                pending = Some(other);
                                break;
                            }
                            Err(_) => break,
                        }
                    }
                    let entries: Vec<usize> = batch.iter().map(|item| item.entry).collect();
                    let published_before: Vec<bool> = match &phase {
                        Phase::Receiving { files } => entries
                            .iter()
                            .map(|index| files.get(*index).is_some_and(|file| file.published))
                            .collect(),
                        _ => Vec::new(),
                    };
                    let outcomes = accept_batch(&setup, &mut phase, &batch);
                    if let Phase::Receiving { files } = &mut phase {
                        let now = now_unix();
                        for (entry, outcome) in entries.iter().zip(&outcomes) {
                            if matches!(outcome, Ok(progress) if progress.accepted) {
                                if let Some(file) = files.get_mut(*entry) {
                                    file.first_range_at.get_or_insert(now);
                                }
                            }
                        }
                        let mut logged = HashSet::new();
                        for (index, was) in entries.iter().zip(&published_before) {
                            let Some(file) = files.get(*index) else {
                                continue;
                            };
                            if file.published && !was && logged.insert(*index) {
                                log.push(LogEvent {
                                    at: now,
                                    kind: "published".to_owned(),
                                    path: Some(file.display_path.clone()),
                                    bytes: Some(file.object.length),
                                    secs: file.first_range_at.map(|from| now.saturating_sub(from)),
                                    count: None,
                                });
                            }
                        }
                    }
                    let received_before = received;
                    for (item, outcome) in batch.into_iter().zip(outcomes) {
                        let outcome = outcome.map(|mut progress| {
                            progress.rebegin = rebegin;
                            progress
                        });
                        match &outcome {
                            Ok(progress) if progress.replay => replays += 1,
                            Ok(progress) if progress.accepted => {
                                received += item.data.len() as u64;
                            }
                            Ok(_) => {}
                            Err(_) => rejected += 1,
                        }
                        let outcome = outcome.map(|mut progress| {
                            progress.received = already + received;
                            progress
                        });
                        send_noted!(item.reply, outcome);
                    }
                    // Checkpoint covered progress past both the byte and the
                    // time floor, never per batch, so the fsync never paces accept.
                    if persist.should_checkpoint(received - received_before) {
                        if let Phase::Receiving { files } = &mut phase {
                            if checkpoint_session(&setup, files) {
                                // A failing checkpoint stops the resume point
                                // from advancing, so its recovery is worth one
                                // line naming how long the transfer flew dark.
                                if checkpoint_failures > 0 {
                                    tracing::info!(
                                        failures = checkpoint_failures,
                                        "mid-transfer checkpoint recovered; the resume point advances again"
                                    );
                                    checkpoint_failures = 0;
                                }
                            } else {
                                checkpoint_failures += 1;
                            }
                        }
                    }
                }
                Cmd::Finish { reply, _lease } => {
                    let report =
                        handle_finish(&setup, &mut phase, replays, rejected, received, &log);
                    send_noted!(reply, report);
                }
                Cmd::Abort { reply, _lease } => {
                    log.terminal(now_unix(), "cancelled", None);
                    let recorded = commit_partial(&setup, &mut phase, replays, rejected, &log);
                    if recorded {
                        forget_session(&setup);
                    } else {
                        preserve_phase(&setup, &mut phase);
                    }
                    record_event(
                        &setup,
                        already + received,
                        last_seen,
                        "cancelled",
                        "cancelled by the sender".to_owned(),
                        replays,
                        rejected,
                    );
                    phase = Phase::Done;
                    let _ = reply.send(if recorded { Ok(()) } else { Err(SessionError::internal("cancelled transfer retains recovery metadata because recording completion failed")) });
                }
                Cmd::Suspend { reply } => {
                    // Checkpoint the exact prefix, then release the staging
                    // handles without removing the files: boot re-attaches
                    // them. Sessions before begin have nothing persisted.
                    let persisted = preserve_phase(&setup, &mut phase);
                    suspended = true;
                    phase = Phase::Done;
                    let _ = reply.send(if persisted {
                        Ok(())
                    } else {
                        Err("checkpoint failed; the resume point keeps its last persisted state and the staging stays on disk for recovery".to_owned())
                    });
                }
            }
            if matches!(phase, Phase::Done) {
                break;
            }
        }
        if !matches!(phase, Phase::Done) && !suspended {
            log.terminal(last_seen, "interrupted", None);
            if commit_partial(&setup, &mut phase, replays, rejected, &log) {
                forget_session(&setup);
            } else {
                preserve_phase(&setup, &mut phase);
            }
            record_event(
                &setup,
                already + received,
                last_seen,
                "interrupted",
                last_error.unwrap_or_else(|| {
                    "session went idle and expired; the sender likely disconnected".to_owned()
                }),
                replays,
                rejected,
            );
        }
        // Dropping unpublished NativeFile values removes their staging.
    });
}

fn handle_seal(setup: &WorkerSetup, phase: &mut Phase, bytes: &[u8]) -> Result<u64, SessionError> {
    if !matches!(phase, Phase::AwaitSeal) {
        return Err(SessionError::conflict("seal was already provided"));
    }
    let ingest = PackageIngest::new_expected(bytes, &setup.expected_package)
        .map_err(|error| SessionError::bad(format!("seal rejected: {:?}", error.code())))?;
    let pages = ingest.page_count();
    if pages == 0 || pages > MAX_PAGES {
        return Err(SessionError::bad(format!(
            "manifest page count {pages} outside 1..={MAX_PAGES}"
        )));
    }
    *phase = Phase::Pages {
        ingest,
        entries: Vec::new(),
        pages_pushed: 0,
        max_entries: max_entries_for_bytes(setup.max_total_bytes),
    };
    Ok(pages)
}

/// The count limit follows the byte budget while retaining a small floor for
/// legitimate empty-file drops, and never exceeds the process-wide ceiling.
pub fn max_entries_for_bytes(max_total_bytes: u64) -> usize {
    let budget = max_total_bytes / ENTRY_ADMISSION_BYTES + ENTRY_ADMISSION_FLOOR;
    usize::try_from(budget)
        .unwrap_or(usize::MAX)
        .min(MAX_ENTRIES)
}

fn entry_count_within_limit(count: usize, max_total_bytes: u64) -> bool {
    count <= max_entries_for_bytes(max_total_bytes)
}

/// Refuses entry batches past [`MAX_SESSION_ENTRIES`]. Applied wherever a
/// session's entry list is first created: HTTP and push admission via
/// [`prepare_files`], boot and push replay via [`restore_files`].
fn check_session_entry_cap(count: usize) -> Result<(), SessionError> {
    if count > MAX_SESSION_ENTRIES {
        return Err(SessionError::bad(format!(
            "session exceeds the {MAX_SESSION_ENTRIES} entry cap"
        )));
    }
    Ok(())
}

fn handle_page(phase: &mut Phase, bytes: &[u8]) -> Result<u64, SessionError> {
    let Phase::Pages {
        ingest,
        entries,
        pages_pushed,
        max_entries,
    } = phase
    else {
        return Err(SessionError::conflict(
            "manifest pages are not expected in this state",
        ));
    };
    let page = ingest.push_page(bytes).map_err(|error| {
        SessionError::bad(format!("manifest page rejected: {:?}", error.code()))
    })?;
    let count = entries
        .len()
        .checked_add(page.entries().len())
        .ok_or_else(|| SessionError::bad("package entry count overflows"))?;
    if count > *max_entries {
        return Err(SessionError::bad(format!(
            "package exceeds {max_entries} entries"
        )));
    }
    let new_entries = page.into_entries();
    entries.extend(new_entries);
    *pages_pushed += 1;
    Ok(ingest.page_count().saturating_sub(*pages_pushed))
}

fn handle_begin(setup: &WorkerSetup, phase: &mut Phase) -> Result<Vec<EntryInfo>, SessionError> {
    // Begin is idempotent once receiving: a client that lost its connection
    // (or its page) calls it again to learn how far each entry got, and picks
    // up from there. Without this a reconnect could only start over.
    if let Phase::Receiving { files } = phase {
        for file in files.iter_mut() {
            if file.object.length == 0 && !file.published {
                publish_file(setup, file, || true)?;
            }
        }
        return Ok(entry_infos(setup, files));
    }
    let Phase::Pages { entries, .. } = phase else {
        return Err(SessionError::conflict(
            "begin is only valid after the seal and all pages",
        ));
    };
    let entries = std::mem::take(entries);
    let Phase::Pages { ingest, .. } = std::mem::replace(phase, Phase::Done) else {
        unreachable!("phase was matched as Pages above");
    };
    // finish() authenticates every buffered page against the expected root.
    let summary = ingest
        .finish()
        .map_err(|error| SessionError::bad(format!("manifest rejected: {:?}", error.code())))?;

    if summary.entries() != entries.len() as u64 {
        return Err(SessionError::bad(
            "package entry count does not match manifest",
        ));
    }

    if !entry_count_within_limit(entries.len(), setup.max_total_bytes) {
        return Err(SessionError::bad(format!(
            "package exceeds {} entries",
            max_entries_for_bytes(setup.max_total_bytes)
        )));
    }

    let mut total: u64 = 0;
    for entry in &entries {
        if !matches!(entry.storage(), EntryStorage::Direct) {
            return Err(SessionError::bad(
                "packed entries are not supported by votport",
            ));
        }
        for component in entry.path() {
            paths::admit_component(component, setup.allow_hidden).map_err(SessionError::bad)?;
        }
        validate_empty_object(&entry.object_id())?;
        total = total
            .checked_add(entry.object_id().length)
            .ok_or_else(|| SessionError::bad("total upload size overflows"))?;
    }
    // Full-fold collision guard (audit finding 503): the pinned manifest
    // folds keys per character, so one package can carry two spellings a
    // case-insensitive recipient collapses (ς/σ, ſ/s, ß/SS) and the second
    // publish overwrites the first. Write-time claims already key on the
    // full fold, so this only moves the refusal ahead of the transfer.
    let names: Vec<String> = entries
        .iter()
        .map(|entry| entry.path().collect::<Vec<_>>().join("/"))
        .collect();
    crate::paths::admit_portable_paths(names.iter().map(String::as_str))
        .map_err(SessionError::bad)?;
    if total > setup.max_total_bytes {
        return Err(SessionError::bad(format!(
            "upload of {total} bytes exceeds the {} byte limit for this link",
            setup.max_total_bytes
        )));
    }

    setup
        .store
        .check_route_manifest(&hex::encode(setup.session_id), || {
            route_manifest(entries.iter().map(|entry| {
                (
                    entry.path().collect::<Vec<_>>().join("/"),
                    entry.object_id(),
                )
            }))
        })
        .map_err(SessionError::bad)?;

    // A read failure also means finish cannot record the upload, so refuse
    // before opening destinations rather than leave untracked files.
    setup
        .store
        .link_metadata(&setup.tenant, &setup.link_id)
        .map_err(|error| SessionError::internal(format!("link read failed: {error}")))?
        .ok_or_else(|| SessionError::conflict("request link no longer exists"))?;

    let destinations = entries
        .iter()
        .map(|entry| (entry.path().map(str::to_owned).collect(), entry.object_id()))
        .collect::<Vec<_>>();
    let (files, allocation) = prepare_files(setup, &destinations, || true)?;
    persist_session(setup, &files)?;
    drop(allocation);
    *phase = Phase::Receiving { files };
    handle_begin(setup, phase)
}

/// Persist checkpoint pacing: a fast transfer's checkpoint needs both floors.
/// The byte floor keeps tiny updates from paying for a transaction, the time
/// floor keeps a fast transfer (40 GbE would cross the byte floor every
/// ~64 ms) from paying for one more often than the pacing interval, so the
/// fsync'd update never paces the accept path. A transfer that never crosses
/// the byte floor still checkpoints behind `MAX_PERSIST_INTERVAL`, so a slow
/// link bounds its crash-loss window at 5 seconds instead of the whole
/// transfer.
const PERSIST_BYTES: u64 = 256 * 1024 * 1024;
const PERSIST_INTERVAL: Duration = Duration::from_secs(2);
/// Slow-path safety floor: dirty work that has waited this long since the
/// last checkpoint is persisted even under the byte floor.
const MAX_PERSIST_INTERVAL: Duration = Duration::from_secs(5);

struct PersistTracker {
    bytes_since: u64,
    last_at: Instant,
}

impl PersistTracker {
    fn new() -> Self {
        Self {
            bytes_since: 0,
            last_at: Instant::now(),
        }
    }

    /// Returns true once the paced floors (byte and time) or the slow-path
    /// floor are met since the last checkpoint, resetting the counters.
    fn should_checkpoint(&mut self, added: u64) -> bool {
        self.should_checkpoint_at(added, Instant::now())
    }

    /// `now` is injected so tests can pin the pacing decision without a clock.
    fn should_checkpoint_at(&mut self, added: u64, now: Instant) -> bool {
        self.bytes_since += added;
        let elapsed = now.duration_since(self.last_at);
        let due = (self.bytes_since >= PERSIST_BYTES && elapsed >= PERSIST_INTERVAL)
            || (elapsed >= MAX_PERSIST_INTERVAL && self.bytes_since > 0);
        if due {
            self.bytes_since = 0;
            self.last_at = now;
        }
        due
    }
}

pub(crate) fn persist_push(setup: &WorkerSetup, key: String) -> Result<(), String> {
    let mut session = persisted_session(setup, &[]);
    if let Some(previous) = setup.store.load_push_session(&key)? {
        if previous.committed_upload_id.is_some() {
            return Err("completed upload is awaiting publication cleanup".into());
        }
        if previous.link_id != session.link_id
            || previous.tenant != session.tenant
            || previous.dest_dir != session.dest_dir
            || previous.dest_rel != session.dest_rel
            || previous.package != session.package
        {
            return Err("push recovery does not match this admission".to_owned());
        }
        session.files = previous.files;
    }
    session.push_key = Some(key);
    setup.store.insert_upload_session(&session)
}

/// Builds the resume record for a session's current files. Published files
/// carry no staging handle; boot re-attach skips them.
fn persisted_session<'a>(
    setup: &WorkerSetup,
    files: impl IntoIterator<Item = &'a FileState>,
) -> PersistedUploadSession {
    let persisted = files
        .into_iter()
        .enumerate()
        .map(|(entry, file)| {
            let (staging_path, journal_path, incarnation, prefix_bytes) = match &file.native {
                Some(native) => (
                    native.staging_path().to_path_buf(),
                    native.journal_path().to_path_buf(),
                    native.incarnation(),
                    native.progress().prefix_bytes,
                ),
                None => (
                    PathBuf::new(),
                    PathBuf::new(),
                    [0u8; 16],
                    file.object.length,
                ),
            };
            PersistedUploadFile {
                entry,
                display_path: file.display_path.clone(),
                stored_components: file
                    .stored_components
                    .split('\0')
                    .map(str::to_owned)
                    .collect(),
                object: file.object.clone(),
                staging_path,
                journal_path,
                incarnation,
                profile: file
                    .native
                    .as_ref()
                    .map_or(CommitProfile::Balanced, |native| native.profile),
                nas_contract: file
                    .native
                    .as_ref()
                    .map_or(setup.destinations.contract(), |native| native.nas_contract),
                prefix_bytes,
                published: file.published,
                receipt: file.receipt,
            }
        })
        .collect();
    PersistedUploadSession {
        committed_upload_id: None,
        push_key: None,
        id: hex::encode(setup.session_id),
        link_id: setup.link_id.clone(),
        tenant: setup.tenant.clone(),
        dest_dir: setup.dest_dir.clone(),
        dest_rel: setup.dest_rel.clone(),
        package: setup.expected_package.clone(),
        max_total_bytes: (setup.max_total_bytes != u64::MAX).then_some(setup.max_total_bytes),
        started_at: setup.started_at,
        files: persisted,
    }
}

/// Admission metadata must survive before any final filename is published.
fn persist_session(setup: &WorkerSetup, files: &[FileState]) -> Result<(), SessionError> {
    let record = persisted_session(setup, files);
    setup
        .store
        .insert_upload_session(&record)
        .map_err(|error| SessionError::internal(format!("persist upload admission: {error}")))?;
    for (file, saved) in files.iter().zip(&record.files) {
        *file.checkpointed.lock().expect("checkpoint poisoned") =
            Some((saved.prefix_bytes, saved.published, saved.receipt));
    }
    Ok(())
}

fn checkpoint_files<'a>(
    setup: &WorkerSetup,
    files: impl IntoIterator<Item = (usize, &'a FileState)>,
) -> Result<(), String> {
    let progress = files
        .into_iter()
        .filter_map(|(index, file)| {
            let row = file_progress(index, file);
            (*file.checkpointed.lock().expect("checkpoint poisoned") != Some((row.1, row.2, row.3)))
                .then_some((row, &file.checkpointed))
        })
        .collect::<Vec<_>>();
    if progress.is_empty() {
        return Ok(());
    }
    setup.store.update_upload_file_progress(
        &hex::encode(setup.session_id),
        progress.iter().map(|(row, _)| *row),
    )?;
    // Record the committed snapshot, since native writes may have advanced meanwhile.
    for ((_, prefix, published, receipt), checkpointed) in progress {
        *checkpointed.lock().expect("checkpoint poisoned") = Some((prefix, published, receipt));
    }
    Ok(())
}

/// Bounds checkpoint-failure warnings per session: the first failure logs
/// immediately, repeats at most once per interval. A failing checkpoint
/// would otherwise warn once per 256 MiB, about 20 lines per second per
/// transfer at 40 GbE.
const CHECKPOINT_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Per-session warning budget for [`checkpoint_session`]. Lives on
/// [`WorkerSetup`] so every checkpoint of one session shares the budget.
pub struct CheckpointWarnPacer {
    last_at: Mutex<Option<Instant>>,
}

impl CheckpointWarnPacer {
    pub fn new() -> Self {
        Self {
            last_at: Mutex::new(None),
        }
    }

    /// True when a failure at `now` must be logged: the first failure of a
    /// session always, afterwards at most once per
    /// [`CHECKPOINT_WARN_INTERVAL`]. `now` is injected so tests can pin the
    /// pacing decision without a clock.
    fn should_log_at(&self, now: Instant) -> bool {
        let mut last = self.last_at.lock().expect("checkpoint warn pacer poisoned");
        let due = last.is_none_or(|at| now.duration_since(at) >= CHECKPOINT_WARN_INTERVAL);
        if due {
            *last = Some(now);
        }
        due
    }

    fn should_log(&self) -> bool {
        self.should_log_at(Instant::now())
    }
}

impl Default for CheckpointWarnPacer {
    fn default() -> Self {
        Self::new()
    }
}

fn checkpoint_session(setup: &WorkerSetup, files: &mut [FileState]) -> bool {
    if let Err(error) = checkpoint_files(setup, files.iter().enumerate()) {
        if setup.checkpoint_warn.should_log() {
            tracing::warn!(
                %error,
                "checkpoint upload session failed; the resume point stops advancing until a checkpoint succeeds"
            );
        }
        return false;
    }
    forget_publications(files)
}

fn forget_publications(files: &mut [FileState]) -> bool {
    let mut complete = true;
    let mut retained: Vec<(String, String)> = Vec::new();
    for file in files.iter_mut().filter(|file| file.published) {
        let Some(staged) = file.native.as_ref() else {
            continue;
        };
        let result = staged.directory().and_then(|directory| {
            directory
                .forget_publication(
                    staged.destination.file_name().unwrap_or_default(),
                    &staged.resume_state(),
                )
                .map_err(|error| SessionError::internal(error.to_string()))
        });
        if let Err(error) = result {
            complete = false;
            retained.push((file.display_path.clone(), error.message));
        } else {
            file.native = None;
        }
    }
    if let Some((first_path, first_error)) = retained.first() {
        tracing::warn!(
            count = retained.len(),
            path = %first_path,
            error = %first_error,
            "retain publication journal for recovery"
        );
    }
    complete
}

/// Removes the resume record once a session is complete or cancelled.
fn forget_session(setup: &WorkerSetup) {
    if let Err(error) = setup
        .store
        .delete_upload_session(&hex::encode(setup.session_id))
    {
        tracing::warn!(%error, "forget upload session failed");
    }
}

/// Re-attaches a persisted session after a restart: reopens each unpublished
/// file's staging from its checkpointed prefix, publishes any file that
/// prefix already completes, and starts the worker in the receiving phase.
/// The staging is reopened under the profile it was created with; the
/// integrity of the resumed bytes is established by the rehash at publish.
/// Returns the staging and journal paths now owned by the worker. On any
/// failure nothing runs and existing recovery metadata remains available.
/// `persisted` is updated with any file published here, so a caller that
/// refuses the resume after a later failure still records those files.
pub fn resume_worker(
    setup: WorkerSetup,
    receiver: mpsc::Receiver<Cmd>,
    persisted: &mut PersistedUploadSession,
) -> Result<(Vec<PathBuf>, u64), String> {
    let (mut files, kept, recovered) = restore_files(&setup, persisted, || {
        setup.destinations.check_live().is_ok()
    })?;
    for file in files.iter_mut().filter(|file| !file.published) {
        if let Some(staged) = file.native.as_mut() {
            staged.preserve = false;
        }
    }

    let already = persisted_received(persisted);
    spawn_worker_from(
        setup,
        receiver,
        Phase::Receiving { files },
        true,
        already,
        recovered,
    );
    Ok((kept, already))
}

fn persisted_resume_state(file: &PersistedUploadFile) -> vot_sdk_file::ResumeState {
    vot_sdk_file::ResumeState {
        staging_name: file.staging_path.file_name().unwrap_or_default().to_owned(),
        journal_name: file.journal_path.file_name().unwrap_or_default().to_owned(),
        incarnation: file.incarnation,
        profile: file.profile,
        nas_contract: file.nas_contract,
        runs: (file.prefix_bytes > 0)
            .then_some((0, file.prefix_bytes))
            .into_iter()
            .collect(),
    }
}

pub(crate) fn cleanup_committed_session(
    store: &Store,
    session: &PersistedUploadSession,
    destinations: &crate::receiving::Destinations,
) -> Result<(), String> {
    if session.committed_upload_id.is_none() {
        return Err("upload has not committed".into());
    }
    for file in &session.files {
        if file.staging_path.as_os_str().is_empty() && file.journal_path.as_os_str().is_empty() {
            continue;
        }
        let destination = paths::join_under(&session.dest_dir, &file.stored_components)?;
        let parent = destination.parent().ok_or("missing destination parent")?;
        let name = destination.file_name().ok_or("missing destination name")?;
        let state = persisted_resume_state(file);
        if file.staging_path != parent.join(".vot-stage").join(&state.staging_name)
            || file.journal_path != parent.join(".vot-stage").join(&state.journal_name)
        {
            return Err("resume metadata is outside the private receiving namespace".into());
        }
        let location = destinations.location(&destination)?;
        let directory =
            vot_sdk_file::ReceiveDirectory::from_directory(location.directory().clone())
                .map_err(|error| error.to_string())?;
        let journal = destinations.location(&file.journal_path)?;
        destinations.check_location(&journal)?;
        match journal.identity() {
            Ok(_) => directory
                .forget_publication(name, &state)
                .map_err(|error| error.to_string())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let staging = destinations.location(&file.staging_path)?;
                match staging.identity() {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error.to_string()),
                    Ok(_) => {
                        return Err("publication journal is missing but staging remains".into())
                    }
                }
            }
            Err(error) => return Err(error.to_string()),
        }
        destinations.check_location(&location)?;
        destinations.check_location(&journal)?;
        match journal.identity() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.to_string()),
            Ok(_) => return Err("publication journal changed during cleanup".into()),
        }
        // Journal unlink must survive before the database forgets the completion fence.
        journal.sync_parent().map_err(|error| error.to_string())?;
    }
    store.delete_upload_session(&session.id)
}

/// Classifies a boot refusal as permanent: the link was deleted or has
/// expired, so the session can never resume and its evidence is discarded.
/// Every other refusal (closed link, structural damage, transient faults)
/// stays recoverable and keeps today's behavior. The strings match the
/// errors [`crate::app::resume_upload_session`] reports for the same causes.
pub(crate) fn permanent_refusal_detail(
    store: &Store,
    session: &crate::store::PersistedUploadSession,
) -> Option<String> {
    match store.upload_link(&session.link_id) {
        Ok(None) => Some("link no longer exists".to_owned()),
        Ok(Some(link)) if link.expires_at.is_some_and(|at| now_unix() >= at) => {
            Some("link is no longer accepting uploads".to_owned())
        }
        _ => None,
    }
}

/// Removes a permanently refused session's staging evidence and its record.
/// The caller commits the interrupted event first; afterwards no boot can
/// re-attach this session, so no duplicate event or staging file remains.
pub(crate) fn discard_refused_session(
    store: &Arc<Store>,
    destinations: &crate::receiving::Destinations,
    session: &crate::store::PersistedUploadSession,
) -> Result<(), String> {
    if let Some(key) = &session.push_key {
        if !crate::auth::valid_hex(key, 32) {
            return Err("invalid push staging key".to_owned());
        }
        let directory = session
            .dest_dir
            .join(".vot-stage")
            .join(format!(".vot-push-{key}"));
        match lock_push_directory(&directory, destinations.contract()) {
            Ok(lock) => destinations.remove_push_directory(&directory, &lock)?,
            // The staging is already gone; only the record remains.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.to_string()),
        }
    } else {
        for file in &session.files {
            for path in [&file.staging_path, &file.journal_path] {
                if path.as_os_str().is_empty() {
                    continue;
                }
                discard_staged_path(destinations, path)?;
            }
        }
    }
    store.delete_upload_session(&session.id)
}

fn discard_staged_path(
    destinations: &crate::receiving::Destinations,
    path: &std::path::Path,
) -> Result<(), String> {
    // Upload evidence only ever lives in a `.vot-stage` directory beside its
    // destination; refuse anything else before resolving it for deletion.
    if path.parent().and_then(std::path::Path::file_name)
        != Some(std::ffi::OsStr::new(".vot-stage"))
    {
        return Err("resume metadata is outside the private receiving namespace".into());
    }
    let location = destinations.location(path)?;
    let held = match location.open_read() {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    location
        .remove_owned(&held)
        .map_err(|error| error.to_string())?;
    location.sync_parent().map_err(|error| error.to_string())
}

#[allow(clippy::type_complexity)]
fn restore_files(
    setup: &WorkerSetup,
    persisted: &mut PersistedUploadSession,
    active: impl Fn() -> bool,
) -> Result<(Vec<FileState>, Vec<PathBuf>, Vec<LogEvent>), String> {
    check_session_entry_cap(persisted.files.len()).map_err(|error| error.message)?;
    if persisted.committed_upload_id.is_some() {
        return Err("completed upload cannot resume receiving".into());
    }
    for file in &persisted.files {
        crate::protocol_paths::check_payload_name_length(
            file.stored_components.last().map_or("", String::as_str),
        )?;
    }
    if setup
        .dest_rel
        .split('/')
        .chain(persisted.dest_rel.split('/'))
        .chain(
            persisted
                .files
                .iter()
                .flat_map(|file| file.stored_components.iter().map(String::as_str)),
        )
        .any(crate::protocol_paths::is_receipt_name)
    {
        return Err("resume path uses a name reserved for signed receipts".into());
    }
    let mut files = Vec::with_capacity(persisted.files.len());
    let mut kept = Vec::new();
    // Audit finding 499: publications completed on the recover path never
    // pass the worker's accept loop, so the resumed log would jump straight
    // from "reattached" to "finished" with no per-file record.
    let mut recovered = Vec::new();
    for file in &mut persisted.files {
        if !active() {
            return Err("receive recovery cancelled".into());
        }
        let destination = paths::join_under(&setup.dest_dir, &file.stored_components)?;
        let parent = destination.parent().ok_or("missing destination parent")?;
        let directory = setup.destinations.directory(parent, false)?;
        let name = destination.file_name().ok_or("missing destination name")?;
        let runs = (file.prefix_bytes > 0).then_some((0, file.prefix_bytes));
        let state = persisted_resume_state(file);
        let native = if file.published
            && !file.journal_path.try_exists().map_err(|e| e.to_string())?
        {
            if !staged_object_valid(&destination, &file.object, &active)? {
                return Err(format!("{} changed after publication", file.display_path));
            }
            None
        } else {
            if file.staging_path != parent.join(".vot-stage").join(&state.staging_name)
                || file.journal_path != parent.join(".vot-stage").join(&state.journal_name)
            {
                return Err("resume metadata is outside the private receiving namespace".to_owned());
            }
            kept.push(file.staging_path.clone());
            kept.push(file.journal_path.clone());
            let coverage = ObjectCoverage::from_runs(&file.object, runs)
                .map_err(|error| format!("{}: {error:?}", file.display_path))?;
            let mut staged = if destination.try_exists().map_err(|e| e.to_string())? {
                let observation = directory
                    .recover_publication(&file.object, name, &state, || {
                        active() && setup.destinations.check_live().is_ok()
                    })
                    .map_err(|error| format!("recover {}: {error}", file.display_path))?;
                let location = directory
                    .destination(name)
                    .map_err(|error| error.to_string())?;
                setup.destinations.check_location(&location)?;
                file.published = true;
                recovered.push(LogEvent {
                    at: now_unix(),
                    kind: "published".to_owned(),
                    path: Some(file.display_path.clone()),
                    bytes: Some(file.object.length),
                    secs: None,
                    count: None,
                });
                if !file.receipt {
                    file.receipt = setup
                        .signer
                        .write_sidecar(
                            &location,
                            &file.object,
                            setup.session_id,
                            observation,
                            file.profile,
                        )
                        .is_ok();
                }
                StagedFile {
                    destinations: Arc::clone(&setup.destinations),
                    destination: destination.clone(),
                    staging: file.staging_path.clone(),
                    journal: file.journal_path.clone(),
                    incarnation: file.incarnation,
                    profile: file.profile,
                    nas_contract: file.nas_contract,
                    coverage: Mutex::new(coverage),
                    active: None,
                    active_directory: None,
                    reopened: true,
                    parked_metadata: None,
                    preserve: true,
                }
            } else {
                let native = directory
                    .resume(&file.object, name, &state)
                    .map_err(|error| format!("{}: {error}", file.display_path))?;
                StagedFile::new(
                    native,
                    destination,
                    coverage,
                    file.profile,
                    Arc::clone(&setup.destinations),
                )
            };
            staged.preserve = true;
            Some(staged)
        };
        files.push(FileState {
            display_path: file.display_path.clone(),
            stored_components: file.stored_components.join("\0"),
            object: file.object.clone(),
            native,
            published: file.published,
            receipt: file.receipt,
            checkpointed: Mutex::new(None),
            first_range_at: None,
            rehash: !file.published && file.prefix_bytes > 0,
        });
    }
    // A prefix that already covers the object publishes now, as begin does
    // for empty objects; the sender only has finish left to call.
    for index in 0..files.len() {
        let file = &mut files[index];
        let complete = file.native.as_ref().is_some_and(|native| {
            let progress = native.progress();
            progress.covered_bytes == progress.total_bytes
        });
        if complete && !file.published {
            let result = publish_file(setup, file, &active);
            persisted.files[index].published = file.published;
            persisted.files[index].receipt = file.receipt;
            if let Some(staged) = &file.native {
                persisted.files[index].prefix_bytes = staged.progress().prefix_bytes;
            }
            if result.is_ok() {
                recovered.push(LogEvent {
                    at: now_unix(),
                    kind: "published".to_owned(),
                    path: Some(file.display_path.clone()),
                    bytes: Some(file.object.length),
                    secs: None,
                    count: None,
                });
            }
            if let Err(error) = result {
                checkpoint_session(setup, &mut files);
                return Err(error.message);
            }
        }
    }
    checkpoint_session(setup, &mut files);
    Ok((files, kept, recovered))
}

fn persisted_received(session: &PersistedUploadSession) -> u64 {
    session
        .files
        .iter()
        .map(|file| {
            if file.published {
                file.object.length
            } else {
                file.prefix_bytes
            }
        })
        .sum()
}

fn entry_infos(setup: &WorkerSetup, files: &[FileState]) -> Vec<EntryInfo> {
    files
        .iter()
        .enumerate()
        .map(|(index, file)| EntryInfo {
            index,
            path: file.display_path.clone(),
            stored_as: stored_rel(&setup.dest_rel, &file.stored_components),
            bytes: file.object.length,
            complete: file.published,
            // A published file has no live handle left to ask, and its
            // coverage is by definition the whole object.
            covered_bytes: if file.published {
                file.object.length
            } else {
                file.native
                    .as_ref()
                    .map_or(0, |native| native.progress().prefix_bytes)
            },
        })
        .collect()
}

struct Delivered {
    stored_components: Vec<String>,
    receipt: bool,
}

/// A file with this object root already delivered on this link under the
/// announced name and still on disk: the transfer is skipped and the
/// existing copy reported, instead of publishing a suffixed duplicate.
fn find_delivered(
    setup: &WorkerSetup,
    object: &ObjectId,
    announced: &[String],
    active: impl Fn() -> bool,
) -> Result<Option<Delivered>, SessionError> {
    // The reuse must sit at the announced name: a renamed re-announce of
    // delivered bytes transfers for real, so no record is synthesized for
    // a name under which nothing was received.
    let expected = if setup.dest_rel.is_empty() {
        announced.join("/")
    } else {
        format!("{}/{}", setup.dest_rel, announced.join("/"))
    };
    let mut after = String::new();
    loop {
        if !active() {
            return Err(SessionError::conflict("receive preparation cancelled"));
        }
        let candidates = setup
            .store
            .delivered_candidates(&setup.tenant, &setup.link_id, object, &after)
            .map_err(SessionError::internal)?;
        let count = candidates.len();
        for (stored_as, receipt) in candidates {
            if stored_as == after {
                continue;
            }
            after = stored_as.clone();
            if !active() {
                return Err(SessionError::conflict("receive preparation cancelled"));
            }
            if stored_as != expected {
                continue;
            }
            // Names reserved for signed receipts never dedupe, even when a
            // record of one exists.
            if announced
                .iter()
                .any(|part| crate::protocol_paths::is_receipt_name(part))
            {
                continue;
            }
            if crate::protocol_paths::check_payload_name_length(
                announced.last().map_or("", String::as_str),
            )
            .is_err()
            {
                continue;
            }
            let Ok(path) = paths::join_under(&setup.dest_dir, announced) else {
                continue;
            };
            match fs::metadata(&path) {
                Ok(meta)
                    if meta.is_file()
                        && meta.len() == object.length
                        && staged_object_valid(&path, object, &active).unwrap_or(false) =>
                {
                    return Ok(Some(Delivered {
                        stored_components: announced.to_vec(),
                        receipt,
                    }));
                }
                _ => {}
            }
        }
        if count < crate::store::DELIVERED_CANDIDATE_PAGE {
            return Ok(None);
        }
    }
}

fn pending_upload_claims(store: &Store, tenant: &str) -> Result<HashSet<Vec<u8>>, SessionError> {
    let mut pending = HashSet::new();
    store
        .visit_pending_upload_paths(tenant, |destination, components| {
            pending
                .insert(stored_path_key(destination, components).map_err(|error| error.message)?);
            Ok(())
        })
        .map_err(SessionError::internal)?;
    Ok(pending)
}

fn check_pending_parent(key: &[u8], pending: &HashSet<Vec<u8>>) -> Result<(), SessionError> {
    if pending.contains(key) {
        return Err(SessionError::conflict(
            "destination folder is reserved by an unfinished upload",
        ));
    }
    Ok(())
}

pub(crate) fn check_upload_directory(
    store: &Store,
    tenant: &str,
    destination: &str,
) -> Result<(), SessionError> {
    if destination.is_empty() {
        return Ok(());
    }
    let key = stored_path_key(destination, &[])?;
    let pending = pending_upload_claims(store, tenant)?;
    for (index, byte) in key.iter().enumerate() {
        if *byte == 0 {
            check_pending_parent(&key[..index], &pending)?;
        }
    }
    check_pending_parent(&key, &pending)
}

fn prepare_files<'a>(
    setup: &'a WorkerSetup,
    entries: &[(Vec<String>, ObjectId)],
    active: impl Fn() -> bool + Sync,
) -> Result<(Vec<FileState>, std::sync::MutexGuard<'a, ()>), SessionError> {
    check_session_entry_cap(entries.len())?;
    for (components, _) in entries {
        crate::protocol_paths::check_payload_name_length(
            components.last().map_or("", String::as_str),
        )
        .map_err(SessionError::bad)?;
    }
    if setup
        .dest_rel
        .split('/')
        .any(crate::protocol_paths::is_receipt_name)
    {
        return Err(SessionError::bad(
            "receiving destination uses a name reserved for signed receipts",
        ));
    }
    let existing = prepare_parallel(entries, |_, (components, object)| {
        find_delivered(setup, object, components, &active)
    })?;
    // Audit finding 373: a live record can still claim one of these stored
    // names under a different object identity, most often because a restore
    // resurrected it after a later upload reused the freed name. Treat such
    // names as taken so the new file takes a suffixed one instead of sharing
    // a stored path with the stale claim.
    let fresh: Vec<(String, String, String)> = entries
        .iter()
        .zip(&existing)
        .filter(|(_, existing)| existing.is_none())
        .map(|((components, object), _)| {
            (
                stored_rel(&setup.dest_rel, &components.join("\0")),
                suite_name(object.suite),
                hex::encode(object.root),
            )
        })
        .collect();
    let conflicts = setup
        .store
        .conflicting_stored_claims(&setup.tenant, &fresh)
        .map_err(SessionError::internal)?;
    // ponytail: large NAS manifests serialize metadata allocation; temporary claims can narrow it.
    let allocation = setup
        .store
        .upload_allocation
        .lock()
        .map_err(|_| SessionError::internal("upload allocation poisoned"))?;
    let pending = pending_upload_claims(&setup.store, &setup.tenant)?;
    let mut parents = HashSet::new();
    for ((components, _), existing) in entries.iter().zip(&existing) {
        if existing.is_some() {
            continue;
        }
        let key = stored_path_key(&setup.dest_rel, components)?;
        for (index, byte) in key.iter().enumerate() {
            if *byte == 0 {
                check_pending_parent(&key[..index], &pending)?;
                parents.insert(key[..index].to_vec());
            }
        }
    }
    for key in &pending {
        for (index, byte) in key.iter().enumerate() {
            if *byte == 0 {
                parents.insert(key[..index].to_vec());
            }
        }
    }
    let mut claimed = pending;
    claimed.extend(parents);
    for name in &conflicts {
        let components: Vec<String> = name.split('/').map(str::to_owned).collect();
        claimed.insert(stored_path_key("", &components)?);
    }
    let claimed = Mutex::new(claimed);
    let files = prepare_parallel(entries, |index, (components, object)| {
        if !active() {
            return Err(SessionError::conflict("receive preparation cancelled"));
        }
        if let Some(existing) = &existing[index] {
            return Ok(FileState {
                display_path: components.join("/"),
                stored_components: existing.stored_components.join("\0"),
                object: object.clone(),
                native: None,
                published: true,
                receipt: existing.receipt,
                checkpointed: Mutex::new(None),
                first_range_at: None,
                rehash: false,
            });
        }
        open_destination_for(setup, components.clone(), object.clone(), &claimed)
    })?;
    Ok((files, allocation))
}

fn prepare_parallel<T: Sync, U: Send>(
    entries: &[T],
    prepare: impl Fn(usize, &T) -> Result<U, SessionError> + Sync,
) -> Result<Vec<U>, SessionError> {
    if entries.len() < MAX_CHUNK_BATCH * 2 {
        return entries
            .iter()
            .enumerate()
            .map(|(index, entry)| prepare(index, entry))
            .collect();
    }
    let stopped = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let chunk_size = entries.len().div_ceil(MAX_CHUNK_BATCH);
        let workers = entries
            .chunks(chunk_size)
            .enumerate()
            .map(|(chunk_index, chunk)| {
                let prepare = &prepare;
                let stopped = &stopped;
                scope.spawn(move || {
                    let mut files = Vec::with_capacity(chunk.len());
                    for (index, entry) in chunk.iter().enumerate() {
                        if stopped.load(Ordering::Acquire) {
                            break;
                        }
                        match prepare(chunk_index * chunk_size + index, entry) {
                            Ok(file) => files.push(file),
                            Err(error) => {
                                stopped.store(true, Ordering::Release);
                                return Err(error);
                            }
                        }
                    }
                    Ok(files)
                })
            })
            .collect::<Vec<_>>();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().expect("receive preparation panicked"))
            .collect::<Vec<_>>();
        Ok(results
            .into_iter()
            .collect::<Result<Vec<_>, SessionError>>()?
            .into_iter()
            .flatten()
            .collect())
    })
}

fn stored_path_key(destination: &str, components: &[String]) -> Result<Vec<u8>, SessionError> {
    use unicode_normalization::UnicodeNormalization as _;
    // Destination prefixes follow server policy, not manifest depth or reserved-name limits.
    if !components.is_empty() {
        vot_manifest::PackagePath::portable(components.iter().cloned())
            .map_err(|error| SessionError::bad(format!("stored path rejected: {error:?}")))?;
    }
    let mut key = Vec::new();
    for component in destination
        .split('/')
        .filter(|part| !part.is_empty())
        .chain(components.iter().map(String::as_str))
    {
        if !key.is_empty() {
            key.push(0);
        }
        let normalized: String = component
            .nfc()
            .map(|character| match character {
                '\u{130}' | '\u{131}' => 'i',
                other => other,
            })
            .collect();
        let folded: String = unicase::UniCase::new(normalized.trim_end_matches(['.', ' ']))
            .to_folded_case()
            .nfc()
            .collect();
        key.extend_from_slice(folded.as_bytes());
    }
    Ok(key)
}

fn open_destination_for(
    setup: &WorkerSetup,
    components: Vec<String>,
    object: ObjectId,
    claimed: &Mutex<HashSet<Vec<u8>>>,
) -> Result<FileState, SessionError> {
    let display_path = components.join("/");
    let parent = paths::join_under(&setup.dest_dir, &components[..components.len() - 1])
        .map_err(SessionError::internal)?;
    let directory = setup
        .destinations
        .directory(&parent, true)
        .map_err(SessionError::internal)?;
    let name = components.last().expect("manifest paths are never empty");
    for attempt in 0..MAX_NAME_ATTEMPTS {
        setup
            .destinations
            .check_live()
            .map_err(SessionError::internal)?;
        let mut stored = components.clone();
        *stored.last_mut().expect("non-empty") = paths::with_suffix(name, attempt);
        crate::protocol_paths::check_payload_name_length(stored.last().expect("non-empty"))
            .map_err(SessionError::bad)?;
        let key = stored_path_key(&setup.dest_rel, &stored)?;
        if !claimed
            .lock()
            .expect("name claims poisoned")
            .insert(key.clone())
        {
            continue;
        }
        // The full stored path including the file name; `parent` above is
        // only for creating intermediate directories.
        let destination =
            paths::join_under(&setup.dest_dir, &stored).map_err(SessionError::internal)?;
        let profile = CommitProfile::Balanced;
        match directory.create(
            &object,
            destination.file_name().expect("non-empty"),
            profile,
        ) {
            Ok(native) => {
                return Ok(FileState {
                    display_path,
                    stored_components: stored.join("\0"),
                    object: object.clone(),
                    native: Some(StagedFile::new(
                        native,
                        destination,
                        ObjectCoverage::new(&object),
                        profile,
                        Arc::clone(&setup.destinations),
                    )),
                    published: false,
                    receipt: false,
                    checkpointed: Mutex::new(None),
                    first_range_at: None,
                    rehash: false,
                });
            }
            Err(error) if error.kind() == vot_sdk_file::ErrorKind::AlreadyExists => {
                claimed.lock().expect("name claims poisoned").remove(&key);
            }
            Err(error) => {
                return Err(SessionError::internal(format!(
                    "prepare {display_path}: {error}"
                )));
            }
        }
    }
    Err(SessionError::conflict(format!(
        "could not find a free name for {display_path}"
    )))
}

/// One buffered chunk command waiting to be verified and accepted.
struct BatchChunk {
    entry: usize,
    offset: u64,
    proof: Bytes,
    data: Bytes,
    reply: Reply<ChunkProgress>,
    _lease: SessionLease,
}

/// The most in-flight chunks the sender keeps (upload.js UPLOADS_IN_FLIGHT),
/// so a full window verifies and writes at once instead of one at a time.
const MAX_CHUNK_BATCH: usize = 8;

/// A range's accept result before publication; publication needs `&mut files`
/// so it happens in the sequential post-pass, not the parallel accept.
struct AcceptCore {
    accepted: bool,
    replay: bool,
    covered_bytes: u64,
    total_bytes: u64,
    complete: bool,
}

/// Longest a duplicate range waits for the in-flight winner to commit its
/// one bounded write. A retry after the winner commits classifies as a
/// replay, which is VOT's documented semantics for a covered range.
const RANGE_IN_FLIGHT_BUDGET: Duration = Duration::from_secs(2);

/// Verifies and accepts one range against a shared file. Takes `&FileState`
/// so a batch of ranges runs from as many threads as chunks (accept is
/// `&self` since ADR-0046). A duplicate range still in flight elsewhere is
/// retried, never surfaced: the sender's retry logic aborts the whole file
/// on any non-transient error.
fn accept_range(
    files: &[FileState],
    entry: usize,
    offset: u64,
    proof: &[u8],
    data: &[u8],
) -> Result<AcceptCore, SessionError> {
    let file = files
        .get(entry)
        .ok_or_else(|| SessionError::bad(format!("no entry {entry}")))?;
    if file.published {
        // The file already verified completely; treat retries as replays.
        return Ok(AcceptCore {
            accepted: false,
            replay: true,
            covered_bytes: file.object.length,
            total_bytes: file.object.length,
            complete: true,
        });
    }
    let verified = verify_range(&file.object, offset, data, proof).map_err(|error| {
        SessionError::bad(format!(
            "range at offset {offset} failed verification: {:?}",
            error.code()
        ))
    })?;
    let staged = file
        .native
        .as_ref()
        .ok_or_else(|| SessionError::internal("file state lost"))?;
    let deadline = Instant::now() + RANGE_IN_FLIGHT_BUDGET;
    let acceptance = loop {
        match staged.native()?.accept(&verified) {
            Ok(acceptance) => break acceptance,
            Err(error) if error.kind() == vot_sdk_file::ErrorKind::RangeInFlight => {
                if Instant::now() >= deadline {
                    return Err(SessionError::internal("range stayed in flight too long"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                return Err(SessionError::internal(format!("write failed: {error}")));
            }
        }
    };
    staged.record(&verified)?;
    Ok(AcceptCore {
        accepted: matches!(acceptance.status, RangeStatus::Accepted),
        replay: matches!(acceptance.status, RangeStatus::Replay),
        covered_bytes: acceptance.progress.covered_bytes,
        total_bytes: acceptance.progress.total_bytes,
        complete: acceptance.progress.covered_bytes == acceptance.progress.total_bytes,
    })
}

/// Verifies and accepts a batch of chunks in parallel, then publishes any
/// files a chunk completed. Parallelism is per batch; a shared thread pool
/// would only matter if scoped-thread churn ever measures.
// ponytail: scoped threads per batch; add a pool only if churn measures.
// Measured 2026-09-01 (concurrent_load upload phase, 16 x 64 MiB at once):
// 1400 to 1740 MiB/s aggregate, completion p50 550 to 700 ms, p95 580 to
// 730 ms, no errors. At 8 MiB chunks that run spawns about 130 scoped
// threads, so churn is not visible at this chunk size.
fn accept_batch(
    setup: &WorkerSetup,
    phase: &mut Phase,
    batch: &[BatchChunk],
) -> Vec<Result<ChunkProgress, SessionError>> {
    let Phase::Receiving { files } = phase else {
        return batch
            .iter()
            .map(|_| {
                Err(SessionError::conflict(
                    "chunks are only accepted after begin",
                ))
            })
            .collect();
    };
    let opening = map_batch_files(files, batch.iter().map(|item| item.entry), |file| {
        if file.published {
            return Ok(());
        }
        file.native
            .as_mut()
            .ok_or_else(|| SessionError::internal("file state lost"))?
            .reopen()
    });
    // Verify and accept every range against the shared files. Disjoint
    // ranges of one file, and ranges of different files, all proceed at once.
    let cores: Vec<Result<AcceptCore, SessionError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = batch
            .iter()
            .map(|item| {
                let files = &*files;
                let opened = opening
                    .get(&item.entry)
                    .cloned()
                    .unwrap_or_else(|| Err(SessionError::bad(format!("no entry {}", item.entry))));
                scope.spawn(move || {
                    opened?;
                    accept_range(files, item.entry, item.offset, &item.proof, &item.data)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("accept thread panicked"))
            .collect()
    });
    let publication = map_batch_files(
        files,
        batch.iter().zip(&cores).filter_map(|(item, core)| {
            matches!(core, Ok(core) if core.complete).then_some(item.entry)
        }),
        |file| {
            if file.published {
                Ok(())
            } else {
                publish_file(setup, file, || true)
            }
        },
    );
    let outcomes = batch
        .iter()
        .zip(cores)
        .map(|(item, core)| {
            let core = core?;
            if core.complete {
                publication[&item.entry].clone()?;
            }
            Ok(ChunkProgress {
                accepted: core.accepted,
                replay: core.replay,
                covered_bytes: core.covered_bytes,
                total_bytes: core.total_bytes,
                complete: core.complete,
                received: 0,
                rebegin: false,
            })
        })
        .collect();
    for item in batch {
        if let Some(staged) = files
            .get_mut(item.entry)
            .and_then(|file| file.native.as_mut())
        {
            staged.park();
        }
    }
    outcomes
}

fn map_batch_files<T: Send>(
    files: &mut [FileState],
    entries: impl Iterator<Item = usize>,
    action: impl Fn(&mut FileState) -> T + Sync,
) -> HashMap<usize, T> {
    let mut entries = entries
        .filter(|entry| *entry < files.len())
        .collect::<Vec<_>>();
    entries.sort_unstable();
    entries.dedup();
    if entries.len() == 1 {
        let entry = entries[0];
        return HashMap::from([(entry, action(&mut files[entry]))]);
    }
    std::thread::scope(|scope| {
        let mut remaining = files;
        let mut offset = 0;
        let mut workers = Vec::with_capacity(entries.len());
        for entry in entries {
            let (_, tail) = remaining.split_at_mut(entry - offset);
            let (file, tail) = tail.split_first_mut().expect("validated batch entry");
            remaining = tail;
            offset = entry + 1;
            let action = &action;
            workers.push((entry, scope.spawn(move || action(file))));
        }
        workers
            .into_iter()
            .map(|(entry, worker)| (entry, worker.join().expect("batch file worker panicked")))
            .collect()
    })
}

fn prepare_publication(
    file: &mut FileState,
    active: impl Fn() -> bool,
) -> Result<(), SessionError> {
    let staged = file
        .native
        .as_mut()
        .ok_or_else(|| SessionError::internal("file state lost"))?;
    staged.reopen()?;
    file.rehash |= staged.reopened;
    // Uncertain recovery verifies the held file after its writes have joined.
    if file.rehash {
        let input = staged
            .native()?
            .read_staging()
            .map_err(|error| SessionError::internal(error.to_string()))?;
        if !opened_object_valid(input, &file.object, active).map_err(SessionError::internal)? {
            *staged.coverage.lock().expect("staging coverage poisoned") =
                ObjectCoverage::new(&file.object);
            staged.park();
            staged.reopened = false;
            file.rehash = false;
            return Err(SessionError::bad(format!("publish {} refused after resume: staged bytes do not match the announced object; retry the upload", file.display_path)));
        }
        file.rehash = false;
    }
    Ok(())
}

fn publish_file(
    setup: &WorkerSetup,
    file: &mut FileState,
    active: impl Fn() -> bool,
) -> Result<(), SessionError> {
    if !active() {
        return Err(SessionError::conflict("receive publication cancelled"));
    }
    prepare_publication(file, &active)?;
    if !active() {
        return Err(SessionError::conflict("receive publication cancelled"));
    }
    finish_publication(setup, file)
}

fn finish_publication(setup: &WorkerSetup, file: &mut FileState) -> Result<(), SessionError> {
    setup
        .destinations
        .check_live()
        .map_err(SessionError::internal)?;
    let native = file
        .native
        .as_mut()
        .ok_or_else(|| SessionError::internal("file state lost"))?;
    let location = native
        .directory()?
        .destination(native.destination.file_name().unwrap_or_default())
        .map_err(|error| SessionError::internal(error.to_string()))?;
    setup
        .destinations
        .check_location(&location)
        .map_err(SessionError::conflict)?;
    let active = native
        .active
        .as_mut()
        .ok_or_else(|| SessionError::internal("staging is not open"))?;
    active.publish_retaining_journal().map_err(|error| {
        SessionError::conflict(format!(
            "publish {} failed: {error}; the name may have been taken mid-upload, retry the upload",
            file.display_path
        ))
    })?;
    native.preserve = true;
    setup
        .destinations
        .check_location(&location)
        .map_err(SessionError::conflict)?;
    // Best effort: the file is delivered and verified either way, and the
    // record notes whether its receipt exists.
    if let Some(observation) = active.publish_observation() {
        match setup.signer.write_sidecar(
            &location,
            &file.object,
            setup.session_id,
            observation,
            native.profile,
        ) {
            Ok(_) => {
                file.receipt = true;
            }
            Err(error) => {
                tracing::warn!(file = %file.display_path, "receipt: {error}");
            }
        }
    }
    file.published = true;
    native.preserve = true;
    native.park();
    Ok(())
}

fn staged_object_valid(
    path: &std::path::Path,
    object: &ObjectId,
    active: impl Fn() -> bool,
) -> Result<bool, String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let input = options
        .open(path)
        .map_err(|error| format!("open staging: {error}"))?;
    opened_object_valid(input, object, active)
}

fn opened_object_valid(
    mut input: fs::File,
    object: &ObjectId,
    active: impl Fn() -> bool,
) -> Result<bool, String> {
    let suite = Suite::try_from(object.suite).map_err(|_| "unsupported suite".to_owned())?;
    let metadata = input
        .metadata()
        .map_err(|error| format!("stat staging: {error}"))?;
    if !metadata.is_file() {
        return Err("staging is not a regular file".to_owned());
    }
    if metadata.len() != object.length {
        return Ok(false);
    }
    let mut builder = InMemoryObjectBuilder::new(suite, Some(object.length), object.length)
        .map_err(|error| format!("object builder: {:?}", error.code()))?;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut remaining = object.length;
    while remaining > 0 {
        if !active() {
            return Err("staging verification cancelled".to_owned());
        }
        let limit = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
        let count = input
            .read(&mut buf[..limit])
            .map_err(|error| format!("read staging: {error}"))?;
        if count == 0 {
            return Ok(false);
        }
        remaining -= count as u64;
        builder
            .update(&buf[..count])
            .map_err(|error| format!("hash staging: {:?}", error.code()))?;
    }
    if input
        .read(&mut buf[..1])
        .map_err(|error| format!("read staging: {error}"))?
        != 0
    {
        return Ok(false);
    }
    let prepared = builder
        .finish()
        .map_err(|error| format!("hash staging: {:?}", error.code()))?;
    Ok(prepared.object_id() == object)
}

fn handle_finish(
    setup: &WorkerSetup,
    phase: &mut Phase,
    replays: u64,
    rejected: u64,
    received: u64,
    log: &TransferLog,
) -> Result<FinishReport, SessionError> {
    let Phase::Receiving { files } = phase else {
        return Err(SessionError::conflict("nothing to finish in this state"));
    };
    if let Some(file) = files.iter().find(|file| !file.published) {
        return Err(SessionError::bad(format!(
            "{} is not fully received yet",
            file.display_path
        )));
    }
    // The outcome joins the record only when the commit succeeds: a failed
    // finish is retried against the same log.
    let mut events = log.snapshot();
    events.push(TransferLog::plain(now_unix(), "finished", Some(replays)));
    let mut report = commit_upload(setup, files, replays, rejected, Some("http"), events)?;
    report.received = received;
    if checkpoint_session(setup, files) {
        forget_session(setup);
    }
    *phase = Phase::Done;
    Ok(report)
}

/// A session that ends without finishing still leaves its published files
/// on disk. Record them as a partial upload so retention, dedupe, and the
/// operator listing see them; without a record they would be orphans.
/// Returns whether the final checkpoint persisted, so shutdown can report
/// an honest suspend result.
fn preserve_phase(setup: &WorkerSetup, phase: &mut Phase) -> bool {
    if let Phase::Receiving { files } = phase {
        let persisted = checkpoint_session(setup, files);
        for file in files {
            if let Some(native) = file.native.take() {
                native.abandon();
            }
        }
        persisted
    } else {
        true
    }
}

fn commit_partial(
    setup: &WorkerSetup,
    phase: &mut Phase,
    replays: u64,
    rejected: u64,
    log: &TransferLog,
) -> bool {
    let Phase::Receiving { files } = phase else {
        return true;
    };
    let unresolved = setup.destinations.check_live().is_err()
        || files.iter().any(|file| {
            !file.published
                && file.native.as_ref().is_some_and(|staged| {
                    staged.preserve
                        || staged
                            .active
                            .as_ref()
                            .is_some_and(NativeFile::recovery_required)
                })
        });
    let records = file_records(setup, files.iter().filter(|file| file.published));
    if records.is_empty() {
        return !unresolved;
    }
    match commit_upload_records(
        setup,
        records,
        replays,
        rejected,
        Some("http"),
        true,
        log.snapshot(),
    ) {
        Ok(_) => !unresolved && checkpoint_session(setup, files),
        Err(error) => {
            tracing::warn!(link = %setup.link_id, error = %error.message, "partial upload record failed");
            false
        }
    }
}

/// Records a persisted session the boot resume refused, including any files
/// it had already published.
pub fn commit_persisted_interruption(
    store: &Arc<Store>,
    ended: &mpsc::UnboundedSender<SessionEnded>,
    session: &crate::store::PersistedUploadSession,
    detail: &str,
) {
    if session.committed_upload_id.is_some() {
        return;
    }
    let records: Vec<FileRecord> = session
        .files
        .iter()
        .filter(|file| file.published)
        .map(|file| FileRecord {
            path: file.display_path.clone(),
            stored_as: stored_rel(&session.dest_rel, &file.stored_components.join("\0")),
            bytes: file.object.length,
            suite: suite_name(file.object.suite),
            root: hex::encode(file.object.root),
            receipt: file.receipt,
            deleted: false,
        })
        .collect();
    let at = now_unix();
    let recovery_id = format!("recovery-{}", session.id);
    if !records.is_empty() {
        let upload = UploadRecord {
            id: recovery_id,
            started_at: session.started_at,
            completed_at: at,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: Some(
                if session.push_key.is_some() {
                    "push"
                } else {
                    "http"
                }
                .to_owned(),
            ),
            package_root: hex::encode(session.package.root),
            total_bytes: records.iter().map(|record| record.bytes).sum(),
            files: records,
            partial: true,
            log: vec![LogEvent {
                at,
                kind: "interrupted".to_owned(),
                path: None,
                bytes: None,
                secs: None,
                count: None,
            }],
        };
        if let Err(error) =
            store.append_upload_from_session(&session.tenant, &session.link_id, upload, &session.id)
        {
            tracing::warn!(link = %session.link_id, %error, "partial upload record failed at boot");
        }
    }
    let received = persisted_received(session);
    let event = crate::store::SessionEvent {
        at,
        started_at: session.started_at,
        outcome: "interrupted".to_owned(),
        detail: format!("resume after restart failed: {detail}"),
        received_bytes: received,
        expected_bytes: session.package.length,
        replayed_chunks: 0,
        rejected_chunks: 0,
    };
    let _ = record_session_event(
        store,
        ended,
        &session.tenant,
        &session.link_id,
        "",
        &session.id,
        event,
    );
}

fn commit_upload(
    setup: &WorkerSetup,
    files: &[FileState],
    replays: u64,
    rejected: u64,
    transport: Option<&str>,
    log: Vec<LogEvent>,
) -> Result<FinishReport, SessionError> {
    commit_upload_records(
        setup,
        file_records(setup, files.iter()),
        replays,
        rejected,
        transport,
        false,
        log,
    )
}

fn commit_upload_records(
    setup: &WorkerSetup,
    records: Vec<FileRecord>,
    replays: u64,
    rejected: u64,
    transport: Option<&str>,
    partial: bool,
    log: Vec<LogEvent>,
) -> Result<FinishReport, SessionError> {
    let upload = UploadRecord {
        partial,
        log,
        id: crate::auth::random_token(),
        started_at: setup.started_at,
        completed_at: now_unix(),
        replayed_chunks: replays,
        rejected_chunks: rejected,
        transport: transport.map(str::to_owned),
        package_root: hex::encode(setup.expected_package.root),
        total_bytes: records.iter().map(|record| record.bytes).sum(),
        files: records.clone(),
    };
    let upload_id = setup
        .store
        .append_upload_from_session(
            &setup.tenant,
            &setup.link_id,
            upload,
            &hex::encode(setup.session_id),
        )
        .map_err(SessionError::internal)?
        .ok_or_else(|| SessionError::conflict("request link no longer exists"))?;
    Ok(FinishReport {
        upload_id,
        files: records,
        received: 0,
    })
}

fn file_records<'a>(
    setup: &WorkerSetup,
    files: impl Iterator<Item = &'a FileState>,
) -> Vec<FileRecord> {
    files
        .map(|file| FileRecord {
            path: file.display_path.clone(),
            stored_as: stored_rel(&setup.dest_rel, &file.stored_components),
            bytes: file.object.length,
            suite: suite_name(file.object.suite),
            root: hex::encode(file.object.root),
            receipt: file.receipt,
            deleted: false,
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PushObjectKey {
    suite: u16,
    root: [u8; 32],
    length: u64,
}

impl From<&vot_cli::ReceiveObject> for PushObjectKey {
    fn from(object: &vot_cli::ReceiveObject) -> Self {
        Self {
            suite: object.object.suite,
            root: object.object.root,
            length: object.object.length,
        }
    }
}

struct PushEntry {
    file: Option<FileState>,
}

type PushFiles = Arc<std::sync::RwLock<Vec<(usize, FileState)>>>;

struct PushObject {
    entries: Vec<usize>,
    complete: bool,
    active: Option<PushFiles>,
}

#[derive(Default)]
struct PushReceiveInner {
    entries: Vec<PushEntry>,
    objects: HashMap<PushObjectKey, PushObject>,
    remaining: usize,
    manifest_ready: bool,
    committing: bool,
    succeeded: bool,
    last_error: Option<String>,
}

struct PushReceive {
    app: Arc<crate::app::App>,
    setup: WorkerSetup,
    control: PushControl,
    runtime: tokio::runtime::Handle,
    staging: PathBuf,
    inner: Mutex<PushReceiveInner>,
    received: AtomicU64,
    activity_origin: Instant,
    last_active: AtomicU64,
    checkpoint: Mutex<PersistTracker>,
    /// Serializes whole checkpoints without holding `inner` across the store
    /// commit, so receive-path calls only wait for the snapshot phases.
    checkpointing: Mutex<()>,
    /// Entries whose stored progress changed since the last checkpoint.
    dirty: Mutex<HashSet<usize>>,
}

impl PushReceive {
    fn check_active(&self) -> Result<(), SessionError> {
        self.mark_active();
        if self.control.is_cancelled() {
            return Err(SessionError::conflict("native push was cancelled"));
        }
        self.setup
            .destinations
            .check_live()
            .map_err(SessionError::internal)
    }

    fn cli_error(&self, error: SessionError) -> vot_cli::Error {
        self.inner.lock().expect("push receive poisoned").last_error = Some(error.message.clone());
        vot_cli::Error::Io(std::io::Error::other(error.message))
    }

    fn mark_active(&self) {
        self.mark_active_at(self.activity_origin.elapsed().as_secs());
    }

    fn mark_active_at(&self, elapsed_secs: u64) {
        let previous = self.last_active.load(Ordering::Acquire);
        if elapsed_secs > previous
            && self
                .last_active
                .compare_exchange(previous, elapsed_secs, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            if let Some(lock) = self
                .control
                .directory_lock
                .lock()
                .expect("push directory poisoned")
                .as_ref()
            {
                let _ = lock.set_modified(std::time::SystemTime::now());
            }
            let id = hex::encode(self.setup.session_id);
            let _ = self.app.sessions.mark_active(&id);
            self.app
                .sessions
                .set_received(&id, self.received.load(Ordering::Relaxed));
        }
    }

    fn prepare_manifest(
        &self,
        summary: vot_cli::PackageSummary,
        records: &[vot_cli::EntryRecord],
    ) -> Result<(), SessionError> {
        let _lease = self
            .app
            .sessions
            .push_lease(&hex::encode(self.setup.session_id));
        self.check_active()?;
        let validated = validate_push_manifest(&self.setup, summary, records)?;
        self.setup
            .store
            .link_metadata(&self.setup.tenant, &self.setup.link_id)
            .map_err(|error| SessionError::internal(format!("link read failed: {error}")))?
            .ok_or_else(|| SessionError::conflict("request link no longer exists"))?;
        let mut saved = self
            .control
            .resume_key
            .as_ref()
            .map(|key| self.setup.store.load_push_session(key))
            .transpose()
            .map_err(SessionError::internal)?
            .flatten();
        let restored = if let Some(saved) = saved.as_mut().filter(|saved| !saved.files.is_empty()) {
            if saved.files.len() != validated.len()
                || saved
                    .files
                    .iter()
                    .zip(&validated)
                    .any(|(file, (components, object))| {
                        file.display_path != components.join("/") || file.object != *object
                    })
            {
                return Err(SessionError::conflict(
                    "push manifest changed since its checkpoint",
                ));
            }
            Some(
                restore_files(&self.setup, saved, || self.check_active().is_ok())
                    .map_err(SessionError::internal)?
                    .0,
            )
        } else {
            None
        };
        let (files, allocation) = match restored {
            Some(files) => (files, None),
            None => {
                let (files, allocation) =
                    prepare_files(&self.setup, &validated, || self.check_active().is_ok())?;
                (files, Some(allocation))
            }
        };
        let mut inner = self.inner.lock().expect("push receive poisoned");
        if inner.manifest_ready {
            return Err(SessionError::conflict("push manifest was already prepared"));
        }
        for file in files {
            self.check_active()?;
            let key = PushObjectKey {
                suite: file.object.suite,
                root: file.object.root,
                length: file.object.length,
            };
            let index = inner.entries.len();
            inner.entries.push(PushEntry { file: Some(file) });
            inner
                .objects
                .entry(key)
                .or_insert_with(|| PushObject {
                    entries: Vec::new(),
                    complete: false,
                    active: None,
                })
                .entries
                .push(index);
        }
        let mut record = persisted_session(
            &self.setup,
            inner.entries.iter().filter_map(|entry| entry.file.as_ref()),
        );
        record.push_key = self.control.resume_key.clone();
        self.setup
            .store
            .insert_upload_session(&record)
            .map_err(SessionError::internal)?;
        drop(allocation);
        for (entry, saved) in inner.entries.iter_mut().zip(&record.files) {
            let file = entry.file.as_mut().expect("admitted push file");
            *file.checkpointed.lock().expect("checkpoint poisoned") =
                Some((saved.prefix_bytes, saved.published, saved.receipt));
            if let Some(staged) = file.native.as_mut() {
                staged.preserve = true;
            }
        }
        inner.remaining = inner.objects.len();
        inner.manifest_ready = true;
        drop(inner);
        let _ = self
            .app
            .sessions
            .mark_active(&hex::encode(self.setup.session_id));
        Ok(())
    }

    fn choose_sink(
        self: &Arc<Self>,
        object: &vot_cli::ReceiveObject,
    ) -> Result<Option<Box<dyn vot_cli::ReceiveSink>>, SessionError> {
        let _lease = self
            .app
            .sessions
            .push_lease(&hex::encode(self.setup.session_id));
        self.check_active()?;
        let key = PushObjectKey::from(object);
        let mut inner = self.inner.lock().expect("push receive poisoned");
        let planned = inner
            .objects
            .get(&key)
            .ok_or_else(|| SessionError::bad("push object is absent from the manifest"))?;
        if planned.active.is_some() {
            return Err(SessionError::conflict("push object already has a sink"));
        }
        let indices = planned.entries.clone();
        if indices.iter().all(|index| {
            inner.entries[*index]
                .file
                .as_ref()
                .is_some_and(|file| file.published)
        }) {
            drop(inner);
            // The done sink: resumed_prefix reports the whole object and
            // flush is a no-op, so vot-cli takes its already-complete path,
            // runs the completion hook (which finishes the object here), and
            // marks it done. Returning None instead would mark it done
            // without ever running the hook.
            return Ok(Some(Box::new(PushPublishedSink {
                length: object.object.length,
            })));
        }
        if indices.len() <= MAX_OPEN_PUSH_ALIASES {
            for index in &indices {
                if let Some(staged) = inner.entries[*index]
                    .file
                    .as_mut()
                    .and_then(|file| file.native.as_mut())
                {
                    staged.reopen()?;
                }
            }
        }
        let files = Arc::new(std::sync::RwLock::new(
            indices
                .into_iter()
                .map(|index| {
                    let file = inner.entries[index]
                        .file
                        .take()
                        .expect("admitted push file");
                    (index, file)
                })
                .collect(),
        ));
        inner.objects.get_mut(&key).unwrap().active = Some(Arc::clone(&files));
        Ok(Some(Box::new(PushFileSink {
            files,
            receive: Arc::clone(self),
            stopped: AtomicBool::new(false),
        })))
    }

    fn complete_object(
        self: &Arc<Self>,
        object: &vot_cli::ReceiveObject,
    ) -> Result<(), SessionError> {
        self.finish_object(PushObjectKey::from(object))
    }

    /// Push checkpoint concurrency contract: checkpoints are serialized by
    /// `checkpointing`, and `inner` guards only the snapshot and the swap-in
    /// of results, never the SQLite commit or the NAS journal cleanup, so a
    /// concurrent choose_sink or finish_object stalls only for the brief
    /// phases. Atomicity with respect to the session's own lifecycle (finish
    /// or abort) is preserved without the lock: a snapshot row is recorded
    /// (entry marker set, publication journal forgotten) only when the
    /// entry's progress is unchanged since its snapshot; an entry that moved
    /// on meanwhile stays dirty for the next checkpoint. Markers therefore
    /// never claim store rows that were not committed, and a publication
    /// journal is only forgotten after the store records the file published.
    fn run_checkpoint(&self) -> Result<(), String> {
        let _serial = self.checkpointing.lock().expect("push checkpoint poisoned");
        // Snapshot the dirty entries' rows while `inner` is held.
        let planned = {
            let inner = self.inner.lock().expect("push receive poisoned");
            let active = inner
                .objects
                .values()
                .filter_map(|object| object.active.as_ref())
                .map(|files| files.read().expect("push object poisoned"))
                .collect::<Vec<_>>();
            let dirty = self
                .dirty
                .lock()
                .expect("push dirty poisoned")
                .drain()
                .collect::<Vec<_>>();
            let mut planned = Vec::new();
            let mut lost = Vec::new();
            for index in dirty {
                let Some(file) = inner
                    .entries
                    .get(index)
                    .and_then(|entry| entry.file.as_ref())
                    .or_else(|| {
                        active.iter().find_map(|files| {
                            files
                                .iter()
                                .find(|(entry, _)| *entry == index)
                                .map(|(_, file)| file)
                        })
                    })
                else {
                    lost.push(index);
                    continue;
                };
                let (_, prefix, published, receipt) = file_progress(0, file);
                let current = (prefix, published, receipt);
                if file
                    .checkpointed
                    .lock()
                    .expect("checkpoint poisoned")
                    .as_ref()
                    == Some(&current)
                {
                    continue;
                }
                planned.push((index, current));
            }
            self.dirty.lock().expect("push dirty poisoned").extend(lost);
            planned
        };
        if !planned.is_empty() {
            if let Err(error) = self.setup.store.update_upload_file_progress(
                &hex::encode(self.setup.session_id),
                planned.iter().map(|(index, (prefix, published, receipt))| {
                    (*index, *prefix, *published, *receipt)
                }),
            ) {
                self.dirty
                    .lock()
                    .expect("push dirty poisoned")
                    .extend(planned.iter().map(|(index, _)| *index));
                return Err(error);
            }
        }
        // Swap the committed rows into the entry markers, without `inner`
        // having been held across the commit above.
        let mut moved = Vec::new();
        {
            let mut inner = self.inner.lock().expect("push receive poisoned");
            for (index, row) in planned {
                if let Some(file) = inner
                    .entries
                    .get_mut(index)
                    .and_then(|entry| entry.file.as_mut())
                {
                    record_checkpointed(file, index, row, &mut moved);
                    continue;
                }
                let mut active = None;
                for object in inner.objects.values() {
                    if let Some(files) = object.active.as_ref() {
                        if files
                            .read()
                            .expect("push object poisoned")
                            .iter()
                            .any(|(entry, _)| *entry == index)
                        {
                            active = Some(Arc::clone(files));
                            break;
                        }
                    }
                }
                let Some(active) = active else {
                    moved.push(index);
                    continue;
                };
                let mut files = active.write().expect("push object poisoned");
                let Some((entry, file)) = files.iter_mut().find(|(entry, _)| *entry == index)
                else {
                    moved.push(index);
                    continue;
                };
                record_checkpointed(file, *entry, row, &mut moved);
            }
        }
        self.dirty
            .lock()
            .expect("push dirty poisoned")
            .extend(moved);
        Ok(())
    }

    /// Marks every admitted entry dirty so a flush checkpoint (completion or
    /// abort) covers the whole session rather than only recent writes.
    fn mark_all_dirty(&self, inner: &PushReceiveInner) {
        let mut dirty = self.dirty.lock().expect("push dirty poisoned");
        dirty.extend(
            inner
                .entries
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| entry.file.is_some().then_some(index)),
        );
        for object in inner.objects.values() {
            let Some(files) = object.active.as_ref() else {
                continue;
            };
            dirty.extend(
                files
                    .read()
                    .expect("push object poisoned")
                    .iter()
                    .map(|(entry, _)| *entry),
            );
        }
    }

    fn finish_object(&self, key: PushObjectKey) -> Result<(), SessionError> {
        let _lease = self
            .app
            .sessions
            .push_lease(&hex::encode(self.setup.session_id));
        self.check_active()?;
        let active = {
            let mut inner = self.inner.lock().expect("push receive poisoned");
            let object = inner
                .objects
                .get(&key)
                .ok_or_else(|| SessionError::bad("push object is absent from the manifest"))?;
            if object.complete {
                return Ok(());
            }
            if object.active.is_none()
                && !object.entries.iter().all(|index| {
                    inner.entries[*index]
                        .file
                        .as_ref()
                        .is_some_and(|file| file.published)
                })
            {
                return Err(SessionError::conflict("push object has no completed sink"));
            }
            inner.objects.get_mut(&key).unwrap().active.take()
        };
        if let Some(active) = active {
            let mut files = active.write().expect("push object poisoned");
            let result = files.iter_mut().try_for_each(|(_, file)| {
                self.check_active()?;
                if !file.published {
                    publish_file(&self.setup, file, || self.check_active().is_ok())?;
                }
                Ok(())
            });
            let mut inner = self.inner.lock().expect("push receive poisoned");
            for (index, mut file) in files.drain(..) {
                if let Some(staged) = file.native.as_mut() {
                    staged.park();
                }
                inner.entries[index].file = Some(file);
            }
            result?;
        }
        let records = {
            let mut inner = self.inner.lock().expect("push receive poisoned");
            let planned = inner.objects.get_mut(&key).unwrap();
            if planned.complete {
                return Ok(());
            }
            planned.complete = true;
            inner.remaining = inner
                .remaining
                .checked_sub(1)
                .ok_or_else(|| SessionError::internal("push object count underflow"))?;
            let due = self
                .checkpoint
                .lock()
                .expect("push checkpoint poisoned")
                .should_checkpoint(0);
            let final_checkpoint = inner.remaining == 0;
            if final_checkpoint {
                // Flush at completion covers every entry, not only dirty ones.
                self.mark_all_dirty(&inner);
            }
            // The checkpoint runs without `inner` (see run_checkpoint), so a
            // concurrent choose_sink proceeds while the store commits.
            drop(inner);
            if due || final_checkpoint {
                self.run_checkpoint().map_err(SessionError::internal)?;
            }
            let mut inner = self.inner.lock().expect("push receive poisoned");
            if inner.remaining != 0 || inner.committing {
                return Ok(());
            }
            inner.committing = true;
            let files = inner
                .entries
                .iter()
                .map(|entry| {
                    entry
                        .file
                        .as_ref()
                        .filter(|file| file.published)
                        .ok_or_else(|| SessionError::internal("push file is not published"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            file_records_from_refs(&self.setup, &files)
        };
        let report =
            commit_upload_records(&self.setup, records, 0, 0, Some("push"), false, Vec::new())?;
        let mut inner = self.inner.lock().expect("push receive poisoned");
        inner.succeeded = true;
        drop(inner);
        let sid = hex::encode(self.setup.session_id);
        crate::app::upload_completed(
            &self.app,
            &sid,
            Some(self.setup.link_id.clone()),
            &self.setup.client_ip,
            &report,
            &self.runtime,
        );
        Ok(())
    }
}

fn file_progress(index: usize, file: &FileState) -> (usize, u64, bool, bool) {
    (
        index,
        file.native
            .as_ref()
            .map_or(file.object.length, |staged| staged.progress().prefix_bytes),
        file.published,
        file.receipt,
    )
}

/// Records a committed checkpoint row on an unchanged entry and retires its
/// publication journal; an entry that advanced past its snapshot stays dirty.
fn record_checkpointed(
    file: &mut FileState,
    index: usize,
    row: (u64, bool, bool),
    moved: &mut Vec<usize>,
) {
    let (_, prefix, published, receipt) = file_progress(0, file);
    if (prefix, published, receipt) != row {
        moved.push(index);
        return;
    }
    *file.checkpointed.lock().expect("checkpoint poisoned") = Some(row);
    if file.published {
        forget_publications(std::slice::from_mut(file));
    }
}

impl Drop for PushReceive {
    fn drop(&mut self) {
        let sid = hex::encode(self.setup.session_id);
        let mut inner = self.inner.lock().expect("push receive poisoned");
        let succeeded = inner.succeeded;
        if !succeeded {
            let (outcome, detail) = if self.control.is_aborted() {
                ("cancelled", "cancelled by the sender".to_owned())
            } else {
                (
                    "interrupted",
                    inner
                        .last_error
                        .clone()
                        .unwrap_or_else(|| "native push ended before completion".to_owned()),
                )
            };
            record_event(
                &self.setup,
                self.received.load(Ordering::Acquire),
                now_unix(),
                outcome,
                detail,
                0,
                0,
            );
        }
        let active = inner
            .objects
            .values_mut()
            .filter_map(|object| object.active.take())
            .collect::<Vec<_>>();
        for active in active {
            for (index, mut file) in active.write().expect("push object poisoned").drain(..) {
                if let Some(staged) = file.native.as_mut() {
                    staged.preserve = true;
                    staged.park();
                }
                inner.entries[index].file = Some(file);
            }
        }
        if !succeeded {
            self.mark_all_dirty(&inner);
            // The abort checkpoint runs without `inner` (see run_checkpoint);
            // Drop is exclusive, so re-acquiring below cannot race a sink.
            drop(inner);
            if let Err(error) = self.run_checkpoint() {
                tracing::warn!(%error, "retain native push recovery journals");
            }
            inner = self.inner.lock().expect("push receive poisoned");
        }
        let retain = !succeeded
            || inner.entries.iter().any(|entry| {
                entry
                    .file
                    .as_ref()
                    .is_some_and(|file| file.native.is_some())
            });
        inner.entries.clear();
        drop(inner);
        crate::app::remove_push_ticket(&self.app, &sid);
        if retain {
            let parked = self.control.park();
            if !succeeded && parked {
                let _ = self.app.sessions.mark_active(&sid);
            } else {
                self.app.sessions.remove(&sid);
            }
            return;
        }
        if let Err(error) = self.setup.store.delete_upload_session(&sid) {
            tracing::warn!(%error, "delete completed push session");
        }
        if let Some(lock) = self
            .control
            .directory_lock
            .lock()
            .expect("push directory poisoned")
            .as_ref()
        {
            if let Err(error) = self
                .setup
                .destinations
                .remove_push_directory(&self.staging, lock)
            {
                tracing::warn!(
                    path = %push_staging_log_name(&self.staging),
                    %error,
                    "clear push staging"
                );
            }
        }
        self.app.sessions.remove(&sid);
        self.control.park();
    }
}

impl From<PushObjectKey> for ObjectId {
    fn from(object: PushObjectKey) -> Self {
        Self {
            suite: object.suite,
            root: object.root,
            length: object.length,
        }
    }
}

// A single object may appear at thousands of paths in a repeated-frame package.
const MAX_OPEN_PUSH_ALIASES: usize = 16;

/// The sink for an object that is already fully published. Its bytes exist,
/// so resumed_prefix reports the whole object and flush is a no-op; vot-cli
/// then finishes it through the completion hook instead of its `Ok(None)`
/// directory behaviour, which would mark the object done silently.
struct PushPublishedSink {
    length: u64,
}

impl vot_scheduler::RangeSink for PushPublishedSink {
    fn write_at(&self, _: u64, _: &[u8]) -> Result<(), vot_scheduler::SinkError> {
        // Nothing to place: an already-complete object is never scheduled.
        Err(vot_scheduler::SinkError)
    }
}

impl vot_cli::ReceiveSink for PushPublishedSink {
    fn resumed_prefix(&self) -> Result<u64, vot_cli::Error> {
        Ok(self.length)
    }

    fn flush(&self) -> Result<(), vot_cli::Error> {
        Ok(())
    }

    fn discard_partial(&self) -> Result<(), vot_cli::Error> {
        Ok(())
    }
}

struct PushFileSink {
    files: PushFiles,
    receive: Arc<PushReceive>,
    stopped: AtomicBool,
}

impl PushFileSink {
    fn check_writable(&self) -> Result<(), SessionError> {
        self.receive.mark_active();
        if self.stopped.load(Ordering::Acquire)
            || self.receive.control.is_cancelled()
            || self.receive.app.lease_lost.load(Ordering::Acquire)
        {
            return Err(SessionError::conflict("native push stopped"));
        }
        Ok(())
    }

    fn place(&self, verified: &vot_sdk::verify::VerifiedSlice<'_>) -> Result<(), SessionError> {
        fn accept(
            file: &FileState,
            verified: &vot_sdk::verify::VerifiedSlice<'_>,
        ) -> Result<(), SessionError> {
            if file.published {
                return Ok(());
            }
            let staged = file
                .native
                .as_ref()
                .ok_or_else(|| SessionError::internal("push file state lost"))?;
            staged
                .native()?
                .accept(verified)
                .map_err(|e| SessionError::internal(e.to_string()))?;
            staged.record(verified)
        }
        let files = self
            .files
            .read()
            .map_err(|_| SessionError::internal("push object poisoned"))?;
        self.check_writable()?;
        if files.is_empty() {
            return Err(SessionError::internal("push object is no longer active"));
        }
        if files.len() <= MAX_OPEN_PUSH_ALIASES {
            return files.iter().try_for_each(|(_, file)| {
                self.check_writable()?;
                accept(file, verified)
            });
        }
        drop(files);
        // ponytail: serialize large alias groups; a bounded clone provider can replace repeated writes.
        let mut files = self
            .files
            .write()
            .map_err(|_| SessionError::internal("push object poisoned"))?;
        self.check_writable()?;
        if files.is_empty() {
            return Err(SessionError::internal("push object is no longer active"));
        }
        for (_, file) in files.iter_mut().filter(|(_, file)| !file.published) {
            self.check_writable()?;
            file.native
                .as_mut()
                .ok_or_else(|| SessionError::internal("push file state lost"))?
                .reopen()?;
            let result = accept(file, verified);
            file.native.as_mut().unwrap().park();
            result?;
        }
        Ok(())
    }
}

impl vot_scheduler::RangeSink for PushFileSink {
    fn write_at(&self, _: u64, _: &[u8]) -> Result<(), vot_scheduler::SinkError> {
        Err(vot_scheduler::SinkError)
    }

    fn write_verified(
        &self,
        verified: &vot_scheduler::VerifiedSlice<'_>,
    ) -> Result<(), vot_scheduler::SinkError> {
        if self.stopped.load(Ordering::Acquire)
            || self.receive.control.is_cancelled()
            || self.receive.app.lease_lost.load(Ordering::Acquire)
        {
            return Err(vot_scheduler::SinkError);
        }
        let verified = vot_sdk::verify::VerifiedSlice::from(*verified);
        if self.place(&verified).is_err() {
            self.stopped.store(true, Ordering::Release);
            return Err(vot_scheduler::SinkError);
        }
        {
            let files = self.files.read().expect("push object poisoned");
            self.receive
                .dirty
                .lock()
                .map_err(|_| vot_scheduler::SinkError)?
                .extend(files.iter().map(|(entry, _)| *entry));
        }
        let due = self
            .receive
            .checkpoint
            .lock()
            .map_err(|_| vot_scheduler::SinkError)?
            .should_checkpoint(verified.data().len() as u64);
        if due && self.receive.run_checkpoint().is_err() {
            self.stopped.store(true, Ordering::Release);
            return Err(vot_scheduler::SinkError);
        }
        self.receive
            .received
            .fetch_add(verified.data().len() as u64, Ordering::AcqRel);
        self.receive
            .app
            .push_metrics
            .add_bytes(verified.data().len() as u64);
        self.receive.mark_active();
        Ok(())
    }
}

impl vot_cli::ReceiveSink for PushFileSink {
    fn resumed_prefix(&self) -> Result<u64, vot_cli::Error> {
        let files = self
            .files
            .read()
            .map_err(|_| std::io::Error::other("push object poisoned"))?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(std::io::Error::other("push sink stopped").into());
        }
        files
            .iter()
            .map(|(_, file)| file_progress(0, file).1)
            .min()
            .ok_or_else(|| std::io::Error::other("push object is no longer active").into())
    }

    fn flush(&self) -> Result<(), vot_cli::Error> {
        let mut files = self
            .files
            .write()
            .map_err(|_| std::io::Error::other("push object poisoned"))?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(std::io::Error::other("push sink stopped").into());
        }
        let parked = files.len() > MAX_OPEN_PUSH_ALIASES;
        let result = files
            .iter_mut()
            .filter(|(_, file)| !file.published)
            .try_for_each(|(_, file)| {
                self.check_writable()
                    .map_err(|error| std::io::Error::other(error.message))?;
                let staged = file
                    .native
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("push file state lost"))?;
                staged
                    .reopen()
                    .map_err(|e| std::io::Error::other(e.message))?;
                let result = staged
                    .native()
                    .map_err(|e| std::io::Error::other(e.message))?
                    .read_staging()
                    .map_err(std::io::Error::other)?
                    .sync_all();
                if parked {
                    staged.park();
                }
                result
            });
        if result.is_err() {
            self.stopped.store(true, Ordering::Release);
        }
        result.map_err(Into::into)
    }

    fn discard_partial(&self) -> Result<(), vot_cli::Error> {
        let _files = self
            .files
            .write()
            .map_err(|_| std::io::Error::other("push object poisoned"))?;
        self.stopped.store(true, Ordering::Release);
        Ok(())
    }
}

pub(crate) fn lock_push_directory(
    directory: &std::path::Path,
    contract: vot_sdk_file::NasContract,
) -> std::io::Result<fs::File> {
    let directory = vot_platform_fs::Directory::open_with_nas(directory, contract)?;
    let location = directory.entry(std::ffi::OsStr::new("writer.lock"))?;
    location.require_removal_parent()?;
    let file = location.open(
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CREATE,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;
    lock_push_handle(file, &location.path())
}

fn lock_push_handle(file: fs::File, path: &std::path::Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::MetadataExt as _;
    file.try_lock().map_err(std::io::Error::other)?;
    let held = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !named.is_file() || held.dev() != named.dev() || held.ino() != named.ino() {
        return Err(std::io::Error::other("push lock changed while opening"));
    }
    Ok(file)
}

/// The staging directory supplied to [`vot_cli::PushAdmission`].
#[must_use]
pub fn push_staging_dir(setup: &WorkerSetup) -> PathBuf {
    setup
        .dest_dir
        .join(".vot-stage")
        .join(format!(".vot-push-{}", hex::encode(setup.session_id)))
}

#[derive(Clone)]
pub(crate) struct PushSeamHandle(std::sync::Weak<PushReceive>);

impl PushSeamHandle {
    pub(crate) fn seams(&self) -> Option<vot_cli::ReceiveSeams> {
        self.0.upgrade().map(receive_seams)
    }
}

pub(crate) fn push_seams(
    app: Arc<crate::app::App>,
    setup: WorkerSetup,
    control: PushControl,
    runtime: tokio::runtime::Handle,
) -> (vot_cli::ReceiveSeams, PushSeamHandle) {
    let receive = Arc::new(PushReceive {
        staging: control.staging_dir(&setup),
        app,
        setup,
        control,
        runtime,
        inner: Mutex::new(PushReceiveInner::default()),
        received: AtomicU64::new(0),
        activity_origin: Instant::now(),
        last_active: AtomicU64::new(0),
        checkpoint: Mutex::new(PersistTracker::new()),
        checkpointing: Mutex::new(()),
        dirty: Mutex::new(HashSet::new()),
    });
    let handle = PushSeamHandle(Arc::downgrade(&receive));
    (receive_seams(receive), handle)
}

fn receive_seams(receive: Arc<PushReceive>) -> vot_cli::ReceiveSeams {
    let mut seams = vot_cli::ReceiveSeams::new(receive.control.cancellation());
    seams.manifest = Some(Arc::new({
        let receive = Arc::clone(&receive);
        move |_, summary, entries| {
            receive
                .prepare_manifest(summary, entries)
                .map_err(|error| receive.cli_error(error))
        }
    }));
    seams.sink = Some(Arc::new({
        let receive = Arc::clone(&receive);
        move |_, object| {
            receive
                .choose_sink(object)
                .map_err(|error| receive.cli_error(error))
        }
    }));
    seams.complete = Some(Arc::new(move |_, object| {
        receive
            .complete_object(object)
            .map_err(|error| receive.cli_error(error))
    }));
    seams
}

fn route_manifest(objects: impl Iterator<Item = (String, ObjectId)>) -> String {
    let files: Vec<_> = objects
        .map(|(name, object)| {
            (
                name,
                suite_name(object.suite),
                hex::encode(object.root),
                object.length,
            )
        })
        .collect();
    crate::route_protocol::manifest_digest(
        files.iter().map(|(name, suite, root, bytes)| {
            (name.as_str(), suite.as_str(), root.as_str(), *bytes)
        }),
    )
}

fn validate_push_manifest(
    setup: &WorkerSetup,
    summary: vot_cli::PackageSummary,
    entries: &[vot_cli::EntryRecord],
) -> Result<Vec<(Vec<String>, ObjectId)>, SessionError> {
    if summary.root != setup.expected_package.root
        || summary.logical_length != setup.expected_package.length
    {
        return Err(SessionError::bad(
            "push manifest does not match the admitted package",
        ));
    }
    let max_entries = max_entries_for_bytes(setup.max_total_bytes);
    if entries.is_empty() || entries.len() > max_entries || summary.entries != entries.len() as u64
    {
        return Err(SessionError::bad(format!(
            "package entry count is outside 1..={max_entries}"
        )));
    }
    let mut total = 0_u64;
    let mut validated = Vec::with_capacity(entries.len());
    for entry in entries {
        if !matches!(entry.storage, vot_cli::Storage::Direct) {
            return Err(SessionError::bad(
                "packed entries are not supported by votport",
            ));
        }
        let components = entry
            .path
            .iter()
            .map(|component| match component {
                vot_manifest::Component::Text(text) => {
                    paths::admit_component(text, setup.allow_hidden).map_err(SessionError::bad)?;
                    Ok(text.clone())
                }
                vot_manifest::Component::Bytes(_) => Err(SessionError::bad(
                    "raw byte paths are not supported by votport",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let object = ObjectId {
            suite: entry.suite.identifier(),
            root: entry.logical_root,
            length: entry.logical_length,
        };
        validate_empty_object(&object)?;
        total = total
            .checked_add(object.length)
            .ok_or_else(|| SessionError::bad("total upload size overflows"))?;
        validated.push((components, object));
    }
    // Same full-fold collision guard as the HTTP admission (finding 503).
    let names: Vec<String> = validated.iter().map(|(path, _)| path.join("/")).collect();
    crate::paths::admit_portable_paths(names.iter().map(String::as_str))
        .map_err(SessionError::bad)?;
    if total != summary.logical_length {
        return Err(SessionError::bad(
            "manifest logical length does not match its entries",
        ));
    }
    if total > setup.max_total_bytes {
        return Err(SessionError::bad(format!(
            "upload of {total} bytes exceeds the {} byte limit for this link",
            setup.max_total_bytes
        )));
    }
    setup
        .store
        .check_route_manifest(&hex::encode(setup.session_id), || {
            route_manifest(
                validated
                    .iter()
                    .map(|(path, object)| (path.join("/"), object.clone())),
            )
        })
        .map_err(SessionError::bad)?;
    Ok(validated)
}

fn file_records_from_refs(setup: &WorkerSetup, files: &[&FileState]) -> Vec<FileRecord> {
    files
        .iter()
        .map(|file| FileRecord {
            path: file.display_path.clone(),
            stored_as: stored_rel(&setup.dest_rel, &file.stored_components),
            bytes: file.object.length,
            suite: suite_name(file.object.suite),
            root: hex::encode(file.object.root),
            receipt: file.receipt,
            deleted: false,
        })
        .collect()
}

#[cfg(test)]
enum LocalProofs {
    Blake3(vot_proof_blake3::GroupCvs),
    Sha256(vot_proof_sha256::PieceHashes),
}

#[cfg(test)]
struct LocalRangeCover {
    covered_offset: u64,
    covered_length: u64,
    proof: Vec<u8>,
}

#[cfg(test)]
impl LocalProofs {
    fn prove(&self, offset: u64, length: u64) -> Result<LocalRangeCover, SessionError> {
        match self {
            Self::Blake3(cvs) => vot_proof_blake3::prove_with(cvs, offset, length)
                .map(|cover| LocalRangeCover {
                    covered_offset: cover.covered_offset,
                    covered_length: cover.covered_length,
                    proof: cover.proof,
                })
                .map_err(|error| SessionError::internal(format!("prove staged object: {error:?}"))),
            Self::Sha256(pieces) => vot_proof_sha256::prove_with(pieces, offset, length)
                .map(|cover| LocalRangeCover {
                    covered_offset: cover.covered_offset,
                    covered_length: cover.covered_length,
                    proof: cover.proof,
                })
                .map_err(|error| SessionError::internal(format!("prove staged object: {error:?}"))),
        }
    }
}

#[cfg(test)]
fn reprove_staging(
    path: &std::path::Path,
    object: &ObjectId,
    mut files: Vec<&mut FileState>,
    mut keep_running: impl FnMut() -> bool,
) -> Result<(), SessionError> {
    validate_empty_object(object)?;
    if !keep_running() {
        return Err(SessionError::conflict("native push was cancelled"));
    }
    if object.length == 0 {
        return Ok(());
    }
    let mut staged = fs::File::open(path)
        .map_err(|error| SessionError::internal(format!("open staged object: {error}")))?;
    let actual = staged
        .metadata()
        .map_err(|error| SessionError::internal(format!("stat staged object: {error}")))?
        .len();
    if actual != object.length {
        return Err(SessionError::bad("staged object length changed"));
    }
    let mut proofs = match object.suite {
        1 => LocalProofs::Blake3(vot_proof_blake3::GroupCvs::new()),
        2 => LocalProofs::Sha256(vot_proof_sha256::PieceHashes::new()),
        _ => return Err(SessionError::bad("unsupported staged object suite")),
    };
    let mut left = object.length;
    let mut group = vec![0_u8; vot_scheduler::RANGE_UNIT_BYTES as usize];
    while left != 0 {
        let length = usize::try_from(left.min(group.len() as u64))
            .map_err(|_| SessionError::internal("staged group length"))?;
        staged
            .read_exact(&mut group[..length])
            .map_err(|error| SessionError::internal(format!("read staged object: {error}")))?;
        match &mut proofs {
            LocalProofs::Blake3(cvs) => cvs.push(&group[..length]).map_err(|error| {
                SessionError::internal(format!("hash staged object: {error:?}"))
            })?,
            LocalProofs::Sha256(pieces) => pieces.push(&group[..length]).map_err(|error| {
                SessionError::internal(format!("hash staged object: {error:?}"))
            })?,
        }
        left -= length as u64;
        if !keep_running() {
            return Err(SessionError::conflict("native push was cancelled"));
        }
    }
    match &mut proofs {
        LocalProofs::Blake3(cvs) => cvs.seal(),
        LocalProofs::Sha256(pieces) => pieces.seal(),
    }
    let mut offset = 0_u64;
    while offset < object.length {
        let requested = (object.length - offset).min(vot_scheduler::MAX_PROOF_RANGE_BYTES);
        let cover = proofs.prove(offset, requested)?;
        let length = usize::try_from(cover.covered_length)
            .map_err(|_| SessionError::internal("verified range length"))?;
        let mut data = vec![0_u8; length];
        staged
            .seek(SeekFrom::Start(cover.covered_offset))
            .and_then(|_| staged.read_exact(&mut data))
            .map_err(|error| SessionError::internal(format!("reread staged object: {error}")))?;
        let verified =
            verify_range(object, cover.covered_offset, &data, &cover.proof).map_err(|error| {
                SessionError::bad(format!(
                    "staged object failed verification: {:?}",
                    error.code()
                ))
            })?;
        for file in &mut files {
            let staged = file
                .native
                .as_mut()
                .ok_or_else(|| SessionError::internal("push file state lost"))?;
            staged.reopen()?;
            staged
                .native()?
                .accept(&verified)
                .map_err(|error| SessionError::internal(format!("write failed: {error}")))?;
            staged.record(&verified)?;
            staged.park();
        }
        offset = cover
            .covered_offset
            .checked_add(cover.covered_length)
            .ok_or_else(|| SessionError::internal("verified range offset overflow"))?;
        if !keep_running() {
            return Err(SessionError::conflict("native push was cancelled"));
        }
    }
    Ok(())
}

fn validate_empty_object(object: &ObjectId) -> Result<(), SessionError> {
    if object.length != 0 {
        return Ok(());
    }
    let suite = Suite::try_from(object.suite)
        .map_err(|_| SessionError::bad("unsupported empty object suite"))?;
    let canonical = InMemoryObjectBuilder::new(suite, Some(0), 0)
        .and_then(InMemoryObjectBuilder::finish)
        .map_err(|error| {
            SessionError::internal(format!("build empty object: {:?}", error.code()))
        })?;
    if canonical.object_id().root != object.root {
        return Err(SessionError::bad("empty object root is not canonical"));
    }
    Ok(())
}

/// How many failed/cancelled session events each link keeps, oldest dropped.
const EVENTS_KEPT: usize = 20;

/// Best effort: feedback must never fail a session, so the store error is
/// dropped. `expected_bytes` is the whole package (manifest included) while
/// `received` counts file payload only, so a near-complete session can read
/// slightly under 100%.
fn record_event(
    setup: &WorkerSetup,
    received: u64,
    at: u64,
    outcome: &str,
    detail: String,
    replays: u64,
    rejected: u64,
) {
    let event = crate::store::SessionEvent {
        at,
        started_at: setup.started_at,
        outcome: outcome.to_owned(),
        detail,
        received_bytes: received,
        expected_bytes: setup.expected_package.length,
        replayed_chunks: replays,
        rejected_chunks: rejected,
    };
    let _ = record_session_event(
        &setup.store,
        &setup.ended,
        &setup.tenant,
        &setup.link_id,
        &setup.client_ip,
        &hex::encode(setup.session_id),
        event,
    );
}

/// Receiving-relative log form of a push staging directory: the `.vot-stage`
/// location with its key truncated to 8 characters, matching the session-tag
/// convention, so raw push keys and absolute paths stay out of logs.
pub(crate) fn push_staging_log_name(staging: &std::path::Path) -> String {
    let name = staging
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let key = name.strip_prefix(".vot-push-").unwrap_or(name);
    format!(".vot-stage/.vot-push-{}", key.get(..8).unwrap_or(key))
}

static STAGED_DROP_REOPEN_WARN: OnceLock<Mutex<crate::api::outbound::ErrorDeduper>> =
    OnceLock::new();
static ENDED_SEND_WARN: OnceLock<Mutex<crate::api::outbound::ErrorDeduper>> = OnceLock::new();

/// Warns at most once per interval per distinct `error` for a `site` whose
/// surrounding state cannot carry a pacer (a Drop, a fire-and-forget send):
/// the first occurrence logs immediately, repeats stay bounded.
fn warn_once_per_interval(
    site: &'static str,
    pacer: &OnceLock<Mutex<crate::api::outbound::ErrorDeduper>>,
    error: &'static str,
    message: &'static str,
) {
    let pacer = pacer.get_or_init(|| Mutex::new(crate::api::outbound::ErrorDeduper::new(site)));
    let due = pacer
        .lock()
        .expect("error-path warn pacer poisoned")
        .observe(error, Instant::now());
    if due {
        tracing::warn!("{message}");
    }
}

fn record_session_event(
    store: &Arc<Store>,
    ended_sender: &mpsc::UnboundedSender<SessionEnded>,
    tenant: &str,
    link_id: &str,
    client_ip: &str,
    session_id: &str,
    event: crate::store::SessionEvent,
) -> Result<bool, String> {
    let session_tag = session_id.get(..8).unwrap_or(session_id);
    tracing::warn!(
        target: "audit", event = "upload_session_ended", link = %link_id,
        session_tag = %session_tag,
        outcome = %event.outcome, detail = %event.detail,
        received_bytes = event.received_bytes, expected_bytes = event.expected_bytes,
        "upload session ended without completing"
    );
    store.audit(
        tenant,
        "",
        "upload_session_ended",
        link_id,
        &serde_json::json!({
            "session_tag": session_tag,
            "outcome": event.outcome,
            "detail": event.detail,
            "received_bytes": event.received_bytes,
            "expected_bytes": event.expected_bytes,
            "client_ip": client_ip
        }),
    );
    crate::app::TRANSFERS.ended(&event.outcome);
    let mut ended = SessionEnded {
        notifications: None,
        tenant: tenant.to_owned(),
        link_id: link_id.to_owned(),
        label: String::new(),
        event: event.clone(),
    };
    let stored = store.update_link(tenant, link_id, |link| {
        ended.label = link.label.clone();
        ended.notifications = link.notifications.clone();
        link.events.push(event);
        if link.events.len() > EVENTS_KEPT {
            let excess = link.events.len() - EVENTS_KEPT;
            link.events.drain(..excess);
        }
    });
    match &stored {
        Ok(true) | Ok(false) => {}
        Err(error) => tracing::warn!(
            target: "audit", event = "upload_session_event_store_failed", link = %link_id,
            outcome = %ended.event.outcome, %error,
            "could not record upload session event"
        ),
    }
    if ended_sender.send(ended).is_err() {
        warn_once_per_interval(
            "session end notification",
            &ENDED_SEND_WARN,
            "receiver gone",
            "session end notification failed; the ended-session receiver is gone",
        );
    }
    stored
}

/// Records a native-push ticket that ended before it opened a VOT session.
pub(crate) fn record_unconnected_push(setup: WorkerSetup, aborted: bool) {
    let (outcome, detail) = if aborted {
        ("cancelled", "cancelled by the sender")
    } else {
        ("interrupted", "native push expired before connecting")
    };
    record_event(&setup, 0, now_unix(), outcome, detail.to_owned(), 0, 0);
}

/// `components` is a stored path as [`FileState`] keeps it: admitted
/// components joined by NUL, which cannot appear inside a component name.
fn stored_rel(dest_rel: &str, components: &str) -> String {
    let tail = components.replace('\0', "/");
    if dest_rel.is_empty() {
        tail
    } else {
        format!("{dest_rel}/{tail}")
    }
}

pub fn suite_name(identifier: u16) -> String {
    match identifier {
        1 => "blake3".to_owned(),
        2 => "sha256".to_owned(),
        other => format!("suite-{other}"),
    }
}

/// Registry of live sessions reachable from async handlers.
pub struct Sessions {
    inner: Arc<Mutex<SessionsInner>>,
}

/// Ownership won before process shutdown. It keeps a request admitted while
/// preparation runs without holding the registry mutex across I/O.
pub struct AdmissionGuard {
    inner: Arc<Mutex<SessionsInner>>,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().expect("sessions poisoned");
        inner.active_admissions = inner.active_admissions.saturating_sub(1);
    }
}

pub struct TenantPin {
    inner: Arc<Mutex<SessionsInner>>,
    tenant: String,
}

impl Drop for TenantPin {
    fn drop(&mut self) {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .pinned
            .remove(&self.tenant);
    }
}

pub struct LinkPin {
    inner: Arc<Mutex<SessionsInner>>,
    link_id: String,
}

impl Drop for LinkPin {
    fn drop(&mut self) {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .pinned_links
            .remove(&self.link_id);
    }
}

/// A finished upload kept briefly answerable: the report it committed and the
/// begin entries synthesized from it, both cloned out under the registry
/// mutex. A sender whose finish reply was lost retries and gets the stored
/// report instead of a 404 it would read as a discarded transfer, and a
/// re-attached begin answers every entry complete, so neither path resends
/// bytes or lands a second record.
#[derive(Clone, Debug)]
struct FinishedUpload {
    at: Instant,
    report: FinishReport,
    entries: Vec<EntryInfo>,
}

/// How long a finished upload stays answerable: long enough for a sender to
/// notice the drop, reload, and confirm — far shorter than the upload record
/// itself, which is permanent.
const FINISHED_TTL: Duration = Duration::from_secs(300);
/// How many finished uploads are kept at once; beyond this the oldest give
/// way, and their senders fall back to the pre-finding 404 behavior.
const FINISHED_CAP: usize = 64;

struct SessionsInner {
    map: HashMap<String, SessionHandle>,
    finished: HashMap<String, FinishedUpload>,
    admission_closed: bool,
    commands_closed: bool,
    active_admissions: usize,
    /// Tenants whose storage subtrees are being deleted. Lives on the same
    /// mutex as `map` so [`Sessions::insert_admitted`] cannot race the pin.
    pinned: HashSet<String>,
    /// Named tenants with an outbound operation in progress. This shares the
    /// mutex with `pinned` so delete and operation admission are atomic.
    outbound: HashMap<String, usize>,
    pinned_links: HashSet<String>,
    #[cfg(test)]
    delete_stall: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    #[cfg(test)]
    tenant_purge_stall: Option<(oneshot::Sender<()>, std::sync::mpsc::Receiver<()>)>,
    #[cfg(test)]
    session_create_stall: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    #[cfg(test)]
    finish_stall: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    #[cfg(test)]
    finish_dispatch_stall: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
}

impl SessionsInner {
    /// Drops finished uploads past their answerable window. Lazy, on access:
    /// no timer owns this map, the registry mutex already serializes it, and
    /// an unanswered map entry costs nothing.
    fn prune_finished(&mut self) {
        self.finished
            .retain(|_, finished| finished.at.elapsed() < FINISHED_TTL);
    }
}

pub struct OutboundOperation<'a> {
    sessions: &'a Sessions,
    tenant: Option<String>,
}

/// Outbound admission that can live with a streaming response body.
pub struct OwnedOutboundOperation {
    inner: Arc<Mutex<SessionsInner>>,
    tenant: Option<String>,
}

impl Drop for OwnedOutboundOperation {
    fn drop(&mut self) {
        let Some(tenant) = self.tenant.take() else {
            return;
        };
        let mut inner = self.inner.lock().expect("sessions poisoned");
        if let Some(count) = inner.outbound.get_mut(&tenant) {
            *count -= 1;
            if *count == 0 {
                inner.outbound.remove(&tenant);
            }
        }
    }
}

impl Drop for OutboundOperation<'_> {
    fn drop(&mut self) {
        let Some(tenant) = self.tenant.take() else {
            return;
        };
        let mut inner = self.sessions.inner.lock().expect("sessions poisoned");
        if let Some(count) = inner.outbound.get_mut(&tenant) {
            *count -= 1;
            if *count == 0 {
                inner.outbound.remove(&tenant);
            }
        }
    }
}

pub struct SessionHandle {
    pub link_id: String,
    pub tenant: String,
    pub reserved_bytes: u64,
    pub sender: mpsc::Sender<Cmd>,
    pub kind: SessionKind,
    pub started_at: u64,
    /// When this process began holding the session, on the monotonic clock:
    /// the upload-duration metric's source, so a backwards wall clock cannot
    /// report an infinite rate and a resumed session measures only its own
    /// active time.
    started: Instant,
    activity: Arc<SessionActivity>,
}

impl SessionHandle {
    /// Seconds the session has been live in this process.
    pub(crate) fn active_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

struct SessionActivity {
    in_flight: AtomicUsize,
    last_active: Mutex<Instant>,
    /// Bytes accepted so far, published by the chunk handler for the admin's
    /// live view; never read on the transfer path.
    received: AtomicU64,
}

/// One session in progress, as the admin pages show it.
#[derive(Clone, Debug, Serialize)]
pub struct ActiveTransfer {
    pub link_id: String,
    pub transport: &'static str,
    pub received: u64,
    pub total: u64,
    pub started_at: u64,
}

pub struct SessionCommand {
    pub sender: mpsc::Sender<Cmd>,
    pub lease: SessionLease,
}

pub struct SessionLease {
    activity: Arc<SessionActivity>,
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        *self
            .activity
            .last_active
            .lock()
            .expect("session activity poisoned") = Instant::now();
        self.activity.in_flight.fetch_sub(1, Ordering::Release);
    }
}

pub struct SessionAdmission {
    pub id: String,
    pub link_id: String,
    pub tenant: String,
    pub reserved_bytes: u64,
    pub max_total_bytes: Option<u64>,
    pub max_tenant_sessions: Option<u64>,
    pub max_link_sessions: usize,
    pub max_sessions: usize,
    pub kind: SessionKind,
}

#[derive(Clone, Debug)]
pub enum SessionKind {
    Http,
    Push(PushControl),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TouchError {
    NotFound,
    WrongKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertError {
    ShuttingDown,
    TenantPinned,
    LinkPinned,
    ByteQuota,
    TenantSessionLimit,
    Capacity,
    Store(String),
}

impl Default for Sessions {
    fn default() -> Self {
        Self::new()
    }
}

impl Sessions {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionsInner {
                map: HashMap::new(),
                finished: HashMap::new(),
                admission_closed: false,
                commands_closed: false,
                active_admissions: 0,
                pinned: HashSet::new(),
                outbound: HashMap::new(),
                pinned_links: HashSet::new(),
                #[cfg(test)]
                delete_stall: None,
                #[cfg(test)]
                tenant_purge_stall: None,
                #[cfg(test)]
                session_create_stall: None,
                #[cfg(test)]
                finish_stall: None,
                #[cfg(test)]
                finish_dispatch_stall: None,
            })),
        }
    }

    /// Wins the process-local admission fence, if shutdown has not closed it.
    pub fn try_admit(&self) -> Option<AdmissionGuard> {
        let mut inner = self.inner.lock().expect("sessions poisoned");
        if inner.admission_closed {
            return None;
        }
        inner.active_admissions += 1;
        Some(AdmissionGuard {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Irreversibly stops new sessions. Existing command leases remain valid
    /// until the checkpoint takes HTTP senders below.
    pub fn close_admission(&self) -> bool {
        let mut inner = self.inner.lock().expect("sessions poisoned");
        let first = !inner.admission_closed;
        inner.admission_closed = true;
        first
    }

    /// Preparations that won admission but have not reached their ownership
    /// mutation yet. Shutdown waits for these permits or the shared deadline.
    pub fn active_admissions(&self) -> usize {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .active_admissions
    }

    /// Excludes other tenant mutations and new sessions until the guard drops.
    /// The default tenant (`""`) is never pinned.
    pub fn try_pin_tenant(&self, tenant: &str) -> Option<TenantPin> {
        if tenant.is_empty() {
            return None;
        }
        let mut inner = self.inner.lock().expect("sessions poisoned");
        if !inner.pinned.insert(tenant.to_owned()) {
            return None;
        }
        Some(TenantPin {
            inner: Arc::clone(&self.inner),
            tenant: tenant.to_owned(),
        })
    }

    pub fn tenant_pinned(&self, tenant: &str) -> bool {
        if tenant.is_empty() {
            return false;
        }
        self.inner
            .lock()
            .expect("sessions poisoned")
            .pinned
            .contains(tenant)
    }

    /// Registers a named-tenant outbound operation unless deletion is pinned.
    /// The default tenant is not deletable and needs no counter.
    pub fn try_begin_outbound(&self, tenant: &str) -> Option<OutboundOperation<'_>> {
        let mut inner = self.inner.lock().expect("sessions poisoned");
        if tenant.is_empty() {
            return Some(OutboundOperation {
                sessions: self,
                tenant: None,
            });
        }
        if inner.pinned.contains(tenant) {
            return None;
        }
        *inner.outbound.entry(tenant.to_owned()).or_default() += 1;
        Some(OutboundOperation {
            sessions: self,
            tenant: Some(tenant.to_owned()),
        })
    }

    /// Registers an outbound operation whose guard can outlive the request
    /// handler, such as a response body stream.
    pub fn try_begin_outbound_owned(&self, tenant: &str) -> Option<OwnedOutboundOperation> {
        let mut inner = self.inner.lock().expect("sessions poisoned");
        if tenant.is_empty() {
            return Some(OwnedOutboundOperation {
                inner: Arc::clone(&self.inner),
                tenant: None,
            });
        }
        if inner.pinned.contains(tenant) {
            return None;
        }
        *inner.outbound.entry(tenant.to_owned()).or_default() += 1;
        Some(OwnedOutboundOperation {
            inner: Arc::clone(&self.inner),
            tenant: Some(tenant.to_owned()),
        })
    }

    pub fn active_outbound_for_tenant(&self, tenant: &str) -> usize {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .outbound
            .get(tenant)
            .copied()
            .unwrap_or_default()
    }

    /// Blocks new sessions for `link_id` while its row is being deleted.
    pub fn pin_link_for_delete(&self, link_id: &str) -> bool {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .pinned_links
            .insert(link_id.to_owned())
    }

    /// Blocks new sessions until the returned guard is dropped.
    pub fn try_pin_link(&self, link_id: &str) -> Option<LinkPin> {
        self.pin_link_for_delete(link_id).then(|| LinkPin {
            inner: Arc::clone(&self.inner),
            link_id: link_id.to_owned(),
        })
    }

    pub fn unpin_link(&self, link_id: &str) {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .pinned_links
            .remove(link_id);
    }

    #[cfg(test)]
    pub fn arm_delete_stall(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        self.inner.lock().expect("sessions poisoned").delete_stall = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }

    #[cfg(test)]
    pub fn arm_tenant_purge_stall(&self) -> (oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        self.inner
            .lock()
            .expect("sessions poisoned")
            .tenant_purge_stall = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }

    #[cfg(test)]
    pub fn wait_tenant_purge_stall(&self) {
        let stall = self
            .inner
            .lock()
            .expect("sessions poisoned")
            .tenant_purge_stall
            .take();
        if let Some((entered, release)) = stall {
            let _ = entered.send(());
            release
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("tenant purge stall was not released");
        }
    }

    #[cfg(test)]
    pub fn arm_session_create_stall(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        self.inner
            .lock()
            .expect("sessions poisoned")
            .session_create_stall = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }

    #[cfg(test)]
    pub fn arm_finish_stall(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        self.inner.lock().expect("sessions poisoned").finish_stall = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }

    #[cfg(test)]
    pub fn arm_finish_dispatch_stall(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        self.inner
            .lock()
            .expect("sessions poisoned")
            .finish_dispatch_stall = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }

    #[cfg(test)]
    pub async fn wait_delete_stall(&self) {
        let stall = self
            .inner
            .lock()
            .expect("sessions poisoned")
            .delete_stall
            .take();
        if let Some((entered, release)) = stall {
            let _ = entered.send(());
            let _ = release.await;
        }
    }

    #[cfg(test)]
    pub async fn wait_session_create_stall(&self) {
        let stall = self
            .inner
            .lock()
            .expect("sessions poisoned")
            .session_create_stall
            .take();
        if let Some((entered, release)) = stall {
            let _ = entered.send(());
            let _ = release.await;
        }
    }

    #[cfg(test)]
    pub async fn wait_finish_stall(&self) {
        let stall = self
            .inner
            .lock()
            .expect("sessions poisoned")
            .finish_stall
            .take();
        if let Some((entered, release)) = stall {
            let _ = entered.send(());
            let _ = release.await;
        }
    }

    #[cfg(test)]
    pub async fn wait_finish_dispatch_stall(&self) {
        let stall = self
            .inner
            .lock()
            .expect("sessions poisoned")
            .finish_dispatch_stall
            .take();
        if let Some((entered, release)) = stall {
            let _ = entered.send(());
            let _ = release.await;
        }
    }

    /// Atomically reserves tenant capacity and fails if a delete pin or quota
    /// prevents admission. All checks share the same lock as insertion.
    pub fn insert_admitted(
        &self,
        admission: SessionAdmission,
        sender: mpsc::Sender<Cmd>,
        received_bytes: impl FnOnce() -> Result<(u64, Vec<crate::store::RetainedReservation>), String>,
    ) -> Result<(), InsertError> {
        self.insert_admitted_inner(admission, sender, received_bytes, false)
    }

    /// Inserts a request that acquired admission before shutdown. The guard
    /// is retained through the quota read and registry mutation.
    pub fn insert_admitted_with_guard(
        &self,
        admission: SessionAdmission,
        sender: mpsc::Sender<Cmd>,
        received_bytes: impl FnOnce() -> Result<(u64, Vec<crate::store::RetainedReservation>), String>,
        guard: AdmissionGuard,
    ) -> Result<AdmissionGuard, InsertError> {
        self.insert_admitted_inner(admission, sender, received_bytes, true)
            .map(|()| guard)
    }

    fn insert_admitted_inner(
        &self,
        admission: SessionAdmission,
        sender: mpsc::Sender<Cmd>,
        received_bytes: impl FnOnce() -> Result<(u64, Vec<crate::store::RetainedReservation>), String>,
        reserved: bool,
    ) -> Result<(), InsertError> {
        let SessionAdmission {
            id,
            link_id,
            tenant,
            reserved_bytes,
            max_total_bytes,
            max_tenant_sessions,
            max_link_sessions,
            max_sessions,
            kind,
        } = admission;
        // Read the committed byte total before taking the lock: the read is
        // a blocking SQL query and this mutex gates every in-flight chunk's
        // touch(). The reserved sum below stays exact under the lock; only
        // the committed figure can be a moment stale, fine for a soft quota.
        let received = match max_total_bytes {
            Some(_) => Some(received_bytes().map_err(InsertError::Store)?),
            None => None,
        };
        let mut inner = self.inner.lock().expect("sessions poisoned");
        if inner.commands_closed || (inner.admission_closed && !reserved) {
            return Err(InsertError::ShuttingDown);
        }
        if !tenant.is_empty() && inner.pinned.contains(&tenant) {
            return Err(InsertError::TenantPinned);
        }
        if inner.pinned_links.contains(&link_id) {
            return Err(InsertError::LinkPinned);
        }
        let replacing = match &kind {
            SessionKind::Push(control) => control.resume_key.as_ref().and_then(|key| {
                inner
                    .map
                    .iter()
                    .find_map(|(id, handle)| match &handle.kind {
                        SessionKind::Push(old) if old.resume_key.as_ref() == Some(key) => {
                            Some((id.clone(), old.parked.load(Ordering::Acquire)))
                        }
                        _ => None,
                    })
            }),
            SessionKind::Http => None,
        };
        if replacing.as_ref().is_some_and(|(_, parked)| !parked) {
            return Err(InsertError::Capacity);
        }
        let old_id = replacing.as_ref().map(|(id, _)| id);
        let handles = || {
            inner
                .map
                .iter()
                .filter(|(id, _)| Some(*id) != old_id)
                .map(|(_, handle)| handle)
        };
        if handles().count() >= max_sessions
            || handles().filter(|handle| handle.link_id == link_id).count() >= max_link_sessions
        {
            return Err(InsertError::Capacity);
        }
        let tenant_sessions = handles().filter(|handle| handle.tenant == tenant).count();
        if max_tenant_sessions.is_some_and(|max| tenant_sessions as u64 >= max) {
            return Err(InsertError::TenantSessionLimit);
        }
        if let Some(max_total) = max_total_bytes {
            let (received, retained) = received.unwrap_or_default();
            let resume_key = match &kind {
                SessionKind::Push(control) => control.resume_key.as_ref(),
                SessionKind::Http => None,
            };
            let resuming = retained.iter().any(|reservation| {
                resume_key.is_some()
                    && reservation.push_key.as_ref() == resume_key
                    && reserved_bytes <= reservation.bytes
            });
            let retained_bytes = retained.iter().filter(|reservation| {
                !inner.map.contains_key(&reservation.id)
                    && !handles().any(|handle| matches!(&handle.kind, SessionKind::Push(control) if control.resume_key.is_some() && control.resume_key == reservation.push_key))
            }).fold(0_u64, |total, reservation| total.saturating_add(reservation.bytes));
            let already_reserved = handles()
                .filter(|handle| handle.tenant == tenant)
                .fold(0_u64, |total, handle| {
                    total.saturating_add(handle.reserved_bytes)
                });
            if !resuming
                && reserved_bytes
                    > max_total
                        .saturating_sub(received)
                        .saturating_sub(already_reserved)
                        .saturating_sub(retained_bytes)
            {
                return Err(InsertError::ByteQuota);
            }
        }
        if let Some((old_id, _)) = replacing {
            inner.map.remove(&old_id);
        }
        inner.map.insert(
            id,
            SessionHandle {
                link_id,
                tenant,
                reserved_bytes,
                sender,
                kind,
                started_at: now_unix(),
                started: Instant::now(),
                activity: Arc::new(SessionActivity {
                    in_flight: AtomicUsize::new(0),
                    last_active: Mutex::new(Instant::now()),
                    received: AtomicU64::new(0),
                }),
            },
        );
        Ok(())
    }

    #[cfg(test)]
    pub fn insert(
        &self,
        id: String,
        link_id: String,
        tenant: String,
        sender: mpsc::Sender<Cmd>,
    ) -> Result<(), InsertError> {
        self.insert_resumed(id, link_id, tenant, 0, sender)
    }

    /// Registers a session re-attached at boot. It was admitted before the
    /// restart, so only its byte reservation is re-established.
    pub fn insert_resumed(
        &self,
        id: String,
        link_id: String,
        tenant: String,
        reserved_bytes: u64,
        sender: mpsc::Sender<Cmd>,
    ) -> Result<(), InsertError> {
        self.insert_admitted(
            SessionAdmission {
                id,
                link_id,
                tenant,
                reserved_bytes,
                max_total_bytes: None,
                max_tenant_sessions: None,
                max_link_sessions: usize::MAX,
                max_sessions: usize::MAX,
                kind: SessionKind::Http,
            },
            sender,
            || Ok((0, Vec::new())),
        )
    }

    /// Removes every HTTP session from the registry and returns its command
    /// sender, for shutdown: the workers are suspended through these, and
    /// nothing else can reach or sweep them meanwhile.
    pub fn take_http(&self) -> Vec<mpsc::Sender<Cmd>> {
        let mut senders = Vec::new();
        self.inner
            .lock()
            .map(|mut inner| {
                inner.commands_closed = true;
                inner.map.retain(|_, handle| {
                    if matches!(handle.kind, SessionKind::Http) {
                        senders.push(handle.sender.clone());
                        return false;
                    }
                    true
                });
            })
            .expect("sessions poisoned");
        senders
    }

    /// Concurrent sessions for one tenant namespace.
    pub fn active_for_tenant(&self, tenant: &str) -> usize {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .map
            .values()
            .filter(|handle| handle.tenant == tenant)
            .count()
    }

    /// The link a session belongs to, for completion notifications.
    pub fn link_id(&self, id: &str) -> Option<String> {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .map
            .get(id)
            .map(|handle| handle.link_id.clone())
    }

    pub(crate) fn contains_push_key(&self, key: &str) -> bool {
        self.inner.lock().expect("sessions poisoned").map.values().any(|handle| {
            matches!(&handle.kind, SessionKind::Push(control) if control.resume_key.as_deref() == Some(key))
        })
    }

    pub fn contains_push(&self, id: &str) -> bool {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .map
            .get(id)
            .is_some_and(|handle| matches!(&handle.kind, SessionKind::Push(_)))
    }

    /// Refreshes an active native push without making it reachable by HTTP.
    pub fn mark_active(&self, id: &str) -> bool {
        let inner = self.inner.lock().expect("sessions poisoned");
        let Some(handle) = inner.map.get(id) else {
            return false;
        };
        if !matches!(&handle.kind, SessionKind::Push(_)) {
            return false;
        }
        *handle
            .activity
            .last_active
            .lock()
            .expect("session activity poisoned") = Instant::now();
        true
    }

    fn push_lease(&self, id: &str) -> Option<SessionLease> {
        let inner = self.inner.lock().expect("sessions poisoned");
        let handle = inner.map.get(id)?;
        if !matches!(&handle.kind, SessionKind::Push(_)) {
            return None;
        }
        handle.activity.in_flight.fetch_add(1, Ordering::AcqRel);
        Some(SessionLease {
            activity: Arc::clone(&handle.activity),
        })
    }

    /// Cancels a connected push after releasing the session registry lock.
    pub fn abort_push(&self, id: &str) -> bool {
        let control = self
            .inner
            .lock()
            .expect("sessions poisoned")
            .map
            .get(id)
            .and_then(|handle| match &handle.kind {
                SessionKind::Push(control) => Some(control.clone()),
                SessionKind::Http => None,
            });
        if let Some(control) = control {
            control.abort();
            true
        } else {
            false
        }
    }

    /// Keeps the session registered until the returned command guard drops.
    pub fn touch(&self, id: &str) -> Result<SessionCommand, TouchError> {
        let inner = self.inner.lock().expect("sessions poisoned");
        let handle = inner.map.get(id).ok_or(TouchError::NotFound)?;
        if matches!(&handle.kind, SessionKind::Push(_)) {
            return Err(TouchError::WrongKind);
        }
        *handle
            .activity
            .last_active
            .lock()
            .expect("session activity poisoned") = Instant::now();
        handle.activity.in_flight.fetch_add(1, Ordering::AcqRel);
        Ok(SessionCommand {
            sender: handle.sender.clone(),
            lease: SessionLease {
                activity: Arc::clone(&handle.activity),
            },
        })
    }

    pub fn remove(&self, id: &str) -> Option<SessionHandle> {
        self.inner.lock().expect("sessions poisoned").map.remove(id)
    }

    /// Remembers a finished upload so its finish and begin stay answerable
    /// for [`FINISHED_TTL`]. Entries are synthesized complete from the
    /// report's records: every file a finished upload committed is fully on
    /// disk. Called once, after the record is committed; the oldest entry is
    /// dropped once the cap is reached rather than refusing the newest.
    pub fn remember_finished(&self, id: &str, report: FinishReport) {
        let entries = report
            .files
            .iter()
            .enumerate()
            .map(|(index, file)| EntryInfo {
                index,
                path: file.path.clone(),
                stored_as: file.stored_as.clone(),
                bytes: file.bytes,
                complete: true,
                covered_bytes: file.bytes,
            })
            .collect();
        let mut inner = self.inner.lock().expect("sessions poisoned");
        inner.prune_finished();
        if inner.finished.len() >= FINISHED_CAP {
            if let Some(oldest) = inner
                .finished
                .iter()
                .min_by_key(|(_, finished)| finished.at)
                .map(|(id, _)| id.clone())
            {
                inner.finished.remove(&oldest);
            }
        }
        inner.finished.insert(
            id.to_owned(),
            FinishedUpload {
                at: Instant::now(),
                report,
                entries,
            },
        );
    }

    /// The stored report for a finished upload, if still fresh.
    pub fn finished_report(&self, id: &str) -> Option<FinishReport> {
        let mut inner = self.inner.lock().expect("sessions poisoned");
        inner.prune_finished();
        inner
            .finished
            .get(id)
            .map(|finished| finished.report.clone())
    }

    /// The begin entries for a finished upload, if still fresh: every entry
    /// complete, so a reconciling sender re-selects without resending.
    pub fn finished_entries(&self, id: &str) -> Option<Vec<EntryInfo>> {
        let mut inner = self.inner.lock().expect("sessions poisoned");
        inner.prune_finished();
        inner
            .finished
            .get(id)
            .map(|finished| finished.entries.clone())
    }

    /// Bytes accepted so far by every live session, for the metrics gauge.
    pub fn bytes_in_flight(&self) -> u64 {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .map
            .values()
            .map(|handle| handle.activity.received.load(Ordering::Relaxed))
            .sum()
    }

    pub fn total(&self) -> usize {
        self.inner.lock().expect("sessions poisoned").map.len()
    }

    pub fn push_total(&self) -> usize {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .map
            .values()
            .filter(|handle| matches!(&handle.kind, SessionKind::Push(_)))
            .count()
    }

    /// Records the session's accepted byte count for the live view. Chunk
    /// replies land out of order, so only a larger count moves it.
    pub fn set_received(&self, id: &str, bytes: u64) {
        if let Some(handle) = self.inner.lock().expect("sessions poisoned").map.get(id) {
            handle.activity.received.fetch_max(bytes, Ordering::Relaxed);
        }
    }

    /// A re-attached session keeps its original start and the bytes it had
    /// covered before the restart, for the admin's live view. The monotonic
    /// start is deliberately not rewound: the upload-duration metric then
    /// charges a resumed session only its own active time, never the server's
    /// downtime.
    pub fn seed_resumed(&self, id: &str, started_at: u64, received: u64) {
        if let Some(handle) = self
            .inner
            .lock()
            .expect("sessions poisoned")
            .map
            .get_mut(id)
        {
            handle.started_at = started_at;
            handle.activity.received.store(received, Ordering::Relaxed);
        }
    }

    /// Sessions in progress for one tenant namespace, newest first.
    pub fn active_transfers(&self, tenant: &str) -> Vec<ActiveTransfer> {
        let inner = self.inner.lock().expect("sessions poisoned");
        let mut transfers: Vec<ActiveTransfer> = inner
            .map
            .values()
            .filter(|handle| handle.tenant == tenant)
            .map(|handle| ActiveTransfer {
                link_id: handle.link_id.clone(),
                transport: match &handle.kind {
                    SessionKind::Push(_) => "push",
                    _ => "http",
                },
                received: handle.activity.received.load(Ordering::Relaxed),
                total: handle.reserved_bytes,
                started_at: handle.started_at,
            })
            .collect();
        transfers.sort_by_key(|transfer| std::cmp::Reverse(transfer.started_at));
        transfers
    }

    pub fn active_for_link(&self, link_id: &str) -> usize {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .map
            .values()
            .filter(|handle| handle.link_id == link_id)
            .count()
    }

    /// Drops idle HTTP and unconnected push sessions. A connected push keeps
    /// its reservation until the receive seams observe cancellation and exit.
    pub fn sweep(&self, idle_secs: u64) {
        let mut cancellations = Vec::new();
        self.inner
            .lock()
            .expect("sessions poisoned")
            .map
            .retain(|_, handle| {
                let active = handle.activity.in_flight.load(Ordering::Acquire) > 0
                    || handle
                        .activity
                        .last_active
                        .lock()
                        .expect("session activity poisoned")
                        .elapsed()
                        .as_secs()
                        < idle_secs;
                if active {
                    return true;
                }
                match &handle.kind {
                    SessionKind::Http => false,
                    SessionKind::Push(control) if !control.is_connected() => false,
                    SessionKind::Push(control) => {
                        cancellations.push(control.cancellation());
                        true
                    }
                }
            });
        for cancellation in cancellations {
            cancellation.cancel();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
