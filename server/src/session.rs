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

#[cfg(test)]
mod log_tests {
    use super::*;

    #[test]
    fn terminal_event_survives_the_cap_and_the_tail_is_counted() {
        let mut log = TransferLog::default();
        for _ in 0..(LOG_CAP + 30) {
            log.push(TransferLog::plain(1, "published", None));
        }
        log.terminal(2, "finished", Some(0));
        let events = log.snapshot();
        assert_eq!(events.len(), LOG_CAP + 2);
        assert_eq!(events[LOG_CAP].kind, "finished");
        assert_eq!(events[LOG_CAP + 1].kind, "elided");
        assert_eq!(events[LOG_CAP + 1].count, Some(30));
        // Not consuming: a failed commit retries with the same log.
        assert_eq!(log.snapshot().len(), LOG_CAP + 2);
    }

    #[test]
    fn quiet_threshold() {
        assert_eq!(quiet_after_secs(0), 60);
        assert_eq!(quiet_after_secs(20), 5);
        assert_eq!(quiet_after_secs(600), 60);
    }

    #[test]
    fn error_path_warns_are_paced_per_distinct_error_and_per_site() {
        // Test-local pacers: module statics used by production Drop paths must
        // not carry state into or out of this test.
        static SITE_A: OnceLock<Mutex<crate::api::outbound::ErrorDeduper>> = OnceLock::new();
        static SITE_B: OnceLock<Mutex<crate::api::outbound::ErrorDeduper>> = OnceLock::new();
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            warn_once_per_interval("site a", &SITE_A, "boom", "first message");
            warn_once_per_interval("site a", &SITE_A, "boom", "first message");
            warn_once_per_interval("site a", &SITE_A, "changed", "first message");
            warn_once_per_interval("site b", &SITE_B, "boom", "second message");
        });
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("first message"))
                .count(),
            2,
            "the repeat is paced away, a changed error logs immediately"
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("second message"))
                .count(),
            1,
            "each site paces independently"
        );
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
    spawn_worker_from(setup, receiver, Phase::AwaitSeal, false, 0);
}

/// `already` is what a re-attached session had covered before the restart,
/// so the byte count reported to the admin spans the whole transfer.
fn spawn_worker_from(
    setup: WorkerSetup,
    mut receiver: mpsc::Receiver<Cmd>,
    mut phase: Phase,
    resumed: bool,
    already: u64,
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
            let waiting_since = now_unix();
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
            let silent = arrived.saturating_sub(waiting_since);
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
    let (mut files, kept) = restore_files(&setup, persisted, || {
        setup.destinations.check_live().is_ok()
    })?;
    for file in files.iter_mut().filter(|file| !file.published) {
        if let Some(staged) = file.native.as_mut() {
            staged.preserve = false;
        }
    }

    let already = persisted_received(persisted);
    spawn_worker_from(setup, receiver, Phase::Receiving { files }, true, already);
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
        if key.len() != 32 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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

fn restore_files(
    setup: &WorkerSetup,
    persisted: &mut PersistedUploadSession,
    active: impl Fn() -> bool,
) -> Result<(Vec<FileState>, Vec<PathBuf>), String> {
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
            if let Err(error) = result {
                checkpoint_session(setup, &mut files);
                return Err(error.message);
            }
        }
    }
    checkpoint_session(setup, &mut files);
    Ok((files, kept))
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

/// A file with this object root already delivered on this link and still on
/// disk at its recorded name: the transfer is skipped and the existing copy
/// reported, instead of publishing a suffixed duplicate.
fn find_delivered(
    setup: &WorkerSetup,
    object: &ObjectId,
    active: impl Fn() -> bool,
) -> Result<Option<Delivered>, SessionError> {
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
            after = stored_as;
            if !active() {
                return Err(SessionError::conflict("receive preparation cancelled"));
            }
            // stored_as is relative to the tenant's subtree: it carries the link
            // dest but not the tenant prefix, which is why dest_rel is stripped
            // before joining under dest_dir. A record made under a
            // different link dest no longer lives beneath dest_dir; skip it.
            let rel = if setup.dest_rel.is_empty() {
                after.as_str()
            } else {
                match after.strip_prefix(&format!("{}/", setup.dest_rel)) {
                    Some(rest) => rest,
                    None => continue,
                }
            };
            if rel.split('/').any(crate::protocol_paths::is_receipt_name) {
                continue;
            }
            if crate::protocol_paths::check_payload_name_length(
                rel.rsplit('/').next().unwrap_or_default(),
            )
            .is_err()
            {
                continue;
            }
            let components: Vec<String> = rel.split('/').map(str::to_owned).collect();
            let Ok(path) = paths::join_under(&setup.dest_dir, &components) else {
                continue;
            };
            match fs::metadata(&path) {
                Ok(meta)
                    if meta.is_file()
                        && meta.len() == object.length
                        && staged_object_valid(&path, object, &active).unwrap_or(false) =>
                {
                    return Ok(Some(Delivered {
                        stored_components: components,
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
    let existing = prepare_parallel(entries, |_, (_, object)| {
        find_delivered(setup, object, &active)
    })?;
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
    activity: Arc<SessionActivity>,
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
    /// covered before the restart.
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
mod pin_tests {
    use super::*;

    fn dummy_sender() -> mpsc::Sender<Cmd> {
        mpsc::channel(1).0
    }

    fn admission(
        id: &str,
        bytes: u64,
        max_total_bytes: u64,
        max_tenant_sessions: u64,
    ) -> SessionAdmission {
        SessionAdmission {
            id: id.to_owned(),
            link_id: "link".to_owned(),
            tenant: "acme".to_owned(),
            reserved_bytes: bytes,
            max_total_bytes: Some(max_total_bytes),
            max_tenant_sessions: Some(max_tenant_sessions),
            max_link_sessions: usize::MAX,
            max_sessions: usize::MAX,
            kind: SessionKind::Http,
        }
    }

    #[test]
    fn insert_fails_while_the_tenant_is_pinned() {
        let sessions = Sessions::new();
        let _pin = sessions.try_pin_tenant("acme").unwrap();
        assert!(sessions.tenant_pinned("acme"));
        let err = sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                "acme".to_owned(),
                dummy_sender(),
            )
            .unwrap_err();
        assert_eq!(err, InsertError::TenantPinned);
        assert_eq!(sessions.total(), 0);

        drop(_pin);
        assert!(!sessions.tenant_pinned("acme"));
        sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                "acme".to_owned(),
                dummy_sender(),
            )
            .unwrap();
        assert_eq!(sessions.total(), 1);
    }

    #[test]
    fn shutdown_admission_is_irreversible_and_owned_work_finishes() {
        let sessions = Sessions::new();
        let guard = sessions.try_admit().expect("admission before stop");
        assert!(sessions.close_admission());
        assert!(!sessions.close_admission());

        sessions
            .insert_admitted_with_guard(
                admission("owned", 1, 100, 2),
                dummy_sender(),
                || Ok((0, Vec::new())),
                guard,
            )
            .expect("owned setup may finish after stop");
        assert_eq!(sessions.total(), 1);
        let _ = sessions.take_http();
        assert!(matches!(
            sessions.insert_admitted(admission("late", 1, 100, 2), dummy_sender(), || Ok((
                0,
                Vec::new()
            )),),
            Err(InsertError::ShuttingDown)
        ));
        assert!(sessions.try_admit().is_none());
    }

    #[test]
    fn pin_is_exclusive() {
        let sessions = Sessions::new();
        let _pin = sessions.try_pin_tenant("acme").unwrap();
        assert!(sessions.try_pin_tenant("acme").is_none());
        assert!(sessions.tenant_pinned("acme"));
        drop(_pin);
        assert!(!sessions.tenant_pinned("acme"));
        let _pin = sessions.try_pin_tenant("acme").unwrap();
    }

    #[test]
    fn delete_pin_blocks_new_outbound_operations_while_active_count_remains() {
        let sessions = Sessions::new();
        let operation = sessions.try_begin_outbound("acme").unwrap();
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 1);
        let _pin = sessions.try_pin_tenant("acme").unwrap();
        assert!(sessions.try_begin_outbound("acme").is_none());
        drop(operation);
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 0);
        drop(_pin);
    }

    #[test]
    fn owned_outbound_operation_keeps_tenant_admitted_until_drop() {
        let sessions = Sessions::new();
        let operation = sessions.try_begin_outbound_owned("acme").unwrap();
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 1);
        let _pin = sessions.try_pin_tenant("acme").unwrap();
        assert!(sessions.try_begin_outbound_owned("acme").is_none());
        drop(operation);
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 0);
        drop(_pin);
    }

    #[test]
    fn pin_does_not_apply_to_the_default_tenant() {
        let sessions = Sessions::new();
        assert!(sessions.try_pin_tenant("").is_none());
        assert!(!sessions.tenant_pinned(""));
        sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                String::new(),
                dummy_sender(),
            )
            .unwrap();
    }

    #[test]
    fn admission_reserves_bytes_and_session_slots_without_overflow() {
        let sessions = Sessions::new();
        sessions
            .insert_admitted(admission("s1", 60, 100, 2), dummy_sender(), || {
                Ok((0, Vec::new()))
            })
            .unwrap();
        let mut full = admission("full", 1, 100, 2);
        full.tenant = "other".to_owned();
        full.max_sessions = 1;
        assert_eq!(
            sessions.insert_admitted(full, dummy_sender(), || Ok((0, Vec::new()))),
            Err(InsertError::Capacity)
        );
        assert_eq!(
            sessions.insert_admitted(admission("s2", 60, 100, 2), dummy_sender(), || Ok((
                0,
                Vec::new()
            )),),
            Err(InsertError::ByteQuota)
        );
        assert_eq!(
            sessions.insert_admitted(
                admission("s2", u64::MAX, u64::MAX, 1),
                dummy_sender(),
                || Ok((0, Vec::new())),
            ),
            Err(InsertError::TenantSessionLimit)
        );
        sessions.remove("s1");
        assert_eq!(
            sessions.insert_admitted(admission("stale", 60, 100, 1), dummy_sender(), || Ok((
                60,
                Vec::new()
            )),),
            Err(InsertError::ByteQuota)
        );
        assert_eq!(
            sessions.insert_admitted(admission("full", 1, u64::MAX, 1), dummy_sender(), || Ok((
                u64::MAX,
                Vec::new()
            )),),
            Err(InsertError::ByteQuota)
        );
        sessions
            .insert_admitted(
                admission("s2", u64::MAX, u64::MAX, 1),
                dummy_sender(),
                || Ok((0, Vec::new())),
            )
            .unwrap();
    }

    #[test]
    fn retained_admissions_stay_charged_without_counting_active_sessions_twice() {
        let usage = || {
            Ok((
                0,
                vec![crate::store::RetainedReservation {
                    id: "existing".into(),
                    push_key: Some("checkpoint".into()),
                    bytes: 60,
                }],
            ))
        };
        let sessions = Sessions::new();
        sessions
            .insert_admitted(admission("existing", 60, 100, 10), dummy_sender(), || {
                Ok((0, Vec::new()))
            })
            .unwrap();
        sessions
            .insert_admitted(admission("other", 40, 100, 10), dummy_sender(), usage)
            .unwrap();
        sessions.remove("existing");
        assert_eq!(
            sessions.insert_admitted(admission("new", 1, 100, 10), dummy_sender(), usage),
            Err(InsertError::ByteQuota)
        );
        let mut resume = admission("resume", 60, 100, 10);
        resume.kind = SessionKind::Push(PushControl::resumable("checkpoint".into(), None));
        sessions
            .insert_admitted(resume, dummy_sender(), usage)
            .unwrap();
        sessions.remove("other");
        sessions
            .insert_admitted(admission("replacement", 40, 100, 10), dummy_sender(), usage)
            .unwrap();
    }

    #[test]
    fn parked_push_replacement_excludes_its_own_slot_and_bytes_only() {
        let sessions = Sessions::new();
        let old = PushControl::resumable("same".to_owned(), None);
        let mut first = admission("first", 60, 100, 1);
        first.kind = SessionKind::Push(old);
        first.max_sessions = 1;
        first.max_link_sessions = 1;
        sessions
            .insert_admitted(first, dummy_sender(), || Ok((0, Vec::new())))
            .unwrap();
        let make_retry = || {
            let mut next = admission("next", 60, 100, 1);
            next.kind = SessionKind::Push(PushControl::resumable("same".to_owned(), None));
            next.max_sessions = 1;
            next.max_link_sessions = 1;
            next
        };
        assert_eq!(
            sessions.insert_admitted(make_retry(), dummy_sender(), || Ok((41, Vec::new()))),
            Err(InsertError::ByteQuota)
        );
        assert!(sessions.contains_push("first"));
        sessions
            .insert_admitted(make_retry(), dummy_sender(), || Ok((40, Vec::new())))
            .unwrap();
        assert!(!sessions.contains_push("first"));
        assert!(sessions.contains_push("next"));
        assert_eq!(
            sessions.inner.lock().unwrap().map["next"].reserved_bytes,
            60
        );
        let mut foreign = make_retry();
        foreign.id = "foreign".to_owned();
        foreign.kind = SessionKind::Push(PushControl::resumable("other".to_owned(), None));
        assert_eq!(
            sessions.insert_admitted(foreign, dummy_sender(), || Ok((0, Vec::new()))),
            Err(InsertError::Capacity)
        );
    }

    #[test]
    fn push_touch_is_rejected_without_changing_activity() {
        let sessions = Sessions::new();
        let mut push = admission("push", 0, 100, 1);
        push.kind = SessionKind::Push(PushControl::new());
        sessions
            .insert_admitted(push, dummy_sender(), || Ok((0, Vec::new())))
            .unwrap();

        assert!(matches!(sessions.touch("push"), Err(TouchError::WrongKind)));
        assert!(matches!(
            sessions.touch("missing"),
            Err(TouchError::NotFound)
        ));
        assert_eq!(sessions.active_for_link("link"), 1);
        sessions.sweep(0);
        assert_eq!(sessions.total(), 0);
    }

    #[test]
    fn connected_push_is_cancelled_and_retained_by_idle_sweep() {
        let sessions = Sessions::new();
        let control = PushControl::new();
        let mut push = admission("push", 0, 100, 1);
        push.kind = SessionKind::Push(control.clone());
        sessions
            .insert_admitted(push, dummy_sender(), || Ok((0, Vec::new())))
            .unwrap();

        assert!(sessions.contains_push("push"));
        assert!(control.connect());
        assert!(!control.connect());
        assert!(sessions.push_lease("missing").is_none());
        let lease = sessions.push_lease("push").unwrap();
        sessions.sweep(0);
        assert!(!control.is_cancelled());
        drop(lease);
        sessions.sweep(0);

        assert!(control.is_cancelled());
        assert!(!control.is_aborted());
        assert!(sessions.contains_push("push"));
        assert_eq!(sessions.total(), 1);
    }

    #[test]
    fn abort_marks_push_as_sender_cancelled() {
        let control = PushControl::new();
        control.abort();
        assert!(control.is_cancelled());
        assert!(control.is_aborted());
    }

    #[test]
    fn push_admission_reserves_bytes_until_removal() {
        let sessions = Sessions::new();
        let mut first = admission("push-1", 60, 100, 2);
        first.kind = SessionKind::Push(PushControl::new());
        sessions
            .insert_admitted(first, dummy_sender(), || Ok((0, Vec::new())))
            .unwrap();

        let mut second = admission("push-2", 50, 100, 2);
        second.kind = SessionKind::Push(PushControl::new());
        assert_eq!(
            sessions.insert_admitted(second, dummy_sender(), || Ok((0, Vec::new()))),
            Err(InsertError::ByteQuota)
        );

        sessions.remove("push-1");
        let mut admitted = admission("push-2", 50, 100, 2);
        admitted.kind = SessionKind::Push(PushControl::new());
        sessions
            .insert_admitted(admitted, dummy_sender(), || Ok((0, Vec::new())))
            .unwrap();
    }

    #[test]
    fn sweep_keeps_cancelled_dispatch_commands_registered_until_worker_finishes() {
        let sessions = Sessions::new();
        let (sender, mut receiver) = mpsc::channel(1);
        sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                "acme".to_owned(),
                sender,
            )
            .unwrap();
        let command = sessions.touch("s1").unwrap();
        let (reply, cancelled_dispatch) = oneshot::channel();
        drop(cancelled_dispatch);
        assert!(command
            .sender
            .try_send(Cmd::Finish {
                reply,
                _lease: command.lease,
            })
            .is_ok());
        sessions.sweep(0);
        assert_eq!(sessions.total(), 1);
        let Cmd::Finish { reply, _lease } = receiver.try_recv().unwrap() else {
            panic!("finish command");
        };
        sessions.sweep(0);
        assert_eq!(sessions.total(), 1);
        *_lease
            .activity
            .last_active
            .lock()
            .expect("session activity poisoned") =
            Instant::now() - std::time::Duration::from_secs(2);
        assert!(reply
            .send(Ok(FinishReport {
                received: 0,
                upload_id: "upload".to_owned(),
                files: Vec::new(),
            }))
            .is_err());
        drop(_lease);
        sessions.sweep(1);
        assert_eq!(sessions.total(), 1);
        sessions.sweep(0);
        assert_eq!(sessions.total(), 0);
    }

    #[test]
    fn insert_fails_while_the_link_is_pinned() {
        let sessions = Sessions::new();
        assert!(sessions.pin_link_for_delete("link"));
        let err = sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                String::new(),
                dummy_sender(),
            )
            .unwrap_err();
        assert_eq!(err, InsertError::LinkPinned);
        assert_eq!(sessions.total(), 0);

        sessions.unpin_link("link");
        sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                String::new(),
                dummy_sender(),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn cancelled_task_releases_link_pin() {
        let sessions = Arc::new(Sessions::new());
        let (entered_tx, entered_rx) = oneshot::channel();
        let task = tokio::spawn({
            let sessions = Arc::clone(&sessions);
            async move {
                let _pin = sessions.try_pin_link("link").unwrap();
                let _ = entered_tx.send(());
                std::future::pending::<()>().await;
            }
        });
        entered_rx.await.unwrap();
        task.abort();
        let _ = task.await;

        assert!(sessions.pin_link_for_delete("link"));
        sessions.unpin_link("link");
    }
}

#[cfg(test)]
mod push_tests {
    use super::*;
    use vot_sdk::object::{InMemoryObjectBuilder, Suite};
    use vot_sdk::package::{PackageBuilder, PackageEntry};

    fn open_destination_for(
        setup: &WorkerSetup,
        components: Vec<String>,
        object: ObjectId,
    ) -> Result<FileState, SessionError> {
        super::open_destination_for(setup, components, object, &Mutex::default())
    }

    fn object(suite: Suite, data: &[u8]) -> ObjectId {
        let mut builder =
            InMemoryObjectBuilder::new(suite, Some(data.len() as u64), data.len() as u64).unwrap();
        builder.update(data).unwrap();
        builder.finish().unwrap().object_id().clone()
    }

    fn empty_manifest(count: usize) -> (ObjectId, Vec<u8>, Vec<u8>, Vec<vot_cli::EntryRecord>) {
        let empty = object(Suite::Blake3Bao64, b"");
        let mut builder = PackageBuilder::new().unwrap();
        let mut records = Vec::with_capacity(count);
        for index in 0..count {
            let name = format!("empty-{index:04}");
            let path = vot_manifest::PackagePath::portable([name.as_str()]).unwrap();
            let entry = PackageEntry::direct(vec![name], &empty).unwrap();
            assert!(builder.push(&entry).unwrap().is_none());
            records.push(record(path, &empty));
        }
        let (summary, final_page, mut finalizer) = builder.finish().unwrap().into_parts();
        let page = finalizer.push(final_page).unwrap().into_bytes();
        let seal = finalizer.finish().unwrap().into_bytes();
        (summary.object_id(), page, seal, records)
    }

    fn setup(directory: &std::path::Path, expected_package: ObjectId) -> WorkerSetup {
        let app = crate::api::testing::build(directory);
        setup_with_app(directory, expected_package, &app)
    }

    fn setup_with_app(
        directory: &std::path::Path,
        expected_package: ObjectId,
        app: &crate::app::App,
    ) -> WorkerSetup {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory.join("receive"))
            .unwrap();
        WorkerSetup {
            store: Arc::clone(&app.store),
            link_id: "link".to_owned(),
            tenant: String::new(),
            client_ip: String::new(),
            dest_dir: directory.join("receive"),
            destinations: Arc::new(
                crate::receiving::Destinations::configured(&directory.join("receive"), &app.store)
                    .unwrap(),
            ),
            dest_rel: String::new(),
            expected_package,
            max_total_bytes: u64::MAX,
            allow_hidden: false,
            signer: Arc::clone(&app.signer),
            session_id: [7; 16],
            started_at: 1,
            quiet_after_secs: 5,
            ended: mpsc::unbounded_channel().0,
            checkpoint_warn: CheckpointWarnPacer::new(),
        }
    }

    /// FileState stores the admitted path as one NUL-joined string; tests
    /// that need the component list back split on that separator.
    fn split_components(joined: &str) -> Vec<String> {
        joined.split('\0').map(str::to_owned).collect()
    }

    #[test]
    fn session_event_writer_reports_store_errors() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(crate::store::Store::open(directory.path()).unwrap());
        store
            .with(|connection| connection.execute_batch("DROP TABLE links"))
            .unwrap();
        let (ended_sender, mut ended_receiver) = mpsc::unbounded_channel();
        let error = record_session_event(
            &store,
            &ended_sender,
            "",
            "deleted-link",
            "",
            "",
            crate::store::SessionEvent {
                at: 2,
                started_at: 1,
                outcome: "cancelled".to_owned(),
                detail: "test cancellation".to_owned(),
                received_bytes: 0,
                expected_bytes: 10,
                replayed_chunks: 0,
                rejected_chunks: 0,
            },
        )
        .unwrap_err();
        assert!(error.contains("no such table: links"), "{error}");
        let ended = ended_receiver.try_recv().unwrap();
        assert_eq!(ended.link_id, "deleted-link");
        assert!(ended.label.is_empty());
        assert!(ended.notifications.is_none());
    }

    #[test]
    fn ended_session_rows_carry_the_session_tag_and_detail() {
        let directory = tempfile::tempdir().unwrap();
        let setup = setup(directory.path(), object(Suite::Blake3Bao64, b""));
        record_event(&setup, 3, 2, "cancelled", "sender hung up".to_owned(), 1, 0);
        let rows = setup.store.audit_export(None, 0, 0, 100).unwrap();
        let row = rows
            .iter()
            .find(|row| row.event == "upload_session_ended")
            .expect("the ended session leaves an audit row");
        assert_eq!(row.detail["session_tag"], "07070707");
        assert_eq!(row.detail["detail"], "sender hung up");
    }

    #[tokio::test]
    async fn queued_begin_is_rejected_by_worker_after_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let setup = setup_with_app(directory.path(), object(Suite::Blake3Bao64, b""), &app);
        let (sender, receiver) = mpsc::channel(1);
        spawn_worker(setup, receiver);
        let activity = Arc::new(SessionActivity {
            in_flight: AtomicUsize::new(1),
            last_active: Mutex::new(Instant::now()),
            received: AtomicU64::new(0),
        });
        let (reply, result) = oneshot::channel();
        app.request_shutdown();
        sender
            .send(Cmd::Begin {
                reply,
                _lease: SessionLease { activity },
                stopping: Arc::clone(&app.stopping),
            })
            .await
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), result)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.status, 503);
    }

    fn record_delivered_files(setup: &WorkerSetup, files: Vec<FileRecord>) {
        let mut link = crate::store::tests::test_link(&setup.link_id);
        link.uploads.push(UploadRecord {
            id: "delivered".into(),
            started_at: 0,
            completed_at: 1,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: hex::encode(setup.expected_package.root),
            total_bytes: 0,
            files,
            partial: false,
            log: Vec::new(),
        });
        setup.store.insert_link(link).unwrap();
    }

    #[tokio::test]
    async fn push_activity_does_not_store_wall_clock_seconds() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let setup = setup_with_app(directory.path(), object(Suite::Blake3Bao64, b""), &app);
        let control = PushControl::new();
        let (_seams, handle) = push_seams(
            Arc::clone(&app),
            setup,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();

        receive.mark_active();
        assert!(
            receive.last_active.load(Ordering::Acquire)
                <= receive.activity_origin.elapsed().as_secs(),
            "push activity must use process elapsed time, not Unix seconds"
        );
    }

    #[tokio::test]
    async fn push_activity_refresh_keeps_progress_live_for_idle_sweep() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let setup = setup_with_app(directory.path(), object(Suite::Blake3Bao64, b""), &app);
        let id = hex::encode(setup.session_id);
        let control = PushControl::new();
        assert!(control.connect());
        let (sender, _) = mpsc::channel(1);
        app.sessions
            .insert_admitted(
                SessionAdmission {
                    id: id.clone(),
                    link_id: setup.link_id.clone(),
                    tenant: setup.tenant.clone(),
                    reserved_bytes: 0,
                    max_total_bytes: None,
                    max_tenant_sessions: None,
                    max_link_sessions: usize::MAX,
                    max_sessions: usize::MAX,
                    kind: SessionKind::Push(control.clone()),
                },
                sender,
                || Ok((0, Vec::new())),
            )
            .unwrap();
        let (_seams, handle) = push_seams(
            Arc::clone(&app),
            setup,
            control.clone(),
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        let stale = || {
            let activity = {
                let inner = app.sessions.inner.lock().unwrap();
                Arc::clone(&inner.map[&id].activity)
            };
            *activity.last_active.lock().unwrap() = Instant::now() - Duration::from_secs(60);
        };

        // Elapsed ticks continue after a hypothetical wall-clock rollback.
        receive.mark_active_at(1);
        stale();
        receive.mark_active_at(2);
        app.sessions.sweep(30);

        assert!(!control.is_cancelled());
        assert!(app.sessions.contains_push(&id));
        assert_eq!(receive.last_active.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn admission_reads_policy_and_events_without_unrelated_upload_headers() {
        use vot_sdk::package::{PackageBuilder, PackageEntry};

        for native in [false, true] {
            for count in [1, 0] {
                if !native && count == 0 {
                    continue;
                }
                for corruption in ["header", "events", "missing", "tenant"] {
                    let directory = tempfile::tempdir().unwrap();
                    let app = crate::api::testing::build(directory.path());
                    let expected = object(Suite::Blake3Bao64, b"new content");
                    let (package, page, seal) = if count == 0 {
                        (object(Suite::Blake3Bao64, b""), Vec::new(), Vec::new())
                    } else {
                        let mut builder = PackageBuilder::new().unwrap();
                        assert!(builder
                            .push(
                                &PackageEntry::direct(
                                    vec!["new".into(), "frame".into()],
                                    &expected
                                )
                                .unwrap()
                            )
                            .unwrap()
                            .is_none());
                        let (summary, page, mut finalizer) = builder.finish().unwrap().into_parts();
                        let page = finalizer.push(page).unwrap().into_bytes();
                        let seal = finalizer.finish().unwrap().into_bytes();
                        (summary.object_id().clone(), page, seal)
                    };
                    let mut setup = setup_with_app(directory.path(), package.clone(), &app);
                    if corruption != "missing" {
                        app.store
                            .insert_link(crate::store::tests::test_link("link"))
                            .unwrap();
                    }
                    match corruption {
                        "header" => app.store.with(|c| c.execute_batch("INSERT INTO link_uploads (link_id, tenant, upload_id, document, file_count) VALUES ('link', '', 'unrelated', '{', 0)")).unwrap(),
                        "events" => app.store.with(|c| c.execute_batch("UPDATE links SET events_json='{' WHERE id='link'")).unwrap(),
                        "tenant" => setup.tenant = "other".into(),
                        _ => {}
                    }
                    let result = if native {
                        let (_seams, handle) = push_seams(
                            app.clone(),
                            setup,
                            PushControl::default(),
                            tokio::runtime::Handle::current(),
                        );
                        let receive = handle.0.upgrade().unwrap();
                        let records = if count == 0 {
                            Vec::new()
                        } else {
                            vec![record(
                                vot_manifest::PackagePath::portable(["new", "frame"]).unwrap(),
                                &expected,
                            )]
                        };
                        receive.prepare_manifest(
                            vot_cli::PackageSummary {
                                root: package.root,
                                logical_length: package.length,
                                entries: count,
                            },
                            &records,
                        )
                    } else {
                        let mut phase = Phase::AwaitSeal;
                        handle_seal(&setup, &mut phase, &seal).unwrap();
                        handle_page(&mut phase, &page).unwrap();
                        handle_begin(&setup, &mut phase).map(|_| ())
                    };
                    if count == 0 {
                        assert_eq!(result.unwrap_err().status, 422);
                        assert!(!directory.path().join("receive/new").exists());
                        assert!(app.store.load_upload_sessions().unwrap().is_empty());
                    } else if corruption == "header" {
                        assert!(result.is_ok(), "native={native}, count={count}: {result:?}");
                    } else {
                        assert!(
                            result.is_err(),
                            "native={native}, count={count}, corruption={corruption}"
                        );
                        assert!(!directory.path().join("receive/new").exists());
                        assert!(app.store.load_upload_sessions().unwrap().is_empty());
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn empty_entry_admission_stays_bounded_for_http_and_native() {
        let cap = 1024 * 1024;
        let count = max_entries_for_bytes(cap) + 1;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let (package, page, seal, records) = empty_manifest(count);
        let mut setup = setup_with_app(directory.path(), package.clone(), &app);
        setup.max_total_bytes = cap;

        let mut phase = Phase::AwaitSeal;
        handle_seal(&setup, &mut phase, &seal).unwrap();
        let error = handle_page(&mut phase, &page).unwrap_err();
        assert_eq!(error.status, 422);
        assert!(error.message.contains("512 entries"), "{}", error.message);
        let begin = handle_begin(&setup, &mut phase).unwrap_err();
        assert_eq!(begin.status, 422);
        assert!(begin.message.contains("does not match manifest"));
        assert!(std::fs::read_dir(&setup.dest_dir).unwrap().next().is_none());
        assert!(app.store.load_upload_sessions().unwrap().is_empty());

        let error = validate_push_manifest(
            &setup,
            vot_cli::PackageSummary {
                root: package.root,
                logical_length: package.length,
                entries: count as u64,
            },
            &records,
        )
        .unwrap_err();
        assert_eq!(error.status, 422);
        assert!(error.message.contains("1..=512"), "{}", error.message);
        assert!(std::fs::read_dir(&setup.dest_dir).unwrap().next().is_none());
        assert!(app.store.load_upload_sessions().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exact_empty_entry_limit_is_accepted_by_http_begin_and_native() {
        let cap = 1024 * 1024;
        let count = max_entries_for_bytes(cap);
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let (package, page, seal, records) = empty_manifest(count);
        let mut setup = setup_with_app(directory.path(), package.clone(), &app);
        setup.max_total_bytes = cap;

        let mut phase = Phase::AwaitSeal;
        handle_seal(&setup, &mut phase, &seal).unwrap();
        assert_eq!(handle_page(&mut phase, &page).unwrap(), 0);
        let files = handle_begin(&setup, &mut phase).unwrap();
        assert_eq!(files.len(), count);
        assert_eq!(app.store.load_upload_sessions().unwrap().len(), 1);

        let validated = validate_push_manifest(
            &setup,
            vot_cli::PackageSummary {
                root: package.root,
                logical_length: package.length,
                entries: count as u64,
            },
            &records,
        )
        .unwrap();
        assert_eq!(validated.len(), count);
    }

    #[tokio::test]
    async fn concurrent_uploads_reserve_names_across_overlapping_destinations() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            for nested_destination in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let application = crate::api::testing::build(directory.path());
                let first_object = object(suite, b"first");
                let second_object = object(suite, b"second");
                let first = setup_with_app(directory.path(), first_object.clone(), &application);
                let mut second =
                    setup_with_app(directory.path(), second_object.clone(), &application);
                second.session_id = [8; 16];
                second.link_id = "other".into();
                let first_entries =
                    [(vec!["project".into(), "frame".into()], first_object.clone())];
                let second_name = if nested_destination {
                    second.dest_dir.push("project");
                    second.dest_rel = "project".into();
                    vec!["frame".into()]
                } else {
                    vec!["project".into(), "frame".into()]
                };
                for setup in [&first, &second] {
                    let mut link = crate::store::tests::test_link(&setup.link_id);
                    link.dest = setup.dest_rel.clone();
                    application.store.insert_link(link).unwrap();
                }
                let second_entries = [(second_name, second_object.clone())];
                let (ready, waiting) = std::sync::mpsc::channel();
                let (mut first_files, mut second_files) = std::thread::scope(|scope| {
                    let (start_a, a_start) = std::sync::mpsc::channel();
                    let (start_b, b_start) = std::sync::mpsc::channel();
                    let prepare =
                        |setup: &WorkerSetup,
                         entries: &[(Vec<String>, ObjectId)],
                         start: std::sync::mpsc::Receiver<()>| {
                            ready.send(()).unwrap();
                            start.recv_timeout(Duration::from_secs(5)).unwrap();
                            let (files, allocation) =
                                prepare_files(setup, entries, || true).unwrap();
                            persist_session(setup, &files).unwrap();
                            drop(allocation);
                            files
                        };
                    let a_input = (&first, &first_entries[..]);
                    let b_input = (&second, &second_entries[..]);
                    let a = scope.spawn(move || prepare(a_input.0, a_input.1, a_start));
                    let b = scope.spawn(move || prepare(b_input.0, b_input.1, b_start));
                    for _ in 0..2 {
                        waiting.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    start_a.send(()).unwrap();
                    start_b.send(()).unwrap();
                    (a.join().unwrap(), b.join().unwrap())
                });
                let first_path = paths::join_under(
                    &first.dest_dir,
                    &split_components(&first_files[0].stored_components),
                )
                .unwrap();
                let second_path = paths::join_under(
                    &second.dest_dir,
                    &split_components(&second_files[0].stored_components),
                )
                .unwrap();
                assert_ne!(
                    first_path, second_path,
                    "admitted uploads must own distinct final names before publication"
                );
                for (setup, files, bytes, object) in [
                    (&first, &mut first_files, b"first".as_slice(), &first_object),
                    (
                        &second,
                        &mut second_files,
                        b"second".as_slice(),
                        &second_object,
                    ),
                ] {
                    let source = directory.path().join("source");
                    fs::write(&source, bytes).unwrap();
                    reprove_staging(&source, object, vec![&mut files[0]], || true).unwrap();
                    publish_file(setup, &mut files[0], || true).unwrap();
                    commit_upload(setup, files, 0, 0, Some("http"), Vec::new()).unwrap();
                }
                assert_eq!(fs::read(first_path).unwrap(), b"first");
                assert_eq!(fs::read(second_path).unwrap(), b"second");
            }
        }
    }

    #[test]
    fn publication_reserves_receipt_filename_bytes() {
        for name in ["a".repeat(242), format!("{}ab", "ア".repeat(80))] {
            let directory = tempfile::tempdir().unwrap();
            let bytes = b"frame";
            let object = object(Suite::Blake3Bao64, bytes);
            let setup = setup(directory.path(), object.clone());
            let parent = "p".repeat(255);
            let source = directory.path().join("source");
            fs::write(&source, bytes).unwrap();
            let entries = [(vec![parent.clone(), name.clone()], object.clone())];
            let (mut files, allocation) = prepare_files(&setup, &entries, || true).unwrap();
            drop(allocation);
            let file = &mut files[0];
            reprove_staging(&source, &object, vec![file], || true).unwrap();
            publish_file(&setup, file, || true).unwrap();
            let destination = setup.dest_dir.join(&parent);
            assert_eq!(fs::read(destination.join(&name)).unwrap(), bytes);
            assert!(file.receipt);
            let sidecar = destination.join(format!("{name}.vot-receipt"));
            let receipt = fs::read(&sidecar).unwrap();
            crate::receipt::verify_receipt_with_key(
                &setup.signer.verifying_key(),
                &receipt,
                &object,
            )
            .unwrap();
            let private = destination.join(".vot-stage");
            let before = fs::read_dir(&private).unwrap().count();
            let other = self::object(Suite::Blake3Bao64, b"other");
            let error = prepare_files(&setup, &[(entries[0].0.clone(), other)], || true)
                .err()
                .expect("oversized collision candidate admitted");
            assert!(error.message.contains("242 UTF-8 bytes; shorten"));
            assert_eq!(fs::read(destination.join(&name)).unwrap(), bytes);
            assert_eq!(fs::read(&sidecar).unwrap(), receipt);
            assert!(!destination.join(paths::with_suffix(&name, 1)).exists());
            assert_eq!(fs::read_dir(&private).unwrap().count(), before);
        }
    }

    #[test]
    fn oversized_payload_names_refuse_preparation_before_staging() {
        for name in ["a".repeat(243), "ア".repeat(81)] {
            let directory = tempfile::tempdir().unwrap();
            let object = object(Suite::Blake3Bao64, b"frame");
            let setup = setup(directory.path(), object.clone());
            let entries = [
                (vec!["new".into(), "allowed".into()], object.clone()),
                (vec!["new".into(), name], object),
            ];
            let error = prepare_files(&setup, &entries, || true)
                .err()
                .expect("oversized payload admitted");
            assert!(error.message.contains("242 UTF-8 bytes; shorten"));
            assert!(!setup.dest_dir.join("new").exists());
        }
    }

    #[tokio::test]
    async fn native_and_http_admissions_share_persisted_names() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        application
            .store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let bytes = [b"http".as_slice(), b"native-one", b"native-two"];
        let objects = bytes.map(|bytes| object(Suite::Blake3Bao64, bytes));
        let http = setup_with_app(directory.path(), objects[0].clone(), &application);
        let natives = [1, 2].map(|index| {
            let mut setup = setup_with_app(directory.path(), objects[index].clone(), &application);
            setup.session_id = [index as u8; 16];
            let key = hex::encode([index as u8; 16]);
            setup.destinations.push_directory(&key).unwrap();
            persist_push(&setup, key.clone()).unwrap();
            let (seams, handle) = push_seams(
                application.clone(),
                setup,
                PushControl::resumable(key, None),
                tokio::runtime::Handle::current(),
            );
            (seams, handle.0.upgrade().unwrap())
        });
        let mut files = std::thread::scope(|scope| {
            let (ready, waiting) = std::sync::mpsc::channel();
            let mut starts = Vec::new();
            let workers = natives
                .iter()
                .zip(&objects[1..])
                .map(|((_, receive), object)| {
                    let ready = ready.clone();
                    let (start, waiting) = std::sync::mpsc::channel();
                    starts.push(start);
                    scope.spawn(move || {
                        ready.send(()).unwrap();
                        waiting.recv_timeout(Duration::from_secs(5)).unwrap();
                        for name in ["a".repeat(243), "ア".repeat(81)] {
                            let error = receive
                                .prepare_manifest(
                                    vot_cli::PackageSummary {
                                        root: object.root,
                                        logical_length: object.length,
                                        entries: 1,
                                    },
                                    &[record(
                                        vot_manifest::PackagePath::portable([&name]).unwrap(),
                                        object,
                                    )],
                                )
                                .unwrap_err();
                            assert!(error.message.contains("242 UTF-8 bytes; shorten"));
                            assert!(!receive.setup.dest_dir.join(name).exists());
                        }
                        receive
                            .prepare_manifest(
                                vot_cli::PackageSummary {
                                    root: object.root,
                                    logical_length: object.length,
                                    entries: 1,
                                },
                                &[record(
                                    vot_manifest::PackagePath::portable(["frame"]).unwrap(),
                                    object,
                                )],
                            )
                            .unwrap();
                    })
                })
                .collect::<Vec<_>>();
            for _ in 0..2 {
                waiting.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            for start in starts {
                start.send(()).unwrap();
            }
            let (files, allocation) =
                prepare_files(&http, &[(vec!["frame".into()], objects[0].clone())], || {
                    true
                })
                .unwrap();
            persist_session(&http, &files).unwrap();
            drop(allocation);
            for worker in workers {
                worker.join().unwrap();
            }
            files
        });
        let saved = application.store.load_upload_sessions().unwrap();
        let names = saved
            .iter()
            .map(|session| session.files[0].stored_components.clone())
            .collect::<HashSet<_>>();
        assert_eq!(names.len(), 3);
        let source = directory.path().join("source");
        fs::write(&source, bytes[0]).unwrap();
        reprove_staging(&source, &objects[0], vec![&mut files[0]], || true).unwrap();
        publish_file(&http, &mut files[0], || true).unwrap();
        commit_upload(&http, &files, 0, 0, Some("http"), Vec::new()).unwrap();
        for ((_, receive), (object, bytes)) in
            natives.iter().zip(objects[1..].iter().zip(&bytes[1..]))
        {
            let requested = vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            };
            let sink = Arc::from(receive.choose_sink(&requested).unwrap().unwrap());
            write_push(Arc::clone(&sink), &requested, bytes);
            sink.flush().unwrap();
            receive.complete_object(&requested).unwrap();
        }
        for session in saved {
            let index = if session.id == hex::encode(http.session_id) {
                0
            } else if session.id == hex::encode([1; 16]) {
                1
            } else {
                2
            };
            assert_eq!(
                fs::read(
                    paths::join_under(&http.dest_dir, &session.files[0].stored_components).unwrap()
                )
                .unwrap(),
                bytes[index]
            );
        }
    }

    #[tokio::test]
    async fn parked_native_names_survive_restart_and_competing_admission() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.receive_dir = directory.path().join("receive");
        let application = crate::app::build(config.clone()).unwrap();
        application
            .store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let bytes = &[7_u8; 65537];
        let expected = object(Suite::Blake3Bao64, bytes);
        let first = setup_with_app(directory.path(), expected.clone(), &application);
        let key = hex::encode([3; 16]);
        let stage = first.destinations.push_directory(&key).unwrap();
        persist_push(&first, key.clone()).unwrap();
        let summary = vot_cli::PackageSummary {
            root: expected.root,
            logical_length: expected.length,
            entries: 1,
        };
        let records = [record(
            vot_manifest::PackagePath::portable(["frame"]).unwrap(),
            &expected,
        )];
        let requested = vot_cli::ReceiveObject {
            object: vot_codec::frames::ObjectId {
                suite: expected.suite,
                root: expected.root,
                length: expected.length,
            },
            entries: Vec::new(),
        };
        let control = PushControl::resumable(
            key.clone(),
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            first,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        let sink = Arc::from(receive.choose_sink(&requested).unwrap().unwrap());
        let accept_half = |sink: Arc<dyn vot_cli::ReceiveSink>, offset: u64| {
            let subject = requested.object.try_into().unwrap();
            let length = (bytes.len() as u64 - offset).min(65536);
            let proof = vot_proof_blake3::prove(bytes, offset, length).unwrap();
            let mut verifier =
                vot_scheduler::ReliableReceiver::new(1 << 20, 1 << 20, 1 << 20).unwrap();
            verifier.begin_ranges(subject, Box::new(sink)).unwrap();
            verifier
                .receive_range(subject, offset, &proof.data, &proof.proof)
                .unwrap();
        };
        accept_half(Arc::clone(&sink), 0);
        sink.flush().unwrap();
        drop(sink);
        drop(receive);
        drop(seams);
        let saved = application.store.load_push_sessions().unwrap().remove(0);
        assert_eq!(saved.files[0].prefix_bytes, 65536);
        assert!(!saved.files[0].published);
        drop(application);

        for modified in [
            std::time::SystemTime::UNIX_EPOCH,
            std::time::SystemTime::now() + Duration::from_secs(365 * 86_400),
        ] {
            let lock = lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap();
            lock.set_modified(modified).unwrap();
            drop(lock);
            let application = crate::app::build(config.clone()).unwrap();
            assert!(application.sessions.contains_push_key(&key));
            drop(application);
        }

        let application = crate::app::build(config).unwrap();
        assert_eq!(
            application.store.load_push_sessions().unwrap(),
            std::slice::from_ref(&saved)
        );
        application.sessions.sweep(0);
        assert!(!application.sessions.contains_push_key(&key));
        assert_eq!(
            application
                .store
                .load_push_session(&key)
                .unwrap()
                .unwrap()
                .files[0]
                .prefix_bytes,
            65536
        );
        let competing_object = object(Suite::Blake3Bao64, b"competing");
        let mut competing =
            setup_with_app(directory.path(), competing_object.clone(), &application);
        competing.session_id = [9; 16];
        let (mut files, allocation) = prepare_files(
            &competing,
            &[(vec!["frame".into()], competing_object.clone())],
            || true,
        )
        .unwrap();
        persist_session(&competing, &files).unwrap();
        drop(allocation);
        assert_ne!(
            files[0].stored_components,
            saved.files[0].stored_components.join("\0")
        );
        let mut retry = setup_with_app(directory.path(), expected.clone(), &application);
        retry.session_id = [8; 16];
        persist_push(&retry, key.clone()).unwrap();
        let control = PushControl::resumable(
            key,
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            retry,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        application
            .store
            .with(|c| c.execute_batch("ALTER TABLE files RENAME TO held_files"))
            .unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        application
            .store
            .with(|c| c.execute_batch("ALTER TABLE held_files RENAME TO files"))
            .unwrap();
        let resumed = application.store.load_push_sessions().unwrap().remove(0);
        assert_ne!(resumed.id, saved.id);
        assert_eq!(resumed.files[0], saved.files[0]);
        let sink: Arc<dyn vot_cli::ReceiveSink> =
            Arc::from(receive.choose_sink(&requested).unwrap().unwrap());
        assert_eq!(sink.resumed_prefix().unwrap(), 65536);
        accept_half(Arc::clone(&sink), 65536);
        sink.flush().unwrap();
        drop(sink);
        receive.complete_object(&requested).unwrap();
        drop(receive);
        drop(seams);
        let source = directory.path().join("source");
        fs::write(&source, b"competing").unwrap();
        reprove_staging(&source, &competing_object, vec![&mut files[0]], || true).unwrap();
        publish_file(&competing, &mut files[0], || true).unwrap();
        commit_upload(&competing, &files, 0, 0, Some("http"), Vec::new()).unwrap();
        assert_eq!(fs::read(competing.dest_dir.join("frame")).unwrap(), bytes);
        assert!(competing.dest_dir.join("frame.vot-receipt").is_file());
        assert_eq!(
            fs::read(
                paths::join_under(
                    &competing.dest_dir,
                    &split_components(&files[0].stored_components),
                )
                .unwrap(),
            )
            .unwrap(),
            b"competing"
        );
    }

    #[test]
    fn pending_names_fold_aliases_and_protect_directory_prefixes() {
        for (first_path, second_path, outcome) in [
            (vec!["Straße"], vec!["STRASSE"], "suffix"),
            (vec!["İ"], vec!["ı"], "suffix"),
            (vec!["é"], vec!["e\u{301}"], "suffix"),
            (vec!["folder"], vec!["FOLDER", "child"], "conflict"),
            (vec!["folder", "child"], vec!["FOLDER"], "suffix"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let expected = object(Suite::Blake3Bao64, b"");
            let first = setup(directory.path(), expected.clone());
            let first_path = first_path
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let second_path = second_path
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let (files, allocation) =
                prepare_files(&first, &[(first_path.clone(), expected.clone())], || true).unwrap();
            persist_session(&first, &files).unwrap();
            drop(allocation);
            let result = prepare_files(&first, &[(second_path.clone(), expected.clone())], || true);
            if outcome == "conflict" {
                assert_eq!(result.err().unwrap().status, 409);
            } else {
                let (other, allocation) = result.unwrap();
                drop(allocation);
                assert_ne!(
                    stored_path_key("", &split_components(&other[0].stored_components)).unwrap(),
                    stored_path_key("", &first_path).unwrap()
                );
                assert_ne!(other[0].stored_components, second_path.join("\0"));
            }
        }
    }

    #[test]
    fn failed_admission_and_cancellation_release_only_new_names() {
        let directory = tempfile::tempdir().unwrap();
        let expected = object(Suite::Blake3Bao64, b"frame");
        let application = crate::api::testing::build(directory.path());
        let first = setup_with_app(directory.path(), expected.clone(), &application);
        let mut second = setup_with_app(directory.path(), expected.clone(), &application);
        second.session_id = [8; 16];
        let entries = [(vec!["frame".into()], expected)];
        let (retained, allocation) = prepare_files(&first, &entries, || true).unwrap();
        persist_session(&first, &retained).unwrap();
        drop(allocation);
        application.store.with(|connection| connection.execute_batch(
            "CREATE TRIGGER fail_admission BEFORE INSERT ON upload_sessions BEGIN SELECT RAISE(ABORT, 'fixture'); END;"
        )).unwrap();
        let (failed, allocation) = prepare_files(&second, &entries, || true).unwrap();
        let released_name = failed[0].stored_components.clone();
        assert!(persist_session(&second, &failed).is_err());
        drop(failed);
        drop(allocation);
        application
            .store
            .with(|connection| connection.execute_batch("DROP TRIGGER fail_admission;"))
            .unwrap();
        let active = AtomicUsize::new(0);
        assert!(
            prepare_files(&second, &entries, || active.fetch_add(1, Ordering::Relaxed)
                == 0)
            .is_err()
        );
        let (retry, allocation) = prepare_files(&second, &entries, || true).unwrap();
        drop(allocation);
        assert_eq!(retry[0].stored_components, released_name);
        assert_ne!(retry[0].stored_components, retained[0].stored_components);
        assert_eq!(application.store.load_upload_sessions().unwrap().len(), 1);
        second.tenant = "other".into();
        second.dest_dir =
            paths::join_under(&first.dest_dir, &paths::tenant_prefix("other")).unwrap();
        let (independent, allocation) = prepare_files(&second, &entries, || true).unwrap();
        drop(allocation);
        assert_eq!(
            independent[0].stored_components,
            retained[0].stored_components
        );
    }

    #[test]
    fn pending_names_preserve_destination_policy_and_manifest_depth() {
        for (destination, components) in [
            ("AUX", vec!["frame".to_owned()]),
            ("archive.", vec!["frame".to_owned()]),
            ("project", vec!["x".to_owned(); 256]),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let expected = object(Suite::Blake3Bao64, b"frame");
            let application = crate::api::testing::build(directory.path());
            let mut first = setup_with_app(directory.path(), expected.clone(), &application);
            first.dest_rel = paths::admit_dest(destination).unwrap();
            first.dest_dir.push(destination);
            vot_manifest::PackagePath::portable(components.clone()).unwrap();
            let (files, allocation) =
                prepare_files(&first, &[(components, expected.clone())], || true).unwrap();
            persist_session(&first, &files).unwrap();
            drop(allocation);
            let mut second = setup_with_app(directory.path(), expected.clone(), &application);
            second.session_id = [8; 16];
            second.dest_rel = "unrelated".into();
            second.dest_dir.push("unrelated");
            let (other, allocation) =
                prepare_files(&second, &[(vec!["frame".into()], expected)], || true).unwrap();
            drop(allocation);
            assert_eq!(other[0].stored_components, "frame");
        }
    }

    #[test]
    fn pending_parent_does_not_block_verified_deduplication() {
        let directory = tempfile::tempdir().unwrap();
        let expected = object(Suite::Blake3Bao64, b"original");
        let first = setup(directory.path(), expected.clone());
        let (pending, allocation) =
            prepare_files(&first, &[(vec!["folder".into()], expected.clone())], || {
                true
            })
            .unwrap();
        persist_session(&first, &pending).unwrap();
        drop(allocation);
        fs::write(first.dest_dir.join("existing.bin"), b"original").unwrap();
        let record = FileRecord {
            path: "existing.bin".into(),
            stored_as: "existing.bin".into(),
            bytes: 8,
            suite: suite_name(expected.suite),
            root: hex::encode(expected.root),
            receipt: false,
            deleted: false,
        };
        record_delivered_files(&first, vec![record]);
        let (files, allocation) = prepare_files(
            &first,
            &[(vec!["folder".into(), "copy.bin".into()], expected)],
            || true,
        )
        .unwrap();
        drop(allocation);
        assert_eq!(files[0].stored_components, "existing.bin");
        assert!(files[0].published);
        assert!(files[0].native.is_none());
        assert!(!first.dest_dir.join("folder").exists());
    }

    #[test]
    fn preparation_reserves_distinct_names_before_publication() {
        for count in [2, 32] {
            for (extension, nested) in [("pdf", false), ("PDF", false), ("pdf", true)] {
                let directory = tempfile::tempdir().unwrap();
                let object = object(Suite::Blake3Bao64, b"");
                let setup = setup(directory.path(), object.clone());
                let mut entries = Vec::new();
                for index in 0..count / 2 {
                    let parent = format!("pair-{index}");
                    fs::create_dir(setup.dest_dir.join(&parent)).unwrap();
                    fs::write(setup.dest_dir.join(&parent).join("report.pdf"), b"existing")
                        .unwrap();
                    entries.push((vec![parent, "report.pdf".into()], object.clone()));
                }
                for index in 0..count / 2 {
                    let mut components =
                        vec![format!("pair-{index}"), format!("report-1.{extension}")];
                    if nested {
                        components.push("child".into());
                    }
                    entries.push((components, object.clone()));
                }
                let (mut files, allocation) = prepare_files(&setup, &entries, || true).unwrap();
                persist_session(&setup, &files).unwrap();
                drop(allocation);
                let mut names = HashSet::new();
                for file in &mut files {
                    let path = vot_manifest::PackagePath::portable(split_components(
                        &file.stored_components,
                    ))
                    .unwrap();
                    let key = vot_manifest::canonical_path_key(
                        &path,
                        vot_manifest::PathProfile::Portable,
                    )
                    .unwrap();
                    assert!(
                        names.insert(key),
                        "stored name claimed twice: {}",
                        file.stored_components.replace('\0', "/")
                    );
                    publish_file(&setup, file, || true).unwrap();
                    assert_eq!(
                        fs::metadata(
                            paths::join_under(
                                &setup.dest_dir,
                                &split_components(&file.stored_components)
                            )
                            .unwrap()
                        )
                        .unwrap()
                        .len(),
                        0
                    );
                }
                assert!(checkpoint_session(&setup, &mut files));
                for index in 0..count / 2 {
                    assert_eq!(
                        fs::read(setup.dest_dir.join(format!("pair-{index}/report.pdf"))).unwrap(),
                        b"existing"
                    );
                }
            }
        }
    }

    #[test]
    fn preparation_bounds_workers_preserves_order_and_cleans_up_on_failure() {
        for count in [0, 1, 16, 17, 128] {
            let directory = tempfile::tempdir().unwrap();
            let object = object(Suite::Blake3Bao64, b"frame");
            let setup = setup(directory.path(), object.clone());
            let mut entries = (0..count)
                .map(|index| (vec![format!("frame-{index}")], object.clone()))
                .collect::<Vec<_>>();
            let workers = Mutex::new([HashSet::new(), HashSet::new()]);
            let checks = AtomicUsize::new(0);
            let (files, allocation) = prepare_files(&setup, &entries, || {
                let phase = checks.fetch_add(1, Ordering::Relaxed) / count;
                workers.lock().unwrap()[phase].insert(std::thread::current().id());
                true
            })
            .unwrap();
            drop(allocation);
            assert_eq!(files.len(), count);
            for (index, file) in files.iter().enumerate() {
                assert_eq!(file.stored_components, entries[index].0.join("\0"));
                assert!(!file.published);
            }
            assert_eq!(checks.load(Ordering::Relaxed), count * 2);
            for phase in workers.lock().unwrap().iter() {
                assert!(phase.len() <= MAX_CHUNK_BATCH);
                if count >= MAX_CHUNK_BATCH * 2 {
                    assert!(phase.len() > 1);
                }
            }
            drop(files);
            if count == 0 {
                continue;
            }
            fs::write(setup.dest_dir.join("blocked"), b"unrelated").unwrap();
            entries[count / 2].0 = vec!["blocked".into(), "frame".into()];
            assert!(prepare_files(&setup, &entries, || true).is_err());
            assert_eq!(
                fs::read(setup.dest_dir.join("blocked")).unwrap(),
                b"unrelated"
            );
            assert_eq!(
                fs::read_dir(setup.dest_dir.join(".vot-stage"))
                    .unwrap()
                    .count(),
                0
            );
            let checks = AtomicU64::new(0);
            assert!(
                prepare_files(&setup, &entries, || checks.fetch_add(1, Ordering::Relaxed)
                    < 1)
                .is_err()
            );
            assert_eq!(
                fs::read_dir(setup.dest_dir.join(".vot-stage"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }

    #[test]
    fn stopped_storage_preserves_staging_and_refuses_writes_and_publication() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"data");
        let setup = setup(directory.path(), object.clone());
        let mut file = open_destination_for(&setup, vec!["file".into()], object).unwrap();
        let staged = file.native.as_mut().unwrap();
        staged.reopen().unwrap();
        let staging = staged.staging.clone();
        let journal = staged.journal.clone();
        setup.destinations.stop();
        assert!(staged.native().is_err());
        assert!(staged.reopen().is_err());
        assert!(staged.directory().is_err());
        assert!(finish_publication(&setup, &mut file).is_err());
        let mut phase = Phase::Receiving { files: vec![file] };
        assert!(!commit_partial(
            &setup,
            &mut phase,
            0,
            0,
            &TransferLog::default()
        ));
        drop(phase);
        assert!(staging.is_file());
        assert!(journal.is_file());
        assert!(!setup.dest_dir.join("file").exists());
    }

    #[test]
    fn staged_validation_distinguishes_bad_content_from_io_and_cancellation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("object");
        let expected = object(Suite::Blake3Bao64, b"complete");
        for (bytes, valid) in [
            (b"complete".as_slice(), true),
            (b"corrupt!", false),
            (b"short", false),
            (b"complete!", false),
        ] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(
                staged_object_valid(&path, &expected, || true).unwrap(),
                valid
            );
        }
        fs::write(&path, b"complete").unwrap();
        assert!(staged_object_valid(&path, &expected, || false).is_err());
        assert!(!staged_object_valid(&path, &expected, || {
            use std::io::Write;
            fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"!")
                .unwrap();
            true
        })
        .unwrap());
        fs::remove_file(&path).unwrap();
        assert!(staged_object_valid(&path, &expected, || true).is_err());
        fs::create_dir(&path).unwrap();
        assert!(staged_object_valid(&path, &expected, || true).is_err());
        #[cfg(unix)]
        {
            fs::remove_dir(&path).unwrap();
            let target = directory.path().join("target");
            fs::write(&target, b"complete").unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
            assert!(staged_object_valid(&path, &expected, || true).is_err());
        }
    }

    #[test]
    fn ordinary_parking_preserves_verification_but_changed_bytes_require_rehash() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"verified bytes";
        let object = object(Suite::Blake3Bao64, bytes);
        let setup = setup(directory.path(), object.clone());
        let mut file =
            open_destination_for(&setup, vec!["frame.exr".into()], object.clone()).unwrap();
        let proof = vot_proof_blake3::prove(bytes, 0, bytes.len() as u64).unwrap();
        let verified = verify_range(&object, 0, bytes, &proof.proof).unwrap();
        let staged = file.native.as_mut().unwrap();
        staged.reopen().unwrap();
        staged.native().unwrap().accept(&verified).unwrap();
        staged.record(&verified).unwrap();
        staged.park();
        staged.reopen().unwrap();
        assert!(
            !staged.reopened,
            "ordinary parking must not cause another full payload read"
        );
        staged.park();
        fs::write(staged.staging_path(), b"changed bytes").unwrap();
        assert!(prepare_publication(&mut file, || true).is_err());
        assert!(!setup.dest_dir.join("frame.exr").exists());
    }

    #[test]
    fn cancelled_publication_keeps_verified_staging_before_during_and_after_rehash() {
        for allowed_checks in [0, 1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let bytes = b"verified";
            let object = object(Suite::Blake3Bao64, bytes);
            let setup = setup(directory.path(), object.clone());
            let source = directory.path().join("source");
            fs::write(&source, bytes).unwrap();
            let mut file =
                open_destination_for(&setup, vec!["frame".into()], object.clone()).unwrap();
            reprove_staging(&source, &object, vec![&mut file], || true).unwrap();
            file.rehash = true;
            let checks = std::cell::Cell::new(0);
            assert!(publish_file(&setup, &mut file, || {
                let current = checks.get();
                checks.set(current + 1);
                current < allowed_checks
            })
            .is_err());
            assert!(!setup.dest_dir.join("frame").exists());
            assert_eq!(
                file.native.as_ref().unwrap().progress().prefix_bytes,
                bytes.len() as u64
            );
            publish_file(&setup, &mut file, || true).unwrap();
            assert_eq!(fs::read(setup.dest_dir.join("frame")).unwrap(), bytes);
        }
    }

    #[test]
    fn batch_file_operations_select_each_entry_once_and_overlap() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"batch");
        let setup = setup(directory.path(), object.clone());
        let mut files = (0..4)
            .map(|entry| {
                open_destination_for(&setup, vec![entry.to_string()], object.clone()).unwrap()
            })
            .collect::<Vec<_>>();
        let arrived = AtomicUsize::new(0);
        let parent = std::thread::current().id();
        let results = map_batch_files(&mut files, [3, 0, 3, usize::MAX, 1].into_iter(), |file| {
            assert_ne!(std::thread::current().id(), parent);
            arrived.fetch_add(1, Ordering::SeqCst);
            for _ in 0..1000 {
                if arrived.load(Ordering::SeqCst) == 3 {
                    return file.display_path.clone();
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            panic!("independent batch entries did not overlap");
        });
        assert_eq!(arrived.load(Ordering::SeqCst), 3);
        assert_eq!(
            results,
            HashMap::from([(0, "0".into()), (1, "1".into()), (3, "3".into())])
        );
        let single = map_batch_files(&mut files, [2, 2].into_iter(), |file| {
            assert_eq!(std::thread::current().id(), parent);
            file.display_path.clone()
        });
        assert_eq!(single, HashMap::from([(2, "2".into())]));
        assert!(
            map_batch_files(&mut files, [usize::MAX].into_iter(), |_| panic!(
                "invalid entry selected"
            ))
            .is_empty()
        );
    }

    #[test]
    fn batch_publication_keeps_entry_results_and_failed_staging() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = vec![0x73; 65_536];
        let object = object(Suite::Blake3Bao64, &bytes);
        let setup = setup(directory.path(), object.clone());
        let mut phase = Phase::Receiving {
            files: (0..3)
                .map(|entry| {
                    open_destination_for(&setup, vec![format!("file-{entry}")], object.clone())
                        .unwrap()
                })
                .collect(),
        };
        let chunk = |entry, valid| {
            let proof = vot_proof_blake3::prove(&bytes, 0, bytes.len() as u64).unwrap();
            BatchChunk {
                entry,
                offset: proof.covered_offset,
                proof: proof.proof.into(),
                data: if valid {
                    proof.data.into()
                } else {
                    vec![0; bytes.len()].into()
                },
                reply: oneshot::channel().0,
                _lease: SessionLease {
                    activity: Arc::new(SessionActivity {
                        in_flight: AtomicUsize::new(1),
                        last_active: Mutex::new(Instant::now()),
                        received: AtomicU64::new(0),
                    }),
                },
            }
        };
        if let Phase::Receiving { files } = &mut phase {
            files[0].native.as_mut().unwrap().reopen().unwrap();
        }
        fs::write(setup.dest_dir.join("file-0"), b"existing destination").unwrap();
        let result = accept_batch(
            &setup,
            &mut phase,
            &[
                chunk(2, true),
                chunk(0, true),
                chunk(2, true),
                chunk(usize::MAX, true),
                chunk(1, false),
            ],
        );
        let duplicates = [result[0].as_ref().unwrap(), result[2].as_ref().unwrap()];
        assert!(duplicates.iter().all(|result| result.complete));
        assert_eq!(
            duplicates.iter().filter(|result| result.accepted).count(),
            1
        );
        assert_eq!(duplicates.iter().filter(|result| result.replay).count(), 1);
        assert!(
            result[1].as_ref().unwrap_err().message.contains("publish"),
            "{:?}",
            result[1]
        );
        assert_eq!(result[3].as_ref().unwrap_err().status, 422);
        assert_eq!(result[4].as_ref().unwrap_err().status, 422);
        assert_eq!(
            fs::read(setup.dest_dir.join("file-0")).unwrap(),
            b"existing destination"
        );
        assert!(!setup.dest_dir.join("file-1").exists());
        assert_eq!(fs::read(setup.dest_dir.join("file-2")).unwrap(), bytes);
        let retried = accept_batch(&setup, &mut phase, &[chunk(1, true), chunk(2, true)]);
        assert!(retried
            .iter()
            .all(|result| result.as_ref().is_ok_and(|result| result.complete)));
        assert!(retried[1].as_ref().unwrap().replay);
        let Phase::Receiving { files } = phase else {
            unreachable!()
        };
        assert!(!files[0].published);
        let failed = files[0].native.as_ref().unwrap();
        assert!(failed.journal.is_file());
        assert_eq!(fs::read(&failed.staging).unwrap(), bytes);
        for file in files.into_iter().skip(1) {
            assert!(file.published && file.receipt);
            assert_eq!(
                fs::read(setup.dest_dir.join(&file.display_path)).unwrap(),
                bytes
            );
            assert!(file.native.as_ref().unwrap().active.is_none());
        }
    }

    #[test]
    fn checkpoints_skip_unchanged_rows_and_retry_every_failed_change() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"checkpoint";
        let object = object(Suite::Blake3Bao64, bytes);
        let setup = setup(directory.path(), object.clone());
        let source = directory.path().join("source");
        fs::write(&source, bytes).unwrap();
        let mut files = (0..2)
            .map(|entry| {
                open_destination_for(&setup, vec![format!("frame-{entry}")], object.clone())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        persist_session(&setup, &files).unwrap();
        let connection =
            rusqlite::Connection::open(directory.path().join("data/votport.db")).unwrap();
        connection.execute_batch("CREATE TABLE checkpoint_writes(entry INTEGER);
            CREATE TRIGGER reject_unchanged_checkpoint BEFORE UPDATE ON upload_session_files
            WHEN NEW.prefix_bytes = OLD.prefix_bytes AND NEW.published = OLD.published AND NEW.receipt = OLD.receipt
            BEGIN SELECT RAISE(FAIL, 'unchanged checkpoint row'); END;
            CREATE TRIGGER count_checkpoint AFTER UPDATE ON upload_session_files
            BEGIN INSERT INTO checkpoint_writes VALUES (NEW.entry); END;").unwrap();
        let writes = || {
            connection
                .query_row("SELECT COUNT(*) FROM checkpoint_writes", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
        };
        assert!(checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 0);
        reprove_staging(&source, &object, vec![&mut files[0]], || true).unwrap();
        assert!(checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 1);
        assert!(checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 1);

        *files[0]
            .native
            .as_mut()
            .unwrap()
            .coverage
            .get_mut()
            .unwrap() = ObjectCoverage::new(&object);
        assert!(checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 2);
        reprove_staging(&source, &object, files.iter_mut().collect(), || true).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER fail_second_checkpoint BEFORE UPDATE ON upload_session_files
            WHEN NEW.entry = 1 BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;",
            )
            .unwrap();
        assert!(!checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 2);
        assert!(setup.store.load_upload_sessions().unwrap()[0]
            .files
            .iter()
            .all(|file| file.prefix_bytes == 0));
        connection
            .execute_batch("DROP TRIGGER fail_second_checkpoint;")
            .unwrap();
        assert!(checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 4);
        assert!(setup.store.load_upload_sessions().unwrap()[0]
            .files
            .iter()
            .all(|file| file.prefix_bytes == object.length));

        for (published, receipt) in [(true, false), (true, true), (true, false)] {
            files[0].published = published;
            files[0].receipt = receipt;
            checkpoint_files(&setup, files.iter().enumerate()).unwrap();
            let saved = &setup.store.load_upload_sessions().unwrap()[0].files[0];
            assert_eq!((saved.published, saved.receipt), (published, receipt));
        }
        assert_eq!(writes(), 7);
    }

    #[test]
    fn checkpoint_snapshot_keeps_writes_arriving_during_database_wait() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = vec![0x53; 131_072];
        let mut builder =
            InMemoryObjectBuilder::new(Suite::Blake3Bao64, Some(bytes.len() as u64), 131_072)
                .unwrap();
        builder.update(&bytes).unwrap();
        let prepared = builder.finish().unwrap();
        let setup = setup(directory.path(), prepared.object_id().clone());
        let mut file =
            open_destination_for(&setup, vec!["frame".into()], prepared.object_id().clone())
                .unwrap();
        persist_session(&setup, std::slice::from_ref(&file)).unwrap();
        file.native.as_mut().unwrap().reopen().unwrap();
        let files = [file];
        let send = |offset| {
            let proof = prepared.prove(offset, 65_536).unwrap();
            let offset = offset as usize;
            accept_range(
                &files,
                0,
                offset as u64,
                proof.proof(),
                &bytes[offset..offset + 65_536],
            )
            .unwrap();
        };
        send(0);
        let (snapshot, ready) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            setup
                .store
                .with(|_| {
                    scope.spawn(|| {
                        checkpoint_files(
                            &setup,
                            files.iter().enumerate().chain(std::iter::from_fn(|| {
                                snapshot.send(()).unwrap();
                                None
                            })),
                        )
                        .unwrap();
                    });
                    ready.recv_timeout(Duration::from_secs(5)).unwrap();
                    send(65_536);
                    Ok(())
                })
                .unwrap();
        });
        assert_eq!(
            setup.store.load_upload_sessions().unwrap()[0].files[0].prefix_bytes,
            65_536
        );
        checkpoint_files(&setup, files.iter().enumerate()).unwrap();
        assert_eq!(
            setup.store.load_upload_sessions().unwrap()[0].files[0].prefix_bytes,
            131_072
        );

        let (finished, done) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            setup
                .store
                .with(|_| {
                    scope.spawn(|| {
                        checkpoint_files(&setup, files.iter().enumerate()).unwrap();
                        finished.send(()).unwrap();
                    });
                    done.recv_timeout(Duration::from_secs(5))
                        .expect("unchanged checkpoint waited for SQLite");
                    Ok(())
                })
                .unwrap();
        });
    }

    #[test]
    fn publication_recovery_recognizes_its_existing_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"frame";
        let object = object(Suite::Blake3Bao64, bytes);
        let setup = setup(directory.path(), object.clone());
        let source = directory.path().join("source");
        fs::write(&source, bytes).unwrap();
        let mut file = open_destination_for(&setup, vec!["frame".into()], object).unwrap();
        reprove_staging(&source, &file.object.clone(), vec![&mut file], || true).unwrap();
        persist_session(&setup, std::slice::from_ref(&file)).unwrap();
        publish_file(&setup, &mut file, || true).unwrap();
        assert!(file.published && file.receipt);
        let sidecar = setup.dest_dir.join("frame.vot-receipt");
        let evidence = fs::read(&sidecar).unwrap();
        file.native.take().unwrap().abandon();
        let mut saved = setup.store.load_upload_sessions().unwrap().remove(0);
        assert!(!saved.files[0].published && !saved.files[0].receipt);
        let (files, _) = restore_files(&setup, &mut saved, || true).unwrap();
        assert!(files[0].published && files[0].receipt);
        assert_eq!(fs::read(&sidecar).unwrap(), evidence);
        assert_eq!(fs::read(setup.dest_dir.join("frame")).unwrap(), bytes);
        assert!(setup.store.load_upload_sessions().unwrap()[0].files[0].receipt);
    }

    #[test]
    fn persisted_components_survive_a_save_restore_round_trip_byte_identically() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"frame");
        let setup = setup(directory.path(), object.clone());
        let mut files = vec![
            open_destination_for(&setup, vec!["plain.bin".into()], object.clone()).unwrap(),
            open_destination_for(
                &setup,
                vec!["nested".into(), "dir".into(), "report.pdf".into()],
                object,
            )
            .unwrap(),
        ];
        persist_session(&setup, &files).unwrap();
        // Park the staging the way a crash would leave it, after the
        // admission record carries the live staging paths.
        for file in &mut files {
            file.native.take().unwrap().abandon();
        }
        let mut saved = setup.store.load_upload_sessions().unwrap().remove(0);
        // The persisted cell must remain the pre-existing JSON array of
        // components: the in-memory representation changed, the schema did not.
        let wire = |files: &[crate::store::PersistedUploadFile]| {
            files
                .iter()
                .map(|file| serde_json::to_string(&file.stored_components).unwrap())
                .collect::<Vec<_>>()
        };
        let first_wire = wire(&saved.files);
        assert_eq!(
            saved.files[1].stored_components,
            ["nested", "dir", "report.pdf"]
        );
        let (restored, _) = restore_files(&setup, &mut saved, || true).unwrap();
        assert_eq!(restored[1].stored_components, "nested\0dir\0report.pdf");
        persist_session(&setup, &restored).unwrap();
        let resaved = setup.store.load_upload_sessions().unwrap().remove(0);
        assert_eq!(resaved, saved);
        assert_eq!(wire(&resaved.files), first_wire);
    }

    #[test]
    fn admission_refuses_entries_over_the_session_cap_with_the_cap_named() {
        let directory = tempfile::tempdir().unwrap();
        let expected = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), expected.clone());
        // The empty trailing component is rejected by per-name validation, so
        // if the cap check is ever removed or reordered behind it, this test
        // still fails (fast, with the wrong message) instead of staging
        // MAX_SESSION_ENTRIES real files.
        let entries =
            vec![(vec!["f.bin".to_owned(), String::new()], expected); MAX_SESSION_ENTRIES + 1];
        let error = prepare_files(&setup, &entries, || true).err().unwrap();
        assert_eq!(error.status, 422);
        assert!(error.message.contains("262144"), "{}", error.message);
    }

    #[test]
    fn session_cap_admits_cap_minus_one_entries() {
        assert!(check_session_entry_cap(MAX_SESSION_ENTRIES - 1).is_ok());
        assert!(check_session_entry_cap(MAX_SESSION_ENTRIES).is_ok());
    }

    #[test]
    fn restore_refuses_replaying_persisted_sessions_over_the_entry_cap() {
        let directory = tempfile::tempdir().unwrap();
        let stub = object(Suite::Blake3Bao64, b"");
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        let file = crate::store::PersistedUploadFile {
            entry: 0,
            display_path: String::new(),
            stored_components: vec![String::new()],
            object,
            staging_path: std::path::PathBuf::new(),
            journal_path: std::path::PathBuf::new(),
            incarnation: [0; 16],
            profile: CommitProfile::Balanced,
            nas_contract: vot_sdk_file::NasContract::Unqualified,
            prefix_bytes: 0,
            published: false,
            receipt: false,
        };
        let mut saved = crate::store::PersistedUploadSession {
            committed_upload_id: None,
            push_key: None,
            id: "over-cap".to_owned(),
            link_id: "link".to_owned(),
            tenant: String::new(),
            dest_dir: setup.dest_dir.clone(),
            dest_rel: String::new(),
            package: stub,
            max_total_bytes: None,
            started_at: 1,
            files: vec![file; MAX_SESSION_ENTRIES + 1],
        };
        let error = match restore_files(&setup, &mut saved, || true) {
            Err(error) => error,
            Ok(_) => panic!("over-cap persisted session replay must be refused"),
        };
        assert!(error.contains("262144"), "{error}");
    }

    #[test]
    fn publication_journal_remains_until_the_database_checkpoints_it() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        let mut files =
            vec![open_destination_for(&setup, vec!["empty.exr".into()], object).unwrap()];
        persist_session(&setup, &files).unwrap();
        let journal = files[0].native.as_ref().unwrap().journal_path().to_owned();
        publish_file(&setup, &mut files[0], || true).unwrap();
        assert!(journal.exists());
        let connection =
            rusqlite::Connection::open(directory.path().join("data/votport.db")).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON upload_session_files BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;").unwrap();
        checkpoint_session(&setup, &mut files);
        assert!(journal.exists());
        assert!(!setup.store.load_upload_sessions().unwrap()[0].files[0].published);
        connection
            .execute_batch("DROP TRIGGER fail_checkpoint;")
            .unwrap();
        checkpoint_session(&setup, &mut files);
        assert!(!journal.exists());
        assert!(setup.store.load_upload_sessions().unwrap()[0].files[0].published);
        assert!(setup.dest_dir.join("empty.exr").exists());
    }

    #[tokio::test]
    async fn finished_upload_keeps_recovery_when_the_final_checkpoint_fails() {
        for (fail_checkpoint, fail_cleanup) in [(false, false), (true, false), (false, true)] {
            use std::os::unix::fs::PermissionsExt as _;
            let retain = fail_checkpoint || fail_cleanup;
            let directory = tempfile::tempdir().unwrap();
            let object = object(Suite::Blake3Bao64, b"");
            let setup = setup(directory.path(), object.clone());
            setup
                .store
                .insert_link(crate::store::Link {
                    retention_days: None,
                    id: setup.link_id.clone(),
                    tenant: String::new(),
                    label: "checkpoint".into(),
                    dest: String::new(),
                    password_hash: None,
                    created_at: 0,
                    expires_at: None,
                    max_bytes: None,
                    active: true,
                    legal_hold: false,

                    notifications: None,
                    uploads: Vec::new(),
                    events: Vec::new(),
                })
                .unwrap();
            let mut files =
                vec![open_destination_for(&setup, vec!["frame".into()], object).unwrap()];
            persist_session(&setup, &files).unwrap();
            let journal = files[0].native.as_ref().unwrap().journal_path().to_owned();
            publish_file(&setup, &mut files[0], || true).unwrap();
            let connection =
                rusqlite::Connection::open(directory.path().join("data/votport.db")).unwrap();
            if fail_checkpoint {
                connection.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON upload_session_files BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;").unwrap();
            }
            let private = setup.dest_dir.join(".vot-stage");
            if fail_cleanup {
                fs::set_permissions(&private, fs::Permissions::from_mode(0o770)).unwrap();
            }
            let store = Arc::clone(&setup.store);
            let retry_setup = self::setup(directory.path(), setup.expected_package.clone());
            let sessions = Sessions::new();
            let (sender, receiver) = mpsc::channel(1);
            let sid = hex::encode(setup.session_id);
            sessions
                .insert(sid.clone(), setup.link_id.clone(), String::new(), sender)
                .unwrap();
            let command = sessions.touch(&sid).unwrap();
            let (reply, completed) = oneshot::channel();
            command
                .sender
                .send(Cmd::Finish {
                    reply,
                    _lease: command.lease,
                })
                .await
                .unwrap();
            spawn_worker_from(setup, receiver, Phase::Receiving { files }, false, 0);
            tokio::time::timeout(std::time::Duration::from_secs(5), completed)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(journal.exists(), retain);
            let mut retained = store.load_upload_sessions().unwrap();
            assert_eq!(retained.len(), usize::from(retain));
            if retain {
                fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
                let mut persisted = retained.remove(0);
                assert_eq!(persisted.files[0].published, !fail_checkpoint);
                connection
                    .execute_batch("DROP TRIGGER IF EXISTS fail_checkpoint;")
                    .unwrap();
                let journal_before = fs::read(&journal).unwrap();
                assert!(persisted.committed_upload_id.is_some());
                assert!(restore_files(&retry_setup, &mut persisted, || true).is_err());
                assert_eq!(fs::read(&journal).unwrap(), journal_before);
                cleanup_committed_session(&store, &persisted, &retry_setup.destinations).unwrap();
                assert!(store.load_upload_sessions().unwrap().is_empty());
                assert!(!journal.exists());
            }
        }
    }

    #[tokio::test]
    async fn committed_upload_recovery_never_readmits_or_recreates_deleted_files() {
        use std::os::unix::fs::PermissionsExt as _;
        for (checkpoint, final_state) in [
            (true, "original"),
            (false, "original"),
            (true, "missing"),
            (false, "replaced"),
            (false, "cleaned"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let mut config = crate::api::testing::config(directory.path());
            config.receive_dir = directory.path().join("receive");
            let app = crate::app::build(config.clone()).unwrap();
            let bytes = b"frame";
            let object = object(Suite::Blake3Bao64, bytes);
            let setup = setup_with_app(directory.path(), object.clone(), &app);
            app.store
                .insert_link(crate::store::tests::test_link(&setup.link_id))
                .unwrap();
            let source = directory.path().join("source");
            fs::write(&source, bytes).unwrap();
            let mut file =
                open_destination_for(&setup, vec!["frame".into()], object.clone()).unwrap();
            persist_session(&setup, std::slice::from_ref(&file)).unwrap();
            reprove_staging(&source, &object, vec![&mut file], || true).unwrap();
            publish_file(&setup, &mut file, || true).unwrap();
            let journal = file.native.as_ref().unwrap().journal.clone();
            let private = setup.dest_dir.join(".vot-stage");
            if checkpoint {
                app.store.with(|connection| connection.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON upload_session_files BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;")).unwrap();
            } else {
                fs::set_permissions(&private, fs::Permissions::from_mode(0o770)).unwrap();
            }
            let mut phase = Phase::Receiving { files: vec![file] };
            let report =
                handle_finish(&setup, &mut phase, 0, 0, 5, &TransferLog::default()).unwrap();
            assert!(journal.exists());
            assert_eq!(app.store.load_upload_sessions().unwrap().len(), 1);
            let (received, retained) = app.store.tenant_admission_usage("").unwrap();
            assert_eq!(received, 5);
            assert!(
                retained.is_empty(),
                "committed uploads must not reserve their bytes again"
            );
            app.store
                .with(|connection| {
                    connection.execute_batch("DROP TRIGGER IF EXISTS fail_checkpoint;")
                })
                .unwrap();
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
            let final_path = setup.dest_dir.join("frame");
            if final_state != "original" {
                app.store
                    .remove_upload(
                        "",
                        &setup.link_id,
                        &app.store.load_upload_sessions().unwrap()[0]
                            .committed_upload_id
                            .clone()
                            .unwrap(),
                    )
                    .unwrap();
                app.store
                    .update_link("", &setup.link_id, |link| link.active = false)
                    .unwrap();
                match final_state {
                    "missing" => fs::remove_file(&final_path).unwrap(),
                    "replaced" => {
                        fs::rename(&final_path, directory.path().join("original")).unwrap();
                        fs::write(&final_path, b"operator replacement").unwrap();
                    }
                    "cleaned" => fs::remove_file(&journal).unwrap(),
                    _ => unreachable!(),
                }
            }
            drop(phase);
            drop(setup);
            drop(app);
            for _ in 0..2 {
                let app = crate::app::build(config.clone()).unwrap();
                assert_eq!(
                    app.sessions.total(),
                    0,
                    "completed recovery must not start a receiver"
                );
                app.sessions.sweep(0);
                let link = app.store.link("", "link").unwrap().unwrap();
                if final_state == "original" {
                    assert_eq!(link.uploads.len(), 1);
                    assert_eq!(link.uploads[0].id, report.upload_id);
                    assert!(!link.uploads[0].partial);
                    assert_eq!(fs::read(&final_path).unwrap(), bytes);
                } else {
                    assert!(link.uploads.is_empty(), "deleted history must stay deleted");
                    assert!(!link.active);
                }
                assert!(
                    link.events.is_empty(),
                    "cleanup must not record an interrupted transfer"
                );
                let unresolved = matches!(final_state, "missing" | "replaced");
                assert_eq!(
                    app.store.load_upload_sessions().unwrap().len(),
                    usize::from(unresolved)
                );
                assert!(app.store.tenant_admission_usage("").unwrap().1.is_empty());
                assert_eq!(journal.exists(), unresolved);
                if final_state == "missing" {
                    assert!(!final_path.exists());
                }
                if final_state == "replaced" {
                    assert_eq!(fs::read(&final_path).unwrap(), b"operator replacement");
                }
                drop(app);
            }
        }
    }

    #[tokio::test]
    async fn cleanup_refuses_a_displaced_journal_directory() {
        use std::os::unix::fs::DirBuilderExt as _;
        let root = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(root.path(), object.clone());
        setup
            .store
            .insert_link(crate::store::tests::test_link(&setup.link_id))
            .unwrap();
        let mut file = open_destination_for(&setup, vec!["frame".into()], object).unwrap();
        persist_session(&setup, std::slice::from_ref(&file)).unwrap();
        publish_file(&setup, &mut file, || true).unwrap();
        commit_upload(
            &setup,
            std::slice::from_ref(&file),
            0,
            0,
            Some("http"),
            Vec::new(),
        )
        .unwrap();
        let session = setup.store.load_upload_sessions().unwrap().remove(0);
        let journal = &session.files[0].journal_path;
        let private = setup.dest_dir.join(".vot-stage");
        let held = setup.dest_dir.join("held-stage");
        fs::rename(&private, &held).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
        let previous = held.join(journal.file_name().unwrap());
        fs::copy(&previous, journal).unwrap();
        let bytes = fs::read(&previous).unwrap();
        assert!(cleanup_committed_session(&setup.store, &session, &setup.destinations).is_err());
        assert_eq!(setup.store.load_upload_sessions().unwrap(), vec![session]);
        assert_eq!(fs::read(previous).unwrap(), bytes);
    }

    #[tokio::test]
    async fn completion_fence_commits_atomically_and_survives_history_deletion() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        setup
            .store
            .insert_link(crate::store::tests::test_link(&setup.link_id))
            .unwrap();
        let mut file = open_destination_for(&setup, vec!["frame".into()], object).unwrap();
        persist_session(&setup, std::slice::from_ref(&file)).unwrap();
        publish_file(&setup, &mut file, || true).unwrap();
        assert!(checkpoint_session(&setup, std::slice::from_mut(&mut file)));
        setup.store.with(|connection| connection.execute_batch("CREATE TRIGGER fail_completion BEFORE UPDATE OF committed_upload_id ON upload_sessions BEGIN SELECT RAISE(ABORT, 'completion failure'); END;")).unwrap();
        assert!(commit_upload(
            &setup,
            std::slice::from_ref(&file),
            0,
            0,
            Some("http"),
            Vec::new()
        )
        .unwrap_err()
        .message
        .contains("completion failure"));
        let mut saved = setup.store.load_upload_sessions().unwrap().remove(0);
        assert!(saved.committed_upload_id.is_none());
        assert!(saved.files[0].published);
        assert!(setup
            .store
            .link("", "link")
            .unwrap()
            .unwrap()
            .uploads
            .is_empty());
        assert_eq!(
            setup
                .store
                .with(|connection| connection
                    .query_row("SELECT COUNT(*) FROM files", [], |row| row.get::<_, i64>(0)))
                .unwrap(),
            0
        );
        let (files, _) = restore_files(&setup, &mut saved, || true).unwrap();
        assert!(
            files[0].published,
            "an uncommitted publication must remain recoverable"
        );
        setup
            .store
            .with(|connection| connection.execute_batch("DROP TRIGGER fail_completion;"))
            .unwrap();
        let report = commit_upload(&setup, &files, 0, 0, Some("http"), Vec::new()).unwrap();
        assert_eq!(
            commit_upload(&setup, &files, 0, 0, Some("http"), Vec::new())
                .unwrap()
                .upload_id,
            report.upload_id
        );
        assert_eq!(
            setup.store.link("", "link").unwrap().unwrap().uploads.len(),
            1
        );
        setup
            .store
            .remove_upload("", "link", &report.upload_id)
            .unwrap();
        setup
            .store
            .update_link("", "link", |link| link.active = false)
            .unwrap();
        for partial in [false, true] {
            assert_eq!(
                commit_upload_records(
                    &setup,
                    file_records(&setup, files.iter()),
                    0,
                    0,
                    Some("http"),
                    partial,
                    Vec::new()
                )
                .unwrap()
                .upload_id,
                report.upload_id
            );
            assert!(setup
                .store
                .link("", "link")
                .unwrap()
                .unwrap()
                .uploads
                .is_empty());
        }
        assert!(setup.store.load_upload_sessions().unwrap()[0]
            .committed_upload_id
            .is_some());
    }

    #[test]
    fn retained_publication_journals_warn_once_per_batch_with_one_example() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        let object_id = object(Suite::Blake3Bao64, b"");
        let setup = setup_with_app(directory.path(), object_id.clone(), &application);
        application
            .store
            .insert_link(crate::store::tests::test_link(&setup.link_id))
            .unwrap();
        let mut file_a =
            open_destination_for(&setup, vec!["frame-a".into()], object_id.clone()).unwrap();
        let mut file_b = open_destination_for(&setup, vec!["frame-b".into()], object_id).unwrap();
        publish_file(&setup, &mut file_a, || true).unwrap();
        publish_file(&setup, &mut file_b, || true).unwrap();
        // Removing the journals makes forgetting the publications fail.
        let journal_a = file_a.native.as_ref().unwrap().journal.clone();
        let journal_b = file_b.native.as_ref().unwrap().journal.clone();
        std::fs::remove_file(&journal_a).unwrap();
        std::fs::remove_file(&journal_b).unwrap();

        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            assert!(!forget_publications(&mut [file_a, file_b]));
        });
        let text = std::fs::read_to_string(log.path()).unwrap();
        let warns: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("retain publication journal"))
            .collect();
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(warns[0].contains("\"count\":2"), "{}", warns[0]);
        assert!(warns[0].contains("frame-a"), "{}", warns[0]);
        assert!(!warns[0].contains("frame-b"), "{}", warns[0]);
    }

    #[tokio::test]
    async fn completed_native_teardown_keeps_admission_until_publication_cleanup() {
        for cleaned in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let application = crate::api::testing::build(directory.path());
            let object = object(Suite::Blake3Bao64, b"");
            let setup = setup_with_app(directory.path(), object.clone(), &application);
            application
                .store
                .insert_link(crate::store::tests::test_link(&setup.link_id))
                .unwrap();
            let key = hex::encode([5; 16]);
            let stage = setup.destinations.push_directory(&key).unwrap();
            let lock = lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap();
            let mut file = open_destination_for(&setup, vec!["frame".into()], object).unwrap();
            let mut record = persisted_session(&setup, std::slice::from_ref(&file));
            record.push_key = Some(key.clone());
            setup.store.insert_upload_session(&record).unwrap();
            let journal = file.native.as_ref().unwrap().journal.clone();
            publish_file(&setup, &mut file, || true).unwrap();
            setup
                .store
                .update_upload_file_progress(&record.id, [file_progress(0, &file)])
                .unwrap();
            if cleaned {
                assert!(forget_publications(std::slice::from_mut(&mut file)));
            }
            let report = commit_upload(
                &setup,
                std::slice::from_ref(&file),
                0,
                0,
                Some("push"),
                Vec::new(),
            )
            .unwrap();
            let control = PushControl::resumable(key.clone(), Some(lock));
            let (sender, _) = mpsc::channel(1);
            application
                .sessions
                .insert_admitted(
                    SessionAdmission {
                        id: record.id.clone(),
                        link_id: setup.link_id.clone(),
                        tenant: String::new(),
                        reserved_bytes: 0,
                        max_total_bytes: None,
                        max_tenant_sessions: None,
                        max_link_sessions: usize::MAX,
                        max_sessions: usize::MAX,
                        kind: SessionKind::Push(control.clone()),
                    },
                    sender,
                    || Ok((0, Vec::new())),
                )
                .unwrap();
            let (seams, handle) = push_seams(
                Arc::clone(&application),
                setup,
                control,
                tokio::runtime::Handle::current(),
            );
            let receive = handle.0.upgrade().unwrap();
            {
                let mut inner = receive.inner.lock().unwrap();
                inner.entries.push(PushEntry { file: Some(file) });
                inner.succeeded = true;
            }
            drop(receive);
            drop(seams);
            assert!(handle.0.upgrade().is_none());
            assert_eq!(journal.exists(), !cleaned);
            assert_eq!(
                application.store.load_push_session(&key).unwrap().is_some(),
                !cleaned
            );
            assert_eq!(application.sessions.total(), 0);
            if !cleaned {
                let saved = application.store.load_push_session(&key).unwrap().unwrap();
                assert_eq!(
                    saved.committed_upload_id.as_deref(),
                    Some(report.upload_id.as_str())
                );
                let mut retry =
                    setup_with_app(directory.path(), saved.package.clone(), &application);
                retry.session_id = [8; 16];
                assert!(persist_push(&retry, key.clone())
                    .unwrap_err()
                    .contains("completed upload"));
                for same_id in [false, true] {
                    let mut replacement = record.clone();
                    if same_id {
                        replacement.push_key = Some(hex::encode([9; 16]));
                    } else {
                        replacement.id = hex::encode([8; 16]);
                    }
                    assert!(application
                        .store
                        .insert_upload_session(&replacement)
                        .unwrap_err()
                        .contains("completed upload"));
                    assert_eq!(
                        application.store.load_push_session(&key).unwrap().unwrap(),
                        saved
                    );
                }
            }
            assert!(directory.path().join("receive/frame").exists());
        }
    }

    #[test]
    fn fully_checkpointed_corruption_persists_the_reset_and_allows_resend() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"verified frame";
        let object = object(Suite::Blake3Bao64, bytes);
        let setup = setup(directory.path(), object.clone());
        let source = directory.path().join("source");
        fs::write(&source, bytes).unwrap();
        let mut file = open_destination_for(&setup, vec!["frame".into()], object.clone()).unwrap();
        reprove_staging(&source, &object, vec![&mut file], || true).unwrap();
        persist_session(&setup, std::slice::from_ref(&file)).unwrap();
        let staging = file.native.as_ref().unwrap().staging.clone();
        file.native.take().unwrap().abandon();
        fs::write(&staging, b"corrupted data").unwrap();
        let mut persisted = setup.store.load_upload_sessions().unwrap().remove(0);
        assert_eq!(persisted.files[0].prefix_bytes, bytes.len() as u64);
        assert!(restore_files(&setup, &mut persisted, || true).is_err());
        assert_eq!(persisted.files[0].prefix_bytes, 0);
        let mut persisted = setup.store.load_upload_sessions().unwrap().remove(0);
        assert_eq!(persisted.files[0].prefix_bytes, 0);
        let (mut files, _) = restore_files(&setup, &mut persisted, || true).unwrap();
        reprove_staging(&source, &object, vec![&mut files[0]], || true).unwrap();
        publish_file(&setup, &mut files[0], || true).unwrap();
        assert_eq!(fs::read(setup.dest_dir.join("frame")).unwrap(), bytes);
    }

    #[test]
    fn receipt_name_recovery_preserves_staging_before_publication() {
        for (destination, names, error) in [
            (
                "",
                vec!["frame.vot-receipt".into()],
                "reserved for signed receipts",
            ),
            (
                "",
                vec!["frame.VOT-RECEIPT".into(), "child".into()],
                "reserved for signed receipts",
            ),
            (
                "old.vot-receI\u{307}pt",
                vec!["frame".into()],
                "reserved for signed receipts",
            ),
            ("", vec!["a".repeat(243)], "242 UTF-8 bytes; shorten"),
            ("", vec!["ア".repeat(81)], "242 UTF-8 bytes; shorten"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let bytes = b"frame";
            let object = object(Suite::Blake3Bao64, bytes);
            let mut setup = setup(directory.path(), object.clone());
            setup.dest_rel = destination.into();
            setup.dest_dir = setup.dest_dir.join(destination);
            let source = directory.path().join("source");
            fs::write(&source, bytes).unwrap();
            let legacy_destination = setup.dest_dir.join(names.join("/"));
            let native = setup
                .destinations
                .directory(legacy_destination.parent().unwrap(), true)
                .unwrap()
                .create(
                    &object,
                    legacy_destination.file_name().unwrap(),
                    CommitProfile::Balanced,
                )
                .unwrap();
            let legacy = FileState {
                display_path: names.join("/"),
                stored_components: names.join("\0"),
                object: object.clone(),
                native: Some(StagedFile::new(
                    native,
                    legacy_destination,
                    ObjectCoverage::new(&object),
                    CommitProfile::Balanced,
                    Arc::clone(&setup.destinations),
                )),
                published: false,
                receipt: false,
                checkpointed: Mutex::new(None),
                first_range_at: None,
                rehash: false,
            };
            let mut files = [
                open_destination_for(&setup, vec!["allowed".into()], object.clone()).unwrap(),
                legacy,
            ];
            reprove_staging(&source, &object, files.iter_mut().collect(), || true).unwrap();
            persist_session(&setup, &files).unwrap();
            for file in &mut files {
                file.native.take().unwrap().abandon();
            }
            let mut saved = setup.store.load_upload_sessions().unwrap().remove(0);
            assert!(saved
                .files
                .iter()
                .all(|file| file.prefix_bytes == bytes.len() as u64));
            let before = saved.clone();
            let retained: Vec<_> = saved
                .files
                .iter()
                .flat_map(|file| [&file.staging_path, &file.journal_path])
                .map(|path| (path.clone(), fs::read(path).unwrap()))
                .collect();
            assert!(restore_files(&setup, &mut saved, || true)
                .err()
                .expect("invalid checkpoint resumed")
                .contains(error));
            assert_eq!(saved, before);
            assert_eq!(setup.store.load_upload_sessions().unwrap(), [before]);
            for (path, data) in retained {
                assert_eq!(fs::read(path).unwrap(), data);
            }
            assert!(!setup.dest_dir.join("allowed").exists());
            assert!(!setup.dest_dir.join(names.join("/")).exists());
            if !destination.is_empty() {
                let error = prepare_files(&setup, &[(vec!["new".into()], object.clone())], || true)
                    .err()
                    .expect("reserved destination admitted without a checkpoint manifest");
                assert!(error.message.contains("reserved for signed receipts"));
                assert!(!setup.dest_dir.join("new").exists());
            }
        }
    }

    #[test]
    fn publication_refuses_a_replaced_visible_parent_after_cache_eviction() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        let mut file =
            open_destination_for(&setup, vec!["project".into(), "frame".into()], object).unwrap();
        file.native.as_mut().unwrap().reopen().unwrap();
        for index in 0..16 {
            setup
                .destinations
                .directory(&setup.dest_dir.join(format!("other-{index}")), true)
                .unwrap();
        }
        let selected = setup.dest_dir.join("project");
        let held = setup.dest_dir.join("held");
        fs::rename(&selected, &held).unwrap();
        fs::create_dir(&selected).unwrap();
        assert!(publish_file(&setup, &mut file, || true).is_err());
        assert!(!selected.join("frame").exists());
        assert!(!selected.join("frame.vot-receipt").exists());
        fs::remove_dir(&selected).unwrap();
        fs::rename(&held, &selected).unwrap();
        publish_file(&setup, &mut file, || true).unwrap();
        assert!(selected.join("frame.vot-receipt").exists());
    }

    #[test]
    fn unresolved_partial_upload_keeps_its_admission_and_recovery_history_grows() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        setup
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                id: setup.link_id.clone(),
                tenant: String::new(),
                label: "recovery".into(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,

                notifications: None,
                uploads: Vec::new(),
                events: Vec::new(),
            })
            .unwrap();
        let mut files = (0..2)
            .map(|index| {
                open_destination_for(&setup, vec![format!("frame-{index}")], object.clone())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        persist_session(&setup, &files).unwrap();
        files[1].native.as_mut().unwrap().preserve = true;
        let mut phase = Phase::Receiving { files };
        assert!(!commit_partial(
            &setup,
            &mut phase,
            0,
            0,
            &TransferLog::default()
        ));
        let Phase::Receiving { files } = &mut phase else {
            unreachable!()
        };
        publish_file(&setup, &mut files[0], || true).unwrap();
        let journal = files[0].native.as_ref().unwrap().journal_path().to_owned();
        let connection =
            rusqlite::Connection::open(directory.path().join("data/votport.db")).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON upload_session_files BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;").unwrap();
        assert!(!commit_partial(
            &setup,
            &mut phase,
            0,
            0,
            &TransferLog::default()
        ));
        assert!(journal.exists());
        preserve_phase(&setup, &mut phase);
        assert!(journal.exists());
        assert!(!setup.store.load_upload_sessions().unwrap()[0].files[0].published);
        connection
            .execute_batch("DROP TRIGGER fail_checkpoint;")
            .unwrap();
        let mut persisted = setup.store.load_upload_sessions().unwrap().remove(0);
        let (files, _) = restore_files(&setup, &mut persisted, || true).unwrap();
        assert!(files[0].published);
        assert!(!journal.exists());
        drop(files);
        let mut persisted = setup.store.load_upload_sessions().unwrap().remove(0);
        commit_persisted_interruption(&setup.store, &setup.ended, &persisted, "fixture");
        setup
            .store
            .tombstone_files("", &setup.link_id, &HashSet::from(["frame-0"]))
            .unwrap();
        persisted.files[1].published = true;
        commit_persisted_interruption(&setup.store, &setup.ended, &persisted, "fixture");
        let uploads = setup.store.uploads_by_id(&setup.link_id).unwrap().unwrap();
        let recovered = uploads
            .iter()
            .find(|upload| upload.id == format!("recovery-{}", persisted.id))
            .unwrap();
        assert_eq!(recovered.files.len(), 2);
        assert!(recovered.files[0].deleted);
        assert!(!recovered.files[1].deleted);
    }

    #[cfg(unix)]
    #[test]
    fn push_directory_lock_refuses_a_detached_handle_and_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let stage = directory.path().join("stage");
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new().mode(0o700).create(&stage).unwrap();
        let path = stage.join("writer.lock");
        let stale = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert!(lock_push_handle(stale, &path).is_err());
        let held = lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap();
        assert!(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).is_err());
        drop(held);
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&stage, &alias).unwrap();
        assert!(lock_push_directory(&alias, vot_sdk_file::NasContract::Unqualified).is_err());
    }

    fn write_push(
        sink: Arc<dyn vot_cli::ReceiveSink>,
        object: &vot_cli::ReceiveObject,
        bytes: &[u8],
    ) {
        let subject = object.object.try_into().unwrap();
        let mut verifier = vot_scheduler::ReliableReceiver::new(1 << 20, 1 << 20, 1 << 20).unwrap();
        verifier.begin_ranges(subject, Box::new(sink)).unwrap();
        let proof = vot_proof_blake3::prove(bytes, 0, bytes.len() as u64).unwrap();
        verifier
            .receive_range(subject, 0, bytes, &proof.proof)
            .unwrap();
        verifier.finish_ranges(subject).unwrap();
    }

    #[tokio::test]
    async fn repeated_frames_keep_alias_handles_bounded_and_publish_independent_files() {
        use std::os::unix::fs::MetadataExt as _;
        for (count, cancelled) in [
            (MAX_OPEN_PUSH_ALIASES, false),
            (MAX_OPEN_PUSH_ALIASES + 1, false),
            (MAX_OPEN_PUSH_ALIASES + 1, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let application = crate::api::testing::build(directory.path());
            application
                .store
                .insert_link(crate::store::Link {
                    retention_days: None,
                    id: "link".to_owned(),
                    tenant: String::new(),
                    label: "retry".to_owned(),
                    dest: String::new(),
                    password_hash: None,
                    created_at: 0,
                    expires_at: None,
                    max_bytes: None,
                    active: true,
                    legal_hold: false,

                    notifications: None,
                    uploads: Vec::new(),
                    events: Vec::new(),
                })
                .unwrap();
            let bytes = b"repeated frame";
            let object = object(Suite::Blake3Bao64, bytes);
            let package = ObjectId {
                suite: 1,
                root: [4; 32],
                length: object.length * count as u64,
            };
            let setup = setup_with_app(directory.path(), package.clone(), &application);
            let key = hex::encode([3; 16]);
            setup.destinations.push_directory(&key).unwrap();
            persist_push(&setup, key.clone()).unwrap();
            let records: Vec<_> = (0..count)
                .map(|index| {
                    record(
                        vot_manifest::PackagePath::portable([format!("frame-{index:04}.exr")])
                            .unwrap(),
                        &object,
                    )
                })
                .collect();
            let requested = vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            };
            let (seams, handle) = push_seams(
                application,
                setup,
                PushControl::resumable(key, None),
                tokio::runtime::Handle::current(),
            );
            let receive = handle.0.upgrade().unwrap();
            if cancelled {
                receive.control.cancel();
            }
            let prepared = receive.prepare_manifest(
                vot_cli::PackageSummary {
                    root: package.root,
                    logical_length: package.length,
                    entries: count as u64,
                },
                &records,
            );
            if cancelled {
                assert!(prepared.is_err());
                assert!(receive.inner.lock().unwrap().entries.is_empty());
                continue;
            }
            prepared.unwrap();
            receive.setup.store.with(|connection| {
                connection.execute_batch("CREATE TRIGGER reject_unchanged_checkpoint BEFORE UPDATE ON upload_session_files
                    WHEN NEW.prefix_bytes = OLD.prefix_bytes AND NEW.published = OLD.published AND NEW.receipt = OLD.receipt
                    BEGIN SELECT RAISE(FAIL, 'unchanged checkpoint row'); END;")
            }).unwrap();
            receive.run_checkpoint().unwrap();
            assert!(receive.complete_object(&requested).is_err());
            let sink: Arc<dyn vot_cli::ReceiveSink> =
                Arc::from(receive.choose_sink(&requested).unwrap().unwrap());
            let files = receive.inner.lock().unwrap().objects[&PushObjectKey::from(&requested)]
                .active
                .as_ref()
                .unwrap()
                .clone();
            assert!(
                files
                    .read()
                    .unwrap()
                    .iter()
                    .filter(|(_, file)| file.native.as_ref().unwrap().active.is_some())
                    .count()
                    <= MAX_OPEN_PUSH_ALIASES
            );
            receive.run_checkpoint().unwrap();
            write_push(Arc::clone(&sink), &requested, bytes);
            for _ in 0..2 {
                receive.run_checkpoint().unwrap();
            }
            assert!(receive.setup.store.load_push_sessions().unwrap()[0]
                .files
                .iter()
                .all(|file| file.prefix_bytes == object.length));
            sink.flush().unwrap();
            assert_eq!(sink.resumed_prefix().unwrap(), object.length);
            let mut identities = std::collections::HashSet::new();
            for (_, file) in files.write().unwrap().iter_mut() {
                publish_file(&receive.setup, file, || true).unwrap();
                let path = receive.setup.dest_dir.join(&file.display_path);
                assert_eq!(fs::read(&path).unwrap(), bytes);
                assert!(identities.insert(fs::metadata(&path).unwrap().ino()));
            }
            // This test publishes the sink's files directly instead of through
            // finish_object, so mark them dirty as finish_object would.
            receive
                .dirty
                .lock()
                .unwrap()
                .extend(files.read().unwrap().iter().map(|(entry, _)| *entry));
            receive.run_checkpoint().unwrap();
            assert!(receive.setup.store.load_push_sessions().unwrap()[0]
                .files
                .iter()
                .all(|file| file.published && file.receipt));
            sink.discard_partial().unwrap();
            assert!(sink.resumed_prefix().is_err());
            drop(sink);
            drop(receive);
            drop(seams);
        }
    }

    #[tokio::test]
    async fn push_retry_preserves_direct_files_and_requires_verified_witnesses() {
        let directory = tempfile::tempdir().unwrap();
        let data = [b"first payload".as_slice(), b"second payload".as_slice()];
        let objects = data.map(|bytes| object(Suite::Blake3Bao64, bytes));
        let expected = ObjectId {
            suite: 1,
            root: [9; 32],
            length: data.iter().map(|bytes| bytes.len() as u64).sum(),
        };
        let application = crate::api::testing::build(directory.path());
        let first_setup = setup_with_app(directory.path(), expected.clone(), &application);
        let mut retry_setup = setup_with_app(directory.path(), expected.clone(), &application);
        retry_setup.session_id = [8; 16];
        application
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                id: "link".to_owned(),
                tenant: String::new(),
                label: "retry".to_owned(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,

                notifications: None,
                uploads: Vec::new(),
                events: Vec::new(),
            })
            .unwrap();
        let key = hex::encode([3; 16]);
        let stage = first_setup.destinations.push_directory(&key).unwrap();
        let records = objects
            .iter()
            .enumerate()
            .map(|(index, object)| {
                record(
                    vot_manifest::PackagePath::portable([format!("file-{index}")]).unwrap(),
                    object,
                )
            })
            .collect::<Vec<_>>();
        let summary = vot_cli::PackageSummary {
            root: expected.root,
            logical_length: expected.length,
            entries: 2,
        };
        let receive_objects = objects
            .iter()
            .map(|object| vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            })
            .collect::<Vec<_>>();
        persist_push(&first_setup, key.clone()).unwrap();
        let control = PushControl::resumable(
            key.clone(),
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            first_setup,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        let sink: Arc<dyn vot_cli::ReceiveSink> =
            Arc::from(receive.choose_sink(&receive_objects[0]).unwrap().unwrap());
        assert!(sink.write_at(0, data[0]).is_err());
        write_push(Arc::clone(&sink), &receive_objects[0], data[0]);
        sink.flush().unwrap();
        receive.complete_object(&receive_objects[0]).unwrap();
        drop(sink);
        let sink = receive.choose_sink(&receive_objects[1]).unwrap().unwrap();
        assert!(sink.write_at(0, b"wrong").is_err());
        drop(sink);
        drop(receive);
        drop(seams);
        assert!(handle.0.upgrade().is_none());
        assert!(directory.path().join("receive/file-0").is_file());
        assert!(!stage.join("objects").exists());
        persist_push(&retry_setup, key.clone()).unwrap();
        let control = PushControl::resumable(
            key,
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            retry_setup,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        // The published object resumes through the done sink: the whole
        // length is the prefix, flush is a no-op, and the completion hook
        // finishes it here.
        let done = receive.choose_sink(&receive_objects[0]).unwrap().unwrap();
        assert_eq!(
            done.resumed_prefix().unwrap(),
            receive_objects[0].object.length
        );
        done.flush().unwrap();
        drop(done);
        receive.complete_object(&receive_objects[0]).unwrap();
        let sink: Arc<dyn vot_cli::ReceiveSink> =
            Arc::from(receive.choose_sink(&receive_objects[1]).unwrap().unwrap());
        write_push(Arc::clone(&sink), &receive_objects[1], data[1]);
        sink.flush().unwrap();
        receive.complete_object(&receive_objects[1]).unwrap();
        assert!(application.store.load_push_sessions().unwrap()[0]
            .files
            .iter()
            .all(|file| file.published));
        drop(sink);
        drop(receive);
        drop(seams);
        assert!(!stage.exists());
        assert!(application.store.load_push_sessions().unwrap().is_empty());
        for (index, bytes) in data.iter().enumerate() {
            assert_eq!(
                fs::read(directory.path().join(format!("receive/file-{index}"))).unwrap(),
                *bytes
            );
        }
    }

    #[tokio::test]
    async fn push_retry_finishes_published_objects_through_the_completion_hook() {
        let directory = tempfile::tempdir().unwrap();
        let data = [b"first payload".as_slice(), b"second payload".as_slice()];
        let objects = data.map(|bytes| object(Suite::Blake3Bao64, bytes));
        let expected = ObjectId {
            suite: 1,
            root: [9; 32],
            length: data.iter().map(|bytes| bytes.len() as u64).sum(),
        };
        let application = crate::api::testing::build(directory.path());
        let first_setup = setup_with_app(directory.path(), expected.clone(), &application);
        let mut retry_setup = setup_with_app(directory.path(), expected.clone(), &application);
        retry_setup.session_id = [8; 16];
        application
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                id: "link".to_owned(),
                tenant: String::new(),
                label: "retry".to_owned(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,

                notifications: None,
                uploads: Vec::new(),
                events: Vec::new(),
            })
            .unwrap();
        let key = hex::encode([3; 16]);
        let stage = first_setup.destinations.push_directory(&key).unwrap();
        let records = objects
            .iter()
            .enumerate()
            .map(|(index, object)| {
                record(
                    vot_manifest::PackagePath::portable([format!("file-{index}")]).unwrap(),
                    object,
                )
            })
            .collect::<Vec<_>>();
        let summary = vot_cli::PackageSummary {
            root: expected.root,
            logical_length: expected.length,
            entries: 2,
        };
        let receive_objects = objects
            .iter()
            .map(|object| vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            })
            .collect::<Vec<_>>();
        persist_push(&first_setup, key.clone()).unwrap();
        let control = PushControl::resumable(
            key.clone(),
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            first_setup,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        // Publish both objects in the first session.
        for (index, bytes) in data.iter().enumerate() {
            let sink: Arc<dyn vot_cli::ReceiveSink> = Arc::from(
                receive
                    .choose_sink(&receive_objects[index])
                    .unwrap()
                    .unwrap(),
            );
            write_push(Arc::clone(&sink), &receive_objects[index], bytes);
            sink.flush().unwrap();
            receive.complete_object(&receive_objects[index]).unwrap();
            drop(sink);
        }
        drop(receive);
        drop(seams);
        // The retry session finds every object published: choose_sink hands
        // back the done sink for each, and the completion hook (not the
        // sink) finishes the object and the session. The first session
        // finished completely, so its staging directory was removed; the
        // retry recreates it.
        persist_push(&retry_setup, key.clone()).unwrap();
        retry_setup.destinations.push_directory(&key).unwrap();
        let control = PushControl::resumable(
            key,
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            retry_setup,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        for requested in &receive_objects {
            let done = receive.choose_sink(requested).unwrap().unwrap();
            assert_eq!(done.resumed_prefix().unwrap(), requested.object.length);
            done.flush().unwrap();
            receive.complete_object(requested).unwrap();
        }
        assert!(application.store.load_push_sessions().unwrap()[0]
            .files
            .iter()
            .all(|file| file.published));
        drop(receive);
        drop(seams);
        assert!(!stage.exists());
        assert!(application.store.load_push_sessions().unwrap().is_empty());
        for (index, bytes) in data.iter().enumerate() {
            assert_eq!(
                fs::read(directory.path().join(format!("receive/file-{index}"))).unwrap(),
                *bytes
            );
        }
    }

    #[test]
    fn deduplication_pages_skip_aliases_and_verify_remaining_candidates() {
        let page = crate::store::DELIVERED_CANDIDATE_PAGE;
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            for length in [0, (1 << 20) + 1] {
                let directory = tempfile::tempdir().unwrap();
                let bytes = vec![7; length];
                let expected = object(suite, &bytes);
                let mut setup = setup(directory.path(), expected.clone());
                setup.dest_rel = "project".into();
                setup.dest_dir.push("project");
                fs::create_dir(&setup.dest_dir).unwrap();
                let template = FileRecord {
                    path: "original".into(),
                    stored_as: "project/a-bad".into(),
                    bytes: expected.length,
                    suite: suite_name(expected.suite),
                    root: hex::encode(expected.root),
                    receipt: true,
                    deleted: false,
                };
                let mut files = vec![template.clone(); page * 3 + 3];
                for i in 0..=page {
                    files.push(FileRecord {
                        stored_as: format!("project/b-missing-{i:03}"),
                        ..template.clone()
                    });
                }
                for name in [
                    "outside/elsewhere",
                    "project/../escape",
                    "project/c.vot-receipt",
                    "project/d-short",
                    "project/e-deleted",
                    "project/f-record-length",
                    "project/z-valid",
                ] {
                    files.push(FileRecord {
                        stored_as: name.into(),
                        deleted: name == "project/e-deleted",
                        bytes: expected.length + u64::from(name == "project/f-record-length"),
                        receipt: suite == Suite::Blake3Bao64,
                        ..template.clone()
                    });
                }
                record_delivered_files(&setup, files);
                fs::create_dir(setup.dest_dir.join("outside")).unwrap();
                fs::write(setup.dest_dir.join("outside/elsewhere"), &bytes).unwrap();
                fs::write(setup.dest_dir.parent().unwrap().join("escape"), &bytes).unwrap();
                fs::write(setup.dest_dir.join("a-bad"), vec![9; length.max(1)]).unwrap();
                fs::write(setup.dest_dir.join("d-short"), vec![7; length + 1]).unwrap();
                for name in ["c.vot-receipt", "e-deleted", "f-record-length", "z-valid"] {
                    fs::write(setup.dest_dir.join(name), &bytes).unwrap();
                }
                let checks = AtomicUsize::new(0);
                let found = find_delivered(&setup, &expected, || {
                    let n = checks.fetch_add(1, Ordering::Relaxed);
                    assert!(
                        n < page + 40,
                        "aliases were revisited or pagination failed to advance"
                    );
                    true
                })
                .unwrap()
                .unwrap();
                assert_eq!(found.stored_components, ["z-valid"]);
                assert_eq!(found.receipt, suite == Suite::Blake3Bao64);
                let checks = AtomicUsize::new(0);
                assert_eq!(
                    find_delivered(&setup, &expected, || checks.fetch_add(1, Ordering::Relaxed)
                        < 2)
                    .err()
                    .unwrap()
                    .status,
                    409
                );
                assert_eq!(checks.load(Ordering::Relaxed), 3);
                setup
                    .store
                    .with(|c| c.execute_batch("DROP TABLE files"))
                    .unwrap();
                let result = prepare_files(
                    &setup,
                    &[(vec!["new".into(), "frame".into()], expected)],
                    || true,
                );
                assert_eq!(result.err().unwrap().status, 500);
                assert!(!setup.dest_dir.join("new").exists());
            }
        }
    }

    #[tokio::test]
    async fn deduplication_and_published_recovery_reject_changed_bytes() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let directory = tempfile::tempdir().unwrap();
            let expected = object(suite, b"original");
            let setup = setup(directory.path(), expected.clone());
            fs::create_dir_all(&setup.dest_dir).unwrap();
            let path = setup.dest_dir.join("frame.bin");
            fs::write(&path, b"original").unwrap();
            let record = FileRecord {
                path: "frame.bin".into(),
                stored_as: "frame.bin".into(),
                bytes: 8,
                suite: suite_name(expected.suite),
                root: hex::encode(expected.root),
                receipt: true,
                deleted: false,
            };
            record_delivered_files(&setup, vec![record.clone()]);
            assert!(find_delivered(&setup, &expected, || true)
                .unwrap()
                .is_some());
            assert!(find_delivered(&setup, &expected, || false).is_err());
            for name in [
                "old.vot-receipt".into(),
                "old.vot-receI\u{307}pt/frame".into(),
                "a".repeat(243),
                "ア".repeat(81),
            ] {
                let reserved = setup.dest_dir.join(&name);
                fs::create_dir_all(reserved.parent().unwrap()).unwrap();
                fs::write(&reserved, b"original").unwrap();
                setup
                    .store
                    .with(|c| c.execute("UPDATE files SET stored_as=?1", [&name]))
                    .unwrap();
                let (files, _allocation) = prepare_files(
                    &setup,
                    &[(vec!["renamed.bin".into()], expected.clone())],
                    || true,
                )
                .unwrap();
                assert_eq!(files[0].stored_components, "renamed.bin");
                assert!(!files[0].published);
                assert_eq!(fs::read(&reserved).unwrap(), b"original");
            }
            setup
                .store
                .with(|c| c.execute("UPDATE files SET stored_as=?1", [&record.stored_as]))
                .unwrap();
            fs::write(&path, b"changed!").unwrap();
            assert!(find_delivered(&setup, &expected, || true)
                .unwrap()
                .is_none());
            let file = FileState {
                display_path: record.path.clone(),
                stored_components: record.path,
                object: expected,
                native: None,
                published: true,
                receipt: true,
                checkpointed: Mutex::new(None),
                first_range_at: None,
                rehash: false,
            };
            let mut persisted = persisted_session(&setup, &[file]);
            let (_, receiver) = mpsc::channel(1);
            assert!(resume_worker(setup, receiver, &mut persisted)
                .unwrap_err()
                .contains("changed after publication"));
        }
    }

    #[tokio::test]
    async fn fast_profile_survives_parking_and_restart_on_local_storage() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        let destination = setup.dest_dir.join("fast");
        let native = setup
            .destinations
            .directory(&setup.dest_dir, true)
            .unwrap()
            .create(
                &object,
                destination.file_name().unwrap(),
                CommitProfile::Fast,
            )
            .unwrap();
        let mut staged = StagedFile::new(
            native,
            destination.clone(),
            ObjectCoverage::new(&object),
            CommitProfile::Fast,
            Arc::clone(&setup.destinations),
        );
        staged.reopen().unwrap();
        staged.park();
        let file = FileState {
            display_path: "fast".to_owned(),
            stored_components: "fast".to_owned(),
            object: object.clone(),
            native: Some(staged),
            published: false,
            receipt: false,
            checkpointed: Mutex::new(None),
            first_range_at: None,
            rehash: false,
        };
        let mut persisted = persisted_session(&setup, std::slice::from_ref(&file));
        assert_eq!(persisted.files[0].profile, CommitProfile::Fast);
        file.native.unwrap().abandon();
        let signer = Arc::clone(&setup.signer);
        let (sender, receiver) = mpsc::channel(1);
        resume_worker(setup, receiver, &mut persisted).unwrap();
        drop(sender);
        assert!(persisted.files[0].published);
        let bytes = fs::read(destination.with_extension("vot-receipt")).unwrap();
        let decoded = vot_receipt::decode_authenticated(&bytes).unwrap();
        let verified = vot_receipt::verify_ed25519(&decoded, &signer.verifying_key()).unwrap();
        assert_eq!(verified.receipt().profile, vot_receipt::CommitProfile::Fast);
        let mut baseline = vot_sdk_file::ReceiveDirectory::open(
            directory.path(),
            vot_sdk_file::NasContract::Unqualified,
        )
        .unwrap()
        .create(
            &object,
            std::ffi::OsStr::new("baseline"),
            CommitProfile::Fast,
        )
        .unwrap();
        baseline.publish().unwrap();
        assert_eq!(
            verified.receipt().sequence,
            baseline.publish_observation().unwrap().sequence
        );
    }

    fn record(path: vot_manifest::PackagePath, object: &ObjectId) -> vot_cli::EntryRecord {
        vot_cli::EntryRecord {
            path,
            suite: Suite::try_from(object.suite).unwrap(),
            logical_root: object.root,
            logical_length: object.length,
            storage: vot_cli::Storage::Direct,
        }
    }

    #[test]
    fn six_figure_entry_counts_fit_without_a_large_fixture() {
        for count in [0, 100_000, 999_999, 1_000_000, 1_999_998, 2_000_000] {
            assert!(entry_count_within_limit(count, u64::MAX));
        }
        for count in [2_000_001, usize::MAX] {
            assert!(!entry_count_within_limit(count, u64::MAX));
        }
    }

    #[test]
    fn entry_count_budget_leaves_a_small_empty_file_floor() {
        assert_eq!(max_entries_for_bytes(0), 256);
        assert_eq!(max_entries_for_bytes(1024 * 1024), 512);
        assert!(max_entries_for_bytes(20_000 * 4096) >= 20_000);
        assert!(max_entries_for_bytes(u64::MAX) <= MAX_ENTRIES);
        assert_eq!(max_entries_for_bytes(u64::MAX), MAX_ENTRIES);
    }

    #[test]
    #[ignore = "changes the process descriptor limit; CI runs this test alone"]
    fn dormant_staging_preserves_ranges_and_cleans_up_under_low_descriptor_limit() {
        let mut limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        limit.current = Some(64);
        rustix::process::setrlimit(rustix::process::Resource::Nofile, limit).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let data = vec![23u8; 3 * 65_536];
        let object = object(Suite::Blake3Bao64, &data);
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        let files = (0..128)
            .map(|index| {
                open_destination_for(&setup, vec![format!("file-{index}")], object.clone()).unwrap()
            })
            .collect::<Vec<_>>();
        assert!(files
            .iter()
            .all(|file| file.native.as_ref().unwrap().active.is_none()));
        let mut phase = Phase::Receiving { files };
        let chunk = |entry, offset| {
            let proof = vot_proof_blake3::prove(&data, offset, 65_536).unwrap();
            BatchChunk {
                entry,
                offset: proof.covered_offset,
                proof: proof.proof.into(),
                data: proof.data.into(),
                reply: oneshot::channel().0,
                _lease: SessionLease {
                    activity: Arc::new(SessionActivity {
                        in_flight: AtomicUsize::new(1),
                        last_active: Mutex::new(Instant::now()),
                        received: AtomicU64::new(0),
                    }),
                },
            }
        };
        let send = |phase: &mut Phase, entry, offset| {
            accept_batch(&setup, phase, &[chunk(entry, offset)])
                .pop()
                .unwrap()
        };
        for index in 0..128 {
            let progress = send(&mut phase, index, 131_072).unwrap();
            assert_eq!(progress.covered_bytes, 65_536);
        }
        for offset in [0, 65_536] {
            let batch = (3..3 + MAX_CHUNK_BATCH)
                .map(|entry| chunk(entry, offset))
                .collect::<Vec<_>>();
            for result in accept_batch(&setup, &mut phase, &batch) {
                assert_eq!(result.unwrap().complete, offset == 65_536);
            }
        }
        assert_eq!(send(&mut phase, 0, 0).unwrap().covered_bytes, 131_072);
        assert!(send(&mut phase, 0, 131_072).unwrap().replay);
        assert!(send(&mut phase, 0, 65_536).unwrap().complete);
        assert_eq!(fs::read(setup.dest_dir.join("file-0")).unwrap(), data);
        let Phase::Receiving { files } = &mut phase else {
            unreachable!()
        };
        let persisted = persisted_session(&setup, files.iter());
        assert!(persisted.files[0].published);
        assert_eq!(persisted.files[1].prefix_bytes, 0);
        assert!(!persisted.files[1].staging_path.as_os_str().is_empty());
        let kept = files[1].native.take().unwrap();
        let staging = kept.staging.clone();
        let journal = kept.journal.clone();
        let incarnation = kept.incarnation;
        kept.abandon();
        assert!(staging.exists() && journal.exists());
        let reopened = NativeFile::resume(
            &object,
            setup.dest_dir.join("file-1"),
            &staging,
            &journal,
            incarnation,
            CommitProfile::Balanced,
            [(131_072, 65_536)],
        )
        .unwrap();
        assert_eq!(reopened.progress().covered_bytes, 65_536);
        drop(reopened);
        assert!(!staging.exists() && !journal.exists());
        let tampered = files[2].native.as_ref().unwrap().staging.clone();
        let mut file = fs::OpenOptions::new().write(true).open(tampered).unwrap();
        file.seek(SeekFrom::Start(131_072)).unwrap();
        std::io::Write::write_all(&mut file, b"wrong").unwrap();
        drop(file);
        send(&mut phase, 2, 0).unwrap();
        assert!(send(&mut phase, 2, 65_536).is_err());
        assert!(!setup.dest_dir.join("file-2").exists());
        drop(phase);
        let source = directory.path().join("quic-source");
        fs::write(&source, &data).unwrap();
        let mut destinations = (0..32)
            .map(|index| {
                open_destination_for(&setup, vec![format!("quic-{index}")], object.clone()).unwrap()
            })
            .collect::<Vec<_>>();
        reprove_staging(&source, &object, destinations.iter_mut().collect(), || true).unwrap();
        for destination in &mut destinations {
            let staged = destination.native.as_ref().unwrap();
            assert!(staged.active.is_none());
            assert_eq!(staged.progress().prefix_bytes, object.length);
            let path = staged.destination.clone();
            publish_file(&setup, destination, || true).unwrap();
            assert_eq!(fs::read(path).unwrap(), data);
        }
        drop(destinations);
        assert!(
            !fs::read_dir(&setup.dest_dir).unwrap().any(|entry| matches!(
                entry
                    .unwrap()
                    .path()
                    .extension()
                    .and_then(|part| part.to_str()),
                Some("stage" | "journal")
            ))
        );
    }

    #[test]
    fn push_manifest_rejects_mismatch_pack_raw_path_and_entry_cap() {
        let directory = tempfile::tempdir().unwrap();
        let logical = object(Suite::Blake3Bao64, b"payload");
        let expected = ObjectId {
            suite: 1,
            root: [9; 32],
            length: logical.length,
        };
        let setup = setup(directory.path(), expected.clone());
        let direct = record(
            vot_manifest::PackagePath::portable(["file"]).unwrap(),
            &logical,
        );
        let summary = vot_cli::PackageSummary {
            root: expected.root,
            logical_length: logical.length,
            entries: 1,
        };
        assert!(validate_push_manifest(&setup, summary, std::slice::from_ref(&direct)).is_ok());
        for path in [
            vec!["report.vot-receipt"],
            vec!["report.VOT-RECEIPT", "child"],
            vec!["report.vot-receI\u{307}pt"],
        ] {
            let reserved = record(vot_manifest::PackagePath::portable(path).unwrap(), &logical);
            let error = validate_push_manifest(&setup, summary, &[reserved]).unwrap_err();
            assert!(error.message.contains("reserved for signed receipts"));
        }

        let mut mismatch = summary;
        mismatch.root[0] ^= 1;
        assert!(validate_push_manifest(&setup, mismatch, std::slice::from_ref(&direct)).is_err());
        let mut mismatch = summary;
        mismatch.logical_length += 1;
        assert!(validate_push_manifest(&setup, mismatch, std::slice::from_ref(&direct)).is_err());

        let mut packed = direct.clone();
        packed.storage = vot_cli::Storage::Pack {
            root: logical.root,
            length: logical.length,
            offset: 0,
        };
        assert!(validate_push_manifest(&setup, summary, &[packed]).is_err());

        let raw = record(vot_manifest::PackagePath::raw([b"file"]).unwrap(), &logical);
        assert!(validate_push_manifest(&setup, summary, &[raw]).is_err());

        assert!(!entry_count_within_limit(MAX_ENTRIES + 1, u64::MAX));
    }

    #[test]
    fn local_reproof_accepts_original_and_rejects_tampered_blake3() {
        reproof_accepts_original_and_rejects_tampered(Suite::Blake3Bao64);
    }

    #[test]
    fn local_reproof_accepts_original_and_rejects_tampered_sha256() {
        reproof_accepts_original_and_rejects_tampered(Suite::Sha256Bep52);
    }

    fn reproof_accepts_original_and_rejects_tampered(suite: Suite) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("staged");
        let data = vec![11_u8; vot_scheduler::RANGE_UNIT_BYTES as usize + 17];
        let object = object(suite, &data);
        fs::write(&path, &data).unwrap();
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        let mut destination =
            open_destination_for(&setup, vec!["received".to_owned()], object.clone()).unwrap();
        assert!(reprove_staging(&path, &object, vec![&mut destination], || true).is_ok());
        assert_eq!(
            destination.native.as_ref().unwrap().progress().prefix_bytes,
            object.length
        );

        let mut tampered = data;
        tampered[3] ^= 1;
        fs::write(&path, tampered).unwrap();
        assert!(reprove_staging(&path, &object, Vec::new(), || true).is_err());
    }

    #[test]
    fn empty_object_roots_are_canonical_for_both_suites() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let empty = object(suite, b"");
            assert!(validate_empty_object(&empty).is_ok());
            let mut forged = empty;
            forged.root[0] ^= 1;
            assert!(validate_empty_object(&forged).is_err());
        }
    }

    #[test]
    fn cancelled_reproof_stops_during_hashing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("staged");
        let data = vec![17_u8; 2 * vot_scheduler::RANGE_UNIT_BYTES as usize];
        fs::write(&path, &data).unwrap();
        let object = object(Suite::Blake3Bao64, &data);
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        let mut destination =
            open_destination_for(&setup, vec!["cancelled".to_owned()], object.clone()).unwrap();

        let mut checks = 0;
        assert!(reprove_staging(&path, &object, vec![&mut destination], || {
            checks += 1;
            checks < 2
        })
        .is_err());
        assert_eq!(
            destination
                .native
                .as_ref()
                .unwrap()
                .progress()
                .covered_bytes,
            0
        );
    }

    #[test]
    fn cancelled_reproof_stops_after_an_accepted_range() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("staged");
        let length =
            (vot_scheduler::MAX_PROOF_RANGE_BYTES + vot_scheduler::RANGE_UNIT_BYTES) as usize;
        let data = vec![19_u8; length];
        fs::write(&path, &data).unwrap();
        let object = object(Suite::Blake3Bao64, &data);
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        let mut destination =
            open_destination_for(&setup, vec!["cancelled".to_owned()], object.clone()).unwrap();
        let hash_checks = length.div_ceil(vot_scheduler::RANGE_UNIT_BYTES as usize);
        let mut checks = 0;

        assert!(reprove_staging(&path, &object, vec![&mut destination], || {
            checks += 1;
            checks <= hash_checks + 1
        })
        .is_err());
        assert!(
            destination
                .native
                .as_ref()
                .unwrap()
                .progress()
                .covered_bytes
                > 0
        );
    }

    #[test]
    fn a_published_file_and_journal_survive_an_unrecorded_push_failure() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let bytes = b"published bytes";
        fs::write(&source, bytes).unwrap();
        let object = object(Suite::Blake3Bao64, bytes);
        let setup = setup(directory.path(), object.clone());
        let mut file =
            open_destination_for(&setup, vec!["final".to_owned()], object.clone()).unwrap();
        reprove_staging(&source, &object, vec![&mut file], || true).unwrap();
        let journal = file.native.as_ref().unwrap().journal.clone();
        publish_file(&setup, &mut file, || true).unwrap();
        assert!(journal.is_file());
        drop(file);
        assert_eq!(fs::read(setup.dest_dir.join("final")).unwrap(), bytes);
        assert!(journal.is_file());
    }
    /// Two-object push with the checkpoint trigger forced on: while the sink's
    /// checkpoint blocks inside its SQLite commit (the test holds the store
    /// connection), choose_sink for the second object must still complete.
    #[tokio::test]
    async fn choose_sink_completes_while_a_checkpoint_persistence_is_in_flight() {
        let directory = tempfile::tempdir().unwrap();
        // One completing write for the writer thread, five untouched objects
        // for the probe iterations, each choose_sink a fresh target.
        let data = [
            b"first payload".as_slice(),
            b"payload-1".as_slice(),
            b"payload-2".as_slice(),
            b"payload-3".as_slice(),
            b"payload-4".as_slice(),
            b"payload-5".as_slice(),
        ];
        let objects = data.map(|bytes| object(Suite::Blake3Bao64, bytes));
        let expected = ObjectId {
            suite: 1,
            root: [9; 32],
            length: data.iter().map(|bytes| bytes.len() as u64).sum(),
        };
        let application = crate::api::testing::build(directory.path());
        application
            .store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let setup = setup_with_app(directory.path(), expected.clone(), &application);
        let key = hex::encode([4; 16]);
        setup.destinations.push_directory(&key).unwrap();
        persist_push(&setup, key.clone()).unwrap();
        let records = objects
            .iter()
            .enumerate()
            .map(|(index, object)| {
                record(
                    vot_manifest::PackagePath::portable([format!("file-{index}")]).unwrap(),
                    object,
                )
            })
            .collect::<Vec<_>>();
        let requested = objects
            .iter()
            .map(|object| vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            })
            .collect::<Vec<_>>();
        let (seams, handle) = push_seams(
            application.clone(),
            setup,
            PushControl::resumable(key, None),
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive
            .prepare_manifest(
                vot_cli::PackageSummary {
                    root: expected.root,
                    logical_length: expected.length,
                    entries: data.len() as u64,
                },
                &records,
            )
            .unwrap();
        let (written, written_rx) = std::sync::mpsc::channel();
        // Holding the store connection blocks the checkpoint's SQLite commit
        // for as long as this closure runs: a checkpoint-sized persistence.
        application.store.with(|_| {
            // Force the completing write into a checkpoint-sized flush.
            {
                let mut tracker = receive.checkpoint.lock().unwrap();
                tracker.bytes_since = PERSIST_BYTES;
                tracker.last_at = Instant::now() - PERSIST_INTERVAL;
            }
            let writer = {
                let receive = Arc::clone(&receive);
                let object = requested[0].object;
                let full = requested[0].clone();
                let written = written.clone();
                std::thread::spawn(move || {
                    let sink: Arc<dyn vot_cli::ReceiveSink> =
                        Arc::from(receive.choose_sink(&full).unwrap().unwrap());
                    write_push(
                        sink,
                        &vot_cli::ReceiveObject {
                            object,
                            entries: Vec::new(),
                        },
                        data[0],
                    );
                    let _ = written.send(());
                })
            };
            // While that persistence is in flight, choose_sink for the other
            // objects must not wait for the checkpoint's store commit. One
            // fresh object per probe so no probe trips the already-sinked
            // conflict; a probe that outlives its own timeout is the
            // regression (the checkpoint holding the push state lock) and
            // panics with a diagnosis instead of hanging the suite.
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            for object in requested.iter().skip(1) {
                let (chosen, chosen_rx) = std::sync::mpsc::channel();
                {
                    let receive = Arc::clone(&receive);
                    let object = object.clone();
                    std::thread::spawn(move || {
                        let _ = chosen.send(receive.choose_sink(&object).is_ok());
                    });
                }
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let budget = remaining.min(Duration::from_secs(2));
                match chosen_rx.recv_timeout(budget) {
                    Ok(true) => {}
                    Ok(false) => panic!("choose_sink failed while a checkpoint was in flight"),
                    Err(_) => panic!(
                        "choose_sink did not complete within 2s while a checkpoint persistence was in flight; the checkpoint holds the push state lock across its store commit"
                    ),
                }
            }
            drop(writer);
            Ok(())
        })
        .unwrap();
        written_rx
            .recv_timeout(Duration::from_secs(15))
            .expect("the checkpoint write never finished after the store was released");
        drop(receive);
        drop(seams);
    }

    /// Entry 1 is advanced through a path that bypasses the sink, so it is
    /// never marked dirty (production mutations always mark their entries):
    /// the checkpoint must store entry 0 but leave entry 1's stale row alone
    /// instead of walking every entry.
    #[tokio::test]
    async fn checkpoint_stores_only_dirty_entries() {
        let directory = tempfile::tempdir().unwrap();
        let data = b"first payload";
        let untouched_bytes = vec![0x53; 131_072];
        let mut builder = InMemoryObjectBuilder::new(
            Suite::Blake3Bao64,
            Some(untouched_bytes.len() as u64),
            131_072,
        )
        .unwrap();
        builder.update(&untouched_bytes).unwrap();
        let prepared = builder.finish().unwrap();
        let objects = [
            object(Suite::Blake3Bao64, data),
            prepared.object_id().clone(),
        ];
        let expected = ObjectId {
            suite: 1,
            root: [9; 32],
            length: (data.len() + untouched_bytes.len()) as u64,
        };
        let application = crate::api::testing::build(directory.path());
        application
            .store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let setup = setup_with_app(directory.path(), expected.clone(), &application);
        let key = hex::encode([5; 16]);
        setup.destinations.push_directory(&key).unwrap();
        persist_push(&setup, key.clone()).unwrap();
        let records = objects
            .iter()
            .enumerate()
            .map(|(index, object)| {
                record(
                    vot_manifest::PackagePath::portable([format!("file-{index}")]).unwrap(),
                    object,
                )
            })
            .collect::<Vec<_>>();
        let requested = objects
            .iter()
            .map(|object| vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            })
            .collect::<Vec<_>>();
        let (seams, handle) = push_seams(
            application.clone(),
            setup,
            PushControl::resumable(key, None),
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive
            .prepare_manifest(
                vot_cli::PackageSummary {
                    root: expected.root,
                    logical_length: expected.length,
                    entries: 2,
                },
                &records,
            )
            .unwrap();
        let first: Arc<dyn vot_cli::ReceiveSink> =
            Arc::from(receive.choose_sink(&requested[0]).unwrap().unwrap());
        // Advance entry 1 outside the sink write path: no dirty mark.
        {
            let mut inner = receive.inner.lock().unwrap();
            let file = inner.entries[1].file.as_mut().unwrap();
            file.native.as_mut().unwrap().reopen().unwrap();
            for offset in [0u64, 65_536] {
                let proof = prepared.prove(offset, 65_536).unwrap();
                let index = offset as usize;
                accept_range(
                    std::slice::from_ref(file),
                    0,
                    offset,
                    proof.proof(),
                    &untouched_bytes[index..index + 65_536],
                )
                .unwrap();
            }
        }
        // Force the sink's next write_verified into its checkpoint.
        {
            let mut tracker = receive.checkpoint.lock().unwrap();
            tracker.bytes_since = PERSIST_BYTES;
            tracker.last_at = Instant::now() - PERSIST_INTERVAL;
        }
        write_push(Arc::clone(&first), &requested[0], data);
        let saved = application.store.load_push_sessions().unwrap().remove(0);
        // The dirty entry was stored; the unmarked one was not walked.
        assert_eq!(saved.files[0].prefix_bytes, data.len() as u64);
        assert_eq!(saved.files[1].prefix_bytes, 0);
        drop(first);
        drop(receive);
        drop(seams);
    }
}

#[cfg(test)]
mod parallel_accept_tests {
    use super::*;
    use vot_sdk::object::{InMemoryObjectBuilder, Suite};

    fn object(data: &[u8]) -> ObjectId {
        let mut builder = InMemoryObjectBuilder::new(
            Suite::Blake3Bao64,
            Some(data.len() as u64),
            data.len() as u64,
        )
        .unwrap();
        builder.update(data).unwrap();
        builder.finish().unwrap().object_id().clone()
    }

    // Two threads accept the same range against one shared file, the shape
    // accept_batch runs internally. The in-flight duplicate must be absorbed
    // and replayed, never surfaced as an error: exactly one Accepted and one
    // Replay. This kills a mutant that drops the RangeInFlight retry (the
    // loser would error) or misclassifies the replay.
    #[test]
    fn concurrent_duplicate_range_accepts_once_and_replays_once() {
        let directory = tempfile::tempdir().unwrap();
        let data = vec![0x5a_u8; 64 * 1024];
        let object = object(&data);
        let proof = vot_proof_blake3::prove(&data, 0, data.len() as u64).unwrap();
        let destinations = Arc::new(
            crate::receiving::Destinations::open(
                directory.path(),
                vot_sdk_file::NasContract::Unqualified,
            )
            .unwrap(),
        );
        let native = destinations
            .directory(directory.path(), true)
            .unwrap()
            .create(
                &object,
                std::ffi::OsStr::new("obj"),
                CommitProfile::Balanced,
            )
            .unwrap();
        let mut native = StagedFile::new(
            native,
            directory.path().join("obj"),
            ObjectCoverage::new(&object),
            CommitProfile::Balanced,
            destinations,
        );
        native.reopen().unwrap();
        let files = vec![FileState {
            display_path: "obj".to_owned(),
            stored_components: "obj".to_owned(),
            object,
            native: Some(native),
            published: false,
            receipt: false,
            checkpointed: Mutex::new(None),
            first_range_at: None,
            rehash: false,
        }];
        let results: Vec<AcceptCore> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let files = &files;
                    let proof = &proof;
                    scope.spawn(move || {
                        accept_range(files, 0, proof.covered_offset, &proof.proof, &proof.data)
                            .unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(
            results.iter().filter(|core| core.accepted).count(),
            1,
            "exactly one range is accepted"
        );
        assert_eq!(
            results.iter().filter(|core| core.replay).count(),
            1,
            "the in-flight duplicate replays after the winner commits"
        );
        // A full-object range completes the file for both callers.
        assert!(results.iter().all(|core| core.complete));
    }

    #[test]
    fn persist_tracker_paces_checkpoints_behind_both_floors() {
        let start = Instant::now();
        let mut tracker = PersistTracker {
            bytes_since: 0,
            last_at: start,
        };
        // Neither floor: no checkpoint.
        assert!(!tracker.should_checkpoint_at(1024, start + Duration::from_secs(1)));
        // The time floor alone: no checkpoint.
        assert!(!tracker.should_checkpoint_at(0, start + PERSIST_INTERVAL));
        // The byte floor alone: no checkpoint.
        assert!(!tracker.should_checkpoint_at(PERSIST_BYTES, start + Duration::from_millis(1500)));
        // Both floors met (bytes crossed earlier): checkpoint and reset both.
        assert!(tracker.should_checkpoint_at(0, start + PERSIST_INTERVAL + Duration::from_secs(1)));
        assert_eq!(tracker.bytes_since, 0);
        // After a checkpoint both floors restart.
        assert!(!tracker.should_checkpoint_at(
            PERSIST_BYTES,
            start + PERSIST_INTERVAL + Duration::from_secs(1)
        ));
        assert!(
            tracker.should_checkpoint_at(0, start + 2 * PERSIST_INTERVAL + Duration::from_secs(1))
        );
        // The slow path: dirty work under the byte floor still checkpoints
        // behind MAX_PERSIST_INTERVAL, bounding the crash-loss window for
        // transfers slower than the byte floor.
        let mut slow = PersistTracker {
            bytes_since: 0,
            last_at: start,
        };
        // 100 MiB at 4 s: under both the byte floor and the slow floor.
        assert!(!slow.should_checkpoint_at(100 * 1024 * 1024, start + Duration::from_secs(4)));
        // 100 MiB at 5 s: the slow-path floor alone fires the checkpoint.
        assert!(slow.should_checkpoint_at(0, start + Duration::from_secs(5)));
        assert_eq!(slow.bytes_since, 0);
        // 0 bytes at any age: no dirty work means no checkpoint.
        assert!(!slow.should_checkpoint_at(0, start + Duration::from_secs(60)));
    }

    #[test]
    fn checkpoint_warn_pacer_logs_first_failure_then_paces() {
        let start = Instant::now();
        let pacer = CheckpointWarnPacer::new();
        // The first failure logs immediately.
        assert!(pacer.should_log_at(start));
        // Repeats inside the interval stay quiet, so a failing checkpoint
        // on a fast transfer no longer warns once per 256 MiB.
        assert!(!pacer.should_log_at(start + Duration::from_secs(1)));
        assert!(!pacer.should_log_at(start + CHECKPOINT_WARN_INTERVAL - Duration::from_millis(1)));
        // After the interval the next failure is visible again, so a
        // persistently failing checkpoint cannot go silent.
        assert!(pacer.should_log_at(start + CHECKPOINT_WARN_INTERVAL));
        assert!(!pacer.should_log_at(start + CHECKPOINT_WARN_INTERVAL + Duration::from_secs(1)));
    }
}
