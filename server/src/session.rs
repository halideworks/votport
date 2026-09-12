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
use std::sync::{Arc, Mutex};
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
    /// re-attach, and exit.
    Suspend { reply: oneshot::Sender<()> },
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
            let _ = self.reopen();
        }
    }
}

struct FileState {
    display_path: String,
    stored_components: Vec<String>,
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
                Cmd::Begin { reply, _lease } => {
                    let result = handle_begin(&setup, &mut phase);
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
                    // Checkpoint covered progress on a byte or time threshold,
                    // never per batch, so the fsync never paces accept.
                    if persist.should_checkpoint(received - received_before) {
                        if let Phase::Receiving { files } = &mut phase {
                            checkpoint_session(&setup, files);
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
                    preserve_phase(&setup, &mut phase);
                    suspended = true;
                    phase = Phase::Done;
                    let _ = reply.send(());
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
    };
    Ok(pages)
}

fn entry_count_within_limit(count: usize) -> bool {
    count <= MAX_ENTRIES
}

fn handle_page(phase: &mut Phase, bytes: &[u8]) -> Result<u64, SessionError> {
    let Phase::Pages {
        ingest,
        entries,
        pages_pushed,
    } = phase
    else {
        return Err(SessionError::conflict(
            "manifest pages are not expected in this state",
        ));
    };
    let page = ingest.push_page(bytes).map_err(|error| {
        SessionError::bad(format!("manifest page rejected: {:?}", error.code()))
    })?;
    let new_entries = page.into_entries();
    if !entry_count_within_limit(entries.len() + new_entries.len()) {
        return Err(SessionError::bad(format!(
            "package exceeds {MAX_ENTRIES} entries"
        )));
    }
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
    let Phase::Pages {
        ingest: _,
        entries,
        pages_pushed: _,
    } = phase
    else {
        return Err(SessionError::conflict(
            "begin is only valid after the seal and all pages",
        ));
    };
    let entries = std::mem::take(entries);
    let Phase::Pages { ingest, .. } = std::mem::replace(phase, Phase::Done) else {
        unreachable!("phase was matched as Pages above");
    };
    // finish() authenticates every buffered page against the expected root.
    ingest
        .finish()
        .map_err(|error| SessionError::bad(format!("manifest rejected: {:?}", error.code())))?;

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
    let prior_uploads = setup
        .store
        .uploads_by_id(&setup.link_id)
        .map_err(|error| SessionError::internal(format!("link read failed: {error}")))?
        .ok_or_else(|| SessionError::conflict("request link no longer exists"))?;
    let delivered = delivered_index(&prior_uploads);

    let destinations = entries
        .iter()
        .map(|entry| (entry.path().map(str::to_owned).collect(), entry.object_id()))
        .collect::<Vec<_>>();
    let files = prepare_files(setup, &destinations, &delivered, || true)?;

    persist_session(setup, &files)?;
    *phase = Phase::Receiving { files };
    handle_begin(setup, phase)
}

/// Persist checkpoint pacing: write covered progress no more than this often
/// by bytes or by time, so the fsync'd update never paces the accept path.
const PERSIST_BYTES: u64 = 256 * 1024 * 1024;
const PERSIST_INTERVAL: Duration = Duration::from_secs(5);

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

    /// Returns true when accumulated bytes or elapsed time crosses a
    /// checkpoint threshold, resetting the counters.
    fn should_checkpoint(&mut self, added: u64) -> bool {
        self.bytes_since += added;
        if self.bytes_since >= PERSIST_BYTES || self.last_at.elapsed() >= PERSIST_INTERVAL {
            self.bytes_since = 0;
            self.last_at = Instant::now();
            true
        } else {
            false
        }
    }
}

pub(crate) fn persist_push(setup: &WorkerSetup, key: String) -> Result<(), String> {
    let mut session = persisted_session(setup, &[]);
    if let Some(previous) = setup.store.load_push_session(&key)? {
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
                stored_components: file.stored_components.clone(),
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

fn checkpoint_session(setup: &WorkerSetup, files: &mut [FileState]) -> bool {
    if let Err(error) = checkpoint_files(setup, files.iter().enumerate()) {
        tracing::warn!(%error, "checkpoint upload session failed");
        return false;
    }
    forget_publications(files)
}

fn forget_publications(files: &mut [FileState]) -> bool {
    let mut complete = true;
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
            tracing::warn!(path = %file.display_path, error = %error.message, "retain publication journal for recovery");
        } else {
            file.native = None;
        }
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

fn restore_files(
    setup: &WorkerSetup,
    persisted: &mut PersistedUploadSession,
    active: impl Fn() -> bool,
) -> Result<(Vec<FileState>, Vec<PathBuf>), String> {
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
        let state = vot_sdk_file::ResumeState {
            staging_name: file.staging_path.file_name().unwrap_or_default().to_owned(),
            journal_name: file.journal_path.file_name().unwrap_or_default().to_owned(),
            incarnation: file.incarnation,
            profile: file.profile,
            nas_contract: file.nas_contract,
            runs: runs.into_iter().collect(),
        };
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
            stored_components: file.stored_components.clone(),
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

fn delivered_index(uploads: &[UploadRecord]) -> HashMap<(&str, &str), Vec<&FileRecord>> {
    let mut index: HashMap<_, Vec<_>> = HashMap::new();
    for record in uploads.iter().flat_map(|upload| &upload.files) {
        if !record.deleted {
            index
                .entry((record.suite.as_str(), record.root.as_str()))
                .or_default()
                .push(record);
        }
    }
    index
}

/// A file with this object root already delivered on this link and still on
/// disk at its recorded name: the transfer is skipped and the existing copy
/// reported, instead of publishing a suffixed duplicate.
fn find_delivered(
    setup: &WorkerSetup,
    delivered: &HashMap<(&str, &str), Vec<&FileRecord>>,
    object: &ObjectId,
    active: impl Fn() -> bool,
) -> Option<Delivered> {
    let suite = suite_name(object.suite);
    let root = hex::encode(object.root);
    for record in delivered.get(&(suite.as_str(), root.as_str()))? {
        // stored_as is relative to the tenant's subtree: it carries the link
        // dest but not the tenant prefix, which is why dest_rel is stripped
        // before joining under dest_dir. A record made under a
        // different link dest no longer lives beneath dest_dir; skip it.
        let rel = if setup.dest_rel.is_empty() {
            record.stored_as.as_str()
        } else {
            match record
                .stored_as
                .strip_prefix(&format!("{}/", setup.dest_rel))
            {
                Some(rest) => rest,
                None => continue,
            }
        };
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
                return Some(Delivered {
                    stored_components: components,
                    receipt: record.receipt,
                });
            }
            _ => {}
        }
    }
    None
}

fn prepare_files(
    setup: &WorkerSetup,
    entries: &[(Vec<String>, ObjectId)],
    delivered: &HashMap<(&str, &str), Vec<&FileRecord>>,
    active: impl Fn() -> bool + Sync,
) -> Result<Vec<FileState>, SessionError> {
    let prepare = |(components, object): &(Vec<String>, ObjectId)| {
        if !active() {
            return Err(SessionError::conflict("receive preparation cancelled"));
        }
        if let Some(existing) = find_delivered(setup, delivered, object, &active) {
            return Ok(FileState {
                display_path: components.join("/"),
                stored_components: existing.stored_components,
                object: object.clone(),
                native: None,
                published: true,
                receipt: existing.receipt,
                checkpointed: Mutex::new(None),
                first_range_at: None,
                rehash: false,
            });
        }
        if !active() {
            return Err(SessionError::conflict("receive preparation cancelled"));
        }
        open_destination_for(setup, components.clone(), object.clone())
    };
    if entries.len() < MAX_CHUNK_BATCH * 2 {
        return entries.iter().map(prepare).collect();
    }
    let stopped = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let workers = entries
            .chunks(entries.len().div_ceil(MAX_CHUNK_BATCH))
            .map(|chunk| {
                let prepare = &prepare;
                let stopped = &stopped;
                scope.spawn(move || {
                    let mut files = Vec::with_capacity(chunk.len());
                    for entry in chunk {
                        if stopped.load(Ordering::Acquire) {
                            break;
                        }
                        match prepare(entry) {
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

fn open_destination_for(
    setup: &WorkerSetup,
    components: Vec<String>,
    object: ObjectId,
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
                    stored_components: stored,
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
            Err(error) if error.kind() == vot_sdk_file::ErrorKind::AlreadyExists => {}
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
fn preserve_phase(setup: &WorkerSetup, phase: &mut Phase) {
    if let Phase::Receiving { files } = phase {
        checkpoint_session(setup, files);
        for file in files {
            if let Some(native) = file.native.take() {
                native.abandon();
            }
        }
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
    let records: Vec<FileRecord> = session
        .files
        .iter()
        .filter(|file| file.published)
        .map(|file| FileRecord {
            path: file.display_path.clone(),
            stored_as: stored_rel(&session.dest_rel, &file.stored_components),
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
    record_session_event(store, ended, &session.tenant, &session.link_id, event);
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
    let upload_id = upload.id.clone();
    let recorded = setup
        .store
        .append_upload_from_session(
            &setup.tenant,
            &setup.link_id,
            upload,
            &hex::encode(setup.session_id),
        )
        .map_err(SessionError::internal)?;
    if !recorded {
        return Err(SessionError::conflict("request link no longer exists"));
    }
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
    last_active: AtomicU64,
    checkpoint: Mutex<PersistTracker>,
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
        let now = now_unix();
        let previous = self.last_active.load(Ordering::Acquire);
        if now > previous
            && self
                .last_active
                .compare_exchange(previous, now, Ordering::AcqRel, Ordering::Acquire)
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
        let prior_uploads = self
            .setup
            .store
            .uploads_by_id(&self.setup.link_id)
            .map_err(|error| SessionError::internal(format!("link read failed: {error}")))?
            .ok_or_else(|| SessionError::conflict("request link no longer exists"))?;
        let delivered = delivered_index(&prior_uploads);
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
        let files = match restored {
            Some(files) => files,
            None => prepare_files(&self.setup, &validated, &delivered, || {
                self.check_active().is_ok()
            })?,
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
            self.finish_object(key)?;
            return Ok(None);
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

    fn checkpoint(&self, inner: &mut PushReceiveInner) -> Result<(), String> {
        {
            let active = inner
                .objects
                .values()
                .filter_map(|object| object.active.as_ref())
                .map(|files| files.read().expect("push object poisoned"))
                .collect::<Vec<_>>();
            checkpoint_files(
                &self.setup,
                inner
                    .entries
                    .iter()
                    .enumerate()
                    .filter_map(|(index, entry)| entry.file.as_ref().map(|file| (index, file)))
                    .chain(
                        active
                            .iter()
                            .flat_map(|files| files.iter().map(|(index, file)| (*index, file))),
                    ),
            )?;
        }
        for entry in &mut inner.entries {
            if let Some(file) = entry.file.as_mut() {
                forget_publications(std::slice::from_mut(file));
            }
        }
        Ok(())
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
            if due || inner.remaining == 0 {
                self.checkpoint(&mut inner)
                    .map_err(SessionError::internal)?;
            }
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
            if let Err(error) = self.checkpoint(&mut inner) {
                tracing::warn!(%error, "retain native push recovery journals");
            }
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
            if self.control.park() {
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
                .clear_push_directory(&self.staging, lock)
            {
                tracing::warn!(path = %self.staging.display(), %error, "clear push staging");
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
        let due = self
            .receive
            .checkpoint
            .lock()
            .map_err(|_| vot_scheduler::SinkError)?
            .should_checkpoint(verified.data().len() as u64);
        if due {
            let mut inner = self
                .receive
                .inner
                .lock()
                .map_err(|_| vot_scheduler::SinkError)?;
            if self.receive.checkpoint(&mut inner).is_err() {
                self.stopped.store(true, Ordering::Release);
                return Err(vot_scheduler::SinkError);
            }
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
        last_active: AtomicU64::new(now_unix()),
        checkpoint: Mutex::new(PersistTracker::new()),
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
    if entries.is_empty()
        || !entry_count_within_limit(entries.len())
        || summary.entries != entries.len() as u64
    {
        return Err(SessionError::bad(format!(
            "package entry count is outside 1..={MAX_ENTRIES}"
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
    record_session_event(
        &setup.store,
        &setup.ended,
        &setup.tenant,
        &setup.link_id,
        event,
    );
}

fn record_session_event(
    store: &Arc<Store>,
    ended_sender: &mpsc::UnboundedSender<SessionEnded>,
    tenant: &str,
    link_id: &str,
    event: crate::store::SessionEvent,
) {
    tracing::warn!(
        target: "audit", event = "upload_session_ended", link = %link_id,
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
            "outcome": event.outcome,
            "received_bytes": event.received_bytes,
            "expected_bytes": event.expected_bytes
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
    let _ = store.update_link(tenant, link_id, |link| {
        ended.label = link.label.clone();
        ended.notifications = link.notifications.clone();
        link.events.push(event);
        if link.events.len() > EVENTS_KEPT {
            let excess = link.events.len() - EVENTS_KEPT;
            link.events.drain(..excess);
        }
    });
    let _ = ended_sender.send(ended);
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

fn stored_rel(dest_rel: &str, components: &[String]) -> String {
    let tail = components.join("/");
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

pub struct LinkPin<'a> {
    sessions: &'a Sessions,
    link_id: String,
}

impl Drop for LinkPin<'_> {
    fn drop(&mut self) {
        self.sessions.unpin_link(&self.link_id);
    }
}

struct SessionsInner {
    map: HashMap<String, SessionHandle>,
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
    session_create_stall: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    #[cfg(test)]
    finish_stall: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
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
                pinned: HashSet::new(),
                outbound: HashMap::new(),
                pinned_links: HashSet::new(),
                #[cfg(test)]
                delete_stall: None,
                #[cfg(test)]
                session_create_stall: None,
                #[cfg(test)]
                finish_stall: None,
            })),
        }
    }

    /// Blocks new sessions for `tenant` until the owner calls
    /// [`Self::unpin_tenant`]. Returns whether this caller acquired the pin.
    /// The default tenant (`""`) is never pinned.
    pub fn pin_tenant_for_delete(&self, tenant: &str) -> bool {
        if tenant.is_empty() {
            return false;
        }
        self.inner
            .lock()
            .expect("sessions poisoned")
            .pinned
            .insert(tenant.to_owned())
    }

    pub fn unpin_tenant(&self, tenant: &str) {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .pinned
            .remove(tenant);
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
    pub fn try_pin_link(&self, link_id: &str) -> Option<LinkPin<'_>> {
        self.pin_link_for_delete(link_id).then(|| LinkPin {
            sessions: self,
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

    /// Atomically reserves tenant capacity and fails if a delete pin or quota
    /// prevents admission. All checks share the same lock as insertion.
    pub fn insert_admitted(
        &self,
        admission: SessionAdmission,
        sender: mpsc::Sender<Cmd>,
        received_bytes: impl FnOnce() -> Result<(u64, Vec<crate::store::RetainedReservation>), String>,
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
            .expect("sessions poisoned")
            .map
            .retain(|_, handle| {
                if matches!(handle.kind, SessionKind::Http) {
                    senders.push(handle.sender.clone());
                    return false;
                }
                true
            });
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
        assert!(sessions.pin_tenant_for_delete("acme"));
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

        sessions.unpin_tenant("acme");
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
    fn pin_is_exclusive() {
        let sessions = Sessions::new();
        assert!(sessions.pin_tenant_for_delete("acme"));
        assert!(!sessions.pin_tenant_for_delete("acme"));
        assert!(sessions.tenant_pinned("acme"));
        sessions.unpin_tenant("acme");
        assert!(!sessions.tenant_pinned("acme"));
        assert!(sessions.pin_tenant_for_delete("acme"));
    }

    #[test]
    fn delete_pin_blocks_new_outbound_operations_while_active_count_remains() {
        let sessions = Sessions::new();
        let operation = sessions.try_begin_outbound("acme").unwrap();
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 1);
        assert!(sessions.pin_tenant_for_delete("acme"));
        assert!(sessions.try_begin_outbound("acme").is_none());
        drop(operation);
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 0);
        sessions.unpin_tenant("acme");
    }

    #[test]
    fn owned_outbound_operation_keeps_tenant_admitted_until_drop() {
        let sessions = Sessions::new();
        let operation = sessions.try_begin_outbound_owned("acme").unwrap();
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 1);
        assert!(sessions.pin_tenant_for_delete("acme"));
        assert!(sessions.try_begin_outbound_owned("acme").is_none());
        drop(operation);
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 0);
        sessions.unpin_tenant("acme");
    }

    #[test]
    fn pin_does_not_apply_to_the_default_tenant() {
        let sessions = Sessions::new();
        assert!(!sessions.pin_tenant_for_delete(""));
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

    fn object(suite: Suite, data: &[u8]) -> ObjectId {
        let mut builder =
            InMemoryObjectBuilder::new(suite, Some(data.len() as u64), data.len() as u64).unwrap();
        builder.update(data).unwrap();
        builder.finish().unwrap().object_id().clone()
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
            let workers = Mutex::new(HashSet::new());
            let files = prepare_files(&setup, &entries, &HashMap::new(), || {
                workers.lock().unwrap().insert(std::thread::current().id());
                true
            })
            .unwrap();
            assert_eq!(files.len(), count);
            for (index, file) in files.iter().enumerate() {
                assert_eq!(file.stored_components, entries[index].0);
                assert!(!file.published);
            }
            let workers = workers.lock().unwrap().len();
            assert!(workers <= MAX_CHUNK_BATCH);
            if count >= MAX_CHUNK_BATCH * 2 {
                assert!(workers > 1);
            }
            drop(files);
            if count == 0 {
                continue;
            }
            fs::write(setup.dest_dir.join("blocked"), b"unrelated").unwrap();
            entries[count / 2].0 = vec!["blocked".into(), "frame".into()];
            assert!(prepare_files(&setup, &entries, &HashMap::new(), || true).is_err());
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
            assert!(prepare_files(&setup, &entries, &HashMap::new(), || checks
                .fetch_add(1, Ordering::Relaxed)
                < 1)
            .is_err());
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
                let checks = AtomicU64::new(0);
                assert!(restore_files(&retry_setup, &mut persisted, || {
                    checks.fetch_add(1, Ordering::Relaxed) < 2
                })
                .is_err());
                assert_eq!(checks.load(Ordering::Relaxed), 3);
                assert_eq!(fs::read(&journal).unwrap(), journal_before);
                let (files, _) = restore_files(&retry_setup, &mut persisted, || true).unwrap();
                assert!(files[0].published);
                assert!(!journal.exists());
            }
        }
    }

    #[tokio::test]
    async fn completed_native_teardown_keeps_admission_until_publication_cleanup() {
        for cleaned in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let application = crate::api::testing::build(directory.path());
            let object = object(Suite::Blake3Bao64, b"");
            let setup = setup_with_app(directory.path(), object.clone(), &application);
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
            let (seams, handle) = push_seams(
                Arc::clone(&application),
                setup,
                PushControl::resumable(key.clone(), Some(lock)),
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
            .tombstone_files("", &setup.link_id, |file| file.stored_as == "frame-0")
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
            receive
                .checkpoint(&mut receive.inner.lock().unwrap())
                .unwrap();
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
            receive
                .checkpoint(&mut receive.inner.lock().unwrap())
                .unwrap();
            write_push(Arc::clone(&sink), &requested, bytes);
            for _ in 0..2 {
                receive
                    .checkpoint(&mut receive.inner.lock().unwrap())
                    .unwrap();
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
            receive
                .checkpoint(&mut receive.inner.lock().unwrap())
                .unwrap();
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
        assert!(receive.choose_sink(&receive_objects[0]).unwrap().is_none());
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
        assert!(stage.join("writer.lock").is_file());
        assert_eq!(fs::read_dir(&stage).unwrap().count(), 1);
        assert!(application.store.load_push_sessions().unwrap().is_empty());
        for (index, bytes) in data.iter().enumerate() {
            assert_eq!(
                fs::read(directory.path().join(format!("receive/file-{index}"))).unwrap(),
                *bytes
            );
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
            let delivered =
                HashMap::from([((record.suite.as_str(), record.root.as_str()), vec![&record])]);
            assert!(find_delivered(&setup, &delivered, &expected, || true).is_some());
            assert!(find_delivered(&setup, &delivered, &expected, || false).is_none());
            fs::write(&path, b"changed!").unwrap();
            assert!(find_delivered(&setup, &delivered, &expected, || true).is_none());
            let file = FileState {
                display_path: record.path.clone(),
                stored_components: vec![record.path],
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
            stored_components: vec!["fast".to_owned()],
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
            assert!(entry_count_within_limit(count));
        }
        for count in [2_000_001, usize::MAX] {
            assert!(!entry_count_within_limit(count));
        }
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

        assert!(!entry_count_within_limit(MAX_ENTRIES + 1));
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
            stored_components: vec!["obj".to_owned()],
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
    fn persist_tracker_checkpoints_on_bytes_and_on_time() {
        let mut tracker = PersistTracker::new();
        // A small addition well under the byte threshold does not checkpoint.
        assert!(!tracker.should_checkpoint(1024));
        // Crossing the byte threshold does, and resets the counter.
        assert!(tracker.should_checkpoint(PERSIST_BYTES));
        assert!(!tracker.should_checkpoint(1024));
        // The time threshold fires independently of bytes.
        tracker.last_at = Instant::now() - PERSIST_INTERVAL;
        assert!(tracker.should_checkpoint(0));
    }
}
