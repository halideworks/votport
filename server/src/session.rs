//! Upload sessions: one worker thread per session owns all VOT state.
//!
//! The VOT SDK objects (`PackageIngest`, `NativeFile`) are kept on a single
//! dedicated thread per session; async handlers talk to it over a bounded
//! channel. That serializes disk writes per session and keeps the SDK types
//! off the async executor entirely.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Bytes;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

use vot_sdk::object::{InMemoryObjectBuilder, ObjectId, Suite};
use vot_sdk::package::{EntryStorage, PackageEntry, PackageIngest};
use vot_sdk::verify::verify_range;
use vot_sdk_file::{CommitProfile, NativeFile, RangeStatus};

use crate::paths;
use crate::store::{now_unix, FileRecord, Store, UploadRecord};

pub const MAX_SEAL_BYTES: usize = 1024 * 1024;
pub const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PAGES: u64 = 4096;
pub const MAX_ENTRIES: usize = 20_000;
/// Covered bytes the client sends per chunk request.
pub const CHUNK_BYTES: u64 = 8 * 1024 * 1024;
/// Body cap for one chunk request (data + proof + slack).
pub const MAX_CHUNK_BODY_BYTES: usize = 9 * 1024 * 1024;
const MAX_NAME_ATTEMPTS: u32 = 100;

#[derive(Debug)]
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
}

#[derive(Clone, Debug, Serialize)]
pub struct FinishReport {
    pub upload_id: String,
    pub files: Vec<FileRecord>,
}

/// Everything a worker needs that outlives one request.
pub struct WorkerSetup {
    pub store: Arc<Store>,
    pub link_id: String,
    pub tenant: String,
    /// Absolute directory this session publishes into.
    pub dest_dir: PathBuf,
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
}

/// Shared control for one native-push admission and its eventual connection.
#[derive(Clone, Default)]
pub struct PushControl {
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

struct FileState {
    display_path: String,
    stored_components: Vec<String>,
    object: ObjectId,
    native: Option<NativeFile>,
    published: bool,
    receipt: bool,
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
pub fn spawn_worker(setup: WorkerSetup, mut receiver: mpsc::Receiver<Cmd>) {
    std::thread::spawn(move || {
        let mut phase = Phase::AwaitSeal;
        // Feedback for the admin: bytes newly accepted this session and the
        // last error handed to the sender, recorded if the session dies.
        let mut received: u64 = 0;
        let mut replays: u64 = 0;
        let mut rejected: u64 = 0;
        let mut last_error: Option<String> = None;
        // When the sender was last heard from. The worker only exits long
        // after that (the idle sweep), so stamping the event with now_unix()
        // there would date a five-minute failure two days late.
        let mut last_seen = now_unix();
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
        while let Some(cmd) = receiver.blocking_recv() {
            last_seen = now_unix();
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
                    // A failed begin has consumed the pages: the phase is
                    // already Done, the worker exits below, and the exit-time
                    // "interrupted" fall-through is skipped. Record it here.
                    if let Err(error) = &result {
                        if matches!(phase, Phase::Done) {
                            record_event(
                                &setup,
                                received,
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
                    let result = handle_chunk(&setup, &mut phase, entry, offset, &proof, &data);
                    match &result {
                        Ok(progress) if progress.replay => replays += 1,
                        Ok(progress) if progress.accepted => received += data.len() as u64,
                        Ok(_) => {}
                        Err(_) => rejected += 1,
                    }
                    send_noted!(reply, result);
                }
                Cmd::Finish { reply, _lease } => {
                    send_noted!(reply, handle_finish(&setup, &mut phase, replays, rejected));
                }
                Cmd::Abort { reply, _lease } => {
                    record_event(
                        &setup,
                        received,
                        last_seen,
                        "cancelled",
                        "cancelled by the sender".to_owned(),
                        replays,
                        rejected,
                    );
                    phase = Phase::Done;
                    let _ = reply.send(Ok(()));
                }
            }
            if matches!(phase, Phase::Done) {
                break;
            }
        }
        if !matches!(phase, Phase::Done) {
            record_event(
                &setup,
                received,
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
    if entries.len() + new_entries.len() > MAX_ENTRIES {
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

    // A read failure also means finish cannot record the upload, so refuse
    // before opening destinations rather than leave untracked files.
    let prior_uploads = setup
        .store
        .uploads_by_id(&setup.link_id)
        .map_err(|error| SessionError::internal(format!("link read failed: {error}")))?
        .ok_or_else(|| SessionError::conflict("request link no longer exists"))?;
    let delivered = delivered_index(&prior_uploads);

    fs::create_dir_all(&setup.dest_dir)
        .map_err(|error| SessionError::internal(format!("create destination: {error}")))?;
    paths::tighten_dir(&setup.dest_dir);

    let mut files = Vec::with_capacity(entries.len());
    for entry in &entries {
        if let Some(existing) = find_delivered(setup, &delivered, &entry.object_id()) {
            files.push(FileState {
                display_path: entry.path().collect::<Vec<_>>().join("/"),
                stored_components: existing.stored_components,
                object: entry.object_id(),
                native: None,
                published: true,
                receipt: existing.receipt,
            });
            continue;
        }
        files.push(open_destination(setup, entry)?);
    }

    // Zero-length objects have complete coverage already; publish now.
    for file in &mut files {
        if file.object.length == 0 && !file.published {
            publish_file(setup, file)?;
        }
    }

    let infos = entry_infos(setup, &files);
    *phase = Phase::Receiving { files };
    Ok(infos)
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
            Ok(meta) if meta.is_file() && meta.len() == object.length => {
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

fn open_destination(setup: &WorkerSetup, entry: &PackageEntry) -> Result<FileState, SessionError> {
    let components: Vec<String> = entry.path().map(str::to_owned).collect();
    open_destination_for(setup, components, entry.object_id())
}

fn open_destination_for(
    setup: &WorkerSetup,
    components: Vec<String>,
    object: ObjectId,
) -> Result<FileState, SessionError> {
    let display_path = components.join("/");
    let parent = |stored: &[String]| {
        paths::join_under(&setup.dest_dir, &stored[..stored.len() - 1])
            .map_err(SessionError::internal)
    };
    if components.len() > 1 {
        let parent = parent(&components)?;
        fs::create_dir_all(&parent)
            .map_err(|error| SessionError::internal(format!("create folders: {error}")))?;
        // Staging lands in this parent; see paths::tighten_dir.
        paths::tighten_dir(&parent);
    }
    let name = components.last().expect("manifest paths are never empty");
    for attempt in 0..MAX_NAME_ATTEMPTS {
        let mut stored = components.clone();
        *stored.last_mut().expect("non-empty") = paths::with_suffix(name, attempt);
        // The full stored path including the file name; `parent` above is
        // only for creating intermediate directories.
        let destination =
            paths::join_under(&setup.dest_dir, &stored).map_err(SessionError::internal)?;
        match NativeFile::create(&object, &destination, CommitProfile::Balanced) {
            Ok(native) => {
                return Ok(FileState {
                    display_path,
                    stored_components: stored,
                    object,
                    native: Some(native),
                    published: false,
                    receipt: false,
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

fn handle_chunk(
    setup: &WorkerSetup,
    phase: &mut Phase,
    entry: usize,
    offset: u64,
    proof: &[u8],
    data: &[u8],
) -> Result<ChunkProgress, SessionError> {
    let Phase::Receiving { files } = phase else {
        return Err(SessionError::conflict(
            "chunks are only accepted after begin",
        ));
    };
    let file = files
        .get_mut(entry)
        .ok_or_else(|| SessionError::bad(format!("no entry {entry}")))?;
    if file.published {
        // The file already verified completely; treat retries as replays.
        return Ok(ChunkProgress {
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
    let native = file
        .native
        .as_mut()
        .ok_or_else(|| SessionError::internal("file state lost"))?;
    let acceptance = native
        .accept(&verified)
        .map_err(|error| SessionError::internal(format!("write failed: {error}")))?;
    let complete = acceptance.progress.covered_bytes == acceptance.progress.total_bytes;
    if complete {
        publish_file(setup, file)?;
    }
    Ok(ChunkProgress {
        accepted: matches!(acceptance.status, RangeStatus::Accepted),
        replay: matches!(acceptance.status, RangeStatus::Replay),
        covered_bytes: acceptance.progress.covered_bytes,
        total_bytes: acceptance.progress.total_bytes,
        complete,
    })
}

struct Publication {
    destination: PathBuf,
    receipt: Option<PathBuf>,
}

// ponytail: process-wide lock; shard by destination only if publication throughput measures a need.
static PUBLICATION_NAMESPACE: Mutex<()> = Mutex::new(());

struct PublishedPushFiles {
    directory: PathBuf,
    owned: Vec<(PathBuf, PathBuf)>,
    armed: bool,
}

impl PublishedPushFiles {
    fn new(staging: &std::path::Path) -> Result<Self, SessionError> {
        let directory = staging.join("rollback");
        fs::create_dir(&directory)
            .map_err(|error| SessionError::internal(format!("create rollback guards: {error}")))?;
        paths::tighten_dir(&directory);
        Ok(Self {
            directory,
            owned: Vec::new(),
            armed: true,
        })
    }

    fn capture(&mut self, publication: Publication) -> Result<(), SessionError> {
        self.capture_path(publication.destination)?;
        if let Some(path) = publication.receipt {
            self.capture_path(path)?;
        }
        Ok(())
    }

    fn capture_path(&mut self, destination: PathBuf) -> Result<(), SessionError> {
        let guard = self.directory.join(self.owned.len().to_string());
        if let Err(error) = fs::hard_link(&destination, &guard) {
            // Publication just created this path in a private directory. Hold
            // its identity before unlinking so even this failure path cannot
            // remove a replacement.
            if let Ok(file) = fs::File::open(&destination) {
                let _ = vot_platform_fs::remove_file_handle(&file, &destination);
            }
            return Err(SessionError::internal(format!(
                "guard published native push file: {error}"
            )));
        }
        self.owned.push((guard, destination));
        Ok(())
    }

    fn disarm(&mut self) {
        self.armed = false;
        if let Err(error) = fs::remove_dir_all(&self.directory) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %self.directory.display(), %error, "remove native push rollback guards");
            }
        }
    }
}

impl Drop for PublishedPushFiles {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _publication_namespace = PUBLICATION_NAMESPACE
            .lock()
            .expect("publication namespace poisoned");
        for (guard, destination) in self.owned.iter().rev() {
            match fs::File::open(guard)
                .and_then(|file| vot_platform_fs::remove_file_handle(&file, destination))
            {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::error!(path = %destination.display(), %error, "roll back unrecorded native push file");
                }
            }
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn publish_push_entries(
    setup: &WorkerSetup,
    staging: &std::path::Path,
    entries: &mut [PushEntry],
    mut keep_running: impl FnMut() -> bool,
) -> Result<PublishedPushFiles, SessionError> {
    let mut publications = PublishedPushFiles::new(staging)?;
    for entry in entries {
        if !keep_running() {
            return Err(SessionError::conflict("native push was cancelled"));
        }
        let file = entry
            .file
            .as_mut()
            .ok_or_else(|| SessionError::internal("push file state is incomplete"))?;
        if !file.published {
            publish_push_entry(setup, file, &mut publications, || {})?;
        }
    }
    Ok(publications)
}

fn publish_push_entry(
    setup: &WorkerSetup,
    file: &mut FileState,
    publications: &mut PublishedPushFiles,
    after_publish: impl FnOnce(),
) -> Result<(), SessionError> {
    let _publication_namespace = PUBLICATION_NAMESPACE
        .lock()
        .expect("publication namespace poisoned");
    let publication = publish_file_locked(setup, file)?;
    after_publish();
    publications.capture(publication)
}

fn publish_file(setup: &WorkerSetup, file: &mut FileState) -> Result<Publication, SessionError> {
    let _publication_namespace = PUBLICATION_NAMESPACE
        .lock()
        .expect("publication namespace poisoned");
    publish_file_locked(setup, file)
}

fn publish_file_locked(
    setup: &WorkerSetup,
    file: &mut FileState,
) -> Result<Publication, SessionError> {
    let destination = paths::join_under(&setup.dest_dir, &file.stored_components)
        .map_err(SessionError::internal)?;
    let native = file
        .native
        .as_mut()
        .ok_or_else(|| SessionError::internal("file state lost"))?;
    native.publish().map_err(|error| {
        SessionError::conflict(format!(
            "publish {} failed: {error}; the name may have been taken mid-upload, retry the upload",
            file.display_path
        ))
    })?;
    // Best effort: the file is delivered and verified either way, and the
    // record notes whether its receipt exists.
    let receipt = if let Some(observation) = native.publish_observation() {
        match setup
            .signer
            .write_sidecar(&destination, &file.object, setup.session_id, observation)
        {
            Ok(path) => {
                file.receipt = true;
                Some(path)
            }
            Err(error) => {
                tracing::warn!(file = %file.display_path, "receipt: {error}");
                None
            }
        }
    } else {
        None
    };
    file.published = true;
    file.native = None;
    Ok(Publication {
        destination,
        receipt,
    })
}

fn handle_finish(
    setup: &WorkerSetup,
    phase: &mut Phase,
    replays: u64,
    rejected: u64,
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
    let report = commit_upload(setup, files, replays, rejected, Some("http"))?;
    *phase = Phase::Done;
    Ok(report)
}

fn commit_upload(
    setup: &WorkerSetup,
    files: &[FileState],
    replays: u64,
    rejected: u64,
    transport: Option<&str>,
) -> Result<FinishReport, SessionError> {
    commit_upload_records(
        setup,
        file_records(setup, files),
        replays,
        rejected,
        transport,
    )
}

fn commit_upload_records(
    setup: &WorkerSetup,
    records: Vec<FileRecord>,
    replays: u64,
    rejected: u64,
    transport: Option<&str>,
) -> Result<FinishReport, SessionError> {
    let upload = UploadRecord {
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
        .append_upload(&setup.tenant, &setup.link_id, upload)
        .map_err(SessionError::internal)?;
    if !recorded {
        return Err(SessionError::conflict("request link no longer exists"));
    }
    Ok(FinishReport {
        upload_id,
        files: records,
    })
}

fn file_records(setup: &WorkerSetup, files: &[FileState]) -> Vec<FileRecord> {
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
    components: Vec<String>,
    object: ObjectId,
    file: Option<FileState>,
}

struct PushObject {
    entries: Vec<usize>,
    complete: bool,
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
}

impl PushReceive {
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
            let _ = self
                .app
                .sessions
                .mark_active(&hex::encode(self.setup.session_id));
        }
    }

    fn prepare_manifest(
        &self,
        summary: vot_cli::PackageSummary,
        records: &[vot_cli::EntryRecord],
    ) -> Result<(), SessionError> {
        let validated = validate_push_manifest(&self.setup, summary, records)?;
        let prior_uploads = self
            .setup
            .store
            .uploads_by_id(&self.setup.link_id)
            .map_err(|error| SessionError::internal(format!("link read failed: {error}")))?
            .ok_or_else(|| SessionError::conflict("request link no longer exists"))?;
        let delivered = delivered_index(&prior_uploads);
        fs::create_dir_all(self.staging.join("objects"))
            .map_err(|error| SessionError::internal(format!("create push staging: {error}")))?;
        paths::tighten_dir(&self.staging);
        paths::tighten_dir(&self.staging.join("objects"));

        let mut inner = self.inner.lock().expect("push receive poisoned");
        if inner.manifest_ready {
            return Err(SessionError::conflict("push manifest was already prepared"));
        }
        for (components, object) in validated {
            let key = PushObjectKey {
                suite: object.suite,
                root: object.root,
                length: object.length,
            };
            let file = find_delivered(&self.setup, &delivered, &object).map(|existing| FileState {
                display_path: components.join("/"),
                stored_components: existing.stored_components,
                object: object.clone(),
                native: None,
                published: true,
                receipt: existing.receipt,
            });
            let index = inner.entries.len();
            inner.entries.push(PushEntry {
                components,
                object,
                file,
            });
            inner
                .objects
                .entry(key)
                .or_insert_with(|| PushObject {
                    entries: Vec::new(),
                    complete: false,
                })
                .entries
                .push(index);
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
        let key = PushObjectKey::from(object);
        let all_delivered = {
            let inner = self.inner.lock().expect("push receive poisoned");
            let planned = inner
                .objects
                .get(&key)
                .ok_or_else(|| SessionError::bad("push object is absent from the manifest"))?;
            planned
                .entries
                .iter()
                .all(|index| inner.entries[*index].file.is_some())
        };
        if all_delivered {
            self.finish_object(key, Vec::new())?;
            return Ok(None);
        }
        let path = self.staging.join("objects").join(hex::encode(key.root));
        let sink = vot_scheduler::FileSink::create_new(&path, key.length)
            .map_err(|error| SessionError::internal(format!("create push object: {error}")))?;
        Ok(Some(Box::new(PushFileSink {
            sink,
            path,
            receive: Arc::clone(self),
        })))
    }

    fn complete_object(
        self: &Arc<Self>,
        object: &vot_cli::ReceiveObject,
    ) -> Result<(), SessionError> {
        let key = PushObjectKey::from(object);
        let pending = {
            let inner = self.inner.lock().expect("push receive poisoned");
            inner
                .objects
                .get(&key)
                .ok_or_else(|| SessionError::bad("push object is absent from the manifest"))?
                .entries
                .iter()
                .filter_map(|index| {
                    let entry = &inner.entries[*index];
                    entry
                        .file
                        .is_none()
                        .then(|| (*index, entry.components.clone(), entry.object.clone()))
                })
                .collect::<Vec<_>>()
        };
        let mut completed = Vec::with_capacity(pending.len());
        for (index, components, object) in pending {
            if self.control.is_cancelled() {
                return Err(SessionError::conflict("native push was cancelled"));
            }
            completed.push((
                index,
                open_destination_for(&self.setup, components, object)?,
            ));
        }
        let path = self.staging.join("objects").join(hex::encode(key.root));
        let files = completed
            .iter_mut()
            .map(|(_, file)| file)
            .collect::<Vec<_>>();
        reprove_staging(&path, &ObjectId::from(key), files, || {
            self.mark_active();
            !self.control.is_cancelled()
        })?;
        self.finish_object(key, completed)
    }

    fn finish_object(
        &self,
        key: PushObjectKey,
        completed: Vec<(usize, FileState)>,
    ) -> Result<(), SessionError> {
        let (records, mut publications) = {
            let mut inner = self.inner.lock().expect("push receive poisoned");
            for (index, file) in completed {
                inner.entries[index].file = Some(file);
            }
            let planned = inner
                .objects
                .get_mut(&key)
                .ok_or_else(|| SessionError::bad("push object is absent from the manifest"))?;
            if planned.complete {
                return Ok(());
            }
            planned.complete = true;
            inner.remaining = inner
                .remaining
                .checked_sub(1)
                .ok_or_else(|| SessionError::internal("push object count underflow"))?;
            if inner.remaining != 0 || inner.committing {
                return Ok(());
            }
            inner.committing = true;
            if self.control.is_cancelled() {
                return Err(SessionError::conflict("native push was cancelled"));
            }
            let publications =
                publish_push_entries(&self.setup, &self.staging, &mut inner.entries, || {
                    !self.control.is_cancelled()
                })?;
            let files = inner
                .entries
                .iter()
                .map(|entry| {
                    entry
                        .file
                        .as_ref()
                        .ok_or_else(|| SessionError::internal("push file state is incomplete"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            (file_records_from_refs(&self.setup, &files), publications)
        };
        if self.control.is_cancelled() {
            return Err(SessionError::conflict("native push was cancelled"));
        }
        let report = commit_upload_records(&self.setup, records, 0, 0, Some("push"))?;
        publications.disarm();
        self.inner.lock().expect("push receive poisoned").succeeded = true;
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

impl Drop for PushReceive {
    fn drop(&mut self) {
        let sid = hex::encode(self.setup.session_id);
        let inner = self.inner.lock().expect("push receive poisoned");
        if !inner.succeeded {
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
        drop(inner);
        if let Err(error) = fs::remove_dir_all(&self.staging) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %self.staging.display(), %error, "remove push staging");
            }
        }
        self.app.sessions.remove(&sid);
        crate::app::remove_push_ticket(&self.app, &sid);
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

struct PushFileSink {
    sink: vot_scheduler::FileSink,
    path: PathBuf,
    receive: Arc<PushReceive>,
}

impl vot_scheduler::RangeSink for PushFileSink {
    fn write_at(&self, covered_offset: u64, data: &[u8]) -> Result<(), vot_scheduler::SinkError> {
        vot_scheduler::RangeSink::write_at(&self.sink, covered_offset, data)?;
        self.receive
            .received
            .fetch_add(data.len() as u64, Ordering::AcqRel);
        self.receive.app.push_metrics.add_bytes(data.len() as u64);
        self.receive.mark_active();
        Ok(())
    }
}

impl vot_cli::ReceiveSink for PushFileSink {
    fn flush(&self) -> Result<(), vot_cli::Error> {
        self.sink.file().sync_all().map_err(Into::into)
    }

    fn discard_partial(&self) -> Result<(), vot_cli::Error> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// The staging directory supplied to [`vot_cli::PushAdmission`].
#[must_use]
pub fn push_staging_dir(setup: &WorkerSetup) -> PathBuf {
    setup
        .dest_dir
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
        staging: push_staging_dir(&setup),
        app,
        setup,
        control,
        runtime,
        inner: Mutex::new(PushReceiveInner::default()),
        received: AtomicU64::new(0),
        last_active: AtomicU64::new(now_unix()),
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
    if entries.is_empty() || entries.len() > MAX_ENTRIES || summary.entries != entries.len() as u64
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

enum LocalProofs {
    Blake3(vot_proof_blake3::GroupCvs),
    Sha256(vot_proof_sha256::PieceHashes),
}

struct LocalRangeCover {
    covered_offset: u64,
    covered_length: u64,
    proof: Vec<u8>,
}

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
            file.native
                .as_mut()
                .ok_or_else(|| SessionError::internal("push file state lost"))?
                .accept(&verified)
                .map_err(|error| SessionError::internal(format!("write failed: {error}")))?;
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
    tracing::warn!(
        target: "audit", event = "upload_session_ended", link = %setup.link_id,
        outcome = %event.outcome, detail = %event.detail,
        received_bytes = event.received_bytes, expected_bytes = event.expected_bytes,
        "upload session ended without completing"
    );
    setup.store.audit(
        &setup.tenant,
        "",
        "upload_session_ended",
        &setup.link_id,
        &serde_json::json!({
            "outcome": event.outcome,
            "received_bytes": event.received_bytes,
            "expected_bytes": event.expected_bytes
        }),
    );
    let _ = setup
        .store
        .update_link(&setup.tenant, &setup.link_id, |link| {
            link.events.push(event);
            if link.events.len() > EVENTS_KEPT {
                let excess = link.events.len() - EVENTS_KEPT;
                link.events.drain(..excess);
            }
        });
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
    inner: Mutex<SessionsInner>,
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
    activity: Arc<SessionActivity>,
}

struct SessionActivity {
    in_flight: AtomicUsize,
    last_active: Mutex<Instant>,
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
            inner: Mutex::new(SessionsInner {
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
            }),
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
        received_bytes: impl FnOnce() -> Result<u64, String>,
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
        let mut inner = self.inner.lock().expect("sessions poisoned");
        if !tenant.is_empty() && inner.pinned.contains(&tenant) {
            return Err(InsertError::TenantPinned);
        }
        if inner.pinned_links.contains(&link_id) {
            return Err(InsertError::LinkPinned);
        }
        if inner.map.len() >= max_sessions
            || inner
                .map
                .values()
                .filter(|handle| handle.link_id == link_id)
                .count()
                >= max_link_sessions
        {
            return Err(InsertError::Capacity);
        }
        let tenant_sessions = inner
            .map
            .values()
            .filter(|handle| handle.tenant == tenant)
            .count();
        if max_tenant_sessions.is_some_and(|max| tenant_sessions as u64 >= max) {
            return Err(InsertError::TenantSessionLimit);
        }
        if let Some(max_total) = max_total_bytes {
            let received = received_bytes().map_err(InsertError::Store)?;
            let already_reserved = inner
                .map
                .values()
                .filter(|handle| handle.tenant == tenant)
                .fold(0_u64, |total, handle| {
                    total.saturating_add(handle.reserved_bytes)
                });
            if reserved_bytes
                > max_total
                    .saturating_sub(received)
                    .saturating_sub(already_reserved)
            {
                return Err(InsertError::ByteQuota);
            }
        }
        inner.map.insert(
            id,
            SessionHandle {
                link_id,
                tenant,
                reserved_bytes,
                sender,
                kind,
                activity: Arc::new(SessionActivity {
                    in_flight: AtomicUsize::new(0),
                    last_active: Mutex::new(Instant::now()),
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
        self.insert_admitted(
            SessionAdmission {
                id,
                link_id,
                tenant,
                reserved_bytes: 0,
                max_total_bytes: None,
                max_tenant_sessions: None,
                max_link_sessions: usize::MAX,
                max_sessions: usize::MAX,
                kind: SessionKind::Http,
            },
            sender,
            || Ok(0),
        )
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

    pub fn remove(&self, id: &str) {
        self.inner.lock().expect("sessions poisoned").map.remove(id);
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
            .insert_admitted(admission("s1", 60, 100, 2), dummy_sender(), || Ok(0))
            .unwrap();
        let mut full = admission("full", 1, 100, 2);
        full.tenant = "other".to_owned();
        full.max_sessions = 1;
        assert_eq!(
            sessions.insert_admitted(full, dummy_sender(), || Ok(0)),
            Err(InsertError::Capacity)
        );
        assert_eq!(
            sessions.insert_admitted(admission("s2", 60, 100, 2), dummy_sender(), || Ok(0),),
            Err(InsertError::ByteQuota)
        );
        assert_eq!(
            sessions.insert_admitted(
                admission("s2", u64::MAX, u64::MAX, 1),
                dummy_sender(),
                || Ok(0),
            ),
            Err(InsertError::TenantSessionLimit)
        );
        sessions.remove("s1");
        assert_eq!(
            sessions.insert_admitted(admission("stale", 60, 100, 1), dummy_sender(), || Ok(60),),
            Err(InsertError::ByteQuota)
        );
        assert_eq!(
            sessions.insert_admitted(admission("full", 1, u64::MAX, 1), dummy_sender(), || Ok(
                u64::MAX
            ),),
            Err(InsertError::ByteQuota)
        );
        sessions
            .insert_admitted(
                admission("s2", u64::MAX, u64::MAX, 1),
                dummy_sender(),
                || Ok(0),
            )
            .unwrap();
    }

    #[test]
    fn push_touch_is_rejected_without_changing_activity() {
        let sessions = Sessions::new();
        let mut push = admission("push", 0, 100, 1);
        push.kind = SessionKind::Push(PushControl::new());
        sessions
            .insert_admitted(push, dummy_sender(), || Ok(0))
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
            .insert_admitted(push, dummy_sender(), || Ok(0))
            .unwrap();

        assert!(sessions.contains_push("push"));
        assert!(control.connect());
        assert!(!control.connect());
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
            .insert_admitted(first, dummy_sender(), || Ok(0))
            .unwrap();

        let mut second = admission("push-2", 50, 100, 2);
        second.kind = SessionKind::Push(PushControl::new());
        assert_eq!(
            sessions.insert_admitted(second, dummy_sender(), || Ok(0)),
            Err(InsertError::ByteQuota)
        );

        sessions.remove("push-1");
        let mut admitted = admission("push-2", 50, 100, 2);
        admitted.kind = SessionKind::Push(PushControl::new());
        sessions
            .insert_admitted(admitted, dummy_sender(), || Ok(0))
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
        WorkerSetup {
            store: Arc::clone(&app.store),
            link_id: "link".to_owned(),
            tenant: String::new(),
            dest_dir: directory.join("receive"),
            dest_rel: String::new(),
            expected_package,
            max_total_bytes: u64::MAX,
            allow_hidden: false,
            signer: Arc::clone(&app.signer),
            session_id: [7; 16],
            started_at: 1,
        }
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

        let too_many = vec![direct; MAX_ENTRIES + 1];
        let oversized = vot_cli::PackageSummary {
            entries: too_many.len() as u64,
            ..summary
        };
        assert!(validate_push_manifest(&setup, oversized, &too_many).is_err());
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
    fn unpublished_record_guards_remove_only_held_files() {
        let directory = tempfile::tempdir().unwrap();
        let staging = directory.path().join("staging");
        fs::create_dir(&staging).unwrap();
        let destination = directory.path().join("published");
        let receipt = directory.path().join("published.vot-receipt");
        paths::tighten_dir(directory.path());
        fs::write(&destination, b"data").unwrap();
        fs::write(&receipt, b"receipt").unwrap();

        let mut guards = PublishedPushFiles::new(&staging).unwrap();
        guards
            .capture(Publication {
                destination: destination.clone(),
                receipt: Some(receipt.clone()),
            })
            .unwrap();
        drop(guards);

        assert!(!destination.exists());
        assert!(!receipt.exists());
    }

    #[test]
    fn rollback_guard_preserves_a_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let staging = directory.path().join("staging");
        fs::create_dir(&staging).unwrap();
        paths::tighten_dir(directory.path());
        let destination = directory.path().join("published");
        fs::write(&destination, b"ours").unwrap();
        let mut guards = PublishedPushFiles::new(&staging).unwrap();
        guards
            .capture(Publication {
                destination: destination.clone(),
                receipt: None,
            })
            .unwrap();
        fs::remove_file(&destination).unwrap();
        fs::write(&destination, b"replacement").unwrap();

        drop(guards);

        assert_eq!(fs::read(destination).unwrap(), b"replacement");
    }

    #[test]
    fn publication_namespace_serializes_capture_and_replacement_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let staged = directory.path().join("object");
        let data = vec![29_u8; 1024];
        fs::write(&staged, &data).unwrap();
        let object = object(Suite::Blake3Bao64, &data);
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        paths::tighten_dir(&setup.dest_dir);
        let mut file =
            open_destination_for(&setup, vec!["published".to_owned()], object.clone()).unwrap();
        reprove_staging(&staged, &object, vec![&mut file], || true).unwrap();
        let staging = directory.path().join("staging");
        fs::create_dir(&staging).unwrap();
        let mut guards = PublishedPushFiles::new(&staging).unwrap();
        publish_push_entry(&setup, &mut file, &mut guards, || {
            assert!(PUBLICATION_NAMESPACE.try_lock().is_err());
        })
        .unwrap();
        let destination = setup.dest_dir.join("published");
        fs::remove_file(&destination).unwrap();
        fs::write(&destination, b"replacement").unwrap();
        drop(guards);

        assert_eq!(fs::read(destination).unwrap(), b"replacement");
    }

    #[test]
    fn rollback_guard_creation_failure_removes_the_just_published_file() {
        let directory = tempfile::tempdir().unwrap();
        let staging = directory.path().join("staging");
        fs::create_dir(&staging).unwrap();
        paths::tighten_dir(directory.path());
        let destination = directory.path().join("published");
        fs::write(&destination, b"ours").unwrap();
        let mut guards = PublishedPushFiles::new(&staging).unwrap();
        fs::write(guards.directory.join("0"), b"collision").unwrap();

        assert!(guards
            .capture(Publication {
                destination: destination.clone(),
                receipt: None,
            })
            .is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn cancellation_between_final_publications_rolls_back_the_first() {
        let directory = tempfile::tempdir().unwrap();
        let staged = directory.path().join("object");
        let data = vec![23_u8; 1024];
        fs::write(&staged, &data).unwrap();
        let object = object(Suite::Blake3Bao64, &data);
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        paths::tighten_dir(&setup.dest_dir);
        let mut first =
            open_destination_for(&setup, vec!["first".to_owned()], object.clone()).unwrap();
        let mut second =
            open_destination_for(&setup, vec!["second".to_owned()], object.clone()).unwrap();
        reprove_staging(&staged, &object, vec![&mut first, &mut second], || true).unwrap();
        let staging = directory.path().join("push-staging");
        fs::create_dir(&staging).unwrap();
        let mut entries = [
            PushEntry {
                components: vec!["first".to_owned()],
                object: object.clone(),
                file: Some(first),
            },
            PushEntry {
                components: vec!["second".to_owned()],
                object,
                file: Some(second),
            },
        ];
        let mut checks = 0;

        assert!(publish_push_entries(&setup, &staging, &mut entries, || {
            checks += 1;
            checks < 2
        })
        .is_err());
        assert!(!setup.dest_dir.join("first").exists());
        assert!(!setup.dest_dir.join("second").exists());
    }
}
