//! Upload sessions: one worker thread per session owns all VOT state.
//!
//! The VOT SDK objects (`PackageIngest`, `NativeFile`) are kept on a single
//! dedicated thread per session; async handlers talk to it over a bounded
//! channel. That serializes disk writes per session and keeps the SDK types
//! off the async executor entirely.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::Bytes;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

use vot_sdk::object::ObjectId;
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
    },
    Page {
        bytes: Bytes,
        reply: Reply<u64>,
    },
    Begin {
        reply: Reply<Vec<EntryInfo>>,
    },
    Chunk {
        entry: usize,
        offset: u64,
        proof: Bytes,
        data: Bytes,
        reply: Reply<ChunkProgress>,
    },
    Finish {
        reply: Reply<FinishReport>,
    },
    /// Sender gave up; lets the worker record a "cancelled" event before it
    /// exits, instead of the generic "interrupted" the drop path records.
    Abort {
        reply: Reply<()>,
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

pub fn spawn_worker(setup: WorkerSetup) -> mpsc::Sender<Cmd> {
    // Depth matches the client's chunk concurrency so handlers rarely block on
    // send. Queued chunks are Bytes aliasing the request bodies, not copies,
    // so the queue holds refcounts rather than duplicated buffers.
    let (sender, mut receiver) = mpsc::channel::<Cmd>(8);
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
                Cmd::Seal { bytes, reply } => {
                    send_noted!(reply, handle_seal(&setup, &mut phase, &bytes));
                }
                Cmd::Page { bytes, reply } => {
                    send_noted!(reply, handle_page(&mut phase, &bytes));
                }
                Cmd::Begin { reply } => {
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
                Cmd::Finish { reply } => {
                    send_noted!(reply, handle_finish(&setup, &mut phase, replays, rejected));
                }
                Cmd::Abort { reply } => {
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
    sender
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

    fs::create_dir_all(&setup.dest_dir)
        .map_err(|error| SessionError::internal(format!("create destination: {error}")))?;
    paths::tighten_dir(&setup.dest_dir);

    // Files this link already delivered, for dedupe on identical roots.
    let prior_uploads = setup
        .store
        .link(&setup.link_id)
        .map(|link| link.uploads)
        .unwrap_or_default();

    let mut files = Vec::with_capacity(entries.len());
    for entry in &entries {
        if let Some(existing) = find_delivered(setup, &prior_uploads, &entry.object_id()) {
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

/// A file with this object root already delivered on this link and still on
/// disk at its recorded name: the transfer is skipped and the existing copy
/// reported, instead of publishing a suffixed duplicate.
fn find_delivered(
    setup: &WorkerSetup,
    uploads: &[UploadRecord],
    object: &ObjectId,
) -> Option<Delivered> {
    let suite = suite_name(object.suite);
    let root = hex::encode(object.root);
    for record in uploads.iter().flat_map(|upload| &upload.files) {
        if record.deleted || record.root != root || record.suite != suite {
            continue;
        }
        // stored_as is relative to the receive root. A record made under a
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
    let display_path = components.join("/");
    let object = entry.object_id();
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

fn publish_file(setup: &WorkerSetup, file: &mut FileState) -> Result<(), SessionError> {
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
    if let Some(observation) = native.publish_observation() {
        let destination = paths::join_under(&setup.dest_dir, &file.stored_components);
        match destination
            .map_err(|error| error.to_string())
            .and_then(|destination| {
                setup.signer.write_sidecar(
                    &destination,
                    &file.object,
                    setup.session_id,
                    observation,
                )
            }) {
            Ok(_) => file.receipt = true,
            Err(error) => tracing::warn!(file = %file.display_path, "receipt: {error}"),
        }
    }
    file.published = true;
    file.native = None;
    Ok(())
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
    let records: Vec<FileRecord> = files
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
        .collect();
    let upload = UploadRecord {
        id: crate::auth::random_token(),
        started_at: setup.started_at,
        completed_at: now_unix(),
        replayed_chunks: replays,
        rejected_chunks: rejected,
        package_root: hex::encode(setup.expected_package.root),
        total_bytes: records.iter().map(|record| record.bytes).sum(),
        files: records.clone(),
    };
    let upload_id = upload.id.clone();
    setup
        .store
        .update_link(&setup.link_id, |link| link.uploads.push(upload))
        .map_err(SessionError::internal)?;
    *phase = Phase::Done;
    Ok(FinishReport {
        upload_id,
        files: records,
    })
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
    let _ = setup.store.update_link(&setup.link_id, |link| {
        link.events.push(event);
        if link.events.len() > EVENTS_KEPT {
            let excess = link.events.len() - EVENTS_KEPT;
            link.events.drain(..excess);
        }
    });
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
    map: Mutex<HashMap<String, SessionHandle>>,
}

pub struct SessionHandle {
    pub link_id: String,
    pub sender: mpsc::Sender<Cmd>,
    pub last_active: Instant,
}

impl Default for Sessions {
    fn default() -> Self {
        Self::new()
    }
}

impl Sessions {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, id: String, link_id: String, sender: mpsc::Sender<Cmd>) {
        self.map.lock().expect("sessions poisoned").insert(
            id,
            SessionHandle {
                link_id,
                sender,
                last_active: Instant::now(),
            },
        );
    }

    /// The link a session belongs to, for completion notifications.
    pub fn link_id(&self, id: &str) -> Option<String> {
        self.map
            .lock()
            .expect("sessions poisoned")
            .get(id)
            .map(|handle| handle.link_id.clone())
    }

    /// Returns the sender for a session and refreshes its idle clock.
    pub fn touch(&self, id: &str) -> Option<mpsc::Sender<Cmd>> {
        let mut map = self.map.lock().expect("sessions poisoned");
        let handle = map.get_mut(id)?;
        handle.last_active = Instant::now();
        Some(handle.sender.clone())
    }

    pub fn remove(&self, id: &str) {
        self.map.lock().expect("sessions poisoned").remove(id);
    }

    pub fn total(&self) -> usize {
        self.map.lock().expect("sessions poisoned").len()
    }

    pub fn active_for_link(&self, link_id: &str) -> usize {
        self.map
            .lock()
            .expect("sessions poisoned")
            .values()
            .filter(|handle| handle.link_id == link_id)
            .count()
    }

    /// Drops sessions idle beyond `idle_secs`; their workers then exit and
    /// clean up staging files.
    pub fn sweep(&self, idle_secs: u64) {
        self.map
            .lock()
            .expect("sessions poisoned")
            .retain(|_, handle| handle.last_active.elapsed().as_secs() < idle_secs);
    }
}
