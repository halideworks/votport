//! Upload sessions: one worker thread per session owns all VOT state.
//!
//! The VOT SDK objects (`PackageIngest`, `NativeFile`) are kept on a single
//! dedicated thread per session; async handlers talk to it over a bounded
//! channel. That serializes disk writes per session and keeps the SDK types
//! off the async executor entirely.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
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
        .link_by_id(&setup.link_id)
        .map_err(|error| SessionError::internal(format!("link read failed: {error}")))?
        .ok_or_else(|| SessionError::conflict("request link no longer exists"))?
        .uploads;

    fs::create_dir_all(&setup.dest_dir)
        .map_err(|error| SessionError::internal(format!("create destination: {error}")))?;
    paths::tighten_dir(&setup.dest_dir);

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
    let recorded = setup
        .store
        .append_upload(&setup.tenant, &setup.link_id, upload)
        .map_err(SessionError::internal)?;
    if !recorded {
        return Err(SessionError::conflict("request link no longer exists"));
    }
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
    /// Tenants whose receive subtree is being deleted. Lives on the same
    /// mutex as `map` so [`Sessions::insert_admitted`] cannot race the pin.
    pinned: HashSet<String>,
    pinned_links: HashSet<String>,
    #[cfg(test)]
    delete_stall: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    #[cfg(test)]
    session_create_stall: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
    #[cfg(test)]
    finish_stall: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
}

pub struct SessionHandle {
    pub link_id: String,
    pub tenant: String,
    pub reserved_bytes: u64,
    pub sender: mpsc::Sender<Cmd>,
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

    /// Keeps the session registered until the returned command guard drops.
    pub fn touch(&self, id: &str) -> Option<SessionCommand> {
        let inner = self.inner.lock().expect("sessions poisoned");
        let handle = inner.map.get(id)?;
        *handle
            .activity
            .last_active
            .lock()
            .expect("session activity poisoned") = Instant::now();
        handle.activity.in_flight.fetch_add(1, Ordering::AcqRel);
        Some(SessionCommand {
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

    pub fn active_for_link(&self, link_id: &str) -> usize {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .map
            .values()
            .filter(|handle| handle.link_id == link_id)
            .count()
    }

    /// Drops sessions idle beyond `idle_secs`; their workers then exit and
    /// clean up staging files.
    pub fn sweep(&self, idle_secs: u64) {
        self.inner
            .lock()
            .expect("sessions poisoned")
            .map
            .retain(|_, handle| {
                handle.activity.in_flight.load(Ordering::Acquire) > 0
                    || handle
                        .activity
                        .last_active
                        .lock()
                        .expect("session activity poisoned")
                        .elapsed()
                        .as_secs()
                        < idle_secs
            });
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
