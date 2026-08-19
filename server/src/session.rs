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

use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

use vot_sdk::object::ObjectId;
use vot_sdk::package::{EntryStorage, PackageEntry, PackageIngest};
use vot_sdk::verify::verify_range;
use vot_sdk_file::{CommitProfile, NativeFile, RangeStatus};

use crate::paths;
use crate::store::{FileRecord, Store, UploadRecord, now_unix};

pub const MAX_SEAL_BYTES: usize = 1024 * 1024;
pub const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PAGES: u64 = 4096;
pub const MAX_ENTRIES: usize = 20_000;
/// Covered bytes the client sends per chunk request.
pub const CHUNK_BYTES: u64 = 2 * 1024 * 1024;
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
        bytes: Vec<u8>,
        reply: Reply<u64>,
    },
    Page {
        bytes: Vec<u8>,
        reply: Reply<u64>,
    },
    Begin {
        reply: Reply<Vec<EntryInfo>>,
    },
    Chunk {
        entry: usize,
        offset: u64,
        proof: Vec<u8>,
        data: Vec<u8>,
        reply: Reply<ChunkProgress>,
    },
    Finish {
        reply: Reply<FinishReport>,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct EntryInfo {
    pub index: usize,
    pub path: String,
    pub stored_as: String,
    pub bytes: u64,
    pub complete: bool,
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
}

struct FileState {
    display_path: String,
    stored_components: Vec<String>,
    object: ObjectId,
    native: Option<NativeFile>,
    published: bool,
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
    let (sender, mut receiver) = mpsc::channel::<Cmd>(2);
    std::thread::spawn(move || {
        let mut phase = Phase::AwaitSeal;
        while let Some(cmd) = receiver.blocking_recv() {
            match cmd {
                Cmd::Seal { bytes, reply } => {
                    let _ = reply.send(handle_seal(&setup, &mut phase, &bytes));
                }
                Cmd::Page { bytes, reply } => {
                    let _ = reply.send(handle_page(&mut phase, &bytes));
                }
                Cmd::Begin { reply } => {
                    let _ = reply.send(handle_begin(&setup, &mut phase));
                }
                Cmd::Chunk {
                    entry,
                    offset,
                    proof,
                    data,
                    reply,
                } => {
                    let _ = reply.send(handle_chunk(&mut phase, entry, offset, &proof, &data));
                }
                Cmd::Finish { reply } => {
                    let _ = reply.send(handle_finish(&setup, &mut phase));
                }
            }
            if matches!(phase, Phase::Done) {
                break;
            }
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
    let page = ingest
        .push_page(bytes)
        .map_err(|error| SessionError::bad(format!("manifest page rejected: {:?}", error.code())))?;
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
            paths::admit_component(component, setup.allow_hidden)
                .map_err(SessionError::bad)?;
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

    let mut files = Vec::with_capacity(entries.len());
    for entry in &entries {
        files.push(open_destination(setup, entry)?);
    }

    // Zero-length objects have complete coverage already; publish now.
    for file in &mut files {
        if file.object.length == 0 {
            publish_file(file)?;
        }
    }

    let infos = files
        .iter()
        .enumerate()
        .map(|(index, file)| EntryInfo {
            index,
            path: file.display_path.clone(),
            stored_as: stored_rel(&setup.dest_rel, &file.stored_components),
            bytes: file.object.length,
            complete: file.published,
        })
        .collect();
    *phase = Phase::Receiving { files };
    Ok(infos)
}

fn open_destination(
    setup: &WorkerSetup,
    entry: &PackageEntry,
) -> Result<FileState, SessionError> {
    let components: Vec<String> = entry.path().map(str::to_owned).collect();
    let display_path = components.join("/");
    let object = entry.object_id();
    if components.len() > 1 {
        let parent = paths::join_under(&setup.dest_dir, &components[..components.len() - 1]);
        fs::create_dir_all(&parent)
            .map_err(|error| SessionError::internal(format!("create folders: {error}")))?;
    }
    let name = components.last().expect("manifest paths are never empty");
    for attempt in 0..MAX_NAME_ATTEMPTS {
        let mut stored = components.clone();
        *stored.last_mut().expect("non-empty") = paths::with_suffix(name, attempt);
        let destination = paths::join_under(&setup.dest_dir, &stored);
        match NativeFile::create(&object, &destination, CommitProfile::Balanced) {
            Ok(native) => {
                return Ok(FileState {
                    display_path,
                    stored_components: stored,
                    object,
                    native: Some(native),
                    published: false,
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
        publish_file(file)?;
    }
    Ok(ChunkProgress {
        accepted: matches!(acceptance.status, RangeStatus::Accepted),
        replay: matches!(acceptance.status, RangeStatus::Replay),
        covered_bytes: acceptance.progress.covered_bytes,
        total_bytes: acceptance.progress.total_bytes,
        complete,
    })
}

fn publish_file(file: &mut FileState) -> Result<(), SessionError> {
    let native = file
        .native
        .as_mut()
        .ok_or_else(|| SessionError::internal("file state lost"))?;
    native.publish().map_err(|error| {
        SessionError::conflict(format!(
            "publish {} failed: {error}; the name may have been taken mid-upload — retry the upload",
            file.display_path
        ))
    })?;
    file.published = true;
    file.native = None;
    Ok(())
}

fn handle_finish(setup: &WorkerSetup, phase: &mut Phase) -> Result<FinishReport, SessionError> {
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
        })
        .collect();
    let upload = UploadRecord {
        id: crate::auth::random_token(),
        completed_at: now_unix(),
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
