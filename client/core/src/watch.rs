//! Watch folders: a folder whose settled drops ship to a request link
//! without anyone at the keyboard.
//!
//! The list of watches lives in `watches.json` under the state directory,
//! owner-only, so the apps and `votport watch` share one list. A watcher
//! thread scans each folder every [`POLL`]: a top-level file or folder whose
//! fingerprint (entry count, total bytes, newest change) has not moved for
//! [`SETTLE`] and whose newest change is itself at least that old is handed
//! to the listener once, as one drop, so a stalled writer cannot have a
//! half-written drop shipped under it; the caller ships
//! it with [`ship`], which moves it into the folder's `shipped` subfolder
//! when the send ends well, so the folder itself is the ledger. A drop that
//! fails stays where it is with its failed card and Retry; it is handed over
//! again only if it changes.
//!
//! ponytail: polling, not the platform's file events; two seconds of scan
//! per watch is nothing next to a settle window, and it needs no dependency.
//! A watch to a password link keeps that password in the same owner-only
//! file, since an unattended send has to hold it; the keychain is the
//! upgrade with the signed apps.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::api::{split_link_as, LinkKind};
use crate::error::{Error, Result};
use crate::identity::{state_dir, write_private};

const FILE: &str = "watches.json";
/// The subfolder a shipped drop is moved into.
pub const SHIPPED: &str = "shipped";
/// How long a drop must hold still before it ships. A writer that pauses
/// between two writes looks exactly like a finished one, so the window has
/// to outlast that pause: two appends 15 s apart split the previous 10 s
/// window and shipped as two half-drops. The live-confirmed pause is the
/// floor; the headroom keeps a slower pause from landing on the boundary.
/// ponytail: a pause longer than the window still splits; telling a live
/// writer from a finished one needs open-handle detection, not more
/// polling.
pub const SETTLE: Duration = Duration::from_secs(30);
/// How often a watched folder is scanned.
pub const POLL: Duration = Duration::from_secs(2);

/// One native watch send at a time. The permit covers the platform callback
/// queue as well as the blocking send, so a fast poll cannot strand a burst
/// of callbacks as native sessions.
const WATCH_CAPACITY: usize = 1;

/// One watched folder, as a shell lists it. Never the password.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Watch {
    pub id: String,
    /// The folder, absolute.
    pub dir: String,
    /// The request link its drops ship to.
    pub link: String,
    pub has_password: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct Stored {
    id: String,
    dir: String,
    link: String,
    #[serde(default)]
    password: Option<String>,
}

impl From<&Stored> for Watch {
    fn from(stored: &Stored) -> Self {
        Self {
            id: stored.id.clone(),
            dir: stored.dir.clone(),
            link: stored.link.clone(),
            has_password: stored.password.is_some(),
        }
    }
}

fn path() -> PathBuf {
    state_dir().join(FILE)
}

fn load() -> Vec<Stored> {
    std::fs::read(path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn store(list: &[Stored]) -> Result<()> {
    std::fs::create_dir_all(state_dir())?;
    let bytes = serde_json::to_vec(list).map_err(|error| Error::Other(error.to_string()))?;
    write_private(&path(), &bytes)
}

/// The watched folders, in the order they were added.
#[must_use]
pub fn watches() -> Vec<Watch> {
    load().iter().map(Watch::from).collect()
}

/// Adds a watch: `dir` must be a folder, `link` a request link. A folder
/// already watched is replaced.
///
/// # Errors
/// A `dir` that is not a folder ([`Error::Read`]) or a link that is not a
/// request link.
pub fn add_watch(dir: &str, link: &str, password: Option<String>) -> Result<Watch> {
    let dir = std::fs::canonicalize(dir).map_err(|source| Error::Read {
        path: PathBuf::from(dir),
        source,
    })?;
    if !dir.is_dir() {
        return Err(Error::Read {
            path: dir,
            source: std::io::Error::new(std::io::ErrorKind::NotADirectory, "not a folder"),
        });
    }
    split_link_as(link, LinkKind::Request)?;
    let dir = dir.to_string_lossy().into_owned();
    let mut list = load();
    let removed = list
        .iter()
        .filter(|stored| stored.dir == dir)
        .map(|stored| stored.id.clone())
        .collect::<Vec<_>>();
    list.retain(|stored| stored.dir != dir);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let stored = Stored {
        id: crate::journal::fresh_id(now),
        dir,
        link: link.trim().to_owned(),
        password: password.filter(|p| !p.is_empty()),
    };
    list.push(stored.clone());
    store(&list)?;
    for id in removed {
        release_watch(&id);
    }
    Ok(Watch::from(&stored))
}

/// Removes a watch. Nothing in the folder changes.
///
/// # Errors
/// A write failure.
pub fn remove_watch(id: &str) -> Result<()> {
    let mut list = load();
    list.retain(|stored| stored.id != id);
    let result = store(&list);
    if result.is_ok() {
        release_watch(id);
    }
    result
}

/// A shell's sink for drops that settled. Called from the watcher thread,
/// once per drop; the shell then runs [`ship`] as it would a send.
#[uniffi::export(with_foreign)]
pub trait WatchListener: Send + Sync {
    fn ready(&self, watch_id: String, path: String, admission: Arc<WatchAdmission>);
}

/// A watch drop's native send permit. Shells keep this opaque object while
/// handing a callback to their UI thread; dropping it releases the permit.
#[derive(uniffi::Object)]
pub struct WatchAdmission {
    flight: Mutex<Option<Flight>>,
    key: (String, String),
}

impl WatchAdmission {
    pub(crate) fn take(&self, watch_id: &str, path: &str) -> Result<Flight> {
        let flight = self
            .flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or_else(|| Error::AlreadyShipping {
                path: path.to_owned(),
            })?;
        if self.key.0 != watch_id || self.key.1 != path || flight.0 != path {
            pending_remove(&self.key);
            drop(flight);
            return Err(Error::Other("watch admission path changed".to_owned()));
        }
        pending_remove(&self.key);
        Ok(flight)
    }

    fn release(&self) {
        let flight = self
            .flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if flight.is_some() {
            pending_remove(&self.key);
            #[cfg(test)]
            wait_before_admission_flight_drop();
            drop(flight);
        }
    }
}

impl Drop for WatchAdmission {
    fn drop(&mut self) {
        self.release();
    }
}

/// The running watcher. `stop` ends the scan at its next poll, and so does
/// dropping the last handle: the thread holds only a weak reference.
#[derive(Debug, Default, uniffi::Object)]
pub struct Watcher {
    stopped: AtomicBool,
}

#[uniffi::export]
impl Watcher {
    /// Stops the scan at its next poll.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }
}

/// Where one top-level entry of a watched folder stands.
struct Seen {
    fingerprint: (u64, u64, Option<SystemTime>),
    since: Instant,
    handed: bool,
}

/// Starts scanning every watched folder on its own thread with the default
/// settle window. The list is re-read on every poll, so a watch added or
/// removed while it runs takes effect.
#[uniffi::export]
pub fn watch_all(listener: Arc<dyn WatchListener>) -> Arc<Watcher> {
    watch_with(SETTLE, POLL, listener)
}

/// [`watch_all`] with its timings named, for a test.
pub fn watch_with(
    settle: Duration,
    poll: Duration,
    listener: Arc<dyn WatchListener>,
) -> Arc<Watcher> {
    let watcher = Arc::new(Watcher::default());
    let handle = Arc::downgrade(&watcher);
    std::thread::Builder::new()
        .name("votport watch".to_owned())
        .spawn(move || {
            let mut seen: HashMap<(String, PathBuf), Seen> = HashMap::new();
            loop {
                match handle.upgrade() {
                    Some(watcher) if !watcher.stopped.load(Ordering::Acquire) => {}
                    _ => return,
                }
                let now = Instant::now();
                let wall = SystemTime::now();
                let list = load();
                seen.retain(|(id, _), _| list.iter().any(|w| &w.id == id));
                for watch in &list {
                    scan(watch, settle, now, wall, &mut seen, listener.as_ref());
                }
                std::thread::sleep(poll);
            }
        })
        .expect("spawn the watch thread");
    watcher
}

/// Whether a drop whose fingerprint has held still for `held` settles: the
/// fingerprint must be unchanged for the window and its newest change must
/// be at least the window old, so a writer that stalls mid-drop longer
/// than the window cannot have a half-written drop shipped under it. A
/// newest change in the future (clock skew, NFS) counts as aged, and a
/// drop whose newest change cannot be read is not held by the age rule.
fn settled(held: Duration, newest: Option<SystemTime>, now: SystemTime, window: Duration) -> bool {
    held >= window
        && newest.is_none_or(|newest| match now.duration_since(newest) {
            // A newest change in the future counts as aged.
            Err(_) => true,
            Ok(age) => age >= window,
        })
}

/// One pass over one watched folder.
fn scan(
    watch: &Stored,
    settle: Duration,
    now: Instant,
    wall: SystemTime,
    seen: &mut HashMap<(String, PathBuf), Seen>,
    listener: &dyn WatchListener,
) {
    let Ok(entries) = std::fs::read_dir(&watch.dir) else {
        return;
    };
    let mut present = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == SHIPPED {
            continue;
        }
        let path = entry.path();
        present.push(path.clone());
        // Gone between the listing and the stat: the next poll settles it.
        // Anything else keeps its state, so a handed drop is not handed
        // twice because a file was replaced while the walk ran.
        let Some(fingerprint) = fingerprint(&path) else {
            continue;
        };
        // An empty folder is a drop still being assembled, never a send.
        if fingerprint.0 == 0 {
            continue;
        }
        let key = (watch.id.clone(), path.clone());
        let state = seen.entry(key).or_insert(Seen {
            fingerprint,
            since: now,
            handed: false,
        });
        if state.fingerprint != fingerprint {
            state.fingerprint = fingerprint;
            state.since = now;
            state.handed = false;
            continue;
        }
        if !state.handed && settled(now.duration_since(state.since), fingerprint.2, wall, settle) {
            let path = path.to_string_lossy().into_owned();
            let Some(admission) = try_admit(&watch.id, &path) else {
                continue;
            };
            state.handed = true;
            listener.ready(watch.id.clone(), path, admission);
        }
    }
    seen.retain(|(id, path), _| id != &watch.id || present.contains(path));
}

/// Entry count, total bytes, and newest modification under `path`, or
/// `None` when `path` itself is gone. A file or subfolder inside that
/// cannot be read counts as one entry, so the drop still settles and the
/// send says what is wrong rather than the watcher staying silent. Symlinks
/// are skipped before metadata traversal.
fn fingerprint(path: &Path) -> Option<(u64, u64, Option<SystemTime>)> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let mut count = 0;
    let mut bytes = 0;
    let mut newest = meta.modified().ok();
    if meta.is_dir() {
        let mut stack = vec![path.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                count += 1;
                continue;
            };
            for entry in entries {
                let Ok(entry) = entry else {
                    count += 1;
                    continue;
                };
                let Ok(file_type) = entry.file_type() else {
                    count += 1;
                    continue;
                };
                if file_type.is_symlink() {
                    continue;
                }
                let Ok(meta) = entry.metadata() else {
                    count += 1;
                    continue;
                };
                let modified = meta.modified().ok();
                newest = match (newest, modified) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
                if meta.is_dir() {
                    stack.push(entry.path());
                } else {
                    count += 1;
                    bytes += meta.len();
                }
            }
        }
    } else {
        count = 1;
        bytes = meta.len();
    }
    Some((count, bytes, newest))
}

/// The paths being shipped right now, so a drop that changes while its
/// send runs is not shipped twice at once.
static IN_FLIGHT: Mutex<Option<HashSet<String>>> = std::sync::Mutex::new(None);
static WATCH_IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
type PendingAdmissions = HashMap<(String, String), Weak<WatchAdmission>>;
static WATCH_PENDING: Mutex<Option<PendingAdmissions>> = Mutex::new(None);

#[cfg(test)]
struct AdmissionGate {
    arrived: std::sync::mpsc::Sender<()>,
    proceed: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
const ADMISSION_TEST_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(test)]
static ADMISSION_RECHECK_GATE: Mutex<Option<AdmissionGate>> = Mutex::new(None);
#[cfg(test)]
static ADMISSION_RELEASE_GATE: Mutex<Option<AdmissionGate>> = Mutex::new(None);

/// Holds a path in flight; dropping it releases the path.
pub(crate) struct Flight(String, bool);

impl Drop for Flight {
    fn drop(&mut self) {
        if let Some(set) = IN_FLIGHT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
        {
            set.remove(&self.0);
        }
        if self.1 {
            WATCH_IN_FLIGHT.fetch_sub(1, Ordering::Release);
        }
    }
}

/// Claims `path` for one ship.
///
/// # Errors
/// [`Error::AlreadyShipping`] when the path is already shipping; the
/// journal drops the refused send's entry, since nothing of it moved.
pub(crate) fn single_flight(path: &str) -> Result<Flight> {
    let mut guard = IN_FLIGHT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let set = guard.get_or_insert_with(std::collections::HashSet::new);
    if !set.insert(path.to_owned()) {
        return Err(Error::AlreadyShipping {
            path: path.to_owned(),
        });
    }
    Ok(Flight(path.to_owned(), false))
}

fn try_admit(watch_id: &str, path: &str) -> Option<Arc<WatchAdmission>> {
    let admission = {
        let mut guard = IN_FLIGHT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let set = guard.get_or_insert_with(HashSet::new);
        if WATCH_IN_FLIGHT.load(Ordering::Acquire) >= WATCH_CAPACITY || !set.insert(path.to_owned())
        {
            return None;
        }
        let admission = Arc::new(WatchAdmission {
            flight: Mutex::new(Some(Flight(path.to_owned(), true))),
            key: (watch_id.to_owned(), path.to_owned()),
        });
        WATCH_IN_FLIGHT.fetch_add(1, Ordering::Release);
        pending_insert(&admission);
        admission
    };
    #[cfg(test)]
    wait_before_admission_recheck();
    if load().iter().any(|stored| stored.id == watch_id) {
        Some(admission)
    } else {
        admission.release();
        None
    }
}

#[cfg(test)]
fn wait_before_admission_recheck() {
    let gate = ADMISSION_RECHECK_GATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(gate) = gate {
        gate.arrived
            .send(())
            .expect("admission recheck test is alive");
        gate.proceed
            .recv_timeout(ADMISSION_TEST_TIMEOUT)
            .expect("admission recheck test released the hook");
    }
}

#[cfg(test)]
fn wait_before_admission_flight_drop() {
    let gate = ADMISSION_RELEASE_GATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    if let Some(gate) = gate {
        gate.arrived
            .send(())
            .expect("admission release test is alive");
        gate.proceed
            .recv_timeout(ADMISSION_TEST_TIMEOUT)
            .expect("admission release test released the hook");
    }
}

fn pending_insert(admission: &Arc<WatchAdmission>) {
    WATCH_PENDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(admission.key.clone(), Arc::downgrade(admission));
}

fn pending_remove(key: &(String, String)) {
    if let Some(pending) = WATCH_PENDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_mut()
    {
        pending.remove(key);
    }
}

fn release_watch(watch_id: &str) {
    let admissions = {
        let mut guard = WATCH_PENDING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(pending) = guard.as_mut() else {
            return;
        };
        let mut admissions = Vec::new();
        pending.retain(|(id, _), weak| {
            if id == watch_id {
                if let Some(admission) = weak.upgrade() {
                    admissions.push(admission);
                }
                false
            } else {
                weak.strong_count() != 0
            }
        });
        admissions
    };
    for admission in admissions {
        admission.release();
    }
}

/// Whether `path` sits at the top of a watched folder, as a watch drop
/// does: a resumed send of such a path parks it the way [`ship`] does,
/// so the next watch run does not ship what the run delivered.
pub(crate) fn is_watched_drop(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let dir = parent.to_string_lossy().into_owned();
    load().iter().any(|stored| stored.dir == dir)
}

/// The link and password of a watch, for the send.
pub(crate) fn credentials(watch_id: &str) -> Result<(String, Option<String>)> {
    load()
        .into_iter()
        .find(|stored| stored.id == watch_id)
        .map(|stored| (stored.link, stored.password))
        .ok_or_else(|| Error::UnknownTransfer {
            id: watch_id.to_owned(),
        })
}

/// Moves a shipped drop into the folder's `shipped` subfolder, keeping its
/// name; a taken name gets a timestamp, a taken timestamp a counter.
///
/// # Errors
/// A rename failure (the drop stays where it is).
pub(crate) fn park(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Other("no parent".to_owned()))?;
    let shipped = parent.join(SHIPPED);
    std::fs::create_dir_all(&shipped)?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::Other("no name".to_owned()))?
        .to_os_string();
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut target = shipped.join(&name);
    let mut attempt = 0u32;
    while target.exists() {
        attempt += 1;
        let mut stamped = name.clone();
        stamped.push(if attempt == 1 {
            format!(".{stamp}")
        } else {
            format!(".{stamp}-{attempt}")
        });
        target = shipped.join(stamped);
    }
    std::fs::rename(path, &target)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Mutex};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_state() -> (tempfile::TempDir, crate::identity::TestState) {
        let state = tempfile::tempdir().unwrap();
        let scope = crate::identity::test_state_dir(state.path());
        (state, scope)
    }

    /// A wall clock behind the real one, so every drop a test writes is
    /// already aged past `window` and only the hold timing is exercised.
    fn aged_wall(window: Duration) -> SystemTime {
        SystemTime::now() - window * 3
    }

    struct Collect(Mutex<Vec<(String, String)>>);

    impl WatchListener for Collect {
        fn ready(&self, watch_id: String, path: String, _admission: Arc<WatchAdmission>) {
            self.0.lock().unwrap().push((watch_id, path));
        }
    }

    struct Holding {
        calls: Mutex<Vec<String>>,
        admissions: Mutex<Vec<Arc<WatchAdmission>>>,
    }

    impl WatchListener for Holding {
        fn ready(&self, _watch_id: String, path: String, admission: Arc<WatchAdmission>) {
            self.calls.lock().unwrap().push(path);
            self.admissions.lock().unwrap().push(admission);
        }
    }

    #[test]
    fn watch_admission_stays_bounded_until_each_callback_releases_it() {
        let _test_lock = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let watch = watch_in(dir.path());
        let (_state, _state_scope) = test_state();
        store(std::slice::from_ref(&watch)).unwrap();
        let listener = Arc::new(Holding {
            calls: Mutex::new(Vec::new()),
            admissions: Mutex::new(Vec::new()),
        });
        let mut seen = HashMap::new();
        let settle = Duration::from_millis(10);
        for name in ["a", "b", "c"] {
            std::fs::write(dir.path().join(name), name).unwrap();
        }
        let t0 = Instant::now();
        let wall = aged_wall(settle);
        scan(&watch, settle, t0, wall, &mut seen, listener.as_ref());
        scan(
            &watch,
            settle,
            t0 + settle,
            wall,
            &mut seen,
            listener.as_ref(),
        );
        assert_eq!(listener.calls.lock().unwrap().len(), WATCH_CAPACITY);
        assert_eq!(listener.admissions.lock().unwrap().len(), WATCH_CAPACITY);

        // Additional polls leave the other settled drops unhanded while the
        // callback's queued send still owns the only native slot.
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(1),
            wall,
            &mut seen,
            listener.as_ref(),
        );
        assert_eq!(listener.calls.lock().unwrap().len(), WATCH_CAPACITY);

        listener.admissions.lock().unwrap().clear();
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(2),
            wall,
            &mut seen,
            listener.as_ref(),
        );
        assert_eq!(listener.calls.lock().unwrap().len(), 2);
        listener.admissions.lock().unwrap().clear();
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(3),
            wall,
            &mut seen,
            listener.as_ref(),
        );
        let calls = listener.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls.iter().collect::<HashSet<_>>().len(), calls.len());
        listener.admissions.lock().unwrap().clear();
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(4),
            wall,
            &mut seen,
            listener.as_ref(),
        );
        assert_eq!(listener.calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn removing_a_watch_releases_queued_admission() {
        let _test_lock = TEST_LOCK.lock().unwrap();
        let (_state, _state_scope) = test_state();
        let folder = tempfile::tempdir().unwrap();
        let watch = watch_in(folder.path());
        store(std::slice::from_ref(&watch)).unwrap();
        let admission = try_admit(&watch.id, "/tmp/watch-admission").unwrap();
        release_watch(&watch.id);
        assert!(admission.take(&watch.id, "/tmp/watch-admission").is_err());
        drop(admission);
    }

    #[test]
    fn an_old_consumed_admission_cannot_remove_a_new_registration() {
        let _test_lock = TEST_LOCK.lock().unwrap();
        let (_state, _state_scope) = test_state();
        let folder = tempfile::tempdir().unwrap();
        let watch = watch_in(folder.path());
        store(std::slice::from_ref(&watch)).unwrap();
        let path = "/tmp/watch-admission-same-key";
        let old = try_admit(&watch.id, path).unwrap();
        drop(old.take(&watch.id, path).unwrap());
        let current = try_admit(&watch.id, path).unwrap();
        drop(old);
        release_watch(&watch.id);
        assert!(current.take(&watch.id, path).is_err());
        assert_eq!(WATCH_IN_FLIGHT.load(Ordering::Acquire), 0);
        drop(current);
    }

    #[test]
    fn an_owned_release_unregisters_before_freeing_capacity() {
        let _test_lock = TEST_LOCK.lock().unwrap();
        let (_state, _state_scope) = test_state();
        let folder = tempfile::tempdir().unwrap();
        let watch = watch_in(folder.path());
        store(std::slice::from_ref(&watch)).unwrap();
        let path = "/tmp/watch-admission-release-order";
        let current = try_admit(&watch.id, path).unwrap();
        let (arrived_tx, arrived_rx) = mpsc::channel();
        let (proceed_tx, proceed_rx) = mpsc::channel();
        *ADMISSION_RELEASE_GATE.lock().unwrap() = Some(AdmissionGate {
            arrived: arrived_tx,
            proceed: proceed_rx,
        });
        let release = current.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            release.release();
            done_tx.send(()).unwrap();
        });
        arrived_rx
            .recv_timeout(ADMISSION_TEST_TIMEOUT)
            .expect("admission release hook arrived");
        let successor = try_admit(&watch.id, path);
        proceed_tx.send(()).unwrap();
        done_rx
            .recv_timeout(ADMISSION_TEST_TIMEOUT)
            .expect("admission release completed");
        thread.join().unwrap();
        assert!(successor.is_none());
        let next = try_admit(&watch.id, path).unwrap();
        release_watch(&watch.id);
        assert!(next.take(&watch.id, path).is_err());
        assert_eq!(WATCH_IN_FLIGHT.load(Ordering::Acquire), 0);
        drop(current);
    }

    #[test]
    fn an_admission_rechecks_a_watch_after_registration() {
        let _test_lock = TEST_LOCK.lock().unwrap();
        let (_state, _state_scope) = test_state();
        let folder = tempfile::tempdir().unwrap();
        let watch = watch_in(folder.path());
        store(std::slice::from_ref(&watch)).unwrap();

        let (registered_tx, registered_rx) = mpsc::channel();
        let (proceed_tx, proceed_rx) = mpsc::channel();
        *ADMISSION_RECHECK_GATE.lock().unwrap() = Some(AdmissionGate {
            arrived: registered_tx,
            proceed: proceed_rx,
        });
        let id = watch.id.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = try_admit(&id, "/tmp/watch-admission-race");
            done_tx.send(result.is_none()).unwrap();
            result
        });
        registered_rx
            .recv_timeout(ADMISSION_TEST_TIMEOUT)
            .expect("admission recheck hook arrived");
        remove_watch(&watch.id).unwrap();
        proceed_tx.send(()).unwrap();
        assert!(done_rx.recv_timeout(ADMISSION_TEST_TIMEOUT).unwrap());
        assert!(thread.join().unwrap().is_none());
        assert_eq!(WATCH_IN_FLIGHT.load(Ordering::Acquire), 0);
        assert!(IN_FLIGHT
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(HashSet::is_empty));
    }

    #[test]
    fn a_drop_is_handed_over_once_it_holds_still_and_again_if_it_changes() {
        let _test_lock = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let watch = Stored {
            id: "w".to_owned(),
            dir: dir.path().to_string_lossy().into_owned(),
            link: "https://d/r/t".to_owned(),
            password: None,
        };
        let (_state, _state_scope) = test_state();
        store(std::slice::from_ref(&watch)).unwrap();
        let seen_list = Arc::new(Collect(Mutex::new(Vec::new())));
        let mut seen = HashMap::new();
        let settle = Duration::from_millis(50);
        std::fs::write(dir.path().join("a.bin"), b"12345").unwrap();
        std::fs::write(dir.path().join(".hidden"), b"x").unwrap();
        std::fs::create_dir(dir.path().join(SHIPPED)).unwrap();
        let t0 = Instant::now();
        let wall = aged_wall(settle);
        scan(&watch, settle, t0, wall, &mut seen, seen_list.as_ref());
        assert!(seen_list.0.lock().unwrap().is_empty(), "not yet settled");
        // Grows before the window: the clock restarts.
        std::fs::write(dir.path().join("a.bin"), b"1234567").unwrap();
        scan(
            &watch,
            settle,
            t0 + Duration::from_millis(40),
            wall,
            &mut seen,
            seen_list.as_ref(),
        );
        scan(
            &watch,
            settle,
            t0 + Duration::from_millis(80),
            wall,
            &mut seen,
            seen_list.as_ref(),
        );
        assert!(seen_list.0.lock().unwrap().is_empty(), "restarted at 40 ms");
        scan(
            &watch,
            settle,
            t0 + Duration::from_millis(95),
            wall,
            &mut seen,
            seen_list.as_ref(),
        );
        let handed = seen_list.0.lock().unwrap().clone();
        assert_eq!(handed.len(), 1);
        assert!(handed[0].1.ends_with("a.bin"));
        // Held still longer: not handed again.
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(5),
            wall,
            &mut seen,
            seen_list.as_ref(),
        );
        assert_eq!(seen_list.0.lock().unwrap().len(), 1);
        // Parked into shipped/, then forgotten; a same-named new drop is new.
        let parked = park(&dir.path().join("a.bin")).unwrap();
        assert_eq!(parked, dir.path().join(SHIPPED).join("a.bin"));
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(6),
            wall,
            &mut seen,
            seen_list.as_ref(),
        );
        assert!(seen.is_empty());
        std::fs::write(dir.path().join("a.bin"), b"new").unwrap();
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(7),
            wall,
            &mut seen,
            seen_list.as_ref(),
        );
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(8),
            wall,
            &mut seen,
            seen_list.as_ref(),
        );
        assert_eq!(seen_list.0.lock().unwrap().len(), 2);
        let parked_again = park(&dir.path().join("a.bin")).unwrap();
        assert_ne!(parked_again, parked, "a taken name gets a stamp");
        std::fs::write(dir.path().join("a.bin"), b"third").unwrap();
        let parked_third = park(&dir.path().join("a.bin")).unwrap();
        assert!(
            parked_third != parked && parked_third != parked_again,
            "a taken stamp gets a counter"
        );
        assert!(
            dir.path().join(".hidden").is_file(),
            "dotfiles are never handed"
        );
        assert!(!dir.path().join(SHIPPED).join(".hidden").exists());
    }

    /// A drop settles only when its fingerprint has held still for the
    /// window and its newest change is itself at least the window old.
    #[test]
    fn settling_needs_both_a_held_fingerprint_and_an_aged_newest_change() {
        let window = Duration::from_secs(10);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let aged = now - window;
        let fresh = now - Duration::from_secs(1);
        let future = now + Duration::from_secs(60);
        // A fingerprint that holds still is not enough: while its newest
        // change is fresh, a stalled writer keeps the drop unsettled.
        assert!(!settled(window, Some(fresh), now, window));
        assert!(!settled(window * 100, Some(fresh), now, window));
        assert!(!settled(Duration::ZERO, Some(aged), now, window));
        // Held for the window and aged for the window settles.
        assert!(settled(window, Some(aged), now, window));
        // A newest change in the future counts as aged, but it never
        // skips the hold.
        assert!(settled(window, Some(future), now, window));
        assert!(!settled(Duration::ZERO, Some(future), now, window));
        // A drop whose newest change cannot be read is not held by the
        // age rule.
        assert!(settled(window, None, now, window));
    }

    /// A stalled writer: the fingerprint holds still well past the window,
    /// but the drop stays unsettled while its newest change is fresh, hands
    /// over once that change ages past the window, and a future change
    /// counts as aged.
    #[test]
    fn a_fresh_newest_change_blocks_settling_until_it_ages() {
        let _test_lock = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let watch = watch_in(dir.path());
        let (_state, _state_scope) = test_state();
        store(std::slice::from_ref(&watch)).unwrap();
        let handed = Arc::new(Collect(Mutex::new(Vec::new())));
        let mut seen = HashMap::new();
        let settle = Duration::from_millis(50);
        std::fs::write(dir.path().join("a.bin"), b"12345").unwrap();
        let newest = fingerprint(&dir.path().join("a.bin")).unwrap().2.unwrap();
        let t0 = Instant::now();
        scan(
            &watch,
            settle,
            t0,
            newest + settle / 2,
            &mut seen,
            handed.as_ref(),
        );
        scan(
            &watch,
            settle,
            t0 + settle * 10,
            newest + settle / 2,
            &mut seen,
            handed.as_ref(),
        );
        assert!(
            handed.0.lock().unwrap().is_empty(),
            "a fresh newest change holds the drop"
        );
        scan(
            &watch,
            settle,
            t0 + settle * 10,
            newest + settle,
            &mut seen,
            handed.as_ref(),
        );
        assert_eq!(handed.0.lock().unwrap().len(), 1);
        // A newest change in the future (clock skew) counts as aged.
        std::fs::write(dir.path().join("b.bin"), b"1").unwrap();
        let next = fingerprint(&dir.path().join("b.bin")).unwrap().2.unwrap();
        scan(
            &watch,
            settle,
            t0 + settle * 11,
            next - settle * 2,
            &mut seen,
            handed.as_ref(),
        );
        scan(
            &watch,
            settle,
            t0 + settle * 12,
            next - settle * 2,
            &mut seen,
            handed.as_ref(),
        );
        assert_eq!(handed.0.lock().unwrap().len(), 2);
    }

    /// The live confirmation of the settle defect: two 1 MiB appends
    /// 15 s apart let the previous 10 s window settle the first half while
    /// the writer was still pausing, and the drop shipped twice. The hold
    /// and age rules can only cover a pause the window outlasts, so the
    /// window must stay past the live-confirmed one.
    #[test]
    fn the_settle_window_outlasts_the_live_confirmed_append_pause() {
        let pause = Duration::from_secs(15);
        assert!(
            SETTLE > pause,
            "a {pause:?} pause between appends must not settle as a finished drop"
        );
    }

    fn watch_in(dir: &Path) -> Stored {
        Stored {
            id: "w".to_owned(),
            dir: dir.to_string_lossy().into_owned(),
            link: "https://d/r/t".to_owned(),
            password: None,
        }
    }

    #[test]
    fn a_folder_with_only_hidden_metadata_is_handed_for_an_empty_send() {
        let _test_lock = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let watch = watch_in(dir.path());
        let (_state, _state_scope) = test_state();
        store(std::slice::from_ref(&watch)).unwrap();
        let handed = Arc::new(Collect(Mutex::new(Vec::new())));
        let mut seen = HashMap::new();
        let settle = Duration::from_millis(10);
        std::fs::create_dir(dir.path().join("seq")).unwrap();
        let empty_at = Instant::now();
        let wall = aged_wall(settle);
        scan(&watch, settle, empty_at, wall, &mut seen, handed.as_ref());
        scan(
            &watch,
            settle,
            empty_at + settle,
            wall,
            &mut seen,
            handed.as_ref(),
        );
        assert!(handed.0.lock().unwrap().is_empty());
        std::fs::write(dir.path().join("seq/.DS_Store"), b"metadata").unwrap();
        let t0 = Instant::now();
        let wall = aged_wall(settle);
        scan(&watch, settle, t0, wall, &mut seen, handed.as_ref());
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(1),
            wall,
            &mut seen,
            handed.as_ref(),
        );
        assert_eq!(handed.0.lock().unwrap().len(), 1);
        std::fs::write(dir.path().join("seq/a"), b"1").unwrap();
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(2),
            wall,
            &mut seen,
            handed.as_ref(),
        );
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(3),
            wall,
            &mut seen,
            handed.as_ref(),
        );
        assert_eq!(handed.0.lock().unwrap().len(), 2);
    }

    /// An unreadable subfolder counts as one entry, so the drop changes,
    /// settles again, and is handed over for the send to report it.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_subfolder_still_settles_and_is_handed_over() {
        let _test_lock = TEST_LOCK.lock().unwrap();
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let watch = watch_in(dir.path());
        let (_state, _state_scope) = test_state();
        store(std::slice::from_ref(&watch)).unwrap();
        let handed = Arc::new(Collect(Mutex::new(Vec::new())));
        let mut seen = HashMap::new();
        let settle = Duration::from_millis(10);
        let drop = dir.path().join("seq");
        std::fs::create_dir_all(drop.join("inner")).unwrap();
        std::fs::write(drop.join("inner/a"), b"12").unwrap();
        let t0 = Instant::now();
        let wall = aged_wall(settle);
        scan(&watch, settle, t0, wall, &mut seen, handed.as_ref());
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(1),
            wall,
            &mut seen,
            handed.as_ref(),
        );
        assert_eq!(handed.0.lock().unwrap().len(), 1);
        std::fs::set_permissions(drop.join("inner"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        // Root reads anything; the case cannot be made there.
        let unreadable = std::fs::read_dir(drop.join("inner")).is_err();
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(2),
            wall,
            &mut seen,
            handed.as_ref(),
        );
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(3),
            wall,
            &mut seen,
            handed.as_ref(),
        );
        std::fs::set_permissions(drop.join("inner"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        if unreadable {
            assert_eq!(
                handed.0.lock().unwrap().len(),
                2,
                "handed again for the send to say why"
            );
        }
    }

    #[test]
    fn a_folder_fingerprint_covers_its_files() {
        let _test_lock = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let drop = dir.path().join("seq");
        std::fs::create_dir_all(drop.join("sub")).unwrap();
        std::fs::write(drop.join("a"), b"12").unwrap();
        std::fs::write(drop.join("sub/b"), b"345").unwrap();
        let (count, bytes, newest) = fingerprint(&drop).unwrap();
        assert_eq!((count, bytes), (2, 5));
        assert!(newest.is_some());
        assert_eq!(fingerprint(&dir.path().join("missing")), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_fingerprint_covers_hidden_and_skips_symlinked_descendants() {
        let _test_lock = TEST_LOCK.lock().unwrap();
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let drop = root.path().join("drop");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(drop.join("nested")).unwrap();
        std::fs::write(drop.join("visible"), b"12").unwrap();
        std::fs::write(drop.join("nested/file"), b"345").unwrap();
        std::fs::write(drop.join(".DS_Store"), b"ignored").unwrap();
        std::fs::create_dir(drop.join(".cache")).unwrap();
        std::fs::write(drop.join(".cache/file"), b"ignored").unwrap();
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, drop.join("outside")).unwrap();
        symlink(&drop, drop.join("cycle")).unwrap();

        let (count, bytes, newest) = fingerprint(&drop).unwrap();
        assert_eq!((count, bytes), (4, 19));
        assert!(newest.is_some());
    }
}
