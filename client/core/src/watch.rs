//! Watch folders: a folder whose settled drops ship to a request link
//! without anyone at the keyboard.
//!
//! The list of watches lives in `watches.json` under the state directory,
//! owner-only, so the apps and `votport watch` share one list. A watcher
//! thread scans each folder every [`POLL`]: a top-level file or folder whose
//! fingerprint (entry count, total bytes, newest change) has not moved for
//! [`SETTLE`] is handed to the listener once, as one drop; the caller ships
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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::api::{split_link_as, LinkKind};
use crate::error::{Error, Result};
use crate::identity::{state_dir, write_private};

const FILE: &str = "watches.json";
/// The subfolder a shipped drop is moved into.
pub const SHIPPED: &str = "shipped";
/// How long a drop must hold still before it ships.
pub const SETTLE: Duration = Duration::from_secs(10);
/// How often a watched folder is scanned.
pub const POLL: Duration = Duration::from_secs(2);

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
    Ok(Watch::from(&stored))
}

/// Removes a watch. Nothing in the folder changes.
///
/// # Errors
/// A write failure.
pub fn remove_watch(id: &str) -> Result<()> {
    let mut list = load();
    list.retain(|stored| stored.id != id);
    store(&list)
}

/// A shell's sink for drops that settled. Called from the watcher thread,
/// once per drop; the shell then runs [`ship`] as it would a send.
#[uniffi::export(with_foreign)]
pub trait WatchListener: Send + Sync {
    fn ready(&self, watch_id: String, path: String);
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
                let list = load();
                seen.retain(|(id, _), _| list.iter().any(|w| &w.id == id));
                for watch in &list {
                    scan(watch, settle, now, &mut seen, listener.as_ref());
                }
                std::thread::sleep(poll);
            }
        })
        .expect("spawn the watch thread");
    watcher
}

/// One pass over one watched folder.
fn scan(
    watch: &Stored,
    settle: Duration,
    now: Instant,
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
        if !state.handed && now.duration_since(state.since) >= settle {
            state.handed = true;
            listener.ready(watch.id.clone(), path.to_string_lossy().into_owned());
        }
    }
    seen.retain(|(id, path), _| id != &watch.id || present.contains(path));
}

/// Entry count, total bytes, and newest modification under `path`, or
/// `None` when `path` itself is gone. A file or subfolder inside that
/// cannot be read counts as one entry, so the drop still settles and the
/// send says what is wrong rather than the watcher staying silent.
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
static IN_FLIGHT: std::sync::Mutex<Option<std::collections::HashSet<String>>> =
    std::sync::Mutex::new(None);

/// Holds a path in flight; dropping it releases the path.
pub(crate) struct Flight(String);

impl Drop for Flight {
    fn drop(&mut self) {
        if let Some(set) = IN_FLIGHT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_mut()
        {
            set.remove(&self.0);
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
    Ok(Flight(path.to_owned()))
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
    use std::sync::Mutex;

    struct Collect(Mutex<Vec<(String, String)>>);

    impl WatchListener for Collect {
        fn ready(&self, watch_id: String, path: String) {
            self.0.lock().unwrap().push((watch_id, path));
        }
    }

    #[test]
    fn a_drop_is_handed_over_once_it_holds_still_and_again_if_it_changes() {
        let dir = tempfile::tempdir().unwrap();
        let watch = Stored {
            id: "w".to_owned(),
            dir: dir.path().to_string_lossy().into_owned(),
            link: "https://d/r/t".to_owned(),
            password: None,
        };
        let seen_list = Arc::new(Collect(Mutex::new(Vec::new())));
        let mut seen = HashMap::new();
        let settle = Duration::from_millis(50);
        std::fs::write(dir.path().join("a.bin"), b"12345").unwrap();
        std::fs::write(dir.path().join(".hidden"), b"x").unwrap();
        std::fs::create_dir(dir.path().join(SHIPPED)).unwrap();
        let t0 = Instant::now();
        scan(&watch, settle, t0, &mut seen, seen_list.as_ref());
        assert!(seen_list.0.lock().unwrap().is_empty(), "not yet settled");
        // Grows before the window: the clock restarts.
        std::fs::write(dir.path().join("a.bin"), b"1234567").unwrap();
        scan(
            &watch,
            settle,
            t0 + Duration::from_millis(40),
            &mut seen,
            seen_list.as_ref(),
        );
        scan(
            &watch,
            settle,
            t0 + Duration::from_millis(80),
            &mut seen,
            seen_list.as_ref(),
        );
        assert!(seen_list.0.lock().unwrap().is_empty(), "restarted at 40 ms");
        scan(
            &watch,
            settle,
            t0 + Duration::from_millis(95),
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
            &mut seen,
            seen_list.as_ref(),
        );
        assert!(seen.is_empty());
        std::fs::write(dir.path().join("a.bin"), b"new").unwrap();
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(7),
            &mut seen,
            seen_list.as_ref(),
        );
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(8),
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

    fn watch_in(dir: &Path) -> Stored {
        Stored {
            id: "w".to_owned(),
            dir: dir.to_string_lossy().into_owned(),
            link: "https://d/r/t".to_owned(),
            password: None,
        }
    }

    #[test]
    fn an_empty_folder_never_ships() {
        let dir = tempfile::tempdir().unwrap();
        let watch = watch_in(dir.path());
        let handed = Arc::new(Collect(Mutex::new(Vec::new())));
        let mut seen = HashMap::new();
        let settle = Duration::from_millis(10);
        std::fs::create_dir(dir.path().join("seq")).unwrap();
        let t0 = Instant::now();
        scan(&watch, settle, t0, &mut seen, handed.as_ref());
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(1),
            &mut seen,
            handed.as_ref(),
        );
        assert!(
            handed.0.lock().unwrap().is_empty(),
            "an empty folder is not a drop"
        );
        std::fs::write(dir.path().join("seq/a"), b"1").unwrap();
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(2),
            &mut seen,
            handed.as_ref(),
        );
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(3),
            &mut seen,
            handed.as_ref(),
        );
        assert_eq!(handed.0.lock().unwrap().len(), 1);
    }

    /// An unreadable subfolder counts as one entry, so the drop changes,
    /// settles again, and is handed over for the send to report it.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_subfolder_still_settles_and_is_handed_over() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let watch = watch_in(dir.path());
        let handed = Arc::new(Collect(Mutex::new(Vec::new())));
        let mut seen = HashMap::new();
        let settle = Duration::from_millis(10);
        let drop = dir.path().join("seq");
        std::fs::create_dir_all(drop.join("inner")).unwrap();
        std::fs::write(drop.join("inner/a"), b"12").unwrap();
        let t0 = Instant::now();
        scan(&watch, settle, t0, &mut seen, handed.as_ref());
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(1),
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
            &mut seen,
            handed.as_ref(),
        );
        scan(
            &watch,
            settle,
            t0 + Duration::from_secs(3),
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
}
