//! The transfer journal: one small file per transfer under the state
//! directory, written when a transfer starts and removed when it ends well,
//! so a transfer that was cut by a quit, a crash, or a failure is still there
//! at the next launch for a shell to offer again. It holds what is needed to
//! start the transfer over (the link, the paths or the destination), plus a
//! resumable HTTP session when one has reached its manifest boundary, and
//! never the password.
//!
//! ponytail: a directory of JSON files, not SQLite; one file per transfer is
//! the whole schema, and a pre-release app has no migrations to carry.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// How long a journalled entry is kept for its retry. Past this a transfer
/// was never offered again (or its offer was refused) and the entry is
/// abandoned: the journal is swept at the next listing rather than growing
/// forever on sends that failed retryably and were never resumed.
const RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

use crate::error::{Error, Result};
use crate::identity::state_dir;

/// One journalled transfer. Crosses the FFI as is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct Entry {
    pub id: String,
    pub kind: Kind,
    /// The request or delivery link, as pasted.
    pub link: String,
    /// The dropped paths of a send, empty for a receive.
    #[serde(default)]
    pub paths: Vec<String>,
    /// The destination folder of a receive.
    #[serde(default)]
    pub dest: Option<String>,
    /// Whether the transfer was started with a password, which the journal
    /// does not keep, so a resume must ask for it again.
    #[serde(default)]
    pub needs_password: bool,
    /// The HTTP upload session that a paused or retryable send can resume.
    /// Older journal entries have no session and start a fresh send.
    #[serde(default)]
    pub http: Option<HttpResume>,
    /// Seconds since the Unix epoch when the transfer started.
    pub started_unix: u64,
}

/// The server identity and package authority for a resumable HTTP send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct HttpResume {
    pub session: String,
    pub chunk_bytes: u64,
    pub root: String,
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Send,
    Receive,
}

/// Where the journal lives: `<state dir>/journal`.
#[must_use]
pub fn dir() -> PathBuf {
    state_dir().join("journal")
}

fn path_of(dir: &std::path::Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// A fresh id: the start time and 64 random bits, so two transfers started
/// in the same second never share a file.
pub(crate) fn fresh_id(started_unix: u64) -> String {
    let random: u64 = rand::random();
    format!("{started_unix}-{random:016x}")
}

/// Records a transfer that is starting and returns its entry. Paths are made
/// absolute, so a resume from another working directory names the same
/// files. A journal that cannot be written does not stop the transfer: the
/// caller gets the entry anyway and only the resume is lost.
#[must_use]
pub fn record(
    kind: Kind,
    link: &str,
    paths: Vec<String>,
    dest: Option<String>,
    needs_password: bool,
) -> Entry {
    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    let entry = Entry {
        id: fresh_id(started_unix),
        kind,
        link: link.to_owned(),
        paths: paths.into_iter().map(|path| absolute(&path)).collect(),
        dest: dest.map(|dest| absolute(&dest)),
        needs_password,
        http: None,
        started_unix,
    };
    let _ = write_in(&dir(), &entry);
    entry
}

/// `path` made absolute against the working directory, without touching the
/// filesystem; a path that cannot be resolved is kept as given.
pub(crate) fn absolute(path: &str) -> String {
    std::path::absolute(path)
        .map(|abs| abs.display().to_string())
        .unwrap_or_else(|_| path.to_owned())
}

/// Marks an entry as needing a password, learned from a run that failed for
/// the lack of one, so the next offer asks up front.
pub fn mark_needs_password(id: &str) {
    let dir = dir();
    if let Ok(mut entry) = get_in(&dir, id) {
        entry.needs_password = true;
        let _ = write_in(&dir, &entry);
    }
}

/// Records the server session after its first successful `begin`. Unlike the
/// initial journal write, this boundary is required for a resumable send, so
/// a write failure is returned to the caller.
pub fn mark_http(id: &str, http: HttpResume) -> Result<()> {
    let dir = dir();
    let mut entry = get_in(&dir, id)?;
    entry.http = Some(http);
    write_in(&dir, &entry)
}

/// Points a journalled receive's next run at `dest`, already absolute: a
/// retry that re-asks for the folder records the answer, so the card, a
/// later offer, and the run itself agree on where it lands. Best effort like
/// [`mark_needs_password`]: a write that fails only means the next offer
/// suggests the old folder.
pub fn set_dest(id: &str, dest: &str) {
    set_dest_in(&dir(), id, dest);
}

fn set_dest_in(dir: &std::path::Path, id: &str, dest: &str) {
    if let Ok(mut entry) = get_in(dir, id) {
        entry.dest = Some(dest.to_owned());
        let _ = write_in(dir, &entry);
    }
}

/// Removes a stale HTTP session association while retaining the journalled
/// paths for an explicit retry from a fresh session.
pub fn clear_http(id: &str) -> Result<()> {
    let dir = dir();
    let mut entry = get_in(&dir, id)?;
    entry.http = None;
    write_in(&dir, &entry)
}

fn protect_directory(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn write_in(dir: &std::path::Path, entry: &Entry) -> Result<()> {
    fs::create_dir_all(dir)?;
    protect_directory(dir)?;
    let bytes = serde_json::to_vec_pretty(entry)
        .map_err(|error| Error::Other(format!("encoding a journal entry: {error}")))?;
    crate::identity::write_private(&path_of(dir, &entry.id), &bytes)
}

/// Forgets the pending send entries that name exactly `path`: a watch drop
/// shipping afresh after a cut send has nothing to resume. The callback runs
/// before each entry is removed, so an owner can release any server session
/// without racing the journal deletion.
pub(crate) fn forget_send_of(path: &str, mut before_forget: impl FnMut(&Entry)) {
    let path = absolute(path);
    for entry in pending() {
        if entry.kind == Kind::Send && entry.paths == [path.clone()] {
            before_forget(&entry);
            forget(&entry.id);
        }
    }
}

/// Removes a transfer from the journal. A missing entry is not an error.
pub fn forget(id: &str) {
    forget_in(&dir(), id);
}

fn forget_in(dir: &std::path::Path, id: &str) {
    let _ = fs::remove_file(path_of(dir, id));
}

/// The journalled transfers, oldest first. An entry that cannot be read is
/// skipped, never refused. Entries past [`RETENTION_SECS`] are abandoned:
/// dropped here and at every later listing, the same expiry an evidence
/// report meets, so entries kept for a retry that never came cannot
/// accumulate forever.
#[must_use]
pub fn pending() -> Vec<Entry> {
    pending_in(&dir())
}

fn pending_in(dir: &std::path::Path) -> Vec<Entry> {
    let Ok(read) = protect_directory(dir).and_then(|()| fs::read_dir(dir)) else {
        return Vec::new();
    };
    let mut entries: Vec<Entry> = read
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .filter_map(|path| serde_json::from_slice(&fs::read(path).ok()?).ok())
        .collect();
    entries.sort_by(|a, b| a.started_unix.cmp(&b.started_unix).then(a.id.cmp(&b.id)));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    let (current, abandoned): (Vec<_>, Vec<_>) = entries
        .into_iter()
        .partition(|entry| now.saturating_sub(entry.started_unix) <= RETENTION_SECS);
    for entry in &abandoned {
        forget_in(dir, &entry.id);
    }
    current
}

/// One journalled transfer by id.
///
/// # Errors
/// An id the journal does not hold.
pub fn get(id: &str) -> Result<Entry> {
    get_in(&dir(), id)
}

fn get_in(dir: &std::path::Path, id: &str) -> Result<Entry> {
    let bytes = protect_directory(dir)
        .and_then(|()| fs::read(path_of(dir, id)))
        .map_err(|_| Error::UnknownTransfer { id: id.to_owned() })?;
    serde_json::from_slice(&bytes).map_err(|_| Error::UnknownTransfer { id: id.to_owned() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_entry_is_pending_until_forgotten_and_a_broken_file_is_skipped() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("journal");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let first = Entry {
            id: "1-a".into(),
            kind: Kind::Receive,
            link: "https://drop.example/s/DEL".into(),
            paths: Vec::new(),
            dest: Some("/tmp/landed".into()),
            needs_password: true,
            http: None,
            started_unix: now - 10,
        };
        let second = Entry {
            id: "2-b".into(),
            kind: Kind::Send,
            link: "https://drop.example/r/REQ".into(),
            paths: vec!["/shots".into()],
            dest: None,
            needs_password: false,
            http: None,
            started_unix: now,
        };
        fs::create_dir_all(&dir).unwrap();
        let retained = serde_json::to_vec(&first).unwrap();
        fs::write(path_of(&dir, &first.id), &retained).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path_of(&dir, &first.id), fs::Permissions::from_mode(0o644))
                .unwrap();
            for lookup in ["pending", "get"] {
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
                let entries = if lookup == "pending" {
                    pending_in(&dir)
                } else {
                    vec![get_in(&dir, &first.id).unwrap()]
                };
                assert_eq!(entries, std::slice::from_ref(&first), "{lookup}");
                assert_eq!(
                    fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                    0o700,
                    "{lookup} must protect existing journal credentials"
                );
                assert_eq!(fs::read(path_of(&dir, &first.id)).unwrap(), retained);
            }
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        }
        write_in(&dir, &second).unwrap();
        write_in(&dir, &first).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for entry in [&first, &second] {
                assert_eq!(
                    fs::metadata(path_of(&dir, &entry.id))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600,
                    "journal link credentials must be private"
                );
            }
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        fs::write(dir.join("junk.json"), b"{not json").unwrap();
        fs::write(dir.join("note.txt"), b"ignored").unwrap();
        assert_eq!(pending_in(&dir), vec![first.clone(), second.clone()]);
        assert_eq!(get_in(&dir, "1-a").unwrap(), first);
        assert!(matches!(
            get_in(&dir, "nope"),
            Err(Error::UnknownTransfer { .. })
        ));
        forget_in(&dir, "1-a");
        forget_in(&dir, "never-there");
        assert_eq!(pending_in(&dir), vec![second.clone()]);
        assert!(
            !dir.read_dir().unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp")),
            "no temp file is left behind"
        );
        // A temp left by a crash mid-write is never listed as an entry.
        fs::write(dir.join("3-c.99.tmp"), serde_json::to_vec(&second).unwrap()).unwrap();
        assert_eq!(pending_in(&dir).len(), 1);
    }

    #[test]
    fn fresh_ids_differ_within_a_second() {
        assert_ne!(fresh_id(7), fresh_id(7));
        assert!(fresh_id(7).starts_with("7-"));
    }

    /// A receive re-asked for its folder journals the answer, so the next
    /// offer and the run itself follow the new folder; an id the journal
    /// does not hold is quietly ignored, as a missing entry is elsewhere.
    #[test]
    fn a_re_asked_receive_journals_the_folder_it_was_given() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("journal");
        let entry = Entry {
            id: "1-a".into(),
            kind: Kind::Receive,
            link: "https://drop.example/s/DEL".into(),
            paths: Vec::new(),
            dest: Some("/tmp/landed".into()),
            needs_password: false,
            http: None,
            started_unix: 0,
        };
        fs::create_dir_all(&dir).unwrap();
        write_in(&dir, &entry).unwrap();
        set_dest_in(&dir, "1-a", "/tmp/elsewhere");
        assert_eq!(
            get_in(&dir, "1-a").unwrap().dest.as_deref(),
            Some("/tmp/elsewhere")
        );
        set_dest_in(&dir, "never-there", "/tmp/ignored");
        assert!(matches!(
            get_in(&dir, "never-there"),
            Err(Error::UnknownTransfer { .. })
        ));
    }

    /// An entry kept for a retry that never came is dropped at the next
    /// listing once it is past retention, so abandoned sends do not
    /// accumulate forever.
    #[test]
    fn entries_past_retention_are_dropped_by_the_next_listing() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("journal");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let fresh = Entry {
            id: "fresh".into(),
            kind: Kind::Send,
            link: "https://drop.example/r/REQ".into(),
            paths: vec!["/shots".into()],
            dest: None,
            needs_password: false,
            http: None,
            started_unix: now,
        };
        let abandoned = Entry {
            id: "abandoned".into(),
            started_unix: now - RETENTION_SECS - 1,
            ..fresh.clone()
        };
        write_in(&dir, &fresh).unwrap();
        write_in(&dir, &abandoned).unwrap();
        assert_eq!(pending_in(&dir), vec![fresh.clone()]);
        assert!(get_in(&dir, "fresh").is_ok());
        assert!(
            get_in(&dir, &abandoned.id).is_err(),
            "the abandoned entry is gone"
        );
        // The listing itself is stable once the sweep has run.
        assert_eq!(pending_in(&dir), vec![fresh]);
    }
}
