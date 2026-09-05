//! The transfer journal: one small file per transfer under the state
//! directory, written when a transfer starts and removed when it ends well,
//! so a transfer that was cut by a quit, a crash, or a failure is still there
//! at the next launch for a shell to offer again. It holds what is needed to
//! start the transfer over (the link, the paths or the destination) and never
//! the password.
//!
//! ponytail: a directory of JSON files, not SQLite; one file per transfer is
//! the whole schema, and a pre-release app has no migrations to carry.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

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
    /// Seconds since the Unix epoch when the transfer started.
    pub started_unix: u64,
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
fn fresh_id(started_unix: u64) -> String {
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
        started_unix,
    };
    let _ = write_in(&dir(), &entry);
    entry
}

/// `path` made absolute against the working directory, without touching the
/// filesystem; a path that cannot be resolved is kept as given.
fn absolute(path: &str) -> String {
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

fn write_in(dir: &std::path::Path, entry: &Entry) -> Result<()> {
    fs::create_dir_all(dir)?;
    let bytes = serde_json::to_vec_pretty(entry)
        .map_err(|error| Error::Other(format!("encoding a journal entry: {error}")))?;
    // Written whole under a temp name, so a crash mid-write never leaves a
    // half entry for the next launch to refuse.
    // Not a `.json` name, so a listing never sees a half-written entry.
    let temp = dir.join(format!("{}.{}.tmp", entry.id, std::process::id()));
    fs::write(&temp, bytes)?;
    fs::rename(&temp, path_of(dir, &entry.id))?;
    Ok(())
}

/// Removes a transfer from the journal. A missing entry is not an error.
pub fn forget(id: &str) {
    forget_in(&dir(), id);
}

fn forget_in(dir: &std::path::Path, id: &str) {
    let _ = fs::remove_file(path_of(dir, id));
}

/// The journalled transfers, oldest first. An entry that cannot be read is
/// skipped, never refused.
#[must_use]
pub fn pending() -> Vec<Entry> {
    pending_in(&dir())
}

fn pending_in(dir: &std::path::Path) -> Vec<Entry> {
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut entries: Vec<Entry> = read
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .filter_map(|path| serde_json::from_slice(&fs::read(path).ok()?).ok())
        .collect();
    entries.sort_by(|a, b| a.started_unix.cmp(&b.started_unix).then(a.id.cmp(&b.id)));
    entries
}

/// One journalled transfer by id.
///
/// # Errors
/// An id the journal does not hold.
pub fn get(id: &str) -> Result<Entry> {
    get_in(&dir(), id)
}

fn get_in(dir: &std::path::Path, id: &str) -> Result<Entry> {
    let bytes =
        fs::read(path_of(dir, id)).map_err(|_| Error::UnknownTransfer { id: id.to_owned() })?;
    serde_json::from_slice(&bytes).map_err(|_| Error::UnknownTransfer { id: id.to_owned() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_entry_is_pending_until_forgotten_and_a_broken_file_is_skipped() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("journal");
        let first = Entry {
            id: "1-a".into(),
            kind: Kind::Receive,
            link: "https://drop.example/s/DEL".into(),
            paths: Vec::new(),
            dest: Some("/tmp/landed".into()),
            needs_password: true,
            started_unix: 1,
        };
        let second = Entry {
            id: "2-b".into(),
            kind: Kind::Send,
            link: "https://drop.example/r/REQ".into(),
            paths: vec!["/shots".into()],
            dest: None,
            needs_password: false,
            started_unix: 2,
        };
        write_in(&dir, &second).unwrap();
        write_in(&dir, &first).unwrap();
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
}
