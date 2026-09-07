//! Single-writer lease on the receive root.
//!
//! The flock on `data/lock` fences two instances over one local or block
//! data directory. It cannot fence a standby whose `data/` is a replica, and
//! flock semantics vary on NFS. The one path both instances share in every
//! supported topology is the receive root, so the lease lives there: a file
//! created exclusively at boot, renewed by a heartbeat, and taken over only
//! when its renewal is older than [`STALE_AFTER`]. A holder whose heartbeat
//! finds another holder's name in the file has been superseded and must
//! stop, since the other instance is now re-attaching its staging.
//!
//! Staleness compares the holder's wall clock at renewal with the reader's;
//! the margin is far wider than NTP drift between two hosts.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const FILE_NAME: &str = ".votport-lease";
/// Heartbeat interval.
pub const RENEW_EVERY: Duration = Duration::from_secs(30);
/// A lease renewed longer ago than this may be taken over.
pub const STALE_AFTER: u64 = 90;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Lease {
    /// `<host>:<pid>:<random>`; the random part makes two boots on one host
    /// distinct.
    pub holder: String,
    pub acquired_at: u64,
    pub renewed_at: u64,
}

impl Lease {
    pub fn age(&self, now: u64) -> u64 {
        now.saturating_sub(self.renewed_at)
    }

    pub fn stale(&self, now: u64) -> bool {
        self.age(now) > STALE_AFTER
    }
}

pub fn path(receive_dir: &Path) -> PathBuf {
    receive_dir.join(FILE_NAME)
}

pub fn new_holder() -> String {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "host".to_owned());
    format!(
        "{host}:{}:{}",
        std::process::id(),
        &crate::auth::random_token()[..8]
    )
}

pub fn read(path: &Path) -> Result<Option<Lease>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("{} is not a lease file: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
}

/// Writes the lease through a sibling temporary and a rename, so a reader
/// never sees a partial file, on NFS included.
fn write(path: &Path, lease: &Lease) -> Result<(), String> {
    let temporary = path.with_file_name(format!(
        "{FILE_NAME}.{}.tmp",
        &crate::auth::random_token()[..8]
    ));
    let bytes = serde_json::to_vec(lease).map_err(|error| error.to_string())?;
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| format!("create {}: {error}", temporary.display()))?;
        std::io::Write::write_all(&mut file, &bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        std::fs::rename(&temporary, path)
            .map_err(|error| format!("rename {} into place: {error}", temporary.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Takes the lease for `holder`: creates it when absent, takes over a stale
/// one, refuses a live one with the holder and age in the message.
pub fn acquire(path: &Path, holder: &str, now: u64) -> Result<Lease, String> {
    let lease = Lease {
        holder: holder.to_owned(),
        acquired_at: now,
        renewed_at: now,
    };
    // Exclusive create is the common path and the only atomic one: two
    // instances booting together over an absent lease cannot both win.
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            let bytes = serde_json::to_vec(&lease).map_err(|error| error.to_string())?;
            std::io::Write::write_all(&mut file, &bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("write {}: {error}", path.display()))?;
            return Ok(lease);
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("create {}: {error}", path.display())),
    }
    match read(path)? {
        Some(current) if !current.stale(now) && current.holder != holder => Err(format!(
            "{} is held by {} (renewed {} s ago); only one instance may serve a receive root, and a dead holder's lease expires after {STALE_AFTER} s",
            path.display(),
            current.holder,
            current.age(now)
        )),
        // Stale, ours from an earlier boot, or removed between the create
        // and the read: take it.
        _ => write(path, &lease).map(|()| lease),
    }
}

pub enum Renewal {
    Renewed,
    /// Another instance took the lease over; this one must stop serving.
    Lost {
        holder: String,
    },
}

/// Renews the holder's lease; reports a takeover instead of overwriting it.
pub fn renew(path: &Path, holder: &str, acquired_at: u64, now: u64) -> Result<Renewal, String> {
    if let Some(current) = read(path)? {
        if current.holder != holder {
            return Ok(Renewal::Lost {
                holder: current.holder,
            });
        }
    }
    // A missing file means an operator removed it; rewriting keeps the
    // fence rather than yielding it.
    write(
        path,
        &Lease {
            holder: holder.to_owned(),
            acquired_at,
            renewed_at: now,
        },
    )?;
    Ok(Renewal::Renewed)
}

/// Drops the lease if this holder still owns it. Production never calls
/// this: the file is a fence until the process is gone and its staleness
/// clock has run out. The in-process restart tests need it.
pub fn release(path: &Path, holder: &str) {
    if let Ok(Some(current)) = read(path) {
        if current.holder == holder {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_creates_refuses_live_and_takes_over_stale() {
        let directory = tempfile::tempdir().unwrap();
        let path = path(directory.path());
        let first = acquire(&path, "a:1:x", 1_000).unwrap();
        assert_eq!(read(&path).unwrap().unwrap(), first);

        let error = acquire(&path, "b:2:y", 1_050).unwrap_err();
        assert!(error.contains("held by a:1:x"), "{error}");
        assert!(error.contains("renewed 50 s ago"), "{error}");
        assert_eq!(read(&path).unwrap().unwrap().holder, "a:1:x");

        // The same holder re-acquires its own lease.
        assert_eq!(acquire(&path, "a:1:x", 1_060).unwrap().holder, "a:1:x");

        // Past STALE_AFTER the standby takes over.
        let taken = acquire(&path, "b:2:y", 1_060 + STALE_AFTER + 1).unwrap();
        assert_eq!(taken.holder, "b:2:y");
        assert_eq!(read(&path).unwrap().unwrap().holder, "b:2:y");
        // Exactly at the boundary it is still live.
        assert!(!Lease {
            holder: String::new(),
            acquired_at: 0,
            renewed_at: 100
        }
        .stale(100 + STALE_AFTER));
        assert!(std::fs::read_dir(directory.path())
            .unwrap()
            .flatten()
            .all(|entry| entry.file_name() == FILE_NAME));
    }

    #[test]
    fn renew_updates_the_clock_and_reports_a_takeover() {
        let directory = tempfile::tempdir().unwrap();
        let path = path(directory.path());
        acquire(&path, "a:1:x", 1_000).unwrap();
        assert!(matches!(
            renew(&path, "a:1:x", 1_000, 1_030).unwrap(),
            Renewal::Renewed
        ));
        let current = read(&path).unwrap().unwrap();
        assert_eq!((current.acquired_at, current.renewed_at), (1_000, 1_030));

        acquire(&path, "b:2:y", 1_030 + STALE_AFTER + 1).unwrap();
        match renew(&path, "a:1:x", 1_000, 2_000).unwrap() {
            Renewal::Lost { holder } => assert_eq!(holder, "b:2:y"),
            Renewal::Renewed => panic!("a superseded holder renewed"),
        }
        assert_eq!(
            read(&path).unwrap().unwrap().holder,
            "b:2:y",
            "the loser must not overwrite the winner"
        );

        // A removed file is re-created by the holder, not yielded.
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            renew(&path, "b:2:y", 0, 2_100).unwrap(),
            Renewal::Renewed
        ));
        assert_eq!(read(&path).unwrap().unwrap().holder, "b:2:y");

        release(&path, "a:1:x");
        assert!(path.exists(), "release by a non-holder is a no-op");
        release(&path, "b:2:y");
        assert!(!path.exists());
    }

    #[test]
    fn a_corrupt_lease_file_is_an_error_not_a_takeover() {
        let directory = tempfile::tempdir().unwrap();
        let path = path(directory.path());
        std::fs::write(&path, b"not json").unwrap();
        assert!(read(&path).unwrap_err().contains("not a lease file"));
        assert!(acquire(&path, "a:1:x", 5).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"not json");
    }
}
