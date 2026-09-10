//! Receive-root ownership held by a kernel file lock in the private namespace.
//! The permanent lock inode is never renamed or unlinked. Heartbeat timestamps
//! describe ownership; an expired clock does not authorize a second writer.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vot_platform_fs::{Directory, FileLocation};

pub const FILE_NAME: &str = ".votport-lease";
pub const RENEW_EVERY: Duration = Duration::from_secs(30);
const LOCK_NAME: &str = "writer.lock";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Lease {
    pub holder: String,
    pub acquired_at: u64,
    pub renewed_at: u64,
}

impl Lease {
    pub fn age(&self, now: u64) -> u64 {
        now.saturating_sub(self.renewed_at)
    }
}

pub fn path(receive_dir: &Path) -> PathBuf {
    receive_dir.join(".vot-stage").join(FILE_NAME)
}

pub fn new_holder() -> String {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "host".to_owned());
    format!(
        "{host}:{}:{}",
        std::process::id(),
        &crate::auth::random_token()[..8]
    )
}

pub struct Guard {
    root: Directory,
    directory: Directory,
    lock: File,
    lock_location: FileLocation,
    location: FileLocation,
    pub record: Lease,
}

impl Guard {
    pub fn acquire(root: &Directory, holder: &str, now: u64) -> Result<Self, String> {
        check_root(root)?;
        let directory = root
            .private_child(OsStr::new(".vot-stage"))
            .map_err(|e| e.to_string())?;
        let location = directory
            .entry(OsStr::new(FILE_NAME))
            .map_err(|e| e.to_string())?;
        let lock_location = directory
            .entry(OsStr::new(LOCK_NAME))
            .map_err(|e| e.to_string())?;
        let lock = lock_location
            .open(
                rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CREATE,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .map_err(|e| e.to_string())?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |e| {
                format!(
                    "{FILE_NAME} is held by {}; cannot acquire storage lock: {e}",
                    read(&location)
                        .ok()
                        .flatten()
                        .map_or_else(|| "another instance".to_owned(), |r| r.holder)
                )
            },
        )?;
        let record = Lease {
            holder: holder.to_owned(),
            acquired_at: now,
            renewed_at: now,
        };
        let guard = Self {
            root: root.clone(),
            directory,
            lock,
            lock_location,
            location,
            record,
        };
        guard.check_namespace()?;
        write(&guard.location, &guard.record)?;
        Ok(guard)
    }

    fn check_namespace(&self) -> Result<(), String> {
        check_root(&self.root)?;
        let visible = self
            .root
            .open_child(OsStr::new(".vot-stage"))
            .map_err(|e| e.to_string())?;
        let visible = visible.file().metadata().map_err(|e| e.to_string())?;
        let held = self
            .directory
            .file()
            .metadata()
            .map_err(|e| e.to_string())?;
        if (visible.dev(), visible.ino()) != (held.dev(), held.ino())
            || !self
                .lock_location
                .same_file(&self.lock)
                .map_err(|e| e.to_string())?
        {
            return Err("receiving storage lock directory changed".to_owned());
        }
        Ok(())
    }

    pub fn renew(&mut self, now: u64) -> Result<(), String> {
        self.check_namespace()?;
        if read(&self.location)?.is_none_or(|r| r.holder != self.record.holder) {
            return Err("receiving storage ownership changed".to_owned());
        }
        let mut next = self.record.clone();
        next.renewed_at = now;
        write(&self.location, &next)?;
        self.record = next;
        Ok(())
    }
}

pub(crate) fn check_root(root: &Directory) -> Result<(), String> {
    if root.nas_contract() == vot_platform_fs::NasContract::Unqualified {
        let metadata = root.file().metadata().map_err(|e| e.to_string())?;
        if !protected_root(
            metadata.uid(),
            rustix::process::geteuid().as_raw(),
            metadata.mode(),
        ) {
            return Err("The receiving folder must be owned by the Votport service account. Remove group/other write access or set the sticky bit to protect its private control folder.".to_owned());
        }
    }
    Ok(())
}

fn protected_root(owner: u32, service: u32, mode: u32) -> bool {
    owner == service && (mode & 0o022 == 0 || mode & 0o1000 != 0)
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(file) = self.location.open_read() {
            if read_file(&file).is_ok_and(|r| r.holder == self.record.holder) {
                let _ = self.location.remove_owned(&file);
                let _ = self.location.sync_parent();
            }
        }
    }
}

pub fn read(location: &FileLocation) -> Result<Option<Lease>, String> {
    match location.open_read() {
        Ok(file) => read_file(&file).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn read_file(file: &File) -> Result<Lease, String> {
    let mut bytes = Vec::new();
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 16_384 {
        return Err("lease record is too large".to_owned());
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid lease record: {e}"))
}

fn write(location: &FileLocation, lease: &Lease) -> Result<(), String> {
    let temporary = location
        .sibling(OsStr::new(&format!(
            "lease-{}.tmp",
            crate::auth::random_token()
        )))
        .map_err(|e| e.to_string())?;
    let mut file = temporary.create().map_err(|e| e.to_string())?;
    let result = (|| {
        let bytes = serde_json::to_vec(lease).map_err(std::io::Error::other)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        temporary.replace_private(location)?;
        location.sync_parent()
    })();
    if result.is_err() {
        let _ = temporary.remove_owned(&file);
    }
    result.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_requires_the_permanent_lock_even_after_a_stale_heartbeat() {
        let root = tempfile::Builder::new()
            .permissions({
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::Permissions::from_mode(0o700)
            })
            .tempdir()
            .unwrap();
        let directory = Directory::open(root.path()).unwrap();
        let mut first = Guard::acquire(&directory, "first", 1).unwrap();
        assert!(Guard::acquire(&directory, "second", u64::MAX).is_err());
        first.renew(30).unwrap();
        assert_eq!(read(&first.location).unwrap().unwrap().renewed_at, 30);
        let lock_identity = first.lock_location.identity().unwrap();
        let location = first.location.clone();
        drop(first);
        assert!(read(&location).unwrap().is_none());
        let second = Guard::acquire(&directory, "second", 31).unwrap();
        assert_eq!(second.lock_location.identity().unwrap(), lock_identity);
        assert_eq!(read(&location).unwrap().unwrap().holder, "second");
    }

    #[test]
    fn shared_local_roots_need_sticky_protection_and_namespace_replacement_stops_renewal() {
        use std::os::unix::fs::PermissionsExt as _;
        for (owner, mode, expected) in [
            (1, 0o700, true),
            (1, 0o755, true),
            (1, 0o770, false),
            (1, 0o777, false),
            (1, 0o1770, true),
            (1, 0o1777, true),
            (2, 0o1700, false),
            (2, 0o700, false),
        ] {
            assert_eq!(protected_root(owner, 1, mode), expected);
        }
        let root = tempfile::Builder::new()
            .permissions({
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::Permissions::from_mode(0o700)
            })
            .tempdir()
            .unwrap();
        let directory = Directory::open(root.path()).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(Guard::acquire(&directory, "first", 1).is_err());
        assert!(!root.path().join(".vot-stage").exists());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o1770)).unwrap();
        let mut first = Guard::acquire(&directory, "first", 1).unwrap();
        assert!(Guard::acquire(&directory, "second", 2).is_err());
        std::fs::rename(root.path().join(".vot-stage"), root.path().join("moved")).unwrap();
        assert!(first.renew(3).is_err());
        let second = Guard::acquire(&directory, "second", 4).unwrap();
        assert!(first.renew(5).is_err());
        drop(first);
        assert_eq!(read(&second.location).unwrap().unwrap().holder, "second");
    }

    #[test]
    fn replaced_control_state_and_symlinks_never_renew_or_escape() {
        let root = tempfile::Builder::new()
            .permissions({
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::Permissions::from_mode(0o700)
            })
            .tempdir()
            .unwrap();
        let directory = Directory::open(root.path()).unwrap();
        let mut guard = Guard::acquire(&directory, "first", 1).unwrap();
        write(
            &guard.location,
            &Lease {
                holder: "different".to_owned(),
                acquired_at: 2,
                renewed_at: 2,
            },
        )
        .unwrap();
        assert!(guard.renew(3).is_err());
        let location = guard.location.clone();
        drop(guard);
        assert_eq!(read(&location).unwrap().unwrap().holder, "different");
        std::fs::remove_file(location.path()).unwrap();
        std::os::unix::fs::symlink(root.path().join("outside"), location.path()).unwrap();
        assert!(read(&location).is_err());
        assert!(!root.path().join("outside").exists());
    }
}
