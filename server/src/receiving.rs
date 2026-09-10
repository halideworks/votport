//! Bounded directory handles shared by parked receive files.

use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use serde::{Deserialize, Serialize};
use vot_platform_fs::Directory;
use vot_sdk_file::{NasContract, ReceiveDirectory};

const DIRECTORY_CACHE_SIZE: usize = 8;
pub const SETTING_KEY: &str = "receive_nas_qualification";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageIdentity {
    pub path: PathBuf,
    pub filesystem: String,
    pub source: String,
    pub mount_root: String,
    pub inode: String,
    pub service_uid: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Qualification {
    pub storage: StorageIdentity,
    pub qualified_at: u64,
    pub qualified_by: String,
}

pub fn saved_qualification(store: &crate::store::Store) -> Result<Option<Qualification>, String> {
    store
        .setting(SETTING_KEY)?
        .map(|value| {
            serde_json::from_str(&value).map_err(|e| format!("invalid NAS qualification: {e}"))
        })
        .transpose()
}

pub fn storage_identity(path: &Path) -> Result<StorageIdentity, String> {
    let file = File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    );
    identity_of(path, &file)
}

fn identity_of(path: &Path, file: &File) -> Result<StorageIdentity, String> {
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    #[cfg(target_os = "linux")]
    let (filesystem, source, mount_root) = {
        use rustix::fs::{AtFlags, StatxFlags};
        let stat = rustix::fs::statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
            .map_err(|e| e.to_string())?;
        if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
            return Err("storage mount identity is unavailable".to_owned());
        }
        mount_identity(
            &std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| e.to_string())?,
            stat.stx_mnt_id,
        )?
    };
    #[cfg(not(target_os = "linux"))]
    let (filesystem, source, mount_root) = ("local".to_owned(), String::new(), String::new());
    Ok(StorageIdentity {
        path: path.to_owned(),
        filesystem,
        source,
        mount_root,
        inode: metadata.ino().to_string(),
        service_uid: rustix::process::geteuid().as_raw(),
    })
}

#[cfg(target_os = "linux")]
fn mount_identity(mounts: &str, id: u64) -> Result<(String, String, String), String> {
    let fields = mounts
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            (fields.first()?.parse::<u64>().ok()? == id).then_some(fields)
        })
        .ok_or("storage mount is no longer attached")?;
    let separator = fields
        .iter()
        .position(|field| *field == "-")
        .filter(|index| *index >= 6 && fields.len() == *index + 4)
        .ok_or("invalid storage mount information")?;
    validate_locking(fields[separator + 1], fields[separator + 3])?;
    Ok((
        fields[separator + 1].to_owned(),
        fields[separator + 2].to_owned(),
        fields[3].to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn validate_locking(filesystem: &str, options: &str) -> Result<(), String> {
    let unsupported = options.split(',').any(|option| match filesystem {
        "cifs" | "smb3" => option == "nobrl",
        "nfs" | "nfs4" => matches!(option, "local_lock=all" | "local_lock=flock" | "nolock"),
        _ => false,
    });
    if unsupported {
        return Err("receiving storage requires server-coordinated file locks".to_owned());
    }
    Ok(())
}

pub struct Active {
    pub destinations: std::sync::Arc<Destinations>,
    pub lease: crate::lease::Guard,
}

impl Active {
    pub fn open(destinations: Destinations, holder: &str) -> Result<Self, String> {
        let lease =
            crate::lease::Guard::acquire(&destinations.root, holder, crate::store::now_unix())?;
        destinations.probe()?;
        Ok(Self {
            destinations: std::sync::Arc::new(destinations),
            lease,
        })
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.destinations.stop();
    }
}

pub struct Destinations {
    stopped: Arc<AtomicBool>,
    root: Directory,
    path: PathBuf,
    directories: Mutex<Vec<(PathBuf, ReceiveDirectory)>>,
}

impl Destinations {
    pub fn open(path: &Path, contract: NasContract) -> Result<Self, String> {
        Ok(Self::from_directory(
            Directory::open_with_nas(path, contract).map_err(|e| e.to_string())?,
            path,
        ))
    }

    pub fn configured(path: &Path, store: &crate::store::Store) -> Result<Self, String> {
        let saved = saved_qualification(store)?;
        let contract = if saved.is_some() {
            NasContract::ServerAcknowledged
        } else {
            NasContract::Unqualified
        };
        let root = Directory::open_with_nas(path, contract).map_err(|e| e.to_string())?;
        crate::lease::check_root(&root)?;
        if let Some(saved) = saved {
            if saved.storage != identity_of(path, root.file())? {
                return Err(
                    "receiving storage changed; review its NAS qualification in Storage".to_owned(),
                );
            }
        }
        Ok(Self::from_directory(root, path))
    }

    fn from_directory(root: Directory, path: &Path) -> Self {
        Self {
            stopped: Arc::new(AtomicBool::new(false)),
            root,
            path: path.to_owned(),
            directories: Mutex::new(Vec::new()),
        }
    }

    pub fn identity(&self) -> Result<StorageIdentity, String> {
        identity_of(&self.path, self.root.file())
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }

    pub fn check_live(&self) -> Result<(), String> {
        if self.stopped.load(Ordering::Acquire) {
            Err("receiving storage ownership was lost".to_owned())
        } else {
            Ok(())
        }
    }

    pub fn check_current(&self) -> Result<(), String> {
        self.check_live()?;
        if storage_identity(&self.path)? != self.identity()? {
            return Err("receiving folder or mount changed; reopen storage in Storage".to_owned());
        }
        // Revalidate the held mount's current client options at admission and heartbeat.
        #[cfg(target_os = "linux")]
        if self.contract() == NasContract::ServerAcknowledged {
            vot_platform_fs::validate_nas_mount(self.root.file()).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn is_nas(&self) -> bool {
        self.contract() == NasContract::ServerAcknowledged
    }

    pub fn push_directory(&self, key: &str) -> Result<PathBuf, String> {
        self.check_live()?;
        if key.len() != 32 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid push control key".to_owned());
        }
        self.root
            .private_child(OsStr::new(".vot-stage"))
            .and_then(|private| private.private_child(OsStr::new(&format!(".vot-push-{key}"))))
            .map_err(|e| e.to_string())?;
        Ok(self
            .path
            .join(".vot-stage")
            .join(format!(".vot-push-{key}")))
    }

    pub fn lease_record(&self) -> Result<Option<crate::lease::Lease>, String> {
        let directory = self
            .root
            .open_child(OsStr::new(".vot-stage"))
            .map_err(|e| e.to_string())?;
        crate::lease::read(
            &directory
                .entry(OsStr::new(crate::lease::FILE_NAME))
                .map_err(|e| e.to_string())?,
        )
    }

    pub fn probe(&self) -> Result<(), String> {
        use std::io::Write as _;
        self.check_current()?;
        let private = self
            .root
            .private_child(OsStr::new(".vot-stage"))
            .map_err(|e| e.to_string())?;
        let token = crate::auth::random_token();
        let source = private
            .entry(OsStr::new(&format!("probe-{token}")))
            .map_err(|e| e.to_string())?;
        let linked = source
            .sibling(OsStr::new(&format!("probe-{token}-link")))
            .map_err(|e| e.to_string())?;
        let mut file = source.create().map_err(|e| e.to_string())?;
        let result = (|| {
            file.write_all(b"votport storage check")?;
            file.sync_all()?;
            source.link_to(&file, &linked)?;
            if !linked.same_file(&file)? {
                return Err(std::io::Error::other("storage changed hard-link identity"));
            }
            private.sync()?;
            self.root.sync()
        })();
        let unlink = linked.remove_owned(&file);
        let remove = source.remove_owned(&file);
        result
            .and(unlink)
            .and(remove)
            .and_then(|()| private.sync())
            .map_err(|e| e.to_string())
    }

    pub fn contract(&self) -> NasContract {
        self.root.nas_contract()
    }

    pub fn location(&self, path: &Path) -> Result<vot_platform_fs::FileLocation, String> {
        self.check_live()?;
        let relative = path
            .strip_prefix(&self.path)
            .map_err(|_| "file is outside receiving storage")?;
        let mut components = relative.components().peekable();
        let mut directory = self.root.clone();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err("invalid receiving filename".to_owned());
            };
            if components.peek().is_none() {
                return directory.entry(name).map_err(|e| e.to_string());
            }
            directory = directory.open_child(name).map_err(|e| e.to_string())?;
        }
        Err("missing receiving filename".to_owned())
    }

    pub fn check_location(&self, held: &vot_platform_fs::FileLocation) -> Result<(), String> {
        let current = self.location(&held.path())?;
        let current = current
            .directory()
            .file()
            .metadata()
            .map_err(|e| e.to_string())?;
        let held = held
            .directory()
            .file()
            .metadata()
            .map_err(|e| e.to_string())?;
        if (current.dev(), current.ino()) != (held.dev(), held.ino()) {
            return Err(
                "receiving folder moved during upload; restore its location before resuming".into(),
            );
        }
        Ok(())
    }

    pub fn remove_received(&self, components: &[String]) -> Result<(), String> {
        let Some(payload) = self.removal_location(components)? else {
            return Ok(());
        };
        let mut name = payload.name().to_owned();
        name.push(".vot-receipt");
        let sidecar = payload.sibling(&name).map_err(|e| e.to_string())?;
        let directory = payload.directory().clone();
        let files = [payload, sidecar]
            .into_iter()
            .map(|location| match location.open_read() {
                Ok(file) => Ok(Some((location, file))),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.to_string()),
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (location, file) in files.into_iter().flatten() {
            self.check_live()?;
            location.remove_owned(&file).map_err(|e| e.to_string())?;
        }
        directory.sync().map_err(|e| e.to_string())
    }

    fn removal_location(
        &self,
        components: &[String],
    ) -> Result<Option<vot_platform_fs::FileLocation>, String> {
        self.check_current()?;
        crate::paths::join_under(&self.path, components)?;
        let (name, parents) = components
            .split_last()
            .ok_or("missing receiving filename")?;
        let mut directory = self.root.clone();
        for name in parents {
            let entry = directory
                .entry(OsStr::new(name))
                .map_err(|e| e.to_string())?;
            entry.require_removal_parent().map_err(|_| "automatic deletion requires folders whose entries can only be replaced by the VOTPort service account".to_owned())?;
            directory = match directory.open_child(OsStr::new(name)) {
                Ok(directory) => directory,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.to_string()),
            };
        }
        let payload = directory
            .entry(OsStr::new(name))
            .map_err(|e| e.to_string())?;
        payload.require_removal_parent().map_err(|_| "automatic deletion requires folders whose entries can only be replaced by the VOTPort service account".to_owned())?;
        Ok(Some(payload))
    }

    pub fn remove_tree(&self, components: &[String]) -> Result<(), String> {
        if let Some(location) = self.removal_location(components)? {
            self.remove_tree_at(location).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn remove_tree_at(&self, location: vot_platform_fs::FileLocation) -> std::io::Result<()> {
        self.check_live().map_err(std::io::Error::other)?;
        location.require_removal_parent()?;
        let directory = match location.directory().open_child(location.name()) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        self.clear_directory(&directory, None)?;
        self.check_live().map_err(std::io::Error::other)?;
        location.require_removal_parent()?;
        rustix::fs::unlinkat(
            location.directory().file(),
            location.name(),
            rustix::fs::AtFlags::REMOVEDIR,
        )?;
        location.sync_parent()
    }

    fn clear_directory(&self, directory: &Directory, keep: Option<&OsStr>) -> std::io::Result<()> {
        use std::os::unix::ffi::OsStrExt as _;
        directory
            .entry(OsStr::new("check"))?
            .require_removal_parent()?;
        for entry in rustix::fs::Dir::read_from(directory.file())? {
            let entry = entry?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name == "." || name == ".." || Some(name) == keep {
                continue;
            }
            let child = directory.entry(name)?;
            let stat = rustix::fs::statat(
                directory.file(),
                name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?;
            if rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory
            {
                self.remove_tree_at(child)?;
            } else {
                self.check_live().map_err(std::io::Error::other)?;
                child.require_removal_parent()?;
                if stat.st_uid != rustix::process::geteuid().as_raw() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "subtree contains files owned by another account",
                    ));
                }
                rustix::fs::unlinkat(directory.file(), name, rustix::fs::AtFlags::empty())?;
            }
        }
        directory.sync()
    }

    pub fn clear_push_directory(&self, path: &Path, lock: &File) -> Result<Directory, String> {
        self.check_current()?;
        let location = self.location(&path.join("writer.lock"))?;
        let directory = location.directory();
        directory.require_private().map_err(|e| e.to_string())?;
        if !location.same_file(lock).map_err(|e| e.to_string())? {
            return Err("push control directory no longer holds its writer lock".into());
        }
        // Keep the lock inode and its parent permanent so a new writer cannot bypass a held lock.
        self.clear_directory(directory, Some(OsStr::new("writer.lock")))
            .map_err(|e| e.to_string())?;
        Ok(directory.clone())
    }

    pub fn child(&self, components: &[String]) -> Result<Self, String> {
        self.check_live()?;
        let mut directory = self.root.clone();
        let mut path = self.path.clone();
        for name in components {
            directory = if name == crate::paths::TENANT_STORAGE_DIR {
                directory.private_child(OsStr::new(name))
            } else {
                directory.create_child(OsStr::new(name))
            }
            .map_err(|e| format!("open receive folder {name}: {e}"))?;
            path.push(name);
        }
        let mut child = Self::from_directory(directory, &path);
        child.stopped = Arc::clone(&self.stopped);
        Ok(child)
    }

    pub fn directory(&self, path: &Path, create: bool) -> Result<ReceiveDirectory, String> {
        self.check_live()?;
        let relative = path
            .strip_prefix(&self.path)
            .map_err(|_| "receive folder is outside its root")?;
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err("invalid receive folder".to_owned());
        }
        let mut cache = self
            .directories
            .lock()
            .expect("receive directories poisoned");
        if let Some(index) = cache.iter().position(|(key, _)| key == relative) {
            let entry = cache.remove(index);
            let directory = entry.1.clone();
            cache.push(entry);
            return Ok(directory);
        }
        let mut directory = self.root.clone();
        for name in relative.components() {
            directory = if create && name.as_os_str() == crate::paths::TENANT_STORAGE_DIR {
                directory.private_child(name.as_os_str())
            } else if create {
                directory.create_child(name.as_os_str())
            } else {
                directory.open_child(name.as_os_str())
            }
            .map_err(|e| format!("open receive folder: {e}"))?;
        }
        let directory = ReceiveDirectory::from_directory(directory).map_err(|e| e.to_string())?;
        if cache.len() == DIRECTORY_CACHE_SIZE {
            cache.remove(0);
        }
        cache.push((relative.to_owned(), directory.clone()));
        Ok(directory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_identity_preserves_large_inodes_as_decimal_strings() {
        let root = tempfile::tempdir().unwrap();
        let mut identity = storage_identity(root.path()).unwrap();
        for inode in [9_007_199_254_740_993_u64, u64::MAX] {
            identity.inode = inode.to_string();
            let json = serde_json::to_value(&identity).unwrap();
            assert_eq!(json["inode"].as_str(), Some(inode.to_string().as_str()));
            assert_eq!(
                serde_json::from_value::<StorageIdentity>(json).unwrap(),
                identity
            );
        }
    }

    #[test]
    fn deletion_requires_protected_ancestors_and_never_follows_links() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let outside = tempfile::tempdir().unwrap();
        let destinations = Destinations::open(root.path(), NasContract::Unqualified).unwrap();
        let folder = root.path().join("project");
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&folder)
            .unwrap();
        std::fs::write(folder.join("frame"), b"payload").unwrap();
        std::fs::write(folder.join("frame.vot-receipt"), b"receipt").unwrap();
        let components = vec!["project".into(), "frame".into()];
        for shared in [root.path(), folder.as_path()] {
            let mode = std::fs::metadata(shared).unwrap().permissions();
            std::fs::set_permissions(shared, std::fs::Permissions::from_mode(0o770)).unwrap();
            assert!(destinations.remove_received(&components).is_err());
            assert!(destinations.remove_tree(&["project".into()]).is_err());
            assert_eq!(std::fs::read(folder.join("frame")).unwrap(), b"payload");
            assert!(folder.join("frame.vot-receipt").exists());
            std::fs::set_permissions(shared, mode).unwrap();
        }
        std::fs::write(outside.path().join("frame"), b"unrelated").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("alias")).unwrap();
        assert!(destinations
            .remove_received(&["alias".into(), "frame".into()])
            .is_err());
        assert!(destinations
            .remove_received(&["..".into(), "frame".into()])
            .is_err());
        destinations.remove_received(&components).unwrap();
        destinations.remove_received(&components).unwrap();
        assert!(!folder.join("frame.vot-receipt").exists());
        std::os::unix::fs::symlink(outside.path(), folder.join("alias")).unwrap();
        destinations.remove_tree(&["project".into()]).unwrap();
        assert!(!folder.exists());
        assert_eq!(
            std::fs::read(outside.path().join("frame")).unwrap(),
            b"unrelated"
        );
    }

    #[test]
    fn push_cleanup_keeps_its_lock_inode_and_refuses_an_unrelated_lock() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let destinations = Destinations::open(root.path(), NasContract::Unqualified).unwrap();
        let path = destinations.push_directory(&"01".repeat(16)).unwrap();
        let lock = crate::session::lock_push_directory(&path, NasContract::Unqualified).unwrap();
        let inode = lock.metadata().unwrap().ino();
        let foreign = tempfile::tempfile().unwrap();
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path.join("engine"))
            .unwrap();
        std::fs::write(path.join("engine/checkpoint"), b"metadata").unwrap();
        assert!(destinations.clear_push_directory(&path, &foreign).is_err());
        assert!(path.join("engine/checkpoint").exists());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        destinations.clear_push_directory(&path, &lock).unwrap();
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
        assert_eq!(
            std::fs::metadata(path.join("writer.lock")).unwrap().ino(),
            inode
        );
        assert!(crate::session::lock_push_directory(&path, NasContract::Unqualified).is_err());
        drop(lock);
        assert!(crate::session::lock_push_directory(&path, NasContract::Unqualified).is_ok());
    }

    #[test]
    fn directories_are_bounded_and_never_follow_a_replaced_parent() {
        let root = tempfile::tempdir().unwrap();
        let destinations = Destinations::open(root.path(), NasContract::Unqualified).unwrap();
        for index in 0..100 {
            destinations
                .directory(&root.path().join(index.to_string()), true)
                .unwrap();
        }
        assert_eq!(
            destinations.directories.lock().unwrap().len(),
            DIRECTORY_CACHE_SIZE
        );
        assert!(destinations
            .directory(&root.path().join("../escape"), true)
            .is_err());
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        assert!(destinations
            .directory(&root.path().join("link"), true)
            .is_err());
        assert!(outside.path().read_dir().unwrap().next().is_none());
        assert!(destinations
            .directory(&root.path().join("missing"), false)
            .is_err());
        assert!(!root.path().join("missing").exists());
    }

    #[test]
    fn ownership_loss_stops_every_child_and_cached_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let active = Active::open(
            Destinations::open(root.path(), NasContract::Unqualified).unwrap(),
            "fixture",
        )
        .unwrap();
        let child = active.destinations.child(&["child".into()]).unwrap();
        child.directory(&root.path().join("child"), true).unwrap();
        assert!(child.check_current().is_ok());
        drop(active);
        assert!(child.check_live().is_err());
        assert!(child.check_current().is_err());
        assert!(child.directory(&root.path().join("child"), true).is_err());
        assert!(child.child(&["new".into()]).is_err());
        assert!(child.location(&root.path().join("child/file")).is_err());
        assert!(child.push_directory(&"a".repeat(32)).is_err());
        assert!(!root.path().join("child/new").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn server_locking_cannot_be_replaced_with_client_only_locks() {
        for (filesystem, options, valid) in [
            ("cifs", "vers=3.1.1,cifsacl,serverino", true),
            ("smb3", "nobrl", false),
            ("cifs", "nobrl", false),
            ("nfs4", "hard,local_lock=none", true),
            ("nfs4", "hard,local_lock=flock", false),
            ("nfs", "hard,local_lock=all", false),
            ("nfs", "nolock", false),
            ("ext4", "rw", true),
        ] {
            assert_eq!(validate_locking(filesystem, options).is_ok(), valid);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn qualification_identifies_the_export_and_refuses_a_missing_mount() {
        let mounts = "15 1 0:4 /media /mnt rw,relatime shared:1 - cifs //nas/project rw,vers=3.1.1\n16 1 0:5 /exports /mnt/nested rw - nfs4 other:/project rw,vers=4.1,hard";
        assert_eq!(
            mount_identity(mounts, 15).unwrap(),
            ("cifs".into(), "//nas/project".into(), "/media".into())
        );
        assert_eq!(
            mount_identity(mounts, 16).unwrap(),
            ("nfs4".into(), "other:/project".into(), "/exports".into())
        );
        for (text, id) in [
            (mounts, 17),
            ("15", 15),
            ("15 - cifs a rw", 15),
            ("", 15),
            ("15 1 0:4 / /mnt rw - cifs a", 15),
        ] {
            assert!(mount_identity(text, id).is_err());
        }
        let root = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(&root.path().join("data")).unwrap();
        let selected = root.path().join("received");
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&selected)
            .unwrap();
        assert!(Destinations::configured(&selected, &store).is_ok());
        let qualification = Qualification {
            storage: storage_identity(&selected).unwrap(),
            qualified_at: 1,
            qualified_by: "fixture".into(),
        };
        store
            .put_settings(
                "fixture",
                &[(
                    SETTING_KEY.into(),
                    crate::store::SettingWrite::Set(serde_json::to_string(&qualification).unwrap()),
                )],
            )
            .unwrap();
        assert!(
            Destinations::configured(&selected, &store).is_err(),
            "NAS qualification must not enable its underlying local directory"
        );
        store
            .put_settings(
                "fixture",
                &[(
                    SETTING_KEY.into(),
                    crate::store::SettingWrite::Set("{}".into()),
                )],
            )
            .unwrap();
        assert!(Destinations::configured(&selected, &store).is_err());
    }
}
