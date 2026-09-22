//! Copy-on-write materialization keeps the stage independent of published files.

use super::*;

pub(super) fn cleanup(bundle: &Path) -> std::io::Result<()> {
    match fs::remove_dir_all(bundle.join(".materialize")) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

pub(super) fn supported(stage_parent: &Path, dest: &Path) -> bool {
    let probe = || -> std::io::Result<bool> {
        fs::create_dir_all(dest)?;
        let source = tempfile::NamedTempFile::new_in(stage_parent)?;
        source.as_file().set_len(4096)?;
        let output = tempfile::tempdir_in(dest)?;
        Ok(copy(source.path(), &output.path().join("probe"))?.is_some())
    };
    probe().unwrap_or(false)
}

#[cfg(not(windows))]
pub(super) fn publish(
    source: &Path,
    bundle: &Path,
    dest: &Path,
    path: &Path,
    identity: &ObjectId,
    observer: &mut dyn Observer,
) -> Result<bool> {
    if observer.cancelled() {
        return Err(Error::Cancelled);
    }
    crate::receive::validate_parent(dest, path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    crate::receive::validate_parent(dest, path)?;
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    let clone_root = bundle.join(".materialize");
    match fs::DirBuilder::new().mode(0o700).create(&clone_root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&clone_root)?;
            if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::Other(
                    "the clone staging directory is not private".into(),
                ));
            }
        }
        Err(error) => return Err(error.into()),
    }
    let directory = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&clone_root)?;
    let temporary = directory.path().join("object");
    let Some(file) = copy(source, &temporary)? else {
        return Ok(false);
    };
    if !reusable_file(&temporary, identity, true, observer)? {
        return Err(Error::Other("the cloned object disappeared".into()));
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.sync_all()?;
    if observer.cancelled() {
        return Err(Error::Cancelled);
    }
    crate::receive::validate_parent(dest, path)?;
    if !vot_platform_fs::same_file_handle(&file, &temporary)? {
        return Err(Error::Other(
            "the cloned object changed before publication".into(),
        ));
    }
    match tempfile::TempPath::try_from_path(&temporary)?.persist_noclobber(path) {
        Ok(()) => {}
        Err(error)
            if error.error.raw_os_error() == Some(rustix::io::Errno::XDEV.raw_os_error()) =>
        {
            return Ok(false)
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::Exists {
                path: path.to_path_buf(),
            })
        }
        Err(error) => return Err(crate::receive::io_at(path, error.error)),
    }
    Ok(true)
}

fn copy(source: &Path, destination: &Path) -> std::io::Result<Option<File>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use rustix::io::Errno;
        let source = File::open(source)?;
        #[cfg(target_os = "linux")]
        let result = {
            use std::os::unix::fs::OpenOptionsExt as _;
            let output = fs::OpenOptions::new()
                .mode(0o600)
                .read(true)
                .write(true)
                .create_new(true)
                .open(destination)?;
            rustix::fs::ioctl_ficlone(&output, &source).map(|()| output)
        };
        #[cfg(target_os = "macos")]
        let result = rustix::fs::fclonefileat(
            &source,
            rustix::fs::CWD,
            destination,
            rustix::fs::CloneFlags::empty(),
        )
        .and_then(|()| {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(destination)
                .map_err(|error| Errno::from_io_error(&error).unwrap_or(Errno::IO))
        });
        match result {
            Ok(file) => Ok(Some(file)),
            Err(Errno::XDEV | Errno::OPNOTSUPP | Errno::NOTTY | Errno::INVAL) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (source, destination);
        Ok(None)
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn cloned_outputs_are_verified_independent_and_never_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        fs::write(&source, b"original content").unwrap();
        let mut builder =
            vot_object::ObjectBuilder::new(vot_object::Suite::Blake3Bao64, Some(16)).unwrap();
        builder.update(b"original content").unwrap();
        let identity = builder.finish().unwrap().object_id().clone();
        let destination = directory.path().join("output");
        let supported = publish(
            &source,
            directory.path(),
            directory.path(),
            &destination,
            &identity,
            &mut crate::progress::Silent,
        )
        .unwrap();
        if std::env::var_os("VOTPORT_REQUIRE_CLONE").is_some() {
            assert!(
                supported,
                "this qualification run requires filesystem clones"
            );
        }
        if !supported {
            assert!(!destination.exists());
            return;
        }
        assert_eq!(fs::read(&destination).unwrap(), b"original content");
        fs::write(&destination, b"changed by recipient").unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"original content");
        assert!(matches!(
            publish(
                &source,
                directory.path(),
                directory.path(),
                &destination,
                &identity,
                &mut crate::progress::Silent
            ),
            Err(Error::Exists { .. })
        ));
        let mut wrong = identity;
        wrong.root[0] ^= 1;
        let refused = directory.path().join("refused");
        assert!(publish(
            &source,
            directory.path(),
            directory.path(),
            &refused,
            &wrong,
            &mut crate::progress::Silent
        )
        .is_err());
        assert!(!refused.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"changed by recipient");
        let orphan = directory.path().join(".materialize/interrupted");
        fs::write(&orphan, "orphan").unwrap();
        cleanup(directory.path()).unwrap();
        assert!(!orphan.exists());
        assert_eq!(fs::read(&source).unwrap(), b"original content");
    }
}
