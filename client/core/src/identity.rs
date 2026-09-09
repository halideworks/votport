//! The device holder key.
//!
//! A push preflight names a holder public key; the push then proves possession
//! of the matching private key. The client keeps one Ed25519 key per machine
//! in its state directory, created on first use. A keychain-backed key is a
//! later platform concern; this file-backed key is what the CLI and the first
//! shells use.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;

use crate::error::Result;

/// The per-user state directory for votport client data, without creating it.
///
/// `XDG_DATA_HOME` or `~/.local/share` on Linux, `~/Library/Application
/// Support` on macOS, `%APPDATA%` on Windows, each under a `votport` subdir.
#[must_use]
pub fn state_dir() -> PathBuf {
    let base = platform_data_home();
    base.join("votport")
}

#[cfg(target_os = "windows")]
fn platform_data_home() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(target_os = "macos")]
fn platform_data_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support"))
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn platform_data_home() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg);
    }
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".local/share"))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// This machine's push holder key.
pub struct Device {
    key: SigningKey,
}

impl Device {
    /// Loads the device key from the state directory, creating it on first use.
    ///
    /// # Errors
    /// A read or write failure.
    pub fn load_or_create() -> Result<Self> {
        Self::load_or_create_in(&state_dir())
    }

    /// Loads or creates the device key under `dir`, for a caller (a test, a
    /// shell) that names its own state directory.
    ///
    /// # Errors
    /// A read or write failure.
    pub fn load_or_create_in(dir: &std::path::Path) -> Result<Self> {
        let path = dir.join("device.key");
        let read = || -> Result<Option<Self>> {
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let seed = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                        crate::Error::Other("device key is damaged; restore it from backup before accepting enrolled deliveries".into())
                    })?;
                    Ok(Some(Self {
                        key: SigningKey::from_bytes(&seed),
                    }))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    match std::fs::symlink_metadata(&path) {
                        Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => Ok(None),
                        Ok(meta) if meta.is_file() => Ok(None),
                        _ => Err(error.into()),
                    }
                }
                Err(error) => Err(error.into()),
            }
        };
        if let Some(device) = read()? {
            return Ok(device);
        }
        std::fs::create_dir_all(dir)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("device-key.lock"))?;
        lock.lock()?;
        if let Some(device) = read()? {
            return Ok(device);
        }
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        write_private(&path, &key.to_bytes())?;
        Ok(Self { key })
    }

    /// The signing key, for building a capability holder.
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        self.key.clone()
    }

    /// The holder public key as 64 hex characters, for the preflight request.
    #[must_use]
    pub fn holder_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }
}

/// Writes `bytes` to `path`, readable and writable only by the owner on Unix.
///
/// The bytes are written to a per-process sibling temp file and renamed into
/// place, so an interrupted write never leaves a short `path` for the next run
/// to reject, and two concurrent first-time writers do not share a temp.
pub(crate) fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let temp = path.with_extension(format!(
        "{}-{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_key_is_stable_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let first = Device::load_or_create_in(dir.path()).unwrap();
        let second = Device::load_or_create_in(dir.path()).unwrap();
        assert_eq!(first.holder_key_hex(), second.holder_key_hex());
        assert_eq!(first.holder_key_hex().len(), 64);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("device.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the key file is owner-only");
        }
    }

    #[test]
    fn a_damaged_enrolled_key_is_not_silently_replaced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(dir.path().join("device.key"), b"").unwrap();
        assert!(Device::load_or_create_in(dir.path()).is_err());
        assert_eq!(std::fs::read(dir.path().join("device.key")).unwrap(), b"");
        #[cfg(unix)]
        {
            std::fs::remove_file(dir.path().join("device.key")).unwrap();
            std::os::unix::fs::symlink("missing-key", dir.path().join("device.key")).unwrap();
            assert!(Device::load_or_create_in(dir.path()).is_err());
            assert!(std::fs::symlink_metadata(dir.path().join("device.key"))
                .unwrap()
                .is_symlink());
        }
    }

    #[test]
    fn concurrent_first_loads_keep_one_enrollable_key() {
        let dir = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let (sender, receiver) = std::sync::mpsc::channel();
        for _ in 0..16 {
            let path = dir.path().to_owned();
            let barrier = barrier.clone();
            let sender = sender.clone();
            std::thread::spawn(move || {
                barrier.wait();
                sender
                    .send(Device::load_or_create_in(&path).unwrap().holder_key_hex())
                    .unwrap();
            });
        }
        drop(sender);
        let first = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        for _ in 1..16 {
            assert_eq!(
                receiver
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap(),
                first
            );
        }
        assert_eq!(
            Device::load_or_create_in(dir.path())
                .unwrap()
                .holder_key_hex(),
            first
        );
    }
}
