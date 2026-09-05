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
        // A file of exactly 32 bytes is the key; anything else (an empty file
        // left by an interrupted first write, say) is treated as absent and
        // regenerated, since a device key is machine-local and disposable.
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Ok(Self {
                    key: SigningKey::from_bytes(&seed),
                });
            }
        }
        std::fs::create_dir_all(dir)?;
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
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension(format!("key.{}.tmp", std::process::id()));
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&temp, bytes)?;
    }
    std::fs::rename(&temp, path)?;
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
    fn a_short_key_file_is_regenerated_not_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        // An interrupted first write leaves an empty file; the next load must
        // regenerate rather than refuse forever.
        std::fs::write(dir.path().join("device.key"), b"").unwrap();
        let device = Device::load_or_create_in(dir.path()).expect("regenerated");
        assert_eq!(device.holder_key_hex().len(), 64);
    }
}
