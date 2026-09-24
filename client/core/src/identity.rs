//! The device holder key.
//!
//! A push preflight names a holder public key; the push then proves possession
//! of the matching private key. The client keeps one Ed25519 key per machine
//! in its state directory, created on first use. A keychain-backed key is a
//! later platform concern; this file-backed key is what the CLI and the first
//! shells use.

use std::path::PathBuf;

#[cfg(test)]
use std::sync::{Mutex, MutexGuard};

use ed25519_dalek::SigningKey;

use crate::error::Result;

#[cfg(test)]
static TEST_STATE_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
#[cfg(test)]
static TEST_STATE_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) struct TestState {
    previous: Option<PathBuf>,
    _lock: MutexGuard<'static, ()>,
}

#[cfg(test)]
pub(crate) fn test_state_dir(path: &std::path::Path) -> TestState {
    let lock = TEST_STATE_LOCK.lock().unwrap();
    let previous = TEST_STATE_DIR.lock().unwrap().replace(path.to_owned());
    TestState {
        previous,
        _lock: lock,
    }
}

#[cfg(test)]
impl Drop for TestState {
    fn drop(&mut self) {
        *TEST_STATE_DIR.lock().unwrap() = self.previous.take();
    }
}

/// The per-user state directory for votport client data, without creating it.
///
/// `XDG_DATA_HOME` or `~/.local/share` on Linux, `~/Library/Application
/// Support` on macOS, `%LOCALAPPDATA%` on Windows, each under a `votport`
/// subdir. Local, not Roaming: a Roaming profile syncs to the domain
/// controller and follows the user to every machine, and this directory
/// holds the device key, the port session cookie, and watch passwords.
#[must_use]
pub fn state_dir() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_STATE_DIR.lock().unwrap().clone() {
        return path;
    }
    let base = platform_data_home();
    base.join("votport")
}

#[cfg(target_os = "windows")]
fn platform_data_home() -> PathBuf {
    // Local, not Roaming: Roaming syncs to the domain controller at logoff
    // and follows the user to every machine, and this tree holds secrets.
    std::env::var_os("LOCALAPPDATA")
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
    /// Uses a signing key managed by the caller.
    #[must_use]
    pub fn from_signing_key(key: SigningKey) -> Self {
        Self { key }
    }

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
        let key = SigningKey::from_bytes(&rand::random());
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

/// Writes `bytes` to `path`, readable and writable only by the owner.
///
/// The bytes are written to a per-process sibling temp file and renamed into
/// place, so an interrupted write never leaves a short `path` for the next run
/// to reject, and two concurrent first-time writers do not share a temp. On
/// Unix the temp is created 0600; on Windows it gets a protected DACL naming
/// only this user.
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
        #[cfg(windows)]
        restrict_to_user(&temp)?;
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

/// Gives `path` a protected DACL granting only this user, the closest
/// equivalent of the Unix 0600 a private file gets elsewhere. Without it the
/// file inherits the parent's ACEs, which on a Roaming-profile or shared
/// machine can include wider read access. Replaces whatever ACEs the file
/// inherited; the creator is the user, so the owner keeps full control.
///
/// # Errors
/// Any Win32 failure, so a file that cannot be restricted is not written.
#[cfg(windows)]
fn restrict_to_user(path: &std::path::Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, GENERIC_ALL};
    use windows_sys::Win32::Security::Authorization::{
        SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, SET_ACCESS, SE_FILE_OBJECT,
        TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
        PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
    };
    // OpenProcessToken is filed under Threading in windows-sys.
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut length = 0u32;
        // Sizing call fails with ERROR_INSUFFICIENT_BUFFER by design.
        let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut length);
        let mut buffer = vec![0u8; length as usize];
        let filled = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        );
        CloseHandle(token);
        if filled == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
        let mut trustee: TRUSTEE_W = std::mem::zeroed();
        trustee.TrusteeForm = TRUSTEE_IS_SID;
        trustee.TrusteeType = TRUSTEE_IS_USER;
        trustee.ptstrName = user.User.Sid.cast();
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: SET_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: trustee,
        };
        let mut acl: *mut ACL = std::ptr::null_mut();
        let built = SetEntriesInAclW(1, &access, std::ptr::null(), &mut acl);
        if built != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(built as i32).into());
        }
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let status = SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null(),
        );
        LocalFree(acl.cast());
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32).into());
        }
        Ok(())
    }
}

/// Removes the whole per-user state directory: the stored port session,
/// the watch list with its saved passwords, the transfer journal, the
/// evidence outbox, and the device key. A shell offers this as "Remove
/// local data" so an uninstall leaves nothing behind. Watch scans and the
/// evidence retry worker end on their own, each re-reading state that is
/// now gone.
///
/// # Errors
/// A state directory that cannot be removed.
pub fn forget_everything() -> Result<()> {
    match std::fs::remove_dir_all(state_dir()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other.map_err(crate::Error::from),
    }
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
