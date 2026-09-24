//! Versioned, deliberately small application backups.
//!
//! The bundle is a tar stream containing one manifest, the SQLite snapshot,
//! and the handful of identities owned by the data directory.  It never
//! walks a directory: this is both the allowlist and the archive's security
//! boundary.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use age::secrecy::SecretString;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::{MultipartUpload, ObjectStore, ObjectStoreExt as _};
use rand::RngCore as _;
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{Archive, Builder, Header};

pub const SETTING_KEY: &str = "backup_config";
pub const SECRETS_FILE: &str = "backup-secrets.json";
pub const STATUS_FILE: &str = "backup-status.json";
pub const PENDING_FILE: &str = ".votport-restore-pending.json";
pub const VERSION: u32 = 2;
const MAX_MANIFEST: u64 = 64 * 1024;
const MAX_MARKER: u64 = MAX_MANIFEST + 16 * 1024;
const MAX_IDENTITY: u64 = 16 * 1024 * 1024;
const PART_SIZE: usize = 5 * 1024 * 1024;
const MAX_S3_LIST_ENTRIES: usize = 100_000;
const S3_LIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
const ARCHIVE_FILES: [&str; 5] = [
    "votport.db",
    "receipt.key",
    "push-issuer.key",
    "push.crt",
    "push.key",
];

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Destination {
    #[default]
    Local,
    S3,
    Both,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BackupConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub retention_days: u64,
    pub retention_count: u64,
    pub destination: Destination,
    pub local_path: Option<String>,
    pub s3_endpoint: Option<String>,
    pub s3_region: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_prefix: Option<String>,
    pub encrypt: bool,
    pub s3_path_style: bool,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 86_400,
            retention_days: 30,
            retention_count: 30,
            destination: Destination::Local,
            local_path: None,
            s3_endpoint: None,
            s3_region: None,
            s3_bucket: None,
            s3_prefix: None,
            encrypt: false,
            s3_path_style: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BackupSecrets {
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub passphrase: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct BackupStatus {
    pub running: bool,
    pub last_attempt_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub created_at: u64,
    pub schema_version: u64,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InventoryItem {
    pub id: String,
    pub source: &'static str,
    pub bytes: u64,
    pub created_at: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    pub source: String,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingRestore {
    stage: String,
    version: u32,
    manifest: Manifest,
    mode: RestoreMode,
    #[serde(default)]
    phase: RestorePhase,
    #[serde(default)]
    rollback: Option<String>,
    /// The inventory id of the restored archive, recorded when the restore
    /// was staged from a named backup. A replica pull stages from the live
    /// primary and has none; the applied-restore log and audit row then name
    /// the archive only by its manifest created_at.
    #[serde(default)]
    archive: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RestoreMode {
    Historical,
    Replica,
}

impl RestoreMode {
    pub(crate) fn label(self) -> &'static str {
        match self {
            RestoreMode::Historical => "historical",
            RestoreMode::Replica => "replica",
        }
    }
}

/// What a boot-time `apply_pending_restore` installed, for the applied
/// log line and the audit row that closes the silent gap between the last
/// pre-backup entry and the next login (audit finding 494).
pub(crate) struct AppliedRestore {
    pub(crate) archive: Option<String>,
    pub(crate) created_at: u64,
    pub(crate) mode: RestoreMode,
    pub(crate) schema_version: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RestorePhase {
    #[default]
    Prepared,
    OldMoved,
    NewInstalled,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublicConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub retention_days: u64,
    pub retention_count: u64,
    pub destination: Destination,
    pub local_path: Option<String>,
    pub s3_endpoint: Option<String>,
    pub s3_region: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_prefix: Option<String>,
    pub s3_path_style: bool,
    pub encrypt: bool,
    pub s3_credentials_configured: bool,
    pub passphrase_configured: bool,
}

impl BackupConfig {
    pub fn validate(&self, data_dir: &Path) -> Result<(), String> {
        if self.interval_secs < 60 || self.interval_secs > 31_536_000 {
            return Err("interval_secs must be 60..31536000".into());
        }
        if self.retention_days > 36_500 || self.retention_count > 10_000 {
            return Err("retention is out of range".into());
        }
        if let Some(path) = &self.local_path {
            let path = Path::new(path);
            if path.as_os_str().len() > 4096
                || !path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err("local_path must be an absolute non-traversing path".into());
            }
        }
        let root = self.local_root(data_dir)?;
        validate_local_root(&root, data_dir, self.local_path.is_some())?;
        let uses_s3 = matches!(self.destination, Destination::S3 | Destination::Both);
        if uses_s3 {
            self.s3_endpoint
                .as_deref()
                .ok_or("S3 endpoint is required")?;
            self.s3_bucket.as_deref().ok_or("S3 bucket is required")?;
        }
        if let Some(endpoint) = &self.s3_endpoint {
            validate_endpoint(endpoint)?;
        }
        if let Some(bucket) = &self.s3_bucket {
            validate_bucket(bucket)?;
        }
        if self
            .s3_region
            .as_ref()
            .is_some_and(|region| region.len() > 255)
        {
            return Err("S3 region is too long".into());
        }
        if let Some(prefix) = &self.s3_prefix {
            validate_prefix(prefix)?;
        }
        Ok(())
    }
    pub fn local_root(&self, data_dir: &Path) -> Result<PathBuf, String> {
        if let Some(path) = &self.local_path {
            let root = PathBuf::from(path);
            if !root.is_absolute() {
                return Err("local_path must be absolute".into());
            }
            Ok(root)
        } else {
            Ok(data_dir.join("backups"))
        }
    }
    pub fn public(&self, secrets: &BackupSecrets) -> PublicConfig {
        PublicConfig {
            enabled: self.enabled,
            interval_secs: self.interval_secs,
            retention_days: self.retention_days,
            retention_count: self.retention_count,
            destination: self.destination.clone(),
            local_path: self.local_path.clone(),
            s3_endpoint: self.s3_endpoint.clone(),
            s3_region: self.s3_region.clone(),
            s3_bucket: self.s3_bucket.clone(),
            s3_prefix: self.s3_prefix.clone(),
            s3_path_style: self.s3_path_style,
            encrypt: self.encrypt,
            s3_credentials_configured: secrets.access_key_id.is_some()
                && secrets.secret_access_key.is_some(),
            passphrase_configured: secrets.passphrase.is_some(),
        }
    }
}

impl BackupSecrets {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("access key", self.access_key_id.as_deref()),
            ("secret key", self.secret_access_key.as_deref()),
        ] {
            if value.is_some_and(|value| value.is_empty() || value.len() > 4096) {
                return Err(format!("backup {name} must be 1..4096 bytes"));
            }
        }
        if self
            .passphrase
            .as_deref()
            .is_some_and(|value| value.chars().count() < 12 || value.len() > 4096)
        {
            return Err("backup passphrase must be 12..4096 characters".into());
        }
        Ok(())
    }
}

/// Audit finding 558: both local-root validators stop the writable-ancestor
/// walk at data_dir. Ancestors above it are outside votport's control (a
/// group-writable operator home is normal under Ubuntu's umask 002), and the
/// inventory must not refuse archives that writes and prunes accept.
fn local_root_ancestry_stop<'a>(root: &Path, data_dir: &'a Path) -> Option<&'a Path> {
    root.starts_with(data_dir).then_some(data_dir)
}

fn validate_local_root(root: &Path, data_dir: &Path, require_existing: bool) -> Result<(), String> {
    if root == data_dir {
        return Err("local backup path must not be the data directory".into());
    }
    if require_existing && !root.exists() {
        return Err("custom local backup path must already exist".into());
    }
    validate_private_ancestry(root, local_root_ancestry_stop(root, data_dir))
}

fn validate_private_ancestry(root: &Path, stop: Option<&Path>) -> Result<(), String> {
    let mut current = root.to_path_buf();
    loop {
        if let Ok(meta) = fs::symlink_metadata(&current) {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err("local backup path contains a symlink or non-directory".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = meta.permissions().mode();
                if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                    return Err("local backup path has an unsafe writable ancestor".into());
                }
            }
        }
        if stop.is_some_and(|stop| current == stop) {
            break;
        }
        if !current.pop() {
            break;
        }
    }
    Ok(())
}

pub(crate) fn validate_endpoint(value: &str) -> Result<(), String> {
    if value.len() > 2048 {
        return Err("invalid S3 endpoint".into());
    }
    let url = reqwest::Url::parse(value).map_err(|_| "invalid S3 endpoint")?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        return Err("invalid S3 endpoint".into());
    }
    if url.scheme() == "http" && !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
    {
        return Err("S3 endpoint must use HTTPS except loopback".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("S3 endpoint cannot contain query or fragment".into());
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || (url.path() != "" && url.path() != "/")
    {
        return Err("S3 endpoint cannot contain userinfo or a path".into());
    }
    Ok(())
}
pub(crate) fn validate_bucket(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err("invalid S3 bucket".into());
    }
    Ok(())
}
fn validate_prefix(value: &str) -> Result<(), String> {
    if value.len() > 1024
        || value.starts_with('/')
        || value.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        })
    {
        return Err("invalid S3 prefix".into());
    }
    Ok(())
}

pub fn decode_config(value: Option<String>) -> Result<BackupConfig, String> {
    let mut config: BackupConfig = value
        .map(|v| serde_json::from_str(&v).map_err(|_| "invalid backup configuration".to_owned()))
        .transpose()?
        .unwrap_or_default();
    for field in [
        &mut config.local_path,
        &mut config.s3_endpoint,
        &mut config.s3_region,
        &mut config.s3_bucket,
        &mut config.s3_prefix,
    ] {
        if field.as_deref().is_some_and(str::is_empty) {
            *field = None;
        }
    }
    Ok(config)
}

pub fn parse_config(value: Option<String>, data_dir: &Path) -> Result<BackupConfig, String> {
    let config = decode_config(value)?;
    config.validate(data_dir)?;
    Ok(config)
}

pub fn ensure_no_pending_restore(data_dir: &Path) -> Result<(), String> {
    if data_dir
        .join(PENDING_FILE)
        .try_exists()
        .map_err(|error| error.to_string())?
    {
        return Err("restore pending; restart required".into());
    }
    Ok(())
}

fn read_pending_restore(data_dir: &Path) -> Result<Option<PendingRestore>, String> {
    let path = data_dir.join(PENDING_FILE);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    if !meta.file_type().is_file() || meta.len() > MAX_MARKER {
        return Err("invalid pending restore marker".into());
    }
    let marker: PendingRestore =
        serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|_| "invalid pending restore marker".to_owned())?;
    if !marker.stage.starts_with(".votport-restore-stage-") || marker.stage.contains(['/', '\\']) {
        return Err("invalid pending restore stage".into());
    }
    Ok(Some(marker))
}

pub(crate) fn pending_restore_stage(data_dir: &Path) -> Result<Option<String>, String> {
    read_pending_restore(data_dir).map(|marker| marker.map(|marker| marker.stage))
}

fn generated_scratch_name(name: &str, prefix: &str, suffix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|name| name.strip_suffix(suffix))
        .is_some_and(|token| {
            token.len() == 32
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn data_scratch_kind(name: &str) -> Option<bool> {
    if generated_scratch_name(name, ".votport-backup-db-", "")
        || generated_scratch_name(name, ".votport-replica-", ".tar")
        || generated_scratch_name(name, ".votport-restore-", ".download")
        || generated_scratch_name(name, ".votport-restore-", ".tar")
        // Stage temps of files this crate and the standby worker write into
        // the data directory through atomic_write_private: a failed rename
        // leaves the temp behind for the orphan sweep. The two status files
        // start with a dot themselves, hence the doubled dot.
        || generated_scratch_name(name, ".backup-status.json-", ".stage")
        || generated_scratch_name(name, ".backup-secrets.json-", ".stage")
        || generated_scratch_name(name, ".votport-restore-pending.json-", ".stage")
        || generated_scratch_name(name, "..votport-standby-status.json-", ".stage")
    {
        return Some(false);
    }
    generated_scratch_name(name, ".votport-restore-stage-", "").then_some(true)
}

const BACKUP_ROOT_LOCK: &str = ".votport-backup.lock";
const BACKUP_ROOT_STAGE_PREFIX: &str = ".votport-backup-stage-";

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum BackupPausePoint {
    Archive,
    Encrypt,
}

#[cfg(test)]
struct BackupWorkerPause {
    data_dir: PathBuf,
    point: BackupPausePoint,
    started: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
static BACKUP_WORKER_PAUSE: OnceLock<Mutex<Vec<BackupWorkerPause>>> = OnceLock::new();

#[cfg(test)]
fn pause_backup_worker(data_dir: &Path, point: BackupPausePoint) {
    let mut guard = BACKUP_WORKER_PAUSE
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .expect("backup worker pause lock");
    let Some(index) = guard
        .iter()
        .position(|pause| pause.data_dir == data_dir && pause.point == point)
    else {
        return;
    };
    let pause = guard.swap_remove(index);
    drop(guard);
    let _ = pause.started.send(());
    let _ = pause
        .release
        .recv_timeout(std::time::Duration::from_secs(10));
}

/// Stable cross-process fence for one local backup root.
#[derive(Clone)]
pub(crate) struct BackupRootLock {
    pub(crate) file: Arc<File>,
}

#[cfg(unix)]
fn open_backup_root_lock(path: &Path) -> Result<File, String> {
    match crate::paths::create_private_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("create backup root lock: {error}")),
    }
    let file = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("open backup root lock: {error}"))?;
    let file = File::from(file);
    if !vot_platform_fs::same_file_handle(&file, path)
        .map_err(|error| format!("check backup root lock: {error}"))?
    {
        return Err("backup root lock changed while opening".into());
    }
    crate::paths::tighten_private_file(path)?;
    if !vot_platform_fs::same_file_handle(&file, path)
        .map_err(|error| format!("check backup root lock: {error}"))?
    {
        return Err("backup root lock changed while protecting".into());
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_backup_root_lock(_path: &Path) -> Result<File, String> {
    Err("backup root fencing is unavailable on this platform".into())
}

pub(crate) fn try_lock_backup_root(root: &Path) -> Result<Option<BackupRootLock>, String> {
    let root = ensure_backup_root(root)?;
    let path = root.join(BACKUP_ROOT_LOCK);
    let file = open_backup_root_lock(&path)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
        Err(std::fs::TryLockError::Error(error)) => {
            return Err(format!("lock backup root: {error}"))
        }
    }
    if !vot_platform_fs::same_file_handle(&file, &path)
        .map_err(|error| format!("check locked backup root: {error}"))?
    {
        let _ = file.unlock();
        return Err("backup root lock changed while locking".into());
    }
    Ok(Some(BackupRootLock {
        file: Arc::new(file),
    }))
}

fn backup_root_stage(name: &str) -> bool {
    generated_scratch_name(name, BACKUP_ROOT_STAGE_PREFIX, ".tar")
        || generated_scratch_name(name, BACKUP_ROOT_STAGE_PREFIX, ".tar.age")
}

/// Removes new fenced archive stages when the root is not busy.
pub(crate) fn sweep_backup_root_orphans(root: &Path) -> Result<Option<usize>, String> {
    let Some(_lock) = try_lock_backup_root(root)? else {
        return Ok(None);
    };
    let mut removed = 0;
    for entry in fs::read_dir(root).map_err(|error| error.to_string())? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, "backup root stage entry could not be inspected");
                continue;
            }
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !backup_root_stage(&name) {
            continue;
        }
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "backup root stage metadata failed");
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "backup root stage cleanup failed")
            }
        }
    }
    Ok(Some(removed))
}

/// Removes interrupted scratch owned by this locked data directory; bad markers preserve evidence.
pub(crate) fn sweep_data_dir_orphans(data_dir: &Path) -> Result<usize, String> {
    let keep = pending_restore_stage(data_dir)?;
    let mut removed = 0;
    for entry in fs::read_dir(data_dir).map_err(|error| error.to_string())? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, "data scratch entry could not be inspected");
                continue;
            }
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(directory) = data_scratch_kind(&name) else {
            continue;
        };
        if keep.as_deref() == Some(name.as_str()) {
            continue;
        }
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "data scratch entry metadata failed");
                continue;
            }
        };
        if metadata.file_type().is_symlink()
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
        {
            continue;
        }
        let result = if directory {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        match result {
            Ok(()) => removed += 1,
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "data scratch cleanup failed")
            }
        }
    }
    Ok(removed)
}

pub fn read_secrets(data_dir: &Path) -> Result<BackupSecrets, String> {
    let path = data_dir.join(SECRETS_FILE);
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BackupSecrets::default()),
        Err(e) => return Err(e.to_string()),
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > MAX_MANIFEST {
        return Err("invalid backup secrets file".into());
    }
    crate::paths::tighten_private_file(&path)?;
    let bytes = fs::read(&path).map_err(|e| e.to_string())?;
    let secrets: BackupSecrets =
        serde_json::from_slice(&bytes).map_err(|_| "invalid backup secrets file".to_owned())?;
    secrets.validate()?;
    Ok(secrets)
}

pub fn write_secrets(data_dir: &Path, secrets: &BackupSecrets) -> Result<(), String> {
    fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    secrets.validate()?;
    let bytes = serde_json::to_vec(secrets).map_err(|e| e.to_string())?;
    atomic_write_private(&data_dir.join(SECRETS_FILE), &bytes)
}

pub fn read_status(data_dir: &Path) -> Result<BackupStatus, String> {
    let path = data_dir.join(STATUS_FILE);
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BackupStatus::default()),
        Err(e) => return Err(e.to_string()),
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > MAX_MANIFEST {
        return Err("invalid backup status file".into());
    }
    let mut status: BackupStatus =
        serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|_| "invalid backup status file".to_owned())?;
    status.running = false;
    Ok(status)
}

fn write_status(data_dir: &Path, mut status: BackupStatus) -> Result<(), String> {
    status.running = false;
    let bytes = serde_json::to_vec(&status).map_err(|e| e.to_string())?;
    atomic_write_private(&data_dir.join(STATUS_FILE), &bytes)
}

pub(crate) fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("private file has no parent")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid private filename")?;
    let stage = parent.join(format!(".{name}-{}.stage", crate::auth::random_token()));
    let mut cleanup = CleanupPath::new(stage.clone());
    let mut file = create_private_new(&stage).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    fs::rename(&stage, path).map_err(|e| e.to_string())?;
    cleanup.keep();
    sync_directory(parent)
}

fn create_private_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

fn open_regular_nofollow(path: &Path) -> Result<File, String> {
    #[cfg(unix)]
    let file = {
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        File::from(fd)
    };
    #[cfg(not(unix))]
    let file = File::open(path).map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("path is not a regular file".into());
    }
    Ok(file)
}

pub(crate) fn copy_private_file(source: &Path, destination: &Path) -> Result<(), String> {
    let mut source = open_regular_nofollow(source)?;
    let mut cleanup = CleanupPath::new(destination.to_path_buf());
    let mut destination_file = create_private_new(destination).map_err(|e| e.to_string())?;
    io::copy(&mut source, &mut destination_file).map_err(|e| e.to_string())?;
    destination_file.sync_all().map_err(|e| e.to_string())?;
    cleanup.keep();
    Ok(())
}

pub(crate) struct CleanupPath {
    path: PathBuf,
    keep: bool,
    directory: bool,
}

impl CleanupPath {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            keep: false,
            directory: false,
        }
    }

    pub(crate) fn directory(path: PathBuf) -> Self {
        Self {
            path,
            keep: false,
            directory: true,
        }
    }

    pub(crate) fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for CleanupPath {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        let removal = match fs::symlink_metadata(&self.path) {
            Ok(meta) if self.directory && meta.is_dir() && !meta.file_type().is_symlink() => {
                fs::remove_dir_all(&self.path)
            }
            Ok(meta) if !self.directory && meta.is_file() && !meta.file_type().is_symlink() => {
                fs::remove_file(&self.path)
            }
            Err(_) => return,
            Ok(_) => return,
        };
        if let Err(error) = removal {
            // ponytail: static pacer because a Drop carries no pacer; sweep
            // boot cleans leftovers anyway, this only makes failures visible.
            let due = SCRATCH_REMOVAL_WARN
                .get_or_init(|| {
                    Mutex::new(crate::api::outbound::ErrorDeduper::new("scratch removal"))
                })
                .lock()
                .expect("scratch removal warn pacer poisoned")
                .observe("removal failed", Instant::now());
            if due {
                tracing::warn!(
                    path = %self.path.file_name().unwrap_or_default().to_string_lossy(),
                    error = ?error.kind(),
                    "scratch removal failed; it stays until the next orphan sweep"
                );
            }
        }
    }
}

static SCRATCH_REMOVAL_WARN: OnceLock<Mutex<crate::api::outbound::ErrorDeduper>> = OnceLock::new();

fn publish_new(source: &Path, destination: &Path) -> Result<(), String> {
    fs::hard_link(source, destination).map_err(|e| e.to_string())?;
    fs::remove_file(source).map_err(|e| e.to_string())
}

/// Retires the standby's status file once this directory boots as the live
/// instance. The file marks a promotion: while it exists every boot only
/// validates the schema instead of migrating, so a promoted primary would
/// refuse the next upgrade, and the metrics would keep reporting standby lag.
pub(crate) fn retire_standby_status(data_dir: &Path) -> Result<(), String> {
    match fs::remove_file(data_dir.join(crate::standby::STATUS_FILE)) {
        Ok(()) => sync_directory(data_dir),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove the standby status file: {error}")),
    }
}

fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        File::open(path)
            .map_err(|e| e.to_string())?
            .sync_all()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn owned_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (name.starts_with("votport-backup-v2-")
        && (name.ends_with(".tar") || name.ends_with(".tar.age")))
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'.')
}
pub fn validate_id(id: &str) -> Result<(), String> {
    if id.contains('/') || id.contains('\\') || !owned_name(id) {
        Err("invalid backup id".into())
    } else {
        Ok(())
    }
}

fn file_hash(path: &Path) -> Result<(u64, String), String> {
    let mut file = open_regular_nofollow(path)?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hash.update(&buf[..n]);
    }
    Ok((size, hex::encode(hash.finalize())))
}

fn identities(data_dir: &Path) -> Vec<(&'static str, PathBuf)> {
    ["receipt.key", "push-issuer.key", "push.crt", "push.key"]
        .into_iter()
        .map(|name| (name, data_dir.join(name)))
        .filter(|(_, p)| {
            fs::symlink_metadata(p)
                .map(|m| {
                    m.file_type().is_file()
                        && !m.file_type().is_symlink()
                        && m.len() <= MAX_IDENTITY
                })
                .unwrap_or(false)
        })
        .collect()
}

fn add_file(builder: &mut Builder<File>, name: &str, path: &Path) -> Result<(), String> {
    let mut header = Header::new_gnu();
    let (size, _) = file_hash(path)?;
    header.set_size(size);
    header.set_mode(0o600);
    header.set_cksum();
    let mut file = open_regular_nofollow(path)?;
    builder
        .append_data(&mut header, name, &mut file)
        .map_err(|e| e.to_string())
}

pub fn create_archive(
    store: &crate::store::Store,
    data_dir: &Path,
    stage: &Path,
    schema_version: u64,
) -> Result<Manifest, String> {
    let snapshot = data_dir.join(format!(
        ".votport-backup-db-{}",
        crate::auth::random_token()
    ));
    let _snapshot_cleanup = CleanupPath::new(snapshot.clone());
    store.backup_into(&snapshot)?;
    let identity_files = identities(data_dir);
    let identity_names: HashSet<_> = identity_files.iter().map(|(name, _)| *name).collect();
    if !identity_names.contains("receipt.key") {
        return Err("required identity missing: receipt.key".into());
    }
    validate_identity_material(data_dir, &identity_names)?;
    let mut entries = Vec::new();
    let (size, sha256) = file_hash(&snapshot)?;
    entries.push(ManifestEntry {
        name: "votport.db".into(),
        size,
        sha256,
    });
    for (name, path) in &identity_files {
        let (size, sha256) = file_hash(path)?;
        entries.push(ManifestEntry {
            name: (*name).into(),
            size,
            sha256,
        });
    }
    let manifest = Manifest {
        version: VERSION,
        created_at: now(),
        schema_version,
        entries,
    };
    let mut stage_cleanup = CleanupPath::new(stage.to_path_buf());
    let file = create_private_new(stage).map_err(|e| e.to_string())?;
    let mut builder = Builder::new(file.try_clone().map_err(|e| e.to_string())?);
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    if manifest_bytes.len() as u64 > MAX_MANIFEST {
        return Err("manifest too large".into());
    }
    let mut header = Header::new_gnu();
    header.set_size(manifest_bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    builder
        .append_data(&mut header, "manifest.json", manifest_bytes.as_slice())
        .map_err(|e| e.to_string())?;
    add_file(&mut builder, "votport.db", &snapshot)?;
    for (name, path) in identity_files {
        add_file(&mut builder, name, &path)?;
    }
    builder.finish().map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    stage_cleanup.keep();
    Ok(manifest)
}

pub fn encrypt_file(input: &Path, output: &Path, passphrase: &str) -> Result<(), String> {
    let input_file = open_regular_nofollow(input)?;
    let mut cleanup = CleanupPath::new(output.to_path_buf());
    let mut output_file = create_private_new(output).map_err(|e| e.to_string())?;
    let encryptor = age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_owned()));
    let mut writer = encryptor
        .wrap_output(&mut output_file)
        .map_err(|e| e.to_string())?;
    io::copy(&mut io::BufReader::new(input_file), &mut writer).map_err(|e| e.to_string())?;
    writer.finish().map_err(|e| e.to_string())?;
    output_file.sync_all().map_err(|e| e.to_string())?;
    cleanup.keep();
    Ok(())
}
pub fn decrypt_file(input: &Path, output: &Path, passphrase: &str) -> Result<(), String> {
    let input_file = open_regular_nofollow(input)?;
    let decryptor = age::Decryptor::new(input_file).map_err(|e| e.to_string())?;
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_owned()));
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| e.to_string())?;
    let mut cleanup = CleanupPath::new(output.to_path_buf());
    let mut file = create_private_new(output).map_err(|e| e.to_string())?;
    io::copy(&mut reader, &mut file).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    cleanup.keep();
    Ok(())
}

pub fn validate_and_extract(
    archive: &Path,
    destination: &Path,
    schema_version: u64,
) -> Result<Manifest, String> {
    let file = File::open(archive).map_err(|e| e.to_string())?;
    let mut archive = Archive::new(file);
    let mut names = HashSet::new();
    let mut manifest = None;
    for item in archive.entries().map_err(|e| e.to_string())? {
        let mut entry = item.map_err(|e| e.to_string())?;
        let path = entry.path().map_err(|e| e.to_string())?.into_owned();
        let name = path.to_str().ok_or("non-UTF8 archive path")?;
        if path.components().count() != 1
            || (name != "manifest.json" && !ARCHIVE_FILES.contains(&name))
            || !names.insert(name.to_owned())
        {
            return Err("archive contains an unexpected or duplicate entry".into());
        }
        let kind = entry.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() || !kind.is_file() {
            return Err("archive links are not allowed".into());
        }
        if name == "manifest.json" {
            if entry.size() > MAX_MANIFEST {
                return Err("manifest too large".into());
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            manifest = Some(
                serde_json::from_slice::<Manifest>(&bytes)
                    .map_err(|_| "invalid manifest".to_owned())?,
            );
        } else {
            if entry.size() > MAX_IDENTITY && name != "votport.db" {
                return Err("identity file too large".into());
            }
            let target = destination.join(name);
            let mut output = create_private_new(&target).map_err(|e| e.to_string())?;
            io::copy(&mut entry, &mut output).map_err(|e| e.to_string())?;
            output.sync_all().map_err(|e| e.to_string())?;
            crate::paths::tighten_private_file(&target)?;
        }
    }
    let manifest = manifest.ok_or("manifest missing")?;
    let actual: HashSet<_> = names
        .iter()
        .filter(|name| name.as_str() != "manifest.json")
        .map(String::as_str)
        .collect();
    let expected: HashSet<_> = manifest
        .entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    if expected != actual {
        return Err("manifest entries are invalid".into());
    }
    validate_staged_restore(destination, &manifest, schema_version)?;
    sync_directory(destination)?;
    Ok(manifest)
}

fn validate_staged_restore(
    destination: &Path,
    manifest: &Manifest,
    schema_version: u64,
) -> Result<(), String> {
    if manifest.version != VERSION || manifest.schema_version != schema_version {
        return Err("unsupported backup version or schema".into());
    }
    let expected: HashSet<_> = manifest
        .entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    if expected.len() != manifest.entries.len()
        || !expected.contains("votport.db")
        || !expected.contains("receipt.key")
        || expected
            .iter()
            .any(|name| !ARCHIVE_FILES.contains(name) || *name == "manifest.json")
    {
        return Err("manifest entries are invalid".into());
    }
    let mut actual = HashSet::new();
    for item in fs::read_dir(destination).map_err(|e| e.to_string())? {
        let item = item.map_err(|e| e.to_string())?;
        let name = item
            .file_name()
            .to_str()
            .ok_or("invalid restore filename")?
            .to_owned();
        let meta = fs::symlink_metadata(item.path()).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink()
            || !meta.is_file()
            || !ARCHIVE_FILES.contains(&name.as_str())
            || !actual.insert(name)
        {
            return Err("invalid restore stage contents".into());
        }
    }
    if actual.iter().map(String::as_str).collect::<HashSet<_>>() != expected {
        return Err("pending restore manifest mismatch".into());
    }
    for entry in &manifest.entries {
        let (size, hash) = file_hash(&destination.join(&entry.name))?;
        if size != entry.size || hash != entry.sha256 {
            return Err("backup checksum mismatch".into());
        }
    }
    validate_identity_material(destination, &expected)?;
    validate_database(
        &destination.join("votport.db"),
        manifest.schema_version,
        schema_version,
    )
}

fn validate_identity_material(destination: &Path, names: &HashSet<&str>) -> Result<(), String> {
    for name in ["receipt.key", "push-issuer.key"] {
        if names.contains(name) && file_hash(&destination.join(name))?.0 != 32 {
            return Err(format!("invalid backup identity: {name}"));
        }
    }
    let has_certificate = names.contains("push.crt");
    let has_key = names.contains("push.key");
    if has_certificate != has_key {
        return Err("push certificate and key must be restored together".into());
    }
    if has_certificate {
        let certificate = fs::read(destination.join("push.crt")).map_err(|e| e.to_string())?;
        let key = fs::read_to_string(destination.join("push.key")).map_err(|e| e.to_string())?;
        let key = rcgen::KeyPair::from_pem(&key).map_err(|_| "invalid push private key")?;
        let (_, certificate) = x509_parser::pem::parse_x509_pem(&certificate)
            .map_err(|_| "invalid push certificate")?;
        let (_, certificate) = x509_parser::parse_x509_certificate(&certificate.contents)
            .map_err(|_| "invalid push certificate")?;
        if certificate.public_key().subject_public_key.data.as_ref() != key.public_key_raw() {
            return Err("push certificate and private key do not match".into());
        }
    }
    Ok(())
}

fn validate_database(path: &Path, expected_schema: u64, current_schema: u64) -> Result<(), String> {
    if expected_schema != current_schema {
        return Err("backup database schema does not match this binary".into());
    }
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| format!("invalid backup database: {e}"))?;
    validate_database_connection(&connection, current_schema)
}

fn validate_database_connection(
    connection: &rusqlite::Connection,
    schema_version: u64,
) -> Result<(), String> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|e| format!("invalid backup database: {e}"))?;
    if integrity != "ok" {
        return Err("backup database integrity check failed".into());
    }
    crate::store::validate_schema(connection, schema_version)?;
    read_backup_config(connection).map(|_| ())
}

fn read_backup_config(connection: &rusqlite::Connection) -> Result<BackupConfig, String> {
    let setting = connection
        .query_row(
            "SELECT value FROM settings WHERE key=?1",
            [SETTING_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    decode_config(setting)
}

fn prepare_restored_database(
    path: &Path,
    schema_version: u64,
    mode: RestoreMode,
) -> Result<(), String> {
    let mut connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|e| format!("cannot prepare restored database: {e}"))?;
    // SQLite must recover a hot rollback journal before validating a resumed restore.
    validate_database_connection(&connection, schema_version)?;
    let _: String = connection
        .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
        .map_err(|e| format!("cannot prepare restored database: {e}"))?;
    let transaction = connection.transaction().map_err(|e| e.to_string())?;
    let mut config = read_backup_config(&transaction)?;
    config.enabled = false;
    transaction
        .execute(
            "UPDATE settings SET value=?1 WHERE key=?2",
            [
                serde_json::to_string(&config).map_err(|error| error.to_string())?,
                SETTING_KEY.into(),
            ],
        )
        .map_err(|error| error.to_string())?;
    if mode == RestoreMode::Historical {
        let at = now().min(i64::MAX as u64) as i64;
        for table in ["outbound_grants", "automation_tokens", "inbound_routes"] {
            transaction
                .execute(
                    &format!("UPDATE {table} SET revoked_at=?1 WHERE revoked_at IS NULL"),
                    [at],
                )
                .map_err(|e| e.to_string())?;
        }
        for (key, value) in [
            ("scim_token", ""),
            ("scim_token_previous", ""),
            ("replica_token", ""),
            ("upload_retention_days", "0"),
        ] {
            transaction.execute(
                "INSERT INTO settings(key,value,updated_at,updated_by) VALUES (?1,?2,?3,'restore')
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,updated_by=excluded.updated_by",
                rusqlite::params![key, value, at],
            ).map_err(|e| e.to_string())?;
        }
        // Tenant and link retention narrow the platform value, so all three
        // scopes are cleared or the sweep keeps deleting after a restore.
        transaction.execute_batch(
            "UPDATE links SET active=0, retention_days=NULL;
             UPDATE tenants SET retention_days=NULL;
             DELETE FROM upload_session_files;
             DELETE FROM meta WHERE key LIKE 'interrupted_session:%';
             DELETE FROM upload_sessions;
             DELETE FROM outbound_fetch_tickets;
             UPDATE delivery_storage SET document=json_set(document,'$.enabled',json('false'));
             UPDATE notification_destinations SET document=json_set(document,'$.enabled',json('false'));
             UPDATE delivery_webhooks SET enabled=0;
             UPDATE trade_routes SET credential='',enrollment=NULL,
                 document=json_set(document,'$.state','revoked','$.cancel_active',json('false'),
                     '$.error','Restored from backup; create a new invitation to reconnect.');
             DELETE FROM trade_rotations;
             DELETE FROM trade_invitations;
             UPDATE delivery_jobs SET state='suspended',owner='',
                 document=json_set(document,'$.state','suspended',
                     '$.error','Held after restoring a backup. Create a new job to deliver these files.')
                 WHERE state<>'suspended';"
        ).map_err(|e| e.to_string())?;
    }
    transaction.commit().map_err(|e| e.to_string())?;
    drop(connection);
    File::open(path)
        .map_err(|e| e.to_string())?
        .sync_all()
        .map_err(|e| e.to_string())
}

/// Commit a validated extraction as a restart-time transaction. The marker
/// contains only a basename, and the extracted directory has already passed
/// the fixed archive allowlist above. `archive` is the inventory id of the
/// restored archive when one exists, carried to the applied-restore record.
pub(crate) fn write_pending_restore(
    data_dir: &Path,
    mut extracted: CleanupPath,
    manifest: Manifest,
    mode: RestoreMode,
    archive: Option<&str>,
) -> Result<(), String> {
    let previous = read_pending_restore(data_dir)?;
    if previous
        .as_ref()
        .is_some_and(|marker| marker.phase != RestorePhase::Prepared || marker.rollback.is_some())
    {
        return Err("a restore is being applied; restart to finish it first".into());
    }
    if !extracted.directory || extracted.path.parent() != Some(data_dir) {
        return Err("invalid restore stage".into());
    }
    let stage_name = extracted
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("invalid restore stage")?;
    if !stage_name.starts_with(".votport-restore-stage-") || stage_name.contains(['/', '\\']) {
        return Err("invalid restore stage".into());
    }
    let marker = PendingRestore {
        stage: stage_name.to_owned(),
        version: VERSION,
        manifest,
        mode,
        phase: RestorePhase::Prepared,
        rollback: None,
        archive: archive.filter(|id| !id.is_empty()).map(|id| id.to_owned()),
    };
    // A failed directory sync can leave the new marker installed. Retain both stages until success.
    extracted.keep();
    persist_pending_restore(data_dir, &marker)?;
    if let Some(previous) = previous.filter(|previous| previous.stage != marker.stage) {
        if let Err(error) = fs::remove_dir_all(data_dir.join(previous.stage)) {
            if error.kind() != io::ErrorKind::NotFound {
                tracing::warn!(%error, "previous replica stage cleanup failed");
            }
        }
    }
    Ok(())
}

fn persist_pending_restore(data_dir: &Path, marker: &PendingRestore) -> Result<(), String> {
    let bytes = serde_json::to_vec(marker).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_MARKER {
        return Err("pending restore marker is too large".into());
    }
    atomic_write_private(&data_dir.join(PENDING_FILE), &bytes)
}

/// Removes a replica a previous run staged and its marker, so a standby
/// (or a stopped historical restore) does not hold extracted rows and
/// identity keys the source has since deleted until someone promotes it.
/// A restore that was being applied is never touched: its marker and
/// rollback state are the evidence the next boot finishes from.
pub(crate) fn discard_staged_replica(data_dir: &Path) -> Result<bool, String> {
    let Some(marker) = read_pending_restore(data_dir)? else {
        return Ok(false);
    };
    if marker.phase != RestorePhase::Prepared || marker.rollback.is_some() {
        return Ok(false);
    }
    let stage = data_dir.join(&marker.stage);
    if let Err(error) = fs::remove_dir_all(&stage) {
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error.to_string());
        }
    }
    match fs::remove_file(data_dir.join(PENDING_FILE)) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    Ok(true)
}

/// Applies a staged restore at boot. Returns what was installed, so the
/// caller with an open store can land the `backup_restore_applied` audit
/// row; `None` when nothing was pending.
pub(crate) fn apply_pending_restore(
    data_dir: &Path,
    schema_version: u64,
) -> Result<Option<AppliedRestore>, String> {
    let marker_path = data_dir.join(PENDING_FILE);
    let Some(mut marker) = read_pending_restore(data_dir)? else {
        return Ok(None);
    };
    if marker.version != VERSION
        || marker.manifest.version != VERSION
        || marker.manifest.schema_version != schema_version
        || marker.stage.contains('/')
        || !marker.stage.starts_with(".votport-restore-stage-")
    {
        return Err("invalid pending restore marker".into());
    }
    let stage = data_dir.join(&marker.stage);
    if marker.phase == RestorePhase::Prepared {
        let smeta = fs::symlink_metadata(&stage).map_err(|e| e.to_string())?;
        if smeta.file_type().is_symlink() || !smeta.file_type().is_dir() {
            return Err("invalid restore stage".into());
        }
        validate_staged_restore(&stage, &marker.manifest, schema_version)?;
    } else if marker.phase == RestorePhase::OldMoved {
        let staged_database = stage.join("votport.db");
        let database = if staged_database.try_exists().map_err(|e| e.to_string())? {
            staged_database
        } else {
            data_dir.join("votport.db")
        };
        validate_database(&database, marker.manifest.schema_version, schema_version)?;
    }

    if marker.phase == RestorePhase::Prepared {
        let rollback_name = marker.rollback.clone().unwrap_or_else(|| {
            format!(".votport-restore-rollback-{}", crate::auth::random_token())
        });
        if rollback_name.contains('/') || !rollback_name.starts_with(".votport-restore-rollback-") {
            return Err("invalid restore rollback path".into());
        }
        marker.rollback = Some(rollback_name.clone());
        persist_pending_restore(data_dir, &marker)?;
        let rollback = data_dir.join(&rollback_name);
        match fs::create_dir(&rollback) {
            Ok(()) => crate::paths::tighten_private_dir(&rollback)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                crate::paths::tighten_private_dir(&rollback)?
            }
            Err(error) => return Err(error.to_string()),
        }
        for name in ARCHIVE_FILES
            .into_iter()
            .chain(["secret", "votport.db-wal", "votport.db-shm"])
        {
            let current = data_dir.join(name);
            let saved = rollback.join(name);
            match (
                fs::symlink_metadata(&current).is_ok(),
                fs::symlink_metadata(&saved).is_ok(),
            ) {
                (true, false) => fs::rename(&current, &saved).map_err(|e| e.to_string())?,
                (false, true) | (false, false) => {}
                (true, true) => return Err(format!("restore rollback already contains {name}")),
            }
        }
        sync_directory(data_dir)?;
        sync_directory(&rollback)?;
        marker.phase = RestorePhase::OldMoved;
        persist_pending_restore(data_dir, &marker)?;
    }

    if marker.phase == RestorePhase::OldMoved {
        for entry in &marker.manifest.entries {
            let source = stage.join(&entry.name);
            let installed = data_dir.join(&entry.name);
            match (
                fs::symlink_metadata(&source).is_ok(),
                fs::symlink_metadata(&installed).is_ok(),
            ) {
                (true, false) => {
                    let (size, hash) = file_hash(&source)?;
                    if size != entry.size || hash != entry.sha256 {
                        return Err(format!("staged restore file is invalid: {}", entry.name));
                    }
                    fs::rename(&source, &installed).map_err(|e| e.to_string())?
                }
                (false, true) => {
                    let (size, hash) = file_hash(&installed)?;
                    if size != entry.size || hash != entry.sha256 {
                        return Err(format!("installed restore file is invalid: {}", entry.name));
                    }
                }
                (false, false) => return Err(format!("restore file is missing: {}", entry.name)),
                (true, true) => return Err(format!("restore file exists twice: {}", entry.name)),
            }
        }
        validate_database(
            &data_dir.join("votport.db"),
            marker.manifest.schema_version,
            schema_version,
        )?;
        sync_directory(data_dir)?;
        sync_directory(&stage)?;
        marker.phase = RestorePhase::NewInstalled;
        persist_pending_restore(data_dir, &marker)?;
    }

    prepare_restored_database(&data_dir.join("votport.db"), schema_version, marker.mode)?;
    write_secrets(data_dir, &BackupSecrets::default())?;
    write_status(data_dir, BackupStatus::default())?;

    // Restoring data must invalidate every pre-restore browser session. If a
    // crash occurs after this write, the existing new secret is retained.
    let secret = data_dir.join("secret");
    if !fs::symlink_metadata(&secret).is_ok() {
        let mut rotated = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut rotated);
        crate::auth::write_private(&secret, &rotated).map_err(|e| e.to_string())?;
    } else {
        crate::paths::tighten_private_file(&secret)?;
    }
    for name in ["votport.db-wal", "votport.db-shm"] {
        match fs::remove_file(data_dir.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    sync_directory(data_dir)?;
    if stage.exists() {
        fs::remove_dir_all(&stage).map_err(|e| e.to_string())?;
    }
    fs::remove_file(marker_path).map_err(|e| e.to_string())?;
    sync_directory(data_dir)?;
    // A boot restore used to be silent between the marker and the next
    // login: name the archive it installed here (audit finding 494).
    let applied = AppliedRestore {
        archive: marker.archive.clone(),
        created_at: marker.manifest.created_at,
        mode: marker.mode,
        schema_version: marker.manifest.schema_version,
    };
    tracing::info!(
        target: "audit",
        event = "backup_restore_applied",
        id = applied.archive.as_deref().unwrap_or("unknown"),
        mode = applied.mode.label(),
        created_at = applied.created_at,
        schema_version = applied.schema_version,
        "backup restore applied at boot"
    );
    Ok(Some(applied))
}

/// Lands the audit row for a boot-applied restore into the freshly restored
/// store, so the log no longer jumps from the last pre-backup entry to the
/// next login without marking the gap (audit finding 494).
pub(crate) fn record_applied_restore(store: &crate::store::Store, applied: &AppliedRestore) {
    store.audit(
        "",
        "",
        "backup_restore_applied",
        applied.archive.as_deref().unwrap_or_default(),
        &serde_json::json!({
            "mode": applied.mode.label(),
            "created_at": applied.created_at,
            "schema_version": applied.schema_version,
        }),
    );
}

/// Reconciles the restored records against the receive tree (audit finding
/// 498): a restore rolls the database back, so payloads and receipts
/// published after the backup stay on disk with no record, while live
/// records can name payloads removed since the backup. Stats the live
/// records after install, tombstones the records whose payload is gone
/// (audit finding 373) and reports both gaps in one audit row so holdings
/// and disk can be reconciled deliberately instead of silently disagreeing.
pub(crate) fn survey_restored_payloads(store: &crate::store::Store, receive_dir: &Path) {
    if !receive_dir.try_exists().unwrap_or(false) {
        return;
    }
    let records: Vec<(String, String)> = match store.with(|connection| {
        connection
            .prepare("SELECT tenant, stored_as FROM files WHERE deleted = 0 AND stored_as <> ''")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()
    }) {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "restored payload survey could not read records");
            return;
        }
    };
    let referenced: HashSet<String> = records
        .iter()
        .map(|(tenant, stored_as)| crate::paths::stored_components(tenant, stored_as).join("/"))
        .collect();
    let mut on_disk = HashSet::new();
    let mut unreadable = Vec::new();
    let walked = collect_payload_files(receive_dir, "", &mut on_disk, &mut unreadable)
        .map_err(|error| tracing::warn!(%error, "restored payload survey could not read the receive tree"))
        .is_ok();
    // A folder the service may not list (lost+found, System Volume
    // Information) says nothing about the records under it.
    let missing: Vec<&String> = referenced
        .difference(&on_disk)
        .filter(|path| {
            !unreadable
                .iter()
                .any(|prefix| path.starts_with(&format!("{prefix}/")))
        })
        .collect();
    let unreferenced: Vec<&String> = on_disk.difference(&referenced).collect();
    // A tree that could not be read, or that holds no payload at all while
    // live records exist, is a volume that is not there yet (unmounted, not
    // restored), not proof every payload is gone; tombstoning then would
    // erase the index permanently. Report only.
    let trusted = walked && !(on_disk.is_empty() && !records.is_empty());
    // Audit finding 373: a restored record whose payload is gone would stay
    // listed, charged against quota and targeted by retention on a path that
    // no longer holds its bytes. Tombstone the stat-misses now, while the
    // restored database is still closed to sessions.
    let mut tombstoned = 0usize;
    if trusted && !missing.is_empty() {
        let missing_set: HashSet<&String> = missing.iter().copied().collect();
        let stale: Vec<(&String, &String)> = records
            .iter()
            .filter(|(tenant, stored_as)| {
                missing_set.contains(&crate::paths::stored_components(tenant, stored_as).join("/"))
            })
            .map(|(tenant, stored_as)| (tenant, stored_as))
            .collect();
        tombstoned = match store.with(|connection| {
            let mut statement = connection.prepare(
                "UPDATE files SET deleted=1, path='' WHERE tenant=?1 AND stored_as=?2 AND deleted=0",
            )?;
            let mut changed = 0usize;
            for (tenant, stored_as) in stale {
                changed += statement.execute(rusqlite::params![tenant, stored_as])?;
            }
            Ok(changed)
        }) {
            Ok(changed) => changed,
            Err(error) => {
                tracing::warn!(%error, "restored payload survey could not tombstone missing records");
                0
            }
        };
    }
    if missing.is_empty() && unreferenced.is_empty() {
        return;
    }
    let detail = serde_json::json!({
        "missing_count": missing.len(),
        "missing": sample_names(&missing),
        "unreferenced_count": unreferenced.len(),
        "unreferenced": sample_names(&unreferenced),
        "tombstoned": tombstoned,
        "receive_tree_trusted": trusted,
        "unreadable": unreadable.iter().take(8).collect::<Vec<_>>(),
    });
    tracing::warn!(
        target: "audit",
        event = "restore_payload_mismatch",
        missing = missing.len(),
        unreferenced = unreferenced.len(),
        tombstoned,
        "restored records and receive tree disagree"
    );
    store.audit("", "", "restore_payload_mismatch", "", &detail);
}

/// Every payload file under the receive root, as receive-root-relative
/// paths. Upload staging and the instance lease are machinery, not payloads;
/// a receipt sidecar rides with its payload, so only the payload is named.
fn collect_payload_files(
    directory: &Path,
    prefix: &str,
    out: &mut HashSet<String>,
    unreadable: &mut Vec<String>,
) -> std::io::Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        // Below the root, a folder the service may not list is noted and
        // skipped; any other failure, or an unreadable root, stops the walk.
        Err(error)
            if !prefix.is_empty() && error.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            unreadable.push(prefix.to_owned());
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let directory = metadata.is_dir();
        let file = metadata.is_file();
        if directory && (name == ".vot-stage" || crate::protocol_paths::is_push_staging_name(&name))
        {
            continue;
        }
        if file && crate::protocol_paths::is_receipt_name(&name) {
            continue;
        }
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if directory {
            collect_payload_files(&entry.path(), &relative, out, unreadable)?;
        } else if file {
            out.insert(relative);
        }
    }
    Ok(())
}

/// Bounds the audit row: a wide mismatch still names a inspectable sample.
fn sample_names(names: &[&String]) -> Vec<String> {
    const SAMPLE: usize = 8;
    names
        .iter()
        .take(SAMPLE)
        .map(|name| (*name).clone())
        .collect()
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn backup_filename(encrypted: bool) -> String {
    format!(
        "votport-backup-v2-{}-{}.tar{}",
        now(),
        crate::auth::random_token(),
        if encrypted { ".age" } else { "" }
    )
}

pub fn legacy_snapshot_filename() -> String {
    format!("votport-{}-{}.db", now(), &crate::auth::random_token()[..8])
}

pub fn owned_legacy_snapshot(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix("votport-")
        .and_then(|name| name.strip_suffix(".db"))
    else {
        return false;
    };
    let Some((timestamp, token)) = stem.split_once('-') else {
        return false;
    };
    timestamp
        .parse::<u64>()
        .is_ok_and(|value| value.to_string() == timestamp)
        && token.len() == 8
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
pub(crate) fn ensure_backups_dir(data_dir: &Path) -> Result<PathBuf, String> {
    ensure_backup_root(&data_dir.join("backups"))
}
pub fn ensure_backup_root(path: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    crate::paths::tighten_private_dir(path)?;
    validate_private_ancestry(path, Some(path))?;
    Ok(path.to_path_buf())
}

pub fn prune_local_root(
    root: &Path,
    retention_days: u64,
    retention_count: u64,
) -> Result<(), String> {
    let Some(_lock) = try_lock_backup_root(root)? else {
        return Err("backup root is busy".into());
    };
    prune_local_root_protected(root, retention_days, retention_count, None)
}

fn prune_local_root_protected(
    root: &Path,
    retention_days: u64,
    retention_count: u64,
    protected_id: Option<&str>,
) -> Result<(), String> {
    prune_local_root_protected_at(
        root,
        retention_days,
        retention_count,
        protected_id,
        SystemTime::now(),
    )
}

fn prune_local_root_protected_at(
    root: &Path,
    retention_days: u64,
    retention_count: u64,
    protected_id: Option<&str>,
    now: SystemTime,
) -> Result<(), String> {
    let root = ensure_backup_root(root)?;
    let mut files = local_files(&root)?;
    files.sort_by(|left, right| {
        (right.0.as_str() == protected_id.unwrap_or_default())
            .cmp(&(left.0.as_str() == protected_id.unwrap_or_default()))
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| right.0.cmp(&left.0))
    });
    let cutoff = now
        .checked_sub(std::time::Duration::from_secs(
            retention_days.saturating_mul(86_400),
        ))
        .unwrap_or(UNIX_EPOCH);
    for (index, (name, _, created, path)) in files.iter().enumerate() {
        if protected_id == Some(name.as_str()) {
            continue;
        }
        if (retention_days > 0 && *created < cutoff)
            || (retention_count > 0 && index >= retention_count as usize)
        {
            fs::remove_file(path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// While the remote copy of a Both backup keeps failing, each retry adds a
/// full local archive. Keeps every archive from before the last complete
/// run untouched, as the restore points the outage must not rotate away,
/// and of the archives taken since, only the newest (`keep`).
fn prune_outage_copies(root: &Path, last_success: u64, keep: &str) -> Result<(), String> {
    for (name, _, created, path) in local_files(root)? {
        // Whole seconds, like the recorded success, so the archive of that
        // successful run is never mistaken for a copy taken after it.
        let created = created
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        if name != keep && created > last_success {
            fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
    }
    sync_directory(root)
}

fn local_files(root: &Path) -> Result<Vec<(String, u64, SystemTime, PathBuf)>, String> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !owned_name(&name) {
            continue;
        }
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            continue;
        }
        let created = meta.modified().unwrap_or(UNIX_EPOCH);
        files.push((name, meta.len(), created, entry.path()));
    }
    Ok(files)
}

fn s3_root(config: &BackupConfig) -> String {
    config
        .s3_prefix
        .as_deref()
        .map(|prefix| format!("{prefix}/"))
        .unwrap_or_default()
}

fn s3_path(config: &BackupConfig, id: &str) -> ObjectPath {
    ObjectPath::from(format!("{}{id}", s3_root(config)))
}

fn owned_s3_id<'a>(config: &BackupConfig, location: &'a ObjectPath) -> Option<&'a str> {
    let location = location.as_ref();
    let id = location.strip_prefix(&s3_root(config))?;
    (!id.contains('/') && owned_name(id)).then_some(id)
}

pub async fn upload_s3(
    config: &BackupConfig,
    secrets: &BackupSecrets,
    local: &Path,
    id: &str,
) -> Result<(), String> {
    let store = s3_store(config, secrets)?;
    let path = s3_path(config, id);
    let mut file = tokio::fs::File::from_std(open_regular_nofollow(local)?);
    let mut upload = store
        .put_multipart(&path)
        .await
        .map_err(|_| "S3 upload could not start".to_owned())?;
    upload_file_parts(&mut upload, &mut file).await
}

async fn upload_file_parts(
    upload: &mut Box<dyn MultipartUpload>,
    file: &mut tokio::fs::File,
) -> Result<(), String> {
    let mut part = 0usize;
    loop {
        let mut buf = vec![0u8; PART_SIZE];
        let n = match tokio::io::AsyncReadExt::read(file, &mut buf).await {
            Ok(n) => n,
            Err(_) => {
                abort_upload_parts(upload, part, "reading the backup file").await;
                return Err("backup file could not be read".into());
            }
        };
        if n == 0 {
            break;
        }
        part += 1;
        if upload.put_part(buf[..n].to_vec().into()).await.is_err() {
            abort_upload_parts(upload, part, "uploading a part").await;
            return Err("S3 upload failed".into());
        }
    }
    if upload.complete().await.is_err() {
        abort_upload_parts(upload, part, "completing the upload").await;
        return Err("S3 upload failed".into());
    }
    Ok(())
}

/// Reports a failed multipart abort before the upload gives up: unfinished
/// parts stay in the store until its lifecycle expires them, so the failure
/// must be visible. The log names the stage and part count, not the object.
async fn abort_upload_parts(
    upload: &mut Box<dyn MultipartUpload>,
    parts: usize,
    stage: &'static str,
) {
    if let Err(error) = upload.abort().await {
        tracing::warn!(
            stage,
            parts,
            reason = abort_failure_class(&error),
            "multipart abort failed; unfinished parts stay until the store expires them"
        );
    }
}

/// Class of an S3 abort failure: object_store Display strings carry the
/// object path and endpoint URL, so only the failure class is logged.
fn abort_failure_class(error: &object_store::Error) -> &'static str {
    match error {
        object_store::Error::NotFound { .. }
        | object_store::Error::AlreadyExists { .. }
        | object_store::Error::NotModified { .. }
        | object_store::Error::Precondition { .. } => {
            "the store answered the abort with a conflicting object state"
        }
        object_store::Error::PermissionDenied { .. }
        | object_store::Error::Unauthenticated { .. } => "the store refused the abort",
        object_store::Error::NotSupported { .. } | object_store::Error::NotImplemented { .. } => {
            "the store cannot abort uploads"
        }
        _ => "the store abort request failed",
    }
}

fn s3_store(
    config: &BackupConfig,
    secrets: &BackupSecrets,
) -> Result<Arc<dyn ObjectStore>, String> {
    let endpoint = config
        .s3_endpoint
        .as_deref()
        .ok_or("S3 endpoint is required")?;
    let access = secrets
        .access_key_id
        .as_deref()
        .ok_or("S3 credentials are not configured")?;
    let secret = secrets
        .secret_access_key
        .as_deref()
        .ok_or("S3 credentials are not configured")?;
    let mut builder = AmazonS3Builder::new()
        .with_endpoint(endpoint)
        .with_bucket_name(config.s3_bucket.as_deref().ok_or("S3 bucket is required")?)
        .with_access_key_id(access)
        .with_secret_access_key(secret);
    if let Some(region) = &config.s3_region {
        builder = builder.with_region(region);
    }
    builder = builder.with_virtual_hosted_style_request(!config.s3_path_style);
    builder = crate::api::outbound::workflows::storage::client_settings(builder, endpoint);
    Ok(Arc::new(
        builder
            .build()
            .map_err(|_| "invalid S3 configuration".to_owned())?,
    ))
}

pub async fn download_s3(
    config: &BackupConfig,
    secrets: &BackupSecrets,
    id: &str,
    destination: &Path,
) -> Result<(), String> {
    let store = s3_store(config, secrets)?;
    let path = s3_path(config, id);
    use futures_util::StreamExt;
    let mut stream = store
        .get(&path)
        .await
        .map_err(|_| "S3 backup download failed".to_owned())?
        .into_stream();
    let mut cleanup = CleanupPath::new(destination.to_path_buf());
    let mut file =
        tokio::fs::File::from_std(create_private_new(destination).map_err(|e| e.to_string())?);
    use tokio::io::AsyncWriteExt;
    while let Some(chunk) = stream.next().await {
        file.write_all(&chunk.map_err(|_| "S3 backup download failed".to_owned())?)
            .await
            .map_err(|e| e.to_string())?;
    }
    file.sync_all().await.map_err(|e| e.to_string())?;
    cleanup.keep();
    Ok(())
}

pub async fn inventory_s3(
    config: &BackupConfig,
    secrets: &BackupSecrets,
) -> Result<Vec<InventoryItem>, String> {
    let store = s3_store(config, secrets)?;
    let mut result = Vec::new();
    for item in list_s3_backups(&*store, config, MAX_S3_LIST_ENTRIES, S3_LIST_TIMEOUT).await? {
        let Some(id) = owned_s3_id(config, &item.location) else {
            continue;
        };
        result.push(InventoryItem {
            id: id.to_owned(),
            source: "s3",
            bytes: item.size,
            created_at: item.last_modified.timestamp().max(0) as u64,
        });
    }
    result.sort_by_key(|b| std::cmp::Reverse(b.created_at));
    Ok(result)
}

async fn list_s3_backups(
    store: &dyn ObjectStore,
    config: &BackupConfig,
    max_entries: usize,
    timeout: std::time::Duration,
) -> Result<Vec<object_store::ObjectMeta>, String> {
    use futures_util::StreamExt;
    tokio::time::timeout(timeout, async {
        let root = s3_root(config);
        let list_prefix = (!root.is_empty()).then(|| ObjectPath::from(root));
        let mut stream = store.list(list_prefix.as_ref());
        let mut files = Vec::new();
        let mut seen = 0;
        while let Some(item) = stream.next().await {
            let item = item.map_err(|_| "S3 backup listing failed".to_owned())?;
            if seen == max_entries {
                return Err(format!("S3 backup listing exceeds {max_entries} objects; use a dedicated backup prefix"));
            }
            seen += 1;
            if owned_s3_id(config, &item.location).is_some() {
                files.push(item);
            }
        }
        Ok(files)
    })
    .await
    .map_err(|_| "S3 backup listing timed out".to_owned())?
}

pub async fn prune_s3(
    config: &BackupConfig,
    secrets: &BackupSecrets,
    retention_days: u64,
    retention_count: u64,
    protected_id: Option<&str>,
) -> Result<(), String> {
    let store = s3_store(config, secrets)?;
    prune_s3_store(
        store,
        config,
        s3_age_cutoff(now(), retention_days),
        retention_count,
        protected_id,
        MAX_S3_LIST_ENTRIES,
        S3_LIST_TIMEOUT,
    )
    .await
}

fn s3_age_cutoff(now: u64, days: u64) -> Option<i64> {
    (days > 0)
        .then(|| i64::try_from(now.saturating_sub(days.saturating_mul(86_400))).unwrap_or(i64::MAX))
}

async fn prune_s3_store(
    store: Arc<dyn ObjectStore>,
    config: &BackupConfig,
    age_cutoff: Option<i64>,
    retention_count: u64,
    protected_id: Option<&str>,
    max_entries: usize,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let mut files = list_s3_backups(&*store, config, max_entries, timeout).await?;
    files.sort_by(|left, right| {
        let left_id = owned_s3_id(config, &left.location).unwrap_or_default();
        let right_id = owned_s3_id(config, &right.location).unwrap_or_default();
        (right_id == protected_id.unwrap_or_default())
            .cmp(&(left_id == protected_id.unwrap_or_default()))
            .then_with(|| right.last_modified.cmp(&left.last_modified))
            .then_with(|| right.location.cmp(&left.location))
    });
    for (index, item) in files.into_iter().enumerate() {
        if owned_s3_id(config, &item.location) == protected_id {
            continue;
        }
        if age_cutoff.is_some_and(|cutoff| item.last_modified.timestamp() < cutoff)
            || (retention_count > 0 && index >= retention_count as usize)
        {
            store
                .delete(&item.location)
                .await
                .map_err(|_| "S3 pruning failed".to_owned())?;
        }
    }
    Ok(())
}

/// Audit finding 371: an operator must be able to discard a backup copy, or
/// every pre-erasure archive keeps the full database restorable forever.
pub fn delete_local_backup(root: &Path, id: &str) -> Result<bool, String> {
    validate_id(id)?;
    let root = ensure_backup_root(root)?;
    let Some(_lock) = try_lock_backup_root(&root)? else {
        return Err("backup root is busy".into());
    };
    let path = root.join(id);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    if !meta.is_file() {
        return Ok(false);
    }
    fs::remove_file(&path).map_err(|e| e.to_string())?;
    sync_directory(&root)?;
    Ok(true)
}

/// Audit finding 371: the S3 half of the on-demand backup deletion.
pub async fn delete_s3_backup(
    config: &BackupConfig,
    secrets: &BackupSecrets,
    id: &str,
) -> Result<bool, String> {
    validate_id(id)?;
    let store = s3_store(config, secrets)?;
    match store.delete(&s3_path(config, id)).await {
        Ok(()) => Ok(true),
        Err(object_store::Error::NotFound { .. }) => Ok(false),
        Err(_) => Err("S3 backup deletion failed".to_owned()),
    }
}

pub fn inventory_local_root(root: &Path, data_dir: &Path) -> Result<Vec<InventoryItem>, String> {
    validate_private_ancestry(root, local_root_ancestry_stop(root, data_dir))?;
    let mut result = Vec::new();
    for (id, bytes, created_at, _) in local_files(root)? {
        let created_at = created_at
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        result.push(InventoryItem {
            id,
            source: "local",
            bytes,
            created_at,
        });
    }
    result.sort_by_key(|b| std::cmp::Reverse(b.created_at));
    Ok(result)
}

/// Record durable scheduler state around a single maintenance run.
pub async fn run(
    app: Arc<crate::app::App>,
    config: BackupConfig,
    secrets: BackupSecrets,
) -> Result<String, String> {
    let guard = Arc::clone(&app.backup_lock)
        .try_lock_owned()
        .map_err(|_| "backup already running".to_owned())?;
    run_with_guard(app, config, secrets, guard).await
}

pub(crate) async fn run_with_guard(
    app: Arc<crate::app::App>,
    config: BackupConfig,
    secrets: BackupSecrets,
    guard: tokio::sync::OwnedMutexGuard<()>,
) -> Result<String, String> {
    tokio::spawn(run_operation(app, config, secrets, guard))
        .await
        .map_err(|error| format!("backup operation task failed: {error}"))?
}

async fn run_operation(
    app: Arc<crate::app::App>,
    config: BackupConfig,
    secrets: BackupSecrets,
    _guard: tokio::sync::OwnedMutexGuard<()>,
) -> Result<String, String> {
    ensure_no_pending_restore(&app.config.data_dir)?;
    let retention = app.retention_observation()?;
    let mut status = read_status(&app.config.data_dir).unwrap_or_default();
    status.last_attempt_at = Some(now());
    status.last_error = None;
    write_status(&app.config.data_dir, status.clone())?;
    let result = run_inner(Arc::clone(&app), config, secrets, retention).await;
    match result {
        Ok(id) => {
            status.last_success_at = Some(now());
            status.last_error = None;
            write_status(&app.config.data_dir, status)?;
            Ok(id)
        }
        Err(error) => {
            if error.copies_complete {
                status.last_success_at = Some(now());
            }
            status.last_error = Some(error.message.chars().take(512).collect());
            write_status(&app.config.data_dir, status)?;
            Err(error.message)
        }
    }
}

struct RunFailure {
    message: String,
    copies_complete: bool,
}

impl RunFailure {
    fn before(message: impl ToString) -> Self {
        Self {
            message: message.to_string(),
            copies_complete: false,
        }
    }

    fn after(message: impl ToString, copies_complete: bool) -> Self {
        Self {
            message: message.to_string(),
            copies_complete,
        }
    }
}

/// Build once in a private staging name, atomically publish the local object,
/// then upload that exact object to S3 if requested.
async fn run_inner(
    app: Arc<crate::app::App>,
    config: BackupConfig,
    secrets: BackupSecrets,
    retention: crate::app::RetentionObservation,
) -> Result<String, RunFailure> {
    config
        .validate(&app.config.data_dir)
        .map_err(RunFailure::before)?;
    let backups = config
        .local_root(&app.config.data_dir)
        .map_err(RunFailure::before)?;
    let backups = ensure_backup_root(&backups).map_err(RunFailure::before)?;
    let Some(root_lock) = try_lock_backup_root(&backups).map_err(RunFailure::before)? else {
        return Err(RunFailure::before("backup root is busy"));
    };
    let encrypted = config.encrypt;
    if encrypted && secrets.passphrase.is_none() {
        return Err(RunFailure::before(
            "encryption passphrase is not configured",
        ));
    }
    let id = backup_filename(encrypted);
    let final_path = backups.join(&id);
    let stage_token = crate::auth::random_token();
    let raw = backups.join(format!("{BACKUP_ROOT_STAGE_PREFIX}{stage_token}.tar"));
    let store = Arc::clone(&app.store);
    let data_dir = app.config.data_dir.clone();
    let archive_data_dir = data_dir.clone();
    let raw_for_archive = raw.clone();
    let root_file = Arc::clone(&root_lock.file);
    tokio::task::spawn_blocking(move || {
        let _root_file = root_file;
        let result = create_archive(
            &store,
            &archive_data_dir,
            &raw_for_archive,
            crate::store::SCHEMA_VERSION,
        );
        #[cfg(test)]
        pause_backup_worker(&archive_data_dir, BackupPausePoint::Archive);
        result
    })
    .await
    .map_err(RunFailure::before)?
    .map_err(RunFailure::before)?;
    let mut raw_cleanup = CleanupPath::new(raw.clone());
    let mut final_cleanup = CleanupPath::new(final_path.clone());
    if encrypted {
        let pass = secrets
            .passphrase
            .as_deref()
            .ok_or_else(|| RunFailure::before("encryption passphrase is not configured"))?
            .to_owned();
        let input = raw.clone();
        let output = backups.join(format!("{BACKUP_ROOT_STAGE_PREFIX}{stage_token}.tar.age"));
        let _output_cleanup = CleanupPath::new(output.clone());
        let published = final_path.clone();
        let output_for_encrypt = output.clone();
        let root_file = Arc::clone(&root_lock.file);
        #[cfg(test)]
        let encrypt_data_dir = data_dir;
        tokio::task::spawn_blocking(move || {
            let _root_file = root_file;
            let result = encrypt_file(&input, &output_for_encrypt, &pass);
            #[cfg(test)]
            pause_backup_worker(&encrypt_data_dir, BackupPausePoint::Encrypt);
            result
        })
        .await
        .map_err(RunFailure::before)?
        .map_err(RunFailure::before)?;
        fs::remove_file(&raw).map_err(RunFailure::before)?;
        raw_cleanup.keep();
        publish_new(&output, &published).map_err(RunFailure::before)?;
    } else {
        publish_new(&raw, &final_path).map_err(RunFailure::before)?;
        raw_cleanup.keep();
    }
    sync_directory(&backups).map_err(RunFailure::before)?;
    let mut copies_complete = false;
    let retention_days = if retention.allow_age {
        config.retention_days
    } else {
        0
    };
    let prune_local = |copies_complete| {
        prune_local_root_protected_at(
            &backups,
            retention_days,
            config.retention_count,
            Some(&id),
            UNIX_EPOCH + std::time::Duration::from_secs(retention.effective_at),
        )
        .map_err(|error| RunFailure::after(error, copies_complete))
    };
    if matches!(config.destination, Destination::Local | Destination::Both) {
        final_cleanup.keep();
        copies_complete = config.destination == Destination::Local;
    }
    if config.destination == Destination::Local {
        prune_local(copies_complete)?;
    }
    if matches!(config.destination, Destination::S3 | Destination::Both) {
        if let Err(error) = upload_s3(&config, &secrets, &final_path, &id).await {
            if config.destination == Destination::Both {
                let last_success = read_status(&app.config.data_dir)
                    .ok()
                    .and_then(|status| status.last_success_at);
                // With no complete run on record (after a restore, or an
                // unreadable status) nothing marks where the outage began,
                // so the ordinary count and age rule bounds the copies.
                let pruned = match last_success {
                    Some(at) => prune_outage_copies(&backups, at, &id),
                    None => prune_local(false).map_err(|failure| failure.message),
                };
                if let Err(prune) = pruned {
                    tracing::warn!(error = %prune, "local backups taken during the remote outage could not be pruned");
                }
            }
            return Err(RunFailure::after(error, copies_complete));
        }
        copies_complete = true;
    }
    // With both destinations, local archives rotate only once the remote
    // copy exists: a failing remote is retried every few minutes, and
    // pruning by count on each retry would replace every pre-outage restore
    // point with copies of the current state.
    if config.destination == Destination::Both {
        prune_local(copies_complete)?;
    }
    if matches!(config.destination, Destination::S3) {
        fs::remove_file(&final_path).map_err(|error| RunFailure::after(error, copies_complete))?;
        final_cleanup.keep();
    }
    if matches!(config.destination, Destination::S3 | Destination::Both) {
        let store = s3_store(&config, &secrets)
            .map_err(|error| RunFailure::after(error, copies_complete))?;
        prune_s3_store(
            store,
            &config,
            s3_age_cutoff(retention.effective_at, retention_days),
            config.retention_count,
            Some(&id),
            MAX_S3_LIST_ENTRIES,
            S3_LIST_TIMEOUT,
        )
        .await
        .map_err(|error| RunFailure::after(error, copies_complete))?;
    }
    Ok(id)
}

fn scheduler_due(config: &BackupConfig, status: &BackupStatus, timestamp: u64) -> bool {
    if !config.enabled {
        return false;
    }
    if status.last_error.is_some()
        && status
            .last_attempt_at
            .is_some_and(|last_attempt| timestamp.saturating_sub(last_attempt) < 300)
    {
        return false;
    }
    if let Some(last_success) = status.last_success_at {
        return timestamp.saturating_sub(last_success) >= config.interval_secs;
    }
    true
}

fn backup_lock_warning_due(
    busy_since: &mut Option<std::time::Instant>,
    config: &BackupConfig,
    timestamp: std::time::Instant,
) -> bool {
    if !config.enabled {
        *busy_since = None;
        return false;
    }
    let since = busy_since.get_or_insert(timestamp);
    if timestamp.duration_since(*since) < std::time::Duration::from_secs(config.interval_secs) {
        return false;
    }
    *since = timestamp;
    true
}

pub async fn scheduler(app: Arc<crate::app::App>) {
    scheduler_with_interval(app, std::time::Duration::from_secs(60)).await;
}

async fn scheduler_with_interval(app: Arc<crate::app::App>, interval: std::time::Duration) {
    let mut busy_since = None;
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = app.wait_for_shutdown() => return,
            _ = ticker.tick() => {}
        }
        if app.is_stopping() {
            return;
        }
        let Ok(guard) = Arc::clone(&app.backup_lock).try_lock_owned() else {
            match app
                .store
                .setting(SETTING_KEY)
                .map_err(|error| error.to_string())
                .and_then(|setting| parse_config(setting, &app.config.data_dir))
            {
                Ok(config) => {
                    if backup_lock_warning_due(&mut busy_since, &config, std::time::Instant::now())
                    {
                        tracing::warn!(
                            interval_secs = config.interval_secs,
                            "backup scheduler repeatedly deferred because maintenance lock is busy"
                        );
                    }
                }
                Err(error) => tracing::error!("backup scheduler config while waiting: {error}"),
            }
            continue;
        };
        if app.is_stopping() {
            return;
        }
        busy_since = None;
        if let Err(error) = ensure_no_pending_restore(&app.config.data_dir) {
            tracing::error!("backup scheduler paused: {error}");
            continue;
        }
        let setting = match app.store.setting(SETTING_KEY) {
            Ok(setting) => setting,
            Err(error) => {
                tracing::error!("backup scheduler settings: {error}");
                continue;
            }
        };
        let config = match parse_config(setting, &app.config.data_dir) {
            Ok(config) => config,
            Err(error) => {
                tracing::error!("backup scheduler config: {error}");
                continue;
            }
        };
        let status = match read_status(&app.config.data_dir) {
            Ok(status) => status,
            Err(error) => {
                tracing::error!("backup scheduler status: {error}");
                continue;
            }
        };
        if !scheduler_due(&config, &status, now()) {
            continue;
        }
        let secrets = match read_secrets(&app.config.data_dir) {
            Ok(s) => s,
            Err(error) => {
                tracing::error!("backup secrets: {error}");
                continue;
            }
        };
        if app.is_stopping() {
            return;
        }
        match run_with_guard(Arc::clone(&app), config, secrets, guard).await {
            Ok(id) => {
                tracing::info!(target: "audit", event = "backup_scheduled", id = %id, "scheduled backup completed");
            }
            Err(error) => tracing::error!("scheduled backup: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct ReapedChild(Option<std::process::Child>);

    impl ReapedChild {
        fn new(child: std::process::Child) -> Self {
            Self(Some(child))
        }

        fn wait_bounded(
            &mut self,
            timeout: std::time::Duration,
        ) -> std::io::Result<std::process::ExitStatus> {
            let deadline = std::time::Instant::now() + timeout;
            loop {
                let status = self.0.as_mut().expect("child already reaped").try_wait()?;
                if let Some(status) = status {
                    self.0 = None;
                    return Ok(status);
                }
                if std::time::Instant::now() >= deadline {
                    let child = self.0.as_mut().expect("child already reaped");
                    let _ = child.kill();
                    let status = child.wait()?;
                    self.0 = None;
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("child did not exit after {timeout:?}: {status}"),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }

    impl Drop for ReapedChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn install_backup_pause(
        data_dir: &Path,
        point: BackupPausePoint,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        BACKUP_WORKER_PAUSE
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .unwrap()
            .push(BackupWorkerPause {
                data_dir: data_dir.to_owned(),
                point,
                started: started_tx,
                release: release_rx,
            });
        (started_rx, release_tx)
    }

    #[test]
    fn failed_multipart_abort_is_reported_without_changing_the_outcome() {
        #[derive(Debug)]
        struct FailingAbortMultipart {
            aborts: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl MultipartUpload for FailingAbortMultipart {
            fn put_part(&mut self, _data: object_store::PutPayload) -> object_store::UploadPart {
                Box::pin(async {
                    Err(object_store::Error::Generic {
                        store: "test",
                        source: Box::new(io::Error::other("part failed")),
                    })
                })
            }

            async fn complete(&mut self) -> object_store::Result<object_store::PutResult> {
                Err(object_store::Error::Generic {
                    store: "test",
                    source: Box::new(io::Error::other("complete failed")),
                })
            }

            async fn abort(&mut self) -> object_store::Result<()> {
                self.aborts.store(true, Ordering::SeqCst);
                Err(object_store::Error::Generic {
                    store: "test",
                    source: Box::new(io::Error::other("abort refused by the test store")),
                })
            }
        }

        let aborts = Arc::new(AtomicBool::new(false));
        let mut upload: Box<dyn MultipartUpload> = Box::new(FailingAbortMultipart {
            aborts: Arc::clone(&aborts),
        });
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"part bytes").unwrap();
        let file = std::fs::File::open(file.path()).unwrap();

        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        let result = tracing::subscriber::with_default(subscriber, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let mut file = tokio::fs::File::from_std(file);
                    upload_file_parts(&mut upload, &mut file).await
                })
        });
        assert!(
            result.is_err(),
            "the upload still fails when aborting fails"
        );
        assert!(aborts.load(Ordering::SeqCst), "abort was attempted");
        let warns: Vec<String> = std::fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .filter(|line| line.contains("multipart abort failed"))
            .map(str::to_owned)
            .collect();
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(warns[0].contains("uploading a part"), "{}", warns[0]);
        assert!(warns[0].contains("\"parts\":1"), "{}", warns[0]);
        assert!(
            !warns[0].contains("refused by the test store"),
            "abort error detail leaked: {}",
            warns[0]
        );
    }

    fn initialized_root() -> (tempfile::TempDir, crate::store::Store) {
        let root = tempfile::tempdir().unwrap();
        crate::paths::tighten_private_dir(root.path()).unwrap();
        let store = crate::store::Store::open(root.path()).unwrap();
        fs::write(root.path().join("secret"), [7; 32]).unwrap();
        crate::paths::tighten_private_file(&root.path().join("secret")).unwrap();
        fs::write(root.path().join("receipt.key"), [8; 32]).unwrap();
        crate::paths::tighten_private_file(&root.path().join("receipt.key")).unwrap();
        (root, store)
    }

    /// Audit finding 498: after a restore, live records can name payloads
    /// that are gone while post-backup payloads sit on disk unreferenced.
    /// The survey must report both, and nothing else, exactly once.
    #[test]
    fn restored_payload_survey_reports_both_gaps_in_one_audit_row() {
        let (root, store) = initialized_root();
        let receive = root.path().join("received");
        store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,
                        deleted,stored_as,path,suite,root,receipt)
                     VALUES ('link-gone','','upload-gone',0,0,20,0,'gone.bin','gone.bin','md5','root',0)",
                    [],
                )
            })
            .unwrap();
        std::fs::create_dir_all(receive.join("sub")).unwrap();
        fs::write(receive.join("sub/kept.bin"), [0u8; 64]).unwrap();
        fs::write(receive.join("sub/kept.bin.vot-receipt"), b"signed").unwrap();
        // Staging machinery and an unrelated tenant namespace stay unreported.
        std::fs::create_dir_all(receive.join(".vot-stage")).unwrap();
        fs::write(receive.join(".vot-stage/lease"), b"lease").unwrap();

        survey_restored_payloads(&store, &receive);

        let rows = store.audit_export(None, 0, 0, 100).unwrap();
        let rows: Vec<_> = rows
            .into_iter()
            .filter(|row| row.event == "restore_payload_mismatch")
            .collect();
        assert_eq!(rows.len(), 1, "exactly one mismatch row");
        let detail = &rows[0].detail;
        assert_eq!(detail["missing_count"], 1, "{detail}");
        assert_eq!(detail["missing"][0], "gone.bin", "{detail}");
        assert_eq!(detail["unreferenced_count"], 1, "{detail}");
        assert_eq!(detail["unreferenced"][0], "sub/kept.bin", "{detail}");

        // Once the tree is reconciled, a further survey stays quiet.
        store
            .with(|connection| {
                connection.execute("DELETE FROM files WHERE stored_as = 'gone.bin'", [])
            })
            .unwrap();
        fs::remove_file(receive.join("sub/kept.bin")).unwrap();
        fs::remove_file(receive.join("sub/kept.bin.vot-receipt")).unwrap();
        survey_restored_payloads(&store, &receive);
        let rows = store.audit_export(None, 0, 0, 100).unwrap();
        assert_eq!(
            rows.iter()
                .filter(|row| row.event == "restore_payload_mismatch")
                .count(),
            1,
            "an agreeing tree writes no further row"
        );
    }

    /// A promoted standby boots as the live instance with its status file
    /// still in place; while it exists every boot skips schema migrations, so
    /// the live boot retires it and later boots migrate normally.
    #[test]
    fn a_live_boot_retires_the_standby_status_file() {
        let directory = tempfile::tempdir().unwrap();
        let config = crate::api::testing::config(directory.path());
        std::fs::create_dir_all(&config.data_dir).unwrap();
        crate::paths::tighten_private_dir(&config.data_dir).unwrap();
        drop(crate::store::Store::open(&config.data_dir).unwrap());
        let status = config.data_dir.join(crate::standby::STATUS_FILE);
        fs::write(&status, b"{}").unwrap();
        let app = crate::app::build(config).unwrap();
        assert!(!status.exists(), "the live boot retired the standby status");
        drop(app);
        // A second boot with nothing to retire is fine.
        retire_standby_status(directory.path().join("data").as_path()).unwrap();
    }

    /// A receive volume that is not mounted yet at the restore boot shows as
    /// an empty or unreadable tree; tombstoning then would permanently erase
    /// the index of payloads that are still on the NAS. Report, never erase.
    #[cfg(unix)]
    #[test]
    fn restored_payload_survey_keeps_records_when_the_tree_is_empty_or_unreadable() {
        use std::os::unix::fs::PermissionsExt as _;

        let (root, store) = initialized_root();
        let receive = root.path().join("received");
        std::fs::create_dir_all(&receive).unwrap();
        store
            .with(|connection| {
                connection.execute_batch(
                    "INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,
                        deleted,stored_as,path,suite,root,receipt)
                     VALUES ('link','','upload',0,0,20,0,'sub/kept.bin','sub/kept.bin','md5','root',0),
                            ('link','','upload',1,0,20,0,'gone.bin','gone.bin','md5','root',0)",
                )
            })
            .unwrap();
        let live = |store: &crate::store::Store| {
            store
                .with(|connection| {
                    connection.query_row(
                        "SELECT COUNT(*) FROM files WHERE deleted = 0",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                })
                .unwrap()
        };
        let latest = |store: &crate::store::Store| {
            store
                .audit_export(None, 0, 0, 100)
                .unwrap()
                .into_iter()
                .rfind(|row| row.event == "restore_payload_mismatch")
                .expect("the gap is reported")
                .detail
        };
        // An empty mountpoint: nothing is tombstoned, the gap is reported.
        survey_restored_payloads(&store, &receive);
        assert_eq!(live(&store), 2);
        assert_eq!(latest(&store)["receive_tree_trusted"], false);
        assert_eq!(latest(&store)["tombstoned"], 0);
        // A subfolder the service may not list (lost+found on a volume root)
        // keeps the records under it, while the rest still reconciles.
        std::fs::create_dir_all(receive.join("sub")).unwrap();
        fs::write(receive.join("other.bin"), [0u8; 8]).unwrap();
        fs::set_permissions(receive.join("sub"), fs::Permissions::from_mode(0o000)).unwrap();
        let readable = fs::read_dir(receive.join("sub")).is_ok();
        if !readable {
            survey_restored_payloads(&store, &receive);
        }
        fs::set_permissions(receive.join("sub"), fs::Permissions::from_mode(0o700)).unwrap();
        if readable {
            // Running with privileges that ignore the mode; nothing to prove.
            return;
        }
        assert_eq!(
            live(&store),
            1,
            "gone.bin is tombstoned, sub/kept.bin is kept"
        );
        let detail = latest(&store);
        assert_eq!(detail["tombstoned"], 1);
        assert_eq!(detail["receive_tree_trusted"], true);
        assert_eq!(detail["unreadable"][0], "sub");
    }

    /// Audit finding 373: the survey must tombstone the live records whose
    /// payload did not survive the restore, so nothing lists, charges or
    /// retires against a path that no longer holds the record's bytes,
    /// while a record whose payload stats stays live.
    #[test]
    fn restored_payload_survey_tombstones_records_missing_from_disk() {
        let (root, store) = initialized_root();
        let receive = root.path().join("received");
        store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,
                        deleted,stored_as,path,suite,root,receipt)
                     VALUES ('link-gone','','upload-gone',0,0,20,0,'gone.bin','gone.bin','md5','root-old',0)",
                    [],
                )?;
                connection.execute(
                    "INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,
                        deleted,stored_as,path,suite,root,receipt)
                     VALUES ('link-kept','','upload-kept',0,0,64,0,'kept.bin','kept.bin','md5','root-new',0)",
                    [],
                )
            })
            .unwrap();
        std::fs::create_dir_all(&receive).unwrap();
        fs::write(receive.join("kept.bin"), [0u8; 64]).unwrap();

        survey_restored_payloads(&store, &receive);

        let (deleted, path): (i64, String) = store
            .with(|connection| {
                connection.query_row(
                    "SELECT deleted, path FROM files WHERE stored_as='gone.bin'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
            })
            .unwrap();
        assert_eq!(
            (deleted, path.as_str()),
            (1, ""),
            "the miss must be tombstoned"
        );
        let kept: i64 = store
            .with(|connection| {
                connection.query_row(
                    "SELECT deleted FROM files WHERE stored_as='kept.bin'",
                    [],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(kept, 0, "a record whose payload stats must stay live");
        let rows = store.audit_export(None, 0, 0, 100).unwrap();
        let row = rows
            .iter()
            .find(|row| row.event == "restore_payload_mismatch")
            .expect("one mismatch row");
        assert_eq!(row.detail["missing"][0], "gone.bin", "{}", row.detail);
        assert_eq!(row.detail["tombstoned"], 1, "{}", row.detail);

        // The reconciled tree agrees on a further survey.
        survey_restored_payloads(&store, &receive);
        let rows = store.audit_export(None, 0, 0, 100).unwrap();
        assert_eq!(
            rows.iter()
                .filter(|row| row.event == "restore_payload_mismatch")
                .count(),
            1,
            "a tombstoned record stops being reported"
        );
    }

    #[test]
    fn orphan_sweep_matches_status_stage_temps_and_reports_failed_removals() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path();
        let token = "a".repeat(32);
        let stage_temps = [
            format!(".backup-status.json-{token}.stage"),
            format!(".backup-secrets.json-{token}.stage"),
            format!(".votport-restore-pending.json-{token}.stage"),
            format!("..votport-standby-status.json-{token}.stage"),
        ];
        for name in &stage_temps {
            std::fs::write(data.join(name), b"scratch").unwrap();
        }
        assert_eq!(sweep_data_dir_orphans(data).unwrap(), 4);
        assert!(stage_temps.iter().all(|name| !data.join(name).exists()));

        // A removal that fails warns with the file name and error class,
        // never the absolute path.
        use std::os::unix::fs::PermissionsExt as _;
        let guarded = data.join("guarded");
        std::fs::create_dir(&guarded).unwrap();
        let stuck = format!(".backup-status.json-{token}.stage");
        std::fs::write(guarded.join(&stuck), b"scratch").unwrap();
        std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o555)).unwrap();
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            drop(CleanupPath::new(guarded.join(&stuck)));
        });
        std::fs::set_permissions(&guarded, std::fs::Permissions::from_mode(0o755)).unwrap();
        let warns: Vec<String> = std::fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .filter(|line| line.contains("scratch removal failed"))
            .map(str::to_owned)
            .collect();
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(warns[0].contains(&stuck), "{}", warns[0]);
        assert!(
            !warns[0].contains("guarded"),
            "absolute path leaked: {}",
            warns[0]
        );
    }

    #[test]
    fn data_scratch_sweep_removes_only_complete_owned_names() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path();
        let token = "a".repeat(32);
        let other = "b".repeat(32);
        let removed = [
            format!(".votport-backup-db-{token}"),
            format!(".votport-replica-{token}.tar"),
            format!(".votport-restore-{token}.download"),
            format!(".votport-restore-{token}.tar"),
        ];
        for name in &removed {
            fs::write(data.join(name), b"scratch").unwrap();
        }
        let orphan_stage = data.join(format!(".votport-restore-stage-{other}"));
        fs::create_dir(&orphan_stage).unwrap();
        let kept_stage_name = format!(".votport-restore-stage-{token}");
        let kept_stage = data.join(&kept_stage_name);
        fs::create_dir(&kept_stage).unwrap();
        write_pending_restore(
            data,
            CleanupPath::directory(kept_stage),
            Manifest {
                version: VERSION,
                created_at: 1,
                schema_version: crate::store::SCHEMA_VERSION,
                entries: Vec::new(),
            },
            RestoreMode::Replica,
            None,
        )
        .unwrap();

        fs::create_dir(data.join(format!(".votport-restore-{other}.tar"))).unwrap();
        fs::write(data.join(".votport-restore-stage-not-hex"), b"foreign").unwrap();
        fs::write(data.join(".votport-restore-not-hex.download"), b"foreign").unwrap();
        fs::create_dir(data.join(format!(".votport-restore-rollback-{other}"))).unwrap();
        fs::write(data.join(format!(".status-{other}.stage")), b"unrelated").unwrap();

        assert_eq!(sweep_data_dir_orphans(data).unwrap(), 5);
        for name in removed {
            assert!(!data.join(name).exists());
        }
        assert!(data.join(&kept_stage_name).is_dir());
        assert!(data.join(format!(".votport-restore-{other}.tar")).is_dir());
        assert!(data.join(".votport-restore-stage-not-hex").is_file());
        assert!(data.join(".votport-restore-not-hex.download").is_file());
        assert!(data
            .join(format!(".votport-restore-rollback-{other}"))
            .is_dir());
        assert!(data.join(format!(".status-{other}.stage")).is_file());
    }

    #[test]
    fn data_scratch_sweep_skips_everything_when_marker_is_invalid() {
        let root = tempfile::tempdir().unwrap();
        let scratch = root
            .path()
            .join(format!(".votport-backup-db-{}", "c".repeat(32)));
        fs::write(&scratch, b"scratch").unwrap();
        fs::write(root.path().join(PENDING_FILE), b"invalid").unwrap();

        assert!(sweep_data_dir_orphans(root.path()).is_err());
        assert!(scratch.exists());
    }

    #[test]
    fn backup_root_sweep_removes_only_owned_archive_stages() {
        let root = tempfile::tempdir().unwrap();
        let token = "a".repeat(32);
        let plain = format!("{BACKUP_ROOT_STAGE_PREFIX}{token}.tar");
        let encrypted = format!("{BACKUP_ROOT_STAGE_PREFIX}{}.tar.age", "b".repeat(32));
        for name in [&plain, &encrypted] {
            fs::write(root.path().join(name), b"stage").unwrap();
        }
        for name in [
            format!("votport-backup-v2-1-{token}.tar"),
            format!(".votport-backup-v2-1-{token}.tar.rollback"),
            format!(".votport-backup-v2-1-{token}.tar.stage"),
            format!(".votport-backup-v2-1-{token}.tar.age.stage"),
            format!(".votport-backup-v2-1-{token}.tar.age.age.stage"),
            format!("{BACKUP_ROOT_STAGE_PREFIX}{}-foreign.tar", "c".repeat(32)),
            format!("{BACKUP_ROOT_STAGE_PREFIX}{}x.tar", "d".repeat(32)),
        ] {
            fs::write(root.path().join(name), b"keep").unwrap();
        }
        fs::create_dir(
            root.path()
                .join(format!("{BACKUP_ROOT_STAGE_PREFIX}{}.tar", "e".repeat(32))),
        )
        .unwrap();

        assert_eq!(sweep_backup_root_orphans(root.path()).unwrap(), Some(2));
        assert!(!root.path().join(plain).exists());
        assert!(!root.path().join(encrypted).exists());
        assert!(root
            .path()
            .join(format!("votport-backup-v2-1-{token}.tar"))
            .exists());
        assert!(root
            .path()
            .join(format!(".votport-backup-v2-1-{token}.tar.rollback"))
            .exists());
        assert!(root
            .path()
            .join(format!("{BACKUP_ROOT_STAGE_PREFIX}{}.tar", "e".repeat(32)))
            .is_dir());
        assert!(root.path().join(BACKUP_ROOT_LOCK).exists());
    }

    #[cfg(unix)]
    #[test]
    fn backup_root_sweep_preserves_symlink_stage() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let token = "c".repeat(32);
        let target = root.path().join("target");
        fs::write(&target, b"target").unwrap();
        let link = root
            .path()
            .join(format!("{BACKUP_ROOT_STAGE_PREFIX}{token}.tar"));
        symlink(&target, &link).unwrap();

        assert_eq!(sweep_backup_root_orphans(root.path()).unwrap(), Some(0));
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn backup_root_lock_rejects_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("outside");
        fs::write(&target, b"target").unwrap();
        let lock = root.path().join(BACKUP_ROOT_LOCK);
        symlink(&target, &lock).unwrap();

        assert!(try_lock_backup_root(root.path()).is_err());
        assert!(fs::symlink_metadata(&lock)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"target");
    }

    #[test]
    fn primary_boot_sweeps_the_configured_custom_backup_root() {
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        crate::paths::tighten_private_dir(&data_dir).unwrap();
        let backup_root = data_dir.join("custom-backups");
        fs::create_dir(&backup_root).unwrap();
        crate::paths::tighten_private_dir(&backup_root).unwrap();
        let app = crate::api::testing::build(root.path());
        let config = BackupConfig {
            local_path: Some(backup_root.to_string_lossy().into_owned()),
            ..BackupConfig::default()
        };
        app.store
            .put_settings(
                "test",
                &[(
                    SETTING_KEY.to_owned(),
                    crate::store::SettingWrite::Set(serde_json::to_string(&config).unwrap()),
                )],
            )
            .unwrap();
        let stored = app.store.setting(SETTING_KEY).unwrap();
        assert_eq!(
            parse_config(stored, &data_dir)
                .unwrap()
                .local_root(&data_dir)
                .unwrap(),
            backup_root
        );
        crate::app::release_data_lock(&app);
        drop(app);

        let stage = backup_root.join(format!("{BACKUP_ROOT_STAGE_PREFIX}{}.tar", "e".repeat(32)));
        fs::write(&stage, b"orphan").unwrap();
        let app = crate::api::testing::build(root.path());
        assert!(!stage.exists());
        crate::app::release_data_lock(&app);
    }

    #[test]
    fn backup_root_sweep_waits_for_competing_process_fence() {
        const ROOT_ENV: &str = "VOTPORT_TEST_BACKUP_ROOT_FENCE";
        const READY_ENV: &str = "VOTPORT_TEST_BACKUP_ROOT_FENCE_READY";
        const RELEASE_ENV: &str = "VOTPORT_TEST_BACKUP_ROOT_FENCE_RELEASE";
        if let Some(root) = std::env::var_os(ROOT_ENV) {
            let root = PathBuf::from(root);
            let _lock = try_lock_backup_root(&root).unwrap().unwrap();
            let stage = root.join(format!("{BACKUP_ROOT_STAGE_PREFIX}{}.tar", "d".repeat(32)));
            fs::write(&stage, b"live writer stage").unwrap();
            fs::write(std::env::var_os(READY_ENV).unwrap(), b"ready").unwrap();
            let release = PathBuf::from(std::env::var_os(RELEASE_ENV).unwrap());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while !release.exists() {
                if std::time::Instant::now() >= deadline {
                    eprintln!("backup root fence child timed out waiting for release");
                    std::process::exit(2);
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let ready = root.path().join("ready");
        let release = root.path().join("release");
        let mut child = ReapedChild::new(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backup::tests::backup_root_sweep_waits_for_competing_process_fence",
                ])
                .env(ROOT_ENV, root.path())
                .env(READY_ENV, &ready)
                .env(RELEASE_ENV, &release)
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "competing process did not acquire the backup root fence"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        assert_eq!(sweep_backup_root_orphans(root.path()).unwrap(), None);
        let stage = root
            .path()
            .join(format!("{BACKUP_ROOT_STAGE_PREFIX}{}.tar", "d".repeat(32)));
        assert!(stage.exists());
        fs::write(&release, b"release").unwrap();
        assert!(child
            .wait_bounded(std::time::Duration::from_secs(15))
            .unwrap()
            .success());
        assert_eq!(sweep_backup_root_orphans(root.path()).unwrap(), Some(1));
        assert!(!stage.exists());
    }

    #[tokio::test]
    async fn cancelled_backup_request_keeps_worker_fence_until_archive_finishes() {
        let root = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(root.path());
        let backups = app.config.data_dir.join("backups");
        let data_dir = app.config.data_dir.clone();
        let (archive_started, archive_release) =
            install_backup_pause(&data_dir, BackupPausePoint::Archive);

        let request = tokio::spawn(run(
            Arc::clone(&app),
            BackupConfig {
                encrypt: true,
                ..BackupConfig::default()
            },
            BackupSecrets {
                passphrase: Some("test passphrase".to_owned()),
                ..BackupSecrets::default()
            },
        ));
        tokio::task::spawn_blocking(move || {
            archive_started.recv_timeout(std::time::Duration::from_secs(15))
        })
        .await
        .unwrap()
        .expect("archive worker did not reach the cancellation barrier");
        let stage = fs::read_dir(&backups)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(backup_root_stage)
            })
            .expect("paused archive stage was not visible");
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(app.backup_lock.try_lock().is_err());
        assert!(try_lock_backup_root(&backups).unwrap().is_none());
        assert!(stage.exists());

        let (encrypt_started, encrypt_release) =
            install_backup_pause(&data_dir, BackupPausePoint::Encrypt);
        archive_release.send(()).unwrap();
        tokio::task::spawn_blocking(move || {
            encrypt_started.recv_timeout(std::time::Duration::from_secs(15))
        })
        .await
        .unwrap()
        .expect("encryption worker did not reach the cancellation barrier");
        let encrypted_stage = fs::read_dir(&backups)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(backup_root_stage)
                    && path.extension().and_then(|ext| ext.to_str()) == Some("age")
            })
            .expect("paused encrypted stage was not visible");
        assert!(app.backup_lock.try_lock().is_err());
        assert!(try_lock_backup_root(&backups).unwrap().is_none());
        assert!(encrypted_stage.exists());

        encrypt_release.send(()).unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if app.backup_lock.try_lock().is_ok() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "backup worker did not finish"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!stage.exists());
        assert!(!encrypted_stage.exists());
        assert_eq!(local_files(&backups).unwrap().len(), 1);
        let status = read_status(&app.config.data_dir).unwrap();
        assert!(status.last_success_at.is_some());
        assert_eq!(status.last_error, None);
    }

    #[cfg(unix)]
    #[test]
    fn a_next_primary_boot_reaps_scratch_left_by_a_forced_exit() {
        const CHILD_ROOT: &str = "VOTPORT_TEST_BACKUP_SCRATCH_EXIT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let data = PathBuf::from(root);
            fs::create_dir_all(&data).unwrap();
            let token = "e".repeat(32);
            for name in [
                format!(".votport-backup-db-{token}"),
                format!(".votport-replica-{token}.tar"),
                format!(".votport-restore-{token}.download"),
                format!(".votport-restore-{token}.tar"),
            ] {
                fs::write(data.join(name), b"interrupted").unwrap();
            }
            fs::create_dir(data.join(format!(".votport-restore-stage-{token}"))).unwrap();
            std::process::exit(0);
        }

        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backup::tests::a_next_primary_boot_reaps_scratch_left_by_a_forced_exit",
            ])
            .env(CHILD_ROOT, &data)
            .status()
            .unwrap();
        assert!(status.success(), "child exited with {status}");

        let app = crate::api::testing::build(root.path());
        let token = "e".repeat(32);
        for name in [
            format!(".votport-backup-db-{token}"),
            format!(".votport-replica-{token}.tar"),
            format!(".votport-restore-{token}.download"),
            format!(".votport-restore-{token}.tar"),
            format!(".votport-restore-stage-{token}"),
        ] {
            assert!(!data.join(name).exists());
        }
        crate::app::release_data_lock(&app);
    }

    #[cfg(unix)]
    #[test]
    fn data_scratch_sweep_preserves_symlink_and_non_utf8_entries() {
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::symlink;

        let root = tempfile::Builder::new()
            .prefix("votport-non-utf8-")
            .tempdir_in("/tmp")
            .unwrap();
        let token = "d".repeat(32);
        let target = root.path().join("target");
        fs::write(&target, b"target").unwrap();
        let link = root.path().join(format!(".votport-backup-db-{token}"));
        symlink(&target, &link).unwrap();
        let non_utf = std::ffi::OsString::from_vec(b".votport-replica-\xff.tar".to_vec());
        let non_utf_path = root.path().join(&non_utf);
        fs::write(&non_utf_path, b"foreign").unwrap();

        assert_eq!(sweep_data_dir_orphans(root.path()).unwrap(), 0);
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
        assert!(non_utf.to_str().is_none());
        assert!(fs::symlink_metadata(non_utf_path).is_ok());
    }

    #[test]
    fn rejects_traversal_and_foreign_names() {
        assert!(validate_id("../x").is_err());
        assert!(validate_id("other.tar").is_err());
        assert!(validate_prefix("../x").is_err());
        assert_eq!(
            BackupConfig::default()
                .local_root(Path::new("relative-data"))
                .unwrap(),
            Path::new("relative-data/backups")
        );
        let inactive_s3 = BackupConfig {
            s3_endpoint: Some("https://s3.example.com".into()),
            s3_bucket: Some("saved-bucket".into()),
            ..BackupConfig::default()
        };
        assert!(inactive_s3.validate(Path::new("/data")).is_ok());
        let root = tempfile::tempdir().unwrap();
        let missing = BackupConfig {
            local_path: Some(root.path().join("missing").to_string_lossy().into_owned()),
            ..BackupConfig::default()
        };
        assert!(missing.validate(root.path()).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let backup = root.path().join("backup");
            fs::create_dir(&backup).unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
            let unsafe_root = BackupConfig {
                local_path: Some(backup.to_string_lossy().into_owned()),
                ..BackupConfig::default()
            };
            assert!(unsafe_root.validate(Path::new("/data")).is_err());
        }
    }
    #[test]
    fn config_redacts_secrets() {
        let c = BackupConfig::default();
        let p = c.public(&BackupSecrets {
            access_key_id: Some("a".into()),
            secret_access_key: Some("b".into()),
            passphrase: Some("p".into()),
        });
        assert!(serde_json::to_string(&p)
            .unwrap()
            .find("secret_access_key")
            .is_none());
        assert!(p.s3_credentials_configured);
    }

    #[test]
    fn archive_round_trip_and_age_encryption() {
        let (root, store) = initialized_root();
        let raw = root.path().join("bundle.tar");
        let manifest =
            create_archive(&store, root.path(), &raw, crate::store::SCHEMA_VERSION).unwrap();
        assert_eq!(manifest.version, VERSION);
        let extracted = root.path().join("extract");
        fs::create_dir(&extracted).unwrap();
        validate_and_extract(&raw, &extracted, crate::store::SCHEMA_VERSION).unwrap();
        assert!(manifest.entries.iter().all(|entry| entry.name != "secret"));
        assert!(!extracted.join("secret").exists());
        assert_eq!(fs::read(extracted.join("receipt.key")).unwrap(), [8; 32]);
        fs::remove_file(root.path().join("secret")).unwrap();
        create_archive(
            &store,
            root.path(),
            &root.path().join("without-cookie.tar"),
            crate::store::SCHEMA_VERSION,
        )
        .unwrap();
        let encrypted = root.path().join("bundle.tar.age");
        encrypt_file(&raw, &encrypted, "test passphrase").unwrap();
        let decrypted = root.path().join("decrypted.tar");
        decrypt_file(&encrypted, &decrypted, "test passphrase").unwrap();
        assert_eq!(fs::read(raw).unwrap(), fs::read(decrypted).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_archive_extraction_keeps_partial_identity_private() {
        use std::os::unix::{fs::PermissionsExt as _, process::ExitStatusExt as _};
        const CHILD_ROOT: &str = "VOTPORT_TEST_EXTRACT_WRITE_FAILURE";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            rustix::process::umask(rustix::fs::Mode::empty());
            let mut limit = rustix::process::getrlimit(rustix::process::Resource::Fsize);
            limit.current = Some(0);
            rustix::process::setrlimit(rustix::process::Resource::Fsize, limit).unwrap();
            assert!(validate_and_extract(
                &root.join("bundle.tar"),
                &root.join("extract"),
                crate::store::SCHEMA_VERSION
            )
            .is_err());
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let mut header = Header::new_gnu();
        header.set_path("receipt.key").unwrap();
        header.set_size(32);
        header.set_mode(0o600);
        header.set_cksum();
        let mut builder = Builder::new(File::create(root.path().join("bundle.tar")).unwrap());
        builder.append(&header, &[7; 32][..]).unwrap();
        builder.finish().unwrap();
        fs::create_dir(root.path().join("extract")).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backup::tests::interrupted_archive_extraction_keeps_partial_identity_private",
            ])
            .env(CHILD_ROOT, root.path())
            .status()
            .unwrap();
        assert!(
            status.success() || status.signal() == Some(rustix::process::Signal::XFSZ.as_raw()),
            "{status}"
        );
        let partial = fs::metadata(root.path().join("extract/receipt.key")).unwrap();
        assert_eq!(partial.len(), 0);
        assert_eq!(partial.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn archives_refuse_cookie_keys_and_unsupported_format_versions() {
        let (root, store) = initialized_root();
        let archive = root.path().join("bundle.tar");
        create_archive(&store, root.path(), &archive, crate::store::SCHEMA_VERSION).unwrap();
        let stage = root.path().join("extract");
        fs::create_dir(&stage).unwrap();
        let manifest =
            validate_and_extract(&archive, &stage, crate::store::SCHEMA_VERSION).unwrap();
        for version in [VERSION - 1, VERSION + 1] {
            let mut unsupported = manifest.clone();
            unsupported.version = version;
            assert!(
                validate_staged_restore(&stage, &unsupported, crate::store::SCHEMA_VERSION)
                    .is_err()
            );
        }
        fs::write(stage.join("secret"), [7; 32]).unwrap();
        assert!(validate_staged_restore(&stage, &manifest, crate::store::SCHEMA_VERSION).is_err());
        let smuggled = root.path().join("cookie-key.tar");
        let mut builder = Builder::new(File::create(&smuggled).unwrap());
        add_file(&mut builder, "secret", &stage.join("secret")).unwrap();
        builder.finish().unwrap();
        let refused = root.path().join("refused");
        fs::create_dir(&refused).unwrap();
        assert!(validate_and_extract(&smuggled, &refused, crate::store::SCHEMA_VERSION).is_err());
        assert!(!refused.join("secret").exists());
        assert!(validate_id("votport-backup-v1-1-a.tar").is_err());
    }

    #[test]
    fn restore_refuses_unsupported_schema_and_layout_before_installation() {
        for (version, layout) in [
            (crate::store::SCHEMA_VERSION - 1, Some("reserved-v1")),
            (crate::store::SCHEMA_VERSION + 1, Some("reserved-v1")),
            (crate::store::SCHEMA_VERSION, Some("old")),
            (crate::store::SCHEMA_VERSION, None),
        ] {
            let (root, store) = initialized_root();
            store
                .with(|connection| {
                    connection.execute(
                        "UPDATE meta SET value=?1 WHERE key='schema_version'",
                        [version.to_string()],
                    )?;
                    connection.execute("DELETE FROM meta WHERE key='tenant_storage_layout'", [])?;
                    if let Some(layout) = layout {
                        connection.execute(
                            "INSERT INTO meta(key,value) VALUES ('tenant_storage_layout',?1)",
                            [layout],
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
            let snapshot = root.path().join("unsupported.db");
            store.backup_into(&snapshot).unwrap();
            assert!(validate_database(&snapshot, version, crate::store::SCHEMA_VERSION).is_err());
            let archive = root.path().join("unsupported.tar");
            create_archive(&store, root.path(), &archive, version).unwrap();
            let stage = root.path().join("extract");
            fs::create_dir(&stage).unwrap();
            assert!(validate_and_extract(&archive, &stage, crate::store::SCHEMA_VERSION).is_err());
            assert!(!root.path().join(PENDING_FILE).exists());
            assert!(store.setting("missing").unwrap().is_none());
            assert_eq!(fs::read(root.path().join("receipt.key")).unwrap(), [8; 32]);
        }
    }

    #[test]
    fn archive_manifest_must_name_every_member() {
        let (root, store) = initialized_root();
        let snapshot = root.path().join("snapshot.db");
        store.backup_into(&snapshot).unwrap();
        let (size, sha256) = file_hash(&snapshot).unwrap();
        let entries = vec![ManifestEntry {
            name: "votport.db".into(),
            size,
            sha256,
        }];
        let manifest = Manifest {
            version: VERSION,
            created_at: now(),
            schema_version: crate::store::SCHEMA_VERSION,
            entries,
        };
        let archive_path = root.path().join("smuggled.tar");
        let file = File::create(&archive_path).unwrap();
        let mut builder = Builder::new(file);
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let mut header = Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        builder
            .append_data(&mut header, "manifest.json", bytes.as_slice())
            .unwrap();
        add_file(&mut builder, "votport.db", &snapshot).unwrap();
        add_file(
            &mut builder,
            "receipt.key",
            &root.path().join("receipt.key"),
        )
        .unwrap();
        builder.finish().unwrap();
        let stage = root.path().join("extract-smuggled");
        fs::create_dir(&stage).unwrap();
        assert!(validate_and_extract(&archive_path, &stage, crate::store::SCHEMA_VERSION).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn replacement_preserves_recoverable_stages_until_the_marker_commits() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let stage = root.path().join(".votport-restore-stage-old");
        fs::create_dir(&stage).unwrap();
        let manifest = Manifest {
            version: VERSION,
            created_at: 1,
            schema_version: crate::store::SCHEMA_VERSION,
            entries: Vec::new(),
        };
        write_pending_restore(
            root.path(),
            CleanupPath::directory(stage.clone()),
            manifest.clone(),
            RestoreMode::Historical,
            None,
        )
        .unwrap();
        let original = fs::read(root.path().join(PENDING_FILE)).unwrap();
        let new = root.path().join(".votport-restore-stage-new");
        fs::create_dir(&new).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let failed = write_pending_restore(
            root.path(),
            CleanupPath::directory(new.clone()),
            manifest.clone(),
            RestoreMode::Historical,
            None,
        );
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(failed.is_err(), "test requires an unprivileged user");
        assert_eq!(fs::read(root.path().join(PENDING_FILE)).unwrap(), original);
        assert!(stage.is_dir());
        assert!(
            new.is_dir(),
            "uncertain publication must retain the candidate"
        );
        write_pending_restore(
            root.path(),
            CleanupPath::directory(new.clone()),
            manifest.clone(),
            RestoreMode::Historical,
            None,
        )
        .unwrap();
        assert_eq!(
            pending_restore_stage(root.path()).unwrap().unwrap(),
            new.file_name().unwrap().to_str().unwrap()
        );
        assert!(!stage.exists());
        assert!(new.is_dir());

        for phase in [
            RestorePhase::Prepared,
            RestorePhase::OldMoved,
            RestorePhase::NewInstalled,
        ] {
            let mut pending = read_pending_restore(root.path()).unwrap().unwrap();
            pending.phase = phase;
            pending.rollback = Some(".votport-restore-rollback-test".into());
            persist_pending_restore(root.path(), &pending).unwrap();
            let before = fs::read(root.path().join(PENDING_FILE)).unwrap();
            fs::create_dir(&stage).unwrap();
            assert!(write_pending_restore(
                root.path(),
                CleanupPath::directory(stage.clone()),
                manifest.clone(),
                RestoreMode::Historical,
                None,
            )
            .unwrap_err()
            .contains("being applied"));
            assert_eq!(fs::read(root.path().join(PENDING_FILE)).unwrap(), before);
            assert!(new.is_dir());
            assert!(
                !stage.exists(),
                "unpublished rejected candidate is cleaned up"
            );
        }
    }

    #[test]
    fn a_staged_replica_from_a_stopped_standby_is_discarded_but_a_running_restore_is_kept() {
        let root = tempfile::tempdir().unwrap();
        let manifest = Manifest {
            version: VERSION,
            created_at: 1,
            schema_version: crate::store::SCHEMA_VERSION,
            entries: Vec::new(),
        };

        // A clean stage awaiting promotion goes, marker and all, so a
        // stopped standby stops holding rows the primary deleted.
        let stale = root.path().join(".votport-restore-stage-stale");
        fs::create_dir(&stale).unwrap();
        write_pending_restore(
            root.path(),
            CleanupPath::directory(stale.clone()),
            manifest.clone(),
            RestoreMode::Replica,
            None,
        )
        .unwrap();
        assert!(discard_staged_replica(root.path()).unwrap());
        assert!(!stale.exists());
        assert!(!root.path().join(PENDING_FILE).exists());
        assert!(!discard_staged_replica(root.path()).unwrap());

        // A restore that was being applied is evidence for its next boot.
        let applying = root.path().join(".votport-restore-stage-applying");
        fs::create_dir(&applying).unwrap();
        persist_pending_restore(
            root.path(),
            &PendingRestore {
                stage: ".votport-restore-stage-applying".into(),
                version: VERSION,
                manifest,
                mode: RestoreMode::Replica,
                phase: RestorePhase::OldMoved,
                rollback: Some(".votport-restore-rollback-keep".into()),
                archive: None,
            },
        )
        .unwrap();
        assert!(!discard_staged_replica(root.path()).unwrap());
        assert!(applying.is_dir());
        assert!(root.path().join(PENDING_FILE).exists());
    }

    #[test]
    fn pending_restore_rechecks_staged_hashes_before_moving_live_data() {
        let (root, store) = initialized_root();
        let archive = root.path().join("bundle.tar");
        create_archive(&store, root.path(), &archive, crate::store::SCHEMA_VERSION).unwrap();
        let stage = root.path().join(".votport-restore-stage-test");
        fs::create_dir(&stage).unwrap();
        let manifest =
            validate_and_extract(&archive, &stage, crate::store::SCHEMA_VERSION).unwrap();
        write_pending_restore(
            root.path(),
            CleanupPath::directory(stage.clone()),
            manifest,
            RestoreMode::Historical,
            None,
        )
        .unwrap();
        fs::write(stage.join("receipt.key"), b"tampered").unwrap();
        drop(store);
        assert!(apply_pending_restore(root.path(), crate::store::SCHEMA_VERSION).is_err());
        assert!(root.path().join("votport.db").exists());
        assert_eq!(fs::read(root.path().join("secret")).unwrap(), [7; 32]);
    }

    #[test]
    fn resumed_restore_validates_every_phase_before_changing_files() {
        const CHILD_DATABASE: &str = "VOTPORT_TEST_RESTORE_HOT_JOURNAL";
        if let Some(path) = std::env::var_os(CHILD_DATABASE) {
            let connection = rusqlite::Connection::open(path).unwrap();
            connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA cache_size=1;
                BEGIN IMMEDIATE;
                INSERT INTO settings(key,value,updated_at) VALUES ('uncommitted',hex(zeroblob(65536)),1);").unwrap();
            std::process::exit(0);
        }
        for (phase, installed) in [
            (RestorePhase::OldMoved, false),
            (RestorePhase::OldMoved, true),
            (RestorePhase::NewInstalled, true),
        ] {
            for (version, layout) in [
                (crate::store::SCHEMA_VERSION - 1, Some("reserved-v1")),
                (crate::store::SCHEMA_VERSION + 1, Some("reserved-v1")),
                (crate::store::SCHEMA_VERSION, Some("old")),
                (crate::store::SCHEMA_VERSION, None),
                (crate::store::SCHEMA_VERSION, Some("reserved-v1")),
            ] {
                let (root, store) = initialized_root();
                let archive = root.path().join("bundle.tar");
                create_archive(&store, root.path(), &archive, crate::store::SCHEMA_VERSION)
                    .unwrap();
                drop(store);
                let stage = root.path().join(".votport-restore-stage-test");
                fs::create_dir(&stage).unwrap();
                let mut manifest =
                    validate_and_extract(&archive, &stage, crate::store::SCHEMA_VERSION).unwrap();
                let rollback = root.path().join(".votport-restore-rollback-test");
                fs::create_dir(&rollback).unwrap();
                for name in ARCHIVE_FILES.into_iter().chain(["secret"]) {
                    let path = root.path().join(name);
                    if path.exists() {
                        fs::rename(path, rollback.join(name)).unwrap();
                    }
                }
                if installed {
                    for entry in &manifest.entries {
                        if entry.name == "votport.db" || phase == RestorePhase::NewInstalled {
                            fs::rename(stage.join(&entry.name), root.path().join(&entry.name))
                                .unwrap();
                        }
                    }
                }
                let database = if installed {
                    root.path().join("votport.db")
                } else {
                    stage.join("votport.db")
                };
                let connection = rusqlite::Connection::open(&database).unwrap();
                connection
                    .execute(
                        "UPDATE meta SET value=?1 WHERE key='schema_version'",
                        [version.to_string()],
                    )
                    .unwrap();
                connection
                    .execute("DELETE FROM meta WHERE key='tenant_storage_layout'", [])
                    .unwrap();
                if let Some(layout) = layout {
                    connection
                        .execute(
                            "INSERT INTO meta(key,value) VALUES ('tenant_storage_layout',?1)",
                            [layout],
                        )
                        .unwrap();
                }
                drop(connection);
                manifest.schema_version = version;
                let entry = manifest
                    .entries
                    .iter_mut()
                    .find(|entry| entry.name == "votport.db")
                    .unwrap();
                (entry.size, entry.sha256) = file_hash(&database).unwrap();
                persist_pending_restore(
                    root.path(),
                    &PendingRestore {
                        stage: ".votport-restore-stage-test".into(),
                        version: VERSION,
                        manifest,
                        mode: RestoreMode::Historical,
                        phase,
                        rollback: Some(".votport-restore-rollback-test".into()),
                        archive: Some("archive-test".into()),
                    },
                )
                .unwrap();
                if version == crate::store::SCHEMA_VERSION && layout == Some("reserved-v1") {
                    if phase == RestorePhase::NewInstalled {
                        let status = std::process::Command::new(std::env::current_exe().unwrap())
                            .args(["--exact", "backup::tests::resumed_restore_validates_every_phase_before_changing_files"])
                            .env(CHILD_DATABASE, &database).status().unwrap();
                        assert!(status.success());
                        let mut journal =
                            File::open(root.path().join("votport.db-journal")).unwrap();
                        let mut header = [0; 8];
                        journal.read_exact(&mut header).unwrap();
                        assert_eq!(header, [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]);
                    }
                    apply_pending_restore(root.path(), crate::store::SCHEMA_VERSION).unwrap();
                    assert!(!root.path().join(PENDING_FILE).exists());
                    assert!(!stage.exists());
                    assert_ne!(fs::read(root.path().join("secret")).unwrap(), [7; 32]);
                    assert_eq!(fs::read(rollback.join("secret")).unwrap(), [7; 32]);
                    let restored = crate::store::Store::open(root.path()).unwrap();
                    assert!(restored.setting("uncommitted").unwrap().is_none());
                    continue;
                }
                let paths = [root.path(), stage.as_path(), rollback.as_path()]
                    .into_iter()
                    .flat_map(|directory| {
                        fs::read_dir(directory)
                            .unwrap()
                            .map(|entry| entry.unwrap().path())
                    })
                    .filter(|path| path.is_file())
                    .collect::<Vec<_>>();
                let before = paths
                    .iter()
                    .map(|path| fs::read(path).unwrap())
                    .collect::<Vec<_>>();
                assert!(apply_pending_restore(root.path(), crate::store::SCHEMA_VERSION).is_err());
                for (path, bytes) in paths.iter().zip(before) {
                    assert_eq!(fs::read(path).unwrap(), bytes, "{}", path.display());
                }
                assert!(!root.path().join("secret").exists());
            }
        }
    }

    #[test]
    fn archive_validation_refuses_invalid_backup_settings_before_activation() {
        for value in ["not json", r#"{"unknown":true}"#] {
            let (root, store) = initialized_root();
            store
                .put_settings(
                    "test",
                    &[(
                        SETTING_KEY.into(),
                        crate::store::SettingWrite::Set(value.into()),
                    )],
                )
                .unwrap();
            let archive = root.path().join("backup.tar");
            create_archive(&store, root.path(), &archive, crate::store::SCHEMA_VERSION).unwrap();
            drop(store);
            let database = fs::read(root.path().join("votport.db")).unwrap();
            let secret = fs::read(root.path().join("secret")).unwrap();
            let stage = root.path().join(".votport-restore-stage-invalid-settings");
            fs::create_dir(&stage).unwrap();
            assert_eq!(
                validate_and_extract(&archive, &stage, crate::store::SCHEMA_VERSION).unwrap_err(),
                "invalid backup configuration"
            );
            assert_eq!(fs::read(root.path().join("votport.db")).unwrap(), database);
            assert_eq!(fs::read(root.path().join("secret")).unwrap(), secret);
            assert!(!root.path().join(PENDING_FILE).exists());
        }
    }

    #[test]
    fn restore_preserves_backup_settings_and_clears_target_secrets_and_history() {
        for mode in [RestoreMode::Historical, RestoreMode::Replica] {
            for interrupted in [false, true] {
                let (root, store) = initialized_root();
                let mut config = BackupConfig {
                    enabled: true,
                    interval_secs: 12_345,
                    retention_days: 7,
                    retention_count: 4,
                    destination: Destination::Both,
                    local_path: Some(
                        root.path()
                            .join("unmounted-backups")
                            .to_str()
                            .unwrap()
                            .into(),
                    ),
                    s3_endpoint: Some("https://backups.example.invalid".into()),
                    s3_region: Some("custom-region".into()),
                    s3_bucket: Some("archived-bucket".into()),
                    s3_prefix: Some("saved-prefix".into()),
                    encrypt: true,
                    s3_path_style: true,
                };
                store
                    .put_settings(
                        "test",
                        &[(
                            SETTING_KEY.into(),
                            crate::store::SettingWrite::Set(
                                serde_json::to_string(&config).unwrap(),
                            ),
                        )],
                    )
                    .unwrap();
                let archive = root.path().join("backup.tar");
                create_archive(&store, root.path(), &archive, crate::store::SCHEMA_VERSION)
                    .unwrap();
                drop(store);
                write_secrets(
                    root.path(),
                    &BackupSecrets {
                        access_key_id: Some("target-key".into()),
                        secret_access_key: Some("target-secret".into()),
                        passphrase: Some("target-passphrase".into()),
                    },
                )
                .unwrap();
                write_status(
                    root.path(),
                    BackupStatus {
                        last_attempt_at: Some(123),
                        last_success_at: Some(100),
                        last_error: Some("target failure".into()),
                        ..BackupStatus::default()
                    },
                )
                .unwrap();
                let secret_path = root.path().join(SECRETS_FILE);
                let status_path = root.path().join(STATUS_FILE);
                let secrets = fs::read(&secret_path).unwrap();
                let history = fs::read(&status_path).unwrap();
                let stage = root.path().join(".votport-restore-stage-backups");
                fs::create_dir(&stage).unwrap();
                let manifest =
                    validate_and_extract(&archive, &stage, crate::store::SCHEMA_VERSION).unwrap();
                write_pending_restore(
                    root.path(),
                    CleanupPath::directory(stage),
                    manifest,
                    mode,
                    None,
                )
                .unwrap();
                assert_eq!(fs::read(&secret_path).unwrap(), secrets);
                assert_eq!(fs::read(&status_path).unwrap(), history);
                if interrupted {
                    fs::remove_file(&status_path).unwrap();
                    fs::create_dir(&status_path).unwrap();
                    assert!(
                        apply_pending_restore(root.path(), crate::store::SCHEMA_VERSION).is_err()
                    );
                    assert_eq!(
                        read_pending_restore(root.path()).unwrap().unwrap().phase,
                        RestorePhase::NewInstalled
                    );
                    fs::remove_dir(&status_path).unwrap();
                }
                apply_pending_restore(root.path(), crate::store::SCHEMA_VERSION).unwrap();
                prepare_restored_database(
                    &root.path().join("votport.db"),
                    crate::store::SCHEMA_VERSION,
                    mode,
                )
                .unwrap();
                let restored = crate::store::Store::open(root.path()).unwrap();
                config.enabled = false;
                assert_eq!(
                    decode_config(restored.setting(SETTING_KEY).unwrap()).unwrap(),
                    config
                );
                assert_eq!(
                    fs::read(&secret_path).unwrap(),
                    serde_json::to_vec(&BackupSecrets::default()).unwrap()
                );
                assert_eq!(
                    fs::read(&status_path).unwrap(),
                    serde_json::to_vec(&BackupStatus::default()).unwrap()
                );
                assert!(!root.path().join(PENDING_FILE).exists());
                drop(restored);
                fs::write(&secret_path, &secrets).unwrap();
                fs::write(&status_path, &history).unwrap();
                apply_pending_restore(root.path(), crate::store::SCHEMA_VERSION).unwrap();
                assert_eq!(fs::read(&secret_path).unwrap(), secrets);
                assert_eq!(fs::read(&status_path).unwrap(), history);
            }
        }
    }

    #[test]
    fn restore_removes_wal_rotates_sessions_and_keeps_rollback() {
        let (root, store) = initialized_root();
        let historical = BackupConfig {
            enabled: true,
            ..BackupConfig::default()
        };
        store
            .put_settings(
                "test",
                &[(
                    SETTING_KEY.into(),
                    crate::store::SettingWrite::Set(serde_json::to_string(&historical).unwrap()),
                )],
            )
            .unwrap();
        let archive = root.path().join("bundle.tar");
        create_archive(&store, root.path(), &archive, crate::store::SCHEMA_VERSION).unwrap();
        let stage = root.path().join(".votport-restore-stage-test");
        fs::create_dir(&stage).unwrap();
        let manifest =
            validate_and_extract(&archive, &stage, crate::store::SCHEMA_VERSION).unwrap();
        drop(store);
        fs::write(root.path().join("secret"), [9; 32]).unwrap();
        fs::write(root.path().join("votport.db-wal"), b"stale-wal").unwrap();
        fs::write(root.path().join("votport.db-shm"), b"stale-shm").unwrap();
        write_pending_restore(
            root.path(),
            CleanupPath::directory(stage.clone()),
            manifest,
            RestoreMode::Historical,
            None,
        )
        .unwrap();
        apply_pending_restore(root.path(), crate::store::SCHEMA_VERSION).unwrap();
        let secret = fs::read(root.path().join("secret")).unwrap();
        assert_ne!(secret, [7; 32]);
        assert_ne!(secret, [9; 32]);
        assert!(!root.path().join("votport.db-wal").exists());
        assert!(!root.path().join("votport.db-shm").exists());
        assert!(!root.path().join(PENDING_FILE).exists());
        assert!(fs::read_dir(root.path())
            .unwrap()
            .flatten()
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".votport-restore-rollback-")));
        let restored = crate::store::Store::open(root.path()).unwrap();
        assert_eq!(
            decode_config(restored.setting(SETTING_KEY).unwrap()).unwrap(),
            BackupConfig {
                enabled: false,
                ..historical
            }
        );
    }

    #[test]
    fn an_applied_boot_restore_is_logged_and_audited() {
        let (root, store) = initialized_root();
        let archive = root.path().join("bundle.tar");
        create_archive(&store, root.path(), &archive, crate::store::SCHEMA_VERSION).unwrap();
        let stage = root.path().join(".votport-restore-stage-test");
        fs::create_dir(&stage).unwrap();
        let manifest =
            validate_and_extract(&archive, &stage, crate::store::SCHEMA_VERSION).unwrap();
        drop(store);
        write_pending_restore(
            root.path(),
            CleanupPath::directory(stage),
            manifest.clone(),
            RestoreMode::Historical,
            Some("arch-7"),
        )
        .unwrap();
        // Capture the boot log the way the scratch-removal warning is
        // asserted: a JSON subscriber over a temp file (audit finding 494).
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        let applied = tracing::subscriber::with_default(subscriber, || {
            apply_pending_restore(root.path(), crate::store::SCHEMA_VERSION).unwrap()
        })
        .expect("an applied restore is returned to the caller");
        assert_eq!(applied.archive.as_deref(), Some("arch-7"));
        assert_eq!(applied.created_at, manifest.created_at);
        assert_eq!(applied.mode, RestoreMode::Historical);
        assert_eq!(applied.schema_version, crate::store::SCHEMA_VERSION);
        let lines: Vec<String> = std::fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert!(
            lines.iter().any(|line| {
                line.contains("backup_restore_applied")
                    && line.contains(r#""id":"arch-7""#)
                    && line.contains(r#""mode":"historical""#)
            }),
            "applied restore line missing from {lines:?}"
        );

        // The freshly restored store carries the audit row that marks the
        // silent gap between the last pre-backup entry and the next login.
        let restored_store = crate::store::Store::open(root.path()).unwrap();
        record_applied_restore(&restored_store, &applied);
        assert!(restored_store
            .audit_export(Some(""), 0, 0, 100)
            .unwrap()
            .iter()
            .any(|row| row.event == "backup_restore_applied"));
    }

    #[test]
    fn historical_restore_suspends_authority_and_preserves_evidence_while_replica_resumes() {
        use crate::store::tests::{test_link, test_outbound_grant};
        use crate::workflow::tests::{project, request};
        use rusqlite::params;
        for mode in [RestoreMode::Historical, RestoreMode::Replica] {
            let (root, store) = initialized_root();
            store.insert_link(test_link("link")).unwrap();
            let project = store.save_delivery_project("", "admin", project()).unwrap();
            let mut jobs = Vec::new();
            for state in [
                "queued",
                "preparing",
                "exporting",
                "failed",
                "ready",
                "retired",
            ] {
                let mut request = request();
                request.operation_id = state.into();
                let mut job = store
                    .enqueue_delivery_job("", "sender", 1, None, project.clone(), request)
                    .unwrap();
                job.state = state.parse().unwrap();
                job.checks["snapshot_bytes"] = serde_json::json!(17);
                job.checks["route_revocations"] =
                    serde_json::json!({"destination":{"state":"pending"}});
                let mut grant = test_outbound_grant(&job.id, "", 0);
                grant.token_hash =
                    crate::auth::hash_token(&store.delivery_job_token("", &job.id).unwrap());
                grant.expires_at = now() + 3600;
                if state == "retired" {
                    grant.revoked_at = Some(7);
                }
                if state == "exporting" {
                    job.received = Some(crate::workflow::Received {
                        link_id: "link".into(),
                        upload_id: "upload".into(),
                    });
                }
                store.insert_outbound_grant(grant).unwrap();
                let source = store
                    .event_signer
                    .sign_route(crate::route_protocol::RouteDocument {
                        issuer: store.event_signer.public_hex.clone(),
                        operation_id: job.id.clone(),
                        manifest: "ab".repeat(32),
                        label: "delivery".into(),
                        metadata: Default::default(),
                        parent_receipt: None,
                        visited: vec![store.event_signer.public_hex.clone()],
                        permission: None,
                    });
                store.with(|c| {
                    c.execute("UPDATE delivery_jobs SET state=?2,deadline=1,document=?3 WHERE id=?1", params![job.id, state, serde_json::to_string(&job).unwrap()])?;
                    c.execute("INSERT INTO outbound_routes(job_id,destination_id,origin,route_id,peer_key,source) VALUES (?1,'destination','http://localhost','route',?2,?3)", params![job.id,store.event_signer.public_hex,serde_json::to_string(&source).unwrap()])?;
                    Ok(())
                }).unwrap();
                if state == "ready" {
                    store
                        .rotate_delivery_job_token("", &job.id, 0, &crate::auth::random_token())
                        .unwrap();
                    job = store.delivery_job(&job.id).unwrap().unwrap();
                }
                let token = store.delivery_job_token("", &job.id).unwrap();
                jobs.push((job, source, token));
            }
            store.with(|c| c.execute_batch(
                "INSERT INTO settings(key,value,updated_at) VALUES ('backup_config','{}',1),('scim_token','current',1),('scim_token_previous','previous',1),('replica_token','replica',1),('upload_retention_days','30',1);
                 INSERT INTO delivery_storage(id,revision,document) VALUES ('destination',1,'{\"enabled\":true}');
                 INSERT INTO delivery_storage_credentials(id,document) VALUES ('destination','{\"secret\":\"kept\"}');
                 INSERT INTO notification_destinations(id,tenant,document) VALUES ('notify','','{\"enabled\":true,\"token\":\"kept\"}');
                 INSERT INTO delivery_webhooks(tenant,url,secret,revision,enabled,cursor) VALUES ('','http://localhost','kept',1,1,0);
                 INSERT INTO delivery_webhook_attempts(tenant,event_id,revision,status,next_try) VALUES ('',1,1,'pending',0);
                 INSERT INTO automation_tokens(id,token_hash,tenant,label,created_at,expires_at) VALUES ('agent','agent-token','','agent',1,9223372036854775807);
                 INSERT INTO trade_routes(id,tenant,direction,peer_key,endpoint,document,credential,enrollment) VALUES ('trade','','incoming','peer','link','{\"state\":\"active\",\"cancel_active\":true}','credential','{}');
                 INSERT INTO trade_endpoints(id,tenant,document) VALUES ('link','','{}');
                 INSERT INTO trade_invitations(id,tenant,endpoint,secret_hash,expected_key,expires_at) VALUES ('invitation','','link','secret','peer',9223372036854775807);
                 INSERT INTO trade_rotations(route_id,credential) VALUES ('trade','next');
                 INSERT INTO inbound_routes(id,tenant,link_id,issuer,operation_id,source,ancestry,created_at) VALUES ('inbound','','link','peer','operation','{}','[]',1);
                 INSERT INTO outbound_fetch_tickets(token_id,grant_id,manifest_root,expires_at) VALUES ('ticket','grant','root',9223372036854775807);
                 INSERT INTO upload_sessions(id,link_id,tenant,dest_dir,dest_rel,package_suite,package_root,package_length,started_at,created_at) VALUES ('session','link','','dir','dir',1,'root',1,1,1);
                 INSERT INTO upload_session_files(session_id,entry,display_path,stored_components,object_suite,object_root,object_length,staging_path,journal_path,incarnation) VALUES ('session',0,'file','[]',1,'root',1,'stage','journal','incarnation');
                 INSERT OR IGNORE INTO tenants(key,incarnation,label,created_at) VALUES ('retained','retained-1','Retained',1);
                 UPDATE tenants SET retention_days=30;
                 UPDATE links SET retention_days=30;"
            )).unwrap();
            let archive = root.path().join("restore.tar");
            create_archive(&store, root.path(), &archive, crate::store::SCHEMA_VERSION).unwrap();
            drop(store);
            let stage = root.path().join(".votport-restore-stage-policy");
            fs::create_dir(&stage).unwrap();
            let manifest =
                validate_and_extract(&archive, &stage, crate::store::SCHEMA_VERSION).unwrap();
            write_pending_restore(
                root.path(),
                CleanupPath::directory(stage),
                manifest,
                mode,
                None,
            )
            .unwrap();
            assert_eq!(
                read_pending_restore(root.path()).unwrap().unwrap().mode,
                mode
            );
            let marker_path = root.path().join(PENDING_FILE);
            let marker = fs::read(&marker_path).unwrap();
            for value in [None, Some("unknown")] {
                let mut invalid: serde_json::Value = serde_json::from_slice(&marker).unwrap();
                if let Some(value) = value {
                    invalid["mode"] = serde_json::json!(value);
                } else {
                    invalid.as_object_mut().unwrap().remove("mode");
                }
                fs::write(&marker_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
                assert!(read_pending_restore(root.path()).is_err());
            }
            fs::write(&marker_path, marker).unwrap();
            apply_pending_restore(root.path(), crate::store::SCHEMA_VERSION).unwrap();
            prepare_restored_database(
                &root.path().join("votport.db"),
                crate::store::SCHEMA_VERSION,
                mode,
            )
            .unwrap();
            let store = crate::store::Store::open(root.path()).unwrap();
            let historical = mode == RestoreMode::Historical;
            assert_ne!(fs::read(root.path().join("secret")).unwrap(), [7; 32]);
            assert_eq!(store.link("", "link").unwrap().unwrap().active, !historical);
            let backup_setting = store
                .setting(SETTING_KEY)
                .unwrap()
                .expect("backup settings retained");
            assert_eq!(
                decode_config(Some(backup_setting)).unwrap(),
                BackupConfig::default()
            );
            for (key, previous) in [
                ("scim_token", "current"),
                ("scim_token_previous", "previous"),
                ("replica_token", "replica"),
                ("upload_retention_days", "30"),
            ] {
                assert_eq!(
                    store.setting(key).unwrap().as_deref(),
                    Some(if historical {
                        if key == "upload_retention_days" {
                            "0"
                        } else {
                            ""
                        }
                    } else {
                        previous
                    })
                );
            }
            // Tenant and link retention narrow the platform value, so a
            // historical restore clears them too.
            let scoped: Vec<Option<i64>> = store
                .with(|c| {
                    c.prepare("SELECT retention_days FROM links UNION ALL SELECT retention_days FROM tenants")?
                        .query_map([], |row| row.get(0))?
                        .collect()
                })
                .unwrap();
            assert!(scoped.len() >= 2);
            assert!(scoped
                .iter()
                .all(|days| *days == if historical { None } else { Some(30) }));
            for (job, source, token) in &jobs {
                let restored = store.delivery_job(&job.id).unwrap().unwrap();
                assert_eq!(store.delivery_job_token("", &job.id).unwrap(), *token);
                assert_eq!(restored.token_generation, job.token_generation);
                assert_eq!(
                    store
                        .delivery_token_active(&job.id, &crate::auth::hash_token(token))
                        .unwrap(),
                    !historical && job.state != crate::workflow::JobState::Retired
                );
                assert_eq!(
                    restored.state,
                    if historical {
                        crate::workflow::JobState::Suspended
                    } else {
                        job.state
                    }
                );
                assert_eq!(restored.checks, job.checks);
                assert_eq!(
                    store
                        .outbound_grant_by_id(&job.id)
                        .unwrap()
                        .unwrap()
                        .revoked_at
                        .is_some(),
                    historical || job.state == crate::workflow::JobState::Retired
                );
                if job.state == crate::workflow::JobState::Retired {
                    assert_eq!(
                        store
                            .outbound_grant_by_id(&job.id)
                            .unwrap()
                            .unwrap()
                            .revoked_at,
                        Some(7)
                    );
                }
                let saved: String = store
                    .with(|c| {
                        c.query_row(
                            "SELECT source FROM outbound_routes WHERE job_id=?1",
                            [&job.id],
                            |row| row.get(0),
                        )
                    })
                    .unwrap();
                assert_eq!(
                    serde_json::from_str::<crate::route_protocol::SignedRoute>(&saved).unwrap(),
                    *source
                );
                if historical {
                    assert!(!restored.released());
                    for action in ["approve", "retry", "cancel"] {
                        assert!(store
                            .change_delivery_job("", &job.id, "sender", true, action, None)
                            .unwrap_err()
                            .contains("held after restore"));
                    }
                    assert!(store
                        .rotate_delivery_job_token("", &job.id, 0, "new")
                        .is_err());
                    assert!(store
                        .extend_outbound_grant("", &job.id, 3600, now())
                        .is_err());
                }
            }
            for query in [
                "SELECT COUNT(*) FROM upload_sessions", "SELECT COUNT(*) FROM upload_session_files",
                "SELECT COUNT(*) FROM outbound_fetch_tickets", "SELECT COUNT(*) FROM trade_invitations",
                "SELECT COUNT(*) FROM trade_rotations", "SELECT COUNT(*) FROM automation_tokens WHERE revoked_at IS NULL",
                "SELECT COUNT(*) FROM inbound_routes WHERE revoked_at IS NULL",
                "SELECT COUNT(*) FROM delivery_storage WHERE json_extract(document,'$.enabled')=1",
                "SELECT COUNT(*) FROM notification_destinations WHERE json_extract(document,'$.enabled')=1",
                "SELECT COUNT(*) FROM delivery_webhooks WHERE enabled=1",
                "SELECT COUNT(*) FROM trade_routes WHERE credential='credential' AND enrollment IS NOT NULL AND json_extract(document,'$.state')='active'",
            ] {
                let count: i64 = store.with(|c| c.query_row(query, [], |row| row.get(0))).unwrap();
                assert_eq!(count, i64::from(!historical), "{query}");
            }
            assert_eq!(
                store
                    .with(|c| c.query_row(
                        "SELECT document FROM delivery_storage_credentials WHERE id='destination'",
                        [],
                        |row| row.get::<_, String>(0)
                    ))
                    .unwrap(),
                "{\"secret\":\"kept\"}"
            );
            assert_eq!(
                store
                    .with(|c| c.query_row(
                        "SELECT COUNT(*) FROM delivery_webhook_attempts",
                        [],
                        |row| row.get::<_, i64>(0)
                    ))
                    .unwrap(),
                1
            );
            assert_eq!(
                store.receive_workflow_pending("", "link").unwrap(),
                !historical
            );
            if historical {
                assert!(store
                    .claim_delivery_job("new-owner", now())
                    .unwrap()
                    .is_none());
                assert!(store
                    .claim_snapshot_retirement(now() + 30 * 86400)
                    .unwrap()
                    .is_none());
                assert!(store.claim_route_revocation(now()).unwrap().is_none());
                let events = store
                    .with(|c| {
                        c.query_row("SELECT COUNT(*) FROM delivery_events", [], |row| {
                            row.get::<_, i64>(0)
                        })
                    })
                    .unwrap();
                store.escalate_delivery_jobs(now()).unwrap();
                assert_eq!(
                    store
                        .with(|c| c
                            .query_row("SELECT COUNT(*) FROM delivery_events", [], |row| row
                                .get::<_, i64>(0)))
                        .unwrap(),
                    events
                );
                store.queue_delivery_webhooks(now()).unwrap();
                assert!(store.due_delivery_webhooks(now()).unwrap().is_empty());
                assert!(store
                    .authenticate_automation_token("agent-token", now())
                    .unwrap()
                    .is_none());
            }
        }
    }

    #[test]
    fn backup_rejects_malformed_or_mismatched_identities() {
        let (root, store) = initialized_root();
        fs::write(root.path().join("receipt.key"), b"short").unwrap();
        assert!(create_archive(
            &store,
            root.path(),
            &root.path().join("bad-receipt.tar"),
            crate::store::SCHEMA_VERSION,
        )
        .is_err());

        fs::write(root.path().join("receipt.key"), [8; 32]).unwrap();
        let certificate_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let other_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&certificate_key)
            .unwrap();
        fs::write(root.path().join("push.crt"), certificate.pem()).unwrap();
        fs::write(
            root.path().join("push.key"),
            certificate_key.serialize_pem(),
        )
        .unwrap();
        assert!(create_archive(
            &store,
            root.path(),
            &root.path().join("valid-push.tar"),
            crate::store::SCHEMA_VERSION,
        )
        .is_ok());
        fs::write(root.path().join("push.key"), other_key.serialize_pem()).unwrap();
        assert!(create_archive(
            &store,
            root.path(),
            &root.path().join("bad-push.tar"),
            crate::store::SCHEMA_VERSION,
        )
        .is_err());
    }

    #[test]
    fn pruning_zero_means_unlimited() {
        let root = tempfile::tempdir().unwrap();
        let first = "votport-backup-v2-1-a.tar";
        let second = "votport-backup-v2-2-b.tar.age";
        fs::write(root.path().join(first), b"one").unwrap();
        fs::write(root.path().join(second), b"two").unwrap();
        prune_local_root(root.path(), 0, 0).unwrap();
        assert!(root.path().join(first).exists());
        assert!(root.path().join(second).exists());
        prune_local_root(root.path(), 0, 1).unwrap();
        assert_eq!(
            inventory_local_root(root.path(), root.path())
                .unwrap()
                .len(),
            1
        );
    }

    /// Audit finding 558: the inventory stops the writable-ancestor walk at
    /// data_dir, exactly like validate_local_root, so a group-writable
    /// ancestor above the data directory (Ubuntu's umask 002 makes operator
    /// directories 0775) cannot empty an inventory whose archives write and
    /// prune without complaint.
    #[test]
    fn inventory_local_root_stops_the_ancestor_walk_at_the_data_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let mut permissions = fs::metadata(directory.path()).unwrap().permissions();
        permissions.set_mode(0o775);
        fs::set_permissions(directory.path(), permissions).unwrap();
        let data_dir = directory.path().join("data");
        let root = data_dir.join("backups");
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)
            .unwrap();
        let id = "votport-backup-v2-20260101T000000Z.tar";
        fs::write(root.join(id), b"archive").unwrap();
        let inventory = inventory_local_root(&root, &data_dir).unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].id, id);
    }

    #[test]
    fn protected_local_backup_survives_retention_ties() {
        let root = tempfile::tempdir().unwrap();
        let protected = "votport-backup-v2-1-a.tar";
        let other = "votport-backup-v2-1-b.tar";
        let modified =
            fs::FileTimes::new().set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1));
        for name in [protected, other] {
            let file = File::create(root.path().join(name)).unwrap();
            file.set_times(modified).unwrap();
        }
        prune_local_root_protected(root.path(), 0, 1, Some(protected)).unwrap();
        assert!(root.path().join(protected).exists());
        assert!(!root.path().join(other).exists());
    }

    #[test]
    fn local_backup_age_pruning_uses_the_guarded_time() {
        let root = tempfile::tempdir().unwrap();
        let old = root.path().join("votport-backup-v2-1-old.tar");
        let recent = root.path().join("votport-backup-v2-2-recent.tar");
        let base = 1_800_000_000;
        for (path, at) in [(&old, base), (&recent, base + 9 * 86_400)] {
            let file = File::create(path).unwrap();
            file.set_times(
                fs::FileTimes::new().set_modified(UNIX_EPOCH + std::time::Duration::from_secs(at)),
            )
            .unwrap();
        }
        prune_local_root_protected_at(
            root.path(),
            7,
            0,
            None,
            UNIX_EPOCH + std::time::Duration::from_secs(base + 10 * 86_400),
        )
        .unwrap();
        assert!(!old.exists());
        assert!(recent.exists());
    }

    #[test]
    fn backup_lock_warnings_start_at_the_interval_and_reset() {
        use std::time::{Duration, Instant};
        let mut config = BackupConfig {
            enabled: true,
            interval_secs: 300,
            ..BackupConfig::default()
        };
        let start = Instant::now();
        let mut busy_since = None;
        for (offset, expected) in [
            (0, false),
            (299, false),
            (300, true),
            (301, false),
            (599, false),
            (600, true),
        ] {
            assert_eq!(
                backup_lock_warning_due(
                    &mut busy_since,
                    &config,
                    start + Duration::from_secs(offset)
                ),
                expected
            );
        }
        config.enabled = false;
        assert!(!backup_lock_warning_due(
            &mut busy_since,
            &config,
            start + Duration::from_secs(900)
        ));
        assert_eq!(busy_since, None);
        config.enabled = true;
        assert!(!backup_lock_warning_due(
            &mut busy_since,
            &config,
            start + Duration::from_secs(1200)
        ));
        assert_eq!(busy_since, Some(start + Duration::from_secs(1200)));
        assert!(backup_lock_warning_due(
            &mut busy_since,
            &config,
            start + Duration::from_secs(1500)
        ));
    }

    #[tokio::test]
    async fn s3_listing_limits_preserve_all_remote_objects() {
        use object_store::throttle::{ThrottleConfig, ThrottledStore};
        use std::time::Duration;
        let store = Arc::new(ThrottledStore::new(
            object_store::memory::InMemory::new(),
            ThrottleConfig::default(),
        ));
        let config = BackupConfig {
            s3_prefix: Some("backups".into()),
            ..BackupConfig::default()
        };
        let keys = [
            "votport-backup-v2-1-a.tar",
            "votport-backup-v2-2-b.tar",
            "unrelated",
        ]
        .map(|id| s3_path(&config, id));
        for key in &keys {
            store.put(key, "file".into()).await.unwrap();
        }
        for (limit, delay, message) in [(2, 0, "exceeds"), (3, 50, "timed out")] {
            store.config_mut(|c| c.wait_list_per_entry = Duration::from_millis(delay));
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                prune_s3_store(
                    store.clone(),
                    &config,
                    None,
                    1,
                    None,
                    limit,
                    Duration::from_millis(90),
                ),
            )
            .await
            .unwrap();
            assert!(result.unwrap_err().contains(message));
            for key in &keys {
                assert!(store.head(key).await.is_ok(), "{key}");
            }
        }
        store.config_mut(|c| c.wait_list_per_entry = Duration::ZERO);
        let files = list_s3_backups(&*store, &config, 3, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(files.len(), 2);
        assert!(files
            .iter()
            .all(|file| owned_s3_id(&config, &file.location).is_some()));
        prune_s3_store(
            store.clone(),
            &config,
            None,
            1,
            None,
            3,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(store.head(&keys[2]).await.is_ok());
        assert_eq!(
            usize::from(store.head(&keys[0]).await.is_ok())
                + usize::from(store.head(&keys[1]).await.is_ok()),
            1
        );
    }

    #[tokio::test]
    async fn held_backup_run_preserves_count_pruning() {
        let root = tempfile::tempdir().unwrap();
        let config = crate::api::testing::config(root.path());
        let store = crate::store::Store::open(&config.data_dir).unwrap();
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM meta WHERE key = ?1",
                    [crate::store::RETENTION_CLOCK_KEY],
                )
            })
            .unwrap();
        drop(store);
        let app = crate::app::build(config).unwrap();
        let backups = ensure_backups_dir(&app.config.data_dir).unwrap();
        let old = backups.join("votport-backup-v2-1-old.tar");
        fs::write(&old, b"old").unwrap();
        let backup_config = BackupConfig {
            retention_days: 7,
            retention_count: 1,
            destination: Destination::Local,
            ..BackupConfig::default()
        };
        run(Arc::clone(&app), backup_config, BackupSecrets::default())
            .await
            .unwrap();
        assert!(!old.exists());
        assert_eq!(local_files(&backups).unwrap().len(), 1);
    }

    #[test]
    fn s3_age_cutoff_disables_zero_days_and_saturates_bounds() {
        assert_eq!(s3_age_cutoff(100_000, 0), None);
        assert_eq!(s3_age_cutoff(100_000, 1), Some(13_600));
        assert_eq!(s3_age_cutoff(1, u64::MAX), Some(0));
        assert_eq!(s3_age_cutoff(u64::MAX, 1), Some(i64::MAX));
    }

    #[tokio::test]
    async fn s3_count_pruning_helper_preserves_policy_during_hold() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let config = BackupConfig {
            s3_prefix: Some("backups".into()),
            ..BackupConfig::default()
        };
        for id in ["votport-backup-v2-1-old.tar", "votport-backup-v2-2-new.tar"] {
            store
                .put(&s3_path(&config, id), "backup".into())
                .await
                .unwrap();
        }
        prune_s3_store(
            Arc::clone(&store),
            &config,
            None,
            1,
            None,
            MAX_S3_LIST_ENTRIES,
            S3_LIST_TIMEOUT,
        )
        .await
        .unwrap();
        assert_eq!(
            list_s3_backups(&*store, &config, MAX_S3_LIST_ENTRIES, S3_LIST_TIMEOUT)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn protected_s3_backup_survives_same_second_retention() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let config = BackupConfig {
            s3_prefix: Some("backups".into()),
            ..BackupConfig::default()
        };
        let protected = "votport-backup-v2-1-a.tar";
        let other = "votport-backup-v2-1-b.tar";
        let protected_path = s3_path(&config, protected);
        let other_path = s3_path(&config, other);
        loop {
            store.put(&protected_path, "one".into()).await.unwrap();
            store.put(&other_path, "two".into()).await.unwrap();
            if store
                .head(&protected_path)
                .await
                .unwrap()
                .last_modified
                .timestamp()
                == store
                    .head(&other_path)
                    .await
                    .unwrap()
                    .last_modified
                    .timestamp()
            {
                break;
            }
        }
        prune_s3_store(
            Arc::clone(&store),
            &config,
            None,
            1,
            Some(protected),
            MAX_S3_LIST_ENTRIES,
            S3_LIST_TIMEOUT,
        )
        .await
        .unwrap();
        assert!(store.head(&protected_path).await.is_ok());
        assert!(store.head(&other_path).await.is_err());
    }

    #[test]
    fn s3_prefix_ownership_is_exact() {
        let config = BackupConfig {
            s3_prefix: Some("team/backups".into()),
            ..BackupConfig::default()
        };
        let id = "votport-backup-v2-1-a.tar";
        assert_eq!(
            owned_s3_id(&config, &ObjectPath::from(format!("team/backups/{id}"))),
            Some(id)
        );
        assert_eq!(
            owned_s3_id(&config, &ObjectPath::from(format!("team/backups-old/{id}"))),
            None
        );
        assert_eq!(
            owned_s3_id(
                &config,
                &ObjectPath::from(format!("team/backups/nested/{id}"))
            ),
            None
        );
    }

    #[tokio::test]
    async fn partial_backup_failure_preserves_success_and_retries_after_backoff() {
        let requested = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&requested);
        let router = axum::Router::new().fallback(move || {
            seen.store(true, Ordering::Relaxed);
            async { axum::http::StatusCode::FORBIDDEN }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        for previous in [None, Some(now() - 90_000)] {
            requested.store(false, Ordering::Relaxed);
            let root = tempfile::tempdir().unwrap();
            let app = crate::api::testing::build(root.path());
            let config = BackupConfig {
                enabled: true,
                destination: Destination::Both,
                s3_endpoint: Some(endpoint.clone()),
                s3_bucket: Some("backups".into()),
                s3_region: Some("us-east-1".into()),
                s3_path_style: true,
                retention_count: 1,
                ..BackupConfig::default()
            };
            write_status(
                &app.config.data_dir,
                BackupStatus {
                    last_success_at: previous,
                    ..BackupStatus::default()
                },
            )
            .unwrap();
            let secrets = BackupSecrets {
                access_key_id: Some("test-key".into()),
                secret_access_key: Some("test-secret".into()),
                ..BackupSecrets::default()
            };
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                run(Arc::clone(&app), config.clone(), secrets),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert!(requested.load(Ordering::Relaxed));
            assert_eq!(error, "S3 upload could not start");
            assert_eq!(
                local_files(&config.local_root(&app.config.data_dir).unwrap())
                    .unwrap()
                    .len(),
                1
            );
            let failed = read_status(&app.config.data_dir).unwrap();
            assert_eq!(failed.last_success_at, previous);
            assert_eq!(failed.last_error.as_deref(), Some(error.as_str()));
            let attempt = failed.last_attempt_at.unwrap();
            assert!(!scheduler_due(&config, &failed, attempt + 299));
            assert!(scheduler_due(&config, &failed, attempt + 300));
            // A retry against the still-failing remote leaves the restore
            // points from before the last complete run alone, and keeps only
            // the newest of the copies taken during the outage: rotating by
            // count would replace the pre-outage points, and keeping every
            // retry would fill the data volume.
            let root = config.local_root(&app.config.data_dir).unwrap();
            let pre_outage = previous.map(|at| {
                let path = root.join(format!("votport-backup-v2-{at}-{}.tar", "a".repeat(32)));
                fs::write(&path, b"pre-outage").unwrap();
                fs::File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    // Written within the second the success was recorded in,
                    // which the whole-second comparison keeps as pre-outage.
                    .set_modified(UNIX_EPOCH + std::time::Duration::from_millis(at * 1000 + 400))
                    .unwrap();
                path
            });
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            let secrets = BackupSecrets {
                access_key_id: Some("test-key".into()),
                secret_access_key: Some("test-secret".into()),
                ..BackupSecrets::default()
            };
            tokio::time::timeout(
                std::time::Duration::from_secs(15),
                run(Arc::clone(&app), config.clone(), secrets),
            )
            .await
            .unwrap()
            .unwrap_err();
            let kept = local_files(&root).unwrap();
            assert_eq!(kept.len(), 1 + usize::from(pre_outage.is_some()));
            if let Some(path) = &pre_outage {
                assert!(path.exists(), "the pre-outage restore point is kept");
            }
            let local = BackupConfig {
                destination: Destination::Local,
                ..config
            };
            run(Arc::clone(&app), local.clone(), BackupSecrets::default())
                .await
                .unwrap();
            let succeeded = read_status(&app.config.data_dir).unwrap();
            assert!(succeeded.last_error.is_none());
            assert!(succeeded
                .last_success_at
                .is_some_and(|success| success >= attempt));
            assert!(!scheduler_due(&local, &succeeded, attempt + 300));
        }
        stop.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn scheduler_pauses_without_changing_history_and_resumes_after_restore_clears() {
        use std::time::Duration;

        let root = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(root.path());
        let config = BackupConfig {
            enabled: true,
            ..BackupConfig::default()
        };
        app.store
            .put_settings(
                "test",
                &[(
                    SETTING_KEY.into(),
                    crate::store::SettingWrite::Set(serde_json::to_string(&config).unwrap()),
                )],
            )
            .unwrap();
        write_status(
            &app.config.data_dir,
            BackupStatus {
                last_attempt_at: Some(1),
                last_success_at: Some(1),
                last_error: Some("previous attempt failed".into()),
                ..BackupStatus::default()
            },
        )
        .unwrap();
        let status_path = app.config.data_dir.join(STATUS_FILE);
        let history = fs::read(&status_path).unwrap();
        let archive_root = ensure_backups_dir(&app.config.data_dir).unwrap();
        let pending = app.config.data_dir.join(PENDING_FILE);
        fs::write(&pending, b"pending").unwrap();
        let mut worker = Box::pin(scheduler_with_interval(
            Arc::clone(&app),
            Duration::from_millis(20),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(80), &mut worker)
                .await
                .is_err(),
            "pending restore must pause the scheduler, not terminate it"
        );
        assert_eq!(fs::read(&status_path).unwrap(), history);
        assert!(local_files(&archive_root).unwrap().is_empty());

        fs::remove_file(pending).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                _ = &mut worker => panic!("scheduler terminated after the restore cleared"),
                _ = async {
                    loop {
                        let status = read_status(&app.config.data_dir).unwrap();
                        if status.last_success_at.is_some_and(|at| at > 1) {
                            assert!(status.last_error.is_none());
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                } => {}
            }
        })
        .await
        .expect("same scheduler must resume and complete a backup");
        assert_eq!(local_files(&archive_root).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn scheduler_exits_before_a_shutdown_tick_starts_backup() {
        let root = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(root.path());
        app.request_shutdown();

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            scheduler_with_interval(Arc::clone(&app), std::time::Duration::from_millis(1)),
        )
        .await
        .expect("scheduler must observe shutdown");
        assert!(!root.path().join("backups").exists());
        assert!(read_status(&app.config.data_dir).is_ok());
    }

    #[test]
    fn scheduler_uses_durable_success_and_failure_times() {
        let config = BackupConfig {
            enabled: true,
            interval_secs: 600,
            ..BackupConfig::default()
        };
        assert!(scheduler_due(&config, &BackupStatus::default(), 1_000));
        assert!(!scheduler_due(
            &config,
            &BackupStatus {
                last_success_at: Some(900),
                ..BackupStatus::default()
            },
            1_000
        ));
        assert!(!scheduler_due(
            &config,
            &BackupStatus {
                last_success_at: Some(1),
                last_attempt_at: Some(900),
                last_error: Some("failed".into()),
                ..BackupStatus::default()
            },
            1_000
        ));
        assert!(scheduler_due(
            &config,
            &BackupStatus {
                last_attempt_at: Some(600),
                last_error: Some("failed".into()),
                ..BackupStatus::default()
            },
            1_000
        ));
    }
}
