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
use std::time::{SystemTime, UNIX_EPOCH};

use age::secrecy::SecretString;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::{MultipartUpload, ObjectStore};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{Archive, Builder, Header};

pub const SETTING_KEY: &str = "backup_config";
pub const SECRETS_FILE: &str = "backup-secrets.json";
pub const STATUS_FILE: &str = "backup-status.json";
pub const PENDING_FILE: &str = ".votport-restore-pending.json";
pub const VERSION: u32 = 1;
const MAX_MANIFEST: u64 = 64 * 1024;
const MAX_MARKER: u64 = MAX_MANIFEST + 16 * 1024;
const MAX_IDENTITY: u64 = 16 * 1024 * 1024;
const PART_SIZE: usize = 5 * 1024 * 1024;
const MANAGED_FILES: [&str; 6] = [
    "votport.db",
    "secret",
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
    #[serde(default)]
    phase: RestorePhase,
    #[serde(default)]
    rollback: Option<String>,
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

fn validate_local_root(root: &Path, data_dir: &Path, require_existing: bool) -> Result<(), String> {
    if root == data_dir {
        return Err("local backup path must not be the data directory".into());
    }
    if require_existing && !root.exists() {
        return Err("custom local backup path must already exist".into());
    }
    let trusted = root.starts_with(data_dir).then_some(data_dir);
    validate_private_ancestry(root, trusted)
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

fn validate_endpoint(value: &str) -> Result<(), String> {
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
fn validate_bucket(value: &str) -> Result<(), String> {
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

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
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
        match fs::symlink_metadata(&self.path) {
            Ok(meta) if self.directory && meta.is_dir() && !meta.file_type().is_symlink() => {
                let _ = fs::remove_dir_all(&self.path);
            }
            Ok(meta) if !self.directory && meta.is_file() && !meta.file_type().is_symlink() => {
                let _ = fs::remove_file(&self.path);
            }
            Err(_) => {}
            Ok(_) => {}
        }
    }
}

fn publish_new(source: &Path, destination: &Path) -> Result<(), String> {
    fs::hard_link(source, destination).map_err(|e| e.to_string())?;
    fs::remove_file(source).map_err(|e| e.to_string())
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
    (name.starts_with("votport-backup-v1-")
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
    [
        "secret",
        "receipt.key",
        "push-issuer.key",
        "push.crt",
        "push.key",
    ]
    .into_iter()
    .map(|name| (name, data_dir.join(name)))
    .filter(|(_, p)| {
        fs::symlink_metadata(p)
            .map(|m| {
                m.file_type().is_file() && !m.file_type().is_symlink() && m.len() <= MAX_IDENTITY
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
    for required in ["secret", "receipt.key"] {
        if !identity_names.contains(required) {
            return Err(format!("required identity missing: {required}"));
        }
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
            || !matches!(
                name,
                "manifest.json"
                    | "votport.db"
                    | "secret"
                    | "receipt.key"
                    | "push-issuer.key"
                    | "push.crt"
                    | "push.key"
            )
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
            let mut output = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&target)
                .map_err(|e| e.to_string())?;
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
    if manifest.version != VERSION || manifest.schema_version > schema_version {
        return Err("unsupported backup version or schema".into());
    }
    let expected: HashSet<_> = manifest
        .entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    if expected.len() != manifest.entries.len()
        || !expected.contains("votport.db")
        || !expected.contains("secret")
        || !expected.contains("receipt.key")
        || expected
            .iter()
            .any(|name| !MANAGED_FILES.contains(name) || *name == "manifest.json")
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
            || !MANAGED_FILES.contains(&name.as_str())
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
    for name in ["secret", "receipt.key", "push-issuer.key"] {
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
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| format!("invalid backup database: {e}"))?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|e| format!("invalid backup database: {e}"))?;
    if integrity != "ok" {
        return Err("backup database integrity check failed".into());
    }
    let actual_schema = connection
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|e| format!("invalid backup schema: {e}"))?
        .parse::<u64>()
        .map_err(|_| "invalid backup schema".to_owned())?;
    if actual_schema != expected_schema || actual_schema > current_schema {
        return Err("backup database schema does not match its manifest or is too new".into());
    }
    Ok(())
}

fn disable_restored_backups(path: &Path) -> Result<(), String> {
    let connection = rusqlite::Connection::open(path)
        .map_err(|e| format!("cannot disable restored backups: {e}"))?;
    let _: String = connection
        .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
        .map_err(|e| format!("cannot disable restored backups: {e}"))?;
    let has_settings: bool = connection
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'settings')",
            [],
            |row| row.get(0),
        )
        .map_err(|e| format!("cannot inspect restored settings: {e}"))?;
    if has_settings {
        connection
            .execute("DELETE FROM settings WHERE key = ?1", [SETTING_KEY])
            .map_err(|e| format!("cannot disable restored backups: {e}"))?;
    }
    drop(connection);
    File::open(path)
        .map_err(|e| e.to_string())?
        .sync_all()
        .map_err(|e| e.to_string())
}

/// Commit a validated extraction as a restart-time transaction. The marker
/// contains only a basename, and the extracted directory has already passed
/// the fixed archive allowlist above.
pub fn write_pending_restore(
    data_dir: &Path,
    extracted: &Path,
    manifest: Manifest,
) -> Result<(), String> {
    let stage_name = extracted
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("invalid restore stage")?;
    if !stage_name.starts_with(".votport-restore-stage-") || stage_name.contains('/') {
        return Err("invalid restore stage".into());
    }
    let marker = PendingRestore {
        stage: stage_name.to_owned(),
        version: VERSION,
        manifest,
        phase: RestorePhase::Prepared,
        rollback: None,
    };
    persist_pending_restore(data_dir, &marker)
}

fn persist_pending_restore(data_dir: &Path, marker: &PendingRestore) -> Result<(), String> {
    let bytes = serde_json::to_vec(marker).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_MARKER {
        return Err("pending restore marker is too large".into());
    }
    atomic_write_private(&data_dir.join(PENDING_FILE), &bytes)
}

pub fn apply_pending_restore(data_dir: &Path, schema_version: u64) -> Result<(), String> {
    let marker_path = data_dir.join(PENDING_FILE);
    let meta = match fs::symlink_metadata(&marker_path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() || meta.len() > MAX_MARKER {
        return Err("invalid pending restore marker".into());
    }
    let mut marker: PendingRestore =
        serde_json::from_slice(&fs::read(&marker_path).map_err(|e| e.to_string())?)
            .map_err(|_| "invalid pending restore marker".to_owned())?;
    if marker.version != VERSION
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
        for name in MANAGED_FILES
            .into_iter()
            .chain(["votport.db-wal", "votport.db-shm"])
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
            if entry.name == "secret" {
                continue;
            }
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

    // Historical backup destinations must never become active with the
    // deployment's current credentials. An admin explicitly re-enables them.
    disable_restored_backups(&data_dir.join("votport.db"))?;

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
    sync_directory(data_dir)
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn backup_filename(encrypted: bool) -> String {
    format!(
        "votport-backup-v1-{}-{}.tar{}",
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

pub fn ensure_backups_dir(data_dir: &Path) -> Result<PathBuf, String> {
    ensure_backup_root(&data_dir.join("backups"))
}
pub fn ensure_backup_root(path: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    crate::paths::tighten_private_dir(path)?;
    validate_private_ancestry(path, Some(path))?;
    Ok(path.to_path_buf())
}

pub fn prune_local(
    data_dir: &Path,
    retention_days: u64,
    retention_count: u64,
) -> Result<(), String> {
    prune_local_root(
        &ensure_backups_dir(data_dir)?,
        retention_days,
        retention_count,
    )
}
pub fn prune_local_root(
    root: &Path,
    retention_days: u64,
    retention_count: u64,
) -> Result<(), String> {
    prune_local_root_protected(root, retention_days, retention_count, None)
}

fn prune_local_root_protected(
    root: &Path,
    retention_days: u64,
    retention_count: u64,
    protected_id: Option<&str>,
) -> Result<(), String> {
    let root = ensure_backup_root(root)?;
    let mut files = local_files(&root)?;
    files.sort_by(|left, right| {
        (right.0.as_str() == protected_id.unwrap_or_default())
            .cmp(&(left.0.as_str() == protected_id.unwrap_or_default()))
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| right.0.cmp(&left.0))
    });
    let cutoff = SystemTime::now()
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
    loop {
        let mut buf = vec![0u8; PART_SIZE];
        let n = match tokio::io::AsyncReadExt::read(file, &mut buf).await {
            Ok(n) => n,
            Err(_) => {
                let _ = upload.abort().await;
                return Err("backup file could not be read".into());
            }
        };
        if n == 0 {
            break;
        }
        if upload.put_part(buf[..n].to_vec().into()).await.is_err() {
            let _ = upload.abort().await;
            return Err("S3 upload failed".into());
        }
    }
    if upload.complete().await.is_err() {
        let _ = upload.abort().await;
        return Err("S3 upload failed".into());
    }
    Ok(())
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
    if endpoint.starts_with("http://") {
        builder = builder.with_allow_http(true);
    }
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
    use futures_util::StreamExt;
    let store = s3_store(config, secrets)?;
    let root = s3_root(config);
    let list_prefix = (!root.is_empty()).then(|| ObjectPath::from(root));
    let mut stream = store.list(list_prefix.as_ref());
    let mut result = Vec::new();
    while let Some(item) = stream.next().await {
        let item = item.map_err(|_| "S3 snapshot inventory unavailable".to_owned())?;
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

pub async fn prune_s3(
    config: &BackupConfig,
    secrets: &BackupSecrets,
    retention_days: u64,
    retention_count: u64,
    protected_id: Option<&str>,
) -> Result<(), String> {
    let store = s3_store(config, secrets)?;
    prune_s3_store(store, config, retention_days, retention_count, protected_id).await
}

async fn prune_s3_store(
    store: Arc<dyn ObjectStore>,
    config: &BackupConfig,
    retention_days: u64,
    retention_count: u64,
    protected_id: Option<&str>,
) -> Result<(), String> {
    use futures_util::StreamExt;
    let root = s3_root(config);
    let list_prefix = (!root.is_empty()).then(|| ObjectPath::from(root));
    let mut stream = store.list(list_prefix.as_ref());
    let mut files = Vec::new();
    while let Some(item) = stream.next().await {
        let item = item.map_err(|_| "S3 pruning failed".to_owned())?;
        if owned_s3_id(config, &item.location).is_some() {
            files.push(item);
        }
    }
    files.sort_by(|left, right| {
        let left_id = owned_s3_id(config, &left.location).unwrap_or_default();
        let right_id = owned_s3_id(config, &right.location).unwrap_or_default();
        (right_id == protected_id.unwrap_or_default())
            .cmp(&(left_id == protected_id.unwrap_or_default()))
            .then_with(|| right.last_modified.cmp(&left.last_modified))
            .then_with(|| right.location.cmp(&left.location))
    });
    let cutoff = now().saturating_sub(retention_days.saturating_mul(86_400)) as i64;
    for (index, item) in files.into_iter().enumerate() {
        if owned_s3_id(config, &item.location) == protected_id {
            continue;
        }
        if (retention_days > 0 && item.last_modified.timestamp() < cutoff)
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

pub fn inventory_local(data_dir: &Path) -> Result<Vec<InventoryItem>, String> {
    inventory_local_root(&ensure_backups_dir(data_dir)?)
}
pub fn inventory_local_root(root: &Path) -> Result<Vec<InventoryItem>, String> {
    validate_private_ancestry(root, None)?;
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
    ensure_no_pending_restore(&app.config.data_dir)?;
    let mut status = read_status(&app.config.data_dir).unwrap_or_default();
    status.last_attempt_at = Some(now());
    status.last_error = None;
    write_status(&app.config.data_dir, status.clone())?;
    let result = run_inner(Arc::clone(&app), config, secrets).await;
    match result {
        Ok(id) => {
            status.last_success_at = Some(now());
            status.last_error = None;
            write_status(&app.config.data_dir, status)?;
            Ok(id)
        }
        Err(error) => {
            if error.published {
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
    published: bool,
}

impl RunFailure {
    fn before(message: impl ToString) -> Self {
        Self {
            message: message.to_string(),
            published: false,
        }
    }

    fn after(message: impl ToString, published: bool) -> Self {
        Self {
            message: message.to_string(),
            published,
        }
    }
}

/// Build once in a private staging name, atomically publish the local object,
/// then upload that exact object to S3 if requested.
async fn run_inner(
    app: Arc<crate::app::App>,
    config: BackupConfig,
    secrets: BackupSecrets,
) -> Result<String, RunFailure> {
    config
        .validate(&app.config.data_dir)
        .map_err(RunFailure::before)?;
    let backups = config
        .local_root(&app.config.data_dir)
        .map_err(RunFailure::before)?;
    let backups = ensure_backup_root(&backups).map_err(RunFailure::before)?;
    let encrypted = config.encrypt;
    if encrypted && secrets.passphrase.is_none() {
        return Err(RunFailure::before(
            "encryption passphrase is not configured",
        ));
    }
    let id = backup_filename(encrypted);
    let final_path = backups.join(&id);
    let raw = backups.join(format!(".{id}.stage"));
    let store = Arc::clone(&app.store);
    let data_dir = app.config.data_dir.clone();
    let raw_for_archive = raw.clone();
    tokio::task::spawn_blocking(move || {
        create_archive(
            &store,
            &data_dir,
            &raw_for_archive,
            crate::store::SCHEMA_VERSION,
        )
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
        let output = backups.join(format!(".{id}.age.stage"));
        let _output_cleanup = CleanupPath::new(output.clone());
        let published = final_path.clone();
        let output_for_encrypt = output.clone();
        tokio::task::spawn_blocking(move || encrypt_file(&input, &output_for_encrypt, &pass))
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
    let mut published = false;
    if matches!(config.destination, Destination::Local | Destination::Both) {
        final_cleanup.keep();
        published = true;
        prune_local_root_protected(
            &backups,
            config.retention_days,
            config.retention_count,
            Some(&id),
        )
        .map_err(|error| RunFailure::after(error, published))?;
    }
    if matches!(config.destination, Destination::S3 | Destination::Both) {
        upload_s3(&config, &secrets, &final_path, &id)
            .await
            .map_err(|error| RunFailure::after(error, published))?;
        published = true;
    }
    if matches!(config.destination, Destination::S3) {
        fs::remove_file(&final_path).map_err(|error| RunFailure::after(error, published))?;
        final_cleanup.keep();
    }
    if matches!(config.destination, Destination::S3 | Destination::Both) {
        prune_s3(
            &config,
            &secrets,
            config.retention_days,
            config.retention_count,
            Some(&id),
        )
        .await
        .map_err(|error| RunFailure::after(error, published))?;
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

pub async fn scheduler(app: Arc<crate::app::App>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        ticker.tick().await;
        let Ok(_guard) = app.backup_lock.try_lock() else {
            continue;
        };
        if let Err(error) = ensure_no_pending_restore(&app.config.data_dir) {
            tracing::info!("backup scheduler stopped: {error}");
            return;
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
        match run(Arc::clone(&app), config, secrets).await {
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

    #[derive(Debug)]
    struct FailingMultipart {
        aborted: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl MultipartUpload for FailingMultipart {
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
            self.aborted.store(true, Ordering::SeqCst);
            Ok(())
        }
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
        assert_eq!(fs::read(extracted.join("secret")).unwrap(), [7; 32]);
        let encrypted = root.path().join("bundle.tar.age");
        encrypt_file(&raw, &encrypted, "test passphrase").unwrap();
        let decrypted = root.path().join("decrypted.tar");
        decrypt_file(&encrypted, &decrypted, "test passphrase").unwrap();
        assert_eq!(fs::read(raw).unwrap(), fs::read(decrypted).unwrap());
    }

    #[test]
    fn archive_manifest_must_name_every_member() {
        let (root, store) = initialized_root();
        let snapshot = root.path().join("snapshot.db");
        store.backup_into(&snapshot).unwrap();
        let mut entries = Vec::new();
        for (name, path) in [
            ("votport.db", snapshot.as_path()),
            ("secret", &root.path().join("secret")),
        ] {
            let (size, sha256) = file_hash(path).unwrap();
            entries.push(ManifestEntry {
                name: name.into(),
                size,
                sha256,
            });
        }
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
        add_file(&mut builder, "secret", &root.path().join("secret")).unwrap();
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

    #[test]
    fn pending_restore_rechecks_staged_hashes_before_moving_live_data() {
        let (root, store) = initialized_root();
        let archive = root.path().join("bundle.tar");
        create_archive(&store, root.path(), &archive, crate::store::SCHEMA_VERSION).unwrap();
        let stage = root.path().join(".votport-restore-stage-test");
        fs::create_dir(&stage).unwrap();
        let manifest =
            validate_and_extract(&archive, &stage, crate::store::SCHEMA_VERSION).unwrap();
        write_pending_restore(root.path(), &stage, manifest).unwrap();
        fs::write(stage.join("receipt.key"), b"tampered").unwrap();
        drop(store);
        assert!(apply_pending_restore(root.path(), crate::store::SCHEMA_VERSION).is_err());
        assert!(root.path().join("votport.db").exists());
        assert_eq!(fs::read(root.path().join("secret")).unwrap(), [7; 32]);
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
        write_pending_restore(root.path(), &stage, manifest).unwrap();
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
        assert_eq!(restored.setting(SETTING_KEY).unwrap(), None);
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
        let first = "votport-backup-v1-1-a.tar";
        let second = "votport-backup-v1-2-b.tar.age";
        fs::write(root.path().join(first), b"one").unwrap();
        fs::write(root.path().join(second), b"two").unwrap();
        prune_local_root(root.path(), 0, 0).unwrap();
        assert!(root.path().join(first).exists());
        assert!(root.path().join(second).exists());
        prune_local_root(root.path(), 0, 1).unwrap();
        assert_eq!(inventory_local_root(root.path()).unwrap().len(), 1);
    }

    #[test]
    fn protected_local_backup_survives_retention_ties() {
        let root = tempfile::tempdir().unwrap();
        let protected = "votport-backup-v1-1-a.tar";
        let other = "votport-backup-v1-1-b.tar";
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

    #[tokio::test]
    async fn protected_s3_backup_survives_same_second_retention() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let config = BackupConfig {
            s3_prefix: Some("backups".into()),
            ..BackupConfig::default()
        };
        let protected = "votport-backup-v1-1-a.tar";
        let other = "votport-backup-v1-1-b.tar";
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
        prune_s3_store(Arc::clone(&store), &config, 0, 1, Some(protected))
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
        let id = "votport-backup-v1-1-a.tar";
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

    #[tokio::test]
    async fn failed_multipart_part_is_aborted() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("upload");
        fs::write(&path, b"backup").unwrap();
        let mut file = tokio::fs::File::open(path).await.unwrap();
        let aborted = Arc::new(AtomicBool::new(false));
        let mut upload: Box<dyn MultipartUpload> = Box::new(FailingMultipart {
            aborted: Arc::clone(&aborted),
        });
        assert_eq!(
            upload_file_parts(&mut upload, &mut file).await,
            Err("S3 upload failed".into())
        );
        assert!(aborted.load(Ordering::SeqCst));
    }
}
