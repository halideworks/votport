//! Persistent state: request links and their completed uploads.
//!
//! SQLite (WAL, synchronous FULL) in the data directory. The public API is
//! the one the JSON-document store had: every mutation commits durably before
//! returning, and callers stay free of SQL. Uploads and session events remain
//! embedded JSON on the link row; splitting them into tables is phase 2 work
//! (see docs/multi-tenancy.md).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::config::Config;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileRecord {
    /// Path as named inside the uploaded package.
    pub path: String,
    /// Path actually stored on disk, relative to the owning tenant's subtree.
    pub stored_as: String,
    pub bytes: u64,
    /// Hash suite of the object root ("blake3" or "sha256").
    pub suite: String,
    /// Hex object root the received bytes verified against.
    pub root: String,
    /// Whether a signed `.vot-receipt` sidecar was written next to the file.
    #[serde(default)]
    pub receipt: bool,
    /// Set when the admin deleted the stored file. The freed name can be
    /// reused by later, different content, so a tombstoned record must never
    /// satisfy dedupe even if a same-length file sits at its path again.
    #[serde(default)]
    pub deleted: bool,
}

/// A session that ended without a completed upload: cancelled by the sender
/// or interrupted (disconnect, expiry, terminal error). Kept per link, newest
/// last, capped, so the admin can see what went wrong and how far it got.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionEvent {
    pub at: u64,
    pub started_at: u64,
    /// "cancelled", "interrupted", or "rejected" (begin refused the package).
    pub outcome: String,
    pub detail: String,
    pub received_bytes: u64,
    pub expected_bytes: u64,
    /// Chunks the sender re-sent that were already verified: retries after a
    /// response was lost in transit, so a proxy for how flaky the line was.
    /// (TCP hides actual wire loss; there is no FEC at this layer.)
    #[serde(default)]
    pub replayed_chunks: u64,
    /// Chunks the server refused (bad proof, bounds, state).
    #[serde(default)]
    pub rejected_chunks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadRecord {
    pub id: String,
    /// When the session was created; 0 on records from before this field.
    #[serde(default)]
    pub started_at: u64,
    pub completed_at: u64,
    /// See [`SessionEvent::replayed_chunks`].
    #[serde(default)]
    pub replayed_chunks: u64,
    #[serde(default)]
    pub rejected_chunks: u64,
    /// Transport that completed the upload; `None` is the legacy HTTP value.
    #[serde(default)]
    pub transport: Option<String>,
    /// Hex root of the verified package manifest.
    pub package_root: String,
    pub total_bytes: u64,
    pub files: Vec<FileRecord>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OutboundGrant {
    pub id: String,
    pub token_hash: String,
    pub password_hash: Option<String>,
    pub tenant: String,
    pub link_id: String,
    pub upload_id: String,
    pub package_root: String,
    pub name: String,
    pub suite: String,
    pub root: String,
    pub file_index: usize,
    pub bytes: u64,
    pub label: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
    pub downloads: u64,
    pub max_downloads: Option<u64>,
    pub notify_on_download: bool,
    pub first_download_at: Option<u64>,
    pub last_download_at: Option<u64>,
    pub files: Vec<OutboundGrantFile>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AutomationToken {
    pub id: String,
    pub token_hash: String,
    pub tenant: String,
    pub label: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
    pub last_used_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboundDownloadResult {
    pub first_download: bool,
    pub completed_delivery: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutboundGrantFile {
    pub source: String,
    pub name: String,
    pub suite: String,
    pub root: String,
    pub bytes: u64,
    pub receipt_b64: String,
    #[serde(default)]
    pub downloads: u64,
    #[serde(default)]
    pub first_download_at: Option<u64>,
    #[serde(default)]
    pub last_download_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Link {
    pub id: String,
    pub label: String,
    /// Owning tenant key ("" = the default tenant).
    #[serde(default)]
    pub tenant: String,
    /// Destination subdirectory relative to the owning tenant's subtree.
    pub dest: String,
    #[serde(default)]
    pub password_hash: Option<String>,
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    pub active: bool,
    #[serde(default)]
    pub legal_hold: bool,
    #[serde(default)]
    pub notify_on_upload: bool,
    #[serde(default)]
    pub uploads: Vec<UploadRecord>,
    #[serde(default)]
    pub events: Vec<SessionEvent>,
}

#[derive(Serialize)]
pub struct LinkCursor {
    pub created_at: u64,
    pub id: String,
}

pub struct LinkPage {
    pub links: Vec<Link>,
    pub next_cursor: Option<LinkCursor>,
}

impl Link {
    pub fn usable_now(&self) -> bool {
        self.active && self.expires_at.is_none_or(|at| now_unix() < at)
    }
}

/// A tenant namespace: its own links, receive subtree, and quotas.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tenant {
    /// URL-safe key used in paths and tokens ("" is reserved for default).
    pub key: String,
    pub label: String,
    /// Group whose members administer this tenant's links (SSO mapping).
    pub admin_group: Option<String>,
    /// Cap on received-but-not-deleted bytes across the tenant's links.
    pub max_total_bytes: Option<u64>,
    pub max_links: Option<u64>,
    /// Cap on concurrent upload sessions for the whole tenant.
    pub max_sessions: Option<u64>,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TenantUsage {
    pub tenant: String,
    pub links: u64,
    pub received_bytes: u64,
}

impl Tenant {
    /// The namespace files for this tenant publish into, relative to the
    /// receive root. The default tenant keeps today's layout so existing
    /// deployments see no path change.
    pub fn path_prefix(&self) -> Vec<String> {
        crate::paths::tenant_prefix(&self.key)
    }
}

/// An SSO principal recorded at last successful sign-in.
#[derive(Clone, Debug, Serialize)]
pub struct Principal {
    pub subject: String,
    pub blocked: bool,
    pub credential_version: u64,
    pub last_login_at: u64,
    pub last_groups: Vec<String>,
    #[serde(rename = "grants")]
    pub last_grants: serde_json::Value,
    pub source: String,
}

/// One settings PUT: write TEXT (including empty disable) or delete the row.
#[derive(Clone, Debug)]
pub enum SettingWrite {
    Set(String),
    Reset,
}

/// Env values with a written settings row overlaid. Callers must not cache
/// this across requests: a PUT is visible on the next read.
#[derive(Clone, Debug)]
pub struct ResolvedSettings {
    pub notify_webhook: Option<String>,
    pub notify_ntfy: Option<String>,
    pub notify_ntfy_token: Option<String>,
    pub notify_pushover: Option<(String, String)>,
    /// Some iff host, from, and at least one `to` all resolve non-empty.
    pub smtp: Option<ResolvedSmtp>,
    pub audit_retention_days: u64,
    pub upload_retention_days: u64,
    pub default_max_total_bytes: Option<u64>,
    pub default_max_links: Option<u64>,
    pub default_max_sessions: Option<u64>,
    pub public_password_login: bool,
}

/// Assembled SMTP channel. Username and password are optional.
#[derive(Clone, Debug)]
pub struct ResolvedSmtp {
    pub host: String,
    pub port: u16,
    pub starttls: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub to: Vec<String>,
}

/// Resolved settings plus whether each key came from the database or env.
/// `source` is `"env"` when the row is absent or its TEXT was invalid.
#[derive(Clone, Debug)]
pub struct SettingsOverlay {
    pub resolved: ResolvedSettings,
    pub notify_webhook_source: &'static str,
    pub notify_ntfy_source: &'static str,
    pub notify_ntfy_token_source: &'static str,
    pub notify_pushover_token_set: bool,
    pub notify_pushover_token_source: &'static str,
    pub notify_pushover_user_set: bool,
    pub notify_pushover_user_source: &'static str,
    pub smtp_host: Option<String>,
    pub smtp_host_source: &'static str,
    pub smtp_port: u16,
    pub smtp_port_source: &'static str,
    pub smtp_starttls: bool,
    pub smtp_starttls_source: &'static str,
    pub smtp_username: Option<String>,
    pub smtp_username_source: &'static str,
    pub smtp_password_set: bool,
    pub smtp_password_source: &'static str,
    pub smtp_from: Option<String>,
    pub smtp_from_source: &'static str,
    pub smtp_to: Option<String>,
    pub smtp_to_source: &'static str,
    pub audit_retention_days_source: &'static str,
    pub upload_retention_days_source: &'static str,
    pub default_max_total_bytes_source: &'static str,
    pub default_max_links_source: &'static str,
    pub default_max_sessions_source: &'static str,
    pub public_password_login_source: &'static str,
}

/// The pre-SQLite state document, kept only to import legacy state.json files.
#[derive(Deserialize)]
struct LegacyDocument {
    #[serde(default)]
    links: Vec<Link>,
    #[serde(default)]
    admin_password_hash: Option<String>,
}

const SCHEMA_VERSION: u64 = 16;

pub const OUTBOUND_DOWNLOAD_LIMIT_REACHED: &str = "outbound download limit reached";

const SETTINGS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL DEFAULT ''
);
";

const PRINCIPALS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS principals (
    subject TEXT PRIMARY KEY,
    credential_version INTEGER NOT NULL DEFAULT 1,
    blocked INTEGER NOT NULL DEFAULT 0,
    last_login_at INTEGER NOT NULL DEFAULT 0,
    last_groups TEXT NOT NULL DEFAULT '[]',
    last_grants TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL DEFAULT 'sso'
);
";

const LEGAL_HOLD_SCHEMA: &str =
    "ALTER TABLE links ADD COLUMN legal_hold INTEGER NOT NULL DEFAULT 0;";

const FILES_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS files (
    link_id TEXT NOT NULL,
    tenant TEXT NOT NULL DEFAULT '',
    upload_index INTEGER NOT NULL,
    file_index INTEGER NOT NULL,
    bytes_hi INTEGER NOT NULL,
    bytes_lo INTEGER NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (link_id, upload_index, file_index)
);
CREATE INDEX IF NOT EXISTS files_tenant_live ON files(tenant, deleted, bytes_hi, bytes_lo);
";

const OUTBOUND_GRANTS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS outbound_grants (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    tenant TEXT NOT NULL,
    link_id TEXT NOT NULL,
    upload_id TEXT NOT NULL,
    package_root TEXT NOT NULL,
    name TEXT NOT NULL,
    suite TEXT NOT NULL,
    root TEXT NOT NULL,
    file_index INTEGER NOT NULL,
    bytes_hi INTEGER NOT NULL,
    bytes_lo INTEGER NOT NULL,
    label TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    downloads INTEGER NOT NULL DEFAULT 0,
    max_downloads INTEGER,
    first_download_at INTEGER,
    last_download_at INTEGER,
    files_json TEXT NOT NULL DEFAULT '[]',
    file_count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS outbound_grants_tenant_created ON outbound_grants(tenant, created_at);
CREATE INDEX IF NOT EXISTS outbound_grants_file
    ON outbound_grants(tenant, link_id, upload_id, file_index);
";

const OUTBOUND_GRANTS_FILES_SCHEMA: &str =
    "ALTER TABLE outbound_grants ADD COLUMN files_json TEXT NOT NULL DEFAULT '[]';";

const OUTBOUND_GRANTS_FILE_COUNT_SCHEMA: &str =
    "ALTER TABLE outbound_grants ADD COLUMN file_count INTEGER NOT NULL DEFAULT 1;
     UPDATE outbound_grants
     SET file_count = CASE WHEN json_array_length(files_json) = 0
                           THEN 1 ELSE json_array_length(files_json) END;";

const OUTBOUND_GRANT_FILES_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS outbound_grant_files (
    grant_id TEXT NOT NULL,
    file_index INTEGER NOT NULL,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    suite TEXT NOT NULL,
    root TEXT NOT NULL,
    bytes_hi INTEGER NOT NULL,
    bytes_lo INTEGER NOT NULL,
    receipt_b64 TEXT NOT NULL,
    downloads INTEGER NOT NULL DEFAULT 0,
    first_download_at INTEGER,
    last_download_at INTEGER,
    PRIMARY KEY (grant_id, file_index)
);
CREATE INDEX IF NOT EXISTS outbound_grant_files_downloads
    ON outbound_grant_files(grant_id, downloads);
";

const OUTBOUND_GRANTS_PASSWORD_SCHEMA: &str =
    "ALTER TABLE outbound_grants ADD COLUMN password_hash TEXT;";

const OUTBOUND_GRANTS_DELIVERY_SCHEMA: &str =
    "ALTER TABLE outbound_grants ADD COLUMN first_download_at INTEGER;
     ALTER TABLE outbound_grants ADD COLUMN last_download_at INTEGER;";

const AUTOMATION_TOKENS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS automation_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    tenant TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS automation_tokens_tenant_created
    ON automation_tokens(tenant, created_at);
";

const OUTBOUND_GRANTS_LIMIT_SCHEMA: &str =
    "ALTER TABLE outbound_grants ADD COLUMN max_downloads INTEGER;";

const NOTIFICATION_POLICY_SCHEMA: &str =
    "ALTER TABLE links ADD COLUMN notify_on_upload INTEGER NOT NULL DEFAULT 0;
     ALTER TABLE outbound_grants ADD COLUMN notify_on_download INTEGER NOT NULL DEFAULT 0;";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    at INTEGER NOT NULL,
    tenant TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT '',
    event TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log(at);
CREATE TABLE IF NOT EXISTS tenants (
    key TEXT PRIMARY KEY,
    label TEXT NOT NULL DEFAULT '',
    admin_group TEXT,
    max_total_bytes INTEGER,
    max_links INTEGER,
    max_sessions INTEGER,
    created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
    tenant TEXT NOT NULL DEFAULT '',
    label TEXT NOT NULL,
    dest TEXT NOT NULL DEFAULT '',
    password_hash TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    max_bytes INTEGER,
    active INTEGER NOT NULL DEFAULT 1,
    uploads_json TEXT NOT NULL DEFAULT '[]',
    events_json TEXT NOT NULL DEFAULT '[]'
);
";

pub struct Store {
    connection: Mutex<Connection>,
}

impl Store {
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(data_dir)
            .map_err(|error| format!("create {}: {error}", data_dir.display()))?;
        let path = data_dir.join("votport.db");
        let connection =
            Connection::open(&path).map_err(|error| format!("open {}: {error}", path.display()))?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| error.to_string())?;
        // Durability matches the old fsync-per-persist store: a completed
        // mutation survives power loss.
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| error.to_string())?;
        connection
            .execute_batch(SCHEMA)
            .map_err(|error| format!("schema: {error}"))?;
        // The db/-wal directory entries are new; sync them like the old JSON
        // store synced its renames.
        if let Ok(dir) = std::fs::File::open(data_dir) {
            let _ = dir.sync_all();
        }
        let store = Self {
            connection: Mutex::new(connection),
        };
        // v1/v2 databases predate tenant scoping: existing links belong to
        // the default tenant (""). Idempotent: ignored when the column exists.
        store
            .with(|connection| {
                connection
                    .execute_batch("ALTER TABLE links ADD COLUMN tenant TEXT NOT NULL DEFAULT ''")
            })
            .ok();
        store.with(|connection| {
            connection.execute_batch(
                "CREATE INDEX IF NOT EXISTS links_tenant ON links(tenant);
                 CREATE INDEX IF NOT EXISTS links_tenant_created
                 ON links(tenant, created_at DESC, id DESC)",
            )
        })?;
        store.migrate()?;
        store.import_legacy(data_dir)?;
        Ok(store)
    }

    /// Moves pre-isolation named-tenant subtrees under the reserved storage
    /// directory. The marker is written last, so a crash between renames can
    /// resume without moving a subtree twice.
    pub fn migrate_tenant_storage(&self, receive_dir: &Path) -> Result<(), String> {
        const KEY: &str = "tenant_storage_layout";
        const LAYOUT: &str = "reserved-v1";
        let marker = self.with(|connection| {
            connection
                .query_row("SELECT value FROM meta WHERE key = ?1", [KEY], |row| {
                    row.get::<_, String>(0)
                })
                .optional()
        })?;
        if let Some(marker) = marker {
            return if marker == LAYOUT {
                Ok(())
            } else {
                Err(format!("unsupported tenant storage layout {marker:?}"))
            };
        }

        let target_root = receive_dir.join(crate::paths::TENANT_STORAGE_DIR);
        let metadata = |path: &Path| match std::fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("inspect {}: {error}", path.display())),
        };
        let target_root_metadata = metadata(&target_root)?;
        if target_root_metadata
            .as_ref()
            .is_some_and(|metadata| !metadata.file_type().is_dir())
        {
            return Err(format!(
                "tenant storage migration expected a directory at {}; move it aside",
                target_root.display()
            ));
        }

        let default_links = self.links("")?;
        let default_owns_prefix = |key: &str| {
            let uses_prefix = |path: &str| {
                let component = path.split('/').next().unwrap_or_default();
                component.contains('~')
                    || !component.is_ascii()
                    || component.eq_ignore_ascii_case(key)
            };
            default_links.iter().any(|link| {
                uses_prefix(&link.dest)
                    || link
                        .uploads
                        .iter()
                        .flat_map(|upload| &upload.files)
                        .any(|file| !file.deleted && uses_prefix(&file.stored_as))
            })
        };
        if target_root_metadata.is_some() && default_owns_prefix(crate::paths::TENANT_STORAGE_DIR) {
            return Err(format!(
                "tenant storage migration cannot determine ownership of {}; a default-tenant link also uses that prefix",
                target_root.display()
            ));
        }
        let tenants = self.tenants()?;
        let mut moves = Vec::new();
        for tenant in tenants {
            if !crate::paths::portable_tenant_key(&tenant.key) {
                return Err(format!(
                    "tenant key {:?} is not portable; rename it using lowercase ASCII letters, digits, '-' or '_'",
                    tenant.key
                ));
            }
            let source = crate::paths::join_under(receive_dir, std::slice::from_ref(&tenant.key))?;
            let target = target_root.join(&tenant.key);
            let source_metadata = metadata(&source)?;
            let target_metadata = metadata(&target)?;
            for (path, metadata) in [(&source, &source_metadata), (&target, &target_metadata)] {
                if metadata
                    .as_ref()
                    .is_some_and(|metadata| !metadata.file_type().is_dir())
                {
                    return Err(format!(
                        "tenant storage migration expected a directory at {}; move it aside",
                        path.display()
                    ));
                }
            }
            let source_exists = source_metadata.is_some();
            let target_exists = target_metadata.is_some();
            if source_exists && target_exists {
                return Err(format!(
                    "tenant storage migration found both {} and {}; move one aside",
                    source.display(),
                    target.display()
                ));
            }
            if (source_exists || target_exists) && default_owns_prefix(&tenant.key) {
                return Err(format!(
                    "tenant storage migration cannot determine ownership of {}; a default-tenant link also uses that prefix",
                    source.display()
                ));
            }
            moves.push((source, target, source_exists));
        }

        for (source, target, source_exists) in moves {
            if !source_exists {
                continue;
            }
            std::fs::create_dir_all(&target_root)
                .map_err(|error| format!("create {}: {error}", target_root.display()))?;
            crate::paths::tighten_dir(&target_root);
            std::fs::rename(&source, &target).map_err(|error| {
                format!("move {} to {}: {error}", source.display(), target.display())
            })?;
        }
        // The database marker must not reach durable storage before the
        // directory renames it represents, including renames resumed from an
        // earlier process.
        #[cfg(unix)]
        {
            if target_root.exists() {
                std::fs::File::open(&target_root)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| format!("sync {}: {error}", target_root.display()))?;
            }
            std::fs::File::open(receive_dir)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("sync {}: {error}", receive_dir.display()))?;
        }
        self.with(|connection| {
            connection.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                [KEY, LAYOUT],
            )
        })?;
        Ok(())
    }

    /// Forward-only schema steps. A file written by a newer binary is refused
    /// rather than stamped down: rewriting `schema_version` would hide tables
    /// this process cannot read.
    fn migrate(&self) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let stored = schema_version_stored(&connection)?;
        if stored > SCHEMA_VERSION {
            return Err(format!(
                "database schema version {stored} is newer than this binary ({SCHEMA_VERSION}); refusing to start"
            ));
        }
        if stored == SCHEMA_VERSION {
            return Ok(());
        }
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        if stored < 4 {
            transaction
                .execute_batch(SETTINGS_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
        }
        if stored < 5 {
            transaction
                .execute_batch(PRINCIPALS_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
        }
        if stored < 6 {
            transaction
                .execute_batch(LEGAL_HOLD_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
        }
        if stored < 7 {
            transaction
                .execute_batch(FILES_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
            let links = {
                let mut statement = transaction
                    .prepare(
                        "SELECT id, tenant, label, dest, password_hash, created_at, expires_at,
                                max_bytes, active, legal_hold, 0 AS notify_on_upload, uploads_json, events_json
                         FROM links ORDER BY rowid",
                    )
                    .map_err(|error| error.to_string())?;
                let rows = statement
                    .query_map([], row_to_link)
                    .map_err(|error| error.to_string())?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?
            };
            for link in &links {
                rebuild_link_files(&transaction, link).map_err(|error| error.to_string())?;
            }
        }
        if stored < 8 {
            transaction
                .execute_batch(OUTBOUND_GRANTS_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
        } else if stored < 9 {
            transaction
                .execute_batch(OUTBOUND_GRANTS_FILES_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
        }
        if (8..10).contains(&stored) {
            transaction
                .execute_batch(OUTBOUND_GRANTS_PASSWORD_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
        }
        if (8..11).contains(&stored) {
            transaction
                .execute_batch(OUTBOUND_GRANTS_DELIVERY_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
        }
        if stored < 12 {
            transaction
                .execute_batch(AUTOMATION_TOKENS_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
        }
        if (8..13).contains(&stored) {
            transaction
                .execute_batch(OUTBOUND_GRANTS_LIMIT_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
        }
        if stored < 14 {
            transaction
                .execute_batch(NOTIFICATION_POLICY_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
        }
        if (8..15).contains(&stored) {
            transaction
                .execute_batch(OUTBOUND_GRANTS_FILE_COUNT_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
        }
        if stored < 16 {
            transaction
                .execute_batch(OUTBOUND_GRANT_FILES_SCHEMA)
                .map_err(|error| format!("schema: {error}"))?;
            let grant_ids = {
                let mut statement = transaction
                    .prepare("SELECT id FROM outbound_grants WHERE length(trim(files_json)) > 2")
                    .map_err(|error| error.to_string())?;
                let rows = statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(|error| error.to_string())?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?
            };
            let mut insert = transaction
                .prepare(
                    "INSERT INTO outbound_grant_files
                     (grant_id, file_index, source, name, suite, root, bytes_hi, bytes_lo,
                      receipt_b64, downloads, first_download_at, last_download_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                )
                .map_err(|error| error.to_string())?;
            for id in grant_ids {
                let files_json: String = transaction
                    .query_row(
                        "SELECT files_json FROM outbound_grants WHERE id = ?1",
                        [&id],
                        |row| row.get(0),
                    )
                    .map_err(|error| error.to_string())?;
                let files: Vec<OutboundGrantFile> =
                    serde_json::from_str(&files_json).map_err(|error| {
                        format!("parse outbound grant files during migration: {error}")
                    })?;
                for (index, file) in files.into_iter().enumerate() {
                    let (bytes_hi, bytes_lo) = split_bytes(file.bytes);
                    insert
                        .execute(rusqlite::params![
                            id,
                            i64::try_from(index).unwrap_or(i64::MAX),
                            file.source,
                            file.name,
                            file.suite,
                            file.root,
                            bytes_hi,
                            bytes_lo,
                            file.receipt_b64,
                            i64::try_from(file.downloads).unwrap_or(i64::MAX),
                            file.first_download_at
                                .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                            file.last_download_at
                                .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                        ])
                        .map_err(|error| error.to_string())?;
                }
            }
        }
        transaction
            .execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [SCHEMA_VERSION.to_string()],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    /// Imports a legacy state.json once: links and the admin hash move into
    /// the database, the file is renamed so a later crash cannot re-import
    /// stale state over newer rows.
    fn import_legacy(&self, data_dir: &Path) -> Result<(), String> {
        let path = data_dir.join("state.json");
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("read {}: {error}", path.display())),
        };
        let document: LegacyDocument = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse {}: {error}", path.display()))?;
        {
            let mut connection = self.connection.lock().expect("store poisoned");
            let transaction = connection
                .transaction()
                .map_err(|error| error.to_string())?;
            for link in &document.links {
                // OR IGNORE keeps a retry idempotent: if a previous run
                // committed the import but died before the rename, the rows
                // are already there and identical.
                let inserted = transaction
                    .execute(
                        "INSERT OR IGNORE INTO links (id, tenant, label, dest, password_hash,
                                                      created_at, expires_at, max_bytes, active,
                                                      legal_hold, notify_on_upload, uploads_json, events_json)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                        link_params(link),
                    )
                    .map_err(|error| error.to_string())?;
                if inserted > 0 {
                    rebuild_link_files(&transaction, link).map_err(|error| error.to_string())?;
                }
            }
            if let Some(hash) = &document.admin_password_hash {
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO meta (key, value) VALUES ('admin_password_hash', ?1)",
                        [hash],
                    )
                    .map_err(|error| error.to_string())?;
            }
            transaction.commit().map_err(|error| error.to_string())?;
        }
        let imported = data_dir.join("state.json.imported");
        std::fs::rename(&path, imported).map_err(|error| error.to_string())?;
        tracing::info!(
            target: "audit",
            links = document.links.len(),
            "imported legacy state.json into sqlite"
        );
        self.audit(
            "",
            "",
            "legacy_state_imported",
            "",
            &serde_json::json!({ "links": document.links.len() }),
        );
        Ok(())
    }

    /// Runs `f` with the connection, mapping SQL errors into strings.
    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T, String> {
        let connection = self.connection.lock().expect("store poisoned");
        f(&connection).map_err(|error| error.to_string())
    }

    pub fn health_check(&self) -> Result<(), String> {
        self.with(|connection| {
            connection
                .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .and_then(|_| {
                    connection
                        .query_row("SELECT 1 FROM meta LIMIT 1", [], |row| row.get::<_, i64>(0))
                })
                .map(|_| ())
        })
    }

    pub fn admin_password_hash(&self) -> Result<Option<String>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT value FROM meta WHERE key = 'admin_password_hash'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })
    }

    pub fn set_admin_password_hash(&self, hash: String) -> Result<(), String> {
        self.with(|connection| {
            connection
                .execute(
                    "INSERT INTO meta (key, value) VALUES ('admin_password_hash', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [hash],
                )
                .map(|_| ())
        })
    }

    pub fn insert_automation_token(&self, token: AutomationToken) -> Result<(), String> {
        self.with(|connection| {
            connection
                .execute(
                    "INSERT INTO automation_tokens
                         (id, token_hash, tenant, label, created_at, expires_at, revoked_at,
                          last_used_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        token.id,
                        token.token_hash,
                        token.tenant,
                        token.label,
                        i64::try_from(token.created_at).unwrap_or(i64::MAX),
                        i64::try_from(token.expires_at).unwrap_or(i64::MAX),
                        token
                            .revoked_at
                            .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                        token
                            .last_used_at
                            .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    ],
                )
                .map(|_| ())
        })
    }

    pub fn automation_tokens(&self, tenant: &str) -> Result<Vec<AutomationToken>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, token_hash, tenant, label, created_at, expires_at, revoked_at,
                        last_used_at
                 FROM automation_tokens
                 WHERE tenant = ?1 ORDER BY created_at, rowid",
            )?;
            let rows = statement.query_map([tenant], map_automation_token)?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn authenticate_automation_token(
        &self,
        token_hash: &str,
        at: u64,
    ) -> Result<Option<AutomationToken>, String> {
        let at = i64::try_from(at).unwrap_or(i64::MAX);
        self.with(|connection| {
            connection
                .query_row(
                    "UPDATE automation_tokens
                     SET last_used_at = ?2
                     WHERE token_hash = ?1 AND revoked_at IS NULL AND expires_at > ?2
                     RETURNING id, token_hash, tenant, label, created_at, expires_at,
                               revoked_at, last_used_at",
                    rusqlite::params![token_hash, at],
                    map_automation_token,
                )
                .optional()
        })
    }

    pub fn revoke_automation_token(&self, tenant: &str, id: &str, at: u64) -> Result<bool, String> {
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE automation_tokens SET revoked_at = ?3
                     WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL",
                    rusqlite::params![tenant, id, i64::try_from(at).unwrap_or(i64::MAX)],
                )
                .map(|changed| changed > 0)
        })
    }

    pub fn links(&self, tenant: &str) -> Result<Vec<Link>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                        active, legal_hold, notify_on_upload, uploads_json, events_json
                 FROM links WHERE tenant = ?1 ORDER BY rowid",
            )?;
            let rows = statement.query_map([tenant], row_to_link)?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn links_page(
        &self,
        tenant: &str,
        limit: u64,
        before: Option<&LinkCursor>,
        search: &str,
        status: &str,
        now: u64,
    ) -> Result<LinkPage, String> {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let sql_limit = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        let (before_set, before_created_at, before_id) = before
            .map(|cursor| {
                (
                    1_i64,
                    i64::try_from(cursor.created_at).unwrap_or(i64::MAX),
                    cursor.id.as_str(),
                )
            })
            .unwrap_or((0, 0, ""));
        let search = escape_like(search).to_lowercase();
        let now = i64::try_from(now).unwrap_or(i64::MAX);
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                        active, legal_hold, notify_on_upload, uploads_json, events_json
                 FROM links
                 WHERE tenant = ?1
                   AND (?2 = '' OR lower(label) LIKE '%' || ?2 || '%' ESCAPE '\\'
                        OR lower(dest) LIKE '%' || ?2 || '%' ESCAPE '\\')
                   AND (?3 = 'all'
                        OR (?3 = 'open' AND active != 0
                            AND (expires_at IS NULL OR expires_at > ?4))
                        OR (?3 = 'closed' AND (active = 0
                            OR (expires_at IS NOT NULL AND expires_at <= ?4))))
                   AND (?5 = 0 OR created_at < ?6
                        OR (created_at = ?6 AND id < ?7))
                 ORDER BY created_at DESC, id DESC
                 LIMIT ?8",
            )?;
            let rows = statement.query_map(
                rusqlite::params![
                    tenant,
                    search,
                    status,
                    now,
                    before_set,
                    before_created_at,
                    before_id,
                    sql_limit,
                ],
                row_to_link,
            )?;
            rows.collect::<Result<Vec<_>, _>>()
        })
        .map(|mut links| {
            let next_cursor = if links.len() > limit {
                links.truncate(limit);
                links.last().map(|link| LinkCursor {
                    created_at: link.created_at,
                    id: link.id.clone(),
                })
            } else {
                None
            };
            LinkPage { links, next_cursor }
        })
    }

    pub fn link(&self, tenant: &str, id: &str) -> Result<Option<Link>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                            active, legal_hold, notify_on_upload, uploads_json, events_json
                     FROM links WHERE tenant = ?1 AND id = ?2",
                    rusqlite::params![tenant, id],
                    row_to_link,
                )
                .optional()
        })
    }

    /// Looks a link up by id alone, for the public upload protocol: the
    /// 128-bit id is the capability, and senders never know a tenant key.
    /// Administrative reads stay tenant-scoped.
    pub fn link_by_id(&self, id: &str) -> Result<Option<Link>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                            active, legal_hold, notify_on_upload, uploads_json, events_json
                     FROM links WHERE id = ?1",
                    [id],
                    row_to_link,
                )
                .optional()
        })
    }

    /// Public upload routes need link policy, not its ever-growing history.
    pub fn upload_link(&self, id: &str) -> Result<Option<Link>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT id, tenant, label, dest, password_hash, created_at, expires_at,
                            max_bytes, active, legal_hold, notify_on_upload, '[]' AS uploads_json,
                            '[]' AS events_json
                     FROM links WHERE id = ?1",
                    [id],
                    row_to_link,
                )
                .optional()
        })
    }

    pub fn uploads_by_id(&self, id: &str) -> Result<Option<Vec<UploadRecord>>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT uploads_json, events_json FROM links WHERE id = ?1",
                    [id],
                    |row| {
                        let uploads = parse_json(&row.get::<_, String>(0)?, 0)?;
                        let _: Vec<SessionEvent> = parse_json(&row.get::<_, String>(1)?, 1)?;
                        Ok(uploads)
                    },
                )
                .optional()
        })
    }

    pub fn insert_link(&self, link: Link) -> Result<(), InsertLinkError> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| InsertLinkError::Store(error.to_string()))?;
        // Named tenants have no FK; refuse inside this lock so a concurrent
        // remove_tenant cannot commit an orphan link.
        if !link.tenant.is_empty() {
            let exists: i64 = transaction
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM tenants WHERE key = ?1)",
                    [&link.tenant],
                    |row| row.get(0),
                )
                .map_err(|error| InsertLinkError::Store(error.to_string()))?;
            if exists == 0 {
                return Err(InsertLinkError::NamedTenantGone);
            }
        }
        insert_link_row(&transaction, &link)
            .map_err(|error| InsertLinkError::Store(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| InsertLinkError::Store(error.to_string()))?;
        Ok(())
    }

    /// Applies `mutate` to the link and commits; Ok(false) when absent.
    /// Always scoped to the link's own tenant: the caller passes the tenant
    /// it authenticated for, and a mismatched id simply reads as absent.
    pub fn update_link(
        &self,
        tenant: &str,
        id: &str,
        mutate: impl FnOnce(&mut Link),
    ) -> Result<bool, String> {
        self.update_link_inner(tenant, id, mutate, false)
    }

    pub fn update_link_uploads(
        &self,
        tenant: &str,
        id: &str,
        mutate: impl FnOnce(&mut Link),
    ) -> Result<bool, String> {
        self.update_link_inner(tenant, id, mutate, true)
    }

    fn update_link_inner(
        &self,
        tenant: &str,
        id: &str,
        mutate: impl FnOnce(&mut Link),
        sync_uploads: bool,
    ) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let Some(mut link) = read_link(&transaction, tenant, id)? else {
            return Ok(false);
        };
        mutate(&mut link);
        write_link_row(&transaction, &link).map_err(|error| error.to_string())?;
        if sync_uploads {
            sync_link_files(&transaction, &link).map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn append_upload(
        &self,
        tenant: &str,
        id: &str,
        upload: UploadRecord,
    ) -> Result<bool, String> {
        let upload_json = serde_json::to_string(&upload).map_err(|error| error.to_string())?;
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let Some((uploads_json, events_json)) = transaction
            .query_row(
                "SELECT uploads_json, events_json FROM links WHERE tenant = ?1 AND id = ?2",
                rusqlite::params![tenant, id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?
        else {
            return Ok(false);
        };
        let uploads: Vec<UploadRecord> =
            parse_json(&uploads_json, 0).map_err(|error| error.to_string())?;
        let _: Vec<SessionEvent> =
            parse_json(&events_json, 1).map_err(|error| error.to_string())?;
        let upload_index = i64::try_from(uploads.len()).unwrap_or(i64::MAX);
        drop((uploads, uploads_json, events_json));
        transaction
            .execute(
                "UPDATE links
                 SET uploads_json = json_insert(uploads_json, '$[#]', json(?3))
                 WHERE tenant = ?1 AND id = ?2",
                rusqlite::params![tenant, id, upload_json],
            )
            .map_err(|error| error.to_string())?;
        insert_upload_files(&transaction, id, tenant, upload_index, &upload)
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn tombstone_files(
        &self,
        tenant: &str,
        id: &str,
        matches: impl Fn(&FileRecord) -> bool,
    ) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let Some(mut link) = read_link(&transaction, tenant, id)? else {
            return Ok(false);
        };
        let mut changed = Vec::new();
        for (upload_index, upload) in link.uploads.iter_mut().enumerate() {
            for (file_index, file) in upload.files.iter_mut().enumerate() {
                if !file.deleted && matches(file) {
                    file.deleted = true;
                    changed.push((upload_index, file_index));
                }
            }
        }
        write_link_row(&transaction, &link).map_err(|error| error.to_string())?;
        let mut update = transaction
            .prepare_cached(
                "UPDATE files SET deleted = 1
                 WHERE link_id = ?1 AND upload_index = ?2 AND file_index = ?3",
            )
            .map_err(|error| error.to_string())?;
        for (upload_index, file_index) in changed {
            update
                .execute(rusqlite::params![
                    link.id,
                    i64::try_from(upload_index).unwrap_or(i64::MAX),
                    i64::try_from(file_index).unwrap_or(i64::MAX),
                ])
                .map_err(|error| error.to_string())?;
        }
        drop(update);
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn remove_link(&self, tenant: &str, id: &str) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "DELETE FROM files
                 WHERE link_id IN (SELECT id FROM links WHERE tenant = ?1 AND id = ?2)",
                rusqlite::params![tenant, id],
            )
            .map_err(|error| error.to_string())?;
        let changed = transaction
            .execute(
                "DELETE FROM links WHERE tenant = ?1 AND id = ?2",
                [tenant, id],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(changed > 0)
    }

    // ------------------------------------------------------------- tenants

    pub fn insert_tenant(&self, tenant: Tenant) -> Result<(), InsertTenantError> {
        self.with(|connection| {
            // Filesystems commonly compare names case-insensitively even
            // though SQLite's primary key does not.
            let folded = tenant.key.to_lowercase();
            let mut statement = connection.prepare("SELECT key FROM tenants")?;
            let keys = statement.query_map([], |row| row.get::<_, String>(0))?;
            for key in keys {
                if key?.to_lowercase() == folded {
                    return Ok(Some(InsertTenantError::AlreadyExists));
                }
            }
            drop(statement);
            connection.execute(
                "INSERT INTO tenants (key, label, admin_group, max_total_bytes, max_links, max_sessions, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    tenant.key,
                    tenant.label,
                    tenant.admin_group,
                    tenant.max_total_bytes.map(encode_quota),
                    tenant.max_links.map(encode_quota),
                    tenant.max_sessions.map(encode_quota),
                    i64::try_from(tenant.created_at).unwrap_or(0)
                ],
            )?;
            Ok(None)
        })
        .map_err(InsertTenantError::Store)
        .and_then(|refusal| match refusal {
            None => Ok(()),
            Some(error) => Err(error),
        })
    }

    pub fn tenants(&self) -> Result<Vec<Tenant>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT key, label, admin_group, CAST(max_total_bytes AS TEXT),
                        CAST(max_links AS TEXT), CAST(max_sessions AS TEXT), created_at
                 FROM tenants ORDER BY rowid",
            )?;
            let rows = statement.query_map([], map_tenant)?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn tenant(&self, key: &str) -> Result<Option<Tenant>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT key, label, admin_group, CAST(max_total_bytes AS TEXT),
                            CAST(max_links AS TEXT), CAST(max_sessions AS TEXT), created_at
                     FROM tenants WHERE key = ?1",
                    [key],
                    map_tenant,
                )
                .optional()
        })
    }

    pub fn tenant_link_count(&self, key: &str) -> Result<u64, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT COUNT(*) FROM links WHERE tenant = ?1",
                    [key],
                    |row| row.get::<_, i64>(0),
                )
                .map(|count| count.max(0) as u64)
        })
    }

    /// Deletes a tenant row atomically unless links still reference it.
    /// Ok(Some(())) = deleted, Ok(None) = absent,
    /// Ok(Some(links)) via Err variant... see [`TenantRemoval`].
    pub fn remove_tenant(&self, key: &str) -> Result<TenantRemoval, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let removal = {
            let changed = transaction
                .execute(
                    "DELETE FROM tenants WHERE key = ?1
                 AND NOT EXISTS (SELECT 1 FROM links WHERE tenant = ?1)",
                    [key],
                )
                .map_err(|error| error.to_string())?;
            if changed > 0 {
                TenantRemoval::Deleted
            } else {
                let exists: i64 = transaction
                    .query_row(
                        "SELECT EXISTS (SELECT 1 FROM tenants WHERE key = ?1)",
                        [key],
                        |row| row.get(0),
                    )
                    .map_err(|error| error.to_string())?;
                if exists == 0 {
                    TenantRemoval::Absent
                } else {
                    TenantRemoval::HasLinks
                }
            }
        };
        if matches!(removal, TenantRemoval::Deleted | TenantRemoval::Absent) {
            transaction
                .execute(
                    "DELETE FROM outbound_grant_files
                     WHERE grant_id IN (SELECT id FROM outbound_grants WHERE tenant = ?1)",
                    [key],
                )
                .map_err(|error| error.to_string())?;
            transaction
                .execute("DELETE FROM outbound_grants WHERE tenant = ?1", [key])
                .map_err(|error| error.to_string())?;
            transaction
                .execute("DELETE FROM automation_tokens WHERE tenant = ?1", [key])
                .map_err(|error| error.to_string())?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(removal)
    }

    pub fn update_tenant(&self, tenant: &Tenant) -> Result<bool, String> {
        self.with(|connection| {
            let changed = connection.execute(
                "UPDATE tenants SET label = ?2, admin_group = ?3, max_total_bytes = ?4,
                                    max_links = ?5, max_sessions = ?6
                 WHERE key = ?1",
                rusqlite::params![
                    tenant.key,
                    tenant.label,
                    tenant.admin_group,
                    tenant.max_total_bytes.map(encode_quota),
                    tenant.max_links.map(encode_quota),
                    tenant.max_sessions.map(encode_quota),
                ],
            )?;
            Ok(changed > 0)
        })
    }

    // ----------------------------------------------------------- principals

    pub fn principal(&self, subject: &str) -> Result<Option<Principal>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT subject, credential_version, blocked, last_login_at,
                            last_groups, last_grants, source
                     FROM principals WHERE subject = ?1",
                    [subject],
                    map_principal,
                )
                .optional()
        })
    }

    pub fn principals_page(
        &self,
        limit: usize,
        offset: usize,
        query: Option<&str>,
    ) -> Result<(Vec<Principal>, u64), String> {
        let limit = i64::try_from(limit).map_err(|_| "principal limit overflow".to_owned())?;
        let offset = i64::try_from(offset).map_err(|_| "principal offset overflow".to_owned())?;
        let query = query.map(|value| format!("%{}%", escape_like(value)));
        self.with(|connection| {
            let total = connection.query_row(
                "SELECT COUNT(*) FROM principals
                 WHERE (?1 IS NULL OR subject LIKE ?1 ESCAPE '\\' COLLATE NOCASE)",
                rusqlite::params![query.as_deref()],
                |row| row.get::<_, i64>(0),
            )?;
            let mut statement = connection.prepare(
                "SELECT subject, credential_version, blocked, last_login_at,
                        last_groups, last_grants, source
                 FROM principals
                 WHERE (?1 IS NULL OR subject LIKE ?1 ESCAPE '\\' COLLATE NOCASE)
                 ORDER BY last_login_at DESC, subject ASC
                 LIMIT ?2 OFFSET ?3",
            )?;
            let rows =
                statement.query_map(rusqlite::params![query, limit, offset], map_principal)?;
            Ok((
                rows.collect::<Result<Vec<_>, _>>()?,
                u64::try_from(total).unwrap_or(0),
            ))
        })
    }

    /// Inserts or refreshes last-login fields without resetting version or block.
    pub fn upsert_sso_principal(
        &self,
        subject: &str,
        groups: &[String],
        grants: &serde_json::Value,
    ) -> Result<Principal, String> {
        let groups_json = serde_json::to_string(groups).unwrap_or_else(|_| "[]".to_owned());
        let grants_json = serde_json::to_string(grants).unwrap_or_else(|_| "[]".to_owned());
        let at = i64::try_from(now_unix()).unwrap_or(0);
        self.with(|connection| {
            connection.query_row(
                "INSERT INTO principals (subject, last_login_at, last_groups, last_grants, source)
                 VALUES (?1, ?2, ?3, ?4, 'sso')
                 ON CONFLICT(subject) DO UPDATE SET
                    last_login_at = excluded.last_login_at,
                    last_groups = excluded.last_groups,
                    last_grants = excluded.last_grants
                 RETURNING subject, credential_version, blocked, last_login_at,
                           last_groups, last_grants, source",
                rusqlite::params![subject, at, groups_json, grants_json],
                map_principal,
            )
        })
    }

    /// Missing row accepts cv 1 only. A present row must match version and be
    /// unblocked. A read failure denies: this decides whether a session is
    /// still valid, and the safe answer to "cannot tell" is no. The local
    /// break-glass subject never reaches here, so denying cannot lock the
    /// operator out.
    pub fn principal_allows(&self, subject: &str, credential_version: u64) -> bool {
        match self.principal(subject) {
            Ok(None) => credential_version == 1,
            Ok(Some(row)) => credential_version == row.credential_version && !row.blocked,
            Err(error) => {
                tracing::error!(%error, subject, "principal read failed; refusing the session");
                false
            }
        }
    }

    pub fn revoke_principal(&self, subject: &str) -> Result<bool, String> {
        self.with(|connection| {
            let changed = connection.execute(
                "UPDATE principals SET credential_version = credential_version + 1, blocked = 1
                 WHERE subject = ?1",
                [subject],
            )?;
            Ok(changed > 0)
        })
    }

    pub fn unblock_principal(&self, subject: &str) -> Result<bool, String> {
        self.with(|connection| {
            let exists: i64 = connection.query_row(
                "SELECT EXISTS (SELECT 1 FROM principals WHERE subject = ?1)",
                [subject],
                |row| row.get(0),
            )?;
            if exists == 0 {
                return Ok(false);
            }
            connection.execute(
                "UPDATE principals SET blocked = 0 WHERE subject = ?1",
                [subject],
            )?;
            Ok(true)
        })
    }

    // ------------------------------------------------- operations helpers

    /// Consistent snapshot of the database via SQLite's VACUUM INTO. The
    /// destination must not exist.
    pub fn backup_into(&self, destination: &Path) -> Result<(), String> {
        self.with(|connection| {
            connection.execute("VACUUM INTO ?1", [destination.to_string_lossy().as_ref()])
        })
        .map(|_| ())
    }

    /// Every link across every tenant. Internal use only (retention sweeps,
    /// metrics); administrative API reads stay tenant-scoped.
    pub fn all_links(&self) -> Result<Vec<Link>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                        active, legal_hold, notify_on_upload, uploads_json, events_json
                 FROM links ORDER BY rowid",
            )?;
            let rows = statement.query_map([], row_to_link)?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn audit_count(&self) -> Result<u64, String> {
        self.with(|connection| {
            connection
                .query_row("SELECT count(*) FROM audit_log", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map(|value| value.max(0) as u64)
        })
    }

    // -------------------------------------------------------------- settings

    pub fn setting(&self, key: &str) -> Result<Option<String>, String> {
        self.with(|connection| {
            connection
                .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                    row.get(0)
                })
                .optional()
        })
    }

    pub fn settings_map(&self) -> Result<HashMap<String, String>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare("SELECT key, value FROM settings")?;
            let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<Result<HashMap<_, _>, _>>()
        })
    }

    pub fn put_settings(
        &self,
        actor: &str,
        writes: &[(String, SettingWrite)],
    ) -> Result<(), String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let now = i64::try_from(now_unix()).unwrap_or(0);
        for (key, write) in writes {
            match write {
                SettingWrite::Set(value) => {
                    transaction
                        .execute(
                            "INSERT INTO settings (key, value, updated_at, updated_by)
                             VALUES (?1, ?2, ?3, ?4)
                             ON CONFLICT(key) DO UPDATE SET
                                value = excluded.value,
                                updated_at = excluded.updated_at,
                                updated_by = excluded.updated_by",
                            rusqlite::params![key, value, now, actor],
                        )
                        .map_err(|error| error.to_string())?;
                }
                SettingWrite::Reset => {
                    transaction
                        .execute("DELETE FROM settings WHERE key = ?1", [key])
                        .map_err(|error| error.to_string())?;
                }
            }
        }
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn delete_setting(&self, key: &str) -> Result<(), String> {
        self.with(|connection| connection.execute("DELETE FROM settings WHERE key = ?1", [key]))
            .map(|_| ())
    }

    pub fn overlay(&self, config: &Config) -> Result<SettingsOverlay, String> {
        Ok(overlay_rows(&self.settings_map()?, config))
    }

    pub fn resolved_settings(&self, config: &Config) -> Result<ResolvedSettings, String> {
        Ok(self.overlay(config)?.resolved)
    }

    /// Quotas that apply to `tenant_key`: the tenant row for a named
    /// namespace, or `default_max_*` for the implicit default tenant.
    pub fn quotas_for(&self, tenant_key: &str, config: &Config) -> Result<Quotas, String> {
        if tenant_key.is_empty() {
            let settings = self.resolved_settings(config)?;
            Ok((
                settings.default_max_total_bytes,
                settings.default_max_links,
                settings.default_max_sessions,
            ))
        } else {
            Ok(self
                .tenant(tenant_key)?
                .map(|tenant| {
                    (
                        tenant.max_total_bytes,
                        tenant.max_links,
                        tenant.max_sessions,
                    )
                })
                .unwrap_or((None, None, None)))
        }
    }

    // -------------------------------------------------------------- quotas

    /// Bytes received-and-not-deleted across a tenant's links.
    pub fn tenant_received_bytes(&self, tenant: &str) -> Result<u64, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT COALESCE(SUM(bytes_hi), 0), COALESCE(SUM(bytes_lo), 0) FROM files
                     WHERE tenant = ?1 AND deleted = 0",
                    [tenant],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .map(|(hi, lo)| combine_byte_sums(hi, lo))
        })
    }

    /// Link and live-byte totals for every tenant in one grouped query.
    pub fn tenant_usage(&self) -> Result<Vec<TenantUsage>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "WITH namespaces(tenant) AS (
                     SELECT ''
                     UNION SELECT key FROM tenants
                     UNION SELECT tenant FROM links
                 ), link_counts AS (
                     SELECT tenant, COUNT(*) AS links FROM links GROUP BY tenant
                 ), file_bytes AS (
                     SELECT tenant, SUM(bytes_hi) AS bytes_hi, SUM(bytes_lo) AS bytes_lo
                     FROM files WHERE deleted = 0 GROUP BY tenant
                 )
                 SELECT namespaces.tenant, COALESCE(link_counts.links, 0),
                        COALESCE(file_bytes.bytes_hi, 0), COALESCE(file_bytes.bytes_lo, 0)
                 FROM namespaces
                 LEFT JOIN link_counts USING (tenant)
                 LEFT JOIN file_bytes USING (tenant)
                 ORDER BY namespaces.tenant",
            )?;
            let rows = statement.query_map([], |row| {
                Ok(TenantUsage {
                    tenant: row.get(0)?,
                    links: row.get::<_, i64>(1)?.max(0) as u64,
                    received_bytes: combine_byte_sums(row.get(2)?, row.get(3)?),
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    // ------------------------------------------------------ outbound grants

    pub fn insert_outbound_grant(&self, grant: OutboundGrant) -> Result<(), String> {
        let (bytes_hi, bytes_lo) = split_bytes(grant.bytes);
        let files_json = serde_json::to_string(&grant.files).unwrap_or_else(|_| "[]".to_owned());
        let file_count = i64::try_from(grant.files.len().max(1)).unwrap_or(i64::MAX);
        let grant_id = grant.id.clone();
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        transaction.execute(
                "INSERT INTO outbound_grants
                 (id, token_hash, password_hash, tenant, link_id, upload_id, package_root, name, suite,
                  root, file_index, bytes_hi, bytes_lo, label, created_at, expires_at, revoked_at,
                  downloads, max_downloads, notify_on_download, first_download_at, last_download_at,
                  files_json, file_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
                rusqlite::params![
                    &grant_id,
                    grant.token_hash,
                    grant.password_hash,
                    grant.tenant,
                    grant.link_id,
                    grant.upload_id,
                    grant.package_root,
                    grant.name,
                    grant.suite,
                    grant.root,
                    i64::try_from(grant.file_index).unwrap_or(i64::MAX),
                    bytes_hi,
                    bytes_lo,
                    grant.label,
                    i64::try_from(grant.created_at).unwrap_or(i64::MAX),
                    i64::try_from(grant.expires_at).unwrap_or(i64::MAX),
                    grant.revoked_at.map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    i64::try_from(grant.downloads).unwrap_or(i64::MAX),
                    grant
                        .max_downloads
                        .map(|count| i64::try_from(count).unwrap_or(i64::MAX)),
                    grant.notify_on_download,
                    grant
                        .first_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    grant
                        .last_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    files_json,
                    file_count,
                ],
            )
            .map_err(|error| error.to_string())?;
        let mut child = transaction
            .prepare(
                "INSERT INTO outbound_grant_files
             (grant_id, file_index, source, name, suite, root, bytes_hi, bytes_lo,
              receipt_b64, downloads, first_download_at, last_download_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )
            .map_err(|error| error.to_string())?;
        for (index, file) in grant.files.into_iter().enumerate() {
            let (file_bytes_hi, file_bytes_lo) = split_bytes(file.bytes);
            child
                .execute(rusqlite::params![
                    &grant_id,
                    i64::try_from(index).unwrap_or(i64::MAX),
                    file.source,
                    file.name,
                    file.suite,
                    file.root,
                    file_bytes_hi,
                    file_bytes_lo,
                    file.receipt_b64,
                    i64::try_from(file.downloads).unwrap_or(i64::MAX),
                    file.first_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                    file.last_download_at
                        .map(|at| i64::try_from(at).unwrap_or(i64::MAX)),
                ])
                .map_err(|error| error.to_string())?;
        }
        drop(child);
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn outbound_grants(&self, tenant: &str) -> Result<Vec<OutboundGrant>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                        name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                        expires_at, revoked_at, downloads, max_downloads, notify_on_download, first_download_at,
                        last_download_at,
                        files_json
                 FROM outbound_grants WHERE tenant = ?1 ORDER BY created_at, rowid",
            )?;
            let rows = statement.query_map([tenant], map_outbound_grant)?;
            let mut grants = rows.collect::<Result<Vec<_>, _>>()?;
            for grant in &mut grants {
                overlay_outbound_file_counters(connection, grant)?;
            }
            Ok(grants)
        })
    }

    pub fn outbound_grants_page(
        &self,
        tenant: &str,
        limit: usize,
        offset: usize,
        file_preview_limit: usize,
    ) -> Result<(Vec<(OutboundGrant, usize)>, u64), String> {
        let limit = i64::try_from(limit).map_err(|_| "outbound grant limit overflow".to_owned())?;
        let offset =
            i64::try_from(offset).map_err(|_| "outbound grant offset overflow".to_owned())?;
        let file_preview_limit = i64::try_from(file_preview_limit)
            .map_err(|_| "outbound grant file preview limit overflow".to_owned())?;
        self.with(|connection| {
            let grants = {
                let mut statement = connection.prepare(
                    "SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                            name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                            expires_at, revoked_at, downloads, max_downloads, notify_on_download, first_download_at,
                            last_download_at,
                            file_count,
                            CASE WHEN file_count <= ?4
                                 THEN files_json ELSE '[]' END AS files_json
                     FROM outbound_grants WHERE tenant = ?1
                     ORDER BY created_at DESC, rowid DESC LIMIT ?2 OFFSET ?3",
                )?;
                let rows = statement.query_map(
                    rusqlite::params![tenant, limit, offset, file_preview_limit],
                    map_outbound_grant_page,
                )?;
                let mut grants = rows.collect::<Result<Vec<_>, _>>()?;
                for (grant, _) in &mut grants {
                    overlay_outbound_file_counters(connection, grant)?;
                }
                grants
            };
            let total =
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM outbound_grants WHERE tenant = ?1",
                        [tenant],
                        |row| row.get::<_, i64>(0),
                    )
                    .map(|count| count.max(0) as u64)?;
            Ok((grants, total))
        })
    }

    pub fn outbound_grant_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<OutboundGrant>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                            name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                            expires_at, revoked_at, downloads, max_downloads, notify_on_download, first_download_at,
                            last_download_at,
                            files_json
                     FROM outbound_grants WHERE token_hash = ?1",
                    [token_hash],
                    map_outbound_grant,
                )
                .optional()
                .and_then(|grant| {
                    grant
                        .map(|mut grant| {
                            overlay_outbound_file_counters(connection, &mut grant)?;
                            Ok(grant)
                        })
                        .transpose()
                })
        })
    }

    /// Looks up one outbound file without parsing the full manifest.
    pub fn outbound_grant_file_by_token_hash(
        &self,
        token_hash: &str,
        index: usize,
    ) -> Result<Option<(OutboundGrant, Option<OutboundGrantFile>)>, String> {
        self.with(|connection| {
            let parent = connection
                .query_row(
                    "SELECT id, token_hash, password_hash, tenant, link_id, upload_id, package_root,
                            name, suite, root, file_index, bytes_hi, bytes_lo, label, created_at,
                            expires_at, revoked_at, downloads, max_downloads, notify_on_download,
                            first_download_at, last_download_at, file_count
                     FROM outbound_grants WHERE token_hash = ?1",
                    [token_hash],
                    |row| {
                        let file_count = row.get::<_, i64>("file_count")?;
                        Ok((map_outbound_grant_base(row)?, file_count.max(0) as usize))
                    },
                )
                .optional()?;
            let Some((grant, file_count)) = parent else {
                return Ok(None);
            };
            if index >= file_count {
                return Ok(None);
            }
            let row = connection
                .query_row(
                    "SELECT source, name, suite, root, bytes_hi, bytes_lo, receipt_b64,
                            downloads, first_download_at, last_download_at
                     FROM outbound_grant_files WHERE grant_id = ?1 AND file_index = ?2",
                    rusqlite::params![grant.id, i64::try_from(index).unwrap_or(i64::MAX)],
                    map_outbound_grant_file,
                )
                .optional()?;
            if row.is_none() {
                let has_children: bool = connection.query_row(
                    "SELECT EXISTS (SELECT 1 FROM outbound_grant_files WHERE grant_id = ?1)",
                    [&grant.id],
                    |row| row.get(0),
                )?;
                if has_children || file_count != 1 {
                    return Ok(None);
                }
                let files_json: String = connection.query_row(
                    "SELECT files_json FROM outbound_grants WHERE id = ?1",
                    [&grant.id],
                    |row| row.get(0),
                )?;
                if !serde_json::from_str::<Vec<OutboundGrantFile>>(&files_json)
                    .map(|files| files.is_empty())
                    .unwrap_or(false)
                {
                    return Ok(None);
                }
            }
            Ok(Some((grant, row)))
        })
    }

    pub fn rotate_outbound_grant_token(
        &self,
        tenant: &str,
        id: &str,
        token_hash: &str,
    ) -> Result<bool, String> {
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE outbound_grants SET token_hash = ?3
                     WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL",
                    rusqlite::params![tenant, id, token_hash],
                )
                .map(|changed| changed > 0)
        })
    }

    pub fn extend_outbound_grant(
        &self,
        tenant: &str,
        id: &str,
        seconds: u64,
        now: u64,
    ) -> Result<Option<u64>, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let result = (|| {
            let existing: Option<i64> = transaction
                .query_row(
                    "SELECT expires_at FROM outbound_grants
                     WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL",
                    rusqlite::params![tenant, id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            let Some(existing) = existing else {
                return Ok(None);
            };
            let base = (existing.max(0) as u64).max(now.min(i64::MAX as u64));
            let new_expiry = base.saturating_add(seconds).min(i64::MAX as u64);
            let changed = transaction
                .execute(
                    "UPDATE outbound_grants SET expires_at = ?3
                     WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL",
                    rusqlite::params![tenant, id, new_expiry as i64],
                )
                .map_err(|error| error.to_string())?;
            if changed == 0 {
                return Ok(None);
            }
            Ok(Some(new_expiry))
        })();
        match result {
            Ok(result) => {
                transaction.commit().map_err(|error| error.to_string())?;
                Ok(result)
            }
            Err(error) => Err(error),
        }
    }

    pub fn revoke_outbound_grant(&self, tenant: &str, id: &str, at: u64) -> Result<bool, String> {
        self.with(|connection| {
            connection.execute(
                "UPDATE outbound_grants SET revoked_at = ?3
                 WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL",
                rusqlite::params![tenant, id, i64::try_from(at).unwrap_or(i64::MAX)],
            )
        })
        .map(|changed| changed > 0)
    }

    pub fn set_outbound_notify_on_download(
        &self,
        tenant: &str,
        id: &str,
        enabled: bool,
    ) -> Result<bool, String> {
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE outbound_grants SET notify_on_download = ?3
                     WHERE tenant = ?1 AND id = ?2",
                    rusqlite::params![tenant, id, enabled],
                )
                .map(|changed| changed > 0)
        })
    }

    pub fn record_outbound_download(
        &self,
        id: &str,
        indexes: &[usize],
        at: u64,
    ) -> Result<OutboundDownloadResult, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let result = (|| {
            let (downloads, max_downloads, first_download_at, normalized): (
                i64,
                Option<i64>,
                Option<i64>,
                bool,
            ) = transaction
                .query_row(
                    "SELECT g.downloads, g.max_downloads, g.first_download_at,
                                EXISTS (SELECT 1 FROM outbound_grant_files
                                        WHERE grant_id = g.id)
                         FROM outbound_grants AS g WHERE g.id = ?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "outbound grant not found".to_owned())?;
            let downloads = downloads.max(0) as u64;
            let max_downloads = max_downloads.and_then(|max| u64::try_from(max).ok());
            if max_downloads.is_some_and(|max| downloads >= max) {
                return Err(OUTBOUND_DOWNLOAD_LIMIT_REACHED.to_owned());
            }
            if normalized {
                let mut unique_indexes = indexes.to_vec();
                unique_indexes.sort_unstable();
                unique_indexes.dedup();
                let was_all_files_downloaded = downloads > 0;
                let first_download = first_download_at.is_none();
                let at = i64::try_from(at).unwrap_or(i64::MAX);
                let first_download_at = if first_download {
                    Some(at)
                } else {
                    first_download_at
                };
                let mut update = transaction
                    .prepare(
                        "UPDATE outbound_grant_files
                         SET downloads = CASE WHEN downloads = 9223372036854775807
                                              THEN downloads ELSE downloads + 1 END,
                             first_download_at = COALESCE(first_download_at, ?3),
                             last_download_at = ?3
                         WHERE grant_id = ?1 AND file_index = ?2
                           AND (?4 IS NULL OR downloads < ?4)",
                    )
                    .map_err(|error| error.to_string())?;
                let max_downloads =
                    max_downloads.map(|value| i64::try_from(value).unwrap_or(i64::MAX));
                for index in &unique_indexes {
                    let changed = update
                        .execute(rusqlite::params![
                            id,
                            i64::try_from(*index).unwrap_or(i64::MAX),
                            at,
                            max_downloads,
                        ])
                        .map_err(|error| error.to_string())?;
                    if changed == 0 {
                        let exists: bool = transaction
                            .query_row(
                                "SELECT EXISTS (SELECT 1 FROM outbound_grant_files
                                                 WHERE grant_id = ?1 AND file_index = ?2)",
                                rusqlite::params![id, i64::try_from(*index).unwrap_or(i64::MAX)],
                                |row| row.get(0),
                            )
                            .map_err(|error| error.to_string())?;
                        if exists {
                            return Err(OUTBOUND_DOWNLOAD_LIMIT_REACHED.to_owned());
                        }
                        return Err("outbound file index out of range".to_owned());
                    }
                }
                drop(update);
                let downloads = if unique_indexes.is_empty() {
                    downloads
                } else {
                    transaction
                        .query_row(
                            "SELECT downloads FROM outbound_grant_files
                             WHERE grant_id = ?1 ORDER BY downloads LIMIT 1",
                            [id],
                            |row| row.get::<_, i64>(0),
                        )
                        .map(|value| value.max(0) as u64)
                        .map_err(|error| error.to_string())?
                };
                let completed_delivery = !was_all_files_downloaded && downloads > 0;
                transaction
                    .execute(
                        "UPDATE outbound_grants
                         SET downloads = ?2, first_download_at = ?3, last_download_at = ?4
                         WHERE id = ?1",
                        rusqlite::params![
                            id,
                            i64::try_from(downloads).unwrap_or(i64::MAX),
                            first_download_at,
                            at,
                        ],
                    )
                    .map_err(|error| error.to_string())?;
                return Ok(OutboundDownloadResult {
                    first_download,
                    completed_delivery,
                });
            }
            let files_json: String = transaction
                .query_row(
                    "SELECT files_json FROM outbound_grants WHERE id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            let files: Vec<OutboundGrantFile> = serde_json::from_str(&files_json)
                .map_err(|error| format!("parse outbound grant files: {error}"))?;
            if !files.is_empty() {
                return Err("outbound grant files are not normalized".to_owned());
            }
            let mut unique_indexes = indexes.to_vec();
            unique_indexes.sort_unstable();
            unique_indexes.dedup();
            if unique_indexes.iter().any(|&index| index != 0) {
                return Err("outbound file index out of range".to_owned());
            }
            let first_download = first_download_at.is_none();
            let at = i64::try_from(at).unwrap_or(i64::MAX);
            let first_download_at = if first_download {
                Some(at)
            } else {
                first_download_at
            };
            let downloads = downloads.saturating_add(1);
            transaction
                .execute(
                    "UPDATE outbound_grants
                     SET downloads = ?2, first_download_at = ?3, last_download_at = ?4
                     WHERE id = ?1",
                    rusqlite::params![
                        id,
                        i64::try_from(downloads).unwrap_or(i64::MAX),
                        first_download_at,
                        at,
                    ],
                )
                .map_err(|error| error.to_string())?;
            Ok(OutboundDownloadResult {
                first_download,
                completed_delivery: first_download,
            })
        })();
        match result {
            Ok(result) => {
                transaction.commit().map_err(|error| error.to_string())?;
                Ok(result)
            }
            Err(error) => Err(error),
        }
    }

    pub fn has_active_outbound_grant(
        &self,
        tenant: &str,
        link_id: &str,
        upload_id: &str,
        file_index: usize,
        now: u64,
    ) -> Result<bool, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM outbound_grants
                     WHERE tenant = ?1 AND link_id = ?2 AND upload_id = ?3 AND file_index = ?4
                       AND revoked_at IS NULL AND expires_at > ?5
                       AND (max_downloads IS NULL OR downloads < max_downloads)
                 )",
                rusqlite::params![
                    tenant,
                    link_id,
                    upload_id,
                    i64::try_from(file_index).unwrap_or(i64::MAX),
                    i64::try_from(now).unwrap_or(i64::MAX),
                ],
                |row| row.get::<_, i64>(0),
            )
        })
        .map(|exists| exists != 0)
    }

    pub fn has_active_library_grant(
        &self,
        tenant: &str,
        source: &str,
        now: u64,
    ) -> Result<bool, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT files_json
                 FROM outbound_grants
                 WHERE tenant = ?1 AND length(trim(files_json)) > 2
                   AND revoked_at IS NULL AND expires_at > ?2
                   AND (max_downloads IS NULL OR downloads < max_downloads)",
            )?;
            let rows = statement.query_map(
                rusqlite::params![tenant, i64::try_from(now).unwrap_or(i64::MAX)],
                |row| row.get::<_, String>(0),
            )?;
            for row in rows {
                let files: Vec<OutboundGrantFile> =
                    serde_json::from_str(&row?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                if files.iter().any(|file| file.source == source) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .map_err(|error| error.to_string())
    }

    pub fn active_outbound_file_keys(
        &self,
        tenant: &str,
        link_id: &str,
        now: u64,
    ) -> Result<Vec<(String, usize)>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT upload_id, file_index
                 FROM outbound_grants
                 WHERE tenant = ?1 AND link_id = ?2
                   AND revoked_at IS NULL AND expires_at > ?3
                   AND (max_downloads IS NULL OR downloads < max_downloads)",
            )?;
            let rows = statement.query_map(
                rusqlite::params![tenant, link_id, i64::try_from(now).unwrap_or(i64::MAX)],
                |row| {
                    let upload_id = row.get::<_, String>(0)?;
                    let file_index = usize::try_from(row.get::<_, i64>(1)?).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Integer,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "outbound grant file index is outside usize range",
                            )),
                        )
                    })?;
                    Ok((upload_id, file_index))
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn link_has_active_outbound_grants(
        &self,
        tenant: &str,
        link_id: &str,
        now: u64,
    ) -> Result<bool, String> {
        self.with(|connection| {
            connection.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM outbound_grants
                     WHERE tenant = ?1 AND link_id = ?2
                       AND revoked_at IS NULL AND expires_at > ?3
                       AND (max_downloads IS NULL OR downloads < max_downloads)
                 )",
                rusqlite::params![tenant, link_id, i64::try_from(now).unwrap_or(i64::MAX),],
                |row| row.get::<_, i64>(0),
            )
        })
        .map(|exists| exists != 0)
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn insert_link_row(connection: &Connection, link: &Link) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO links (id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                            active, legal_hold, notify_on_upload, uploads_json, events_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        link_params(link),
    )?;
    rebuild_link_files(connection, link)?;
    Ok(())
}

fn write_link_row(connection: &Connection, link: &Link) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE links SET label = ?3, dest = ?4, password_hash = ?5, created_at = ?6,
                          expires_at = ?7, max_bytes = ?8, active = ?9,
                          legal_hold = ?10, notify_on_upload = ?11, uploads_json = ?12, events_json = ?13
         WHERE id = ?1 AND tenant = ?2",
        link_params(link),
    )?;
    Ok(())
}

fn rebuild_link_files(connection: &Connection, link: &Link) -> rusqlite::Result<()> {
    connection.execute("DELETE FROM files WHERE link_id = ?1", [&link.id])?;
    for (upload_index, upload) in link.uploads.iter().enumerate() {
        insert_upload_files(
            connection,
            &link.id,
            &link.tenant,
            i64::try_from(upload_index).unwrap_or(i64::MAX),
            upload,
        )?;
    }
    Ok(())
}

fn insert_upload_files(
    connection: &Connection,
    link_id: &str,
    tenant: &str,
    upload_index: i64,
    upload: &UploadRecord,
) -> rusqlite::Result<()> {
    let mut insert = connection.prepare_cached(
        "INSERT INTO files
             (link_id, tenant, upload_index, file_index, bytes_hi, bytes_lo, deleted)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for (file_index, file) in upload.files.iter().enumerate() {
        let (bytes_hi, bytes_lo) = split_bytes(file.bytes);
        insert.execute(rusqlite::params![
            link_id,
            tenant,
            upload_index,
            i64::try_from(file_index).unwrap_or(i64::MAX),
            bytes_hi,
            bytes_lo,
            file.deleted,
        ])?;
    }
    Ok(())
}

fn sync_link_files(connection: &Connection, link: &Link) -> rusqlite::Result<()> {
    let mut existing = {
        let mut statement = connection.prepare_cached(
            "SELECT upload_index, file_index, bytes_hi, bytes_lo, deleted
             FROM files WHERE link_id = ?1",
        )?;
        let rows = statement.query_map([&link.id], |row| {
            Ok((
                (row.get::<_, i64>(0)?, row.get::<_, i64>(1)?),
                (
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, bool>(4)?,
                ),
            ))
        })?;
        rows.collect::<Result<HashMap<_, _>, _>>()?
    };
    let mut upsert = connection.prepare_cached(
        "INSERT INTO files
             (link_id, tenant, upload_index, file_index, bytes_hi, bytes_lo, deleted)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(link_id, upload_index, file_index) DO UPDATE SET
             tenant = excluded.tenant, bytes_hi = excluded.bytes_hi,
             bytes_lo = excluded.bytes_lo, deleted = excluded.deleted",
    )?;
    for (upload_index, upload) in link.uploads.iter().enumerate() {
        for (file_index, file) in upload.files.iter().enumerate() {
            let key = (
                i64::try_from(upload_index).unwrap_or(i64::MAX),
                i64::try_from(file_index).unwrap_or(i64::MAX),
            );
            let (bytes_hi, bytes_lo) = split_bytes(file.bytes);
            let value = (bytes_hi, bytes_lo, file.deleted);
            if existing.remove(&key) == Some(value) {
                continue;
            }
            upsert.execute(rusqlite::params![
                link.id,
                link.tenant,
                key.0,
                key.1,
                bytes_hi,
                bytes_lo,
                file.deleted,
            ])?;
        }
    }
    drop(upsert);
    let mut delete = connection.prepare_cached(
        "DELETE FROM files WHERE link_id = ?1 AND upload_index = ?2 AND file_index = ?3",
    )?;
    for ((upload_index, file_index), _) in existing {
        delete.execute(rusqlite::params![link.id, upload_index, file_index])?;
    }
    Ok(())
}

fn split_bytes(bytes: u64) -> (i64, i64) {
    ((bytes >> 32) as i64, (bytes & 0xffff_ffff) as i64)
}

fn combine_byte_sums(hi: i64, lo: i64) -> u64 {
    u64::try_from(hi)
        .ok()
        .and_then(|hi| hi.checked_mul(1 << 32))
        .and_then(|bytes| u64::try_from(lo).ok().and_then(|lo| bytes.checked_add(lo)))
        .unwrap_or(u64::MAX)
}

fn encode_quota(value: u64) -> String {
    format!("u:{value}")
}

fn decode_quota(value: Option<String>, column: usize) -> rusqlite::Result<Option<u64>> {
    value
        .map(|value| {
            value
                .strip_prefix("u:")
                .unwrap_or(&value)
                .parse()
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        column,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
        })
        .transpose()
}

fn link_params(link: &Link) -> [rusqlite::types::Value; 13] {
    use rusqlite::types::Value as V;
    let uploads = serde_json::to_string(&link.uploads).unwrap_or_else(|_| "[]".to_owned());
    let events = serde_json::to_string(&link.events).unwrap_or_else(|_| "[]".to_owned());
    [
        V::from(link.id.clone()),
        V::from(link.tenant.clone()),
        V::from(link.label.clone()),
        V::from(link.dest.clone()),
        link.password_hash.clone().map(V::from).unwrap_or(V::Null),
        V::from(i64::try_from(link.created_at).unwrap_or(i64::MAX)),
        link.expires_at
            .map(|at| V::from(i64::try_from(at).unwrap_or(i64::MAX)))
            .unwrap_or(V::Null),
        link.max_bytes
            .map(|b| i64::try_from(b).unwrap_or(i64::MAX))
            .map(V::from)
            .unwrap_or(V::Null),
        V::from(link.active),
        V::from(link.legal_hold),
        V::from(link.notify_on_upload),
        V::from(uploads),
        V::from(events),
    ]
}

fn row_to_link(row: &rusqlite::Row<'_>) -> rusqlite::Result<Link> {
    let uploads_json: String = row.get("uploads_json")?;
    let events_json: String = row.get("events_json")?;
    Ok(Link {
        id: row.get("id")?,
        tenant: row.get("tenant")?,
        label: row.get("label")?,
        dest: row.get("dest")?,
        password_hash: row.get("password_hash")?,
        created_at: row.get::<_, i64>("created_at")?.max(0) as u64,
        expires_at: row
            .get::<_, Option<i64>>("expires_at")?
            .and_then(|value| u64::try_from(value).ok()),
        max_bytes: row
            .get::<_, Option<i64>>("max_bytes")?
            .and_then(|value| u64::try_from(value).ok()),
        active: row.get::<_, i64>("active")? != 0,
        legal_hold: row.get::<_, i64>("legal_hold")? != 0,
        notify_on_upload: row.get::<_, i64>("notify_on_upload")? != 0,
        uploads: parse_json(&uploads_json, 11)?,
        events: parse_json(&events_json, 12)?,
    })
}

fn map_outbound_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutboundGrant> {
    let mut grant = map_outbound_grant_base(row)?;
    grant.files = parse_json(&row.get::<_, String>("files_json")?, 20)?;
    Ok(grant)
}

fn map_outbound_grant_base(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutboundGrant> {
    Ok(OutboundGrant {
        id: row.get("id")?,
        token_hash: row.get("token_hash")?,
        password_hash: row.get("password_hash")?,
        tenant: row.get("tenant")?,
        link_id: row.get("link_id")?,
        upload_id: row.get("upload_id")?,
        package_root: row.get("package_root")?,
        name: row.get("name")?,
        suite: row.get("suite")?,
        root: row.get("root")?,
        file_index: usize::try_from(row.get::<_, i64>("file_index")?.max(0)).unwrap_or(usize::MAX),
        bytes: combine_byte_sums(row.get("bytes_hi")?, row.get("bytes_lo")?),
        label: row.get("label")?,
        created_at: row.get::<_, i64>("created_at")?.max(0) as u64,
        expires_at: row.get::<_, i64>("expires_at")?.max(0) as u64,
        revoked_at: row
            .get::<_, Option<i64>>("revoked_at")?
            .and_then(|value| u64::try_from(value).ok()),
        downloads: row.get::<_, i64>("downloads")?.max(0) as u64,
        max_downloads: row
            .get::<_, Option<i64>>("max_downloads")?
            .and_then(|value| u64::try_from(value).ok()),
        notify_on_download: row.get::<_, i64>("notify_on_download")? != 0,
        first_download_at: row
            .get::<_, Option<i64>>("first_download_at")?
            .and_then(|value| u64::try_from(value).ok()),
        last_download_at: row
            .get::<_, Option<i64>>("last_download_at")?
            .and_then(|value| u64::try_from(value).ok()),
        files: Vec::new(),
    })
}

fn map_outbound_grant_file(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutboundGrantFile> {
    Ok(OutboundGrantFile {
        source: row.get("source")?,
        name: row.get("name")?,
        suite: row.get("suite")?,
        root: row.get("root")?,
        bytes: combine_byte_sums(row.get("bytes_hi")?, row.get("bytes_lo")?),
        receipt_b64: row.get("receipt_b64")?,
        downloads: row.get::<_, i64>("downloads")?.max(0) as u64,
        first_download_at: row
            .get::<_, Option<i64>>("first_download_at")?
            .and_then(|value| u64::try_from(value).ok()),
        last_download_at: row
            .get::<_, Option<i64>>("last_download_at")?
            .and_then(|value| u64::try_from(value).ok()),
    })
}

fn overlay_outbound_file_counters(
    connection: &Connection,
    grant: &mut OutboundGrant,
) -> rusqlite::Result<()> {
    if grant.files.is_empty() {
        return Ok(());
    }
    let mut statement = connection.prepare(
        "SELECT file_index, downloads, first_download_at, last_download_at
         FROM outbound_grant_files WHERE grant_id = ?1 ORDER BY file_index",
    )?;
    let rows = statement.query_map([&grant.id], |row| {
        Ok((
            row.get::<_, i64>("file_index")?,
            row.get::<_, i64>("downloads")?,
            row.get::<_, Option<i64>>("first_download_at")?,
            row.get::<_, Option<i64>>("last_download_at")?,
        ))
    })?;
    for row in rows {
        let (index, downloads, first, last) = row?;
        if let Some(file) = grant
            .files
            .get_mut(usize::try_from(index).unwrap_or(usize::MAX))
        {
            file.downloads = downloads.max(0) as u64;
            file.first_download_at = first.and_then(|value| u64::try_from(value).ok());
            file.last_download_at = last.and_then(|value| u64::try_from(value).ok());
        }
    }
    Ok(())
}

fn map_outbound_grant_page(row: &rusqlite::Row<'_>) -> rusqlite::Result<(OutboundGrant, usize)> {
    let grant = map_outbound_grant(row)?;
    let file_count = row.get::<_, i64>("file_count")?;
    let file_count = usize::try_from(file_count).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    Ok((grant, file_count))
}

fn map_automation_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<AutomationToken> {
    Ok(AutomationToken {
        id: row.get("id")?,
        token_hash: row.get("token_hash")?,
        tenant: row.get("tenant")?,
        label: row.get("label")?,
        created_at: row.get::<_, i64>("created_at")?.max(0) as u64,
        expires_at: row.get::<_, i64>("expires_at")?.max(0) as u64,
        revoked_at: row
            .get::<_, Option<i64>>("revoked_at")?
            .and_then(|value| u64::try_from(value).ok()),
        last_used_at: row
            .get::<_, Option<i64>>("last_used_at")?
            .and_then(|value| u64::try_from(value).ok()),
    })
}

fn read_link(connection: &Connection, tenant: &str, id: &str) -> Result<Option<Link>, String> {
    connection
        .query_row(
            "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                        active, legal_hold, notify_on_upload, uploads_json, events_json
             FROM links WHERE tenant = ?1 AND id = ?2",
            rusqlite::params![tenant, id],
            row_to_link,
        )
        .optional()
        .map_err(|error| error.to_string())
}

/// One row of the audit log as exported.
#[derive(Clone, Debug, Serialize)]
pub struct AuditRow {
    pub rowid: i64,
    pub at: u64,
    pub tenant: String,
    pub actor: String,
    pub event: String,
    pub subject: String,
    pub detail: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AuditFilters<'a> {
    pub event: Option<&'a str>,
    pub query: Option<&'a str>,
}

fn map_tenant(row: &rusqlite::Row<'_>) -> rusqlite::Result<Tenant> {
    Ok(Tenant {
        key: row.get(0)?,
        label: row.get(1)?,
        admin_group: row.get(2)?,
        max_total_bytes: decode_quota(row.get(3)?, 3)?,
        max_links: decode_quota(row.get(4)?, 4)?,
        max_sessions: decode_quota(row.get(5)?, 5)?,
        created_at: row.get::<_, i64>(6)?.max(0) as u64,
    })
}

fn map_principal(row: &rusqlite::Row<'_>) -> rusqlite::Result<Principal> {
    let last_groups: String = row.get("last_groups")?;
    let last_grants: String = row.get("last_grants")?;
    Ok(Principal {
        subject: row.get("subject")?,
        credential_version: row.get::<_, i64>("credential_version")?.max(0) as u64,
        blocked: row.get::<_, i64>("blocked")? != 0,
        last_login_at: row.get::<_, i64>("last_login_at")?.max(0) as u64,
        last_groups: parse_json(&last_groups, 4)?,
        last_grants: parse_json(&last_grants, 5)?,
        source: row.get("source")?,
    })
}

fn map_audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRow> {
    Ok(AuditRow {
        rowid: row.get(0)?,
        at: row.get::<_, i64>(1)?.max(0) as u64,
        tenant: row.get(2)?,
        actor: row.get(3)?,
        event: row.get(4)?,
        subject: row.get(5)?,
        detail: parse_json(&row.get::<_, String>(6)?, 6)?,
    })
}

fn parse_json<T: DeserializeOwned>(text: &str, column: usize) -> rusqlite::Result<T> {
    serde_json::from_str(text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn insert_audit_row(
    connection: &Connection,
    tenant: &str,
    actor: &str,
    event: &str,
    subject: &str,
    detail: &serde_json::Value,
) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO audit_log (at, tenant, actor, event, subject, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            i64::try_from(now_unix()).unwrap_or(0),
            tenant,
            actor,
            event,
            subject,
            detail.to_string()
        ],
    )
}

impl Store {
    /// Inserts one audit row. Best effort: the tracing event at the call site
    /// is the operational record; the row is the queryable one.
    pub fn audit(
        &self,
        tenant: &str,
        actor: &str,
        event: &str,
        subject: &str,
        detail: &serde_json::Value,
    ) {
        let _ = self
            .with(|connection| insert_audit_row(connection, tenant, actor, event, subject, detail));
    }

    /// Changes a legal hold and records it in the same transaction.
    pub fn set_link_legal_hold(
        &self,
        tenant: &str,
        id: &str,
        legal_hold: bool,
        actor: &str,
    ) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let updated = transaction
            .execute(
                "UPDATE links SET legal_hold = ?3 WHERE tenant = ?1 AND id = ?2",
                rusqlite::params![tenant, id, legal_hold],
            )
            .map_err(|error| error.to_string())?;
        if updated == 0 {
            return Ok(false);
        }
        insert_audit_row(
            &transaction,
            tenant,
            actor,
            "link_legal_hold_changed",
            id,
            &serde_json::json!({ "legal_hold": legal_hold }),
        )
        .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    /// Audit rows strictly after the (at, rowid) cursor, oldest first,
    /// capped. When `tenant` is non-empty only that namespace's rows are
    /// returned; the empty string sees everything (platform admin).
    pub fn audit_export(
        &self,
        tenant: &str,
        since: u64,
        after_rowid: u64,
        limit: u64,
    ) -> Result<Vec<AuditRow>, String> {
        self.audit_export_filtered(tenant, since, after_rowid, limit, AuditFilters::default())
    }

    pub fn audit_export_filtered(
        &self,
        tenant: &str,
        since: u64,
        after_rowid: u64,
        limit: u64,
        filters: AuditFilters<'_>,
    ) -> Result<Vec<AuditRow>, String> {
        self.with(|connection| {
            Self::audit_export_query(connection, tenant, since, after_rowid, limit, filters)
        })
    }

    pub fn audit_recent(
        &self,
        tenant: &str,
        before_rowid: u64,
        limit: u64,
    ) -> Result<Vec<AuditRow>, String> {
        self.audit_recent_filtered(tenant, before_rowid, limit, AuditFilters::default())
    }

    pub fn audit_recent_filtered(
        &self,
        tenant: &str,
        before_rowid: u64,
        limit: u64,
        filters: AuditFilters<'_>,
    ) -> Result<Vec<AuditRow>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare_cached(
                "SELECT rowid, at, tenant, actor, event, subject, detail
                 FROM audit_log
                 WHERE (?1 = '' OR tenant = ?1)
                   AND (?2 = '' OR event = ?2)
                   AND (?3 = '' OR instr(lower(CASE WHEN tenant = '' THEN 'default' ELSE tenant END), lower(?3)) > 0
                        OR instr(lower(actor), lower(?3)) > 0
                        OR instr(lower(event), lower(?3)) > 0
                        OR instr(lower(subject), lower(?3)) > 0)
                   AND (?4 = 0 OR rowid < ?4)
                 ORDER BY rowid DESC LIMIT ?5",
            )?;
            let rows = statement.query_map(
                rusqlite::params![
                    tenant,
                    filters.event.unwrap_or(""),
                    filters.query.unwrap_or(""),
                    i64::try_from(before_rowid).unwrap_or(i64::MAX),
                    i64::try_from(limit).unwrap_or(i64::MAX),
                ],
                map_audit_row,
            )?;
            rows.collect()
        })
    }

    fn audit_export_query(
        connection: &Connection,
        tenant: &str,
        since: u64,
        after_rowid: u64,
        limit: u64,
        filters: AuditFilters<'_>,
    ) -> rusqlite::Result<Vec<AuditRow>> {
        let since = i64::try_from(since).unwrap_or(0);
        let after_rowid = i64::try_from(after_rowid).unwrap_or(0);
        let limit = i64::try_from(limit).unwrap_or(1000);
        let mut statement = connection.prepare_cached(
            "SELECT rowid, at, tenant, actor, event, subject, detail
             FROM audit_log
             WHERE (at > ?1 OR (at = ?1 AND rowid > ?2))
               AND (?3 = '' OR event = ?3)
               AND (?4 = '' OR instr(lower(CASE WHEN tenant = '' THEN 'default' ELSE tenant END), lower(?4)) > 0
                    OR instr(lower(actor), lower(?4)) > 0
                    OR instr(lower(event), lower(?4)) > 0
                    OR instr(lower(subject), lower(?4)) > 0)
               AND (?5 = '' OR tenant = ?5)
             ORDER BY at, rowid LIMIT ?6",
        )?;
        let rows = statement.query_map(
            rusqlite::params![
                since,
                after_rowid,
                filters.event.unwrap_or(""),
                filters.query.unwrap_or(""),
                tenant,
                limit,
            ],
            map_audit_row,
        )?;
        rows.collect()
    }

    /// Deletes audit rows older than `before`; returns how many.
    pub fn audit_prune(&self, before: u64) -> Result<usize, String> {
        self.with(|connection| {
            connection.execute(
                "DELETE FROM audit_log WHERE at < ?1",
                [i64::try_from(before).unwrap_or(0)],
            )
        })
    }
}

/// Outcome of [`Store::remove_tenant`].
#[derive(Debug, PartialEq)]
pub enum TenantRemoval {
    Deleted,
    Absent,
    HasLinks,
}

/// The three caps that apply to a namespace: total bytes, links, concurrent
/// sessions. None is unlimited.
pub type Quotas = (Option<u64>, Option<u64>, Option<u64>);

/// Outcome of [`Store::insert_tenant`].
#[derive(Debug, PartialEq)]
pub enum InsertTenantError {
    /// A tenant with that key is already there.
    AlreadyExists,
    Store(String),
}

/// Outcome of [`Store::insert_link`].
#[derive(Debug, PartialEq)]
pub enum InsertLinkError {
    NamedTenantGone,
    Store(String),
}

fn schema_version_stored(connection: &Connection) -> Result<u64, String> {
    let value: Option<String> = connection
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    match value {
        None => Ok(3),
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| format!("meta.schema_version is not a number ({raw})")),
    }
}

fn overlay_rows(rows: &HashMap<String, String>, config: &Config) -> SettingsOverlay {
    let (notify_webhook, notify_webhook_source) =
        overlay_text(rows, "notify_webhook", config.notify_webhook.clone());
    let (notify_ntfy, notify_ntfy_source) =
        overlay_text(rows, "notify_ntfy", config.notify_ntfy.clone());
    let (notify_ntfy_token, notify_ntfy_token_source) =
        overlay_text(rows, "notify_ntfy_token", config.notify_ntfy_token.clone());
    let env_pushover_token = config
        .notify_pushover
        .as_ref()
        .map(|(token, _)| token.clone());
    let env_pushover_user = config
        .notify_pushover
        .as_ref()
        .map(|(_, user)| user.clone());
    let (pushover_token, notify_pushover_token_source) =
        overlay_text(rows, "notify_pushover_token", env_pushover_token);
    let (pushover_user, notify_pushover_user_source) =
        overlay_text(rows, "notify_pushover_user", env_pushover_user);
    let notify_pushover_token_set = pushover_token.is_some();
    let notify_pushover_user_set = pushover_user.is_some();
    let notify_pushover = match (pushover_token, pushover_user) {
        (Some(token), Some(user)) => Some((token, user)),
        _ => None,
    };
    let (smtp_host, smtp_host_source) = overlay_text(rows, "smtp_host", config.smtp_host.clone());
    let (smtp_port, smtp_port_source) = overlay_port(rows, "smtp_port", config.smtp_port);
    let (smtp_starttls, smtp_starttls_source) =
        overlay_bool(rows, "smtp_starttls", config.smtp_starttls);
    let (smtp_username, smtp_username_source) =
        overlay_text(rows, "smtp_username", config.smtp_username.clone());
    let (smtp_password, smtp_password_source) =
        overlay_text(rows, "smtp_password", config.smtp_password.clone());
    let smtp_password_set = smtp_password.is_some();
    let (smtp_from, smtp_from_source) = overlay_text(rows, "smtp_from", config.smtp_from.clone());
    let (smtp_to, smtp_to_source) = overlay_text(rows, "smtp_to", config.smtp_to.clone());
    let smtp = assemble_smtp(
        smtp_host.clone(),
        smtp_port,
        smtp_starttls,
        smtp_username.clone(),
        smtp_password.clone(),
        smtp_from.clone(),
        smtp_to.clone(),
    );
    let (audit_retention_days, audit_retention_days_source) =
        overlay_u64(rows, "audit_retention_days", config.audit_retention_days);
    let (upload_retention_days, upload_retention_days_source) =
        overlay_u64(rows, "upload_retention_days", config.upload_retention_days);
    let (default_max_total_bytes, default_max_total_bytes_source) = overlay_positive(
        rows,
        "default_max_total_bytes",
        config.default_max_total_bytes,
    );
    let (default_max_links, default_max_links_source) =
        overlay_positive(rows, "default_max_links", config.default_max_links);
    let (default_max_sessions, default_max_sessions_source) =
        overlay_positive(rows, "default_max_sessions", config.default_max_sessions);
    let (public_password_login, public_password_login_source) =
        overlay_bool(rows, "public_password_login", config.public_password_login);
    SettingsOverlay {
        resolved: ResolvedSettings {
            notify_webhook,
            notify_ntfy,
            notify_ntfy_token,
            notify_pushover,
            smtp,
            audit_retention_days,
            upload_retention_days,
            default_max_total_bytes,
            default_max_links,
            default_max_sessions,
            public_password_login,
        },
        notify_webhook_source,
        notify_ntfy_source,
        notify_ntfy_token_source,
        notify_pushover_token_set,
        notify_pushover_token_source,
        notify_pushover_user_set,
        notify_pushover_user_source,
        smtp_host,
        smtp_host_source,
        smtp_port,
        smtp_port_source,
        smtp_starttls,
        smtp_starttls_source,
        smtp_username,
        smtp_username_source,
        smtp_password_set,
        smtp_password_source,
        smtp_from,
        smtp_from_source,
        smtp_to,
        smtp_to_source,
        audit_retention_days_source,
        upload_retention_days_source,
        default_max_total_bytes_source,
        default_max_links_source,
        default_max_sessions_source,
        public_password_login_source,
    }
}

fn overlay_text(
    rows: &HashMap<String, String>,
    key: &str,
    env: Option<String>,
) -> (Option<String>, &'static str) {
    match rows.get(key) {
        None => (env, "env"),
        Some(value) if value.is_empty() => (None, "db"),
        Some(value) => (Some(value.clone()), "db"),
    }
}

fn overlay_u64(rows: &HashMap<String, String>, key: &str, env: u64) -> (u64, &'static str) {
    match rows.get(key) {
        None => (env, "env"),
        Some(value) => match value.parse::<u64>() {
            Ok(parsed) => (parsed, "db"),
            Err(_) => {
                tracing::error!(key, value, "invalid settings value; using env default");
                (env, "env")
            }
        },
    }
}

fn overlay_positive(
    rows: &HashMap<String, String>,
    key: &str,
    env: Option<u64>,
) -> (Option<u64>, &'static str) {
    match rows.get(key) {
        None => (env, "env"),
        Some(value) => match value.parse::<u64>() {
            Ok(parsed) if parsed > 0 => (Some(parsed), "db"),
            _ => {
                tracing::error!(key, value, "invalid settings value; using env default");
                (env, "env")
            }
        },
    }
}

fn overlay_port(rows: &HashMap<String, String>, key: &str, env: u16) -> (u16, &'static str) {
    match rows.get(key) {
        None => (env, "env"),
        Some(value) => match value.parse::<u16>() {
            Ok(parsed) if parsed >= 1 => (parsed, "db"),
            _ => {
                tracing::error!(key, value, "invalid settings value; using env default");
                (env, "env")
            }
        },
    }
}

fn trimmed_option(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn smtp_recipients(to: &str) -> Vec<String> {
    to.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn assemble_smtp(
    host: Option<String>,
    port: u16,
    starttls: bool,
    username: Option<String>,
    password: Option<String>,
    from: Option<String>,
    to: Option<String>,
) -> Option<ResolvedSmtp> {
    let host = trimmed_option(host)?;
    let from = trimmed_option(from)?;
    let recipients = to
        .as_deref()
        .map(smtp_recipients)
        .filter(|parts| !parts.is_empty())?;
    Some(ResolvedSmtp {
        host,
        port,
        starttls,
        username: trimmed_option(username),
        password,
        from,
        to: recipients,
    })
}

fn overlay_bool(rows: &HashMap<String, String>, key: &str, env: bool) -> (bool, &'static str) {
    match rows.get(key) {
        None => (env, "env"),
        Some(value) if value == "1" => (true, "db"),
        Some(value) if value == "0" => (false, "db"),
        Some(value) => {
            tracing::error!(key, value, "invalid settings value; using env default");
            (env, "env")
        }
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_upload_records_default_to_http_transport() {
        let record: UploadRecord = serde_json::from_str(
            r#"{"id":"legacy","completed_at":1,"package_root":"root","total_bytes":0,"files":[]}"#,
        )
        .unwrap();
        assert_eq!(record.transport, None);
    }

    #[test]
    fn a_broken_table_is_an_error_not_a_panic() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .with(|connection| connection.execute_batch("DROP TABLE links"))
            .unwrap();
        // The point of the Result: a handler answers 500 and logs, instead of
        // a panicked task dropping the connection with nothing recorded.
        assert!(store.links("").is_err());
        assert!(store.link("", "any").is_err());
        assert!(store.all_links().is_err());
        // A principal that cannot be read denies the session rather than
        // admitting it.
        store
            .with(|connection| connection.execute_batch("DROP TABLE principals"))
            .unwrap();
        assert!(!store.principal_allows("user@example.com", 1));
    }

    pub(crate) fn test_link(id: &str) -> Link {
        Link {
            id: id.to_owned(),
            tenant: String::new(),
            label: "test".to_owned(),
            dest: String::new(),
            password_hash: None,
            created_at: 0,
            expires_at: None,
            max_bytes: None,
            active: true,
            legal_hold: false,
            notify_on_upload: false,
            uploads: Vec::new(),
            events: Vec::new(),
        }
    }

    pub(crate) fn link_in(tenant: &str, id: &str) -> Link {
        Link {
            tenant: tenant.to_owned(),
            ..test_link(id)
        }
    }

    pub(crate) fn test_tenant(key: &str) -> Tenant {
        Tenant {
            key: key.to_owned(),
            label: key.to_owned(),
            admin_group: None,
            max_total_bytes: None,
            max_links: None,
            max_sessions: None,
            created_at: 0,
        }
    }

    pub(crate) fn test_outbound_grant(id: &str, tenant: &str, file_index: usize) -> OutboundGrant {
        OutboundGrant {
            id: id.to_owned(),
            token_hash: format!("hash-{id}"),
            password_hash: None,
            tenant: tenant.to_owned(),
            link_id: "link".to_owned(),
            upload_id: "upload".to_owned(),
            package_root: "package".to_owned(),
            name: "file.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: format!("root-{id}"),
            file_index,
            bytes: u64::MAX,
            label: "download".to_owned(),
            created_at: 10,
            expires_at: 20,
            revoked_at: None,
            downloads: 0,
            max_downloads: None,
            notify_on_download: false,
            first_download_at: None,
            last_download_at: None,
            files: Vec::new(),
        }
    }

    fn test_automation_token(id: &str, tenant: &str) -> AutomationToken {
        AutomationToken {
            id: id.to_owned(),
            token_hash: format!("hash-{id}"),
            tenant: tenant.to_owned(),
            label: format!("Token {id}"),
            created_at: 10,
            expires_at: 20,
            revoked_at: None,
            last_used_at: None,
        }
    }

    #[test]
    fn outbound_grants_migrate_and_round_trip_full_byte_range() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let schema = store
            .with(|connection| {
                connection.query_row(
                    "SELECT value FROM meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
            })
            .unwrap();
        assert_eq!(schema, "16");
        assert!(store
            .with(|connection| {
                connection.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'outbound_grants'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
            })
            .unwrap() > 0);

        let grant = test_outbound_grant("g1", "acme", 3);
        store.insert_outbound_grant(grant.clone()).unwrap();
        assert_eq!(store.outbound_grants("acme").unwrap(), vec![grant]);
    }

    #[test]
    fn outbound_grants_round_trip_multiple_library_files() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("library", "acme", 0);
        grant.files = vec![
            OutboundGrantFile {
                source: "objects/a".to_owned(),
                name: "a.txt".to_owned(),
                suite: "blake3".to_owned(),
                root: "aa".to_owned(),
                bytes: 3,
                receipt_b64: "receipt-a".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            },
            OutboundGrantFile {
                source: "objects/b".to_owned(),
                name: "b.txt".to_owned(),
                suite: "sha256".to_owned(),
                root: "bb".to_owned(),
                bytes: u64::MAX,
                receipt_b64: "receipt-b".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            },
        ];
        store.insert_outbound_grant(grant.clone()).unwrap();
        assert_eq!(
            store.outbound_grant_by_token_hash("hash-library").unwrap(),
            Some(grant)
        );
        store.record_outbound_download("library", &[0], 30).unwrap();
        assert_eq!(
            store
                .with(|connection| connection.query_row(
                    "SELECT file_count FROM outbound_grants WHERE id = 'library'",
                    [],
                    |row| row.get::<_, i64>(0),
                ))
                .unwrap(),
            2
        );
        let page = store.outbound_grants_page("acme", 10, 0, 2).unwrap().0;
        assert_eq!(page[0].0.files[0].downloads, 1);
    }

    #[test]
    fn normalized_file_lookup_and_download_do_not_parse_or_rewrite_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("normalized", "acme", 0);
        grant.files = (0..3)
            .map(|index| OutboundGrantFile {
                source: format!("objects/{index}"),
                name: format!("file-{index}"),
                suite: "blake3".to_owned(),
                root: format!("root-{index}"),
                bytes: if index == 2 { u64::MAX } else { index + 1 },
                receipt_b64: format!("receipt-{index}"),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .collect();
        store.insert_outbound_grant(grant.clone()).unwrap();
        let original_json: String = store
            .with(|connection| {
                connection.query_row(
                    "SELECT files_json FROM outbound_grants WHERE id = 'normalized'",
                    [],
                    |row| row.get(0),
                )
            })
            .unwrap();
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE outbound_grants SET files_json = 'deliberately invalid' WHERE id = 'normalized'",
                    [],
                )
            })
            .unwrap();
        let (_, file) = store
            .outbound_grant_file_by_token_hash("hash-normalized", 2)
            .unwrap()
            .unwrap();
        assert_eq!(file.unwrap().bytes, u64::MAX);
        store
            .record_outbound_download("normalized", &[2], 30)
            .unwrap();
        let current_json: String = store
            .with(|connection| {
                connection.query_row(
                    "SELECT files_json FROM outbound_grants WHERE id = 'normalized'",
                    [],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(current_json, "deliberately invalid");
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE outbound_grants SET files_json = ?1 WHERE id = 'normalized'",
                    [&original_json],
                )
            })
            .unwrap();
        let full = store
            .outbound_grant_by_token_hash("hash-normalized")
            .unwrap()
            .unwrap();
        assert_eq!(full.files[2].downloads, 1);
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE outbound_grant_files SET downloads = 9223372036854775807
                     WHERE grant_id = 'normalized' AND file_index = 2",
                    [],
                )
            })
            .unwrap();
        store
            .record_outbound_download("normalized", &[2], 31)
            .unwrap();
        let saturated: i64 = store
            .with(|connection| {
                connection.query_row(
                    "SELECT downloads FROM outbound_grant_files
                     WHERE grant_id = 'normalized' AND file_index = 2",
                    [],
                    |row| row.get(0),
                )
            })
            .unwrap();
        assert_eq!(saturated, i64::MAX);
    }

    #[test]
    fn legacy_file_lookup_allows_only_scalar_index_zero() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("legacy-lookup", "acme", 0))
            .unwrap();
        let (grant, file) = store
            .outbound_grant_file_by_token_hash("hash-legacy-lookup", 0)
            .unwrap()
            .unwrap();
        assert_eq!(grant.id, "legacy-lookup");
        assert!(file.is_none());
        assert!(store
            .outbound_grant_file_by_token_hash("hash-legacy-lookup", 1)
            .unwrap()
            .is_none());

        let mut normalized = test_outbound_grant("missing-child", "acme", 0);
        normalized.files = vec![OutboundGrantFile {
            source: "objects/only".to_owned(),
            name: "only".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: 1,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        store.insert_outbound_grant(normalized).unwrap();
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM outbound_grant_files WHERE grant_id = 'missing-child'",
                    [],
                )
            })
            .unwrap();
        assert!(store
            .outbound_grant_file_by_token_hash("hash-missing-child", 0)
            .unwrap()
            .is_none());
    }

    #[test]
    fn v15_migration_backfills_exact_normalized_rows() {
        let directory = tempfile::tempdir().unwrap();
        let mut grant = test_outbound_grant("migrate", "acme", 0);
        grant.files = vec![OutboundGrantFile {
            source: "objects/large".to_owned(),
            name: "large.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: u64::MAX,
            receipt_b64: "receipt".to_owned(),
            downloads: 7,
            first_download_at: Some(11),
            last_download_at: Some(22),
        }];
        {
            let store = Store::open(directory.path()).unwrap();
            store.insert_outbound_grant(grant.clone()).unwrap();
            let files_json = serde_json::to_string(&grant.files).unwrap();
            store
                .with(|connection| {
                    connection.execute(
                        "UPDATE outbound_grants SET files_json = ?1 WHERE id = 'migrate'",
                        [&files_json],
                    )
                })
                .unwrap();
        }
        let connection = Connection::open(directory.path().join("votport.db")).unwrap();
        connection
            .execute_batch(
                "DROP TABLE outbound_grant_files;
                 UPDATE meta SET value = '15' WHERE key = 'schema_version';",
            )
            .unwrap();
        drop(connection);
        let store = Store::open(directory.path()).unwrap();
        let row = store
            .with(|connection| {
                connection.query_row(
                    "SELECT source, bytes_hi, bytes_lo, downloads, first_download_at, last_download_at
                     FROM outbound_grant_files WHERE grant_id = 'migrate' AND file_index = 0",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    },
                )
            })
            .unwrap();
        assert_eq!(
            row,
            (
                "objects/large".to_owned(),
                i64::from(u32::MAX),
                i64::from(u32::MAX),
                7,
                11,
                22
            )
        );
        assert_eq!(store.outbound_grants("acme").unwrap()[0], grant);
    }

    #[test]
    fn protected_outbound_grant_password_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("protected", "acme", 0);
        grant.password_hash = Some("argon2id-hash".to_owned());

        store.insert_outbound_grant(grant.clone()).unwrap();

        assert_eq!(
            store
                .outbound_grant_by_token_hash("hash-protected")
                .unwrap(),
            Some(grant)
        );
    }

    #[test]
    fn outbound_grants_are_tenant_scoped_and_hash_lookup_is_global() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("g1", "acme", 0))
            .unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("g2", "other", 1))
            .unwrap();

        assert_eq!(store.outbound_grants("acme").unwrap().len(), 1);
        assert_eq!(
            store
                .outbound_grant_by_token_hash("hash-g1")
                .unwrap()
                .unwrap()
                .id,
            "g1"
        );
    }

    #[test]
    fn active_library_grants_match_source_with_tenant_and_lifecycle_scope() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut active = test_outbound_grant("active", "acme", 0);
        active.files = vec![OutboundGrantFile {
            source: "project/file.bin".to_owned(),
            name: "file.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: 1,
            receipt_b64: "receipt".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        store.insert_outbound_grant(active).unwrap();

        let mut other = test_outbound_grant("other", "other", 0);
        other.files = vec![OutboundGrantFile {
            source: "other/file.bin".to_owned(),
            name: "file.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: 1,
            receipt_b64: "receipt".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        store.insert_outbound_grant(other).unwrap();

        for (id, revoked_at, expires_at, downloads, max_downloads) in [
            ("expired", None, Some(14), 0, None),
            ("revoked", Some(12), Some(20), 0, None),
            ("spent", None, Some(20), 1, Some(1)),
        ] {
            let mut grant = test_outbound_grant(id, "acme", 0);
            grant.files = vec![OutboundGrantFile {
                source: "ignored/file.bin".to_owned(),
                name: "file.bin".to_owned(),
                suite: "blake3".to_owned(),
                root: "root".to_owned(),
                bytes: 1,
                receipt_b64: "receipt".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            }];
            grant.revoked_at = revoked_at;
            grant.expires_at = expires_at.unwrap();
            grant.downloads = downloads;
            grant.max_downloads = max_downloads;
            store.insert_outbound_grant(grant).unwrap();
        }

        assert!(store
            .has_active_library_grant("acme", "project/file.bin", 15)
            .unwrap());
        assert!(!store
            .has_active_library_grant("other", "project/file.bin", 15)
            .unwrap());
        assert!(!store
            .has_active_library_grant("acme", "ignored/file.bin", 15)
            .unwrap());
    }

    #[test]
    fn outbound_grants_page_is_newest_first_bounded_and_tenant_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for id in ["g1", "g2", "g3"] {
            store
                .insert_outbound_grant(test_outbound_grant(id, "acme", 0))
                .unwrap();
        }
        store
            .insert_outbound_grant(test_outbound_grant("other", "other", 0))
            .unwrap();

        let page = store.outbound_grants_page("acme", 2, 0, 64).unwrap();
        assert_eq!(page.1, 3);
        assert_eq!(
            page.0
                .into_iter()
                .map(|(grant, _)| grant.id)
                .collect::<Vec<_>>(),
            ["g3", "g2"]
        );
        assert_eq!(
            store
                .outbound_grants_page("acme", 2, 2, 64)
                .unwrap()
                .0
                .into_iter()
                .map(|(grant, _)| grant.id)
                .collect::<Vec<_>>(),
            ["g1"]
        );
        assert!(store
            .outbound_grants_page("acme", 2, 3, 64)
            .unwrap()
            .0
            .is_empty());
        assert_eq!(store.outbound_grants_page("other", 2, 0, 64).unwrap().1, 1);
    }

    #[test]
    fn outbound_grants_page_reports_counts_and_bounds_file_previews() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let legacy = test_outbound_grant("legacy", "acme", 0);
        store.insert_outbound_grant(legacy).unwrap();
        let mut small = test_outbound_grant("small", "acme", 0);
        small.files = (0..2)
            .map(|index| OutboundGrantFile {
                source: format!("small-{index}"),
                name: format!("small-{index}.txt"),
                suite: "blake3".to_owned(),
                root: format!("small-root-{index}"),
                bytes: index + 1,
                receipt_b64: "receipt".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .collect();
        store.insert_outbound_grant(small).unwrap();
        let mut large = test_outbound_grant("large", "acme", 0);
        large.files = (0..3)
            .map(|index| OutboundGrantFile {
                source: format!("large-{index}"),
                name: format!("large-{index}.txt"),
                suite: "blake3".to_owned(),
                root: format!("large-root-{index}"),
                bytes: index + 1,
                receipt_b64: "receipt".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .collect();
        store.insert_outbound_grant(large).unwrap();

        let counts = store
            .with(|connection| {
                let mut statement = connection.prepare(
                    "SELECT id, file_count FROM outbound_grants WHERE tenant = 'acme' ORDER BY id",
                )?;
                let rows = statement.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?;
                rows.collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        assert_eq!(
            counts,
            [
                ("large".to_owned(), 3),
                ("legacy".to_owned(), 1),
                ("small".to_owned(), 2),
            ]
        );

        let page = store.outbound_grants_page("acme", 10, 0, 2).unwrap().0;
        let find = |id: &str| page.iter().find(|(grant, _)| grant.id == id).unwrap();
        let (legacy, legacy_count) = find("legacy");
        assert_eq!(*legacy_count, 1);
        assert!(legacy.files.is_empty());
        let (small, small_count) = find("small");
        assert_eq!(*small_count, 2);
        assert_eq!(small.files.len(), 2);
        let (large, large_count) = find("large");
        assert_eq!(*large_count, 3);
        assert!(large.files.is_empty());
    }

    #[test]
    fn automation_tokens_round_trip_and_list_by_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let token = test_automation_token("t1", "acme");
        store.insert_automation_token(token.clone()).unwrap();
        store
            .insert_automation_token(test_automation_token("t2", "other"))
            .unwrap();

        assert_eq!(store.automation_tokens("acme").unwrap(), vec![token]);
        assert!(store.automation_tokens("missing").unwrap().is_empty());
    }

    #[test]
    fn remove_tenant_cleans_outbound_credentials_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut grant = test_outbound_grant("grant", "acme", 0);
        grant.files = vec![OutboundGrantFile {
            source: "objects/file".to_owned(),
            name: "file".to_owned(),
            suite: "blake3".to_owned(),
            root: "root".to_owned(),
            bytes: 1,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        store.insert_outbound_grant(grant).unwrap();
        store
            .insert_automation_token(test_automation_token("token", "acme"))
            .unwrap();

        assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Deleted);
        assert!(store.outbound_grants("acme").unwrap().is_empty());
        assert!(store
            .outbound_grant_by_token_hash("hash-grant")
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .with(|connection| connection.query_row(
                    "SELECT COUNT(*) FROM outbound_grant_files",
                    [],
                    |row| row.get::<_, i64>(0),
                ))
                .unwrap(),
            0
        );
        assert!(store.automation_tokens("acme").unwrap().is_empty());
        assert!(store
            .authenticate_automation_token("hash-token", 15)
            .unwrap()
            .is_none());
    }

    #[test]
    fn automation_token_authentication_updates_last_used_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_automation_token(test_automation_token("t1", "acme"))
            .unwrap();

        let authenticated = store
            .authenticate_automation_token("hash-t1", 15)
            .unwrap()
            .unwrap();
        assert_eq!(authenticated.last_used_at, Some(15));
        assert_eq!(store.automation_tokens("acme").unwrap()[0], authenticated);
        assert!(store
            .authenticate_automation_token("hash-t1", 20)
            .unwrap()
            .is_none());
    }

    #[test]
    fn automation_token_revocation_is_tenant_scoped_and_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_automation_token(test_automation_token("t1", "acme"))
            .unwrap();

        assert!(!store.revoke_automation_token("other", "t1", 12).unwrap());
        assert!(store
            .authenticate_automation_token("hash-t1", 15)
            .unwrap()
            .is_some());
        assert!(store.revoke_automation_token("acme", "t1", 16).unwrap());
        assert!(!store.revoke_automation_token("acme", "t1", 17).unwrap());
        assert_eq!(
            store.automation_tokens("acme").unwrap()[0].revoked_at,
            Some(16)
        );
        assert!(store
            .authenticate_automation_token("hash-t1", 18)
            .unwrap()
            .is_none());
    }

    #[test]
    fn outbound_grant_expiry_and_revoke_control_active_state() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("g1", "acme", 0))
            .unwrap();

        assert!(store
            .has_active_outbound_grant("acme", "link", "upload", 0, 19)
            .unwrap());
        assert!(!store
            .has_active_outbound_grant("acme", "link", "upload", 0, 20)
            .unwrap());
        assert!(store.revoke_outbound_grant("acme", "g1", 12).unwrap());
        assert!(!store.revoke_outbound_grant("acme", "g1", 13).unwrap());
        assert!(!store
            .has_active_outbound_grant("acme", "link", "upload", 0, 11)
            .unwrap());
    }

    #[test]
    fn outbound_download_count_and_active_link_query_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("g1", "acme", 0))
            .unwrap();
        let mut other = test_outbound_grant("g2", "acme", 1);
        other.link_id = "other-link".to_owned();
        other.expires_at = 100;
        store.insert_outbound_grant(other).unwrap();

        assert_eq!(
            store.record_outbound_download("g1", &[0], 100).unwrap(),
            OutboundDownloadResult {
                first_download: true,
                completed_delivery: true,
            }
        );
        assert_eq!(
            store.record_outbound_download("g1", &[0], 110).unwrap(),
            OutboundDownloadResult {
                first_download: false,
                completed_delivery: false,
            }
        );
        let grant = store
            .outbound_grant_by_token_hash("hash-g1")
            .unwrap()
            .unwrap();
        assert_eq!(grant.downloads, 2);
        assert_eq!(grant.first_download_at, Some(100));
        assert_eq!(grant.last_download_at, Some(110));
        assert!(store
            .record_outbound_download("missing", &[0], 100)
            .is_err());
        assert!(store
            .link_has_active_outbound_grants("acme", "link", 19)
            .unwrap());
        assert!(!store
            .link_has_active_outbound_grants("other", "link", 19)
            .unwrap());
        assert!(store
            .link_has_active_outbound_grants("acme", "other-link", 99)
            .unwrap());
        assert!(!store
            .link_has_active_outbound_grants("acme", "other-link", 100)
            .unwrap());
    }

    #[test]
    fn outbound_download_limit_refuses_after_one_download() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("limited", "acme", 0);
        grant.max_downloads = Some(1);
        store.insert_outbound_grant(grant).unwrap();

        assert!(store
            .has_active_outbound_grant("acme", "link", "upload", 0, 19)
            .unwrap());
        store.record_outbound_download("limited", &[0], 15).unwrap();
        let downloaded = store
            .outbound_grant_by_token_hash("hash-limited")
            .unwrap()
            .unwrap();
        let error = store
            .record_outbound_download("limited", &[0], 16)
            .unwrap_err();
        assert_eq!(error, OUTBOUND_DOWNLOAD_LIMIT_REACHED);
        assert_eq!(
            store
                .outbound_grant_by_token_hash("hash-limited")
                .unwrap()
                .unwrap(),
            downloaded
        );
        assert!(!store
            .has_active_outbound_grant("acme", "link", "upload", 0, 19)
            .unwrap());
        assert!(!store
            .link_has_active_outbound_grants("acme", "link", 19)
            .unwrap());
    }

    #[test]
    fn outbound_grant_token_rotation_is_tenant_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("rotate", "acme", 0))
            .unwrap();

        assert!(!store
            .rotate_outbound_grant_token("other", "rotate", "new-hash")
            .unwrap());
        assert!(store
            .rotate_outbound_grant_token("acme", "rotate", "new-hash")
            .unwrap());
        assert!(store
            .outbound_grant_by_token_hash("hash-rotate")
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .outbound_grant_by_token_hash("new-hash")
                .unwrap()
                .unwrap()
                .id,
            "rotate"
        );
        store.revoke_outbound_grant("acme", "rotate", 12).unwrap();
        assert!(!store
            .rotate_outbound_grant_token("acme", "rotate", "other-hash")
            .unwrap());
    }

    #[test]
    fn outbound_grant_extension_handles_live_expired_and_scoped_rows() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut expired = test_outbound_grant("expired", "acme", 0);
        expired.expires_at = 10;
        store.insert_outbound_grant(expired).unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("live", "acme", 1))
            .unwrap();
        store
            .insert_outbound_grant(test_outbound_grant("revoked", "acme", 2))
            .unwrap();
        store.revoke_outbound_grant("acme", "revoked", 12).unwrap();

        assert_eq!(
            store.extend_outbound_grant("acme", "live", 5, 15).unwrap(),
            Some(25)
        );
        assert_eq!(
            store
                .extend_outbound_grant("acme", "expired", 5, 20)
                .unwrap(),
            Some(25)
        );
        assert_eq!(
            store.extend_outbound_grant("other", "live", 5, 20).unwrap(),
            None
        );
        assert_eq!(
            store
                .extend_outbound_grant("acme", "revoked", 5, 20)
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .outbound_grant_by_token_hash("hash-expired")
                .unwrap()
                .unwrap()
                .expires_at,
            25
        );
    }

    #[test]
    fn outbound_download_tracking_reports_first_and_completed_transitions() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("multi", "acme", 0);
        grant.files = vec![
            OutboundGrantFile {
                source: "objects/a".to_owned(),
                name: "a.txt".to_owned(),
                suite: "blake3".to_owned(),
                root: "aa".to_owned(),
                bytes: 3,
                receipt_b64: "receipt-a".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            },
            OutboundGrantFile {
                source: "objects/b".to_owned(),
                name: "b.txt".to_owned(),
                suite: "blake3".to_owned(),
                root: "bb".to_owned(),
                bytes: 4,
                receipt_b64: "receipt-b".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            },
        ];
        store.insert_outbound_grant(grant).unwrap();

        assert_eq!(
            store.record_outbound_download("multi", &[1], 100).unwrap(),
            OutboundDownloadResult {
                first_download: true,
                completed_delivery: false,
            }
        );
        assert_eq!(
            store.record_outbound_download("multi", &[0], 200).unwrap(),
            OutboundDownloadResult {
                first_download: false,
                completed_delivery: true,
            }
        );
        assert_eq!(
            store
                .record_outbound_download("multi", &[0, 1, 1], 300)
                .unwrap(),
            OutboundDownloadResult {
                first_download: false,
                completed_delivery: false,
            }
        );
        let grant = store
            .outbound_grant_by_token_hash("hash-multi")
            .unwrap()
            .unwrap();
        assert_eq!(grant.downloads, 2);
        assert_eq!(grant.first_download_at, Some(100));
        assert_eq!(grant.last_download_at, Some(300));
        assert_eq!(grant.files[0].downloads, 2);
        assert_eq!(grant.files[0].first_download_at, Some(200));
        assert_eq!(grant.files[0].last_download_at, Some(300));
        assert_eq!(grant.files[1].downloads, 2);
        assert_eq!(grant.files[1].first_download_at, Some(100));
        assert_eq!(grant.files[1].last_download_at, Some(300));
    }

    #[test]
    fn outbound_multi_file_limit_applies_per_file_and_counts_rounds() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("multi-limit", "acme", 0);
        grant.max_downloads = Some(1);
        grant.files = (0..2)
            .map(|index| OutboundGrantFile {
                source: format!("objects/{index}"),
                name: format!("{index}.txt"),
                suite: "blake3".to_owned(),
                root: format!("root-{index}"),
                bytes: 1,
                receipt_b64: "receipt".to_owned(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            })
            .collect();
        store.insert_outbound_grant(grant).unwrap();

        store
            .record_outbound_download("multi-limit", &[0], 100)
            .unwrap();
        let grant = store
            .outbound_grant_by_token_hash("hash-multi-limit")
            .unwrap()
            .unwrap();
        assert_eq!(grant.downloads, 0);
        assert_eq!(grant.files[0].downloads, 1);
        assert_eq!(grant.files[1].downloads, 0);

        let completed = store
            .record_outbound_download("multi-limit", &[1], 200)
            .unwrap();
        assert!(completed.completed_delivery);
        let grant = store
            .outbound_grant_by_token_hash("hash-multi-limit")
            .unwrap()
            .unwrap();
        assert_eq!(grant.downloads, 1);
        assert_eq!(grant.files[0].downloads, 1);
        assert_eq!(grant.files[1].downloads, 1);

        assert_eq!(
            store
                .record_outbound_download("multi-limit", &[0], 300)
                .unwrap_err(),
            OUTBOUND_DOWNLOAD_LIMIT_REACHED
        );
        let grant = store
            .outbound_grant_by_token_hash("hash-multi-limit")
            .unwrap()
            .unwrap();
        assert_eq!(grant.files[1].downloads, 1);
    }

    #[test]
    fn outbound_download_tracking_rejects_invalid_indexes_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut grant = test_outbound_grant("atomic", "acme", 0);
        grant.files = vec![OutboundGrantFile {
            source: "objects/a".to_owned(),
            name: "a.txt".to_owned(),
            suite: "blake3".to_owned(),
            root: "aa".to_owned(),
            bytes: 3,
            receipt_b64: "receipt-a".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        store.insert_outbound_grant(grant.clone()).unwrap();

        assert!(store
            .record_outbound_download("atomic", &[0, 1], 100)
            .is_err());
        assert_eq!(
            store
                .outbound_grant_by_token_hash("hash-atomic")
                .unwrap()
                .unwrap(),
            grant
        );
    }

    #[test]
    fn legal_hold_rolls_back_when_audit_fails() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("held")).unwrap();
        store
            .with(|connection| connection.execute_batch("DROP TABLE audit_log"))
            .unwrap();

        assert!(store
            .set_link_legal_hold("", "held", true, "admin")
            .is_err());
        assert!(!store.link("", "held").unwrap().unwrap().legal_hold);
    }

    #[test]
    fn links_round_trip_with_uploads_and_events() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = test_link("link-1");
        link.uploads.push(UploadRecord {
            id: "up-1".to_owned(),
            started_at: 1,
            completed_at: 2,
            replayed_chunks: 3,
            rejected_chunks: 4,
            transport: None,
            package_root: "aa".to_owned(),
            total_bytes: 5,
            files: vec![FileRecord {
                path: "a.txt".to_owned(),
                stored_as: "a.txt".to_owned(),
                bytes: 5,
                suite: "blake3".to_owned(),
                root: "bb".to_owned(),
                receipt: true,
                deleted: false,
            }],
        });
        link.events.push(SessionEvent {
            at: 3,
            started_at: 1,
            outcome: "cancelled".to_owned(),
            detail: "by sender".to_owned(),
            received_bytes: 6,
            expected_bytes: 7,
            replayed_chunks: 8,
            rejected_chunks: 9,
        });
        store.insert_link(link).unwrap();

        let loaded = store.link("", "link-1").unwrap().unwrap();
        assert_eq!(loaded.uploads.len(), 1);
        assert!(loaded.uploads[0].files[0].receipt);
        assert_eq!(loaded.events[0].outcome, "cancelled");
        assert_eq!(store.links("").unwrap().len(), 1);
        let upload_link = store.upload_link("link-1").unwrap().unwrap();
        assert!(upload_link.uploads.is_empty());
        assert!(upload_link.events.is_empty());
        assert_eq!(store.uploads_by_id("link-1").unwrap().unwrap().len(), 1);
        assert!(store.upload_link("missing").unwrap().is_none());
        assert!(store.uploads_by_id("missing").unwrap().is_none());
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE links SET uploads_json = 'broken' WHERE id = 'link-1'",
                    [],
                )
            })
            .unwrap();
        assert!(store.uploads_by_id("link-1").is_err());
        assert!(store.link("", "link-1").is_err());
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE links SET uploads_json = '[]', events_json = 'broken' WHERE id = 'link-1'",
                    [],
                )
            })
            .unwrap();
        assert!(store.uploads_by_id("link-1").is_err());
        assert!(store.link("", "link-1").is_err());
    }

    #[test]
    fn tenant_storage_migration_resumes_and_marks_completion() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        let receive = directory.path().join("receive");
        std::fs::create_dir_all(&receive).unwrap();
        let store = Store::open(&data).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        store.insert_tenant(test_tenant("globex")).unwrap();

        std::fs::create_dir_all(receive.join("acme")).unwrap();
        std::fs::write(receive.join("acme/invoice.pdf"), b"acme").unwrap();
        let target_root = receive.join(crate::paths::TENANT_STORAGE_DIR);
        std::fs::create_dir_all(target_root.join("globex")).unwrap();
        std::fs::write(target_root.join("globex/done.pdf"), b"globex").unwrap();

        store.migrate_tenant_storage(&receive).unwrap();
        assert!(!receive.join("acme").exists());
        assert_eq!(
            std::fs::read(target_root.join("acme/invoice.pdf")).unwrap(),
            b"acme"
        );
        assert!(target_root.join("globex/done.pdf").exists());

        // Once marked, a root path named after a tenant belongs to the
        // default tenant and must never be reinterpreted on restart.
        std::fs::create_dir_all(receive.join("acme")).unwrap();
        std::fs::write(receive.join("acme/root.txt"), b"root").unwrap();
        store.migrate_tenant_storage(&receive).unwrap();
        assert!(receive.join("acme/root.txt").exists());
    }

    #[test]
    fn tenant_storage_migration_refuses_ambiguous_subtrees() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        let receive = directory.path().join("receive");
        let store = Store::open(&data).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        std::fs::create_dir_all(receive.join("acme")).unwrap();
        std::fs::create_dir_all(receive.join(crate::paths::TENANT_STORAGE_DIR).join("acme"))
            .unwrap();

        let error = store.migrate_tenant_storage(&receive).unwrap_err();
        assert!(error.contains("found both"), "{error}");

        std::fs::remove_dir_all(receive.join(crate::paths::TENANT_STORAGE_DIR)).unwrap();
        std::fs::remove_dir_all(receive.join("acme")).unwrap();
        std::fs::write(receive.join("acme"), b"default tenant").unwrap();
        let error = store.migrate_tenant_storage(&receive).unwrap_err();
        assert!(error.contains("expected a directory"), "{error}");
    }

    #[test]
    fn tenant_storage_migration_refuses_default_owned_prefixes() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        let receive = directory.path().join("receive");
        let store = Store::open(&data).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        std::fs::create_dir_all(receive.join("acme")).unwrap();
        std::fs::write(receive.join("acme/invoice.pdf"), b"default").unwrap();
        let mut link = test_link("root");
        link.uploads.push(UploadRecord {
            id: "upload".to_owned(),
            started_at: 0,
            completed_at: 1,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "root".to_owned(),
            total_bytes: 7,
            files: vec![FileRecord {
                path: "acme/invoice.pdf".to_owned(),
                stored_as: "Acme/invoice.pdf".to_owned(),
                bytes: 7,
                suite: "blake3".to_owned(),
                root: "object".to_owned(),
                receipt: false,
                deleted: false,
            }],
        });
        store.insert_link(link).unwrap();

        let error = store.migrate_tenant_storage(&receive).unwrap_err();
        assert!(error.contains("cannot determine ownership"), "{error}");
        assert!(receive.join("acme/invoice.pdf").exists());
        assert!(!receive.join(crate::paths::TENANT_STORAGE_DIR).exists());

        std::fs::remove_dir_all(receive.join("acme")).unwrap();
        std::fs::create_dir_all(receive.join(crate::paths::TENANT_STORAGE_DIR).join("acme"))
            .unwrap();
        store
            .update_link("", "root", |link| {
                link.uploads[0].files[0].stored_as =
                    ".VOT-TENANTS.STAGE/acme/invoice.pdf".to_owned();
            })
            .unwrap();

        let error = store.migrate_tenant_storage(&receive).unwrap_err();
        assert!(error.contains("cannot determine ownership"), "{error}");
        assert!(receive
            .join(crate::paths::TENANT_STORAGE_DIR)
            .join("acme")
            .exists());
    }

    #[test]
    fn tenant_storage_migration_refuses_nonportable_legacy_keys() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        let receive = directory.path().join("receive");
        let store = Store::open(&data).unwrap();
        store.insert_tenant(test_tenant("Acme")).unwrap();
        assert_eq!(
            store.insert_tenant(test_tenant("acme")).unwrap_err(),
            InsertTenantError::AlreadyExists
        );

        let error = store.migrate_tenant_storage(&receive).unwrap_err();
        assert!(error.contains("is not portable"), "{error}");

        store
            .with(|connection| {
                connection.execute("DELETE FROM tenants", [])?;
                connection.execute(
                    "INSERT INTO tenants (key, label) VALUES ('가', 'legacy unicode')",
                    [],
                )
            })
            .unwrap();

        let error = store.migrate_tenant_storage(&receive).unwrap_err();
        assert!(error.contains("is not portable"), "{error}");
    }

    #[test]
    fn tenant_storage_migration_case_folds_default_destinations() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        let receive = directory.path().join("receive");
        let store = Store::open(&data).unwrap();
        store.insert_tenant(test_tenant("s")).unwrap();
        std::fs::create_dir_all(receive.join("s")).unwrap();
        let mut link = test_link("dest");
        link.dest = "S".to_owned();
        store.insert_link(link).unwrap();

        let error = store.migrate_tenant_storage(&receive).unwrap_err();
        assert!(error.contains("cannot determine ownership"), "{error}");

        store
            .update_link("", "dest", |link| link.dest = "ſ".to_owned())
            .unwrap();
        let error = store.migrate_tenant_storage(&receive).unwrap_err();
        assert!(error.contains("cannot determine ownership"), "{error}");

        store
            .update_link("", "dest", |link| link.dest = "TENANT~1".to_owned())
            .unwrap();
        let error = store.migrate_tenant_storage(&receive).unwrap_err();
        assert!(error.contains("cannot determine ownership"), "{error}");
    }

    #[test]
    fn update_and_remove_report_presence() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("link-1")).unwrap();
        let found = store
            .update_link("", "link-1", |link| link.active = false)
            .unwrap();
        assert!(found);
        assert!(!store.link("", "link-1").unwrap().unwrap().active);
        assert!(!store.update_link("", "missing", |_| {}).unwrap());
        assert!(store.remove_link("", "link-1").unwrap());
        assert!(!store.remove_link("", "link-1").unwrap());
        assert!(store.link("", "link-1").unwrap().is_none());
    }

    #[test]
    fn links_preserve_insertion_order() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("b")).unwrap();
        store.insert_link(test_link("a")).unwrap();
        let ids: Vec<String> = store
            .links("")
            .unwrap()
            .into_iter()
            .map(|link| link.id)
            .collect();
        assert_eq!(ids, ["b", "a"]);
    }

    #[test]
    fn admin_hash_persists_across_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(store.admin_password_hash().unwrap().is_none());
        store
            .set_admin_password_hash("argon2-hash".to_owned())
            .unwrap();
        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        assert_eq!(
            reopened.admin_password_hash().unwrap().as_deref(),
            Some("argon2-hash")
        );
    }

    #[test]
    fn optional_columns_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = test_link("link-1");
        link.password_hash = Some("argon2".to_owned());
        link.expires_at = Some(12345);
        link.max_bytes = Some(999);
        store.insert_link(link).unwrap();
        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        let loaded = reopened.link("", "link-1").unwrap().unwrap();
        assert_eq!(loaded.password_hash.as_deref(), Some("argon2"));
        assert_eq!(loaded.expires_at, Some(12345));
        assert_eq!(loaded.max_bytes, Some(999));
        // And the None side survives too.
        let mut bare = test_link("link-2");
        bare.expires_at = None;
        reopened.insert_link(bare).unwrap();
        assert_eq!(
            reopened.link("", "link-2").unwrap().unwrap().expires_at,
            None
        );
    }

    #[test]
    fn legacy_import_read_errors_refuse_startup() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("state.json")).unwrap();
        assert!(Store::open(directory.path()).is_err());
    }

    #[test]
    fn interrupted_import_retries_cleanly() {
        let directory = tempfile::tempdir().unwrap();
        // Simulate a crash after the first link was committed but before the
        // rename: the database already holds old-link-a while state.json
        // still lists both.
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_link(test_link_with_label("old-link-a", "old"))
            .unwrap();
        drop(store);
        std::fs::write(
            directory.path().join("state.json"),
            r#"{"links":[
                {"id":"old-link-a","label":"old","dest":"","created_at":0,"active":true},
                {"id":"old-link-b","label":"old","dest":"","created_at":0,"active":true}]}"#,
        )
        .unwrap();
        let reopened = Store::open(directory.path()).unwrap();
        assert!(reopened.link("", "old-link-a").unwrap().is_some());
        assert!(reopened.link("", "old-link-b").unwrap().is_some());
        assert!(!directory.path().join("state.json").exists());
    }

    fn test_link_with_label(id: &str, label: &str) -> Link {
        let mut link = test_link(id);
        link.label = label.to_owned();
        link
    }

    #[test]
    fn audit_rows_round_trip_export_and_prune() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit(
            "",
            "",
            "link_created",
            "link-1",
            &serde_json::json!({ "label": "x" }),
        );
        store.audit("", "", "admin_login", "10.0.0.1", &serde_json::json!({}));

        let rows = store.audit_export("", 0, 0, 100).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].event, "link_created");
        assert_eq!(rows[0].tenant, "");
        assert_eq!(rows[0].detail["label"], "x");
        // `since` is strictly greater-than (rows share second granularity).
        let after_all = store
            .audit_export("", rows.last().unwrap().at + 1, 0, 100)
            .unwrap();
        assert!(after_all.is_empty());
        assert_eq!(store.audit_export("", 0, 0, 1).unwrap().len(), 1);

        // Pruning removes only rows strictly older than the cutoff.
        let now = now_unix();
        let pruned = store.audit_prune(now + 1).unwrap();
        assert_eq!(pruned, 2);
        assert!(store.audit_export("", 0, 0, 100).unwrap().is_empty());

        store.audit("", "", "test", "corrupt", &serde_json::json!({}));
        store
            .with(|connection| connection.execute("UPDATE audit_log SET detail = 'broken'", []))
            .unwrap();
        assert!(store.audit_export("", 0, 0, 100).is_err());
    }

    #[test]
    fn legacy_state_json_is_imported_and_renamed() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("state.json"),
            r#"{"links":[{"id":"old-link","label":"old","dest":"","created_at":0,"active":true,
                "uploads":[{"id":"up","completed_at":1,"package_root":"root","total_bytes":3,
                "files":[{"path":"a","stored_as":"a","bytes":3,"suite":"blake3","root":"object","receipt":false}]}]}],
                "admin_password_hash":"old-hash"}"#,
        )
        .unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(store.link("", "old-link").unwrap().is_some());
        assert_eq!(
            store.admin_password_hash().unwrap().as_deref(),
            Some("old-hash")
        );
        assert_eq!(store.tenant_received_bytes("").unwrap(), 3);
        assert!(!directory.path().join("state.json").exists());
        assert!(directory.path().join("state.json.imported").exists());
        // Reopening must not re-import stale state over newer rows.
        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        assert!(reopened.link("", "old-link").unwrap().is_some());
    }
}

#[cfg(test)]
mod tenant_tests {
    use super::tests::{link_in, test_tenant};
    use super::*;

    #[test]
    fn links_are_invisible_across_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_tenant(Tenant {
                key: "acme".to_owned(),
                label: "Acme".to_owned(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        store.insert_link(link_in("acme", "secret-link")).unwrap();
        store.insert_link(link_in("", "default-link")).unwrap();

        assert!(store.link("acme", "secret-link").unwrap().is_some());
        // Another tenant (and the default) cannot see or touch it.
        assert!(store.link("", "secret-link").unwrap().is_none());
        assert!(!store.update_link("", "secret-link", |_| {}).unwrap());
        assert!(!store.remove_link("", "secret-link").unwrap());
        assert_eq!(store.links("acme").unwrap().len(), 1);
        assert_eq!(store.links("").unwrap().len(), 1);
    }

    #[test]
    fn tenant_crud_refuses_while_links_remain() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_tenant(Tenant {
                key: "acme".to_owned(),
                label: String::new(),
                admin_group: Some("acme-admins".to_owned()),
                max_total_bytes: Some(1024),
                max_links: Some(2),
                max_sessions: Some(1),
                created_at: 0,
            })
            .unwrap();
        assert_eq!(store.tenants().unwrap().len(), 1);
        assert_eq!(store.tenant("acme").unwrap().unwrap().max_links, Some(2));
        assert!(store.tenant("missing").unwrap().is_none());

        store.insert_link(link_in("acme", "blocked")).unwrap();
        // The handler refuses deletion while links remain; the store exposes
        // the count and the raw delete.
        assert_eq!(store.tenant_link_count("acme").unwrap(), 1);

        store.remove_link("acme", "blocked").unwrap();
        assert_eq!(store.tenant_link_count("acme").unwrap(), 0);
        assert_eq!(store.remove_tenant("acme").unwrap(), TenantRemoval::Deleted);
        assert!(store.tenant("acme").unwrap().is_none());
        let err = store.insert_link(link_in("acme", "orphan")).unwrap_err();
        assert_eq!(err, InsertLinkError::NamedTenantGone);
        assert!(store.link("acme", "orphan").unwrap().is_none());
    }

    #[test]
    fn received_bytes_count_live_files_only() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = link_in("acme", "link-1");
        let mut file = FileRecord {
            path: "a.bin".to_owned(),
            stored_as: "a.bin".to_owned(),
            bytes: 500,
            suite: "blake3".to_owned(),
            root: "aa".to_owned(),
            receipt: false,
            deleted: false,
        };
        link.uploads.push(UploadRecord {
            id: "up".to_owned(),
            started_at: 0,
            completed_at: 0,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "cc".to_owned(),
            total_bytes: 500,
            files: vec![file.clone()],
        });
        store.insert_tenant(test_tenant("acme")).unwrap();
        store.insert_link(link.clone()).unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 500);
        assert_eq!(store.tenant_received_bytes("").unwrap(), 0);
        let usage = store.tenant_usage().unwrap();
        assert_eq!(usage.len(), 2);
        assert_eq!(usage[0].tenant, "");
        assert_eq!(usage[0].links, 0);
        assert_eq!(usage[1].tenant, "acme");
        assert_eq!(usage[1].links, 1);
        assert_eq!(usage[1].received_bytes, 500);

        store
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TRIGGER fail_file_update BEFORE UPDATE ON files
                     BEGIN SELECT RAISE(FAIL, 'test file failure'); END;",
                )
            })
            .unwrap();
        assert!(store
            .tombstone_files("acme", "link-1", |file| file.path == "a.bin")
            .is_err());
        assert!(!store.link("acme", "link-1").unwrap().unwrap().uploads[0].files[0].deleted);
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 500);
        store
            .with(|connection| connection.execute_batch("DROP TRIGGER fail_file_update"))
            .unwrap();

        file.deleted = true;
        link.uploads[0].files[0] = file;
        store
            .tombstone_files("acme", "link-1", |file| file.path == "a.bin")
            .unwrap();
        assert_eq!(store.tenant_received_bytes("acme").unwrap(), 0);
        assert_eq!(store.tenant_usage().unwrap()[1].received_bytes, 0);
        assert!(store.remove_link("acme", "link-1").unwrap());
        let files = store
            .with(|connection| {
                connection.query_row("SELECT COUNT(*) FROM files", [], |row| row.get::<_, i64>(0))
            })
            .unwrap();
        assert_eq!(files, 0);
    }

    #[test]
    fn received_bytes_preserve_u64_and_saturate_aggregate() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut link = link_in("acme", "large");
        link.uploads.push(UploadRecord {
            id: "up".to_owned(),
            started_at: 0,
            completed_at: 0,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "root".to_owned(),
            total_bytes: u64::MAX,
            files: vec![
                FileRecord {
                    path: "large".to_owned(),
                    stored_as: "large".to_owned(),
                    bytes: u64::MAX,
                    suite: "blake3".to_owned(),
                    root: "aa".to_owned(),
                    receipt: false,
                    deleted: false,
                },
                FileRecord {
                    path: "one".to_owned(),
                    stored_as: "one".to_owned(),
                    bytes: 1,
                    suite: "blake3".to_owned(),
                    root: "bb".to_owned(),
                    receipt: false,
                    deleted: false,
                },
            ],
        });
        store.insert_link(link).unwrap();

        assert_eq!(store.tenant_received_bytes("acme").unwrap(), u64::MAX);
        assert_eq!(store.tenant_usage().unwrap()[1].received_bytes, u64::MAX);
        store
            .append_upload(
                "acme",
                "large",
                UploadRecord {
                    id: "second".to_owned(),
                    started_at: u64::MAX,
                    completed_at: u64::MAX,
                    replayed_chunks: u64::MAX,
                    rejected_chunks: u64::MAX,
                    transport: None,
                    package_root: "exact".to_owned(),
                    total_bytes: u64::MAX,
                    files: Vec::new(),
                },
            )
            .unwrap();
        let uploads = store.link("acme", "large").unwrap().unwrap().uploads;
        assert_eq!(uploads.len(), 2);
        assert_eq!(uploads[0].total_bytes, u64::MAX);
        assert_eq!(uploads[1].started_at, u64::MAX);
        assert_eq!(uploads[1].total_bytes, u64::MAX);
        let limbs = store
            .with(|connection| {
                connection.query_row(
                    "SELECT bytes_hi, bytes_lo FROM files WHERE file_index = 0",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
            })
            .unwrap();
        assert_eq!(limbs, (u32::MAX as i64, u32::MAX as i64));
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE links SET uploads_json = '[{}]' WHERE id = 'large'",
                    [],
                )
            })
            .unwrap();
        assert!(store
            .append_upload("acme", "large", uploads[1].clone())
            .is_err());
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE links SET uploads_json = '[]', events_json = 'broken'
                     WHERE id = 'large'",
                    [],
                )
            })
            .unwrap();
        assert!(store
            .append_upload("acme", "large", uploads[1].clone())
            .is_err());
    }

    #[test]
    fn tenant_quotas_preserve_u64_across_create_and_update() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut tenant = test_tenant("acme");
        tenant.max_total_bytes = Some(u64::MAX);
        tenant.max_links = Some(u64::MAX);
        tenant.max_sessions = Some(u64::MAX);
        store.insert_tenant(tenant).unwrap();
        assert_eq!(
            store.tenant("acme").unwrap().unwrap().max_total_bytes,
            Some(u64::MAX)
        );

        let mut tenant = store.tenant("acme").unwrap().unwrap();
        tenant.max_total_bytes = Some(u64::MAX - 1);
        tenant.max_links = Some(u64::MAX - 1);
        tenant.max_sessions = Some(u64::MAX - 1);
        assert!(store.update_tenant(&tenant).unwrap());
        drop(store);

        let reopened = Store::open(directory.path()).unwrap();
        let tenant = reopened.tenant("acme").unwrap().unwrap();
        assert_eq!(tenant.max_total_bytes, Some(u64::MAX - 1));
        assert_eq!(tenant.max_links, Some(u64::MAX - 1));
        assert_eq!(tenant.max_sessions, Some(u64::MAX - 1));
    }

    #[test]
    fn projection_writes_only_changed_files() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut link = link_in("acme", "link");
        let file = FileRecord {
            path: "a".to_owned(),
            stored_as: "a".to_owned(),
            bytes: 1,
            suite: "blake3".to_owned(),
            root: "aa".to_owned(),
            receipt: false,
            deleted: false,
        };
        link.uploads.push(UploadRecord {
            id: "up".to_owned(),
            started_at: 0,
            completed_at: 0,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "root".to_owned(),
            total_bytes: 50,
            files: vec![file.clone(); 50],
        });
        store.insert_link(link).unwrap();
        store
            .with(|connection| {
                connection.execute_batch(
                    "CREATE TABLE projection_writes (count INTEGER NOT NULL);
                     INSERT INTO projection_writes VALUES (0);
                     CREATE TRIGGER count_file_insert AFTER INSERT ON files BEGIN
                       UPDATE projection_writes SET count = count + 1; END;
                     CREATE TRIGGER count_file_update AFTER UPDATE ON files BEGIN
                       UPDATE projection_writes SET count = count + 1; END;
                     CREATE TRIGGER count_file_delete AFTER DELETE ON files BEGIN
                       UPDATE projection_writes SET count = count + 1; END;",
                )
            })
            .unwrap();

        store
            .update_link("acme", "link", |link| link.active = false)
            .unwrap();
        store
            .append_upload(
                "acme",
                "link",
                UploadRecord {
                    id: "new".to_owned(),
                    started_at: 0,
                    completed_at: 0,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: None,
                    package_root: "new-root".to_owned(),
                    total_bytes: 1,
                    files: vec![FileRecord {
                        path: "b".to_owned(),
                        stored_as: "b".to_owned(),
                        ..file
                    }],
                },
            )
            .unwrap();
        let writes = || {
            store
                .with(|connection| {
                    connection.query_row("SELECT count FROM projection_writes", [], |row| {
                        row.get::<_, i64>(0)
                    })
                })
                .unwrap()
        };
        assert_eq!(writes(), 1);
        store
            .tombstone_files("acme", "link", |file| file.path == "b")
            .unwrap();
        assert_eq!(writes(), 2);
    }
}

#[cfg(test)]
mod ops_tests {
    use super::tests::{test_link, test_tenant};
    use super::*;

    #[test]
    fn backup_creates_a_queryable_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("link-1")).unwrap();

        let snapshot = directory.path().join("snapshot.db");
        store.backup_into(&snapshot).unwrap();
        assert!(snapshot.exists());

        // The snapshot is a real database with the same rows: drop it into
        // a fresh data dir and open it as one.
        let restore = tempfile::tempdir().unwrap();
        std::fs::copy(&snapshot, restore.path().join("votport.db")).unwrap();
        let reopened = Store::open(restore.path()).unwrap();
        assert!(reopened.link("", "link-1").unwrap().is_some());

        // A fresh VACUUM INTO needs the destination gone; that is the
        // caller's contract.
        std::fs::remove_file(&snapshot).unwrap();
        store.backup_into(&snapshot).unwrap();
        assert!(snapshot.exists());
    }

    #[test]
    fn all_links_spans_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("default-link")).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        let mut scoped = test_link("scoped-link");
        scoped.tenant = "acme".to_owned();
        store.insert_link(scoped).unwrap();
        assert_eq!(store.all_links().unwrap().len(), 2);
    }
}

#[cfg(test)]
mod phase4_review_tests {
    use super::tests::{link_in, test_outbound_grant, test_tenant};
    use super::*;

    #[test]
    fn v1_database_without_tenant_column_migrates() {
        let directory = tempfile::tempdir().unwrap();
        // Simulate a v1 database: links table without the tenant column.
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                     CREATE TABLE links (
                        id TEXT PRIMARY KEY,
                        label TEXT NOT NULL DEFAULT '',
                        dest TEXT NOT NULL DEFAULT '',
                        password_hash TEXT,
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER,
                        max_bytes INTEGER,
                        active INTEGER NOT NULL DEFAULT 1,
                        uploads_json TEXT NOT NULL DEFAULT '[]',
                        events_json TEXT NOT NULL DEFAULT '[]'
                     );
                     INSERT INTO links (id, label, created_at, active)
                     VALUES ('v1-link', 'old', 0, 1);",
                )
                .unwrap();
        }
        let store = Store::open(directory.path()).unwrap();
        assert!(store.link("", "v1-link").unwrap().is_some());
        assert_eq!(store.link("", "v1-link").unwrap().unwrap().tenant, "");
    }

    #[test]
    fn link_by_id_spans_tenants_for_the_public_protocol() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .insert_tenant(super::tests::test_tenant("acme"))
            .unwrap();
        store.insert_link(link_in("acme", "scoped")).unwrap();
        // Senders never know a tenant key; the id is the capability.
        assert!(store.link_by_id("scoped").unwrap().is_some());
        assert!(store.link_by_id("missing").unwrap().is_none());
    }

    #[test]
    fn audit_export_cursor_survives_same_second_rows() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for index in 0..3 {
            store.audit(
                "",
                "",
                "event",
                &format!("row-{index}"),
                &serde_json::json!({}),
            );
        }
        // Page size 2: the third row shares the second with the first two
        // and must still be reachable through the rowid cursor.
        let page_one = store.audit_export("", 0, 0, 2).unwrap();
        assert_eq!(page_one.len(), 2);
        let last = page_one.last().unwrap();
        let page_two = store
            .audit_export("", last.at, last.rowid as u64, 2)
            .unwrap();
        assert_eq!(page_two.len(), 1);
        assert_eq!(page_two[0].subject, "row-2");
    }

    #[test]
    fn audit_export_filters_by_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit("acme", "", "link_created", "l-1", &serde_json::json!({}));
        store.audit("", "", "admin_login", "ip", &serde_json::json!({}));
        let scoped = store.audit_export("acme", 0, 0, 100).unwrap();
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].tenant, "acme");
    }

    #[test]
    fn links_page_is_stable_literal_filtered_and_tenant_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut newest = link_in("", "z-link");
        newest.created_at = 100;
        newest.label = "Hundred% match".to_owned();
        newest.dest = "incoming".to_owned();
        let mut middle = link_in("", "m-link");
        middle.created_at = 100;
        middle.label = "100X match".to_owned();
        let mut oldest = link_in("", "a-link");
        oldest.created_at = 100;
        oldest.active = false;
        store.insert_link(newest).unwrap();
        store.insert_link(middle).unwrap();
        store.insert_link(oldest).unwrap();
        store.insert_tenant(test_tenant("acme")).unwrap();
        store.insert_link(link_in("acme", "foreign")).unwrap();

        let first = store
            .links_page("", 2, None, "HUNDRED%", "all", 1000)
            .unwrap();
        assert_eq!(
            first
                .links
                .iter()
                .map(|link| link.id.as_str())
                .collect::<Vec<_>>(),
            vec!["z-link"]
        );

        let first = store.links_page("", 2, None, "", "all", 1000).unwrap();
        assert_eq!(
            first
                .links
                .iter()
                .map(|link| link.id.as_str())
                .collect::<Vec<_>>(),
            vec!["z-link", "m-link"]
        );
        let cursor = first.next_cursor.unwrap();
        let second = store
            .links_page("", 2, Some(&cursor), "", "all", 1000)
            .unwrap();
        assert_eq!(second.links[0].id, "a-link");
        assert!(second.next_cursor.is_none());
        assert!(store
            .links_page("", 2, None, "", "all", 1000)
            .unwrap()
            .links
            .iter()
            .all(|link| link.tenant.is_empty()));
        assert_eq!(
            store
                .links_page("", 10, None, "", "open", 1000)
                .unwrap()
                .links
                .len(),
            2
        );
        assert_eq!(
            store
                .links_page("", 10, None, "", "closed", 1000)
                .unwrap()
                .links
                .len(),
            1
        );
    }

    #[test]
    fn links_page_unfiltered_query_uses_created_index() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let plan = store
            .with(|connection| {
                let mut statement = connection.prepare(
                    "EXPLAIN QUERY PLAN
                     SELECT id FROM links
                     WHERE tenant = ?1
                       AND (?2 = '' OR lower(label) LIKE '%' || ?2 || '%' ESCAPE '\\'
                            OR lower(dest) LIKE '%' || ?2 || '%' ESCAPE '\\')
                       AND (?3 = 'all'
                            OR (?3 = 'open' AND active != 0
                                AND (expires_at IS NULL OR expires_at > ?4))
                            OR (?3 = 'closed' AND (active = 0
                                OR (expires_at IS NOT NULL AND expires_at <= ?4))))
                       AND (?5 = 0 OR created_at < ?6
                            OR (created_at = ?6 AND id < ?7))
                     ORDER BY created_at DESC, id DESC
                     LIMIT ?8",
                )?;
                let rows = statement.query_map(
                    rusqlite::params!["", "", "all", 1000_i64, 0_i64, 0_i64, "", 11_i64],
                    |row| row.get::<_, String>(3),
                )?;
                rows.collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        assert!(plan
            .iter()
            .any(|detail| detail.contains("USING INDEX links_tenant_created")));
    }

    #[test]
    fn active_outbound_file_keys_filter_scope_state_and_bad_indexes() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();

        store
            .insert_outbound_grant(test_outbound_grant("active", "acme", 2))
            .unwrap();
        let mut expired = test_outbound_grant("expired", "acme", 3);
        expired.expires_at = 19;
        store.insert_outbound_grant(expired).unwrap();
        let mut revoked = test_outbound_grant("revoked", "acme", 4);
        revoked.revoked_at = Some(1);
        store.insert_outbound_grant(revoked).unwrap();
        let mut spent = test_outbound_grant("spent", "acme", 5);
        spent.max_downloads = Some(1);
        spent.downloads = 1;
        store.insert_outbound_grant(spent).unwrap();
        let other_tenant = test_outbound_grant("other-tenant", "other", 6);
        store.insert_outbound_grant(other_tenant).unwrap();
        let mut other_link = test_outbound_grant("other-link", "acme", 7);
        other_link.link_id = "other-link".to_owned();
        store.insert_outbound_grant(other_link).unwrap();

        assert_eq!(
            store.active_outbound_file_keys("acme", "link", 19).unwrap(),
            vec![("upload".to_owned(), 2)]
        );
        assert!(store
            .active_outbound_file_keys("acme", "link", 20)
            .unwrap()
            .is_empty());

        store
            .with(|connection| {
                connection.execute(
                    "UPDATE outbound_grants SET file_index = ?1 WHERE id = ?2",
                    rusqlite::params![-1_i64, "active"],
                )
            })
            .unwrap();
        assert!(store.active_outbound_file_keys("acme", "link", 19).is_err());
    }

    #[test]
    fn recent_audit_is_descending_and_tenant_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit("acme", "", "first", "a", &serde_json::json!({}));
        store.audit("acme", "", "second", "b", &serde_json::json!({}));
        store.audit("other", "", "foreign", "c", &serde_json::json!({}));

        let page = store.audit_recent("acme", 0, 1).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].event, "second");
        let older = store
            .audit_recent("acme", page[0].rowid as u64, 10)
            .unwrap();
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].event, "first");
    }

    #[test]
    fn audit_filters_match_fields_without_searching_detail() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.audit(
            "acme",
            "Alice",
            "link_created",
            "request-1",
            &serde_json::json!({"secret_marker": "needle"}),
        );
        store.audit(
            "acme",
            "Bob",
            "link_deleted",
            "request-2",
            &serde_json::json!({}),
        );
        store.audit(
            "other",
            "Alice",
            "link_created",
            "request-3",
            &serde_json::json!({}),
        );
        store.audit("", "", "default_event", "request-4", &serde_json::json!({}));

        let filters = AuditFilters {
            event: Some("link_created"),
            query: Some("ALICE"),
        };
        let recent = store
            .audit_recent_filtered("acme", 0, 100, filters)
            .unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].subject, "request-1");

        let detail_only = store
            .audit_recent_filtered(
                "acme",
                0,
                100,
                AuditFilters {
                    event: None,
                    query: Some("needle"),
                },
            )
            .unwrap();
        assert!(detail_only.is_empty());

        let display_tenant = store
            .audit_recent_filtered(
                "",
                0,
                100,
                AuditFilters {
                    event: None,
                    query: Some("DEFAULT"),
                },
            )
            .unwrap();
        assert_eq!(display_tenant.len(), 1);
        assert_eq!(display_tenant[0].event, "default_event");

        let legacy = store
            .audit_export_filtered("acme", 0, 0, 100, filters)
            .unwrap();
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].subject, "request-1");
    }

    #[test]
    fn filtered_audit_cursor_paginates_recent_rows() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for subject in ["first", "second", "third"] {
            store.audit("acme", "", "match", subject, &serde_json::json!({}));
        }
        let filters = AuditFilters {
            event: Some("match"),
            query: None,
        };
        let first = store.audit_recent_filtered("acme", 0, 2, filters).unwrap();
        assert_eq!(first.len(), 2);
        let second = store
            .audit_recent_filtered("acme", first[1].rowid as u64, 2, filters)
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].subject, "first");
    }
}

#[cfg(test)]
mod settings_tests {
    use super::tests::test_link;
    use super::*;

    fn test_config() -> Config {
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            push_bind: None,
            push_certificate: None,
            push_private_key: None,
            push_advertise: None,
            data_dir: std::path::PathBuf::from("/nonexistent"),
            receive_dir: std::path::PathBuf::from("/nonexistent"),
            outbound_dir: std::path::PathBuf::from("/nonexistent"),
            web_root: std::path::PathBuf::from("../web"),
            admin_password_hash: "x".to_owned(),
            admin_token_tag: "tag".to_owned(),
            notify_webhook: Some("https://env.example/hook".to_owned()),
            notify_ntfy: None,
            notify_ntfy_token: Some("env-token".to_owned()),
            notify_pushover: None,
            smtp_host: None,
            smtp_port: 587,
            smtp_starttls: true,
            smtp_username: None,
            smtp_password: None,
            smtp_from: None,
            smtp_to: None,
            public_url: None,
            max_upload_bytes: 1024,
            allow_hidden: false,
            session_idle_secs: 60,
            audit_retention_days: 400,
            upload_retention_days: 0,
            metrics_token: None,
            trusted_proxies: Vec::new(),
            oidc: None,
            default_max_total_bytes: None,
            default_max_links: None,
            default_max_sessions: None,
            public_password_login: true,
        }
    }

    fn schema_version(data_dir: &Path) -> String {
        let connection = Connection::open(data_dir.join("votport.db")).unwrap();
        connection
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn empty_settings_table_follows_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(
            overlay.resolved.notify_webhook.as_deref(),
            Some("https://env.example/hook")
        );
        assert_eq!(overlay.notify_webhook_source, "env");
        assert_eq!(overlay.resolved.audit_retention_days, 400);
        assert_eq!(overlay.audit_retention_days_source, "env");
        assert_eq!(overlay.resolved.upload_retention_days, 0);
        assert_eq!(
            overlay.resolved.notify_ntfy_token.as_deref(),
            Some("env-token")
        );
        assert!(overlay.resolved.default_max_total_bytes.is_none());
        assert!(overlay.resolved.public_password_login);
    }

    #[test]
    fn written_key_wins_unwritten_keys_keep_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "notify_webhook".to_owned(),
                    SettingWrite::Set("https://db.example/hook".to_owned()),
                )],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(
            overlay.resolved.notify_webhook.as_deref(),
            Some("https://db.example/hook")
        );
        assert_eq!(overlay.notify_webhook_source, "db");
        assert_eq!(overlay.resolved.audit_retention_days, 400);
        assert_eq!(overlay.audit_retention_days_source, "env");
    }

    #[test]
    fn empty_string_disables_url_despite_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "notify_webhook".to_owned(),
                    SettingWrite::Set(String::new()),
                )],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(overlay.resolved.notify_webhook, None);
        assert_eq!(overlay.notify_webhook_source, "db");
    }

    #[test]
    fn reset_deletes_the_row_and_env_applies() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "notify_webhook".to_owned(),
                    SettingWrite::Set("https://db.example/hook".to_owned()),
                )],
            )
            .unwrap();
        store
            .put_settings(
                "local",
                &[("notify_webhook".to_owned(), SettingWrite::Reset)],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(
            overlay.resolved.notify_webhook.as_deref(),
            Some("https://env.example/hook")
        );
        assert_eq!(overlay.notify_webhook_source, "env");
        assert!(store.setting("notify_webhook").unwrap().is_none());
    }

    #[test]
    fn invalid_stored_days_skip_to_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "audit_retention_days".to_owned(),
                    SettingWrite::Set("nope".to_owned()),
                )],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(overlay.resolved.audit_retention_days, 400);
        assert_eq!(overlay.audit_retention_days_source, "env");
    }

    #[test]
    fn db_retention_is_what_the_sweeper_would_read() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "audit_retention_days".to_owned(),
                    SettingWrite::Set("7".to_owned()),
                )],
            )
            .unwrap();
        assert_eq!(
            store
                .resolved_settings(&test_config())
                .unwrap()
                .audit_retention_days,
            7
        );
    }

    #[test]
    fn open_refuses_a_newer_schema_version() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        drop(store);
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection
                .execute(
                    "UPDATE meta SET value = '99' WHERE key = 'schema_version'",
                    [],
                )
                .unwrap();
        }
        let error = match Store::open(directory.path()) {
            Err(error) => error,
            Ok(_) => panic!("expected open to refuse a newer schema"),
        };
        assert!(error.contains("99"), "{error}");
        assert!(error.contains("newer"), "{error}");
        assert_eq!(schema_version(directory.path()), "99");
    }

    #[test]
    fn open_does_not_stamp_schema_version_down() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        drop(store);
        assert_eq!(schema_version(directory.path()), "16");
        Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), "16");
    }

    #[test]
    fn v4_database_migrates_to_current_schema() {
        let directory = tempfile::tempdir().unwrap();
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                     CREATE TABLE settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at INTEGER NOT NULL,
                        updated_by TEXT NOT NULL DEFAULT ''
                     );
                     INSERT INTO meta (key, value) VALUES ('schema_version', '4');",
                )
                .unwrap();
        }
        let store = Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), "16");
        assert!(store.principals_page(50, 0, None).unwrap().0.is_empty());
        assert!(store.principal("nobody").unwrap().is_none());
    }

    #[test]
    fn v5_database_migrates_to_current_schema() {
        let directory = tempfile::tempdir().unwrap();
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection.execute_batch(SCHEMA).unwrap();
            connection.execute_batch(SETTINGS_SCHEMA).unwrap();
            connection.execute_batch(PRINCIPALS_SCHEMA).unwrap();
            connection
                .execute_batch(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', '5');
                     INSERT INTO links (id, label, created_at) VALUES ('old-link', 'old', 0);",
                )
                .unwrap();
        }

        let store = Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), "16");
        assert!(!store.link("", "old-link").unwrap().unwrap().legal_hold);
    }

    #[test]
    fn v6_database_migrates_to_current_schema() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut link = test_link("old-link");
        link.uploads.push(UploadRecord {
            id: "up".to_owned(),
            started_at: 0,
            completed_at: 1,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: "root".to_owned(),
            total_bytes: 9,
            files: vec![FileRecord {
                path: "a".to_owned(),
                stored_as: "a".to_owned(),
                bytes: 9,
                suite: "blake3".to_owned(),
                root: "object".to_owned(),
                receipt: false,
                deleted: false,
            }],
        });
        store.insert_link(link).unwrap();
        store
            .with(|connection| {
                connection.execute_batch(
                    "DROP TABLE files;
                     DROP TABLE outbound_grants;
                     ALTER TABLE links DROP COLUMN notify_on_upload;
                     UPDATE meta SET value = '6' WHERE key = 'schema_version';",
                )
            })
            .unwrap();
        drop(store);

        let reopened = Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), "16");
        assert_eq!(reopened.tenant_received_bytes("").unwrap(), 9);
    }

    #[test]
    fn v8_database_adds_empty_outbound_files_json() {
        let directory = tempfile::tempdir().unwrap();
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection.execute_batch(SCHEMA).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE outbound_grants (
                         id TEXT PRIMARY KEY,
                         token_hash TEXT UNIQUE NOT NULL,
                         tenant TEXT NOT NULL,
                         link_id TEXT NOT NULL,
                         upload_id TEXT NOT NULL,
                         package_root TEXT NOT NULL,
                         name TEXT NOT NULL,
                         suite TEXT NOT NULL,
                         root TEXT NOT NULL,
                         file_index INTEGER NOT NULL,
                         bytes_hi INTEGER NOT NULL,
                         bytes_lo INTEGER NOT NULL,
                         label TEXT NOT NULL,
                         created_at INTEGER NOT NULL,
                         expires_at INTEGER NOT NULL,
                         revoked_at INTEGER,
                         downloads INTEGER NOT NULL DEFAULT 0
                     );
                     INSERT INTO outbound_grants
                         (id, token_hash, tenant, link_id, upload_id, package_root, name, suite,
                          root, file_index, bytes_hi, bytes_lo, label, created_at, expires_at)
                     VALUES ('g1', 'hash-g1', 'acme', 'link', 'upload', 'package', 'file.bin',
                             'blake3', 'root', 0, 0, 1, 'download', 10, 20);
                     INSERT INTO meta (key, value) VALUES ('schema_version', '8');",
                )
                .unwrap();
        }

        let store = Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), "16");
        let grant = store
            .outbound_grant_by_token_hash("hash-g1")
            .unwrap()
            .unwrap();
        assert!(grant.files.is_empty());
        assert!(grant.password_hash.is_none());
        assert!(grant.first_download_at.is_none());
        assert!(grant.last_download_at.is_none());
    }

    #[test]
    fn v9_database_adds_nullable_outbound_password_hash() {
        let directory = tempfile::tempdir().unwrap();
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection.execute_batch(SCHEMA).unwrap();
            connection
                .execute_batch(
                    r#"CREATE TABLE outbound_grants (
                         id TEXT PRIMARY KEY,
                         token_hash TEXT UNIQUE NOT NULL,
                         tenant TEXT NOT NULL,
                         link_id TEXT NOT NULL,
                         upload_id TEXT NOT NULL,
                         package_root TEXT NOT NULL,
                         name TEXT NOT NULL,
                         suite TEXT NOT NULL,
                         root TEXT NOT NULL,
                         file_index INTEGER NOT NULL,
                         bytes_hi INTEGER NOT NULL,
                         bytes_lo INTEGER NOT NULL,
                         label TEXT NOT NULL,
                         created_at INTEGER NOT NULL,
                         expires_at INTEGER NOT NULL,
                         revoked_at INTEGER,
                         downloads INTEGER NOT NULL DEFAULT 0,
                         files_json TEXT NOT NULL DEFAULT '[]'
                     );
                     INSERT INTO outbound_grants
                         (id, token_hash, tenant, link_id, upload_id, package_root, name, suite,
                         root, file_index, bytes_hi, bytes_lo, label, created_at, expires_at,
                         files_json)
                     VALUES ('g1', 'hash-g1', 'acme', 'link', 'upload', 'package', 'file.bin',
                             'blake3', 'root', 0, 0, 1, 'download', 10, 20,
                             '[{"source":"objects/a","name":"a.txt","suite":"blake3","root":"aa","bytes":3,"receipt_b64":"receipt-a"}]');
                     INSERT INTO meta (key, value) VALUES ('schema_version', '9');"#,
                )
                .unwrap();
        }

        let store = Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), "16");
        let grant = store
            .outbound_grant_by_token_hash("hash-g1")
            .unwrap()
            .unwrap();
        assert!(grant.password_hash.is_none());
        assert!(grant.first_download_at.is_none());
        assert!(grant.last_download_at.is_none());
        assert_eq!(grant.files[0].downloads, 0);
        assert!(grant.files[0].first_download_at.is_none());
        assert!(grant.files[0].last_download_at.is_none());
    }

    #[test]
    fn v10_database_adds_outbound_delivery_timestamps() {
        let directory = tempfile::tempdir().unwrap();
        drop(Store::open(directory.path()).unwrap());
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection
                .execute_batch(
                    "DROP TABLE automation_tokens;
                     ALTER TABLE outbound_grants DROP COLUMN max_downloads;
                     ALTER TABLE outbound_grants DROP COLUMN first_download_at;
                     ALTER TABLE outbound_grants DROP COLUMN last_download_at;
                     ALTER TABLE outbound_grants DROP COLUMN file_count;
                     ALTER TABLE links DROP COLUMN notify_on_upload;
                     ALTER TABLE outbound_grants DROP COLUMN notify_on_download;
                     UPDATE meta SET value = '10' WHERE key = 'schema_version';",
                )
                .unwrap();
        }

        drop(Store::open(directory.path()).unwrap());
        let connection = Connection::open(directory.path().join("votport.db")).unwrap();
        assert_eq!(schema_version(directory.path()), "16");
        let columns: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('outbound_grants')
                 WHERE name IN ('first_download_at', 'last_download_at')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(columns, 2);
    }

    #[test]
    fn v11_database_adds_automation_tokens() {
        let directory = tempfile::tempdir().unwrap();
        drop(Store::open(directory.path()).unwrap());
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection
                .execute_batch(
                    "DROP TABLE automation_tokens;
                     ALTER TABLE outbound_grants DROP COLUMN max_downloads;
                     ALTER TABLE outbound_grants DROP COLUMN file_count;
                     ALTER TABLE links DROP COLUMN notify_on_upload;
                     ALTER TABLE outbound_grants DROP COLUMN notify_on_download;
                     UPDATE meta SET value = '11' WHERE key = 'schema_version';",
                )
                .unwrap();
        }

        drop(Store::open(directory.path()).unwrap());
        let connection = Connection::open(directory.path().join("votport.db")).unwrap();
        assert_eq!(schema_version(directory.path()), "16");
        let table_exists: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'automation_tokens'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_exists, 1);
        let index_exists: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index' AND name = 'automation_tokens_tenant_created'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index_exists, 1);
    }

    #[test]
    fn v12_database_adds_nullable_outbound_download_limit() {
        let directory = tempfile::tempdir().unwrap();
        drop(Store::open(directory.path()).unwrap());
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection
                .execute_batch(
                    "ALTER TABLE outbound_grants DROP COLUMN max_downloads;
                     ALTER TABLE outbound_grants DROP COLUMN file_count;
                     ALTER TABLE links DROP COLUMN notify_on_upload;
                     ALTER TABLE outbound_grants DROP COLUMN notify_on_download;
                     UPDATE meta SET value = '12' WHERE key = 'schema_version';",
                )
                .unwrap();
        }

        drop(Store::open(directory.path()).unwrap());
        let connection = Connection::open(directory.path().join("votport.db")).unwrap();
        assert_eq!(schema_version(directory.path()), "16");
        let default: Option<String> = connection
            .query_row(
                "SELECT dflt_value FROM pragma_table_info('outbound_grants')
                 WHERE name = 'max_downloads'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(default.is_none());
        for (table, column) in [
            ("links", "notify_on_upload"),
            ("outbound_grants", "notify_on_download"),
        ] {
            let (default, not_null): (Option<String>, i64) = connection
                .query_row(
                    &format!("SELECT dflt_value, \"notnull\" FROM pragma_table_info('{table}') WHERE name = '{column}'"),
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(default.as_deref(), Some("0"));
            assert_eq!(not_null, 1);
        }
    }

    #[test]
    fn v15_database_backfills_outbound_file_counts() {
        let directory = tempfile::tempdir().unwrap();
        drop(Store::open(directory.path()).unwrap());
        {
            let connection = Connection::open(directory.path().join("votport.db")).unwrap();
            connection
                .execute_batch(
                    "ALTER TABLE outbound_grants DROP COLUMN file_count;
                     INSERT INTO outbound_grants
                         (id, token_hash, tenant, link_id, upload_id, package_root, name, suite,
                          root, file_index, bytes_hi, bytes_lo, label, created_at, expires_at,
                          files_json)
                     VALUES
                         ('empty', 'hash-empty', 'acme', 'link', 'upload', 'package', 'empty.bin',
                          'blake3', 'root', 0, 0, 1, 'download', 10, 20, '[]'),
                         ('single', 'hash-single', 'acme', 'link', 'upload', 'package', 'single.bin',
                         'blake3', 'root', 0, 0, 1, 'download', 10, 20,
                         '[{\"source\":\"objects/single\",\"name\":\"single.bin\",\"suite\":\"blake3\",\"root\":\"root\",\"bytes\":1,\"receipt_b64\":\"\"}]'),
                         ('multi', 'hash-multi', 'acme', 'link', 'upload', 'package', 'multi.bin',
                         'blake3', 'root', 0, 0, 1, 'download', 10, 20,
                         '[{\"source\":\"objects/multi-0\",\"name\":\"multi-0.bin\",\"suite\":\"blake3\",\"root\":\"root\",\"bytes\":1,\"receipt_b64\":\"\"},
                           {\"source\":\"objects/multi-1\",\"name\":\"multi-1.bin\",\"suite\":\"blake3\",\"root\":\"root\",\"bytes\":2,\"receipt_b64\":\"\"}]');
                     UPDATE meta SET value = '14' WHERE key = 'schema_version';",
                )
                .unwrap();
        }

        drop(Store::open(directory.path()).unwrap());
        let connection = Connection::open(directory.path().join("votport.db")).unwrap();
        assert_eq!(schema_version(directory.path()), "16");
        let counts: Vec<(String, i64)> = {
            let mut statement = connection
                .prepare("SELECT id, file_count FROM outbound_grants ORDER BY id")
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(
            counts,
            [
                ("empty".to_owned(), 1),
                ("multi".to_owned(), 2),
                ("single".to_owned(), 1),
            ]
        );
    }

    #[test]
    fn smtp_is_none_without_host() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut config = test_config();
        config.smtp_from = Some("votport@example.com".to_owned());
        config.smtp_to = Some("ops@example.com".to_owned());
        assert!(store.resolved_settings(&config).unwrap().smtp.is_none());
    }

    #[test]
    fn smtp_is_none_when_host_and_from_lack_to() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let mut config = test_config();
        config.smtp_host = Some("smtp.example.com".to_owned());
        config.smtp_from = Some("votport@example.com".to_owned());
        assert!(store.resolved_settings(&config).unwrap().smtp.is_none());
    }

    #[test]
    fn smtp_assembles_when_host_from_and_to_resolve() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[(
                    "smtp_host".to_owned(),
                    SettingWrite::Set("db.example.com".to_owned()),
                )],
            )
            .unwrap();
        let mut config = test_config();
        config.smtp_from = Some("votport@example.com".to_owned());
        config.smtp_to = Some("ops@example.com,  alerts@example.com".to_owned());
        let smtp = store
            .resolved_settings(&config)
            .unwrap()
            .smtp
            .expect("host from DB plus from/to from env");
        assert_eq!(smtp.host, "db.example.com");
        assert_eq!(smtp.from, "votport@example.com");
        assert_eq!(smtp.to, vec!["ops@example.com", "alerts@example.com"]);
        assert_eq!(smtp.port, 587);
        assert!(smtp.starttls);
        assert!(smtp.password.is_none());
    }

    #[test]
    fn invalid_smtp_port_skips_to_env() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_settings(
                "local",
                &[("smtp_port".to_owned(), SettingWrite::Set("nope".to_owned()))],
            )
            .unwrap();
        let overlay = store.overlay(&test_config()).unwrap();
        assert_eq!(overlay.smtp_port, 587);
        assert_eq!(overlay.smtp_port_source, "env");
    }
}

#[cfg(test)]
mod principals_store_tests {
    use super::*;

    #[test]
    fn upsert_revoke_unblock_preserve_version() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let grants = serde_json::json!([{"tenant":"","role":"admin"}]);
        let row = store
            .upsert_sso_principal("user@example.com", &["employees".to_owned()], &grants)
            .unwrap();
        assert_eq!(row.credential_version, 1);
        assert!(!row.blocked);
        assert_eq!(row.last_groups, vec!["employees".to_owned()]);
        assert_eq!(row.source, "sso");
        assert!(store.principal_allows("user@example.com", 1));
        assert!(!store.principal_allows("user@example.com", 2));
        assert!(store.principal_allows("missing", 1));
        assert!(!store.principal_allows("missing", 2));

        assert!(store.revoke_principal("user@example.com").unwrap());
        let revoked = store.principal("user@example.com").unwrap().unwrap();
        assert_eq!(revoked.credential_version, 2);
        assert!(revoked.blocked);
        assert!(!store.principal_allows("user@example.com", 1));
        assert!(!store.principal_allows("user@example.com", 2));

        assert!(store.unblock_principal("user@example.com").unwrap());
        let unblocked = store.principal("user@example.com").unwrap().unwrap();
        assert_eq!(unblocked.credential_version, 2);
        assert!(!unblocked.blocked);
        assert!(store.principal_allows("user@example.com", 2));
        assert!(!store.principal_allows("user@example.com", 1));
        assert!(!store.revoke_principal("missing").unwrap());
        assert!(!store.unblock_principal("missing").unwrap());

        store
            .with(|connection| {
                connection.execute(
                    "UPDATE principals SET last_groups = 'broken' WHERE subject = ?1",
                    ["user@example.com"],
                )
            })
            .unwrap();
        assert!(store.principal("user@example.com").is_err());
        assert!(!store.principal_allows("user@example.com", 2));
        store
            .with(|connection| {
                connection.execute(
                    "UPDATE principals SET last_groups = '[]', last_grants = 'broken'
                     WHERE subject = ?1",
                    ["user@example.com"],
                )
            })
            .unwrap();
        assert!(store.principal("user@example.com").is_err());
        assert!(!store.principal_allows("user@example.com", 2));
    }

    #[test]
    fn principals_page_searches_literally_and_orders_stably() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for subject in ["Alice%literal", "alice_literal", "aliceXliteral"] {
            store
                .upsert_sso_principal(subject, &[], &serde_json::json!([]))
                .unwrap();
        }
        store
            .with(|connection| connection.execute("UPDATE principals SET last_login_at = 0", []))
            .unwrap();

        let (page, total) = store.principals_page(2, 0, Some("%literal")).unwrap();
        assert_eq!(total, 1);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].subject, "Alice%literal");

        let (page, total) = store.principals_page(2, 0, Some("_literal")).unwrap();
        assert_eq!(total, 1);
        assert_eq!(page[0].subject, "alice_literal");

        let (page, total) = store.principals_page(2, 0, Some("ALICEXLITERAL")).unwrap();
        assert_eq!(total, 1);
        assert_eq!(page[0].subject, "aliceXliteral");

        let (page, total) = store.principals_page(2, 0, None).unwrap();
        assert_eq!(total, 3);
        assert_eq!(
            page.iter()
                .map(|item| item.subject.as_str())
                .collect::<Vec<_>>(),
            ["Alice%literal", "aliceXliteral"]
        );
        let (page, total) = store.principals_page(2, 2, None).unwrap();
        assert_eq!(total, 3);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].subject, "alice_literal");
    }
}
