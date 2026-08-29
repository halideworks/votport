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
    pub uploads: Vec<UploadRecord>,
    #[serde(default)]
    pub events: Vec<SessionEvent>,
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

const SCHEMA_VERSION: u64 = 7;

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
            connection.execute_batch("CREATE INDEX IF NOT EXISTS links_tenant ON links(tenant)")
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
                                max_bytes, active, legal_hold, uploads_json, events_json
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
                                                      legal_hold, uploads_json, events_json)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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

    pub fn links(&self, tenant: &str) -> Result<Vec<Link>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                        active, legal_hold, uploads_json, events_json
                 FROM links WHERE tenant = ?1 ORDER BY rowid",
            )?;
            let rows = statement.query_map([tenant], row_to_link)?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn link(&self, tenant: &str, id: &str) -> Result<Option<Link>, String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                            active, legal_hold, uploads_json, events_json
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
                            active, legal_hold, uploads_json, events_json
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
                            max_bytes, active, legal_hold, '[]' AS uploads_json,
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
        self.with(|connection| {
            let mut statement = connection.prepare(
                "DELETE FROM tenants WHERE key = ?1
                 AND NOT EXISTS (SELECT 1 FROM links WHERE tenant = ?1)",
            )?;
            let changed = statement.execute([key])?;
            if changed > 0 {
                return Ok(TenantRemoval::Deleted);
            }
            let exists: i64 = connection.query_row(
                "SELECT EXISTS (SELECT 1 FROM tenants WHERE key = ?1)",
                [key],
                |row| row.get(0),
            )?;
            if exists == 0 {
                Ok(TenantRemoval::Absent)
            } else {
                Ok(TenantRemoval::HasLinks)
            }
        })
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

    pub fn principals(&self) -> Result<Vec<Principal>, String> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT subject, credential_version, blocked, last_login_at,
                        last_groups, last_grants, source
                 FROM principals ORDER BY last_login_at DESC, subject",
            )?;
            let rows = statement.query_map([], map_principal)?;
            rows.collect::<Result<Vec<_>, _>>()
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
                        active, legal_hold, uploads_json, events_json
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
}

fn insert_link_row(connection: &Connection, link: &Link) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO links (id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                            active, legal_hold, uploads_json, events_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        link_params(link),
    )?;
    rebuild_link_files(connection, link)?;
    Ok(())
}

fn write_link_row(connection: &Connection, link: &Link) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE links SET label = ?3, dest = ?4, password_hash = ?5, created_at = ?6,
                          expires_at = ?7, max_bytes = ?8, active = ?9,
                          legal_hold = ?10, uploads_json = ?11, events_json = ?12
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

fn link_params(link: &Link) -> [rusqlite::types::Value; 12] {
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
        uploads: parse_json(&uploads_json, 10)?,
        events: parse_json(&events_json, 11)?,
    })
}

fn read_link(connection: &Connection, tenant: &str, id: &str) -> Result<Option<Link>, String> {
    connection
        .query_row(
            "SELECT id, tenant, label, dest, password_hash, created_at, expires_at, max_bytes,
                    active, legal_hold, uploads_json, events_json
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
        self.with(|connection| {
            if tenant.is_empty() {
                Self::audit_export_query(connection, "", since, after_rowid, limit)
            } else {
                Self::audit_export_query(connection, tenant, since, after_rowid, limit)
            }
        })
    }

    fn audit_export_query(
        connection: &Connection,
        tenant: &str,
        since: u64,
        after_rowid: u64,
        limit: u64,
    ) -> rusqlite::Result<Vec<AuditRow>> {
        let since = i64::try_from(since).unwrap_or(0);
        let after_rowid = i64::try_from(after_rowid).unwrap_or(0);
        let limit = i64::try_from(limit).unwrap_or(1000);
        if tenant.is_empty() {
            let mut statement = connection.prepare_cached(
                "SELECT rowid, at, tenant, actor, event, subject, detail
                 FROM audit_log
                 WHERE at > ?1 OR (at = ?1 AND rowid > ?2)
                 ORDER BY at, rowid LIMIT ?3",
            )?;
            let rows =
                statement.query_map(rusqlite::params![since, after_rowid, limit], map_audit_row)?;
            rows.collect()
        } else {
            let mut statement = connection.prepare_cached(
                "SELECT rowid, at, tenant, actor, event, subject, detail
                 FROM audit_log
                 WHERE tenant = ?4 AND (at > ?1 OR (at = ?1 AND rowid > ?2))
                 ORDER BY at, rowid LIMIT ?3",
            )?;
            let rows = statement.query_map(
                rusqlite::params![since, after_rowid, limit, tenant],
                map_audit_row,
            )?;
            rows.collect()
        }
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
    use super::tests::link_in;
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
        assert_eq!(schema_version(directory.path()), "7");
        Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), "7");
    }

    #[test]
    fn v4_database_gains_principals_and_stamps_7() {
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
        assert_eq!(schema_version(directory.path()), "7");
        assert!(store.principals().unwrap().is_empty());
        assert!(store.principal("nobody").unwrap().is_none());
    }

    #[test]
    fn v5_database_gains_legal_hold_and_stamps_7() {
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
        assert_eq!(schema_version(directory.path()), "7");
        assert!(!store.link("", "old-link").unwrap().unwrap().legal_hold);
    }

    #[test]
    fn v6_database_backfills_files_and_stamps_7() {
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
                     UPDATE meta SET value = '6' WHERE key = 'schema_version';",
                )
            })
            .unwrap();
        drop(store);

        let reopened = Store::open(directory.path()).unwrap();
        assert_eq!(schema_version(directory.path()), "7");
        assert_eq!(reopened.tenant_received_bytes("").unwrap(), 9);
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
}
