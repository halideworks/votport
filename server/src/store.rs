//! Persistent state: request links and their completed uploads.
//!
//! SQLite (WAL, synchronous FULL) in the data directory. The public API is
//! the one the JSON-document store had: every mutation commits durably before
//! returning, and callers stay free of SQL. Uploads and session events remain
//! embedded JSON on the link row; splitting them into tables is phase 2 work
//! (see docs/multi-tenancy.md).

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension as _};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileRecord {
    /// Path as named inside the uploaded package.
    pub path: String,
    /// Path actually stored on disk, relative to the receive root.
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
    /// Hex root of the verified package manifest.
    pub package_root: String,
    pub total_bytes: u64,
    pub files: Vec<FileRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Link {
    pub id: String,
    pub label: String,
    /// Destination subdirectory relative to the receive root ("" = root).
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
    pub uploads: Vec<UploadRecord>,
    #[serde(default)]
    pub events: Vec<SessionEvent>,
}

impl Link {
    pub fn usable_now(&self) -> bool {
        self.active && self.expires_at.is_none_or(|at| now_unix() < at)
    }
}

/// The pre-SQLite state document, kept only to import legacy state.json files.
#[derive(Deserialize)]
struct LegacyDocument {
    #[serde(default)]
    links: Vec<Link>,
    #[serde(default)]
    admin_password_hash: Option<String>,
}

const SCHEMA_VERSION: &str = "1";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
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
        let store = Self {
            connection: Mutex::new(connection),
        };
        store.import_legacy(data_dir)?;
        store
            .with(|connection| {
                connection.execute(
                    "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?1)",
                    [SCHEMA_VERSION],
                )
            })?
            .map_err(|error| error.to_string())?;
        Ok(store)
    }

    /// Imports a legacy state.json once: links and the admin hash move into
    /// the database, the file is renamed so a later crash cannot re-import
    /// stale state over newer rows.
    fn import_legacy(&self, data_dir: &Path) -> Result<(), String> {
        let path = data_dir.join("state.json");
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(());
        };
        let document: LegacyDocument = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse {}: {error}", path.display()))?;
        {
            let connection = self.connection.lock().expect("store poisoned");
            for link in &document.links {
                insert_link_row(&connection, link).map_err(|error| error.to_string())?;
            }
            if let Some(hash) = &document.admin_password_hash {
                connection
                    .execute(
                        "INSERT OR IGNORE INTO meta (key, value) VALUES ('admin_password_hash', ?1)",
                        [hash],
                    )
                    .map_err(|error| error.to_string())?;
            }
        }
        let imported = data_dir.join("state.json.imported");
        std::fs::rename(&path, imported).map_err(|error| error.to_string())?;
        tracing::info!(
            target: "audit",
            links = document.links.len(),
            "imported legacy state.json into sqlite"
        );
        Ok(())
    }

    /// Runs `f` with the connection; Ok(Err(..)) carries a mapped SQL error.
    fn with<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<Result<T, String>, String> {
        let connection = self.connection.lock().expect("store poisoned");
        Ok(f(&connection).map_err(|error| error.to_string()))
    }

    pub fn admin_password_hash(&self) -> Option<String> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT value FROM meta WHERE key = 'admin_password_hash'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })
        .expect("store poisoned")
        .expect("store poisoned")
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
        })?
    }

    pub fn links(&self) -> Vec<Link> {
        self.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT id, label, dest, password_hash, created_at, expires_at, max_bytes,
                        active, uploads_json, events_json
                 FROM links ORDER BY rowid",
            )?;
            let rows = statement.query_map([], row_to_link)?;
            rows.collect::<Result<Vec<_>, _>>()
        })
        .expect("store poisoned")
        .expect("store poisoned")
    }

    pub fn link(&self, id: &str) -> Option<Link> {
        self.with(|connection| {
            connection
                .query_row(
                    "SELECT id, label, dest, password_hash, created_at, expires_at, max_bytes,
                            active, uploads_json, events_json
                     FROM links WHERE id = ?1",
                    [id],
                    row_to_link,
                )
                .optional()
        })
        .expect("store poisoned")
        .expect("store poisoned")
    }

    pub fn insert_link(&self, link: Link) -> Result<(), String> {
        self.with(|connection| insert_link_row(connection, &link))?
    }

    /// Applies `mutate` to the link and commits; Ok(false) when absent.
    pub fn update_link(&self, id: &str, mutate: impl FnOnce(&mut Link)) -> Result<bool, String> {
        let mut connection = self.connection.lock().expect("store poisoned");
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let Some(mut link) = read_link(&transaction, id)? else {
            return Ok(false);
        };
        mutate(&mut link);
        write_link_row(&transaction, &link).map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(true)
    }

    pub fn remove_link(&self, id: &str) -> Result<bool, String> {
        self.with(|connection| {
            let changed = connection.execute("DELETE FROM links WHERE id = ?1", [id])?;
            Ok(changed > 0)
        })?
    }
}

fn insert_link_row(connection: &Connection, link: &Link) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO links (id, label, dest, password_hash, created_at, expires_at, max_bytes,
                            active, uploads_json, events_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        link_params(link),
    )?;
    Ok(())
}

fn write_link_row(connection: &Connection, link: &Link) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE links SET label = ?2, dest = ?3, password_hash = ?4, created_at = ?5,
                          expires_at = ?6, max_bytes = ?7, active = ?8,
                          uploads_json = ?9, events_json = ?10
         WHERE id = ?1",
        link_params(link),
    )?;
    Ok(())
}

fn link_params(link: &Link) -> [rusqlite::types::Value; 10] {
    use rusqlite::types::Value as V;
    let uploads = serde_json::to_string(&link.uploads).unwrap_or_else(|_| "[]".to_owned());
    let events = serde_json::to_string(&link.events).unwrap_or_else(|_| "[]".to_owned());
    [
        V::from(link.id.clone()),
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
        V::from(uploads),
        V::from(events),
    ]
}

fn row_to_link(row: &rusqlite::Row<'_>) -> rusqlite::Result<Link> {
    let uploads_json: String = row.get("uploads_json")?;
    let events_json: String = row.get("events_json")?;
    Ok(Link {
        id: row.get("id")?,
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
        uploads: serde_json::from_str(&uploads_json).unwrap_or_default(),
        events: serde_json::from_str(&events_json).unwrap_or_default(),
    })
}

fn read_link(connection: &Connection, id: &str) -> Result<Option<Link>, String> {
    connection
        .query_row(
            "SELECT id, label, dest, password_hash, created_at, expires_at, max_bytes,
                    active, uploads_json, events_json
             FROM links WHERE id = ?1",
            [id],
            row_to_link,
        )
        .optional()
        .map_err(|error| error.to_string())
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_link(id: &str) -> Link {
        Link {
            id: id.to_owned(),
            label: "test".to_owned(),
            dest: String::new(),
            password_hash: None,
            created_at: 0,
            expires_at: None,
            max_bytes: None,
            active: true,
            uploads: Vec::new(),
            events: Vec::new(),
        }
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

        let loaded = store.link("link-1").unwrap();
        assert_eq!(loaded.uploads.len(), 1);
        assert!(loaded.uploads[0].files[0].receipt);
        assert_eq!(loaded.events[0].outcome, "cancelled");
        assert_eq!(store.links().len(), 1);
    }

    #[test]
    fn update_and_remove_report_presence() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("link-1")).unwrap();
        let found = store
            .update_link("link-1", |link| link.active = false)
            .unwrap();
        assert!(found);
        assert!(!store.link("link-1").unwrap().active);
        assert!(!store.update_link("missing", |_| {}).unwrap());
        assert!(store.remove_link("link-1").unwrap());
        assert!(!store.remove_link("link-1").unwrap());
        assert!(store.link("link-1").is_none());
    }

    #[test]
    fn links_preserve_insertion_order() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store.insert_link(test_link("b")).unwrap();
        store.insert_link(test_link("a")).unwrap();
        let ids: Vec<String> = store.links().into_iter().map(|link| link.id).collect();
        assert_eq!(ids, ["b", "a"]);
    }

    #[test]
    fn admin_hash_persists_across_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(store.admin_password_hash().is_none());
        store
            .set_admin_password_hash("argon2-hash".to_owned())
            .unwrap();
        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        assert_eq!(
            reopened.admin_password_hash().as_deref(),
            Some("argon2-hash")
        );
    }

    #[test]
    fn legacy_state_json_is_imported_and_renamed() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("state.json"),
            r#"{"links":[{"id":"old-link","label":"old","dest":"","created_at":0,"active":true}],
                "admin_password_hash":"old-hash"}"#,
        )
        .unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(store.link("old-link").is_some());
        assert_eq!(store.admin_password_hash().as_deref(), Some("old-hash"));
        assert!(!directory.path().join("state.json").exists());
        assert!(directory.path().join("state.json.imported").exists());
        // Reopening must not re-import stale state over newer rows.
        drop(store);
        let reopened = Store::open(directory.path()).unwrap();
        assert!(reopened.link("old-link").is_some());
    }
}
