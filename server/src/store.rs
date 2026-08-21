//! Persistent state: request links and their completed uploads.
//!
//! Everything lives in one JSON document written atomically (temp file +
//! rename) under the data directory. Scale target is a personal server, so a
//! mutex around one document is deliberate.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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

#[derive(Debug, Default, Serialize, Deserialize)]
struct Document {
    #[serde(default)]
    links: Vec<Link>,
    /// Argon2 PHC hash set by "change password" in the admin UI. Once present
    /// it wins over VOTPORT_ADMIN_PASSWORD, so a restart cannot silently roll
    /// the password back to whatever the environment still holds. To recover a
    /// lost password, delete this field from state.json and restart.
    #[serde(default)]
    admin_password_hash: Option<String>,
}

pub struct Store {
    path: PathBuf,
    document: Mutex<Document>,
}

impl Store {
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(data_dir)
            .map_err(|error| format!("create {}: {error}", data_dir.display()))?;
        let path = data_dir.join("state.json");
        let document = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| format!("parse {}: {error}", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Document::default(),
            Err(error) => return Err(format!("read {}: {error}", path.display())),
        };
        Ok(Self {
            path,
            document: Mutex::new(document),
        })
    }

    pub fn admin_password_hash(&self) -> Option<String> {
        self.document
            .lock()
            .expect("store poisoned")
            .admin_password_hash
            .clone()
    }

    pub fn set_admin_password_hash(&self, hash: String) -> Result<(), String> {
        let mut document = self.document.lock().expect("store poisoned");
        document.admin_password_hash = Some(hash);
        persist(&self.path, &document)
    }

    pub fn links(&self) -> Vec<Link> {
        self.document.lock().expect("store poisoned").links.clone()
    }

    pub fn link(&self, id: &str) -> Option<Link> {
        self.document
            .lock()
            .expect("store poisoned")
            .links
            .iter()
            .find(|link| link.id == id)
            .cloned()
    }

    pub fn insert_link(&self, link: Link) -> Result<(), String> {
        let mut document = self.document.lock().expect("store poisoned");
        document.links.push(link);
        persist(&self.path, &document)
    }

    /// Applies `mutate` to the link and persists; Ok(false) when absent.
    pub fn update_link(&self, id: &str, mutate: impl FnOnce(&mut Link)) -> Result<bool, String> {
        let mut document = self.document.lock().expect("store poisoned");
        let Some(link) = document.links.iter_mut().find(|link| link.id == id) else {
            return Ok(false);
        };
        mutate(link);
        persist(&self.path, &document).map(|()| true)
    }

    pub fn remove_link(&self, id: &str) -> Result<bool, String> {
        let mut document = self.document.lock().expect("store poisoned");
        let before = document.links.len();
        document.links.retain(|link| link.id != id);
        if document.links.len() == before {
            return Ok(false);
        }
        persist(&self.path, &document).map(|()| true)
    }
}

fn persist(path: &Path, document: &Document) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(document).map_err(|error| error.to_string())?;
    let temp = path.with_extension("json.tmp");
    // A crash between write and rename leaves the temp behind; write_private
    // uses create_new, so a stale temp would fail every persist forever.
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("remove {}: {error}", temp.display())),
    }
    // 0600: the document holds the argon2 admin and link password hashes.
    crate::auth::write_private(&temp, &bytes)
        .map_err(|error| format!("write {}: {error}", temp.display()))?;
    fs::rename(&temp, path).map_err(|error| error.to_string())?;
    // The rename is only durable once its directory entry is.
    if let Ok(dir) = fs::File::open(path.parent().unwrap_or(Path::new("."))) {
        let _ = dir.sync_all();
    }
    Ok(())
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
    fn persist_recovers_from_a_stale_temp_file() {
        let directory = tempfile::tempdir().unwrap();
        // Left behind by a crash between write and rename.
        std::fs::write(directory.path().join("state.json.tmp"), b"garbage").unwrap();
        let store = Store::open(directory.path()).unwrap();
        let link = Link {
            id: "test-link".to_owned(),
            label: "test".to_owned(),
            dest: String::new(),
            password_hash: None,
            created_at: 0,
            expires_at: None,
            max_bytes: None,
            active: true,
            uploads: Vec::new(),
            events: Vec::new(),
        };
        store
            .insert_link(link)
            .expect("stale temp must not wedge the store");
        assert_eq!(store.links().len(), 1);
    }
}
