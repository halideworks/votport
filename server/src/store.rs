//! Persistent state: request links and their completed uploads.
//!
//! Everything lives in one JSON document written atomically (temp file +
//! rename) under the data directory. Scale target is a personal server, so a
//! mutex around one document is deliberate.

use std::fs;
use std::io::Write as _;
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadRecord {
    pub id: String,
    pub completed_at: u64,
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
    pub fn update_link(
        &self,
        id: &str,
        mutate: impl FnOnce(&mut Link),
    ) -> Result<bool, String> {
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
    let mut file = fs::File::create(&temp).map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::rename(&temp, path).map_err(|error| error.to_string())
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
