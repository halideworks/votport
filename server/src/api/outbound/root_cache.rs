//! Reusable verified roots for unchanged outbound library files.
//!
//! Sharing a library file costs a full BLAKE3-Bao read of every selected
//! byte. Most re-shares hand back the same files, so this sidecar remembers
//! `(tenant, source path, size, mtime) -> root` after a successful hash and
//! lets [`super::hash_library_file`] skip the re-read when all three key
//! parts still match, the same invalidation rule build systems use. A
//! content change that keeps size and mtime is not caught here - realistic
//! on NAS exports with coarse mtime granularity, where two writes can land
//! in one timestamp tick; the per-download integrity checks stay the last
//! word and fail closed, which is exactly the pre-cache behavior for a file
//! mutated after grant creation.
//!
//! Storage follows the `outbound.proofs` precedent: a small file under
//! `data_dir`, never the main schema. Eviction is by age
//! ([`ROOT_CACHE_MAX_AGE_SECS`], applied when the sidecar loads) and by
//! count ([`ROOT_CACHE_MAX_ENTRIES`], oldest `cached_at` dropped in eighths
//! when the cap is exceeded), which bounds the file at a few megabytes. A
//! corrupt or truncated sidecar is discarded and rebuilt by rehashing; a
//! restart loses only entries written since the last persist.
//! VOTPORT PROPRIETARY LICENSE.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::store::now_unix;

/// Bounded sidecar: ~250 bytes per entry keeps the file under ~2 MB.
pub(crate) const ROOT_CACHE_MAX_ENTRIES: usize = 8192;
/// Entries older than thirty days are dropped on load; files re-shared that
/// rarely are worth one fresh read to keep the sidecar small.
const ROOT_CACHE_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;
const ROOT_CACHE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct RootCacheEntry {
    tenant: String,
    path: String,
    size: u64,
    mtime_nanos: u64,
    root: String,
    cached_at: u64,
}

#[derive(Default)]
struct RootCacheState {
    loaded: bool,
    dirty: bool,
    entries: HashMap<String, RootCacheEntry>,
}

pub(crate) struct RootCache {
    path: PathBuf,
    state: Mutex<RootCacheState>,
}

fn cache_key(tenant: &str, path: &Path, size: u64, mtime_nanos: u64) -> String {
    format!(
        "{tenant}\u{0}{}\u{0}{size}\u{0}{mtime_nanos}",
        path.display()
    )
}

/// mtime as nanos since the Unix epoch, saturating to 0 when unavailable or
/// pre-epoch; 0 is still a usable key part, it just matches only itself.
pub(crate) fn mtime_nanos(metadata: &std::fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

impl RootCache {
    pub(crate) fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("outbound-roots.json"),
            state: Mutex::new(RootCacheState::default()),
        }
    }

    /// Root hex for a source whose size and mtime are unchanged since the
    /// cached hash. Loads the sidecar once per process.
    pub(crate) fn lookup(
        &self,
        tenant: &str,
        path: &Path,
        size: u64,
        mtime: u64,
    ) -> Option<String> {
        let key = cache_key(tenant, path, size, mtime);
        let mut state = self.state.lock().expect("root cache poisoned");
        self.ensure_loaded(&mut state);
        state.entries.get(&key).map(|entry| entry.root.clone())
    }

    /// Records a freshly hashed root. Age- and count-bounded; see the module
    /// comment for the eviction contract.
    pub(crate) fn insert(&self, tenant: &str, path: &Path, size: u64, mtime: u64, root: String) {
        let key = cache_key(tenant, path, size, mtime);
        let mut state = self.state.lock().expect("root cache poisoned");
        self.ensure_loaded(&mut state);
        state.entries.insert(
            key,
            RootCacheEntry {
                tenant: tenant.to_owned(),
                path: path.display().to_string(),
                size,
                mtime_nanos: mtime,
                root,
                cached_at: now_unix(),
            },
        );
        if state.entries.len() > ROOT_CACHE_MAX_ENTRIES {
            // Drop exactly an eighth of the entries, oldest first with a key
            // tie-break: a `>` cutoff on cached_at would wipe every entry
            // sharing the cutoff second, and bulk folder hashes land in one
            // now_unix() second.
            let evict = state.entries.len() / 8;
            let mut order: Vec<(u64, &String)> = state
                .entries
                .iter()
                .map(|(key, entry)| (entry.cached_at, key))
                .collect();
            order.sort_unstable();
            let victims: Vec<String> = order[..evict]
                .iter()
                .map(|(_, key)| (*key).clone())
                .collect();
            drop(order);
            for key in victims {
                state.entries.remove(&key);
            }
        }
        state.dirty = true;
    }

    /// Writes the sidecar atomically when anything changed since the last
    /// persist; callers invoke it after a grant's hashing phase.
    pub(crate) fn persist(&self) {
        let mut state = self.state.lock().expect("root cache poisoned");
        if !state.dirty {
            return;
        }
        let document = serde_json::json!({
            "version": ROOT_CACHE_VERSION,
            "entries": state.entries.values().collect::<Vec<_>>(),
        });
        let result = (|| {
            let body = serde_json::to_vec(&document).ok()?;
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent).ok()?;
            }
            let mut stage = self.path.clone();
            stage.set_extension("json.stage");
            stage
                .as_mut_os_string()
                .push(format!("-{}", crate::auth::random_token()));
            {
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o600);
                }
                let mut file = options.open(&stage).ok()?;
                file.write_all(&body).ok()?;
                file.sync_all().ok()?;
            }
            std::fs::rename(&stage, &self.path).ok()
        })();
        if result.is_some() {
            state.dirty = false;
        }
    }

    fn ensure_loaded(&self, state: &mut RootCacheState) {
        if state.loaded {
            return;
        }
        state.loaded = true;
        let Ok(bytes) = std::fs::read(&self.path) else {
            return;
        };
        let Ok(document) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            // Corrupt sidecar: discard and let rehashing rebuild it.
            return;
        };
        let version = document["version"].as_u64();
        if version != Some(ROOT_CACHE_VERSION as u64) {
            return;
        }
        let Some(entries) = document["entries"].as_array() else {
            return;
        };
        let cutoff = now_unix().saturating_sub(ROOT_CACHE_MAX_AGE_SECS);
        for entry in entries {
            let Ok(entry) = serde_json::from_value::<RootCacheEntry>(entry.clone()) else {
                continue;
            };
            if entry.cached_at < cutoff {
                continue;
            }
            state.entries.insert(
                cache_key(
                    &entry.tenant,
                    Path::new(&entry.path),
                    entry.size,
                    entry.mtime_nanos,
                ),
                entry,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(root: &str, cached_at: u64) -> RootCacheEntry {
        RootCacheEntry {
            tenant: "acme".to_owned(),
            path: "/library/project/a.bin".to_owned(),
            size: 4,
            mtime_nanos: 100,
            root: root.to_owned(),
            cached_at,
        }
    }

    #[test]
    fn lookup_round_trips_through_the_sidecar_and_evicts() {
        let directory = tempfile::tempdir().unwrap();
        let cache = RootCache::new(directory.path());
        let path = Path::new("/library/project/a.bin");
        assert_eq!(cache.lookup("acme", path, 4, 100), None);
        cache.insert("acme", path, 4, 100, "ab".repeat(32));
        cache.persist();
        assert!(directory.path().join("outbound-roots.json").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(directory.path().join("outbound-roots.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the sidecar stays operator-only");
        }

        // A fresh instance over the same data dir replays the entry.
        let reloaded = RootCache::new(directory.path());
        assert_eq!(
            reloaded.lookup("acme", path, 4, 100).as_deref(),
            Some(&"ab".repeat(32)[..])
        );
        assert_eq!(
            reloaded.lookup("acme", path, 5, 100),
            None,
            "size is part of the key"
        );
        assert_eq!(
            reloaded.lookup("acme", path, 4, 101),
            None,
            "mtime is part of the key"
        );
        assert_eq!(
            reloaded.lookup("other", path, 4, 100),
            None,
            "tenant is part of the key"
        );

        // Entries past the age bound are dropped on load.
        let stale = directory.path().join("outbound-roots.json");
        let document = serde_json::json!({
            "version": 1,
            "entries": [
                serde_json::to_value(entry(&"ab".repeat(32), now_unix())).unwrap(),
                serde_json::to_value(entry(&"cd".repeat(32), now_unix() - ROOT_CACHE_MAX_AGE_SECS - 1)).unwrap(),
            ],
        });
        std::fs::write(&stale, serde_json::to_vec(&document).unwrap()).unwrap();
        let aged = RootCache::new(directory.path());
        assert_eq!(
            aged.lookup("acme", path, 4, 100).as_deref(),
            Some(&"ab".repeat(32)[..])
        );

        // A corrupt sidecar is discarded, not fatal.
        std::fs::write(&stale, b"{not json").unwrap();
        let corrupt = RootCache::new(directory.path());
        assert_eq!(corrupt.lookup("acme", path, 4, 100), None);
        corrupt.insert("acme", path, 4, 100, "ef".repeat(32));
        corrupt.persist();
        let rebuilt = RootCache::new(directory.path());
        assert_eq!(
            rebuilt.lookup("acme", path, 4, 100).as_deref(),
            Some(&"ef".repeat(32)[..])
        );
    }

    /// A folder hash lands thousands of inserts in one now_unix() second;
    /// eviction must drop exactly an eighth of them, not every entry that
    /// shares the cutoff timestamp.
    #[test]
    fn bulk_same_second_eviction_keeps_the_fresh_majority() {
        let directory = tempfile::tempdir().unwrap();
        let cache = RootCache::new(directory.path());
        let path = Path::new("/library/project/a.bin");
        for index in 0..=(ROOT_CACHE_MAX_ENTRIES as u64) {
            cache.insert("acme", path, index, index, "ab".repeat(32));
        }
        let state = cache.state.lock().unwrap();
        let crossings = ROOT_CACHE_MAX_ENTRIES + 1;
        assert_eq!(state.entries.len(), crossings - crossings / 8);
        assert!(state.entries.contains_key(&cache_key(
            "acme",
            path,
            ROOT_CACHE_MAX_ENTRIES as u64,
            ROOT_CACHE_MAX_ENTRIES as u64
        )));
    }
}
