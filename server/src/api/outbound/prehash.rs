//! Prepare stable Library sources before an operator requests a delivery link.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;

const POLL: Duration = Duration::from_secs(15);
const MAX_WARM_FILES: usize = root_cache::ROOT_CACHE_MAX_ENTRIES / 2;
const RETRY: Duration = Duration::from_secs(300);
type Stamp = (u64, u64, Option<(u64, u64, i64, i64)>);
type Observations = HashMap<(String, String), (Stamp, Instant)>;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Source {
    changed: u64,
    stamp: Stamp,
    tenant: String,
    name: String,
}

fn stamp(meta: &std::fs::Metadata) -> Stamp {
    (meta.len(), mtime_nanos(meta), change_stamp(meta))
}

pub(super) fn idle(app: &App) -> bool {
    !app.is_stopping()
        && !app.lease_lost.load(Ordering::Acquire)
        && app.sessions.total() == 0
        && app.native_active() == 0
        && app
            .outbound_active
            .lock()
            .expect("outbound active poisoned")
            .is_empty()
}

fn eligible(path: &Path, size: u64, max: u64) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    !["tmp", "part", "stage", "journal", "crdownload", "download"]
        .iter()
        .any(|value| extension.eq_ignore_ascii_case(value))
        && valid_preparation_length(size, None, max)
}

fn cached_object(app: &App, tenant: &str, path: &Path, stamp: Stamp) -> Option<ObjectId> {
    let (size, mtime, change) = stamp;
    app.root_cache
        .lookup(tenant, path, size, mtime, change)
        .and_then(|root| hex::decode(root).ok())
        .and_then(|root| root.try_into().ok())
        .map(|root| ObjectId {
            suite: 1,
            root,
            length: size,
        })
}

pub(super) fn status(
    app: &App,
    tenant: &str,
    name: &str,
    background: bool,
    idle: bool,
) -> &'static str {
    let Ok(path) = safe_library_path(app, tenant, name) else {
        return "unavailable";
    };
    let root = library_root(app, tenant);
    if !library_components_safe(&app.config.outbound_dir, &root)
        || !library_components_safe(&root, &path)
    {
        return "unavailable";
    }
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return "unavailable";
    };
    if !meta.is_file() || !valid_preparation_length(meta.len(), None, app.config.max_upload_bytes) {
        return "unavailable";
    }
    if cached_object(app, tenant, &path, stamp(&meta)).is_some_and(|object| {
        object.length < BATCH_STAGE_BYTES
            || cached_catalog_usable(&app.config.data_dir.join("outbound.proofs"), &object)
    }) {
        return "ready";
    }
    // Inspect existing ownership without adding entries to the hash-lock registry.
    let lock = app
        .library_hash_locks
        .lock()
        .expect("library hash locks poisoned")
        .get(&path)
        .cloned();
    if lock.is_some_and(|lock| lock.try_lock().is_err()) {
        return "preparing";
    }
    if !background || !eligible(&path, meta.len(), app.config.max_upload_bytes) {
        return "on_demand";
    }
    if !idle {
        return "waiting_for_idle";
    }
    "not_prepared"
}

fn scan(app: &App) -> io::Result<Vec<Source>> {
    let mut tenants = vec![String::new()];
    tenants.extend(
        app.store
            .tenants()
            .map_err(io::Error::other)?
            .into_iter()
            .map(|tenant| tenant.key),
    );
    let mut sources = BinaryHeap::new();
    let mut visited = 0;
    for tenant in tenants {
        if !tenant.is_empty() && !crate::paths::portable_tenant_key(&tenant) {
            continue;
        }
        let root = library_root(app, &tenant);
        if !library_root_safe(&root) || !library_components_safe(&app.config.outbound_dir, &root) {
            continue;
        }
        visit_library_files(
            &root,
            &root,
            &mut visited,
            MAX_LIBRARY_SEARCH_NODES,
            0,
            &|name| {
                name.to_str().is_some_and(|name| {
                    crate::paths::admit_component(name, app.config.allow_hidden).is_ok()
                })
            },
            &mut |path, meta| {
                if !idle(app) {
                    return false;
                }
                let Some(name) = path.strip_prefix(&root).ok().and_then(|path| path.to_str())
                else {
                    return true;
                };
                if !eligible(path, meta.len(), app.config.max_upload_bytes)
                    || safe_library_path(app, &tenant, name).is_err()
                {
                    return true;
                }
                let stamp = stamp(meta);
                let changed = stamp
                    .2
                    .map_or(0, |(_, _, seconds, nanos)| {
                        u64::try_from(seconds)
                            .unwrap_or(0)
                            .saturating_mul(1_000_000_000)
                            .saturating_add(u64::try_from(nanos).unwrap_or(0))
                    })
                    .max(stamp.1);
                sources.push(Reverse(Source {
                    changed,
                    stamp,
                    tenant: tenant.clone(),
                    name: name.replace('\\', "/"),
                }));
                // ponytail: warm the newest 4,096 sources and reserve half the cache for foreground use.
                // Larger libraries need a larger cache or an explicit watched-folder scope.
                if sources.len() > MAX_WARM_FILES {
                    sources.pop();
                }
                true
            },
        );
    }
    Ok(sources.into_iter().map(|Reverse(source)| source).collect())
}

fn ready(
    app: &App,
    observed: &mut Observations,
    sources: Vec<Source>,
    now: Instant,
) -> Vec<Source> {
    let mut next = Observations::new();
    let mut ready = Vec::new();
    for source in sources {
        let key = (source.tenant.clone(), source.name.clone());
        let since = observed
            .remove(&key)
            .filter(|(stamp, _)| *stamp == source.stamp)
            .map_or(now, |(_, since)| since);
        next.insert(key, (source.stamp, since));
        let path = library_root(app, &source.tenant).join(&source.name);
        let complete =
            cached_object(app, &source.tenant, &path, source.stamp).is_some_and(|object| {
                cached_catalog_usable(&app.config.data_dir.join("outbound.proofs"), &object)
            });
        if now.saturating_duration_since(since) >= POLL && !complete {
            ready.push(source);
        }
    }
    *observed = next;
    ready.sort_unstable();
    ready
}

fn warm(app: &App, source: &Source) -> io::Result<()> {
    let _operation = begin_outbound_operation(app, &source.tenant)
        .map_err(|_| io::Error::other("library unavailable"))?;
    let root = library_root(app, &source.tenant);
    let path = safe_library_path(app, &source.tenant, &source.name)
        .map_err(|_| io::Error::other("library source unavailable"))?;
    if !library_components_safe(&root, &path)
        || stamp(&std::fs::symlink_metadata(&path)?) != source.stamp
    {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "library source changed",
        ));
    }
    hash_library_file(
        &root,
        &source.name,
        &path,
        &app.config.data_dir.join("outbound.proofs"),
        app.config.max_upload_bytes,
        &source.tenant,
        &app.root_cache,
        None,
        Some(app),
    )?;
    Ok(())
}

pub async fn worker(app: Arc<App>) {
    if !app.config.library_prehash {
        return;
    }
    let mut observed = Observations::new();
    let mut pending = Vec::new();
    let mut scanned = None::<Instant>;
    let mut persisted = Instant::now();
    let mut errors = ErrorDeduper::new("library prehash scan");
    loop {
        if app.is_stopping() || app.lease_lost.load(Ordering::Acquire) {
            return;
        }
        if idle(&app) {
            if scanned.is_none_or(|at| at.elapsed() >= POLL) {
                let scan_app = Arc::clone(&app);
                let mut previous = std::mem::take(&mut observed);
                let result = tokio::task::spawn_blocking(move || {
                    if scan_app
                        .store
                        .resolved_settings(&scan_app.config)
                        .map_err(io::Error::other)?
                        .draining
                    {
                        return Ok((Observations::new(), Vec::new()));
                    }
                    let sources = scan(&scan_app)?;
                    let pending = ready(&scan_app, &mut previous, sources, Instant::now());
                    Ok::<_, io::Error>((previous, pending))
                })
                .await;
                scanned = Some(Instant::now());
                match result {
                    Ok(Ok((next, sources))) => {
                        observed = next;
                        pending = sources;
                        errors.recovered();
                    }
                    result => {
                        pending.clear();
                        let error = format!("{result:?}");
                        if errors.observe(&error, Instant::now()) {
                            tracing::warn!(%error, "library prehash scan failed");
                        }
                    }
                }
            }
            if let Some(source) = pending.pop() {
                let path = library_root(&app, &source.tenant).join(&source.name);
                let hash_lock = library_hash_lock(&app, &path);
                if let Ok(hash_guard) = hash_lock.try_lock_owned() {
                    if LIBRARY_HASH_PERMITS.available_permits() == LIBRARY_HASH_CONCURRENCY {
                        if let Ok(permit) = LIBRARY_HASH_PERMITS.try_acquire() {
                            let worker = Arc::clone(&app);
                            let selected = source.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                let _permit = permit;
                                let _hash_guard = hash_guard;
                                warm(&worker, &selected)
                            })
                            .await;
                            let failed = match result {
                                Ok(Ok(())) => false,
                                Ok(Err(error)) => error.kind() != io::ErrorKind::Interrupted,
                                Err(_) => true,
                            };
                            if failed {
                                if let Some((_, since)) =
                                    observed.get_mut(&(source.tenant, source.name))
                                {
                                    *since = Instant::now() + RETRY;
                                }
                            }
                            if pending.is_empty() || persisted.elapsed() >= POLL {
                                let cache_app = Arc::clone(&app);
                                let _ = tokio::task::spawn_blocking(move || {
                                    cache_app.root_cache.persist()
                                })
                                .await;
                                persisted = Instant::now();
                            }
                            continue;
                        }
                    }
                }
            }
        }
        tokio::select! {
            _ = app.wait_for_shutdown() => return,
            _ = tokio::time::sleep(POLL) => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_for_stable_sources_and_reuses_the_foreground_identity_and_catalog() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let path = app.config.outbound_dir.join("clip.bin");
        let bytes = vec![7; 256 * 1024 + 17];
        std::fs::write(&path, &bytes).unwrap();
        let mut observed = Observations::new();
        let now = Instant::now();
        assert!(ready(&app, &mut observed, scan(&app).unwrap(), now).is_empty());
        assert!(ready(
            &app,
            &mut observed,
            scan(&app).unwrap(),
            now + POLL - Duration::from_nanos(1)
        )
        .is_empty());
        let mut eligible = ready(&app, &mut observed, scan(&app).unwrap(), now + POLL);
        assert_eq!(eligible.len(), 1);
        let source = eligible.pop().unwrap();
        app.outbound_active.lock().unwrap().insert("busy".into());
        assert_eq!(
            warm(&app, &source).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        let (size, mtime, change) = source.stamp;
        assert!(app
            .root_cache
            .lookup("", &path, size, mtime, change)
            .is_none());
        app.outbound_active.lock().unwrap().clear();
        warm(&app, &source).unwrap();
        let expected = prepare_library_file(
            &path,
            Suite::Blake3Bao64,
            None,
            app.config.max_upload_bytes,
            None,
        )
        .unwrap();
        assert_eq!(
            app.root_cache.lookup("", &path, size, mtime, change),
            Some(hex::encode(expected.object_id().root))
        );
        assert!(proof::validate_catalog(
            &std::fs::read(catalog_path(
                &app.config.data_dir.join("outbound.proofs"),
                expected.object_id()
            ))
            .unwrap(),
            expected.object_id()
        )
        .is_ok());
        assert!(ready(&app, &mut observed, scan(&app).unwrap(), now + POLL + POLL).is_empty());
        app.root_cache.persist();
        let reloaded = RootCache::new(&app.config.data_dir);
        let proofs = app.config.data_dir.join("outbound.proofs");
        let catalog = catalog_path(&proofs, expected.object_id());
        let orphan = proofs.join(format!("1-{}-42.vot-catalog", "ab".repeat(32)));
        std::fs::write(&orphan, b"orphan").unwrap();
        crate::app::clean_outbound_proofs(&app.config.data_dir, &app.store, &reloaded, 1);
        assert!(catalog.is_file());
        assert!(!orphan.exists());
        std::fs::write(&catalog, b"corrupt").unwrap();
        assert_eq!(
            ready(&app, &mut observed, scan(&app).unwrap(), now + POLL + POLL).len(),
            1
        );
        app.outbound_active.lock().unwrap().insert("busy".into());
        assert_eq!(
            warm(&app, &source).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        app.outbound_active.lock().unwrap().clear();
        warm(&app, &source).unwrap();
        assert!(cached_catalog_usable(&proofs, expected.object_id()));
        std::fs::write(&path, vec![8; bytes.len() + 1]).unwrap();
        assert_eq!(
            warm(&app, &source).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(ready(&app, &mut observed, scan(&app).unwrap(), now + POLL + POLL).is_empty());
        assert_eq!(
            ready(&app, &mut observed, scan(&app).unwrap(), now + POLL * 3).len(),
            1
        );
        std::fs::remove_file(&path).unwrap();
        assert!(ready(&app, &mut observed, scan(&app).unwrap(), now + POLL * 4).is_empty());
        assert!(observed.is_empty());
    }

    #[test]
    fn scans_nested_files_and_tenants_without_stages_private_snapshots_or_links() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_tenant(crate::store::tests::test_tenant("acme"))
            .unwrap();
        for name in [
            "nested/clip.bin",
            ".scratch/hidden.bin",
            "unfinished.PART",
            ".vot-x.stage",
            ".votport-workflows/private.bin",
        ] {
            let path = app.config.outbound_dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"x").unwrap();
        }
        let tenant = library_root(&app, "acme");
        std::fs::create_dir_all(&tenant).unwrap();
        std::fs::write(tenant.join("own.bin"), b"tenant").unwrap();
        #[cfg(unix)]
        std::fs::write(app.config.outbound_dir.join("bad\\name.bin"), b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(directory.path(), app.config.outbound_dir.join("escape"))
            .unwrap();
        let mut files = scan(&app)
            .unwrap()
            .into_iter()
            .map(|source| (source.tenant, source.name))
            .collect::<Vec<_>>();
        files.sort();
        assert_eq!(
            files,
            [
                (String::new(), "nested/clip.bin".into()),
                ("acme".into(), "own.bin".into())
            ]
        );
        app.lease_lost.store(true, Ordering::Release);
        assert!(!idle(&app));
        assert!(scan(&app).unwrap().is_empty());
    }

    #[tokio::test]
    async fn same_source_shares_one_hash_lock_and_finished_sources_do_not_accumulate() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let first = library_hash_lock(&app, Path::new("one"));
        let same = library_hash_lock(&app, Path::new("one"));
        assert!(Arc::ptr_eq(&first, &same));
        let other = library_hash_lock(&app, Path::new("two"));
        let guard = first.lock().await;
        assert!(same.try_lock().is_err());
        assert!(other.try_lock().is_ok());
        drop(guard);
        drop(first);
        drop(same);
        drop(other);
        let _next = library_hash_lock(&app, Path::new("next"));
        assert_eq!(app.library_hash_locks.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn worker_prepares_a_new_file_without_creating_a_grant_and_stops_cleanly() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.library_prehash = true;
        let app = crate::app::build(config).unwrap();
        let path = app.config.outbound_dir.join("new.bin");
        std::fs::write(&path, vec![9; 128 * 1024]).unwrap();
        let task = tokio::spawn(worker(Arc::clone(&app)));
        let meta = std::fs::metadata(&path).unwrap();
        let (size, mtime, change) = stamp(&meta);
        let warmed = tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                if app
                    .root_cache
                    .lookup("", &path, size, mtime, change)
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        app.request_shutdown();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        warmed.unwrap();
        assert!(app.store.outbound_grants("").unwrap().is_empty());
        assert!(app.config.data_dir.join("outbound-roots.json").is_file());
    }
}
