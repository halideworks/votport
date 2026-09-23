use super::*;

#[cfg(test)]
mod outbound_stage_tests {
    use super::*;

    #[test]
    fn catalog_prune_keeps_active_and_foreign_entries() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("outbound.proofs");
        std::fs::create_dir_all(&root).unwrap();
        let active_root = "00".repeat(32);
        let active = format!("1-{active_root}-10.vot-catalog");
        let stale = format!("2-{}-11.vot-catalog", "11".repeat(32));
        // A leaf cache prunes by the same key as its catalog.
        let active_leaves = format!("1-{active_root}-10.leaves");
        let stale_leaves = format!("2-{}-11.leaves", "11".repeat(32));
        std::fs::write(root.join(&active_leaves), b"leaves").unwrap();
        std::fs::write(root.join(&stale_leaves), b"leaves").unwrap();
        let foreign =
            "1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-12.vot-catalog";
        std::fs::write(root.join(&active), b"active").unwrap();
        std::fs::write(root.join(&stale), b"stale").unwrap();
        std::fs::write(root.join(foreign), b"foreign").unwrap();
        std::fs::write(root.join("operator.txt"), b"operator").unwrap();
        let foreign_stage = root.join(".1-operator.vot-catalog.stage-foreign");
        std::fs::write(&foreign_stage, b"operator").unwrap();
        let owned_stage = root.join(format!(".{active}.stage-{}", "aa".repeat(16)));
        std::fs::write(&owned_stage, b"owned").unwrap();
        // A leaf cache's own stage is also swept.
        let leaf_stage = root.join(format!(".{active_leaves}.stage-{}", "dd".repeat(16)));
        std::fs::write(&leaf_stage, b"leaf-stage").unwrap();
        #[cfg(unix)]
        {
            let stage_link = root.join(format!(".{active}.stage-{}", "bb".repeat(16)));
            std::os::unix::fs::symlink(&owned_stage, &stage_link).unwrap();
            std::os::unix::fs::symlink(
                &stale,
                root.join(format!("2-{}-12.vot-catalog", "22".repeat(32))),
            )
            .unwrap();
        }
        let (keys, unparseable) = active_catalog_names(vec![(
            "grant-1".to_owned(),
            "blake3".to_owned(),
            active_root,
            10,
        )]);
        assert!(unparseable.is_empty());

        prune_outbound_proofs(&root, &keys);

        assert!(root.join(&active).exists());
        assert!(!root.join(stale).exists());
        assert!(
            root.join(&active_leaves).exists(),
            "an active grant's leaves are kept"
        );
        assert!(
            !root.join(&stale_leaves).exists(),
            "a stale grant's leaves are pruned"
        );
        assert!(root.join(foreign).exists());
        assert!(root.join("operator.txt").exists());
        clean_outbound_proof_stages(directory.path());
        assert!(foreign_stage.exists());
        assert!(!owned_stage.exists());
        assert!(!leaf_stage.exists(), "a leaf cache stage is swept");
        #[cfg(unix)]
        assert!(std::fs::symlink_metadata(
            root.join(format!("2-{}-12.vot-catalog", "22".repeat(32)))
        )
        .is_ok());
        #[cfg(unix)]
        assert!(std::fs::symlink_metadata(
            root.join(format!(".{active}.stage-{}", "bb".repeat(16)))
        )
        .is_ok());
    }

    #[test]
    fn startup_cleanup_removes_only_outbound_stage_entries() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("outbound.stage");
        let owned = root.join(".vot-outbound-dead");
        let unrelated = root.join("keep");
        std::fs::create_dir_all(&owned).unwrap();
        std::fs::create_dir_all(&unrelated).unwrap();
        std::fs::write(owned.join("file"), b"staged").unwrap();
        std::fs::write(unrelated.join("file"), b"operator").unwrap();

        clean_outbound_stage(directory.path());

        assert!(!owned.exists());
        assert!(unrelated.join("file").exists());
    }

    #[test]
    fn startup_preserves_unreconciled_files_on_shared_storage() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let stage = app.config.outbound_dir.join(".vot-crash.stage");
        std::fs::write(&stage, b"staged").unwrap();
        release_data_lock(&app);
        drop(app);

        let _app = crate::api::testing::build(directory.path());
        assert_eq!(std::fs::read(&stage).unwrap(), b"staged");
    }

    /// Audit finding 222: without write access both sweeps fail their
    /// removals, and each warn must name the item it could not remove.
    #[test]
    fn startup_cleanup_warns_with_entry_names_when_removals_fail() {
        let directory = tempfile::tempdir().unwrap();
        let stage = directory.path().join("outbound.stage");
        let owned = stage.join(".vot-outbound-dead");
        std::fs::create_dir_all(&owned).unwrap();
        std::fs::write(owned.join("part"), b"staged").unwrap();
        let backups = directory.path().join("backups");
        std::fs::create_dir_all(&backups).unwrap();
        let snapshot = backups.join("votport-1-aaaaaaaa.db");
        std::fs::write(&snapshot, b"snapshot").unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o555)).unwrap();

        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            clean_outbound_stage(directory.path());
            // A future cutoff makes the fresh snapshot count as expired.
            prune_legacy_snapshots(
                &backups,
                std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
            );
        });
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o755)).unwrap();

        let text = std::fs::read_to_string(log.path()).unwrap();
        let stage_warn = text
            .lines()
            .find(|line| line.contains("outbound stage cleanup failed"))
            .expect("the stage removal warns");
        assert!(stage_warn.contains(".vot-outbound-dead"), "{stage_warn}");
        let snapshot_warn = text
            .lines()
            .find(|line| line.contains("legacy snapshot removal failed"))
            .expect("the snapshot removal warns");
        assert!(
            snapshot_warn.contains("votport-1-aaaaaaaa.db"),
            "{snapshot_warn}"
        );
    }

    /// Audit finding 223: a grant whose suite does not parse cannot name its
    /// catalogs, so the prune must keep every catalog and warn with the
    /// grant's identity instead of pruning against a partial keep set.
    #[test]
    fn unparseable_grant_keeps_its_catalog_and_warns_with_identity() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let now = crate::store::now_unix();
        app.store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO outbound_grants(id, token_hash, tenant, link_id, upload_id,
                        package_root, name, suite, root, file_index, bytes_hi, bytes_lo,
                        label, created_at, expires_at, downloads)
                     VALUES ('grant-unparseable', 'hash', 'team', 'link', 'upload',
                        'root', 'file.txt', 'md5', 'root', 0, 0, 8,
                        'Delivery', 0, ?1, 0)",
                    rusqlite::params![i64::try_from(now + 3600).unwrap()],
                )
            })
            .unwrap();
        UNPARSEABLE_GRANT_WARN
            .get_or_init(|| {
                Mutex::new(crate::api::outbound::ErrorDeduper::new(
                    "unparseable outbound grant",
                ))
            })
            .lock()
            .unwrap()
            .reset();
        let root = app.config.data_dir.join("outbound.proofs");
        std::fs::create_dir_all(&root).unwrap();
        let stale = format!("2-{}-11.vot-catalog", "11".repeat(32));
        std::fs::write(root.join(&stale), b"stale").unwrap();

        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            clean_outbound_proofs(&app.config.data_dir, &app.store, now);
        });

        assert!(
            root.join(&stale).exists(),
            "conservative retention keeps every catalog when a grant does not parse"
        );
        let text = std::fs::read_to_string(log.path()).unwrap();
        let warn = text
            .lines()
            .find(|line| line.contains("outbound grant does not parse"))
            .expect("the unparseable grant warns");
        assert!(warn.contains("grant-unparseable"), "{warn}");
        assert!(warn.contains("unknown suite md5"), "{warn}");
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    /// Audit finding 553: main binds the listener before app::build opens
    /// the store, so a long migration holds connections in the listen
    /// backlog instead of leaving healthz refusing connections for the
    /// whole startup. The startup sequence lives in main, so the order is
    /// pinned against the binary source itself.
    #[test]
    fn startup_binds_the_listener_before_the_store_opens() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let bind = source
            .find("TcpListener::bind")
            .expect("the http listener still binds");
        let build = source
            .find("app::build(config)")
            .expect("startup still builds the app");
        assert!(
            bind < build,
            "the listener must bind before app::build opens the store"
        );
    }

    /// Audit finding 564: SIGTERM drains HTTP but does not cancel an
    /// in-flight storage export, so the compose stop grace period carries
    /// the line tying the deadline to the export time of the largest single
    /// file; a SIGKILL at the deadline is what orphans the multipart upload.
    #[test]
    fn the_stop_grace_period_doc_ties_the_deadline_to_the_largest_single_file() {
        let compose = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../docker-compose.yml"
        ));
        let grace = compose
            .find("stop_grace_period")
            .expect("the compose stop grace period stays configured");
        assert!(
            compose[..grace].contains("largest single file"),
            "the comment above the grace period must tie it to the largest single file"
        );
    }

    #[test]
    fn receiving_checks_do_not_hold_ownership_state_or_delay_renewal() {
        use std::time::{Duration, Instant};
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let destinations = app.receiving_destinations().unwrap();
        let pause = crate::receiving::CheckPause::new(&destinations, 1);
        let checking = app.clone();
        let worker = std::thread::spawn(move || checking.receiving_destinations());
        let deadline = Instant::now() + Duration::from_secs(1);
        while pause.entered() == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pause.entered(), 1);
        let state_available = app.receiving.try_lock().is_ok();
        let renewing = app.clone();
        let (done, completed) = std::sync::mpsc::channel();
        let renewal = std::thread::spawn(move || {
            done.send(renew_lease(&renewing, now_unix())).unwrap();
        });
        let renewed = completed.recv_timeout(Duration::from_millis(500)).ok();
        pause.release();
        worker.join().unwrap().unwrap();
        renewal.join().unwrap();
        assert!(
            state_available,
            "currentness check held the ownership mutex"
        );
        assert_eq!(renewed, Some(true), "currentness check blocked renewal");
    }

    #[tokio::test]
    async fn receiving_checks_keep_their_bound_after_request_cancellation() {
        use std::time::Duration;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let destinations = app.receiving_destinations().unwrap();
        let pause = crate::receiving::CheckPause::new(&destinations, usize::MAX);
        let mut requests = Vec::new();
        for _ in 0..24 {
            let app = app.clone();
            requests.push(tokio::spawn(async move {
                app.receiving_destinations_async().await
            }));
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while pause.entered() < 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(pause.entered(), 8, "only eight checks may reach storage");
        for request in requests {
            request.abort();
            assert!(matches!(request.await, Err(error) if error.is_cancelled()));
        }
        let mut later = Vec::new();
        for _ in 0..12 {
            let app = app.clone();
            later.push(tokio::spawn(async move {
                app.receiving_destinations_async().await
            }));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            pause.entered(),
            8,
            "cancellation must not release running checks"
        );
        assert!(later.iter().all(|request| !request.is_finished()));
        pause.release();
        for request in later {
            tokio::time::timeout(Duration::from_secs(2), request)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.receiving_permits.available_permits() != 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(pause.entered(), 20, "cancelled waiters must never run");
        assert_eq!(app.receiving_permits.available_permits(), 8);
    }

    #[tokio::test]
    async fn receiving_renewal_waits_off_the_executor_and_keeps_ownership() {
        use std::time::{Duration, Instant};
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let destinations = app.receiving_destinations().unwrap();
        let pause = crate::receiving::CheckPause::new(&destinations, 1);
        let worker = app.clone();
        let renewal = tokio::spawn(async move { renew_lease_once(&worker).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while pause.entered() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let started = Instant::now();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!renewal.is_finished());
        assert!(app.receiving.try_lock().is_ok());
        release_data_lock(&app);
        assert!(lock_data_dir(&app.config.data_dir).is_err());
        assert!(crate::lease::Guard::acquire(
            &vot_platform_fs::Directory::open(&app.config.receive_dir).unwrap(),
            "other",
            now_unix()
        )
        .is_err());
        pause.release();
        assert!(!tokio::time::timeout(Duration::from_secs(2), renewal)
            .await
            .unwrap()
            .unwrap());
        assert!(destinations.check_current().is_err());
        release_data_lock(&app);
        assert!(lock_data_dir(&app.config.data_dir).is_ok());
        assert!(crate::lease::Guard::acquire(
            &vot_platform_fs::Directory::open(&app.config.receive_dir).unwrap(),
            "other",
            now_unix()
        )
        .is_ok());
    }

    #[test]
    fn receiving_shutdown_keeps_queued_check_and_reconfiguration_fences() {
        for reconfigure in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let app = crate::api::testing::build(directory.path());
            let permit = if reconfigure {
                &app.receiving_reconfigure
            } else {
                &app.receiving_permits
            }
            .clone()
            .try_acquire_owned()
            .unwrap();
            release_data_lock(&app);
            assert!(lock_data_dir(&app.config.data_dir).is_err());
            assert!(crate::lease::Guard::acquire(
                &vot_platform_fs::Directory::open(&app.config.receive_dir).unwrap(),
                "other",
                now_unix()
            )
            .is_err());
            assert!(app.receiving_permits.is_closed());
            assert!(app.receiving_reconfigure.is_closed());
            drop(permit);
            release_data_lock(&app);
            assert!(lock_data_dir(&app.config.data_dir).is_ok());
            assert!(crate::lease::Guard::acquire(
                &vot_platform_fs::Directory::open(&app.config.receive_dir).unwrap(),
                "other",
                now_unix()
            )
            .is_ok());
        }
    }

    async fn wait_health_idle(app: &App) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while app.health.state.lock().unwrap().running {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    struct PausedHealth {
        release: std::sync::mpsc::Sender<()>,
        holder: Option<std::thread::JoinHandle<()>>,
    }

    impl PausedHealth {
        fn new(app: &Arc<App>, receiving: bool) -> Self {
            let app = app.clone();
            let (entered, waiting) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            let holder = std::thread::spawn(move || {
                let pause = || {
                    entered.send(()).unwrap();
                    let _ = released.recv_timeout(std::time::Duration::from_secs(8));
                };
                if receiving {
                    let _state = app.receiving.lock().unwrap();
                    pause();
                } else {
                    app.store
                        .with(|_| {
                            pause();
                            Ok(())
                        })
                        .unwrap();
                }
            });
            waiting
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            Self {
                release,
                holder: Some(holder),
            }
        }
    }

    impl Drop for PausedHealth {
        fn drop(&mut self) {
            let _ = self.release.send(());
            self.holder.take().unwrap().join().unwrap();
        }
    }

    async fn blocked_health_request(path: &str) {
        use std::time::{Duration, Instant};
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let store = app.store.clone();
        let (entered, waiting) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            store
                .with(|_| {
                    entered.send(()).unwrap();
                    let _ = released.recv_timeout(Duration::from_secs(3));
                    Ok(())
                })
                .unwrap();
        });
        waiting.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        let (response, timer_elapsed) = tokio::join!(
            router(app.clone()).oneshot(Request::get(path).body(Body::empty()).unwrap()),
            async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                started.elapsed()
            },
        );
        let elapsed = started.elapsed();
        let _ = release.send(());
        holder.join().unwrap();
        wait_health_idle(&app).await;
        assert!(
            timer_elapsed < Duration::from_millis(500),
            "{path} blocked the async timer for {timer_elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "{path} waited {elapsed:?}"
        );
        assert_eq!(response.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn health_routes_do_not_block_healthz_on_sqlite() {
        blocked_health_request("/healthz").await;
    }

    #[tokio::test]
    async fn health_routes_do_not_block_readyz_on_sqlite() {
        blocked_health_request("/readyz").await;
    }

    #[tokio::test]
    async fn cancelled_health_requests_leave_only_one_blocking_probe() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let pause = PausedHealth::new(&app, false);
        let request = tokio::spawn(
            router(app.clone()).oneshot(Request::get("/healthz").body(Body::empty()).unwrap()),
        );
        tokio::time::timeout(HEALTH_WAIT, async {
            while app.health.probes.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        tokio::time::sleep(HEALTH_WAIT + std::time::Duration::from_millis(50)).await;
        let mut statuses = Vec::new();
        let started = std::time::Instant::now();
        for index in 0..20 {
            let path = if index % 2 == 0 {
                "/healthz"
            } else {
                "/readyz"
            };
            statuses.push(
                router(app.clone())
                    .oneshot(Request::get(path).body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
            );
        }
        let elapsed = started.elapsed();
        let probes = app.health.probes.load(Ordering::Relaxed);
        drop(pause);
        wait_health_idle(&app).await;
        assert!(statuses
            .iter()
            .all(|status| *status == StatusCode::SERVICE_UNAVAILABLE));
        assert!(elapsed < HEALTH_WAIT, "busy requests waited {elapsed:?}");
        assert_eq!(probes, 1);
        assert!(
            app.health
                .state
                .lock()
                .unwrap()
                .snapshot
                .as_ref()
                .unwrap()
                .healthy
        );
    }

    #[tokio::test]
    async fn shared_health_cache_expires_and_never_refreshes_an_over_age_probe() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        assert!(health_snapshot(&app).await.unwrap().healthy);
        let response = router(app.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 1);
        app.health
            .state
            .lock()
            .unwrap()
            .snapshot
            .as_mut()
            .unwrap()
            .started -= HEALTH_TTL;
        let pause = PausedHealth::new(&app, false);
        let started = std::time::Instant::now();
        assert!(health_snapshot(&app).await.is_none());
        assert!(health_snapshot(&app).await.is_none());
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 2);
        tokio::time::sleep(
            HEALTH_TTL.saturating_sub(started.elapsed()) + std::time::Duration::from_millis(50),
        )
        .await;
        drop(pause);
        wait_health_idle(&app).await;
        assert!(!app
            .health
            .state
            .lock()
            .unwrap()
            .snapshot
            .as_ref()
            .unwrap()
            .fresh(app.store.settings_generation()));
        assert!(health_snapshot(&app).await.unwrap().healthy);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn failed_health_probes_are_cached_and_panics_are_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        std::fs::remove_dir(&app.config.outbound_dir).unwrap();
        assert!(!health_snapshot(&app).await.unwrap().healthy);
        assert!(!health_snapshot(&app).await.unwrap().healthy);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 1);
        std::fs::create_dir(&app.config.outbound_dir).unwrap();
        app.health
            .state
            .lock()
            .unwrap()
            .snapshot
            .as_mut()
            .unwrap()
            .started -= HEALTH_TTL;
        let store = app.store.clone();
        assert!(std::thread::spawn(move || {
            let _ = store.with::<()>(|_| panic!("fixture store poison"));
        })
        .join()
        .is_err());
        assert!(!health_snapshot(&app).await.unwrap().healthy);
        assert!(!health_snapshot(&app).await.unwrap().healthy);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn shutdown_retains_both_fences_until_a_health_probe_finishes() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let pause = PausedHealth::new(&app, true);
        assert!(health_snapshot(&app).await.is_none());
        let started = std::time::Instant::now();
        release_data_lock(&app);
        let elapsed = started.elapsed();
        let data_refused = build(app.config.clone()).is_err();
        let mut standby = app.config.clone();
        standby.data_dir = directory.path().join("standby");
        let receive_refused = build(standby.clone()).is_err();
        let frozen = health_snapshot(&app).await.is_none();
        drop(pause);
        wait_health_idle(&app).await;
        assert!(
            elapsed < HEALTH_WAIT,
            "release waited on a running probe: {elapsed:?}"
        );
        assert!(
            data_refused && receive_refused,
            "both fences must remain held"
        );
        assert!(frozen);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 1);
        assert!(health_snapshot(&app).await.is_none());
        release_data_lock(&app);
        let standby = build(standby).unwrap();
        release_data_lock(&standby);
    }

    #[test]
    fn an_outstanding_health_probe_does_not_delay_process_exit() {
        const ROOT: &str = "VOTPORT_TEST_HEALTH_PROBE_EXIT";
        if let Some(root) = std::env::var_os(ROOT) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let app = crate::api::testing::build(std::path::Path::new(&root));
                let _pause = PausedHealth::new(&app, true);
                assert!(health_snapshot(&app).await.is_none());
                assert!(app.health.state.lock().unwrap().running);
                std::process::exit(0);
            });
            unreachable!();
        }
        let directory = tempfile::tempdir().unwrap();
        let log = std::fs::File::create(directory.path().join("child.log")).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "app::tests::health_tests::an_outstanding_health_probe_does_not_delay_process_exit",
                "--nocapture",
            ])
            .env(ROOT, directory.path())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let outcome = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            outcome.is_some_and(|status| status.success()),
            "probe shutdown failed: {}",
            std::fs::read_to_string(directory.path().join("child.log")).unwrap()
        );
        use std::os::unix::fs::MetadataExt as _;
        let config = crate::api::testing::config(directory.path());
        let record = crate::lease::path(&config.receive_dir);
        let previous: crate::lease::Lease =
            serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
        let lock = record.parent().unwrap().join("writer.lock");
        let inode = std::fs::metadata(&lock).unwrap().ino();
        let app = crate::api::testing::build(directory.path());
        let current: crate::lease::Lease =
            serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
        assert_ne!(previous.holder, current.holder);
        assert_eq!(current.holder, app.lease_holder);
        assert_eq!(std::fs::metadata(&lock).unwrap().ino(), inode);
        release_data_lock(&app);
    }

    #[tokio::test]
    async fn health_settings_generation_tracks_successful_writes_and_resets() {
        use crate::store::SettingWrite;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(false));
        app.store
            .put_settings(
                "fixture",
                &[("draining".into(), SettingWrite::Set("1".into()))],
            )
            .unwrap();
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(true));
        let generation = app.store.settings_generation();
        let probes = app.health.probes.load(Ordering::Relaxed);
        app.store.with(|c| c.execute_batch(
            "CREATE TRIGGER refuse_settings BEFORE INSERT ON settings BEGIN SELECT RAISE(FAIL,'fixture refusal'); END;
             CREATE TRIGGER refuse_reset BEFORE DELETE ON settings BEGIN SELECT RAISE(FAIL,'fixture refusal'); END;"
        )).unwrap();
        assert!(app
            .store
            .put_settings(
                "fixture",
                &[("draining".into(), SettingWrite::Set("0".into()))]
            )
            .is_err());
        assert!(app.store.delete_setting("draining").is_err());
        assert_eq!(app.store.settings_generation(), generation);
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(true));
        assert_eq!(app.health.probes.load(Ordering::Relaxed), probes);
        app.store
            .with(|c| c.execute_batch("DROP TRIGGER refuse_settings; DROP TRIGGER refuse_reset;"))
            .unwrap();
        app.store.delete_setting("draining").unwrap();
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(false));
        app.store
            .put_settings(
                "fixture",
                &[("draining".into(), SettingWrite::Set("1".into()))],
            )
            .unwrap();
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(true));
        app.store
            .put_settings("fixture", &[("draining".into(), SettingWrite::Reset)])
            .unwrap();
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(false));
        assert_eq!(app.health.probes.load(Ordering::Relaxed), probes + 3);
    }

    #[tokio::test]
    async fn settings_changed_during_a_probe_invalidate_its_result() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let pause = PausedHealth::new(&app, true);
        assert!(health_snapshot(&app).await.is_none());
        app.store
            .put_settings(
                "fixture",
                &[(
                    "draining".into(),
                    crate::store::SettingWrite::Set("1".into()),
                )],
            )
            .unwrap();
        drop(pause);
        wait_health_idle(&app).await;
        assert!(!app
            .health
            .state
            .lock()
            .unwrap()
            .snapshot
            .as_ref()
            .unwrap()
            .fresh(app.store.settings_generation()));
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(true));
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn cached_readiness_keeps_live_sessions_and_lease_loss() {
        use http_body_util::BodyExt as _;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        assert!(health_snapshot(&app).await.unwrap().healthy);
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        app.sessions
            .insert_resumed("live".into(), "link".into(), String::new(), 0, sender)
            .unwrap();
        let response = router(app.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["sessions_active"], 1);
        app.sessions.remove("live");
        app.lease_lost.store(true, Ordering::Relaxed);
        let response = router(app.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["sessions_active"], 0);
        assert_eq!(json["lease"]["lost"], true);
        assert_eq!(json["lease"]["mine"], false);
        assert!(json["lease"]["holder"].is_null());
        assert!(json["lease"]["age_secs"].is_null());
        let response = router(app.clone())
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn healthz_is_public_and_probes_database_and_directories() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let receive = app.config.receive_dir.clone();
        let outbound = app.config.outbound_dir.clone();
        let response = router(app)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert!(std::fs::read_dir(receive)
            .unwrap()
            .flatten()
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".votport-health-")));
        assert!(std::fs::read_dir(outbound)
            .unwrap()
            .flatten()
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".votport-health-")));
    }

    #[tokio::test]
    async fn strict_transport_security_follows_the_https_public_origin() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let response = router(app)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.headers()[header::STRICT_TRANSPORT_SECURITY],
            "max-age=31536000"
        );

        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.public_url = Some("http://localhost:8103".to_owned());
        let app = crate::app::build(config).unwrap();
        let response = router(app)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(!response
            .headers()
            .contains_key(header::STRICT_TRANSPORT_SECURITY));
    }

    #[tokio::test]
    async fn suspension_deadline_includes_a_full_worker_queue() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let (reply, _done) = tokio::sync::oneshot::channel();
        sender.send(session::Cmd::Suspend { reply }).await.unwrap();
        app.sessions
            .insert_resumed("blocked".into(), "link".into(), String::new(), 0, sender)
            .unwrap();
        let (sender, mut healthy) = tokio::sync::mpsc::channel(1);
        app.sessions
            .insert_resumed("healthy".into(), "link".into(), String::new(), 0, sender)
            .unwrap();
        let shutdown = tokio::spawn({
            let app = app.clone();
            async move { suspend_sessions(&app).await }
        });
        let Some(session::Cmd::Suspend { reply }) =
            tokio::time::timeout(std::time::Duration::from_secs(1), healthy.recv())
                .await
                .unwrap()
        else {
            panic!("a blocked worker must not prevent another worker suspending");
        };
        reply.send(Ok(())).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(35), shutdown)
            .await
            .expect("a full worker queue must not bypass the 30-second shutdown deadline")
            .unwrap();
        assert_eq!(receiver.len(), 1);
        assert!(
            !receiver.is_closed(),
            "a timed-out sender must not trigger EOF cleanup of partial files"
        );
        assert_eq!(app.sessions.total(), 0);
        receiver.recv().await.unwrap();
        let Some(session::Cmd::Suspend { reply }) =
            tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                .await
                .unwrap()
        else {
            panic!("the pending suspension must still reach a recovered worker");
        };
        reply.send(Ok(())).unwrap();
    }

    /// Drives `suspend_sessions` against manually answered workers and
    /// returns the log records it emitted, so the summary can be pinned
    /// without asserting on a real NAS checkpoint.
    async fn suspend_summary_records(
        app: std::sync::Arc<App>,
        answers: Vec<Result<(), String>>,
    ) -> Vec<serde_json::Value> {
        use tracing::instrument::WithSubscriber;
        let mut receivers = Vec::new();
        for (index, _) in answers.iter().enumerate() {
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            app.sessions
                .insert_resumed(
                    format!("worker-{index}"),
                    "link".into(),
                    String::new(),
                    0,
                    sender,
                )
                .unwrap();
            receivers.push(receiver);
        }
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        let suspend =
            tokio::spawn(async move { suspend_sessions(&app).await }.with_subscriber(subscriber));
        for (mut receiver, answer) in receivers.into_iter().zip(answers) {
            let Some(session::Cmd::Suspend { reply }) =
                tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                    .await
                    .unwrap()
            else {
                panic!("suspend must reach every worker");
            };
            let _ = reply.send(answer);
        }
        tokio::time::timeout(std::time::Duration::from_secs(35), suspend)
            .await
            .unwrap()
            .unwrap();
        std::fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn suspend_summary_counts_only_persisted_sessions() {
        use tracing::instrument::WithSubscriber;
        let failure = "checkpoint failed; staging kept".to_owned();
        // Mixed through the real path: only the persisted session counts
        // toward the suspended total and the failure is named.
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let records = suspend_summary_records(
            app,
            vec![Ok(()), Err(failure.clone()), Err(failure.clone())],
        )
        .await;
        let summary = records
            .iter()
            .find(|record| {
                record["fields"]["message"].as_str().is_some_and(|message| {
                    message.contains("suspended upload sessions with failures")
                })
            })
            .unwrap_or_else(|| panic!("no suspend summary in {records:?}"));
        assert_eq!(summary["fields"]["suspended"], 1);
        assert_eq!(summary["fields"]["failed"], 2);
        assert!(
            summary["fields"]["message"]
                .as_str()
                .unwrap()
                .contains(&failure),
            "failures must be named: {summary}"
        );
        // All-fail: zero sessions count toward the suspended total.
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        async {
            summarize_suspend(vec![Some(Err(failure.clone())), Some(Err(failure.clone()))]);
        }
        .with_subscriber(subscriber)
        .await;
        let records: Vec<serde_json::Value> = std::fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let summary = records
            .iter()
            .find(|record| {
                record["fields"]["message"].as_str().is_some_and(|message| {
                    message.contains("suspended upload sessions with failures")
                })
            })
            .unwrap_or_else(|| panic!("no suspend summary in {records:?}"));
        assert_eq!(summary["fields"]["suspended"], 0);
        assert_eq!(summary["fields"]["failed"], 2);
        assert!(
            summary["fields"]["message"]
                .as_str()
                .unwrap()
                .contains(&failure),
            "failures must be named: {summary}"
        );
    }

    #[tokio::test]
    async fn readyz_follows_draining_and_healthz_does_not() {
        use http_body_util::BodyExt as _;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let response = router(app.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ready"], true);
        assert_eq!(json["draining"], false);
        assert_eq!(json["sessions_active"], 0);

        app.store
            .put_settings(
                "test",
                &[(
                    "draining".to_owned(),
                    crate::store::SettingWrite::Set("1".to_owned()),
                )],
            )
            .unwrap();
        let response = router(app.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ready"], false);
        assert_eq!(json["draining"], true);
        let response = router(app)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_reports_process_stop_without_waiting_for_health() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.request_shutdown();
        let response = router(app)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["ready"], false);
        assert_eq!(value["draining"], true);
    }

    #[tokio::test]
    async fn shutdown_waiter_observes_stop_requested_before_it_starts() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.request_shutdown();
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            app.wait_for_shutdown(),
        )
        .await
        .expect("persistent stop state wakes late waiter");
        assert!(app
            .shutdown_deadline(std::time::Duration::from_secs(240))
            .is_some());
        app.request_shutdown();
        assert!(app.is_stopping());
    }

    #[tokio::test]
    async fn readyz_is_unavailable_when_storage_cannot_be_probed() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        std::fs::remove_dir_all(&app.config.receive_dir).unwrap();
        let response = router(app)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_second_instance_on_the_same_receive_root_refuses_to_boot_and_readyz_shows_the_lease()
    {
        use http_body_util::BodyExt as _;
        let directory = tempfile::tempdir().unwrap();
        let first = crate::api::testing::build(directory.path());
        // Its own data directory, so only the receive-root lease can refuse it.
        let mut config = crate::api::testing::config(&directory.path().join("standby"));
        config.receive_dir = first.config.receive_dir.clone();
        let error = match build(config.clone()) {
            Ok(_) => panic!("second instance booted over a live lease"),
            Err(error) => error,
        };
        assert!(error.contains(".votport-lease is held by"), "{error}");
        assert!(error.contains(&first.lease_holder), "{error}");

        let response = router(first.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["lease"]["holder"], first.lease_holder);
        assert_eq!(json["lease"]["mine"], true);
        assert_eq!(json["lease"]["lost"], false);
        assert!(json["lease"]["age_secs"].as_u64().unwrap() < 5);
        let metrics = metrics_text(&first).unwrap();
        assert!(metrics.contains("votport_lease_held 1\n"), "{metrics}");

        // Once the holder is gone and its clock has run out, the standby
        // takes over; the old holder's next heartbeat learns it lost.
        let path = crate::lease::path(&first.config.receive_dir);
        let stale = crate::lease::Lease {
            holder: first.lease_holder.clone(),
            acquired_at: 1,
            renewed_at: 1,
        };
        release_data_lock(&first);
        assert!(!path.exists(), "a clean shutdown yields the lease");
        std::fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
        let standby = build(config).unwrap();
        assert!(!renew_lease(&first, crate::store::now_unix()));
        assert!(first.lease_lost.load(Ordering::Relaxed));
        assert!(!renew_lease(&first, crate::store::now_unix()), "stays lost");
        assert!(renew_lease(&standby, crate::store::now_unix()));
        let response = router(first.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["lease"]["lost"], true);
        assert_eq!(json["lease"]["mine"], false);
        assert!(json["lease"]["holder"].is_null());
        assert!(metrics_text(&first)
            .unwrap()
            .contains("votport_lease_held 0\n"));
        assert!(metrics_text(&standby)
            .unwrap()
            .contains("votport_lease_held 1\n"));
    }

    #[test]
    fn a_boot_that_fails_after_taking_the_lease_gives_it_back() {
        let directory = tempfile::tempdir().unwrap();
        let config = crate::api::testing::config(directory.path());
        // A directory where the database file belongs makes Store::open
        // fail, which is after the lease is taken.
        std::fs::create_dir_all(config.data_dir.join("votport.db")).unwrap();
        assert!(build(config.clone()).is_err());
        assert!(
            !crate::lease::path(&config.receive_dir).exists(),
            "the failed boot must not leave its lease behind"
        );
        std::fs::remove_dir_all(config.data_dir.join("votport.db")).unwrap();
        build(config).unwrap();
    }

    #[test]
    fn overlapping_storage_roots_fail_before_store_open() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.outbound_dir = config.data_dir.join("library");
        let error = build(config.clone())
            .err()
            .expect("overlapping roots booted");
        assert!(error.contains("VOTPORT_DATA_DIR"), "{error}");
        assert!(error.contains("VOTPORT_OUTBOUND_DIR"), "{error}");
        assert!(!config.data_dir.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let directory = tempfile::tempdir().unwrap();
            let mut config = crate::api::testing::config(directory.path());
            std::fs::create_dir_all(&config.data_dir).unwrap();
            let alias = directory.path().join("received-alias");
            symlink(&config.data_dir, &alias).unwrap();
            config.receive_dir = alias;
            let error = build(config.clone()).err().expect("symlink alias booted");
            assert!(error.contains("VOTPORT_DATA_DIR"), "{error}");
            assert!(error.contains("VOTPORT_RECEIVE_DIR"), "{error}");
            assert!(!config.data_dir.join("votport.db").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_second_instance_on_the_same_data_directory_refuses_to_boot() {
        let directory = tempfile::tempdir().unwrap();
        let first = crate::api::testing::build(directory.path());
        let error = match build(crate::api::testing::config(directory.path())) {
            Ok(_) => panic!("second instance booted over a held data directory"),
            Err(error) => error,
        };
        assert!(error.contains("held by another votport process"), "{error}");
        release_data_lock(&first);
        drop(first);
        crate::api::testing::build(directory.path());
    }

    #[tokio::test]
    async fn healthz_returns_generic_unavailable_when_storage_cannot_be_probed() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let outbound = app.config.outbound_dir.clone();
        std::fs::remove_dir_all(&outbound).unwrap();
        std::fs::write(&outbound, b"not a directory").unwrap();

        let response = router(app)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
    }

    #[tokio::test]
    async fn healthz_returns_unavailable_when_database_schema_cannot_be_read() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let connection =
            rusqlite::Connection::open(app.config.data_dir.join("votport.db")).unwrap();
        connection.execute_batch("DROP TABLE meta").unwrap();

        let response = router(app)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn lease_loss_writes_an_audit_row_and_counts_the_loss() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let path = crate::lease::path(&app.config.receive_dir);
        // Another writer overwrites the lease file while we still hold the
        // lock: the next heartbeat is the takeover path.
        std::fs::write(
            &path,
            br#"{"holder":"other-instance","acquired_at":1,"renewed_at":1}"#,
        )
        .unwrap();

        assert!(!renew_lease(&app, crate::store::now_unix()));
        assert!(app.lease_lost.load(Ordering::Relaxed));
        assert_eq!(app.lease_lost_total.load(Ordering::Relaxed), 1);
        assert!(!app.mount_disqualified.load(Ordering::Relaxed));
        let rows = app.store.audit_recent(None, u64::MAX, 10).unwrap();
        let lost = rows
            .iter()
            .find(|row| row.event == "lease_lost")
            .expect("lease takeover writes an audit row");
        assert_eq!(lost.detail["holder"], app.lease_holder.as_str());
        assert!(metrics_text(&app)
            .unwrap()
            .contains("votport_lease_lost_total 1\n"));
        release_data_lock(&app);
    }

    #[tokio::test]
    async fn a_remounted_receive_root_is_reported_as_mount_disqualified() {
        use http_body_util::BodyExt as _;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        // Swap the directory under the held path, the way a remount onto a
        // new filesystem would: the stored identity no longer matches.
        let receive = app.config.receive_dir.clone();
        let moved = receive.with_extension("moved");
        std::fs::rename(&receive, &moved).unwrap();
        std::fs::create_dir(&receive).unwrap();

        assert!(!renew_lease(&app, crate::store::now_unix()));
        assert!(app.mount_disqualified.load(Ordering::Relaxed));
        assert!(app.lease_lost.load(Ordering::Relaxed));
        assert_eq!(app.lease_lost_total.load(Ordering::Relaxed), 0);
        let rows = app.store.audit_recent(None, u64::MAX, 10).unwrap();
        let disqualified = rows
            .iter()
            .find(|row| row.event == "mount_disqualified")
            .expect("a remount writes its own audit row");
        assert_eq!(disqualified.detail["holder"], app.lease_holder.as_str());
        assert!(disqualified.detail["error"]
            .as_str()
            .unwrap()
            .contains("receiving folder or mount changed"));
        let response = router(app.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["mount"]["disqualified"], true);
        assert_eq!(json["ready"], false);
        release_data_lock(&app);
    }

    #[test]
    fn metrics_reports_the_maintained_audit_count() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .audit("", "", "metrics_test", "row", &serde_json::json!({}));

        let metrics = metrics_text(&app).unwrap();
        assert!(metrics.contains("votport_audit_rows 1\n"));
        assert!(metrics.contains("votport_delivery_event_chain_failures_total "));
    }

    #[test]
    fn metrics_expose_the_detectable_failure_states() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let document = serde_json::json!({
            "id":"d1","revision":1,"label":"Ops","channel":"webhook",
            "target":"https://example.test/hook","enabled":true,
            "url":"https://example.test/hook","token":"","user":"",
            "recipients":[],"thread_id":""
        })
        .to_string();
        app.store
            .with(|c| {
                c.execute(
                    "INSERT INTO notification_destinations(id,tenant,document,last_at,last_delivered) VALUES('d1','fixture',?1,1,0)",
                    [&document],
                )?;
                c.execute(
                    "INSERT INTO delivery_webhook_attempts(tenant,event_id,revision,status,attempts,next_try) VALUES('fixture',1,1,'dead',12,0)",
                    [],
                )?;
                c.execute(
                    "INSERT INTO trade_routes(id,tenant,direction,peer_key,endpoint,document,credential) VALUES('r1','fixture','inbound','peer','endpoint','{\"state\":\"unreachable\"}','secret')",
                    [],
                )?;
                Ok(())
            })
            .unwrap();

        let metrics = metrics_text(&app).unwrap();
        for line in [
            "votport_backup_failing 0\n",
            "votport_standby_lag_seconds 0\n",
            "votport_notification_destinations_failing 1\n",
            "votport_webhook_attempts_dead 1\n",
            "votport_trade_routes_unreachable 1\n",
            "votport_retention_sweep_failures_total 0\n",
            "votport_migration_pending 0\n",
            "votport_lease_lost_total 0\n",
        ] {
            assert!(metrics.contains(line), "expected metrics line {line}");
        }

        // An enabled backup whose last attempt failed counts as failing.
        std::fs::write(
            app.config.data_dir.join("backup-status.json"),
            br#"{"running":false,"last_attempt_at":1,"last_success_at":null,"last_error":"disk full"}"#,
        )
        .unwrap();
        app.store
            .put_settings(
                "test",
                &[(
                    crate::backup::SETTING_KEY.to_owned(),
                    crate::store::SettingWrite::Set(
                        serde_json::to_string(&crate::backup::BackupConfig {
                            enabled: true,
                            interval_secs: 86_400,
                            ..Default::default()
                        })
                        .unwrap(),
                    ),
                )],
            )
            .unwrap();
        let metrics = metrics_text(&app).unwrap();
        assert!(metrics.contains("votport_backup_failing 1\n"));
    }
}

#[cfg(test)]
mod shutdown_process_tests {
    use super::*;

    use std::future::IntoFuture;

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    use vot_sdk::object::{InMemoryObjectBuilder, Suite};
    use vot_sdk::package::{PackageBuilder, PackageEntry};

    const CHILD_ROOT: &str = "VOTPORT_TEST_SHUTDOWN_CHILD_ROOT";
    const EXPECTED_PREFIX_BYTES: u64 = 64 * 1024;

    async fn send_request(
        application: &Arc<App>,
        request: Request<Body>,
    ) -> axum::response::Response {
        router(Arc::clone(application))
            .oneshot(request)
            .await
            .unwrap()
    }

    fn connect_info(request: &mut Request<Body>) {
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                43210,
            ))));
    }

    async fn child_setup_and_checkpoint(root: &std::path::Path) {
        let application = crate::api::testing::build(root);
        application
            .store
            .insert_link(crate::store::tests::test_link("child"))
            .unwrap();

        let bytes = vec![7u8; 128 * 1024];
        let mut object = InMemoryObjectBuilder::new(
            Suite::Blake3Bao64,
            Some(bytes.len() as u64),
            bytes.len() as u64,
        )
        .unwrap();
        object.update(&bytes).unwrap();
        let prepared = object.finish().unwrap();
        let mut package = PackageBuilder::new().unwrap();
        let entry =
            PackageEntry::direct(vec!["partial.bin".to_owned()], prepared.object_id()).unwrap();
        assert!(package.push(&entry).unwrap().is_none());
        let (summary, final_page, mut finalizer) = package.finish().unwrap().into_parts();
        let page = finalizer.push(final_page).unwrap().into_bytes();
        let seal = finalizer.finish().unwrap().into_bytes();
        let package_id = summary.object_id();

        let mut create = Request::builder()
            .method("POST")
            .uri("/api/r/child/session")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "package": {
                        "suite": "blake3",
                        "root": hex::encode(package_id.root),
                        "length": package_id.length,
                    }
                })
                .to_string(),
            ))
            .unwrap();
        connect_info(&mut create);
        let response = send_request(&application, create).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let session = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["session"]
            .as_str()
            .unwrap()
            .to_owned();

        for (path, body) in [
            (format!("/api/session/{session}/seal"), seal),
            (format!("/api/session/{session}/page"), page),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .body(Body::from(body))
                .unwrap();
            assert_eq!(
                send_request(&application, request).await.status(),
                StatusCode::OK
            );
        }
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/session/{session}/begin"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            send_request(&application, request).await.status(),
            StatusCode::OK
        );

        let proof = prepared.prove(0, EXPECTED_PREFIX_BYTES).unwrap();
        let start = proof.covered_offset() as usize;
        let end = start + proof.covered_length() as usize;
        assert_eq!(start, 0);
        assert_eq!(proof.covered_length(), EXPECTED_PREFIX_BYTES);
        let mut body = proof.proof().to_vec();
        let proof_len = body.len();
        body.extend_from_slice(&bytes[start..end]);
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/session/{session}/chunk?entry=0&offset={start}"
            ))
            .header("x-votport-proof", proof_len.to_string())
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            send_request(&application, request).await.status(),
            StatusCode::OK
        );
        let saved = application.store.load_upload_sessions().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].files[0].prefix_bytes, 0);

        // Hold a real handler so graceful shutdown cannot finish before checkpoint.
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let entered = Arc::new(tokio::sync::Mutex::new(Some(entered_tx)));
        let release = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
        let held_route = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            get(move || {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                async move {
                    if let Some(sender) = entered.lock().await.take() {
                        let _ = sender.send(());
                    }
                    if let Some(receiver) = release.lock().await.take() {
                        let _ = receiver.await;
                    }
                    StatusCode::OK
                }
            })
        };
        let router = router(Arc::clone(&application)).route("/__test_hold", held_route);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (signal_ready_tx, signal_ready_rx) = tokio::sync::oneshot::channel();
        let server = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal_ready(
            Arc::clone(&application),
            signal_ready_tx,
        ))
        .into_future();
        let mut drain = tokio::spawn(drain_and_checkpoint(
            Arc::clone(&application),
            server,
            std::time::Duration::from_millis(50),
        ));
        let client = reqwest::Client::new();
        let held = tokio::spawn(client.get(format!("http://{address}/__test_hold")).send());
        match tokio::time::timeout(std::time::Duration::from_secs(1), entered_rx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => {
                held.abort();
                drain.abort();
                let _ = held.await;
                let _ = drain.await;
                panic!("held HTTP handler did not start");
            }
        }
        match tokio::time::timeout(std::time::Duration::from_secs(1), signal_ready_rx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => {
                held.abort();
                drain.abort();
                let _ = held.await;
                let _ = drain.await;
                panic!("shutdown signal was not installed");
            }
        }
        // Unix exercises the same SIGTERM waiter as main; other targets use the API path.
        #[cfg(unix)]
        {
            let status = std::process::Command::new("kill")
                .args(["-TERM", &std::process::id().to_string()])
                .status()
                .unwrap();
            assert!(status.success(), "self SIGTERM failed: {status}");
        }
        #[cfg(not(unix))]
        application.request_shutdown();
        if tokio::time::timeout(
            std::time::Duration::from_secs(1),
            application.wait_for_shutdown(),
        )
        .await
        .is_err()
        {
            held.abort();
            drain.abort();
            let _ = held.await;
            let _ = drain.await;
            panic!("SIGTERM did not request shutdown");
        }
        if held.is_finished() {
            held.abort();
            drain.abort();
            let _ = held.await;
            let _ = drain.await;
            panic!("held handler completed before drain");
        }

        let drain_result =
            match tokio::time::timeout(std::time::Duration::from_secs(2), &mut drain).await {
                Ok(result) => result,
                Err(_) => {
                    held.abort();
                    drain.abort();
                    let _ = held.await;
                    let _ = drain.await;
                    panic!("bounded shutdown did not reach checkpoint");
                }
            };
        drain_result
            .expect("shutdown task panicked")
            .expect("shutdown checkpoint failed");
    }

    #[tokio::test]
    async fn child_deadline_checkpoints_and_restart_reattaches_upload() {
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            child_setup_and_checkpoint(std::path::Path::new(&root)).await;
            std::process::exit(0);
        }

        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("child.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "app::tests::shutdown_process_tests::child_deadline_checkpoints_and_restart_reattaches_upload",
                "--nocapture",
            ])
            .env(CHILD_ROOT, directory.path())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            status.is_some_and(|status| status.success()),
            "child shutdown did not complete: {}",
            std::fs::read_to_string(log_path).unwrap()
        );

        let application = crate::api::testing::build(directory.path());
        let sessions = application.store.load_upload_sessions().unwrap();
        assert_eq!(sessions.len(), 1, "checkpoint was not durable");
        assert_eq!(application.sessions.total(), 1, "restart did not reattach");
        assert_eq!(
            sessions[0]
                .files
                .iter()
                .find(|file| file.display_path == "partial.bin")
                .map(|file| file.prefix_bytes),
            Some(EXPECTED_PREFIX_BYTES)
        );
        release_data_lock(&application);
    }
}

#[cfg(test)]
mod asset_cache_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    async fn fetch(path: &str) -> Response {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        request(app, path).await
    }

    async fn request(app: Arc<App>, path: &str) -> Response {
        router(app)
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn unstamped_assets_revalidate_and_stamped_assets_are_immutable() {
        let directory = tempfile::tempdir().unwrap();
        let assets = directory.path().join("web/assets");
        std::fs::create_dir_all(&assets).unwrap();
        std::fs::create_dir(assets.join("subdir")).unwrap();
        std::fs::create_dir(assets.join("vendor")).unwrap();
        std::fs::write(assets.join("app.js"), b"root-script").unwrap();
        std::fs::write(assets.join("vendor/vendor.js"), b"vendor-script").unwrap();
        std::fs::write(assets.join("fonts.css"), b"body {}").unwrap();
        let favicon = assets.join("favicon.png");
        std::fs::write(&favicon, b"fixture").unwrap();
        let app = crate::api::testing::build(directory.path());
        use sha2::Digest as _;
        let mut expected_web_build = sha2::Sha256::new();
        for (name, contents) in [
            ("assets/app.js", &b"root-script"[..]),
            ("assets/vendor/vendor.js", &b"vendor-script"[..]),
        ] {
            expected_web_build.update(name.as_bytes());
            expected_web_build.update(contents);
        }
        let expected_web_build = hex::encode(expected_web_build.finalize());
        assert_eq!(app.web_build, expected_web_build[..16]);
        let favicon_stamp = app.asset_versions["/favicon.png"].stamp.clone();
        let fonts_stamp = app.asset_versions["/fonts.css"].stamp.clone();
        let plain = router(app.clone())
            .oneshot(
                Request::get("/assets/fonts.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(plain.status(), StatusCode::OK);
        assert_eq!(plain.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(plain.headers()[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(
            plain
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            b"body {}"
        );

        let stamped = request(
            app.clone(),
            &format!("/assets/favicon.png?v={favicon_stamp}"),
        )
        .await;
        assert_eq!(stamped.status(), StatusCode::OK);
        assert_eq!(
            stamped.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(stamped.headers()[header::REFERRER_POLICY], "no-referrer");

        for query in [
            "not-a-stamp".to_owned(),
            "0011223344556677".to_owned(),
            "001122334455667A".to_owned(),
            "001122334455667G".to_owned(),
            "001122334455667".to_owned(),
            format!("{favicon_stamp}&v={favicon_stamp}"),
        ] {
            let response = request(app.clone(), &format!("/assets/favicon.png?v={query}")).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
        }

        let wrong_path =
            request(app.clone(), &format!("/assets/fonts.css?v={favicon_stamp}")).await;
        assert_eq!(wrong_path.status(), StatusCode::OK);
        assert_eq!(wrong_path.headers()[header::CACHE_CONTROL], "no-cache");

        let encoded_alias = request(
            app.clone(),
            &format!("/assets/%66avicon.png?v={favicon_stamp}"),
        )
        .await;
        assert_eq!(encoded_alias.status(), StatusCode::OK);
        assert_eq!(encoded_alias.headers()[header::CACHE_CONTROL], "no-cache");

        let dot_alias = request(
            app.clone(),
            &format!("/assets/./favicon.png?v={favicon_stamp}"),
        )
        .await;
        assert_eq!(dot_alias.status(), StatusCode::OK);
        assert_eq!(dot_alias.headers()[header::CACHE_CONTROL], "no-cache");

        std::fs::write(&favicon, b"replacement").unwrap();
        let replaced = request(
            app.clone(),
            &format!("/assets/favicon.png?v={favicon_stamp}"),
        )
        .await;
        assert_eq!(replaced.status(), StatusCode::OK);
        assert_eq!(replaced.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(
            replaced
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            b"replacement"
        );

        let unchanged_other =
            request(app.clone(), &format!("/assets/fonts.css?v={fonts_stamp}")).await;
        assert_eq!(unchanged_other.status(), StatusCode::OK);
        assert_eq!(
            unchanged_other.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );

        let missing = request(app.clone(), "/assets/no-such-file.png?v=0011223344556677").await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(missing.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(
            missing.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        let body = missing.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"asset not found\n");

        for path in ["/assets/subdir", "/assets/subdir/"] {
            let directory_response = router(app.clone())
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(directory_response.status(), StatusCode::NOT_FOUND);
            assert!(directory_response.headers().get(header::LOCATION).is_none());
            assert_eq!(
                directory_response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .as_ref(),
                b"asset not found\n"
            );

            let directory_head = router(app.clone())
                .oneshot(Request::head(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(directory_head.status(), StatusCode::NOT_FOUND);
            assert!(directory_head.headers().get(header::LOCATION).is_none());
            assert!(directory_head
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty());
        }

        let head = router(app)
            .oneshot(
                Request::head("/assets/no-such-file.png")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            head.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert!(head
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());
    }

    #[tokio::test]
    async fn unknown_page_returns_plain_text_not_found_body() {
        let response = fetch("/mistyped-page").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"page not found\n");
    }

    #[tokio::test]
    async fn assets_carry_the_page_content_security_policy() {
        // Audit finding 517: a dedicated worker's policy comes from its own
        // response, so hash-worker.js ran with no CSP at all.
        let directory = tempfile::tempdir().unwrap();
        let assets = directory.path().join("web/assets");
        std::fs::create_dir_all(&assets).unwrap();
        std::fs::write(assets.join("hash-worker.js"), b"self.onmessage = () => {};").unwrap();
        let app = crate::api::testing::build(directory.path());
        let response = request(app, "/assets/hash-worker.js").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], CSP);
    }
}

#[cfg(test)]
mod page_header_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn pages_send_cross_origin_opener_policy_and_no_coep() {
        // Audit finding 518: without COOP an attacker page that opens the
        // login or a recipient page in a popup keeps a cross-origin window
        // handle for XS-Leaks. COEP stays off: nothing uses SharedArrayBuffer.
        let directory = tempfile::tempdir().unwrap();
        let web = directory.path().join("web");
        std::fs::create_dir_all(&web).unwrap();
        std::fs::write(
            web.join("index.html"),
            "<!doctype html><title>admin</title>",
        )
        .unwrap();
        std::fs::write(
            web.join("verify.html"),
            "<!doctype html><title>verify</title>",
        )
        .unwrap();
        let app = crate::api::testing::build(directory.path());
        for path in ["/", "/verify"] {
            let response = router(app.clone())
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response
                    .headers()
                    .get("cross-origin-opener-policy")
                    .and_then(|value| value.to_str().ok()),
                Some("same-origin"),
                "{path}"
            );
            assert!(
                response
                    .headers()
                    .get("cross-origin-embedder-policy")
                    .is_none(),
                "{path}"
            );
            // The body is still the served page, so the header layer did not
            // replace the response.
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(!body.is_empty(), "{path}");
        }
    }
}

#[cfg(test)]
mod api_response_tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{HeaderValue, Request};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn api_responses_are_private_and_keep_head_and_method_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());

        let success = router(app.clone())
            .oneshot(
                Request::get("/api/receipt-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(success.status(), StatusCode::OK);
        assert_eq!(success.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(success.headers()[header::CONTENT_TYPE], "application/json");

        let audit = router(app.clone())
            .oneshot(
                Request::get("/api/admin/audit")
                    .header(
                        header::COOKIE,
                        crate::api::admin::test_admin_cookie(
                            &app,
                            &crate::auth::AdminIdentity::local_admin(),
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(audit.status(), StatusCode::OK);
        assert_eq!(audit.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            audit.headers()[header::CONTENT_TYPE],
            "application/x-ndjson; charset=utf-8"
        );
        let _ = audit.into_body().collect().await.unwrap().to_bytes();

        let fallback = router(app.clone())
            .oneshot(
                Request::get("/api/no-such-endpoint")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fallback.status(), StatusCode::NOT_FOUND);
        assert_eq!(fallback.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(fallback.headers()[header::CONTENT_TYPE], "application/json");
        let fallback_body = fallback.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&fallback_body).contains("request does not match"));

        let method_error = router(app.clone())
            .oneshot(
                Request::post("/api/admin/session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(method_error.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(method_error.headers()[header::CACHE_CONTROL], "no-store");
        assert!(method_error
            .headers()
            .get(header::ALLOW)
            .is_some_and(|value| value.as_bytes().windows(3).any(|part| part == b"GET")));
        assert_eq!(
            method_error.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        let body = method_error.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "request_failed");

        let unsupported = router(app.clone())
            .oneshot(
                Request::post("/api/r/missing/verify")
                    .header(header::CONTENT_TYPE, "text/plain")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        8080,
                    ))))
                    .body(Body::from("not json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unsupported.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(unsupported.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            unsupported.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        let unsupported_body = unsupported.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&unsupported_body).contains("request does not match"));

        let invalid_receipt = router(app.clone())
            .oneshot(
                Request::post("/api/verify")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        8080,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_receipt.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(invalid_receipt.headers()[header::CACHE_CONTROL], "no-store");
        let invalid_receipt_body = invalid_receipt
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let invalid_receipt_body: serde_json::Value =
            serde_json::from_slice(&invalid_receipt_body).unwrap();
        assert_eq!(invalid_receipt_body["error"], "This is not a vot-receipt.");

        let too_large = router(app.clone())
            .oneshot(
                Request::post("/api/verify")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        8080,
                    ))))
                    .body(Body::from(vec![0; 64 * 1024 + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(too_large.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            too_large.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        let too_large_body = too_large.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&too_large_body).contains("request does not match"));

        let head_failure = router(app.clone())
            .oneshot(
                Request::head("/api/no-such-endpoint")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head_failure.status(), StatusCode::NOT_FOUND);
        assert_eq!(head_failure.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            head_failure.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        assert!(head_failure
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());

        let head_fixture = tower::ServiceBuilder::new()
            .layer(axum::middleware::from_fn(api_response_policy))
            .service(tower::service_fn(|_| async {
                Ok::<_, std::convert::Infallible>(
                    (
                        StatusCode::BAD_REQUEST,
                        [(header::CONTENT_TYPE, "text/plain")],
                        Body::from("fixture error"),
                    )
                        .into_response(),
                )
            }));
        let head_fixture_response = head_fixture
            .oneshot(
                Request::head("/api/head-fixture")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head_fixture_response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            head_fixture_response.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        assert!(head_fixture_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());

        let head = router(app)
            .oneshot(
                Request::head("/api/receipt-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers()[header::CACHE_CONTROL], "no-store");
        assert!(head
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());
    }

    #[tokio::test]
    async fn api_normalization_preserves_non_body_headers() {
        let mut response = (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::CONTENT_TYPE, "text/plain")],
            Body::from("legacy error"),
        )
            .into_response();
        response
            .headers_mut()
            .append(header::ALLOW, HeaderValue::from_static("GET"));
        response
            .headers_mut()
            .append(header::RETRY_AFTER, HeaderValue::from_static("60"));
        response.headers_mut().append(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=api"),
        );
        response
            .headers_mut()
            .append(header::SET_COOKIE, HeaderValue::from_static("a=1"));
        response
            .headers_mut()
            .append(header::SET_COOKIE, HeaderValue::from_static("b=2"));
        response.extensions_mut().insert(7_u32);

        let normalized = crate::api::normalize_response(response).await;
        assert_eq!(normalized.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(normalized.headers()[header::ALLOW], "GET");
        assert_eq!(normalized.headers()[header::RETRY_AFTER], "60");
        assert_eq!(
            normalized.headers()[header::WWW_AUTHENTICATE],
            "Bearer realm=api"
        );
        assert_eq!(
            normalized
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        assert_eq!(
            normalized.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        assert_eq!(normalized.extensions().get::<u32>(), Some(&7));
        let body = normalized.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("request does not match the API"));

        let scim_body = r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401","detail":"invalid bearer"}"#;
        let scim = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_TYPE, "Application/SCIM+JSON; charset=utf-8")
            .body(Body::from(scim_body))
            .unwrap();
        let scim = crate::api::normalize_response(scim).await;
        assert_eq!(
            scim.headers()[header::CONTENT_TYPE],
            "Application/SCIM+JSON; charset=utf-8"
        );
        assert_eq!(
            scim.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            scim_body.as_bytes()
        );
    }
}

#[cfg(test)]
mod push_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn push_restart_preserves_quota_and_cleanup_waits_for_the_directory_lock() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_link(crate::store::Link {
                retention_days: None,
                verification: "default".to_owned(),
                id: "resume".to_owned(),
                tenant: String::new(),
                label: "resume".to_owned(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,

                notifications: None,
                uploads: Vec::new(),
                events: Vec::new(),
            })
            .unwrap();
        let key = hex::encode([4; 16]);
        let stage = app
            .receiving_destinations()
            .unwrap()
            .push_directory(&key)
            .unwrap();
        std::fs::create_dir_all(stage.join("objects")).unwrap();
        let object_path = stage.join("objects/retained.stage");
        std::fs::write(&object_path, b"staged bytes").unwrap();
        let persisted = crate::store::PersistedUploadSession {
            committed_upload_id: None,
            id: hex::encode([5; 16]),
            push_key: Some(key.clone()),
            link_id: "resume".to_owned(),
            tenant: String::new(),
            dest_dir: app.config.receive_dir.clone(),
            dest_rel: String::new(),
            package: vot_sdk::object::ObjectId {
                suite: 1,
                root: [7; 32],
                length: 12,
            },
            max_total_bytes: Some(12),
            started_at: crate::store::now_unix(),
            files: Vec::new(),
        };
        app.store.insert_upload_session(&persisted).unwrap();
        let kept = resume_upload_sessions(
            &app.config,
            &app.store,
            &app.signer,
            &app.sessions,
            &app.session_ended,
            app.receiving.lock().unwrap().as_mut().unwrap(),
        )
        .unwrap();
        assert!(app.sessions.contains_push_key(&key));
        let (sender, _) = tokio::sync::mpsc::channel(1);
        assert_eq!(
            app.sessions.insert_admitted(
                session::SessionAdmission {
                    id: "extra".to_owned(),
                    link_id: "resume".to_owned(),
                    tenant: String::new(),
                    reserved_bytes: 1,
                    max_total_bytes: Some(12),
                    max_tenant_sessions: None,
                    max_link_sessions: usize::MAX,
                    max_sessions: usize::MAX,
                    kind: session::SessionKind::Http,
                },
                sender,
                || Ok((0, Vec::new()))
            ),
            Err(session::InsertError::ByteQuota)
        );
        crate::paths::clean_staging(&app.config.receive_dir, &kept);
        assert_eq!(std::fs::read(&object_path).unwrap(), b"staged bytes");
        sweep_push_staging(&app);
        assert!(object_path.exists());
        let lock =
            session::lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap();
        app.sessions.sweep(0);
        assert!(!app.sessions.contains_push_key(&key));
        sweep_push_staging(&app);
        assert!(object_path.exists());
        drop(lock);
        sweep_push_staging(&app);
        assert!(!stage.exists());
        assert!(app.store.load_push_sessions().unwrap().is_empty());
        app.store.insert_upload_session(&persisted).unwrap();
        sweep_push_staging(&app);
        assert!(app.store.load_push_sessions().unwrap().is_empty());
    }

    fn push_config(directory: &std::path::Path) -> Config {
        let mut config = crate::api::testing::config(directory);
        config.push_bind = Some("127.0.0.1:0".parse().unwrap());
        config.push_advertise = Some("push.example.test:8322".to_owned());
        config
    }

    #[tokio::test]
    async fn push_staging_lock_failures_warn_paced_and_receiving_relative() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_link(crate::store::tests::test_link("resume"))
            .unwrap();
        let key = hex::encode([4; 16]);
        let persisted = crate::store::PersistedUploadSession {
            committed_upload_id: None,
            id: hex::encode([5; 16]),
            push_key: Some(key.clone()),
            link_id: "resume".to_owned(),
            tenant: String::new(),
            dest_dir: app.config.receive_dir.clone(),
            dest_rel: String::new(),
            package: vot_sdk::object::ObjectId {
                suite: 1,
                root: [7; 32],
                length: 12,
            },
            max_total_bytes: Some(12),
            started_at: crate::store::now_unix(),
            files: Vec::new(),
        };
        app.store.insert_upload_session(&persisted).unwrap();
        // The staging directory opens, but without write access the lock file
        // inside it fails with a non-NotFound error the sweep must report.
        use std::os::unix::fs::PermissionsExt as _;
        let staging = app
            .config
            .receive_dir
            .join(".vot-stage")
            .join(format!(".vot-push-{key}"));
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o555)).unwrap();
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            sweep_push_staging(&app);
            sweep_push_staging(&app);
        });
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755)).unwrap();
        let warns: Vec<String> = std::fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .filter(|line| line.contains("push staging could not be locked"))
            .map(str::to_owned)
            .collect();
        assert_eq!(warns.len(), 1, "the repeat sweep stays silent: {warns:?}");
        assert!(warns[0].contains(".vot-stage/.vot-push-"), "{}", warns[0]);
        assert!(warns[0].contains(&key[..8]), "{}", warns[0]);
        assert!(
            !warns[0].contains(
                directory
                    .path()
                    .to_string_lossy()
                    .get(..16)
                    .unwrap_or(&directory.path().to_string_lossy())
            ),
            "absolute path leaked: {}",
            warns[0]
        );
        // The staging was skipped, not treated as missing: the record stays.
        assert_eq!(app.store.load_push_sessions().unwrap().len(), 1);
    }

    async fn identity(app: Arc<App>) -> serde_json::Value {
        let response = router(app)
            .oneshot(
                Request::builder()
                    .uri("/api/push-identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    #[tokio::test]
    async fn push_identity_is_public_and_stable_across_restarts() {
        let directory = tempfile::tempdir().unwrap();
        let first = build(push_config(directory.path())).unwrap();
        let first_handle = Arc::clone(&first);
        let first_identity = identity(first).await;
        assert_eq!(first_identity["address"], "push.example.test:8322");
        assert_eq!(
            first_identity["certificate_digest"].as_str().unwrap().len(),
            64
        );
        assert_eq!(
            first_identity["issuer_public_key"].as_str().unwrap().len(),
            64
        );
        let certificate = std::fs::read(directory.path().join("data/push.crt")).unwrap();
        let key = std::fs::read(directory.path().join("data/push.key")).unwrap();
        let issuer = std::fs::read(directory.path().join("data/push-issuer.key")).unwrap();

        release_data_lock(&first_handle);
        drop(first_handle);
        let second = build(push_config(directory.path())).unwrap();
        assert_eq!(identity(second).await, first_identity);
        assert_eq!(
            std::fs::read(directory.path().join("data/push.crt")).unwrap(),
            certificate
        );
        assert_eq!(
            std::fs::read(directory.path().join("data/push.key")).unwrap(),
            key
        );
        assert_eq!(
            std::fs::read(directory.path().join("data/push-issuer.key")).unwrap(),
            issuer
        );
    }

    #[tokio::test]
    async fn push_identity_is_not_exposed_when_disabled() {
        let directory = tempfile::tempdir().unwrap();
        let response = router(crate::api::testing::build(directory.path()))
            .oneshot(
                Request::builder()
                    .uri("/api/push-identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn startup_validation_precedes_filesystem_changes() {
        for invalid in ["idle", "url", "hash"] {
            for push in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let mut config = push_config(directory.path());
                if !push {
                    config.push_bind = None;
                }
                let expected = match invalid {
                    "idle" => {
                        config.session_idle_secs = 0;
                        "VOTPORT_SESSION_IDLE_SECS"
                    }
                    "url" => {
                        config.public_url = Some("https://drop.example.com/base".into());
                        "VOTPORT_PUBLIC_URL"
                    }
                    "hash" => {
                        config.admin_password_hash = "invalid".into();
                        "VOTPORT_ADMIN_PASSWORD_HASH"
                    }
                    _ => unreachable!(),
                };
                let data = config.data_dir.clone();
                assert!(build(config)
                    .err()
                    .expect("invalid configuration was admitted")
                    .contains(expected));
                assert!(
                    !data.exists(),
                    "{invalid}, push={push}: startup created files"
                );
            }
        }
    }

    #[test]
    fn native_push_audience_obeys_capability_identity_bounds() {
        let exact = "x".repeat(vot_capability::bounds::IDENTITY.1 - "votport:".len());
        assert_eq!(
            push_audience(Some(&exact), "unused").unwrap().len(),
            vot_capability::bounds::IDENTITY.1
        );
        assert!(push_audience(Some(&format!("{exact}x")), "unused").is_err());
        assert!(push_audience(Some("drop.example\ninvalid"), "unused").is_err());
    }

    #[test]
    fn stale_push_setup_and_seams_are_spent() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        let missing_setup = PushTicket {
            session_id: "stale-setup".to_owned(),
            expires_at: u64::MAX,
            expected_package: vot_sdk::object::ObjectId {
                suite: 1,
                root: [78; 32],
                length: 1,
            },
            directory: directory.path().to_owned(),
            setup: None,
            seams: None,
            control: session::PushControl::new(),
        };
        assert!(matches!(
            ticket_setup(&missing_setup),
            Err(PushRefusalReason::Spent)
        ));

        let setup = session::WorkerSetup {
            store: Arc::clone(&application.store),
            link_id: "stale-seams".to_owned(),
            tenant: String::new(),
            dest_dir: directory.path().join("destination"),
            destinations: Arc::new(
                crate::receiving::Destinations::open(
                    directory.path(),
                    vot_sdk_file::NasContract::Unqualified,
                )
                .unwrap()
                .child(&["destination".into()])
                .unwrap(),
            ),
            client_ip: String::new(),
            dest_rel: String::new(),
            expected_package: missing_setup.expected_package.clone(),
            max_total_bytes: 1,
            allow_hidden: false,
            verification: "default".to_owned(),
            signer: Arc::clone(&application.signer),
            session_id: [79; 16],
            started_at: crate::store::now_unix(),
            quiet_after_secs: 5,
            ended: application.session_ended.clone(),
            checkpoint_warn: session::CheckpointWarnPacer::new(),
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (seams, stale_handle) = session::push_seams(
            Arc::clone(&application),
            setup,
            session::PushControl::new(),
            runtime.handle().clone(),
        );
        drop(seams);
        let dead_seams = PushTicket {
            seams: Some(stale_handle),
            ..missing_setup
        };
        assert!(matches!(
            live_ticket_seams(&dead_seams),
            Err(PushRefusalReason::Spent)
        ));
    }

    #[test]
    fn capability_refusal_reason_distinguishes_expiry_from_invalid_proof() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
        let foreign_issuer = ed25519_dalek::SigningKey::from_bytes(&[92; 32]);
        let holder_key = ed25519_dalek::SigningKey::from_bytes(&[93; 32]);
        let audience = "votport:push.example.test:8322";
        let requirement = vot_cli::authz::PushRequirement::new(
            "votport",
            vot_cli::authz::key_id_of(&issuer.verifying_key()),
            issuer.verifying_key(),
            audience,
        );
        let challenge = requirement.challenge([94; 32]);
        let binding = vot_transport_api::ChannelBinding::from_bytes([95; 32]);
        let now = 1_700_000_000;
        let root = [96; 32];
        let signed = vot_cli::authz::issue_push(
            "votport",
            audience,
            &issuer,
            holder_key.verifying_key().to_bytes(),
            root,
            97,
            now,
            10,
        )
        .unwrap();
        let holder = vot_cli::authz::Holder::new(signed, holder_key.clone()).unwrap();
        let open = holder.answer(&challenge, binding).unwrap();
        let expired_now = now + 10 + 301;
        let expired = vot_cli::PushPresentation {
            peer: "127.0.0.1:1".parse().unwrap(),
            challenge: &challenge,
            open: &open,
            channel_binding: binding,
            now: expired_now,
        };
        assert_eq!(
            capability_refusal_reason(&requirement, &expired),
            PushRefusalReason::Expired
        );

        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let expired_for_admission = vot_cli::PushPresentation {
            peer: expired.peer,
            challenge: expired.challenge,
            open: expired.open,
            channel_binding: expired.channel_binding,
            now: now + 11,
        };
        assert!(admit_push(
            &application,
            &requirement,
            expired_for_admission,
            runtime.handle()
        )
        .is_none());
        assert_eq!(
            application
                .push_metrics
                .refusals(PushRefusalReason::Expired),
            1
        );
        assert_eq!(
            application.push_metrics.refusals(PushRefusalReason::Spent),
            0
        );

        let foreign_signed = vot_cli::authz::issue_push(
            "votport",
            audience,
            &foreign_issuer,
            holder_key.verifying_key().to_bytes(),
            root,
            97,
            now,
            10,
        )
        .unwrap();
        let foreign_holder = vot_cli::authz::Holder::new(foreign_signed, holder_key).unwrap();
        let foreign_open = foreign_holder.answer(&challenge, binding).unwrap();
        let foreign = vot_cli::PushPresentation {
            open: &foreign_open,
            ..expired
        };
        assert_eq!(
            capability_refusal_reason(&requirement, &foreign),
            PushRefusalReason::Capability
        );

        let wrong_binding = vot_transport_api::ChannelBinding::from_bytes([98; 32]);
        let wrong_binding_presentation = vot_cli::PushPresentation {
            channel_binding: wrong_binding,
            ..expired
        };
        assert_eq!(
            capability_refusal_reason(&requirement, &wrong_binding_presentation),
            PushRefusalReason::Capability
        );
    }

    #[test]
    fn push_ticket_sweep_removes_expired_unconnected_tickets() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(push_config(directory.path())).unwrap();
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let live_control = session::PushControl::new();
        application
            .sessions
            .insert_admitted(
                session::SessionAdmission {
                    id: "live".to_owned(),
                    link_id: "link".to_owned(),
                    tenant: String::new(),
                    reserved_bytes: 0,
                    max_total_bytes: None,
                    max_tenant_sessions: None,
                    max_link_sessions: usize::MAX,
                    max_sessions: usize::MAX,
                    kind: session::SessionKind::Push(live_control.clone()),
                },
                sender,
                || Ok((0, Vec::new())),
            )
            .unwrap();
        let now = crate::store::now_unix();
        let expired_control = session::PushControl::new();
        let (expired_sender, _expired_receiver) = tokio::sync::mpsc::channel(1);
        application
            .sessions
            .insert_admitted(
                session::SessionAdmission {
                    id: "expired".to_owned(),
                    link_id: "link".to_owned(),
                    tenant: String::new(),
                    reserved_bytes: 0,
                    max_total_bytes: None,
                    max_tenant_sessions: None,
                    max_link_sessions: usize::MAX,
                    max_sessions: usize::MAX,
                    kind: session::SessionKind::Push(expired_control.clone()),
                },
                expired_sender,
                || Ok((0, Vec::new())),
            )
            .unwrap();
        application.push_tickets.lock().unwrap().extend([
            (
                [1; 16],
                PushTicket {
                    session_id: "live".to_owned(),
                    expires_at: now + 60,
                    expected_package: vot_sdk::object::ObjectId {
                        suite: 1,
                        root: [1; 32],
                        length: 1,
                    },
                    directory: directory.path().join("live"),
                    setup: None,
                    seams: None,
                    control: live_control.clone(),
                },
            ),
            (
                [2; 16],
                PushTicket {
                    session_id: "missing".to_owned(),
                    expires_at: now + 60,
                    expected_package: vot_sdk::object::ObjectId {
                        suite: 1,
                        root: [2; 32],
                        length: 1,
                    },
                    directory: directory.path().join("missing"),
                    setup: None,
                    seams: None,
                    control: session::PushControl::new(),
                },
            ),
            (
                [3; 16],
                PushTicket {
                    session_id: "expired".to_owned(),
                    expires_at: now,
                    expected_package: vot_sdk::object::ObjectId {
                        suite: 1,
                        root: [3; 32],
                        length: 1,
                    },
                    directory: directory.path().join("expired"),
                    setup: None,
                    seams: None,
                    control: expired_control.clone(),
                },
            ),
        ]);

        sweep_push_tickets(&application);

        let tickets = application.push_tickets.lock().unwrap();
        assert_eq!(tickets.len(), 1);
        assert!(tickets.contains_key(&[1; 16]));
        assert!(!live_control.is_cancelled());
        assert!(expired_control.is_cancelled());
        assert_eq!(application.sessions.total(), 1);
        assert!(application.sessions.contains_push("live"));
    }

    #[test]
    fn push_ticket_sweep_keeps_expired_connected_tickets() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(push_config(directory.path())).unwrap();
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let control = session::PushControl::new();
        assert!(control.connect());
        application
            .sessions
            .insert_admitted(
                session::SessionAdmission {
                    id: "connected".to_owned(),
                    link_id: "link".to_owned(),
                    tenant: String::new(),
                    reserved_bytes: 0,
                    max_total_bytes: None,
                    max_tenant_sessions: None,
                    max_link_sessions: usize::MAX,
                    max_sessions: usize::MAX,
                    kind: session::SessionKind::Push(control.clone()),
                },
                sender,
                || Ok((0, Vec::new())),
            )
            .unwrap();
        application.push_tickets.lock().unwrap().insert(
            [4; 16],
            PushTicket {
                session_id: "connected".to_owned(),
                expires_at: crate::store::now_unix(),
                expected_package: vot_sdk::object::ObjectId {
                    suite: 1,
                    root: [4; 32],
                    length: 1,
                },
                directory: directory.path().join("connected"),
                setup: None,
                seams: None,
                control: control.clone(),
            },
        );

        sweep_push_tickets(&application);

        let tickets = application.push_tickets.lock().unwrap();
        assert!(tickets.contains_key(&[4; 16]));
        assert!(!control.is_cancelled());
    }

    #[test]
    fn managed_credentials_regenerate_when_one_file_is_left_behind() {
        for lone in ["push.crt", "push.key"] {
            let directory = tempfile::tempdir().unwrap();
            let data = directory.path().join("data");
            std::fs::create_dir_all(&data).unwrap();
            std::fs::write(data.join(lone), b"interrupted").unwrap();

            let config = push_config(directory.path());
            push_credentials(&config).unwrap();

            assert!(std::fs::read(data.join("push.crt"))
                .unwrap()
                .starts_with(b"-----BEGIN CERTIFICATE-----"));
            assert!(std::fs::read(data.join("push.key"))
                .unwrap()
                .starts_with(b"-----BEGIN"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn managed_credentials_tighten_existing_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let config = push_config(directory.path());
        std::fs::create_dir_all(&config.data_dir).unwrap();
        let (certificate, key) = push_credentials(&config).unwrap();
        for path in [&certificate, &key] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        push_credentials(&config).unwrap();
        for path in [certificate, key] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn invalid_push_issuer_is_regenerated_and_then_stable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("push-issuer.key");
        std::fs::write(&path, b"interrupted").unwrap();

        let first = load_push_issuer(directory.path()).unwrap();
        let first_bytes = std::fs::read(&path).unwrap();
        assert_eq!(first_bytes.len(), 32);
        let second = load_push_issuer(directory.path()).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(std::fs::read(path).unwrap(), first_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn push_issuer_tightens_an_existing_key() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("push-issuer.key");
        std::fs::write(&path, [9u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        load_push_issuer(directory.path()).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn supplied_credentials_are_strict_and_never_removed() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("supplied.crt");
        let key = directory.path().join("supplied.key");
        std::fs::write(&certificate, b"keep this file").unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.push_bind = Some("127.0.0.1:0".parse().unwrap());
        config.push_certificate = Some(certificate.clone());
        config.push_private_key = Some(key.clone());

        assert!(build(config).is_err());
        assert_eq!(std::fs::read(certificate).unwrap(), b"keep this file");
        assert!(!key.exists());
    }

    #[test]
    fn private_publication_never_overwrites_and_cleans_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let existing = directory.path().join("existing.key");
        std::fs::write(&existing, b"original").unwrap();
        assert!(publish_private(&existing, b"replacement").is_err());
        assert_eq!(std::fs::read(&existing).unwrap(), b"original");

        let created = directory.path().join("created.key");
        publish_private(&created, b"new secret").unwrap();
        assert_eq!(std::fs::read(&created).unwrap(), b"new secret");
        assert!(std::fs::read_dir(directory.path())
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp-")));
    }
}

#[cfg(test)]
mod push_metrics_tests {
    use super::*;

    #[test]
    fn push_metrics_keep_fixed_refusal_series() {
        let metrics = PushMetrics::default();
        metrics.add_bytes(7);
        for reason in PushRefusalReason::ALL {
            metrics.refuse(reason);
        }
        assert_eq!(metrics.bytes(), 7);
        assert!(PushRefusalReason::ALL
            .iter()
            .all(|reason| metrics.refusals(*reason) == 1));
        assert_eq!(PushRefusalReason::Rate.label(), "rate");
        assert_eq!(PushRefusalReason::Capability.label(), "capability");
        assert_eq!(PushRefusalReason::Expired.label(), "expired");
        assert_eq!(PushRefusalReason::Spent.label(), "spent");
    }
}

#[cfg(test)]
mod transfer_metrics_tests {
    use super::*;

    #[test]
    fn ended_notifies_only_rejections_and_interrupted_transfers_with_bytes() {
        let event = |outcome: &str, received_bytes: u64| crate::store::SessionEvent {
            at: 2,
            started_at: 1,
            outcome: outcome.to_owned(),
            detail: String::new(),
            received_bytes,
            expected_bytes: 10,
            replayed_chunks: 0,
            rejected_chunks: 0,
        };
        for (outcome, received, expected) in [
            ("rejected", 0, true),
            ("rejected", 5, true),
            ("interrupted", 0, false),
            ("interrupted", 1, true),
            ("cancelled", 5, false),
            ("published", 5, false),
            ("", 5, false),
        ] {
            assert_eq!(
                ended_notifies(&event(outcome, received)),
                expected,
                "{outcome} {received}"
            );
        }
    }

    #[test]
    fn outcome_table_is_fixed() {
        for (index, outcome) in TRANSFER_OUTCOMES.iter().enumerate() {
            assert_eq!(transfer_outcome_index(outcome), Some(index));
        }
        assert_eq!(transfer_outcome_index("exploded"), None);
        assert_eq!(transfer_outcome_index(""), None);
    }

    #[test]
    fn transfer_metrics_keep_fixed_series_and_cumulative_buckets() {
        let metrics = TransferMetrics::new();
        metrics.ended("rejected");
        metrics.ended("interrupted");
        metrics.ended("interrupted");
        metrics.ended("exploded");
        metrics.published(2 << 20, 5);
        metrics.published(3 << 30, 700);
        assert_eq!(metrics.ended_count("published"), 2);
        assert_eq!(metrics.ended_count("rejected"), 1);
        assert_eq!(metrics.ended_count("cancelled"), 0);
        assert_eq!(metrics.ended_count("interrupted"), 2);
        assert_eq!(metrics.ended_count("exploded"), 0);
        let loads = |buckets: &[AtomicU64; 7]| {
            buckets
                .iter()
                .map(|bucket| bucket.load(Ordering::Relaxed))
                .collect::<Vec<_>>()
        };
        assert_eq!(loads(&metrics.bytes_buckets), [0, 1, 1, 1, 2, 2, 2]);
        assert_eq!(loads(&metrics.duration_buckets), [0, 1, 1, 1, 2, 2, 2]);
        let text = metrics.prometheus();
        assert!(text.contains("votport_upload_sessions_ended_total{outcome=\"interrupted\"} 2\n"));
        assert!(text.contains("votport_upload_bytes_bucket{le=\"1048576\"} 0\n"));
        assert!(text.contains("votport_upload_bytes_bucket{le=\"+Inf\"} 2\n"));
        assert!(text.contains(&format!(
            "votport_upload_bytes_sum {}\n",
            (2u64 << 20) + (3 << 30)
        )));
        assert!(text.contains("votport_upload_duration_seconds_count 2\n"));
        assert!(text.contains("votport_upload_duration_seconds_sum 705\n"));
        assert_eq!(text.matches("_bucket{").count(), 14);
    }
}

#[cfg(test)]
mod request_metrics_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::time::Duration;

    #[test]
    fn request_ids_accept_only_bounded_safe_values() {
        let valid = Request::get("/")
            .header("x-request-id", "client.req-1_ok")
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_id(&valid), "client.req-1_ok");
        let too_long = "x".repeat(65);
        for value in ["", "has/slash", "has space", &too_long] {
            let request = Request::get("/")
                .header("x-request-id", value)
                .body(Body::empty())
                .unwrap();
            let generated = request_id(&request);
            assert_eq!(generated.len(), 32);
            assert!(generated
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')));
        }
    }

    #[test]
    fn request_metrics_keep_fixed_status_series_and_cumulative_buckets() {
        let metrics = RequestMetrics::default();
        metrics.observe(StatusCode::OK, Duration::from_millis(5));
        metrics.observe(StatusCode::MOVED_PERMANENTLY, Duration::from_millis(75));
        metrics.observe(StatusCode::BAD_REQUEST, Duration::from_millis(200));
        metrics.observe(
            StatusCode::INTERNAL_SERVER_ERROR,
            Duration::from_millis(2_000),
        );
        metrics.observe(
            StatusCode::from_u16(199).unwrap(),
            Duration::from_millis(6_000),
        );
        let text = metrics.prometheus();
        for class in REQUEST_STATUS_CLASSES {
            assert!(text.contains(&format!(
                "votport_http_requests_total{{status=\"{class}\"}} 1"
            )));
        }
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"0.01\"} 1"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"0.05\"} 1"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"0.1\"} 2"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"0.5\"} 3"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"1\"} 3"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"5\"} 4"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"+Inf\"} 5"));
        assert_eq!(
            text.matches("votport_http_request_duration_seconds_bucket{le=\"+Inf\"}")
                .count(),
            1
        );
        assert!(text.contains("votport_http_request_duration_seconds_count 5"));
        assert!(text.contains("votport_http_request_duration_seconds_sum 8.280000000"));
    }

    #[test]
    fn outbound_upload_timing_uses_one_fixed_route_and_histogram() {
        let upload = Request::post("/api/admin/outbound-files?path=project/file.bin")
            .body(Body::empty())
            .unwrap();
        assert!(is_outbound_upload(&upload));
        let other = Request::post("/api/admin/outbound-grants")
            .body(Body::empty())
            .unwrap();
        assert!(!is_outbound_upload(&other));
        let list = Request::get("/api/admin/outbound-files")
            .body(Body::empty())
            .unwrap();
        assert!(!is_outbound_upload(&list));

        let metrics = RequestMetrics::default();
        metrics.observe_outbound_upload(Duration::from_millis(75));
        let text = metrics.prometheus();
        assert!(text.contains(
            "# HELP votport_http_outbound_upload_duration_seconds HTTP time to response headers for outbound library uploads in seconds."
        ));
        assert!(text.contains("votport_http_outbound_upload_duration_seconds_bucket{le=\"0.1\"} 1"));
        assert!(
            text.contains("votport_http_outbound_upload_duration_seconds_bucket{le=\"+Inf\"} 1")
        );
        assert!(text.contains("votport_http_outbound_upload_duration_seconds_count 1"));
        assert!(text.contains("votport_http_outbound_upload_duration_seconds_sum 0.075000000"));
    }

    #[test]
    fn request_metrics_in_flight_returns_to_zero() {
        let metrics = RequestMetrics::default();
        let in_flight = metrics.begin();
        assert!(metrics
            .prometheus()
            .contains("votport_http_requests_in_flight 1"));
        drop(in_flight);
        assert!(metrics
            .prometheus()
            .contains("votport_http_requests_in_flight 0"));
    }

    #[tokio::test]
    async fn request_middleware_sets_valid_or_generated_request_id() {
        use tower::ServiceExt as _;

        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let response = router(app.clone())
            .oneshot(
                Request::get("/healthz")
                    .header("x-request-id", "client.req-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["x-request-id"], "client.req-1");

        let response = router(app)
            .oneshot(
                Request::get("/healthz")
                    .header("x-request-id", "bad/id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let generated = response.headers()["x-request-id"].to_str().unwrap();
        assert_eq!(generated.len(), 32);
        assert!(generated
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')));
    }

    #[tokio::test]
    async fn request_middleware_records_only_outbound_upload_posts() {
        use tower::ServiceExt as _;

        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-files?path=x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(app
            .request_metrics
            .prometheus()
            .contains("votport_http_outbound_upload_duration_seconds_count 1"));

        router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?path=x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(app
            .request_metrics
            .prometheus()
            .contains("votport_http_outbound_upload_duration_seconds_count 1"));
    }
}

#[cfg(test)]
mod retention_scope_tests {
    use super::narrowest_retention_days;

    #[test]
    fn narrowest_retention_takes_the_smallest_positive_scope() {
        assert_eq!(narrowest_retention_days(30, None, None), Some(30));
        assert_eq!(narrowest_retention_days(30, Some(7), None), Some(7));
        assert_eq!(narrowest_retention_days(30, Some(90), Some(14)), Some(14));
        // Zero is "off" at that level, never a zero-day wipe.
        assert_eq!(narrowest_retention_days(0, Some(7), None), Some(7));
        assert_eq!(narrowest_retention_days(30, Some(0), Some(45)), Some(30));
        // Nothing set anywhere keeps uploads.
        assert_eq!(narrowest_retention_days(0, None, None), None);
        assert_eq!(narrowest_retention_days(0, Some(0), Some(0)), None);
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;
    use crate::store::{FileRecord, Link, OutboundGrant, SettingWrite, UploadRecord};

    #[test]
    fn retention_clock_seeds_new_database_and_holds_existing_until_ack() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(store.retention_clock_anchor().unwrap().is_some());
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM meta WHERE key = ?1",
                    [crate::store::RETENTION_CLOCK_KEY],
                )
            })
            .unwrap();

        let clock = RetentionClock::open(&store).unwrap();
        let base = 1_800_000_000;
        let future = base + 31 * 86_400;
        assert_eq!(
            clock
                .observe_with_elapsed(&store, future, Duration::ZERO)
                .unwrap(),
            RetentionObservation {
                effective_at: future,
                allow_age: false,
            }
        );

        clock
            .acknowledge(&store, "platform-operator", base)
            .unwrap();
        assert_eq!(
            clock.status_with_elapsed(base + 2, Duration::ZERO)["capped"],
            false,
            "one-second boundary drift does not show a spurious acknowledgement prompt"
        );
        assert_eq!(
            clock.status_with_elapsed(base + 3, Duration::ZERO)["capped"],
            true
        );
        let held_uptime = clock
            .observe_with_elapsed(&store, future, Duration::ZERO)
            .unwrap();
        assert_eq!(held_uptime.effective_at, base);
        assert!(held_uptime.allow_age);
        assert_eq!(
            clock
                .observe_with_elapsed(&store, future, Duration::from_secs(86_400))
                .unwrap()
                .effective_at,
            base + 86_400
        );
        assert_eq!(
            clock
                .observe_with_elapsed(&store, future, Duration::from_secs(86_400))
                .unwrap()
                .effective_at,
            base + 86_400,
            "repeated calls cannot manufacture additional retention age"
        );
        let persisted = store.retention_clock_anchor().unwrap().unwrap();
        assert_eq!(persisted, base + 86_400);

        let reopened = RetentionClock::open(&store).unwrap();
        assert_eq!(
            reopened
                .observe_with_elapsed(&store, future, Duration::ZERO)
                .unwrap()
                .effective_at,
            persisted,
            "a restart starts from persisted effective time"
        );
        assert_eq!(
            reopened
                .observe_with_elapsed(&store, base - 1, Duration::ZERO)
                .unwrap()
                .effective_at,
            base - 1,
            "backward wall time lowers only the current cutoff"
        );
        assert_eq!(store.retention_clock_anchor().unwrap(), Some(persisted));
        reopened
            .acknowledge(&store, "platform-operator", base - 1)
            .unwrap();
        assert_eq!(
            store.retention_clock_anchor().unwrap(),
            Some(persisted),
            "an acknowledgement cannot move trusted time backwards"
        );
        let audit = store.audit_export(None, 0, 0, 10).unwrap();
        assert!(audit
            .iter()
            .any(|row| row.event == "retention_clock_acknowledged"));
    }

    #[test]
    fn retention_observe_and_ack_interleaving_keeps_anchor_atomic() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(directory.path()).unwrap());
        let clock = Arc::new(RetentionClock::open(&store).unwrap());
        let base = store.retention_clock_anchor().unwrap().unwrap();
        let raw = base + 200 * 86_400;
        let acknowledged = base + 100 * 86_400;
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (observe_done_tx, observe_done_rx) = std::sync::mpsc::channel();
        *clock
            .observe_hook
            .lock()
            .expect("retention observe hook poisoned") = Some(RetentionObserveHook {
            reached: reached_tx,
            release: release_rx,
        });

        let observing_clock = Arc::clone(&clock);
        let observing_store = Arc::clone(&store);
        let observer = std::thread::spawn(move || {
            let result = observing_clock.observe_with_elapsed(
                &observing_store,
                raw,
                Duration::from_secs(31 * 86_400),
            );
            observe_done_tx.send(result).unwrap();
        });
        reached_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("observe must reach the forced interleaving");

        let (ack_started_tx, ack_started_rx) = std::sync::mpsc::channel();
        let (ack_done_tx, ack_done_rx) = std::sync::mpsc::channel();
        let acknowledging_clock = Arc::clone(&clock);
        let acknowledging_store = Arc::clone(&store);
        let acknowledger = std::thread::spawn(move || {
            ack_started_tx.send(()).unwrap();
            let result = acknowledging_clock.acknowledge(
                &acknowledging_store,
                "platform-operator",
                acknowledged,
            );
            ack_done_tx.send(result).unwrap();
        });
        ack_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("acknowledgement thread must start");
        let ack_waited = ack_done_rx.recv_timeout(Duration::from_millis(50)).is_err();
        release_tx.send(()).unwrap();
        assert!(
            ack_waited,
            "acknowledgement must wait for the observation clock guard"
        );

        let observation = observe_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("observe must finish after the forced interleaving")
            .unwrap();
        observer.join().unwrap();
        assert_eq!(observation.effective_at, base + 31 * 86_400);
        assert!(ack_done_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .is_ok());
        acknowledger.join().unwrap();
        assert_eq!(store.retention_clock_anchor().unwrap(), Some(acknowledged));
        assert_eq!(
            clock
                .observe_with_elapsed(&store, raw, Duration::ZERO)
                .unwrap()
                .effective_at,
            acknowledged,
            "old uptime cannot be applied to the new acknowledgement anchor"
        );
    }

    #[tokio::test]
    async fn injected_future_runs_real_age_cleanup_and_grant_protection() {
        let directory = tempfile::tempdir().unwrap();
        let config = crate::api::testing::config(directory.path());
        let store = Store::open(&config.data_dir).unwrap();
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
        let base = crate::store::now_unix();
        let future = base + 31 * 86_400;
        app.store
            .put_settings(
                "test",
                &[
                    (
                        "audit_retention_days".to_owned(),
                        SettingWrite::Set("7".to_owned()),
                    ),
                    (
                        "upload_retention_days".to_owned(),
                        SettingWrite::Set("1".to_owned()),
                    ),
                ],
            )
            .unwrap();
        std::fs::create_dir_all(&app.config.receive_dir).unwrap();
        let make_link = |id: &str, upload_id: &str, name: &str, completed_at: u64| {
            let path = app.config.receive_dir.join(name);
            let file = crate::receiving::tests::published_file(
                &path,
                name.as_bytes(),
                vot_verifier::Suite::Blake3Bao64,
                &app.signer,
            );
            Link {
                retention_days: None,
                verification: "default".to_owned(),
                id: id.to_owned(),
                tenant: String::new(),
                label: id.to_owned(),
                dest: String::new(),
                password_hash: None,
                created_at: base,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,
                notifications: None,
                uploads: vec![UploadRecord {
                    partial: false,
                    log: Vec::new(),
                    id: upload_id.to_owned(),
                    started_at: base,
                    completed_at,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: None,
                    package_root: "root".to_owned(),
                    total_bytes: file.bytes,
                    files: vec![file],
                }],
                events: Vec::new(),
            }
        };
        let old = make_link("old", "old-upload", "old.txt", base - 8 * 86_400);
        let expired = make_link(
            "expired-future",
            "expired-upload",
            "expired-future.txt",
            future - 2 * 86_400,
        );
        let protected = make_link(
            "protected-future",
            "protected-upload",
            "protected-future.txt",
            future - 2 * 86_400,
        );
        let expired_object = expired.uploads[0].files[0].clone();
        let protected_object = protected.uploads[0].files[0].clone();
        app.store.insert_link(old).unwrap();
        app.store.insert_link(expired).unwrap();
        app.store.insert_link(protected).unwrap();
        let make_grant =
            |id: &str, link_id: &str, upload_id: &str, object: &FileRecord, expires_at: u64| {
                app.store
                    .insert_outbound_grant(OutboundGrant {
                        id: id.to_owned(),
                        token_hash: format!("{id}-hash"),
                        password_hash: None,
                        tenant: String::new(),
                        link_id: link_id.to_owned(),
                        upload_id: upload_id.to_owned(),
                        package_root: "root".to_owned(),
                        name: object.path.clone(),
                        suite: object.suite.clone(),
                        root: object.root.clone(),
                        file_index: 0,
                        bytes: object.bytes,
                        label: id.to_owned(),
                        created_at: base,
                        expires_at,
                        revoked_at: None,
                        downloads: 0,
                        max_downloads: None,
                        notifications: None,
                        first_download_at: None,
                        last_download_at: None,
                        files: Vec::new(),
                    })
                    .unwrap();
            };
        make_grant(
            "expired-grant",
            "expired-future",
            "expired-upload",
            &expired_object,
            future - 3_600,
        );
        make_grant(
            "future-grant",
            "protected-future",
            "protected-upload",
            &protected_object,
            future + 86_400,
        );

        app.store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO audit_log(at,tenant,actor,event,subject,detail)
                     VALUES (?1,'','test','future_audit','subject','{}')",
                    [i64::try_from(base - 8 * 86_400).unwrap()],
                )
            })
            .unwrap();
        let snapshot = app.config.data_dir.join("backups/votport-1-deadbeef.db");
        std::fs::create_dir_all(snapshot.parent().unwrap()).unwrap();
        std::fs::write(&snapshot, b"snapshot").unwrap();
        std::fs::File::open(&snapshot)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(base - 31 * 86_400)),
            )
            .unwrap();
        let proof_dir = app.config.data_dir.join("outbound.proofs");
        std::fs::create_dir_all(&proof_dir).unwrap();
        let expired_proof = proof_dir.join(format!(
            "1-{}-{}.vot-catalog",
            expired_object.root, expired_object.bytes
        ));
        let protected_proof = proof_dir.join(format!(
            "1-{}-{}.vot-catalog",
            protected_object.root, protected_object.bytes
        ));
        std::fs::write(&expired_proof, b"expired proof").unwrap();
        std::fs::write(&protected_proof, b"protected proof").unwrap();

        let held = app.retention_observation().unwrap();
        assert!(!held.allow_age);
        sweep_daily_at(&app, held).await;
        assert!(app.config.receive_dir.join("old.txt").exists());
        assert!(app.config.receive_dir.join("expired-future.txt").exists());
        assert!(snapshot.exists());
        assert!(expired_proof.exists());
        assert!(protected_proof.exists());

        app.acknowledge_retention_clock_at("platform-operator", base, base)
            .unwrap();
        let zero = app
            .retention_clock
            .observe_with_elapsed(&app.store, future, Duration::ZERO)
            .unwrap();
        assert_eq!(zero.effective_at, base);
        sweep_daily_at(&app, zero).await;
        assert!(!app.config.receive_dir.join("old.txt").exists());
        assert!(app.config.receive_dir.join("expired-future.txt").exists());
        assert!(app.config.receive_dir.join("protected-future.txt").exists());
        assert!(!snapshot.exists());
        assert!(expired_proof.exists());
        assert!(protected_proof.exists());

        let one_day = app
            .retention_clock
            .observe_with_elapsed(&app.store, future, Duration::from_secs(86_400))
            .unwrap();
        assert_eq!(one_day.effective_at, base + 86_400);
        sweep_daily_at(&app, one_day).await;
        assert!(app.config.receive_dir.join("expired-future.txt").exists());
        assert!(app.config.receive_dir.join("protected-future.txt").exists());
        assert!(expired_proof.exists());
        assert!(protected_proof.exists());

        let full_age = app
            .retention_clock
            .observe_with_elapsed(&app.store, future, Duration::from_secs(31 * 86_400))
            .unwrap();
        assert_eq!(full_age.effective_at, future);
        sweep_daily_at(&app, full_age).await;
        assert!(!app.config.receive_dir.join("expired-future.txt").exists());
        assert!(app.config.receive_dir.join("protected-future.txt").exists());
        assert!(!expired_proof.exists());
        assert!(protected_proof.exists());
        assert_eq!(
            app.store
                .audit_export(None, 0, 0, 100)
                .unwrap()
                .iter()
                .filter(|row| row.event == "future_audit")
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn poisoned_cleanup_duties_leave_other_work_and_later_passes_running() {
        use std::time::{Duration, SystemTime};

        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.push_bind = Some("127.0.0.1:0".parse().unwrap());
        config.push_advertise = Some("push.example.test:8322".into());
        let mut app = build(config).unwrap();
        Arc::get_mut(&mut app).unwrap().config.session_idle_secs = 0;
        let poisoned = Arc::clone(&app);
        assert!(std::thread::spawn(move || {
            let _guard = poisoned.push_tickets.lock().unwrap();
            panic!("poison ticket registry");
        })
        .join()
        .is_err());
        assert!(app.push_tickets.is_poisoned());
        let backups = crate::backup::ensure_backups_dir(&app.config.data_dir).unwrap();
        let snapshot = backups.join("votport-1-deadbeef.db");
        let old =
            std::fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1));
        for round in 0..3 {
            if round == 2 {
                let store = Arc::clone(&app.store);
                assert!(std::thread::spawn(move || {
                    let _ = store.with::<()>(|_| panic!("poison store"));
                })
                .join()
                .is_err());
                std::fs::File::create(&snapshot)
                    .unwrap()
                    .set_times(old)
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(5), sweep_daily(&app))
                    .await
                    .expect("failed settings must not terminate or stall the daily pass");
                assert!(
                    snapshot.exists(),
                    "unreadable settings must prevent destructive cleanup"
                );
            }
            let (sender, _receiver) = tokio::sync::mpsc::channel(1);
            app.sessions
                .insert_admitted(
                    session::SessionAdmission {
                        id: format!("expired-{round}"),
                        link_id: "link".into(),
                        tenant: String::new(),
                        reserved_bytes: 0,
                        max_total_bytes: None,
                        max_tenant_sessions: None,
                        max_link_sessions: usize::MAX,
                        max_sessions: usize::MAX,
                        kind: session::SessionKind::Http,
                    },
                    sender,
                    || Ok((0, Vec::new())),
                )
                .unwrap();
            let stage = app
                .config
                .outbound_dir
                .join(format!(".vot-outbound-00-{}.stage", "a".repeat(64)));
            std::fs::File::create(&stage)
                .unwrap()
                .set_times(old)
                .unwrap();
            assert_eq!(app.sessions.total(), 1);
            tokio::time::timeout(Duration::from_secs(5), sweep_short(&app))
                .await
                .expect("one poisoned duty must not stall unrelated cleanup");
            assert_eq!(app.sessions.total(), 0);
            assert!(
                !stage.exists(),
                "library cleanup must run after the failed duty"
            );
            assert!(
                app.push_tickets.is_poisoned(),
                "cleanup must not clear unsafe poisoned state"
            );
        }
    }

    #[tokio::test]
    async fn daily_cleanup_waits_and_does_not_block_idle_session_cleanup() {
        use std::time::{Duration, SystemTime};

        let directory = tempfile::tempdir().unwrap();
        let mut app = build(crate::api::testing::config(directory.path())).unwrap();
        Arc::get_mut(&mut app).unwrap().config.session_idle_secs = 0;
        let backups = crate::backup::ensure_backups_dir(&app.config.data_dir).unwrap();
        let snapshot = backups.join("votport-1-deadbeef.db");
        let add_expired = || {
            let (sender, _receiver) = tokio::sync::mpsc::channel(1);
            app.sessions
                .insert_admitted(
                    session::SessionAdmission {
                        id: "expired".into(),
                        link_id: "link".into(),
                        tenant: String::new(),
                        reserved_bytes: 0,
                        max_total_bytes: None,
                        max_tenant_sessions: None,
                        max_link_sessions: usize::MAX,
                        max_sessions: usize::MAX,
                        kind: session::SessionKind::Http,
                    },
                    sender,
                    || Ok((0, Vec::new())),
                )
                .unwrap();
            std::fs::File::create(&snapshot)
                .unwrap()
                .set_times(
                    std::fs::FileTimes::new()
                        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
                )
                .unwrap();
        };
        add_expired();
        let worker = tokio::spawn(session_sweeper_with_delays(
            Arc::clone(&app),
            Duration::from_millis(5),
            Duration::from_secs(60),
        ));
        let short_ran = tokio::time::timeout(Duration::from_secs(5), async {
            while app.sessions.total() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        worker.abort();
        let _ = worker.await;
        short_ran.expect("short cleanup must run before the first daily deadline");
        assert!(
            snapshot.exists(),
            "daily cleanup must not run immediately at startup"
        );

        add_expired();
        let (locked, ready) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let store = Arc::clone(&app.store);
        let blocker = tokio::task::spawn_blocking(move || {
            store.with(|_| {
                locked.send(()).unwrap();
                released
                    .recv_timeout(Duration::from_secs(10))
                    .expect("test must release retention settings lock");
                Ok(())
            })
        });
        tokio::time::timeout(Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        let worker = tokio::spawn(session_sweeper_with_delays(
            Arc::clone(&app),
            Duration::from_millis(50),
            Duration::from_millis(1),
        ));
        let short_ran = tokio::time::timeout(Duration::from_secs(2), async {
            while app.sessions.total() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        let retained_while_blocked = snapshot.exists();
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), blocker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let daily_ran = tokio::time::timeout(Duration::from_secs(5), async {
            while snapshot.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        worker.abort();
        let _ = worker.await;
        short_ran.expect("blocked daily cleanup must not stop idle-session expiry");
        assert!(retained_while_blocked);
        daily_ran.expect("daily cleanup must finish after its blocker clears");
    }

    #[test]
    fn legacy_snapshot_pruning_keeps_operator_files() {
        let directory = tempfile::tempdir().unwrap();
        let generated = directory.path().join("votport-1-deadbeef.db");
        let operator = directory.path().join("votport-before-upgrade.db");
        let modified = std::fs::FileTimes::new()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1));
        for path in [&generated, &operator] {
            let file = std::fs::File::create(path).unwrap();
            file.set_times(modified).unwrap();
        }
        prune_legacy_snapshots(
            directory.path(),
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(2),
        );
        assert!(!generated.exists());
        assert!(operator.exists());
    }

    #[tokio::test]
    async fn retention_preserves_protected_files_and_tombstones_expired_files() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let cutoff = crate::store::now_unix();
        app.store
            .put_settings(
                "test",
                &[(
                    "upload_retention_days".to_owned(),
                    SettingWrite::Set("1".to_owned()),
                )],
            )
            .unwrap();
        std::fs::create_dir_all(&app.config.receive_dir).unwrap();
        let held_path = app.config.receive_dir.join("held.txt");
        let expired_path = app.config.receive_dir.join("expired.txt");
        let active_path = app.config.receive_dir.join("active.txt");
        let shared_path = app.config.receive_dir.join("shared.txt");
        let outbound_path = app.config.receive_dir.join("outbound.txt");
        let failed_path = app.config.receive_dir.join("failed.txt");
        std::fs::write(&held_path, b"held").unwrap();
        std::fs::write(&expired_path, b"expired").unwrap();
        std::fs::write(&active_path, b"active").unwrap();
        std::fs::write(&shared_path, b"shared").unwrap();
        std::fs::write(&outbound_path, b"outbound").unwrap();
        std::fs::write(&failed_path, b"failed").unwrap();

        let held = Link {
            retention_days: None,
            verification: "default".to_owned(),
            id: "held".to_owned(),
            tenant: String::new(),
            label: "held".to_owned(),
            dest: String::new(),
            password_hash: None,
            created_at: 0,
            expires_at: None,
            max_bytes: None,
            active: true,
            legal_hold: true,

            notifications: None,
            uploads: vec![UploadRecord {
                partial: false,
                log: Vec::new(),
                id: "upload".to_owned(),
                started_at: 0,
                completed_at: 1,
                replayed_chunks: 0,
                rejected_chunks: 0,
                transport: None,
                package_root: "root".to_owned(),
                total_bytes: 4,
                files: vec![FileRecord {
                    path: "held.txt".to_owned(),
                    stored_as: "held.txt".to_owned(),
                    bytes: 4,
                    suite: "blake3".to_owned(),
                    root: "object".to_owned(),
                    receipt: false,
                    deleted: false,
                }],
            }],
            events: Vec::new(),
        };
        let mut expired = held.clone();
        expired.id = "expired".to_owned();
        expired.label = "expired".to_owned();
        expired.legal_hold = false;
        expired.uploads[0].files[0].path = "expired.txt".to_owned();
        expired.uploads[0].files[0].stored_as = "expired.txt".to_owned();
        let mut active = expired.clone();
        active.id = "active".to_owned();
        active.label = "active".to_owned();
        active.uploads[0].files[0].path = "active.txt".to_owned();
        active.uploads[0].files[0].stored_as = "active.txt".to_owned();
        let mut shared = expired.clone();
        shared.id = "shared".to_owned();
        shared.label = "shared".to_owned();
        shared.uploads[0].files[0].path = "shared.txt".to_owned();
        shared.uploads[0].files[0].stored_as = "shared.txt".to_owned();
        shared.uploads.push(shared.uploads[0].clone());
        shared.uploads[1].id = "recent".to_owned();
        shared.uploads[1].completed_at = cutoff;
        let mut failed = expired.clone();
        failed.id = "failed".to_owned();
        failed.label = "failed".to_owned();
        failed.uploads[0].files[0].path = "failed.txt".to_owned();
        failed.uploads[0].files[0].stored_as = "failed.txt".to_owned();
        let mut outbound = expired.clone();
        outbound.id = "outbound".to_owned();
        outbound.label = "outbound".to_owned();
        outbound.uploads[0].files[0].path = "outbound.txt".to_owned();
        outbound.uploads[0].files[0].stored_as = "outbound.txt".to_owned();
        app.store.insert_link(held.clone()).unwrap();
        expired.uploads[0].files[0] = crate::receiving::tests::published_file(
            &expired_path,
            b"expired",
            vot_verifier::Suite::Blake3Bao64,
            &app.signer,
        );
        failed.uploads[0].files[0] = crate::receiving::tests::published_file(
            &failed_path,
            b"failed",
            vot_verifier::Suite::Blake3Bao64,
            &app.signer,
        );
        app.store.insert_link(expired).unwrap();
        app.store.insert_link(active).unwrap();
        app.store.insert_link(shared).unwrap();
        app.store.insert_link(outbound).unwrap();
        app.store.insert_link(failed).unwrap();
        app.store
            .insert_outbound_grant(OutboundGrant {
                id: "grant".to_owned(),
                token_hash: "hash".to_owned(),
                password_hash: None,
                tenant: String::new(),
                link_id: "outbound".to_owned(),
                upload_id: "upload".to_owned(),
                package_root: "root".to_owned(),
                name: "outbound.txt".to_owned(),
                suite: "blake3".to_owned(),
                root: "object".to_owned(),
                file_index: 0,
                bytes: 8,
                label: "outbound".to_owned(),
                created_at: cutoff,
                expires_at: cutoff.saturating_add(86_400),
                revoked_at: None,
                downloads: 0,
                max_downloads: None,

                notifications: None,
                first_download_at: None,
                last_download_at: None,
                files: Vec::new(),
            })
            .unwrap();

        // The candidate came from the first read before an administrator set
        // the hold. The re-read under the lifecycle pin must still preserve it.
        // An unavailable or replaced receive root must not tombstone live records.
        let receiving = app
            .receiving
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .destinations
            .clone();
        for missing in [false, true] {
            let displaced = directory.path().join("displaced");
            std::fs::rename(&app.config.receive_dir, &displaced).unwrap();
            if !missing {
                std::fs::create_dir(&app.config.receive_dir).unwrap();
                std::fs::write(&expired_path, b"replacement").unwrap();
            }
            let candidate = app.store.link("", "expired").unwrap().unwrap();
            let result = expire_link_uploads(&app, candidate, cutoff, cutoff).await;
            let Some(Err(error)) = result else {
                panic!("unavailable receiving storage must surface a retention error");
            };
            assert!(!error.is_empty());
            assert!(!app.store.link("", "expired").unwrap().unwrap().uploads[0].files[0].deleted);
            assert_eq!(
                std::fs::read(displaced.join("expired.txt")).unwrap(),
                b"expired"
            );
            if !missing {
                assert_eq!(std::fs::read(&expired_path).unwrap(), b"replacement");
                std::fs::remove_dir_all(&app.config.receive_dir).unwrap();
            }
            std::fs::rename(displaced, &app.config.receive_dir).unwrap();
        }
        let daily_displaced = directory.path().join("daily-displaced");
        std::fs::rename(&app.config.receive_dir, &daily_displaced).unwrap();
        use tracing::instrument::WithSubscriber;
        let daily_log = tempfile::NamedTempFile::new().unwrap();
        let daily_writer = daily_log.reopen().unwrap();
        let daily_subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || daily_writer.try_clone().unwrap())
            .finish();
        sweep_daily_at(
            &app,
            RetentionObservation {
                effective_at: cutoff,
                allow_age: true,
            },
        )
        .with_subscriber(daily_subscriber)
        .await;
        let daily_log = std::fs::read_to_string(daily_log.path()).unwrap();
        assert_eq!(
            daily_log
                .lines()
                .filter(|line| line.contains("retention stopped; receiving storage unavailable"))
                .count(),
            1,
            "{daily_log}"
        );
        assert!(!app.store.link("", "expired").unwrap().unwrap().uploads[0].files[0].deleted);
        assert!(!app.store.link("", "failed").unwrap().unwrap().uploads[0].files[0].deleted);
        assert_eq!(
            std::fs::read(daily_displaced.join("expired.txt")).unwrap(),
            b"expired"
        );
        std::fs::rename(daily_displaced, &app.config.receive_dir).unwrap();
        receiving.check_current().unwrap();
        let mut stale_held = held;
        stale_held.legal_hold = false;
        assert!(matches!(
            expire_link_uploads(&app, stale_held, cutoff, cutoff).await,
            Some(Ok(()))
        ));

        let (active_tx, _active_rx) = tokio::sync::mpsc::channel(1);
        app.sessions
            .insert(
                "active-session".to_owned(),
                "active".to_owned(),
                String::new(),
                active_tx,
            )
            .unwrap();
        let active_candidate = app.store.link("", "active").unwrap().unwrap();
        assert!(matches!(
            expire_link_uploads(&app, active_candidate, cutoff, cutoff).await,
            Some(Ok(()))
        ));
        assert!(active_path.exists());

        let shared_candidate = app.store.link("", "shared").unwrap().unwrap();
        assert!(matches!(
            expire_link_uploads(&app, shared_candidate, cutoff, cutoff).await,
            Some(Ok(()))
        ));
        assert!(shared_path.exists());
        assert!(app
            .store
            .link("", "shared")
            .unwrap()
            .unwrap()
            .uploads
            .iter()
            .all(|upload| !upload.files[0].deleted));

        let outbound_candidate = app.store.link("", "outbound").unwrap().unwrap();
        assert!(matches!(
            expire_link_uploads(&app, outbound_candidate, cutoff, cutoff).await,
            Some(Ok(()))
        ));
        assert!(outbound_path.exists());
        assert!(!app.store.link("", "outbound").unwrap().unwrap().uploads[0].files[0].deleted);

        let connection =
            rusqlite::Connection::open(app.config.data_dir.join("votport.db")).unwrap();
        connection
            .execute(
                "UPDATE outbound_grants SET file_index = ?1 WHERE id = ?2",
                rusqlite::params![i64::MAX, "grant"],
            )
            .unwrap();
        let malformed_candidate = app.store.link("", "outbound").unwrap().unwrap();
        assert!(matches!(
            expire_link_uploads(&app, malformed_candidate, cutoff, cutoff).await,
            Some(Ok(()))
        ));
        assert!(outbound_path.exists());
        assert!(!app.store.link("", "outbound").unwrap().unwrap().uploads[0].files[0].deleted);

        connection
            .execute_batch(
                "CREATE TRIGGER fail_link_update BEFORE UPDATE ON files
                 BEGIN SELECT RAISE(FAIL, 'test update failure'); END;",
            )
            .unwrap();
        let failed_candidate = app.store.link("", "failed").unwrap().unwrap();
        assert!(matches!(
            expire_link_uploads(&app, failed_candidate, cutoff, cutoff).await,
            Some(Ok(()))
        ));
        connection
            .execute_batch("DROP TRIGGER fail_link_update")
            .unwrap();
        assert!(failed_path.exists());
        assert!(!app.store.link("", "failed").unwrap().unwrap().uploads[0].files[0].deleted);
        assert!(app
            .store
            .audit_export(None, 0, 0, 100)
            .unwrap()
            .iter()
            .all(|row| row.subject != "failed"));

        let sweep_app = Arc::clone(&app);
        let sweeper = tokio::spawn(async move { sweep_daily(&sweep_app).await });
        for _ in 0..100 {
            if !expired_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        sweeper.abort();
        let _ = sweeper.await;

        assert!(held_path.exists());
        assert!(!expired_path.exists());
        assert!(active_path.exists());
        assert!(!app.store.link("", "held").unwrap().unwrap().uploads[0].files[0].deleted);
        assert!(app.store.link("", "expired").unwrap().unwrap().uploads[0].files[0].deleted);
        assert!(!app.store.link("", "active").unwrap().unwrap().uploads[0].files[0].deleted);
        let mut released = false;
        for _ in 0..100 {
            if app.sessions.pin_link_for_delete("expired") {
                released = true;
                app.sessions.unpin_link("expired");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            released,
            "the blocking deletion must finish and release its pin after sweeper cancellation"
        );
    }
    #[tokio::test]
    async fn audit_pruning_records_a_summary_row_that_outlives_its_own_cycle() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let base = now_unix();
        app.store
            .put_settings(
                "platform-operator",
                &[(
                    "audit_retention_days".to_owned(),
                    SettingWrite::Set("1".to_owned()),
                )],
            )
            .unwrap();
        // Seed one expired row so the cycle provably prunes something.
        app.store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO audit_log (at, tenant, actor, event, subject, detail)
                     VALUES (?1, '', '', 'expired_audit', '', '{}')",
                    [(base.saturating_sub(2 * 86_400) as i64)],
                )
            })
            .unwrap();
        app.acknowledge_retention_clock_at("platform-operator", base, base)
            .unwrap();
        let observation = app
            .retention_clock
            .observe_with_elapsed(&app.store, base, Duration::ZERO)
            .unwrap();
        assert!(observation.allow_age);

        sweep_daily_at(&app, observation).await;

        let rows = app.store.audit_export(Some(""), 0, 0, 100).unwrap();
        assert!(rows.iter().all(|row| row.event != "expired_audit"));
        let row = rows
            .iter()
            .find(|row| row.event == "audit_pruned")
            .expect("pruning records a summary row");
        assert_eq!(row.detail["pruned"], serde_json::json!(1));
        assert_eq!(row.detail["retention_days"], serde_json::json!(1));
        assert!(row.detail["cutoff"].is_number());
    }
}

#[cfg(test)]
mod sso_slot_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    fn force_failed_at(slot: &SsoSlot<u8>, at: Instant) {
        *slot.inner.lock().expect("sso slot poisoned") = SsoSlotState::Failed { at };
    }

    fn past_cooldown() -> Option<Instant> {
        Instant::now().checked_sub(SSO_COOLDOWN + Duration::from_secs(1))
    }

    #[tokio::test]
    async fn health_peek_is_true_only_for_ready() {
        let empty = SsoSlot::<u8>::new();
        assert!(!empty.health_peek());

        let failed = SsoSlot::<u8>::new();
        let _ = failed
            .get_or_discover_with(|| async { Err("down".to_owned()) })
            .await;
        assert!(!failed.health_peek());

        let ready = SsoSlot::<u8>::new();
        let client = ready
            .get_or_discover_with(|| async { Ok(7u8) })
            .await
            .expect("discover");
        assert_eq!(*client, 7);
        assert!(ready.health_peek());

        let guard = ready.inner.lock().expect("sso slot poisoned");
        assert!(!ready.health_peek());
        drop(guard);
        assert!(ready.health_peek());
    }

    #[tokio::test]
    async fn failed_discovery_cools_down() {
        let slot = SsoSlot::<u8>::new();
        let hits = Arc::new(AtomicU32::new(0));
        let first = slot
            .get_or_discover_with({
                let hits = Arc::clone(&hits);
                move || {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Err("down".to_owned())
                    }
                }
            })
            .await;
        assert_eq!(first, Err(()));
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let second = slot
            .get_or_discover_with({
                let hits = Arc::clone(&hits);
                move || {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Ok(1u8)
                    }
                }
            })
            .await;
        assert_eq!(second, Err(()));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(!slot.health_peek());
    }

    #[tokio::test]
    async fn elapsed_cooldown_retries_discovery() {
        let slot = SsoSlot::<u8>::new();
        let Some(at) = past_cooldown() else {
            return;
        };
        force_failed_at(&slot, at);
        let hits = Arc::new(AtomicU32::new(0));
        let result = slot
            .get_or_discover_with({
                let hits = Arc::clone(&hits);
                move || {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Ok(3u8)
                    }
                }
            })
            .await
            .expect("retry after cooldown");
        assert_eq!(*result, 3);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(slot.health_peek());

        let again = slot
            .get_or_discover_with({
                let hits = Arc::clone(&hits);
                move || {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Ok(9u8)
                    }
                }
            })
            .await
            .expect("ready is sticky");
        assert_eq!(*again, 3);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_empty_callers_share_one_discover() {
        let slot = Arc::new(SsoSlot::<u8>::new());
        let hits = Arc::new(AtomicU32::new(0));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let entered_tx = std::sync::Mutex::new(Some(entered_tx));
        let release_rx = std::sync::Mutex::new(Some(release_rx));

        let slot_a = Arc::clone(&slot);
        let hits_a = Arc::clone(&hits);
        let first = tokio::spawn(async move {
            slot_a
                .get_or_discover_with(|| {
                    let hits = Arc::clone(&hits_a);
                    let entered_tx = entered_tx.lock().unwrap().take();
                    let release_rx = release_rx.lock().unwrap().take();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        if let Some(tx) = entered_tx {
                            let _ = tx.send(());
                        }
                        if let Some(rx) = release_rx {
                            let _ = rx.await;
                        }
                        Ok(7u8)
                    }
                })
                .await
        });

        entered_rx.await.unwrap();
        assert!(!slot.health_peek());

        let slot_b = Arc::clone(&slot);
        let hits_b = Arc::clone(&hits);
        let second = slot_b
            .get_or_discover_with(|| {
                let hits = Arc::clone(&hits_b);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Ok(8u8)
                }
            })
            .await;
        assert_eq!(second, Err(()));
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let _ = release_tx.send(());
        let first = first.await.unwrap().expect("first discover");
        assert_eq!(*first, 7);
        assert!(slot.health_peek());
    }

    #[tokio::test]
    async fn cancelled_discover_does_not_stick_discovering() {
        let slot = Arc::new(SsoSlot::<u8>::new());
        let hits = Arc::new(AtomicU32::new(0));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let entered_tx = std::sync::Mutex::new(Some(entered_tx));
        let release_rx = std::sync::Mutex::new(Some(release_rx));

        let slot_a = Arc::clone(&slot);
        let hits_a = Arc::clone(&hits);
        let first = tokio::spawn(async move {
            slot_a
                .get_or_discover_with(|| {
                    let hits = Arc::clone(&hits_a);
                    let entered_tx = entered_tx.lock().unwrap().take();
                    let release_rx = release_rx.lock().unwrap().take();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        if let Some(tx) = entered_tx {
                            let _ = tx.send(());
                        }
                        if let Some(rx) = release_rx {
                            let _ = rx.await;
                        }
                        Ok(1u8)
                    }
                })
                .await
        });

        entered_rx.await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        drop(release_tx);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        {
            let guard = slot.inner.lock().expect("sso slot poisoned");
            assert!(matches!(*guard, SsoSlotState::Failed { .. }));
        }

        let second = slot
            .get_or_discover_with(|| {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Ok(2u8)
                }
            })
            .await;
        assert_eq!(second, Err(()));
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let Some(at) = past_cooldown() else {
            return;
        };
        force_failed_at(&slot, at);
        let third = slot
            .get_or_discover_with(|| {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Ok(3u8)
                }
            })
            .await
            .expect("retry after cancelled claim");
        assert_eq!(*third, 3);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(slot.health_peek());
    }

    #[tokio::test]
    async fn invalidate_ready_sends_the_slot_through_the_failure_cooldown() {
        let slot = SsoSlot::<u8>::new();
        let hits = Arc::new(AtomicU32::new(0));
        let discover = {
            let hits = Arc::clone(&hits);
            move || {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Ok(1u8)
                }
            }
        };

        // Empty stays Empty: there is nothing to expire.
        slot.invalidate_ready();
        assert!(!slot.health_peek());
        slot.get_or_discover_with(discover.clone())
            .await
            .expect("empty slot still discovers");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(slot.health_peek());

        // One verification failure flips Ready into the Failed cooldown.
        slot.invalidate_ready();
        assert!(!slot.health_peek());
        assert_eq!(slot.get_or_discover_with(discover.clone()).await, Err(()));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the cooldown refuses re-discovery"
        );

        // Repeated failures do not extend the cooldown: the timestamp of the
        // Failed slot survives invalidate_ready, so once it elapses the next
        // caller re-discovers.
        let Some(at) = past_cooldown() else {
            return;
        };
        force_failed_at(&slot, at);
        slot.invalidate_ready();
        slot.get_or_discover_with(discover)
            .await
            .expect("an expired cooldown is not prolonged by a repeated failure");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(slot.health_peek());
    }
}

#[cfg(test)]
mod audit_observability_tests {
    use super::*;

    #[test]
    fn refused_pushes_leave_an_audit_row_with_reason_and_peer() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        refuse_push(
            &application,
            PushRefusalReason::Spent,
            "10.1.2.3:4".parse().unwrap(),
        );
        let rows = application.store.audit_export(None, 0, 0, 100).unwrap();
        let row = rows
            .iter()
            .find(|row| row.event == "push_refused")
            .expect("the refused push leaves an audit row");
        assert_eq!(row.detail["reason"], "spent");
        assert_eq!(row.detail["peer"], "10.1.2.3:4");
        // A rate refusal is the flood itself: counted, with no row per try.
        for _ in 0..3 {
            refuse_push(
                &application,
                PushRefusalReason::Rate,
                "10.1.2.3:5".parse().unwrap(),
            );
        }
        let rows = application.store.audit_export(None, 0, 0, 100).unwrap();
        assert_eq!(
            rows.iter()
                .filter(|row| row.event == "push_refused")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn completed_uploads_are_recorded_under_the_upload_id() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::tests::test_tenant("acme"))
            .unwrap();
        application
            .store
            .insert_link(crate::store::tests::link_in("acme", "link-1"))
            .unwrap();
        let report = crate::session::FinishReport {
            upload_id: "upload-9".to_owned(),
            files: vec![crate::store::FileRecord {
                path: "a.bin".to_owned(),
                stored_as: "a.bin".to_owned(),
                bytes: 5000,
                suite: "blake3".to_owned(),
                root: "00".to_owned(),
                receipt: false,
                deleted: false,
            }],
            received: 5000,
        };
        upload_completed(
            &application,
            "07070707070707070707070707070707",
            Some("link-1".to_owned()),
            "10.0.0.9",
            &report,
            &tokio::runtime::Handle::current(),
        );
        let rows = application
            .store
            .audit_export(Some("acme"), 0, 0, 100)
            .unwrap();
        let row = rows
            .iter()
            .find(|row| row.event == "upload_completed")
            .expect("the completed upload leaves an audit row");
        assert_eq!(row.subject, "upload-9");
        assert_eq!(row.detail["files"], 1);
        assert_eq!(row.detail["bytes"], 5000);
        assert_eq!(row.detail["client_ip"], "10.0.0.9");

        // With the link gone the row still lands, on the default tenant.
        upload_completed(
            &application,
            "07070707070707070707070707070707",
            None,
            "10.0.0.9",
            &report,
            &tokio::runtime::Handle::current(),
        );
        let rows = application.store.audit_export(Some(""), 0, 0, 100).unwrap();
        let row = rows
            .iter()
            .find(|row| row.event == "upload_completed")
            .expect("the completed upload is recorded even without its link");
        assert_eq!(row.subject, "upload-9");
    }
}

#[cfg(test)]
mod legal_hold_marker_tests {
    use super::*;
    use crate::store::{Link, UploadRecord};
    use axum::body::Body;
    use tower::ServiceExt as _;

    async fn login_cookie(router: Router) -> String {
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/login")
                    .header("content-type", "application/json")
                    .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        1234,
                    ))))
                    .body(Body::from(format!(
                        "{{\"password\":\"{}\"}}",
                        crate::api::testing::TEST_PASSWORD
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    // Audit finding 376: the legal-hold flag is a restorable row, so this
    // test clears it the way a pre-hold restore would and proves the
    // out-of-database marker still pins the sweep, the delete handlers, and
    // audit pruning.
    #[tokio::test]
    async fn hold_marker_enforces_the_hold_after_a_restore_clears_the_flag() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        std::fs::create_dir_all(&app.config.receive_dir).unwrap();
        let path = app.config.receive_dir.join("held.txt");
        let file = crate::receiving::tests::published_file(
            &path,
            b"held",
            vot_verifier::Suite::Blake3Bao64,
            &app.signer,
        );
        app.store
            .insert_link(Link {
                retention_days: None,
                verification: "default".to_owned(),
                id: "held".to_owned(),
                tenant: String::new(),
                label: "held".to_owned(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,
                notifications: None,
                uploads: vec![UploadRecord {
                    partial: false,
                    log: Vec::new(),
                    id: "upload".to_owned(),
                    started_at: 0,
                    completed_at: 1,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: None,
                    package_root: "root".to_owned(),
                    total_bytes: file.bytes,
                    files: vec![file],
                }],
                events: Vec::new(),
            })
            .unwrap();
        let cookie = login_cookie(router(app.clone())).await;
        let response = router(app.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/links/held")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from("{\"legal_hold\":true}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(app.link_hold_pinned("held"), "the API pins the marker");

        // A backup restored from before the hold clears the restorable flag;
        // the marker file is not in the archive and survives.
        app.store
            .set_link_legal_hold("", "held", false, "restore")
            .unwrap();
        assert!(!app.store.link("", "held").unwrap().unwrap().legal_hold);
        assert!(app.link_hold_pinned("held"));

        // The retention sweep skips the link and keeps its bytes.
        let cutoff = now_unix() + 60;
        let candidate = app.store.link("", "held").unwrap().unwrap();
        expire_link_uploads(&app, candidate, cutoff, cutoff)
            .await
            .unwrap()
            .unwrap();
        assert!(path.exists(), "the marker alone must hold the sweep");
        // Delete handlers refuse every received-data deletion for the link.
        for uri in [
            "/api/admin/links/held",
            "/api/admin/links/held/uploads/upload",
            "/api/admin/links/held/uploads/upload/files/0",
        ] {
            let response = router(app.clone())
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(uri)
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CONFLICT, "{uri}");
        }
        // Audit rows naming the held link survive pruning.
        app.store
            .audit("", "", "upload_completed", "held", &serde_json::json!({}));
        app.store
            .audit("", "", "upload_completed", "gone", &serde_json::json!({}));
        app.store.audit_prune(cutoff, &app.held_link_ids()).unwrap();
        let rows = app.store.audit_export(None, 0, 0, 100).unwrap();
        assert!(rows
            .iter()
            .any(|row| row.event == "upload_completed" && row.subject == "held"));
        assert!(!rows
            .iter()
            .any(|row| row.event == "upload_completed" && row.subject == "gone"));

        // Releasing the hold removes the marker and lets retention run.
        let response = router(app.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/links/held")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from("{\"legal_hold\":false}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!app.link_hold_pinned("held"));
        let candidate = app.store.link("", "held").unwrap().unwrap();
        expire_link_uploads(&app, candidate, cutoff, cutoff)
            .await
            .unwrap()
            .unwrap();
        assert!(!path.exists());
    }
}
