use super::*;

#[cfg(test)]
mod log_tests {
    use super::*;

    #[test]
    fn terminal_event_survives_the_cap_and_the_tail_is_counted() {
        let mut log = TransferLog::default();
        for _ in 0..(LOG_CAP + 30) {
            log.push(TransferLog::plain(1, "published", None));
        }
        log.terminal(2, "finished", Some(0));
        let events = log.snapshot();
        assert_eq!(events.len(), LOG_CAP + 2);
        assert_eq!(events[LOG_CAP].kind, "finished");
        assert_eq!(events[LOG_CAP + 1].kind, "elided");
        assert_eq!(events[LOG_CAP + 1].count, Some(30));
        // Not consuming: a failed commit retries with the same log.
        assert_eq!(log.snapshot().len(), LOG_CAP + 2);
    }

    #[test]
    fn quiet_threshold() {
        assert_eq!(quiet_after_secs(0), 60);
        assert_eq!(quiet_after_secs(20), 5);
        assert_eq!(quiet_after_secs(600), 60);
    }

    #[test]
    fn error_path_warns_are_paced_per_distinct_error_and_per_site() {
        // Test-local pacers: module statics used by production Drop paths must
        // not carry state into or out of this test.
        static SITE_A: OnceLock<Mutex<crate::api::outbound::ErrorDeduper>> = OnceLock::new();
        static SITE_B: OnceLock<Mutex<crate::api::outbound::ErrorDeduper>> = OnceLock::new();
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            warn_once_per_interval("site a", &SITE_A, "boom", "first message");
            warn_once_per_interval("site a", &SITE_A, "boom", "first message");
            warn_once_per_interval("site a", &SITE_A, "changed", "first message");
            warn_once_per_interval("site b", &SITE_B, "boom", "second message");
        });
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("first message"))
                .count(),
            2,
            "the repeat is paced away, a changed error logs immediately"
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("second message"))
                .count(),
            1,
            "each site paces independently"
        );
    }
}

#[cfg(test)]
mod pin_tests {
    use super::*;

    fn dummy_sender() -> mpsc::Sender<Cmd> {
        mpsc::channel(1).0
    }

    fn admission(
        id: &str,
        bytes: u64,
        max_total_bytes: u64,
        max_tenant_sessions: u64,
    ) -> SessionAdmission {
        SessionAdmission {
            id: id.to_owned(),
            link_id: "link".to_owned(),
            tenant: "acme".to_owned(),
            reserved_bytes: bytes,
            max_total_bytes: Some(max_total_bytes),
            max_tenant_sessions: Some(max_tenant_sessions),
            max_link_sessions: usize::MAX,
            max_sessions: usize::MAX,
            kind: SessionKind::Http,
        }
    }

    #[test]
    fn insert_fails_while_the_tenant_is_pinned() {
        let sessions = Sessions::new();
        let _pin = sessions.try_pin_tenant("acme").unwrap();
        assert!(sessions.tenant_pinned("acme"));
        let err = sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                "acme".to_owned(),
                dummy_sender(),
            )
            .unwrap_err();
        assert_eq!(err, InsertError::TenantPinned);
        assert_eq!(sessions.total(), 0);

        drop(_pin);
        assert!(!sessions.tenant_pinned("acme"));
        sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                "acme".to_owned(),
                dummy_sender(),
            )
            .unwrap();
        assert_eq!(sessions.total(), 1);
    }

    #[test]
    fn resumed_sessions_measure_their_own_active_time() {
        let sessions = Sessions::new();
        sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                "acme".to_owned(),
                dummy_sender(),
            )
            .unwrap();
        // The server was down for an hour when the sender re-attached: the
        // live view keeps the session's original wall-clock start, while the
        // monotonic start stays at the re-attach, so the upload-duration
        // metric charges only the resumed session's own active time.
        sessions.seed_resumed("s1", now_unix() - 3600, 1024);
        let handle = sessions.remove("s1").unwrap();
        assert_eq!(handle.started_at, now_unix() - 3600);
        assert!(handle.active_seconds() < 5, "monotonic start was rewound");
    }

    #[test]
    fn shutdown_admission_is_irreversible_and_owned_work_finishes() {
        let sessions = Sessions::new();
        let guard = sessions.try_admit().expect("admission before stop");
        assert!(sessions.close_admission());
        assert!(!sessions.close_admission());

        sessions
            .insert_admitted_with_guard(
                admission("owned", 1, 100, 2),
                dummy_sender(),
                || Ok((0, Vec::new())),
                guard,
            )
            .expect("owned setup may finish after stop");
        assert_eq!(sessions.total(), 1);
        let _ = sessions.take_http();
        assert!(matches!(
            sessions.insert_admitted(admission("late", 1, 100, 2), dummy_sender(), || Ok((
                0,
                Vec::new()
            )),),
            Err(InsertError::ShuttingDown)
        ));
        assert!(sessions.try_admit().is_none());
    }

    #[test]
    fn pin_is_exclusive() {
        let sessions = Sessions::new();
        let _pin = sessions.try_pin_tenant("acme").unwrap();
        assert!(sessions.try_pin_tenant("acme").is_none());
        assert!(sessions.tenant_pinned("acme"));
        drop(_pin);
        assert!(!sessions.tenant_pinned("acme"));
        let _pin = sessions.try_pin_tenant("acme").unwrap();
    }

    #[test]
    fn delete_pin_blocks_new_outbound_operations_while_active_count_remains() {
        let sessions = Sessions::new();
        let operation = sessions.try_begin_outbound("acme").unwrap();
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 1);
        let _pin = sessions.try_pin_tenant("acme").unwrap();
        assert!(sessions.try_begin_outbound("acme").is_none());
        drop(operation);
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 0);
        drop(_pin);
    }

    #[test]
    fn owned_outbound_operation_keeps_tenant_admitted_until_drop() {
        let sessions = Sessions::new();
        let operation = sessions.try_begin_outbound_owned("acme").unwrap();
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 1);
        let _pin = sessions.try_pin_tenant("acme").unwrap();
        assert!(sessions.try_begin_outbound_owned("acme").is_none());
        drop(operation);
        assert_eq!(sessions.active_outbound_for_tenant("acme"), 0);
        drop(_pin);
    }

    #[test]
    fn pin_does_not_apply_to_the_default_tenant() {
        let sessions = Sessions::new();
        assert!(sessions.try_pin_tenant("").is_none());
        assert!(!sessions.tenant_pinned(""));
        sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                String::new(),
                dummy_sender(),
            )
            .unwrap();
    }

    #[test]
    fn admission_reserves_bytes_and_session_slots_without_overflow() {
        let sessions = Sessions::new();
        sessions
            .insert_admitted(admission("s1", 60, 100, 2), dummy_sender(), || {
                Ok((0, Vec::new()))
            })
            .unwrap();
        let mut full = admission("full", 1, 100, 2);
        full.tenant = "other".to_owned();
        full.max_sessions = 1;
        assert_eq!(
            sessions.insert_admitted(full, dummy_sender(), || Ok((0, Vec::new()))),
            Err(InsertError::Capacity)
        );
        assert_eq!(
            sessions.insert_admitted(admission("s2", 60, 100, 2), dummy_sender(), || Ok((
                0,
                Vec::new()
            )),),
            Err(InsertError::ByteQuota)
        );
        assert_eq!(
            sessions.insert_admitted(
                admission("s2", u64::MAX, u64::MAX, 1),
                dummy_sender(),
                || Ok((0, Vec::new())),
            ),
            Err(InsertError::TenantSessionLimit)
        );
        sessions.remove("s1");
        assert_eq!(
            sessions.insert_admitted(admission("stale", 60, 100, 1), dummy_sender(), || Ok((
                60,
                Vec::new()
            )),),
            Err(InsertError::ByteQuota)
        );
        assert_eq!(
            sessions.insert_admitted(admission("full", 1, u64::MAX, 1), dummy_sender(), || Ok((
                u64::MAX,
                Vec::new()
            )),),
            Err(InsertError::ByteQuota)
        );
        sessions
            .insert_admitted(
                admission("s2", u64::MAX, u64::MAX, 1),
                dummy_sender(),
                || Ok((0, Vec::new())),
            )
            .unwrap();
    }

    #[test]
    fn retained_admissions_stay_charged_without_counting_active_sessions_twice() {
        let usage = || {
            Ok((
                0,
                vec![crate::store::RetainedReservation {
                    id: "existing".into(),
                    push_key: Some("checkpoint".into()),
                    bytes: 60,
                }],
            ))
        };
        let sessions = Sessions::new();
        sessions
            .insert_admitted(admission("existing", 60, 100, 10), dummy_sender(), || {
                Ok((0, Vec::new()))
            })
            .unwrap();
        sessions
            .insert_admitted(admission("other", 40, 100, 10), dummy_sender(), usage)
            .unwrap();
        sessions.remove("existing");
        assert_eq!(
            sessions.insert_admitted(admission("new", 1, 100, 10), dummy_sender(), usage),
            Err(InsertError::ByteQuota)
        );
        let mut resume = admission("resume", 60, 100, 10);
        resume.kind = SessionKind::Push(PushControl::resumable("checkpoint".into(), None));
        sessions
            .insert_admitted(resume, dummy_sender(), usage)
            .unwrap();
        sessions.remove("other");
        sessions
            .insert_admitted(admission("replacement", 40, 100, 10), dummy_sender(), usage)
            .unwrap();
    }

    #[test]
    fn parked_push_replacement_excludes_its_own_slot_and_bytes_only() {
        let sessions = Sessions::new();
        let old = PushControl::resumable("same".to_owned(), None);
        let mut first = admission("first", 60, 100, 1);
        first.kind = SessionKind::Push(old);
        first.max_sessions = 1;
        first.max_link_sessions = 1;
        sessions
            .insert_admitted(first, dummy_sender(), || Ok((0, Vec::new())))
            .unwrap();
        let make_retry = || {
            let mut next = admission("next", 60, 100, 1);
            next.kind = SessionKind::Push(PushControl::resumable("same".to_owned(), None));
            next.max_sessions = 1;
            next.max_link_sessions = 1;
            next
        };
        assert_eq!(
            sessions.insert_admitted(make_retry(), dummy_sender(), || Ok((41, Vec::new()))),
            Err(InsertError::ByteQuota)
        );
        assert!(sessions.contains_push("first"));
        sessions
            .insert_admitted(make_retry(), dummy_sender(), || Ok((40, Vec::new())))
            .unwrap();
        assert!(!sessions.contains_push("first"));
        assert!(sessions.contains_push("next"));
        assert_eq!(
            sessions.inner.lock().unwrap().map["next"].reserved_bytes,
            60
        );
        let mut foreign = make_retry();
        foreign.id = "foreign".to_owned();
        foreign.kind = SessionKind::Push(PushControl::resumable("other".to_owned(), None));
        assert_eq!(
            sessions.insert_admitted(foreign, dummy_sender(), || Ok((0, Vec::new()))),
            Err(InsertError::Capacity)
        );
    }

    #[test]
    fn push_touch_is_rejected_without_changing_activity() {
        let sessions = Sessions::new();
        let mut push = admission("push", 0, 100, 1);
        push.kind = SessionKind::Push(PushControl::new());
        sessions
            .insert_admitted(push, dummy_sender(), || Ok((0, Vec::new())))
            .unwrap();

        assert!(matches!(sessions.touch("push"), Err(TouchError::WrongKind)));
        assert!(matches!(
            sessions.touch("missing"),
            Err(TouchError::NotFound)
        ));
        assert_eq!(sessions.active_for_link("link"), 1);
        sessions.sweep(0);
        assert_eq!(sessions.total(), 0);
    }

    #[test]
    fn connected_push_is_cancelled_and_retained_by_idle_sweep() {
        let sessions = Sessions::new();
        let control = PushControl::new();
        let mut push = admission("push", 0, 100, 1);
        push.kind = SessionKind::Push(control.clone());
        sessions
            .insert_admitted(push, dummy_sender(), || Ok((0, Vec::new())))
            .unwrap();

        assert!(sessions.contains_push("push"));
        assert!(control.connect());
        assert!(!control.connect());
        assert!(sessions.push_lease("missing").is_none());
        let lease = sessions.push_lease("push").unwrap();
        sessions.sweep(0);
        assert!(!control.is_cancelled());
        drop(lease);
        sessions.sweep(0);

        assert!(control.is_cancelled());
        assert!(!control.is_aborted());
        assert!(sessions.contains_push("push"));
        assert_eq!(sessions.total(), 1);
    }

    #[test]
    fn abort_marks_push_as_sender_cancelled() {
        let control = PushControl::new();
        control.abort();
        assert!(control.is_cancelled());
        assert!(control.is_aborted());
    }

    #[test]
    fn push_admission_reserves_bytes_until_removal() {
        let sessions = Sessions::new();
        let mut first = admission("push-1", 60, 100, 2);
        first.kind = SessionKind::Push(PushControl::new());
        sessions
            .insert_admitted(first, dummy_sender(), || Ok((0, Vec::new())))
            .unwrap();

        let mut second = admission("push-2", 50, 100, 2);
        second.kind = SessionKind::Push(PushControl::new());
        assert_eq!(
            sessions.insert_admitted(second, dummy_sender(), || Ok((0, Vec::new()))),
            Err(InsertError::ByteQuota)
        );

        sessions.remove("push-1");
        let mut admitted = admission("push-2", 50, 100, 2);
        admitted.kind = SessionKind::Push(PushControl::new());
        sessions
            .insert_admitted(admitted, dummy_sender(), || Ok((0, Vec::new())))
            .unwrap();
    }

    #[test]
    fn sweep_keeps_cancelled_dispatch_commands_registered_until_worker_finishes() {
        let sessions = Sessions::new();
        let (sender, mut receiver) = mpsc::channel(1);
        sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                "acme".to_owned(),
                sender,
            )
            .unwrap();
        let command = sessions.touch("s1").unwrap();
        let (reply, cancelled_dispatch) = oneshot::channel();
        drop(cancelled_dispatch);
        assert!(command
            .sender
            .try_send(Cmd::Finish {
                reply,
                _lease: command.lease,
            })
            .is_ok());
        sessions.sweep(0);
        assert_eq!(sessions.total(), 1);
        let Cmd::Finish { reply, _lease } = receiver.try_recv().unwrap() else {
            panic!("finish command");
        };
        sessions.sweep(0);
        assert_eq!(sessions.total(), 1);
        *_lease
            .activity
            .last_active
            .lock()
            .expect("session activity poisoned") =
            Instant::now() - std::time::Duration::from_secs(2);
        assert!(reply
            .send(Ok(FinishReport {
                received: 0,
                upload_id: "upload".to_owned(),
                files: Vec::new(),
            }))
            .is_err());
        drop(_lease);
        sessions.sweep(1);
        assert_eq!(sessions.total(), 1);
        sessions.sweep(0);
        assert_eq!(sessions.total(), 0);
    }

    #[test]
    fn insert_fails_while_the_link_is_pinned() {
        let sessions = Sessions::new();
        assert!(sessions.pin_link_for_delete("link"));
        let err = sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                String::new(),
                dummy_sender(),
            )
            .unwrap_err();
        assert_eq!(err, InsertError::LinkPinned);
        assert_eq!(sessions.total(), 0);

        sessions.unpin_link("link");
        sessions
            .insert(
                "s1".to_owned(),
                "link".to_owned(),
                String::new(),
                dummy_sender(),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn cancelled_task_releases_link_pin() {
        let sessions = Arc::new(Sessions::new());
        let (entered_tx, entered_rx) = oneshot::channel();
        let task = tokio::spawn({
            let sessions = Arc::clone(&sessions);
            async move {
                let _pin = sessions.try_pin_link("link").unwrap();
                let _ = entered_tx.send(());
                std::future::pending::<()>().await;
            }
        });
        entered_rx.await.unwrap();
        task.abort();
        let _ = task.await;

        assert!(sessions.pin_link_for_delete("link"));
        sessions.unpin_link("link");
    }
}

#[cfg(test)]
mod push_tests {
    use super::*;
    use vot_sdk::object::{InMemoryObjectBuilder, Suite};
    use vot_sdk::package::{PackageBuilder, PackageEntry};

    fn open_destination_for(
        setup: &WorkerSetup,
        components: Vec<String>,
        object: ObjectId,
    ) -> Result<FileState, SessionError> {
        super::open_destination_for(setup, components, object, &Mutex::default())
    }

    fn object(suite: Suite, data: &[u8]) -> ObjectId {
        let mut builder =
            InMemoryObjectBuilder::new(suite, Some(data.len() as u64), data.len() as u64).unwrap();
        builder.update(data).unwrap();
        builder.finish().unwrap().object_id().clone()
    }

    fn empty_manifest(count: usize) -> (ObjectId, Vec<u8>, Vec<u8>, Vec<vot_cli::EntryRecord>) {
        let empty = object(Suite::Blake3Bao64, b"");
        let mut builder = PackageBuilder::new().unwrap();
        let mut records = Vec::with_capacity(count);
        for index in 0..count {
            let name = format!("empty-{index:04}");
            let path = vot_manifest::PackagePath::portable([name.as_str()]).unwrap();
            let entry = PackageEntry::direct(vec![name], &empty).unwrap();
            assert!(builder.push(&entry).unwrap().is_none());
            records.push(record(path, &empty));
        }
        let (summary, final_page, mut finalizer) = builder.finish().unwrap().into_parts();
        let page = finalizer.push(final_page).unwrap().into_bytes();
        let seal = finalizer.finish().unwrap().into_bytes();
        (summary.object_id(), page, seal, records)
    }

    fn setup(directory: &std::path::Path, expected_package: ObjectId) -> WorkerSetup {
        let app = crate::api::testing::build(directory);
        setup_with_app(directory, expected_package, &app)
    }

    fn setup_with_app(
        directory: &std::path::Path,
        expected_package: ObjectId,
        app: &crate::app::App,
    ) -> WorkerSetup {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory.join("receive"))
            .unwrap();
        WorkerSetup {
            store: Arc::clone(&app.store),
            link_id: "link".to_owned(),
            tenant: String::new(),
            client_ip: String::new(),
            dest_dir: directory.join("receive"),
            destinations: Arc::new(
                crate::receiving::Destinations::configured(&directory.join("receive"), &app.store)
                    .unwrap(),
            ),
            dest_rel: String::new(),
            expected_package,
            max_total_bytes: u64::MAX,
            allow_hidden: false,
            verification: "default".to_owned(),
            signer: Arc::clone(&app.signer),
            session_id: [7; 16],
            started_at: 1,
            quiet_after_secs: 5,
            ended: mpsc::unbounded_channel().0,
            checkpoint_warn: CheckpointWarnPacer::new(),
        }
    }

    /// FileState stores the admitted path as one NUL-joined string; tests
    /// that need the component list back split on that separator.
    fn split_components(joined: &str) -> Vec<String> {
        joined.split('\0').map(str::to_owned).collect()
    }

    #[test]
    fn session_event_writer_reports_store_errors() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(crate::store::Store::open(directory.path()).unwrap());
        store
            .with(|connection| connection.execute_batch("DROP TABLE links"))
            .unwrap();
        let (ended_sender, mut ended_receiver) = mpsc::unbounded_channel();
        let error = record_session_event(
            &store,
            &ended_sender,
            "",
            "deleted-link",
            "",
            "",
            crate::store::SessionEvent {
                at: 2,
                started_at: 1,
                outcome: "cancelled".to_owned(),
                detail: "test cancellation".to_owned(),
                received_bytes: 0,
                expected_bytes: 10,
                replayed_chunks: 0,
                rejected_chunks: 0,
            },
        )
        .unwrap_err();
        assert!(error.contains("no such table: links"), "{error}");
        let ended = ended_receiver.try_recv().unwrap();
        assert_eq!(ended.link_id, "deleted-link");
        assert!(ended.label.is_empty());
        assert!(ended.notifications.is_none());
    }

    #[test]
    fn ended_session_rows_carry_the_session_tag_and_detail() {
        let directory = tempfile::tempdir().unwrap();
        let setup = setup(directory.path(), object(Suite::Blake3Bao64, b""));
        record_event(&setup, 3, 2, "cancelled", "sender hung up".to_owned(), 1, 0);
        let rows = setup.store.audit_export(None, 0, 0, 100).unwrap();
        let row = rows
            .iter()
            .find(|row| row.event == "upload_session_ended")
            .expect("the ended session leaves an audit row");
        assert_eq!(row.detail["session_tag"], "07070707");
        assert_eq!(row.detail["detail"], "sender hung up");
    }

    #[tokio::test]
    async fn queued_begin_is_rejected_by_worker_after_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let setup = setup_with_app(directory.path(), object(Suite::Blake3Bao64, b""), &app);
        let (sender, receiver) = mpsc::channel(1);
        spawn_worker(setup, receiver);
        let activity = Arc::new(SessionActivity {
            in_flight: AtomicUsize::new(1),
            last_active: Mutex::new(Instant::now()),
            received: AtomicU64::new(0),
        });
        let (reply, result) = oneshot::channel();
        app.request_shutdown();
        sender
            .send(Cmd::Begin {
                reply,
                _lease: SessionLease { activity },
                stopping: Arc::clone(&app.stopping),
            })
            .await
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), result)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.status, 503);
    }

    fn record_delivered_files(setup: &WorkerSetup, files: Vec<FileRecord>) {
        let mut link = crate::store::tests::test_link(&setup.link_id);
        link.uploads.push(UploadRecord {
            id: "delivered".into(),
            started_at: 0,
            completed_at: 1,
            replayed_chunks: 0,
            rejected_chunks: 0,
            transport: None,
            package_root: hex::encode(setup.expected_package.root),
            total_bytes: 0,
            files,
            partial: false,
            log: Vec::new(),
        });
        setup.store.insert_link(link).unwrap();
    }

    #[tokio::test]
    async fn push_activity_does_not_store_wall_clock_seconds() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let setup = setup_with_app(directory.path(), object(Suite::Blake3Bao64, b""), &app);
        let control = PushControl::new();
        let (_seams, handle) = push_seams(
            Arc::clone(&app),
            setup,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();

        receive.mark_active();
        assert!(
            receive.last_active.load(Ordering::Acquire)
                <= receive.activity_origin.elapsed().as_secs(),
            "push activity must use process elapsed time, not Unix seconds"
        );
    }

    #[tokio::test]
    async fn push_activity_refresh_keeps_progress_live_for_idle_sweep() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let setup = setup_with_app(directory.path(), object(Suite::Blake3Bao64, b""), &app);
        let id = hex::encode(setup.session_id);
        let control = PushControl::new();
        assert!(control.connect());
        let (sender, _) = mpsc::channel(1);
        app.sessions
            .insert_admitted(
                SessionAdmission {
                    id: id.clone(),
                    link_id: setup.link_id.clone(),
                    tenant: setup.tenant.clone(),
                    reserved_bytes: 0,
                    max_total_bytes: None,
                    max_tenant_sessions: None,
                    max_link_sessions: usize::MAX,
                    max_sessions: usize::MAX,
                    kind: SessionKind::Push(control.clone()),
                },
                sender,
                || Ok((0, Vec::new())),
            )
            .unwrap();
        let (_seams, handle) = push_seams(
            Arc::clone(&app),
            setup,
            control.clone(),
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        let stale = || {
            let activity = {
                let inner = app.sessions.inner.lock().unwrap();
                Arc::clone(&inner.map[&id].activity)
            };
            *activity.last_active.lock().unwrap() = Instant::now() - Duration::from_secs(60);
        };

        // Elapsed ticks continue after a hypothetical wall-clock rollback.
        receive.mark_active_at(1);
        stale();
        receive.mark_active_at(2);
        app.sessions.sweep(30);

        assert!(!control.is_cancelled());
        assert!(app.sessions.contains_push(&id));
        assert_eq!(receive.last_active.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn admission_reads_policy_and_events_without_unrelated_upload_headers() {
        use vot_sdk::package::{PackageBuilder, PackageEntry};

        for native in [false, true] {
            for count in [1, 0] {
                if !native && count == 0 {
                    continue;
                }
                for corruption in ["header", "events", "missing", "tenant"] {
                    let directory = tempfile::tempdir().unwrap();
                    let app = crate::api::testing::build(directory.path());
                    let expected = object(Suite::Blake3Bao64, b"new content");
                    let (package, page, seal) = if count == 0 {
                        (object(Suite::Blake3Bao64, b""), Vec::new(), Vec::new())
                    } else {
                        let mut builder = PackageBuilder::new().unwrap();
                        assert!(builder
                            .push(
                                &PackageEntry::direct(
                                    vec!["new".into(), "frame".into()],
                                    &expected
                                )
                                .unwrap()
                            )
                            .unwrap()
                            .is_none());
                        let (summary, page, mut finalizer) = builder.finish().unwrap().into_parts();
                        let page = finalizer.push(page).unwrap().into_bytes();
                        let seal = finalizer.finish().unwrap().into_bytes();
                        (summary.object_id().clone(), page, seal)
                    };
                    let mut setup = setup_with_app(directory.path(), package.clone(), &app);
                    if corruption != "missing" {
                        app.store
                            .insert_link(crate::store::tests::test_link("link"))
                            .unwrap();
                    }
                    match corruption {
                        "header" => app.store.with(|c| c.execute_batch("INSERT INTO link_uploads (link_id, tenant, upload_id, document, file_count) VALUES ('link', '', 'unrelated', '{', 0)")).unwrap(),
                        "events" => app.store.with(|c| c.execute_batch("UPDATE links SET events_json='{' WHERE id='link'")).unwrap(),
                        "tenant" => setup.tenant = "other".into(),
                        _ => {}
                    }
                    let result = if native {
                        let (_seams, handle) = push_seams(
                            app.clone(),
                            setup,
                            PushControl::default(),
                            tokio::runtime::Handle::current(),
                        );
                        let receive = handle.0.upgrade().unwrap();
                        let records = if count == 0 {
                            Vec::new()
                        } else {
                            vec![record(
                                vot_manifest::PackagePath::portable(["new", "frame"]).unwrap(),
                                &expected,
                            )]
                        };
                        receive.prepare_manifest(
                            vot_cli::PackageSummary {
                                root: package.root,
                                logical_length: package.length,
                                entries: count,
                            },
                            &records,
                        )
                    } else {
                        let mut phase = Phase::AwaitSeal;
                        handle_seal(&setup, &mut phase, &seal).unwrap();
                        handle_page(&mut phase, &page).unwrap();
                        handle_begin(&setup, &mut phase).map(|_| ())
                    };
                    if count == 0 {
                        assert_eq!(result.unwrap_err().status, 422);
                        assert!(!directory.path().join("receive/new").exists());
                        assert!(app.store.load_upload_sessions().unwrap().is_empty());
                    } else if corruption == "header" {
                        assert!(result.is_ok(), "native={native}, count={count}: {result:?}");
                    } else {
                        assert!(
                            result.is_err(),
                            "native={native}, count={count}, corruption={corruption}"
                        );
                        assert!(!directory.path().join("receive/new").exists());
                        assert!(app.store.load_upload_sessions().unwrap().is_empty());
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn empty_entry_admission_stays_bounded_for_http_and_native() {
        let cap = 1024 * 1024;
        let count = max_entries_for_bytes(cap) + 1;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let (package, page, seal, records) = empty_manifest(count);
        let mut setup = setup_with_app(directory.path(), package.clone(), &app);
        setup.max_total_bytes = cap;

        let mut phase = Phase::AwaitSeal;
        handle_seal(&setup, &mut phase, &seal).unwrap();
        let error = handle_page(&mut phase, &page).unwrap_err();
        assert_eq!(error.status, 422);
        assert!(error.message.contains("512 entries"), "{}", error.message);
        let begin = handle_begin(&setup, &mut phase).unwrap_err();
        assert_eq!(begin.status, 422);
        assert!(begin.message.contains("does not match manifest"));
        assert!(std::fs::read_dir(&setup.dest_dir).unwrap().next().is_none());
        assert!(app.store.load_upload_sessions().unwrap().is_empty());

        let error = validate_push_manifest(
            &setup,
            vot_cli::PackageSummary {
                root: package.root,
                logical_length: package.length,
                entries: count as u64,
            },
            &records,
        )
        .unwrap_err();
        assert_eq!(error.status, 422);
        assert!(error.message.contains("1..=512"), "{}", error.message);
        assert!(std::fs::read_dir(&setup.dest_dir).unwrap().next().is_none());
        assert!(app.store.load_upload_sessions().unwrap().is_empty());
    }

    /// Audit finding 503: the pinned manifest folds keys per character, so a
    /// package can carry two spellings a case-insensitive recipient collapses
    /// (final sigma, long s). Both admission seams refuse the pair before a
    /// byte moves.
    #[tokio::test]
    async fn fold_collisions_are_refused_at_http_and_native_admission() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        // Sorted by the pinned manifest's per-character keys, so the builder
        // itself accepts the package; the admission guard must refuse it.
        for (first, second) in [("σίσυφος.mov", "ΣΊΣΥΦΟΣ.mov"), ("straße.mov", "ſtraße.mov")]
        {
            let payload = object(Suite::Blake3Bao64, b"payload");
            let mut builder = PackageBuilder::new().unwrap();
            for name in [first, second] {
                let entry = PackageEntry::direct(vec![name.to_string()], &payload).unwrap();
                assert!(builder.push(&entry).unwrap().is_none());
            }
            let (summary, final_page, mut finalizer) = builder.finish().unwrap().into_parts();
            let page = finalizer.push(final_page).unwrap().into_bytes();
            let seal = finalizer.finish().unwrap().into_bytes();
            let setup = setup_with_app(directory.path(), summary.object_id().clone(), &app);

            let mut phase = Phase::AwaitSeal;
            handle_seal(&setup, &mut phase, &seal).unwrap();
            handle_page(&mut phase, &page).unwrap();
            let error = handle_begin(&setup, &mut phase).unwrap_err();
            assert!(error.message.contains("collide"), "{}", error.message);

            let error = validate_push_manifest(
                &setup,
                vot_cli::PackageSummary {
                    root: summary.object_id().root,
                    logical_length: 2 * payload.length,
                    entries: 2,
                },
                &[
                    record(
                        vot_manifest::PackagePath::portable([first]).unwrap(),
                        &payload,
                    ),
                    record(
                        vot_manifest::PackagePath::portable([second]).unwrap(),
                        &payload,
                    ),
                ],
            )
            .unwrap_err();
            assert!(error.message.contains("collide"), "{}", error.message);
        }
        assert!(app.store.load_upload_sessions().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exact_empty_entry_limit_is_accepted_by_http_begin_and_native() {
        let cap = 1024 * 1024;
        let count = max_entries_for_bytes(cap);
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let (package, page, seal, records) = empty_manifest(count);
        let mut setup = setup_with_app(directory.path(), package.clone(), &app);
        setup.max_total_bytes = cap;

        let mut phase = Phase::AwaitSeal;
        handle_seal(&setup, &mut phase, &seal).unwrap();
        assert_eq!(handle_page(&mut phase, &page).unwrap(), 0);
        let files = handle_begin(&setup, &mut phase).unwrap();
        assert_eq!(files.len(), count);
        assert_eq!(app.store.load_upload_sessions().unwrap().len(), 1);

        let validated = validate_push_manifest(
            &setup,
            vot_cli::PackageSummary {
                root: package.root,
                logical_length: package.length,
                entries: count as u64,
            },
            &records,
        )
        .unwrap();
        assert_eq!(validated.len(), count);
    }

    #[tokio::test]
    async fn concurrent_uploads_reserve_names_across_overlapping_destinations() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            for nested_destination in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let application = crate::api::testing::build(directory.path());
                let first_object = object(suite, b"first");
                let second_object = object(suite, b"second");
                let first = setup_with_app(directory.path(), first_object.clone(), &application);
                let mut second =
                    setup_with_app(directory.path(), second_object.clone(), &application);
                second.session_id = [8; 16];
                second.link_id = "other".into();
                let first_entries =
                    [(vec!["project".into(), "frame".into()], first_object.clone())];
                let second_name = if nested_destination {
                    second.dest_dir.push("project");
                    second.dest_rel = "project".into();
                    vec!["frame".into()]
                } else {
                    vec!["project".into(), "frame".into()]
                };
                for setup in [&first, &second] {
                    let mut link = crate::store::tests::test_link(&setup.link_id);
                    link.dest = setup.dest_rel.clone();
                    application.store.insert_link(link).unwrap();
                }
                let second_entries = [(second_name, second_object.clone())];
                let (ready, waiting) = std::sync::mpsc::channel();
                let (mut first_files, mut second_files) = std::thread::scope(|scope| {
                    let (start_a, a_start) = std::sync::mpsc::channel();
                    let (start_b, b_start) = std::sync::mpsc::channel();
                    let prepare =
                        |setup: &WorkerSetup,
                         entries: &[(Vec<String>, ObjectId)],
                         start: std::sync::mpsc::Receiver<()>| {
                            ready.send(()).unwrap();
                            start.recv_timeout(Duration::from_secs(5)).unwrap();
                            let (files, allocation) =
                                prepare_files(setup, entries, || true).unwrap();
                            persist_session(setup, &files).unwrap();
                            drop(allocation);
                            files
                        };
                    let a_input = (&first, &first_entries[..]);
                    let b_input = (&second, &second_entries[..]);
                    let a = scope.spawn(move || prepare(a_input.0, a_input.1, a_start));
                    let b = scope.spawn(move || prepare(b_input.0, b_input.1, b_start));
                    for _ in 0..2 {
                        waiting.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    start_a.send(()).unwrap();
                    start_b.send(()).unwrap();
                    (a.join().unwrap(), b.join().unwrap())
                });
                let first_path = paths::join_under(
                    &first.dest_dir,
                    &split_components(&first_files[0].stored_components),
                )
                .unwrap();
                let second_path = paths::join_under(
                    &second.dest_dir,
                    &split_components(&second_files[0].stored_components),
                )
                .unwrap();
                assert_ne!(
                    first_path, second_path,
                    "admitted uploads must own distinct final names before publication"
                );
                for (setup, files, bytes, object) in [
                    (&first, &mut first_files, b"first".as_slice(), &first_object),
                    (
                        &second,
                        &mut second_files,
                        b"second".as_slice(),
                        &second_object,
                    ),
                ] {
                    let source = directory.path().join("source");
                    fs::write(&source, bytes).unwrap();
                    reprove_staging(&source, object, vec![&mut files[0]], || true).unwrap();
                    publish_file(setup, &mut files[0], || true).unwrap();
                    commit_upload(setup, files, 0, 0, Some("http"), Vec::new()).unwrap();
                }
                assert_eq!(fs::read(first_path).unwrap(), b"first");
                assert_eq!(fs::read(second_path).unwrap(), b"second");
            }
        }
    }

    /// Audit finding 373: a live record resurrected by a restore can still
    /// claim a stored name under different content; preparation must take a
    /// suffixed name instead of reusing the claimed one, while a record of
    /// the same identity leaves the name reusable.
    #[test]
    fn preparation_avoids_stored_names_claimed_by_other_records() {
        let directory = tempfile::tempdir().unwrap();
        let fresh = object(Suite::Blake3Bao64, b"fresh bytes");
        let old = object(Suite::Blake3Bao64, b"old bytes..");
        let suite = suite_name(fresh.suite);
        let app = crate::api::testing::build(directory.path());
        let setup = setup_with_app(directory.path(), fresh.clone(), &app);
        let insert = |link: &str, stored_as: &str, root: &str| {
            let suite = suite.clone();
            app.store.with(move |connection| {
                connection.execute(
                    "INSERT INTO files(link_id,tenant,upload_id,file_index,bytes_hi,bytes_lo,
                        deleted,stored_as,path,suite,root,receipt)
                     VALUES (?1,'','old',0,0,11,0,?2,?2,?3,?4,0)",
                    rusqlite::params![link, stored_as, suite, root],
                )
            })
        };
        insert("link-a", "frame", &hex::encode(old.root)).unwrap();
        let entries = [(vec!["frame".into()], fresh.clone())];
        let (files, allocation) = prepare_files(&setup, &entries, || true).unwrap();
        drop(allocation);
        assert_eq!(
            files[0].stored_components, "frame-1",
            "a name claimed by a different root must be skipped"
        );
        drop(files);
        insert("link-b", "take", &hex::encode(fresh.root)).unwrap();
        let entries = [(vec!["take".into()], fresh)];
        let (files, allocation) = prepare_files(&setup, &entries, || true).unwrap();
        drop(allocation);
        assert_eq!(
            files[0].stored_components, "take",
            "a same-identity record leaves the name reusable"
        );
    }

    #[test]
    fn publication_reserves_receipt_filename_bytes() {
        for name in ["a".repeat(242), format!("{}ab", "ア".repeat(80))] {
            let directory = tempfile::tempdir().unwrap();
            let bytes = b"frame";
            let object = object(Suite::Blake3Bao64, bytes);
            let setup = setup(directory.path(), object.clone());
            let parent = "p".repeat(255);
            let source = directory.path().join("source");
            fs::write(&source, bytes).unwrap();
            let entries = [(vec![parent.clone(), name.clone()], object.clone())];
            let (mut files, allocation) = prepare_files(&setup, &entries, || true).unwrap();
            drop(allocation);
            let file = &mut files[0];
            reprove_staging(&source, &object, vec![file], || true).unwrap();
            publish_file(&setup, file, || true).unwrap();
            let destination = setup.dest_dir.join(&parent);
            assert_eq!(fs::read(destination.join(&name)).unwrap(), bytes);
            assert!(file.receipt);
            let sidecar = destination.join(format!("{name}.vot-receipt"));
            let receipt = fs::read(&sidecar).unwrap();
            crate::receipt::verify_receipt_with_key(
                &setup.signer.verifying_key(),
                &receipt,
                &object,
            )
            .unwrap();
            let private = destination.join(".vot-stage");
            let before = fs::read_dir(&private).unwrap().count();
            let other = self::object(Suite::Blake3Bao64, b"other");
            // Audit finding 540: the collision suffix used to push a
            // cap-filling name past the budget, refusing every retry as a
            // permanent error. The stem now gives up bytes, so the sibling
            // stages beside the published pair instead.
            let (mut siblings, allocation) =
                prepare_files(&setup, &[(entries[0].0.clone(), other.clone())], || true).unwrap();
            drop(allocation);
            let sibling = &mut siblings[0];
            let sibling_source = directory.path().join("sibling");
            fs::write(&sibling_source, b"other").unwrap();
            reprove_staging(&sibling_source, &other, vec![sibling], || true).unwrap();
            publish_file(&setup, sibling, || true).unwrap();
            let sibling_name = paths::with_suffix(&name, 1);
            assert!(
                crate::protocol_paths::check_payload_name_length(&sibling_name).is_ok(),
                "{sibling_name:?}"
            );
            assert_eq!(fs::read(destination.join(&sibling_name)).unwrap(), b"other");
            assert_eq!(fs::read(destination.join(&name)).unwrap(), bytes);
            assert_eq!(fs::read(&sidecar).unwrap(), receipt);
            // Each published file retains its staged journal until commit,
            // so the sibling adds one to the one the first file left.
            assert_eq!(fs::read_dir(&private).unwrap().count(), before + 1);
        }
    }

    #[test]
    fn oversized_payload_names_refuse_preparation_before_staging() {
        for name in ["a".repeat(243), "ア".repeat(81)] {
            let directory = tempfile::tempdir().unwrap();
            let object = object(Suite::Blake3Bao64, b"frame");
            let setup = setup(directory.path(), object.clone());
            let entries = [
                (vec!["new".into(), "allowed".into()], object.clone()),
                (vec!["new".into(), name], object),
            ];
            let error = prepare_files(&setup, &entries, || true)
                .err()
                .expect("oversized payload admitted");
            assert!(error.message.contains("242 UTF-8 bytes; shorten"));
            assert!(!setup.dest_dir.join("new").exists());
        }
    }

    #[tokio::test]
    async fn native_and_http_admissions_share_persisted_names() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        application
            .store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let bytes = [b"http".as_slice(), b"native-one", b"native-two"];
        let objects = bytes.map(|bytes| object(Suite::Blake3Bao64, bytes));
        let http = setup_with_app(directory.path(), objects[0].clone(), &application);
        let natives = [1, 2].map(|index| {
            let mut setup = setup_with_app(directory.path(), objects[index].clone(), &application);
            setup.session_id = [index as u8; 16];
            let key = hex::encode([index as u8; 16]);
            setup.destinations.push_directory(&key).unwrap();
            persist_push(&setup, key.clone()).unwrap();
            let (seams, handle) = push_seams(
                application.clone(),
                setup,
                PushControl::resumable(key, None),
                tokio::runtime::Handle::current(),
            );
            (seams, handle.0.upgrade().unwrap())
        });
        let mut files = std::thread::scope(|scope| {
            let (ready, waiting) = std::sync::mpsc::channel();
            let mut starts = Vec::new();
            let workers = natives
                .iter()
                .zip(&objects[1..])
                .map(|((_, receive), object)| {
                    let ready = ready.clone();
                    let (start, waiting) = std::sync::mpsc::channel();
                    starts.push(start);
                    scope.spawn(move || {
                        ready.send(()).unwrap();
                        waiting.recv_timeout(Duration::from_secs(5)).unwrap();
                        for name in ["a".repeat(243), "ア".repeat(81)] {
                            let error = receive
                                .prepare_manifest(
                                    vot_cli::PackageSummary {
                                        root: object.root,
                                        logical_length: object.length,
                                        entries: 1,
                                    },
                                    &[record(
                                        vot_manifest::PackagePath::portable([&name]).unwrap(),
                                        object,
                                    )],
                                )
                                .unwrap_err();
                            assert!(error.message.contains("242 UTF-8 bytes; shorten"));
                            assert!(!receive.setup.dest_dir.join(name).exists());
                        }
                        receive
                            .prepare_manifest(
                                vot_cli::PackageSummary {
                                    root: object.root,
                                    logical_length: object.length,
                                    entries: 1,
                                },
                                &[record(
                                    vot_manifest::PackagePath::portable(["frame"]).unwrap(),
                                    object,
                                )],
                            )
                            .unwrap();
                    })
                })
                .collect::<Vec<_>>();
            for _ in 0..2 {
                waiting.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            for start in starts {
                start.send(()).unwrap();
            }
            let (files, allocation) =
                prepare_files(&http, &[(vec!["frame".into()], objects[0].clone())], || {
                    true
                })
                .unwrap();
            persist_session(&http, &files).unwrap();
            drop(allocation);
            for worker in workers {
                worker.join().unwrap();
            }
            files
        });
        let saved = application.store.load_upload_sessions().unwrap();
        let names = saved
            .iter()
            .map(|session| session.files[0].stored_components.clone())
            .collect::<HashSet<_>>();
        assert_eq!(names.len(), 3);
        let source = directory.path().join("source");
        fs::write(&source, bytes[0]).unwrap();
        reprove_staging(&source, &objects[0], vec![&mut files[0]], || true).unwrap();
        publish_file(&http, &mut files[0], || true).unwrap();
        commit_upload(&http, &files, 0, 0, Some("http"), Vec::new()).unwrap();
        for ((_, receive), (object, bytes)) in
            natives.iter().zip(objects[1..].iter().zip(&bytes[1..]))
        {
            let requested = vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            };
            let sink = Arc::from(receive.choose_sink(&requested).unwrap().unwrap());
            write_push(Arc::clone(&sink), &requested, bytes);
            sink.flush().unwrap();
            receive.complete_object(&requested).unwrap();
        }
        for session in saved {
            let index = if session.id == hex::encode(http.session_id) {
                0
            } else if session.id == hex::encode([1; 16]) {
                1
            } else {
                2
            };
            assert_eq!(
                fs::read(
                    paths::join_under(&http.dest_dir, &session.files[0].stored_components).unwrap()
                )
                .unwrap(),
                bytes[index]
            );
        }
    }

    #[tokio::test]
    async fn parked_native_names_survive_restart_and_competing_admission() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.receive_dir = directory.path().join("receive");
        let application = crate::app::build(config.clone()).unwrap();
        application
            .store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let bytes = &[7_u8; 65537];
        let expected = object(Suite::Blake3Bao64, bytes);
        let first = setup_with_app(directory.path(), expected.clone(), &application);
        let key = hex::encode([3; 16]);
        let stage = first.destinations.push_directory(&key).unwrap();
        persist_push(&first, key.clone()).unwrap();
        let summary = vot_cli::PackageSummary {
            root: expected.root,
            logical_length: expected.length,
            entries: 1,
        };
        let records = [record(
            vot_manifest::PackagePath::portable(["frame"]).unwrap(),
            &expected,
        )];
        let requested = vot_cli::ReceiveObject {
            object: vot_codec::frames::ObjectId {
                suite: expected.suite,
                root: expected.root,
                length: expected.length,
            },
            entries: Vec::new(),
        };
        let control = PushControl::resumable(
            key.clone(),
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            first,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        let sink = Arc::from(receive.choose_sink(&requested).unwrap().unwrap());
        let accept_half = |sink: Arc<dyn vot_cli::ReceiveSink>, offset: u64| {
            let subject = requested.object.try_into().unwrap();
            let length = (bytes.len() as u64 - offset).min(65536);
            let proof = vot_proof_blake3::prove(bytes, offset, length).unwrap();
            let mut verifier =
                vot_scheduler::ReliableReceiver::new(1 << 20, 1 << 20, 1 << 20).unwrap();
            verifier.begin_ranges(subject, Box::new(sink)).unwrap();
            verifier
                .receive_range(subject, offset, &proof.data, &proof.proof)
                .unwrap();
        };
        accept_half(Arc::clone(&sink), 0);
        sink.flush().unwrap();
        drop(sink);
        drop(receive);
        drop(seams);
        let saved = application.store.load_push_sessions().unwrap().remove(0);
        assert_eq!(saved.files[0].prefix_bytes, 65536);
        assert!(!saved.files[0].published);
        drop(application);

        for modified in [
            std::time::SystemTime::UNIX_EPOCH,
            std::time::SystemTime::now() + Duration::from_secs(365 * 86_400),
        ] {
            let lock = lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap();
            lock.set_modified(modified).unwrap();
            drop(lock);
            let application = crate::app::build(config.clone()).unwrap();
            assert!(application.sessions.contains_push_key(&key));
            drop(application);
        }

        let application = crate::app::build(config).unwrap();
        assert_eq!(
            application.store.load_push_sessions().unwrap(),
            std::slice::from_ref(&saved)
        );
        application.sessions.sweep(0);
        assert!(!application.sessions.contains_push_key(&key));
        assert_eq!(
            application
                .store
                .load_push_session(&key)
                .unwrap()
                .unwrap()
                .files[0]
                .prefix_bytes,
            65536
        );
        let competing_object = object(Suite::Blake3Bao64, b"competing");
        let mut competing =
            setup_with_app(directory.path(), competing_object.clone(), &application);
        competing.session_id = [9; 16];
        let (mut files, allocation) = prepare_files(
            &competing,
            &[(vec!["frame".into()], competing_object.clone())],
            || true,
        )
        .unwrap();
        persist_session(&competing, &files).unwrap();
        drop(allocation);
        assert_ne!(
            files[0].stored_components,
            saved.files[0].stored_components.join("\0")
        );
        let mut retry = setup_with_app(directory.path(), expected.clone(), &application);
        retry.session_id = [8; 16];
        persist_push(&retry, key.clone()).unwrap();
        let control = PushControl::resumable(
            key,
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            retry,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        application
            .store
            .with(|c| c.execute_batch("ALTER TABLE files RENAME TO held_files"))
            .unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        application
            .store
            .with(|c| c.execute_batch("ALTER TABLE held_files RENAME TO files"))
            .unwrap();
        let resumed = application.store.load_push_sessions().unwrap().remove(0);
        assert_ne!(resumed.id, saved.id);
        assert_eq!(resumed.files[0], saved.files[0]);
        let sink: Arc<dyn vot_cli::ReceiveSink> =
            Arc::from(receive.choose_sink(&requested).unwrap().unwrap());
        assert_eq!(sink.resumed_prefix().unwrap(), 65536);
        accept_half(Arc::clone(&sink), 65536);
        sink.flush().unwrap();
        drop(sink);
        receive.complete_object(&requested).unwrap();
        drop(receive);
        drop(seams);
        let source = directory.path().join("source");
        fs::write(&source, b"competing").unwrap();
        reprove_staging(&source, &competing_object, vec![&mut files[0]], || true).unwrap();
        publish_file(&competing, &mut files[0], || true).unwrap();
        commit_upload(&competing, &files, 0, 0, Some("http"), Vec::new()).unwrap();
        assert_eq!(fs::read(competing.dest_dir.join("frame")).unwrap(), bytes);
        assert!(competing.dest_dir.join("frame.vot-receipt").is_file());
        assert_eq!(
            fs::read(
                paths::join_under(
                    &competing.dest_dir,
                    &split_components(&files[0].stored_components),
                )
                .unwrap(),
            )
            .unwrap(),
            b"competing"
        );
    }

    #[test]
    fn pending_names_fold_aliases_and_protect_directory_prefixes() {
        for (first_path, second_path, outcome) in [
            (vec!["Straße"], vec!["STRASSE"], "suffix"),
            (vec!["İ"], vec!["ı"], "suffix"),
            (vec!["é"], vec!["e\u{301}"], "suffix"),
            (vec!["folder"], vec!["FOLDER", "child"], "conflict"),
            (vec!["folder", "child"], vec!["FOLDER"], "suffix"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let expected = object(Suite::Blake3Bao64, b"");
            let first = setup(directory.path(), expected.clone());
            let first_path = first_path
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let second_path = second_path
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let (files, allocation) =
                prepare_files(&first, &[(first_path.clone(), expected.clone())], || true).unwrap();
            persist_session(&first, &files).unwrap();
            drop(allocation);
            let result = prepare_files(&first, &[(second_path.clone(), expected.clone())], || true);
            if outcome == "conflict" {
                assert_eq!(result.err().unwrap().status, 409);
            } else {
                let (other, allocation) = result.unwrap();
                drop(allocation);
                assert_ne!(
                    stored_path_key("", &split_components(&other[0].stored_components)).unwrap(),
                    stored_path_key("", &first_path).unwrap()
                );
                assert_ne!(other[0].stored_components, second_path.join("\0"));
            }
        }
    }

    #[test]
    fn failed_admission_and_cancellation_release_only_new_names() {
        let directory = tempfile::tempdir().unwrap();
        let expected = object(Suite::Blake3Bao64, b"frame");
        let application = crate::api::testing::build(directory.path());
        let first = setup_with_app(directory.path(), expected.clone(), &application);
        let mut second = setup_with_app(directory.path(), expected.clone(), &application);
        second.session_id = [8; 16];
        let entries = [(vec!["frame".into()], expected)];
        let (retained, allocation) = prepare_files(&first, &entries, || true).unwrap();
        persist_session(&first, &retained).unwrap();
        drop(allocation);
        application.store.with(|connection| connection.execute_batch(
            "CREATE TRIGGER fail_admission BEFORE INSERT ON upload_sessions BEGIN SELECT RAISE(ABORT, 'fixture'); END;"
        )).unwrap();
        let (failed, allocation) = prepare_files(&second, &entries, || true).unwrap();
        let released_name = failed[0].stored_components.clone();
        assert!(persist_session(&second, &failed).is_err());
        drop(failed);
        drop(allocation);
        application
            .store
            .with(|connection| connection.execute_batch("DROP TRIGGER fail_admission;"))
            .unwrap();
        let active = AtomicUsize::new(0);
        assert!(
            prepare_files(&second, &entries, || active.fetch_add(1, Ordering::Relaxed)
                == 0)
            .is_err()
        );
        let (retry, allocation) = prepare_files(&second, &entries, || true).unwrap();
        drop(allocation);
        assert_eq!(retry[0].stored_components, released_name);
        assert_ne!(retry[0].stored_components, retained[0].stored_components);
        assert_eq!(application.store.load_upload_sessions().unwrap().len(), 1);
        second.tenant = "other".into();
        second.dest_dir =
            paths::join_under(&first.dest_dir, &paths::tenant_prefix("other")).unwrap();
        let (independent, allocation) = prepare_files(&second, &entries, || true).unwrap();
        drop(allocation);
        assert_eq!(
            independent[0].stored_components,
            retained[0].stored_components
        );
    }

    #[test]
    fn pending_names_preserve_destination_policy_and_manifest_depth() {
        for (destination, components) in [
            ("m".repeat(128), vec!["frame".to_owned()]),
            ("archive 1".to_owned(), vec!["frame".to_owned()]),
            ("project".to_owned(), vec!["x".to_owned(); 256]),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let expected = object(Suite::Blake3Bao64, b"frame");
            let application = crate::api::testing::build(directory.path());
            let mut first = setup_with_app(directory.path(), expected.clone(), &application);
            first.dest_rel = paths::admit_dest(&destination).unwrap();
            first.dest_dir.push(destination);
            vot_manifest::PackagePath::portable(components.clone()).unwrap();
            let (files, allocation) =
                prepare_files(&first, &[(components, expected.clone())], || true).unwrap();
            persist_session(&first, &files).unwrap();
            drop(allocation);
            let mut second = setup_with_app(directory.path(), expected.clone(), &application);
            second.session_id = [8; 16];
            second.dest_rel = "unrelated".into();
            second.dest_dir.push("unrelated");
            let (other, allocation) =
                prepare_files(&second, &[(vec!["frame".into()], expected)], || true).unwrap();
            drop(allocation);
            assert_eq!(other[0].stored_components, "frame");
        }
    }

    #[test]
    fn dedupe_reuses_delivered_bytes_only_under_the_announced_name() {
        let directory = tempfile::tempdir().unwrap();
        let expected = object(Suite::Blake3Bao64, b"original");
        let setup = setup(directory.path(), expected.clone());
        fs::write(setup.dest_dir.join("existing.bin"), b"original").unwrap();
        record_delivered_files(
            &setup,
            vec![FileRecord {
                path: "existing.bin".into(),
                stored_as: "existing.bin".into(),
                bytes: 8,
                suite: suite_name(expected.suite),
                root: hex::encode(expected.root),
                receipt: true,
                deleted: false,
            }],
        );
        // Re-announcing under the recorded name still reuses the delivered
        // copy, receipt flag included: the custody claim is unchanged.
        let (files, allocation) = prepare_files(
            &setup,
            &[(vec!["existing.bin".into()], expected.clone())],
            || true,
        )
        .unwrap();
        drop(allocation);
        assert_eq!(files[0].stored_components, "existing.bin");
        assert!(files[0].published);
        assert!(files[0].receipt);
        // The same root announced under a new name is not a reuse: the file
        // transfers for real, so no record is synthesized for a name under
        // which nothing was received.
        let (files, allocation) =
            prepare_files(&setup, &[(vec!["renamed.bin".into()], expected)], || true).unwrap();
        drop(allocation);
        assert_eq!(files[0].stored_components, "renamed.bin");
        assert!(!files[0].published);
        assert!(!files[0].receipt);
    }

    #[test]
    fn pending_parent_does_not_block_verified_deduplication() {
        let directory = tempfile::tempdir().unwrap();
        let expected = object(Suite::Blake3Bao64, b"original");
        let first = setup(directory.path(), expected.clone());
        let (pending, allocation) = prepare_files(
            &first,
            &[(vec!["folder".into(), "other.bin".into()], expected.clone())],
            || true,
        )
        .unwrap();
        persist_session(&first, &pending).unwrap();
        drop(allocation);
        fs::create_dir_all(first.dest_dir.join("folder")).unwrap();
        fs::write(
            first.dest_dir.join("folder").join("existing.bin"),
            b"original",
        )
        .unwrap();
        let record = FileRecord {
            path: "existing.bin".into(),
            stored_as: "folder/existing.bin".into(),
            bytes: 8,
            suite: suite_name(expected.suite),
            root: hex::encode(expected.root),
            receipt: false,
            deleted: false,
        };
        record_delivered_files(&first, vec![record]);
        let (files, allocation) = prepare_files(
            &first,
            &[(vec!["folder".into(), "existing.bin".into()], expected)],
            || true,
        )
        .unwrap();
        drop(allocation);
        assert_eq!(files[0].stored_components, "folder\0existing.bin");
        assert!(files[0].published);
        assert!(files[0].native.is_none());
        assert!(first
            .dest_dir
            .join("folder")
            .join("other.bin")
            .metadata()
            .is_err());
    }

    #[test]
    fn preparation_reserves_distinct_names_before_publication() {
        for count in [2, 32] {
            for (extension, nested) in [("pdf", false), ("PDF", false), ("pdf", true)] {
                let directory = tempfile::tempdir().unwrap();
                let object = object(Suite::Blake3Bao64, b"");
                let setup = setup(directory.path(), object.clone());
                let mut entries = Vec::new();
                for index in 0..count / 2 {
                    let parent = format!("pair-{index}");
                    fs::create_dir(setup.dest_dir.join(&parent)).unwrap();
                    fs::write(setup.dest_dir.join(&parent).join("report.pdf"), b"existing")
                        .unwrap();
                    entries.push((vec![parent, "report.pdf".into()], object.clone()));
                }
                for index in 0..count / 2 {
                    let mut components =
                        vec![format!("pair-{index}"), format!("report-1.{extension}")];
                    if nested {
                        components.push("child".into());
                    }
                    entries.push((components, object.clone()));
                }
                let (mut files, allocation) = prepare_files(&setup, &entries, || true).unwrap();
                persist_session(&setup, &files).unwrap();
                drop(allocation);
                let mut names = HashSet::new();
                for file in &mut files {
                    let path = vot_manifest::PackagePath::portable(split_components(
                        &file.stored_components,
                    ))
                    .unwrap();
                    let key = vot_manifest::canonical_path_key(
                        &path,
                        vot_manifest::PathProfile::Portable,
                    )
                    .unwrap();
                    assert!(
                        names.insert(key),
                        "stored name claimed twice: {}",
                        file.stored_components.replace('\0', "/")
                    );
                    publish_file(&setup, file, || true).unwrap();
                    assert_eq!(
                        fs::metadata(
                            paths::join_under(
                                &setup.dest_dir,
                                &split_components(&file.stored_components)
                            )
                            .unwrap()
                        )
                        .unwrap()
                        .len(),
                        0
                    );
                }
                assert!(checkpoint_session(&setup, &mut files));
                for index in 0..count / 2 {
                    assert_eq!(
                        fs::read(setup.dest_dir.join(format!("pair-{index}/report.pdf"))).unwrap(),
                        b"existing"
                    );
                }
            }
        }
    }

    #[test]
    fn preparation_bounds_workers_preserves_order_and_cleans_up_on_failure() {
        for count in [0, 1, 16, 17, 128] {
            let directory = tempfile::tempdir().unwrap();
            let object = object(Suite::Blake3Bao64, b"frame");
            let setup = setup(directory.path(), object.clone());
            let mut entries = (0..count)
                .map(|index| (vec![format!("frame-{index}")], object.clone()))
                .collect::<Vec<_>>();
            let workers = Mutex::new([HashSet::new(), HashSet::new()]);
            let checks = AtomicUsize::new(0);
            let (files, allocation) = prepare_files(&setup, &entries, || {
                let phase = checks.fetch_add(1, Ordering::Relaxed) / count;
                workers.lock().unwrap()[phase].insert(std::thread::current().id());
                true
            })
            .unwrap();
            drop(allocation);
            assert_eq!(files.len(), count);
            for (index, file) in files.iter().enumerate() {
                assert_eq!(file.stored_components, entries[index].0.join("\0"));
                assert!(!file.published);
            }
            assert_eq!(checks.load(Ordering::Relaxed), count * 2);
            for phase in workers.lock().unwrap().iter() {
                assert!(phase.len() <= MAX_CHUNK_BATCH);
                if count >= MAX_CHUNK_BATCH * 2 {
                    assert!(phase.len() > 1);
                }
            }
            drop(files);
            if count == 0 {
                continue;
            }
            fs::write(setup.dest_dir.join("blocked"), b"unrelated").unwrap();
            entries[count / 2].0 = vec!["blocked".into(), "frame".into()];
            assert!(prepare_files(&setup, &entries, || true).is_err());
            assert_eq!(
                fs::read(setup.dest_dir.join("blocked")).unwrap(),
                b"unrelated"
            );
            assert_eq!(
                fs::read_dir(setup.dest_dir.join(".vot-stage"))
                    .unwrap()
                    .count(),
                0
            );
            let checks = AtomicU64::new(0);
            assert!(
                prepare_files(&setup, &entries, || checks.fetch_add(1, Ordering::Relaxed)
                    < 1)
                .is_err()
            );
            assert_eq!(
                fs::read_dir(setup.dest_dir.join(".vot-stage"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }

    #[test]
    fn stopped_storage_preserves_staging_and_refuses_writes_and_publication() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"data");
        let setup = setup(directory.path(), object.clone());
        let mut file = open_destination_for(&setup, vec!["file".into()], object).unwrap();
        let staged = file.native.as_mut().unwrap();
        staged.reopen().unwrap();
        let staging = staged.staging.clone();
        let journal = staged.journal.clone();
        setup.destinations.stop();
        assert!(staged.native().is_err());
        assert!(staged.reopen().is_err());
        assert!(staged.directory().is_err());
        assert!(finish_publication(&setup, &mut file).is_err());
        let mut phase = Phase::Receiving { files: vec![file] };
        assert!(!commit_partial(
            &setup,
            &mut phase,
            0,
            0,
            &TransferLog::default()
        ));
        drop(phase);
        assert!(staging.is_file());
        assert!(journal.is_file());
        assert!(!setup.dest_dir.join("file").exists());
    }

    #[test]
    fn staged_validation_distinguishes_bad_content_from_io_and_cancellation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("object");
        let expected = object(Suite::Blake3Bao64, b"complete");
        for (bytes, valid) in [
            (b"complete".as_slice(), true),
            (b"corrupt!", false),
            (b"short", false),
            (b"complete!", false),
        ] {
            fs::write(&path, bytes).unwrap();
            assert_eq!(
                staged_object_valid(&path, &expected, || true).unwrap(),
                valid
            );
        }
        fs::write(&path, b"complete").unwrap();
        assert!(staged_object_valid(&path, &expected, || false).is_err());
        assert!(!staged_object_valid(&path, &expected, || {
            use std::io::Write;
            fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"!")
                .unwrap();
            true
        })
        .unwrap());
        fs::remove_file(&path).unwrap();
        assert!(staged_object_valid(&path, &expected, || true).is_err());
        fs::create_dir(&path).unwrap();
        assert!(staged_object_valid(&path, &expected, || true).is_err());
        #[cfg(unix)]
        {
            fs::remove_dir(&path).unwrap();
            let target = directory.path().join("target");
            fs::write(&target, b"complete").unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
            assert!(staged_object_valid(&path, &expected, || true).is_err());
        }
    }

    #[test]
    fn ordinary_parking_preserves_verification_but_changed_bytes_require_rehash() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"verified bytes";
        let object = object(Suite::Blake3Bao64, bytes);
        let setup = setup(directory.path(), object.clone());
        let mut file =
            open_destination_for(&setup, vec!["frame.exr".into()], object.clone()).unwrap();
        let proof = vot_proof_blake3::prove(bytes, 0, bytes.len() as u64).unwrap();
        let verified = verify_range(&object, 0, bytes, &proof.proof).unwrap();
        let staged = file.native.as_mut().unwrap();
        staged.reopen().unwrap();
        staged.native().unwrap().accept(&verified).unwrap();
        staged.record(&verified).unwrap();
        staged.park();
        staged.reopen().unwrap();
        assert!(
            !staged.reopened,
            "ordinary parking must not cause another full payload read"
        );
        staged.park();
        fs::write(staged.staging_path(), b"changed bytes").unwrap();
        assert!(prepare_publication(&mut file, || true).is_err());
        assert!(!setup.dest_dir.join("frame.exr").exists());
    }

    #[test]
    fn cancelled_publication_keeps_verified_staging_before_during_and_after_rehash() {
        for allowed_checks in [0, 1, 2] {
            let directory = tempfile::tempdir().unwrap();
            let bytes = b"verified";
            let object = object(Suite::Blake3Bao64, bytes);
            let setup = setup(directory.path(), object.clone());
            let source = directory.path().join("source");
            fs::write(&source, bytes).unwrap();
            let mut file =
                open_destination_for(&setup, vec!["frame".into()], object.clone()).unwrap();
            reprove_staging(&source, &object, vec![&mut file], || true).unwrap();
            file.rehash = true;
            let checks = std::cell::Cell::new(0);
            assert!(publish_file(&setup, &mut file, || {
                let current = checks.get();
                checks.set(current + 1);
                current < allowed_checks
            })
            .is_err());
            assert!(!setup.dest_dir.join("frame").exists());
            assert_eq!(
                file.native.as_ref().unwrap().progress().prefix_bytes,
                bytes.len() as u64
            );
            publish_file(&setup, &mut file, || true).unwrap();
            assert_eq!(fs::read(setup.dest_dir.join("frame")).unwrap(), bytes);
        }
    }

    #[test]
    fn batch_file_operations_select_each_entry_once_and_overlap() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"batch");
        let setup = setup(directory.path(), object.clone());
        let mut files = (0..4)
            .map(|entry| {
                open_destination_for(&setup, vec![entry.to_string()], object.clone()).unwrap()
            })
            .collect::<Vec<_>>();
        let arrived = AtomicUsize::new(0);
        let parent = std::thread::current().id();
        let results = map_batch_files(&mut files, [3, 0, 3, usize::MAX, 1].into_iter(), |file| {
            assert_ne!(std::thread::current().id(), parent);
            arrived.fetch_add(1, Ordering::SeqCst);
            for _ in 0..1000 {
                if arrived.load(Ordering::SeqCst) == 3 {
                    return file.display_path.clone();
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            panic!("independent batch entries did not overlap");
        });
        assert_eq!(arrived.load(Ordering::SeqCst), 3);
        assert_eq!(
            results,
            HashMap::from([(0, "0".into()), (1, "1".into()), (3, "3".into())])
        );
        let single = map_batch_files(&mut files, [2, 2].into_iter(), |file| {
            assert_eq!(std::thread::current().id(), parent);
            file.display_path.clone()
        });
        assert_eq!(single, HashMap::from([(2, "2".into())]));
        assert!(
            map_batch_files(&mut files, [usize::MAX].into_iter(), |_| panic!(
                "invalid entry selected"
            ))
            .is_empty()
        );
    }

    #[test]
    fn batch_publication_keeps_entry_results_and_failed_staging() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = vec![0x73; 65_536];
        let object = object(Suite::Blake3Bao64, &bytes);
        let setup = setup(directory.path(), object.clone());
        let mut phase = Phase::Receiving {
            files: (0..3)
                .map(|entry| {
                    open_destination_for(&setup, vec![format!("file-{entry}")], object.clone())
                        .unwrap()
                })
                .collect(),
        };
        let chunk = |entry, valid| {
            let proof = vot_proof_blake3::prove(&bytes, 0, bytes.len() as u64).unwrap();
            BatchChunk {
                entry,
                offset: proof.covered_offset,
                proof: proof.proof.into(),
                data: if valid {
                    proof.data.into()
                } else {
                    vec![0; bytes.len()].into()
                },
                reply: oneshot::channel().0,
                _lease: SessionLease {
                    activity: Arc::new(SessionActivity {
                        in_flight: AtomicUsize::new(1),
                        last_active: Mutex::new(Instant::now()),
                        received: AtomicU64::new(0),
                    }),
                },
            }
        };
        if let Phase::Receiving { files } = &mut phase {
            files[0].native.as_mut().unwrap().reopen().unwrap();
        }
        fs::write(setup.dest_dir.join("file-0"), b"existing destination").unwrap();
        let result = accept_batch(
            &setup,
            &mut phase,
            &[
                chunk(2, true),
                chunk(0, true),
                chunk(2, true),
                chunk(usize::MAX, true),
                chunk(1, false),
            ],
        );
        let duplicates = [result[0].as_ref().unwrap(), result[2].as_ref().unwrap()];
        assert!(duplicates.iter().all(|result| result.complete));
        assert_eq!(
            duplicates.iter().filter(|result| result.accepted).count(),
            1
        );
        assert_eq!(duplicates.iter().filter(|result| result.replay).count(), 1);
        assert!(
            result[1].as_ref().unwrap_err().message.contains("publish"),
            "{:?}",
            result[1]
        );
        assert_eq!(result[3].as_ref().unwrap_err().status, 422);
        assert_eq!(result[4].as_ref().unwrap_err().status, 422);
        assert_eq!(
            fs::read(setup.dest_dir.join("file-0")).unwrap(),
            b"existing destination"
        );
        assert!(!setup.dest_dir.join("file-1").exists());
        assert_eq!(fs::read(setup.dest_dir.join("file-2")).unwrap(), bytes);
        let retried = accept_batch(&setup, &mut phase, &[chunk(1, true), chunk(2, true)]);
        assert!(retried
            .iter()
            .all(|result| result.as_ref().is_ok_and(|result| result.complete)));
        assert!(retried[1].as_ref().unwrap().replay);
        let Phase::Receiving { files } = phase else {
            unreachable!()
        };
        assert!(!files[0].published);
        let failed = files[0].native.as_ref().unwrap();
        assert!(failed.journal.is_file());
        assert_eq!(fs::read(&failed.staging).unwrap(), bytes);
        for file in files.into_iter().skip(1) {
            assert!(file.published && file.receipt);
            assert_eq!(
                fs::read(setup.dest_dir.join(&file.display_path)).unwrap(),
                bytes
            );
            assert!(file.native.as_ref().unwrap().active.is_none());
        }
    }

    #[test]
    fn checkpoints_skip_unchanged_rows_and_retry_every_failed_change() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"checkpoint";
        let object = object(Suite::Blake3Bao64, bytes);
        let setup = setup(directory.path(), object.clone());
        let source = directory.path().join("source");
        fs::write(&source, bytes).unwrap();
        let mut files = (0..2)
            .map(|entry| {
                open_destination_for(&setup, vec![format!("frame-{entry}")], object.clone())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        persist_session(&setup, &files).unwrap();
        let connection =
            rusqlite::Connection::open(directory.path().join("data/votport.db")).unwrap();
        connection.execute_batch("CREATE TABLE checkpoint_writes(entry INTEGER);
            CREATE TRIGGER reject_unchanged_checkpoint BEFORE UPDATE ON upload_session_files
            WHEN NEW.prefix_bytes = OLD.prefix_bytes AND NEW.published = OLD.published AND NEW.receipt = OLD.receipt
            BEGIN SELECT RAISE(FAIL, 'unchanged checkpoint row'); END;
            CREATE TRIGGER count_checkpoint AFTER UPDATE ON upload_session_files
            BEGIN INSERT INTO checkpoint_writes VALUES (NEW.entry); END;").unwrap();
        let writes = || {
            connection
                .query_row("SELECT COUNT(*) FROM checkpoint_writes", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
        };
        assert!(checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 0);
        reprove_staging(&source, &object, vec![&mut files[0]], || true).unwrap();
        assert!(checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 1);
        assert!(checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 1);

        *files[0]
            .native
            .as_mut()
            .unwrap()
            .coverage
            .get_mut()
            .unwrap() = ObjectCoverage::new(&object);
        assert!(checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 2);
        reprove_staging(&source, &object, files.iter_mut().collect(), || true).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER fail_second_checkpoint BEFORE UPDATE ON upload_session_files
            WHEN NEW.entry = 1 BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;",
            )
            .unwrap();
        assert!(!checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 2);
        assert!(setup.store.load_upload_sessions().unwrap()[0]
            .files
            .iter()
            .all(|file| file.prefix_bytes == 0));
        connection
            .execute_batch("DROP TRIGGER fail_second_checkpoint;")
            .unwrap();
        assert!(checkpoint_session(&setup, &mut files));
        assert_eq!(writes(), 4);
        assert!(setup.store.load_upload_sessions().unwrap()[0]
            .files
            .iter()
            .all(|file| file.prefix_bytes == object.length));

        for (published, receipt) in [(true, false), (true, true), (true, false)] {
            files[0].published = published;
            files[0].receipt = receipt;
            checkpoint_files(&setup, files.iter().enumerate()).unwrap();
            let saved = &setup.store.load_upload_sessions().unwrap()[0].files[0];
            assert_eq!((saved.published, saved.receipt), (published, receipt));
        }
        assert_eq!(writes(), 7);
    }

    #[test]
    fn checkpoint_snapshot_keeps_writes_arriving_during_database_wait() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = vec![0x53; 131_072];
        let mut builder =
            InMemoryObjectBuilder::new(Suite::Blake3Bao64, Some(bytes.len() as u64), 131_072)
                .unwrap();
        builder.update(&bytes).unwrap();
        let prepared = builder.finish().unwrap();
        let setup = setup(directory.path(), prepared.object_id().clone());
        let mut file =
            open_destination_for(&setup, vec!["frame".into()], prepared.object_id().clone())
                .unwrap();
        persist_session(&setup, std::slice::from_ref(&file)).unwrap();
        file.native.as_mut().unwrap().reopen().unwrap();
        let files = [file];
        let send = |offset| {
            let proof = prepared.prove(offset, 65_536).unwrap();
            let offset = offset as usize;
            accept_range(
                &files,
                0,
                offset as u64,
                proof.proof(),
                &bytes[offset..offset + 65_536],
            )
            .unwrap();
        };
        send(0);
        let (snapshot, ready) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            setup
                .store
                .with(|_| {
                    scope.spawn(|| {
                        checkpoint_files(
                            &setup,
                            files.iter().enumerate().chain(std::iter::from_fn(|| {
                                snapshot.send(()).unwrap();
                                None
                            })),
                        )
                        .unwrap();
                    });
                    ready.recv_timeout(Duration::from_secs(5)).unwrap();
                    send(65_536);
                    Ok(())
                })
                .unwrap();
        });
        assert_eq!(
            setup.store.load_upload_sessions().unwrap()[0].files[0].prefix_bytes,
            65_536
        );
        checkpoint_files(&setup, files.iter().enumerate()).unwrap();
        assert_eq!(
            setup.store.load_upload_sessions().unwrap()[0].files[0].prefix_bytes,
            131_072
        );

        let (finished, done) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            setup
                .store
                .with(|_| {
                    scope.spawn(|| {
                        checkpoint_files(&setup, files.iter().enumerate()).unwrap();
                        finished.send(()).unwrap();
                    });
                    done.recv_timeout(Duration::from_secs(5))
                        .expect("unchanged checkpoint waited for SQLite");
                    Ok(())
                })
                .unwrap();
        });
    }

    #[test]
    fn publication_recovery_recognizes_its_existing_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"frame";
        let object = object(Suite::Blake3Bao64, bytes);
        let setup = setup(directory.path(), object.clone());
        let source = directory.path().join("source");
        fs::write(&source, bytes).unwrap();
        let mut file = open_destination_for(&setup, vec!["frame".into()], object).unwrap();
        reprove_staging(&source, &file.object.clone(), vec![&mut file], || true).unwrap();
        persist_session(&setup, std::slice::from_ref(&file)).unwrap();
        publish_file(&setup, &mut file, || true).unwrap();
        assert!(file.published && file.receipt);
        let sidecar = setup.dest_dir.join("frame.vot-receipt");
        let evidence = fs::read(&sidecar).unwrap();
        file.native.take().unwrap().abandon();
        let mut saved = setup.store.load_upload_sessions().unwrap().remove(0);
        assert!(!saved.files[0].published && !saved.files[0].receipt);
        let (files, _, _) = restore_files(&setup, &mut saved, || true).unwrap();
        assert!(files[0].published && files[0].receipt);
        assert_eq!(fs::read(&sidecar).unwrap(), evidence);
        assert_eq!(fs::read(setup.dest_dir.join("frame")).unwrap(), bytes);
        assert!(setup.store.load_upload_sessions().unwrap()[0].files[0].receipt);
    }

    /// Audit finding 499: a finish-time restart publishes a fully
    /// checkpointed file on the recover path, and the resumed log used to
    /// jump from "reattached" to "finished" with no per-file publication.
    #[test]
    fn recovered_publication_is_recorded_in_the_resumed_log() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"frame";
        let object = object(Suite::Blake3Bao64, bytes);
        let setup = setup(directory.path(), object.clone());
        let source = directory.path().join("source");
        fs::write(&source, bytes).unwrap();
        let mut file = open_destination_for(&setup, vec!["frame".into()], object.clone()).unwrap();
        reprove_staging(&source, &file.object.clone(), vec![&mut file], || true).unwrap();
        persist_session(&setup, std::slice::from_ref(&file)).unwrap();
        file.native.take().unwrap().abandon();
        let mut saved = setup.store.load_upload_sessions().unwrap().remove(0);
        assert!(!saved.files[0].published);
        assert_eq!(
            saved.files[0].prefix_bytes, object.length,
            "finish-time state"
        );
        assert!(
            !setup.dest_dir.join("frame").exists(),
            "publication is pending"
        );

        let (files, _, events) = restore_files(&setup, &mut saved, || true).unwrap();
        assert!(files[0].published);
        assert_eq!(events.len(), 1, "the recovered publication must be logged");
        assert_eq!(events[0].kind, "published");
        assert_eq!(events[0].path.as_deref(), Some("frame"));
        assert_eq!(events[0].bytes, Some(bytes.len() as u64));
        assert_eq!(fs::read(setup.dest_dir.join("frame")).unwrap(), bytes);
    }

    #[test]
    fn persisted_components_survive_a_save_restore_round_trip_byte_identically() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"frame");
        let setup = setup(directory.path(), object.clone());
        let mut files = vec![
            open_destination_for(&setup, vec!["plain.bin".into()], object.clone()).unwrap(),
            open_destination_for(
                &setup,
                vec!["nested".into(), "dir".into(), "report.pdf".into()],
                object,
            )
            .unwrap(),
        ];
        persist_session(&setup, &files).unwrap();
        // Park the staging the way a crash would leave it, after the
        // admission record carries the live staging paths.
        for file in &mut files {
            file.native.take().unwrap().abandon();
        }
        let mut saved = setup.store.load_upload_sessions().unwrap().remove(0);
        // The persisted cell must remain the pre-existing JSON array of
        // components: the in-memory representation changed, the schema did not.
        let wire = |files: &[crate::store::PersistedUploadFile]| {
            files
                .iter()
                .map(|file| serde_json::to_string(&file.stored_components).unwrap())
                .collect::<Vec<_>>()
        };
        let first_wire = wire(&saved.files);
        assert_eq!(
            saved.files[1].stored_components,
            ["nested", "dir", "report.pdf"]
        );
        let (restored, _, _) = restore_files(&setup, &mut saved, || true).unwrap();
        assert_eq!(restored[1].stored_components, "nested\0dir\0report.pdf");
        persist_session(&setup, &restored).unwrap();
        let resaved = setup.store.load_upload_sessions().unwrap().remove(0);
        assert_eq!(resaved, saved);
        assert_eq!(wire(&resaved.files), first_wire);
    }

    #[test]
    fn admission_refuses_entries_over_the_session_cap_with_the_cap_named() {
        let directory = tempfile::tempdir().unwrap();
        let expected = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), expected.clone());
        // The empty trailing component is rejected by per-name validation, so
        // if the cap check is ever removed or reordered behind it, this test
        // still fails (fast, with the wrong message) instead of staging
        // MAX_SESSION_ENTRIES real files.
        let entries =
            vec![(vec!["f.bin".to_owned(), String::new()], expected); MAX_SESSION_ENTRIES + 1];
        let error = prepare_files(&setup, &entries, || true).err().unwrap();
        assert_eq!(error.status, 422);
        assert!(error.message.contains("262144"), "{}", error.message);
    }

    #[test]
    fn session_cap_admits_cap_minus_one_entries() {
        assert!(check_session_entry_cap(MAX_SESSION_ENTRIES - 1).is_ok());
        assert!(check_session_entry_cap(MAX_SESSION_ENTRIES).is_ok());
    }

    #[test]
    fn restore_refuses_replaying_persisted_sessions_over_the_entry_cap() {
        let directory = tempfile::tempdir().unwrap();
        let stub = object(Suite::Blake3Bao64, b"");
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        let file = crate::store::PersistedUploadFile {
            entry: 0,
            display_path: String::new(),
            stored_components: vec![String::new()],
            object,
            staging_path: std::path::PathBuf::new(),
            journal_path: std::path::PathBuf::new(),
            incarnation: [0; 16],
            profile: CommitProfile::Balanced,
            nas_contract: vot_sdk_file::NasContract::Unqualified,
            prefix_bytes: 0,
            published: false,
            receipt: false,
        };
        let mut saved = crate::store::PersistedUploadSession {
            committed_upload_id: None,
            push_key: None,
            id: "over-cap".to_owned(),
            link_id: "link".to_owned(),
            tenant: String::new(),
            dest_dir: setup.dest_dir.clone(),
            dest_rel: String::new(),
            package: stub,
            max_total_bytes: None,
            started_at: 1,
            files: vec![file; MAX_SESSION_ENTRIES + 1],
        };
        let error = match restore_files(&setup, &mut saved, || true) {
            Err(error) => error,
            Ok(_) => panic!("over-cap persisted session replay must be refused"),
        };
        assert!(error.contains("262144"), "{error}");
    }

    #[test]
    fn publication_journal_remains_until_the_database_checkpoints_it() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        let mut files =
            vec![open_destination_for(&setup, vec!["empty.exr".into()], object).unwrap()];
        persist_session(&setup, &files).unwrap();
        let journal = files[0].native.as_ref().unwrap().journal_path().to_owned();
        publish_file(&setup, &mut files[0], || true).unwrap();
        assert!(journal.exists());
        let connection =
            rusqlite::Connection::open(directory.path().join("data/votport.db")).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON upload_session_files BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;").unwrap();
        checkpoint_session(&setup, &mut files);
        assert!(journal.exists());
        assert!(!setup.store.load_upload_sessions().unwrap()[0].files[0].published);
        connection
            .execute_batch("DROP TRIGGER fail_checkpoint;")
            .unwrap();
        checkpoint_session(&setup, &mut files);
        assert!(!journal.exists());
        assert!(setup.store.load_upload_sessions().unwrap()[0].files[0].published);
        assert!(setup.dest_dir.join("empty.exr").exists());
    }

    #[tokio::test]
    async fn finished_upload_keeps_recovery_when_the_final_checkpoint_fails() {
        for (fail_checkpoint, fail_cleanup) in [(false, false), (true, false), (false, true)] {
            use std::os::unix::fs::PermissionsExt as _;
            let retain = fail_checkpoint || fail_cleanup;
            let directory = tempfile::tempdir().unwrap();
            let object = object(Suite::Blake3Bao64, b"");
            let setup = setup(directory.path(), object.clone());
            setup
                .store
                .insert_link(crate::store::Link {
                    retention_days: None,
                    verification: "default".to_owned(),
                    id: setup.link_id.clone(),
                    tenant: String::new(),
                    label: "checkpoint".into(),
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
            let mut files =
                vec![open_destination_for(&setup, vec!["frame".into()], object).unwrap()];
            persist_session(&setup, &files).unwrap();
            let journal = files[0].native.as_ref().unwrap().journal_path().to_owned();
            publish_file(&setup, &mut files[0], || true).unwrap();
            let connection =
                rusqlite::Connection::open(directory.path().join("data/votport.db")).unwrap();
            if fail_checkpoint {
                connection.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON upload_session_files BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;").unwrap();
            }
            let private = setup.dest_dir.join(".vot-stage");
            if fail_cleanup {
                fs::set_permissions(&private, fs::Permissions::from_mode(0o770)).unwrap();
            }
            let store = Arc::clone(&setup.store);
            let retry_setup = self::setup(directory.path(), setup.expected_package.clone());
            let sessions = Sessions::new();
            let (sender, receiver) = mpsc::channel(1);
            let sid = hex::encode(setup.session_id);
            sessions
                .insert(sid.clone(), setup.link_id.clone(), String::new(), sender)
                .unwrap();
            let command = sessions.touch(&sid).unwrap();
            let (reply, completed) = oneshot::channel();
            command
                .sender
                .send(Cmd::Finish {
                    reply,
                    _lease: command.lease,
                })
                .await
                .unwrap();
            spawn_worker_from(
                setup,
                receiver,
                Phase::Receiving { files },
                false,
                0,
                Vec::new(),
            );
            tokio::time::timeout(std::time::Duration::from_secs(5), completed)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(journal.exists(), retain);
            let mut retained = store.load_upload_sessions().unwrap();
            assert_eq!(retained.len(), usize::from(retain));
            if retain {
                fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
                let mut persisted = retained.remove(0);
                assert_eq!(persisted.files[0].published, !fail_checkpoint);
                connection
                    .execute_batch("DROP TRIGGER IF EXISTS fail_checkpoint;")
                    .unwrap();
                let journal_before = fs::read(&journal).unwrap();
                assert!(persisted.committed_upload_id.is_some());
                assert!(restore_files(&retry_setup, &mut persisted, || true).is_err());
                assert_eq!(fs::read(&journal).unwrap(), journal_before);
                cleanup_committed_session(&store, &persisted, &retry_setup.destinations).unwrap();
                assert!(store.load_upload_sessions().unwrap().is_empty());
                assert!(!journal.exists());
            }
        }
    }

    /// Audit finding 406: the quiet gap used to be two wall-clock reads, so
    /// a forward step mid-transfer fabricated a long quiet event that evicted
    /// a real one from the kept log. The pause is measured by the monotonic
    /// clock: the logged secs must track the real sender silence (a hair over
    /// quiet_after_secs, far below a wall-clock step) while `at` keeps its
    /// wall stamp.
    #[tokio::test]
    async fn quiet_gap_measures_the_pause_with_the_monotonic_clock() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let mut setup = setup(directory.path(), object.clone());
        setup.quiet_after_secs = 1;
        let mut files = vec![open_destination_for(&setup, vec!["frame".into()], object).unwrap()];
        persist_session(&setup, &files).unwrap();
        publish_file(&setup, &mut files[0], || true).unwrap();
        setup
            .store
            .insert_link(crate::store::tests::test_link(&setup.link_id))
            .unwrap();
        let store = Arc::clone(&setup.store);
        let link_id = setup.link_id.clone();
        let (sender, receiver) = mpsc::channel(1);
        spawn_worker_from(
            setup,
            receiver,
            Phase::Receiving { files },
            false,
            0,
            Vec::new(),
        );
        let lease = || SessionLease {
            activity: Arc::new(SessionActivity {
                in_flight: AtomicUsize::new(1),
                last_active: Mutex::new(Instant::now()),
                received: AtomicU64::new(0),
            }),
        };
        // The first command opens the worker's ears; the next arrives after a
        // real pause past quiet_after_secs.
        let (reply, done) = oneshot::channel();
        sender
            .send(Cmd::Page {
                bytes: Bytes::new(),
                reply,
                _lease: lease(),
            })
            .await
            .unwrap();
        let _ = done.await;
        tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
        let (reply, done) = oneshot::channel();
        sender
            .send(Cmd::Page {
                bytes: Bytes::new(),
                reply,
                _lease: lease(),
            })
            .await
            .unwrap();
        let _ = done.await;
        // Ending the transfer commits the log into the link record.
        let (reply, done) = oneshot::channel();
        sender
            .send(Cmd::Abort {
                reply,
                _lease: lease(),
            })
            .await
            .unwrap();
        let _ = done.await;
        let link = store.link("", &link_id).unwrap().unwrap();
        let log = &link.uploads[0].log;
        let quiet: Vec<&LogEvent> = log.iter().filter(|event| event.kind == "quiet").collect();
        assert_eq!(quiet.len(), 1, "{log:?}");
        let secs = quiet[0].secs.unwrap();
        assert!(
            (1..=5).contains(&secs),
            "quiet secs must track the real 1.3 s pause: {log:?}"
        );
        assert_eq!(log.last().unwrap().kind, "cancelled");
    }

    #[tokio::test]
    async fn committed_upload_recovery_never_readmits_or_recreates_deleted_files() {
        use std::os::unix::fs::PermissionsExt as _;
        for (checkpoint, final_state) in [
            (true, "original"),
            (false, "original"),
            (true, "missing"),
            (false, "replaced"),
            (false, "cleaned"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let mut config = crate::api::testing::config(directory.path());
            config.receive_dir = directory.path().join("receive");
            let app = crate::app::build(config.clone()).unwrap();
            let bytes = b"frame";
            let object = object(Suite::Blake3Bao64, bytes);
            let setup = setup_with_app(directory.path(), object.clone(), &app);
            app.store
                .insert_link(crate::store::tests::test_link(&setup.link_id))
                .unwrap();
            let source = directory.path().join("source");
            fs::write(&source, bytes).unwrap();
            let mut file =
                open_destination_for(&setup, vec!["frame".into()], object.clone()).unwrap();
            persist_session(&setup, std::slice::from_ref(&file)).unwrap();
            reprove_staging(&source, &object, vec![&mut file], || true).unwrap();
            publish_file(&setup, &mut file, || true).unwrap();
            let journal = file.native.as_ref().unwrap().journal.clone();
            let private = setup.dest_dir.join(".vot-stage");
            if checkpoint {
                app.store.with(|connection| connection.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON upload_session_files BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;")).unwrap();
            } else {
                fs::set_permissions(&private, fs::Permissions::from_mode(0o770)).unwrap();
            }
            let mut phase = Phase::Receiving { files: vec![file] };
            let report =
                handle_finish(&setup, &mut phase, 0, 0, 5, &TransferLog::default()).unwrap();
            assert!(journal.exists());
            assert_eq!(app.store.load_upload_sessions().unwrap().len(), 1);
            let (received, retained) = app.store.tenant_admission_usage("").unwrap();
            assert_eq!(received, 5);
            assert!(
                retained.is_empty(),
                "committed uploads must not reserve their bytes again"
            );
            app.store
                .with(|connection| {
                    connection.execute_batch("DROP TRIGGER IF EXISTS fail_checkpoint;")
                })
                .unwrap();
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
            let final_path = setup.dest_dir.join("frame");
            if final_state != "original" {
                app.store
                    .remove_upload(
                        "",
                        &setup.link_id,
                        &app.store.load_upload_sessions().unwrap()[0]
                            .committed_upload_id
                            .clone()
                            .unwrap(),
                    )
                    .unwrap();
                app.store
                    .update_link("", &setup.link_id, |link| link.active = false)
                    .unwrap();
                match final_state {
                    "missing" => fs::remove_file(&final_path).unwrap(),
                    "replaced" => {
                        fs::rename(&final_path, directory.path().join("original")).unwrap();
                        fs::write(&final_path, b"operator replacement").unwrap();
                    }
                    "cleaned" => fs::remove_file(&journal).unwrap(),
                    _ => unreachable!(),
                }
            }
            drop(phase);
            drop(setup);
            drop(app);
            for _ in 0..2 {
                let app = crate::app::build(config.clone()).unwrap();
                assert_eq!(
                    app.sessions.total(),
                    0,
                    "completed recovery must not start a receiver"
                );
                app.sessions.sweep(0);
                let link = app.store.link("", "link").unwrap().unwrap();
                if final_state == "original" {
                    assert_eq!(link.uploads.len(), 1);
                    assert_eq!(link.uploads[0].id, report.upload_id);
                    assert!(!link.uploads[0].partial);
                    assert_eq!(fs::read(&final_path).unwrap(), bytes);
                } else {
                    assert!(link.uploads.is_empty(), "deleted history must stay deleted");
                    assert!(!link.active);
                }
                assert!(
                    link.events.is_empty(),
                    "cleanup must not record an interrupted transfer"
                );
                let unresolved = matches!(final_state, "missing" | "replaced");
                assert_eq!(
                    app.store.load_upload_sessions().unwrap().len(),
                    usize::from(unresolved)
                );
                assert!(app.store.tenant_admission_usage("").unwrap().1.is_empty());
                assert_eq!(journal.exists(), unresolved);
                if final_state == "missing" {
                    assert!(!final_path.exists());
                }
                if final_state == "replaced" {
                    assert_eq!(fs::read(&final_path).unwrap(), b"operator replacement");
                }
                drop(app);
            }
        }
    }

    #[tokio::test]
    async fn cleanup_refuses_a_displaced_journal_directory() {
        use std::os::unix::fs::DirBuilderExt as _;
        let root = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(root.path(), object.clone());
        setup
            .store
            .insert_link(crate::store::tests::test_link(&setup.link_id))
            .unwrap();
        let mut file = open_destination_for(&setup, vec!["frame".into()], object).unwrap();
        persist_session(&setup, std::slice::from_ref(&file)).unwrap();
        publish_file(&setup, &mut file, || true).unwrap();
        commit_upload(
            &setup,
            std::slice::from_ref(&file),
            0,
            0,
            Some("http"),
            Vec::new(),
        )
        .unwrap();
        let session = setup.store.load_upload_sessions().unwrap().remove(0);
        let journal = &session.files[0].journal_path;
        let private = setup.dest_dir.join(".vot-stage");
        let held = setup.dest_dir.join("held-stage");
        fs::rename(&private, &held).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
        let previous = held.join(journal.file_name().unwrap());
        fs::copy(&previous, journal).unwrap();
        let bytes = fs::read(&previous).unwrap();
        assert!(cleanup_committed_session(&setup.store, &session, &setup.destinations).is_err());
        assert_eq!(setup.store.load_upload_sessions().unwrap(), vec![session]);
        assert_eq!(fs::read(previous).unwrap(), bytes);
    }

    #[tokio::test]
    async fn completion_fence_commits_atomically_and_survives_history_deletion() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        setup
            .store
            .insert_link(crate::store::tests::test_link(&setup.link_id))
            .unwrap();
        let mut file = open_destination_for(&setup, vec!["frame".into()], object).unwrap();
        persist_session(&setup, std::slice::from_ref(&file)).unwrap();
        publish_file(&setup, &mut file, || true).unwrap();
        assert!(checkpoint_session(&setup, std::slice::from_mut(&mut file)));
        setup.store.with(|connection| connection.execute_batch("CREATE TRIGGER fail_completion BEFORE UPDATE OF committed_upload_id ON upload_sessions BEGIN SELECT RAISE(ABORT, 'completion failure'); END;")).unwrap();
        assert!(commit_upload(
            &setup,
            std::slice::from_ref(&file),
            0,
            0,
            Some("http"),
            Vec::new()
        )
        .unwrap_err()
        .message
        .contains("completion failure"));
        let mut saved = setup.store.load_upload_sessions().unwrap().remove(0);
        assert!(saved.committed_upload_id.is_none());
        assert!(saved.files[0].published);
        assert!(setup
            .store
            .link("", "link")
            .unwrap()
            .unwrap()
            .uploads
            .is_empty());
        assert_eq!(
            setup
                .store
                .with(|connection| connection
                    .query_row("SELECT COUNT(*) FROM files", [], |row| row.get::<_, i64>(0)))
                .unwrap(),
            0
        );
        let (files, _, _) = restore_files(&setup, &mut saved, || true).unwrap();
        assert!(
            files[0].published,
            "an uncommitted publication must remain recoverable"
        );
        setup
            .store
            .with(|connection| connection.execute_batch("DROP TRIGGER fail_completion;"))
            .unwrap();
        let report = commit_upload(&setup, &files, 0, 0, Some("http"), Vec::new()).unwrap();
        assert_eq!(
            commit_upload(&setup, &files, 0, 0, Some("http"), Vec::new())
                .unwrap()
                .upload_id,
            report.upload_id
        );
        assert_eq!(
            setup.store.link("", "link").unwrap().unwrap().uploads.len(),
            1
        );
        setup
            .store
            .remove_upload("", "link", &report.upload_id)
            .unwrap();
        setup
            .store
            .update_link("", "link", |link| link.active = false)
            .unwrap();
        for partial in [false, true] {
            assert_eq!(
                commit_upload_records(
                    &setup,
                    file_records(&setup, files.iter()),
                    0,
                    0,
                    Some("http"),
                    partial,
                    Vec::new()
                )
                .unwrap()
                .upload_id,
                report.upload_id
            );
            assert!(setup
                .store
                .link("", "link")
                .unwrap()
                .unwrap()
                .uploads
                .is_empty());
        }
        assert!(setup.store.load_upload_sessions().unwrap()[0]
            .committed_upload_id
            .is_some());
    }

    #[test]
    fn retained_publication_journals_warn_once_per_batch_with_one_example() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        let object_id = object(Suite::Blake3Bao64, b"");
        let setup = setup_with_app(directory.path(), object_id.clone(), &application);
        application
            .store
            .insert_link(crate::store::tests::test_link(&setup.link_id))
            .unwrap();
        let mut file_a =
            open_destination_for(&setup, vec!["frame-a".into()], object_id.clone()).unwrap();
        let mut file_b = open_destination_for(&setup, vec!["frame-b".into()], object_id).unwrap();
        publish_file(&setup, &mut file_a, || true).unwrap();
        publish_file(&setup, &mut file_b, || true).unwrap();
        // Removing the journals makes forgetting the publications fail.
        let journal_a = file_a.native.as_ref().unwrap().journal.clone();
        let journal_b = file_b.native.as_ref().unwrap().journal.clone();
        std::fs::remove_file(&journal_a).unwrap();
        std::fs::remove_file(&journal_b).unwrap();

        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            assert!(!forget_publications(&mut [file_a, file_b]));
        });
        let text = std::fs::read_to_string(log.path()).unwrap();
        let warns: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("retain publication journal"))
            .collect();
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(warns[0].contains("\"count\":2"), "{}", warns[0]);
        assert!(warns[0].contains("frame-a"), "{}", warns[0]);
        assert!(!warns[0].contains("frame-b"), "{}", warns[0]);
    }

    #[tokio::test]
    async fn completed_native_teardown_keeps_admission_until_publication_cleanup() {
        for cleaned in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let application = crate::api::testing::build(directory.path());
            let object = object(Suite::Blake3Bao64, b"");
            let setup = setup_with_app(directory.path(), object.clone(), &application);
            application
                .store
                .insert_link(crate::store::tests::test_link(&setup.link_id))
                .unwrap();
            let key = hex::encode([5; 16]);
            let stage = setup.destinations.push_directory(&key).unwrap();
            let lock = lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap();
            let mut file = open_destination_for(&setup, vec!["frame".into()], object).unwrap();
            let mut record = persisted_session(&setup, std::slice::from_ref(&file));
            record.push_key = Some(key.clone());
            setup.store.insert_upload_session(&record).unwrap();
            let journal = file.native.as_ref().unwrap().journal.clone();
            publish_file(&setup, &mut file, || true).unwrap();
            setup
                .store
                .update_upload_file_progress(&record.id, [file_progress(0, &file)])
                .unwrap();
            if cleaned {
                assert!(forget_publications(std::slice::from_mut(&mut file)));
            }
            let report = commit_upload(
                &setup,
                std::slice::from_ref(&file),
                0,
                0,
                Some("push"),
                Vec::new(),
            )
            .unwrap();
            let control = PushControl::resumable(key.clone(), Some(lock));
            let (sender, _) = mpsc::channel(1);
            application
                .sessions
                .insert_admitted(
                    SessionAdmission {
                        id: record.id.clone(),
                        link_id: setup.link_id.clone(),
                        tenant: String::new(),
                        reserved_bytes: 0,
                        max_total_bytes: None,
                        max_tenant_sessions: None,
                        max_link_sessions: usize::MAX,
                        max_sessions: usize::MAX,
                        kind: SessionKind::Push(control.clone()),
                    },
                    sender,
                    || Ok((0, Vec::new())),
                )
                .unwrap();
            let (seams, handle) = push_seams(
                Arc::clone(&application),
                setup,
                control,
                tokio::runtime::Handle::current(),
            );
            let receive = handle.0.upgrade().unwrap();
            {
                let mut inner = receive.inner.lock().unwrap();
                inner.entries.push(PushEntry { file: Some(file) });
                inner.succeeded = true;
            }
            drop(receive);
            drop(seams);
            assert!(handle.0.upgrade().is_none());
            assert_eq!(journal.exists(), !cleaned);
            assert_eq!(
                application.store.load_push_session(&key).unwrap().is_some(),
                !cleaned
            );
            assert_eq!(application.sessions.total(), 0);
            if !cleaned {
                let saved = application.store.load_push_session(&key).unwrap().unwrap();
                assert_eq!(
                    saved.committed_upload_id.as_deref(),
                    Some(report.upload_id.as_str())
                );
                let mut retry =
                    setup_with_app(directory.path(), saved.package.clone(), &application);
                retry.session_id = [8; 16];
                assert!(persist_push(&retry, key.clone())
                    .unwrap_err()
                    .contains("completed upload"));
                for same_id in [false, true] {
                    let mut replacement = record.clone();
                    if same_id {
                        replacement.push_key = Some(hex::encode([9; 16]));
                    } else {
                        replacement.id = hex::encode([8; 16]);
                    }
                    assert!(application
                        .store
                        .insert_upload_session(&replacement)
                        .unwrap_err()
                        .contains("completed upload"));
                    assert_eq!(
                        application.store.load_push_session(&key).unwrap().unwrap(),
                        saved
                    );
                }
            }
            assert!(directory.path().join("receive/frame").exists());
        }
    }

    #[test]
    fn fully_checkpointed_corruption_persists_the_reset_and_allows_resend() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = b"verified frame";
        let object = object(Suite::Blake3Bao64, bytes);
        let setup = setup(directory.path(), object.clone());
        let source = directory.path().join("source");
        fs::write(&source, bytes).unwrap();
        let mut file = open_destination_for(&setup, vec!["frame".into()], object.clone()).unwrap();
        reprove_staging(&source, &object, vec![&mut file], || true).unwrap();
        persist_session(&setup, std::slice::from_ref(&file)).unwrap();
        let staging = file.native.as_ref().unwrap().staging.clone();
        file.native.take().unwrap().abandon();
        fs::write(&staging, b"corrupted data").unwrap();
        let mut persisted = setup.store.load_upload_sessions().unwrap().remove(0);
        assert_eq!(persisted.files[0].prefix_bytes, bytes.len() as u64);
        assert!(restore_files(&setup, &mut persisted, || true).is_err());
        assert_eq!(persisted.files[0].prefix_bytes, 0);
        let mut persisted = setup.store.load_upload_sessions().unwrap().remove(0);
        assert_eq!(persisted.files[0].prefix_bytes, 0);
        let (mut files, _, _) = restore_files(&setup, &mut persisted, || true).unwrap();
        reprove_staging(&source, &object, vec![&mut files[0]], || true).unwrap();
        publish_file(&setup, &mut files[0], || true).unwrap();
        assert_eq!(fs::read(setup.dest_dir.join("frame")).unwrap(), bytes);
    }

    #[test]
    fn receipt_name_recovery_preserves_staging_before_publication() {
        for (destination, names, error) in [
            (
                "",
                vec!["frame.vot-receipt".into()],
                "reserved for signed receipts",
            ),
            (
                "",
                vec!["frame.VOT-RECEIPT".into(), "child".into()],
                "reserved for signed receipts",
            ),
            (
                "old.vot-receI\u{307}pt",
                vec!["frame".into()],
                "reserved for signed receipts",
            ),
            ("", vec!["a".repeat(243)], "242 UTF-8 bytes; shorten"),
            ("", vec!["ア".repeat(81)], "242 UTF-8 bytes; shorten"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let bytes = b"frame";
            let object = object(Suite::Blake3Bao64, bytes);
            let mut setup = setup(directory.path(), object.clone());
            setup.dest_rel = destination.into();
            setup.dest_dir = setup.dest_dir.join(destination);
            let source = directory.path().join("source");
            fs::write(&source, bytes).unwrap();
            let legacy_destination = setup.dest_dir.join(names.join("/"));
            let native = setup
                .destinations
                .directory(legacy_destination.parent().unwrap(), true)
                .unwrap()
                .create(
                    &object,
                    legacy_destination.file_name().unwrap(),
                    CommitProfile::Balanced,
                )
                .unwrap();
            let legacy = FileState {
                display_path: names.join("/"),
                stored_components: names.join("\0"),
                object: object.clone(),
                native: Some(StagedFile::new(
                    native,
                    legacy_destination,
                    ObjectCoverage::new(&object),
                    CommitProfile::Balanced,
                    Arc::clone(&setup.destinations),
                )),
                published: false,
                receipt: false,
                checkpointed: Mutex::new(None),
                first_range_at: None,
                rehash: false,
            };
            let mut files = [
                open_destination_for(&setup, vec!["allowed".into()], object.clone()).unwrap(),
                legacy,
            ];
            reprove_staging(&source, &object, files.iter_mut().collect(), || true).unwrap();
            persist_session(&setup, &files).unwrap();
            for file in &mut files {
                file.native.take().unwrap().abandon();
            }
            let mut saved = setup.store.load_upload_sessions().unwrap().remove(0);
            assert!(saved
                .files
                .iter()
                .all(|file| file.prefix_bytes == bytes.len() as u64));
            let before = saved.clone();
            let retained: Vec<_> = saved
                .files
                .iter()
                .flat_map(|file| [&file.staging_path, &file.journal_path])
                .map(|path| (path.clone(), fs::read(path).unwrap()))
                .collect();
            assert!(restore_files(&setup, &mut saved, || true)
                .err()
                .expect("invalid checkpoint resumed")
                .contains(error));
            assert_eq!(saved, before);
            assert_eq!(setup.store.load_upload_sessions().unwrap(), [before]);
            for (path, data) in retained {
                assert_eq!(fs::read(path).unwrap(), data);
            }
            assert!(!setup.dest_dir.join("allowed").exists());
            assert!(!setup.dest_dir.join(names.join("/")).exists());
            if !destination.is_empty() {
                let error = prepare_files(&setup, &[(vec!["new".into()], object.clone())], || true)
                    .err()
                    .expect("reserved destination admitted without a checkpoint manifest");
                assert!(error.message.contains("reserved for signed receipts"));
                assert!(!setup.dest_dir.join("new").exists());
            }
        }
    }

    #[test]
    fn publication_refuses_a_replaced_visible_parent_after_cache_eviction() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        let mut file =
            open_destination_for(&setup, vec!["project".into(), "frame".into()], object).unwrap();
        file.native.as_mut().unwrap().reopen().unwrap();
        for index in 0..16 {
            setup
                .destinations
                .directory(&setup.dest_dir.join(format!("other-{index}")), true)
                .unwrap();
        }
        let selected = setup.dest_dir.join("project");
        let held = setup.dest_dir.join("held");
        fs::rename(&selected, &held).unwrap();
        fs::create_dir(&selected).unwrap();
        assert!(publish_file(&setup, &mut file, || true).is_err());
        assert!(!selected.join("frame").exists());
        assert!(!selected.join("frame.vot-receipt").exists());
        fs::remove_dir(&selected).unwrap();
        fs::rename(&held, &selected).unwrap();
        publish_file(&setup, &mut file, || true).unwrap();
        assert!(selected.join("frame.vot-receipt").exists());
    }

    #[test]
    fn unresolved_partial_upload_keeps_its_admission_and_recovery_history_grows() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        setup
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                verification: "default".to_owned(),
                id: setup.link_id.clone(),
                tenant: String::new(),
                label: "recovery".into(),
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
        let mut files = (0..2)
            .map(|index| {
                open_destination_for(&setup, vec![format!("frame-{index}")], object.clone())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        persist_session(&setup, &files).unwrap();
        files[1].native.as_mut().unwrap().preserve = true;
        let mut phase = Phase::Receiving { files };
        assert!(!commit_partial(
            &setup,
            &mut phase,
            0,
            0,
            &TransferLog::default()
        ));
        let Phase::Receiving { files } = &mut phase else {
            unreachable!()
        };
        publish_file(&setup, &mut files[0], || true).unwrap();
        let journal = files[0].native.as_ref().unwrap().journal_path().to_owned();
        let connection =
            rusqlite::Connection::open(directory.path().join("data/votport.db")).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON upload_session_files BEGIN SELECT RAISE(FAIL, 'checkpoint failure'); END;").unwrap();
        assert!(!commit_partial(
            &setup,
            &mut phase,
            0,
            0,
            &TransferLog::default()
        ));
        assert!(journal.exists());
        preserve_phase(&setup, &mut phase);
        assert!(journal.exists());
        assert!(!setup.store.load_upload_sessions().unwrap()[0].files[0].published);
        connection
            .execute_batch("DROP TRIGGER fail_checkpoint;")
            .unwrap();
        let mut persisted = setup.store.load_upload_sessions().unwrap().remove(0);
        let (files, _, _) = restore_files(&setup, &mut persisted, || true).unwrap();
        assert!(files[0].published);
        assert!(!journal.exists());
        drop(files);
        let mut persisted = setup.store.load_upload_sessions().unwrap().remove(0);
        commit_persisted_interruption(&setup.store, &setup.ended, &persisted, "fixture");
        setup
            .store
            .tombstone_files("", &setup.link_id, &HashSet::from(["frame-0"]))
            .unwrap();
        persisted.files[1].published = true;
        commit_persisted_interruption(&setup.store, &setup.ended, &persisted, "fixture");
        let uploads = setup.store.uploads_by_id(&setup.link_id).unwrap().unwrap();
        let recovered = uploads
            .iter()
            .find(|upload| upload.id == format!("recovery-{}", persisted.id))
            .unwrap();
        assert_eq!(recovered.files.len(), 2);
        assert!(recovered.files[0].deleted);
        assert!(!recovered.files[1].deleted);
    }

    #[cfg(unix)]
    #[test]
    fn push_directory_lock_refuses_a_detached_handle_and_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let stage = directory.path().join("stage");
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new().mode(0o700).create(&stage).unwrap();
        let path = stage.join("writer.lock");
        let stale = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert!(lock_push_handle(stale, &path).is_err());
        let held = lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap();
        assert!(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).is_err());
        drop(held);
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&stage, &alias).unwrap();
        assert!(lock_push_directory(&alias, vot_sdk_file::NasContract::Unqualified).is_err());
    }

    fn write_push(
        sink: Arc<dyn vot_cli::ReceiveSink>,
        object: &vot_cli::ReceiveObject,
        bytes: &[u8],
    ) {
        let subject = object.object.try_into().unwrap();
        let mut verifier = vot_scheduler::ReliableReceiver::new(1 << 20, 1 << 20, 1 << 20).unwrap();
        verifier.begin_ranges(subject, Box::new(sink)).unwrap();
        let proof = vot_proof_blake3::prove(bytes, 0, bytes.len() as u64).unwrap();
        verifier
            .receive_range(subject, 0, bytes, &proof.proof)
            .unwrap();
        verifier.finish_ranges(subject).unwrap();
    }

    #[tokio::test]
    async fn repeated_frames_keep_alias_handles_bounded_and_publish_independent_files() {
        use std::os::unix::fs::MetadataExt as _;
        for (count, cancelled) in [
            (MAX_OPEN_PUSH_ALIASES, false),
            (MAX_OPEN_PUSH_ALIASES + 1, false),
            (MAX_OPEN_PUSH_ALIASES + 1, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let application = crate::api::testing::build(directory.path());
            application
                .store
                .insert_link(crate::store::Link {
                    retention_days: None,
                    verification: "default".to_owned(),
                    id: "link".to_owned(),
                    tenant: String::new(),
                    label: "retry".to_owned(),
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
            let bytes = b"repeated frame";
            let object = object(Suite::Blake3Bao64, bytes);
            let package = ObjectId {
                suite: 1,
                root: [4; 32],
                length: object.length * count as u64,
            };
            let setup = setup_with_app(directory.path(), package.clone(), &application);
            let key = hex::encode([3; 16]);
            setup.destinations.push_directory(&key).unwrap();
            persist_push(&setup, key.clone()).unwrap();
            let records: Vec<_> = (0..count)
                .map(|index| {
                    record(
                        vot_manifest::PackagePath::portable([format!("frame-{index:04}.exr")])
                            .unwrap(),
                        &object,
                    )
                })
                .collect();
            let requested = vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            };
            let (seams, handle) = push_seams(
                application,
                setup,
                PushControl::resumable(key, None),
                tokio::runtime::Handle::current(),
            );
            let receive = handle.0.upgrade().unwrap();
            if cancelled {
                receive.control.cancel();
            }
            let prepared = receive.prepare_manifest(
                vot_cli::PackageSummary {
                    root: package.root,
                    logical_length: package.length,
                    entries: count as u64,
                },
                &records,
            );
            if cancelled {
                assert!(prepared.is_err());
                assert!(receive.inner.lock().unwrap().entries.is_empty());
                continue;
            }
            prepared.unwrap();
            receive.setup.store.with(|connection| {
                connection.execute_batch("CREATE TRIGGER reject_unchanged_checkpoint BEFORE UPDATE ON upload_session_files
                    WHEN NEW.prefix_bytes = OLD.prefix_bytes AND NEW.published = OLD.published AND NEW.receipt = OLD.receipt
                    BEGIN SELECT RAISE(FAIL, 'unchanged checkpoint row'); END;")
            }).unwrap();
            receive.run_checkpoint().unwrap();
            assert!(receive.complete_object(&requested).is_err());
            let sink: Arc<dyn vot_cli::ReceiveSink> =
                Arc::from(receive.choose_sink(&requested).unwrap().unwrap());
            let files = receive.inner.lock().unwrap().objects[&PushObjectKey::from(&requested)]
                .active
                .as_ref()
                .unwrap()
                .clone();
            assert!(
                files
                    .read()
                    .unwrap()
                    .iter()
                    .filter(|(_, file)| file.native.as_ref().unwrap().active.is_some())
                    .count()
                    <= MAX_OPEN_PUSH_ALIASES
            );
            receive.run_checkpoint().unwrap();
            write_push(Arc::clone(&sink), &requested, bytes);
            for _ in 0..2 {
                receive.run_checkpoint().unwrap();
            }
            assert!(receive.setup.store.load_push_sessions().unwrap()[0]
                .files
                .iter()
                .all(|file| file.prefix_bytes == object.length));
            sink.flush().unwrap();
            assert_eq!(sink.resumed_prefix().unwrap(), object.length);
            let mut identities = std::collections::HashSet::new();
            for (_, file) in files.write().unwrap().iter_mut() {
                publish_file(&receive.setup, file, || true).unwrap();
                let path = receive.setup.dest_dir.join(&file.display_path);
                assert_eq!(fs::read(&path).unwrap(), bytes);
                assert!(identities.insert(fs::metadata(&path).unwrap().ino()));
            }
            // This test publishes the sink's files directly instead of through
            // finish_object, so mark them dirty as finish_object would.
            receive
                .dirty
                .lock()
                .unwrap()
                .extend(files.read().unwrap().iter().map(|(entry, _)| *entry));
            receive.run_checkpoint().unwrap();
            assert!(receive.setup.store.load_push_sessions().unwrap()[0]
                .files
                .iter()
                .all(|file| file.published && file.receipt));
            sink.discard_partial().unwrap();
            assert!(sink.resumed_prefix().is_err());
            drop(sink);
            drop(receive);
            drop(seams);
        }
    }

    #[tokio::test]
    async fn push_retry_preserves_direct_files_and_requires_verified_witnesses() {
        let directory = tempfile::tempdir().unwrap();
        let data = [b"first payload".as_slice(), b"second payload".as_slice()];
        let objects = data.map(|bytes| object(Suite::Blake3Bao64, bytes));
        let expected = ObjectId {
            suite: 1,
            root: [9; 32],
            length: data.iter().map(|bytes| bytes.len() as u64).sum(),
        };
        let application = crate::api::testing::build(directory.path());
        let first_setup = setup_with_app(directory.path(), expected.clone(), &application);
        let mut retry_setup = setup_with_app(directory.path(), expected.clone(), &application);
        retry_setup.session_id = [8; 16];
        application
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                verification: "default".to_owned(),
                id: "link".to_owned(),
                tenant: String::new(),
                label: "retry".to_owned(),
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
        let key = hex::encode([3; 16]);
        let stage = first_setup.destinations.push_directory(&key).unwrap();
        let records = objects
            .iter()
            .enumerate()
            .map(|(index, object)| {
                record(
                    vot_manifest::PackagePath::portable([format!("file-{index}")]).unwrap(),
                    object,
                )
            })
            .collect::<Vec<_>>();
        let summary = vot_cli::PackageSummary {
            root: expected.root,
            logical_length: expected.length,
            entries: 2,
        };
        let receive_objects = objects
            .iter()
            .map(|object| vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            })
            .collect::<Vec<_>>();
        persist_push(&first_setup, key.clone()).unwrap();
        let control = PushControl::resumable(
            key.clone(),
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            first_setup,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        let sink: Arc<dyn vot_cli::ReceiveSink> =
            Arc::from(receive.choose_sink(&receive_objects[0]).unwrap().unwrap());
        assert!(sink.write_at(0, data[0]).is_err());
        write_push(Arc::clone(&sink), &receive_objects[0], data[0]);
        sink.flush().unwrap();
        receive.complete_object(&receive_objects[0]).unwrap();
        drop(sink);
        let sink = receive.choose_sink(&receive_objects[1]).unwrap().unwrap();
        assert!(sink.write_at(0, b"wrong").is_err());
        drop(sink);
        drop(receive);
        drop(seams);
        assert!(handle.0.upgrade().is_none());
        assert!(directory.path().join("receive/file-0").is_file());
        assert!(!stage.join("objects").exists());
        persist_push(&retry_setup, key.clone()).unwrap();
        let control = PushControl::resumable(
            key,
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            retry_setup,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        // The published object resumes through the done sink: the whole
        // length is the prefix, flush is a no-op, and the completion hook
        // finishes it here.
        let done = receive.choose_sink(&receive_objects[0]).unwrap().unwrap();
        assert_eq!(
            done.resumed_prefix().unwrap(),
            receive_objects[0].object.length
        );
        done.flush().unwrap();
        drop(done);
        receive.complete_object(&receive_objects[0]).unwrap();
        let sink: Arc<dyn vot_cli::ReceiveSink> =
            Arc::from(receive.choose_sink(&receive_objects[1]).unwrap().unwrap());
        write_push(Arc::clone(&sink), &receive_objects[1], data[1]);
        sink.flush().unwrap();
        receive.complete_object(&receive_objects[1]).unwrap();
        assert!(application.store.load_push_sessions().unwrap()[0]
            .files
            .iter()
            .all(|file| file.published));
        drop(sink);
        drop(receive);
        drop(seams);
        assert!(!stage.exists());
        assert!(application.store.load_push_sessions().unwrap().is_empty());
        for (index, bytes) in data.iter().enumerate() {
            assert_eq!(
                fs::read(directory.path().join(format!("receive/file-{index}"))).unwrap(),
                *bytes
            );
        }
    }

    #[tokio::test]
    async fn push_retry_finishes_published_objects_through_the_completion_hook() {
        let directory = tempfile::tempdir().unwrap();
        let data = [b"first payload".as_slice(), b"second payload".as_slice()];
        let objects = data.map(|bytes| object(Suite::Blake3Bao64, bytes));
        let expected = ObjectId {
            suite: 1,
            root: [9; 32],
            length: data.iter().map(|bytes| bytes.len() as u64).sum(),
        };
        let application = crate::api::testing::build(directory.path());
        let first_setup = setup_with_app(directory.path(), expected.clone(), &application);
        let mut retry_setup = setup_with_app(directory.path(), expected.clone(), &application);
        retry_setup.session_id = [8; 16];
        application
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                verification: "default".to_owned(),
                id: "link".to_owned(),
                tenant: String::new(),
                label: "retry".to_owned(),
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
        let key = hex::encode([3; 16]);
        let stage = first_setup.destinations.push_directory(&key).unwrap();
        let records = objects
            .iter()
            .enumerate()
            .map(|(index, object)| {
                record(
                    vot_manifest::PackagePath::portable([format!("file-{index}")]).unwrap(),
                    object,
                )
            })
            .collect::<Vec<_>>();
        let summary = vot_cli::PackageSummary {
            root: expected.root,
            logical_length: expected.length,
            entries: 2,
        };
        let receive_objects = objects
            .iter()
            .map(|object| vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            })
            .collect::<Vec<_>>();
        persist_push(&first_setup, key.clone()).unwrap();
        let control = PushControl::resumable(
            key.clone(),
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            first_setup,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        // Publish both objects in the first session.
        for (index, bytes) in data.iter().enumerate() {
            let sink: Arc<dyn vot_cli::ReceiveSink> = Arc::from(
                receive
                    .choose_sink(&receive_objects[index])
                    .unwrap()
                    .unwrap(),
            );
            write_push(Arc::clone(&sink), &receive_objects[index], bytes);
            sink.flush().unwrap();
            receive.complete_object(&receive_objects[index]).unwrap();
            drop(sink);
        }
        drop(receive);
        drop(seams);
        // The retry session finds every object published: choose_sink hands
        // back the done sink for each, and the completion hook (not the
        // sink) finishes the object and the session. The first session
        // finished completely, so its staging directory was removed; the
        // retry recreates it.
        persist_push(&retry_setup, key.clone()).unwrap();
        retry_setup.destinations.push_directory(&key).unwrap();
        let control = PushControl::resumable(
            key,
            Some(lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap()),
        );
        let (seams, handle) = push_seams(
            application.clone(),
            retry_setup,
            control,
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive.prepare_manifest(summary, &records).unwrap();
        for requested in &receive_objects {
            let done = receive.choose_sink(requested).unwrap().unwrap();
            assert_eq!(done.resumed_prefix().unwrap(), requested.object.length);
            done.flush().unwrap();
            receive.complete_object(requested).unwrap();
        }
        assert!(application.store.load_push_sessions().unwrap()[0]
            .files
            .iter()
            .all(|file| file.published));
        drop(receive);
        drop(seams);
        assert!(!stage.exists());
        assert!(application.store.load_push_sessions().unwrap().is_empty());
        for (index, bytes) in data.iter().enumerate() {
            assert_eq!(
                fs::read(directory.path().join(format!("receive/file-{index}"))).unwrap(),
                *bytes
            );
        }
    }

    #[test]
    fn deduplication_pages_skip_aliases_and_verify_remaining_candidates() {
        let page = crate::store::DELIVERED_CANDIDATE_PAGE;
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            for length in [0, (1 << 20) + 1] {
                let directory = tempfile::tempdir().unwrap();
                let bytes = vec![7; length];
                let expected = object(suite, &bytes);
                let mut setup = setup(directory.path(), expected.clone());
                setup.dest_rel = "project".into();
                setup.dest_dir.push("project");
                fs::create_dir(&setup.dest_dir).unwrap();
                let template = FileRecord {
                    path: "original".into(),
                    stored_as: "project/a-bad".into(),
                    bytes: expected.length,
                    suite: suite_name(expected.suite),
                    root: hex::encode(expected.root),
                    receipt: true,
                    deleted: false,
                };
                let mut files = vec![template.clone(); page * 3 + 3];
                for i in 0..=page {
                    files.push(FileRecord {
                        stored_as: format!("project/b-missing-{i:03}"),
                        ..template.clone()
                    });
                }
                for name in [
                    "outside/elsewhere",
                    "project/../escape",
                    "project/c.vot-receipt",
                    "project/d-short",
                    "project/e-deleted",
                    "project/f-record-length",
                    "project/z-valid",
                ] {
                    files.push(FileRecord {
                        stored_as: name.into(),
                        deleted: name == "project/e-deleted",
                        bytes: expected.length + u64::from(name == "project/f-record-length"),
                        receipt: suite == Suite::Blake3Bao64,
                        ..template.clone()
                    });
                }
                record_delivered_files(&setup, files);
                fs::create_dir(setup.dest_dir.join("outside")).unwrap();
                fs::write(setup.dest_dir.join("outside/elsewhere"), &bytes).unwrap();
                fs::write(setup.dest_dir.parent().unwrap().join("escape"), &bytes).unwrap();
                fs::write(setup.dest_dir.join("a-bad"), vec![9; length.max(1)]).unwrap();
                fs::write(setup.dest_dir.join("d-short"), vec![7; length + 1]).unwrap();
                for name in ["c.vot-receipt", "e-deleted", "f-record-length", "z-valid"] {
                    fs::write(setup.dest_dir.join(name), &bytes).unwrap();
                }
                let checks = AtomicUsize::new(0);
                let announced = ["z-valid".to_owned()];
                let found = find_delivered(&setup, &expected, &announced, || {
                    let n = checks.fetch_add(1, Ordering::Relaxed);
                    assert!(
                        n < page + 40,
                        "aliases were revisited or pagination failed to advance"
                    );
                    true
                })
                .unwrap()
                .unwrap();
                assert_eq!(found.stored_components, ["z-valid"]);
                let checks = AtomicUsize::new(0);
                assert_eq!(
                    find_delivered(&setup, &expected, &announced, || {
                        checks.fetch_add(1, Ordering::Relaxed) < 2
                    })
                    .err()
                    .unwrap()
                    .status,
                    409
                );
                assert_eq!(checks.load(Ordering::Relaxed), 3);
                setup
                    .store
                    .with(|c| c.execute_batch("DROP TABLE files"))
                    .unwrap();
                let result = prepare_files(
                    &setup,
                    &[(vec!["new".into(), "frame".into()], expected)],
                    || true,
                );
                assert_eq!(result.err().unwrap().status, 500);
                assert!(!setup.dest_dir.join("new").exists());
            }
        }
    }

    #[tokio::test]
    async fn deduplication_rejects_changed_bytes_and_published_recovery_is_settled() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let directory = tempfile::tempdir().unwrap();
            let expected = object(suite, b"original");
            let setup = setup(directory.path(), expected.clone());
            fs::create_dir_all(&setup.dest_dir).unwrap();
            let path = setup.dest_dir.join("frame.bin");
            fs::write(&path, b"original").unwrap();
            let record = FileRecord {
                path: "frame.bin".into(),
                stored_as: "frame.bin".into(),
                bytes: 8,
                suite: suite_name(expected.suite),
                root: hex::encode(expected.root),
                receipt: true,
                deleted: false,
            };
            record_delivered_files(&setup, vec![record.clone()]);
            let announced = ["frame.bin".to_owned()];
            assert!(find_delivered(&setup, &expected, &announced, || true)
                .unwrap()
                .is_some());
            assert!(find_delivered(&setup, &expected, &announced, || false).is_err());
            for name in [
                "old.vot-receipt".into(),
                "old.vot-receI\u{307}pt/frame".into(),
                "a".repeat(243),
                "ア".repeat(81),
            ] {
                let reserved = setup.dest_dir.join(&name);
                fs::create_dir_all(reserved.parent().unwrap()).unwrap();
                fs::write(&reserved, b"original").unwrap();
                setup
                    .store
                    .with(|c| c.execute("UPDATE files SET stored_as=?1", [&name]))
                    .unwrap();
                let (files, _allocation) = prepare_files(
                    &setup,
                    &[(vec!["renamed.bin".into()], expected.clone())],
                    || true,
                )
                .unwrap();
                assert_eq!(files[0].stored_components, "renamed.bin");
                assert!(!files[0].published);
                assert_eq!(fs::read(&reserved).unwrap(), b"original");
            }
            setup
                .store
                .with(|c| c.execute("UPDATE files SET stored_as=?1", [&record.stored_as]))
                .unwrap();
            fs::write(&path, b"changed!").unwrap();
            assert!(find_delivered(&setup, &expected, &announced, || true)
                .unwrap()
                .is_none());
            let file = FileState {
                display_path: record.path.clone(),
                stored_components: record.path,
                object: expected,
                native: None,
                published: true,
                receipt: true,
                checkpointed: Mutex::new(None),
                first_range_at: None,
                rehash: false,
            };
            // A published file whose journal is retired is settled: editing
            // or moving it afterwards does not strand the session.
            let mut persisted = persisted_session(&setup, &[file]);
            let (_, receiver) = mpsc::channel(1);
            resume_worker(setup, receiver, &mut persisted).unwrap();
        }
    }

    #[tokio::test]
    async fn fast_profile_survives_parking_and_restart_on_local_storage() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        let destination = setup.dest_dir.join("fast");
        let native = setup
            .destinations
            .directory(&setup.dest_dir, true)
            .unwrap()
            .create(
                &object,
                destination.file_name().unwrap(),
                CommitProfile::Fast,
            )
            .unwrap();
        let mut staged = StagedFile::new(
            native,
            destination.clone(),
            ObjectCoverage::new(&object),
            CommitProfile::Fast,
            Arc::clone(&setup.destinations),
        );
        staged.reopen().unwrap();
        staged.park();
        let file = FileState {
            display_path: "fast".to_owned(),
            stored_components: "fast".to_owned(),
            object: object.clone(),
            native: Some(staged),
            published: false,
            receipt: false,
            checkpointed: Mutex::new(None),
            first_range_at: None,
            rehash: false,
        };
        let mut persisted = persisted_session(&setup, std::slice::from_ref(&file));
        assert_eq!(persisted.files[0].profile, CommitProfile::Fast);
        file.native.unwrap().abandon();
        let signer = Arc::clone(&setup.signer);
        let (sender, receiver) = mpsc::channel(1);
        resume_worker(setup, receiver, &mut persisted).unwrap();
        drop(sender);
        assert!(persisted.files[0].published);
        let bytes = fs::read(destination.with_extension("vot-receipt")).unwrap();
        let decoded = vot_receipt::decode_authenticated(&bytes).unwrap();
        let verified = vot_receipt::verify_ed25519(&decoded, &signer.verifying_key()).unwrap();
        assert_eq!(verified.receipt().profile, vot_receipt::CommitProfile::Fast);
        let mut baseline = vot_sdk_file::ReceiveDirectory::open(
            directory.path(),
            vot_sdk_file::NasContract::Unqualified,
        )
        .unwrap()
        .create(
            &object,
            std::ffi::OsStr::new("baseline"),
            CommitProfile::Fast,
        )
        .unwrap();
        baseline.publish().unwrap();
        assert_eq!(
            verified.receipt().sequence,
            baseline.publish_observation().unwrap().sequence
        );
    }

    /// Finding 24: the link's verification level, not the mount alone,
    /// picks the publication profile; the receipt records the actual one.
    #[test]
    fn link_verification_level_sets_the_publication_profile() {
        let directory = tempfile::tempdir().unwrap();
        let object = object(Suite::Blake3Bao64, b"");
        let mut setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        // On local storage "default" and "balanced" both resolve Balanced,
        // matching the previous hardcoded behavior.
        for (level, expected) in [
            ("default", CommitProfile::Balanced),
            ("balanced", CommitProfile::Balanced),
        ] {
            setup.verification = level.to_owned();
            let mut file =
                open_destination_for(&setup, vec![format!("{level}")], object.clone()).unwrap();
            let staged = file.native.as_mut().unwrap();
            staged.reopen().unwrap();
            assert_eq!(staged.profile, expected, "level {level}");
            staged.park();
        }
        // "strict" publishes Strict and the receipt records that profile.
        setup.verification = "strict".to_owned();
        let mut file = open_destination_for(&setup, vec!["vault".to_string()], object).unwrap();
        let staged = file.native.as_mut().unwrap();
        staged.reopen().unwrap();
        assert_eq!(staged.profile, CommitProfile::Strict);
        finish_publication(&setup, &mut file).unwrap();
        assert!(file.receipt);
        let bytes = fs::read(setup.dest_dir.join("vault.vot-receipt")).unwrap();
        let decoded = vot_receipt::decode_authenticated(&bytes).unwrap();
        let verified =
            vot_receipt::verify_ed25519(&decoded, &setup.signer.verifying_key()).unwrap();
        assert_eq!(
            verified.receipt().profile,
            vot_receipt::CommitProfile::Strict
        );
    }

    fn record(path: vot_manifest::PackagePath, object: &ObjectId) -> vot_cli::EntryRecord {
        vot_cli::EntryRecord {
            path,
            suite: Suite::try_from(object.suite).unwrap(),
            logical_root: object.root,
            logical_length: object.length,
            storage: vot_cli::Storage::Direct,
        }
    }

    #[test]
    fn six_figure_entry_counts_fit_without_a_large_fixture() {
        for count in [0, 100_000, MAX_SESSION_ENTRIES - 1, MAX_SESSION_ENTRIES] {
            assert!(entry_count_within_limit(count, u64::MAX));
        }
        for count in [MAX_SESSION_ENTRIES + 1, 2_000_000, usize::MAX] {
            assert!(!entry_count_within_limit(count, u64::MAX));
        }
    }

    #[test]
    fn entry_count_budget_leaves_a_small_empty_file_floor() {
        assert_eq!(max_entries_for_bytes(0), 256);
        assert_eq!(max_entries_for_bytes(1024 * 1024), 512);
        assert!(max_entries_for_bytes(20_000 * 4096) >= 20_000);
        assert_eq!(max_entries_for_bytes(u64::MAX), MAX_SESSION_ENTRIES);
    }

    #[test]
    #[ignore = "changes the process descriptor limit; CI runs this test alone"]
    fn dormant_staging_preserves_ranges_and_cleans_up_under_low_descriptor_limit() {
        let mut limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        limit.current = Some(64);
        rustix::process::setrlimit(rustix::process::Resource::Nofile, limit).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let data = vec![23u8; 3 * 65_536];
        let object = object(Suite::Blake3Bao64, &data);
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        let files = (0..128)
            .map(|index| {
                open_destination_for(&setup, vec![format!("file-{index}")], object.clone()).unwrap()
            })
            .collect::<Vec<_>>();
        assert!(files
            .iter()
            .all(|file| file.native.as_ref().unwrap().active.is_none()));
        let mut phase = Phase::Receiving { files };
        let chunk = |entry, offset| {
            let proof = vot_proof_blake3::prove(&data, offset, 65_536).unwrap();
            BatchChunk {
                entry,
                offset: proof.covered_offset,
                proof: proof.proof.into(),
                data: proof.data.into(),
                reply: oneshot::channel().0,
                _lease: SessionLease {
                    activity: Arc::new(SessionActivity {
                        in_flight: AtomicUsize::new(1),
                        last_active: Mutex::new(Instant::now()),
                        received: AtomicU64::new(0),
                    }),
                },
            }
        };
        let send = |phase: &mut Phase, entry, offset| {
            accept_batch(&setup, phase, &[chunk(entry, offset)])
                .pop()
                .unwrap()
        };
        for index in 0..128 {
            let progress = send(&mut phase, index, 131_072).unwrap();
            assert_eq!(progress.covered_bytes, 65_536);
        }
        for offset in [0, 65_536] {
            let batch = (3..3 + MAX_CHUNK_BATCH)
                .map(|entry| chunk(entry, offset))
                .collect::<Vec<_>>();
            for result in accept_batch(&setup, &mut phase, &batch) {
                assert_eq!(result.unwrap().complete, offset == 65_536);
            }
        }
        assert_eq!(send(&mut phase, 0, 0).unwrap().covered_bytes, 131_072);
        assert!(send(&mut phase, 0, 131_072).unwrap().replay);
        assert!(send(&mut phase, 0, 65_536).unwrap().complete);
        assert_eq!(fs::read(setup.dest_dir.join("file-0")).unwrap(), data);
        let Phase::Receiving { files } = &mut phase else {
            unreachable!()
        };
        let persisted = persisted_session(&setup, files.iter());
        assert!(persisted.files[0].published);
        assert_eq!(persisted.files[1].prefix_bytes, 0);
        assert!(!persisted.files[1].staging_path.as_os_str().is_empty());
        let kept = files[1].native.take().unwrap();
        let staging = kept.staging.clone();
        let journal = kept.journal.clone();
        let incarnation = kept.incarnation;
        kept.abandon();
        assert!(staging.exists() && journal.exists());
        let reopened = NativeFile::resume(
            &object,
            setup.dest_dir.join("file-1"),
            &staging,
            &journal,
            incarnation,
            CommitProfile::Balanced,
            [(131_072, 65_536)],
        )
        .unwrap();
        assert_eq!(reopened.progress().covered_bytes, 65_536);
        drop(reopened);
        assert!(!staging.exists() && !journal.exists());
        let tampered = files[2].native.as_ref().unwrap().staging.clone();
        let mut file = fs::OpenOptions::new().write(true).open(tampered).unwrap();
        file.seek(SeekFrom::Start(131_072)).unwrap();
        std::io::Write::write_all(&mut file, b"wrong").unwrap();
        drop(file);
        send(&mut phase, 2, 0).unwrap();
        assert!(send(&mut phase, 2, 65_536).is_err());
        assert!(!setup.dest_dir.join("file-2").exists());
        drop(phase);
        let source = directory.path().join("quic-source");
        fs::write(&source, &data).unwrap();
        let mut destinations = (0..32)
            .map(|index| {
                open_destination_for(&setup, vec![format!("quic-{index}")], object.clone()).unwrap()
            })
            .collect::<Vec<_>>();
        reprove_staging(&source, &object, destinations.iter_mut().collect(), || true).unwrap();
        for destination in &mut destinations {
            let staged = destination.native.as_ref().unwrap();
            assert!(staged.active.is_none());
            assert_eq!(staged.progress().prefix_bytes, object.length);
            let path = staged.destination.clone();
            publish_file(&setup, destination, || true).unwrap();
            assert_eq!(fs::read(path).unwrap(), data);
        }
        drop(destinations);
        assert!(
            !fs::read_dir(&setup.dest_dir).unwrap().any(|entry| matches!(
                entry
                    .unwrap()
                    .path()
                    .extension()
                    .and_then(|part| part.to_str()),
                Some("stage" | "journal")
            ))
        );
    }

    #[test]
    fn push_manifest_rejects_mismatch_pack_raw_path_and_entry_cap() {
        let directory = tempfile::tempdir().unwrap();
        let logical = object(Suite::Blake3Bao64, b"payload");
        let expected = ObjectId {
            suite: 1,
            root: [9; 32],
            length: logical.length,
        };
        let setup = setup(directory.path(), expected.clone());
        let direct = record(
            vot_manifest::PackagePath::portable(["file"]).unwrap(),
            &logical,
        );
        let summary = vot_cli::PackageSummary {
            root: expected.root,
            logical_length: logical.length,
            entries: 1,
        };
        assert!(validate_push_manifest(&setup, summary, std::slice::from_ref(&direct)).is_ok());
        for path in [
            vec!["report.vot-receipt"],
            vec!["report.VOT-RECEIPT", "child"],
            vec!["report.vot-receI\u{307}pt"],
        ] {
            let reserved = record(vot_manifest::PackagePath::portable(path).unwrap(), &logical);
            let error = validate_push_manifest(&setup, summary, &[reserved]).unwrap_err();
            assert!(error.message.contains("reserved for signed receipts"));
        }

        let mut mismatch = summary;
        mismatch.root[0] ^= 1;
        assert!(validate_push_manifest(&setup, mismatch, std::slice::from_ref(&direct)).is_err());
        let mut mismatch = summary;
        mismatch.logical_length += 1;
        assert!(validate_push_manifest(&setup, mismatch, std::slice::from_ref(&direct)).is_err());

        let mut packed = direct.clone();
        packed.storage = vot_cli::Storage::Pack {
            root: logical.root,
            length: logical.length,
            offset: 0,
        };
        assert!(validate_push_manifest(&setup, summary, &[packed]).is_err());

        let raw = record(vot_manifest::PackagePath::raw([b"file"]).unwrap(), &logical);
        assert!(validate_push_manifest(&setup, summary, &[raw]).is_err());

        assert!(!entry_count_within_limit(MAX_SESSION_ENTRIES + 1, u64::MAX));
    }

    #[test]
    fn local_reproof_accepts_original_and_rejects_tampered_blake3() {
        reproof_accepts_original_and_rejects_tampered(Suite::Blake3Bao64);
    }

    #[test]
    fn local_reproof_accepts_original_and_rejects_tampered_sha256() {
        reproof_accepts_original_and_rejects_tampered(Suite::Sha256Bep52);
    }

    fn reproof_accepts_original_and_rejects_tampered(suite: Suite) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("staged");
        let data = vec![11_u8; vot_scheduler::RANGE_UNIT_BYTES as usize + 17];
        let object = object(suite, &data);
        fs::write(&path, &data).unwrap();
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        let mut destination =
            open_destination_for(&setup, vec!["received".to_owned()], object.clone()).unwrap();
        assert!(reprove_staging(&path, &object, vec![&mut destination], || true).is_ok());
        assert_eq!(
            destination.native.as_ref().unwrap().progress().prefix_bytes,
            object.length
        );

        let mut tampered = data;
        tampered[3] ^= 1;
        fs::write(&path, tampered).unwrap();
        assert!(reprove_staging(&path, &object, Vec::new(), || true).is_err());
    }

    #[test]
    fn empty_object_roots_are_canonical_for_both_suites() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let empty = object(suite, b"");
            assert!(validate_empty_object(&empty).is_ok());
            let mut forged = empty;
            forged.root[0] ^= 1;
            assert!(validate_empty_object(&forged).is_err());
        }
    }

    #[test]
    fn cancelled_reproof_stops_during_hashing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("staged");
        let data = vec![17_u8; 2 * vot_scheduler::RANGE_UNIT_BYTES as usize];
        fs::write(&path, &data).unwrap();
        let object = object(Suite::Blake3Bao64, &data);
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        let mut destination =
            open_destination_for(&setup, vec!["cancelled".to_owned()], object.clone()).unwrap();

        let mut checks = 0;
        assert!(reprove_staging(&path, &object, vec![&mut destination], || {
            checks += 1;
            checks < 2
        })
        .is_err());
        assert_eq!(
            destination
                .native
                .as_ref()
                .unwrap()
                .progress()
                .covered_bytes,
            0
        );
    }

    #[test]
    fn cancelled_reproof_stops_after_an_accepted_range() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("staged");
        let length =
            (vot_scheduler::MAX_PROOF_RANGE_BYTES + vot_scheduler::RANGE_UNIT_BYTES) as usize;
        let data = vec![19_u8; length];
        fs::write(&path, &data).unwrap();
        let object = object(Suite::Blake3Bao64, &data);
        let setup = setup(directory.path(), object.clone());
        fs::create_dir_all(&setup.dest_dir).unwrap();
        let mut destination =
            open_destination_for(&setup, vec!["cancelled".to_owned()], object.clone()).unwrap();
        let hash_checks = length.div_ceil(vot_scheduler::RANGE_UNIT_BYTES as usize);
        let mut checks = 0;

        assert!(reprove_staging(&path, &object, vec![&mut destination], || {
            checks += 1;
            checks <= hash_checks + 1
        })
        .is_err());
        assert!(
            destination
                .native
                .as_ref()
                .unwrap()
                .progress()
                .covered_bytes
                > 0
        );
    }

    #[test]
    fn a_published_file_and_journal_survive_an_unrecorded_push_failure() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let bytes = b"published bytes";
        fs::write(&source, bytes).unwrap();
        let object = object(Suite::Blake3Bao64, bytes);
        let setup = setup(directory.path(), object.clone());
        let mut file =
            open_destination_for(&setup, vec!["final".to_owned()], object.clone()).unwrap();
        reprove_staging(&source, &object, vec![&mut file], || true).unwrap();
        let journal = file.native.as_ref().unwrap().journal.clone();
        publish_file(&setup, &mut file, || true).unwrap();
        assert!(journal.is_file());
        drop(file);
        assert_eq!(fs::read(setup.dest_dir.join("final")).unwrap(), bytes);
        assert!(journal.is_file());
    }
    /// Two-object push with the checkpoint trigger forced on: while the sink's
    /// checkpoint blocks inside its SQLite commit (the test holds the store
    /// connection), choose_sink for the second object must still complete.
    #[tokio::test]
    async fn choose_sink_completes_while_a_checkpoint_persistence_is_in_flight() {
        let directory = tempfile::tempdir().unwrap();
        // One completing write for the writer thread, five untouched objects
        // for the probe iterations, each choose_sink a fresh target.
        let data = [
            b"first payload".as_slice(),
            b"payload-1".as_slice(),
            b"payload-2".as_slice(),
            b"payload-3".as_slice(),
            b"payload-4".as_slice(),
            b"payload-5".as_slice(),
        ];
        let objects = data.map(|bytes| object(Suite::Blake3Bao64, bytes));
        let expected = ObjectId {
            suite: 1,
            root: [9; 32],
            length: data.iter().map(|bytes| bytes.len() as u64).sum(),
        };
        let application = crate::api::testing::build(directory.path());
        application
            .store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let setup = setup_with_app(directory.path(), expected.clone(), &application);
        let key = hex::encode([4; 16]);
        setup.destinations.push_directory(&key).unwrap();
        persist_push(&setup, key.clone()).unwrap();
        let records = objects
            .iter()
            .enumerate()
            .map(|(index, object)| {
                record(
                    vot_manifest::PackagePath::portable([format!("file-{index}")]).unwrap(),
                    object,
                )
            })
            .collect::<Vec<_>>();
        let requested = objects
            .iter()
            .map(|object| vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            })
            .collect::<Vec<_>>();
        let (seams, handle) = push_seams(
            application.clone(),
            setup,
            PushControl::resumable(key, None),
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive
            .prepare_manifest(
                vot_cli::PackageSummary {
                    root: expected.root,
                    logical_length: expected.length,
                    entries: data.len() as u64,
                },
                &records,
            )
            .unwrap();
        let (written, written_rx) = std::sync::mpsc::channel();
        // Holding the store connection blocks the checkpoint's SQLite commit
        // for as long as this closure runs: a checkpoint-sized persistence.
        application.store.with(|_| {
            // Force the completing write into a checkpoint-sized flush.
            {
                let mut tracker = receive.checkpoint.lock().unwrap();
                tracker.bytes_since = PERSIST_BYTES;
                tracker.last_at = Instant::now() - PERSIST_INTERVAL;
            }
            let writer = {
                let receive = Arc::clone(&receive);
                let object = requested[0].object;
                let full = requested[0].clone();
                let written = written.clone();
                std::thread::spawn(move || {
                    let sink: Arc<dyn vot_cli::ReceiveSink> =
                        Arc::from(receive.choose_sink(&full).unwrap().unwrap());
                    write_push(
                        sink,
                        &vot_cli::ReceiveObject {
                            object,
                            entries: Vec::new(),
                        },
                        data[0],
                    );
                    let _ = written.send(());
                })
            };
            // While that persistence is in flight, choose_sink for the other
            // objects must not wait for the checkpoint's store commit. One
            // fresh object per probe so no probe trips the already-sinked
            // conflict; a probe that outlives its own timeout is the
            // regression (the checkpoint holding the push state lock) and
            // panics with a diagnosis instead of hanging the suite.
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            for object in requested.iter().skip(1) {
                let (chosen, chosen_rx) = std::sync::mpsc::channel();
                {
                    let receive = Arc::clone(&receive);
                    let object = object.clone();
                    std::thread::spawn(move || {
                        let _ = chosen.send(receive.choose_sink(&object).is_ok());
                    });
                }
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let budget = remaining.min(Duration::from_secs(2));
                match chosen_rx.recv_timeout(budget) {
                    Ok(true) => {}
                    Ok(false) => panic!("choose_sink failed while a checkpoint was in flight"),
                    Err(_) => panic!(
                        "choose_sink did not complete within 2s while a checkpoint persistence was in flight; the checkpoint holds the push state lock across its store commit"
                    ),
                }
            }
            drop(writer);
            Ok(())
        })
        .unwrap();
        written_rx
            .recv_timeout(Duration::from_secs(15))
            .expect("the checkpoint write never finished after the store was released");
        drop(receive);
        drop(seams);
    }

    /// Entry 1 is advanced through a path that bypasses the sink, so it is
    /// never marked dirty (production mutations always mark their entries):
    /// the checkpoint must store entry 0 but leave entry 1's stale row alone
    /// instead of walking every entry.
    #[tokio::test]
    async fn checkpoint_stores_only_dirty_entries() {
        let directory = tempfile::tempdir().unwrap();
        let data = b"first payload";
        let untouched_bytes = vec![0x53; 131_072];
        let mut builder = InMemoryObjectBuilder::new(
            Suite::Blake3Bao64,
            Some(untouched_bytes.len() as u64),
            131_072,
        )
        .unwrap();
        builder.update(&untouched_bytes).unwrap();
        let prepared = builder.finish().unwrap();
        let objects = [
            object(Suite::Blake3Bao64, data),
            prepared.object_id().clone(),
        ];
        let expected = ObjectId {
            suite: 1,
            root: [9; 32],
            length: (data.len() + untouched_bytes.len()) as u64,
        };
        let application = crate::api::testing::build(directory.path());
        application
            .store
            .insert_link(crate::store::tests::test_link("link"))
            .unwrap();
        let setup = setup_with_app(directory.path(), expected.clone(), &application);
        let key = hex::encode([5; 16]);
        setup.destinations.push_directory(&key).unwrap();
        persist_push(&setup, key.clone()).unwrap();
        let records = objects
            .iter()
            .enumerate()
            .map(|(index, object)| {
                record(
                    vot_manifest::PackagePath::portable([format!("file-{index}")]).unwrap(),
                    object,
                )
            })
            .collect::<Vec<_>>();
        let requested = objects
            .iter()
            .map(|object| vot_cli::ReceiveObject {
                object: vot_codec::frames::ObjectId {
                    suite: object.suite,
                    root: object.root,
                    length: object.length,
                },
                entries: Vec::new(),
            })
            .collect::<Vec<_>>();
        let (seams, handle) = push_seams(
            application.clone(),
            setup,
            PushControl::resumable(key, None),
            tokio::runtime::Handle::current(),
        );
        let receive = handle.0.upgrade().unwrap();
        receive
            .prepare_manifest(
                vot_cli::PackageSummary {
                    root: expected.root,
                    logical_length: expected.length,
                    entries: 2,
                },
                &records,
            )
            .unwrap();
        let first: Arc<dyn vot_cli::ReceiveSink> =
            Arc::from(receive.choose_sink(&requested[0]).unwrap().unwrap());
        // Advance entry 1 outside the sink write path: no dirty mark.
        {
            let mut inner = receive.inner.lock().unwrap();
            let file = inner.entries[1].file.as_mut().unwrap();
            file.native.as_mut().unwrap().reopen().unwrap();
            for offset in [0u64, 65_536] {
                let proof = prepared.prove(offset, 65_536).unwrap();
                let index = offset as usize;
                accept_range(
                    std::slice::from_ref(file),
                    0,
                    offset,
                    proof.proof(),
                    &untouched_bytes[index..index + 65_536],
                )
                .unwrap();
            }
        }
        // Force the sink's next write_verified into its checkpoint.
        {
            let mut tracker = receive.checkpoint.lock().unwrap();
            tracker.bytes_since = PERSIST_BYTES;
            tracker.last_at = Instant::now() - PERSIST_INTERVAL;
        }
        write_push(Arc::clone(&first), &requested[0], data);
        let saved = application.store.load_push_sessions().unwrap().remove(0);
        // The dirty entry was stored; the unmarked one was not walked.
        assert_eq!(saved.files[0].prefix_bytes, data.len() as u64);
        assert_eq!(saved.files[1].prefix_bytes, 0);
        drop(first);
        drop(receive);
        drop(seams);
    }
}

#[cfg(test)]
mod parallel_accept_tests {
    use super::*;
    use vot_sdk::object::{InMemoryObjectBuilder, Suite};

    fn object(data: &[u8]) -> ObjectId {
        let mut builder = InMemoryObjectBuilder::new(
            Suite::Blake3Bao64,
            Some(data.len() as u64),
            data.len() as u64,
        )
        .unwrap();
        builder.update(data).unwrap();
        builder.finish().unwrap().object_id().clone()
    }

    // Two threads accept the same range against one shared file, the shape
    // accept_batch runs internally. The in-flight duplicate must be absorbed
    // and replayed, never surfaced as an error: exactly one Accepted and one
    // Replay. This kills a mutant that drops the RangeInFlight retry (the
    // loser would error) or misclassifies the replay.
    #[test]
    fn concurrent_duplicate_range_accepts_once_and_replays_once() {
        let directory = tempfile::tempdir().unwrap();
        let data = vec![0x5a_u8; 64 * 1024];
        let object = object(&data);
        let proof = vot_proof_blake3::prove(&data, 0, data.len() as u64).unwrap();
        let destinations = Arc::new(
            crate::receiving::Destinations::open(
                directory.path(),
                vot_sdk_file::NasContract::Unqualified,
            )
            .unwrap(),
        );
        let native = destinations
            .directory(directory.path(), true)
            .unwrap()
            .create(
                &object,
                std::ffi::OsStr::new("obj"),
                CommitProfile::Balanced,
            )
            .unwrap();
        let mut native = StagedFile::new(
            native,
            directory.path().join("obj"),
            ObjectCoverage::new(&object),
            CommitProfile::Balanced,
            destinations,
        );
        native.reopen().unwrap();
        let files = vec![FileState {
            display_path: "obj".to_owned(),
            stored_components: "obj".to_owned(),
            object,
            native: Some(native),
            published: false,
            receipt: false,
            checkpointed: Mutex::new(None),
            first_range_at: None,
            rehash: false,
        }];
        let results: Vec<AcceptCore> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let files = &files;
                    let proof = &proof;
                    scope.spawn(move || {
                        accept_range(files, 0, proof.covered_offset, &proof.proof, &proof.data)
                            .unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(
            results.iter().filter(|core| core.accepted).count(),
            1,
            "exactly one range is accepted"
        );
        assert_eq!(
            results.iter().filter(|core| core.replay).count(),
            1,
            "the in-flight duplicate replays after the winner commits"
        );
        // A full-object range completes the file for both callers.
        assert!(results.iter().all(|core| core.complete));
    }

    #[test]
    fn persist_tracker_paces_checkpoints_behind_both_floors() {
        let start = Instant::now();
        let mut tracker = PersistTracker {
            bytes_since: 0,
            last_at: start,
        };
        // Neither floor: no checkpoint.
        assert!(!tracker.should_checkpoint_at(1024, start + Duration::from_secs(1)));
        // The time floor alone: no checkpoint.
        assert!(!tracker.should_checkpoint_at(0, start + PERSIST_INTERVAL));
        // The byte floor alone: no checkpoint.
        assert!(!tracker.should_checkpoint_at(PERSIST_BYTES, start + Duration::from_millis(1500)));
        // Both floors met (bytes crossed earlier): checkpoint and reset both.
        assert!(tracker.should_checkpoint_at(0, start + PERSIST_INTERVAL + Duration::from_secs(1)));
        assert_eq!(tracker.bytes_since, 0);
        // After a checkpoint both floors restart.
        assert!(!tracker.should_checkpoint_at(
            PERSIST_BYTES,
            start + PERSIST_INTERVAL + Duration::from_secs(1)
        ));
        assert!(
            tracker.should_checkpoint_at(0, start + 2 * PERSIST_INTERVAL + Duration::from_secs(1))
        );
        // The slow path: dirty work under the byte floor still checkpoints
        // behind MAX_PERSIST_INTERVAL, bounding the crash-loss window for
        // transfers slower than the byte floor.
        let mut slow = PersistTracker {
            bytes_since: 0,
            last_at: start,
        };
        // 100 MiB at 4 s: under both the byte floor and the slow floor.
        assert!(!slow.should_checkpoint_at(100 * 1024 * 1024, start + Duration::from_secs(4)));
        // 100 MiB at 5 s: the slow-path floor alone fires the checkpoint.
        assert!(slow.should_checkpoint_at(0, start + Duration::from_secs(5)));
        assert_eq!(slow.bytes_since, 0);
        // 0 bytes at any age: no dirty work means no checkpoint.
        assert!(!slow.should_checkpoint_at(0, start + Duration::from_secs(60)));
    }

    #[test]
    fn checkpoint_warn_pacer_logs_first_failure_then_paces() {
        let start = Instant::now();
        let pacer = CheckpointWarnPacer::new();
        // The first failure logs immediately.
        assert!(pacer.should_log_at(start));
        // Repeats inside the interval stay quiet, so a failing checkpoint
        // on a fast transfer no longer warns once per 256 MiB.
        assert!(!pacer.should_log_at(start + Duration::from_secs(1)));
        assert!(!pacer.should_log_at(start + CHECKPOINT_WARN_INTERVAL - Duration::from_millis(1)));
        // After the interval the next failure is visible again, so a
        // persistently failing checkpoint cannot go silent.
        assert!(pacer.should_log_at(start + CHECKPOINT_WARN_INTERVAL));
        assert!(!pacer.should_log_at(start + CHECKPOINT_WARN_INTERVAL + Duration::from_secs(1)));
    }
}
