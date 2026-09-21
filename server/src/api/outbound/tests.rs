use super::*;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use http_body_util::BodyExt as _;
use std::time::Duration;
use tower::ServiceExt as _;
use vot_sdk_file::PublishObservation;

#[test]
fn error_deduper_suppresses_unchanged_errors_and_fires_recovery_once() {
    let start = std::time::Instant::now();
    let mut dedupe = ErrorDeduper::new("test site");
    // First occurrence logs immediately.
    assert!(dedupe.observe("store locked", start));
    // An unchanged repeat inside the interval stays quiet.
    assert!(!dedupe.observe("store locked", start + Duration::from_secs(30)));
    // A changed error logs immediately.
    assert!(dedupe.observe("disk full", start + Duration::from_secs(31)));
    // The new error's own cadence suppresses its immediate repeat.
    assert!(!dedupe.observe("disk full", start + Duration::from_secs(40)));
    // After the interval the unchanged error is visible again.
    assert!(dedupe.observe(
        "disk full",
        start + Duration::from_secs(31) + WORKER_LOG_INTERVAL
    ));
    // Recovery is due exactly once, and only after an error.
    assert!(dedupe.recovered());
    assert!(!dedupe.recovered());
}

/// Audit finding 225: a download whose store write fails keeps its 500
/// response but now warns with the grant id and store error instead of
/// vanishing into the generic message.
#[tokio::test]
async fn record_download_warns_when_the_store_write_fails() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    app.store
        .with(|connection| connection.execute_batch("DROP TABLE outbound_grants"))
        .unwrap();
    let grant = crate::notify::tests::test_grant(vec![]);
    let (log, _guard) = crate::logging::captured(crate::logging::stdout_filter(None, false));
    let error = record_download(&app, &grant, &[0]).await.unwrap_err();
    assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    let text = std::fs::read_to_string(log.path()).unwrap();
    let warn = text
        .lines()
        .find(|line| line.contains("record download failed"))
        .expect("the failed store write warns");
    assert!(warn.contains("grant-id"), "{warn}");
}

#[test]
fn skip_notice_logs_first_occurrence_then_paces() {
    let start = std::time::Instant::now();
    let mut notice = SkipNotice::new();
    // The first skipped iteration logs at info.
    assert!(matches!(notice.due(start), SkipLevel::First));
    // Repeats inside the interval stay silent.
    assert!(matches!(
        notice.due(start + Duration::from_secs(1)),
        SkipLevel::Silent
    ));
    assert!(matches!(
        notice.due(start + Duration::from_secs(59)),
        SkipLevel::Silent
    ));
    // After the interval a debug reminder is due, then quiet again.
    assert!(matches!(
        notice.due(start + Duration::from_secs(60)),
        SkipLevel::Repeat
    ));
    assert!(matches!(
        notice.due(start + Duration::from_secs(61)),
        SkipLevel::Silent
    ));
}

/// Wraps the router so tests observe the streamed response the file
/// download admission redirect produces: the one same-origin 307 is
/// replayed with the same method, headers and peer against its lease
/// location, exactly what a real download client does.
fn router(app: std::sync::Arc<App>) -> RedirectFollowing {
    RedirectFollowing { app }
}

struct RedirectFollowing {
    app: std::sync::Arc<App>,
}

impl tower::Service<Request<Body>> for RedirectFollowing {
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response, std::convert::Infallible>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::convert::Infallible>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let app = self.app.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let headers = parts.headers.clone();
            let peer = parts
                .extensions
                .get::<ConnectInfo<std::net::SocketAddr>>()
                .map(|info| info.0);
            let mut response = crate::app::router(app.clone())
                .oneshot(Request::from_parts(parts, body))
                .await
                .unwrap();
            for _ in 0..3 {
                if response.status() != StatusCode::TEMPORARY_REDIRECT
                    && response.status() != StatusCode::PERMANENT_REDIRECT
                {
                    break;
                }
                let Some(location) = response
                    .headers()
                    .get(axum::http::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
                else {
                    break;
                };
                let mut replayed = Request::builder()
                    .method(axum::http::Method::GET)
                    .uri(&location);
                *replayed.headers_mut().unwrap() = headers.clone();
                if let Some(address) = peer {
                    replayed = replayed.extension(ConnectInfo(address));
                }
                let replayed = replayed.body(Body::empty()).unwrap();
                response = crate::app::router(app.clone())
                    .oneshot(replayed)
                    .await
                    .unwrap();
            }
            Ok(response)
        })
    }
}

fn admin_cookie(app: &App) -> String {
    let token = auth::issue_admin_token(
        &app.secret,
        &auth::AdminIdentity::local_admin(),
        &app.config.admin_token_tag,
    );
    format!("votport_admin={token}")
}

fn admin_headers(app: &App) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, admin_cookie(app).parse().unwrap());
    headers.insert("x-votport", "1".parse().unwrap());
    headers
}

/// Idempotent deletes: a repeat delete of an owned automation token
/// answers 200 again; only an unknown id 404s.
#[tokio::test]
async fn automation_token_deletes_are_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let auth = admin_headers(&app);
    app.store
        .insert_automation_token(AutomationToken {
            id: "tok-id".into(),
            token_hash: hash_token("a".repeat(32).as_str()),
            tenant: String::new(),
            label: "jobs".into(),
            directory: None,
            permissions: vec!["jobs:read".into()],
            created_by: String::new(),
            created_at: now_unix(),
            expires_at: now_unix() + 3600,
            revoked_at: None,
            last_used_at: None,
        })
        .unwrap();
    let first = delete_automation_token(
        State(app.clone()),
        AxumPath("tok-id".to_owned()),
        auth.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first.0, json!({"ok": true}));
    assert_eq!(
        delete_automation_token(
            State(app.clone()),
            AxumPath("tok-id".to_owned()),
            auth.clone()
        )
        .await
        .unwrap()
        .0,
        json!({"ok": true})
    );
    assert_eq!(
        delete_automation_token(State(app.clone()), AxumPath("unknown".to_owned()), auth)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
}

/// Idempotent deletes: a repeat delete of an owned admin outbound grant
/// answers 200 again; only an unknown id 404s.
#[tokio::test]
async fn outbound_grant_deletes_are_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let auth = admin_headers(&app);
    app.store
        .insert_outbound_grant(crate::notify::tests::test_grant(vec![]))
        .unwrap();
    let first = delete_outbound_grant(
        State(app.clone()),
        AxumPath("grant-id".to_owned()),
        auth.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first.0, json!({"ok": true}));
    assert_eq!(
        delete_outbound_grant(
            State(app.clone()),
            AxumPath("grant-id".to_owned()),
            auth.clone(),
        )
        .await
        .unwrap()
        .0,
        json!({"ok": true})
    );
    assert_eq!(
        delete_outbound_grant(State(app.clone()), AxumPath("unknown".to_owned()), auth)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
}

fn named_admin_cookie(app: &App, tenant: &str) -> String {
    let identity = auth::AdminIdentity {
        subject: "local".to_owned(),
        tenant: tenant.to_owned(),
        role: "admin".to_owned(),
        grants: vec![auth::TenantGrant {
            incarnation: None,
            tenant: tenant.to_owned(),
            role: "admin".to_owned(),
        }],
        credential_version: 1,
    };
    let token = auth::issue_admin_token(&app.secret, &identity, &app.config.admin_token_tag);
    format!("votport_admin={token}")
}

/// One process-wide stall, so armed tests serialize on `SERIAL` and the
/// guard disarms on drop; concurrent tests must never see the stall.
static LIBRARY_MUTATION_STALL_SERIAL: Mutex<()> = Mutex::new(());

struct ArmedLibraryMutationStall {
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl Drop for ArmedLibraryMutationStall {
    fn drop(&mut self) {
        LIBRARY_MUTATION_STALL
            .lock()
            .expect("library mutation stall poisoned")
            .take();
    }
}

fn arm_library_mutation_stall(
    root: &Path,
) -> (
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
    ArmedLibraryMutationStall,
) {
    let _serial = LIBRARY_MUTATION_STALL_SERIAL
        .lock()
        .expect("library mutation stall serializer poisoned");
    let (entered_rx, release_tx) = rearm_library_mutation_stall(root);
    (
        entered_rx,
        release_tx,
        ArmedLibraryMutationStall { _serial },
    )
}

/// Arms another stall while the caller already holds the serializer
/// guard, e.g. to pin the validation-to-insert window separately from
/// the walk-start stall.
fn rearm_library_mutation_stall(
    root: &Path,
) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    assert!(LIBRARY_MUTATION_STALL
        .lock()
        .expect("library mutation stall poisoned")
        .replace(LibraryMutationStall {
            root: root.to_owned(),
            entered: entered_tx,
            release: release_rx,
        })
        .is_none());
    (entered_rx, release_tx)
}

#[test]
fn outbound_operation_refusal_is_retryable_during_tenant_purge() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let operation = app.sessions.try_begin_outbound("acme").unwrap();
    let _pin = app.sessions.try_pin_tenant("acme").unwrap();
    let error = match begin_outbound_operation(&app, "acme") {
        Err(error) => error,
        Ok(_) => panic!("tenant purge did not block a second outbound operation"),
    };
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.retry_after_seconds, Some(1));
    assert_eq!(error.code, "unavailable");
    drop(operation);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_library_mutation_keeps_admission_until_worker_finishes() {
    use std::time::{Duration, Instant};

    for deleting in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_tenant(crate::store::tests::test_tenant("acme"))
            .unwrap();
        let root = library_root(&app, "acme");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("held.bin"), b"library fixture").unwrap();
        let cookie = named_admin_cookie(&app, "acme");

        let (entered, release, _stall) = arm_library_mutation_stall(&root);
        let watchdog = if deleting {
            let (cancel_watchdog, watchdog_wait) = std::sync::mpsc::channel();
            let watchdog_release = release.clone();
            Some(std::thread::spawn(move || {
                if watchdog_wait.recv_timeout(Duration::from_secs(5)).is_err() {
                    let _ = watchdog_release.send(());
                }
                cancel_watchdog
            }))
        } else {
            None
        };
        let request = if deleting {
            Request::delete("/api/admin/outbound-files?path=held.bin")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap()
        } else {
            Request::post("/api/admin/outbound-grants/preparations")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"paths":["held.bin"],"expires_days":1}"#))
                .unwrap()
        };
        let serving = tokio::spawn(router(app.clone()).oneshot(request));

        if deleting {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if entered.try_recv().is_ok() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("library mutation worker did not enter its critical section");
            let heartbeat_started = Instant::now();
            let heartbeat = tokio::spawn(async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Instant::now()
            });
            let heartbeat_at = heartbeat.await.unwrap();
            assert!(
                !serving.is_finished(),
                "mutation must still be held by the barrier"
            );
            assert!(
                heartbeat_at.duration_since(heartbeat_started) < Duration::from_secs(1),
                "the runtime stalled in the library mutation critical section"
            );
            serving.abort();
            assert!(matches!(
                serving.await,
                Err(error) if error.is_cancelled()
            ));
        } else {
            // The grant request answers 202 while its detached preparation
            // job waits in the mutation critical section: the page gets its
            // instant acknowledgement, and cancelling the request would not
            // cancel the grant work.
            let accepted = tokio::time::timeout(Duration::from_secs(3), serving)
                .await
                .expect("grant creation never returned its 202")
                .unwrap()
                .unwrap();
            assert_eq!(accepted.status(), StatusCode::ACCEPTED);
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if entered.try_recv().is_ok() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("grant preparation did not enter its critical section");
            let heartbeat_started = Instant::now();
            let heartbeat = tokio::spawn(async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Instant::now()
            });
            let heartbeat_at = heartbeat.await.unwrap();
            assert!(
                heartbeat_at.duration_since(heartbeat_started) < Duration::from_secs(1),
                "the runtime stalled in the library mutation critical section"
            );
        }
        assert_eq!(app.sessions.active_outbound_for_tenant("acme"), 1);

        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.sessions.active_outbound_for_tenant("acme") != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled mutation did not release admission after worker completion");
        if let Some(watchdog) = watchdog {
            let cancel_watchdog = watchdog.join().unwrap();
            let _ = cancel_watchdog.send(());
        }
        let grants = app.store.outbound_grants("acme").unwrap();
        assert_eq!(grants.len(), usize::from(!deleting));
        assert_eq!(root.join("held.bin").exists(), !deleting);
        let audit = app.store.audit_recent(Some("acme"), 0, 10).unwrap();
        let event = if deleting {
            "outbound_file_deleted"
        } else {
            "outbound_grant_created"
        };
        assert_eq!(audit.iter().filter(|row| row.event == event).count(), 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_library_validation_does_not_block_outbound_deletion() {
    use std::time::Duration;

    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    app.store
        .insert_tenant(crate::store::tests::test_tenant("acme"))
        .unwrap();
    let root = library_root(&app, "acme");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("held.bin"), b"library fixture").unwrap();
    let cookie = named_admin_cookie(&app, "acme");

    let (entered, release, _stall) = arm_library_mutation_stall(&root);
    // Creation is answered 202 immediately; the validation walk runs in the
    // detached preparation job.
    let accepted = tokio::time::timeout(
        Duration::from_secs(3),
        router(app.clone()).oneshot(
            Request::post("/api/admin/outbound-grants/preparations")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"paths":["held.bin"],"expires_days":1}"#))
                .unwrap(),
        ),
    )
    .await
    .expect("grant creation never returned its 202")
    .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let preparation_id = body(accepted).await["preparation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if entered.try_recv().is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("grant preparation never reached its validation walk");

    // The stalled walk runs without the mutation lock, so the delete must
    // finish while the walk is still stuck instead of queueing behind it.
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        router(app.clone()).oneshot(
            Request::delete("/api/admin/outbound-files?path=held.bin")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("stalled library validation blocked outbound deletion")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!root.join("held.bin").exists());

    release.send(()).unwrap();
    let snapshot = settled_preparation(&app, &cookie, &preparation_id).await;
    assert_eq!(snapshot["status"], "failed");
    assert_eq!(snapshot["error_status"], 404);
    assert!(app.store.outbound_grants("acme").unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn library_deletion_and_validated_insert_are_strictly_ordered() {
    use std::time::Duration;

    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    app.store
        .insert_tenant(crate::store::tests::test_tenant("acme"))
        .unwrap();
    let root = library_root(&app, "acme");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("held.bin"), b"library fixture").unwrap();
    let cookie = named_admin_cookie(&app, "acme");
    let create_request = || {
        Request::post("/api/admin/outbound-grants/preparations")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"paths":["held.bin"],"expires_days":1}"#))
            .unwrap()
    };
    let delete_request = || {
        Request::delete("/api/admin/outbound-files?path=held.bin")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap()
    };

    // Delete first: pin a creation inside the validation-to-insert
    // window (validated, not yet inserted), then run the delete through
    // that window. The delete wins, so the insert must revalidate under
    // the lock and refuse instead of landing a grant for a source that
    // no longer exists.
    let (validated, validated_release, _stall) =
        arm_library_mutation_stall(&root.join(".validated"));
    // The creation request returns 202 while its preparation job walks the
    // validation-to-insert window.
    let accepted = tokio::time::timeout(
        Duration::from_secs(3),
        router(app.clone()).oneshot(create_request()),
    )
    .await
    .expect("grant creation never returned its 202")
    .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let preparation_id = body(accepted).await["preparation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if validated.try_recv().is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("grant creation never reached the validation-to-insert window");
    let (entered, release) = rearm_library_mutation_stall(&root);
    let delete = tokio::spawn(router(app.clone()).oneshot(delete_request()));
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if entered.try_recv().is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("deletion never entered its critical section");
    validated_release.send(()).unwrap();
    release.send(()).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), delete)
        .await
        .expect("deletion never finished after its stall was released")
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot = settled_preparation(&app, &cookie, &preparation_id).await;
    assert_eq!(snapshot["status"], "failed");
    assert_eq!(snapshot["error_status"], 404);
    assert!(app.store.outbound_grants("acme").unwrap().is_empty());
    assert!(!root.join("held.bin").exists());
    let audit = app.store.audit_recent(Some("acme"), 0, 10).unwrap();
    assert_eq!(
        audit
            .iter()
            .filter(|row| row.event == "outbound_grant_created")
            .count(),
        0
    );

    // Insert first: with the grant landed, the delete must observe the
    // active grant and refuse instead of removing the validated source.
    std::fs::write(root.join("held.bin"), b"library fixture").unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        settled_grant_response(app.clone(), &cookie, create_request()),
    )
    .await
    .expect("grant creation stalled outside the mutation lock");
    assert_eq!(response.status(), StatusCode::OK);
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        router(app.clone()).oneshot(delete_request()),
    )
    .await
    .expect("deletion stalled")
    .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(app.store.outbound_grants("acme").unwrap().len(), 1);
    assert!(root.join("held.bin").exists());
}

async fn body(response: Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

/// Polls a preparation endpoint until its job reaches a terminal state and
/// returns the final snapshot.
async fn settled_preparation(
    app: &std::sync::Arc<App>,
    cookie: &str,
    id: &str,
) -> serde_json::Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "grant preparation {id} never settled"
        );
        let poll = router(app.clone())
            .oneshot(
                Request::get(format!("/api/admin/outbound-grants/preparations/{id}"))
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(poll.status(), StatusCode::OK);
        let snapshot = body(poll).await;
        if snapshot["status"] != "preparing" {
            return snapshot;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// POSTs a grant creation request and settles any 202 preparation: the
/// handler answers immediately and hashes in a detached job, so this polls
/// the progress endpoint to a terminal state and rebuilds the response the
/// synchronous path used to return (200 with `grant`/`url`, or the job's
/// error status with `{"error": ...}`). Non-202 replies pass through.
async fn settled_grant_response(
    app: std::sync::Arc<App>,
    cookie: &str,
    request: Request<Body>,
) -> Response {
    let response = router(app.clone()).oneshot(request).await.unwrap();
    if response.status() != StatusCode::ACCEPTED {
        return response;
    }
    let accepted: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let id = accepted["preparation_id"].as_str().unwrap().to_owned();
    let snapshot = settled_preparation(&app, cookie, &id).await;
    match snapshot["status"].as_str() {
        Some("complete") => {
            let payload = serde_json::json!({
                "grant": snapshot["grant"],
                "url": snapshot["url"],
                "operation_id": serde_json::Value::Null,
            });
            Response::builder()
                .status(StatusCode::OK)
                .header("cache-control", "no-store")
                .body(Body::from(payload.to_string()))
                .unwrap()
        }
        Some("failed") => {
            let status =
                StatusCode::from_u16(snapshot["error_status"].as_u64().unwrap_or(500) as u16)
                    .unwrap();
            Response::builder()
                .status(status)
                .header("cache-control", "no-store")
                .body(Body::from(
                    serde_json::json!({"error": snapshot["error"]}).to_string(),
                ))
                .unwrap()
        }
        _ => unreachable!("settled_preparation only returns terminal states"),
    }
}

fn branding_grant(token: &str, password_hash: Option<String>) -> OutboundGrant {
    OutboundGrant {
        id: format!("grant-{token}"),
        token_hash: hash_token(token),
        password_hash,
        tenant: String::new(),
        link_id: String::new(),
        upload_id: String::new(),
        package_root: String::new(),
        name: "file.bin".to_owned(),
        suite: "blake3".to_owned(),
        root: String::new(),
        file_index: 0,
        bytes: 3,
        label: "delivery".to_owned(),
        created_at: 1,
        expires_at: now_unix() + 600,
        revoked_at: None,
        downloads: 0,
        max_downloads: None,

        notifications: None,
        first_download_at: None,
        last_download_at: None,
        files: Vec::new(),
    }
}

#[tokio::test]
async fn receiving_source_check_retains_its_operation_when_cancelled() {
    use std::time::Duration;
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    app.store
        .insert_tenant(crate::store::tests::test_tenant("acme"))
        .unwrap();
    let mut grant = branding_grant(&"a".repeat(32), None);
    grant.tenant = "acme".into();
    grant.files.push(OutboundGrantFile {
        source: "received:missing.bin".into(),
        name: "file.bin".into(),
        suite: "blake3".into(),
        root: hex::encode([7; 32]),
        bytes: 3,
        receipt_b64: String::new(),
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
    });
    let destinations = app.receiving_destinations().unwrap();
    let grant = Arc::new(grant);
    for oversized in [None, Some(false), Some(true)] {
        let pause = crate::receiving::CheckPause::new(&destinations, 1);
        let worker = app.clone();
        let grant = Arc::clone(&grant);
        let serving = tokio::spawn(async move {
            if let Some(oversized) = oversized {
                let chunk = BatchChunk {
                    start: 0,
                    end: 1,
                    bytes: 3,
                    oversized,
                };
                await_batch_chunk(start_batch_chunk(worker, grant, chunk, None)?)
                    .await
                    .map(|_| ())
            } else {
                let operation = begin_outbound_operation_owned(&worker, "acme")?;
                source_info_async(&worker, grant, 0, None, operation, None)
                    .await
                    .map(|_| ())
            }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while pause.entered() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(app.receiving.try_lock().is_ok());
        assert_eq!(app.receiving_permits.available_permits(), 8);
        assert_eq!(app.sessions.active_outbound_for_tenant("acme"), 1);
        serving.abort();
        assert!(matches!(serving.await, Err(error) if error.is_cancelled()));
        assert_eq!(app.sessions.active_outbound_for_tenant("acme"), 1);
        pause.release();
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.sessions.active_outbound_for_tenant("acme") != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn metadata_branding_and_logo_hide_behind_the_password() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    app.store
        .set_branding(&crate::store::Branding {
            tenant: String::new(),
            name: "Acme Corp".to_owned(),
            color: "#12ab99".to_owned(),
            logo_ext: "png".to_owned(),
            updated_at: 0,
            ..Default::default()
        })
        .unwrap();
    let logo = crate::paths::branding_logo_path(&app.config.data_dir, "", "png");
    std::fs::create_dir_all(logo.parent().unwrap()).unwrap();
    std::fs::write(&logo, b"\x89PNG\r\n\x1a\npixels").unwrap();
    let gated = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let open = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    app.store
        .insert_outbound_grant(branding_grant(
            gated,
            Some(auth::hash_password("pw").unwrap()),
        ))
        .unwrap();
    app.store
        .insert_outbound_grant(branding_grant(open, None))
        .unwrap();

    // Pre-password metadata reveals nothing, branding included.
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{gated}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body(response).await;
    assert_eq!(json["has_password"], true);
    assert_eq!(json["authorized"], false);
    assert!(json.get("branding").is_none(), "{json}");
    // ... so the logo hides with it.
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{gated}/logo"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // The password cookie unlocks branding and the logo together.
    let response = router(app.clone())
        .oneshot(
            Request::post(format!("/api/s/{gated}/verify"))
                .header("content-type", "application/json")
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::from(r#"{"password":"pw"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{gated}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body(response).await;
    assert_eq!(json["authorized"], true);
    assert_eq!(json["branding"]["name"], "Acme Corp");
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{gated}/logo"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Without a password, metadata (plain and paged) carries branding
    // and the logo streams.
    for uri in [
        format!("/api/s/{open}"),
        format!("/api/s/{open}?offset=0&limit=10"),
    ] {
        let response = router(app.clone())
            .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body(response).await;
        assert_eq!(json["branding"]["name"], "Acme Corp", "{uri}");
        assert_eq!(json["branding"]["color"], "#12ab99", "{uri}");
        assert_eq!(json["branding"]["has_logo"], true, "{uri}");
    }
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{open}/logo"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "image/png"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

fn zip_entries(bytes: &[u8]) -> std::collections::HashMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut entries = std::collections::HashMap::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).unwrap();
        let name = entry.name().to_owned();
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut contents).unwrap();
        entries.insert(name, contents);
    }
    entries
}

fn object_id(bytes: &[u8]) -> ObjectId {
    let mut builder = InMemoryObjectBuilder::new(
        Suite::try_from(1).unwrap(),
        Some(bytes.len() as u64),
        bytes.len() as u64,
    )
    .unwrap();
    builder.update(bytes).unwrap();
    builder.finish().unwrap().object_id().clone()
}

#[test]
fn library_preparation_preserves_identity_and_enforces_source_bounds() {
    let limit = vot_sdk::object::MAX_OBJECT_LENGTH;
    for (length, expected, max, valid) in [
        (0, None, 0, true),
        (1, None, 0, false),
        (1, None, 1, true),
        (1, Some(0), 1, false),
        (1, Some(2), 2, false),
        (1, Some(1), 1, true),
        (limit, Some(limit), limit, true),
        (0, None, limit + 1, false),
    ] {
        assert_eq!(valid_preparation_length(length, expected, max), valid);
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.bin");
    for length in [0, 31, vot_sdk::object::PROOF_LEAF_SIZE as usize + 17] {
        let bytes = vec![7; length];
        std::fs::write(&path, &bytes).unwrap();
        let prepared =
            prepare_library_file(&path, Suite::Blake3Bao64, None, length as u64).unwrap();
        assert_eq!(prepared.object_id(), &object_id(&bytes));
        assert!(prepare_library_file(
            &path,
            Suite::Blake3Bao64,
            None,
            vot_sdk::object::MAX_OBJECT_LENGTH + 1
        )
        .is_err());
        assert!(prepare_library_file(
            &path,
            Suite::Blake3Bao64,
            Some(length as u64 + 1),
            length as u64 + 1
        )
        .is_err());
        if length != 0 {
            assert!(
                prepare_library_file(&path, Suite::Blake3Bao64, None, length as u64 - 1).is_err()
            );
        }
    }
}

#[test]
fn proof_catalog_round_trip_rejects_tampered_header() {
    let directory = tempfile::tempdir().unwrap();
    let bytes = vec![7u8; 32 * 1024];
    let mut builder = InMemoryObjectBuilder::new(
        Suite::try_from(1).unwrap(),
        Some(bytes.len() as u64),
        bytes.len() as u64,
    )
    .unwrap();
    builder.update(&bytes).unwrap();
    let prepared = builder.finish().unwrap();
    let path = ensure_catalog_from_prepared(directory.path(), &prepared).unwrap();
    let encoded = std::fs::read(&path).unwrap();
    assert!(proof::validate_catalog(&encoded, prepared.object_id()).is_ok());
    let mut tampered = encoded;
    tampered[24] ^= 1;
    std::fs::write(&path, tampered).unwrap();
    assert!(ensure_catalog_from_prepared(directory.path(), &prepared).is_ok());
    let repaired = std::fs::read(path).unwrap();
    assert!(proof::validate_catalog(&repaired, prepared.object_id()).is_ok());
}

#[test]
fn concurrent_cold_catalog_requests_share_one_build() {
    let directory = tempfile::tempdir().unwrap();
    let bytes = vec![9u8; 64 * 1024];
    let source = directory.path().join("source.bin");
    std::fs::write(&source, &bytes).unwrap();
    let expected = object_id(&bytes);
    let root = directory.path().join("proofs");
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| ensure_catalog(&root, &source, &expected).unwrap()))
            .collect();
        for worker in workers {
            let path = worker.join().unwrap();
            let mut file = std::fs::File::open(&path).unwrap();
            assert!(catalog_header(&mut file, &expected).is_ok());
        }
    });
    // Other tests share the static map; only this object's entry matters.
    assert!(!CATALOG_BUILDS
        .lock()
        .unwrap()
        .contains_key(&catalog_path(&root, &expected)));
}

#[tokio::test]
async fn revocation_stops_a_batch_stream_mid_body() {
    let (_directory, mut app, cookie, _first) = fixture().await;
    Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 64 * 1024 * 1024;
    let count = 8usize;
    let part_bytes = 512 * 1024;
    let total = count * part_bytes;
    for index in 0..count {
        let path = format!("cap/part-{index}.bin");
        let response = router(app.clone())
            .oneshot(
                Request::post(format!("/api/admin/outbound-files?path={path}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(vec![b'a' + index as u8; part_bytes]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let paths = (0..count)
        .map(|index| format!("\"cap/part-{index}.bin\""))
        .collect::<Vec<_>>()
        .join(",");
    let created = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                "{{\"paths\":[{paths}],\"max_downloads\":1}}"
            )))
            .unwrap(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let created = body(created).await;
    let token = created["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let id = created["grant"]["id"].as_str().unwrap().to_owned();
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/batch"))
                .extension(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    12,
                ))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let first = stream.next().await.unwrap().unwrap();
    assert!(
        first.len() < total,
        "the batch must have frames left to deliver"
    );
    // Paused: the recipient holds the stream open without polling while
    // the grant is revoked through the admin handler.
    let revoke = Request::delete(format!("/api/admin/outbound-grants/{id}"))
        .header("cookie", &cookie)
        .header("x-votport", "1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router(app.clone()).oneshot(revoke).await.unwrap().status(),
        StatusCode::OK
    );
    // Resuming must stop at the next frame, not deliver the rest of the
    // body the old admission-only checks let through.
    let mut delivered = first.len();
    while let Some(item) = stream.next().await {
        delivered += item.map(|bytes| bytes.len()).unwrap_or(0);
    }
    assert!(
        delivered < total,
        "a revoked stream must not deliver the whole body ({delivered} of {total})"
    );
    // The grant's last live stream ended, so its cancellation token is
    // gone from the map instead of leaking per streamed grant.
    assert!(app.outbound_stream_cancels.lock().unwrap().is_empty());
}

#[tokio::test]
async fn interrupted_batch_leaves_unsent_files_downloadable() {
    let (_directory, app, cookie, _first) = fixture().await;
    for (path, bytes) in [
        ("cap/a.bin", b"file a".as_slice()),
        ("cap/b.bin", b"file b"),
    ] {
        let response = router(app.clone())
            .oneshot(
                Request::post(format!("/api/admin/outbound-files?path={path}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(bytes.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let created = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"paths":["cap/a.bin","cap/b.bin"],"max_downloads":1}"#,
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let created = body(created).await;
    let token = created["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let peer = |port| ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], port)));

    let head_batch = router(app.clone())
        .oneshot(
            Request::head(format!("/api/s/{token}/batch"))
                .extension(peer(10))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head_batch.status(), StatusCode::OK);
    drop(head_batch);
    assert!(!app.config.data_dir.join("outbound.stage").exists());
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&token))
        .unwrap()
        .unwrap();
    assert!(grant.files.iter().all(|file| file.downloads == 0));

    let head_bundle = router(app.clone())
        .oneshot(
            Request::head(format!("/api/s/{token}/bundle"))
                .extension(peer(11))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head_bundle.status(), StatusCode::OK);
    drop(head_bundle);
    assert!(!app.config.data_dir.join("outbound.stage").exists());
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&token))
        .unwrap()
        .unwrap();
    assert!(grant.files.iter().all(|file| file.downloads == 0));

    // A batch response dropped before any body frame is polled records
    // nothing: the old up-front recording burned every file's single
    // download here.
    let aborted = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/batch"))
                .extension(peer(11))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(aborted.status(), StatusCode::OK);
    drop(aborted);
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&token))
        .unwrap()
        .unwrap();
    assert!(grant.files.iter().all(|file| file.downloads == 0));

    // Full consumption records each file exactly once.
    let batch = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/batch"))
                .extension(peer(12))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(batch.status(), StatusCode::OK);
    let expected_length = batch.headers()[header::CONTENT_LENGTH]
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mut stream = batch.into_body().into_data_stream();
    let mut bytes = Vec::with_capacity(expected_length);
    while bytes.len() < expected_length {
        bytes.extend_from_slice(&stream.next().await.unwrap().unwrap());
    }
    drop(stream);
    assert_eq!(bytes.len(), expected_length);
    assert_eq!(bytes, b"file afile b");
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&token))
        .unwrap()
        .unwrap();
    assert!(grant.files.iter().all(|file| file.downloads == 1));

    // The cap is now spent: another batch is refused before any bytes.
    let refused = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/batch"))
                .extension(peer(13))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::NOT_FOUND);

    for path in ["empty/a.bin", "empty/b.bin"] {
        let response = router(app.clone())
            .oneshot(
                Request::post(format!("/api/admin/outbound-files?path={path}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let empty_created = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"paths":["empty/a.bin","empty/b.bin"],"max_downloads":1}"#,
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(empty_created.status(), StatusCode::OK);
    let empty_token = body(empty_created).await["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let empty_batch = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{empty_token}/batch"))
                .extension(peer(14))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(empty_batch.status(), StatusCode::OK);
    assert_eq!(empty_batch.headers()[header::CONTENT_LENGTH], "0");
    drop(empty_batch);
    let empty_grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&empty_token))
        .unwrap()
        .unwrap();
    assert!(empty_grant.files.iter().all(|file| file.downloads == 1));
}

#[tokio::test]
async fn zero_byte_batch_validates_sources_before_counting() {
    let (_directory, app, _cookie, _expected) = fixture().await;
    let empty = object_id(&[]);
    let make_grant = |id: &str, token: &str, source: &str| {
        let mut grant = crate::store::tests::test_outbound_grant(id, "", 0);
        grant.token_hash = hash_token(token);
        grant.expires_at = now_unix() + 600;
        grant.max_downloads = Some(1);
        grant.name = "empty.bin".to_owned();
        grant.suite = "blake3".to_owned();
        grant.root = hex::encode(empty.root);
        grant.bytes = 0;
        grant.files = vec![OutboundGrantFile {
            source: source.to_owned(),
            name: "empty.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: hex::encode(empty.root),
            bytes: 0,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }];
        grant
    };
    let missing_token = "a".repeat(32);
    let missing = make_grant("missing-zero", &missing_token, "missing-zero.bin");
    app.store.insert_outbound_grant(missing).unwrap();
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{missing_token}/batch"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        app.store
            .outbound_grant_by_token_hash(&hash_token(&missing_token))
            .unwrap()
            .unwrap()
            .files[0]
            .downloads,
        0
    );

    let tampered_path = app.config.outbound_dir.join("tampered-zero.bin");
    std::fs::write(&tampered_path, b"x").unwrap();
    let tampered_token = "b".repeat(32);
    let tampered = make_grant("tampered-zero", &tampered_token, "tampered-zero.bin");
    app.store.insert_outbound_grant(tampered).unwrap();
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{tampered_token}/batch"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        app.store
            .outbound_grant_by_token_hash(&hash_token(&tampered_token))
            .unwrap()
            .unwrap()
            .files[0]
            .downloads,
        0
    );
}

#[tokio::test]
async fn batch_integrity_failure_reports_the_corrupt_file() {
    let (_directory, app, cookie, _expected) = fixture().await;
    for (path, bytes) in [
        ("batch/first.bin", b"first".as_slice()),
        ("batch/second.bin", b"second".as_slice()),
    ] {
        let response = router(app.clone())
            .oneshot(
                Request::post(format!("/api/admin/outbound-files?path={path}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(bytes.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let created = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"paths":["batch/first.bin","batch/second.bin"]}"#,
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let created = body(created).await;
    let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
    let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
    let corrupt_path = app.config.outbound_dir.join("batch/second.bin");
    std::fs::write(&corrupt_path, b"tampered").unwrap();
    let failures_before = OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed);
    let audits_before = app.store.audit_count().unwrap();
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/batch"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed) > failures_before,
        "integrity metric did not increment"
    );
    assert_eq!(app.store.audit_count().unwrap(), audits_before + 1);
    let audit = app
        .store
        .audit_recent(Some(""), 0, 100)
        .unwrap()
        .into_iter()
        .find(|row| row.event == "outbound_integrity_failure" && row.subject == grant_id)
        .expect("integrity audit row");
    assert_eq!(audit.detail["file_index"], 1);
    assert_eq!(audit.detail["component"], "batch");
    assert_eq!(
        audit.detail["path"],
        corrupt_path.to_string_lossy().as_ref()
    );
}

#[tokio::test]
async fn corrupt_received_receipt_reports_file_context() {
    let (_directory, app, cookie, _expected) = fixture().await;
    let created = body(
        settled_grant_response(
            app.clone(),
            &cookie,
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7,"max_downloads":1}"#,
                    ))
                .unwrap(),
            )
            .await,
    )
    .await;
    let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
    let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
    let source_path = app.config.receive_dir.join("received.bin");
    std::fs::write(receipt_path(&source_path), b"invalid receipt").unwrap();
    let failures_before = OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed);
    let audits_before = app.store.audit_count().unwrap();
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/files/0"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed) > failures_before,
        "integrity metric did not increment"
    );
    assert_eq!(app.store.audit_count().unwrap(), audits_before + 1);
    let audit = app
        .store
        .audit_recent(Some(""), 0, 100)
        .unwrap()
        .into_iter()
        .find(|row| row.event == "outbound_integrity_failure" && row.subject == grant_id)
        .expect("integrity audit row");
    assert_eq!(audit.detail["file_index"], 0);
    assert_eq!(audit.detail["component"], "file");
    assert_eq!(audit.detail["path"], source_path.to_string_lossy().as_ref());
    assert_eq!(audit.detail["error"], "receipt verification failed");
}

#[tokio::test]
async fn truncated_cached_catalog_source_reports_integrity_failure() {
    let (_directory, app, cookie, expected) = fixture().await;
    let created = body(
        settled_grant_response(
            app.clone(),
            &cookie,
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7,"max_downloads":1}"#,
                    ))
                .unwrap(),
            )
            .await,
    )
    .await;
    let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
    let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
    let source_path = app.config.receive_dir.join("received.bin");
    let expected_object = object_id(&expected);
    let catalog = ensure_catalog(
        &app.config.data_dir.join("outbound.proofs"),
        &source_path,
        &expected_object,
    )
    .unwrap();
    assert!(catalog.is_file());
    std::fs::write(&source_path, &expected[..expected.len() - 1]).unwrap();
    let failures_before = OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed);
    let audits_before = app.store.audit_count().unwrap();
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/files/0"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed) > failures_before,
        "integrity metric did not increment"
    );
    assert_eq!(app.store.audit_count().unwrap(), audits_before + 1);
    let audit = app
        .store
        .audit_recent(Some(""), 0, 100)
        .unwrap()
        .into_iter()
        .find(|row| row.event == "outbound_integrity_failure" && row.subject == grant_id)
        .expect("integrity audit row");
    assert_eq!(audit.detail["file_index"], 0);
    assert_eq!(audit.detail["component"], "file");
    assert_eq!(audit.detail["path"], source_path.to_string_lossy().as_ref());
    assert_eq!(audit.detail["error"], "verified outbound proof truncated");
}

#[tokio::test]
async fn an_interrupted_file_download_records_nothing_until_completion() {
    // One recorded download must mean one delivered download (audit
    // finding 490): admission and mid-stream drops burn no quota, and
    // only a whole-object response that finished counts once.
    let (_directory, app, _cookie, _expected) = fixture().await;
    let contents = vec![0xa5u8; 9 * 1024 * 1024];
    std::fs::write(app.config.outbound_dir.join("large.bin"), &contents).unwrap();
    let object = object_id(&contents);
    let token = "d".repeat(32);
    let mut grant = crate::store::tests::test_outbound_grant("file-once", "", 0);
    grant.token_hash = hash_token(&token);
    grant.expires_at = now_unix() + 600;
    grant.max_downloads = Some(1);
    grant.bytes = contents.len() as u64;
    grant.files = vec![OutboundGrantFile {
        source: "large.bin".to_owned(),
        name: "large.bin".to_owned(),
        suite: "blake3".to_owned(),
        root: hex::encode(object.root),
        bytes: contents.len() as u64,
        receipt_b64: String::new(),
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
    }];
    app.store.insert_outbound_grant(grant).unwrap();

    // Admission redirects and records nothing.
    let admission = crate::app::router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admission.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = admission.headers()[header::LOCATION].to_str().unwrap();
    let lease = location
        .strip_prefix(&format!("/api/s/{token}/file?download_lease="))
        .unwrap_or_else(|| panic!("unexpected redirect location {location}"))
        .to_owned();
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&token))
        .unwrap()
        .unwrap();
    assert_eq!(grant.files[0].downloads, 0);

    // The final URL streams frame by frame; dropping after the first
    // frame leaves the download unrecorded and the quota unspent.
    let first_url = format!("/api/s/{token}/file?download_lease={lease}");
    let aborted = router(app.clone())
        .oneshot(
            Request::get(&first_url)
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(aborted.status(), StatusCode::OK);
    let mut stream = aborted.into_body().into_data_stream();
    let frame = stream.next().await.unwrap().unwrap();
    assert!(!frame.is_empty());
    drop(stream);
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&token))
        .unwrap()
        .unwrap();
    assert_eq!(grant.files[0].downloads, 0);

    // A fresh request is still admitted, and finishing the delivery
    // records the download exactly once.
    let completed = router(app.clone())
        .oneshot(
            Request::get(&first_url)
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let body = completed.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.len(), contents.len());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let downloads = app
                .store
                .outbound_grant_by_token_hash(&hash_token(&token))
                .unwrap()
                .unwrap()
                .files[0]
                .downloads;
            if downloads == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the completed download was not recorded");

    // The single download is spent, so a tokenless retry is refused.
    let exhausted = crate::app::router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exhausted.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn batch_defers_trailing_empty_file_until_its_chunk_is_validated() {
    let (_directory, app, _cookie, expected) = fixture().await;
    let expected_object = object_id(&expected);
    let empty_object = object_id(&[]);
    std::fs::write(app.config.outbound_dir.join("source.bin"), &expected).unwrap();
    std::fs::write(app.config.outbound_dir.join("trailing-empty.bin"), b"x").unwrap();
    let token = "c".repeat(32);
    let mut grant = crate::store::tests::test_outbound_grant("mixed-empty", "", 0);
    grant.token_hash = hash_token(&token);
    grant.expires_at = now_unix() + 600;
    grant.max_downloads = Some(1);
    grant.bytes = expected.len() as u64;
    grant.files = (0..64)
        .map(|index| OutboundGrantFile {
            source: "source.bin".to_owned(),
            name: format!("file-{index}.bin"),
            suite: "blake3".to_owned(),
            root: hex::encode(expected_object.root),
            bytes: expected.len() as u64,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        })
        .chain(std::iter::once(OutboundGrantFile {
            source: "trailing-empty.bin".to_owned(),
            name: "trailing-empty.bin".to_owned(),
            suite: "blake3".to_owned(),
            root: hex::encode(empty_object.root),
            bytes: 0,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }))
        .collect();
    app.store.insert_outbound_grant(grant).unwrap();
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/batch"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    assert!(stream.next().await.unwrap().is_err());
    drop(stream);
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&token))
        .unwrap()
        .unwrap();
    assert!(grant.files.iter().all(|file| file.downloads == 0));
    assert_eq!(grant.files[64].downloads, 0);
}

#[tokio::test]
async fn batch_does_not_record_zero_file_before_next_chunk_validation() {
    let (_directory, mut app, _cookie, _expected) = fixture().await;
    Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 64 * 1024 * 1024;
    let large = vec![b'a'; BATCH_LEAD_BYTES as usize / BATCH_LEAD_FILES];
    let large_object = object_id(&large);
    let empty_object = object_id(&[]);
    std::fs::write(app.config.outbound_dir.join("large.bin"), &large).unwrap();
    std::fs::write(app.config.outbound_dir.join("invalid-empty.bin"), b"x").unwrap();
    let token = "e".repeat(32);
    let mut grant = crate::store::tests::test_outbound_grant("mixed-boundary", "", 0);
    grant.token_hash = hash_token(&token);
    grant.expires_at = now_unix() + 600;
    grant.max_downloads = Some(1);
    grant.bytes = large.len() as u64;
    grant.files = (0..BATCH_LEAD_FILES)
        .map(|index| OutboundGrantFile {
            source: "large.bin".to_owned(),
            name: format!("large-{index}.bin"),
            suite: "blake3".to_owned(),
            root: hex::encode(large_object.root),
            bytes: large.len() as u64,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        })
        .chain([
            OutboundGrantFile {
                source: "invalid-empty.bin".to_owned(),
                name: "invalid-empty.bin".to_owned(),
                suite: "blake3".to_owned(),
                root: hex::encode(empty_object.root),
                bytes: 0,
                receipt_b64: String::new(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            },
            OutboundGrantFile {
                source: "large.bin".to_owned(),
                name: "after-empty.bin".to_owned(),
                suite: "blake3".to_owned(),
                root: hex::encode(large_object.root),
                bytes: large.len() as u64,
                receipt_b64: String::new(),
                downloads: 0,
                first_download_at: None,
                last_download_at: None,
            },
        ])
        .collect();
    app.store.insert_outbound_grant(grant).unwrap();
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/batch"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 4))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let mut saw_error = false;
    while let Some(item) = stream.next().await {
        if item.is_err() {
            saw_error = true;
            break;
        }
    }
    assert!(saw_error);
    drop(stream);
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&token))
        .unwrap()
        .unwrap();
    assert!(grant.files[..BATCH_LEAD_FILES]
        .iter()
        .all(|file| file.downloads == 1));
    assert_eq!(grant.files[BATCH_LEAD_FILES].downloads, 0);
    assert_eq!(grant.files[BATCH_LEAD_FILES + 1].downloads, 0);
}

#[tokio::test]
async fn interrupted_bundle_issues_logical_lease_for_file_recovery() {
    let (_directory, app, _cookie, expected) = fixture().await;
    let object = object_id(&expected);
    std::fs::write(app.config.outbound_dir.join("source.bin"), &expected).unwrap();
    let token = "d".repeat(32);
    let mut grant = crate::store::tests::test_outbound_grant("bundle-resume", "", 0);
    grant.token_hash = hash_token(&token);
    grant.expires_at = now_unix() + 600;
    grant.max_downloads = Some(1);
    grant.bytes = expected.len() as u64;
    grant.files = ["one.bin", "two.bin"]
        .into_iter()
        .map(|name| OutboundGrantFile {
            source: "source.bin".to_owned(),
            name: name.to_owned(),
            suite: "blake3".to_owned(),
            root: hex::encode(object.root),
            bytes: expected.len() as u64,
            receipt_b64: String::new(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        })
        .collect();
    app.store.insert_outbound_grant(grant).unwrap();
    let response = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/bundle"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 1);
    let cookie = cookies[0].split(';').next().unwrap();
    drop(response);
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&token))
        .unwrap()
        .unwrap();
    assert!(grant.files.iter().all(|file| file.downloads == 1));
    let refused = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/files/0"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 6))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::NOT_FOUND);
    for index in 0..2 {
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/files/{index}"))
                    .header(header::COOKIE, cookie)
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        7 + index as u16,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            expected
        );
    }
}

/// Mid-stream recording (a flush inside the window) and the end flush
/// count each file once and the grant once, the same as per-file
/// recording did.
#[tokio::test]
async fn batch_over_the_window_records_each_file_once() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = crate::api::testing::config(directory.path());
    config.max_upload_bytes = 64 * 1024 * 1024;
    let app = crate::app::build(config).unwrap();
    let cookie = admin_cookie(&app);
    let mib = 1024 * 1024;
    // 9 + 9 MiB crosses the 16 MiB window after the second file, so the
    // third is recorded by the end-of-stream flush in a second call.
    for (path, size) in [
        ("win/a.bin", 9 * mib),
        ("win/b.bin", 9 * mib),
        ("win/c.bin", 1),
    ] {
        let bytes: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
        let response = router(app.clone())
            .oneshot(
                Request::post(format!("/api/admin/outbound-files?path={path}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let created = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"paths":["win/a.bin","win/b.bin","win/c.bin"],"max_downloads":2}"#,
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let token = body(created).await["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let batch = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/batch"))
                .extension(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    21,
                ))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(batch.status(), StatusCode::OK);
    let bytes = batch.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes.len(), 18 * mib + 1);
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&token))
        .unwrap()
        .unwrap();
    assert_eq!(
        grant
            .files
            .iter()
            .map(|file| file.downloads)
            .collect::<Vec<_>>(),
        vec![1, 1, 1]
    );
    assert_eq!(grant.downloads, 1);
    // Every staging permit is returned once the stream has drained.
    assert_eq!(
        app.staging_permits.available_permits(),
        STAGING_CONCURRENCY,
        "a staging permit leaked"
    );
}

async fn fixture() -> (tempfile::TempDir, Arc<App>, String, Vec<u8>) {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let bytes = b"outbound fixture".to_vec();
    let mut builder = InMemoryObjectBuilder::new(
        Suite::try_from(1).unwrap(),
        Some(bytes.len() as u64),
        bytes.len() as u64,
    )
    .unwrap();
    builder.update(&bytes).unwrap();
    let object = builder.finish().unwrap().object_id().clone();
    let source = app.config.receive_dir.join("received.bin");
    std::fs::write(&source, &bytes).unwrap();
    app.signer
        .write_sidecar(
            &vot_platform_fs::FileLocation::from_path(&source).unwrap(),
            &object,
            [1; 16],
            PublishObservation {
                incarnation: [2; 16],
                sequence: 1,
            },
            vot_sdk_file::CommitProfile::Balanced,
        )
        .unwrap();
    app.store
        .insert_link(crate::store::Link {
            retention_days: None,
            id: "link".to_owned(),
            label: "link".to_owned(),
            tenant: String::new(),
            dest: String::new(),
            password_hash: None,
            created_at: 1,
            expires_at: None,
            max_bytes: None,
            active: true,
            legal_hold: false,

            notifications: None,
            uploads: vec![crate::store::UploadRecord {
                partial: false,
                log: Vec::new(),
                id: "upload".to_owned(),
                started_at: 1,
                completed_at: 2,
                replayed_chunks: 0,
                rejected_chunks: 0,
                transport: Some("http".to_owned()),
                package_root: "package-root".to_owned(),
                total_bytes: bytes.len() as u64,
                files: vec![crate::store::FileRecord {
                    path: "received.bin".to_owned(),
                    stored_as: "received.bin".to_owned(),
                    bytes: object.length,
                    suite: "blake3".to_owned(),
                    root: hex::encode(object.root),
                    receipt: true,
                    deleted: false,
                }],
            }],
            events: Vec::new(),
        })
        .unwrap();
    (directory, app.clone(), admin_cookie(&app), bytes)
}

#[tokio::test]
async fn payload_gets_write_one_audit_row_per_request() {
    let (_directory, app, cookie, first) = fixture().await;
    for (path, bytes) in [
        ("audit/one.bin", first.as_slice()),
        ("audit/two.bin", b"second file".as_slice()),
    ] {
        let response = router(app.clone())
            .oneshot(
                Request::post(format!("/api/admin/outbound-files?path={path}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(bytes.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let created = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"paths":["audit/one.bin","audit/two.bin"]}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let created = body(created).await;
    let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
    let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
    let audit_rows = || {
        app.store
            .audit_export(None, 0, 0, 100)
            .unwrap()
            .into_iter()
            .filter(|row| row.event == "outbound_downloaded" && row.subject == grant_id)
            .collect::<Vec<_>>()
    };

    // Metadata, HEAD and receipts do not represent a payload request.
    let metadata = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
    let head = router(app.clone())
        .oneshot(
            Request::head(format!("/api/s/{token}/files/0"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    let receipt = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/receipts/0"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(receipt.status(), StatusCode::NOT_FOUND);
    for (path, port) in [("batch", 6), ("bundle", 7)] {
        let head = router(app.clone())
            .oneshot(
                Request::head(format!("/api/s/{token}/{path}"))
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        port,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::OK, "{path}");
        head.into_body().collect().await.unwrap();
    }
    assert!(audit_rows().is_empty());

    // The tokenless GET is admitted with a same-origin redirect that
    // writes its own row; the redirected request streams and writes
    // the payload row. No lease cookie is set anywhere.
    let admission = crate::app::router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/files/0"))
                .header("x-forwarded-for", "198.51.100.7")
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admission.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(admission.headers().get(header::SET_COOKIE).is_none());
    let location = admission.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned();
    let lease = location
        .strip_prefix(&format!("/api/s/{token}/files/0?download_lease="))
        .unwrap_or_else(|| panic!("unexpected redirect location {location}"))
        .to_owned();
    let final_url = format!("/api/s/{token}/files/0?download_lease={lease}");
    let file = router(app.clone())
        .oneshot(
            Request::get(&final_url)
                .header("x-forwarded-for", "198.51.100.7")
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(file.status(), StatusCode::OK);
    assert_eq!(file.into_body().collect().await.unwrap().to_bytes(), first);

    let range = router(app.clone())
        .oneshot(
            Request::get(&final_url)
                .header(header::RANGE, "bytes=0-1")
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        range.into_body().collect().await.unwrap().to_bytes(),
        &first[..2]
    );

    let batch = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/batch"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(batch.status(), StatusCode::OK);
    assert_eq!(
        batch.into_body().collect().await.unwrap().to_bytes(),
        [first.clone(), b"second file".to_vec()].concat()
    );

    let bundle = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/bundle"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 4))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bundle.status(), StatusCode::OK);
    bundle.into_body().collect().await.unwrap();

    // A source failure happens before the request-start boundary.
    std::fs::write(app.config.outbound_dir.join("audit/two.bin"), b"tampered").unwrap();
    let failed = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/files/1"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(failed.status(), StatusCode::NOT_FOUND);

    let rows = audit_rows();
    assert_eq!(rows.len(), 5);
    let mut modes = rows
        .iter()
        .map(|row| row.detail["mode"].as_str().unwrap())
        .collect::<Vec<_>>();
    modes.sort_unstable();
    assert_eq!(modes, ["batch", "bundle", "file", "file", "file"]);
    assert!(rows.iter().all(|row| {
        row.actor.is_empty() && row.tenant.is_empty() && row.detail.get("token").is_none()
    }));
    let file_rows = rows
        .iter()
        .filter(|row| row.detail["mode"] == "file")
        .collect::<Vec<_>>();
    assert_eq!(file_rows.len(), 3);
    assert!(file_rows.iter().all(|row| row.detail["file_index"] == 0));
    assert!(file_rows
        .iter()
        .any(|row| row.detail["client_ip"] == "198.51.100.7"));
    assert!(rows
        .iter()
        .filter(|row| row.detail["mode"] != "file")
        .all(|row| row.detail.get("file_index").is_none()));
}

#[test]
fn tokens_are_strict() {
    assert!(valid_token(&"a".repeat(32)));
    assert!(!valid_token("x"));
    assert!(!valid_token(&"g".repeat(32)));
    // Tokens are minted lowercase and hashed case-sensitively, so an
    // uppercase lookalike is refused here instead of answering a bare
    // not-found after the hash compare (audit finding 510).
    assert!(!valid_token(&"A".repeat(32)));
    assert!(!valid_token("0123456789abcdef0123456789ABCDEF"));
}

#[test]
fn record_range_coalesces_delivered_files() {
    let mib = 1024 * 1024;
    // Forty 1 MiB files.
    let boundaries: Vec<u64> = (1..=40).map(|index| index * mib).collect();
    // Nothing delivered yet, and a partial first file, record nothing.
    assert_eq!(record_range(&boundaries, 0, 0, false), None);
    assert_eq!(record_range(&boundaries, 0, mib - 1, false), None);
    // Under the window: wait, unless the stream is ending.
    assert_eq!(record_range(&boundaries, 0, 15 * mib, false), None);
    assert_eq!(record_range(&boundaries, 0, 15 * mib, true), Some(0..15));
    // At the window: record exactly the covered files.
    assert_eq!(
        record_range(&boundaries, 0, 16 * mib + 7, false),
        Some(0..16)
    );
    // The window is measured from the last recorded boundary.
    assert_eq!(record_range(&boundaries, 16, 31 * mib, false), None);
    assert_eq!(record_range(&boundaries, 16, 32 * mib, false), Some(16..32));
    // Everything recorded: a flush has nothing to do.
    assert_eq!(record_range(&boundaries, 40, 40 * mib, true), None);
}

#[test]
fn batch_chunks_bound_file_count_bytes_and_oversized_files() {
    let file = |bytes| OutboundGrantFile {
        source: String::new(),
        name: String::new(),
        suite: "blake3".to_owned(),
        root: String::new(),
        bytes,
        receipt_b64: String::new(),
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
    };
    let mut grant = OutboundGrant {
        id: String::new(),
        token_hash: String::new(),
        password_hash: None,
        tenant: String::new(),
        link_id: String::new(),
        upload_id: String::new(),
        package_root: String::new(),
        name: String::new(),
        suite: String::new(),
        root: String::new(),
        file_index: 0,
        bytes: 0,
        label: String::new(),
        created_at: 0,
        expires_at: 0,
        revoked_at: None,
        downloads: 0,
        max_downloads: None,

        notifications: None,
        first_download_at: None,
        last_download_at: None,
        files: (0..5_001).map(|_| file(1)).collect(),
    };
    // File counts ramp from the lead size, doubling per chunk.
    let chunks = batch_chunks(&grant, grant.files.len());
    let spans: Vec<(usize, usize)> = chunks.iter().map(|c| (c.start, c.end)).collect();
    assert_eq!(
        spans,
        [
            (0, 64),
            (64, 192),
            (192, 448),
            (448, 960),
            (960, 1_984),
            (1_984, 4_032),
            (4_032, 5_001),
        ]
    );
    assert!(chunks.iter().all(|c| !c.oversized));
    assert_eq!(chunks[6].bytes, 969);

    // Byte caps ramp the same way and never exceed BATCH_CHUNK_BYTES.
    grant.files = (0..12).map(|_| file(64 * 1024 * 1024)).collect();
    let chunks = batch_chunks(&grant, grant.files.len());
    let spans: Vec<(usize, usize)> = chunks.iter().map(|c| (c.start, c.end)).collect();
    assert_eq!(spans, [(0, 1), (1, 2), (2, 3), (3, 5), (5, 9), (9, 12)]);
    assert!(chunks.iter().all(|c| c.bytes <= BATCH_CHUNK_BYTES));

    grant.files = vec![file(BATCH_STAGE_BYTES), file(1)];
    let chunks = batch_chunks(&grant, grant.files.len());
    assert_eq!(chunks.len(), 2);
    assert!(chunks[0].oversized);
    assert!(!chunks[1].oversized);
    assert_eq!((chunks[0].bytes, chunks[1].bytes), (BATCH_STAGE_BYTES, 1));

    grant.files = vec![file(BATCH_STAGE_BYTES + 1), file(1)];
    let chunks = batch_chunks(&grant, grant.files.len());
    assert_eq!(chunks.len(), 2);
    assert!(chunks[0].oversized);
    assert_eq!(
        (chunks[0].start, chunks[0].end, chunks[0].bytes),
        (0, 1, BATCH_STAGE_BYTES + 1)
    );
    assert!(!chunks[1].oversized);
}

#[test]
fn concurrent_library_dir_creation_accepts_same_parent() {
    let directory = tempfile::tempdir().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles = (0..8)
        .map(|index| {
            let barrier = std::sync::Arc::clone(&barrier);
            let path = directory
                .path()
                .join("shared")
                .join(format!("nested-{index}"));
            std::thread::spawn(move || {
                barrier.wait();
                create_library_dirs(&path)
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
    assert!(directory.path().join("shared").is_dir());
}

#[test]
fn hashes_are_not_raw_tokens() {
    assert_ne!(hash_token("a"), "a");
}
#[test]
fn byte_ranges_support_all_single_range_forms() {
    assert_eq!(parse_range("bytes=2-4", 10), Some((2, 4)));
    assert_eq!(parse_range("bytes=2-", 10), Some((2, 9)));
    assert_eq!(parse_range("bytes=-3", 10), Some((7, 9)));
    assert_eq!(parse_range("bytes=-99", 10), Some((0, 9)));
    assert_eq!(parse_range("BYTES=0-99", 10), Some((0, 9)));
}
#[test]
fn byte_ranges_reject_malformed_and_unsatisfiable_values() {
    for value in [
        "bytes=",
        "bytes=1-2,4-5",
        "bytes=abc-2",
        "bytes=2-1",
        "bytes=10-",
        "bytes=-0",
    ] {
        assert_eq!(parse_range(value, 10), None, "{value}");
    }
    assert_eq!(parse_range("bytes=0-", 0), None);
}
#[test]
fn automation_share_rate_is_bounded_per_ip() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    for _ in 0..60 {
        assert!(app.automation_rate.allow("127.0.0.1"));
    }
    assert!(!app.automation_rate.allow("127.0.0.1"));
    assert!(app.automation_rate.allow("127.0.0.2"));
}

#[test]
fn outbound_grants_paging_rejects_invalid_bounds_and_overflow() {
    assert_eq!(
        outbound_grants_paging(OutboundGrantsQuery {
            limit: None,
            offset: None,
        })
        .unwrap(),
        (50, 0)
    );
    for limit in ["0", "101", "nope"] {
        assert_eq!(
            outbound_grants_paging(OutboundGrantsQuery {
                limit: Some(limit.to_owned()),
                offset: None,
            })
            .unwrap_err()
            .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    for offset in ["-1", "18446744073709551616"] {
        assert_eq!(
            outbound_grants_paging(OutboundGrantsQuery {
                limit: None,
                offset: Some(offset.to_owned()),
            })
            .unwrap_err()
            .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}

#[test]
fn outbound_metadata_paging_defaults_and_rejects_invalid_bounds() {
    assert_eq!(
        outbound_metadata_paging(OutboundMetadataQuery {
            limit: None,
            offset: None,
        })
        .unwrap(),
        None
    );
    assert_eq!(
        outbound_metadata_paging(OutboundMetadataQuery {
            limit: None,
            offset: Some("4".to_owned()),
        })
        .unwrap(),
        Some((4, 100))
    );
    for limit in ["0", "501", "nope"] {
        assert_eq!(
            outbound_metadata_paging(OutboundMetadataQuery {
                limit: Some(limit.to_owned()),
                offset: None,
            })
            .unwrap_err()
            .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    for offset in ["-1", "18446744073709551616"] {
        assert_eq!(
            outbound_metadata_paging(OutboundMetadataQuery {
                limit: None,
                offset: Some(offset.to_owned()),
            })
            .unwrap_err()
            .status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}

#[tokio::test]
async fn outbound_grants_handler_returns_default_page_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    for index in 0..51 {
        app.store
            .insert_outbound_grant(OutboundGrant {
                id: format!("grant-{index}"),
                token_hash: format!("hash-{index}"),
                password_hash: None,
                tenant: String::new(),
                link_id: String::new(),
                upload_id: String::new(),
                package_root: String::new(),
                name: "file.bin".to_owned(),
                suite: "blake3".to_owned(),
                root: String::new(),
                file_index: 0,
                bytes: 0,
                label: format!("grant-{index}"),
                created_at: 1,
                expires_at: 2,
                revoked_at: None,
                downloads: 0,
                max_downloads: None,

                notifications: None,
                first_download_at: None,
                last_download_at: None,
                files: Vec::new(),
            })
            .unwrap();
    }

    let response = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-grants")
                .header("cookie", admin_cookie(&app))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body(response).await;
    assert_eq!(listed["limit"], 50);
    assert_eq!(listed["offset"], 0);
    assert_eq!(listed["total"], 51);
    assert_eq!(listed["has_more"], true);
    assert_eq!(listed["grants"].as_array().unwrap().len(), 50);
    assert_eq!(listed["grants"][0]["file_count"], 1);
    assert_eq!(listed["grants"][0]["files_truncated"], false);
    assert_eq!(listed["grants"][0]["files"], json!([]));
    assert_eq!(listed["grants"][0]["id"], "grant-50");
}

#[tokio::test]
async fn deleting_library_files_checks_safety_and_active_grants() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    std::fs::create_dir_all(&app.config.outbound_dir).unwrap();
    let path = app.config.outbound_dir.join("delete.bin");
    std::fs::write(&path, b"payload").unwrap();
    let request_app = app.clone();
    let request = |path: &str| {
        Request::delete(format!("/api/admin/outbound-files?path={path}"))
            .header("cookie", admin_cookie(&request_app))
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap()
    };

    let response = router(app.clone())
        .oneshot(request("../outside"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let mut grant = OutboundGrant {
        id: "active".to_owned(),
        token_hash: "active-hash".to_owned(),
        password_hash: None,
        tenant: String::new(),
        link_id: String::new(),
        upload_id: String::new(),
        package_root: String::new(),
        name: "delete.bin".to_owned(),
        suite: "blake3".to_owned(),
        root: String::new(),
        file_index: 0,
        bytes: 7,
        label: "delete.bin".to_owned(),
        created_at: now_unix(),
        expires_at: now_unix().saturating_add(60),
        revoked_at: None,
        downloads: 0,
        max_downloads: Some(1),

        notifications: None,
        first_download_at: None,
        last_download_at: None,
        files: Vec::new(),
    };
    grant.files = vec![OutboundGrantFile {
        source: "delete.bin".to_owned(),
        name: "delete.bin".to_owned(),
        suite: "blake3".to_owned(),
        root: "root".to_owned(),
        bytes: 7,
        receipt_b64: "receipt".to_owned(),
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
    }];
    app.store.insert_outbound_grant(grant).unwrap();
    let response = router(app.clone())
        .oneshot(request("delete.bin"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(path.exists());

    app.store
        .revoke_outbound_grant("", "active", now_unix())
        .unwrap();
    let response = router(app).oneshot(request("delete.bin")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!path.exists());
}

#[test]
fn library_grant_revalidation_rejects_changed_sources() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("outbound");
    std::fs::create_dir(&root).unwrap();
    let path = root.join("file.bin");
    std::fs::write(&path, b"payload").unwrap();
    let selections = vec![("file.bin".to_owned(), path.clone())];
    let file = OutboundGrantFile {
        source: "file.bin".to_owned(),
        name: "file.bin".to_owned(),
        suite: "blake3".to_owned(),
        root: "root".to_owned(),
        bytes: 7,
        receipt_b64: "receipt".to_owned(),
        downloads: 0,
        first_download_at: None,
        last_download_at: None,
    };
    assert!(library_sources_match(
        &root,
        &selections,
        std::slice::from_ref(&file)
    ));
    std::fs::write(&path, b"changed length").unwrap();
    assert!(!library_sources_match(&root, &selections, &[file]));
}

#[test]
fn filenames_are_single_safe_components() {
    for (name, fallback, encoded) in [
        ("../a/b?.txt", "b_.txt", "b%3F.txt"),
        ("a\\file.txt", "file.txt", "file.txt"),
        ("a-z_1~. txt", "a-z_1_. txt", "a-z_1~.%20txt"),
        ("x\";\r\n*.txt", "x_____.txt", "x%22%3B%0D%0A%2A.txt"),
        ("100% prêt.txt", "100_ pr_t.txt", "100%25%20pr%C3%AAt.txt"),
        ("", "download.bin", "download.bin"),
        (".", "download.bin", "download.bin"),
        ("..", "download.bin", "download.bin"),
    ] {
        assert_eq!(
            attachment_filename(name).unwrap(),
            format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
        );
    }
    let name = format!("{}.mov.vot-receipt", "a".repeat(239));
    let header = attachment_filename(&name).unwrap();
    assert!(header
        .to_str()
        .unwrap()
        .starts_with(&format!("attachment; filename=\"{name}\";")));
    assert!(header
        .to_str()
        .unwrap()
        .ends_with(&format!("filename*=UTF-8''{name}")));
}

/// Audit finding 507: downloads keep the extension at any name length.
/// The retired safe_filename truncated the whole name to 180 characters
/// after the extension, so a 204-character name downloaded with none.
#[test]
fn long_names_keep_their_extension() {
    let name = format!("{}.mov", "a".repeat(200));
    assert_eq!(name.len(), 204);
    let header = attachment_filename(&name).unwrap();
    let header = header.to_str().unwrap();
    assert!(
        header.ends_with(&format!("filename*=UTF-8''{name}")),
        "{header}"
    );
    assert!(header.contains(&format!("filename=\"{name}\"")), "{header}");
}
#[test]
fn bundle_paths_are_relative_and_normalized() {
    assert_eq!(
        bundle_path("project/file.bin").as_deref(),
        Some("project/file.bin")
    );
    assert!(bundle_path("../file.bin").is_none());
    assert!(bundle_path("/file.bin").is_none());
    assert!(bundle_path("project/../file.bin").is_none());
    assert!(bundle_path("").is_none());
}
#[test]
fn drop_guards_remove_stage_and_active_grant() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let stage = directory.path().join("stage").join("file");
    std::fs::create_dir_all(stage.parent().unwrap()).unwrap();
    std::fs::write(&stage, b"payload").unwrap();
    let budget = Arc::new(StageBudget::new());
    let reservation = budget
        .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 1, 1)
        .unwrap();
    assert!(budget
        .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 1, 1)
        .is_err());
    let staged = StagedFile {
        path: stage.clone(),
        reservation: Some(reservation),
    };
    let active = ActiveDownload::claim(Arc::clone(&app), "grant").unwrap();
    drop((staged, active));
    assert!(!stage.exists());
    assert!(!app.outbound_active.lock().unwrap().contains("grant"));
    assert!(budget
        .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 1, 1)
        .is_ok());
}

#[test]
fn build_bundle_verifies_sources_and_keeps_archive_readable() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let first_path = directory.path().join("first");
    let second_path = directory.path().join("second");
    let first_bytes = b"first payload";
    let second_bytes = b"second payload";
    std::fs::write(&first_path, first_bytes).unwrap();
    std::fs::write(&second_path, second_bytes).unwrap();
    let first_object = object_id(first_bytes);
    let second_object = object_id(second_bytes);
    let first_receipt = app
        .signer
        .encode(
            &first_object,
            [1; 16],
            PublishObservation {
                incarnation: [2; 16],
                sequence: 1,
            },
            vot_sdk_file::CommitProfile::Balanced,
            vot_sdk_file::NasContract::Unqualified,
        )
        .unwrap();
    let second_receipt = app
        .signer
        .encode(
            &second_object,
            [3; 16],
            PublishObservation {
                incarnation: [4; 16],
                sequence: 2,
            },
            vot_sdk_file::CommitProfile::Balanced,
            vot_sdk_file::NasContract::Unqualified,
        )
        .unwrap();

    let grant = branding_grant("bundle-test", None);
    let archive = build_bundle(
        &app,
        &grant,
        vec![
            (
                Source {
                    path: first_path,
                    object: first_object,
                    name: "first.txt".to_owned(),
                    receipt: Some(first_receipt),
                },
                "first.txt".to_owned(),
            ),
            (
                Source {
                    path: second_path,
                    object: second_object,
                    name: "second.txt".to_owned(),
                    receipt: Some(second_receipt),
                },
                "second.txt".to_owned(),
            ),
        ],
    )
    .unwrap();

    let entries = zip_entries(&std::fs::read(&archive.path).unwrap());
    assert_eq!(entries["first.txt"], b"first payload");
    assert_eq!(entries["second.txt"], b"second payload");
    drop(archive);
}

#[test]
fn build_bundle_rejects_ambiguous_names_before_staging() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let grant = branding_grant("bundle-test", None);
    for names in [
        ["Café.mov", "Cafe\u{301}.mov"],
        ["folder", "FOLDER/clip.mov"],
    ] {
        let files = names
            .into_iter()
            .map(|name| {
                (
                    Source {
                        path: directory.path().join(name),
                        object: ObjectId {
                            suite: 1,
                            root: [0; 32],
                            length: 1,
                        },
                        name: name.into(),
                        receipt: None,
                    },
                    bundle_path(name).unwrap(),
                )
            })
            .collect();
        let error = build_bundle(&app, &grant, files).err().unwrap();
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error.message.contains("collide"));
        assert!(!app.config.data_dir.join("outbound.stage").exists());
    }
}

#[test]
fn build_bundle_rejects_source_mismatch_without_archive() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let grant = branding_grant("integrity-test", None);
    let source_path = directory.path().join("source");
    let source_for_assert = source_path.clone();
    std::fs::write(&source_path, b"actual payload").unwrap();
    let expected = object_id(b"expected payload");
    let failures_before = OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed);
    let audits_before = app.store.audit_count().unwrap();

    assert!(build_bundle(
        &app,
        &grant,
        vec![(
            Source {
                path: source_path,
                object: expected,
                name: "source.txt".to_owned(),
                receipt: Some(Vec::new()),
            },
            "source.txt".to_owned(),
        )],
    )
    .is_err());
    assert!(
        OUTBOUND_INTEGRITY_FAILURES.load(Ordering::Relaxed) > failures_before,
        "integrity metric did not increment"
    );
    assert_eq!(app.store.audit_count().unwrap(), audits_before + 1);
    let audit = app
        .store
        .audit_recent(Some(&grant.tenant), 0, 10)
        .unwrap()
        .into_iter()
        .find(|row| row.event == "outbound_integrity_failure")
        .expect("integrity audit row");
    assert_eq!(audit.subject, grant.id);
    assert_eq!(audit.detail["file_index"], 0);
    assert_eq!(audit.detail["component"], "bundle");
    assert_eq!(
        audit.detail["path"],
        source_for_assert.to_string_lossy().as_ref()
    );
    assert!(app
        .config
        .data_dir
        .join("outbound.stage")
        .read_dir()
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn bundle_error_mapping_keeps_io_failures_internal() {
    assert_eq!(
        map_bundle_error(io::Error::new(io::ErrorKind::InvalidData, "mismatch")).status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        map_bundle_error(io::Error::other("disk full")).status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        map_bundle_error(io::Error::new(io::ErrorKind::NotFound, "gone")).status,
        StatusCode::NOT_FOUND
    );
}

#[test]
fn archive_size_bound_checks_payload_and_zip_overhead() {
    let source = Source {
        path: PathBuf::new(),
        object: ObjectId {
            suite: 1,
            root: [0; 32],
            length: 10,
        },
        name: "unused".to_owned(),
        receipt: None,
    };
    let files = vec![(source, "project/file.exr".to_owned())];
    assert_eq!(
        archive_size_bound(&files),
        Some(10 + 30 + 46 + 64 + 2 * "project/file.exr".len() as u64 + 98)
    );
    assert!(archive_size_bound(&[(
        Source {
            path: PathBuf::new(),
            object: ObjectId {
                suite: 1,
                root: [0; 32],
                length: u64::MAX,
            },
            name: "unused".to_owned(),
            receipt: None,
        },
        "file".to_owned(),
    )])
    .is_none());
}

#[test]
fn stage_budget_reserves_concurrently_and_resets_after_last_drop() {
    let budget = Arc::new(StageBudget::new());
    let first = budget
        .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 10, 10)
        .unwrap();
    assert!(matches!(
        budget.reserve_with_free_space(MIN_STAGE_FREE_BYTES + 10, 1),
        Err(StageReserveError::Insufficient)
    ));
    drop(first);
    let second = budget
        .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 20, 20)
        .unwrap();
    drop(second);
    assert!(budget
        .reserve_with_free_space(MIN_STAGE_FREE_BYTES + 1, 1)
        .is_ok());
}

#[test]
fn stage_capacity_errors_are_507() {
    assert_eq!(
        stage_capacity_error().status,
        StatusCode::INSUFFICIENT_STORAGE
    );
    assert_eq!(
        map_stage_reserve_error(StageReserveError::Overflow).status,
        StatusCode::INSUFFICIENT_STORAGE
    );
}

#[test]
fn active_downloads_allow_sixteen_distinct_files_per_grant() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let active: Vec<_> = (0..MAX_ACTIVE_PER_GRANT)
        .map(|index| ActiveDownload::claim(Arc::clone(&app), &format!("grant:{index}")))
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(ActiveDownload::claim(Arc::clone(&app), "grant:16").is_err());
    assert!(ActiveDownload::claim(Arc::clone(&app), "grant:0").is_err());
    drop(active);
    assert!(ActiveDownload::claim(Arc::clone(&app), "grant:4").is_ok());
}

#[test]
fn leased_ranges_can_run_alongside_one_unleased_file_download() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let first = ActiveDownload::claim(Arc::clone(&app), "grant:0").unwrap();
    let leased =
        ActiveDownload::claim_with_grant(Arc::clone(&app), "grant:0:lease-unique", "grant")
            .unwrap();
    assert!(ActiveDownload::claim(Arc::clone(&app), "grant:0").is_err());
    drop((first, leased));
}

#[tokio::test]
async fn download_headers_preserve_unicode_file_and_receipt_names() {
    let (_directory, app, cookie, _) = fixture().await;
    app.store
        .with(|connection| {
            connection.execute(
                "UPDATE files SET path=?1 WHERE link_id='link' AND file_index=0",
                ["folder/納品 café.mov"],
            )
        })
        .unwrap();
    let response = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7}"#,
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let created = body(response).await;
    let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
    for (path, extension) in [
        ("file", ""),
        ("files/0", ""),
        ("receipt", ".vot-receipt"),
        ("receipts/0", ".vot-receipt"),
    ] {
        for method in [axum::http::Method::GET, axum::http::Method::HEAD] {
            let response = router(app.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(format!("/api/s/{token}/{path}"))
                        .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response.headers()[header::CONTENT_DISPOSITION],
                format!("attachment; filename=\"__ caf_.mov{extension}\"; filename*=UTF-8''%E7%B4%8D%E5%93%81%20caf%C3%A9.mov{extension}"),
                "{path}"
            );
            response.into_body().collect().await.unwrap();
        }
    }
}

#[tokio::test]
async fn grant_flow_serves_verified_file_and_receipt_then_revokes() {
    let (_directory, app, cookie, expected_bytes) = fixture().await;
    let create = Request::post("/api/admin/outbound-grants")
        .header("cookie", &cookie)
        .header("x-votport", "1")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"link_id":"link","upload_id":"upload","file_index":0,"label":"fixture","expires_days":7}"#,
        ))
        .unwrap();
    let response = router(app.clone()).oneshot(create).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let created = body(response).await;
    assert_eq!(created["grant"]["file_index"], 0);
    assert!(created["grant"].get("token_hash").is_none());
    let url = created["url"].as_str().unwrap();
    let token = url.rsplit('/').next().unwrap();
    assert_eq!(url, format!("https://drop.example.com/s/{token}"));
    let id = created["grant"]["id"].as_str().unwrap().to_owned();
    for _ in 0..2 {
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/admin/outbound-grants/{id}/url"))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(body(response).await["url"], url);
    }
    let refused = router(app.clone())
        .oneshot(
            Request::get(format!("/api/admin/outbound-grants/{id}/url"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    let listing = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-grants")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!body(listing).await.to_string().contains(token));

    let metadata = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
    assert_eq!(metadata.headers()[header::CACHE_CONTROL], "no-store");
    let metadata = body(metadata).await;
    assert_eq!(metadata["bytes"], expected_bytes.len());
    assert_eq!(metadata["length"], expected_bytes.len());
    assert_eq!(metadata["suite"], "blake3");
    assert_eq!(metadata["name"], "received.bin");
    assert_eq!(metadata["root"].as_str().unwrap().len(), 64);
    assert_eq!(metadata["receipt_key"], app.signer.public_hex);
    assert_eq!(metadata["receipt_url"], format!("/api/s/{token}/receipt"));
    assert_eq!(metadata["download_url"], format!("/api/s/{token}/file"));
    assert_eq!(metadata["bundle_url"], format!("/api/s/{token}/bundle"));

    let paged = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}?limit=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(paged.status(), StatusCode::OK);
    let paged = body(paged).await;
    assert_eq!(paged["files_total"], 1);
    assert_eq!(paged["offset"], 0);
    assert_eq!(paged["limit"], 1);
    assert_eq!(paged["has_more"], false);
    assert_eq!(paged["files"].as_array().unwrap().len(), 1);
    assert_eq!(
        paged["files"][0]["download_url"],
        format!("/api/s/{token}/files/0")
    );

    let receipt = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/receipt"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(receipt.status(), StatusCode::OK);
    assert_eq!(
        receipt.into_body().collect().await.unwrap().to_bytes(),
        std::fs::read(app.config.receive_dir.join("received.bin.vot-receipt")).unwrap()
    );

    let file = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(file.status(), StatusCode::OK);
    assert_eq!(
        file.headers()[header::CONTENT_LENGTH],
        expected_bytes.len().to_string()
    );
    assert_eq!(
        file.into_body().collect().await.unwrap().to_bytes(),
        expected_bytes
    );
    let catalog = app.config.data_dir.join("outbound.proofs").join(format!(
        "1-{}-{}.vot-catalog",
        metadata["root"].as_str().unwrap(),
        expected_bytes.len()
    ));
    assert!(catalog.is_file());
    let catalog_bytes = std::fs::read(&catalog).unwrap();
    assert!(!app.config.data_dir.join("outbound.stage").exists());
    let second = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        second.into_body().collect().await.unwrap().to_bytes(),
        expected_bytes
    );
    assert_eq!(std::fs::read(catalog).unwrap(), catalog_bytes);
    std::fs::write(
        app.config.receive_dir.join("received.bin"),
        b"tampered fixture",
    )
    .unwrap();
    let tampered = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tampered.status(), StatusCode::NOT_FOUND);
    assert!(app.outbound_active.lock().unwrap().is_empty());

    let conflict = router(app.clone())
        .oneshot(
            Request::delete("/api/admin/links/link/uploads/upload/files/0")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    let revoke = Request::delete(format!("/api/admin/outbound-grants/{id}"))
        .header("cookie", &cookie)
        .header("x-votport", "1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router(app.clone()).oneshot(revoke).await.unwrap().status(),
        StatusCode::OK
    );
    let refused = router(app.clone())
        .oneshot(
            Request::get(format!("/api/admin/outbound-grants/{id}/url"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::NOT_FOUND);
    for suffix in ["", "/receipt", "/file"] {
        let mut request = Request::get(format!("/api/s/{token}{suffix}"));
        if suffix == "/file" {
            request =
                request.extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))));
        }
        assert_eq!(
            router(app.clone())
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn resumable_downloads_count_once_and_head_does_not_stage() {
    let (_directory, app, cookie, expected_bytes) = fixture().await;
    let created = body(
        settled_grant_response(
            app.clone(),
            &cookie,
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7,"max_downloads":1}"#,
                    ))
                .unwrap(),
            )
            .await,
    )
    .await;
    let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
    let head = router(app.clone())
        .oneshot(
            Request::head(format!("/api/s/{token}/file"))
                .header(header::RANGE, "bytes=0-6")
                .header(header::IF_RANGE, "\"not-the-etag\"")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(
        head.headers()[header::CONTENT_LENGTH],
        expected_bytes.len().to_string()
    );
    assert!(head.headers().get(header::SET_COOKIE).is_none());
    assert!(!app.config.data_dir.join("outbound.stage").exists());

    let first = crate::app::router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .header(header::RANGE, "bytes=0-6")
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(first.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(first.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(first.headers()[header::REFERRER_POLICY], "no-referrer");
    let location = first.headers()[header::LOCATION].to_str().unwrap();
    let lease = location
        .strip_prefix(&format!("/api/s/{token}/file?download_lease="))
        .unwrap_or_else(|| panic!("unexpected redirect location {location}"));
    assert!(
        !lease.is_empty()
            && lease
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'.'),
        "lease {lease} is not an issued token"
    );
    // Admission does not record: an aborted delivery must burn no quota
    // (audit finding 490).
    let grant = app
        .store
        .outbound_grant_by_id(created["grant"]["id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(grant.downloads, 0);

    // The redirected request streams the range and hands out no lease
    // cookie. A partial range response records nothing (audit finding
    // 490): only a whole-object delivery counts, so resumes stay free.
    let final_url = format!("/api/s/{token}/file?download_lease={lease}");
    let second = router(app.clone())
        .oneshot(
            Request::get(&final_url)
                .header(header::RANGE, "bytes=0-6")
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(second.headers()[header::CONTENT_RANGE], "bytes 0-6/16");
    assert_eq!(second.headers()[header::CONTENT_LENGTH], "7");
    assert_eq!(second.headers()[header::ACCEPT_RANGES], "bytes");
    assert!(second.headers().get(header::SET_COOKIE).is_none());
    let etag = second.headers()[header::ETAG].to_str().unwrap().to_owned();
    assert_eq!(
        second.into_body().collect().await.unwrap().to_bytes(),
        &expected_bytes[..7]
    );

    // A Range resume on the final URL neither redirects nor counts.
    let resume = router(app.clone())
        .oneshot(
            Request::get(&final_url)
                .header(header::RANGE, "bytes=7-")
                .header(header::IF_RANGE, etag)
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resume.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(resume.headers()[header::CONTENT_RANGE], "bytes 7-15/16");
    assert_eq!(
        resume.into_body().collect().await.unwrap().to_bytes(),
        &expected_bytes[7..]
    );
    let grant = app
        .store
        .outbound_grant_by_id(created["grant"]["id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(grant.downloads, 0);

    // The abandoned ranges spent nothing, so a tokenless retry is
    // admitted again instead of refused. The plain router (no redirect
    // replay) observes the admission alone.
    let retry = crate::app::router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = retry.headers()[header::LOCATION].to_str().unwrap();
    let fresh = location
        .strip_prefix(&format!("/api/s/{token}/file?download_lease="))
        .unwrap_or_else(|| panic!("unexpected redirect location {location}"))
        .to_owned();

    // A full delivery records once, after its last frame is handed to
    // the transport (audit finding 490).
    let full = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file?download_lease={fresh}"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(full.status(), StatusCode::OK);
    assert_eq!(
        full.headers()[header::CONTENT_LENGTH],
        expected_bytes.len().to_string()
    );
    assert_eq!(
        full.into_body().collect().await.unwrap().to_bytes(),
        &expected_bytes[..]
    );
    let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let downloads = app
                .store
                .outbound_grant_by_id(&grant_id)
                .unwrap()
                .unwrap()
                .downloads;
            if downloads == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the completed download was not recorded");

    // The single download is spent, so a tokenless retry is refused.
    let exhausted = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .header(header::RANGE, "bytes=7-15")
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exhausted.status(), StatusCode::NOT_FOUND);

    // A forged lease and a lease minted for another index both count as
    // absent and land on the same refusal.
    let grant = app
        .store
        .outbound_grant_by_id(created["grant"]["id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    let wrong_index = auth::issue_download_lease(&app.secret, &grant.id, &grant.token_hash, 1, 60);
    for absent in ["forged.deadbeef.deadbeef".to_owned(), wrong_index] {
        let refused = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file?download_lease={absent}"))
                    .header(header::RANGE, "bytes=7-15")
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::NOT_FOUND, "{absent}");
    }

    let id = created["grant"]["id"].as_str().unwrap();
    let rotated = router(app.clone())
        .oneshot(
            Request::patch(format!("/api/admin/outbound-grants/{id}"))
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"rotate":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotated.status(), StatusCode::OK);
    let old_lease_after_rotation = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file?download_lease={lease}"))
                .header(header::RANGE, "bytes=7-15")
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(old_lease_after_rotation.status(), StatusCode::NOT_FOUND);

    let created = body(
        settled_grant_response(
            app.clone(),
            &cookie,
            Request::post("/api/admin/outbound-grants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7}"#,
                ))
                .unwrap(),
        )
        .await,
    )
    .await;
    let revoke_token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
    let admission = crate::app::router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{revoke_token}/file"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admission.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(admission.headers().get(header::SET_COOKIE).is_none());
    let location = admission.headers()[header::LOCATION].to_str().unwrap();
    let revoke_lease = location
        .strip_prefix(&format!("/api/s/{revoke_token}/file?download_lease="))
        .unwrap_or_else(|| panic!("unexpected redirect location {location}"))
        .to_owned();
    let revoke_id = created["grant"]["id"].as_str().unwrap();
    let revoke = router(app.clone())
        .oneshot(
            Request::delete(format!("/api/admin/outbound-grants/{revoke_id}"))
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::OK);
    let old_lease_after_revoke = router(app.clone())
        .oneshot(
            Request::get(format!(
                "/api/s/{revoke_token}/file?download_lease={revoke_lease}"
            ))
            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(old_lease_after_revoke.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn range_errors_and_if_range_mismatch_are_safe() {
    let (_directory, app, cookie, expected_bytes) = fixture().await;
    let created = body(
        settled_grant_response(
            app.clone(),
            &cookie,
            Request::post("/api/admin/outbound-grants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7}"#,
                ))
                .unwrap(),
        )
        .await,
    )
    .await;
    let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
    for value in ["bytes=0-1,2-3", "bytes=99-", "bytes=3-2"] {
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .header(header::RANGE, value)
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes */16");
    }
    let mut multiple = Request::get(format!("/api/s/{token}/file"))
        .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
        .body(Body::empty())
        .unwrap();
    multiple
        .headers_mut()
        .append(header::RANGE, HeaderValue::from_static("bytes=0-1"));
    multiple
        .headers_mut()
        .append(header::RANGE, HeaderValue::from_static("bytes=2-3"));
    let multiple = router(app.clone()).oneshot(multiple).await.unwrap();
    assert_eq!(multiple.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(multiple.headers()[header::CONTENT_RANGE], "bytes */16");
    let full = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .header(header::RANGE, "bytes=0-1")
                .header(header::IF_RANGE, "\"wrong\"")
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(full.status(), StatusCode::OK);
    assert_eq!(full.headers()[header::CONTENT_LENGTH], "16");
    assert!(full.headers().get(header::CONTENT_RANGE).is_none());
    assert_eq!(
        full.into_body().collect().await.unwrap().to_bytes(),
        expected_bytes
    );
}

#[tokio::test]
async fn grant_lifecycle_rotation_and_extension_are_scoped() {
    let (_directory, app, cookie, _expected_bytes) = fixture().await;
    let response = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7}"#,
            ))
            .unwrap(),
    )
    .await;
    let created = body(response).await;
    let old_url = created["url"].as_str().unwrap().to_owned();
    let old_token = old_url.rsplit('/').next().unwrap().to_owned();
    let id = created["grant"]["id"].as_str().unwrap();
    let invalid = router(app.clone())
        .oneshot(
            Request::patch(format!("/api/admin/outbound-grants/{id}"))
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"rotate":true,"extend_days":7}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let rotated = router(app.clone())
        .oneshot(
            Request::patch(format!("/api/admin/outbound-grants/{id}"))
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"rotate":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotated.status(), StatusCode::OK);
    let rotated = body(rotated).await;
    let new_url = rotated["url"].as_str().unwrap();
    assert_ne!(new_url, old_url);
    assert_eq!(
        router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{old_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let extended = router(app.clone())
        .oneshot(
            Request::patch(format!("/api/admin/outbound-grants/{id}"))
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"extend_days":7}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(extended.status(), StatusCode::OK);
    assert!(body(extended).await["expires_at"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn exhausted_grant_is_not_available_for_a_second_download() {
    let (_directory, app, cookie, expected_bytes) = fixture().await;
    let response = settled_grant_response(
        app.clone(),
        &cookie,
            Request::post("/api/admin/outbound-grants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"link_id":"link","upload_id":"upload","file_index":0,"expires_days":7,"max_downloads":1}"#,
                ))
            .unwrap(),
        )
        .await;
    let created = body(response).await;
    assert_eq!(created["grant"]["max_downloads"], 1);
    let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();
    let first = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        first.into_body().collect().await.unwrap().to_bytes(),
        expected_bytes
    );
    // The record lands after the body's last frame is handed off, on a
    // spawned task; a second admission must observe it (finding 490).
    let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let downloads = app
                .store
                .outbound_grant_by_id(&grant_id)
                .unwrap()
                .unwrap()
                .downloads;
            if downloads == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the completed download was not recorded");
    let second = router(app)
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn password_grant_gates_metadata_file_receipt_and_evidence() {
    let (_directory, app, cookie, expected_bytes) = fixture().await;
    let response = settled_grant_response(
        app.clone(),
        &cookie,
            Request::post("/api/admin/outbound-grants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"link_id":"link","upload_id":"upload","file_index":0,"password":"correct horse","expires_days":7}"#,
                ))
            .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let created = body(response).await;
    assert_eq!(created["grant"]["has_password"], true);
    assert!(created["grant"].get("password_hash").is_none());
    let grant_id = created["grant"]["id"].as_str().unwrap().to_owned();
    let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();

    let metadata = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
    let metadata = body(metadata).await;
    assert_eq!(
        metadata,
        json!({ "has_password": true, "authorized": false })
    );
    let paged = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}?offset=0&limit=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(paged.status(), StatusCode::OK);
    assert_eq!(
        body(paged).await,
        json!({ "has_password": true, "authorized": false })
    );

    for suffix in ["/file", "/receipt", "/bundle", "/batch"] {
        let mut request = Request::get(format!("/api/s/{token}{suffix}"));
        if matches!(suffix, "/file" | "/bundle" | "/batch") {
            request =
                request.extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))));
        }
        assert_eq!(
            router(app.clone())
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    let wrong = router(app.clone())
        .oneshot(
            Request::post(format!("/api/s/{token}/verify"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"wrong"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    let verified = router(app.clone())
        .oneshot(
            Request::post(format!("/api/s/{token}/verify"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"correct horse"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verified.status(), StatusCode::OK);
    let set_cookie = verified.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(set_cookie.starts_with("votport_s_"));
    assert!(set_cookie.contains(&format!("; Path=/api/s/{token}; HttpOnly; SameSite=Lax;")));
    let grant_cookie = set_cookie.split(';').next().unwrap().to_owned();

    let verdicts: Vec<_> = app
        .store
        .audit_export(Some(""), 0, 0, 100)
        .unwrap()
        .into_iter()
        .filter(|row| {
            row.subject == grant_id
                && matches!(row.event.as_str(), "link_password_failed" | "link_unlocked")
        })
        .collect();
    assert_eq!(
        verdicts
            .iter()
            .map(|row| row.event.as_str())
            .collect::<Vec<_>>(),
        ["link_password_failed", "link_unlocked"]
    );
    assert!(verdicts.iter().all(|row| {
        row.actor.is_empty()
            && row.detail["kind"] == "delivery"
            && row.detail["client_ip"] == "127.0.0.1"
            && !row.detail.to_string().contains("correct horse")
            && !row.detail.to_string().contains(token)
            && !row.detail.to_string().contains("$argon2")
    }));
    assert_ne!(grant_id, token);

    let holder = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes(),
    );
    let challenge_request = |cookie: &str| {
        Request::post(format!("/api/s/{token}/evidence-challenge"))
            .header("content-type", "application/json")
            .header("cookie", cookie)
            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 4))))
            .body(Body::from(json!({"holder": holder}).to_string()))
            .unwrap()
    };
    let forged_cookie = format!("{}=forged", grant_cookie_name(&grant_id));
    for denied_cookie in ["", cookie.as_str(), forged_cookie.as_str()] {
        let response = router(app.clone())
            .oneshot(challenge_request(denied_cookie))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body(response).await["error"], "delivery password required");
    }
    let response = router(app.clone())
        .oneshot(challenge_request(&grant_cookie))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let signed: crate::delivery_protocol::SignedChallenge =
        serde_json::from_value(body(response).await).unwrap();
    assert!(signed.verify(&app.signer.public_hex));
    assert_eq!(signed.challenge.grant_id, grant_id);
    assert_eq!(signed.challenge.holder, holder);
    assert_eq!(signed.challenge.origin, "https://drop.example.com");
    assert_eq!(
        signed.challenge.manifest,
        app.store.delivery_manifest(&grant_id).unwrap()
    );

    let metadata = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}"))
                .header("cookie", &grant_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
    assert_eq!(body(metadata).await["label"], "received.bin");
    let paged = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}?offset=0&limit=1"))
                .header("cookie", &grant_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(paged.status(), StatusCode::OK);
    assert_eq!(body(paged).await["files_total"], 1);

    let file = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/file"))
                .header("cookie", &grant_cookie)
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(file.status(), StatusCode::OK);
    assert_eq!(
        file.into_body().collect().await.unwrap().to_bytes(),
        expected_bytes
    );

    let bundle = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/bundle"))
                .header("cookie", &grant_cookie)
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bundle.status(), StatusCode::OK);
    assert_eq!(bundle.headers()[header::CONTENT_TYPE], "application/zip");
    assert_eq!(
        bundle.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"deliverables.zip\""
    );
    assert!(bundle.headers().get(header::ACCEPT_RANGES).is_none());
    let bundle = bundle.into_body().collect().await.unwrap().to_bytes();
    let entries = zip_entries(&bundle);
    assert_eq!(
        entries
            .keys()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>(),
        ["received.bin"].into_iter().collect()
    );
    assert_eq!(entries["received.bin"], expected_bytes);
    assert!(!entries.keys().any(|name| name.contains("receipt")));
    assert!(!entries.contains_key("manifest.json"));
    assert!(app.outbound_active.lock().unwrap().is_empty());

    let receipt = router(app)
        .oneshot(
            Request::get(format!("/api/s/{token}/receipt"))
                .header("cookie", &grant_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(receipt.status(), StatusCode::OK);
}

#[tokio::test]
async fn indexed_file_downloads_charge_fractional_grant_units() {
    let (_directory, app, cookie, first) = fixture().await;
    for (path, bytes) in [
        ("rate/one.bin", first.as_slice()),
        ("rate/two.bin", b"second file".as_slice()),
    ] {
        let response = router(app.clone())
            .oneshot(
                Request::post(format!("/api/admin/outbound-files?path={path}"))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(bytes.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let created = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"paths":["rate/one.bin","rate/two.bin"]}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let token = body(created).await["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();

    // Leave two full units. Each indexed download is answered by two
    // requests, the admission and the redirected stream, and each
    // request must cost half a unit; a full-unit endpoint wiring would
    // refuse the second download's replay.
    let key = hash_token(&token);
    for _ in 0..1_998 {
        assert!(app.outbound_rate.allow(&key));
    }
    for (index, expected) in [first, b"second file".to_vec()].into_iter().enumerate() {
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/files/{index}"))
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        31,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            expected
        );
    }
}

#[tokio::test]
async fn library_grants_reject_nonportable_names_before_source_access() {
    let (_directory, app, cookie, _) = fixture().await;
    let library = library_root(&app, "");
    std::fs::create_dir_all(&library).unwrap();
    for names in [
        vec!["Café.mov", "Cafe\u{301}.mov"],
        vec!["ΣΊΣΥΦΟΣ.mov", "σίσυφος.mov"],
        vec!["ſtraße.mov", "strasse.mov"],
        vec!["I.mov", "ı.mov"],
        vec!["XML:EDL/clip.mov"],
        vec!["clip.mov."],
    ] {
        for materialized in [false, true] {
            if materialized {
                for (index, name) in names.iter().enumerate() {
                    let path = library.join(name);
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    std::fs::write(path, [index as u8]).unwrap();
                }
            }
            let response = settled_grant_response(
                app.clone(),
                &cookie,
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"paths":names}).to_string()))
                    .unwrap(),
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{names:?}"
            );
            assert!(app.store.outbound_grants("").unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn library_upload_list_multi_file_grant_and_mutation_failure() {
    let (_directory, app, cookie, first) = fixture().await;
    let upload = |path: &str, bytes: &[u8]| {
        let request = Request::post(format!("/api/admin/outbound-files?path={path}"))
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .body(Body::from(bytes.to_vec()))
            .unwrap();
        async { router(app.clone()).oneshot(request).await.unwrap() }
    };
    assert_eq!(
        upload("project/one.bin", &first).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        upload("project/two.bin", b"second file").await.status(),
        StatusCode::OK
    );
    let audits = app.store.audit_export(None, 0, 0, 100).unwrap();
    assert!(audits.iter().any(|row| {
        row.event == "outbound_file_uploaded"
            && row.actor == "local"
            && row.subject == "project/one.bin"
            && row.detail["path"] == "project/one.bin"
            && row.detail["bytes"] == first.len()
    }));

    let listed = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-files?directory=project")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = body(listed).await;
    assert_eq!(listed["files"].as_array().unwrap().len(), 2);
    assert!(listed["files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|file| file["path"] == "project/one.bin"));

    for path in ["../escape", "project/../escape", "project//escape"] {
        assert_eq!(
            upload(path, b"bad").await.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            app.config.outbound_dir.join("project"),
            app.config.outbound_dir.join("link"),
        )
        .unwrap();
        assert_eq!(
            upload("link/escape", b"bad").await.status(),
            StatusCode::CONFLICT
        );
    }
    assert_eq!(
        upload("project/one.bin", b"overwrite").await.status(),
        StatusCode::CONFLICT
    );

    let duplicate = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"paths":["project/one.bin","project/one.bin"]}"#,
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let response = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"paths":["project/one.bin","project/two.bin"],"label":"project"}"#,
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let created = body(response).await;
    assert_eq!(created["grant"]["file_count"], 2);
    assert_eq!(created["grant"]["files_truncated"], false);
    assert_eq!(created["grant"]["files"].as_array().unwrap().len(), 2);
    let token = created["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let metadata = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let metadata = body(metadata).await;
    assert_eq!(metadata["files"].as_array().unwrap().len(), 2);
    assert!(metadata["receipt_url"].is_null());
    assert!(metadata["files"]
        .as_array()
        .unwrap()
        .iter()
        .all(|file| file["receipt_url"].is_null()));
    // The unpaged shape sums every file too, not the first file's bytes.
    let expected: u64 = metadata["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["bytes"].as_u64().unwrap())
        .sum();
    assert_eq!(metadata["total_bytes"].as_u64().unwrap(), expected);
    for (offset, expected_name, expected_url, has_more) in [
        (
            0,
            "project/one.bin",
            format!("/api/s/{token}/files/0"),
            true,
        ),
        (
            1,
            "project/two.bin",
            format!("/api/s/{token}/files/1"),
            false,
        ),
    ] {
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}?offset={offset}&limit=1"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let page = body(response).await;
        assert_eq!(page["files_total"], 2);
        // The byte total covers the whole grant, not only this page.
        assert_eq!(page["total_bytes"].as_u64().unwrap(), expected);
        assert_eq!(page["offset"], offset);
        assert_eq!(page["limit"], 1);
        assert_eq!(page["has_more"], has_more);
        assert_eq!(page["files"].as_array().unwrap().len(), 1);
        assert_eq!(page["files"][0]["name"], expected_name);
        assert_eq!(page["files"][0]["download_url"], expected_url);
        assert!(page["receipt_url"].is_null());
        assert!(page["files"][0]["receipt_url"].is_null());
    }
    let end = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}?offset=2&limit=1"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(end.status(), StatusCode::OK);
    let end = body(end).await;
    assert_eq!(end["files_total"], 2);
    assert_eq!(end["offset"], 2);
    assert_eq!(end["files"], json!([]));
    assert_eq!(end["has_more"], false);
    assert_eq!(metadata["batch_url"], format!("/api/s/{token}/batch"));
    let batch = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/batch"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(batch.status(), StatusCode::OK);
    assert_eq!(
        batch.headers()[header::CONTENT_TYPE],
        "application/vnd.votport.batch"
    );
    assert_eq!(batch.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        batch.headers()[header::CONTENT_LENGTH],
        (first.len() + 11).to_string()
    );
    assert_eq!(
        batch.into_body().collect().await.unwrap().to_bytes(),
        [first.clone(), b"second file".to_vec()].concat()
    );
    assert!(app.outbound_active.lock().unwrap().is_empty());
    let bundle = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/bundle"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 5))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bundle.status(), StatusCode::OK);
    let bundle = bundle.into_body().collect().await.unwrap().to_bytes();
    let entries = zip_entries(&bundle);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries["project/one.bin"], first);
    assert_eq!(entries["project/two.bin"], b"second file");
    assert!(!entries.keys().any(|name| name.contains("receipt")));
    assert!(!entries.contains_key("manifest.json"));
    assert!(app.outbound_active.lock().unwrap().is_empty());
    for (index, expected) in [first, b"second file".to_vec()].into_iter().enumerate() {
        let file = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/files/{index}"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 3))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(file.status(), StatusCode::OK);
        assert_eq!(
            file.into_body().collect().await.unwrap().to_bytes(),
            expected
        );
        let receipt = router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/receipts/{index}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt.status(), StatusCode::NOT_FOUND);
    }
    std::fs::write(app.config.outbound_dir.join("project/one.bin"), b"mutated").unwrap();
    let batch = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/batch"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 7))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(batch.status(), StatusCode::NOT_FOUND);
    assert!(
        std::fs::read_dir(app.config.data_dir.join("outbound.stage"))
            .unwrap()
            .next()
            .is_none()
    );
    let mutated = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/files/0"))
                .header(header::RANGE, "bytes=0-1")
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 4))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mutated.status(), StatusCode::NOT_FOUND);
    let bundle = router(app)
        .oneshot(
            Request::get(format!("/api/s/{token}/bundle"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 6))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bundle.status(), StatusCode::NOT_FOUND);
}

fn outbound_query(pairs: &[(&str, &str)]) -> String {
    let mut url = reqwest::Url::parse("http://localhost/api/admin/outbound-files").unwrap();
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
    }
    format!("{}?{}", url.path(), url.query().unwrap())
}

fn outbound_file_path(path: &str) -> String {
    outbound_query(&[("path", path)])
}

#[tokio::test]
async fn library_uploads_refuse_nonportable_names_before_staging() {
    let (_directory, app, cookie, _) = fixture().await;
    let portable = "unicode/Café.mov";
    let response = router(app.clone())
        .oneshot(
            Request::post(outbound_file_path(portable))
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::from("portable"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read(app.config.outbound_dir.join(portable)).unwrap(),
        b"portable"
    );

    let invalid = [
        "XML:EDL/clip.mov",
        "trailing.",
        "trailing ",
        "CON.txt",
        "a<b>.mov",
        "\u{ff0e}/clip.mov",
        "\u{202e}fdp.exe",
    ];
    for (index, path) in invalid.iter().enumerate() {
        let response = router(app.clone())
            .oneshot(
                Request::post(outbound_file_path(path))
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from("rejected"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{path}"
        );
        let destination = app.config.outbound_dir.join(path);
        assert!(!destination.exists(), "{path}");
        let upload_id = format!("{index:064x}");
        let stage = outbound_stage_name(&destination, &upload_id);
        assert!(
            !destination.parent().unwrap().join(stage).exists(),
            "{path}"
        );
    }

    for (index, path) in invalid.iter().enumerate() {
        let upload_id = format!("{:064x}", index + invalid.len());
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                path,
                &upload_id,
                0,
                7,
                8,
                b"rejected",
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{path}"
        );
        let destination = app.config.outbound_dir.join(path);
        assert!(!destination.exists(), "{path}");
        let stage = outbound_stage_name(&destination, &upload_id);
        assert!(
            !destination.parent().unwrap().join(stage).exists(),
            "{path}"
        );
    }
}

#[tokio::test]
async fn library_255_byte_directory_remains_browseable_and_selectable() {
    let (_directory, app, cookie, _) = fixture().await;
    let directory = "d".repeat(255);
    let file = format!("{directory}/clip.mov");
    let response = router(app.clone())
        .oneshot(
            Request::post(outbound_file_path(&file))
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::from("portable"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let listed = router(app.clone())
        .oneshot(
            Request::get(outbound_query(&[("directory", &directory)]))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(body(listed).await["files"][0]["path"], file);

    let paged = router(app.clone())
        .oneshot(
            Request::get(outbound_query(&[("directory", &directory), ("limit", "1")]))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(paged.status(), StatusCode::OK);
    let paged = body(paged).await;
    assert_eq!(paged["files"][0]["path"], file);
    assert_eq!(paged["truncated"], false);

    let selected = router(app.clone())
        .oneshot(
            Request::get(outbound_query(&[("selection", &directory)]))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(selected.status(), StatusCode::OK);
    assert_eq!(body(selected).await["files"][0]["path"], file);

    let grant = settled_grant_response(
        app,
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "directory": directory,
                    "label": "long directory",
                    "expires_days": 1
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(grant.status(), StatusCode::OK);
}

#[tokio::test]
async fn library_grant_restore_requires_outbound_volume() {
    let (directory, app, cookie, expected) = fixture().await;
    let source = app.config.outbound_dir.join("restore.bin");
    std::fs::write(&source, &expected).unwrap();
    let created = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"paths":["restore.bin"],"label":"restore"}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::OK);
    let token = body(created).await["url"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();

    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(&token))
        .unwrap()
        .unwrap();
    assert!(grant.files[0].receipt_b64.is_empty());
    let mut cached = grant.files[0].clone();
    cached.receipt_b64 = base64::prelude::BASE64_STANDARD.encode(
        app.signer
            .encode(
                &object_id(&expected),
                [61; 16],
                PublishObservation {
                    incarnation: [62; 16],
                    sequence: 1,
                },
                vot_sdk_file::CommitProfile::Fast,
                vot_sdk_file::NasContract::Unqualified,
            )
            .unwrap(),
    );
    assert!(
        source_info_indexed_with_file(&app, &grant, 0, Some(&cached))
            .unwrap()
            .receipt
            .is_none()
    );

    let receipt = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/receipts/0"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(receipt.status(), StatusCode::NOT_FOUND);

    let snapshot = directory.path().join("backup.db");
    app.store.backup_into(&snapshot).unwrap();
    let restored_directory = tempfile::tempdir().unwrap();
    let restored_data = restored_directory.path().join("data");
    std::fs::create_dir_all(&restored_data).unwrap();
    std::fs::copy(&snapshot, restored_data.join("votport.db")).unwrap();
    std::fs::copy(
        directory.path().join("data/receipt.key"),
        restored_data.join("receipt.key"),
    )
    .unwrap();
    let restored = crate::api::testing::build(restored_directory.path());

    let unavailable = router(restored.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}/files/0"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::NOT_FOUND);

    std::fs::create_dir_all(&restored.config.outbound_dir).unwrap();
    std::fs::copy(&source, restored.config.outbound_dir.join("restore.bin")).unwrap();
    let available = router(restored)
        .oneshot(
            Request::get(format!("/api/s/{token}/files/0"))
                .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(available.status(), StatusCode::OK);
    assert_eq!(
        available.into_body().collect().await.unwrap().to_bytes(),
        expected
    );
}

#[tokio::test]
async fn library_upload_limit_cleans_temporary_file() {
    let directory = tempfile::tempdir().unwrap();
    let mut app = crate::api::testing::build(directory.path());
    Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 3;
    let cookie = admin_cookie(&app);
    let response = router(app.clone())
        .oneshot(
            Request::post("/api/admin/outbound-files?path=too-large.bin")
                .header("cookie", cookie)
                .header("x-votport", "1")
                .body(Body::from("four"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!app.config.outbound_dir.join("too-large.bin").exists());
    assert!(std::fs::read_dir(&app.config.outbound_dir)
        .map(|entries| entries
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().ends_with(".stage")))
        .unwrap_or(true));
}

#[cfg(unix)]
#[tokio::test]
async fn whole_file_upload_stage_is_owned_while_a_slow_body_is_active() {
    use std::time::{Duration, SystemTime};

    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let cookie = admin_cookie(&app);
    let (sender, receiver) = mpsc::channel::<Result<Bytes, std::io::Error>>(2);
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async {
        receiver.recv().await.map(|chunk| (chunk, receiver))
    });
    let request = Request::post("/api/admin/outbound-files?path=slow.bin")
        .header("cookie", cookie)
        .header("x-votport", "1")
        .body(Body::from_stream(stream))
        .unwrap();
    let upload = tokio::spawn(router(app.clone()).oneshot(request));

    sender.send(Ok(Bytes::from_static(b"first"))).await.unwrap();
    let stage = tokio::time::timeout(Duration::from_secs(2), async {
        for _ in 0..200 {
            if let Some(stage) = std::fs::read_dir(&app.config.outbound_dir)
                .unwrap()
                .flatten()
                .map(|entry| entry.path())
                .find(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| {
                            name.starts_with(".vot-outbound-") && name.ends_with(".stage")
                        })
                })
                .filter(|stage| {
                    std::fs::read(stage).is_ok_and(|contents| contents.as_slice() == b"first")
                })
            {
                return stage;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("whole-file upload did not write its first chunk");
    })
    .await
    .expect("whole-file upload did not create its stage");
    let name = stage.file_name().unwrap().to_str().unwrap();
    let (stripe, digest) = name
        .strip_prefix(".vot-outbound-")
        .and_then(|name| name.strip_suffix(".stage"))
        .and_then(|name| name.split_once('-'))
        .expect("whole-file upload used an unowned stage name");
    assert_eq!(
        stripe,
        format!(
            "{:02x}",
            outbound_upload_stripe(&app.config.outbound_dir.join("slow.bin"))
        )
    );
    assert!(stripe.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(valid_outbound_upload_id(digest));

    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    let now = old + Duration::from_secs(app.config.session_idle_secs);
    std::fs::File::open(&stage)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(old))
        .unwrap();
    sweep_upload_stages(&app, now);
    assert!(stage.exists(), "sweeper removed an active upload stage");

    sender
        .send(Ok(Bytes::from_static(b"second")))
        .await
        .unwrap();
    drop(sender);
    let response = tokio::time::timeout(Duration::from_secs(2), upload)
        .await
        .expect("whole-file upload did not finish")
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read(app.config.outbound_dir.join("slow.bin")).unwrap(),
        b"firstsecond"
    );
    assert!(!stage.exists());
}

#[tokio::test]
async fn library_grant_caps_the_aggregate_selection_size() {
    let directory = tempfile::tempdir().unwrap();
    let mut app = crate::api::testing::build(directory.path());
    Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 5;
    std::fs::write(app.config.outbound_dir.join("one.bin"), b"one").unwrap();
    std::fs::write(app.config.outbound_dir.join("two.bin"), b"two").unwrap();
    let cookie = admin_cookie(&app);
    let response = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"paths":["one.bin","two.bin"]}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

fn chunk_request(
    cookie: &str,
    path: &str,
    upload_id: &str,
    start: u64,
    end: u64,
    total: u64,
    bytes: &[u8],
) -> Request<Body> {
    Request::post(outbound_file_path(path))
        .header("cookie", cookie)
        .header("x-votport", "1")
        .header(OUTBOUND_UPLOAD_ID, upload_id)
        .header(
            header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{total}"),
        )
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(Body::from(bytes.to_vec()))
        .unwrap()
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn chunk_checkpoint_refuses_a_file_that_cannot_sync() {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .await
        .unwrap();
    file.write_all(b"chunk").await.unwrap();
    let response = sync_outbound_chunk(&mut file)
        .await
        .unwrap_err()
        .into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn resumable_library_upload_keeps_partial_files_unpublished() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    let upload_id = "a".repeat(64);
    let response = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "partial.bin",
            &upload_id,
            0,
            2,
            6,
            b"abc",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let progress = body(response).await;
    assert_eq!(progress["complete"], false);
    assert_eq!(progress["offset"], 3);
    assert_eq!(progress["bytes"], 6);
    assert!(!app.config.outbound_dir.join("partial.bin").exists());
    assert_eq!(
        std::fs::read(app.config.outbound_dir.join(outbound_stage_name(
            &app.config.outbound_dir.join("partial.bin"),
            &upload_id,
        )))
        .unwrap(),
        b"abc"
    );
    assert!(app.store.audit_export(None, 0, 0, 100).unwrap().is_empty());
}

#[tokio::test]
async fn resumable_library_upload_resynchronizes_and_audits_completion() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    let upload_id = "b".repeat(64);
    let first = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "resume.bin",
            &upload_id,
            0,
            2,
            6,
            b"abc",
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let mismatch = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "resume.bin",
            &upload_id,
            0,
            2,
            6,
            b"abc",
        ))
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::OK);
    assert_eq!(body(mismatch).await["offset"], 3);

    let complete = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "resume.bin",
            &upload_id,
            3,
            5,
            6,
            b"def",
        ))
        .await
        .unwrap();
    assert_eq!(complete.status(), StatusCode::OK);
    let complete = body(complete).await;
    assert_eq!(complete["complete"], true);
    assert_eq!(complete["offset"], 6);
    assert_eq!(
        std::fs::read(app.config.outbound_dir.join("resume.bin")).unwrap(),
        b"abcdef"
    );
    let stage = app.config.outbound_dir.join(outbound_stage_name(
        &app.config.outbound_dir.join("resume.bin"),
        &upload_id,
    ));
    assert!(vot_platform_fs::same_file_regular(
        &stage,
        &app.config.outbound_dir.join("resume.bin")
    )
    .unwrap());
    let audits = app.store.audit_export(None, 0, 0, 100).unwrap();
    assert_eq!(
        audits
            .iter()
            .filter(|row| row.event == "outbound_file_uploaded")
            .count(),
        1
    );
    assert_eq!(audits[0].detail["bytes"], 6);
}

#[tokio::test]
async fn resumable_library_upload_replays_only_its_published_witness() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    let upload_id = "1".repeat(64);
    for (start, end, bytes) in [(0, 2, b"abc".as_slice()), (3, 5, b"def".as_slice())] {
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "replay.bin",
                &upload_id,
                start,
                end,
                6,
                bytes,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let destination = app.config.outbound_dir.join("replay.bin");
    let stage = app
        .config
        .outbound_dir
        .join(outbound_stage_name(&destination, &upload_id));
    let uploaded = || {
        app.store
            .audit_export(None, 0, 0, 100)
            .unwrap()
            .into_iter()
            .filter(|row| row.event == "outbound_file_uploaded")
            .count()
    };
    assert!(vot_platform_fs::same_file_regular(&stage, &destination).unwrap());
    let audits_before = uploaded();

    // The final response may be lost after publication. The same upload
    // id and hardlink witness make the retry an idempotent completion.
    let replay = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "replay.bin",
            &upload_id,
            3,
            5,
            6,
            b"def",
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(body(replay).await["complete"], true);
    assert_eq!(uploaded(), audits_before);
    assert_eq!(std::fs::read(&destination).unwrap(), b"abcdef");

    // A different upload id has no witness and cannot claim the name.
    let foreign = "2".repeat(64);
    let response = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "replay.bin",
            &foreign,
            0,
            5,
            6,
            b"abcdef",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(!app
        .config
        .outbound_dir
        .join(outbound_stage_name(&destination, &foreign))
        .exists());

    // Matching bytes are still rejected when the caller's declared total
    // differs from the published file.
    let response = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "replay.bin",
            &upload_id,
            0,
            6,
            7,
            b"abcdefg",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // Replacing the destination breaks the hardlink witness, even at the
    // same size, so a stale final reply cannot bless a new file.
    std::fs::remove_file(&destination).unwrap();
    std::fs::write(&destination, b"ghijkl").unwrap();
    let response = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "replay.bin",
            &upload_id,
            3,
            5,
            6,
            b"def",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(stage.exists());
    assert_eq!(uploaded(), audits_before);
}

#[cfg(unix)]
#[test]
fn completed_stage_expiry_starts_at_publication() {
    use std::time::{Duration, SystemTime};

    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let identity = auth::AdminIdentity::local_admin();
    let upload_id = "4".repeat(64);
    let destination = app.config.outbound_dir.join("completion-time.bin");
    let stage = app
        .config
        .outbound_dir
        .join(outbound_stage_name(&destination, &upload_id));
    std::fs::write(&stage, b"abcdef").unwrap();
    std::fs::File::open(&stage).unwrap().sync_all().unwrap();
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    std::fs::File::open(&stage)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(old))
        .unwrap();

    let complete = publish_outbound_stage(
        &app,
        &identity,
        &stage,
        &destination,
        "completion-time.bin",
        6,
    )
    .unwrap();
    assert_eq!(complete.status(), StatusCode::OK);
    let published_at = std::fs::metadata(&stage).unwrap().modified().unwrap();
    assert!(published_at > old);

    let before_expiry = published_at
        .checked_add(Duration::from_secs(
            app.config.session_idle_secs.saturating_sub(1),
        ))
        .unwrap();
    sweep_upload_stages(&app, before_expiry);
    assert!(stage.exists());
    sweep_upload_stages(
        &app,
        published_at
            .checked_add(Duration::from_secs(app.config.session_idle_secs))
            .unwrap(),
    );
    assert!(!stage.exists());
    assert_eq!(std::fs::read(destination).unwrap(), b"abcdef");
}

#[cfg(unix)]
#[test]
fn publication_refresh_failure_keeps_destination_unpublished() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let identity = auth::AdminIdentity::local_admin();
    let destination = app.config.outbound_dir.join("refresh-failure.bin");
    let stage = app
        .config
        .outbound_dir
        .join(outbound_stage_name(&destination, &"5".repeat(64)));
    std::os::unix::fs::symlink(app.config.outbound_dir.join("missing-stage-target"), &stage)
        .unwrap();

    assert!(publish_outbound_stage(
        &app,
        &identity,
        &stage,
        &destination,
        "refresh-failure.bin",
        0,
    )
    .is_err());
    assert!(matches!(
        std::fs::symlink_metadata(&destination),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert!(std::fs::symlink_metadata(&stage)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[cfg(unix)]
#[tokio::test]
async fn resumable_library_upload_rejects_symlink_witnesses() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    let upload_id = "3".repeat(64);
    for (start, end, bytes) in [(0, 2, b"abc".as_slice()), (3, 5, b"def".as_slice())] {
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "symlink.bin",
                &upload_id,
                start,
                end,
                6,
                bytes,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let destination = app.config.outbound_dir.join("symlink.bin");
    let stage = app
        .config
        .outbound_dir
        .join(outbound_stage_name(&destination, &upload_id));
    let external = app.config.outbound_dir.join("symlink-target.bin");
    std::fs::remove_file(&destination).unwrap();
    std::fs::write(&external, b"abcdef").unwrap();
    std::os::unix::fs::symlink(&external, &destination).unwrap();
    let response = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "symlink.bin",
            &upload_id,
            3,
            5,
            6,
            b"def",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(stage.exists());
    std::fs::remove_file(&destination).unwrap();
    std::fs::write(&destination, b"abcdef").unwrap();
    std::fs::remove_file(&stage).unwrap();
    std::os::unix::fs::symlink(&destination, &stage).unwrap();
    let response = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "symlink.bin",
            &upload_id,
            3,
            5,
            6,
            b"def",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(std::fs::symlink_metadata(&stage)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[tokio::test]
async fn resumable_library_upload_rolls_back_an_invalid_chunk() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    let upload_id = "e".repeat(64);
    let first = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "rollback.bin",
            &upload_id,
            0,
            2,
            6,
            b"abc",
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let invalid = Request::post("/api/admin/outbound-files?path=rollback.bin")
        .header("cookie", &cookie)
        .header("x-votport", "1")
        .header(OUTBOUND_UPLOAD_ID, &upload_id)
        .header(header::CONTENT_RANGE, "bytes 3-5/6")
        .header(header::CONTENT_LENGTH, 3)
        .body(Body::from("defg"))
        .unwrap();
    let invalid = router(app.clone()).oneshot(invalid).await.unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert!(!app.config.outbound_dir.join("rollback.bin").exists());
    let stage = app.config.outbound_dir.join(outbound_stage_name(
        &app.config.outbound_dir.join("rollback.bin"),
        &upload_id,
    ));
    assert_eq!(std::fs::read(stage).unwrap(), b"abc");
}

#[tokio::test]
async fn resumable_library_upload_separates_sibling_stages_with_same_id() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    let upload_id = "f".repeat(64);
    for (path, bytes) in [("sibling-a.bin", b"abc"), ("sibling-b.bin", b"xyz")] {
        let response = router(app.clone())
            .oneshot(chunk_request(&cookie, path, &upload_id, 0, 2, 6, bytes))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let first = app.config.outbound_dir.join(outbound_stage_name(
        &app.config.outbound_dir.join("sibling-a.bin"),
        &upload_id,
    ));
    let second = app.config.outbound_dir.join(outbound_stage_name(
        &app.config.outbound_dir.join("sibling-b.bin"),
        &upload_id,
    ));
    assert_ne!(first, second);
    assert_eq!(std::fs::read(first).unwrap(), b"abc");
    assert_eq!(std::fs::read(second).unwrap(), b"xyz");
}

#[tokio::test]
async fn an_unacknowledged_stage_tail_is_replayed_instead_of_trusted() {
    for stale in [b"wrong".as_slice(), b"wrong data"] {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "e".repeat(64);
        let path = app.config.outbound_dir.join("late.bin");
        let stage = app
            .config
            .outbound_dir
            .join(outbound_stage_name(&path, &upload_id));
        std::fs::write(&stage, stale).unwrap();
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie, "late.bin", &upload_id, 0, 4, 10, b"whole",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let progress = body(response).await;
        assert_eq!(progress["complete"], false);
        assert_eq!(progress["offset"], 5);
        assert!(!path.exists());
        assert_eq!(std::fs::read(&stage).unwrap(), b"whole");
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie, "late.bin", &upload_id, 5, 9, 10, b" file",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body(response).await["complete"], true);
        assert_eq!(std::fs::read(&path).unwrap(), b"whole file");
        assert!(vot_platform_fs::same_file_regular(&stage, &path).unwrap());
    }
}

#[tokio::test]
async fn chunk_replay_preserves_the_acknowledged_prefix_and_rewinds_missing_bytes() {
    for (stale, expected_status, expected_offset) in [
        (b"wholewrong".as_slice(), StatusCode::OK, 10),
        (b"who".as_slice(), StatusCode::CONFLICT, 3),
    ] {
        let (_directory, app, cookie, _bytes) = fixture().await;
        let upload_id = "e".repeat(64);
        let path = app.config.outbound_dir.join("prefix.bin");
        let stage = path
            .parent()
            .unwrap()
            .join(outbound_stage_name(&path, &upload_id));
        std::fs::write(&stage, stale).unwrap();
        let response = router(app.clone())
            .oneshot(chunk_request(
                &cookie,
                "prefix.bin",
                &upload_id,
                5,
                9,
                10,
                b" file",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), expected_status);
        assert_eq!(body(response).await["offset"], expected_offset);
        if expected_status == StatusCode::CONFLICT {
            assert_eq!(std::fs::read(&stage).unwrap(), b"who");
            let response = router(app.clone())
                .oneshot(chunk_request(
                    &cookie,
                    "prefix.bin",
                    &upload_id,
                    3,
                    9,
                    10,
                    b"le file",
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(body(response).await["complete"], true);
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"whole file");
    }
}

#[tokio::test]
async fn stages_from_before_durable_acknowledgements_are_not_resumed() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    let upload_id = "e".repeat(64);
    let path = app.config.outbound_dir.join("older.bin");
    let mut old_hash = Sha256::new();
    old_hash.update(path.to_string_lossy().as_bytes());
    old_hash.update([0]);
    old_hash.update(upload_id.as_bytes());
    let old_stage = path.parent().unwrap().join(format!(
        ".vot-outbound-{:02x}-{}.stage",
        outbound_upload_stripe(&path),
        hex::encode(old_hash.finalize()),
    ));
    std::fs::write(&old_stage, b"wrong").unwrap();
    let response = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "older.bin",
            &upload_id,
            5,
            9,
            10,
            b" file",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(body(response).await["offset"], 0);
    assert!(!path.exists());
    assert_eq!(std::fs::read(&old_stage).unwrap(), b"wrong");
}

#[tokio::test]
async fn a_refused_chunk_body_is_read_through_before_the_answer() {
    // The body arrives in pieces and the handler must pull every one
    // before answering, or a client mid-write sees a reset connection
    // instead of the 422 (here: a path the library refuses).
    let (_directory, app, cookie, _bytes) = fixture().await;
    let pulled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&pulled);
    let pieces: Vec<Result<Bytes, std::io::Error>> =
        (0..8).map(|_| Ok(Bytes::from(vec![7u8; 1024]))).collect();
    let body = Body::from_stream(futures_util::stream::iter(pieces).inspect(move |_| {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }));
    let response = router(app.clone())
        .oneshot(
            Request::post("/api/admin/outbound-files?path=../escape.bin")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header(OUTBOUND_UPLOAD_ID, "d".repeat(64))
                .header(header::CONTENT_RANGE, "bytes 0-8191/16384")
                .header(header::CONTENT_LENGTH, 8192)
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(pulled.load(std::sync::atomic::Ordering::SeqCst), 8);
}

#[tokio::test]
async fn resumable_library_upload_rejects_limits_before_staging() {
    let directory = tempfile::tempdir().unwrap();
    let mut app = crate::api::testing::build(directory.path());
    Arc::get_mut(&mut app).unwrap().config.max_upload_bytes = 5;
    let cookie = admin_cookie(&app);
    let upload_id = "c".repeat(64);
    let response = router(app.clone())
        .oneshot(chunk_request(
            &cookie,
            "limited.bin",
            &upload_id,
            0,
            5,
            6,
            b"abcdef",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!app.config.outbound_dir.join("limited.bin").exists());
    assert!(!app
        .config
        .outbound_dir
        .join(outbound_stage_name(
            &app.config.outbound_dir.join("limited.bin"),
            &upload_id,
        ))
        .exists());
    let mut headers = HeaderMap::new();
    headers.insert(OUTBOUND_UPLOAD_ID, HeaderValue::from_static("bad"));
    headers.insert(
        header::CONTENT_RANGE,
        HeaderValue::from_static("bytes 0-16777216/16777217"),
    );
    assert_eq!(
        parse_outbound_content_range(&headers).unwrap(),
        (0, 16_777_216, 16_777_217)
    );
}

#[tokio::test]
async fn resumable_library_upload_serializes_duplicate_chunks() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    let upload_id = "d".repeat(64);
    let first = chunk_request(&cookie, "concurrent.bin", &upload_id, 0, 2, 6, b"abc");
    let second = chunk_request(&cookie, "concurrent.bin", &upload_id, 0, 2, 6, b"xyz");
    let (first, second) = tokio::join!(
        router(app.clone()).oneshot(first),
        router(app.clone()).oneshot(second),
    );
    let statuses = [first.unwrap().status(), second.unwrap().status()];
    assert_eq!(statuses, [StatusCode::OK, StatusCode::OK]);
    assert_eq!(
        std::fs::metadata(app.config.outbound_dir.join(outbound_stage_name(
            &app.config.outbound_dir.join("concurrent.bin"),
            &upload_id,
        )))
        .unwrap()
        .len(),
        3
    );
    assert!(app
        .outbound_upload_locks
        .iter()
        .all(|lock| lock.try_lock().is_ok()));
}

#[cfg(unix)]
#[test]
fn expired_upload_stages_are_removed_without_touching_active_or_unowned_files() {
    use std::time::{Duration, SystemTime};

    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let root = &app.config.outbound_dir;
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    let now = old + Duration::from_secs(app.config.session_idle_secs);
    let write = |path: &Path, modified| {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"partial").unwrap();
        std::fs::File::open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
    };
    let stage = |path: &Path, id: &str| path.parent().unwrap().join(outbound_stage_name(path, id));
    let destination = root.join("project/expired.bin");
    let completed_destination = root.join("project/completed.bin");
    let completed_stage = stage(&completed_destination, &"0".repeat(64));
    write(&completed_stage, old);
    std::fs::hard_link(&completed_stage, &completed_destination).unwrap();
    let expired = stage(&destination, &"a".repeat(64));
    let abandoned = stage(&destination, &"b".repeat(64));
    let recent = stage(&destination, &"c".repeat(64));
    write(&expired, old);
    write(&abandoned, old);
    write(&recent, old + Duration::from_secs(1));
    let completed_stripe = outbound_upload_stripe(&completed_destination);
    let active_destination = (0..1000)
        .map(|i| root.join(format!("active-{i}.bin")))
        .find(|path| {
            let stripe = outbound_upload_stripe(path);
            stripe > 1
                && stripe != outbound_upload_stripe(&destination)
                && stripe != completed_stripe
        })
        .unwrap();
    let active = stage(&active_destination, &"d".repeat(64));
    write(&active, old);
    let guard = app.outbound_upload_locks[outbound_upload_stripe(&active_destination)]
        .try_lock()
        .unwrap();

    let digest = "e".repeat(64);
    let preserved: Vec<_> = [
        "operator.bin".to_owned(),
        format!(".vot-outbound-{digest}.stage"),
        format!(".vot-outbound-0-{digest}.stage"),
        format!(".vot-outbound-+1-{digest}.stage"),
        format!(".vot-outbound-ff-{digest}.stage"),
        format!(".vot-outbound-zz-{digest}.stage"),
        ".vot-outbound-00-short.stage".to_owned(),
        format!(".vot-outbound-00-{}.stage", "g".repeat(64)),
        format!(".vot-outbound-00-{digest}.journal"),
    ]
    .into_iter()
    .map(|name| root.join(name))
    .collect();
    for path in &preserved {
        write(path, old);
    }
    let external = directory.path().join("external");
    let external_stage = stage(&external.join("file.bin"), &digest);
    write(&external_stage, old);
    std::os::unix::fs::symlink(&external, root.join("linked-directory")).unwrap();
    let linked_stage = stage(&destination, &digest);
    std::os::unix::fs::symlink(&external_stage, &linked_stage).unwrap();
    let stamp = rustix::fs::Timespec {
        tv_sec: 1000,
        tv_nsec: 0,
    };
    rustix::fs::utimensat(
        rustix::fs::CWD,
        &linked_stage,
        &rustix::fs::Timestamps {
            last_access: stamp,
            last_modification: stamp,
        },
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .unwrap();

    sweep_upload_stages(&app, now - Duration::from_secs(1));
    assert!(
        expired.exists(),
        "a stage younger than the idle limit stays"
    );
    sweep_upload_stages(&app, now);
    assert!(!expired.exists() && !abandoned.exists());
    assert!(!completed_stage.exists() && completed_destination.exists());
    assert!(recent.exists() && active.exists());
    assert!(preserved.iter().all(|path| path.exists()));
    assert!(external_stage.exists() && linked_stage.exists());
    drop(guard);
    sweep_upload_stages(&app, now);
    assert!(
        !active.exists(),
        "an expired stage is removed once its request ends"
    );
}

#[tokio::test]
async fn root_library_listing_excludes_tenants_and_stages_and_is_sorted() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    std::fs::write(app.config.outbound_dir.join("z.bin"), b"z").unwrap();
    std::fs::write(app.config.outbound_dir.join("a.bin"), b"a").unwrap();
    std::fs::create_dir_all(
        app.config
            .outbound_dir
            .join(crate::paths::TENANT_STORAGE_DIR)
            .join("named"),
    )
    .unwrap();
    std::fs::write(
        app.config
            .outbound_dir
            .join(crate::paths::TENANT_STORAGE_DIR)
            .join("named/secret.bin"),
        b"secret",
    )
    .unwrap();
    std::fs::write(app.config.outbound_dir.join(".vot-crash.stage"), b"staged").unwrap();

    let response = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-files?directory=")
                .header("cookie", admin_cookie(&app))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body(response).await;
    assert_eq!(listed["files"][0]["path"], "a.bin");
    assert_eq!(listed["files"][1]["path"], "z.bin");
    assert_eq!(listed["files"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn scoped_library_directory_lists_sorted_direct_entries() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let root = &app.config.outbound_dir;
    std::fs::write(root.join("z.bin"), b"z").unwrap();
    std::fs::write(root.join("a.bin"), b"a").unwrap();
    std::fs::create_dir_all(root.join("zdir/nested")).unwrap();
    std::fs::create_dir_all(root.join("adir")).unwrap();
    std::fs::create_dir_all(root.join(".vot-dir.stage")).unwrap();
    std::fs::write(root.join("adir/nested.bin"), b"nested").unwrap();
    std::fs::write(root.join(".vot-upload.stage"), b"stage").unwrap();
    std::fs::create_dir_all(root.join(crate::paths::TENANT_STORAGE_DIR).join("named")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("adir"), root.join("link")).unwrap();

    let response = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-files?directory=")
                .header("cookie", admin_cookie(&app))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body(response).await;
    assert_eq!(listed["directory"], "");
    assert_eq!(listed["directories"], json!(["adir", "zdir"]));
    assert_eq!(listed["files"][0]["path"], "a.bin");
    assert_eq!(listed["files"][1]["path"], "z.bin");
    assert_eq!(listed["truncated"], false);

    let response = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-files?directory=&limit=2")
                .header("cookie", admin_cookie(&app))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let first_page = body(response).await;
    assert_eq!(first_page["directories"], json!(["adir"]));
    assert_eq!(
        first_page["files"],
        json!([{ "path": "a.bin", "bytes": 1 }])
    );
    assert_eq!(first_page["truncated"], true);
    assert_eq!(first_page["next_cursor"], "adir");

    let response = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-files?directory=&limit=2&after=adir")
                .header("cookie", admin_cookie(&app))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let second_page = body(response).await;
    assert_eq!(second_page["directories"], json!(["zdir"]));
    assert_eq!(
        second_page["files"],
        json!([{ "path": "z.bin", "bytes": 1 }])
    );
    assert_eq!(second_page["truncated"], false);
    assert!(second_page["next_cursor"].is_null());

    for query in [
        "?directory=adir&limit=2&after=z.bin",
        "?q=adir&after=adir",
        "?directory=&limit=0",
        "?directory=&limit=1001",
        "?directory=&limit=nope",
    ] {
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/admin/outbound-files{query}"))
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{query}"
        );
    }

    let response = router(app.clone())
        .oneshot(
            Request::get(format!(
                "/api/admin/outbound-files?directory={}",
                crate::paths::TENANT_STORAGE_DIR
            ))
            .header("cookie", admin_cookie(&app))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let response = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-files?directory=adir")
                .header("cookie", admin_cookie(&app))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body(response).await;
    assert_eq!(listed["directory"], "adir");
    assert_eq!(listed["directories"], json!([]));
    assert_eq!(listed["files"][0]["path"], "adir/nested.bin");

    let response = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-files?selection=adir")
                .header("cookie", admin_cookie(&app))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let selected = body(response).await;
    assert_eq!(
        selected["files"],
        json!([{ "path": "adir/nested.bin", "bytes": 6 }])
    );

    std::fs::create_dir_all(root.join("large")).unwrap();
    for index in 0..65 {
        std::fs::write(root.join(format!("large/file-{index:02}.bin")), b"x").unwrap();
    }
    let response = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-files?selection=large")
                .header("cookie", admin_cookie(&app))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await["files"].as_array().unwrap().len(), 65);

    #[cfg(unix)]
    {
        let response = router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?selection=link")
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[cfg(unix)]
#[test]
fn library_pages_skip_literal_backslash_direct_filenames() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("a\\b"), b"skip").unwrap();
    std::fs::write(directory.path().join("portable"), b"keep").unwrap();
    let (directories, files, truncated) =
        direct_library_entries_page(directory.path(), directory.path(), "", 1).unwrap();
    assert!(directories.is_empty());
    assert_eq!(files, [json!({ "path": "portable", "bytes": 4 })]);
    assert!(!truncated);
}

#[tokio::test]
async fn library_views_exclude_private_workflow_storage() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    let root = &app.config.outbound_dir;
    for name in [
        ".votport-workflows/job/secret.bin",
        ".VOTPORT-WORKFLOWS/job/secret.bin",
        "public/.votport-workflows/job/secret.bin",
        "public/.VOTPORT-WORKFLOWS/job/secret.bin",
        ".vot-hidden.stage/secret.bin",
        "public/.vot-hidden.stage/secret.bin",
        "public/visible.bin",
        "public/.notes",
        "public/.vot-workflows.txt",
    ] {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"x").unwrap();
    }
    let expected = json!([
        {"path":"public/.notes","bytes":1},
        {"path":"public/.vot-workflows.txt","bytes":1},
        {"path":"public/visible.bin","bytes":1},
    ]);
    for query in ["?directory=public", "?selection=public"] {
        let response = router(app.clone())
            .oneshot(
                Request::get(format!("/api/admin/outbound-files{query}"))
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{query}");
        let listed = body(response).await;
        assert_eq!(listed["files"], expected, "{query}: {listed}");
        if query.contains("directory") {
            assert_eq!(listed["directories"], json!([]));
            assert_eq!(listed["truncated"], false);
        }
    }
    let (matches, truncated) = list_library_search(root, "secret");
    assert!(matches.is_empty() && !truncated);
    let (matches, truncated) = list_library_search(root, "visible");
    assert_eq!(
        matches,
        vec![json!({"path":"public/visible.bin","bytes":1})]
    );
    assert!(!truncated);
    let (directories, files, has_more) = direct_library_entries_page(root, root, "", 1).unwrap();
    assert_eq!(directories, ["public"]);
    assert!(files.is_empty() && !has_more);
}

#[test]
fn library_directory_safety_checks_root_and_every_component() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("library");
    std::fs::create_dir_all(root.join("nested/child")).unwrap();
    std::fs::write(root.join("file"), b"x").unwrap();
    for (path, expected) in [
        (root.clone(), true),
        (root.join("nested/child"), true),
        (root.join("missing"), false),
        (root.join("file"), false),
        (root.join("file/child"), false),
        (directory.path().to_owned(), false),
    ] {
        assert_eq!(library_directory_safe(&root, &path), expected, "{path:?}");
    }
    assert!(!library_directory_safe(
        &root.join("file"),
        &root.join("file")
    ));
    #[cfg(unix)]
    {
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        assert!(!library_directory_safe(&link, &link.join("nested")));
        std::os::unix::fs::symlink(root.join("nested"), root.join("link")).unwrap();
        assert!(!library_directory_safe(&root, &root.join("link")));
        assert!(!library_directory_safe(&root, &root.join("link/child")));
    }
}

#[test]
fn scoped_library_directory_caps_direct_entries() {
    let directory = tempfile::tempdir().unwrap();
    for index in 0..=MAX_LIBRARY_DIRECTORY_ENTRIES {
        std::fs::write(directory.path().join(format!("file-{index:04}.bin")), b"x").unwrap();
    }
    let (directories, files, truncated) = direct_library_entries_page(
        directory.path(),
        directory.path(),
        "",
        MAX_LIBRARY_DIRECTORY_ENTRIES,
    )
    .unwrap();
    assert!(directories.is_empty());
    assert_eq!(files.len(), MAX_LIBRARY_DIRECTORY_ENTRIES);
    assert!(truncated);
    assert_eq!(files[0]["path"], "file-0000.bin");
    assert_eq!(
        files[MAX_LIBRARY_DIRECTORY_ENTRIES - 1]["path"],
        "file-0999.bin"
    );
}

#[test]
fn library_search_stops_at_node_budget() {
    let directory = tempfile::tempdir().unwrap();
    let nested = directory.path().join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join("missed-match.bin"), b"x").unwrap();
    let (matches, truncated) = list_library_search_with_budget(directory.path(), "match", 1);
    assert!(matches.is_empty());
    assert!(truncated);
}

#[test]
fn library_search_stops_at_depth_budget() {
    let directory = tempfile::tempdir().unwrap();
    let mut nested = directory.path().to_owned();
    for index in 0..=MAX_LIBRARY_SEARCH_DEPTH {
        nested.push(format!("nested-{index:03}"));
        std::fs::create_dir(&nested).unwrap();
    }
    std::fs::write(nested.join("missed-match.bin"), b"x").unwrap();

    let (matches, truncated) = list_library_search(directory.path(), "match");

    assert!(matches.is_empty());
    assert!(truncated);
}

#[test]
fn library_search_reports_missing_directory_as_truncated() {
    let directory = tempfile::tempdir().unwrap();
    let mut matches = BinaryHeap::new();
    let mut visited = 0;

    assert!(search_library_dir(
        directory.path(),
        &directory.path().join("missing"),
        "match",
        &mut matches,
        &mut visited,
        1,
        0,
    ));
}

#[tokio::test]
async fn admin_directory_grant_supports_large_projects_and_public_metadata() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    let project = app.config.outbound_dir.join("project");
    std::fs::create_dir(&project).unwrap();
    for index in 0..=1000 {
        std::fs::write(project.join(format!("file-{index:02}.bin")), b"x").unwrap();
    }
    for payload in [
        json!({ "directory": "project", "paths": ["project/file-00.bin"] }),
        json!({ "directory": "a/".repeat(MAX_LIBRARY_DIRECTORY_INPUT_BYTES / 2 + 1) }),
    ] {
        let response = settled_grant_response(
            app.clone(),
            &cookie,
                Request::post("/api/admin/outbound-grants")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "expires_days": 1, "directory": payload["directory"], "paths": payload["paths"] }).to_string(),
                    ))
                .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    let response = settled_grant_response(
        app.clone(),
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "directory": "project", "expires_days": 1 }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let created = body(response).await;
    assert_eq!(created["grant"]["file_count"], 1001);
    assert_eq!(created["grant"]["files_truncated"], true);
    assert_eq!(created["grant"]["files"], json!([]));
    let token = created["url"].as_str().unwrap().rsplit('/').next().unwrap();

    let metadata = router(app.clone())
        .oneshot(
            Request::get(format!("/api/s/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
    let metadata = body(metadata).await;
    let files = metadata["files"].as_array().unwrap();
    assert_eq!(files.len(), 1001);
    assert!(files
        .windows(2)
        .all(|pair| { pair[0]["name"].as_str().unwrap() <= pair[1]["name"].as_str().unwrap() }));

    let history = router(app)
        .oneshot(
            Request::get("/api/admin/outbound-grants")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(history.status(), StatusCode::OK);
    let history = body(history).await;
    assert_eq!(history["grants"][0]["file_count"], 1001);
    assert_eq!(history["grants"][0]["files_truncated"], true);
    assert_eq!(history["grants"][0]["files"], json!([]));
}

#[tokio::test]
async fn grant_admission_bounds_request_bodies_and_releases_for_valid_grants() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    let held = app
        .outbound_grant_permits
        .clone()
        .try_acquire_many_owned(LIBRARY_GRANT_CONCURRENCY as u32)
        .unwrap();
    let pending =
        Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        router(app.clone()).oneshot(
            Request::post("/api/admin/outbound-grants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(pending)
                .unwrap(),
        ),
    )
    .await
    .expect("grant admission attempted to read a refused body")
    .unwrap();
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    drop(held);

    let root = app.config.outbound_dir.join("admitted");
    std::fs::create_dir_all(&root).unwrap();
    let paths = (0..65)
        .map(|index| {
            let path = root.join(format!("file-{index:02}.bin"));
            std::fs::write(&path, b"x").unwrap();
            format!("admitted/file-{index:02}.bin")
        })
        .collect::<Vec<_>>();
    let accepted = settled_grant_response(
        app,
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "paths": paths, "expires_days": 1 }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(body(accepted).await["grant"]["file_count"], 65);
}

#[tokio::test]
async fn grant_admission_permit_survives_parsing_while_hashers_wait() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    std::fs::write(app.config.outbound_dir.join("held.bin"), b"x").unwrap();
    let hash_held = LIBRARY_HASH_PERMITS
        .acquire_many(LIBRARY_HASH_CONCURRENCY as u32)
        .await
        .unwrap();
    // The 202 lands without touching admission; the preparation job picks
    // up the admission permit and keeps it while its hashers wait.
    let request = Request::post("/api/admin/outbound-grants/preparations")
        .header("cookie", &cookie)
        .header("x-votport", "1")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"paths":["held.bin"],"expires_days":1}"#))
        .unwrap();
    let response = router(app.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let preparation_id = body(response).await["preparation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while app.outbound_grant_permits.available_permits() != LIBRARY_GRANT_CONCURRENCY - 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "the preparation job never took its admission permit"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    drop(hash_held);
    let snapshot = settled_preparation(&app, &cookie, &preparation_id).await;
    assert_eq!(snapshot["status"], "complete");
    assert_eq!(
        app.outbound_grant_permits.available_permits(),
        LIBRARY_GRANT_CONCURRENCY
    );
}

#[tokio::test]
async fn large_selection_bodies_require_authentication_before_reading() {
    let (_directory, app, cookie, _first) = fixture().await;
    let pending =
        Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        router(app.clone()).oneshot(
            Request::post("/api/admin/outbound-grants")
                .header("content-type", "application/json")
                .body(pending)
                .unwrap(),
        ),
    )
    .await
    .expect("unauthenticated request attempted to read its body")
    .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let paths = (0..100_001)
        .map(|index| format!("sequence/frame-{index:06}.exr"))
        .collect::<Vec<_>>();
    let response = settled_grant_response(
        app,
        &cookie,
        Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "paths": paths,
                    "expires_days": 1,
                }))
                .unwrap(),
            ))
            .unwrap(),
    )
    .await;
    // The selection passes count/body limits and reaches file validation.
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "{}",
        body(response).await
    );
}

#[test]
fn recursive_library_enumerator_rejects_more_than_project_limit() {
    let directory = tempfile::tempdir().unwrap();
    let limit = 3;
    for index in 0..=limit {
        std::fs::write(directory.path().join(format!("file-{index:04}.bin")), b"x").unwrap();
    }
    let error = enumerate_automation_files(directory.path(), directory.path(), limit).unwrap_err();
    assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(error.message.contains(&format!("maximum {limit}")));
}

#[test]
fn library_selection_refuses_file_entry_depth_and_path_budgets() {
    let boundary_root = tempfile::tempdir().unwrap();
    std::fs::write(boundary_root.path().join("x"), b"x").unwrap();
    let paths = enumerate_automation_files_with_budget(
        boundary_root.path(),
        boundary_root.path(),
        1,
        Some(LibraryEnumerationBudget {
            max_entries: 1,
            max_depth: 0,
            max_path_bytes: 1,
        }),
    )
    .unwrap();
    assert_eq!(paths, vec!["x"]);

    let directory = tempfile::tempdir().unwrap();
    for index in 0..=3 {
        std::fs::write(directory.path().join(format!("file-{index}.bin")), b"x").unwrap();
    }
    let error = enumerate_automation_files_with_budget(
        directory.path(),
        directory.path(),
        3,
        Some(LibraryEnumerationBudget {
            max_entries: 10,
            max_depth: 10,
            max_path_bytes: 1000,
        }),
    )
    .unwrap_err();
    assert_eq!(
        error.message,
        "library selection is too large; choose a narrower folder or select individual files"
    );

    let nested = directory.path().join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join("nested.bin"), b"x").unwrap();
    let error = enumerate_automation_files_with_budget(
        directory.path(),
        directory.path(),
        10,
        Some(LibraryEnumerationBudget {
            max_entries: 1,
            max_depth: 10,
            max_path_bytes: 1000,
        }),
    )
    .unwrap_err();
    assert_eq!(
        error.message,
        "library selection is too large; choose a narrower folder or select individual files"
    );

    let depth_root = tempfile::tempdir().unwrap();
    let mut deep = depth_root.path().to_owned();
    for index in 0..=2 {
        deep.push(format!("nested-{index}"));
        std::fs::create_dir(&deep).unwrap();
    }
    std::fs::write(deep.join("deep.bin"), b"x").unwrap();
    let error = enumerate_automation_files_with_budget(
        depth_root.path(),
        depth_root.path(),
        10,
        Some(LibraryEnumerationBudget {
            max_entries: 10,
            max_depth: 1,
            max_path_bytes: 1000,
        }),
    )
    .unwrap_err();
    assert_eq!(
        error.message,
        "library selection is too large; choose a narrower folder or select individual files"
    );

    let path_root = tempfile::tempdir().unwrap();
    std::fs::write(path_root.path().join("long-name.bin"), b"x").unwrap();
    let error = enumerate_automation_files_with_budget(
        path_root.path(),
        path_root.path(),
        10,
        Some(LibraryEnumerationBudget {
            max_entries: 10,
            max_depth: 10,
            max_path_bytes: 4,
        }),
    )
    .unwrap_err();
    assert_eq!(
        error.message,
        "library selection is too large; choose a narrower folder or select individual files"
    );
}

#[tokio::test]
async fn scoped_library_search_is_literal_case_insensitive_and_capped() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    for index in 0..205 {
        std::fs::write(
            app.config
                .outbound_dir
                .join(format!("match-{index:03}.bin")),
            b"x",
        )
        .unwrap();
    }
    std::fs::create_dir_all(app.config.outbound_dir.join("nested")).unwrap();
    std::fs::write(app.config.outbound_dir.join("nested/noise.bin"), b"match").unwrap();
    std::fs::create_dir_all(
        app.config
            .outbound_dir
            .join(crate::paths::TENANT_STORAGE_DIR)
            .join("named"),
    )
    .unwrap();
    std::fs::write(
        app.config
            .outbound_dir
            .join(crate::paths::TENANT_STORAGE_DIR)
            .join("named/match-reserved.bin"),
        b"x",
    )
    .unwrap();
    std::fs::write(app.config.outbound_dir.join(".vot-match.stage"), b"x").unwrap();
    #[cfg(unix)]
    {
        std::fs::create_dir_all(directory.path().join("outside")).unwrap();
        std::fs::write(directory.path().join("outside/match-outside.bin"), b"x").unwrap();
        std::os::unix::fs::symlink(
            directory.path().join("outside"),
            app.config.outbound_dir.join("000-match-link"),
        )
        .unwrap();
    }

    let response = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-files?q=MaTcH")
                .header("cookie", admin_cookie(&app))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body(response).await;
    assert_eq!(
        listed["files"].as_array().unwrap().len(),
        MAX_LIBRARY_SEARCH_RESULTS
    );
    assert_eq!(listed["files"][0]["path"], "match-000.bin");
    assert_eq!(listed["files"][199]["path"], "match-199.bin");
    assert_eq!(listed["truncated"], true);
    let paths = listed["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(!paths.iter().any(|path| path.contains("reserved")));
    assert!(!paths.iter().any(|path| path.ends_with(".stage")));
    assert!(!paths.iter().any(|path| path.contains("outside")));
}

#[tokio::test]
async fn scoped_library_listing_rejects_invalid_queries() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    for uri in [
        "/api/admin/outbound-files".to_owned(),
        "/api/admin/outbound-files?directory=one&q=two".to_owned(),
        "/api/admin/outbound-files?directory=one&selection=two".to_owned(),
        "/api/admin/outbound-files?selection=".to_owned(),
        "/api/admin/outbound-files?q=".to_owned(),
        format!("/api/admin/outbound-files?q={}", "x".repeat(101)),
        format!("/api/admin/outbound-files?directory={}", "x".repeat(1025)),
    ] {
        let response = router(app.clone())
            .oneshot(
                Request::get(uri)
                    .header("cookie", admin_cookie(&app))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}

#[test]
fn scope_matches_whole_components() {
    assert!(within_scope("project", "project"));
    assert!(within_scope("project", "project/sub"));
    assert!(within_scope("/project/", "project/sub/deeper"));
    assert!(!within_scope("project", "project-old"));
    assert!(!within_scope("project", "other"));
    assert!(!within_scope("project/sub", "project"));
}

/// A token confined to a directory shares that directory and its
/// children only; anything else is refused and audited.
#[tokio::test]
async fn scoped_automation_token_shares_only_its_directory() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    for path in ["project/sub", "project-old", "other"] {
        std::fs::create_dir_all(app.config.outbound_dir.join(path)).unwrap();
        std::fs::write(app.config.outbound_dir.join(path).join("f.txt"), b"f").unwrap();
    }
    let create = router(app.clone())
        .oneshot(
            Request::post("/api/admin/automation-tokens")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"label":"Nightly","expires_days":1,"directory":"project/"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = create.status();
    let created = body(create).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["automation_token"]["directory"], json!("project"));
    let raw = created["token"].as_str().unwrap().to_owned();
    // A traversal, absolute, or over-long directory is refused at issue time.
    let long = format!("\"{}\"", "a/".repeat(600));
    for bad in [r#""../x""#, r#""/abs""#, long.as_str()] {
        let create = router(app.clone())
            .oneshot(
                Request::post("/api/admin/automation-tokens")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"label":"bad","expires_days":1,"directory":{bad}}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create.status(), StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    let share = |directory: &'static str| {
        let app = app.clone();
        let raw = raw.clone();
        async move {
            router(app)
                .oneshot(
                    Request::post("/api/automation/share")
                        .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                        .header("content-type", "application/json")
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            12,
                        ))))
                        .body(Body::from(format!(
                            r#"{{"directory":"{directory}","expires_days":1}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(share("project").await, StatusCode::OK);
    assert_eq!(share("project/sub").await, StatusCode::OK);
    assert_eq!(share("project-old").await, StatusCode::FORBIDDEN);
    assert_eq!(share("other").await, StatusCode::FORBIDDEN);
    let refusals: Vec<String> = app
        .store
        .audit_export(None, 0, 0, 100)
        .unwrap()
        .into_iter()
        .filter(|row| row.event == "automation_refused")
        .map(|row| format!("{} {}", row.actor, row.subject))
        .collect();
    assert_eq!(refusals.len(), 2, "{refusals:?}");
    assert!(refusals.iter().all(|row| row.starts_with("automation:")));
    assert!(refusals.iter().any(|row| row.ends_with(" project-old")));
    let listed = router(app.clone())
        .oneshot(
            Request::get("/api/admin/automation-tokens")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        body(listed).await["tokens"][0]["directory"],
        json!("project")
    );
}

#[tokio::test]
async fn automation_token_shares_recursive_library_without_leaking_token() {
    let (_directory, app, cookie, _bytes) = fixture().await;
    std::fs::create_dir_all(app.config.outbound_dir.join("project/sub")).unwrap();
    std::fs::write(app.config.outbound_dir.join("project/a.txt"), b"a").unwrap();
    std::fs::write(app.config.outbound_dir.join("project/sub/b.txt"), b"b").unwrap();
    let create = router(app.clone())
        .oneshot(
            Request::post("/api/admin/automation-tokens")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"label":"CI","expires_days":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    assert_eq!(
        create.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let created = body(create).await;
    let raw = created["token"].as_str().unwrap().to_owned();
    assert!(valid_token(&raw));
    assert!(created["automation_token"].get("token_hash").is_none());

    let listed = router(app.clone())
        .oneshot(
            Request::get("/api/admin/automation-tokens")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let listed = body(listed).await;
    assert!(listed["tokens"][0].get("token_hash").is_none());
    assert!(listed["tokens"][0].get("token").is_none());

    for authorization in [
        None,
        Some("Bearer nope"),
        Some("Bearer 00000000000000000000000000000000"),
    ] {
        let mut request = Request::post("/api/automation/share")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"directory":"project","expires_days":1}"#))
            .unwrap();
        if let Some(value) = authorization {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, HeaderValue::from_static(value));
        }
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                10,
            ))));
        assert_eq!(
            router(app.clone()).oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let refusals = app
        .store
        .audit_export(None, 0, 0, 100)
        .unwrap()
        .into_iter()
        .filter(|row| row.event == "automation_refused")
        .map(|row| row.detail["reason"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        refusals,
        [
            "missing or malformed bearer",
            "missing or malformed bearer",
            "unknown, expired, or revoked token"
        ]
    );

    let share = router(app.clone())
        .oneshot(
            Request::post("/api/automation/share")
                .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                .header("content-type", "application/json")
                .extension(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    11,
                ))))
                .body(Body::from(r#"{"directory":"project","expires_days":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(share.status(), StatusCode::OK);
    let share = body(share).await;
    assert_eq!(share["grant"]["label"], "project");
    assert_eq!(share["grant"]["files"][0]["name"], "project/a.txt");
    assert_eq!(share["grant"]["files"][1]["name"], "project/sub/b.txt");
    assert_eq!(share["grant"]["has_password"], false);

    let large = app.config.outbound_dir.join("automation-large");
    std::fs::create_dir(&large).unwrap();
    for index in 0..=1000 {
        std::fs::write(large.join(format!("file-{index:02}.bin")), b"x").unwrap();
    }
    let large_share = router(app.clone())
        .oneshot(
            Request::post("/api/automation/share")
                .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                .header("content-type", "application/json")
                .extension(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    15,
                ))))
                .body(Body::from(
                    r#"{"directory":"automation-large","expires_days":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(large_share.status(), StatusCode::OK);
    let large_share = body(large_share).await;
    assert_eq!(large_share["grant"]["file_count"], 1001);
    assert_eq!(large_share["grant"]["files_truncated"], true);
    assert_eq!(large_share["grant"]["label"], "automation-large");

    for directory in ["/project", "../project", "project/../project"] {
        let response = router(app.clone())
            .oneshot(
                Request::post("/api/automation/share")
                    .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        12,
                    ))))
                    .body(Body::from(format!(
                        r#"{{"directory":"{directory}","expires_days":1}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            app.config.outbound_dir.join("project/a.txt"),
            app.config.outbound_dir.join("project/link"),
        )
        .unwrap();
        let response = router(app.clone())
            .oneshot(
                Request::post("/api/automation/share")
                    .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        13,
                    ))))
                    .body(Body::from(r#"{"directory":"project","expires_days":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    let id = created["automation_token"]["id"].as_str().unwrap();
    let revoke = router(app.clone())
        .oneshot(
            Request::delete(format!("/api/admin/automation-tokens/{id}"))
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::OK);
    let denied = router(app)
        .oneshot(
            Request::post("/api/automation/share")
                .header(header::AUTHORIZATION, format!("Bearer {raw}"))
                .header("content-type", "application/json")
                .extension(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    14,
                ))))
                .body(Body::from(r#"{"directory":"project","expires_days":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
}

/// POST /outbound-grants with library paths answers 202 immediately, the
/// detached job reports file and byte progress, the finished preparation
/// stays readable for late polls, and an unknown id (a restarted server's
/// registry is empty) answers 404 with a clear retry hint.
#[tokio::test(flavor = "current_thread")]
async fn grant_preparations_report_progress_then_terminal_outcomes() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    app.store
        .insert_tenant(crate::store::tests::test_tenant("acme"))
        .unwrap();
    let root = library_root(&app, "acme");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.bin"), vec![9u8; 4096]).unwrap();
    let cookie = named_admin_cookie(&app, "acme");

    let response = router(app.clone())
        .oneshot(
            Request::post("/api/admin/outbound-grants/preparations")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"paths":["a.bin"],"expires_days":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let accepted = body(response).await;
    let id = accepted["preparation_id"].as_str().unwrap().to_owned();

    let snapshot = settled_preparation(&app, &cookie, &id).await;
    assert_eq!(snapshot["status"], "complete");
    assert_eq!(snapshot["files_total"], 1);
    assert_eq!(snapshot["files_done"], 1);
    assert_eq!(snapshot["bytes_total"], 4096);
    assert_eq!(snapshot["bytes_done"], 4096);
    assert!(snapshot["url"].as_str().unwrap().contains("/s/"));
    assert_eq!(snapshot["grant"]["files"][0]["bytes"], 4096);

    // Late polls of a finished preparation still find it.
    let again = router(app.clone())
        .oneshot(
            Request::get(format!("/api/admin/outbound-grants/preparations/{id}"))
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::OK);
    assert_eq!(body(again).await["status"], "complete");

    // The registry lives on the App, so a restart (or any unknown id)
    // answers 404 instead of pretending to still prepare.
    let lost = router(app.clone())
        .oneshot(
            Request::get("/api/admin/outbound-grants/preparations/prep-lost")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(lost.status(), StatusCode::NOT_FOUND);
    assert!(body(lost).await["error"]
        .as_str()
        .unwrap()
        .contains("no longer available"));
}

/// While one preparation for a session is hashing (held by the mutation
/// stall), a second POST is refused with 409; once the first settles the
/// terminal entry is pruned and a new grant is accepted again.
#[tokio::test(flavor = "current_thread")]
async fn a_second_library_grant_while_one_prepares_is_refused_until_it_settles() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    app.store
        .insert_tenant(crate::store::tests::test_tenant("acme"))
        .unwrap();
    let root = library_root(&app, "acme");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.bin"), vec![3u8; 1024]).unwrap();
    let cookie = named_admin_cookie(&app, "acme");
    let make_request = || {
        Request::builder()
            .method("POST")
            .uri("/api/admin/outbound-grants/preparations")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"paths":["a.bin"],"expires_days":1}"#))
            .unwrap()
    };

    let (entered, release, _stall) = arm_library_mutation_stall(&root);
    let first = router(app.clone()).oneshot(make_request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let id = body(first).await["preparation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if entered.try_recv().is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("preparation never reached the mutation stall");

    let second = router(app.clone()).oneshot(make_request()).await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
    assert!(body(second).await["error"]
        .as_str()
        .unwrap()
        .contains("already running"));
    release.send(()).unwrap();
    let snapshot = settled_preparation(&app, &cookie, &id).await;
    assert_eq!(snapshot["status"], "complete");

    // The terminal preparation is pruned on the next attempt.
    let third = router(app.clone()).oneshot(make_request()).await.unwrap();
    assert_eq!(third.status(), StatusCode::ACCEPTED);
    let third_body = body(third).await;
    let snapshot = settled_preparation(
        &app,
        &cookie,
        third_body["preparation_id"].as_str().unwrap(),
    )
    .await;
    assert_eq!(snapshot["status"], "complete");
}

/// Hashed library roots consult the sidecar cache: a first grant misses and
/// populates it, an unchanged source (same size and mtime) hits, and a
/// content rewrite with a bumped mtime misses again and stores the new root.
#[tokio::test(flavor = "current_thread")]
async fn hashed_library_roots_come_from_the_cache_until_the_source_changes() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    app.store
        .insert_tenant(crate::store::tests::test_tenant("acme"))
        .unwrap();
    let root = library_root(&app, "acme");
    std::fs::create_dir_all(&root).unwrap();
    let file = root.join("a.bin");
    std::fs::write(&file, vec![1u8; 64]).unwrap();
    let cookie = named_admin_cookie(&app, "acme");
    let create_request = || {
        Request::post("/api/admin/outbound-grants/preparations")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"paths":["a.bin"],"expires_days":1}"#))
            .unwrap()
    };
    let cached = || {
        let stat = std::fs::symlink_metadata(&file).unwrap();
        app.root_cache
            .lookup("acme", &file, stat.len(), mtime_nanos(&stat))
    };

    assert!(cached().is_none(), "nothing hashed yet");
    let first = settled_grant_response(app.clone(), &cookie, create_request()).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_root = body(first).await["grant"]["files"][0]["root"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        cached().unwrap(),
        first_root,
        "the first hash populates the cache"
    );

    // Same size, same mtime: the accepted heuristic hits the cache even
    // though the bytes changed underneath (rsync-style ceiling), so the
    // rewrite restores the original mtime before re-sharing.
    let before = std::fs::symlink_metadata(&file).unwrap();
    std::fs::write(&file, vec![2u8; 64]).unwrap();
    std::fs::File::options()
        .append(true)
        .open(&file)
        .unwrap()
        .set_modified(before.modified().unwrap())
        .unwrap();
    let second = settled_grant_response(app.clone(), &cookie, create_request()).await;
    assert_eq!(second.status(), StatusCode::OK);
    let second_body = body(second).await;
    let second_root = second_body["grant"]["files"][0]["root"].as_str().unwrap();
    assert_eq!(second_root, first_root, "unchanged stat reuses the root");
    assert_eq!(cached().unwrap(), first_root);

    // A content rewrite that also moves mtime must miss and re-hash.
    std::fs::write(&file, vec![3u8; 64]).unwrap();
    let bumped = std::time::SystemTime::now() + Duration::from_secs(120);
    std::fs::File::options()
        .append(true)
        .open(&file)
        .unwrap()
        .set_modified(bumped)
        .unwrap();
    assert!(cached().is_none(), "a changed source invalidates its entry");
    let third = settled_grant_response(app.clone(), &cookie, create_request()).await;
    assert_eq!(third.status(), StatusCode::OK);
    let third_root = body(third).await["grant"]["files"][0]["root"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(third_root, first_root, "new bytes hash to a new root");
    assert_eq!(cached().unwrap(), third_root);
}

#[tokio::test(flavor = "current_thread")]
async fn library_grant_creation_stays_synchronous_for_the_pinned_cli() {
    let directory = tempfile::tempdir().unwrap();
    let app = crate::api::testing::build(directory.path());
    app.store
        .insert_tenant(crate::store::tests::test_tenant("acme"))
        .unwrap();
    let root = library_root(&app, "acme");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.bin"), vec![9u8; 512]).unwrap();
    let cookie = named_admin_cookie(&app, "acme");
    let response = router(app.clone())
        .oneshot(
            Request::post("/api/admin/outbound-grants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"paths":["a.bin"],"expires_days":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body(response).await;
    assert!(payload["preparation_id"].is_null());
    assert_eq!(payload["grant"]["files"][0]["name"], "a.bin");
    assert!(payload["url"].as_str().unwrap().contains("/s/"));
}
