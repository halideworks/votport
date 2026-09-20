use super::*;

#[cfg(test)]
mod status_cache_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn admin_status_carries_health_readiness_lease_and_draining() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        let cookie = test_admin_cookie(&application, &auth::AdminIdentity::local_admin());
        let response = crate::app::router(Arc::clone(&application))
            .oneshot(
                Request::get("/api/admin/status")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // The dashboard strip paints a banner from these fields; they must
        // mirror what /readyz reports.
        assert_eq!(body["health"], true);
        assert_eq!(body["ready"], true);
        assert_eq!(body["draining"], false);
        assert_eq!(body["lease"]["mine"], true);
        assert_eq!(body["lease"]["lost"], false);
        assert_eq!(body["lease"]["holder"], application.lease_holder);
        assert!(body["lease"]["age_secs"].as_u64().is_some());
        assert_eq!(body["mount"]["disqualified"], false);
    }

    #[tokio::test]
    async fn concurrent_polls_share_one_refresh_and_publish_stale_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        let cookie = test_admin_cookie(&application, &auth::AdminIdentity::local_admin());
        let router = crate::app::router(Arc::clone(&application));
        let request = |uri| {
            Request::get(uri)
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap()
        };
        let (first, second) = tokio::join!(
            router.clone().oneshot(request("/api/admin/status")),
            router.oneshot(request("/api/admin/status")),
        );
        assert_eq!(first.unwrap().status(), StatusCode::OK);
        assert_eq!(second.unwrap().status(), StatusCode::OK);
        assert_eq!(
            application.admin_status.refreshes.load(Ordering::Relaxed),
            1
        );

        tokio::time::sleep(Duration::from_secs(1)).await;
        let response = crate::app::router(Arc::clone(&application))
            .oneshot(request("/api/admin/status"))
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["stale"], false);
        assert!(body["sampled_at"].as_u64().is_some());
        assert!(body["today"]["uploads"].as_u64().is_some());
        let rolling_since = body["today"]["since"].as_u64().unwrap();

        let response = crate::app::router(Arc::clone(&application))
            .oneshot(request("/api/admin/status?since=1704067200"))
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["today"]["since"], 1_704_067_200u64);
        assert_ne!(body["today"]["since"].as_u64().unwrap(), rolling_since);
        assert!(application.admin_status.refreshes.load(Ordering::Relaxed) >= 2);

        application
            .admin_status
            .state
            .lock()
            .unwrap()
            .entries
            .iter_mut()
            .find(|entry| entry.key.since == Some(1_704_067_200))
            .and_then(|entry| entry.snapshot.as_mut())
            .unwrap()
            .started -= ADMIN_STATUS_TTL;
        let response = crate::app::router(application)
            .oneshot(request("/api/admin/status?since=1704067200"))
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["stale"], true);
        assert!(body["sampled_at"].as_u64().is_some());
    }

    #[tokio::test]
    async fn stuck_refresh_keeps_live_status_response_available() {
        let directory = tempfile::tempdir().unwrap();
        let assets = directory.path().join("web/assets");
        std::fs::create_dir_all(&assets).unwrap();
        std::fs::write(assets.join("status-strip.js"), b"").unwrap();
        let application = crate::api::testing::build(directory.path());
        let cookie = test_admin_cookie(&application, &auth::AdminIdentity::local_admin());
        application.admin_status.state.lock().unwrap().running = true;
        let router = crate::app::router(Arc::clone(&application));
        let status_request = Request::get("/api/admin/status")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let status = tokio::spawn(router.clone().oneshot(status_request));
        tokio::time::sleep(Duration::from_millis(20)).await;
        let started = Instant::now();
        let asset = router
            .oneshot(
                Request::get("/assets/status-strip.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(asset.status(), StatusCode::OK);
        assert!(started.elapsed() < Duration::from_millis(250));

        let response = status.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(body["today"].is_null());
        assert!(body["stored"].is_null());
        assert!(body["outbound"]["open_grants"].is_null());
        assert_eq!(body["sampled_at"], serde_json::Value::Null);
        assert_eq!(body["stale"], true);
        assert!(body["stale_error"].as_str().is_some());
    }

    #[test]
    fn status_worker_rejects_a_recreated_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        let tenant = || crate::store::Tenant {
            retention_days: None,
            incarnation: String::new(),
            key: "team".to_owned(),
            label: "team".to_owned(),
            admin_group: None,
            max_total_bytes: None,
            max_links: None,
            max_sessions: None,
            created_at: 0,
        };
        application.store.insert_tenant(tenant()).unwrap();
        let incarnation = application
            .store
            .tenant("team")
            .unwrap()
            .unwrap()
            .incarnation;
        let key = StatusKey {
            tenant: "team".to_owned(),
            incarnation: Some(incarnation),
            since: None,
        };
        assert!(status_key_is_current(&application, &key).unwrap());
        assert!(matches!(
            application.store.remove_tenant("team").unwrap(),
            crate::store::TenantRemoval::Deleted
        ));
        application.store.insert_tenant(tenant()).unwrap();
        assert!(!status_key_is_current(&application, &key).unwrap());
    }

    #[tokio::test]
    async fn status_worker_holds_tenant_guard_until_done_and_drops_on_early_exit() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::Tenant {
                retention_days: None,
                incarnation: String::new(),
                key: "team".to_owned(),
                label: "team".to_owned(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        let key = StatusKey {
            tenant: "team".to_owned(),
            incarnation: Some(
                application
                    .store
                    .tenant("team")
                    .unwrap()
                    .unwrap()
                    .incarnation,
            ),
            since: Some(0),
        };

        // Admission refusal must complete without ever reaching the scan
        // gate. The result channel makes that assertion bounded too.
        let held_pin = application.sessions.try_pin_tenant("team").unwrap();
        let (no_entry_tx, no_entry_rx) = std::sync::mpsc::sync_channel(1);
        let no_entry_app = Arc::clone(&application);
        let no_entry_key = key.clone();
        let no_entry_worker = std::thread::spawn(move || {
            let result = refresh_status_sync(&no_entry_app, &no_entry_key);
            no_entry_tx.send(result).unwrap();
        });
        let no_entry_result = no_entry_rx
            .recv_timeout(ADMIN_STATUS_TEST_WAIT)
            .expect("refused status worker did not finish");
        assert!(matches!(
            no_entry_result,
            Err(error) if error == "tenant operation unavailable"
        ));
        assert!(no_entry_worker.join().is_ok());
        drop(held_pin);

        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let gate = Arc::new(StatusScanGate {
            entered: entered_tx,
            release: std::sync::Mutex::new(release_rx),
        });
        *application.admin_status.scan_gate.lock().unwrap() = Some(Arc::clone(&gate));
        let worker_app = Arc::clone(&application);
        let worker_key = key.clone();
        let (worker_done_tx, worker_done_rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = refresh_status_sync(&worker_app, &worker_key);
            worker_done_tx.send(result).unwrap();
        });
        entered_rx
            .recv_timeout(ADMIN_STATUS_TEST_WAIT)
            .expect("status worker did not enter the scan gate");
        let cookie = test_admin_cookie(&application, &auth::AdminIdentity::local_admin());
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookie.parse().unwrap());
        headers.insert("x-votport", "1".parse().unwrap());
        let response = delete_tenant(
            State(Arc::clone(&application)),
            axum::extract::Path("team".to_owned()),
            headers,
        )
        .await
        .unwrap_err()
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        release_tx.send(()).unwrap();
        assert!(worker_done_rx
            .recv_timeout(ADMIN_STATUS_TEST_WAIT)
            .expect("released status worker did not finish")
            .is_ok());
        assert!(worker.join().is_ok());
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, cookie.parse().unwrap());
        headers.insert("x-votport", "1".parse().unwrap());
        let _ = delete_tenant(
            State(Arc::clone(&application)),
            axum::extract::Path("team".to_owned()),
            headers,
        )
        .await
        .unwrap();

        *application.admin_status.scan_gate.lock().unwrap() = None;
        application
            .store
            .insert_tenant(crate::store::Tenant {
                retention_days: None,
                incarnation: String::new(),
                key: "team".to_owned(),
                label: "team".to_owned(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        assert!(refresh_status_sync(&application, &key).is_err());
        assert!(application.sessions.try_pin_tenant("team").is_some());
    }

    #[test]
    fn stale_observation_waits_for_completion_throttle() {
        let now = Instant::now();
        let entry = StatusEntry {
            key: StatusKey {
                tenant: String::new(),
                incarnation: None,
                since: None,
            },
            snapshot: Some(StatusSnapshot {
                sampled_at: 0,
                started: now - ADMIN_STATUS_TTL,
                today_uploads: 0,
                today_bytes: 0,
                stored: json!({}),
                receive_disk: None,
                outbound: crate::store::OutboundSummary {
                    open_grants: 0,
                    deliveries: 0,
                    active: 0,
                },
                outbound_disk: None,
                since: 0,
                warning: None,
            }),
            error: None,
            last_refresh: Some(now),
        };
        assert!(!entry.needs_refresh(now + ADMIN_STATUS_TTL - Duration::from_nanos(1)));
        assert!(entry.needs_refresh(now + ADMIN_STATUS_TTL));
        let cold = StatusEntry {
            last_refresh: None,
            ..entry
        };
        assert!(cold.needs_refresh(now));
    }
}

#[cfg(test)]
mod audit_filter_tests {
    use super::*;

    #[test]
    fn audit_filters_are_bounded_and_blank_values_are_absent() {
        assert_eq!(validate_audit_filter(None, "q").unwrap(), None);
        assert_eq!(
            validate_audit_filter(Some(String::new()), "q").unwrap(),
            None
        );
        assert_eq!(
            validate_audit_filter(Some(" \t".to_owned()), "q").unwrap(),
            None
        );
        assert!(validate_audit_filter(Some("🙂".repeat(100)), "q").is_ok());
        assert!(validate_audit_filter(Some("🙂".repeat(101)), "q").is_err());
        assert_eq!(
            validate_audit_filter(Some("  actor  ".to_owned()), "q").unwrap(),
            Some("actor".to_owned())
        );
    }
}

#[cfg(test)]
mod handler_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::store::UploadRecord;

    async fn login_attempt(
        application: Arc<App>,
        peer: [u8; 4],
        password: &str,
    ) -> axum::http::Response<axum::body::Body> {
        app::router(application)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/login")
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((peer, 1234))))
                    .body(Body::from(format!("{{\"password\":\"{password}\"}}")))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_flood_of_attempts_does_not_refuse_the_operator() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // Every attempt from a different bucket, so none is refused by the
        // per-IP throttle. The operator must still sign in while they are in
        // flight.
        let mut flood = Vec::new();
        for index in 0..20u8 {
            let application = application.clone();
            flood.push(tokio::spawn(async move {
                login_attempt(application, [10, 0, 0, index], "wrong").await;
            }));
        }
        // Bounded so a regression fails with a diagnosis rather than hanging.
        // This checks that the operator is not refused, not that the wait is
        // short: queue latency under a flood is an accepted residual, and the
        // semaphore is FIFO.
        let operator = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            login_attempt(
                application.clone(),
                [198, 51, 100, 4],
                testing::TEST_PASSWORD,
            ),
        )
        .await
        .expect("the operator never completed sign-in during a flood");
        assert_eq!(
            operator.status(),
            StatusCode::OK,
            "the operator signs in while the flood is in flight"
        );
        for task in flood {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(60), task).await;
        }
    }

    #[tokio::test]
    async fn a_rejected_new_password_costs_no_guess_budget() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login_cookie(app::router(application.clone())).await;
        // Six requests whose new password is too short. None of them reaches
        // a verification, so none may spend the budget that guards the
        // current password, or a script could lock every admin out of
        // rotation without guessing anything.
        for _ in 0..6 {
            let response = change_password_req(
                application.clone(),
                &cookie,
                testing::TEST_PASSWORD,
                "short",
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let response = change_password_req(
            application.clone(),
            &cookie,
            testing::TEST_PASSWORD,
            "a-much-longer-passphrase",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn change_password_req(
        application: Arc<App>,
        cookie: &str,
        current: &str,
        new: &str,
    ) -> axum::http::Response<axum::body::Body> {
        app::router(application)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/password")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        1234,
                    ))))
                    .body(Body::from(format!(
                        r#"{{"current":"{current}","new":"{new}"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn sign_out_and_password_refusals_reach_the_audit_trail() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login_cookie(app::router(application.clone())).await;

        let response = app::router(application.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/logout")
                    .header("cookie", cookie.clone())
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // A wrong current password is refused and recorded like the sibling
        // sign-in failure row: address and event only, no secret material.
        let response = change_password_req(
            application.clone(),
            &cookie,
            "not-the-password",
            "a-much-longer-passphrase",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // A successful rotation carries the acting principal, not a literal.
        let sso = crate::auth::AdminIdentity {
            subject: "sso:admin".to_owned(),
            tenant: String::new(),
            role: "admin".to_owned(),
            grants: vec![crate::auth::TenantGrant {
                incarnation: None,
                tenant: String::new(),
                role: "admin".to_owned(),
            }],
            credential_version: 1,
        };
        let sso_cookie = format!(
            "votport_admin={}",
            crate::auth::issue_admin_token(
                &application.secret,
                &sso,
                &admin_token_phc(&application).unwrap(),
            )
        );
        let response = change_password_req(
            application.clone(),
            &sso_cookie,
            testing::TEST_PASSWORD,
            "another-long-passphrase",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let rows = application.store.audit_export(None, 0, 0, 100).unwrap();
        let out = rows
            .iter()
            .find(|row| row.event == "admin_signed_out")
            .expect("the sign-out is recorded");
        assert_eq!(out.actor, "local");
        let failed = rows
            .iter()
            .find(|row| row.event == "admin_password_change_failed")
            .expect("the refused change is recorded");
        assert_eq!(failed.subject, "127.0.0.1");
        assert_eq!(failed.actor, "");
        assert_eq!(failed.detail, json!({}));
        let changed = rows
            .iter()
            .find(|row| row.event == "admin_password_changed")
            .expect("the rotation is recorded");
        assert_eq!(changed.actor, "sso:admin");
    }

    #[tokio::test]
    async fn sign_in_failures_do_not_block_a_password_change() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login_cookie(app::router(application.clone())).await;
        // Sign-in failures must not reach the counter that guards password
        // rotation: an operator holding a session has to be able to rotate.
        for index in 0..6u8 {
            login_attempt(application.clone(), [203, 0, 113, index], "wrong").await;
        }
        let response = app::router(application.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/password")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [203, 0, 113, 200],
                        1234,
                    ))))
                    .body(Body::from(format!(
                        r#"{{"current":"{}","new":"a-much-longer-passphrase"}}"#,
                        testing::TEST_PASSWORD
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn spread_out_failures_never_reach_a_fresh_address() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // Twelve failures, spread four per address so no single address
        // locks itself, and well past the five that used to trip a global
        // counter. Nothing may accumulate across addresses, or an attacker
        // who spreads guesses denies the operator the break-glass credential.
        // Kept small on purpose: every one of these runs a real argon2.
        for index in 0..3u8 {
            for _ in 0..4 {
                assert_eq!(
                    login_attempt(application.clone(), [203, 0, 113, index], "wrong")
                        .await
                        .status(),
                    StatusCode::UNAUTHORIZED
                );
            }
        }
        assert_eq!(
            login_attempt(
                application.clone(),
                [198, 51, 100, 4],
                testing::TEST_PASSWORD
            )
            .await
            .status(),
            StatusCode::OK,
            "a fresh address signs in normally"
        );
    }

    #[tokio::test]
    async fn a_link_password_flood_cannot_queue_the_operator_out() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // Every permit of the public link budget held: that path is the one
        // an unauthenticated caller can flood. Sign-in has its own budget, so
        // it must not wait on this one.
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(
                Arc::clone(&application.link_verify_permits)
                    .acquire_owned()
                    .await
                    .unwrap(),
            );
        }
        let signed_in = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            login_attempt(
                application.clone(),
                [198, 51, 100, 4],
                testing::TEST_PASSWORD,
            ),
        )
        .await
        .expect("sign-in waited on the link password budget");
        assert_eq!(signed_in.status(), StatusCode::OK);
        drop(held);
    }

    #[tokio::test]
    async fn a_guessing_address_cannot_lock_out_the_operator() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // Well past the five-failure lockout: a global throttle here would
        // deny the break-glass credential to everyone, which is exactly what
        // an operator needs during an identity-provider outage.
        for _ in 0..15 {
            let response = login_attempt(application.clone(), [203, 0, 113, 9], "wrong").await;
            assert!(
                response.status() == StatusCode::UNAUTHORIZED
                    || response.status() == StatusCode::TOO_MANY_REQUESTS
            );
        }
        assert_eq!(
            login_attempt(application.clone(), [203, 0, 113, 9], "wrong")
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the guessing address is locked"
        );
        assert_eq!(
            login_attempt(
                application.clone(),
                [198, 51, 100, 4],
                testing::TEST_PASSWORD
            )
            .await
            .status(),
            StatusCode::OK,
            "another address still signs in"
        );
    }

    async fn login_cookie(router: axum::Router) -> String {
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/login")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                1234,
            ))))
            .body(Body::from(format!(
                "{{\"password\":\"{}\"}}",
                testing::TEST_PASSWORD
            )))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response
            .headers()
            .get(header::SET_COOKIE)
            .expect("login sets a cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn admin_api_rejects_the_unauthenticated() {
        let directory = tempfile::tempdir().unwrap();
        let router = app::router(testing::build(directory.path()));
        let response = router
            .oneshot(
                Request::get("/api/admin/links")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn legal_hold_refuses_all_received_data_deletions() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                id: "held".to_owned(),
                label: "held".to_owned(),
                tenant: String::new(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: true,

                notifications: None,
                uploads: Vec::new(),
                events: Vec::new(),
            })
            .unwrap();
        let cookie = login_cookie(app::router(application.clone())).await;
        for uri in [
            "/api/admin/links/held",
            "/api/admin/links/held/uploads/upload",
            "/api/admin/links/held/uploads/upload/files/0",
        ] {
            let response = app::router(application.clone())
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
        assert!(application.store.link("", "held").unwrap().is_some());
    }

    #[tokio::test]
    async fn record_deletes_refuse_while_received_files_exist() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                id: "link".to_owned(),
                label: "link".to_owned(),
                tenant: String::new(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,

                notifications: None,
                uploads: vec![crate::store::UploadRecord {
                    partial: false,
                    log: Vec::new(),
                    id: "upload".to_owned(),
                    started_at: 0,
                    completed_at: 1,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: Some("http".to_owned()),
                    package_root: "root".to_owned(),
                    total_bytes: 4,
                    files: vec![crate::store::FileRecord {
                        path: "received.bin".to_owned(),
                        stored_as: "received.bin".to_owned(),
                        bytes: 4,
                        suite: "blake3".to_owned(),
                        root: "aa".repeat(32),
                        receipt: false,
                        deleted: false,
                    }],
                }],
                events: Vec::new(),
            })
            .unwrap();
        let cookie = login_cookie(app::router(application.clone())).await;
        // The record is the only registry of the payload's stored path, so
        // both record deletes refuse while the file exists.
        for uri in [
            "/api/admin/links/link/uploads/upload",
            "/api/admin/links/link",
        ] {
            let response = app::router(application.clone())
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
        assert!(application.store.link("", "link").unwrap().is_some());
        assert!(application
            .store
            .link_upload("", "link", "upload")
            .unwrap()
            .is_some());

        // Deleting the file itself unblocks both: the tombstone plus the
        // unlink means the record no longer names anything on disk.
        let delete = |uri: &str| {
            Request::builder()
                .method("DELETE")
                .uri(uri)
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap()
        };
        let response = app::router(application.clone())
            .oneshot(delete("/api/admin/links/link/uploads/upload/files/0"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app::router(application.clone())
            .oneshot(delete("/api/admin/links/link/uploads/upload"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app::router(application.clone())
            .oneshot(delete("/api/admin/links/link"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(application.store.link("", "link").unwrap().is_none());
    }

    #[tokio::test]
    async fn paged_links_return_a_stable_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        for id in ["z-link", "m-link", "a-link"] {
            application
                .store
                .insert_link(crate::store::Link {
                    retention_days: None,
                    id: id.to_owned(),
                    label: id.to_owned(),
                    tenant: String::new(),
                    dest: String::new(),
                    password_hash: None,
                    created_at: 10,
                    expires_at: None,
                    max_bytes: None,
                    active: true,
                    legal_hold: false,

                    notifications: None,
                    uploads: Vec::new(),
                    events: Vec::new(),
                })
                .unwrap();
        }
        let cookie = login_cookie(app::router(application.clone())).await;
        let response = app::router(application.clone())
            .oneshot(
                Request::get("/api/admin/links?limit=2")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let links = json["links"].as_array().unwrap();
        assert_eq!(links[0]["id"], "z-link");
        assert_eq!(links[1]["id"], "m-link");
        assert_eq!(
            json["next_cursor"],
            serde_json::json!({"created_at": 10, "id": "m-link"})
        );

        let response = app::router(application)
            .oneshot(
                Request::get("/api/admin/links?limit=2&before_created_at=10&before_id=m-link")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["links"].as_array().unwrap()[0]["id"], "a-link");
        assert!(json["next_cursor"].is_null());
    }

    #[test]
    fn upload_view_maps_legacy_upload_transport_to_http() {
        let view = upload_view(
            crate::store::UploadHeader {
                position: 1,
                file_count: 0,
                route: None,
                upload: UploadRecord {
                    partial: false,
                    log: Vec::new(),
                    id: "upload".into(),
                    started_at: 0,
                    completed_at: 1,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: None,
                    package_root: "root".into(),
                    total_bytes: 0,
                    files: Vec::new(),
                },
            },
            true,
        );
        assert_eq!(serde_json::to_value(view).unwrap()["transport"], "http");
    }

    #[test]
    fn patch_tenant_null_clears_and_omission_preserves() {
        let cleared: PatchTenantRequest = serde_json::from_str(
            r#"{"admin_group":null,"max_total_bytes":null,"max_links":null,"max_sessions":null}"#,
        )
        .unwrap();
        assert_eq!(cleared.admin_group, Some(None));
        assert_eq!(cleared.max_total_bytes, Some(None));
        assert_eq!(cleared.max_links, Some(None));
        assert_eq!(cleared.max_sessions, Some(None));

        let omitted: PatchTenantRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(omitted.admin_group, None);
        assert_eq!(omitted.max_total_bytes, None);
        assert_eq!(omitted.max_links, None);
        assert_eq!(omitted.max_sessions, None);
    }

    #[tokio::test]
    async fn mutating_admin_routes_require_the_csrf_header() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;

        // Valid session, no X-Votport header: cross-site forms must fail.
        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"label":"no header"}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // The same request with the header succeeds.
        let router = app::router(application);
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"label":"with header"}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Axum 0.8 keeps its route table private, so this walks the `.route(`
    /// registrations in app.rs the way the bare-require-admin lint walks
    /// handler sources. Every mutating admin, trade and notifications route
    /// must refuse a viewer session that lacks the X-Votport header: the
    /// require_admin_write role check and the CSRF header check both answer
    /// 403, so a route that loses either gate fails here.
    fn registered_mutating_routes(source: &str) -> Vec<(String, String)> {
        const METHODS: [(&str, &str); 4] = [
            ("POST", "post("),
            ("PUT", "put("),
            ("PATCH", "patch("),
            ("DELETE", "delete("),
        ];
        let mut routes = Vec::new();
        let mut rest = source;
        while let Some(start) = rest.find(".route(") {
            let arguments = &rest[start + ".route(".len()..];
            let mut depth = 1usize;
            let mut end = arguments.len();
            for (offset, character) in arguments.char_indices() {
                match character {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = offset;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let span = &arguments[..end];
            if let Some(path) = span.trim_start().strip_prefix('"') {
                let path = path.split('"').next().unwrap_or_default().to_owned();
                for (method, needle) in METHODS {
                    if span.contains(needle) {
                        routes.push((method.to_owned(), path.clone()));
                    }
                }
            }
            rest = &arguments[end..];
        }
        routes.sort();
        routes.dedup();
        routes
    }

    #[tokio::test]
    async fn every_mutating_admin_trade_and_notification_route_rejects_a_viewer_without_the_csrf_header(
    ) {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let viewer = super::test_admin_cookie(
            &application,
            &crate::auth::AdminIdentity {
                subject: "sso:router-gate".to_owned(),
                tenant: String::new(),
                role: "viewer".to_owned(),
                grants: vec![crate::auth::TenantGrant {
                    incarnation: None,
                    tenant: String::new(),
                    role: "viewer".to_owned(),
                }],
                credential_version: 1,
            },
        );

        let signed_message = r#"{"document":{"issuer":"pin","audience":"","purpose":"status","nonce":"pin","expires_at":0,"body":{}},"signature":"pin"}"#;
        // (method, route template, query, JSON body). Bodies only need to
        // satisfy each handler's JSON extractor: the gate fires before any
        // validation, so a minimal well-formed value reaches the 403.
        let covered: [(&str, &str, &str, &str); 49] = [
            ("POST", "/api/admin/logout", "", ""),
            ("PUT", "/api/admin/backups", "", "{}"),
            ("POST", "/api/admin/backups", "", ""),
            (
                "POST",
                "/api/admin/backups/restore",
                "",
                r#"{"source":"local","id":"pin"}"#,
            ),
            (
                "POST",
                "/api/admin/tenants",
                "",
                r#"{"key":"pin","label":"pin"}"#,
            ),
            (
                "POST",
                "/api/admin/receiving-storage",
                "",
                r#"{"storage":{"path":"/pin","filesystem":"pin","source":"pin","mount_root":"pin","inode":"1","service_uid":0}}"#,
            ),
            ("PUT", "/api/admin/settings", "", "{}"),
            (
                "POST",
                "/api/admin/settings/retention-clock/acknowledge",
                "",
                r#"{"observed_at":1}"#,
            ),
            ("PATCH", "/api/admin/tenants/{key}", "", "{}"),
            ("DELETE", "/api/admin/tenants/{key}", "", ""),
            ("PUT", "/api/admin/branding/{key}", "", r#"{"name":"pin"}"#),
            ("DELETE", "/api/admin/branding/{key}", "", ""),
            ("PUT", "/api/admin/branding/{key}/logo", "", ""),
            ("DELETE", "/api/admin/branding/{key}/logo", "", ""),
            ("POST", "/api/admin/tenant", "", r#"{"tenant":"pin"}"#),
            (
                "POST",
                "/api/admin/principals/revoke",
                "",
                r#"{"subject":"pin"}"#,
            ),
            (
                "POST",
                "/api/admin/principals/unblock",
                "",
                r#"{"subject":"pin"}"#,
            ),
            (
                "POST",
                "/api/admin/principals/purge",
                "",
                r#"{"subject":"pin"}"#,
            ),
            ("POST", "/api/admin/outbound-grants", "", ""),
            ("PATCH", "/api/admin/outbound-grants/{id}", "", "{}"),
            ("DELETE", "/api/admin/outbound-grants/{id}", "", ""),
            (
                "POST",
                "/api/admin/automation-tokens",
                "",
                r#"{"label":"pin","expires_days":1}"#,
            ),
            ("DELETE", "/api/admin/automation-tokens/{id}", "", ""),
            (
                "DELETE",
                "/api/admin/backups/{source}/{id}",
                "",
                r#"{"source":"local"}"#,
            ),
            ("POST", "/api/admin/outbound-files", "?path=pin", ""),
            ("DELETE", "/api/admin/outbound-files", "?path=pin", ""),
            (
                "POST",
                "/api/admin/password",
                "",
                r#"{"current":"pin","new":"pin2"}"#,
            ),
            ("POST", "/api/admin/links", "", r#"{"label":"pin"}"#),
            ("POST", "/api/admin/links/{id}", "", "{}"),
            ("PATCH", "/api/admin/links/{id}", "", "{}"),
            ("DELETE", "/api/admin/links/{id}", "", ""),
            ("DELETE", "/api/admin/links/{id}/uploads/{upload}", "", ""),
            (
                "DELETE",
                "/api/admin/links/{id}/uploads/{upload}/files/{index}",
                "",
                "",
            ),
            ("POST", "/api/port/enroll", "", signed_message),
            ("POST", "/api/port/status", "", signed_message),
            ("POST", "/api/port/rotate", "", signed_message),
            (
                "POST",
                "/api/trade-routes",
                "",
                r#"{"invitation":{"document":{"issuer":"pin","audience":"","purpose":"invitation","nonce":"pin","expires_at":0,"body":{}},"signature":"pin"},"name":"pin","notifications":{"mode":"off"}}"#,
            ),
            (
                "PUT",
                "/api/trade-routes/port",
                "",
                r#"{"name":"pin","address":"https://port.example"}"#,
            ),
            (
                "POST",
                "/api/trade-routes/endpoints",
                "",
                r#"{"id":"pin00000","name":"pin","category":"internal","forwarding":false,"metadata_keys":[],"notifications":{"mode":"off"}}"#,
            ),
            (
                "POST",
                "/api/trade-routes/invitations",
                "",
                r#"{"endpoint":"pin","expires_in":3600}"#,
            ),
            ("POST", "/api/trade-routes/inspect", "", "{}"),
            (
                "PUT",
                "/api/trade-routes/{id}",
                "",
                r#"{"revision":1,"state":"active","cancel_active":false,"notifications":{"mode":"off"}}"#,
            ),
            ("POST", "/api/trade-routes/{id}/test", "", ""),
            ("POST", "/api/trade-routes/{id}/rotate", "", ""),
            (
                "PUT",
                "/api/trade-routes/{id}/address",
                "",
                r#"{"address":"https://port.example","revision":1}"#,
            ),
            ("POST", "/api/notifications", "", "{}"),
            (
                "PUT",
                "/api/notifications/defaults",
                "",
                r#"{"mode":"off"}"#,
            ),
            ("DELETE", "/api/notifications/{id}", "", r#"{"revision":1}"#),
            ("POST", "/api/notifications/{id}/test", "", ""),
        ];

        // Sync the table against app.rs: a new mutating route on these
        // prefixes cannot merge without appearing here (or below as a
        // documented exemption).
        let source = std::fs::read_to_string("src/app.rs").unwrap();
        let prefixes = [
            "/api/admin",
            "/api/port",
            "/api/trade-routes",
            "/api/notifications",
        ];
        let mut registered: Vec<(String, String)> = registered_mutating_routes(&source)
            .into_iter()
            .filter(|(_, path)| prefixes.iter().any(|prefix| path.starts_with(prefix)))
            .collect();
        // Pre-authentication endpoints: they act for the caller's password or
        // one-time desktop sign-in code, never on the presented session, so
        // the viewer and CSRF gates do not apply.
        let exempt = [
            ("POST", "/api/admin/login"),
            ("POST", "/api/admin/sso/exchange"),
        ];
        registered.retain(|pair| !exempt.contains(&(pair.0.as_str(), pair.1.as_str())));
        let mut expected: Vec<(String, String)> = covered
            .iter()
            .map(|(method, template, _, _)| (method.to_string(), template.to_string()))
            .collect();
        expected.sort();
        assert_eq!(
            registered, expected,
            "route table out of sync with src/app.rs"
        );

        for (method, template, query, body) in covered {
            let mut path = String::new();
            let mut characters = template.chars();
            while let Some(character) = characters.next() {
                if character == '{' {
                    while characters.next() != Some('}') {}
                    path.push('1');
                } else {
                    path.push(character);
                }
            }
            let uri = format!("{path}{query}");
            let mut builder = Request::builder()
                .method(method)
                .uri(&uri)
                .header("cookie", &viewer)
                .extension(ConnectInfo(std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    1234,
                ))));
            if !body.is_empty() {
                builder = builder.header("content-type", "application/json");
            }
            let request = builder.body(Body::from(body)).unwrap();
            let response = app::router(application.clone())
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {uri}");
        }
    }

    #[tokio::test]
    async fn audit_export_requires_sign_in_and_emits_jsonl() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application.store.audit(
            "",
            "",
            "link_created",
            "l-1",
            &serde_json::json!({ "label": "x" }),
        );

        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/audit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let expected_cursor = application
            .store
            .audit_export(None, 0, 0, 100)
            .unwrap()
            .last()
            .map(|row| format!("{},{}", row.at, row.rowid));
        let router = app::router(application.clone());
        for limit in ["0", "10001"] {
            let response = app::router(application.clone())
                .oneshot(
                    Request::get(format!("/api/admin/audit?limit={limit}"))
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
        let request = Request::builder()
            .uri("/api/admin/audit?limit=100")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"audit.jsonl\""
        );
        assert_eq!(
            response
                .headers()
                .get("x-votport-audit-cursor")
                .and_then(|value| value.to_str().ok()),
            expected_cursor.as_deref()
        );
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(line["event"], "link_created");
        assert_eq!(line["subject"], "l-1");
        assert_eq!(line["detail"]["label"], "x");
    }

    #[tokio::test]
    async fn audit_export_cursor_walks_tied_timestamps_to_empty_terminal_page() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .with(|connection| {
                for index in 0..5 {
                    connection.execute(
                        "INSERT INTO audit_log(at,tenant,actor,event,subject,detail)
                         VALUES (?1,'','','cursor_test',?2,'{}')",
                        rusqlite::params![77_i64, format!("subject-{index}")],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        let cookie = login_cookie(app::router(application.clone())).await;
        let mut after_rowid = 0;
        let mut subjects = Vec::new();
        for expected_count in [2, 2, 1] {
            let response = app::router(application.clone())
                .oneshot(
                    Request::get(format!(
                        "/api/admin/audit?limit=2&since=77&after_rowid={after_rowid}&event=cursor_test"
                    ))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let cursor = response
                .headers()
                .get("x-votport-audit-cursor")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            use http_body_util::BodyExt as _;
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let rows: Vec<_> = String::from_utf8(body.to_vec())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect();
            assert_eq!(rows.len(), expected_count);
            let last = rows.last().unwrap();
            let expected_cursor = format!("77,{}", last["rowid"]);
            assert_eq!(cursor.as_deref(), Some(expected_cursor.as_str()));
            after_rowid = last["rowid"].as_u64().unwrap();
            subjects.extend(
                rows.into_iter()
                    .map(|row| row["subject"].as_str().unwrap().to_owned()),
            );
        }
        assert_eq!(
            subjects,
            (0..5)
                .map(|index| format!("subject-{index}"))
                .collect::<Vec<_>>()
        );

        let response = app::router(application)
            .oneshot(
                Request::get(format!(
                    "/api/admin/audit?limit=2&since=77&after_rowid={after_rowid}&event=cursor_test"
                ))
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("x-votport-audit-cursor").is_none());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn audit_recent_cursor_returns_newest_rows_and_rejects_mixed_cursors() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login_cookie(app::router(application.clone())).await;
        application
            .store
            .audit("", "", "oldest", "a", &serde_json::json!({}));
        application
            .store
            .audit("", "", "middle", "b", &serde_json::json!({}));
        application
            .store
            .audit("", "", "newest", "c", &serde_json::json!({}));

        let response = app::router(application.clone())
            .oneshot(
                Request::get("/api/admin/audit?before_rowid=0&limit=2")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let events: Vec<_> = String::from_utf8(body.to_vec())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
            .collect();
        assert_eq!(events, vec!["newest", "middle"]);

        let response = app::router(application)
            .oneshot(
                Request::get("/api/admin/audit?before_rowid=3&since=0")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn holdings_reports_platform_usage() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login_cookie(app::router(application.clone())).await;
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"label":"holdings"}"#))
            .unwrap();
        assert_eq!(
            app::router(application.clone())
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let response = app::router(application)
            .oneshot(
                Request::get("/api/admin/holdings")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["holdings"][0]["tenant"], "");
        assert_eq!(json["holdings"][0]["links"], 1);
        assert_eq!(json["holdings"][0]["received_bytes"], 0);
    }

    #[tokio::test]
    async fn received_file_delete_refuses_an_active_session() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let path = application.config.receive_dir.join("received.bin");
        std::fs::write(&path, b"keep").unwrap();
        application
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                id: "link".to_owned(),
                label: "link".to_owned(),
                tenant: String::new(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,

                notifications: None,
                uploads: vec![crate::store::UploadRecord {
                    partial: false,
                    log: Vec::new(),
                    id: "upload".to_owned(),
                    started_at: 0,
                    completed_at: 1,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: Some("http".to_owned()),
                    package_root: "root".to_owned(),
                    total_bytes: 4,
                    files: vec![crate::store::FileRecord {
                        path: "received.bin".to_owned(),
                        stored_as: "received.bin".to_owned(),
                        bytes: 4,
                        suite: "blake3".to_owned(),
                        root: "root".to_owned(),
                        receipt: false,
                        deleted: false,
                    }],
                }],
                events: Vec::new(),
            })
            .unwrap();
        application
            .sessions
            .insert(
                "session".to_owned(),
                "link".to_owned(),
                String::new(),
                tokio::sync::mpsc::channel(1).0,
            )
            .unwrap();

        let cookie = login_cookie(app::router(application.clone())).await;
        let response = app::router(application.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/admin/links/link/uploads/upload/files/0")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        let link = application.store.link("", "link").unwrap().unwrap();
        assert!(!link.uploads[0].files[0].deleted);
        let pin = application
            .sessions
            .try_pin_link("link")
            .expect("file delete released its link pin");
        drop(pin);
    }

    #[tokio::test]
    async fn https_public_url_marks_cookies_secure() {
        let directory = tempfile::tempdir().unwrap();
        let router = app::router(testing::build(directory.path()));
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/login")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                1234,
            ))))
            .body(Body::from(format!(
                "{{\"password\":\"{}\"}}",
                testing::TEST_PASSWORD
            )))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(cookie.contains("; Secure"), "cookie was {cookie}");
    }

    /// Audit finding 105: kill the process in the crash window between the
    /// filesystem unlink and the next store commit (the audit row), then pin
    /// what boot finds. The child arms FAIL_AFTER_UNLINK and aborts inside
    /// delete_received_file_sync; the parent reopens the crashed data
    /// directory and asserts the established reconciliation behavior: the
    /// tombstone that carries the quota decrement commits before the unlink,
    /// so the reopened store already agrees with the disk.
    #[test]
    fn abort_between_unlink_and_store_commit_leaves_the_quota_reconciled() {
        const ROOT: &str = "FAIL_AFTER_UNLINK_ROOT";
        if let Some(root) = std::env::var_os(ROOT) {
            let app = testing::build(std::path::Path::new(&root));
            std::fs::create_dir_all(&app.config.receive_dir).unwrap();
            let record = crate::receiving::tests::published_file(
                &app.config.receive_dir.join("report.bin"),
                b"crash window payload",
                vot_verifier::Suite::Blake3Bao64,
                &app.signer,
            );
            app.store
                .insert_link(crate::store::Link {
                    retention_days: None,
                    id: "crash-link".to_owned(),
                    tenant: String::new(),
                    label: "crash".to_owned(),
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
                        id: "crash-upload".to_owned(),
                        started_at: 1,
                        completed_at: 2,
                        replayed_chunks: 0,
                        rejected_chunks: 0,
                        transport: None,
                        package_root: "crash-root".to_owned(),
                        total_bytes: record.bytes,
                        files: vec![record],
                    }],
                    events: Vec::new(),
                })
                .unwrap();
            let identity = auth::AdminIdentity::local_admin();
            let response =
                delete_received_file_sync(&app, &identity, "crash-link", "crash-upload", 0);
            unreachable!("the abort switch must kill the child before the commit: {response:?}");
        }
        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("child.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "api::admin::tests::handler_tests::abort_between_unlink_and_store_commit_leaves_the_quota_reconciled",
                "--nocapture",
            ])
            .env("FAIL_AFTER_UNLINK", "1")
            .env(ROOT, directory.path())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child did not abort in time: {}",
                std::fs::read_to_string(&log_path).unwrap_or_default()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let crash = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            !status.success(),
            "the child should have died from the abort switch: {status} / {crash}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            assert_eq!(
                status.signal(),
                Some(6),
                "the child should have died from SIGABRT: {crash}"
            );
        }
        assert!(
            crash.contains("FAIL_AFTER_UNLINK: received file unlinked"),
            "the child did not reach the crash window: {crash}"
        );

        // Boot over the crashed directory: the tombstone that decrements the
        // quota commits before the unlink, so the reopened store already
        // agrees with the disk and no reconciliation pass is needed.
        let app = testing::build(directory.path());
        assert!(!app.config.receive_dir.join("report.bin").exists());
        assert!(!app
            .config
            .receive_dir
            .join("report.bin.vot-receipt")
            .exists());
        let upload = app
            .store
            .link_upload("", "crash-link", "crash-upload")
            .unwrap()
            .unwrap();
        assert!(
            upload.files[0].deleted,
            "the tombstone committed before the abort"
        );
        assert_eq!(
            app.store.tenant_stored("").unwrap(),
            (0, 0),
            "the deleted file's bytes must not be counted after the crash"
        );
        let (bytes_hi, bytes_lo, state) = app
            .store
            .with(|connection| {
                connection.query_row(
                    "SELECT bytes_hi,bytes_lo,state FROM tenant_quota_usage WHERE tenant=''",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
            })
            .unwrap();
        assert_eq!(
            (bytes_hi, bytes_lo, state),
            (0, 0, 0),
            "the quota cache kept the tombstone's answer"
        );
        let rows = app.store.audit_export(None, 0, 0, 100).unwrap();
        assert!(
            rows.iter().all(|row| row.event != "received_file_deleted"),
            "the abort must land before the audit row commits"
        );
    }
}

#[cfg(test)]
mod tenant_authz_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::auth::{self, TenantGrant};

    /// Mints an admin session cookie for an arbitrary identity, exactly as
    /// the SSO callback would after verifying a provider response.
    fn cookie_for(app: &App, tenant: &str, role: &str) -> String {
        let identity = auth::AdminIdentity {
            subject: format!("sso:{tenant}"),
            tenant: tenant.to_owned(),
            role: role.to_owned(),
            grants: vec![TenantGrant {
                incarnation: None,
                tenant: tenant.to_owned(),
                role: role.to_owned(),
            }],
            credential_version: 1,
        };
        super::test_admin_cookie(app, &identity)
    }

    #[tokio::test]
    async fn audit_scope_requires_platform_authority_in_both_cursors_and_search() {
        use http_body_util::BodyExt as _;
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        for key in ["acme", "other"] {
            application
                .store
                .insert_tenant(crate::store::tests::test_tenant(key))
                .unwrap();
        }
        for tenant in ["", "acme", "other"] {
            application.store.audit(
                tenant,
                "actor",
                "scope_test",
                &format!("needle-{tenant}"),
                &json!({}),
            );
        }
        for (tenant, role, all) in [
            ("", "viewer", false),
            ("", "admin", true),
            ("", "auditor", true),
            ("acme", "viewer", false),
            ("acme", "admin", false),
            ("acme", "auditor", false),
        ] {
            let cookie = cookie_for(&application, tenant, role);
            for uri in [
                "/api/admin/audit?q=needle",
                "/api/admin/audit?before_rowid=0&q=needle",
                "/api/admin/search?q=needle",
            ] {
                let response = app::router(application.clone())
                    .oneshot(
                        Request::get(uri)
                            .header("cookie", &cookie)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                if role == "auditor" && uri.contains("/search") {
                    assert_eq!(response.status(), StatusCode::FORBIDDEN);
                    continue;
                }
                assert_eq!(response.status(), StatusCode::OK, "{tenant}/{role} {uri}");
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                if uri.contains("/search") {
                    let body = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
                    assert!(body.get("audit").is_none(), "{tenant}/{role} {uri}");
                    continue;
                }
                let subjects: Vec<String> = std::str::from_utf8(&bytes)
                    .unwrap()
                    .lines()
                    .map(|line| {
                        serde_json::from_str::<serde_json::Value>(line).unwrap()["subject"]
                            .as_str()
                            .unwrap()
                            .to_owned()
                    })
                    .collect();
                let mut expected: Vec<_> = if all {
                    ["", "acme", "other"].to_vec()
                } else {
                    vec![tenant]
                }
                .into_iter()
                .map(|tenant| format!("needle-{tenant}"))
                .collect();
                let mut subjects = subjects;
                subjects.sort();
                expected.sort();
                assert_eq!(subjects, expected, "{tenant}/{role} {uri}");
            }
        }
    }

    /// The `AuditorIdentity` newtype makes a bare `require_admin` result
    /// unusable without destructuring; this pin keeps the destructuring
    /// sites to the definition, the construction in `require_admin`, and
    /// the two gates, in admin.rs where they live. Raise the count only
    /// for a deliberate new gate.
    #[test]
    fn auditor_identity_is_unwrapped_only_by_the_two_gates() {
        let admin_rs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api/admin.rs");
        let text = std::fs::read_to_string(admin_rs).unwrap();
        // Split so this test's own source cannot match the needle.
        let needle = concat!("AuditorIdentity", "(");
        assert_eq!(
            text.matches(needle).count(),
            4,
            "AuditorIdentity must appear only as the struct definition, the \
             construction in require_admin, and the unwraps in \
             require_operator and require_platform_admin"
        );
    }

    #[tokio::test]
    async fn auditor_sees_the_audit_trail_and_nothing_else() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "auditor");
        let get = |path: &'static str| {
            let cookie = cookie.clone();
            let application = application.clone();
            async move {
                app::router(application)
                    .oneshot(
                        Request::get(path)
                            .header("cookie", cookie)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            }
        };
        let session = get("/api/admin/session").await;
        assert_eq!(session.status(), StatusCode::OK);
        let session: serde_json::Value = serde_json::from_slice(
            &http_body_util::BodyExt::collect(session.into_body())
                .await
                .unwrap()
                .to_bytes(),
        )
        .unwrap();
        assert_eq!(session["pages"], serde_json::json!(["audit"]));
        assert_eq!(get("/api/admin/audit").await.status(), StatusCode::OK);
        for denied in [
            "/api/admin/links",
            "/api/admin/outbound-files",
            "/api/admin/outbound-grants",
            "/api/admin/automation-tokens",
        ] {
            assert_eq!(
                get(denied).await.status(),
                StatusCode::FORBIDDEN,
                "{denied} must refuse the auditor role"
            );
        }
        for denied in ["/api/workflows/events", "/api/workflows/events/export"] {
            let response = app::router(application.clone())
                .oneshot(
                    Request::get(denied)
                        .header("cookie", cookie.clone())
                        .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{denied}");
        }
        // Platform routes already demand the admin role.
        assert_eq!(
            get("/api/admin/holdings").await.status(),
            StatusCode::FORBIDDEN
        );
        // Writes fail on the role check even with the CSRF header present.
        let write = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/links")
                    .header("cookie", cookie.clone())
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"label":"x","dest":"d"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(write.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn workflow_project_mutation_is_mirrored_for_platform_auditor() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let project = crate::workflow::tests::project();
        let admin_cookie =
            super::test_admin_cookie(&application, &auth::AdminIdentity::local_admin());
        let response = app::router(application.clone())
            .oneshot(
                Request::put("/api/workflows/projects")
                    .header("cookie", admin_cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&project).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let signed = application
            .store
            .delivery_events("", 0, 100)
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "project_policy_changed")
            .expect("project mutation must append its signed control event");
        assert!(signed.verify());

        let cookie = cookie_for(&application, "", "auditor");
        let response = app::router(application)
            .oneshot(
                Request::get("/api/admin/audit?event=project_policy_changed")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.lines().any(|line| {
                let row: serde_json::Value = serde_json::from_str(line).unwrap();
                row["event"] == "project_policy_changed"
                    && row["tenant"] == ""
                    && row["subject"] == ""
                    && row["detail"]["delivery_event_id"] == signed.id
                    && row["detail"]["delivery_event_hash"] == signed.hash
                    && row["detail"]["delivery_event_issuer"] == signed.issuer
                    && row["detail"]["summary"]["project_id"] == project.id
            }),
            "signed project event was not mirrored into the auditor JSONL export: {text:?}"
        );
    }

    #[tokio::test]
    async fn tenant_admins_cannot_reach_other_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::Tenant {
                retention_days: None,
                incarnation: String::new(),
                key: "acme".to_owned(),
                label: String::new(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        application
            .store
            .insert_link(crate::store::Link {
                tenant: "acme".to_owned(),
                ..crate::store::Link {
                    retention_days: None,
                    id: "acme-link".to_owned(),
                    tenant: "acme".to_owned(),
                    label: "acme".to_owned(),
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
                }
            })
            .unwrap();

        // An admin whose only grant is the default tenant: acme's link is
        // invisible, and switching without the grant is refused.
        let outsider = cookie_for(&application, "", "admin");
        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/links")
                    .header("cookie", &outsider)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["links"].as_array().unwrap().len(), 0);

        // Foreign IDs are rejected before touching the global lifecycle pin.
        assert!(application.sessions.pin_link_for_delete("acme-link"));
        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &outsider)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"legal_hold":true}"#))
            .unwrap();
        assert_eq!(
            router.oneshot(request).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let router = app::router(application.clone());
        let request = Request::builder()
            .method("DELETE")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &outsider)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.oneshot(request).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        application.sessions.unpin_link("acme-link");

        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/tenant")
            .header("cookie", &outsider)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"tenant":"acme"}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // An acme admin sees exactly their own link and can toggle it.
        let acme_admin = cookie_for(&application, "acme", "admin");
        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/links")
                    .header("cookie", &acme_admin)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let links = json["links"].as_array().unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["id"], "acme-link");

        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &acme_admin)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"active":false}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &acme_admin)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"legal_hold":true}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            application
                .store
                .link("acme", "acme-link")
                .unwrap()
                .unwrap()
                .legal_hold
        );
        assert!(application
            .store
            .audit_export(Some("acme"), 0, 0, 100)
            .unwrap()
            .iter()
            .any(|row| row.event == "link_legal_hold_changed"));

        assert!(application.sessions.pin_link_for_delete("acme-link"));
        let router = app::router(application.clone());
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &acme_admin)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"legal_hold":false}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        application.sessions.unpin_link("acme-link");
        assert!(
            application
                .store
                .link("acme", "acme-link")
                .unwrap()
                .unwrap()
                .legal_hold
        );

        // A viewer gets read-only access: reads pass, writes are 403.
        let viewer = cookie_for(&application, "acme", "viewer");
        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/links")
                    .header("cookie", &viewer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let router = app::router(application);
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/links/acme-link")
            .header("cookie", &viewer)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(r#"{"active":true}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

#[cfg(test)]
mod branding_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::auth::{self, TenantGrant};

    fn cookie_for(app: &App, tenant: &str, role: &str) -> String {
        let identity = auth::AdminIdentity {
            subject: format!("sso:{tenant}:{role}"),
            tenant: tenant.to_owned(),
            role: role.to_owned(),
            grants: vec![TenantGrant {
                incarnation: None,
                tenant: tenant.to_owned(),
                role: role.to_owned(),
            }],
            credential_version: 1,
        };
        super::test_admin_cookie(app, &identity)
    }

    fn insert_tenant(app: &App, key: &str) {
        app.store
            .insert_tenant(crate::store::Tenant {
                retention_days: None,
                incarnation: String::new(),
                key: key.to_owned(),
                label: String::new(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
    }

    async fn put_branding(app: &Arc<App>, cookie: &str, key: &str, body: &str) -> StatusCode {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/admin/branding/{key}"))
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .header("x-votport", "1")
            .body(Body::from(body.to_owned()))
            .unwrap();
        app::router(app.clone())
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    async fn put_logo(
        app: &Arc<App>,
        cookie: &str,
        key: &str,
        content_type: &str,
        bytes: Vec<u8>,
    ) -> StatusCode {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/admin/branding/{key}/logo"))
            .header("cookie", cookie)
            .header("content-type", content_type)
            .header("x-votport", "1")
            .body(Body::from(bytes))
            .unwrap();
        app::router(app.clone())
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    #[test]
    fn cancelled_branding_unlink_keeps_its_target_admitted() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        for key in ["acme", "other"] {
            application
                .store
                .insert_tenant(crate::store::tests::test_tenant(key))
                .unwrap();
        }
        application
            .store
            .set_branding(&crate::store::Branding {
                tenant: "acme".into(),
                logo_ext: "png".into(),
                ..Default::default()
            })
            .unwrap();
        let path = paths::branding_logo_path(&application.config.data_dir, "acme", "png");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"old").unwrap();
        let mut identity = auth::AdminIdentity::local_admin();
        identity.subject = "sso:editor".into();
        // The branding gate is scoped to the active tenant, so the editor
        // works while switched into the tenant being unlinked.
        identity.tenant = "acme".into();
        identity.grants = ["acme", "other"]
            .map(|tenant| auth::TenantGrant {
                incarnation: None,
                tenant: tenant.into(),
                role: "admin".into(),
            })
            .to_vec();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            super::test_admin_cookie(&application, &identity)
                .parse()
                .unwrap(),
        );
        headers.insert("x-votport", "1".parse().unwrap());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (release, wait) = std::sync::mpsc::channel();
            let (ready, started) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                ready.send(()).unwrap();
                wait.recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap();
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), started)
                .await
                .unwrap()
                .unwrap();
            let request = tokio::spawn(delete_branding(
                State(application.clone()),
                Path("acme".into()),
                headers,
            ));
            for _ in 0..200 {
                if application.store.branding("acme").unwrap().is_none() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            assert!(application.store.branding("acme").unwrap().is_none());
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
            let held = application.sessions.active_outbound_for_tenant("acme");
            let mut headers = HeaderMap::new();
            headers.insert(
                header::COOKIE,
                super::test_admin_cookie(&application, &auth::AdminIdentity::local_admin())
                    .parse()
                    .unwrap(),
            );
            headers.insert("x-votport", "1".parse().unwrap());
            let deletion = delete_tenant(
                State(application.clone()),
                Path("acme".into()),
                headers.clone(),
            )
            .await;
            release.send(()).unwrap();
            blocker.await.unwrap();
            assert_eq!(
                held, 1,
                "the queued unlink must retain its target guard after cancellation"
            );
            assert_eq!(deletion.unwrap_err().status, StatusCode::CONFLICT);
            for _ in 0..200 {
                if application.sessions.active_outbound_for_tenant("acme") == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            assert_eq!(application.sessions.active_outbound_for_tenant("acme"), 0);
            assert!(!path.exists());
            let _ = delete_tenant(State(application.clone()), Path("acme".into()), headers)
                .await
                .unwrap();
            application
                .store
                .insert_tenant(crate::store::tests::test_tenant("acme"))
                .unwrap();
            std::fs::write(&path, b"new").unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"new");
        });
    }

    #[tokio::test]
    async fn footer_branding_is_bounded_escaped_and_preserved_by_older_clients() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let platform = cookie_for(&application, "", "admin");
        let valid = json!({"name":"Studio", "footer_text":"<script> & studio", "footer_link_label":"Privacy <policy>", "footer_link_url":"HTTPS://studio.example/privacy#terms"});
        assert_eq!(
            put_branding(&application, &platform, "default", &valid.to_string()).await,
            StatusCode::OK
        );
        assert_eq!(
            put_branding(&application, &platform, "default", r#"{"name":"Renamed"}"#).await,
            StatusCode::OK
        );
        let saved = application.store.branding("").unwrap().unwrap();
        assert_eq!(saved.footer_text, "<script> & studio");
        assert_eq!(
            saved.footer_link_url,
            "https://studio.example/privacy#terms"
        );
        let html = crate::api::branding_footer(&saved);
        assert!(html.contains("&lt;script&gt; &amp; studio"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("Privacy &lt;policy&gt;"));
        assert!(html.contains("noopener noreferrer"));
        for (field, value) in [
            ("footer_text", "x".repeat(161)),
            ("footer_text", "line\nbreak".into()),
            ("footer_link_label", "x".repeat(41)),
            ("footer_link_label", "".into()),
            ("footer_link_url", "javascript:alert(1)".into()),
            ("footer_link_url", "https://user:secret@example.com".into()),
            (
                "footer_link_url",
                format!("https://example.com/{}", "x".repeat(2048)),
            ),
            (
                "footer_link_url",
                format!("https://example.com/{}", "é".repeat(400)),
            ),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = json!(value);
            assert_eq!(
                put_branding(&application, &platform, "default", &invalid.to_string()).await,
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        assert_eq!(
            put_branding(
                &application,
                &cookie_for(&application, "", "viewer"),
                "default",
                &valid.to_string()
            )
            .await,
            StatusCode::FORBIDDEN
        );
        insert_tenant(&application, "studio");
        assert_eq!(
            put_branding(
                &application,
                &cookie_for(&application, "studio", "admin"),
                "default",
                &valid.to_string()
            )
            .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            put_branding(
                &application,
                &platform,
                "default",
                r#"{"name":"Studio","footer_text":"","footer_link_label":"","footer_link_url":""}"#
            )
            .await,
            StatusCode::OK
        );
        assert!(application
            .store
            .branding("")
            .unwrap()
            .unwrap()
            .footer_text
            .is_empty());
    }

    #[tokio::test]
    async fn put_branding_validates_color_and_stores_the_row() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let platform = cookie_for(&application, "", "admin");

        for bad in ["#12zz99", "12ab99", "#12ab9", "#12ab999", "red"] {
            let body = format!(r#"{{"name":"Acme","color":"{bad}"}}"#);
            assert_eq!(
                put_branding(&application, &platform, "default", &body).await,
                StatusCode::UNPROCESSABLE_ENTITY,
                "color {bad:?} was admitted"
            );
        }
        assert!(application.store.branding("").unwrap().is_none());

        assert_eq!(
            put_branding(
                &application,
                &platform,
                "default",
                r##"{"name":"  Acme Corp  ","color":"#12Ab99"}"##
            )
            .await,
            StatusCode::OK
        );
        let row = application.store.branding("").unwrap().unwrap();
        assert_eq!(row.name, "Acme Corp");
        assert_eq!(row.color, "#12Ab99");
        assert_eq!(row.logo_ext, "");

        // Empty color clears the accent; DELETE removes the row entirely.
        assert_eq!(
            put_branding(
                &application,
                &platform,
                "default",
                r#"{"name":"Acme Corp","color":""}"#
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(application.store.branding("").unwrap().unwrap().color, "");
        let request = Request::builder()
            .method("DELETE")
            .uri("/api/admin/branding/default")
            .header("cookie", &platform)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app::router(application.clone())
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(application.store.branding("").unwrap().is_none());
    }

    #[tokio::test]
    async fn wrong_tenant_admin_cannot_brand_other_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        insert_tenant(&application, "acme");
        insert_tenant(&application, "beta");
        let acme = cookie_for(&application, "acme", "admin");

        for foreign in ["default", "beta", "missing"] {
            assert_eq!(
                put_branding(
                    &application,
                    &acme,
                    foreign,
                    r#"{"name":"Acme","color":""}"#
                )
                .await,
                StatusCode::FORBIDDEN,
                "{foreign} accepted a foreign admin"
            );
        }
        assert_eq!(
            put_branding(&application, &acme, "acme", r#"{"name":"Acme","color":""}"#).await,
            StatusCode::OK
        );
        assert_eq!(
            application.store.branding("acme").unwrap().unwrap().name,
            "Acme"
        );

        // A platform admin brands any tenant; an unknown one is 404.
        let platform = cookie_for(&application, "", "admin");
        assert_eq!(
            put_branding(
                &application,
                &platform,
                "beta",
                r#"{"name":"Beta","color":""}"#
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            put_branding(
                &application,
                &platform,
                "missing",
                r#"{"name":"X","color":""}"#
            )
            .await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn switched_admin_brands_only_the_active_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        insert_tenant(&application, "acme");
        insert_tenant(&application, "bloom");
        // A principal holding both the default-tenant and acme grants sits
        // switched into acme: the default grant must not reach other
        // tenants' branding while the session is elsewhere.
        let mut identity = auth::AdminIdentity {
            subject: "sso:mixed".into(),
            tenant: "acme".into(),
            role: "admin".into(),
            grants: vec![
                TenantGrant {
                    incarnation: None,
                    tenant: String::new(),
                    role: "admin".into(),
                },
                TenantGrant {
                    incarnation: None,
                    tenant: "acme".into(),
                    role: "admin".into(),
                },
            ],
            credential_version: 1,
        };
        let switched = super::test_admin_cookie(&application, &identity);
        assert_eq!(
            put_branding(&application, &switched, "bloom", r#"{"name":"Bloom"}"#).await,
            StatusCode::FORBIDDEN,
            "a default-tenant grant must not follow a switched-in admin"
        );
        assert_eq!(
            put_branding(&application, &switched, "default", r#"{"name":"X"}"#).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            put_branding(&application, &switched, "acme", r#"{"name":"Acme"}"#).await,
            StatusCode::OK
        );
        // Back on the default tenant, the platform grant brands any tenant.
        identity.tenant = String::new();
        let platform = super::test_admin_cookie(&application, &identity);
        assert_eq!(
            put_branding(&application, &platform, "bloom", r#"{"name":"Bloom"}"#).await,
            StatusCode::OK
        );
        assert_eq!(
            application.store.branding("bloom").unwrap().unwrap().name,
            "Bloom"
        );
    }

    #[tokio::test]
    async fn logo_upload_enforces_type_magic_and_size() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let platform = cookie_for(&application, "", "admin");
        let png = b"\x89PNG\r\n\x1a\npixels".to_vec();

        assert_eq!(
            put_logo(&application, &platform, "default", "image/gif", png.clone()).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            put_logo(
                &application,
                &platform,
                "default",
                "image/png",
                b"\xff\xd8\xffjpeg".to_vec()
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut oversized = png.clone();
        oversized.resize(MAX_LOGO_BYTES + 1, 0);
        assert_eq!(
            put_logo(&application, &platform, "default", "image/png", oversized).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert!(application.store.branding("").unwrap().is_none());

        assert_eq!(
            put_logo(&application, &platform, "default", "image/png", png).await,
            StatusCode::OK
        );
        let row = application.store.branding("").unwrap().unwrap();
        assert_eq!(row.logo_ext, "png");
        let stored = paths::branding_logo_path(&application.config.data_dir, "", "png");
        assert!(stored.is_file());

        // Replacing with another type removes the stale file.
        assert_eq!(
            put_logo(
                &application,
                &platform,
                "default",
                "image/svg+xml",
                b"<svg xmlns='http://www.w3.org/2000/svg'/>".to_vec()
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            application.store.branding("").unwrap().unwrap().logo_ext,
            "svg"
        );
        assert!(!stored.exists());

        // DELETE clears the extension and the file; name and color survive.
        let request = Request::builder()
            .method("DELETE")
            .uri("/api/admin/branding/default/logo")
            .header("cookie", &platform)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app::router(application.clone())
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            application.store.branding("").unwrap().unwrap().logo_ext,
            ""
        );
        assert!(!paths::branding_logo_path(&application.config.data_dir, "", "svg").exists());
    }

    #[tokio::test]
    async fn tenant_delete_removes_the_branding_row_and_logo_file() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        insert_tenant(&application, "acme");
        let platform = cookie_for(&application, "", "admin");
        assert_eq!(
            put_logo(
                &application,
                &platform,
                "acme",
                "image/png",
                b"\x89PNG\r\n\x1a\npixels".to_vec()
            )
            .await,
            StatusCode::OK
        );
        let logo = paths::branding_logo_path(&application.config.data_dir, "acme", "png");
        assert!(logo.is_file());

        let request = Request::builder()
            .method("DELETE")
            .uri("/api/admin/tenants/acme")
            .header("cookie", &platform)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app::router(application.clone())
                .oneshot(request)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(application.store.branding("acme").unwrap().is_none());
        assert!(!logo.exists());
    }

    #[tokio::test]
    async fn branding_mutations_require_the_csrf_header() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let platform = cookie_for(&application, "", "admin");
        let request = Request::builder()
            .method("PUT")
            .uri("/api/admin/branding/default")
            .header("cookie", &platform)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"Acme","color":""}"#))
            .unwrap();
        let response = app::router(application.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "missing X-Votport header");
    }
}

#[cfg(test)]
mod tenant_offboard_tests {
    use super::*;

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use std::sync::Arc;

    use crate::api::testing;
    use crate::app;
    use crate::session::InsertError;
    use crate::store::{Link, Tenant};

    async fn login_cookie(router: axum::Router) -> String {
        let request = Request::builder()
            .method("POST")
            .uri("/api/admin/login")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                1234,
            ))))
            .body(Body::from(format!(
                "{{\"password\":\"{}\"}}",
                testing::TEST_PASSWORD
            )))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response
            .headers()
            .get(header::SET_COOKIE)
            .expect("login sets a cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    fn named_tenant(key: &str) -> Tenant {
        Tenant {
            retention_days: None,
            incarnation: String::new(),
            key: key.to_owned(),
            label: key.to_owned(),
            admin_group: None,
            max_total_bytes: None,
            max_links: None,
            max_sessions: None,
            created_at: 0,
        }
    }

    fn default_link(id: &str, dest: &str) -> Link {
        Link {
            retention_days: None,
            id: id.to_owned(),
            tenant: String::new(),
            label: id.to_owned(),
            dest: dest.to_owned(),
            password_hash: None,
            created_at: 0,
            expires_at: None,
            max_bytes: None,
            active: true,
            legal_hold: false,

            notifications: None,
            uploads: Vec::new(),
            events: Vec::new(),
        }
    }

    fn named_link(tenant: &str, id: &str) -> Link {
        Link {
            tenant: tenant.to_owned(),
            ..default_link(id, "")
        }
    }

    fn write_dummy(receive_dir: &std::path::Path, key: &str) -> std::path::PathBuf {
        let dir = receive_dir.join(crate::paths::TENANT_STORAGE_DIR).join(key);
        std::fs::create_dir_all(&dir).unwrap();
        crate::paths::tighten_dir(&dir);
        std::fs::write(dir.join("x.bin"), b"hello").unwrap();
        dir
    }

    fn write_outbound_dummy(outbound_dir: &std::path::Path, key: &str) -> std::path::PathBuf {
        let dir = outbound_dir
            .join(crate::paths::TENANT_STORAGE_DIR)
            .join(key);
        std::fs::create_dir_all(&dir).unwrap();
        crate::paths::tighten_dir(&dir);
        std::fs::write(dir.join("x.bin"), b"hello").unwrap();
        dir
    }

    async fn create_tenant_req(
        application: Arc<App>,
        cookie: &str,
        key: &str,
    ) -> axum::http::Response<axum::body::Body> {
        let router = app::router(application);
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/tenants")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"key":"{key}","label":"{key}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn delete_tenant_req(
        application: Arc<App>,
        cookie: &str,
        key: &str,
    ) -> axum::http::Response<axum::body::Body> {
        let router = app::router(application);
        router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/admin/tenants/{key}"))
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn recreated_tenant_rejects_active_and_inactive_old_grants() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        for key in ["acme", "other"] {
            application.store.insert_tenant(named_tenant(key)).unwrap();
        }
        let mut identity = auth::AdminIdentity::local_admin();
        identity.subject = "sso:editor".into();
        identity.tenant = "acme".into();
        identity.grants = ["acme", "other"]
            .map(|tenant| auth::TenantGrant {
                incarnation: None,
                tenant: tenant.into(),
                role: "admin".into(),
            })
            .to_vec();
        let active = super::test_admin_cookie(&application, &identity);
        identity.tenant = "other".into();
        let inactive = super::test_admin_cookie(&application, &identity);
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, active.parse().unwrap());
        assert!(super::test_require_admin(&application, &headers).is_ok());
        assert_eq!(
            application.store.remove_tenant("acme").unwrap(),
            crate::store::TenantRemoval::Deleted
        );
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        assert!(
            super::test_require_admin(&application, &headers).is_err(),
            "a recreated tenant must not inherit an old active grant"
        );
        headers.insert(header::COOKIE, inactive.parse().unwrap());
        headers.insert("x-votport", "1".parse().unwrap());
        let authenticated = super::test_require_admin(&application, &headers).unwrap();
        assert_eq!(authenticated.tenant, "other");
        assert!(branding_tenant(&application, "acme", &authenticated).is_err());
        assert!(switch_tenant(
            State(application.clone()),
            headers,
            Json(SwitchTenantRequest {
                tenant: "acme".into()
            })
        )
        .await
        .is_err());
        let local = super::test_admin_cookie(&application, &auth::AdminIdentity::local_admin());
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, local.parse().unwrap());
        assert!(super::test_require_admin(&application, &headers)
            .unwrap()
            .grants
            .iter()
            .any(|grant| grant.tenant == "acme"));
    }

    #[tokio::test]
    async fn authenticated_tenant_requests_fence_deletion_only_for_their_namespace() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        for key in ["acme", "other"] {
            application.store.insert_tenant(named_tenant(key)).unwrap();
        }
        let mut identity = auth::AdminIdentity::local_admin();
        identity.subject = "sso:editor".into();
        identity.tenant = "acme".into();
        identity.grants = vec![auth::TenantGrant {
            incarnation: None,
            tenant: "acme".into(),
            role: "admin".into(),
        }];
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            super::test_admin_cookie(&application, &identity)
                .parse()
                .unwrap(),
        );
        let admitted = super::test_require_admin(&application, &headers).unwrap();
        let local = super::test_admin_cookie(&application, &auth::AdminIdentity::local_admin());
        assert_eq!(
            delete_tenant_req(application.clone(), &local, "acme")
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            delete_tenant_req(application.clone(), &local, "other")
                .await
                .status(),
            StatusCode::OK
        );
        drop(admitted);
        assert_eq!(
            delete_tenant_req(application.clone(), &local, "acme")
                .await
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn delete_purges_the_receive_subtree() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");
        assert!(tenant_dir.join("x.bin").exists());

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!tenant_dir.exists());

        let rows = application.store.audit_export(None, 0, 0, 100).unwrap();
        let deleted = rows
            .iter()
            .find(|row| row.event == "tenant_deleted")
            .expect("tenant_deleted audit");
        assert_eq!(deleted.detail["purged_receive"], true);
        assert_eq!(deleted.detail["row_deleted"], true);
        assert!(application.store.tenant("acme").unwrap().is_none());
    }

    #[tokio::test]
    async fn inactive_storage_refuses_tenant_and_file_deletion() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");
        let cookie = login_cookie(app::router(application.clone())).await;
        *application.receiving.lock().unwrap() = Err("mount unavailable".into());
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(tenant_dir.join("x.bin").exists());
        assert!(application.store.tenant("acme").unwrap().is_some());
        let headers = HeaderMap::from_iter([
            (header::COOKIE, cookie.parse().unwrap()),
            (
                axum::http::HeaderName::from_static("x-votport"),
                "1".parse().unwrap(),
            ),
        ]);
        let response = delete_received_file(
            State(application),
            Path(("link".into(), "upload".into(), 0)),
            headers,
        )
        .await;
        assert_eq!(
            response.unwrap_err().into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn delete_purges_the_outbound_subtree_without_receive_files() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let outbound_dir = write_outbound_dummy(&application.config.outbound_dir, "acme");
        let default_file = application.config.outbound_dir.join("default.bin");
        std::fs::write(&default_file, b"keep").unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!outbound_dir.exists());
        assert!(!application
            .config
            .receive_dir
            .join(crate::paths::TENANT_STORAGE_DIR)
            .join("acme")
            .exists());
        assert!(default_file.exists());
        let rows = application.store.audit_export(None, 0, 0, 100).unwrap();
        let deleted = rows
            .iter()
            .find(|row| row.event == "tenant_deleted")
            .expect("tenant_deleted audit");
        assert_eq!(deleted.detail["purged_receive"], false);
        assert_eq!(deleted.detail["purged_outbound"], true);
    }

    #[tokio::test]
    async fn absent_tenant_retry_purges_leftover_outbound_subtree() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let outbound_dir = write_outbound_dummy(&application.config.outbound_dir, "acme");

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!outbound_dir.exists());
        assert!(application.store.tenant("acme").unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_refuses_an_active_outbound_operation() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let operation = application.sessions.try_begin_outbound("acme").unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(application.store.tenant("acme").unwrap().is_some());
        drop(operation);
    }

    #[tokio::test]
    async fn live_link_refuses_delete_and_unpins() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        application
            .store
            .insert_link(named_link("acme", "still-live"))
            .unwrap();
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(tenant_dir.join("x.bin").exists());
        assert!(!application.sessions.tenant_pinned("acme"));
        application
            .sessions
            .insert(
                "s1".to_owned(),
                "still-live".to_owned(),
                "acme".to_owned(),
                tokio::sync::mpsc::channel(1).0,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn store_read_failure_during_delete_unpins_the_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        rusqlite::Connection::open(application.config.data_dir.join("votport.db"))
            .unwrap()
            .execute_batch("DROP TABLE links")
            .unwrap();

        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!application.sessions.tenant_pinned("acme"));
    }

    #[tokio::test]
    async fn link_delete_refuses_an_active_session_then_unpins() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(default_link("busy", ""))
            .unwrap();
        application
            .sessions
            .insert(
                "session".to_owned(),
                "busy".to_owned(),
                String::new(),
                tokio::sync::mpsc::channel(1).0,
            )
            .unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let request = || {
            Request::builder()
                .method("DELETE")
                .uri("/api/admin/links/busy")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .body(Body::empty())
                .unwrap()
        };
        let response = app::router(application.clone())
            .oneshot(request())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(application.store.link("", "busy").unwrap().is_some());

        application.sessions.remove("session");
        let response = app::router(application.clone())
            .oneshot(request())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(application.store.link("", "busy").unwrap().is_none());
    }

    #[tokio::test]
    async fn live_session_refuses_delete_and_leaves_files() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");
        application
            .sessions
            .insert(
                "live".to_owned(),
                "link".to_owned(),
                "acme".to_owned(),
                tokio::sync::mpsc::channel(1).0,
            )
            .unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(tenant_dir.join("x.bin").exists());
        assert!(!application.sessions.tenant_pinned("acme"));
        assert!(application.store.tenant("acme").unwrap().is_some());
    }

    #[tokio::test]
    async fn unknown_key_without_a_directory_is_404() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let keep = application.config.receive_dir.join("keep.bin");
        std::fs::write(&keep, b"root").unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "ghost").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(keep.exists());
        // The private receiving namespace is not tenant content.
        let mut entries: Vec<_> = std::fs::read_dir(&application.config.receive_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != ".vot-stage")
            .collect();
        entries.sort();
        assert_eq!(entries, vec![std::ffi::OsString::from("keep.bin")]);
        assert!(!application.sessions.tenant_pinned("ghost"));
    }

    #[tokio::test]
    async fn leftover_retry_ignores_a_same_named_default_destination() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");
        application
            .store
            .insert_link(default_link("root-dest", "acme"))
            .unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!tenant_dir.exists());
        assert!(application.store.link("", "root-dest").unwrap().is_some());
        assert!(!application.sessions.tenant_pinned("acme"));
    }

    #[tokio::test]
    async fn leftover_retry_purges_an_orphaned_directory() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");
        assert!(application.store.tenant("acme").unwrap().is_none());

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!tenant_dir.exists());
        let rows = application.store.audit_export(None, 0, 0, 100).unwrap();
        let deleted = rows
            .iter()
            .find(|row| row.event == "tenant_deleted")
            .expect("tenant_deleted audit");
        assert_eq!(deleted.detail["purged_receive"], true);
        assert_eq!(deleted.detail["row_deleted"], false);
    }

    #[tokio::test]
    async fn overlapping_delete_does_not_unpin_until_owner_finishes() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let (entered, release) = application.sessions.arm_delete_stall();
        let first_app = application.clone();
        let first_cookie = cookie.clone();
        let first =
            tokio::spawn(async move { delete_tenant_req(first_app, &first_cookie, "acme").await });
        entered.await.unwrap();
        assert!(application.sessions.tenant_pinned("acme"));
        assert!(application.store.tenant("acme").unwrap().is_none());

        let second = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let body = second.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"]
                .as_str()
                .unwrap_or_default()
                .contains("already in progress"),
            "error was {json}"
        );
        assert!(application.sessions.tenant_pinned("acme"));
        assert!(tenant_dir.join("x.bin").exists());

        let created = create_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(created.status(), StatusCode::CONFLICT);
        assert!(application.sessions.tenant_pinned("acme"));
        assert!(application.store.tenant("acme").unwrap().is_none());

        release.send(()).unwrap();
        let first_resp = first.await.unwrap();
        assert_eq!(first_resp.status(), StatusCode::OK);
        assert!(!application.sessions.tenant_pinned("acme"));
        assert!(!tenant_dir.exists());
    }

    #[tokio::test]
    async fn tenant_mutation_cancelled_before_purge_releases_its_pin() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let path = tenant_receive_dir(&application.config.receive_dir, "acme").unwrap();
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("frame"), b"old").unwrap();
        let cookie = super::test_admin_cookie(&application, &auth::AdminIdentity::local_admin());
        let (entered, _release) = application.sessions.arm_delete_stall();
        let request_app = application.clone();
        let request_cookie = cookie.clone();
        let request =
            tokio::spawn(
                async move { delete_tenant_req(request_app, &request_cookie, "acme").await },
            );
        tokio::time::timeout(std::time::Duration::from_secs(2), entered)
            .await
            .unwrap()
            .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(!application.sessions.tenant_pinned("acme"));
        assert!(application.store.tenant("acme").unwrap().is_none());
        assert!(path.join("frame").exists());
        assert_eq!(
            delete_tenant_req(application.clone(), &cookie, "acme")
                .await
                .status(),
            StatusCode::OK
        );
        assert!(!path.exists());
        assert_eq!(
            create_tenant_req(application, &cookie, "acme")
                .await
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn tenant_mutation_creation_excludes_deletion_until_insert_finishes() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        let path = tenant_receive_dir(&application.config.receive_dir, "acme").unwrap();
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("frame"), b"old").unwrap();
        let cookie = super::test_admin_cookie(&application, &auth::AdminIdentity::local_admin());
        let (entered, release) = application.sessions.arm_delete_stall();
        let request_app = application.clone();
        let request_cookie = cookie.clone();
        let request =
            tokio::spawn(
                async move { create_tenant_req(request_app, &request_cookie, "acme").await },
            );
        tokio::time::timeout(std::time::Duration::from_secs(2), entered)
            .await
            .unwrap()
            .unwrap();
        let deletion = delete_tenant_req(application.clone(), &cookie, "acme")
            .await
            .status();
        let retained =
            application.store.tenant("acme").unwrap().is_some() && path.join("frame").exists();
        release.send(()).unwrap();
        let creation = request.await.unwrap().status();
        assert_eq!(deletion, StatusCode::CONFLICT);
        assert!(retained);
        assert_eq!(creation, StatusCode::CONFLICT);
        assert!(!application.sessions.tenant_pinned("acme"));
        assert_eq!(
            delete_tenant_req(application.clone(), &cookie, "acme")
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            create_tenant_req(application, &cookie, "acme")
                .await
                .status(),
            StatusCode::OK
        );
    }

    #[test]
    fn tenant_mutation_cancelled_purge_retains_ownership_until_all_files_are_removed() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(named_tenant("acme"))
            .unwrap();
        application
            .store
            .set_branding(&crate::store::Branding {
                tenant: "acme".into(),
                logo_ext: "png".into(),
                ..Default::default()
            })
            .unwrap();
        let paths = [
            tenant_receive_dir(&application.config.receive_dir, "acme")
                .unwrap()
                .join("received"),
            tenant_outbound_dir(&application.config.outbound_dir, "acme")
                .unwrap()
                .join("library"),
            paths::branding_logo_path(&application.config.data_dir, "acme", "png"),
        ];
        for path in &paths {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"old").unwrap();
        }
        let cookie = super::test_admin_cookie(&application, &auth::AdminIdentity::local_admin());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (entered_purge, release_purge) = application.sessions.arm_tenant_purge_stall();
            let request_app = application.clone();
            let request_cookie = cookie.clone();
            let request = tokio::spawn(async move {
                delete_tenant_req(request_app, &request_cookie, "acme").await
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), entered_purge)
                .await
                .unwrap()
                .unwrap();
            assert!(application.store.tenant("acme").unwrap().is_none());
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
            assert!(application.sessions.tenant_pinned("acme"));
            assert_eq!(
                create_tenant_req(application.clone(), &cookie, "acme")
                    .await
                    .status(),
                StatusCode::CONFLICT
            );
            assert!(application.sessions.tenant_pinned("acme"));
            assert!(paths.iter().all(|path| path.exists()));
            assert_eq!(
                create_tenant_req(application.clone(), &cookie, "acme")
                    .await
                    .status(),
                StatusCode::CONFLICT
            );
            let weak = Arc::downgrade(&application);
            drop(application);
            let application = weak
                .upgrade()
                .expect("the purge must retain the application and its storage leases");
            release_purge.send(()).unwrap();
            for _ in 0..200 {
                if !application.sessions.tenant_pinned("acme") {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            assert!(!application.sessions.tenant_pinned("acme"));
            assert!(paths.iter().all(|path| !path.exists()));
            assert_eq!(
                create_tenant_req(application, &cookie, "acme")
                    .await
                    .status(),
                StatusCode::OK
            );
            for path in paths {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, b"new").unwrap();
                assert_eq!(std::fs::read(path).unwrap(), b"new");
            }
        });
    }

    #[tokio::test]
    async fn create_tenant_refuses_a_pinned_key() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let _pin = application.sessions.try_pin_tenant("acme").unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = create_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"]
                .as_str()
                .unwrap_or_default()
                .contains("already in progress"),
            "error was {json}"
        );
        assert!(application.store.tenant("acme").unwrap().is_none());
        assert!(application.sessions.tenant_pinned("acme"));
    }

    #[tokio::test]
    async fn create_tenant_refuses_a_multi_segment_key() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        // A key with a separator passes admit_dest but would be unreachable:
        // DELETE matches one path segment and join_under refuses the
        // component, so uploads into it fail too.
        let response = create_tenant_req(application.clone(), &cookie, "a/b").await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(application.store.tenants().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_removes_a_legacy_multi_segment_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // A row of the shape create_tenant used to accept. Deleting it must
        // drop the row without touching disk: no upload ever published under
        // such a key, so that path can only hold a default-tenant link's
        // files.
        application
            .store
            .insert_tenant(crate::store::Tenant {
                retention_days: None,
                incarnation: String::new(),
                key: "clients/acme".to_owned(),
                label: "legacy".to_owned(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        // What a default-tenant link with dest "clients/acme" would have
        // received. The delete must not reach it.
        let bystander = application.config.receive_dir.join("clients").join("acme");
        std::fs::create_dir_all(&bystander).unwrap();
        std::fs::write(bystander.join("statement.pdf"), b"kept").unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "clients%2Facme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(application.store.tenants().unwrap().is_empty());
        assert!(bystander.join("statement.pdf").exists());
    }

    #[tokio::test]
    async fn delete_purges_only_the_reserved_tenant_subtree() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::Tenant {
                retention_days: None,
                incarnation: String::new(),
                key: "acme".to_owned(),
                label: "acme".to_owned(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        application
            .store
            .insert_link(default_link("default-link", "acme"))
            .unwrap();
        let default_dir = application.config.receive_dir.join("acme");
        std::fs::create_dir_all(&default_dir).unwrap();
        std::fs::write(default_dir.join("invoice.pdf"), b"kept").unwrap();
        let tenant_dir = write_dummy(&application.config.receive_dir, "acme");

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(application.store.tenant("acme").unwrap().is_none());
        assert!(!tenant_dir.exists());
        assert!(default_dir.join("invoice.pdf").exists());
        assert!(!application.sessions.tenant_pinned("acme"));
    }

    #[tokio::test]
    async fn unknown_key_with_a_colliding_link_but_no_directory_is_404() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // A colliding link exists, but there is no tenant row and nothing on
        // disk, so there is no purge to conflict with: this is a 404, not the
        // purge refusal.
        application
            .store
            .insert_link(default_link("root-dest", "acme"))
            .unwrap();
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = delete_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_tenant_does_not_claim_the_same_named_default_folder() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let occupied = application.config.receive_dir.join("acme");
        std::fs::create_dir_all(&occupied).unwrap();
        std::fs::write(occupied.join("invoice.pdf"), b"someone else's").unwrap();

        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = create_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(application.store.tenants().unwrap().len(), 1);
        assert!(occupied.join("invoice.pdf").exists());
    }

    #[test]
    fn stored_paths_resolve_inside_the_owning_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let root = &application.config.receive_dir;
        // stored_as is relative to the tenant's own subtree, because the
        // session builds it from the link dest while the tenant prefix is
        // added separately when the destination directory is assembled.
        assert_eq!(
            stored_path(&application, "acme", "inbox/a.txt").unwrap(),
            root.join(crate::paths::TENANT_STORAGE_DIR)
                .join("acme")
                .join("inbox")
                .join("a.txt")
        );
        // The default tenant has no prefix.
        assert_eq!(
            stored_path(&application, "", "inbox/a.txt").unwrap(),
            root.join("inbox").join("a.txt")
        );
        // The two must never resolve to the same file: that is one namespace
        // deleting another's bytes.
        assert_ne!(
            stored_path(&application, "acme", "inbox/a.txt").unwrap(),
            stored_path(&application, "", "inbox/a.txt").unwrap()
        );
    }

    #[tokio::test]
    async fn create_tenant_accepts_an_empty_folder() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        // An empty directory holds nobody's files, so it is not a collision.
        std::fs::create_dir_all(application.config.receive_dir.join("acme")).unwrap();
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = create_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn create_tenant_allows_a_same_named_default_link_destination() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(default_link("root-dest", "acme"))
            .unwrap();
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        let response = create_tenant_req(application.clone(), &cookie, "acme").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(application.store.tenants().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn create_link_allows_a_dest_named_after_a_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let router = app::router(application.clone());
        let cookie = login_cookie(router).await;
        assert_eq!(
            create_tenant_req(application.clone(), &cookie, "acme")
                .await
                .status(),
            StatusCode::OK
        );
        for dest in ["acme", "acme/invoices"] {
            let response = app::router(application.clone())
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/admin/links")
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"label":"invoices","dest":"{dest}"}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "dest {dest}");
        }
        assert_eq!(application.store.links("").unwrap().len(), 2);
    }

    #[test]
    fn tenant_keys_are_single_segments() {
        assert_eq!(admit_tenant_key("acme").ok().as_deref(), Some("acme"));
        assert_eq!(admit_tenant_key("/acme/").ok().as_deref(), Some("acme"));
        assert_eq!(
            admit_tenant_key("acme-1_ok").ok().as_deref(),
            Some("acme-1_ok")
        );
        for bad in [
            "a/b",
            "",
            "default",
            "..",
            "clients/acme",
            "Acme",
            "café",
            "acme.inc",
            "acme corp",
        ] {
            assert!(admit_tenant_key(bad).is_err(), "{bad} was admitted");
        }
        // Delete admits a multi-segment key so legacy rows stay removable.
        assert_eq!(
            admit_tenant_ref("clients/acme").ok().as_deref(),
            Some("clients/acme")
        );
        for bad in ["", "default", ".."] {
            assert!(admit_tenant_ref(bad).is_err(), "{bad} was admitted");
        }
    }

    #[test]
    fn insert_returns_pinned_while_delete_holds_the_pin() {
        let sessions = crate::session::Sessions::new();
        let _pin = sessions.try_pin_tenant("acme").unwrap();
        let err = sessions
            .insert(
                "s".to_owned(),
                "l".to_owned(),
                "acme".to_owned(),
                tokio::sync::mpsc::channel(1).0,
            )
            .unwrap_err();
        assert_eq!(err, InsertError::TenantPinned);
    }
}

#[cfg(test)]
mod ops_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;

    #[tokio::test]
    async fn metrics_refuse_a_bad_token_and_serve_counts() {
        let directory = tempfile::tempdir().unwrap();
        let mut config_source = testing_config_with_token(directory.path(), Some("secret-token"));
        let application = build_with(config_source.take().unwrap());
        let router = app::router(application.clone());

        let response = router
            .oneshot(
                Request::get("/metrics")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/metrics")
                    .header("authorization", "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        use http_body_util::BodyExt as _;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("votport_tenants"));
        assert!(text.contains("votport_received_bytes{tenant=\"default\"} 0"));
        assert!(text.contains("votport_sessions_active"));
    }

    fn testing_config_with_token(
        _directory: &std::path::Path,
        token: Option<&str>,
    ) -> Option<crate::config::Config> {
        let mut config = testing_config_snapshot();
        config.metrics_token = token.map(str::to_owned);
        Some(config)
    }

    fn testing_config_snapshot() -> crate::config::Config {
        // testing::build owns its tempdirs; this variant re-derives the same
        // config with a metrics token so /metrics authz can be exercised.
        let directory = std::env::temp_dir().join(format!(
            "votport-metrics-test-{}",
            crate::auth::random_token()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let mut config = testing_config_public();
        config.data_dir = directory.join("data");
        config.receive_dir = directory.join("received");
        config.outbound_dir = directory.join("outbound");
        config
    }

    fn testing_config_public() -> crate::config::Config {
        crate::config::Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            push_bind: None,
            push_certificate: None,
            push_private_key: None,
            push_advertise: None,
            serve_bind: None,
            serve_advertise: None,
            data_dir: std::path::PathBuf::from("/nonexistent"),
            receive_dir: std::path::PathBuf::from("/nonexistent"),
            outbound_dir: std::path::PathBuf::from("/nonexistent"),
            web_root: std::path::PathBuf::from("../web"),
            admin_password_hash: crate::auth::hash_password(testing::TEST_PASSWORD).unwrap(),
            admin_token_tag: "tag".to_owned(),

            smtp_host: None,
            smtp_port: 587,
            smtp_starttls: true,
            smtp_username: None,
            smtp_password: None,
            scim_token: None,
            replica_token: None,
            smtp_from: None,

            public_url: None,
            max_upload_bytes: 1024 * 1024,
            workflow_snapshot_bytes: 4 * 1024 * 1024,
            allow_hidden: false,
            session_idle_secs: 60,
            audit_retention_days: 400,
            upload_retention_days: 0,
            default_max_total_bytes: None,
            default_max_links: None,
            default_max_sessions: None,
            public_password_login: true,
            require_provisioning: false,
            metrics_token: None,
            max_total_sessions: 32,
            max_link_sessions: 8,
            sso_session_secs: 7 * 24 * 3600,
            trusted_proxies: Vec::new(),
            oidc: None,
        }
    }

    fn build_with(config: crate::config::Config) -> std::sync::Arc<App> {
        app::build(config).unwrap()
    }
}

#[cfg(test)]
mod backup_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;

    async fn login(application: Arc<App>) -> String {
        let response = app::router(application)
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
                        testing::TEST_PASSWORD
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

    #[tokio::test]
    async fn backup_route_serves_a_snapshot_and_requires_sign_in() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .audit("", "", "probe", "", &serde_json::json!({}));
        let cookie = super::test_admin_cookie(
            &application,
            &auth::AdminIdentity {
                subject: "platform-admin".to_owned(),
                tenant: String::new(),
                role: "admin".to_owned(),
                grants: vec![auth::TenantGrant {
                    incarnation: None,
                    tenant: String::new(),
                    role: "admin".to_owned(),
                }],
                credential_version: 1,
            },
        );
        let backup_audits = || {
            application
                .store
                .audit_recent_filtered(
                    None,
                    0,
                    100,
                    AuditFilters {
                        event: Some("backup_created"),
                        query: None,
                    },
                )
                .unwrap()
        };

        // Unauthenticated requests are refused.
        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/backup")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(backup_audits().is_empty());

        // Signed in, the route serves a non-empty SQLite snapshot.
        // Without the CSRF header a cross-site navigation cannot trigger a snapshot.
        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/backup")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(backup_audits().is_empty());

        let router = app::router(application.clone());
        let response = router
            .oneshot(
                Request::get("/api/admin/backup")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_length = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!body.is_empty());
        // SQLite databases begin with the magic string.
        assert!(body.starts_with(b"SQLite format 3\0"));
        assert_eq!(content_length, Some(body.len()));
        let audits = backup_audits();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].actor, "platform-admin");
        assert_eq!(audits[0].detail["bytes"], body.len());
    }

    #[tokio::test]
    async fn backup_settings_match_the_browser_contract_and_redact_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login(application.clone()).await;
        let local_path = application.config.data_dir.join("custom-backups");
        std::fs::create_dir(&local_path).unwrap();
        let body = serde_json::json!({
            "enabled": true,
            "interval_secs": 3600,
            "retention_days": 7,
            "retention_count": 5,
            "destination": "local",
            "local_path": local_path,
            "s3_endpoint": null,
            "s3_region": null,
            "s3_bucket": null,
            "s3_prefix": null,
            "s3_path_style": false,
            "encrypt": true,
            "access_key_id": "visible-only-on-write",
            "secret_access_key": "never-return-this",
            "passphrase": "correct horse battery staple"
        });

        let response = app::router(application.clone())
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let guard = application.backup_lock.lock().await;
        let response = app::router(application.clone())
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let error = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{}",
            String::from_utf8_lossy(&error)
        );
        drop(guard);

        let response = app::router(application.clone())
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app::router(application.clone())
            .oneshot(
                Request::get("/api/admin/backups")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("never-return-this"));
        assert!(!text.contains("correct horse battery staple"));
        let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response["config"]["interval_secs"], 3600);
        assert_eq!(response["config"]["passphrase_configured"], true);

        let mut unknown = body;
        unknown["unexpected"] = serde_json::json!(true);
        let response = app::router(application.clone())
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(unknown.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/backups")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let created: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let id = created["id"].as_str().unwrap();
        let shutdown_application = Arc::clone(&application);
        let shutdown_waiter = tokio::spawn(async move {
            shutdown_application.wait_for_shutdown().await;
        });
        tokio::task::yield_now().await;
        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/backups/restore")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(
                        serde_json::json!({ "source": "local", "id": id }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let restored: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(restored["pending"], true);
        tokio::time::timeout(std::time::Duration::from_secs(1), shutdown_waiter)
            .await
            .unwrap()
            .unwrap();

        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/backups")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            crate::backup::scheduler(application),
        )
        .await
        .expect("scheduler must exit after shutdown");
    }

    /// Audit finding 551: a non-archive offered to the restore endpoint
    /// answers one fixed 422, retryable false, instead of a retryable 500
    /// quoting the tar parser.
    #[tokio::test]
    async fn restore_refuses_a_non_archive_with_one_fixed_422() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login(application.clone()).await;
        let backups = crate::backup::ensure_backups_dir(&application.config.data_dir).unwrap();
        let id = "votport-backup-v2-notanarchive.tar";
        std::fs::write(backups.join(id), b"this is not a tar archive").unwrap();
        let response = app::router(application)
            .oneshot(
                Request::post("/api/admin/backups/restore")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(
                        serde_json::json!({ "source": "local", "id": id }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["retryable"], false);
        assert_eq!(
            body["error"],
            "This file is not a votport backup this server can restore."
        );
    }

    /// Audit finding 555: a newer-schema archive is refused with the same
    /// fixed 422 instead of a 500, and the backup inventory names the server
    /// schema so an operator can compare an archive before restoring it.
    #[tokio::test]
    async fn restore_refuses_a_newer_schema_archive_without_a_500_and_the_inventory_names_the_schema(
    ) {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login(application.clone()).await;
        let backups = crate::backup::ensure_backups_dir(&application.config.data_dir).unwrap();
        let stage = application
            .config
            .data_dir
            .join(".votport-test-newer-schema.tar");
        crate::backup::create_archive(
            &application.store,
            &application.config.data_dir,
            &stage,
            crate::store::SCHEMA_VERSION + 1,
        )
        .unwrap();
        let id = "votport-backup-v2-newer-schema.tar";
        std::fs::rename(&stage, backups.join(id)).unwrap();
        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/backups/restore")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(
                        serde_json::json!({ "source": "local", "id": id }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["retryable"], false);
        assert_eq!(
            body["error"],
            "This file is not a votport backup this server can restore."
        );
        let response = app::router(application)
            .oneshot(
                Request::get("/api/admin/backups")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["schema_version"], crate::store::SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn backup_pause_reports_current_restore_blocker_without_replacing_history() {
        use crate::backup::{BackupConfig, BackupSecrets, BackupStatus, Destination};

        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login(application.clone()).await;
        let data_dir = &application.config.data_dir;
        let backup_dir = crate::backup::ensure_backups_dir(data_dir).unwrap();
        let local_inventory_error =
            crate::backup::inventory_local_root(&backup_dir, data_dir).err();
        let history = serde_json::to_vec(&BackupStatus {
            last_attempt_at: Some(123),
            last_success_at: Some(100),
            last_error: Some("previous upload failed".into()),
            ..BackupStatus::default()
        })
        .unwrap();
        let status_path = data_dir.join(crate::backup::STATUS_FILE);
        std::fs::write(&status_path, &history).unwrap();
        crate::backup::write_secrets(
            data_dir,
            &BackupSecrets {
                access_key_id: Some("test-key".into()),
                secret_access_key: Some("test-secret".into()),
                ..BackupSecrets::default()
            },
        )
        .unwrap();
        let pending = data_dir.join(crate::backup::PENDING_FILE);
        for state in ["pending", "unreadable", "cleared"] {
            if state == "pending" {
                std::fs::write(&pending, b"pending").unwrap();
            } else {
                std::fs::remove_file(&pending).unwrap();
                if state == "unreadable" {
                    std::os::unix::fs::symlink(&pending, &pending).unwrap();
                }
            }
            let expected_pause = crate::backup::ensure_no_pending_restore(data_dir).err();
            assert_eq!(expected_pause.is_some(), state != "cleared");
            let config = BackupConfig {
                destination: if state == "cleared" {
                    Destination::Local
                } else {
                    Destination::S3
                },
                s3_endpoint: Some("http://127.0.0.1:1".into()),
                s3_region: Some("us-east-1".into()),
                s3_bucket: Some("backups".into()),
                s3_path_style: true,
                ..BackupConfig::default()
            };
            application
                .store
                .put_settings(
                    "test",
                    &[(
                        crate::backup::SETTING_KEY.into(),
                        crate::store::SettingWrite::Set(serde_json::to_string(&config).unwrap()),
                    )],
                )
                .unwrap();
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                app::router(application.clone()).oneshot(
                    Request::get("/api/admin/backups")
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap(),
                ),
            )
            .await
            .expect("restore pause must not wait for remote inventory")
            .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(body["paused_reason"], serde_json::json!(expected_pause));
            assert_eq!(
                body["inventory_error"],
                serde_json::json!(local_inventory_error)
            );
            assert_eq!(body["status"]["last_success_at"], 100);
            assert_eq!(body["status"]["last_error"], "previous upload failed");
            assert_eq!(std::fs::read(&status_path).unwrap(), history);
        }
    }

    #[tokio::test]
    async fn missing_backup_mount_can_be_repaired_in_app() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = login(application.clone()).await;
        let missing = application.config.data_dir.join("detached-backups");
        std::fs::create_dir(&missing).unwrap();
        let mut body = serde_json::json!({
            "enabled": false,
            "interval_secs": 3600,
            "retention_days": 7,
            "retention_count": 5,
            "destination": "local",
            "local_path": missing,
            "s3_endpoint": null,
            "s3_region": null,
            "s3_bucket": null,
            "s3_prefix": null,
            "s3_path_style": false,
            "encrypt": false
        });
        let response = app::router(application.clone())
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        std::fs::remove_dir(&missing).unwrap();

        let response = app::router(application.clone())
            .oneshot(
                Request::get("/api/admin/backups")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert!(response["inventory_error"].is_string());
        assert_eq!(response["config"]["local_path"], body["local_path"]);

        body["local_path"] = serde_json::Value::Null;
        let response = app::router(application)
            .oneshot(
                Request::put("/api/admin/backups")
                    .header("content-type", "application/json")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Audit finding 500: a failed snapshot export used to leave SQLite's
    /// 0-byte, world-readable destination in data/backups, where only the
    /// 30-day legacy prune would take it; the export guard removes it.
    #[test]
    fn failed_snapshot_export_removes_the_partial_file() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        let store = crate::store::Store::open(&data).unwrap();
        // Corrupt every page past the first so the header still opens but
        // VACUUM INTO fails after SQLite has created its destination: the
        // exact leftover the finding observed.
        let database = data.join("votport.db");
        let size = std::fs::metadata(&database).unwrap().len();
        assert!(size > 4096, "a fresh store database spans multiple pages");
        {
            use std::io::{Seek as _, Write as _};
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&database)
                .unwrap();
            let mut offset = 4096;
            while offset < size {
                file.seek(std::io::SeekFrom::Start(offset)).unwrap();
                file.write_all(&[0xDE; 1024]).unwrap();
                offset += 1024;
            }
        }
        std::fs::remove_file(data.join("votport.db-wal")).ok();
        std::fs::remove_file(data.join("votport.db-shm")).ok();

        let backups = directory.path().join("backups");
        std::fs::create_dir(&backups).unwrap();
        let destination = backups.join("votport-test.db");
        let error = export_database_snapshot(&store, &backups, &destination).unwrap_err();
        assert_ne!(error, "backup root is busy", "{error}");
        assert!(
            !destination.exists(),
            "the partial export must be removed: {error}"
        );
    }
}

#[cfg(test)]
mod settings_api_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::auth::{self, TenantGrant};
    use crate::store::SettingWrite;

    #[test]
    fn deployment_profiles_report_detection_and_missing_mounts() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            deployment_commit_profile(&directory.path().join("missing")),
            None
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            deployment_commit_profile(directory.path()),
            Some("balanced")
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(deployment_commit_profile(directory.path()), None);
    }

    #[tokio::test]
    async fn sso_session_lifetime_follows_the_settings_overlay() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let sso = auth::AdminIdentity {
            subject: "sso:user".to_owned(),
            tenant: String::new(),
            role: "admin".to_owned(),
            grants: vec![TenantGrant {
                incarnation: None,
                tenant: String::new(),
                role: "admin".to_owned(),
            }],
            credential_version: 1,
        };
        // Env default: 7 days for both SSO and break-glass.
        let cookie = issue_admin_cookie(&application, &sso, None).unwrap();
        assert!(cookie.contains("Max-Age=604800"), "{cookie}");
        application
            .store
            .put_settings(
                "sso:admin",
                &[(
                    "sso_session_secs".to_owned(),
                    SettingWrite::Set("3600".to_owned()),
                )],
            )
            .unwrap();
        let cookie = issue_admin_cookie(&application, &sso, None).unwrap();
        assert!(cookie.contains("Max-Age=3600"), "{cookie}");
        let later = now_unix() + 86_400;
        let capped = issue_admin_cookie(&application, &sso, Some(later)).unwrap();
        assert!(capped.contains("Max-Age=3600"), "{capped}");
        let (_, expires) = auth::verify_admin_token(
            &application.secret,
            &admin_token_phc(&application).unwrap(),
            auth::cookie_value(&capped, ADMIN_COOKIE).unwrap(),
        )
        .unwrap();
        assert!(
            expires < later,
            "the current policy can shorten the original expiry"
        );
        // Break-glass keeps its fixed lifetime regardless of the setting.
        let local =
            issue_admin_cookie(&application, &auth::AdminIdentity::local_admin(), None).unwrap();
        assert!(local.contains("Max-Age=604800"), "{local}");
    }

    #[tokio::test]
    async fn sso_session_setting_bounds_are_atomic_and_resettable() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let put = |value: serde_json::Value| {
            app::router(application.clone()).oneshot(
                Request::put("/api/admin/settings")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"sso_session_secs": value}).to_string()))
                    .unwrap(),
            )
        };

        let response = put(json!(MAX_SSO_SESSION_SECS)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            application.store.setting("sso_session_secs").unwrap(),
            Some(MAX_SSO_SESSION_SECS.to_string())
        );
        for value in [json!(0), json!(MAX_SSO_SESSION_SECS + 1), json!(u64::MAX)] {
            let response = put(value).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(
                application.store.setting("sso_session_secs").unwrap(),
                Some(MAX_SSO_SESSION_SECS.to_string())
            );
        }

        let response = put(serde_json::Value::Null).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(application
            .store
            .setting("sso_session_secs")
            .unwrap()
            .is_none());
    }

    fn cookie_for(app: &App, tenant: &str, role: &str) -> String {
        let identity = auth::AdminIdentity {
            subject: format!("sso:{tenant}:{role}"),
            tenant: tenant.to_owned(),
            role: role.to_owned(),
            grants: vec![TenantGrant {
                incarnation: None,
                tenant: tenant.to_owned(),
                role: role.to_owned(),
            }],
            credential_version: 1,
        };
        super::test_admin_cookie(app, &identity)
    }

    async fn send(
        application: Arc<App>,
        request: Request<Body>,
    ) -> (StatusCode, serde_json::Value) {
        let response = app::router(application).oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
        (status, json)
    }

    #[tokio::test]
    async fn receiving_storage_checks_require_platform_admin_csrf_and_current_identity() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::tests::test_tenant("team"))
            .unwrap();
        let url = "/api/admin/receiving-storage";
        for (tenant, role) in [("", "viewer"), ("", "auditor"), ("team", "admin")] {
            let (status, _) = send(
                Arc::clone(&application),
                Request::get(url)
                    .header("cookie", cookie_for(&application, tenant, role))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
        let cookie = cookie_for(&application, "", "admin");
        let (status, view) = send(
            Arc::clone(&application),
            Request::get(url)
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["ready"], true);
        assert_eq!(view["nas"], false);
        let body = json!({"storage": view["storage"]});
        for (csrf, changed, expected) in [
            (false, false, StatusCode::FORBIDDEN),
            (true, true, StatusCode::CONFLICT),
            (true, false, StatusCode::OK),
        ] {
            let mut body = body.clone();
            if changed {
                body["storage"]["inode"] = json!("0");
            }
            let mut request = Request::post(url)
                .header("cookie", &cookie)
                .header("content-type", "application/json");
            if csrf {
                request = request.header("x-votport", "1");
            }
            let (status, _) = send(
                Arc::clone(&application),
                request.body(Body::from(body.to_string())).unwrap(),
            )
            .await;
            assert_eq!(status, expected);
        }
        assert!(crate::receiving::saved_qualification(&application.store)
            .unwrap()
            .is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn receiving_storage_recheck_rejects_a_root_alias_before_probe() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let storage = crate::receiving::storage_identity(&application.config.receive_dir).unwrap();
        let moved = directory.path().join("received-before-alias");
        std::fs::rename(&application.config.receive_dir, &moved).unwrap();
        symlink(
            &application.config.data_dir,
            &application.config.receive_dir,
        )
        .unwrap();
        let cookie = cookie_for(&application, "", "admin");
        let (status, _) = send(
            Arc::clone(&application),
            Request::post("/api/admin/receiving-storage")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(json!({"storage":storage}).to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn receiving_storage_probe_keeps_its_claim_when_cancelled() {
        use std::time::Duration;
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let destinations = application.receiving_destinations().unwrap();
        let pause = crate::receiving::CheckPause::new(&destinations, 1);
        let cookie = cookie_for(&application, "", "admin");
        let storage = crate::receiving::storage_identity(&application.config.receive_dir).unwrap();
        let request = || {
            Request::post("/api/admin/receiving-storage")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(json!({"storage":storage}).to_string()))
                .unwrap()
        };
        let probing = tokio::spawn(send(application.clone(), request()));
        tokio::time::timeout(Duration::from_secs(1), async {
            while pause.entered() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(application.receiving.try_lock().is_ok());
        assert!(application.receiving_destinations_async().await.is_ok());
        assert!(app::renew_lease(&application, now_unix()));
        assert_eq!(
            send(application.clone(), request()).await.0,
            StatusCode::CONFLICT
        );
        probing.abort();
        assert!(probing.await.unwrap_err().is_cancelled());
        assert_eq!(
            send(application.clone(), request()).await.0,
            StatusCode::CONFLICT
        );
        pause.release();
        tokio::time::timeout(Duration::from_secs(2), async {
            while application.receiving_reconfigure.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(send(application.clone(), request()).await.0, StatusCode::OK);
        assert!(
            std::fs::read_dir(application.config.receive_dir.join(".vot-stage"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("probe-"))
        );
    }

    #[tokio::test]
    async fn corrected_local_storage_permissions_can_be_rechecked_in_the_ui() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let config = testing::config(directory.path());
        std::fs::create_dir(&config.receive_dir).unwrap();
        std::fs::set_permissions(&config.receive_dir, std::fs::Permissions::from_mode(0o770))
            .unwrap();
        let application = app::build(config).unwrap();
        assert!(application.receiving_destinations().is_err());
        application
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                id: "resume".into(),
                tenant: String::new(),
                label: "resume".into(),
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
        application
            .store
            .insert_upload_session(&crate::store::PersistedUploadSession {
                committed_upload_id: None,
                push_key: None,
                id: hex::encode([9; 16]),
                link_id: "resume".into(),
                tenant: String::new(),
                dest_dir: application.config.receive_dir.clone(),
                dest_rel: String::new(),
                package: vot_sdk::object::ObjectId {
                    suite: 1,
                    root: [7; 32],
                    length: 1,
                },
                max_total_bytes: Some(1),
                started_at: now_unix(),
                files: Vec::new(),
            })
            .unwrap();
        std::fs::set_permissions(
            &application.config.receive_dir,
            std::fs::Permissions::from_mode(0o1770),
        )
        .unwrap();
        let cookie = cookie_for(&application, "", "admin");
        let storage = crate::receiving::storage_identity(&application.config.receive_dir).unwrap();
        let (status, view) = send(
            Arc::clone(&application),
            Request::post("/api/admin/receiving-storage")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(json!({"storage":storage}).to_string()))
                .unwrap(),
        )
        .await;
        let resumed = application.sessions.total();
        app::suspend_sessions(&application).await;
        assert_eq!(status, StatusCode::OK, "{view}");
        assert_eq!(resumed, 1, "activation must retain the recovered session");
        assert_eq!(view["ready"], true);
        assert!(crate::receiving::saved_qualification(&application.store)
            .unwrap()
            .is_none());
    }

    #[test]
    fn nas_qualification_saves_each_value_with_audit() {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(&directory.path().join("data")).unwrap();
        let first = crate::receiving::StorageIdentity {
            path: directory.path().join("received-a"),
            filesystem: "nfs4".to_owned(),
            source: "server:/share-a".to_owned(),
            mount_root: "/".to_owned(),
            inode: "1".to_owned(),
            service_uid: 1000,
        };
        save_nas_qualification(&store, "operator-a", first.clone(), 41).unwrap();
        let saved = crate::receiving::saved_qualification(&store)
            .unwrap()
            .unwrap();
        assert_eq!(saved.storage, first);
        assert_eq!(saved.qualified_at, 41);
        assert_eq!(saved.qualified_by, "operator-a");
        let event = |storage: &crate::receiving::StorageIdentity, qualified_at: u64| {
            json!({
                "storage": storage,
                "qualified_at": qualified_at,
            })
        };
        let audits = || {
            store
                .audit_recent_filtered(
                    None,
                    0,
                    100,
                    AuditFilters {
                        event: Some("receiving_nas_qualification_saved"),
                        query: None,
                    },
                )
                .unwrap()
        };
        let rows = audits();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].actor, "operator-a");
        assert_eq!(rows[0].subject, crate::receiving::SETTING_KEY);
        assert_eq!(rows[0].detail, event(&first, 41));

        let second = crate::receiving::StorageIdentity {
            path: directory.path().join("received-b"),
            filesystem: "cifs".to_owned(),
            source: "//server/share-b".to_owned(),
            mount_root: "/mnt/share-b".to_owned(),
            inode: "2".to_owned(),
            service_uid: 1001,
        };
        save_nas_qualification(&store, "operator-b", second.clone(), 42).unwrap();
        let saved = crate::receiving::saved_qualification(&store)
            .unwrap()
            .unwrap();
        assert_eq!(saved.storage, second);
        assert_eq!(saved.qualified_at, 42);
        assert_eq!(saved.qualified_by, "operator-b");
        let rows = audits();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].actor, "operator-b");
        assert_eq!(rows[0].detail, event(&second, 42));
        assert_eq!(rows[1].actor, "operator-a");
        assert_eq!(rows[1].detail, event(&first, 41));

        store
            .with(|connection| connection.execute_batch("DROP TABLE settings"))
            .unwrap();
        assert!(save_nas_qualification(&store, "operator-c", second, 43).is_err());
        assert_eq!(audits().len(), 2);
    }

    #[tokio::test]
    async fn missing_qualified_nas_keeps_admin_available_and_refuses_local_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let config = application.config.clone();
        let qualification = crate::receiving::Qualification {
            storage: crate::receiving::storage_identity(&config.receive_dir).unwrap(),
            qualified_at: 1,
            qualified_by: "fixture".to_owned(),
        };
        application
            .store
            .put_settings(
                "fixture",
                &[(
                    crate::receiving::SETTING_KEY.to_owned(),
                    crate::store::SettingWrite::Set(serde_json::to_string(&qualification).unwrap()),
                )],
            )
            .unwrap();
        app::release_data_lock(&application);
        drop(application);
        let application = app::build(config).unwrap();
        assert!(application.receiving_destinations().is_err());
        let cookie = cookie_for(&application, "", "admin");
        let (status, view) = send(
            Arc::clone(&application),
            Request::get("/api/admin/receiving-storage")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(view["ready"], false);
        let (status, _) = send(Arc::clone(&application), Request::post("/api/admin/receiving-storage")
            .header("cookie", &cookie).header("x-votport", "1").header("content-type", "application/json")
            .body(Body::from(json!({"storage":view["storage"],"enable":true,"stable_acknowledgments":true,"private_namespace":true}).to_string())).unwrap()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(application.receiving_destinations().is_err());
        assert!(!crate::lease::path(&application.config.receive_dir).exists());
    }

    #[tokio::test]
    async fn admin_html_bootstraps_only_the_authenticated_navigation() {
        let directory = tempfile::tempdir().unwrap();
        let web = directory.path().join("web");
        std::fs::create_dir_all(&web).unwrap();
        for (page, contents) in [
            ("index.html", "<html><head></head><body></body></html>"),
            (
                "audit.html",
                "<html><head></head><body><nav id=\"nav\" class=\"nav\"></nav></body></html>",
            ),
            ("request.html", "<html><head></head><body></body></html>"),
            ("tenants.html", include_str!("../../../../web/tenants.html")),
        ] {
            std::fs::write(web.join(page), contents).unwrap();
        }
        let application = testing::build(directory.path());
        for key in ["team", "</script><script>oops</script>"] {
            application
                .store
                .insert_tenant(crate::store::tests::test_tenant(key))
                .unwrap();
        }
        for (tenant, role) in [
            ("", "admin"),
            ("team", "operator"),
            ("team", "admin"),
            ("team", "auditor"),
            ("</script><script>oops</script>", "viewer"),
        ] {
            let cookie = cookie_for(&application, tenant, role);
            let (_, expected) = send(
                application.clone(),
                Request::get("/api/admin/session")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(expected["tenant"], tenant);
            let response = app::router(application.clone())
                .oneshot(
                    Request::get("/audit")
                        .header(header::COOKIE, &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "private, no-store"
            );
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let html = std::str::from_utf8(&bytes).unwrap();
            let bootstrap = html
                .split("<script id=\"admin-session\" type=\"application/json\">")
                .nth(1)
                .unwrap()
                .split("</script>")
                .next()
                .unwrap();
            assert!(!bootstrap.contains('<'));
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(bootstrap).unwrap(),
                expected
            );
            let nav = html
                .split("<nav id=\"nav\" class=\"nav\">")
                .nth(1)
                .unwrap()
                .split("</nav>")
                .next()
                .unwrap();
            for page in [
                "receive",
                "deliver",
                "workflows",
                "storage",
                "automation",
                "tenants",
                "audit",
                "system",
            ] {
                assert_eq!(
                    nav.contains(&format!("href=\"/{page}\"")),
                    expected["pages"].as_array().unwrap().contains(&json!(page))
                );
            }
            assert_eq!(nav.matches("aria-current=\"page\"").count(), 1);
            assert!(nav.contains("href=\"/audit\" class=\"active\" aria-current=\"page\""));
            if tenant == "team" && role == "admin" {
                assert!(expected["pages"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("tenants")));
                assert!(!expected["pages"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("system")));
                assert!(nav.contains(
                    "href=\"/tenants\" data-hint=\"Set how recipients see this tenant.\">Branding</a>"
                ));
                assert!(!nav.contains(">Tenants</a>"));
            }
            if (tenant.is_empty() || tenant == "team") && role == "admin" {
                let response = app::router(application.clone())
                    .oneshot(
                        Request::get("/tenants")
                            .header(header::COOKIE, &cookie)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                let html = std::str::from_utf8(&bytes).unwrap();
                let expected_title = if tenant == "team" {
                    "<title>VOTPort &middot; Branding</title>"
                } else {
                    "<title>VOTPort &middot; Tenants</title>"
                };
                let expected_heading = if tenant == "team" {
                    "<h1 id=\"page-title\">Branding</h1>"
                } else {
                    "<h1 id=\"page-title\">Tenant namespaces</h1>"
                };
                assert!(html.contains(expected_title), "{expected_title}");
                assert!(html.contains(expected_heading), "{expected_heading}");
            }
        }
        for route in ["/audit", "/r/public-link", "/"] {
            let response = app::router(application.clone())
                .oneshot(Request::get(route).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                if route == "/audit" {
                    "private, no-store"
                } else {
                    "no-cache"
                }
            );
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert!(!std::str::from_utf8(&bytes)
                .unwrap()
                .contains("id=\"admin-session\""));
        }
    }

    #[tokio::test]
    async fn draining_round_trips_through_the_settings_route() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application.clone(),
            Request::get("/api/admin/settings")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["draining"], false);

        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"draining":true}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // The JSON bool is stored and resolves back to draining.
        assert!(
            application
                .store
                .resolved_settings(&application.config)
                .unwrap()
                .draining
        );
        let (_, json) = send(
            application,
            Request::get("/api/admin/settings")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(json["draining"], true);
        assert!(json["overridden_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key == "draining"));
    }

    #[tokio::test]
    async fn retention_clock_acknowledgement_is_platform_admin_only_and_visible() {
        let directory = tempfile::tempdir().unwrap();
        let config = testing::config(directory.path());
        let store = crate::store::Store::open(&config.data_dir).unwrap();
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM meta WHERE key = ?1",
                    [crate::store::RETENTION_CLOCK_KEY],
                )
            })
            .unwrap();
        drop(store);
        let application = app::build(config).unwrap();
        let cookie = cookie_for(&application, "", "admin");
        let (_, json) = send(
            Arc::clone(&application),
            Request::get("/api/admin/settings")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(json["retention_clock"]["held"], true);
        assert!(application
            .store
            .audit_export(None, 0, 0, 10)
            .unwrap()
            .iter()
            .any(|row| row.event == "retention_clock_held"));
        let observed_at = json["retention_clock"]["raw_wall_at"]
            .as_u64()
            .expect("settings must expose the displayed wall observation");

        let (status, _) = send(
            Arc::clone(&application),
            Request::post("/api/admin/settings/retention-clock/acknowledge")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"observed_at":{observed_at}}}"#)))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        assert_eq!(
            application.acknowledge_retention_clock_at(
                "platform-operator",
                observed_at,
                observed_at.saturating_sub(86_400),
            ),
            Err(crate::app::RetentionClockAcknowledgementError::FutureObservation),
            "a backward correction makes the displayed observation invalid"
        );

        let future = observed_at.saturating_add(86_400);
        let (status, _) = send(
            Arc::clone(&application),
            Request::post("/api/admin/settings/retention-clock/acknowledge")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"observed_at":{future}}}"#)))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            application.store.retention_clock_anchor().unwrap(),
            None,
            "a future displayed observation cannot acknowledge the clock"
        );

        let older = observed_at.saturating_sub(86_400);
        let (status, json) = send(
            Arc::clone(&application),
            Request::post("/api/admin/settings/retention-clock/acknowledge")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"observed_at":{older}}}"#)))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["retention_clock"]["held"], false);
        assert_eq!(
            application.store.retention_clock_anchor().unwrap(),
            Some(older),
            "the acknowledgement must persist the displayed observation"
        );
        assert!(application
            .store
            .audit_export(None, 0, 0, 10)
            .unwrap()
            .iter()
            .any(|row| row.event == "retention_clock_acknowledged"));
    }

    #[tokio::test]
    async fn get_settings_returns_env_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application,
            Request::get("/api/admin/settings")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["audit_retention_days"], 400);
        assert_eq!(json["upload_retention_days"], 0);
        assert_eq!(json["smtp_host"], serde_json::Value::Null);
        assert_eq!(json["smtp_password_set"], false);
        assert_eq!(json["default_max_total_bytes"], serde_json::Value::Null);
        assert_eq!(json["public_password_login"], true);
        assert_eq!(json["sso_configured"], false);
        assert_eq!(json["smtp_host"], serde_json::Value::Null);
        assert_eq!(json["smtp_port"], 587);
        assert_eq!(json["smtp_starttls"], true);
        assert_eq!(json["smtp_password_set"], false);
        assert!(json.get("smtp_password").is_none());
        assert_eq!(json["overridden_keys"], json!([]));
        let deployment = &json["deployment"];
        assert_eq!(deployment["bind"], "127.0.0.1:0");
        assert_eq!(deployment["public_url"], "https://drop.example.com");
        assert_eq!(
            deployment["data_dir"],
            directory.path().join("data").to_string_lossy().as_ref()
        );
        assert_eq!(
            deployment["receive_dir"],
            directory.path().join("received").to_string_lossy().as_ref()
        );
        assert_eq!(
            deployment["outbound_dir"],
            directory.path().join("outbound").to_string_lossy().as_ref()
        );
        assert_eq!(deployment["receive_commit_profile"], "balanced");
        #[cfg(target_os = "linux")]
        assert_eq!(deployment["outbound_filesystem_profile"], "balanced");
        #[cfg(not(target_os = "linux"))]
        assert!(deployment["outbound_filesystem_profile"].is_null());
        assert_eq!(deployment["max_upload_bytes"], 1024 * 1024);
        assert_eq!(deployment["allow_hidden"], false);
        assert_eq!(deployment["session_idle_secs"], 60);
        assert_eq!(deployment["trusted_proxies"], json!([]));
        assert_eq!(deployment["metrics_configured"], false);
        assert_eq!(deployment["push_configured"], false);
        assert_eq!(deployment["push_private_key_configured"], false);
        assert_eq!(deployment["oidc_configured"], false);
        assert_eq!(deployment["oidc_client_secret_configured"], false);
        // Config::admin_password_hash is represented by the existing
        // password form. Config::admin_token_tag is internal session state,
        // so neither belongs in this API payload.
        for field in [
            "smtp_host",
            "smtp_port",
            "smtp_starttls",
            "smtp_username",
            "smtp_password_set",
            "smtp_from",
            "audit_retention_days",
            "upload_retention_days",
            "default_max_total_bytes",
            "default_max_links",
            "default_max_sessions",
            "public_password_login",
            "sso_session_secs",
            "sso_configured",
            "overridden_keys",
        ] {
            assert!(json.get(field).is_some(), "missing settings field {field}");
        }
        for field in [
            "bind",
            "public_url",
            "data_dir",
            "receive_dir",
            "outbound_dir",
            "web_root",
            "max_upload_bytes",
            "allow_hidden",
            "session_idle_secs",
            "max_total_sessions",
            "max_link_sessions",
            "trusted_proxies",
            "metrics_configured",
            "push_bind",
            "push_advertise",
            "push_certificate",
            "push_certificate_configured",
            "push_private_key_configured",
            "push_configured",
            "oidc_issuer",
            "oidc_client_id",
            "oidc_admin_group",
            "oidc_client_secret_configured",
            "oidc_configured",
        ] {
            assert!(
                deployment.get(field).is_some(),
                "missing deployment field {field}"
            );
        }
        for secret in [
            "admin_password_hash",
            "admin_token_tag",
            "metrics_token",
            "push_private_key",
            "oidc_client_secret",
            "smtp_password",
        ] {
            assert!(
                json.get(secret).is_none() && deployment.get(secret).is_none(),
                "secret leaked as {secret}"
            );
        }
    }

    #[tokio::test]
    async fn get_settings_redacts_smtp_password() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application,
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"smtp_host":"smtp.example.com","smtp_from":"votport@example.com","smtp_password":"s3cret"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["smtp_host"], "smtp.example.com");
        assert_eq!(json["smtp_password_set"], true);
        assert!(json["overridden_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key == "smtp_password"));
        assert!(json.get("smtp_password").is_none());
    }

    #[tokio::test]
    async fn put_then_get_lists_accepted_overrides() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"audit_retention_days":7,"smtp_host":"https://db.example/hook"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["audit_retention_days"], 7);
        assert_eq!(json["smtp_host"], "https://db.example/hook");
        let overridden_keys = json["overridden_keys"].as_array().unwrap();
        assert!(overridden_keys
            .iter()
            .any(|key| key == "audit_retention_days"));
        assert!(overridden_keys.iter().any(|key| key == "smtp_host"));
        assert!(!overridden_keys
            .iter()
            .any(|key| key == "upload_retention_days"));

        let (status, json) = send(
            application,
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"smtp_host":null}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["smtp_host"], serde_json::Value::Null);
        assert!(!json["overridden_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key == "smtp_host"));
    }

    #[tokio::test]
    async fn put_omitting_a_secret_leaves_the_previous_value() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"smtp_password":"secret-token"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, json) = send(
            application,
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"audit_retention_days":10}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["smtp_password_set"], true);
        assert!(json["overridden_keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key == "smtp_password"));
        assert!(json.get("smtp_password").is_none());
        assert_eq!(json["audit_retention_days"], 10);
    }

    #[tokio::test]
    async fn put_rejects_zero_default_quota_and_unknown_settings() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"default_max_total_bytes":0}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, json) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"audit_retention_days":0}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["audit_retention_days"], 0);

        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"removed_notification_setting":"ftp://nope"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, _) = send(
            application,
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"smtp_port":0}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn viewer_and_named_admin_cannot_read_settings_or_tenants() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::tests::test_tenant("acme"))
            .unwrap();
        let viewer = cookie_for(&application, "", "viewer");
        let named = cookie_for(&application, "acme", "admin");

        for cookie in [&viewer, &named] {
            let (status, _) = send(
                application.clone(),
                Request::get("/api/admin/settings")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            let (status, _) = send(
                application.clone(),
                Request::get("/api/admin/tenants")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn put_settings_requires_csrf_header() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application,
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"audit_retention_days":1}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json["error"], "missing X-Votport header");
    }

    #[tokio::test]
    async fn patch_tenant_quota_then_create_session_hits_the_cap() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::Tenant {
                retention_days: None,
                incarnation: String::new(),
                key: "acme".to_owned(),
                label: String::new(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        application
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                id: "acme-link".to_owned(),
                tenant: "acme".to_owned(),
                label: "open".to_owned(),
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
        let cookie = cookie_for(&application, "", "admin");
        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PATCH")
                .uri("/api/admin/tenants/acme")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"max_total_bytes":100}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let router = app::router(application);
        let request = Request::builder()
            .method("POST")
            .uri("/api/r/acme-link/session")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
            .body(Body::from(
                r#"{"package":{"suite":"blake3","root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","length":200}}"#,
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn create_tenant_fills_omitted_quotas_from_overlay() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"default_max_total_bytes":100}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, json) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/tenants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"key":"acme","label":"Acme","admin_group":" admins "}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["key"], "acme");
        let tenant = application
            .store
            .tenant("acme")
            .unwrap()
            .expect("tenant stored");
        assert_eq!(tenant.max_total_bytes, Some(100));
        assert_eq!(tenant.max_links, None);
        assert_eq!(tenant.max_sessions, None);
        assert_eq!(tenant.admin_group.as_deref(), Some(" admins "));
        let audits = application
            .store
            .audit_recent_filtered(
                None,
                0,
                100,
                AuditFilters {
                    event: Some("tenant_created"),
                    query: None,
                },
            )
            .unwrap();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].actor, "sso::admin");
        assert_eq!(audits[0].subject, "acme");
        assert_eq!(
            audits[0].detail,
            json!({
                "label": "Acme",
                "admin_group": " admins ",
                "max_total_bytes": 100,
                "max_links": null,
                "max_sessions": null,
                "retention_days": null,
            })
        );
        let (status, _) = send(
            application.clone(),
            Request::post("/api/admin/tenants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"key":"acme","label":"Acme","admin_group":" admins "}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            application
                .store
                .audit_recent_filtered(
                    None,
                    0,
                    100,
                    AuditFilters {
                        event: Some("tenant_created"),
                        query: None,
                    },
                )
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn tenant_api_round_trips_full_u64_quotas() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let (status, json) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/tenants")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"key":"acme","label":"Acme","max_total_bytes":18446744073709551615,"max_links":18446744073709551615,"max_sessions":18446744073709551615}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["key"], "acme");
        let tenant = application.store.tenant("acme").unwrap().unwrap();
        assert_eq!(tenant.max_total_bytes, Some(u64::MAX));
        assert_eq!(tenant.max_links, Some(u64::MAX));
        assert_eq!(tenant.max_sessions, Some(u64::MAX));

        let (status, json) = send(
            application.clone(),
            Request::builder()
                .method("PATCH")
                .uri("/api/admin/tenants/acme")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"max_total_bytes":18446744073709551614,"max_links":18446744073709551614,"max_sessions":18446744073709551614}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["ok"], true);
        let tenant = application.store.tenant("acme").unwrap().unwrap();
        assert_eq!(tenant.max_total_bytes, Some(u64::MAX - 1));
        assert_eq!(tenant.max_links, Some(u64::MAX - 1));
        assert_eq!(tenant.max_sessions, Some(u64::MAX - 1));
    }

    #[tokio::test]
    async fn default_tenant_create_session_hits_overlay_byte_cap() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_link(crate::store::Link {
                retention_days: None,
                id: "default-link".to_owned(),
                tenant: String::new(),
                label: "open".to_owned(),
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
        let cookie = cookie_for(&application, "", "admin");
        let (status, _) = send(
            application.clone(),
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"default_max_total_bytes":100}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let router = app::router(application);
        let request = Request::builder()
            .method("POST")
            .uri("/api/r/default-link/session")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
            .body(Body::from(
                r#"{"package":{"suite":"blake3","root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","length":200}}"#,
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn overlay_skips_invalid_text_without_panic() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .put_settings(
                "local",
                &[(
                    "audit_retention_days".to_owned(),
                    SettingWrite::Set("nope".to_owned()),
                )],
            )
            .unwrap();
        let resolved = application
            .store
            .resolved_settings(&application.config)
            .unwrap();
        assert_eq!(resolved.audit_retention_days, 400);
    }
    #[tokio::test]
    async fn settings_audit_rows_record_change_shape_without_secret_values() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, "", "admin");
        let put = |value: serde_json::Value| {
            app::router(application.clone()).oneshot(
                Request::put("/api/admin/settings")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(value.to_string()))
                    .unwrap(),
            )
        };

        let response = put(json!({
            "smtp_host": "smtp1.example.test",
            "smtp_password": "hunter2hunter2"
        }))
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let row = application
            .store
            .audit_export(Some(""), 0, 0, 100)
            .unwrap()
            .into_iter()
            .find(|row| row.event == "settings_updated")
            .expect("settings changes are audited");
        assert_eq!(
            row.detail["changes"]["smtp_host"],
            json!({
                "from": serde_json::Value::Null,
                "to": "smtp1.example.test"
            })
        );
        assert_eq!(
            row.detail["changes"]["smtp_password"],
            json!({"changed": true, "from_set": false, "to_set": true})
        );
        assert!(!row.detail.to_string().contains("hunter2"));

        // Rotating the SCIM token moves the old value into scim_token_previous;
        // that move is recorded as a value-free sensitive change too.
        let response = put(json!({"scim_token": "first-scim-token-1234"}))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = put(json!({"scim_token": "second-scim-token-5678"}))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let row = application
            .store
            .audit_export(Some(""), 0, 0, 100)
            .unwrap()
            .into_iter()
            .rfind(|row| row.event == "settings_updated")
            .unwrap();
        assert_eq!(
            row.detail["changes"]["scim_token_previous"],
            json!({"changed": true, "from_set": false, "to_set": true})
        );
        assert_eq!(
            row.detail["changes"]["scim_token"],
            json!({"changed": true, "from_set": true, "to_set": true})
        );
        let detail = row.detail.to_string();
        assert!(!detail.contains("first-scim-token-1234"));
        assert!(!detail.contains("second-scim-token-5678"));

        // Resets record the value they removed.
        let response = put(json!({"smtp_host": serde_json::Value::Null}))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let row = application
            .store
            .audit_export(Some(""), 0, 0, 100)
            .unwrap()
            .into_iter()
            .rfind(|row| row.event == "settings_updated")
            .unwrap();
        assert_eq!(row.detail["reset"], json!(["smtp_host"]));
        assert_eq!(
            row.detail["changes"]["smtp_host"],
            json!({
                "from": "smtp1.example.test",
                "to": serde_json::Value::Null
            })
        );
    }
}

#[cfg(test)]
mod principals_api_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::auth::{self, TenantGrant};

    fn cookie_for(app: &App, identity: auth::AdminIdentity) -> String {
        super::test_admin_cookie(app, &identity)
    }

    fn sso_identity(subject: &str, cv: u64) -> auth::AdminIdentity {
        auth::AdminIdentity {
            subject: subject.to_owned(),
            tenant: String::new(),
            role: "admin".to_owned(),
            grants: vec![TenantGrant {
                incarnation: None,
                tenant: String::new(),
                role: "admin".to_owned(),
            }],
            credential_version: cv,
        }
    }

    fn cookie_without_cv(app: &App, subject: &str) -> String {
        let payload = serde_json::json!({
            "subject": subject,
            "tenant": "",
            "role": "admin",
            "grants": [{"tenant": "", "role": "admin", "incarnation": null}]
        })
        .to_string();
        format!(
            "votport_admin={}; Path=/",
            auth::issue_admin_token_from_payload(
                &app.secret,
                &payload,
                &admin_token_phc(app).unwrap()
            )
        )
    }

    fn platform_cookie(app: &App) -> String {
        cookie_for(app, auth::AdminIdentity::local_admin())
    }

    fn cookie_token(set_cookie: &str) -> &str {
        set_cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("votport_admin=")
            .unwrap()
    }

    fn payload_cv(set_cookie: &str) -> u64 {
        let token = cookie_token(set_cookie);
        let payload_hex = token.split('.').nth(1).unwrap();
        let payload = hex::decode(payload_hex).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        json["cv"].as_u64().unwrap()
    }

    async fn send(
        application: Arc<App>,
        request: Request<Body>,
    ) -> (StatusCode, serde_json::Value, Option<String>) {
        let response = app::router(application).oneshot(request).await.unwrap();
        let status = response.status();
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
        (status, json, cookie)
    }

    fn insert_acme(application: &App) {
        application
            .store
            .insert_tenant(crate::store::Tenant {
                retention_days: None,
                incarnation: String::new(),
                key: "acme".to_owned(),
                label: String::new(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
    }

    #[tokio::test]
    async fn payload_without_cv_still_verifies_when_no_row() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_without_cv(&application, "user@example.com");
        let (status, json, _) = send(
            application,
            Request::get("/api/admin/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["ok"], true);
    }

    #[tokio::test]
    async fn missing_row_with_cv_2_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = cookie_for(&application, sso_identity("user@example.com", 2));
        let (status, _, _) = send(
            application,
            Request::get("/api/admin/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cv_1_against_row_2_fails_require_admin() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        application
            .store
            .revoke_principal("user@example.com")
            .unwrap();
        let cookie = cookie_for(&application, sso_identity("user@example.com", 1));
        let (status, _, _) = send(
            application,
            Request::get("/api/admin/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_then_unblock_then_live_version_passes() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        let platform = platform_cookie(&application);
        let (status, _, _) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/revoke")
                .header("cookie", &platform)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"user@example.com"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let stale = cookie_for(&application, sso_identity("user@example.com", 1));
        let (status, _, _) = send(
            application.clone(),
            Request::get("/api/admin/session")
                .header("cookie", &stale)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _, _) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/unblock")
                .header("cookie", &platform)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"user@example.com"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, _) = send(
            application.clone(),
            Request::get("/api/admin/session")
                .header("cookie", &stale)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let live = application
            .store
            .principal("user@example.com")
            .unwrap()
            .unwrap()
            .credential_version;
        assert_eq!(live, 2);
        let cookie = cookie_for(&application, sso_identity("user@example.com", live));
        let (status, json, _) = send(
            application,
            Request::get("/api/admin/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["ok"], true);
    }

    #[tokio::test]
    async fn purge_erases_a_blocked_principal_and_refuses_an_active_one() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("user@example.com", &["employees".to_owned()], &json!([]))
            .unwrap();
        // The membership names the subject with mixed case, like a SCIM
        // client may have stored it; the purge must reach it folded.
        application
            .store
            .create_scim_group("employees", None, &["User@Example.com".to_owned()])
            .unwrap();
        let platform = platform_cookie(&application);
        let purge = |subject: &'static str| {
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/purge")
                .header("cookie", &platform)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"subject":"{subject}"}}"#)))
                .unwrap()
        };

        // An active principal cannot be erased; revoke comes first.
        let (status, _, _) = send(application.clone(), purge("user@example.com")).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(application
            .store
            .principal("user@example.com")
            .unwrap()
            .is_some());

        let (status, _, _) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/revoke")
                .header("cookie", &platform)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"user@example.com"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _, _) = send(application.clone(), purge("user@example.com")).await;
        assert_eq!(status, StatusCode::OK);
        // The row and its memberships are gone, matched folded like the row
        // itself, and a retried purge answers 404 like a missing principal.
        assert!(application
            .store
            .principal("USER@example.com")
            .unwrap()
            .is_none());
        assert!(application
            .store
            .scim_groups_of("user@example.com")
            .unwrap()
            .is_empty());
        let (status, _, _) = send(application.clone(), purge("user@example.com")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = send(application.clone(), purge("missing@example.com")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn switch_tenant_reissues_the_same_cv() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        insert_acme(&application);
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        application
            .store
            .revoke_principal("user@example.com")
            .unwrap();
        application
            .store
            .unblock_principal("user@example.com")
            .unwrap();
        for role in ["viewer", "admin", "auditor"] {
            for target_role in ["admin", "viewer"] {
                let mut identity = sso_identity("user@example.com", 2);
                identity.role = role.into();
                identity.grants[0].role = role.into();
                identity.grants.push(TenantGrant {
                    incarnation: Some(
                        application
                            .store
                            .tenant("acme")
                            .unwrap()
                            .unwrap()
                            .incarnation,
                    ),
                    tenant: "acme".to_owned(),
                    role: target_role.to_owned(),
                });
                let cookie = format!(
                    "votport_admin={}",
                    auth::issue_admin_token_with_ttl(
                        &application.secret,
                        &identity,
                        &admin_token_phc(&application).unwrap(),
                        60,
                    )
                );
                let expires = cookie_token(&cookie).split('.').next().unwrap();
                for (csrf, target, expected) in [
                    (true, "acme", StatusCode::OK),
                    (false, "acme", StatusCode::FORBIDDEN),
                    (true, "other", StatusCode::FORBIDDEN),
                ] {
                    let mut request = Request::post("/api/admin/tenant")
                        .header("cookie", &cookie)
                        .header("content-type", "application/json");
                    if csrf {
                        request = request.header("x-votport", "1");
                    }
                    let (status, _, set_cookie) = send(
                        application.clone(),
                        request
                            .body(Body::from(json!({"tenant": target}).to_string()))
                            .unwrap(),
                    )
                    .await;
                    assert_eq!(
                        status, expected,
                        "{role} to {target}/{target_role}, csrf={csrf}"
                    );
                    if expected == StatusCode::OK {
                        let set_cookie = set_cookie.expect("switch reissues a cookie");
                        assert_eq!(payload_cv(&set_cookie), 2);
                        assert_eq!(
                            cookie_token(&set_cookie).split('.').next().unwrap(),
                            expires
                        );
                        let (switched, switched_expires) = auth::verify_admin_token(
                            &application.secret,
                            &admin_token_phc(&application).unwrap(),
                            cookie_token(&set_cookie),
                        )
                        .unwrap();
                        assert_eq!(switched_expires.to_string(), expires);
                        assert_eq!(switched.tenant, target);
                        assert_eq!(switched.role, target_role);
                    } else {
                        assert!(set_cookie.is_none());
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn local_switch_cookie_stays_under_browser_limit_with_many_tenants() {
        // Browsers refuse cookies over 4096 bytes; the local admin's grants
        // are recomputed from the store on every request, so the reissued
        // switch cookie must not carry them or the switch silently no-ops
        // once the tenant count grows.
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        for index in 0..60 {
            application
                .store
                .insert_tenant(crate::store::Tenant {
                    retention_days: None,
                    incarnation: format!("{:024x}", index),
                    key: format!("tenant-{index:02}"),
                    label: String::new(),
                    admin_group: None,
                    max_total_bytes: None,
                    max_links: None,
                    max_sessions: None,
                    created_at: 0,
                })
                .unwrap();
        }
        let cookie = test_admin_cookie(&application, &auth::AdminIdentity::local_admin());
        let (status, _, set_cookie) = send(
            application.clone(),
            Request::post("/api/admin/tenant")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(json!({"tenant": "tenant-07"}).to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let set_cookie = set_cookie.expect("switch reissues a cookie");
        assert!(
            set_cookie.len() < 4096,
            "local switch cookie must stay under the 4096-byte browser limit"
        );
        let (switched, _) = auth::verify_admin_token(
            &application.secret,
            &admin_token_phc(&application).unwrap(),
            cookie_token(&set_cookie),
        )
        .unwrap();
        assert_eq!(switched.tenant, "tenant-07");
        assert!(switched.grants.is_empty());
        // The trimmed grants are recomputed per request, so the switched
        // cookie resolves to the switched tenant scope on the next request.
        let follow = send(
            application,
            Request::get("/api/admin/session")
                .header(
                    "cookie",
                    format!("votport_admin={}", cookie_token(&set_cookie)),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(follow.0, StatusCode::OK);
        assert_eq!(follow.1["tenant"], "tenant-07");
    }

    #[tokio::test]
    async fn local_identity_sees_named_tenant_grants() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        insert_acme(&application);
        let cookie = platform_cookie(&application);
        let (status, json, _) = send(
            application.clone(),
            Request::get("/api/admin/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let grants = json["grants"].as_array().unwrap();
        assert!(
            grants
                .iter()
                .any(|grant| grant["tenant"] == "acme" && grant["role"] == "admin"),
            "grants were {grants:?}"
        );
        let (status, _, _) = send(
            application,
            Request::builder()
                .method("POST")
                .uri("/api/admin/tenant")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"tenant":"acme"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn upsert_then_list_tenants_contains_the_subject() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal(
                "user@example.com",
                &["employees".to_owned()],
                &json!([{"tenant":"","role":"viewer"}]),
            )
            .unwrap();
        let cookie = platform_cookie(&application);
        let (status, json, _) = send(
            application,
            Request::get("/api/admin/tenants")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let principals = json["principals"].as_array().unwrap();
        assert_eq!(principals.len(), 1);
        assert_eq!(principals[0]["subject"], "user@example.com");
        assert_eq!(principals[0]["blocked"], false);
        assert_eq!(principals[0]["credential_version"], 1);
        assert_eq!(principals[0]["last_groups"][0], "employees");
        assert_eq!(principals[0]["source"], "sso");
    }

    #[tokio::test]
    async fn principal_page_is_platform_only_and_validates_bounds() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::tests::test_tenant("acme"))
            .unwrap();
        application
            .store
            .upsert_sso_principal("Alice%literal", &[], &json!([]))
            .unwrap();
        let named = cookie_for(
            &application,
            auth::AdminIdentity {
                subject: "named-admin".to_owned(),
                tenant: "acme".to_owned(),
                role: "admin".to_owned(),
                grants: vec![TenantGrant {
                    incarnation: None,
                    tenant: "acme".to_owned(),
                    role: "admin".to_owned(),
                }],
                credential_version: 1,
            },
        );
        let (status, _, _) = send(
            application.clone(),
            Request::get("/api/admin/principals")
                .header("cookie", &named)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let platform = platform_cookie(&application);
        let (status, json, _) = send(
            application.clone(),
            Request::get("/api/admin/principals?limit=1&q=%25literal")
                .header("cookie", &platform)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["total"], 1);
        assert_eq!(json["principals"][0]["subject"], "Alice%literal");

        for uri in [
            "/api/admin/principals?limit=0",
            "/api/admin/principals?limit=101",
            "/api/admin/principals?offset=-1",
        ] {
            let (status, _, _) = send(
                application.clone(),
                Request::get(uri)
                    .header("cookie", &platform)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{uri}");
        }
        let long_query = "a".repeat(101);
        let (status, _, _) = send(
            application,
            Request::get(format!("/api/admin/principals?q={long_query}"))
                .header("cookie", &platform)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn legacy_tenant_principals_are_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        for index in 0..51 {
            application
                .store
                .upsert_sso_principal(&format!("user-{index:02}"), &[], &json!([]))
                .unwrap();
        }
        let platform = platform_cookie(&application);
        let (status, json, _) = send(
            application,
            Request::get("/api/admin/tenants")
                .header("cookie", &platform)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["principals"].as_array().unwrap().len(), 50);
        assert_eq!(json["principals_truncated"], true);
    }

    #[tokio::test]
    async fn named_tenant_admin_cannot_revoke() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        insert_acme(&application);
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        let cookie = cookie_for(
            &application,
            auth::AdminIdentity {
                subject: "sso:acme".to_owned(),
                tenant: "acme".to_owned(),
                role: "admin".to_owned(),
                grants: vec![TenantGrant {
                    incarnation: None,
                    tenant: "acme".to_owned(),
                    role: "admin".to_owned(),
                }],
                credential_version: 1,
            },
        );
        let (status, _, _) = send(
            application,
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/revoke")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"user@example.com"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn viewer_cannot_list_principals() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        let cookie = cookie_for(
            &application,
            auth::AdminIdentity {
                subject: "sso:viewer".to_owned(),
                tenant: String::new(),
                role: "viewer".to_owned(),
                grants: vec![TenantGrant {
                    incarnation: None,
                    tenant: String::new(),
                    role: "viewer".to_owned(),
                }],
                credential_version: 1,
            },
        );
        let (status, json, _) = send(
            application,
            Request::get("/api/admin/tenants")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(json.get("principals").is_none());
    }

    #[tokio::test]
    async fn revoke_refuses_local_and_unknown() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = platform_cookie(&application);
        let (status, _, _) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/revoke")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"local"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, _, _) = send(
            application,
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/revoke")
                .header("cookie", &cookie)
                .header("x-votport", "1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"missing@example.com"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn revoke_requires_csrf_header() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("user@example.com", &[], &json!([]))
            .unwrap();
        let cookie = platform_cookie(&application);
        let (status, _, _) = send(
            application.clone(),
            Request::builder()
                .method("POST")
                .uri("/api/admin/principals/revoke")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"subject":"user@example.com"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let row = application
            .store
            .principal("user@example.com")
            .unwrap()
            .unwrap();
        assert!(!row.blocked);
        assert_eq!(row.credential_version, 1);
    }

    #[test]
    fn principal_updates_log_the_reduced_subject_form() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        application
            .store
            .upsert_sso_principal("jane@example.com", &[], &json!([]))
            .unwrap();
        let (log, _guard) = crate::logging::captured(crate::logging::audit_filter());
        let _ = mutate_principal(&application, "local", "jane@example.com", true).unwrap();
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert!(text.contains("principal_revoked"), "{text}");
        assert!(text.contains("ja..om (16)"), "{text}");
        assert!(!text.contains("jane@example.com"), "{text}");
    }
}

#[cfg(test)]
mod notification_and_limit_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use crate::api::testing;
    use crate::app;

    fn admin_cookie(application: &App) -> String {
        let token = auth::issue_admin_token(
            &application.secret,
            &auth::AdminIdentity::local_admin(),
            &application.config.admin_token_tag,
        );
        format!("votport_admin={token}")
    }

    async fn create_link(application: Arc<App>, max_bytes: Option<u64>) -> StatusCode {
        let cookie = admin_cookie(&application);
        app::router(application)
            .oneshot(
                Request::post("/api/admin/links")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({ "label": "test", "max_bytes": max_bytes }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn explicit_link_max_bytes_must_be_within_configured_bounds() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let audit_count = || {
            application
                .store
                .audit_recent_filtered(
                    None,
                    0,
                    100,
                    AuditFilters {
                        event: Some("link_created"),
                        query: None,
                    },
                )
                .unwrap()
                .len()
        };
        let before = audit_count();
        assert_eq!(
            create_link(application.clone(), Some(0)).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(audit_count(), before);
        let before = audit_count();
        assert_eq!(
            create_link(
                application.clone(),
                Some(application.config.max_upload_bytes.saturating_add(1)),
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(audit_count(), before);
        assert_eq!(create_link(application.clone(), None).await, StatusCode::OK);
        assert_eq!(
            create_link(application.clone(), Some(123)).await,
            StatusCode::OK
        );
        assert!(application
            .store
            .links("")
            .unwrap()
            .iter()
            .any(|link| link.max_bytes == Some(123)));
        assert_eq!(application.store.links("").unwrap()[0].max_bytes, None);
        assert_eq!(audit_count(), 2);
    }

    #[tokio::test]
    async fn create_link_expiry_uses_requested_days() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = admin_cookie(&application);
        let before = crate::store::now_unix();
        let response = app::router(application.clone())
            .oneshot(
                Request::post("/api/admin/links")
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "label": "expiring",
                            "password": "audit-secret",
                            "expires_days": 7,
                            "max_bytes": 123,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let after = crate::store::now_unix();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let id = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["link"]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let link = application.store.upload_link(&id).unwrap().unwrap();
        assert!((before..=after).contains(&link.created_at));
        assert!((before + 7 * 86_400..=after + 7 * 86_400).contains(&link.expires_at.unwrap()));
        assert!(link.password_hash.is_some());
        assert_eq!(link.max_bytes, Some(123));
        let audits = application
            .store
            .audit_recent_filtered(
                None,
                0,
                100,
                AuditFilters {
                    event: Some("link_created"),
                    query: None,
                },
            )
            .unwrap();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].actor, "local");
        assert_eq!(audits[0].subject, id);
        assert_eq!(audits[0].detail["label"], "expiring");
        assert_eq!(audits[0].detail["has_password"], true);
        assert_eq!(audits[0].detail["expires_at"], json!(link.expires_at));
        assert_eq!(audits[0].detail["max_bytes"], 123);
        let detail = audits[0].detail.to_string();
        assert!(!detail.contains("audit-secret"));
        assert!(!link
            .password_hash
            .as_deref()
            .is_some_and(|hash| detail.contains(hash)));
    }

    #[tokio::test]
    async fn request_link_expiry_bounds_are_enforced_at_the_authenticated_api() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = admin_cookie(&application);
        let cases = [
            ("missing", json!({ "label": "missing" }), None, true),
            (
                "null",
                json!({ "label": "null", "expires_days": null }),
                None,
                true,
            ),
            (
                "one",
                json!({ "label": "one", "expires_days": 1 }),
                Some(1u32),
                true,
            ),
            (
                "maximum",
                json!({ "label": "maximum", "expires_days": 3650 }),
                Some(3650u32),
                true,
            ),
            (
                "zero",
                json!({ "label": "zero", "expires_days": 0 }),
                None,
                false,
            ),
            (
                "over-max",
                json!({ "label": "over-max", "expires_days": 3651 }),
                None,
                false,
            ),
            (
                "u32-max",
                json!({ "label": "u32-max", "expires_days": u32::MAX }),
                None,
                false,
            ),
        ];
        for (label, body, expected_days, accepted) in cases {
            let before = application.store.links("").unwrap().len();
            let response = app::router(application.clone())
                .oneshot(
                    Request::post("/api/admin/links")
                        .header("cookie", &cookie)
                        .header("x-votport", "1")
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let response_body = response.into_body().collect().await.unwrap().to_bytes();
            let after = application.store.links("").unwrap().len();
            if accepted {
                assert_eq!(status, StatusCode::OK, "{label}");
                assert_eq!(after, before + 1, "{label}");
                let id = serde_json::from_slice::<serde_json::Value>(&response_body).unwrap()
                    ["link"]["id"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let link = application.store.upload_link(&id).unwrap().unwrap();
                assert_eq!(
                    link.expires_at,
                    expected_days.map(|days| link.created_at + u64::from(days) * 86_400),
                    "{label}"
                );
            } else {
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{label}");
                assert_eq!(after, before, "{label}");
                assert!(
                    String::from_utf8_lossy(&response_body)
                        .contains("expires_days must be between"),
                    "{label}: {}",
                    String::from_utf8_lossy(&response_body)
                );
            }
        }
    }

    #[tokio::test]
    async fn receive_link_passwords_are_limited_to_256_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = admin_cookie(&application);
        let create = |password: String| {
            let application = application.clone();
            let cookie = cookie.clone();
            async move {
                app::router(application.clone())
                    .oneshot(
                        Request::post("/api/admin/links")
                            .header("cookie", &cookie)
                            .header("x-votport", "1")
                            .header("content-type", "application/json")
                            .body(Body::from(
                                json!({ "label": "test", "password": password }).to_string(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
                    .status()
            }
        };

        assert_eq!(create("a".repeat(256)).await, StatusCode::OK);
        assert_eq!(create("é".repeat(128)).await, StatusCode::OK);
        assert_eq!(
            create("a".repeat(257)).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            create("é".repeat(129)).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[tokio::test]
    async fn switch_tenant_requires_csrf_header() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let cookie = admin_cookie(&application);
        let response = app::router(application)
            .oneshot(
                Request::post("/api/admin/tenant")
                    .header("cookie", cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tenant":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

#[cfg(test)]
mod backup_delete_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    use crate::api::testing;
    use crate::app;

    fn admin_cookie(application: &Arc<App>) -> String {
        super::test_admin_cookie(
            application,
            &auth::AdminIdentity {
                subject: "platform-admin".to_owned(),
                tenant: String::new(),
                role: "admin".to_owned(),
                grants: vec![auth::TenantGrant {
                    incarnation: None,
                    tenant: String::new(),
                    role: "admin".to_owned(),
                }],
                credential_version: 1,
            },
        )
    }

    async fn delete_backup(application: &Arc<App>, cookie: &str, uri: &str) -> StatusCode {
        app::router(application.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(uri)
                    .header("cookie", cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn delete_route_removes_a_local_archive_and_audits_it() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let backups = crate::backup::ensure_backups_dir(&application.config.data_dir).unwrap();
        let snapshot = backups.join("votport-backup-v2-1-deadbeef.tar");
        std::fs::write(&snapshot, b"snapshot").unwrap();
        let cookie = admin_cookie(&application);
        // Unknown source and invalid identifiers are refused before touching disk.
        assert_eq!(
            delete_backup(
                &application,
                &cookie,
                "/api/admin/backups/scsi/votport-backup-v2-1-deadbeef.tar"
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            delete_backup(
                &application,
                &cookie,
                "/api/admin/backups/local/votport-1-%3Cbad%3E"
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert!(snapshot.exists());
        // S3 deletion without an S3 destination is refused.
        assert_eq!(
            delete_backup(
                &application,
                &cookie,
                "/api/admin/backups/s3/votport-backup-v2-1-deadbeef.tar"
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        // A file with a non-archive name in the backup root is not deletable as an archive.
        assert_eq!(
            delete_backup(
                &application,
                &cookie,
                "/api/admin/backups/local/votport-backup-v2-1-deadbeef.tar.bad"
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert!(snapshot.exists());
        assert_eq!(
            delete_backup(
                &application,
                &cookie,
                "/api/admin/backups/local/votport-backup-v2-1-deadbeef.tar"
            )
            .await,
            StatusCode::OK
        );
        assert!(!snapshot.exists());
        // Deleting an already deleted archive is 404, not a silent success.
        assert_eq!(
            delete_backup(
                &application,
                &cookie,
                "/api/admin/backups/local/votport-backup-v2-1-deadbeef.tar"
            )
            .await,
            StatusCode::NOT_FOUND
        );
        let audits = application.store.audit_export(None, 0, 0, 100).unwrap();
        let row = audits
            .iter()
            .find(|row| row.event == "backup_deleted")
            .expect("deletion is audited");
        assert_eq!(row.subject, "votport-backup-v2-1-deadbeef.tar");
        assert_eq!(row.detail["source"], "local");
    }
}

#[cfg(test)]
mod status_tests {
    use super::active_grant_hashes;

    #[test]
    fn in_flight_keys_collapse_to_their_grant() {
        let keys = ["abc:0", "abc:batch", "abc:1:lease-token", "def:bundle"];
        assert_eq!(
            active_grant_hashes(keys.iter().copied()),
            vec!["abc".to_owned(), "def".to_owned()]
        );
    }
}

#[cfg(test)]
mod received_page_tests {
    use super::*;
    use crate::{
        api::testing,
        app,
        store::tests::{link_in, test_tenant},
    };
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    fn cookie(app: &App, tenant: &str, role: &str) -> String {
        test_admin_cookie(
            app,
            &auth::AdminIdentity {
                subject: format!("sso:{tenant}:{role}"),
                tenant: tenant.into(),
                role: role.into(),
                grants: vec![auth::TenantGrant {
                    incarnation: None,
                    tenant: tenant.into(),
                    role: role.into(),
                }],
                credential_version: 1,
            },
        )
    }

    async fn get(app: &Arc<App>, cookie: &str, route: &str) -> Response {
        app::router(Arc::clone(app))
            .oneshot(
                Request::get(route)
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn json(response: Response) -> serde_json::Value {
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    fn seed(app: &App) {
        app.store.insert_tenant(test_tenant("team")).unwrap();
        for index in 0..101 {
            app.store
                .insert_link(link_in("team", &format!("request-{index:03}")))
                .unwrap();
        }
        let record = serde_json::from_value(json!({
            "id":"upload", "started_at":10, "completed_at":20, "total_bytes":201,
            "package_root":"package", "replayed_chunks":2, "rejected_chunks":3,
            "files":(0..201).map(|index|json!({"path":format!("file-{index}"),"stored_as":format!("file-{index}"),
                "bytes":1,"suite":"blake3","root":"aa","receipt":true,"deleted":index == 1})).collect::<Vec<_>>(),
            "log":[{"at":10,"kind":"opened"},{"at":12,"kind":"published","path":"file-0","bytes":5,"secs":2},
                {"at":15,"kind":"quiet","secs":2},{"at":18,"kind":"reattached"},{"at":20,"kind":"finished"}],
        })).unwrap();
        app.store
            .append_upload("team", "request-000", record)
            .unwrap();
    }

    #[tokio::test]
    async fn received_pages_are_bounded_scoped_and_lazy() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        seed(&application);
        let cookie = cookie(&application, "team", "operator");
        let listing = json(get(&application, &cookie, "/api/admin/links").await).await;
        assert_eq!(listing["links"].as_array().unwrap().len(), 50);
        assert!(listing["next_cursor"].is_object());
        assert!(listing["links"]
            .as_array()
            .unwrap()
            .iter()
            .all(|link| link.get("uploads").is_none()));
        let exact = json(get(&application, &cookie, "/api/admin/links/request-000").await).await;
        assert_eq!(exact["link"]["id"], "request-000");
        assert_eq!(exact["link"]["upload_count"], 1);
        assert!(exact["link"].get("uploads").is_none());
        assert_eq!(
            get(&application, &cookie, "/api/admin/links/missing")
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        let selected =
            json(get(&application, &cookie, "/api/admin/links?search=request-000").await).await;
        assert_eq!(selected["links"][0]["upload_count"], 1);
        assert_eq!(selected["links"][0]["upload_bytes"], 201);
        let headers = json(
            get(
                &application,
                &cookie,
                "/api/admin/links/request-000/uploads",
            )
            .await,
        )
        .await;
        assert_eq!(headers["uploads"][0]["file_count"], 201);
        assert!(headers["uploads"][0].get("files").is_none());
        assert!(headers["uploads"][0].get("log").is_none());
        let header = json(
            get(
                &application,
                &cookie,
                "/api/admin/links/request-000/uploads/upload",
            )
            .await,
        )
        .await;
        assert_eq!(header["upload"]["log"].as_array().unwrap().len(), 5);
        let mut files = Vec::new();
        for (offset, count, next) in [(0, 100, Some(100)), (100, 100, Some(200)), (200, 1, None)] {
            let page = json(
                get(
                    &application,
                    &cookie,
                    &format!("/api/admin/links/request-000/uploads/upload/files?offset={offset}"),
                )
                .await,
            )
            .await;
            assert_eq!(page["file_count"], 201);
            assert_eq!(page["files"].as_array().unwrap().len(), count);
            assert_eq!(page["next_offset"], json!(next));
            files.extend(page["files"].as_array().unwrap().clone());
        }
        assert_eq!(files.len(), 201);
        for (index, file) in files.iter().enumerate() {
            assert_eq!(file["file_index"], index);
        }
        assert_eq!(files[1]["exists"], false);
        for suffix in ["?limit=0", "?limit=101", "?offset=18446744073709551615"] {
            assert_eq!(
                get(
                    &application,
                    &cookie,
                    &format!("/api/admin/links/request-000/uploads/upload/files{suffix}")
                )
                .await
                .status(),
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        for route in [
            "/api/admin/links?limit=101",
            "/api/admin/links?before_id=x",
            "/api/admin/links/request-000/uploads?before_position=0",
        ] {
            assert_eq!(
                get(&application, &cookie, route).await.status(),
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        for route in [
            "/api/admin/links/request-000",
            "/api/admin/links/request-000/uploads",
            "/api/admin/links/request-000/uploads/upload",
            "/api/admin/links/request-000/uploads/upload/files",
            "/api/admin/links/request-000/uploads/upload/timeline",
        ] {
            assert_eq!(
                get(&application, "", route).await.status(),
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                get(
                    &application,
                    &self::cookie(&application, "", "admin"),
                    route
                )
                .await
                .status(),
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                get(
                    &application,
                    &self::cookie(&application, "team", "viewer"),
                    route
                )
                .await
                .status(),
                StatusCode::OK
            );
        }
    }

    #[tokio::test]
    async fn received_export_is_complete_and_releases_spool_on_drop() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        seed(&application);
        let cookie = cookie(&application, "team", "operator");
        let route = "/api/admin/links/request-000/uploads/upload/timeline";
        let response = get(&application, &cookie, route).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_DISPOSITION],
            "attachment; filename=\"votport-transfer-upload.json\"; filename*=UTF-8''votport-transfer-upload.json"
        );
        assert_eq!(application.sessions.active_outbound_for_tenant("team"), 1);
        // A slow reader holds only its operation guard and private spool, not the Store lock.
        let store = Arc::clone(&application.store);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::task::spawn_blocking(move || {
                store
                    .insert_link(link_in("team", "while-exporting"))
                    .unwrap();
            }),
        )
        .await
        .unwrap()
        .unwrap();
        let scratch = || {
            std::fs::read_dir(&application.config.data_dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".timeline-")
                })
                .count()
        };
        assert_eq!(scratch(), 0);
        drop(response);
        assert_eq!(application.sessions.active_outbound_for_tenant("team"), 0);
        assert_eq!(scratch(), 0);
        let response = get(&application, &cookie, route).await;
        let length: usize = response.headers()[header::CONTENT_LENGTH]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), length);
        assert_eq!(application.sessions.active_outbound_for_tenant("team"), 0);
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["upload"]["files"].as_array().unwrap().len(), 201);
        assert_eq!(document["upload"]["files"][200]["path"], "file-200");
        assert!(document["upload"]["files"][0].get("file_index").is_none());
        assert_eq!(
            document["summary"],
            json!({"files":201,"bytes":201,"duration":10,"average":20.0,"peak":3.0,
            "pauses":2,"restarts":1,"resent":2,"rejected":3,"outcome":"finished","transport":"http"})
        );
        let link = application
            .store
            .link("team", "request-000")
            .unwrap()
            .unwrap();
        let upload = &link.uploads[0];
        assert_eq!(
            document,
            json!({
                "request":{"id":link.id,"label":link.label,"dest":link.dest},
                "upload":{"id":upload.id,"started_at":upload.started_at,"completed_at":upload.completed_at,
                    "transport":"http","package_root":upload.package_root,"total_bytes":upload.total_bytes,
                    "partial":upload.partial,"replayed_chunks":upload.replayed_chunks,"rejected_chunks":upload.rejected_chunks,
                    "files":upload.files.iter().map(|file|json!({"path":file.path,"bytes":file.bytes,"suite":file.suite,
                        "root":file.root,"receipt":file.receipt})).collect::<Vec<_>>()},
                "summary":{"files":201,"bytes":201,"duration":10,"average":20.0,"peak":3.0,
                    "pauses":2,"restarts":1,"resent":2,"rejected":3,"outcome":"finished","transport":"http"},
                "events":upload.log,
            })
        );
        assert!(serde_json::from_slice::<serde_json::Value>(&bytes[..bytes.len() - 1]).is_err());
        assert_eq!(
            get(
                &application,
                &cookie,
                "/api/admin/links/request-000/uploads/missing/timeline"
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(scratch(), 0);
        assert_eq!(application.sessions.active_outbound_for_tenant("team"), 0);
    }
}
