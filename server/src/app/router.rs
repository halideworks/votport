//! HTTP routes, page serving, and per-route request limits.

use super::*;

pub fn router(app: Arc<App>) -> Router {
    let web_root = app.config.web_root.clone();
    let admin_page = web_root.join("index.html");
    let request_page = web_root.join("request.html");
    let outbound_page = web_root.join("send.html");
    let page = |name: &str| web_root.join(format!("{name}.html"));

    // Request pages carry the secret link token in the URL; never let the
    // browser forward it as a referrer.
    const REFERRER_POLICY: &str = "no-referrer";

    let serve_page = |path: std::path::PathBuf| {
        let app = Arc::clone(&app);
        get(move |headers: HeaderMap| {
            let path = path.clone();
            let app = Arc::clone(&app);
            async move {
                match tokio::fs::read_to_string(&path).await {
                    Ok(mut contents) => {
                        let admin_page = contents.contains("<nav id=\"nav\" class=\"nav\"></nav>");
                        let mut footer_tenant = (!admin_page
                            && matches!(
                                path.file_stem().and_then(|name| name.to_str()),
                                Some("index" | "verify")
                            ))
                        .then(String::new);
                        let page_session = admin_page
                            .then(|| api::admin::admin_page_session(&app, &headers))
                            .flatten();
                        if let Some(session) = &page_session {
                            let session = api::admin::admin_session_view(session);
                            footer_tenant = session["tenant"].as_str().map(str::to_owned);
                            let mut nav = String::new();
                            let self_branding = session["tenant"]
                                .as_str()
                                .is_some_and(|tenant| !tenant.is_empty());
                            if self_branding {
                                contents = contents
                                    .replace(
                                        "<title>VOTPort &middot; Tenants</title>",
                                        "<title>VOTPort &middot; Branding</title>",
                                    )
                                    .replace(
                                        "<h1 id=\"page-title\">Tenant namespaces</h1>",
                                        "<h1 id=\"page-title\">Branding</h1>",
                                    );
                            }
                            for (page, default_label) in [
                                ("receive", "Receive"),
                                ("deliver", "Deliver"),
                                ("workflows", "Workflows"),
                                ("trade-routes", "Trade routes"),
                                ("storage", "Storage"),
                                ("automation", "Automation"),
                                ("notifications", "Notifications"),
                                ("tenants", "Tenants"),
                                ("audit", "Audit"),
                                ("system", "System"),
                            ] {
                                if session["pages"]
                                    .as_array()
                                    .is_some_and(|pages| pages.iter().any(|value| value == page))
                                {
                                    let active = if path.file_stem().and_then(|name| name.to_str())
                                        == Some(page)
                                    {
                                        " class=\"active\" aria-current=\"page\""
                                    } else {
                                        ""
                                    };
                                    let (label, hint): (&str, Option<&str>) = if page == "tenants" {
                                        if self_branding {
                                            (
                                                "Branding",
                                                Some("Set how recipients see this tenant."),
                                            )
                                        } else {
                                            (default_label, Some("Manage separate workspaces, each with its own users and files."))
                                        }
                                    } else {
                                        (default_label, None)
                                    };
                                    let hint = hint.map_or(String::new(), |hint| {
                                        format!(" data-hint=\"{hint}\"")
                                    });
                                    nav.push_str(&format!(
                                        "<a href=\"/{page}\"{active}{hint}>{label}</a>"
                                    ));
                                }
                            }
                            contents = contents.replace(
                                "<nav id=\"nav\" class=\"nav\"></nav>",
                                &format!("<nav id=\"nav\" class=\"nav\">{nav}</nav>"),
                            );
                            let bootstrap = session.to_string().replace('<', "\\u003c");
                            contents = contents.replace("</head>", &format!("<script id=\"admin-session\" type=\"application/json\">{bootstrap}</script></head>"));
                        }
                        if let Some(tenant) = footer_tenant {
                            if let Ok(Some(branding)) = app.store.branding(&tenant) {
                                contents = contents.replace(
                                    "<span class=\"footer-custom\"></span>",
                                    &format!(
                                        "<span class=\"footer-custom\">{}</span>",
                                        api::branding_footer(&branding)
                                    ),
                                );
                            }
                        }
                        (
                            [
                                (axum::http::header::CONTENT_SECURITY_POLICY, CSP),
                                (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                                (axum::http::header::REFERRER_POLICY, REFERRER_POLICY),
                                // Audit finding 518: a popup holding a
                                // cross-origin window handle to the login or a
                                // recipient page is an XS-Leak; same-origin
                                // severs it. COEP stays off: nothing here uses
                                // SharedArrayBuffer.
                                (
                                    axum::http::HeaderName::from_static(
                                        "cross-origin-opener-policy",
                                    ),
                                    "same-origin",
                                ),
                                // Admin pages contain the current identity; shared
                                // caches must never retain them.
                                (
                                    axum::http::header::CACHE_CONTROL,
                                    if admin_page {
                                        "private, no-store"
                                    } else {
                                        "no-cache"
                                    },
                                ),
                            ],
                            Html(contents),
                        )
                            .into_response()
                    }
                    Err(_) => (
                        axum::http::StatusCode::NOT_FOUND,
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "text/plain; charset=utf-8",
                        )],
                        "page not found; is VOTPORT_WEB_ROOT set correctly?",
                    )
                        .into_response(),
                }
            }
        })
    };

    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        // Pages.
        .route("/", serve_page(admin_page))
        .route("/r/{token}", serve_page(request_page))
        .route("/s/{token}", serve_page(outbound_page))
        .route("/verify", serve_page(page("verify")))
        // no-cache means revalidate, not never-cache: repeat visits answer
        // conditional GETs with 304s instead of re-downloading the wasm and
        // the hero image, while a redeploy still takes effect immediately.
        // Content-stamped requests (?v=<hash>) skip even the revalidation;
        // asset_cache_control marks those immutable.
        .nest_service(
            "/assets",
            Router::new()
                .fallback_service(
                    ServeDir::new(web_root.join("assets")).append_index_html_on_directories(false),
                )
                .layer(
                    tower::ServiceBuilder::new()
                        .layer(
                            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                                axum::http::header::CACHE_CONTROL,
                                axum::http::HeaderValue::from_static("no-cache"),
                            ),
                        )
                        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
                            axum::http::header::REFERRER_POLICY,
                            axum::http::HeaderValue::from_static("no-referrer"),
                        ))
                        // Audit finding 517: hash-worker.js hashes every
                        // sender's and recipient's file bytes inside a
                        // dedicated worker, whose policy comes from its own
                        // response; without this the worker ran with none.
                        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
                            axum::http::header::CONTENT_SECURITY_POLICY,
                            axum::http::HeaderValue::from_static(CSP),
                        ))
                        .layer(axum::middleware::from_fn_with_state(
                            Arc::clone(&app),
                            asset_cache_control,
                        )),
                ),
        )
        // Admin API.
        .route("/api/admin/login", post(api::admin_login))
        .route("/api/admin/logout", post(api::admin_logout))
        .route("/api/admin/session", get(api::admin_session))
        .route("/api/admin/status", get(api::admin_status))
        .route("/api/admin/search", get(api::admin_search))
        .route("/api/admin/audit", get(api::admin_audit_export))
        .route("/api/admin/holdings", get(api::holdings))
        .route("/api/admin/backup", get(api::backup_database))
        .route(
            "/api/admin/backups",
            get(api::get_backups)
                .put(api::put_backups_config)
                .post(api::create_backup),
        )
        .route("/api/admin/backups/restore", post(api::restore_backup))
        .route(
            "/api/admin/backups/{source}/{id}",
            delete(api::delete_backup),
        )
        .route(
            "/api/admin/tenants",
            get(api::list_tenants).post(api::create_tenant),
        )
        .route("/api/admin/principals", get(api::list_principals))
        .route(
            "/api/admin/receiving-storage",
            get(api::admin::get_receiving_storage).post(api::admin::check_receiving_storage),
        )
        .route(
            "/api/admin/settings",
            get(api::get_settings).put(api::put_settings),
        )
        .route(
            "/api/admin/settings/retention-clock/acknowledge",
            post(api::acknowledge_retention_clock),
        )
        .route(
            "/api/admin/tenants/{key}",
            axum::routing::patch(api::update_tenant).delete(api::delete_tenant),
        )
        .route(
            "/api/admin/branding/{key}",
            get(api::get_branding)
                .put(api::put_branding)
                .delete(api::delete_branding),
        )
        .route(
            "/api/admin/branding/{key}/logo",
            axum::routing::put(api::put_branding_logo)
                .delete(api::delete_branding_logo)
                .layer(DefaultBodyLimit::max(api::admin::MAX_LOGO_BYTES + 1024)),
        )
        .route("/api/admin/tenant", post(api::switch_tenant))
        .route("/api/admin/principals/revoke", post(api::revoke_principal))
        .route(
            "/api/admin/principals/unblock",
            post(api::unblock_principal),
        )
        .route("/api/admin/principals/purge", post(api::purge_principal))
        .route(
            "/api/admin/outbound-grants",
            get(api::list_outbound_grants).merge(post(api::create_outbound_grant).layer(
                DefaultBodyLimit::max(api::outbound::MAX_GRANT_REQUEST_BYTES),
            )),
        )
        .route(
            "/api/admin/outbound-grants/preparations",
            post(api::outbound::create_outbound_grant_preparation).layer(DefaultBodyLimit::max(
                api::outbound::MAX_GRANT_REQUEST_BYTES,
            )),
        )
        .route(
            "/api/admin/outbound-grants/preparations/{id}",
            get(api::outbound::outbound_grant_preparation),
        )
        .route(
            "/api/admin/outbound-grants/{id}",
            get(api::outbound::get_outbound_grant)
                .patch(api::update_outbound_grant)
                .delete(api::delete_outbound_grant),
        )
        .route(
            "/api/admin/outbound-grants/{id}/url",
            get(api::outbound::outbound_grant_url),
        )
        .route(
            "/api/admin/automation-tokens",
            get(api::list_automation_tokens).post(api::create_automation_token),
        )
        .route(
            "/api/admin/automation-tokens/{id}",
            axum::routing::delete(api::delete_automation_token),
        )
        .route(
            "/api/admin/outbound-files",
            get(api::list_outbound_files)
                .post(api::upload_outbound_file)
                .delete(api::delete_outbound_file),
        )
        .route("/api/admin/password", post(api::admin_change_password))
        .route(
            "/api/admin/links",
            get(api::list_links).post(api::create_link),
        )
        .route(
            "/api/admin/links/{id}",
            get(api::get_link)
                .post(api::update_link)
                .patch(api::update_link)
                .delete(api::delete_link),
        )
        .route("/api/admin/links/{id}/qr", get(api::link_qr))
        .route("/api/admin/links/{id}/uploads", get(api::list_link_uploads))
        .route(
            "/api/admin/links/{id}/uploads/{upload}/files",
            get(api::list_upload_files),
        )
        .route(
            "/api/admin/links/{id}/uploads/{upload}/timeline",
            get(api::export_upload_timeline),
        )
        .route(
            "/api/admin/links/{id}/uploads/{upload}",
            get(api::get_link_upload).delete(api::delete_upload_record),
        )
        .route(
            "/api/admin/links/{id}/uploads/{upload}/files/{index}",
            axum::routing::delete(api::delete_received_file),
        )
        .route("/metrics", axum::routing::get(metrics))
        // Multi-page admin: static shells; authz is enforced per API call.
        .route(
            "/api/automation/notifications",
            get(api::outbound::automation::notification_destinations),
        )
        .route(
            "/api/workflows/jobs/{id}/notifications",
            axum::routing::patch(api::outbound::workflows::update_notifications),
        )
        .route("/trade-routes", serve_page(page("trade-routes")))
        .route("/api/port", get(api::trade::discover))
        .route("/api/port/enroll", post(api::trade::enroll))
        .route("/api/port/status", post(api::trade::status))
        .route("/api/port/rotate", post(api::trade::rotate_remote))
        .route(
            "/api/trade-routes",
            get(api::trade::list).post(api::trade::accept),
        )
        .route(
            "/api/trade-routes/port",
            axum::routing::put(api::trade::settings),
        )
        .route("/api/trade-routes/endpoints", post(api::trade::endpoint))
        .route("/api/trade-routes/invitations", post(api::trade::invite))
        .route("/api/trade-routes/inspect", post(api::trade::inspect))
        .route(
            "/api/trade-routes/{id}",
            axum::routing::put(api::trade::update),
        )
        .route("/api/trade-routes/{id}/test", post(api::trade::test))
        .route("/api/trade-routes/{id}/rotate", post(api::trade::rotate))
        .route(
            "/api/trade-routes/{id}/address",
            axum::routing::put(api::trade::change_address),
        )
        .route("/notifications", serve_page(page("notifications")))
        .route(
            "/api/notifications",
            get(api::notifications::list).post(api::notifications::save),
        )
        .route(
            "/api/notifications/defaults",
            axum::routing::put(api::notifications::defaults),
        )
        .route(
            "/api/notifications/{id}",
            axum::routing::delete(api::notifications::delete),
        )
        .route(
            "/api/notifications/{id}/test",
            post(api::notifications::test),
        )
        .route("/receive", serve_page(page("receive")))
        .route("/deliver", serve_page(page("deliver")))
        .route("/workflows", serve_page(page("workflows")))
        .route("/storage", serve_page(page("storage")))
        .route("/automation", serve_page(page("automation")))
        .route("/links", serve_page(page("receive")))
        .route("/tenants", serve_page(page("tenants")))
        .route("/audit", serve_page(page("audit")))
        .route("/system", serve_page(page("system")))
        // SSO sign-in (phase 3 of docs/multi-tenancy.md).
        .route("/api/admin/sso", get(api::sso_available))
        .route("/api/admin/sso/start", get(api::sso_start))
        .route("/api/admin/sso/exchange", post(api::sso::sso_exchange))
        .route("/api/admin/callback", get(api::sso_callback))
        // Public upload API.
        // SCIM 2.0 provisioning, bearer-authenticated, no cookie or CSRF header.
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(api::scim::service_provider_config),
        )
        .route("/scim/v2/ResourceTypes", get(api::scim::resource_types))
        .route("/scim/v2/ResourceTypes/{id}", get(api::scim::resource_type))
        .route("/scim/v2/Schemas", get(api::scim::schemas))
        .route("/scim/v2/Schemas/{id}", get(api::scim::schema))
        .route(
            "/scim/v2/Groups",
            get(api::scim::list_groups).post(api::scim::create_group),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(api::scim::get_group)
                .put(api::scim::replace_group)
                .patch(api::scim::patch_group)
                .delete(api::scim::delete_group),
        )
        .route(
            "/scim/v2/Users",
            get(api::scim::list_users).post(api::scim::create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(api::scim::get_user)
                .put(api::scim::replace_user)
                .patch(api::scim::patch_user)
                .delete(api::scim::delete_user),
        )
        .route("/api/replica", get(api::replica::replica_archive))
        .route("/api/push-identity", get(push_identity))
        .route("/api/r/{token}", get(api::link_info))
        .route("/api/receipt-key", get(api::receipt_key))
        .route(
            "/api/verify",
            post(api::verify_receipt).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/api/r/{token}/logo", get(api::link_logo))
        .route("/api/r/{token}/verify", post(api::verify_link_password))
        .route("/api/r/{token}/push", post(api::create_push_session))
        .route("/api/r/{token}/session", post(api::create_session))
        .route(
            "/api/r/{token}/route",
            post(api::outbound::workflows::routes::receive)
                .layer(DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route(
            "/api/route/{id}/revoke",
            post(api::outbound::workflows::routes::revoke)
                .layer(DefaultBodyLimit::max(2 * 1024 * 1024)),
        )
        .route(
            "/api/admin/links/{id}/uploads/{upload}/route",
            get(api::outbound::workflows::routes::evidence),
        )
        .route("/api/s/{token}", get(api::outbound_metadata))
        .route(
            "/api/s/{token}/evidence-challenge",
            post(api::evidence::challenge),
        )
        .route(
            "/api/workflows/projects",
            get(api::outbound::workflows::projects)
                .put(api::outbound::workflows::put_project)
                .layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route(
            "/api/workflows/jobs",
            get(api::outbound::workflows::list)
                .post(api::outbound::workflows::create)
                .layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route(
            "/api/workflows/jobs/{id}",
            get(api::outbound::workflows::get)
                .post(api::outbound::workflows::change)
                .layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/workflows/jobs/{id}/reprocess",
            post(api::outbound::workflows::reprocess).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/workflows/jobs/{id}/evidence",
            get(api::outbound::workflows::evidence)
                .delete(api::outbound::workflows::purge_evidence),
        )
        .route(
            "/api/workflows/events",
            get(api::outbound::workflows::events),
        )
        .route(
            "/api/workflows/events/export",
            get(api::outbound::workflows::export_events),
        )
        .route(
            "/api/workflows/storage",
            get(api::outbound::workflows::storage::list)
                .put(api::outbound::workflows::storage::put)
                .layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/api/workflows/storage/{id}/test",
            post(api::outbound::workflows::storage::test_connection)
                .layer(DefaultBodyLimit::max(1024)),
        )
        .route(
            "/api/workflows/storage/{id}",
            delete(api::outbound::workflows::storage::remove),
        )
        .route(
            "/api/workflows/webhook",
            get(api::outbound::workflows::webhook)
                .put(api::outbound::workflows::put_webhook)
                .layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/workflows/webhook/attempts",
            get(api::outbound::workflows::webhook_attempts),
        )
        .route(
            "/api/workflows/webhook/replay/{id}",
            post(api::outbound::workflows::replay_webhook),
        )
        .route(
            "/api/s/{token}/recipient-challenge",
            post(api::outbound::workflows::recipient_challenge).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/s/{token}/recipient-verify",
            post(api::outbound::workflows::recipient_verify).layer(DefaultBodyLimit::max(16384)),
        )
        .route(
            "/api/evidence",
            post(api::evidence::submit).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/api/admin/outbound/{id}/evidence",
            get(api::evidence::list),
        )
        .route("/api/s/{token}/logo", get(api::outbound_logo))
        .route("/api/s/{token}/verify", post(api::verify_outbound_password))
        .route("/api/s/{token}/fetch", post(api::serve::mint_fetch))
        .route("/api/s/{token}/bundle", get(api::outbound::outbound_bundle))
        .route("/api/s/{token}/batch", get(api::outbound::outbound_batch))
        .nest(
            "/api/automation",
            Router::new()
                .route("/share", post(api::automation_share))
                .route("/session", get(api::outbound::automation::session))
                .route("/files", get(api::outbound::automation::files))
                .route("/deliveries", get(api::outbound::automation::deliveries))
                .route(
                    "/deliveries/{id}",
                    get(api::outbound::automation::delivery)
                        .delete(api::outbound::automation::revoke),
                )
                .route("/operations/{id}", get(api::outbound::automation::recover)),
        )
        .route("/api/s/{token}/receipt", get(api::outbound_receipt))
        .route(
            "/api/s/{token}/file",
            get(api::outbound_file).head(api::outbound_file_head),
        )
        .route(
            "/api/s/{token}/files/{index}",
            get(api::outbound_file_indexed).head(api::outbound_file_indexed_head),
        )
        .route(
            "/api/s/{token}/receipts/{index}",
            get(api::outbound_receipt_indexed),
        )
        .route(
            "/api/session/{sid}/seal",
            post(api::upload_seal).layer(DefaultBodyLimit::max(session::MAX_SEAL_BYTES + 1024)),
        )
        .route(
            "/api/session/{sid}/page",
            post(api::upload_page).layer(DefaultBodyLimit::max(session::MAX_PAGE_BYTES + 1024)),
        )
        .route("/api/session/{sid}/begin", post(api::upload_begin))
        .route(
            "/api/session/{sid}/chunk",
            post(api::upload_chunk).layer(DefaultBodyLimit::max(session::MAX_CHUNK_BODY_BYTES)),
        )
        .route("/api/session/{sid}/finish", post(api::upload_finish))
        .route("/api/session/{sid}/abort", post(api::upload_abort))
        .fallback(|| async {
            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "page not found\n",
            )
        })
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::X_CONTENT_TYPE_OPTIONS,
                axum::http::HeaderValue::from_static("nosniff"),
            ),
        )
        .layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::REFERRER_POLICY,
                axum::http::HeaderValue::from_static("no-referrer"),
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&app),
            request_observability,
        ))
        .layer(axum::middleware::from_fn(api_response_policy));
    // HSTS follows the same rule as the Secure cookie attribute: the
    // operator-declared public origin decides. The request scheme is
    // invisible behind a terminating proxy and X-Forwarded-Proto is only
    // believed from named proxies, so public_url is the one honest signal;
    // browsers ignore the header over plain http either way.
    let router = if app
        .config
        .public_url
        .as_deref()
        .is_some_and(|url| url.starts_with("https://"))
    {
        router.layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                header::STRICT_TRANSPORT_SECURITY,
                header::HeaderValue::from_static("max-age=31536000"),
            ),
        )
    } else {
        router
    };
    router.with_state(app)
}
