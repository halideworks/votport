use super::*;
use crate::store::{
    NotificationDestination, NotificationMode, NotificationPolicy, NOTIFICATION_EVENTS,
};
use axum::extract::{Path, Request, State};
use std::sync::Arc;

pub const UPLOAD_EVENTS: [&str; 2] = ["upload_complete", "upload_failed"];
pub const DOWNLOAD_EVENTS: [&str; 2] = ["outbound_download_started", "outbound_delivery_complete"];
pub const WORKFLOW_EVENTS: [&str; 4] = [
    "outbound_download_started",
    "outbound_delivery_complete",
    "workflow_retry_scheduled",
    "workflow_failed",
];

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, message)
}

pub(crate) fn validate_policy(
    app: &App,
    tenant: &str,
    policy: &NotificationPolicy,
    events: &[&str],
) -> ApiResult<()> {
    policy.validate(events).map_err(invalid)?;
    for rule in &policy.rules {
        if crate::notify::destination(app, tenant, &rule.destination_id)
            .map_err(store_unavailable)?
            .is_none()
        {
            return Err(invalid(
                "Notification destination is unavailable in this tenant",
            ));
        }
    }
    Ok(())
}

pub(crate) fn creation_policy(
    app: &App,
    tenant: &str,
    policy: Option<NotificationPolicy>,
    events: &[&str],
) -> ApiResult<Option<NotificationPolicy>> {
    if let Some(policy) = &policy {
        validate_policy(app, tenant, policy, events)?;
    }
    Ok(policy)
}

pub async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    catalog(&app, &identity.tenant, true)
}

/// Automation callers pick destinations by id and label; recipient lists
/// stay with the administrators who manage them.
pub(crate) fn catalog(app: &App, tenant: &str, with_recipients: bool) -> ApiResult<Response> {
    let destinations = app
        .store
        .notification_destinations(tenant)
        .map_err(store_unavailable)?
        .iter()
        .map(|destination| {
            let mut view = destination.public();
            if !with_recipients {
                view.as_object_mut()
                    .map(|object| object.remove("recipients"));
            }
            view
        })
        .collect::<Vec<_>>();
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({"destinations":destinations,
        "defaults":app.store.notification_defaults(tenant).map_err(store_unavailable)?,
        "outcomes":app.store.notification_outcomes(tenant).map_err(store_unavailable)?,
        "events":if with_recipients { json!(NOTIFICATION_EVENTS) } else {
            json!({"create_delivery":DOWNLOAD_EVENTS,"create_job":WORKFLOW_EVENTS})
        }})),
    )
        .into_response())
}

pub async fn defaults(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(policy): Json<NotificationPolicy>,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    if policy.mode == NotificationMode::Default {
        return Err(invalid("Tenant defaults must be off or custom"));
    }
    validate_policy(&app, &identity.tenant, &policy, &NOTIFICATION_EVENTS)?;
    app.store
        .save_notification_defaults(&identity.tenant, &policy)
        .map_err(store_unavailable)?;
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "notification_defaults_changed",
        "",
        &json!({}),
    );
    Ok(Json(policy).into_response())
}

fn validate_destination(destination: &NotificationDestination) -> ApiResult<()> {
    if destination.label.trim().is_empty()
        || destination.label.chars().count() > 100
        || destination.target.trim().is_empty()
        || destination.target.chars().count() > 200
        || destination
            .label
            .chars()
            .chain(destination.target.chars())
            .any(char::is_control)
    {
        return Err(invalid("Provide a name (up to 100 characters) and destination description (up to 200 characters)"));
    }
    if ![
        "slack",
        "teams",
        "google_chat",
        "discord",
        "webhook",
        "ntfy",
        "pushover",
        "email",
    ]
    .contains(&destination.channel.as_str())
    {
        return Err(invalid("Unsupported notification service"));
    }
    if destination.token.len() > 8192
        || destination.user.len() > 8192
        || destination
            .token
            .chars()
            .chain(destination.user.chars())
            .any(char::is_control)
    {
        return Err(invalid("Invalid notification credentials"));
    }
    if !["email", "pushover"].contains(&destination.channel.as_str()) {
        if destination.url.is_empty() {
            return Err(invalid("A webhook or topic URL is required"));
        }
        admin::write_url("url", &json!(destination.url))?;
    } else if !destination.url.is_empty() {
        return Err(invalid("This service does not use a webhook URL"));
    }
    if destination.channel == "pushover"
        && (destination.token.is_empty() || destination.user.is_empty())
    {
        return Err(invalid(
            "Pushover requires an application token and user or group key",
        ));
    }
    if destination.channel == "email" {
        if destination.recipients.is_empty()
            || destination.recipients.len() > 50
            || destination.recipients.iter().any(|address| {
                address.len() > 254
                    || address.chars().any(char::is_control)
                    || address.parse::<lettre::message::Mailbox>().is_err()
            })
        {
            return Err(invalid("Provide 1 to 50 valid email recipients"));
        }
    } else if !destination.recipients.is_empty() {
        return Err(invalid("Email recipients apply only to email destinations"));
    }
    if !destination.thread_id.is_empty()
        && (destination.channel != "discord"
            || destination.thread_id.len() > 20
            || !destination.thread_id.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err(invalid("Discord thread ID must contain 1 to 20 digits"));
    }
    if !destination.user.is_empty() && destination.channel != "pushover" {
        return Err(invalid("A user key applies only to Pushover"));
    }
    if !destination.token.is_empty()
        && !["pushover", "ntfy", "webhook"].contains(&destination.channel.as_str())
    {
        return Err(invalid("This service does not use a separate token"));
    }
    Ok(())
}

pub async fn save(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(mut value): Json<serde_json::Value>,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| invalid("A connection object is required"))?;
    let clear_token = match object.remove("clear_token") {
        None => false,
        Some(serde_json::Value::Bool(value)) => value,
        _ => return Err(invalid("clear_token must be a boolean")),
    };
    let mut destination: NotificationDestination =
        serde_json::from_value(value).map_err(|_| invalid("Invalid connection fields"))?;
    destination.label = destination.label.trim().into();
    destination.target = destination.target.trim().into();
    destination.url = destination.url.trim().into();
    if destination.id.is_empty() {
        if destination.revision != 0 {
            return Err(invalid("A new connection starts at revision zero"));
        }
        destination.id = crate::auth::random_token();
    } else {
        let previous = app
            .store
            .notification_destination(&identity.tenant, &destination.id)
            .map_err(store_unavailable)?
            .ok_or_else(ApiError::not_found)?;
        if previous.channel != destination.channel {
            return Err(invalid("Create a new connection to change services"));
        }
        if destination.url.is_empty() {
            destination.url = previous.url;
        }
        if destination.token.is_empty() && !clear_token {
            destination.token = previous.token;
        }
        if destination.user.is_empty() {
            destination.user = previous.user;
        }
    }
    if clear_token {
        destination.token.clear();
    }
    validate_destination(&destination)?;
    if destination.enabled
        && destination.channel == "email"
        && app
            .store
            .resolved_settings(&app.config)
            .map_err(store_unavailable)?
            .smtp
            .is_none()
    {
        return Err(invalid(
            "Configure the server's SMTP relay in System settings first",
        ));
    }
    app.store
        .save_notification_destination(&identity.tenant, &mut destination)
        .map_err(|error| match error.as_str() {
            "Connection changed; reload before saving" => {
                ApiError::new(StatusCode::CONFLICT, error)
            }
            "A tenant can have at most 100 notification destinations" => invalid(error),
            _ => store_unavailable(error),
        })?;
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "notification_destination_changed",
        &destination.id,
        &json!({"channel":destination.channel,"enabled":destination.enabled}),
    );
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(destination.public()),
    )
        .into_response())
}

pub async fn test(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let destination = crate::notify::destination(&app, &identity.tenant, &id)
        .map_err(store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if !destination.enabled {
        return Err(invalid("Enable this destination before testing"));
    }
    let result = crate::notify::test_destination(&app, &identity.tenant, &destination).await;
    // Origin only: webhook and ntfy URLs commonly carry their token in the
    // query string or path, which must not reach the audit log.
    let mut detail = json!({
        "channel": destination.channel,
        "outcome": if result.is_ok() { "success" } else { "failure" },
    });
    if !destination.url.is_empty() {
        detail["url"] = json!(crate::api::audit_url(&destination.url));
    }
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "notification_tested",
        &destination.id,
        &detail,
    );
    // Audit finding 337: a failed test is a probe outcome, not a server
    // error, so it answers 200 with the delivery reason inside the normal
    // envelope instead of a status code outside it.
    Ok((
        StatusCode::OK,
        Json(match result {
            Ok(()) => json!({"delivered": true}),
            Err(reason) => json!({"delivered": false, "reason": reason}),
        }),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::testing;
    use crate::auth::{AdminIdentity, TenantGrant};
    use crate::store::{Tenant, TenantRemoval};
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn headers(app: &App, tenant: &str, role: &str) -> HeaderMap {
        let identity = AdminIdentity {
            subject: "local".into(),
            tenant: tenant.into(),
            role: role.into(),
            grants: vec![TenantGrant {
                incarnation: None,
                tenant: tenant.into(),
                role: role.into(),
            }],
            credential_version: 1,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            admin::test_admin_cookie(app, &identity).parse().unwrap(),
        );
        headers.insert("x-votport", "1".parse().unwrap());
        headers
    }
    fn tenant(key: &str) -> Tenant {
        Tenant {
            incarnation: String::new(),
            key: key.into(),
            label: key.into(),
            admin_group: None,
            max_total_bytes: None,
            max_links: None,
            max_sessions: None,
            created_at: 1,
        }
    }
    async fn body(response: Response) -> serde_json::Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    /// Calls the destination delete handler directly with an optional
    /// If-Match revision and an optional JSON body.
    async fn delete_destination(
        app: &Arc<App>,
        id: &str,
        auth: &HeaderMap,
        if_match: Option<u64>,
        body_json: Option<serde_json::Value>,
    ) -> Result<Response, ApiError> {
        let mut headers = auth.clone();
        if let Some(revision) = if_match {
            headers.insert(header::IF_MATCH, revision.to_string().parse().unwrap());
        }
        let request = Request::builder()
            .body(match body_json {
                Some(value) => Body::from(value.to_string()),
                None => Body::empty(),
            })
            .unwrap();
        delete(State(app.clone()), Path(id.to_owned()), headers, request).await
    }
    fn connection(label: &str) -> serde_json::Value {
        json!({"label":label,"channel":"slack","target":"Production / #incoming","enabled":true,"url":"https://hooks.example.test/private-secret"})
    }
    fn policy(id: &str, event: &str) -> NotificationPolicy {
        serde_json::from_value(
            json!({"mode":"custom","rules":[{"destination_id":id,"events":[event]}]}),
        )
        .unwrap()
    }

    async fn smtp_test_response(steps: &[(&str, &str)], starttls: bool) -> serde_json::Value {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut config = testing::config(directory.path());
        config.smtp_host = Some("127.0.0.1".into());
        config.smtp_port = address.port();
        config.smtp_starttls = starttls;
        config.smtp_username = Some("smtp-user-secret".into());
        config.smtp_password = Some("smtp-password-secret".into());
        config.smtp_from = Some("sender-secret@example.test".into());
        let app = crate::app::build(config).unwrap();
        app.store.insert_tenant(tenant("studio")).unwrap();
        let saved = body(
            save(
                State(app.clone()),
                headers(&app, "studio", "admin"),
                Json(json!({
                    "label":"Email", "channel":"email", "target":"Ops", "enabled":true,
                    "recipients":["recipient-secret@example.test"]
                })),
            )
            .await
            .unwrap(),
        )
        .await;
        let id = saved["id"].as_str().unwrap();
        let (response, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                test(
                    State(app.clone()),
                    Path(id.into()),
                    headers(&app, "studio", "admin")
                ),
                async {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = tokio::io::BufReader::new(socket);
                    for (command, reply) in steps {
                        if !command.is_empty() {
                            let mut line = String::new();
                            socket.read_line(&mut line).await.unwrap();
                            assert!(line.starts_with(command), "expected {command}");
                        }
                        socket.get_mut().write_all(reply.as_bytes()).await.unwrap();
                    }
                }
            )
        })
        .await
        .expect("SMTP Test fixture timed out");
        let response = response.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = body(response).await;
        assert_eq!(response["delivered"], false);
        assert_eq!(
            app.store.notification_outcomes("studio").unwrap()[id]["delivered"],
            false
        );
        assert!(app
            .store
            .notification_outcomes("")
            .unwrap()
            .as_object()
            .unwrap()
            .is_empty());
        let text = response.to_string();
        for secret in [
            "127.0.0.1",
            "relay-secret",
            "smtp-user-secret",
            "smtp-password-secret",
            "sender-secret",
            "recipient-secret",
        ] {
            assert!(!text.contains(secret), "response exposed {secret}");
        }
        response
    }

    #[tokio::test]
    async fn smtp_test_reports_refusal_without_relay_details() {
        let response = smtp_test_response(
            &[
                ("", "220 relay-secret ready\r\n"),
                ("EHLO", "250-relay-secret\r\n250 AUTH PLAIN\r\n"),
                (
                    "AUTH",
                    "535 relay-secret rejected smtp-user-secret smtp-password-secret\r\n",
                ),
            ],
            false,
        )
        .await;
        assert_eq!(response["reason"], "SMTP relay rejected the request. Check the recipients and ask the platform administrator to check relay policy and credentials.");
    }

    #[tokio::test]
    async fn smtp_test_reports_incompatible_settings_without_relay_details() {
        let response = smtp_test_response(
            &[
                ("", "220 relay-secret ready\r\n"),
                ("EHLO", "250 relay-secret\r\n"),
            ],
            true,
        )
        .await;
        assert_eq!(response["reason"], "SMTP settings are incompatible with the relay. Ask the platform administrator to check TLS and authentication settings.");
    }

    #[tokio::test]
    async fn smtp_test_distinguishes_transient_invalid_and_tls_responses() {
        for (steps, starttls, expected) in [
            (vec![("", "421 relay-secret temporarily unavailable\r\n")], false,
             "SMTP relay temporarily refused the request. Try again later."),
            (vec![("", "malformed relay-secret response\r\n")], false,
             "SMTP relay returned an invalid response. Ask the platform administrator to check relay configuration."),
            (vec![("", "220 relay-secret ready\r\n"),
                  ("EHLO", "250-relay-secret\r\n250 STARTTLS\r\n"),
                  ("STARTTLS", "220 begin TLS\r\n")], true,
             "SMTP connection failed. Ask the platform administrator to check the host, port and TLS settings."),
        ] {
            assert_eq!(smtp_test_response(&steps, starttls).await["reason"], expected);
        }
    }

    #[tokio::test]
    async fn webhook_test_reports_unreachable_destination_with_reason_and_no_error_envelope() {
        // Audit finding 337: an unreachable endpoint is a probe outcome, not
        // a 502 outside the envelope.
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store.insert_tenant(tenant("studio")).unwrap();
        // A closed port: the listener is dropped before the request fires.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = closed.local_addr().unwrap();
        drop(closed);
        let mut destination = crate::store::NotificationDestination {
            id: "fixture".into(),
            revision: 0,
            label: "Webhook".into(),
            channel: "webhook".into(),
            target: "Loopback test".into(),
            enabled: true,
            url: format!("http://{address}/hook"),
            token: String::new(),
            user: String::new(),
            recipients: vec![],
            thread_id: String::new(),
            last_reason: None,
        };
        app.store
            .save_notification_destination("studio", &mut destination)
            .unwrap();
        let response = test(
            State(app.clone()),
            Path(destination.id.clone()),
            headers(&app, "studio", "admin"),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body(response).await;
        assert_eq!(body["delivered"], false);
        assert!(
            body["reason"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()),
            "{}",
            body
        );
        let text = body.to_string();
        assert!(!text.contains("error") && !text.contains(&address.to_string()));
        assert_eq!(
            app.store.notification_outcomes("studio").unwrap()[&destination.id]["delivered"],
            false
        );
    }

    #[tokio::test]
    async fn destinations_preserve_secrets_scope_writes_and_remove_tenant_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let app = testing::build(directory.path());
        app.store.insert_tenant(tenant("a")).unwrap();
        app.store.insert_tenant(tenant("b")).unwrap();
        let saved = body(
            save(
                State(app.clone()),
                headers(&app, "a", "admin"),
                Json(connection("Incoming")),
            )
            .await
            .unwrap(),
        )
        .await;
        assert!(!saved.to_string().contains("private-secret"));
        assert_eq!(saved["url_set"], true);
        let id = saved["id"].as_str().unwrap();
        let catalog = body(
            list(State(app.clone()), headers(&app, "b", "admin"))
                .await
                .unwrap(),
        )
        .await;
        assert!(catalog["destinations"].as_array().unwrap().is_empty());
        assert_eq!(catalog["events"], json!(NOTIFICATION_EVENTS));
        assert!(
            validate_policy(&app, "b", &policy(id, "upload_complete"), &UPLOAD_EVENTS).is_err()
        );
        assert!(
            validate_policy(&app, "a", &policy(id, "workflow_failed"), &UPLOAD_EVENTS).is_err()
        );
        let mut update = connection("Renamed");
        update["id"] = json!(id);
        update["revision"] = saved["revision"].clone();
        update["url"] = json!("");
        save(
            State(app.clone()),
            headers(&app, "a", "admin"),
            Json(update.clone()),
        )
        .await
        .unwrap();
        assert_eq!(
            app.store
                .notification_destination("a", id)
                .unwrap()
                .unwrap()
                .url,
            "https://hooks.example.test/private-secret"
        );
        assert!(save(
            State(app.clone()),
            headers(&app, "a", "admin"),
            Json(update.clone())
        )
        .await
        .is_err());
        assert!(save(
            State(app.clone()),
            headers(&app, "b", "admin"),
            Json(update)
        )
        .await
        .is_err());
        assert!(save(
            State(app.clone()),
            headers(&app, "a", "viewer"),
            Json(connection("Forbidden"))
        )
        .await
        .is_err());
        let mut missing = headers(&app, "a", "admin");
        missing.remove("x-votport");
        assert!(save(State(app.clone()), missing, Json(connection("CSRF")))
            .await
            .is_err());
        let rules = policy(id, "upload_complete");
        defaults(
            State(app.clone()),
            headers(&app, "a", "admin"),
            Json(rules.clone()),
        )
        .await
        .unwrap();
        assert_eq!(
            app.store.remove_tenant("a").unwrap(),
            TenantRemoval::Deleted
        );
        assert!(app.store.save_notification_defaults("a", &rules).is_err());
        app.store.insert_tenant(tenant("a")).unwrap();
        assert!(app.store.notification_destinations("a").unwrap().is_empty());
        assert!(!app.store.notification_defaults("a").unwrap().enabled());
    }

    #[tokio::test]
    async fn request_and_delivery_policies_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let app = testing::build(directory.path());
        let saved = body(
            save(
                State(app.clone()),
                headers(&app, "", "admin"),
                Json(connection("Incoming")),
            )
            .await
            .unwrap(),
        )
        .await;
        let upload_policy = policy(saved["id"].as_str().unwrap(), "upload_complete");
        let router = crate::app::router(app.clone());
        let request = |method: &str, uri: &str, value: serde_json::Value| {
            let mut request = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from(value.to_string()))
                .unwrap();
            *request.headers_mut() = headers(&app, "", "admin");
            request
                .headers_mut()
                .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
            request
        };
        let response = router
            .clone()
            .oneshot(request(
                "POST",
                "/api/admin/links",
                json!({"label":"Notification request","notifications":upload_policy}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let link = body(response).await["link"].clone();
        assert_eq!(link["notifications"], json!(upload_policy));
        assert!(link.get("notify_on_upload").is_none());
        let id = link["id"].as_str().unwrap();
        assert_eq!(
            app.store.upload_link(id).unwrap().unwrap().notifications,
            Some(upload_policy.clone())
        );
        let url = format!("/api/admin/links/{id}");
        assert_eq!(
            router
                .clone()
                .oneshot(request(
                    "PATCH",
                    &url,
                    json!({"notifications":{"mode":"off"}})
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            router
                .clone()
                .oneshot(request(
                    "PATCH",
                    &url,
                    json!({"notifications":upload_policy})
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(app
            .store
            .link("", id)
            .unwrap()
            .unwrap()
            .notifications
            .unwrap()
            .enabled());
        let mut grant = crate::notify::tests::test_grant(vec![]);
        grant.tenant = String::new();
        grant.notifications = Some(NotificationPolicy::default());
        app.store.insert_outbound_grant(grant).unwrap();
        assert!(app
            .store
            .set_outbound_notifications("", "grant-id", &upload_policy)
            .unwrap());
        let grant = app.store.outbound_grants("").unwrap().pop().unwrap();
        assert!(grant.notifications.unwrap().enabled());
        let selected = policy(saved["id"].as_str().unwrap(), "outbound_delivery_complete");
        app.store
            .set_outbound_notifications("", "grant-id", &selected)
            .unwrap();
        assert_eq!(
            app.store.outbound_grants_page("", 10, 0, 1).unwrap().0[0]
                .0
                .notifications,
            Some(selected)
        );
    }

    #[test]
    fn routing_only_project_edits_keep_delivery_policy_revision_and_reject_stale_edits() {
        let directory = tempfile::tempdir().unwrap();
        let app = testing::build(directory.path());
        let mut project = app
            .store
            .save_delivery_project("", "local", crate::workflow::tests::project())
            .unwrap();
        let original = project.clone();
        project.notifications = Some(NotificationPolicy::default());
        let saved = app
            .store
            .save_delivery_project("", "local", project.clone())
            .unwrap();
        assert_eq!(saved.revision, original.revision);
        assert_eq!(saved.notification_revision, 1);
        assert!(saved.same_delivery_policy(&original));
        assert!(app
            .store
            .save_delivery_project("", "local", project)
            .is_err());
    }

    #[tokio::test]
    async fn workflow_retry_recovers_after_destination_deletion_and_overrides_keep_the_request() {
        let directory = tempfile::tempdir().unwrap();
        let app = testing::build(directory.path());
        let saved = body(
            save(
                State(app.clone()),
                headers(&app, "", "admin"),
                Json(connection("Workflow")),
            )
            .await
            .unwrap(),
        )
        .await;
        app.store
            .save_delivery_project("", "local", crate::workflow::tests::project())
            .unwrap();
        let mut request = crate::workflow::tests::request();
        request.notifications = Some(policy(saved["id"].as_str().unwrap(), "workflow_failed"));
        let peer = || axum::extract::ConnectInfo("127.0.0.1:1234".parse().unwrap());
        let created = body(
            crate::api::outbound::workflows::create(
                State(app.clone()),
                peer(),
                headers(&app, "", "admin"),
                Json(request.clone()),
            )
            .await
            .unwrap(),
        )
        .await;
        let id = created["job"]["id"].as_str().unwrap();
        let off = NotificationPolicy::default();
        assert!(app.store.set_job_notifications("", id, Some(&off)).unwrap());
        assert_eq!(
            app.store.notification_job_override("", id).unwrap(),
            Some(off)
        );
        assert!(app
            .store
            .notification_job_override("other", id)
            .unwrap()
            .is_none());
        assert_eq!(
            app.store.delivery_job(id).unwrap().unwrap().request,
            request
        );
        let mut grant = crate::notify::tests::test_grant(vec![]);
        grant.id = id.into();
        grant.tenant = String::new();
        grant.link_id.clear();
        app.store.insert_outbound_grant(grant).unwrap();
        let grant = app.store.outbound_grants("").unwrap().pop().unwrap();
        assert_eq!(grant.notifications, Some(NotificationPolicy::default()));
        assert!(app.store.set_job_notifications("", id, None).unwrap());
        let grant = app.store.outbound_grants("").unwrap().pop().unwrap();
        assert_eq!(grant.notifications, request.notifications);
        assert!(app
            .store
            .notification_job_override("", id)
            .unwrap()
            .is_none());
        delete_destination(
            &app,
            saved["id"].as_str().unwrap(),
            &headers(&app, "", "admin"),
            Some(saved["revision"].as_u64().unwrap()),
            None,
        )
        .await
        .unwrap();
        let recovered = body(
            crate::api::outbound::workflows::create(
                State(app.clone()),
                peer(),
                headers(&app, "", "admin"),
                Json(request.clone()),
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(recovered["job"]["id"], created["job"]["id"]);
        request.operation_id = "new-operation".into();
        assert!(crate::api::outbound::workflows::create(
            State(app.clone()),
            peer(),
            headers(&app, "", "admin"),
            Json(request)
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn destination_delete_takes_the_revision_from_if_match() {
        async fn saved(app: &Arc<App>, label: &str) -> serde_json::Value {
            let response = save(
                State(app.clone()),
                headers(app, "", "admin"),
                Json(connection(label)),
            )
            .await
            .unwrap();
            body(response).await
        }
        let directory = tempfile::tempdir().unwrap();
        let app = testing::build(directory.path());
        let revision_of = |saved: &serde_json::Value| saved["revision"].as_u64().unwrap();
        let id_of = |saved: &serde_json::Value| saved["id"].as_str().unwrap().to_owned();

        // A delete with neither If-Match nor a revision body is refused.
        let neither = saved(&app, "Neither").await;
        let error = delete_destination(
            &app,
            &id_of(&neither),
            &headers(&app, "", "admin"),
            None,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::PRECONDITION_REQUIRED);

        // A revision body alone still works through the compatibility window.
        let compat = saved(&app, "Compat").await;
        delete_destination(
            &app,
            &id_of(&compat),
            &headers(&app, "", "admin"),
            None,
            Some(json!({"revision": revision_of(&compat)})),
        )
        .await
        .unwrap();

        // A stale revision is a conflict whatever channel carries it.
        let stale = saved(&app, "Stale").await;
        let error = delete_destination(
            &app,
            &id_of(&stale),
            &headers(&app, "", "admin"),
            Some(revision_of(&stale) + 1),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);

        // Header and body must agree when both are present.
        let disagree = saved(&app, "Disagree").await;
        let error = delete_destination(
            &app,
            &id_of(&disagree),
            &headers(&app, "", "admin"),
            Some(revision_of(&disagree)),
            Some(json!({"revision": revision_of(&disagree) + 1})),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::PRECONDITION_FAILED);

        // An unparseable If-Match is a bad request, not a silent match.
        let garbage = saved(&app, "Garbage").await;
        let mut auth = headers(&app, "", "admin");
        auth.insert(header::IF_MATCH, "weak".parse().unwrap());
        let error = delete_destination(&app, &id_of(&garbage), &auth, None, None)
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);

        // The header-only delete succeeds and a repeat finds the row gone.
        let header_only = saved(&app, "Header").await;
        delete_destination(
            &app,
            &id_of(&header_only),
            &headers(&app, "", "admin"),
            Some(revision_of(&header_only)),
            None,
        )
        .await
        .unwrap();
        let error = delete_destination(
            &app,
            &id_of(&header_only),
            &headers(&app, "", "admin"),
            Some(revision_of(&header_only)),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
    }

    #[test]
    fn destination_fields_and_event_rules_reject_invalid_input() {
        let good: NotificationDestination = serde_json::from_value(connection("Good")).unwrap();
        validate_destination(&good).unwrap();
        for url in [
            "file:///etc/passwd",
            "https://user:secret@example.com/",
            "https://example.com/#secret",
            "https://example.com/\n",
        ] {
            let mut bad = good.clone();
            bad.url = url.into();
            assert!(validate_destination(&bad).is_err(), "{url}");
        }
        let mut bad = good.clone();
        bad.thread_id = "1".into();
        assert!(validate_destination(&bad).is_err());
        for value in [
            json!({"mode":"custom","rules":[]}),
            json!({"mode":"off","rules":[{"destination_id":"x","events":["upload_complete"]}]}),
            json!({"mode":"custom","rules":[{"destination_id":"x","events":["unknown"]}]}),
        ] {
            let policy: NotificationPolicy = serde_json::from_value(value).unwrap();
            assert!(policy.validate(&NOTIFICATION_EVENTS).is_err());
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteDestination {
    revision: u64,
}

/// The revision belongs in `If-Match`; a `{"revision": N}` JSON body is still
/// accepted for one release window. When both are present they must agree
/// (otherwise 412), and a delete with neither is refused with 428.
const DELETE_BODY_LIMIT: usize = 64 * 1024;

/// Reads the delete revision from `If-Match` (an unquoted or quoted revision;
/// an unparseable value is a bad request).
fn if_match_revision(headers: &HeaderMap) -> ApiResult<Option<u64>> {
    let Some(value) = headers.get(header::IF_MATCH) else {
        return Ok(None);
    };
    let text = value
        .to_str()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "If-Match is not a revision"))?
        .trim();
    let text = text.strip_prefix("W/").unwrap_or(text).trim();
    let text = text
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(text);
    text.parse::<u64>().map(Some).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "If-Match must carry the destination revision",
        )
    })
}

pub async fn delete(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    let header_revision = if_match_revision(&headers)?;
    let bytes = axum::body::to_bytes(request.into_body(), DELETE_BODY_LIMIT)
        .await
        .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "delete body is too large"))?;
    let body_revision = if bytes.is_empty() {
        None
    } else {
        Some(
            serde_json::from_slice::<DeleteDestination>(&bytes)
                .map_err(|error| invalid(error.to_string()))?
                .revision,
        )
    };
    let revision = match (header_revision, body_revision) {
        (Some(header), Some(body)) if header != body => {
            return Err(ApiError::new(
                StatusCode::PRECONDITION_FAILED,
                "If-Match does not match the body revision; reload before deleting",
            ));
        }
        (Some(header), _) => header,
        (None, Some(body)) => body,
        (None, None) => {
            return Err(ApiError::new(
                StatusCode::PRECONDITION_REQUIRED,
                "supply the destination revision in If-Match",
            ));
        }
    };
    if !app.store.with(|connection| connection.execute("DELETE FROM notification_destinations WHERE tenant=?1 AND id=?2 AND json_extract(document,'$.revision')=?3", rusqlite::params![identity.tenant,id,i64::try_from(revision).unwrap_or(-1)]).map(|count| count == 1)).map_err(store_unavailable)? {
        return Err(ApiError::new(StatusCode::CONFLICT,"Destination changed or was removed; reload before deleting"));
    }
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "notification_destination_deleted",
        &id,
        &json!({}),
    );
    Ok(Json(json!({"ok":true})).into_response())
}
