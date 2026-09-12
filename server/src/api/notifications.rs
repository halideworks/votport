use super::*;
use crate::store::{
    NotificationDestination, NotificationMode, NotificationPolicy, NOTIFICATION_EVENTS,
};
use axum::extract::{Path, State};
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
        "events":NOTIFICATION_EVENTS})),
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
    let delivered = crate::notify::test_destination(&app, &identity.tenant, &destination).await;
    Ok((if delivered { StatusCode::OK } else { StatusCode::BAD_GATEWAY },Json(json!({"delivered":delivered,"error":if delivered { None } else { Some("The destination did not accept the test. Check its connection settings and try again.") }}))).into_response())
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
    fn connection(label: &str) -> serde_json::Value {
        json!({"label":label,"channel":"slack","target":"Production / #incoming","enabled":true,"url":"https://hooks.example.test/private-secret"})
    }
    fn policy(id: &str, event: &str) -> NotificationPolicy {
        serde_json::from_value(
            json!({"mode":"custom","rules":[{"destination_id":id,"events":[event]}]}),
        )
        .unwrap()
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
        delete(
            State(app.clone()),
            Path(saved["id"].as_str().unwrap().into()),
            headers(&app, "", "admin"),
            Json(DeleteDestination {
                revision: saved["revision"].as_u64().unwrap(),
            }),
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

pub async fn delete(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<DeleteDestination>,
) -> ApiResult<Response> {
    let identity = admin::require_operator(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    if !app.store.with(|connection| connection.execute("DELETE FROM notification_destinations WHERE tenant=?1 AND id=?2 AND json_extract(document,'$.revision')=?3", rusqlite::params![identity.tenant,id,i64::try_from(request.revision).unwrap_or(-1)]).map(|count| count == 1)).map_err(store_unavailable)? {
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
