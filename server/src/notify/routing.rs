use super::*;
use crate::store::{NotificationDestination, NotificationMode, NotificationPolicy};
use futures_util::{stream, StreamExt};
use reqwest::header::{HeaderMap, RETRY_AFTER};
use std::time::{Duration, SystemTime};

const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(1);
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3);

pub(super) struct Route<'a> {
    pub tenant: &'a str,
    pub policy: Option<&'a NotificationPolicy>,
}

pub fn destination(
    app: &App,
    tenant: &str,
    id: &str,
) -> Result<Option<NotificationDestination>, String> {
    app.store.notification_destination(tenant, id)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn send_policy(
    app: &App,
    route: Route<'_>,
    title: String,
    mut body: String,
    mut payload: serde_json::Value,
    event: &str,
    transfer_id: Option<&str>,
    url: Option<&str>,
) {
    let resolved = (|| -> Result<Vec<NotificationDestination>, String> {
        let Some(policy) = route.policy else {
            return Ok(vec![]);
        };
        let defaults;
        let policy = if policy.mode == NotificationMode::Default {
            defaults = app.store.notification_defaults(route.tenant)?;
            &defaults
        } else {
            policy
        };
        if policy.mode != NotificationMode::Custom {
            return Ok(vec![]);
        }
        let mut selected = Vec::new();
        for rule in &policy.rules {
            if !rule.events.iter().any(|e| e == event) {
                continue;
            }
            match destination(app, route.tenant, &rule.destination_id)? {
                // A destination the operator disabled on purpose is quiet
                // by choice; one that was deleted is a rule left behind by
                // the delete, so say so instead of skipping in silence.
                Some(destination) if destination.enabled => selected.push(destination),
                Some(_) => {}
                None => tracing::warn!(
                    event,
                    destination = %rule.destination_id,
                    "notification rule names a deleted destination; its events send nothing"
                ),
            }
        }
        Ok(selected)
    })();
    let destinations = match resolved {
        Ok(destinations) => destinations,
        Err(_) => {
            tracing::error!(event, "Cannot resolve notification destinations");
            return;
        }
    };
    if let Some(id) = transfer_id {
        body.insert_str(0, &format!("ID: {id}\n"));
    }
    if let Some(url) = url {
        // The deep link leads the summary so clipping keeps it, and the
        // structured payload carries it for automations.
        body.insert_str(0, &format!("{url}\n"));
        payload["url"] = serde_json::Value::String(url.to_owned());
    }
    stream::iter(destinations.iter())
        .for_each_concurrent(8, |destination| async {
            let delivered = send_destination(
                app,
                route.tenant,
                destination,
                &title,
                &body,
                &payload,
                event,
                transfer_id,
            )
            .await;
            if let Err(error) = app.store.record_notification_outcome(
                route.tenant,
                destination,
                delivered.is_ok(),
                delivered.err(),
            ) {
                tracing::warn!(%error, "Cannot record notification outcome");
            }
        })
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn send_destination(
    app: &App,
    tenant: &str,
    destination: &NotificationDestination,
    title: &str,
    body: &str,
    payload: &serde_json::Value,
    event: &str,
    transfer_id: Option<&str>,
) -> Result<(), &'static str> {
    let unavailable = |reason| {
        tracing::warn!(
            channel = destination.channel,
            event,
            transfer_id = transfer_id.unwrap_or("none"),
            outcome = "failed",
            reason,
            "notification unavailable"
        );
        reason
    };
    if destination.channel == "email" {
        let settings = app.store.resolved_settings(&app.config)
            .map_err(|_| unavailable("SMTP settings could not be read. Ask the platform administrator to check server settings."))?;
        let smtp = settings.smtp.ok_or_else(|| {
            unavailable(
                "SMTP is not configured. Ask the platform administrator to configure the relay.",
            )
        })?;
        return send_smtp(
            &smtp,
            &destination.recipients,
            title,
            body,
            event,
            transfer_id,
        )
        .await;
    }
    let client = if tenant.is_empty() {
        &app.http
    } else if crate::egress::refused_literal(&destination.url, &app.config.tenant_private_networks)
    {
        return Err(unavailable(INTERNAL_ADDRESS));
    } else {
        &app.tenant_http
    };
    let request =
        destination_request(client, destination, title, body, payload).ok_or_else(|| {
            unavailable("Invalid notification destination");
            DESTINATION_FAILURE
        })?;
    let result = request.send().await;
    if let Ok(response) = &result {
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let Some(delay) = retry_after_delay(response.headers(), SystemTime::now()) else {
                return log_failure(&destination.channel, event, transfer_id, result).await;
            };
            drop(result);
            tokio::time::sleep(delay).await;
            let Some(retry_request) =
                destination_request(client, destination, title, body, payload)
            else {
                unavailable("Invalid notification destination");
                return Err(DESTINATION_FAILURE);
            };
            return log_failure(
                &destination.channel,
                event,
                transfer_id,
                retry_request.send().await,
            )
            .await;
        }
    }
    log_failure(&destination.channel, event, transfer_id, result).await
}

fn retry_after_delay(headers: &HeaderMap, now: SystemTime) -> Option<Duration> {
    let Some(value) = headers.get(RETRY_AFTER) else {
        return Some(DEFAULT_RETRY_AFTER);
    };
    let Ok(value) = value.to_str() else {
        return Some(DEFAULT_RETRY_AFTER);
    };
    let value = value.trim();
    if value.starts_with('-') {
        return None;
    }
    if let Ok(seconds) = value.parse::<f64>() {
        if !seconds.is_finite() || seconds < 0.0 || seconds > MAX_RETRY_AFTER.as_secs_f64() {
            return None;
        }
        return Duration::try_from_secs_f64(seconds).ok();
    }
    let Ok(date) = httpdate::parse_http_date(value) else {
        return Some(DEFAULT_RETRY_AFTER);
    };
    let delay = date.duration_since(now).unwrap_or_default();
    (delay <= MAX_RETRY_AFTER).then_some(delay)
}

fn destination_request(
    client: &reqwest::Client,
    destination: &NotificationDestination,
    title: &str,
    body: &str,
    payload: &serde_json::Value,
) -> Option<reqwest::RequestBuilder> {
    let request = match destination.channel.as_str() {
        "webhook" => client.post(&destination.url).json(payload),
        "ntfy" => {
            let mut url = reqwest::Url::parse(&destination.url).ok()?;
            let pairs = url
                .query_pairs()
                .filter(|(key, _)| !matches!(key.as_ref(), "title" | "t" | "x-title"))
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>();
            url.query_pairs_mut()
                .clear()
                .extend_pairs(pairs)
                .append_pair("title", &clipped_bytes(title, 1024));
            client
                .post(url)
                .body(clipped_bytes(body, 4096).into_owned())
        }
        "pushover" => client
            .post("https://api.pushover.net/1/messages.json")
            .form(&[
                ("token", Cow::Borrowed(destination.token.as_str())),
                ("user", Cow::Borrowed(destination.user.as_str())),
                ("title", clipped_chars(title, 250)),
                ("message", clipped_chars(body, 1024)),
            ]),
        "slack" | "teams" | "google_chat" | "discord" => {
            let mut url = destination.url.clone();
            if destination.channel == "discord" {
                let Ok(mut parsed) = reqwest::Url::parse(&url) else {
                    return None;
                };
                let pairs = parsed
                    .query_pairs()
                    .filter(|(key, _)| {
                        key != "wait" && (key != "thread_id" || destination.thread_id.is_empty())
                    })
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect::<Vec<_>>();
                parsed
                    .query_pairs_mut()
                    .clear()
                    .extend_pairs(pairs)
                    .append_pair("wait", "true");
                if !destination.thread_id.is_empty() {
                    parsed
                        .query_pairs_mut()
                        .append_pair("thread_id", &destination.thread_id);
                }
                url = parsed.into();
            }
            client
                .post(url)
                .json(&chat_payload(&destination.channel, title, body))
        }
        _ => return None,
    };
    let request = if ["webhook", "ntfy"].contains(&destination.channel.as_str())
        && !destination.token.is_empty()
    {
        request.bearer_auth(&destination.token)
    } else {
        request
    };
    Some(request)
}

pub async fn test_destination(
    app: &App,
    tenant: &str,
    destination: &NotificationDestination,
) -> Result<(), &'static str> {
    let title = format!("{}: notification test", title_brand(app, tenant));
    let body = "This is a notification test.\nSample file: Résumé_撮影.mov";
    let delivered = send_destination(
        app,
        tenant,
        destination,
        &title,
        body,
        &json!({"event":"notification_test","message":body}),
        "notification_test",
        None,
    )
    .await;
    let _ = app.store.record_notification_outcome(
        tenant,
        destination,
        delivered.is_ok(),
        delivered.err(),
    );
    delivered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::testing;
    use crate::store::{NotificationRule, SettingWrite};
    use axum::{
        body::to_bytes, extract::Path, response::IntoResponse, routing::post, Json, Router,
    };
    use reqwest::header::HeaderValue;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn push_destination(channel: &str) -> NotificationDestination {
        NotificationDestination {
            id: "fixture".into(),
            revision: 0,
            label: "fixture".into(),
            channel: channel.into(),
            target: "fixture".into(),
            enabled: true,
            url: "http://127.0.0.1/topic?priority=high&title=old&t=old&x-title=old".into(),
            token: "fixture-token".into(),
            user: "fixture-user".into(),
            recipients: vec![],
            thread_id: String::new(),
            last_reason: None,
        }
    }

    #[tokio::test]
    async fn early_notification_failures_are_logged_once() {
        use tracing::instrument::WithSubscriber;
        for case in ["settings", "unset", "discord", "unknown"] {
            let directory = tempfile::tempdir().unwrap();
            let mut config = testing::config(directory.path());
            config.smtp_host = Some("relay-secret.example.test".into());
            config.smtp_from = Some("sender-secret@example.test".into());
            let app = crate::app::build(config).unwrap();
            let mut destination = push_destination(if case == "settings" || case == "unset" {
                "email"
            } else {
                case
            });
            destination.recipients = vec!["recipient-secret@example.test".into()];
            if case == "discord" {
                destination.url = "malformed-secret".into();
            }
            app.store
                .save_notification_destination("", &mut destination)
                .unwrap();
            if case == "settings" {
                app.store
                    .with(|connection| connection.execute("DROP TABLE settings", []))
                    .unwrap();
            } else if case == "unset" {
                app.store
                    .put_settings(
                        "fixture",
                        &[("smtp_host".into(), SettingWrite::Set(String::new()))],
                    )
                    .unwrap();
            }
            let log = tempfile::NamedTempFile::new().unwrap();
            let writer = log.reopen().unwrap();
            let subscriber = tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_ansi(false)
                .with_writer(move || writer.try_clone().unwrap())
                .finish();
            let result = send_destination(
                &app,
                "",
                &destination,
                "Fixture",
                "Body",
                &json!({}),
                "fixture_event",
                Some("fixture-transfer"),
            )
            .with_subscriber(subscriber)
            .await;
            assert!(result.is_err(), "{case}");
            let text = std::fs::read_to_string(log.path()).unwrap();
            let records = text
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(records.len(), 1, "{case}: {text}");
            assert_eq!(records[0]["level"], "WARN");
            let fields = &records[0]["fields"];
            assert_eq!(fields["channel"], destination.channel);
            assert_eq!(fields["event"], "fixture_event");
            assert_eq!(fields["transfer_id"], "fixture-transfer");
            assert_eq!(fields["outcome"], "failed");
        }
    }

    #[test]
    fn retry_after_delay_is_bounded_and_parses_provider_values() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let parse = |value: Option<&str>| {
            let mut headers = HeaderMap::new();
            if let Some(value) = value {
                headers.insert(RETRY_AFTER, HeaderValue::from_str(value).unwrap());
            }
            retry_after_delay(&headers, now)
        };
        assert_eq!(parse(None), Some(DEFAULT_RETRY_AFTER));
        assert_eq!(parse(Some("malformed")), Some(DEFAULT_RETRY_AFTER));
        assert_eq!(parse(Some("1.25")), Some(Duration::from_millis(1250)));
        assert_eq!(parse(Some("3")), Some(MAX_RETRY_AFTER));
        assert_eq!(
            parse(Some(&httpdate::fmt_http_date(now + Duration::from_secs(2)))),
            Some(Duration::from_secs(2))
        );
        assert_eq!(parse(Some("-1")), None);
        assert_eq!(parse(Some("NaN")), None);
        assert_eq!(parse(Some("inf")), None);
        assert_eq!(parse(Some("3.001")), None);
        assert_eq!(
            parse(Some(&httpdate::fmt_http_date(now - Duration::from_secs(1)))),
            Some(Duration::ZERO)
        );
    }

    #[tokio::test]
    async fn webhook_retries_one_429_and_records_the_final_outcome() {
        let directory = tempfile::tempdir().unwrap();
        let app = testing::build(directory.path());
        let attempts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn({
            let attempts = attempts.clone();
            let requests = requests.clone();
            async move {
                axum::serve(
                    listener,
                    Router::new().route(
                        "/",
                        post(move |request: axum::extract::Request| {
                            let attempts = attempts.clone();
                            let requests = requests.clone();
                            async move {
                                let (parts, body) = request.into_parts();
                                let body = to_bytes(body, 16 * 1024).await.unwrap();
                                requests.lock().unwrap().push((
                                    body.to_vec(),
                                    parts.headers.get("authorization").cloned(),
                                ));
                                let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                                let status = match attempt {
                                    1 | 3 => axum::http::StatusCode::TOO_MANY_REQUESTS,
                                    2 => axum::http::StatusCode::NO_CONTENT,
                                    4 => axum::http::StatusCode::TOO_MANY_REQUESTS,
                                    _ => axum::http::StatusCode::BAD_REQUEST,
                                };
                                let mut response = (status, "response").into_response();
                                if matches!(attempt, 1 | 3 | 4) {
                                    response.headers_mut().insert(
                                        axum::http::header::RETRY_AFTER,
                                        axum::http::HeaderValue::from_static("0"),
                                    );
                                }
                                response
                            }
                        }),
                    ),
                )
                .await
                .unwrap();
            }
        });
        let mut destination = push_destination("webhook");
        destination.url = format!("http://{address}/");
        let payload = json!({"message":"body"});
        assert!(send_destination(
            &app,
            "",
            &destination,
            "title",
            "body",
            &payload,
            "event",
            None,
        )
        .await
        .is_ok());
        let policy = NotificationPolicy {
            mode: NotificationMode::Custom,
            rules: vec![NotificationRule {
                destination_id: destination.id.clone(),
                events: vec!["event".into()],
            }],
        };
        app.store
            .save_notification_destination("", &mut destination)
            .unwrap();
        send_policy(
            &app,
            Route {
                tenant: "",
                policy: Some(&policy),
            },
            "title".into(),
            "body".into(),
            payload.clone(),
            "event",
            None,
            None,
        )
        .await;
        assert_eq!(
            app.store.notification_outcomes("").unwrap()["fixture"]["delivered"],
            false
        );
        assert!(send_destination(
            &app,
            "",
            &destination,
            "title",
            "body",
            &payload,
            "event",
            None,
        )
        .await
        .is_err());
        {
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 5);
            let expected_body = serde_json::to_vec(&payload).unwrap();
            for (body, authorization) in requests.iter() {
                assert_eq!(body, &expected_body);
                assert_eq!(authorization.as_ref().unwrap(), "Bearer fixture-token");
            }
        }
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn provider_payload_ntfy_bounds_utf8_bytes() {
        let client = reqwest::Client::new();
        let destination = push_destination("ntfy");
        let title = "界".repeat(342);
        let body = "🎬".repeat(1025);
        let request = destination_request(&client, &destination, &title, &body, &json!({}))
            .unwrap()
            .build()
            .unwrap();
        assert!(request.body().unwrap().as_bytes().unwrap().len() <= 4096);
        let titles = request
            .url()
            .query_pairs()
            .filter(|(k, _)| k == "title")
            .collect::<Vec<_>>();
        assert_eq!(titles.len(), 1);
        assert!(titles[0].1.len() <= 1024);
        assert_eq!(request.headers()["authorization"], "Bearer fixture-token");
        let title = format!("{}a", "界".repeat(341));
        let body = "🎬".repeat(1024);
        let request = destination_request(&client, &destination, &title, &body, &json!({}))
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(request.body().unwrap().as_bytes().unwrap(), body.as_bytes());
        assert!(request
            .url()
            .query_pairs()
            .any(|(key, value)| key == "title" && value == title));
    }

    #[test]
    fn provider_payload_pushover_bounds_characters() {
        let client = reqwest::Client::new();
        let destination = push_destination("pushover");
        let title = "界".repeat(251);
        let body = "🎬".repeat(1025);
        let request = destination_request(&client, &destination, &title, &body, &json!({}))
            .unwrap()
            .build()
            .unwrap();
        let form = reqwest::Url::parse(&format!(
            "http://localhost/?{}",
            std::str::from_utf8(request.body().unwrap().as_bytes().unwrap()).unwrap()
        ))
        .unwrap();
        let values = form
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert!(values["title"].chars().count() <= 250);
        assert!(values["message"].chars().count() <= 1024);
        assert_eq!(values["token"], "fixture-token");
        assert_eq!(values["user"], "fixture-user");
        let title = "🎬".repeat(250);
        let body = "🎬".repeat(1024);
        let request = destination_request(&client, &destination, &title, &body, &json!({}))
            .unwrap()
            .build()
            .unwrap();
        let form = reqwest::Url::parse(&format!(
            "http://localhost/?{}",
            std::str::from_utf8(request.body().unwrap().as_bytes().unwrap()).unwrap()
        ))
        .unwrap();
        let values = form
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(values["title"], title);
        assert_eq!(values["message"], body);
    }

    #[test]
    fn provider_payload_ntfy_encodes_title_controls() {
        let client = reqwest::Client::new();
        let destination = push_destination("ntfy");
        let title = "Müller\n撮影🎬";
        let request = destination_request(&client, &destination, title, "body", &json!({}))
            .unwrap()
            .build()
            .unwrap();
        let params = request
            .url()
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(params["title"], title);
        assert_eq!(params["priority"], "high");
        assert!(!params.contains_key("t") && !params.contains_key("x-title"));
        assert!(!request.headers().contains_key("title"));
    }

    #[tokio::test]
    async fn selected_destinations_receive_only_their_events_and_defaults_do_not_broadcast() {
        let directory = tempfile::tempdir().unwrap();
        let app = testing::build(directory.path());
        let messages = Arc::new(std::sync::Mutex::new(
            Vec::<(String, serde_json::Value)>::new(),
        ));
        let received = messages.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/{destination}",
                    post(
                        move |Path(destination): Path<String>,
                              Json(payload): Json<serde_json::Value>| {
                            let received = received.clone();
                            async move {
                                received.lock().unwrap().push((destination, payload));
                                "ok"
                            }
                        },
                    ),
                ),
            )
            .await
            .unwrap();
        });
        let make = |id: &str| NotificationDestination {
            id: id.into(),
            revision: 0,
            label: id.into(),
            channel: "webhook".into(),
            target: id.into(),
            enabled: true,
            url: format!("http://{address}/{id}"),
            token: String::new(),
            user: String::new(),
            recipients: vec![],
            thread_id: String::new(),
            last_reason: None,
        };
        let mut first = make("first");
        let mut second = make("second");
        let mut unselected = make("unselected");
        let mut email = make("unconfigured-email");
        email.channel = "email".into();
        email.url.clear();
        email.recipients = vec!["ops@example.test".into()];
        assert!(app
            .store
            .resolved_settings(&app.config)
            .unwrap()
            .smtp
            .is_none());
        for destination in [&mut first, &mut second, &mut unselected, &mut email] {
            app.store
                .save_notification_destination("", destination)
                .unwrap();
        }
        app.store
            .put_settings(
                "test",
                &[(
                    "notify_webhook".into(),
                    SettingWrite::Set(format!("http://{address}/legacy")),
                )],
            )
            .unwrap();
        let policy = NotificationPolicy {
            mode: NotificationMode::Custom,
            rules: vec![
                NotificationRule {
                    destination_id: email.id.clone(),
                    events: vec!["outbound_download_started".into()],
                },
                NotificationRule {
                    destination_id: first.id.clone(),
                    events: vec!["outbound_download_started".into()],
                },
                NotificationRule {
                    destination_id: second.id.clone(),
                    events: vec!["outbound_delivery_complete".into()],
                },
            ],
        };
        let mut grant = super::super::tests::test_grant(vec![]);
        grant.tenant = String::new();
        grant.notifications = Some(policy.clone());
        crate::notify::outbound_downloaded(
            app.clone(),
            grant.clone(),
            OutboundDownloadResult {
                first_download: true,
                completed_delivery: true,
                event_at: 0,
            },
        )
        .await;
        let observed = messages.lock().unwrap().clone();
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0].0, "first");
        assert_eq!(observed[0].1["event"], "outbound_download_started");
        assert_eq!(observed[1].0, "second");
        assert_eq!(observed[1].1["event"], "outbound_delivery_complete");
        assert_eq!(
            app.store.notification_outcomes("").unwrap()["first"]["delivered"],
            true
        );
        assert_eq!(
            app.store.notification_outcomes("").unwrap()[&email.id]["delivered"],
            false
        );
        messages.lock().unwrap().clear();
        grant.notifications = Some(NotificationPolicy {
            mode: NotificationMode::Default,
            rules: vec![],
        });
        crate::notify::outbound_downloaded(
            app.clone(),
            grant.clone(),
            OutboundDownloadResult {
                first_download: true,
                completed_delivery: true,
                event_at: 0,
            },
        )
        .await;
        assert!(messages.lock().unwrap().is_empty());
        app.store.save_notification_defaults("", &policy).unwrap();
        second.enabled = false;
        app.store
            .save_notification_destination("", &mut second)
            .unwrap();
        crate::notify::outbound_downloaded(
            app.clone(),
            grant.clone(),
            OutboundDownloadResult {
                first_download: true,
                completed_delivery: true,
                event_at: 0,
            },
        )
        .await;
        assert_eq!(messages.lock().unwrap().len(), 1);
        assert_eq!(messages.lock().unwrap()[0].0, "first");
        messages.lock().unwrap().clear();
        grant.tenant = "different-tenant".into();
        grant.notifications = Some(policy);
        crate::notify::outbound_downloaded(
            app.clone(),
            grant.clone(),
            OutboundDownloadResult {
                first_download: true,
                completed_delivery: true,
                event_at: 0,
            },
        )
        .await;
        assert!(messages.lock().unwrap().is_empty());
        grant.notifications = None;
        crate::notify::outbound_downloaded(
            app,
            grant,
            OutboundDownloadResult {
                first_download: true,
                completed_delivery: true,
                event_at: 0,
            },
        )
        .await;
        assert!(messages.lock().unwrap().is_empty());
        server.abort();
    }
}
