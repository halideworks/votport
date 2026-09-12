use super::*;
use crate::store::{NotificationDestination, NotificationMode, NotificationPolicy};
use futures_util::{stream, StreamExt};

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

pub(super) async fn send_policy(
    app: &App,
    route: Route<'_>,
    title: String,
    body: String,
    payload: serde_json::Value,
    event: &str,
    transfer_id: Option<&str>,
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
            if let Some(destination) =
                destination(app, route.tenant, &rule.destination_id)?.filter(|d| d.enabled)
            {
                selected.push(destination);
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
    stream::iter(destinations.iter())
        .for_each_concurrent(8, |destination| async {
            let delivered = send_destination(
                app,
                destination,
                &title,
                &body,
                &payload,
                event,
                transfer_id,
            )
            .await;
            if let Err(error) =
                app.store
                    .record_notification_outcome(route.tenant, destination, delivered)
            {
                tracing::warn!(%error, "Cannot record notification outcome");
            }
        })
        .await;
}

async fn send_destination(
    app: &App,
    destination: &NotificationDestination,
    title: &str,
    body: &str,
    payload: &serde_json::Value,
    event: &str,
    transfer_id: Option<&str>,
) -> bool {
    if destination.channel == "email" {
        let Ok(settings) = app.store.resolved_settings(&app.config) else {
            return false;
        };
        let Some(smtp) = settings.smtp else {
            return false;
        };
        return log_smtp_failure(
            event,
            transfer_id,
            send_smtp(&smtp, &destination.recipients, title, body).await,
        );
    }
    let request = match destination.channel.as_str() {
        "webhook" => app.http.post(&destination.url).json(payload),
        "ntfy" => app
            .http
            .post(&destination.url)
            .header("Title", title)
            .body(body.to_owned()),
        "pushover" => app
            .http
            .post("https://api.pushover.net/1/messages.json")
            .form(&[
                ("token", destination.token.as_str()),
                ("user", destination.user.as_str()),
                ("title", title),
                ("message", body),
            ]),
        "slack" | "teams" | "google_chat" | "discord" => {
            let mut url = destination.url.clone();
            if destination.channel == "discord" {
                let Ok(mut parsed) = reqwest::Url::parse(&url) else {
                    return false;
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
            app.http
                .post(url)
                .json(&chat_payload(&destination.channel, title, body))
        }
        _ => return false,
    };
    let request = if ["webhook", "ntfy"].contains(&destination.channel.as_str())
        && !destination.token.is_empty()
    {
        request.bearer_auth(&destination.token)
    } else {
        request
    };
    log_failure(
        &destination.channel,
        event,
        transfer_id,
        request.send().await,
    )
    .await
}

pub async fn test_destination(
    app: &App,
    tenant: &str,
    destination: &NotificationDestination,
) -> bool {
    let delivered = send_destination(
        app,
        destination,
        "VOTPort: notification test",
        "This is a VOTPort notification test.",
        &json!({"event":"notification_test","message":"This is a VOTPort notification test."}),
        "notification_test",
        None,
    )
    .await;
    let _ = app
        .store
        .record_notification_outcome(tenant, destination, delivered);
    delivered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::testing;
    use crate::store::{NotificationRule, SettingWrite};
    use axum::{extract::Path, routing::post, Json, Router};

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
        };
        let mut first = make("first");
        let mut second = make("second");
        let mut unselected = make("unselected");
        for destination in [&mut first, &mut second, &mut unselected] {
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
            },
        )
        .await;
        assert!(messages.lock().unwrap().is_empty());
        server.abort();
    }
}
