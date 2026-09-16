//! Transfer notifications: workplace chat, webhook, ntfy, Pushover, SMTP.
//!
//! Best-effort and fire-and-forget: a completed transfer is already recorded
//! and on disk, so a notification failure is logged and nothing else.

mod routing;
pub use routing::{destination, test_destination};
use routing::{send_policy, Route};

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{stream, StreamExt};
use lettre::message::{Mailbox, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::json;

use crate::app::App;
use crate::session::FinishReport;
use crate::store::{OutboundDownloadResult, OutboundGrant, ResolvedSmtp};

const MAX_NOTIFICATION_FILES: usize = 100;
const DESTINATION_FAILURE: &str =
    "The destination did not accept the test. Check its connection settings and try again.";

/// Product name for notification titles: the tenant's brand name when one is
/// set, else the tenant label, else "VOTPort".
/// The absolute deep link into an authenticated admin page for one
/// event, or None without a configured public URL. Notification
/// destinations only ever receive admin detail views: never a bearer
/// receive or download route.
fn admin_link(app: &App, path: &str) -> Option<String> {
    Some(format!(
        "{}{path}",
        app.config.public_url.as_deref()?.trim_end_matches('/')
    ))
}

/// The receive page path that selects one link and opens its card.
fn receive_link(link_id: &str) -> String {
    let id = crate::api::scim::encode_segment(link_id);
    format!("/receive?search={id}#link-{id}")
}

fn title_brand(app: &App, tenant: &str) -> String {
    app.store
        .branding(tenant)
        .ok()
        .flatten()
        .map(|branding| branding.name)
        .filter(|name| !name.is_empty())
        .or_else(|| {
            app.store
                .tenant(tenant)
                .ok()
                .flatten()
                .map(|tenant| tenant.label)
                .filter(|label| !label.is_empty())
        })
        .unwrap_or_else(|| "VOTPort".to_owned())
}

pub async fn trade_uploaded(app: &App, tenant: &str, upload: &str) {
    if let Ok(Some(incoming)) = app.store.received_route(tenant, upload) {
        if let Some(permission) = &incoming.source.document.permission {
            if let (Ok(Some(route)), Ok(Some(policy))) = (
                app.store.trade_route(tenant, &permission.grant),
                app.store.trade_delivery_policy(&incoming.id),
            ) {
                let detail = incoming
                    .receipt
                    .as_ref()
                    .map(|receipt| format!("receipt:{}", receipt.digest()))
                    .unwrap_or_else(|| format!("upload:{upload}"));
                trade_event(app, &route, &policy, "route_received", Some(&detail)).await;
            }
        }
    }
}

/// Sends every configured notification for one completed upload.
pub async fn uploaded(
    app: Arc<App>,
    tenant: String,
    link_id: String,
    label: String,
    completed_at: u64,
    report: FinishReport,
    notifications: Option<crate::store::NotificationPolicy>,
) {
    let transfer_id = report.upload_id.clone();
    let total: u64 = report.files.iter().map(|file| file.bytes).sum();
    let count = report.files.len();
    let files_truncated = count > MAX_NOTIFICATION_FILES;
    let files = report
        .files
        .iter()
        .take(MAX_NOTIFICATION_FILES)
        .collect::<Vec<_>>();
    let title = format!(
        "{}: files received for \"{label}\"",
        title_brand(&app, &tenant)
    );
    let mut body = format!(
        "{count} file(s), {total} bytes\n{}",
        files
            .iter()
            .map(|file| format!("{} ({} bytes)", file.stored_as, file.bytes))
            .collect::<Vec<_>>()
            .join("\n")
    );
    if files_truncated {
        body.push_str(&format!("\nand {} more", count - files.len()));
    }

    let url = admin_link(&app, &receive_link(&link_id));
    let payload = json!({
        "event": "upload_complete",
        "tenant": &tenant,
        "link_id": link_id,
        "label": label,
        "upload_id": report.upload_id,
        "completed_at": completed_at,
        "total_bytes": total,
        "file_count": count,
        "files_truncated": files_truncated,
        "files": files,
    });
    send_policy(
        &app,
        Route {
            tenant: &tenant,
            policy: notifications.as_ref(),
        },
        title,
        body,
        payload,
        "upload_complete",
        Some(&transfer_id),
        url.as_deref(),
    )
    .await;
}

/// Sends the transition notification for an outbound delivery.
pub async fn outbound_downloaded(
    app: Arc<App>,
    grant: OutboundGrant,
    result: OutboundDownloadResult,
) {
    let transitions = [
        (
            result.first_download,
            "outbound_download_started",
            "first file requested",
        ),
        (
            result.completed_delivery,
            "outbound_delivery_complete",
            "every file requested",
        ),
    ];
    let transfer_id = grant.id.clone();
    let (file_count, total_bytes, files, files_truncated) = if grant.files.is_empty() {
        (
            1,
            grant.bytes,
            vec![json!({ "name": &grant.name, "bytes": grant.bytes })],
            false,
        )
    } else {
        let total_bytes = grant
            .files
            .iter()
            .fold(0u64, |total, file| total.saturating_add(file.bytes));
        let file_count = grant.files.len();
        (
            file_count,
            total_bytes,
            grant
                .files
                .iter()
                .take(MAX_NOTIFICATION_FILES)
                .map(|file| json!({ "name": &file.name, "bytes": file.bytes }))
                .collect(),
            file_count > MAX_NOTIFICATION_FILES,
        )
    };
    let download_starts = grant.downloads.max(result.first_download as u64);
    let url = admin_link(
        &app,
        &format!(
            "/deliver#grant-{}",
            crate::api::scim::encode_segment(&grant.id)
        ),
    );
    for (_, event, transition) in transitions.into_iter().filter(|(send, _, _)| *send) {
        let title = format!(
            "{}: outbound {transition} for \"{}\"",
            title_brand(&app, &grant.tenant),
            grant.label
        );
        let body = format!(
            "{}\n{transition}: {file_count} file(s), {total_bytes} bytes",
            grant.label
        );
        let payload = json!({
            "event": event,
            "tenant": &grant.tenant,
            "grant_id": grant.id,
            "label": grant.label,
            "event_at": result.event_at,
            "download_starts": download_starts,
            "file_count": file_count,
            "files_truncated": files_truncated,
            "total_bytes": total_bytes,
            "files": files,
        });
        send_policy(
            &app,
            Route {
                tenant: &grant.tenant,
                policy: grant.notifications.as_ref(),
            },
            title,
            body,
            payload,
            event,
            Some(&transfer_id),
            url.as_deref(),
        )
        .await;
    }
}

/// Notifies that an upload session ended without publishing: rejected at
/// begin, or interrupted by a disconnect, expiry, or terminal error.
pub async fn upload_ended(app: Arc<App>, ended: crate::session::SessionEnded) {
    let event = &ended.event;
    let title = format!(
        "{}: upload {} for \"{}\"",
        title_brand(&app, &ended.tenant),
        event.outcome,
        ended.label
    );
    let body = format!(
        "{}\n{} of {} bytes received",
        event.detail, event.received_bytes, event.expected_bytes
    );
    let url = admin_link(&app, &receive_link(&ended.link_id));
    let payload = json!({
        "event": "upload_failed",
        "tenant": &ended.tenant,
        "label": ended.label,
        "link_id": ended.link_id,
        "outcome": event.outcome,
        "detail": event.detail,
        "received_bytes": event.received_bytes,
        "expected_bytes": event.expected_bytes,
        "started_at": event.started_at,
        "ended_at": event.at,
    });
    send_policy(
        &app,
        Route {
            tenant: &ended.tenant,
            policy: ended.notifications.as_ref(),
        },
        title,
        body,
        payload,
        "upload_failed",
        Some(&ended.link_id),
        url.as_deref(),
    )
    .await;
}

pub async fn workflow_failed(app: Arc<App>, job: crate::workflow::Job) {
    let override_policy = match app.store.notification_job_override(&job.tenant, &job.id) {
        Ok(policy) => policy,
        Err(_) => {
            tracing::error!("Cannot read workflow notification settings");
            return;
        }
    };
    let policy = override_policy
        .as_ref()
        .or(job.request.notifications.as_ref())
        .or(job.project.notifications.as_ref());
    let retrying = job.state == "retrying";
    let title = format!(
        "{}: delivery {} for \"{}\"",
        title_brand(&app, &job.tenant),
        if retrying {
            "retry scheduled"
        } else {
            "needs attention"
        },
        job.request.label
    );
    let body = format!(
        "{}\n{}",
        job.error
            .as_deref()
            .unwrap_or("A destination did not complete"),
        if job.released() {
            "The local download link remains released."
        } else {
            "The download link remains held."
        }
    );
    let event = if retrying {
        "workflow_retry_scheduled"
    } else {
        "workflow_failed"
    };
    let url = admin_link(
        &app,
        &format!(
            "/workflows#job-{}",
            crate::api::scim::encode_segment(&job.id)
        ),
    );
    let payload = json!({"event":event, "tenant":&job.tenant, "job_id":job.id, "label":job.request.label, "state":job.state, "error":job.error, "retry_at":job.checks["retry_at"], "released":job.released()});
    send_policy(
        &app,
        Route {
            tenant: &job.tenant,
            policy,
        },
        title,
        body,
        payload,
        event,
        Some(&job.id),
        url.as_deref(),
    )
    .await;
}

fn clipped_bytes(text: &str, limit: usize) -> Cow<'_, str> {
    if text.len() <= limit {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(format!("{}…", &text[..text.floor_char_boundary(limit - 3)]))
    }
}

fn clipped_chars(text: &str, limit: usize) -> Cow<'_, str> {
    let mut chars = text.char_indices();
    match chars.nth(limit - 1) {
        Some((last, _)) if chars.next().is_some() => Cow::Owned(format!("{}…", &text[..last])),
        _ => Cow::Borrowed(text),
    }
}

const DISCORD_CONTENT_LIMIT: usize = 2000;

fn escape_chat_markdown(text: &str, escape_ampersands: bool) -> String {
    text.chars().fold(
        String::with_capacity(text.len()),
        |mut escaped, character| {
            if (escape_ampersands && character == '&')
                || matches!(
                    character,
                    '\\' | '*'
                        | '_'
                        | '~'
                        | '`'
                        | '['
                        | ']'
                        | '('
                        | ')'
                        | '<'
                        | '>'
                        | '#'
                        | '+'
                        | '-'
                        | '.'
                        | '!'
                        | '|'
                )
            {
                escaped.push('\\');
            }
            escaped.push(character);
            escaped
        },
    )
}

fn clip_escaped(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let mut clipped = String::new();
    let mut length = 0;
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        let escaped_character = character == '\\' && characters.peek().is_some();
        let token_length = if escaped_character { 2 } else { 1 };
        if length + token_length + 1 > limit {
            break;
        }
        clipped.push(character);
        length += 1;
        if escaped_character {
            clipped.push(characters.next().expect("peeked escaped character"));
            length += 1;
        }
    }
    clipped.push('…');
    clipped
}

fn chat_payload(channel: &str, title: &str, body: &str) -> serde_json::Value {
    let title = clipped_chars(title, 150).into_owned();
    let body = clipped_chars(body, 1500).into_owned();
    // When a deep link is present it is the first body line. It passes
    // through as issued: markdown escaping would mangle it, and every
    // chat client linkifies a bare URL without any markup.
    let (link, rest) = match body.split_once('\n') {
        Some((first, rest)) if first.starts_with("http://") || first.starts_with("https://") => {
            (format!("{first}\n"), rest)
        }
        _ => (String::new(), body.as_str()),
    };
    match channel {
        "slack" => {
            let text = format!(
                "{}\n{}{}",
                escape_slack_entities(&title),
                link,
                escape_slack_entities(rest)
            );
            json!({
                "text": text,
                "mrkdwn": false, "unfurl_links": false, "unfurl_media": false,
                "blocks": [
                    {"type":"header", "text":{"type":"plain_text", "text":title}},
                    {"type":"section", "text":{"type":"plain_text", "text":format!("{link}{rest}")}}
                ]
            })
        }
        "teams" => {
            let markdown_title = escape_chat_markdown(&title, false);
            let markdown_body = format!("{link}{}", escape_chat_markdown(rest, false));
            json!({
                "type":"message", "text":format!("{markdown_title}\n{markdown_body}"),
                "attachments":[{"contentType":"application/vnd.microsoft.card.adaptive", "content":{
                    "$schema":"http://adaptivecards.io/schemas/adaptive-card.json", "type":"AdaptiveCard", "version":"1.2",
                    "body":[
                        {"type":"TextBlock", "text":markdown_title, "weight":"Bolder", "wrap":true},
                        {"type":"TextBlock", "text":markdown_body, "wrap":true}
                    ]
                }}]
            })
        }
        "google_chat" => {
            json!({
                "text": format!("{}\n{}{}", escape_chat_markdown(&title, true), link, escape_chat_markdown(rest, true)),
                "markupSyntax": "MARKUP_SYNTAX_MARKDOWN"
            })
        }
        "discord" => {
            let markdown_text = format!(
                "{}\n{}{}",
                escape_chat_markdown(&title, false),
                link,
                escape_chat_markdown(rest, false)
            );
            json!({
                "content": clip_escaped(&markdown_text, DISCORD_CONTENT_LIMIT),
                "allowed_mentions":{"parse":[]}, "flags":4
            })
        }
        _ => unreachable!("known chat channel"),
    }
}

fn escape_slack_entities(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn notification_connection_failure(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "The destination timed out. Try again or check the service status."
    } else {
        "The destination connection failed. Check its URL, network access and TLS settings."
    }
}

async fn log_failure(
    channel: &str,
    event: &str,
    transfer_id: Option<&str>,
    result: Result<reqwest::Response, reqwest::Error>,
) -> Result<(), &'static str> {
    match result {
        Ok(response) if !response.status().is_success() => {
            tracing::warn!(
                channel,
                event,
                transfer_id = transfer_id.unwrap_or("none"),
                status = %response.status(),
                outcome = "failed",
                "notification failed"
            );
            Err(DESTINATION_FAILURE)
        }
        Err(error) => {
            let reason = notification_connection_failure(&error);
            let error = error.without_url();
            tracing::warn!(
                channel,
                event,
                transfer_id = transfer_id.unwrap_or("none"),
                outcome = "failed",
                "notification failed: {error}"
            );
            Err(reason)
        }
        Ok(mut response) if channel == "teams" => {
            let mut body = Vec::new();
            let accepted = loop {
                match response.chunk().await {
                    Ok(Some(chunk)) if body.len() + chunk.len() <= 8192 => {
                        body.extend_from_slice(&chunk)
                    }
                    Ok(None) => {
                        break if String::from_utf8_lossy(&body)
                            .contains("Microsoft Teams endpoint returned HTTP error")
                        {
                            Err(DESTINATION_FAILURE)
                        } else {
                            Ok(())
                        };
                    }
                    Err(error) => break Err(notification_connection_failure(&error)),
                    _ => break Err(DESTINATION_FAILURE),
                }
            };
            if accepted.is_err() {
                tracing::warn!(
                    channel,
                    event,
                    outcome = "failed",
                    "notification response rejected or unreadable"
                );
            }
            accepted
        }
        Ok(_) => Ok(()),
    }
}

fn log_smtp_failure<T, E: std::fmt::Display>(
    event: &str,
    transfer_id: Option<&str>,
    result: Result<T, E>,
) -> Result<T, E> {
    if let Err(error) = &result {
        tracing::warn!(
            channel = "smtp",
            event,
            transfer_id = transfer_id.unwrap_or("none"),
            outcome = "failed",
            "notification failed: {error}"
        );
    }
    result
}

async fn send_smtp(
    smtp: &ResolvedSmtp,
    recipients: &[String],
    title: &str,
    body: &str,
    event: &str,
    transfer_id: Option<&str>,
) -> Result<(), &'static str> {
    let prepared = (|| -> Result<_, String> {
        let from: Mailbox = smtp
            .from
            .parse()
            .map_err(|error| format!("smtp from: {error}"))?;
        let subject = clipped_chars(title, 250).into_owned();
        let body = clipped_bytes(body, 64 * 1024).into_owned();
        let tls = smtp_tls(smtp)?;
        Ok((from, subject, body, tls))
    })();
    let (from, subject, body, tls) = log_smtp_failure(event, transfer_id, prepared)
        .map_err(|_| "SMTP settings could not be used. Ask the platform administrator to check the sender and TLS settings.")?;
    let event = event.to_owned();
    let transfer_id = transfer_id.map(str::to_owned);
    let mut transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host)
        .port(smtp.port)
        .tls(tls)
        .timeout(Some(Duration::from_secs(15)));
    if let Some(username) = &smtp.username {
        transport = transport.credentials(Credentials::new(
            username.clone(),
            smtp.password.clone().unwrap_or_default(),
        ));
    }
    let transport = transport.build();
    let recipients = recipients.to_owned();
    let results = stream::iter(recipients)
        .map(|recipient| {
            let from = from.clone();
            let subject = subject.clone();
            let body = body.clone();
            let transport = transport.clone();
            let event = event.clone();
            let transfer_id = transfer_id.clone();
            async move {
                let to = match recipient.parse() {
                    Ok(to) => to,
                    Err(error) => {
                        let _ = log_smtp_failure(
                            &event,
                            transfer_id.as_deref(),
                            Err::<(), _>(format!("smtp to: {error}")),
                        );
                        return (false, None);
                    }
                };
                let message = match Message::builder()
                    .from(from)
                    .to(to)
                    .subject(subject)
                    .singlepart(SinglePart::plain(body))
                {
                    Ok(message) => message,
                    Err(error) => {
                        let _ =
                            log_smtp_failure(&event, transfer_id.as_deref(), Err::<(), _>(error));
                        return (false, None);
                    }
                };
                match log_smtp_failure(
                    &event,
                    transfer_id.as_deref(),
                    transport.send(message).await,
                ) {
                    Ok(_) => (true, None),
                    Err(error) => (false, Some(smtp_failure_reason(&error))),
                }
            }
        })
        .buffer_unordered(8);
    futures_util::pin_mut!(results);
    let mut accepted = false;
    let mut failure = None;
    while let Some((delivered, reason)) = results.next().await {
        if delivered {
            accepted = true;
        }
        if let Some(reason) = reason {
            failure.get_or_insert(reason);
        }
    }
    if accepted {
        Ok(())
    } else {
        Err(failure.unwrap_or(
            "SMTP settings could not be used. Ask the platform administrator to check the sender and TLS settings.",
        ))
    }
}

fn smtp_failure_reason(error: &lettre::transport::smtp::Error) -> &'static str {
    if error.is_transient() {
        "SMTP relay temporarily refused the request. Try again later."
    } else if error.is_permanent() {
        "SMTP relay rejected the request. Check the recipients and ask the platform administrator to check relay policy and credentials."
    } else if error.is_client() {
        "SMTP settings are incompatible with the relay. Ask the platform administrator to check TLS and authentication settings."
    } else if error.is_response() {
        "SMTP relay returned an invalid response. Ask the platform administrator to check relay configuration."
    } else {
        "SMTP connection failed. Ask the platform administrator to check the host, port and TLS settings."
    }
}

fn smtp_tls(smtp: &ResolvedSmtp) -> Result<Tls, String> {
    if smtp.port == 465 {
        Ok(Tls::Wrapper(tls_params(&smtp.host)?))
    } else if smtp.starttls {
        Ok(Tls::Required(tls_params(&smtp.host)?))
    } else {
        Ok(Tls::None)
    }
}

fn tls_params(host: &str) -> Result<TlsParameters, String> {
    TlsParameters::new(host.to_owned()).map_err(|error| error.to_string())
}

pub async fn trade_event(
    app: &App,
    route: &crate::store::TradeRoute,
    policy: &crate::store::NotificationPolicy,
    event: &str,
    detail: Option<&str>,
) {
    let title = format!(
        "{}: {}",
        title_brand(app, &route.tenant),
        event.replace('_', " ")
    );
    let body = match detail {
        Some(detail) => format!(
            "{} · {} · {}\n{detail}",
            route.name, route.peer_name, route.state
        ),
        None => format!("{} · {} · {}", route.name, route.peer_name, route.state),
    };
    let mut payload = json!({"event":event,"tenant":&route.tenant,"route_id":route.id,"name":route.name,"peer":route.peer_key,"state":route.state});
    if let Some(detail) = detail {
        payload["detail"] = json!(detail);
    }
    let url = admin_link(
        app,
        &format!(
            "/trade-routes#route-{}",
            crate::api::scim::encode_segment(&route.id)
        ),
    );
    send_policy(
        app,
        Route {
            tenant: &route.tenant,
            policy: Some(policy),
        },
        title,
        body,
        payload,
        event,
        None,
        url.as_deref(),
    )
    .await;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use crate::api::testing;
    use crate::app;
    use crate::session::FinishReport;
    use crate::store::{
        now_unix, Branding, FileRecord, Link, NotificationDestination, NotificationMode,
        NotificationPolicy, NotificationRule, OutboundDownloadResult, OutboundGrant,
        OutboundGrantFile, Tenant, TradeRoute, UploadRecord, NOTIFICATION_EVENTS,
    };

    pub(crate) fn test_grant(files: Vec<OutboundGrantFile>) -> OutboundGrant {
        OutboundGrant {
            id: "grant-id".to_owned(),
            token_hash: "token-hash-secret".to_owned(),
            password_hash: Some("password-hash-secret".to_owned()),
            tenant: String::new(),
            link_id: "link-id".to_owned(),
            upload_id: "upload-id".to_owned(),
            package_root: "package-root-secret".to_owned(),
            name: "legacy-file.txt".to_owned(),
            suite: "blake3".to_owned(),
            root: "root-secret".to_owned(),
            file_index: 0,
            bytes: 10,
            label: "delivery-label".to_owned(),
            created_at: 1,
            expires_at: 2,
            revoked_at: None,
            downloads: 0,
            max_downloads: None,

            notifications: Some(test_policy()),
            first_download_at: None,
            last_download_at: None,
            files,
        }
    }

    fn test_file(name: &str, bytes: u64) -> OutboundGrantFile {
        OutboundGrantFile {
            source: "source-secret".to_owned(),
            name: name.to_owned(),
            suite: "blake3".to_owned(),
            root: "file-root-secret".to_owned(),
            bytes,
            receipt_b64: "receipt-secret".to_owned(),
            downloads: 0,
            first_download_at: None,
            last_download_at: None,
        }
    }

    fn test_policy() -> NotificationPolicy {
        NotificationPolicy {
            mode: NotificationMode::Default,
            rules: vec![],
        }
    }

    fn test_trade_route(policy: NotificationPolicy) -> TradeRoute {
        TradeRoute {
            id: "route-id".into(),
            revision: 1,
            tenant: String::new(),
            direction: "outgoing".into(),
            name: "Fixture route".into(),
            peer_name: "Fixture peer".into(),
            peer_key: "peer-key".into(),
            address: "http://127.0.0.1:1".into(),
            endpoint: "endpoint".into(),
            endpoint_name: "Endpoint".into(),
            category: "fixture".into(),
            forwarding: false,
            metadata_keys: Vec::new(),
            state: "active".into(),
            notifications: policy,
            last_contact: None,
            error: None,
            remote_grant: String::new(),
            remote_state: "active".into(),
            cancel_active: false,
        }
    }

    fn test_destination_config(app: &App, channel: &str, url: String) -> NotificationDestination {
        let mut destination = NotificationDestination {
            id: crate::auth::random_token(),
            revision: 0,
            label: channel.into(),
            channel: channel.into(),
            target: "Loopback test".into(),
            enabled: true,
            url,
            token: String::new(),
            user: String::new(),
            recipients: if channel == "email" {
                vec!["ops@example.com".into()]
            } else {
                vec![]
            },
            thread_id: String::new(),
        };
        app.store
            .save_notification_destination("", &mut destination)
            .unwrap();
        let mut defaults = app.store.notification_defaults("").unwrap();
        defaults.mode = NotificationMode::Custom;
        defaults.rules.push(NotificationRule {
            destination_id: destination.id.clone(),
            events: NOTIFICATION_EVENTS.iter().map(|s| (*s).into()).collect(),
        });
        app.store.save_notification_defaults("", &defaults).unwrap();
        destination
    }

    /// A single-request loopback stub that hands the captured request to
    /// the caller.
    fn capture_stub() -> (
        std::net::SocketAddr,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            let n = std::io::Read::read(&mut stream, &mut buf).unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            let _ = std::io::Write::write_all(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        });
        (addr, rx, thread)
    }

    fn webhook_app() -> (
        Arc<App>,
        tempfile::TempDir,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        webhook_app_with(None)
    }

    fn webhook_app_with(
        public_url: Option<&str>,
    ) -> (
        Arc<App>,
        tempfile::TempDir,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        let (addr, rx, thread) = capture_stub();
        let directory = tempfile::tempdir().unwrap();
        let mut application = app::build(testing::config(directory.path())).unwrap();
        Arc::get_mut(&mut application).unwrap().config.public_url = public_url.map(str::to_owned);
        test_destination_config(&application, "webhook", format!("http://{addr}/outbound"));
        (application, directory, rx, thread)
    }

    fn http_stub(status: &'static str) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = std::io::Read::read(&mut stream, &mut buf);
            let response =
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
        });
        (addr, thread)
    }

    fn request_json(request: &str) -> serde_json::Value {
        serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
    }

    fn assert_no_secrets(request: &str) {
        for secret in [
            "token-hash-secret",
            "password-hash-secret",
            "tenant-secret",
            "https://share-secret",
            "source-secret",
            "receipt-secret",
        ] {
            assert!(!request.contains(secret), "{secret}: {request}");
        }
    }

    fn ended(outcome: &str, notify: bool) -> crate::session::SessionEnded {
        ended_with(outcome, notify, 7)
    }

    fn ended_with(
        outcome: &str,
        notify: bool,
        received_bytes: u64,
    ) -> crate::session::SessionEnded {
        crate::session::SessionEnded {
            notifications: notify.then(test_policy),
            tenant: String::new(),
            link_id: "link-1".to_owned(),
            label: "shoot".to_owned(),
            event: crate::store::SessionEvent {
                at: 20,
                started_at: 10,
                outcome: outcome.to_owned(),
                detail: "session went idle".to_owned(),
                received_bytes,
                expected_bytes: 9,
                replayed_chunks: 0,
                rejected_chunks: 0,
            },
        }
    }

    #[test]
    fn summary_limits_keep_complete_unicode_at_boundaries() {
        for text in ["", "abc", "界🎬é"] {
            assert_eq!(clipped_bytes(text, text.len().max(3)), text);
            assert_eq!(clipped_chars(text, text.chars().count().max(1)), text);
        }
        assert_eq!(clipped_bytes("界🎬é", 8), "界…");
        assert_eq!(clipped_bytes("界🎬é", 3), "…");
        assert_eq!(clipped_chars("界🎬é", 2), "界…");
        assert_eq!(clipped_chars("界🎬é", 1), "…");
    }

    #[tokio::test]
    async fn uploaded_ntfy_and_test_share_safe_bounded_requests() {
        use axum::{
            http::{HeaderMap, StatusCode, Uri},
            routing::post,
            Router,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let messages = Arc::new(std::sync::Mutex::new(Vec::<(Uri, HeaderMap, String)>::new()));
        let received = messages.clone();
        let routes = Router::new().route(
            "/topic",
            post(move |uri: Uri, headers: HeaderMap, body: String| {
                received.lock().unwrap().push((uri, headers, body));
                async { (StatusCode::OK, [("connection", "close")]) }
            }),
        );
        let directory = tempfile::tempdir().unwrap();
        let mut application = testing::build(directory.path());
        Arc::get_mut(&mut application).unwrap().config.public_url = None;
        let destination =
            test_destination_config(&application, "ntfy", format!("http://{address}/topic"));
        application
            .store
            .set_branding(&Branding {
                name: "Müller 撮影".into(),
                ..Default::default()
            })
            .unwrap();
        application
            .store
            .insert_tenant(Tenant {
                key: "studio".into(),
                incarnation: String::new(),
                label: "Atelier été".into(),
                admin_group: None,
                max_total_bytes: None,
                max_links: None,
                max_sessions: None,
                created_at: 0,
            })
            .unwrap();
        let mut studio_destination = destination.clone();
        studio_destination.revision = 0;
        application
            .store
            .save_notification_destination("studio", &mut studio_destination)
            .unwrap();
        let files = (0..100)
            .map(|index| FileRecord {
                path: format!("{}-{index}.mov", "撮影🎬".repeat(8)),
                stored_as: format!("{}-{index}.mov", "撮影🎬".repeat(8)),
                bytes: 1,
                suite: "blake3".into(),
                root: "fixture".into(),
                receipt: false,
                deleted: false,
            })
            .collect();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (served, tested) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    axum::serve(listener, routes)
                        .with_graceful_shutdown(async {
                            let _ = stopped.await;
                        })
                        .await
                },
                async {
                    uploaded(
                        application.clone(),
                        String::new(),
                        "link-id".into(),
                        "Müller\n撮影".into(),
                        100,
                        FinishReport {
                            received: 0,
                            upload_id: "up-ntfy".into(),
                            files,
                        },
                        Some(test_policy()),
                    )
                    .await;
                    let branded = test_destination(&application, "", &destination)
                        .await
                        .is_ok();
                    application.store.delete_branding("").unwrap();
                    let default = test_destination(&application, "", &destination)
                        .await
                        .is_ok();
                    let tenant = test_destination(&application, "studio", &studio_destination)
                        .await
                        .is_ok();
                    let _ = stop.send(());
                    branded && default && tenant
                }
            )
        })
        .await
        .unwrap();
        served.unwrap();
        assert!(tested);
        let messages = messages.lock().unwrap();
        assert_eq!(messages.len(), 4);
        let (uri, headers, body) = &messages[0];
        assert!(!headers.contains_key("title"));
        let url = reqwest::Url::parse(&format!("http://localhost{uri}")).unwrap();
        assert!(url
            .query_pairs()
            .any(|(key, value)| key == "title" && value.contains("Müller\n撮影")));
        assert!(url
            .query_pairs()
            .any(|(key, value)| key == "title" && value.starts_with("Müller 撮影:")));
        assert!(body.starts_with("ID: up-ntfy\n100 file(s), 100 bytes\n"));
        assert!(body.len() <= 4096 && body.ends_with('…'));
        assert!(body.contains("撮影🎬"));
        for ((uri, headers, body), brand) in
            messages[1..]
                .iter()
                .zip(["Müller 撮影", "VOTPort", "Atelier été"])
        {
            let url = reqwest::Url::parse(&format!("http://localhost{uri}")).unwrap();
            assert!(
                url.query_pairs()
                    .any(|(key, value)| key == "title"
                        && value == format!("{brand}: notification test")),
                "{url}"
            );
            assert!(!headers.contains_key("title"));
            assert_eq!(
                body,
                "This is a notification test.\nSample file: Résumé_撮影.mov"
            );
        }
    }

    #[test]
    fn chat_messages_bound_unicode_and_disable_mentions() {
        let title = r#"report_[draft]* `v1` ~ (a) <x> #heading - item + one. ! &"#;
        let body =
            r#"<users/all> @everyone file_[final]* `v2` ~ <angle> #heading - item + one. ! &"#;
        let text = format!("{title}\n{body}");
        let escaped_title =
            r#"report\_\[draft\]\* \`v1\` \~ \(a\) \<x\> \#heading \- item \+ one\. \! &"#;
        let escaped_body = r#"\<users/all\> @everyone file\_\[final\]\* \`v2\` \~ \<angle\> \#heading \- item \+ one\. \! &"#;
        let escaped = format!("{escaped_title}\n{escaped_body}");
        let google_escaped_title =
            r#"report\_\[draft\]\* \`v1\` \~ \(a\) \<x\> \#heading \- item \+ one\. \! \&"#;
        let google_escaped_body = r#"\<users/all\> @everyone file\_\[final\]\* \`v2\` \~ \<angle\> \#heading \- item \+ one\. \! \&"#;
        let google_escaped = format!("{google_escaped_title}\n{google_escaped_body}");
        let slack_text = text
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let slack = chat_payload("slack", title, body);
        assert_eq!(slack["blocks"][0]["text"]["type"], "plain_text");
        assert_eq!(slack["blocks"][1]["text"]["type"], "plain_text");
        assert_eq!(slack["text"], slack_text.as_str());
        assert_eq!(slack["blocks"][0]["text"]["text"], title);
        assert_eq!(slack["blocks"][1]["text"]["text"], body);
        assert_eq!(slack["mrkdwn"], false);
        assert_eq!(slack["unfurl_links"], false);
        let teams = chat_payload("teams", title, body);
        let card = &teams["attachments"][0];
        assert_eq!(teams["type"], "message");
        assert_eq!(teams["text"], escaped.as_str());
        assert_eq!(
            card["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );
        assert_eq!(card["content"]["type"], "AdaptiveCard");
        assert_eq!(card["content"]["body"][1]["wrap"], true);
        assert_eq!(card["content"]["body"][0]["text"], escaped_title);
        assert_eq!(card["content"]["body"][1]["text"], escaped_body);
        let google = chat_payload("google_chat", title, body);
        assert_eq!(google["text"], google_escaped.as_str());
        assert_eq!(google["markupSyntax"], "MARKUP_SYNTAX_MARKDOWN");
        let entity_google = chat_payload("google_chat", "literal&amp;.mov", "&#65;.mov");
        assert_eq!(
            entity_google["text"],
            r#"literal\&amp;\.mov
\&\#65;\.mov"#
        );
        let discord = chat_payload("discord", title, body);
        assert_eq!(discord["allowed_mentions"]["parse"], json!([]));
        assert_eq!(discord["flags"], 4);
        assert_eq!(discord["content"], escaped.as_str());
        assert_eq!(
            chat_payload("discord", "short", "body")["content"],
            "short\nbody"
        );
        let long_title = chat_payload("slack", &"🎬".repeat(100), "body");
        assert!(
            long_title["blocks"][0]["text"]["text"]
                .as_str()
                .unwrap()
                .chars()
                .count()
                <= 150
        );
        let emoji_title = "🎬".repeat(100);
        let japanese_title = "撮".repeat(50);
        for title in [&emoji_title, &japanese_title] {
            let payload = chat_payload("slack", title, "body");
            assert_eq!(payload["blocks"][0]["text"]["text"], title.as_str());
        }
        let over_title = "🎬".repeat(151);
        let clipped_title = chat_payload("slack", &over_title, "body")["blocks"][0]["text"]["text"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(clipped_title, format!("{}…", "🎬".repeat(149)));
        assert_eq!(clipped_title.chars().count(), 150);
        let emoji_body = "🎬".repeat(1500);
        let body_payload = chat_payload("slack", "title", &emoji_body);
        assert_eq!(body_payload["blocks"][1]["text"]["text"], emoji_body);
        let over_body = "🎬".repeat(1501);
        let over_body_payload = chat_payload("slack", "title", &over_body);
        let clipped_body = over_body_payload["blocks"][1]["text"]["text"]
            .as_str()
            .unwrap();
        assert_eq!(clipped_body, format!("{}…", "🎬".repeat(1499)));
        assert_eq!(clipped_body.chars().count(), 1500);

        let encoded_body = "*".repeat(1500);
        let discord = chat_payload("discord", "title", &encoded_body);
        let discord_text = discord["content"].as_str().unwrap();
        assert!(discord_text.chars().count() <= DISCORD_CONTENT_LIMIT);
        assert!(discord_text.chars().count() > DISCORD_CONTENT_LIMIT - 10);
        assert!(discord_text.ends_with('…'));
        assert!(!discord_text[..discord_text.len() - '…'.len_utf8()].ends_with('\\'));
        assert!(discord_text.starts_with("title\n\\*\\*\\*"));
    }

    #[tokio::test]
    async fn workplace_channels_send_concurrently_and_tests_select_only_one() {
        use axum::{
            extract::Path,
            http::{StatusCode, Uri},
            response::IntoResponse,
            routing::post,
            Json, Router,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let gate = release.clone();
        let routes = Router::new().route(
            "/{channel}",
            post(
                move |Path(channel): Path<String>,
                      uri: Uri,
                      Json(body): Json<serde_json::Value>| {
                    let tx = tx.clone();
                    let gate = gate.clone();
                    async move {
                        tx.send((channel.clone(), uri, body)).await.unwrap();
                        tokio::time::timeout(Duration::from_secs(5), gate.acquire())
                            .await
                            .unwrap()
                            .unwrap()
                            .forget();
                        if channel == "teams" {
                            (
                                StatusCode::TOO_MANY_REQUESTS,
                                [(axum::http::header::RETRY_AFTER, "4")],
                            )
                                .into_response()
                        } else {
                            StatusCode::OK.into_response()
                        }
                    }
                },
            ),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, routes).await.unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let channels = ["slack", "teams", "google_chat", "discord"];
        let destinations = channels.map(|channel| {
            test_destination_config(
                &application,
                channel,
                format!(
                    "http://{address}/{channel}{}",
                    if channel == "discord" {
                        "?wait=false&thread_id=42"
                    } else {
                        ""
                    }
                ),
            )
        });
        let app = application.clone();
        let all = tokio::spawn(async move {
            let policy = test_policy();
            send_policy(
                &app,
                Route {
                    tenant: "",
                    policy: Some(&policy),
                },
                "notification test".into(),
                "notification test".into(),
                json!({"event":"upload_complete"}),
                "upload_complete",
                None,
                None,
            )
            .await;
        });
        let mut received = Vec::new();
        for _ in channels {
            let (channel, uri, payload) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(payload.to_string().contains("notification test"));
            if channel == "discord" {
                assert_eq!(uri.query(), Some("thread_id=42&wait=true"));
            }
            received.push(channel);
        }
        received.sort();
        assert_eq!(received, ["discord", "google_chat", "slack", "teams"]);
        release.add_permits(4);
        all.await.unwrap();
        let outcomes = application.store.notification_outcomes("").unwrap();
        for destination in &destinations {
            assert_eq!(
                outcomes[&destination.id]["delivered"],
                destination.channel != "teams"
            );
        }
        for destination in destinations {
            let channel = destination.channel.clone();
            let app = application.clone();
            let one =
                tokio::spawn(async move { test_destination(&app, "", &destination).await.is_ok() });
            let (actual, _, _) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(actual, channel);
            release.add_permits(1);
            assert_eq!(one.await.unwrap(), channel != "teams");
            assert!(rx.try_recv().is_err());
        }
        server.abort();
    }

    #[tokio::test]
    async fn notification_redirects_and_teams_error_bodies_are_failures() {
        use axum::{
            extract::Path,
            http::{HeaderMap, StatusCode},
            response::IntoResponse,
            routing::any,
            Router,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let routes = Router::new().route(
            "/{case}",
            any(move |Path(case): Path<String>, headers: HeaderMap| {
                let observed = observed.clone();
                async move {
                    assert!(!headers.contains_key("referer"));
                    match case.as_str() {
                        "redirect" => (StatusCode::TEMPORARY_REDIRECT, [("location", "/leak")])
                            .into_response(),
                        "leak" => {
                            observed.fetch_add(1, Ordering::SeqCst);
                            "ok".into_response()
                        }
                        "throttled" => {
                            "Microsoft Teams endpoint returned HTTP error 429".into_response()
                        }
                        "too-large" => "x".repeat(8193).into_response(),
                        "boundary" => "x".repeat(8192).into_response(),
                        "empty" => StatusCode::ACCEPTED.into_response(),
                        _ => "1".into_response(),
                    }
                }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, routes).await.unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        for (case, delivered) in [
            ("redirect", 0),
            ("throttled", 0),
            ("too-large", 0),
            ("boundary", 1),
            ("empty", 1),
            ("success", 1),
        ] {
            let destination = test_destination_config(
                &application,
                "teams",
                format!("http://{address}/{case}?secret=fixture"),
            );
            assert_eq!(
                test_destination(&application, "", &destination)
                    .await
                    .is_ok(),
                delivered == 1,
                "{case}"
            );
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn upload_ended_sends_failure_webhook_without_secrets() {
        let (application, _directory, rx, thread) = webhook_app();
        upload_ended(application, ended("interrupted", true)).await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(payload["event"], "upload_failed");
        assert_eq!(payload["outcome"], "interrupted");
        assert_eq!(payload["label"], "shoot");
        assert_eq!(payload["link_id"], "link-1");
        assert_eq!(payload["received_bytes"], 7);
        assert_eq!(payload["expected_bytes"], 9);
        assert_eq!(payload["ended_at"], 20);
        assert_no_secrets(&request);
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn uploaded_notification_links_the_receive_page() {
        let (application, _directory, rx, thread) =
            webhook_app_with(Some("https://notify.example/"));
        uploaded(
            application,
            String::new(),
            "link-id".to_owned(),
            "upload-label".to_owned(),
            100,
            FinishReport {
                received: 0,
                upload_id: "upload-id".to_owned(),
                files: vec![],
            },
            Some(test_policy()),
        )
        .await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(
            payload["url"],
            "https://notify.example/receive?search=link-id#link-link-id"
        );
        assert_eq!(payload["tenant"], "");
        assert_no_secrets(&request);
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn upload_ended_notification_links_the_receive_page() {
        let (application, _directory, rx, thread) =
            webhook_app_with(Some("https://notify.example"));
        upload_ended(application, ended("interrupted", true)).await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(
            payload["url"],
            "https://notify.example/receive?search=link-1#link-link-1"
        );
        assert_no_secrets(&request);
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn outbound_downloaded_notification_links_the_deliver_page() {
        let (application, _directory, rx, thread) =
            webhook_app_with(Some("https://notify.example/"));
        let grant = test_grant(vec![test_file("one.txt", 10), test_file("two.txt", 20)]);
        application.store.insert_outbound_grant(grant).unwrap();
        let result = application
            .store
            .record_outbound_download("grant-id", &[0], now_unix())
            .unwrap();
        let grant = application
            .store
            .outbound_grant_by_id("grant-id")
            .unwrap()
            .unwrap();
        outbound_downloaded(application, grant, result).await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(
            payload["url"],
            "https://notify.example/deliver#grant-grant-id"
        );
        assert_no_secrets(&request);
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn workflow_failed_notification_links_the_workflows_page() {
        let (application, _directory, rx, thread) =
            webhook_app_with(Some("https://notify.example/"));
        let mut request = crate::workflow::tests::request();
        request.notifications = Some(test_policy());
        let job = crate::workflow::Job {
            id: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".to_owned(),
            tenant: String::new(),
            token_generation: 0,
            actor: "sender".to_owned(),
            credential_version: 0,
            automation_token_id: None,
            request,
            project: crate::workflow::tests::project(),
            state: "failed".to_owned(),
            manifest: None,
            approved_by: None,
            attempts: 1,
            created_at: 1,
            updated_at: 2,
            error: Some("A destination did not complete".to_owned()),
            checks: serde_json::json!({}),
            received: None,
            reprocessed_from: None,
            reprocessed_as: None,
        };
        workflow_failed(application, job).await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(
            payload["url"],
            "https://notify.example/workflows#job-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        );
        assert_no_secrets(&request);
        thread.join().unwrap();
    }

    #[test]
    fn chat_payload_keeps_deep_links_clickable() {
        let url = "https://notify.example/receive?search=abc123#link-abc123";
        let title = "Port: files received";
        let body = format!("{url}\nfile (1).mov");
        let slack = chat_payload("slack", title, &body);
        let slack_text = slack["text"].as_str().unwrap();
        assert!(
            slack_text.contains(&format!("\n{url}\n")),
            "slack mangled the link: {slack_text}"
        );
        assert!(
            slack_text.contains("file (1).mov"),
            "slack entity escaping altered a plain filename: {slack_text}"
        );
        assert!(
            slack["blocks"][1]["text"]["text"]
                .as_str()
                .unwrap()
                .starts_with(url),
            "slack section mangled the link"
        );
        for channel in ["teams", "google_chat"] {
            let payload = chat_payload(channel, title, &body);
            let text = payload["text"].as_str().unwrap();
            assert!(
                text.contains(&format!("\n{url}\n")),
                "{channel} mangled the link: {text}"
            );
            assert!(
                text.contains("file \\(1\\)\\.mov"),
                "{channel} lost literal filename escaping: {text}"
            );
        }
        let discord = chat_payload("discord", title, &body);
        let content = discord["content"].as_str().unwrap();
        assert!(content.contains(&format!("\n{url}\n")), "{content}");
        assert!(content.contains("file \\(1\\)\\.mov"), "{content}");
    }

    #[tokio::test]
    async fn deep_link_leads_the_summary_and_stays_clickable_in_chat() {
        let (application, _directory, webhook_rx, webhook_thread) =
            webhook_app_with(Some("https://notify.example/"));
        let (address, rx, thread) = capture_stub();
        test_destination_config(&application, "discord", format!("http://{address}/hook"));
        uploaded(
            application,
            String::new(),
            "link-id".to_owned(),
            "upload-label".to_owned(),
            100,
            FinishReport {
                received: 0,
                upload_id: "upload-id".to_owned(),
                files: vec![],
            },
            Some(test_policy()),
        )
        .await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        let content = payload["content"].as_str().unwrap();
        assert!(
            content.contains("\nhttps://notify.example/receive?search=link-id#link-link-id\nID: "),
            "the deep link must lead the summary: {content}"
        );
        assert_no_secrets(&request);
        thread.join().unwrap();
        // The webhook destination of the same app receives its own copy.
        let webhook_request = webhook_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            request_json(&webhook_request)["url"],
            "https://notify.example/receive?search=link-id#link-link-id"
        );
        webhook_thread.join().unwrap();
    }

    #[tokio::test]
    async fn trade_event_details_reach_webhook_without_route_secrets() {
        for (event, detail) in [
            ("route_failed", Some("peer refused the request")),
            ("route_received", Some("receipt:bounded-digest")),
            ("route_approved", None),
        ] {
            let (application, _directory, rx, thread) =
                webhook_app_with(Some("https://notify.example/"));
            let policy = application.store.notification_defaults("").unwrap();
            let route = test_trade_route(policy.clone());
            trade_event(&application, &route, &policy, event, detail).await;
            let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let payload = request_json(&request);
            assert_eq!(payload["event"], event);
            assert_eq!(
                payload["url"],
                "https://notify.example/trade-routes#route-route-id"
            );
            assert_eq!(payload["tenant"], "");
            match detail {
                Some(detail) => {
                    assert_eq!(payload["detail"], detail);
                    assert!(request.contains(detail));
                }
                None => assert!(payload.get("detail").is_none()),
            }
            assert_no_secrets(&request);
            thread.join().unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upload_completion_notification_uses_scalar_persisted_timestamp() {
        let (application, _directory, rx, thread) = webhook_app();
        let policy = application.store.notification_defaults("").unwrap();
        application
            .store
            .insert_link(Link {
                id: "link-id".into(),
                tenant: String::new(),
                label: "upload-label".into(),
                dest: String::new(),
                password_hash: None,
                created_at: 1,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,
                notifications: Some(policy),
                uploads: Vec::new(),
                events: Vec::new(),
            })
            .unwrap();
        assert!(application
            .store
            .append_upload(
                "",
                "link-id",
                UploadRecord {
                    id: "upload-id".into(),
                    started_at: 10,
                    completed_at: 42,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: None,
                    package_root: "package-root".into(),
                    total_bytes: 1,
                    files: vec![FileRecord {
                        path: "file.txt".into(),
                        stored_as: "file.txt".into(),
                        bytes: 1,
                        suite: "blake3".into(),
                        root: "root".into(),
                        receipt: false,
                        deleted: false,
                    }],
                    partial: false,
                    log: Vec::new(),
                },
            )
            .unwrap());
        application
            .store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO link_uploads(link_id, tenant, upload_id, document, file_count)
                     VALUES ('link-id', '', 'unrelated', 'poisoned history', 0)",
                    [],
                )
            })
            .unwrap();
        let report = FinishReport {
            received: 1,
            upload_id: "upload-id".into(),
            files: vec![FileRecord {
                path: "file.txt".into(),
                stored_as: "file.txt".into(),
                bytes: 1,
                suite: "blake3".into(),
                root: "root".into(),
                receipt: false,
                deleted: false,
            }],
        };
        crate::app::upload_completed(
            &application,
            "session-id",
            Some("link-id".into()),
            "",
            &report,
            &tokio::runtime::Handle::current(),
        );
        let payload = request_json(&rx.recv_timeout(Duration::from_secs(5)).unwrap());
        assert_eq!(payload["link_id"], "link-id");
        assert_eq!(payload["completed_at"], 42);
        thread.join().unwrap();
    }

    // Multi-threaded: the blocking recv below must not starve the notifier.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn notifier_skips_cancelled_and_unsubscribed_sessions() {
        let (application, _directory, rx, thread) = webhook_app();
        for skipped in [
            ended("cancelled", true),
            ended("interrupted", false),
            ended_with("interrupted", true, 0),
        ] {
            application.session_ended.send(skipped).unwrap();
        }
        application
            .session_ended
            .send(ended("rejected", true))
            .unwrap();
        let notifier = tokio::spawn(crate::app::upload_ended_notifier(Arc::clone(&application)));
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(request_json(&request)["outcome"], "rejected");
        thread.join().unwrap();
        notifier.abort();
        // A second notifier finds the receiver taken and returns at once.
        crate::app::upload_ended_notifier(application).await;
    }

    #[tokio::test]
    async fn outbound_downloaded_sends_started_webhook_without_secrets() {
        let (application, _directory, rx, thread) = webhook_app();
        let grant = test_grant(vec![test_file("one.txt", 10), test_file("two.txt", 20)]);
        application.store.insert_outbound_grant(grant).unwrap();
        let result = application
            .store
            .record_outbound_download("grant-id", &[0], now_unix())
            .unwrap();
        let grant = application
            .store
            .outbound_grant_by_id("grant-id")
            .unwrap()
            .unwrap();
        outbound_downloaded(Arc::clone(&application), grant, result).await;
        let completed = application
            .store
            .record_outbound_download("grant-id", &[1], now_unix())
            .unwrap();
        assert!(completed.completed_delivery);
        assert_eq!(
            application
                .store
                .outbound_grant_by_id("grant-id")
                .unwrap()
                .unwrap()
                .downloads,
            1
        );
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(payload["event"], "outbound_download_started");
        assert!(payload.get("url").is_none());
        assert_eq!(payload["event_at"], result.event_at);
        assert_eq!(payload["download_starts"], 1);
        assert_eq!(payload["file_count"], 2);
        assert_eq!(payload["total_bytes"], 30);
        assert_eq!(payload["files_truncated"], false);
        assert_no_secrets(&request);
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn uploaded_notification_bounds_large_file_payload() {
        let (application, _directory, rx, thread) = webhook_app();
        let files = (0..101)
            .map(|index| FileRecord {
                path: format!("file-{index}.txt"),
                stored_as: format!("file-{index}.txt"),
                bytes: (index + 1) as u64,
                suite: "blake3".to_owned(),
                root: format!("root-{index}"),
                receipt: false,
                deleted: false,
            })
            .collect();
        uploaded(
            application,
            String::new(),
            "link-id".to_owned(),
            "upload-label".to_owned(),
            100,
            FinishReport {
                received: 0,
                upload_id: "upload-id".to_owned(),
                files,
            },
            Some(test_policy()),
        )
        .await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(payload["link_id"], "link-id");
        assert!(payload.get("url").is_none());
        assert_eq!(payload["completed_at"], 100);
        assert_eq!(payload["file_count"], 101);
        assert_eq!(payload["total_bytes"], 5151);
        assert_eq!(payload["files"].as_array().unwrap().len(), 100);
        assert_eq!(payload["files_truncated"], true);
        assert!(!request.contains("file-100.txt"), "{request}");
        assert_no_secrets(&request);
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn saved_notification_test_reports_delivery_without_secrets() {
        let (application, _directory, rx, thread) = webhook_app();
        let destination = application
            .store
            .notification_destinations("")
            .unwrap()
            .pop()
            .unwrap();
        assert!(test_destination(&application, "", &destination)
            .await
            .is_ok());
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(payload["event"], "notification_test");
        assert_eq!(
            payload["message"],
            "This is a notification test.\nSample file: Résumé_撮影.mov"
        );
        assert_no_secrets(&request);
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn non_success_webhook_is_reported_as_undelivered() {
        let (addr, thread) = http_stub("500 Internal Server Error");
        let directory = tempfile::tempdir().unwrap();
        let application = app::build(testing::config(directory.path())).unwrap();
        let destination =
            test_destination_config(&application, "webhook", format!("http://{addr}/failure"));
        assert_eq!(test_destination(&application, "", &destination).await,
            Err("The destination did not accept the test. Check its connection settings and try again."));
        assert_eq!(
            application.store.notification_outcomes("").unwrap()[&destination.id]["delivered"],
            false
        );
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn notification_tests_distinguish_connection_and_response_timeouts() {
        use tokio::io::AsyncWriteExt;
        for phase in ["connect", "headers", "body"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = if phase == "connect" {
                drop(listener);
                None
            } else {
                Some(tokio::spawn(async move {
                    let (mut stream, _) =
                        tokio::time::timeout(Duration::from_secs(2), listener.accept())
                            .await
                            .unwrap()
                            .unwrap();
                    if phase == "body" {
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
                            .await.unwrap();
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    drop(stream);
                }))
            };
            let directory = tempfile::tempdir().unwrap();
            let mut application = testing::build(directory.path());
            Arc::get_mut(&mut application).unwrap().http = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_millis(100))
                .build()
                .unwrap();
            let destination = test_destination_config(
                &application,
                if phase == "body" { "teams" } else { "webhook" },
                format!("http://{address}/test?secret=fixture-secret"),
            );
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                test_destination(&application, "", &destination),
            )
            .await;
            if let Some(server) = server {
                server.abort();
                let joined = server.await;
                assert!(joined.is_ok() || joined.unwrap_err().is_cancelled());
            }
            let expected = if phase == "connect" {
                "The destination connection failed. Check its URL, network access and TLS settings."
            } else {
                "The destination timed out. Try again or check the service status."
            };
            assert_eq!(result.unwrap(), Err(expected), "{phase}");
            assert_eq!(
                application.store.notification_outcomes("").unwrap()[&destination.id]["delivered"],
                false
            );
        }
    }

    #[tokio::test]
    async fn outbound_downloaded_sends_complete_webhook() {
        let (application, _directory, rx, thread) = webhook_app();
        let mut grant = test_grant(Vec::new());
        grant.downloads = u64::MAX;
        outbound_downloaded(
            application,
            grant,
            OutboundDownloadResult {
                first_download: false,
                completed_delivery: true,
                event_at: 77,
            },
        )
        .await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(payload["event"], "outbound_delivery_complete");
        assert_eq!(payload["event_at"], 77);
        assert_eq!(payload["download_starts"], u64::MAX);
        assert_eq!(payload["file_count"], 1);
        assert_eq!(payload["total_bytes"], 10);
        assert_eq!(payload["files_truncated"], false);
        assert_no_secrets(&request);
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn outbound_downloaded_bounds_large_file_payload() {
        let (application, _directory, rx, thread) = webhook_app();
        let files = (0..101)
            .map(|index| test_file(&format!("file-{index}.txt"), (index + 1) as u64))
            .collect();
        outbound_downloaded(
            application,
            test_grant(files),
            OutboundDownloadResult {
                first_download: true,
                completed_delivery: false,
                event_at: 0,
            },
        )
        .await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(payload["file_count"], 101);
        assert_eq!(payload["total_bytes"], 5151);
        assert_eq!(payload["files"].as_array().unwrap().len(), 100);
        assert_eq!(payload["files_truncated"], true);
        assert_no_secrets(&request);
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn outbound_downloaded_ignores_nontransitions() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::AsyncWriteExt;

        let hits = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&hits);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                observed.fetch_add(1, Ordering::SeqCst);
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        test_destination_config(
            &application,
            "webhook",
            format!("http://{address}/outbound"),
        );
        outbound_downloaded(
            application,
            test_grant(Vec::new()),
            OutboundDownloadResult {
                first_download: false,
                completed_delivery: false,
                event_at: 0,
            },
        )
        .await;
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        server.abort();
        let result = server.await;
        assert!(result.is_err_and(|error| error.is_cancelled()));
    }

    #[tokio::test]
    async fn uploaded_sends_smtp_to_plaintext_loopback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stub = tokio::spawn(async move { smtp_stub(listener).await });

        let directory = tempfile::tempdir().unwrap();
        let mut config = testing::config(directory.path());
        config.smtp_host = Some("127.0.0.1".to_owned());
        config.smtp_port = addr.port();
        config.smtp_starttls = false;
        config.smtp_from = Some("votport@example.com".to_owned());
        config.public_url = None;
        let application = app::build(config).unwrap();
        test_destination_config(&application, "email", String::new());

        uploaded(
            application,
            String::new(),
            "link-id".to_owned(),
            "smtp-label".to_owned(),
            100,
            FinishReport {
                received: 0,
                upload_id: "up-smtp".to_owned(),
                files: (0..100)
                    .map(|index| FileRecord {
                        path: format!("{}Müller_撮影-{index}.mov", "撮影/".repeat(200)),
                        stored_as: format!("{}Müller_撮影-{index}.mov", "撮影/".repeat(200)),
                        bytes: 1,
                        suite: "blake3".into(),
                        root: "fixture".into(),
                        receipt: false,
                        deleted: false,
                    })
                    .collect(),
            },
            Some(test_policy()),
        )
        .await;

        let transcript = tokio::time::timeout(Duration::from_secs(10), stub)
            .await
            .expect("smtp stub timed out")
            .expect("smtp stub join")
            .expect("smtp stub io");
        assert!(
            transcript.to_ascii_uppercase().contains("MAIL FROM"),
            "{transcript}"
        );
        assert!(transcript.contains("votport@example.com"), "{transcript}");
        assert!(transcript.contains("smtp-label"), "{transcript}");
        assert!(transcript.contains("MIME-Version: 1.0"), "{transcript}");
        assert!(
            transcript.contains("Content-Type: text/plain; charset=utf-8"),
            "{transcript}"
        );
        let data = transcript
            .split_once("DATA\r\n")
            .unwrap()
            .1
            .split_once("\r\n.\r\n")
            .unwrap()
            .0;
        let (headers, encoded) = data.split_once("\r\n\r\n").unwrap();
        assert!(
            headers.contains("Content-Transfer-Encoding: base64"),
            "{headers}"
        );
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.lines().collect::<String>())
            .unwrap();
        let text = String::from_utf8(decoded).unwrap().replace("\r\n", "\n");
        assert!(text.starts_with("ID: up-smtp\n100 file(s), 100 bytes\n"));
        assert!(text.contains("Müller_撮影-0.mov"));
        assert!(text.len() <= 64 * 1024 && text.ends_with('…'));
    }

    #[tokio::test]
    async fn uploaded_smtp_continues_after_recipient_rejection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stub = tokio::spawn(async move { smtp_multi_stub(listener, 2).await });

        let directory = tempfile::tempdir().unwrap();
        let mut config = testing::config(directory.path());
        config.smtp_host = Some("127.0.0.1".to_owned());
        config.smtp_port = addr.port();
        config.smtp_starttls = false;
        config.smtp_from = Some("votport@example.com".to_owned());
        let application = Arc::new(app::build(config).unwrap());
        let mut destination = test_destination_config(&application, "email", String::new());
        destination.recipients = vec!["bad@example.com".into(), "good@example.com".into()];
        application
            .store
            .save_notification_destination("", &mut destination)
            .unwrap();

        uploaded(
            Arc::clone(&application),
            String::new(),
            "link-id".to_owned(),
            "smtp-multiple-recipients".to_owned(),
            100,
            FinishReport {
                received: 1,
                upload_id: "up-smtp-multiple".to_owned(),
                files: vec![FileRecord {
                    path: "one.txt".into(),
                    stored_as: "one.txt".into(),
                    bytes: 1,
                    suite: "blake3".into(),
                    root: "fixture".into(),
                    receipt: false,
                    deleted: false,
                }],
            },
            Some(test_policy()),
        )
        .await;

        let mut stub = stub;
        let transcripts = match tokio::time::timeout(Duration::from_secs(10), &mut stub).await {
            Ok(result) => result.expect("smtp stub join").expect("smtp stub io"),
            Err(_) => {
                stub.abort();
                let _ = stub.await;
                panic!("smtp stub timed out");
            }
        };
        assert_eq!(transcripts.len(), 2, "{transcripts:?}");
        for transcript in &transcripts {
            assert_eq!(transcript.matches("MAIL FROM:").count(), 1);
            assert_eq!(transcript.matches("RCPT TO:").count(), 1);
        }
        let rejected = transcripts
            .iter()
            .find(|transcript| transcript.contains("RCPT TO:<bad@example.com>"))
            .expect("rejected recipient transcript");
        assert!(!rejected.contains("good@example.com"));
        let accepted = transcripts
            .iter()
            .find(|transcript| transcript.contains("RCPT TO:<good@example.com>"))
            .expect("accepted recipient transcript");
        assert!(!accepted.contains("bad@example.com"));
        assert_eq!(accepted.matches("DATA\r\n").count(), 1);
        assert_eq!(
            application.store.notification_outcomes("").unwrap()[&destination.id]["delivered"],
            true
        );
    }

    #[tokio::test]
    async fn notification_test_sends_unicode_smtp_sample() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let stub = tokio::spawn(async move { smtp_stub(listener).await });
        let directory = tempfile::tempdir().unwrap();
        let mut config = testing::config(directory.path());
        config.smtp_host = Some("127.0.0.1".into());
        config.smtp_port = address.port();
        config.smtp_starttls = false;
        config.smtp_from = Some("votport@example.com".into());
        let application = app::build(config).unwrap();
        let destination = test_destination_config(&application, "email", String::new());
        assert!(test_destination(&application, "", &destination)
            .await
            .is_ok());
        let transcript = tokio::time::timeout(Duration::from_secs(10), stub)
            .await
            .expect("smtp stub timed out")
            .unwrap()
            .unwrap();
        assert!(
            transcript.contains("Subject: VOTPort: notification test\r\n"),
            "{transcript}"
        );
        assert!(transcript.contains("MIME-Version: 1.0\r\n"), "{transcript}");
        assert!(
            transcript.contains("Content-Type: text/plain; charset=utf-8\r\n"),
            "{transcript}"
        );
        assert!(
            transcript.contains("Content-Transfer-Encoding: quoted-printable\r\n"),
            "{transcript}"
        );
        assert!(transcript.contains("\r\n\r\nThis is a notification test.\r\nSample file: R=C3=A9sum=C3=A9_=E6=92=AE=E5=BD=B1.mov\r\n"), "{transcript}");
    }

    #[test]
    fn log_smtp_failure_does_not_panic() {
        assert_eq!(
            log_smtp_failure("notification_test", None, Ok::<(), &str>(())),
            Ok(())
        );
        assert_eq!(
            log_smtp_failure("notification_test", None, Err::<(), _>("smtp boom")),
            Err("smtp boom")
        );
    }

    async fn smtp_stub(listener: tokio::net::TcpListener) -> std::io::Result<String> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let (socket, _) = listener.accept().await?;
        let (reader, mut writer) = socket.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        writer.write_all(b"220 localhost ESMTP\r\n").await?;
        let mut transcript = String::new();
        let mut line = String::new();
        let mut in_data = false;
        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }
            transcript.push_str(&line);
            if in_data {
                if line == ".\r\n" {
                    in_data = false;
                    writer.write_all(b"250 OK\r\n").await?;
                }
                continue;
            }
            let command = line.get(..4).unwrap_or("").to_ascii_uppercase();
            match command.as_str() {
                "DATA" => {
                    in_data = true;
                    writer.write_all(b"354 End data\r\n").await?;
                }
                "QUIT" => {
                    writer.write_all(b"221 Bye\r\n").await?;
                    break;
                }
                _ => writer.write_all(b"250 OK\r\n").await?,
            }
        }
        Ok(transcript)
    }

    async fn smtp_multi_stub(
        listener: tokio::net::TcpListener,
        expected: usize,
    ) -> std::io::Result<Vec<String>> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let mut transcripts = Vec::with_capacity(expected);
        for _ in 0..expected {
            let (socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "smtp accept timed out")
                })??;
            let (reader, mut writer) = socket.into_split();
            let mut reader = tokio::io::BufReader::new(reader);
            writer.write_all(b"220 localhost ESMTP\r\n").await?;
            let mut transcript = String::new();
            let mut line = String::new();
            let mut in_data = false;
            loop {
                line.clear();
                let n = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "smtp read timed out")
                    })??;
                if n == 0 {
                    break;
                }
                transcript.push_str(&line);
                if in_data {
                    if line == ".\r\n" {
                        in_data = false;
                        writer.write_all(b"250 OK\r\n").await?;
                    }
                    continue;
                }
                if line.starts_with("RCPT TO:<bad@example.com>") {
                    writer.write_all(b"550 bad recipient\r\n").await?;
                } else {
                    match line.get(..4).unwrap_or("").to_ascii_uppercase().as_str() {
                        "DATA" => {
                            in_data = true;
                            writer.write_all(b"354 End data\r\n").await?;
                        }
                        "QUIT" => {
                            writer.write_all(b"221 Bye\r\n").await?;
                            break;
                        }
                        _ => writer.write_all(b"250 OK\r\n").await?,
                    }
                }
            }
            transcripts.push(transcript);
        }
        Ok(transcripts)
    }
}
