//! Upload-completion notifications: webhook, ntfy, Pushover, SMTP.
//!
//! Best-effort and fire-and-forget: a completed transfer is already recorded
//! and on disk, so a notification failure is logged and nothing else.

use std::sync::Arc;
use std::time::Duration;

use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::json;

use crate::app::App;
use crate::session::FinishReport;
use crate::store::{OutboundDownloadResult, OutboundGrant, ResolvedSettings, ResolvedSmtp};

const MAX_NOTIFICATION_FILES: usize = 100;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NotificationReport {
    pub configured: u32,
    pub delivered: u32,
}

/// Product name for notification titles: the tenant's brand name when one is
/// set, else the tenant label, else "votport".
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
        .unwrap_or_else(|| "votport".to_owned())
}

/// Sends every configured notification for one completed upload.
pub async fn uploaded(app: Arc<App>, tenant: String, label: String, report: FinishReport) {
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

    let payload = json!({
        "event": "upload_complete",
        "label": label,
        "upload_id": report.upload_id,
        "total_bytes": total,
        "file_count": count,
        "files_truncated": files_truncated,
        "files": files,
    });
    send_all(
        app,
        title,
        body,
        payload,
        "upload_complete",
        Some(&transfer_id),
    )
    .await;
}

/// Sends the transition notification for an outbound delivery.
pub async fn outbound_downloaded(
    app: Arc<App>,
    grant: OutboundGrant,
    result: OutboundDownloadResult,
) {
    let (event, transition) = if result.completed_delivery {
        ("outbound_delivery_complete", "delivery complete")
    } else if result.first_download {
        ("outbound_download_started", "download started")
    } else {
        return;
    };
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
    let download_starts = grant.downloads.saturating_add(1);
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
        "grant_id": grant.id,
        "label": grant.label,
        "download_starts": download_starts,
        "file_count": file_count,
        "files_truncated": files_truncated,
        "total_bytes": total_bytes,
        "files": files,
    });
    send_all(app, title, body, payload, event, Some(&transfer_id)).await;
}

/// Sends a safe test message using the currently resolved (saved plus
/// environment) notification settings and reports channel outcomes.
pub async fn test_saved(app: Arc<App>) -> Result<NotificationReport, String> {
    let settings = app.store.resolved_settings(&app.config)?;
    Ok(send_resolved(
        &app,
        &settings,
        "votport: notification test".to_owned(),
        "This is a VOTPort notification test.".to_owned(),
        json!({
            "event": "notification_test",
            "message": "This is a VOTPort notification test."
        }),
        "notification_test",
        None,
    )
    .await)
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
    let payload = json!({
        "event": "upload_failed",
        "label": ended.label,
        "link_id": ended.link_id,
        "outcome": event.outcome,
        "detail": event.detail,
        "received_bytes": event.received_bytes,
        "expected_bytes": event.expected_bytes,
        "started_at": event.started_at,
        "ended_at": event.at,
    });
    send_all(
        app,
        title,
        body,
        payload,
        "upload_failed",
        Some(&ended.link_id),
    )
    .await;
}

async fn send_all(
    app: Arc<App>,
    title: String,
    body: String,
    payload: serde_json::Value,
    event: &str,
    transfer_id: Option<&str>,
) {
    // Best effort like the rest of this path: a settings read failure logs
    // and sends nothing, rather than failing a transfer that already landed.
    let settings = match app.store.resolved_settings(&app.config) {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(
                channel = "settings",
                event,
                transfer_id = transfer_id.unwrap_or("none"),
                outcome = "failed",
                %error,
                "settings read failed; skipping notifications"
            );
            return;
        }
    };

    let _ = send_resolved(&app, &settings, title, body, payload, event, transfer_id).await;
}

async fn send_resolved(
    app: &App,
    settings: &ResolvedSettings,
    title: String,
    body: String,
    payload: serde_json::Value,
    event: &str,
    transfer_id: Option<&str>,
) -> NotificationReport {
    let mut report = NotificationReport::default();
    if let Some(url) = &settings.notify_webhook {
        report.configured += 1;
        if log_failure(
            "webhook",
            event,
            transfer_id,
            app.http.post(url).json(&payload).send().await,
        ) {
            report.delivered += 1;
        }
    }
    if let Some(url) = &settings.notify_ntfy {
        report.configured += 1;
        let mut request = app
            .http
            .post(url)
            .header("Title", title.clone())
            .body(body.clone());
        if let Some(token) = &settings.notify_ntfy_token {
            request = request.bearer_auth(token);
        }
        if log_failure("ntfy", event, transfer_id, request.send().await) {
            report.delivered += 1;
        }
    }

    if let Some((token, user)) = &settings.notify_pushover {
        report.configured += 1;
        let request = app
            .http
            .post("https://api.pushover.net/1/messages.json")
            .form(&[
                ("token", token.as_str()),
                ("user", user.as_str()),
                ("title", title.as_str()),
                ("message", body.as_str()),
            ]);
        if log_failure("pushover", event, transfer_id, request.send().await) {
            report.delivered += 1;
        }
    }

    if let Some(smtp) = &settings.smtp {
        report.configured += 1;
        if log_smtp_failure(event, transfer_id, send_smtp(smtp, &title, &body).await) {
            report.delivered += 1;
        }
    }
    if report.delivered < report.configured {
        let outcome = if report.delivered == 0 {
            "failed"
        } else {
            "partial"
        };
        tracing::warn!(
            event,
            transfer_id = transfer_id.unwrap_or("none"),
            configured = report.configured,
            delivered = report.delivered,
            outcome,
            "notification delivery incomplete"
        );
    }
    report
}

fn log_failure(
    channel: &str,
    event: &str,
    transfer_id: Option<&str>,
    result: Result<reqwest::Response, reqwest::Error>,
) -> bool {
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
            false
        }
        Err(error) => {
            let error = error.without_url();
            tracing::warn!(
                channel,
                event,
                transfer_id = transfer_id.unwrap_or("none"),
                outcome = "failed",
                "notification failed: {error}"
            );
            false
        }
        Ok(_) => true,
    }
}

fn log_smtp_failure<E: std::fmt::Display>(
    event: &str,
    transfer_id: Option<&str>,
    result: Result<(), E>,
) -> bool {
    if let Err(error) = result {
        tracing::warn!(
            channel = "smtp",
            event,
            transfer_id = transfer_id.unwrap_or("none"),
            outcome = "failed",
            "notification failed: {error}"
        );
        false
    } else {
        true
    }
}

async fn send_smtp(smtp: &ResolvedSmtp, title: &str, body: &str) -> Result<(), String> {
    let mut builder = Message::builder()
        .from(
            smtp.from
                .parse()
                .map_err(|error| format!("smtp from: {error}"))?,
        )
        .subject(title);
    for recipient in &smtp.to {
        builder = builder.to(recipient
            .parse()
            .map_err(|error| format!("smtp to: {error}"))?);
    }
    let message = builder
        .body(body.to_owned())
        .map_err(|error| format!("smtp message: {error}"))?;

    let tls = smtp_tls(smtp)?;
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
    transport
        .build()
        .send(message)
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::api::testing;
    use crate::app;
    use crate::session::FinishReport;
    use crate::store::{
        FileRecord, OutboundDownloadResult, OutboundGrant, OutboundGrantFile, SettingWrite,
    };

    fn test_grant(files: Vec<OutboundGrantFile>) -> OutboundGrant {
        OutboundGrant {
            id: "grant-id".to_owned(),
            token_hash: "token-hash-secret".to_owned(),
            password_hash: Some("password-hash-secret".to_owned()),
            tenant: "tenant-secret".to_owned(),
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
            notify_on_download: false,
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

    fn webhook_app() -> (
        Arc<App>,
        tempfile::TempDir,
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
        let directory = tempfile::tempdir().unwrap();
        let application = app::build(testing::config(directory.path())).unwrap();
        application
            .store
            .put_settings(
                "local",
                &[(
                    "notify_webhook".to_owned(),
                    SettingWrite::Set(format!("http://{addr}/outbound")),
                )],
            )
            .unwrap();
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
        crate::session::SessionEnded {
            tenant: String::new(),
            link_id: "link-1".to_owned(),
            label: "shoot".to_owned(),
            notify,
            event: crate::store::SessionEvent {
                at: 20,
                started_at: 10,
                outcome: outcome.to_owned(),
                detail: "session went idle".to_owned(),
                received_bytes: 7,
                expected_bytes: 9,
                replayed_chunks: 0,
                rejected_chunks: 0,
            },
        }
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

    // Multi-threaded: the blocking recv below must not starve the notifier.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn notifier_skips_cancelled_and_unsubscribed_sessions() {
        let (application, _directory, rx, thread) = webhook_app();
        for skipped in [ended("cancelled", true), ended("interrupted", false)] {
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
        outbound_downloaded(
            application,
            test_grant(vec![test_file("one.txt", 10), test_file("two.txt", 20)]),
            OutboundDownloadResult {
                first_download: true,
                completed_delivery: false,
            },
        )
        .await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(payload["event"], "outbound_download_started");
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
            "upload-label".to_owned(),
            FinishReport {
                received: 0,
                upload_id: "upload-id".to_owned(),
                files,
            },
        )
        .await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
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
        let report = test_saved(application).await.unwrap();
        assert_eq!(report.configured, 1);
        assert_eq!(report.delivered, 1);
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(payload["event"], "notification_test");
        assert_eq!(payload["message"], "This is a VOTPort notification test.");
        assert_no_secrets(&request);
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn non_success_webhook_is_reported_as_undelivered() {
        let (addr, thread) = http_stub("500 Internal Server Error");
        let directory = tempfile::tempdir().unwrap();
        let application = app::build(testing::config(directory.path())).unwrap();
        application
            .store
            .put_settings(
                "local",
                &[(
                    "notify_webhook".to_owned(),
                    SettingWrite::Set(format!("http://{addr}/failure")),
                )],
            )
            .unwrap();
        let settings = application
            .store
            .resolved_settings(&application.config)
            .unwrap();
        let report = send_resolved(
            &application,
            &settings,
            "title".to_owned(),
            "body".to_owned(),
            json!({ "event": "upload_complete" }),
            "upload_complete",
            Some("upload-1"),
        )
        .await;
        assert_eq!(
            report,
            NotificationReport {
                configured: 1,
                delivered: 0
            }
        );
        thread.join().unwrap();
    }

    #[tokio::test]
    async fn partial_channel_delivery_reports_one_failure() {
        let (webhook_addr, webhook_thread) = http_stub("200 OK");
        let (ntfy_addr, ntfy_thread) = http_stub("503 Service Unavailable");
        let directory = tempfile::tempdir().unwrap();
        let application = app::build(testing::config(directory.path())).unwrap();
        application
            .store
            .put_settings(
                "local",
                &[
                    (
                        "notify_webhook".to_owned(),
                        SettingWrite::Set(format!("http://{webhook_addr}/ok")),
                    ),
                    (
                        "notify_ntfy".to_owned(),
                        SettingWrite::Set(format!("http://{ntfy_addr}/partial")),
                    ),
                ],
            )
            .unwrap();
        let settings = application
            .store
            .resolved_settings(&application.config)
            .unwrap();
        let report = send_resolved(
            &application,
            &settings,
            "title".to_owned(),
            "body".to_owned(),
            json!({ "event": "upload_complete" }),
            "upload_complete",
            Some("upload-2"),
        )
        .await;
        assert_eq!(
            report,
            NotificationReport {
                configured: 2,
                delivered: 1
            }
        );
        webhook_thread.join().unwrap();
        ntfy_thread.join().unwrap();
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
                first_download: true,
                completed_delivery: true,
            },
        )
        .await;
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let payload = request_json(&request);
        assert_eq!(payload["event"], "outbound_delivery_complete");
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
        let directory = tempfile::tempdir().unwrap();
        outbound_downloaded(
            testing::build(directory.path()),
            test_grant(Vec::new()),
            OutboundDownloadResult {
                first_download: false,
                completed_delivery: false,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn uploaded_hits_the_db_webhook_not_env() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(false).unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 8192];
            let n = std::io::Read::read(&mut stream, &mut buf).unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            let _ = std::io::Write::write_all(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        });

        let directory = tempfile::tempdir().unwrap();
        let mut config = testing::config(directory.path());
        config.notify_webhook = Some("http://127.0.0.1:9/env-hook".to_owned());
        let application = app::build(config).unwrap();
        application
            .store
            .put_settings(
                "local",
                &[(
                    "notify_webhook".to_owned(),
                    SettingWrite::Set(format!("http://{addr}/db-hook")),
                )],
            )
            .unwrap();

        uploaded(
            application,
            String::new(),
            "label".to_owned(),
            FinishReport {
                received: 0,
                upload_id: "up-1".to_owned(),
                files: Vec::new(),
            },
        )
        .await;

        let received = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("db webhook was not called");
        assert!(received.contains("/db-hook"), "{received}");
        assert!(!received.contains("/env-hook"), "{received}");
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
        config.smtp_to = Some("ops@example.com".to_owned());
        let application = app::build(config).unwrap();

        uploaded(
            application,
            String::new(),
            "smtp-label".to_owned(),
            FinishReport {
                received: 0,
                upload_id: "up-smtp".to_owned(),
                files: Vec::new(),
            },
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
    }

    #[test]
    fn log_smtp_failure_does_not_panic() {
        log_smtp_failure("notification_test", None, Ok::<(), &str>(()));
        log_smtp_failure("notification_test", None, Err("smtp boom"));
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
}
