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
use crate::store::{OutboundDownloadResult, OutboundGrant, ResolvedSmtp};

/// Sends every configured notification for one completed upload.
pub async fn uploaded(app: Arc<App>, label: String, report: FinishReport) {
    let total: u64 = report.files.iter().map(|file| file.bytes).sum();
    let count = report.files.len();
    let title = format!("votport: files received for \"{label}\"");
    let body = format!(
        "{count} file(s), {total} bytes\n{}",
        report
            .files
            .iter()
            .map(|file| format!("{} ({} bytes)", file.stored_as, file.bytes))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let payload = json!({
        "event": "upload_complete",
        "label": label,
        "upload_id": report.upload_id,
        "total_bytes": total,
        "files": report.files,
    });
    send_all(app, title, body, payload).await;
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
    let (file_count, total_bytes, files) = if grant.files.is_empty() {
        (
            1,
            grant.bytes,
            vec![json!({ "name": &grant.name, "bytes": grant.bytes })],
        )
    } else {
        let total_bytes = grant
            .files
            .iter()
            .fold(0u64, |total, file| total.saturating_add(file.bytes));
        (
            grant.files.len(),
            total_bytes,
            grant
                .files
                .iter()
                .map(|file| json!({ "name": &file.name, "bytes": file.bytes }))
                .collect(),
        )
    };
    let download_starts = grant.downloads.saturating_add(1);
    let title = format!("votport: outbound {transition} for \"{}\"", grant.label);
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
        "total_bytes": total_bytes,
        "files": files,
    });
    send_all(app, title, body, payload).await;
}

async fn send_all(app: Arc<App>, title: String, body: String, payload: serde_json::Value) {
    // Best effort like the rest of this path: a settings read failure logs
    // and sends nothing, rather than failing a transfer that already landed.
    let settings = match app.store.resolved_settings(&app.config) {
        Ok(settings) => settings,
        Err(error) => {
            tracing::error!(%error, "settings read failed; skipping notifications");
            return;
        }
    };

    if let Some(url) = &settings.notify_webhook {
        log_failure("webhook", app.http.post(url).json(&payload).send().await);
    }

    if let Some(url) = &settings.notify_ntfy {
        let mut request = app
            .http
            .post(url)
            .header("Title", title.clone())
            .body(body.clone());
        if let Some(token) = &settings.notify_ntfy_token {
            request = request.bearer_auth(token);
        }
        log_failure("ntfy", request.send().await);
    }

    if let Some((token, user)) = &settings.notify_pushover {
        let request = app
            .http
            .post("https://api.pushover.net/1/messages.json")
            .form(&[
                ("token", token.as_str()),
                ("user", user.as_str()),
                ("title", title.as_str()),
                ("message", body.as_str()),
            ]);
        log_failure("pushover", request.send().await);
    }

    if let Some(smtp) = &settings.smtp {
        log_smtp_failure(send_smtp(smtp, &title, &body).await);
    }
}

fn log_failure(target: &str, result: Result<reqwest::Response, reqwest::Error>) {
    match result {
        Ok(response) if !response.status().is_success() => {
            tracing::warn!(target, status = %response.status(), "notification failed");
        }
        Err(error) => tracing::warn!(target, "notification failed: {error}"),
        Ok(_) => {}
    }
}

fn log_smtp_failure<E: std::fmt::Display>(result: Result<(), E>) {
    if let Err(error) = result {
        tracing::warn!(target = "smtp", "notification failed: {error}");
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
    use crate::store::{OutboundDownloadResult, OutboundGrant, OutboundGrantFile, SettingWrite};

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
            let mut buf = vec![0u8; 8192];
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
        assert_no_secrets(&request);
        thread.join().unwrap();
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
            "label".to_owned(),
            FinishReport {
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
            "smtp-label".to_owned(),
            FinishReport {
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
        log_smtp_failure(Ok::<(), &str>(()));
        log_smtp_failure(Err("smtp boom"));
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
