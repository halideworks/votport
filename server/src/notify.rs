//! Upload-completion notifications: webhook, ntfy, Pushover.
//!
//! Best-effort and fire-and-forget: a completed transfer is already recorded
//! and on disk, so a notification failure is logged and nothing else.

use std::sync::Arc;

use serde_json::json;

use crate::app::App;
use crate::session::FinishReport;

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

    let settings = app.store.resolved_settings(&app.config);

    if let Some(url) = &settings.notify_webhook {
        let payload = json!({
            "event": "upload_complete",
            "label": label,
            "upload_id": report.upload_id,
            "total_bytes": total,
            "files": report.files,
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::api::testing;
    use crate::app;
    use crate::session::FinishReport;
    use crate::store::SettingWrite;

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
}
