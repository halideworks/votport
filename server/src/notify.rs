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

    if let Some(url) = &app.config.notify_webhook {
        let payload = json!({
            "event": "upload_complete",
            "label": label,
            "upload_id": report.upload_id,
            "total_bytes": total,
            "files": report.files,
        });
        log_failure("webhook", app.http.post(url).json(&payload).send().await);
    }

    if let Some(url) = &app.config.notify_ntfy {
        let mut request = app
            .http
            .post(url)
            .header("Title", title.clone())
            .body(body.clone());
        if let Some(token) = &app.config.notify_ntfy_token {
            request = request.bearer_auth(token);
        }
        log_failure("ntfy", request.send().await);
    }

    if let Some((token, user)) = &app.config.notify_pushover {
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
