//! HTTP API: shared error type plus the admin and upload halves.
//!
//! Licensed under the GNU Affero General Public License, version 3 only.

pub mod admin;
pub mod upload;

pub use admin::{
    admin_change_password, admin_login, admin_logout, admin_session, create_link, delete_link,
    delete_received_file, delete_upload_record, link_qr, list_links, update_link,
};
pub use upload::{
    create_session, link_info, upload_abort, upload_begin, upload_chunk, upload_finish,
    upload_page, upload_seal, verify_link_password,
};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::app::App;
use crate::session::SessionError;

pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "not signed in")
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not found")
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl From<SessionError> for ApiError {
    fn from(error: SessionError) -> Self {
        Self::new(
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            error.message,
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn cookie_attributes(app: &App) -> &'static str {
    let secure = app
        .config
        .public_url
        .as_deref()
        .is_none_or(|url| url.starts_with("https://"));
    if secure {
        "; Secure"
    } else {
        ""
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Arc;

    use crate::app::{self, App};
    use crate::config::Config;

    pub(crate) const TEST_PASSWORD: &str = "correct-horse-battery";

    /// An App over temp directories with an https public URL, so cookies
    /// carry the Secure attribute and handlers run without a listener.
    pub(crate) fn build(directory: &std::path::Path) -> Arc<App> {
        let config = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: directory.join("data"),
            receive_dir: directory.join("received"),
            web_root: std::path::PathBuf::from("../web"),
            admin_password_hash: crate::auth::hash_password(TEST_PASSWORD).unwrap(),
            admin_token_tag: "test-tag".to_owned(),
            notify_webhook: None,
            notify_ntfy: None,
            notify_ntfy_token: None,
            notify_pushover: None,
            public_url: Some("https://drop.example.com".to_owned()),
            max_upload_bytes: 1024 * 1024,
            allow_hidden: false,
            session_idle_secs: 60,
        };
        app::build(config).unwrap()
    }
}
