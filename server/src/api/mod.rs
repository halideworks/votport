//! HTTP API: shared error type plus the admin and upload halves.
//!
//! Licensed under the GNU Affero General Public License, version 3 only.

pub mod admin;
pub mod session_rate;
pub mod sso;
pub mod upload;

pub use admin::{
    admin_audit_export, admin_change_password, admin_login, admin_logout, admin_session,
    create_link, create_tenant, delete_link, delete_received_file, delete_tenant,
    delete_upload_record, link_qr, list_links, list_tenants, switch_tenant, update_link,
};
pub use sso::{sso_available, sso_callback, sso_start};
pub use upload::{
    create_session, link_info, upload_abort, upload_begin, upload_chunk, upload_finish,
    upload_page, upload_seal, verify_link_password,
};

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::app::App;
use crate::session::SessionError;

/// Client address for per-IP throttling: the rightmost X-Forwarded-For entry
/// (the one the reverse proxy appended; earlier entries are client-supplied),
/// else the socket peer.
fn client_ip(headers: &HeaderMap, peer: &std::net::SocketAddr) -> String {
    // X-Forwarded-For is honored only from a peer that can be the reverse
    // proxy (loopback or a private/ULA address). A caller reaching the port
    // directly from elsewhere would otherwise mint a fresh throttle bucket
    // per request by spoofing the header.
    if !proxy_peer(&peer.ip()) {
        return peer.ip().to_string();
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|list| list.rsplit(',').next())
        .map(|ip| ip.trim().to_owned())
        .filter(|ip| !ip.is_empty())
        .unwrap_or_else(|| peer.ip().to_string())
}

fn proxy_peer(ip: &std::net::IpAddr) -> bool {
    // Docker bridges can present v4 peers as IPv4-mapped IPv6; unwrap those
    // so the RFC 1918 check still applies.
    let ip = match ip {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => return (v6.segments()[0] & 0xfe00) == 0xfc00 || v6.is_loopback(),
        },
        other => *other,
    };
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        // fc00::/7 unique-local, the v6 analogue of RFC 1918.
        std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

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
            audit_retention_days: 400,
            oidc: None,
        };
        app::build(config).unwrap()
    }
}

#[cfg(test)]
mod ip_tests {
    use super::*;

    #[test]
    fn forwarded_for_is_trusted_only_from_proxy_peers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());
        let proxy: std::net::SocketAddr = "127.0.0.1:80".parse().unwrap();
        let private: std::net::SocketAddr = "172.18.0.2:80".parse().unwrap();
        let public: std::net::SocketAddr = "203.0.113.9:80".parse().unwrap();
        assert_eq!(client_ip(&headers, &proxy), "5.6.7.8");
        assert_eq!(client_ip(&headers, &private), "5.6.7.8");
        assert_eq!(client_ip(&headers, &public), "203.0.113.9");
        assert_eq!(client_ip(&HeaderMap::new(), &proxy), "127.0.0.1");
    }

    #[test]
    fn ipv4_mapped_proxy_peer_is_recognized() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        // A v4-mapped docker bridge address must still count as a proxy peer;
        // treating it as public would put every sender in one throttle bucket.
        let mapped: std::net::SocketAddr = "[::ffff:172.18.0.2]:80".parse().unwrap();
        assert_eq!(client_ip(&headers, &mapped), "9.9.9.9");
        let mapped_public: std::net::SocketAddr = "[::ffff:203.0.113.9]:80".parse().unwrap();
        // A public mapped peer is not a proxy: its socket address is used and
        // the forwarded header is ignored.
        assert_eq!(client_ip(&headers, &mapped_public), "::ffff:203.0.113.9");
    }
}

#[cfg(test)]
mod handler_tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt;

    use crate::api::testing;
    use crate::app;
    use crate::store::Link;

    #[tokio::test]
    async fn unusable_link_hides_its_label() {
        let directory = tempfile::tempdir().unwrap();
        let application = testing::build(directory.path());
        let link = Link {
            id: "closed-link-id".to_owned(),
            tenant: String::new(),
            label: "tax documents".to_owned(),
            dest: String::new(),
            password_hash: None,
            created_at: 0,
            expires_at: None,
            max_bytes: None,
            active: false,
            uploads: Vec::new(),
            events: Vec::new(),
        };
        application.store.insert_link(link).unwrap();

        let router = app::router(application);
        let response = router
            .oneshot(
                Request::get("/api/r/closed-link-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["usable"], false);
        assert_eq!(json["label"], serde_json::Value::Null);
        assert_eq!(json["authorized"], false);
    }
}
