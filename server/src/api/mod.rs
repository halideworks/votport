//! HTTP API: shared error type plus the admin and upload halves.
//!
//! Licensed under the VOTPORT PROPRIETARY LICENSE.

pub mod admin;
pub mod outbound;
pub mod session_rate;
pub mod sso;
pub mod upload;
pub mod verify;

pub use admin::{
    admin_audit_export, admin_change_password, admin_login, admin_logout, admin_session,
    backup_database, create_link, create_tenant, delete_link, delete_received_file, delete_tenant,
    delete_upload_record, get_settings, holdings, link_qr, list_links, list_tenants, put_settings,
    revoke_principal, switch_tenant, test_notifications, unblock_principal, update_link,
    update_tenant,
};
pub use outbound::{
    automation_share, create_automation_token, create_outbound_grant, delete_automation_token,
    delete_outbound_grant, list_automation_tokens, list_outbound_files, list_outbound_grants,
    outbound_file, outbound_file_indexed, outbound_metadata, outbound_receipt,
    outbound_receipt_indexed, update_outbound_grant, upload_outbound_file,
    verify_outbound_password,
};
pub use sso::{sso_available, sso_callback, sso_start};
pub use upload::{
    create_push_session, create_session, link_info, upload_abort, upload_begin, upload_chunk,
    upload_finish, upload_page, upload_seal, verify_link_password,
};
pub use verify::{receipt_key, verify_receipt};

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::app::App;
use crate::session::SessionError;

/// Client address for per-IP throttling: the rightmost X-Forwarded-For entry
/// (the one the reverse proxy appended; earlier entries are client-supplied),
/// else the socket peer.
fn client_ip(
    headers: &HeaderMap,
    peer: &std::net::SocketAddr,
    trusted: &[crate::config::IpCidr],
) -> String {
    let believable = if trusted.is_empty() {
        proxy_peer(&peer.ip())
    } else {
        trusted.iter().any(|block| block.contains(&peer.ip()))
    };
    if !believable {
        return peer.ip().to_string();
    }
    headers
        // The last header line, not the first: the invariant below is about
        // the rightmost entry the proxy appended, and a hop that emits its
        // own line rather than appending would otherwise hand back a value
        // the client chose.
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|list| list.rsplit(',').next())
        .map(|ip| ip.trim().to_owned())
        // Keep only what is actually an address. Without this the header
        // picks the throttle key, so a caller that reaches the port from a
        // private peer could mint an unbounded number of them. Some proxies
        // append host:port, so an address with a port is accepted and stored
        // without it rather than discarded: discarding would collapse every
        // client behind such a proxy into the proxy's own bucket.
        .and_then(|value| parse_forwarded(&value))
        .unwrap_or_else(|| peer.ip().to_string())
}

fn parse_forwarded(value: &str) -> Option<String> {
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    value
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|socket| socket.ip().to_string())
}

/// Bucket for a *guessing* throttle: admin sign-in and link passwords. IPv6
/// clients routinely hold a whole /64, so keying on the full address would
/// give one guesser as many five-attempt budgets as it wants. The cost is
/// that neighbors in one prefix share a lockout, which is the right trade
/// only where the resource being protected is a password.
///
/// Quotas (session creation, receipt checks) deliberately key on the full
/// address instead: sharing an office should not mean sharing an upload
/// budget. Audit rows always keep the real address.
pub(crate) fn throttle_key(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        // A v4-mapped address is a v4 client: docker bridges and a dual-stack
        // bind both present them this way. Bucketing them as v6 would put
        // every v4 client, and ::1, in one bucket whose first four segments
        // are zero, so one guesser would lock out everybody.
        Ok(std::net::IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let [a, b, c, d, ..] = v6.segments();
                format!("{a:x}:{b:x}:{c:x}:{d:x}::/64")
            }
        },
        _ => ip.to_owned(),
    }
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

#[derive(Debug)]
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

/// A failed store read becomes a 500 that says only that the database is
/// unavailable. The rusqlite message goes to the log instead: it can name
/// file paths, and a caller who cannot read the database can do nothing with
/// the detail anyway.
pub(crate) fn store_unavailable(error: String) -> ApiError {
    tracing::error!(target: "audit", event = "store_read_failed", %error, "store read failed");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "database unavailable; try again",
    )
}

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
        app::build(config(directory)).unwrap()
    }

    pub(crate) fn config(directory: &std::path::Path) -> Config {
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            push_bind: None,
            push_certificate: None,
            push_private_key: None,
            push_advertise: None,
            data_dir: directory.join("data"),
            receive_dir: directory.join("received"),
            outbound_dir: directory.join("outbound"),
            web_root: std::path::PathBuf::from("../web"),
            admin_password_hash: crate::auth::hash_password(TEST_PASSWORD).unwrap(),
            admin_token_tag: "test-tag".to_owned(),
            notify_webhook: None,
            notify_ntfy: None,
            notify_ntfy_token: None,
            notify_pushover: None,
            smtp_host: None,
            smtp_port: 587,
            smtp_starttls: true,
            smtp_username: None,
            smtp_password: None,
            smtp_from: None,
            smtp_to: None,
            public_url: Some("https://drop.example.com".to_owned()),
            max_upload_bytes: 1024 * 1024,
            allow_hidden: false,
            session_idle_secs: 60,
            audit_retention_days: 400,
            upload_retention_days: 0,
            default_max_total_bytes: None,
            default_max_links: None,
            default_max_sessions: None,
            public_password_login: true,
            metrics_token: None,
            trusted_proxies: Vec::new(),
            oidc: None,
        }
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
        assert_eq!(client_ip(&headers, &proxy, &[]), "5.6.7.8");
        assert_eq!(client_ip(&headers, &private, &[]), "5.6.7.8");
        assert_eq!(client_ip(&headers, &public, &[]), "203.0.113.9");
        assert_eq!(client_ip(&HeaderMap::new(), &proxy, &[]), "127.0.0.1");
    }

    #[test]
    fn a_second_forwarded_line_does_not_win() {
        // A hop that emits its own header line instead of appending must not
        // let the client's line choose the bucket.
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "9.9.9.9".parse().unwrap());
        headers.append("x-forwarded-for", "203.0.113.9".parse().unwrap());
        let proxy: std::net::SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert_eq!(client_ip(&headers, &proxy, &[]), "203.0.113.9");
    }

    #[test]
    fn a_configured_allowlist_replaces_the_private_range_guess() {
        use crate::config::IpCidr;
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        let proxy: std::net::SocketAddr = "192.0.2.7:80".parse().unwrap();
        let other: std::net::SocketAddr = "192.0.2.8:80".parse().unwrap();
        let trusted = [IpCidr::parse("192.0.2.7/32").unwrap()];
        // The named proxy is believed.
        assert_eq!(client_ip(&headers, &proxy, &trusted), "203.0.113.9");
        // Anything else is not, even though it could reach the port.
        assert_eq!(client_ip(&headers, &other, &trusted), "192.0.2.8");
        // A private peer is believed by the default guess and not by a list
        // that does not name it: naming the proxy is what narrows this.
        let private: std::net::SocketAddr = "172.19.0.1:80".parse().unwrap();
        assert_eq!(client_ip(&headers, &private, &[]), "203.0.113.9");
        assert_eq!(client_ip(&headers, &private, &trusted), "172.19.0.1");
    }

    #[test]
    fn garbage_forwarded_values_fall_back_to_the_peer() {
        let mut headers = HeaderMap::new();
        let proxy: std::net::SocketAddr = "127.0.0.1:80".parse().unwrap();
        for bad in ["not-an-ip", "", "   ", "1.2.3.4.5", "<script>"] {
            headers.insert("x-forwarded-for", bad.parse().unwrap());
            assert_eq!(
                client_ip(&headers, &proxy, &[]),
                "127.0.0.1",
                "value {bad:?}"
            );
        }
        // A proxy that appends a port still names a client. Rejecting these
        // would put every client behind that proxy in one bucket.
        for (value, expected) in [
            ("1.2.3.4:5678", "1.2.3.4"),
            ("[2001:db8::1]:443", "2001:db8::1"),
        ] {
            headers.insert("x-forwarded-for", value.parse().unwrap());
            assert_eq!(
                client_ip(&headers, &proxy, &[]),
                expected,
                "value {value:?}"
            );
        }
    }

    #[test]
    fn mapped_v4_addresses_keep_their_own_buckets() {
        // The whole point of the per-IP bucket is that one guesser locks only
        // itself; treating mapped addresses as v6 put every v4 client in one
        // bucket keyed on four zero segments.
        let first = throttle_key("::ffff:203.0.113.9");
        let second = throttle_key("::ffff:203.0.113.10");
        assert_eq!(first, "203.0.113.9");
        assert_ne!(first, second);
        assert_ne!(first, throttle_key("::1"));
        assert_ne!(second, throttle_key("::1"));
    }

    #[test]
    fn throttle_keys_collapse_an_ipv6_prefix() {
        // One /64 is one bucket, so rotating the host part buys nothing.
        let first = throttle_key("2001:db8:1:2:3:4:5:6");
        assert_eq!(first, throttle_key("2001:db8:1:2:ffff:ffff:ffff:ffff"));
        assert_ne!(first, throttle_key("2001:db8:1:3::1"));
        // v4 and anything unparseable are their own bucket, unchanged.
        assert_eq!(throttle_key("203.0.113.9"), "203.0.113.9");
        assert_eq!(throttle_key("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn ipv4_mapped_proxy_peer_is_recognized() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        // A v4-mapped docker bridge address must still count as a proxy peer;
        // treating it as public would put every sender in one throttle bucket.
        let mapped: std::net::SocketAddr = "[::ffff:172.18.0.2]:80".parse().unwrap();
        assert_eq!(client_ip(&headers, &mapped, &[]), "9.9.9.9");
        let mapped_public: std::net::SocketAddr = "[::ffff:203.0.113.9]:80".parse().unwrap();
        // A public mapped peer is not a proxy: its socket address is used and
        // the forwarded header is ignored.
        assert_eq!(
            client_ip(&headers, &mapped_public, &[]),
            "::ffff:203.0.113.9"
        );
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
            legal_hold: false,
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
