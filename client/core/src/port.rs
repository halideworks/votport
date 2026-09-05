//! The home port: the votport an operator signed in to, and what they can
//! do there without opening the web admin.
//!
//! Sign-in is the admin password against `POST /api/admin/login`; the
//! session cookie the server sets is kept under the state directory beside
//! the device key and never handed to a shell.
//! Every call here runs over that cookie with the `X-Votport` header the
//! server wants on a mutation. A 401 means the session ended (the local
//! admin's lasts seven days), which surfaces as [`Error::NotSignedIn`] and
//! drops the stored session so the next launch asks again.
//!
//! ponytail: a JSON file beside the device key, owner-only on Unix and a
//! plain file under the user's profile on Windows (`write_private` sets no
//! ACL there); the platform keychain is the upgrade when the apps are
//! signed.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::api::Client;
use crate::error::{Error, Result};
use crate::identity::{state_dir, write_private};

const FILE: &str = "port.json";

/// The port an operator is signed in to, as a shell shows it. Never the
/// cookie.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Port {
    /// The origin, e.g. `https://drop.example`.
    pub base: String,
    /// The tenant the session belongs to; empty for the default tenant.
    pub tenant: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Stored {
    base: String,
    cookie: String,
    tenant: String,
}

fn path() -> PathBuf {
    state_dir().join(FILE)
}

fn load() -> Option<Stored> {
    let bytes = std::fs::read(path()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn store(stored: &Stored) -> Result<()> {
    std::fs::create_dir_all(state_dir())?;
    let bytes = serde_json::to_vec(stored).map_err(|error| Error::Other(error.to_string()))?;
    write_private(&path(), &bytes)
}

fn drop_stored() {
    let _ = std::fs::remove_file(path());
}

/// The origin `base` names, trimmed of a trailing slash, when it is an
/// `http` or `https` URL with a host and nothing after it.
fn origin(base: &str) -> Result<String> {
    let trimmed = base.trim().trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| Error::BadLink {
            link: base.to_owned(),
        })?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return Err(Error::BadLink {
            link: base.to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

#[derive(Deserialize)]
struct SessionInfo {
    #[serde(default)]
    tenant: String,
}

/// Signs in to the votport at `base` with the admin password and keeps the
/// session for the calls below.
///
/// # Errors
/// [`Error::BadLink`] for a `base` that is not an origin,
/// [`Error::WrongPassword`], a 429 after too many refusals, or a network
/// failure.
pub fn sign_in(base: &str, password: &str) -> Result<Port> {
    let base = origin(base)?;
    let client = Client::new(&base)?;
    let cookie = client.admin_login(password)?;
    // Stored before the session read: every login spends a throttle slot,
    // so a cookie the server issued is never dropped on a lost reply. The
    // next check fills the tenant in.
    let mut stored = Stored {
        base: base.clone(),
        cookie,
        tenant: String::new(),
    };
    store(&stored)?;
    let session: SessionInfo = client.admin_get("/api/admin/session", &stored.cookie)?;
    stored.tenant = session.tenant.clone();
    store(&stored)?;
    Ok(Port {
        base,
        tenant: session.tenant,
    })
}

/// The stored port, without asking the server whether the session still
/// holds. `None` when nobody is signed in.
#[must_use]
pub fn current() -> Option<Port> {
    load().map(|stored| Port {
        base: stored.base,
        tenant: stored.tenant,
    })
}

/// Asks the server whether the stored session still holds. A session it no
/// longer honours is dropped and `None` comes back, so a launch can show
/// the sign-in again; a network failure leaves the session in place.
///
/// # Errors
/// A network failure or an unexpected status.
pub fn check() -> Result<Option<Port>> {
    let Some(stored) = load() else {
        return Ok(None);
    };
    let client = Client::new(&stored.base)?;
    match client.admin_get::<SessionInfo>("/api/admin/session", &stored.cookie) {
        Ok(session) => {
            if session.tenant != stored.tenant {
                let _ = store(&Stored {
                    tenant: session.tenant.clone(),
                    ..stored.clone()
                });
            }
            Ok(Some(Port {
                base: stored.base,
                tenant: session.tenant,
            }))
        }
        Err(Error::NotSignedIn) => {
            drop_stored();
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Ends the session on the server (best effort) and forgets it here.
pub fn sign_out() {
    if let Some(stored) = load() {
        if let Ok(client) = Client::new(&stored.base) {
            let _ = client.admin_send::<serde_json::Value>(
                reqwest::Method::POST,
                "/api/admin/logout",
                &stored.cookie,
                None,
            );
        }
    }
    drop_stored();
}

/// The client and cookie of the signed-in port.
fn signed() -> Result<(Client, Stored)> {
    let stored = load().ok_or(Error::NotSignedIn)?;
    let client = Client::new(&stored.base)?;
    Ok((client, stored))
}

/// Runs an operator call, dropping the stored session when the server says
/// it ended so the shells stop offering operator screens.
fn run<T>(call: impl FnOnce(&Client, &str) -> Result<T>) -> Result<T> {
    let (client, stored) = signed()?;
    match call(&client, &stored.cookie) {
        Err(Error::NotSignedIn) => {
            drop_stored();
            Err(Error::NotSignedIn)
        }
        other => other,
    }
}

/// A request link the port issued: where senders ship to.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RequestLink {
    pub id: String,
    pub label: String,
    /// The link a sender pastes.
    pub url: String,
    pub has_password: bool,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub max_bytes: Option<u64>,
    /// Open and inside its window: a sender can ship to it now.
    pub usable: bool,
    pub active: bool,
    /// Drops that landed on it.
    pub drops: u64,
    /// Senders shipping to it right now.
    pub receiving: u64,
}

#[derive(Deserialize)]
struct LinkView {
    id: String,
    label: String,
    url: String,
    has_password: bool,
    created_at: u64,
    expires_at: Option<u64>,
    max_bytes: Option<u64>,
    usable: bool,
    active: bool,
    #[serde(default)]
    uploads: Vec<serde_json::Value>,
    #[serde(default)]
    receiving: Vec<serde_json::Value>,
}

impl From<LinkView> for RequestLink {
    fn from(view: LinkView) -> Self {
        Self {
            id: view.id,
            label: view.label,
            url: view.url,
            has_password: view.has_password,
            created_at: view.created_at,
            expires_at: view.expires_at,
            max_bytes: view.max_bytes,
            usable: view.usable,
            active: view.active,
            drops: view.uploads.len() as u64,
            receiving: view.receiving.len() as u64,
        }
    }
}

#[derive(Deserialize)]
struct Links {
    links: Vec<LinkView>,
}

#[derive(Deserialize)]
struct OneLink {
    link: LinkView,
}

/// The port's open request links, newest first, up to the server's page
/// of one hundred.
///
/// # Errors
/// [`Error::NotSignedIn`] or a network failure.
pub fn requests() -> Result<Vec<RequestLink>> {
    run(|client, cookie| {
        let page: Links = client.admin_get("/api/admin/links?status=open&limit=100", cookie)?;
        Ok(page.links.into_iter().map(RequestLink::from).collect())
    })
}

/// What a new request link is issued with.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RequestSpec {
    pub label: String,
    pub password: Option<String>,
    /// Days until it closes; the server's default when `None`.
    pub expires_days: Option<u32>,
    /// The largest drop it accepts; the server's cap when `None`.
    pub max_bytes: Option<u64>,
}

/// Issues a request link on the port.
///
/// # Errors
/// [`Error::NotSignedIn`], a refused spec (a 422 with the server's reason
/// in the detail), or a network failure.
pub fn issue_request(spec: RequestSpec) -> Result<RequestLink> {
    run(|client, cookie| {
        let mut body = serde_json::json!({ "label": spec.label });
        if let Some(password) = spec.password.as_deref().filter(|p| !p.is_empty()) {
            body["password"] = serde_json::json!(password);
        }
        if let Some(days) = spec.expires_days {
            body["expires_days"] = serde_json::json!(days);
        }
        if let Some(max) = spec.max_bytes {
            body["max_bytes"] = serde_json::json!(max);
        }
        let created: OneLink = client.admin_send(
            reqwest::Method::POST,
            "/api/admin/links",
            cookie,
            Some(&body),
        )?;
        Ok(RequestLink::from(created.link))
    })
}

/// Closes a request link: nothing more ships to it; what landed stays.
///
/// # Errors
/// [`Error::NotSignedIn`] or a network failure.
pub fn close_request(id: &str) -> Result<()> {
    run(|client, cookie| {
        let _: serde_json::Value = client.admin_send(
            reqwest::Method::POST,
            &format!("/api/admin/links/{}", url_segment(id)),
            cookie,
            Some(&serde_json::json!({ "active": false })),
        )?;
        Ok(())
    })
}

/// A delivery the port issued: files a recipient can pull. The link itself
/// is shown once, when it is issued; the server keeps only its hash.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record, Deserialize)]
pub struct Delivery {
    pub id: String,
    pub label: Option<String>,
    /// The file's name for a one-file delivery.
    pub name: Option<String>,
    pub has_password: bool,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub downloads: u64,
    pub max_downloads: Option<u64>,
    pub file_count: u64,
}

#[derive(Deserialize)]
struct Grants {
    grants: Vec<Delivery>,
}

/// The port's deliveries, newest first, up to one hundred.
///
/// # Errors
/// [`Error::NotSignedIn`] or a network failure.
pub fn deliveries() -> Result<Vec<Delivery>> {
    run(|client, cookie| {
        let page: Grants = client.admin_get("/api/admin/outbound-grants?limit=100", cookie)?;
        Ok(page.grants)
    })
}

/// Revokes a delivery: its link stops working.
///
/// # Errors
/// [`Error::NotSignedIn`] or a network failure.
pub fn revoke_delivery(id: &str) -> Result<()> {
    run(|client, cookie| {
        let _: serde_json::Value = client.admin_send(
            reqwest::Method::DELETE,
            &format!("/api/admin/outbound-grants/{}", url_segment(id)),
            cookie,
            None,
        )?;
        Ok(())
    })
}

/// One file of the port's library.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record, Deserialize)]
pub struct LibraryFile {
    /// Library-relative, forward slashes.
    pub path: String,
    pub bytes: u64,
}

/// One directory of the port's library: what a deliver screen browses.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record, Deserialize)]
pub struct Library {
    /// The directory listed, library-relative; empty for the root.
    #[serde(default)]
    pub directory: String,
    /// Subdirectory names.
    #[serde(default)]
    pub directories: Vec<String>,
    pub files: Vec<LibraryFile>,
    /// The listing stopped at the server's cap.
    #[serde(default)]
    pub truncated: bool,
}

/// Lists one directory of the library (`""` for the root).
///
/// # Errors
/// [`Error::NotSignedIn`], a refused directory, or a network failure.
pub fn library(directory: &str) -> Result<Library> {
    run(|client, cookie| {
        let query = url_query(directory.trim_matches('/'));
        client.admin_get(
            &format!("/api/admin/outbound-files?directory={query}"),
            cookie,
        )
    })
}

/// What a new delivery is issued with.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeliverySpec {
    /// Library-relative paths of the files.
    pub paths: Vec<String>,
    pub label: String,
    pub password: Option<String>,
    /// Days until it expires, 1 to 30.
    pub expires_days: u32,
    pub max_downloads: Option<u64>,
}

/// A delivery just issued, with the one link the server ever shows for it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IssuedDelivery {
    pub url: String,
    pub delivery: Delivery,
}

#[derive(Deserialize)]
struct Issued {
    url: String,
    grant: Delivery,
}

/// Issues a delivery of library files on the port.
///
/// # Errors
/// [`Error::NotSignedIn`], a refused spec (a 422 with the server's reason
/// in the detail), or a network failure.
pub fn issue_delivery(spec: DeliverySpec) -> Result<IssuedDelivery> {
    run(|client, cookie| {
        let mut body = serde_json::json!({
            "paths": spec.paths,
            "label": spec.label,
            "expires_days": spec.expires_days,
        });
        if let Some(password) = spec.password.as_deref().filter(|p| !p.is_empty()) {
            body["password"] = serde_json::json!(password);
        }
        if let Some(max) = spec.max_downloads {
            body["max_downloads"] = serde_json::json!(max);
        }
        let issued: Issued = client.admin_send(
            reqwest::Method::POST,
            "/api/admin/outbound-grants",
            cookie,
            Some(&body),
        )?;
        Ok(IssuedDelivery {
            url: issued.url,
            delivery: issued.grant,
        })
    })
}

/// Percent-encodes a query value: everything outside the unreserved set,
/// keeping the slashes a library directory is made of.
fn url_query(value: &str) -> String {
    encode(value, true)
}

/// Percent-encodes one path segment (an id from a shell): a slash or a dot
/// pair cannot reach another route.
fn url_segment(value: &str) -> String {
    encode(value, false)
}

fn encode(value: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' => out.push(byte as char),
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_is_a_scheme_and_a_host_and_nothing_else() {
        assert_eq!(
            origin(" https://drop.example/ ").unwrap(),
            "https://drop.example"
        );
        assert_eq!(
            origin("http://127.0.0.1:18080").unwrap(),
            "http://127.0.0.1:18080"
        );
        for bad in [
            "drop.example",
            "https://",
            "https://drop.example/r/abc",
            "ftp://x",
        ] {
            assert!(matches!(origin(bad), Err(Error::BadLink { .. })), "{bad}");
        }
    }

    #[test]
    fn query_values_keep_slashes_and_encode_the_rest() {
        assert_eq!(url_query("client/alex"), "client/alex");
        assert_eq!(url_query("a b&c"), "a%20b%26c");
        assert_eq!(url_segment("abc-1_2"), "abc-1_2");
        assert_eq!(url_segment("../links"), "%2E%2E%2Flinks");
    }

    #[test]
    fn link_views_count_their_drops_and_senders() {
        let view: LinkView = serde_json::from_value(serde_json::json!({
            "id": "l", "label": "Dailies", "url": "https://d/r/l", "has_password": false,
            "created_at": 1, "expires_at": null, "max_bytes": 5, "usable": true, "active": true,
            "uploads": [{}, {}], "receiving": [{}]
        }))
        .unwrap();
        let link = RequestLink::from(view);
        assert_eq!(
            (link.drops, link.receiving, link.max_bytes),
            (2, 1, Some(5))
        );
    }
}
