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

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::api::{ChunkReply, Client};
use crate::error::{human_bytes, Error, Result};
use crate::identity::{state_dir, write_private};
use crate::transfer;

const FILE: &str = "port.json";

/// What a failed operator call tells a shell: the headline for the person,
/// the detail behind it, and whether the session ended (so the operator
/// screens fold). One shape for every call, since the shells hold no copy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum PortError {
    #[error("{headline}")]
    Failed {
        headline: String,
        detail: String,
        signed_out: bool,
    },
}

impl From<Error> for PortError {
    fn from(error: Error) -> Self {
        Self::Failed {
            headline: error.headline(),
            detail: error.to_string(),
            signed_out: matches!(error, Error::NotSignedIn),
        }
    }
}

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
    /// The counts in words: "2 drops, 1 shipping now, password".
    pub summary: String,
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
        let drops = view.uploads.len() as u64;
        let receiving = view.receiving.len() as u64;
        let mut parts = vec![count(drops, "drop", "drops")];
        if receiving > 0 {
            parts.push(format!("{receiving} shipping now"));
        }
        if view.has_password {
            parts.push("password".to_owned());
        }
        Self {
            summary: parts.join(", "),
            id: view.id,
            label: view.label,
            url: view.url,
            has_password: view.has_password,
            created_at: view.created_at,
            expires_at: view.expires_at,
            max_bytes: view.max_bytes,
            usable: view.usable,
            active: view.active,
            drops,
            receiving,
        }
    }
}

fn count(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
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
    /// The counts in words: "2 files, 5 downloads, revoked".
    #[serde(skip)]
    pub summary: String,
}

impl Delivery {
    fn with_summary(mut self) -> Self {
        let mut parts = vec![
            count(self.file_count, "file", "files"),
            count(self.downloads, "download", "downloads"),
        ];
        if let Some(max) = self.max_downloads {
            parts.push(format!("of {max} allowed"));
        }
        if self.has_password {
            parts.push("password".to_owned());
        }
        if self.revoked_at.is_some() {
            parts.push("revoked".to_owned());
        }
        self.summary = parts.join(", ");
        self
    }
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
        Ok(page
            .grants
            .into_iter()
            .map(Delivery::with_summary)
            .collect())
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
    /// `bytes` as a person reads it.
    #[serde(skip)]
    pub size: String,
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
        let mut listing: Library = client.admin_get(
            &format!("/api/admin/outbound-files?directory={query}"),
            cookie,
        )?;
        for file in &mut listing.files {
            file.size = crate::error::human_bytes(file.bytes);
        }
        Ok(listing)
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
            delivery: issued.grant.with_summary(),
        })
    })
}

/// Bytes per outbound chunk: the web sender's size, half the server's cap.
pub const UPLOAD_CHUNK: u64 = 8 * 1024 * 1024;

/// A shell's sink for upload progress. Called from the core's thread.
#[uniffi::export(with_foreign)]
pub trait UploadListener: Send + Sync {
    fn update(&self, view: UploadView);
}

/// Where an upload to the library stands. Computed here, never in a shell.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UploadView {
    /// The library path of the file moving now, or the last one moved.
    pub path: String,
    pub moved_bytes: u64,
    pub total_bytes: u64,
    pub files_done: u64,
    pub files_total: u64,
    /// The library paths landed so far, in order; the whole upload once
    /// `files_done` reaches `files_total`.
    pub landed: Vec<String>,
    /// The one line a screen shows: "Uploading reel.mov, 1.2 GB of 4.0 GB
    /// (2 of 5 files)", then "Added 5 files to the port, 4.0 GB".
    pub status: String,
}

impl UploadView {
    fn status(&self) -> String {
        let files = |count: u64| {
            if count == 1 {
                "1 file".to_owned()
            } else {
                format!("{count} files")
            }
        };
        if self.files_done == self.files_total {
            return format!(
                "Added {} to the port, {}",
                files(self.files_total),
                human_bytes(self.total_bytes)
            );
        }
        let name = self.path.rsplit('/').next().unwrap_or(&self.path);
        let mut line = format!(
            "Uploading {name}, {} of {}",
            human_bytes(self.moved_bytes),
            human_bytes(self.total_bytes)
        );
        if self.files_total > 1 {
            line.push_str(&format!(
                " ({} of {} files)",
                self.files_done + 1,
                self.files_total
            ));
        }
        line
    }
}

/// Uploads a drop (files, and folders with everything under them) into the
/// library under `into` (the UTC date when empty, for the CLI; a shell
/// names the local day), and returns the library files made. A folder keeps
/// its name as the top component, as a drop does. One call takes the whole
/// drop, so one view and one status line span it. Files go up in [`UPLOAD_CHUNK`]
/// pieces under one upload id per file. Requests retried in this call keep
/// that id; a new call starts a fresh stage. A file published before its
/// reply was lost is refused as already on the port, which it is. `stop` is
/// read between chunks. Every view handed to `listener` carries the library
/// paths landed so far, so a failure or a cancel midway still tells the
/// shell what is on the port.
///
/// # Errors
/// [`Error::NotSignedIn`], [`Error::AlreadyOnPort`] for a path the library
/// holds or a delivery serves, [`Error::TooLargeForPort`], [`Error::Cancelled`]
/// when `stop` says so, a read failure, or a network failure.
pub fn upload(
    paths: &[String],
    into: &str,
    stop: &dyn Fn() -> bool,
    listener: &dyn UploadListener,
) -> Result<Vec<LibraryFile>> {
    let mut selected = Vec::new();
    for path in paths {
        transfer::collect(Path::new(path), &mut selected).map_err(|source| Error::Read {
            path: PathBuf::from(path),
            source,
        })?;
    }
    if selected.is_empty() {
        return Err(Error::Empty);
    }
    let folder = into.trim_matches('/');
    let folder = if folder.is_empty() {
        today()
    } else {
        folder.to_owned()
    };
    let mut sizes = Vec::with_capacity(selected.len());
    for file in &selected {
        sizes.push(
            std::fs::metadata(&file.source)
                .map_err(|source| read_failed(&file.source, source))?
                .len(),
        );
    }
    let total_bytes: u64 = sizes.iter().sum();
    let mut view = UploadView {
        path: String::new(),
        moved_bytes: 0,
        total_bytes,
        files_done: 0,
        files_total: selected.len() as u64,
        landed: Vec::new(),
        status: String::new(),
    };
    run(|client, cookie| {
        let mut made = Vec::with_capacity(selected.len());
        for (file, &bytes) in selected.iter().zip(&sizes) {
            let library_path = format!("{folder}/{}", file.relative);
            view.path.clone_from(&library_path);
            let done_before = view.moved_bytes;
            view.status = view.status();
            listener.update(view.clone());
            upload_file(
                client,
                cookie,
                &file.source,
                &library_path,
                bytes,
                stop,
                &mut |sent| {
                    view.moved_bytes = done_before + sent;
                    view.status = view.status();
                    listener.update(view.clone());
                },
            )?;
            view.moved_bytes = done_before + bytes;
            view.files_done += 1;
            view.landed.push(library_path.clone());
            made.push(LibraryFile {
                path: library_path,
                bytes,
                size: human_bytes(bytes),
            });
        }
        view.status = view.status();
        listener.update(view.clone());
        Ok(made)
    })
}

fn upload_file(
    client: &Client,
    cookie: &str,
    source_path: &Path,
    library_path: &str,
    total: u64,
    stop: &dyn Fn() -> bool,
    progress: &mut dyn FnMut(u64),
) -> Result<()> {
    let route = format!("/api/admin/outbound-files?path={}", url_query(library_path));
    // Two 409s mean the path is taken (the file exists, or a delivery
    // serves it); any other 409 carries the port's own reason.
    let refused = |error: Error| match error {
        Error::Server {
            status: 409, body, ..
        } if body.contains("already exists") || body.contains("active grant") => {
            Error::AlreadyOnPort {
                path: library_path.to_owned(),
            }
        }
        Error::Server {
            status: 409, body, ..
        } => Error::PortRefused {
            path: library_path.to_owned(),
            reason: crate::error::server_reason(&body)
                .unwrap_or_else(|| "The port refused that upload.".to_owned()),
        },
        Error::Server { status: 413, .. } => Error::TooLargeForPort {
            path: library_path.to_owned(),
        },
        other => other,
    };
    if total == 0 {
        return client.admin_upload_empty(&route, cookie).map_err(refused);
    }
    // ponytail: cross-call resume needs a content identity, not file metadata.
    let upload_id = hex::encode(rand::random::<[u8; 32]>());
    let mut file =
        std::fs::File::open(source_path).map_err(|source| read_failed(source_path, source))?;
    let mut offset = 0;
    let mut chunk = Vec::new();
    while let Some((start, end)) = next_chunk(offset, total, UPLOAD_CHUNK) {
        if stop() {
            return Err(Error::Cancelled);
        }
        let len = usize::try_from(end - start + 1)
            .map_err(|_| Error::Other("chunk too large".to_owned()))?;
        chunk.resize(len, 0);
        file.seek(SeekFrom::Start(start))
            .and_then(|_| file.read_exact(&mut chunk))
            .map_err(|source| read_failed(source_path, source))?;
        match client
            .admin_upload_chunk(&route, cookie, &upload_id, start, end, total, chunk.clone())
            .map_err(refused)?
        {
            // `total` after any chunk: the stage already held the whole
            // file (a last chunk whose reply was lost) and the server has
            // now published it.
            ChunkReply::Stored { offset: next } if next == end + 1 || next == total => {
                offset = next
            }
            ChunkReply::Stored { offset: next } => {
                return Err(Error::Other(format!(
                    "the server stands at {next} after a chunk ending at {end}"
                )))
            }
            // The server publishes a stage that already holds the whole
            // file, so an offset at or past the end is a stage it should
            // never have.
            ChunkReply::Resume { offset: next } if next < total => offset = next,
            ChunkReply::Resume { offset: next } => {
                return Err(Error::Other(format!(
                    "the server holds {next} of the {total}-byte file but did not publish it"
                )))
            }
        }
        progress(offset);
    }
    Ok(())
}

fn read_failed(path: &Path, source: std::io::Error) -> Error {
    Error::Read {
        path: path.to_path_buf(),
        source,
    }
}

/// The next chunk of a file: `start` and the last byte's index, or None once
/// `offset` has reached `total`. The server's `Content-Range` is inclusive.
fn next_chunk(offset: u64, total: u64, size: u64) -> Option<(u64, u64)> {
    if offset >= total || size == 0 {
        return None;
    }
    let end = offset.saturating_add(size).min(total) - 1;
    Some((offset, end))
}

/// Today's date as `YYYY-MM-DD` in UTC: the folder a CLI upload lands in
/// when no other is named, so the library root stays a list of days and
/// projects rather than loose files. The shells pass their local day.
#[must_use]
pub fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    civil_date(secs / 86_400)
}

/// The civil date of a day count since 1970-01-01 (Howard Hinnant's
/// days-to-civil, proleptic Gregorian).
fn civil_date(days: u64) -> String {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}")
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
    fn chunks_cover_the_file_with_inclusive_ranges() {
        assert_eq!(next_chunk(0, 100, 16), Some((0, 15)));
        assert_eq!(next_chunk(16, 100, 16), Some((16, 31)));
        assert_eq!(next_chunk(96, 100, 16), Some((96, 99)));
        assert_eq!(next_chunk(100, 100, 16), None);
        assert_eq!(next_chunk(0, 16, 16), Some((0, 15)));
        assert_eq!(next_chunk(0, 1, 16), Some((0, 0)));
        assert_eq!(next_chunk(0, 0, 16), None);
        assert_eq!(next_chunk(0, 100, 0), None);
    }

    #[test]
    fn civil_dates_match_the_calendar() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(19_600), "2023-08-31");
        assert_eq!(civil_date(19_723), "2024-01-01");
        assert_eq!(civil_date(19_782), "2024-02-29");
        assert_eq!(civil_date(20_697), "2026-09-01");
    }

    #[test]
    fn the_status_line_reads_the_way_a_person_does() {
        let mut view = UploadView {
            path: "2026-09-06/dailies/reel.mov".to_owned(),
            moved_bytes: 1_200_000_000,
            total_bytes: 4_000_000_000,
            files_done: 1,
            files_total: 5,
            landed: vec!["2026-09-06/dailies/slate.mov".to_owned()],
            status: String::new(),
        };
        assert_eq!(
            view.status(),
            "Uploading reel.mov, 1.2 GB of 4.0 GB (2 of 5 files)"
        );
        view.files_total = 1;
        view.files_done = 0;
        assert_eq!(view.status(), "Uploading reel.mov, 1.2 GB of 4.0 GB");
        view.files_done = 1;
        view.moved_bytes = view.total_bytes;
        assert_eq!(view.status(), "Added 1 file to the port, 4.0 GB");
        view.files_total = 5;
        view.files_done = 5;
        assert_eq!(view.status(), "Added 5 files to the port, 4.0 GB");
    }

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
