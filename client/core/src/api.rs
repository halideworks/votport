//! The votport HTTP API, as the client calls it.
//!
//! A thin blocking wrapper over the request-token session protocol the web
//! sender uses: create, seal, pages, begin, chunks, finish, abort. Types
//! mirror the server's handlers in `server/src/api/upload.rs` and
//! `server/src/session.rs`; the field names are the wire contract.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A blocking client bound to one votport origin.
pub struct Client {
    http: reqwest::blocking::Client,
    base: String,
}

/// What `GET /api/r/{token}` tells a sender about a link.
#[derive(Debug, Clone, Deserialize)]
pub struct LinkInfo {
    #[serde(default)]
    pub label: Option<String>,
    pub needs_password: bool,
    pub usable: bool,
    #[serde(default)]
    pub authorized: bool,
    pub max_bytes: u64,
    pub chunk_bytes: u64,
    pub allow_hidden: bool,
    pub max_entries: usize,
    pub push: bool,
}

/// The package root a create announces. Entries travel through seal and pages.
#[derive(Debug, Clone, Serialize)]
pub struct PackageAnnouncement {
    pub suite: String,
    pub root: String,
    pub length: u64,
}

#[derive(Debug, Serialize)]
struct CreateSessionRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    package: PackageAnnouncement,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreatedSession {
    pub session: String,
    pub chunk_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct SealReply {
    pages: u64,
}

#[derive(Debug, Deserialize)]
struct PageReply {
    remaining_pages: u64,
}

/// One manifest entry as begin reports it: the resume authority.
#[derive(Debug, Clone, Deserialize)]
pub struct EntryInfo {
    pub index: usize,
    pub path: String,
    pub stored_as: String,
    pub bytes: u64,
    pub complete: bool,
    /// Bytes verified contiguously from zero: where a resume restarts.
    pub covered_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct BeginReply {
    entries: Vec<EntryInfo>,
}

/// What one chunk POST reports back.
#[derive(Debug, Clone, Deserialize)]
pub struct ChunkProgress {
    pub accepted: bool,
    pub replay: bool,
    pub covered_bytes: u64,
    pub total_bytes: u64,
    pub complete: bool,
    pub received: u64,
    /// The session was re-attached after a restart; call begin again.
    pub rebegin: bool,
}

/// One published file in a finish report.
#[derive(Debug, Clone, Deserialize)]
pub struct FileRecord {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub root: String,
    #[serde(default)]
    pub receipt: bool,
}

/// What finish reports when the drop is complete.
#[derive(Debug, Clone, Deserialize)]
pub struct FinishReport {
    pub upload_id: String,
    #[serde(default)]
    pub files: Vec<FileRecord>,
}

/// The receiver's push endpoint, from `GET /api/push-identity`, for the probe
/// a client runs before it reserves anything.
#[derive(Debug, Clone, Deserialize)]
pub struct PushIdentity {
    pub address: String,
    pub certificate_digest: String,
}

/// The package a push preflight announces: suite 1, the root, the length, and
/// the entry count.
#[derive(Debug, Clone, Serialize)]
pub struct PushPackageAnnouncement {
    pub suite: u64,
    pub root: String,
    pub length: u64,
    pub entries: u64,
}

#[derive(Debug, Serialize)]
struct CreatePushRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    holder_key: String,
    package: PushPackageAnnouncement,
}

/// What a push preflight mints: the session, the capability to present, the
/// address to dial, the certificate digest to pin, and the expiry.
#[derive(Debug, Clone, Deserialize)]
pub struct PushPreflight {
    pub session: String,
    pub capability: String,
    pub address: String,
    pub certificate_digest: String,
    pub expires_at: u64,
}

/// One deliverable file as `GET /api/s/{token}` reports it: the name it takes
/// on disk, its suite and root, its byte length, and the path to download it.
#[derive(Debug, Clone, Deserialize)]
pub struct OutboundFile {
    pub name: String,
    pub suite: String,
    pub root: String,
    pub bytes: u64,
    /// The path to GET, relative to the origin (`/api/s/{token}/files/{i}`, or
    /// `/api/s/{token}/file` for a single-file grant). Used verbatim.
    pub download_url: String,
}

/// Where a delivery's QUIC fetch dials, present in the metadata only when the
/// server's serve listener is bound.
#[derive(Debug, Clone, Deserialize)]
pub struct FetchEndpoint {
    pub address: String,
    pub certificate_digest: String,
}

/// What `GET /api/s/{token}` tells a receiver about a delivery. A
/// password-gated delivery reports only `has_password`/`authorized` until the
/// receiver verifies; then a second read carries the files.
#[derive(Debug, Clone, Deserialize)]
pub struct OutboundMetadata {
    pub has_password: bool,
    #[serde(default)]
    pub authorized: bool,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub files: Vec<OutboundFile>,
    /// The QUIC fetch endpoint, when the server serves; absent otherwise.
    #[serde(default)]
    pub fetch: Option<FetchEndpoint>,
}

#[derive(Debug, Serialize)]
struct VerifyOutboundRequest<'a> {
    password: &'a str,
}

#[derive(Debug, Serialize)]
struct FetchRequest<'a> {
    holder_key: &'a str,
}

/// What a fetch mint returns: the capability to present, where to dial, the
/// certificate to pin, and the package root the fetch must land on.
#[derive(Debug, Clone, Deserialize)]
pub struct FetchMint {
    pub capability: String,
    pub address: String,
    pub certificate_digest: String,
    pub package_root: String,
    pub expires_at: u64,
}

impl Client {
    /// A client for `base` (the origin, e.g. `https://drop.example`).
    ///
    /// # Errors
    /// A TLS or client build failure.
    pub fn new(base: impl Into<String>) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .user_agent(concat!("votport-client/", env!("CARGO_PKG_VERSION")))
            // No total-request timeout: an 8 MiB chunk on a slow uplink, or a
            // finish that rehashes a resumed file, legitimately runs long. A
            // dead connection is bounded by the connect timeout and by the
            // retry on a stalled request instead.
            .timeout(None)
            .connect_timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|source| Error::Http {
                url: "<client build>".to_owned(),
                source,
            })?;
        Ok(Self {
            http,
            base: base.into().trim_end_matches('/').to_owned(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Runs a request built fresh on each attempt, parsing its JSON body, with
    /// a bounded retry on a transient failure so a brief blip or a server
    /// restart during the transfer does not lose it. `idempotent` says whether
    /// replaying the request after its response was lost is safe.
    fn run<T: for<'de> Deserialize<'de>>(
        &self,
        what: &str,
        idempotent: bool,
        build: impl Fn() -> reqwest::blocking::RequestBuilder,
    ) -> Result<T> {
        retry(idempotent, || {
            let response = build().send().map_err(|source| Error::Http {
                url: what.to_owned(),
                source,
            })?;
            json(response, what)
        })
    }

    /// `GET /api/r/{token}`: what a sender may do with this link.
    ///
    /// # Errors
    /// A network failure or a non-success status.
    pub fn link_info(&self, token: &str) -> Result<LinkInfo> {
        let url = self.url(&format!("/api/r/{token}"));
        self.run("link info", true, || self.http.get(&url))
    }

    /// `POST /api/r/{token}/session`: opens an HTTP upload session.
    ///
    /// # Errors
    /// A network failure or a non-success status.
    pub fn create_session(
        &self,
        token: &str,
        password: Option<&str>,
        package: PackageAnnouncement,
    ) -> Result<CreatedSession> {
        let url = self.url(&format!("/api/r/{token}/session"));
        self.run("create session", false, || {
            self.http.post(&url).json(&CreateSessionRequest {
                password,
                package: package.clone(),
            })
        })
    }

    /// `POST /api/session/{sid}/seal`: the manifest seal. Returns the number
    /// of manifest pages the sender must then post.
    ///
    /// # Errors
    /// A network failure or a non-success status.
    pub fn seal(&self, session: &str, bytes: Vec<u8>) -> Result<u64> {
        let url = self.url(&format!("/api/session/{session}/seal"));
        let reply: SealReply =
            self.run("seal", false, || self.http.post(&url).body(bytes.clone()))?;
        Ok(reply.pages)
    }

    /// `POST /api/session/{sid}/page`: one manifest page. Returns how many
    /// pages remain.
    ///
    /// # Errors
    /// A network failure or a non-success status.
    pub fn page(&self, session: &str, bytes: Vec<u8>) -> Result<u64> {
        let url = self.url(&format!("/api/session/{session}/page"));
        let reply: PageReply =
            self.run("page", false, || self.http.post(&url).body(bytes.clone()))?;
        Ok(reply.remaining_pages)
    }

    /// `POST /api/session/{sid}/begin`: the per-entry resume authority.
    ///
    /// # Errors
    /// A network failure or a non-success status.
    pub fn begin(&self, session: &str) -> Result<Vec<EntryInfo>> {
        let url = self.url(&format!("/api/session/{session}/begin"));
        let reply: BeginReply = self.run("begin", true, || self.http.post(&url))?;
        Ok(reply.entries)
    }

    /// `POST /api/session/{sid}/chunk?entry=&offset=`: one 64 KiB-aligned
    /// chunk, its proof prefixed to its data, the proof length in the header.
    /// A replayed chunk after a retry is idempotent: the server reports it as
    /// a replay and the covered prefix does not go backwards.
    ///
    /// # Errors
    /// A network failure or a non-success status.
    pub fn chunk(
        &self,
        session: &str,
        entry: usize,
        offset: u64,
        proof: &[u8],
        data: &[u8],
    ) -> Result<ChunkProgress> {
        let url = self.url(&format!("/api/session/{session}/chunk"));
        self.run("chunk", true, || {
            let mut body = Vec::with_capacity(proof.len() + data.len());
            body.extend_from_slice(proof);
            body.extend_from_slice(data);
            self.http
                .post(&url)
                .query(&[("entry", entry.to_string()), ("offset", offset.to_string())])
                .header("X-Votport-Proof", proof.len().to_string())
                .body(body)
        })
    }

    /// `POST /api/session/{sid}/finish`. A 422 that says the drop is not
    /// fully received becomes [`Error::Rebegin`], which the caller answers by
    /// beginning again.
    ///
    /// # Errors
    /// A network failure, a rebegin, or another non-success status.
    pub fn finish(&self, session: &str) -> Result<FinishReport> {
        let url = self.url(&format!("/api/session/{session}/finish"));
        retry(false, || {
            let response = self.http.post(&url).send().map_err(|source| Error::Http {
                url: url.clone(),
                source,
            })?;
            let status = response.status();
            if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
                let body = response.text().unwrap_or_default();
                if body.contains("not fully received") {
                    return Err(Error::Rebegin);
                }
                return Err(Error::Server {
                    status: status.as_u16(),
                    what: "finish".to_owned(),
                    body,
                });
            }
            json(response, "finish")
        })
    }

    /// `POST /api/session/{sid}/abort`. Best effort: an unknown session still
    /// answers ok, so this is safe on any failure path.
    pub fn abort(&self, session: &str) {
        let url = self.url(&format!("/api/session/{session}/abort"));
        let _ = self.http.post(&url).send();
    }

    /// `GET /api/push-identity`: the receiver's push address and certificate
    /// digest, so a client can probe the carrier before it reserves anything.
    ///
    /// # Errors
    /// A network failure, or a non-success status (404 when push is off).
    pub fn push_identity(&self) -> Result<PushIdentity> {
        let url = self.url("/api/push-identity");
        self.run("push identity", true, || self.http.get(&url))
    }

    /// `POST /api/r/{token}/push`: reserves a push session and mints a
    /// capability for `holder_key`.
    ///
    /// # Errors
    /// A network failure or a non-success status.
    pub fn create_push_session(
        &self,
        token: &str,
        password: Option<&str>,
        holder_key: &str,
        package: PushPackageAnnouncement,
    ) -> Result<PushPreflight> {
        let url = self.url(&format!("/api/r/{token}/push"));
        self.run("create push session", false, || {
            self.http.post(&url).json(&CreatePushRequest {
                password,
                holder_key: holder_key.to_owned(),
                package: package.clone(),
            })
        })
    }

    /// `GET /api/s/{token}`: what a delivery holds. The no-query form returns
    /// every file, so the receiver needs no paging. `cookie`, when present, is
    /// the grant cookie a verify returned, echoed so a password delivery
    /// answers with its files.
    ///
    /// # Errors
    /// A network failure or a non-success status (404 for an unknown or
    /// expired delivery).
    pub fn outbound_metadata(&self, token: &str, cookie: Option<&str>) -> Result<OutboundMetadata> {
        let url = self.url(&format!("/api/s/{token}"));
        self.run("delivery metadata", true, || {
            with_cookie(self.http.get(&url), cookie)
        })
    }

    /// `POST /api/s/{token}/verify`: proves the delivery password. On success
    /// the server sets a grant cookie; this returns its `name=value` so the
    /// caller can echo it onto the metadata and download requests that follow.
    /// The cookie is not kept in a jar, so a many-file delivery never
    /// accumulates the per-file lease cookies the downloads also set.
    ///
    /// # Errors
    /// A network failure, a non-success status (401 for a wrong password), or
    /// a success that carried no grant cookie.
    pub fn verify_outbound(&self, token: &str, password: &str) -> Result<String> {
        let url = self.url(&format!("/api/s/{token}/verify"));
        // Idempotent: proving the password again only re-issues the cookie.
        retry(true, || {
            let response = self
                .http
                .post(&url)
                .json(&VerifyOutboundRequest { password })
                .send()
                .map_err(|source| Error::Http {
                    url: url.clone(),
                    source,
                })?;
            let status = response.status();
            if !status.is_success() {
                let body = response.text().unwrap_or_default();
                return Err(Error::Server {
                    status: status.as_u16(),
                    what: "delivery verify".to_owned(),
                    body,
                });
            }
            grant_cookie(&response)
                .ok_or_else(|| Error::Other("the delivery verify set no grant cookie".to_owned()))
        })
    }

    /// `GET <path>`: a delivery file's bytes from `offset`, streamed. `path` is
    /// a `download_url` from the metadata, used verbatim; `cookie` is the grant
    /// cookie for a password delivery. Returns the response and the byte offset
    /// its body actually starts at: `offset` when the server honored the range
    /// with 206, or 0 when it answered the whole file with 200. The caller
    /// reads the body incrementally.
    ///
    /// # Errors
    /// A network failure or a non-success status.
    pub fn download(
        &self,
        path: &str,
        cookie: Option<&str>,
        offset: u64,
    ) -> Result<(reqwest::blocking::Response, u64)> {
        let url = self.url(path);
        // The GET is idempotent, so a transient failure before the body starts
        // is retried; a break mid-stream is the caller's to handle by resuming.
        retry(true, || {
            let mut request = with_cookie(self.http.get(&url), cookie);
            if offset > 0 {
                request = request.header(reqwest::header::RANGE, format!("bytes={offset}-"));
            }
            let response = request.send().map_err(|source| Error::Http {
                url: url.clone(),
                source,
            })?;
            let status = response.status();
            if !status.is_success() {
                let body = response.text().unwrap_or_default();
                return Err(Error::Server {
                    status: status.as_u16(),
                    what: "download".to_owned(),
                    body,
                });
            }
            // 206 means the range was honored and the body starts at `offset`;
            // any other success is the whole file from zero.
            let start = if status == reqwest::StatusCode::PARTIAL_CONTENT {
                offset
            } else {
                0
            };
            Ok((response, start))
        })
    }

    /// `POST /api/s/{token}/fetch`: mints a QUIC fetch capability for the
    /// delivery, bound to `holder_key`, and says where to dial. `cookie` is
    /// the grant cookie for a password delivery.
    ///
    /// # Errors
    /// A network failure or a non-success status (404 when the server does not
    /// serve).
    pub fn mint_fetch(
        &self,
        token: &str,
        holder_key: &str,
        cookie: Option<&str>,
    ) -> Result<FetchMint> {
        let url = self.url(&format!("/api/s/{token}/fetch"));
        // Mints a capability and reserves a ticket, so not replayed.
        self.run("mint fetch", false, || {
            with_cookie(
                self.http.post(&url).json(&FetchRequest { holder_key }),
                cookie,
            )
        })
    }
}

/// Attaches `cookie` (a `name=value`) as the request's `Cookie` header, or
/// leaves the request untouched when there is none.
fn with_cookie(
    request: reqwest::blocking::RequestBuilder,
    cookie: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    match cookie {
        Some(value) => request.header(reqwest::header::COOKIE, value),
        None => request,
    }
}

/// The `name=value` of the first `Set-Cookie` a response carries, for the
/// caller to echo back. A verify sets exactly one (the grant cookie).
fn grant_cookie(response: &reqwest::blocking::Response) -> Option<String> {
    response
        .headers()
        .get(reqwest::header::SET_COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .next()
        .map(|pair| pair.trim().to_owned())
        .filter(|pair| !pair.is_empty())
}

/// A transient failure is retried until this much wall-clock has passed, so a
/// transfer survives a server restart: a rolling deploy takes longer than a
/// few backoff steps, and the web sender holds for fifteen seconds a step.
const RETRY_BUDGET: std::time::Duration = std::time::Duration::from_secs(90);

/// The longest a single backoff waits, so the budget is spent in many attempts
/// rather than a few long sleeps.
const RETRY_CAP: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether an error is worth retrying: a connection that could not be made or
/// stalled, or a server that is draining (503). A request whose bytes were
/// written but whose response was lost may have been applied server-side, so
/// it is retried only when replaying it is safe (`idempotent`). A refusal
/// (4xx other than a rebegin) is never retried.
fn is_retryable(error: &Error, idempotent: bool) -> bool {
    match error {
        Error::Http { source, .. } => {
            source.is_connect() || source.is_timeout() || (idempotent && source.is_request())
        }
        // 503 while draining, or 429 from a download rate limiter on an
        // idempotent GET. The budget rides out a brief burst; a delivery of
        // more files than the per-window cap needs resume, which is C7.
        // ponytail: no Retry-After honored (the server sends none); the
        // fixed budget is the ceiling until resume lands.
        Error::Server { status, .. } => *status == 503 || (idempotent && *status == 429),
        _ => false,
    }
}

/// Runs `attempt`, retrying a transient failure with exponential backoff until
/// [`RETRY_BUDGET`] elapses.
fn retry<T>(idempotent: bool, mut attempt: impl FnMut() -> Result<T>) -> Result<T> {
    let deadline = std::time::Instant::now() + RETRY_BUDGET;
    let mut delay = std::time::Duration::from_millis(200);
    loop {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(error)
                if is_retryable(&error, idempotent)
                    && std::time::Instant::now() + delay < deadline =>
            {
                std::thread::sleep(delay);
                delay = (delay * 2).min(RETRY_CAP);
            }
            Err(error) => return Err(error),
        }
    }
}

/// Reads a JSON body, turning a non-success status into [`Error::Server`].
fn json<T: for<'de> Deserialize<'de>>(
    response: reqwest::blocking::Response,
    what: &str,
) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        return Err(Error::Server {
            status: status.as_u16(),
            what: what.to_owned(),
            body,
        });
    }
    response.json().map_err(|source| Error::Http {
        url: what.to_owned(),
        source,
    })
}

/// Splits a request or delivery link into its origin and token. Accepts
/// `/r/<token>` and `/api/r/<token>` (send), `/s/<token>` and
/// `/api/s/<token>` (receive), with or without a trailing path, query, or
/// fragment.
///
/// # Errors
/// A link with none of those markers, or an empty origin or token.
pub fn split_link(link: &str) -> Result<(String, String)> {
    let trimmed = link.split(['?', '#']).next().unwrap_or(link);
    for marker in ["/api/r/", "/r/", "/api/s/", "/s/"] {
        if let Some(index) = trimmed.find(marker) {
            let base = &trimmed[..index];
            let rest = &trimmed[index + marker.len()..];
            let token = rest.split('/').next().unwrap_or("").trim();
            if base.is_empty() || token.is_empty() {
                break;
            }
            return Ok((base.to_owned(), token.to_owned()));
        }
    }
    Err(Error::BadLink {
        link: link.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::split_link;

    #[test]
    fn splits_request_links_into_origin_and_token() {
        let cases = [
            ("https://drop.example/r/ABC", "https://drop.example", "ABC"),
            (
                "https://drop.example/api/r/XYZ",
                "https://drop.example",
                "XYZ",
            ),
            ("https://drop.example/r/ABC/", "https://drop.example", "ABC"),
            (
                "https://drop.example/r/ABC?x=1#f",
                "https://drop.example",
                "ABC",
            ),
            (
                "http://127.0.0.1:8080/r/tok",
                "http://127.0.0.1:8080",
                "tok",
            ),
            ("https://drop.example/s/DEL", "https://drop.example", "DEL"),
            (
                "https://drop.example/api/s/DEL",
                "https://drop.example",
                "DEL",
            ),
            (
                "https://drop.example/s/DEL/?x=1",
                "https://drop.example",
                "DEL",
            ),
        ];
        for (link, base, token) in cases {
            let (got_base, got_token) = split_link(link).expect(link);
            assert_eq!(got_base, base, "{link}");
            assert_eq!(got_token, token, "{link}");
        }
        assert!(split_link("https://drop.example/verify").is_err());
        assert!(split_link("not a url").is_err());
    }
}
