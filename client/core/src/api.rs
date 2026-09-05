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
        Error::Server { status, .. } => *status == 503,
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
