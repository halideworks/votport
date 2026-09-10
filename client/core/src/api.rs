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
    recipient_cookie: std::sync::Mutex<Option<String>>,
    route: Option<String>,
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
    route: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    package: PackageAnnouncement,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreatedSession {
    #[serde(default)]
    pub resume: bool,
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
    route: Option<&'a str>,
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
    #[serde(default)]
    pub grant_id: Option<String>,
    #[serde(default)]
    pub delivery_manifest: Option<String>,
    #[serde(default)]
    pub evidence_authorization: Option<crate::delivery_protocol::SignedChallenge>,
    #[serde(default)]
    pub receipt_key: Option<String>,
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
    fn outbound_cookie(
        &self,
        request: reqwest::blocking::RequestBuilder,
        cookie: Option<&str>,
    ) -> reqwest::blocking::RequestBuilder {
        let recipient = self
            .recipient_cookie
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let value = cookie
            .into_iter()
            .chain(recipient.as_deref())
            .collect::<Vec<_>>()
            .join("; ");
        with_cookie(request, Some(&value))
    }

    pub fn outbound_metadata_for_device(
        &self,
        token: &str,
        cookie: Option<&str>,
        device: Option<&crate::identity::Device>,
    ) -> Result<OutboundMetadata> {
        match self.outbound_metadata_with_holder(
            token,
            cookie,
            device.map(|device| device.holder_key_hex()).as_deref(),
        ) {
            Err(Error::Server {
                status: 403,
                ref body,
                ..
            }) if serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .is_some_and(|value| {
                    value.get("code").and_then(|v| v.as_str()) == Some("recipient_required")
                }) =>
            {
                let device = device.ok_or_else(|| Error::Other("this delivery requires an enrolled device key; enable writable application storage".into()))?;
                self.authorize_recipient(token, device)?;
                self.outbound_metadata_with_holder(token, cookie, Some(&device.holder_key_hex()))
            }
            result => result,
        }
    }

    fn authorize_recipient(&self, token: &str, device: &crate::identity::Device) -> Result<()> {
        let challenge: crate::delivery_protocol::SignedChallenge =
            self.run("recipient challenge", true, || {
                self.http
                    .post(self.url(&format!("/api/s/{token}/recipient-challenge")))
                    .timeout(std::time::Duration::from_secs(10))
                    .header("X-Votport", "1")
                    .json(&serde_json::json!({"holder": device.holder_key_hex()}))
            })?;
        if challenge.challenge.holder != device.holder_key_hex()
            || challenge.challenge.origin.trim_end_matches('/') != self.base
            || !challenge.verify(&challenge.issuer)
        {
            return Err(Error::Other(
                "recipient challenge does not match this device and server".into(),
            ));
        }
        let proof = crate::delivery_protocol::AccessProof::sign(challenge, &device.signing_key());
        let response = self
            .http
            .post(self.url(&format!("/api/s/{token}/recipient-verify")))
            .timeout(std::time::Duration::from_secs(10))
            .header("X-Votport", "1")
            .json(&proof)
            .send()
            .map_err(|e| Error::Other(e.without_url().to_string()))?;
        if !response.status().is_success() {
            return Err(Error::Other(
                "recipient device authorization was refused".into(),
            ));
        }
        let cookie = response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| value.split(';').next())
            .find(|pair| pair.starts_with("votport_recipient_"))
            .ok_or_else(|| Error::Other("recipient authorization returned no session".into()))?
            .to_owned();
        *self
            .recipient_cookie
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(cookie);
        Ok(())
    }

    pub(crate) fn base(&self) -> &str {
        &self.base
    }

    pub fn evidence_challenge(
        &self,
        token: &str,
        cookie: Option<&str>,
        holder: &str,
    ) -> Result<crate::delivery_protocol::SignedChallenge> {
        let response = self
            .outbound_cookie(
                self.http
                    .post(self.url(&format!("/api/s/{token}/evidence-challenge"))),
                cookie,
            )
            .timeout(std::time::Duration::from_secs(5))
            .header("X-Votport", "1")
            .json(&serde_json::json!({"holder": holder}))
            .send()
            .map_err(|e| Error::Other(e.without_url().to_string()))?;
        response
            .error_for_status()
            .map_err(|e| Error::Other(e.without_url().to_string()))?
            .json()
            .map_err(|e| Error::Other(e.to_string()))
    }

    pub fn submit_evidence(&self, evidence: &crate::delivery_protocol::Evidence) -> Result<()> {
        let response = self
            .http
            .post(self.url("/api/evidence"))
            .header("X-Votport", "1")
            .json(evidence)
            .send()
            .map_err(|e| Error::Other(e.without_url().to_string()))?;
        if !response.status().is_success() {
            return Err(Error::Server {
                status: response.status().as_u16(),
                what: "submit delivery acknowledgement".into(),
                body: String::new(),
            });
        }
        #[derive(Deserialize)]
        struct Recorded {
            id: String,
            recorded: bool,
        }
        let result: Recorded = response
            .json()
            .map_err(|e| Error::Other(e.without_url().to_string()))?;
        if !result.recorded || result.id != evidence.id() {
            return Err(Error::Other(
                "server did not confirm this acknowledgement".into(),
            ));
        }
        Ok(())
    }

    /// A client for `base` (the origin, e.g. `https://drop.example`).
    ///
    /// # Errors
    /// A TLS or client build failure.
    pub fn new(base: impl Into<String>) -> Result<Self> {
        Self::with_timeout(base, None)
    }

    /// Creates a peer sender with a bound on each HTTP request.
    ///
    /// # Errors
    /// TLS or HTTP client setup failure.
    pub fn for_route(base: impl Into<String>, route: String) -> Result<Self> {
        let mut client = Self::with_timeout(base, Some(std::time::Duration::from_secs(300)))?;
        client.route = Some(route);
        Ok(client)
    }

    pub(crate) fn is_route(&self) -> bool {
        self.route.is_some()
    }

    pub(crate) fn authentication(base: impl Into<String>) -> Result<Self> {
        Self::with_timeout(base, Some(std::time::Duration::from_secs(20)))
    }

    pub(crate) fn with_timeout(
        base: impl Into<String>,
        timeout: Option<std::time::Duration>,
    ) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("votport-client/", env!("CARGO_PKG_VERSION")))
            // Transfers can legitimately run long; only authentication uses
            // a total-request timeout.
            .timeout(timeout)
            .connect_timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|source| Error::Http {
                url: "<client build>".to_owned(),
                source,
            })?;
        Ok(Self {
            http,
            recipient_cookie: std::sync::Mutex::new(None),
            route: None,
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
                route: self.route.as_deref(),
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
                let body = error_body(response);
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
                route: self.route.as_deref(),
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
        self.outbound_metadata_with_holder(token, cookie, None)
    }

    fn outbound_metadata_with_holder(
        &self,
        token: &str,
        cookie: Option<&str>,
        holder: Option<&str>,
    ) -> Result<OutboundMetadata> {
        let url = self.url(&format!("/api/s/{token}"));
        self.run("delivery metadata", true, || {
            let request = self.outbound_cookie(self.http.get(&url), cookie);
            if let Some(holder) = holder {
                request.header("X-Votport-Device", holder)
            } else {
                request
            }
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
                let body = error_body(response);
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
    /// reads the body incrementally. `lease` retains only this file's download
    /// allowance across retries and must be reset for each new file.
    /// A partial response must match `offset`
    /// and the metadata's `total` length.
    ///
    /// # Errors
    /// A network failure, an unexpected status, or a mismatched byte range.
    pub fn download(
        &self,
        path: &str,
        cookie: Option<&str>,
        lease: &mut Option<String>,
        offset: u64,
        total: u64,
    ) -> Result<(reqwest::blocking::Response, u64)> {
        let url = self.url(path);
        // The GET is idempotent, so a transient failure before the body starts
        // is retried; a break mid-stream is the caller's to handle by resuming.
        retry(true, || {
            let cookies = cookie
                .into_iter()
                .chain(lease.as_deref())
                .collect::<Vec<_>>()
                .join("; ");
            let mut request = self.outbound_cookie(self.http.get(&url), Some(&cookies));
            if offset > 0 {
                request = request.header(reqwest::header::RANGE, format!("bytes={offset}-"));
            }
            let response = request.send().map_err(|source| Error::Http {
                url: url.clone(),
                source,
            })?;
            let status = response.status();
            if !status.is_success() {
                let body = error_body(response);
                return Err(Error::Server {
                    status: status.as_u16(),
                    what: "download".to_owned(),
                    body,
                });
            }
            let start = download_start(
                status,
                response
                    .headers()
                    .get(reqwest::header::CONTENT_RANGE)
                    .and_then(|value| value.to_str().ok()),
                offset,
                total,
            )?;
            if let Some(value) = response
                .headers()
                .get_all(reqwest::header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .filter_map(|value| value.split(';').next())
                .map(str::trim)
                .find(|pair| is_download_lease(pair))
            {
                *lease = Some(value.to_owned());
            }
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
            self.outbound_cookie(
                self.http.post(&url).json(&FetchRequest { holder_key }),
                cookie,
            )
        })
    }
}

fn download_start(
    status: reqwest::StatusCode,
    range: Option<&str>,
    offset: u64,
    total: u64,
) -> Result<u64> {
    if status == reqwest::StatusCode::OK {
        return Ok(0);
    }
    if status != reqwest::StatusCode::PARTIAL_CONTENT {
        return Err(Error::Other(format!("unexpected download status {status}")));
    }
    let parsed = range.and_then(|value| {
        let (start, rest) = value.strip_prefix("bytes ")?.split_once('-')?;
        let (end, length) = rest.split_once('/')?;
        let number = |value: &str| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit())
                .then(|| value.parse::<u64>().ok())
                .flatten()
        };
        Some((number(start)?, number(end)?, number(length)?))
    });
    if offset < total && parsed == Some((offset, total - 1, total)) {
        Ok(offset)
    } else {
        Err(Error::Other(
            "download response has an invalid byte range".to_owned(),
        ))
    }
}

/// The admin session cookie's name, as the server sets it.
const ADMIN_COOKIE: &str = "votport_admin";

impl Client {
    /// `POST /api/admin/login`: the admin session cookie (`name=value`) for
    /// `password`. Never retried: the server counts every attempt against
    /// the caller's address.
    ///
    /// # Errors
    /// [`Error::WrongPassword`] on a refusal, a network failure, or another
    /// non-success status (429 after too many refusals).
    pub fn admin_login(&self, password: &str) -> Result<String> {
        let url = self.url("/api/admin/login");
        let response = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "password": password }))
            .send()
            .map_err(|source| Error::Http {
                url: "sign in".to_owned(),
                source,
            })?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::WrongPassword);
        }
        if !status.is_success() {
            return Err(Error::Server {
                status: status.as_u16(),
                what: "sign in".to_owned(),
                body: error_body(response),
            });
        }
        set_cookie(&response, ADMIN_COOKIE)
            .ok_or_else(|| Error::Other("the sign-in set no session cookie".to_owned()))
    }

    /// An admin `GET` under the session `cookie`, parsed as JSON.
    ///
    /// # Errors
    /// [`Error::NotSignedIn`] when the server no longer honours the session,
    /// a network failure, or another non-success status.
    pub fn admin_get<T: for<'de> Deserialize<'de>>(&self, path: &str, cookie: &str) -> Result<T> {
        let url = self.url(path);
        self.run(path, true, || {
            with_cookie(self.http.get(&url), Some(cookie))
        })
        .map_err(signed_out)
    }

    /// An admin mutation under the session `cookie`, with the `X-Votport`
    /// header the server requires on every non-GET, parsed as JSON. Not
    /// retried: a replay could create a second link or grant.
    ///
    /// # Errors
    /// As [`Client::admin_get`].
    pub fn admin_send<T: for<'de> Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        path: &str,
        cookie: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T> {
        let url = self.url(path);
        let mut request =
            with_cookie(self.http.request(method, &url), Some(cookie)).header("X-Votport", "1");
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().map_err(|source| Error::Http {
            url: path.to_owned(),
            source,
        })?;
        json(response, path).map_err(signed_out)
    }

    pub(crate) fn automation(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let mut request = self
            .http
            .request(method, self.url(path))
            .bearer_auth(token)
            .header("X-Votport", "1")
            .timeout(std::time::Duration::from_secs(30 * 60));
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().map_err(|source| Error::Http {
            url: path.to_owned(),
            source,
        })?;
        json(response, path)
    }
}

/// The server's answer to one outbound chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkReply {
    /// The chunk landed; the stage now holds `offset` bytes.
    Stored { offset: u64 },
    /// The stage held `offset` bytes, not the chunk's start: the client
    /// continues from there (a replay after a lost response, or a resume).
    Resume { offset: u64 },
}

#[derive(Deserialize)]
struct ChunkBody {
    offset: Option<u64>,
}

impl Client {
    /// One chunk of an outbound library upload: `POST
    /// /api/admin/outbound-files?path=` with `Content-Range` and the
    /// upload id. Retried only when the connection never opened, timed out
    /// before a reply, or met a 503: the server compares the stage's length with the
    /// range and answers 409 with its offset when a chunk lands twice, but
    /// a replayed final chunk finds the file already published and gets the
    /// same 409 as a foreign file, with no offset to tell them apart.
    ///
    /// # Errors
    /// [`Error::NotSignedIn`], a 409 without an offset (the file exists or
    /// a delivery serves it), 413 over the port's limit, or a network
    /// failure.
    #[allow(clippy::too_many_arguments)]
    pub fn admin_upload_chunk(
        &self,
        path: &str,
        cookie: &str,
        upload_id: &str,
        start: u64,
        end: u64,
        total: u64,
        body: Vec<u8>,
    ) -> Result<ChunkReply> {
        let url = self.url(path);
        let result: Result<ChunkBody> = self.run(path, false, || {
            with_cookie(self.http.post(&url), Some(cookie))
                .header("X-Votport", "1")
                .header("X-Votport-Upload-Id", upload_id)
                .header(
                    reqwest::header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{total}"),
                )
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(body.clone())
        });
        match result {
            Ok(ChunkBody {
                offset: Some(offset),
            }) => Ok(ChunkReply::Stored { offset }),
            Ok(ChunkBody { offset: None }) => Err(Error::Other(
                "the server stored the chunk without saying where it stands".to_owned(),
            )),
            Err(Error::Server {
                status: 409, body, ..
            }) if offset_in(&body).is_some() => Ok(ChunkReply::Resume {
                offset: offset_in(&body).unwrap_or_default(),
            }),
            Err(error) => Err(signed_out(error)),
        }
    }

    /// An empty outbound file: the chunked route refuses a zero total, so
    /// the plain `POST` with no body writes it.
    ///
    /// # Errors
    /// As [`Client::admin_upload_chunk`].
    pub fn admin_upload_empty(&self, path: &str, cookie: &str) -> Result<()> {
        let url = self.url(path);
        let _: serde_json::Value = self
            .run(path, false, || {
                with_cookie(self.http.post(&url), Some(cookie))
                    .header("X-Votport", "1")
                    .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                    .header(reqwest::header::CONTENT_LENGTH, "0")
            })
            .map_err(signed_out)?;
        Ok(())
    }
}

/// The `offset` a 409 body names when the stage stands elsewhere.
fn offset_in(body: &str) -> Option<u64> {
    serde_json::from_str::<ChunkBody>(body).ok()?.offset
}

/// A 401 on an admin call means the session is gone.
fn signed_out(error: Error) -> Error {
    match error {
        Error::Server { status: 401, .. } => Error::NotSignedIn,
        other => other,
    }
}

/// The `name=value` of the `Set-Cookie` named `name`, when the response
/// carries one.
fn set_cookie(response: &reqwest::blocking::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .map(str::trim)
        .find(|pair| pair.starts_with(name) && pair[name.len()..].starts_with('='))
        .map(str::to_owned)
}

pub(crate) fn is_download_lease(pair: &str) -> bool {
    pair.split_once('=').is_some_and(|(name, value)| {
        name.starts_with("votport_d_")
            && !value.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.=".contains(&byte))
    })
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
        let body = error_body(response);
        return Err(Error::Server {
            status: status.as_u16(),
            what: what.to_owned(),
            body,
        });
    }
    let url = response.url().to_string();
    let bytes = bounded_body(response, 256 * 1024 * 1024).map_err(|error| {
        if let Error::Io(error) = error {
            if error
                .get_ref()
                .is_some_and(|source| source.is::<reqwest::Error>())
            {
                return Error::Http {
                    url,
                    source: *error
                        .into_inner()
                        .expect("checked source")
                        .downcast::<reqwest::Error>()
                        .expect("checked type"),
                };
            }
            Error::Io(error)
        } else {
            error
        }
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| Error::Other(format!("invalid {what} response: {error}")))
}

fn bounded_body(reader: impl std::io::Read, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Other("server response exceeds its limit".into()));
    }
    Ok(bytes)
}

fn error_body(response: reqwest::blocking::Response) -> String {
    use std::io::Read;
    let mut bytes = Vec::new();
    let _ = response.take(8192).read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Which way a link moves bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LinkKind {
    /// A request link (`/r/<token>`): the app sends to it.
    Request,
    /// A delivery link (`/s/<token>`): the app receives from it.
    Delivery,
}

/// A parsed votport link: the origin to talk to, what the link is, and its
/// token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub base: String,
    pub kind: LinkKind,
    pub token: String,
}

/// Splits a request or delivery link into its origin, kind, and token.
/// Accepts `/r/<token>` and `/api/r/<token>` (send), `/s/<token>` and
/// `/api/s/<token>` (receive), with or without a trailing path, query, or
/// fragment.
///
/// # Errors
/// A link with none of those markers, or an empty origin or token.
pub fn split_link(link: &str) -> Result<Link> {
    let trimmed = link.split(['?', '#']).next().unwrap_or(link);
    for (marker, kind) in [
        ("/api/r/", LinkKind::Request),
        ("/r/", LinkKind::Request),
        ("/api/s/", LinkKind::Delivery),
        ("/s/", LinkKind::Delivery),
    ] {
        if let Some(index) = trimmed.find(marker) {
            let base = &trimmed[..index];
            let rest = &trimmed[index + marker.len()..];
            let token = rest.split('/').next().unwrap_or("").trim();
            if base.is_empty() || token.is_empty() {
                break;
            }
            return Ok(Link {
                base: base.to_owned(),
                kind,
                token: token.to_owned(),
            });
        }
    }
    Err(Error::BadLink {
        link: link.to_owned(),
    })
}

/// [`split_link`], refusing a link of the other kind with a message that
/// names the screen it belongs to.
///
/// # Errors
/// As [`split_link`], or a link of the wrong kind.
pub fn split_link_as(link: &str, kind: LinkKind) -> Result<Link> {
    let parsed = split_link(link)?;
    if parsed.kind != kind {
        return Err(Error::WrongLink {
            link: link.to_owned(),
            kind: parsed.kind,
        });
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::{split_link, split_link_as, LinkKind};
    use crate::error::Error;

    #[test]
    fn response_body_limits_accept_the_boundary_and_refuse_excess() {
        assert_eq!(super::bounded_body(&b"{}"[..], 2).unwrap(), b"{}");
        assert!(super::bounded_body(&b"{}x"[..], 2).is_err());
        assert!(super::bounded_body(std::io::empty(), 0).unwrap().is_empty());
    }

    #[test]
    fn stalled_json_body_keeps_its_network_error_and_retries() {
        use std::io::{BufRead, BufReader, Write};
        use std::time::Duration;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for attempt in 0..2 {
                let mut stream = (0..400)
                    .find_map(|_| {
                        if let Ok((stream, _)) = listener.accept() {
                            Some(stream)
                        } else {
                            std::thread::sleep(Duration::from_millis(5));
                            None
                        }
                    })
                    .expect("retry reached the server");
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request = BufReader::new(&stream);
                for _ in 0..64 {
                    let mut line = String::new();
                    assert!(request.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{",
                    )
                    .unwrap();
                if attempt == 0 {
                    std::thread::sleep(Duration::from_millis(200));
                } else {
                    stream.write_all(b"}").unwrap();
                }
            }
        });
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        let mut attempts = 0;
        let value: serde_json::Value = super::retry(true, || {
            attempts += 1;
            assert!(
                attempts <= 2,
                "retry must terminate after the successful response"
            );
            let result = super::json(http.get(&url).send().unwrap(), "session");
            if attempts == 1 {
                assert!(matches!(&result, Err(Error::Http { source, .. }) if source.is_timeout()));
            }
            result
        })
        .unwrap();
        assert_eq!(value, serde_json::json!({}));
        assert_eq!(attempts, 2);
        server.join().unwrap();
    }

    #[test]
    fn credential_posts_do_not_follow_redirects() {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        use std::time::Duration;

        fn serve(listener: TcpListener, response: String, done: Arc<AtomicBool>) -> bool {
            listener.set_nonblocking(true).unwrap();
            for _ in 0..400 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut reader = BufReader::new(&stream);
                        let mut length = 0;
                        for _ in 0..64 {
                            let mut line = String::new();
                            assert!(reader.read_line(&mut line).unwrap() > 0);
                            if line == "\r\n" {
                                break;
                            }
                            if let Some(value) =
                                line.to_ascii_lowercase().strip_prefix("content-length:")
                            {
                                length = value.trim().parse::<usize>().unwrap();
                            }
                        }
                        assert!(length < 1024);
                        reader.read_exact(&mut vec![0; length]).unwrap();
                        stream.write_all(response.as_bytes()).unwrap();
                        return true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if done.load(Ordering::Relaxed) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            }
            false
        }

        for status in [307, 308, 301, 302, 303] {
            let origin = TcpListener::bind("127.0.0.1:0").unwrap();
            let destination = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", origin.local_addr().unwrap());
            let location = format!("http://{}/stolen", destination.local_addr().unwrap());
            let done = Arc::new(AtomicBool::new(false));
            let first_done = Arc::clone(&done);
            let first = std::thread::spawn(move || {
                serve(origin, format!("HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), first_done)
            });
            let second_done = Arc::clone(&done);
            let second = std::thread::spawn(move || {
                serve(destination, "HTTP/1.1 200 OK\r\nSet-Cookie: votport_admin=redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(), second_done)
            });
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = super::Client::new(base)
                    .unwrap()
                    .admin_login("secret-password");
                done.store(true, Ordering::Relaxed);
                sender.send(result).unwrap();
            });
            let result = receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("login stalled");
            assert!(first.join().unwrap(), "origin was not contacted");
            assert!(
                !second.join().unwrap(),
                "{status} contacted a second origin"
            );
            assert!(
                matches!(result, Err(Error::Server { status: actual, .. }) if actual == status),
                "{result:?}"
            );
        }
    }

    #[test]
    fn download_responses_match_the_requested_range() {
        for (status, range, offset, total, expected) in [
            (200, None, 2, 4, Some(0)),
            (200, None, 0, 0, Some(0)),
            (206, Some("bytes 2-3/4"), 2, 4, Some(2)),
            (206, Some("bytes 0-3/4"), 0, 4, Some(0)),
            (206, Some("bytes 02-03/04"), 2, 4, Some(2)),
            (206, None, 2, 4, None),
            (206, Some("bytes 0-3/4"), 2, 4, None),
            (206, Some("bytes 2-2/4"), 2, 4, None),
            (206, Some("bytes 2-3/5"), 2, 4, None),
            (206, Some("bytes 2-3/*"), 2, 4, None),
            (206, Some("items 2-3/4"), 2, 4, None),
            (206, Some("bytes 2-3"), 2, 4, None),
            (206, Some("bytes 2/3/4"), 2, 4, None),
            (206, Some("bytes x-3/4"), 2, 4, None),
            (206, Some("bytes 2-x/4"), 2, 4, None),
            (206, Some("bytes +2-3/4"), 2, 4, None),
            (206, Some("bytes 2-+3/4"), 2, 4, None),
            (206, Some("bytes 2-3/+4"), 2, 4, None),
            (206, Some("bytes 18446744073709551616-3/4"), 2, 4, None),
            (206, Some("bytes 2-18446744073709551616/4"), 2, 4, None),
            (206, Some("bytes 2-3/18446744073709551616"), 2, 4, None),
            (206, Some("bytes -3/4"), 2, 4, None),
            (206, Some("bytes 2-/4"), 2, 4, None),
            (206, Some("bytes 2-3/"), 2, 4, None),
            (206, Some("bytes 4-3/4"), 4, 4, None),
            (206, Some("bytes 5-3/4"), 5, 4, None),
            (206, Some("bytes 0-0/0"), 0, 0, None),
            (201, None, 2, 4, None),
            (202, None, 2, 4, None),
            (204, None, 2, 4, None),
            (205, None, 2, 4, None),
        ] {
            assert_eq!(
                super::download_start(
                    reqwest::StatusCode::from_u16(status).unwrap(),
                    range,
                    offset,
                    total
                )
                .ok(),
                expected,
                "{status} {range:?} at {offset}/{total}"
            );
        }
    }

    #[test]
    fn invalid_download_responses_preserve_the_partial() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::time::Duration;
        for response in [
            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-1/4\r\nContent-Length: 2\r\nConnection: close\r\n\r\ncd",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                for _ in 0..400 {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                            stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                            let mut reader = BufReader::new(&stream);
                            for _ in 0..64 {
                                let mut line = String::new();
                                assert!(reader.read_line(&mut line).unwrap() > 0);
                                if line == "\r\n" { break; }
                            }
                            stream.write_all(response.as_bytes()).unwrap();
                            return;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
                        Err(error) => panic!("accept failed: {error}"),
                    }
                }
                panic!("download never connected");
            });
            let client = super::Client {
                http: reqwest::blocking::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build().unwrap(),
                base,
                recipient_cookie: std::sync::Mutex::new(None),
                route: None,
            };
            let dir = tempfile::tempdir().unwrap();
            let destination = dir.path().join("file");
            let partial = dir.path().join(".vot-file.journal");
            std::fs::write(&partial, b"ab").unwrap();
            let (sender, receiver) = std::sync::mpsc::channel();
            let target = destination.clone();
            std::thread::spawn(move || {
                let result = crate::receive::write_verified(&mut |offset| {
                let (response, start) = client.download("/file", None, &mut None, offset, 4)?;
                Ok(crate::receive::Resumed { reader: Box::new(response), start })
            }, &target, [0; 32], "unused", 4, 0, &mut crate::progress::Silent);
                let _ = sender.send(result);
            });
            let result = receiver.recv_timeout(Duration::from_secs(5)).expect("download stalled");
            server.join().unwrap();
            assert_eq!(std::fs::read(partial).unwrap(), b"ab");
            assert!(matches!(result, Err(Error::Other(_))), "{result:?}");
            assert!(!destination.exists());
        }
    }

    #[test]
    fn splits_request_links_into_origin_and_token() {
        use LinkKind::{Delivery, Request};
        let cases = [
            (
                "https://drop.example/r/ABC",
                "https://drop.example",
                Request,
                "ABC",
            ),
            (
                "https://drop.example/api/r/XYZ",
                "https://drop.example",
                Request,
                "XYZ",
            ),
            (
                "https://drop.example/r/ABC/",
                "https://drop.example",
                Request,
                "ABC",
            ),
            (
                "https://drop.example/r/ABC?x=1#f",
                "https://drop.example",
                Request,
                "ABC",
            ),
            (
                "http://127.0.0.1:8080/r/tok",
                "http://127.0.0.1:8080",
                Request,
                "tok",
            ),
            (
                "https://drop.example/s/DEL",
                "https://drop.example",
                Delivery,
                "DEL",
            ),
            (
                "https://drop.example/api/s/DEL",
                "https://drop.example",
                Delivery,
                "DEL",
            ),
            (
                "https://drop.example/s/DEL/?x=1",
                "https://drop.example",
                Delivery,
                "DEL",
            ),
            // The first marker wins, so a host or path that happens to hold
            // the other letter does not change the kind.
            (
                "https://s.example/r/ABC/s/x",
                "https://s.example",
                Request,
                "ABC",
            ),
        ];
        for (link, base, kind, token) in cases {
            let got = split_link(link).expect(link);
            assert_eq!(
                (got.base.as_str(), got.kind, got.token.as_str()),
                (base, kind, token),
                "{link}"
            );
        }
        assert!(split_link("https://drop.example/verify").is_err());
        assert!(split_link("not a url").is_err());
    }

    #[test]
    fn a_link_of_the_other_kind_is_refused_by_name() {
        let wrong = split_link_as("https://drop.example/s/DEL", LinkKind::Request);
        assert!(
            matches!(
                wrong,
                Err(Error::WrongLink {
                    kind: LinkKind::Delivery,
                    ..
                })
            ),
            "{wrong:?}"
        );
        assert!(split_link_as("https://drop.example/r/ABC", LinkKind::Request).is_ok());
    }
}
