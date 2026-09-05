//! One send, end to end: inspect the link, validate the drop, build the
//! manifest once, and move the bytes over push or HTTP.
//!
//! Push is tried first when the link offers it: a 2 second QUIC probe decides
//! whether the receiver's carrier is reachable before anything is reserved. A
//! network that will not carry QUIC falls back to the HTTP session path the
//! web sender uses.

use std::path::PathBuf;

use tempfile::TempDir;

use crate::api::{Client, FinishReport, LinkInfo};
use crate::error::{Error, Result};
use crate::identity::Device;
use crate::package::{self, Prepared};
use crate::progress::Observer;
use crate::send_push::Outcome;
use crate::{entries, send_http, send_push};

/// A drop to send: the link token, an optional password, and the files, each
/// as the relative path it takes in the package and the file that holds it.
pub struct Drop {
    pub token: String,
    pub password: Option<String>,
    pub files: Vec<Selected>,
}

/// One selected file: its package-relative path and the file on disk.
pub struct Selected {
    pub relative: String,
    pub source: PathBuf,
}

/// How a drop was sent.
pub enum Sent {
    /// Over the HTTP session path, with its finish report.
    Http(FinishReport),
    /// Over the QUIC push path; `files` were pushed.
    Push { files: usize },
}

/// The link, the built manifest, and the staging directory that holds it, ready
/// to send. The token and password ride along for the send calls.
struct Ready {
    client: Client,
    token: String,
    password: Option<String>,
    info: LinkInfo,
    prepared: Prepared,
    // The manifest lives here for the life of the send (a push assembles a
    // server that reads it); dropping this removes it.
    _staging: TempDir,
}

/// Inspects the link, validates the drop, and builds the manifest.
fn prepare(base: &str, drop: Drop) -> Result<Ready> {
    let client = Client::new(base)?;
    let info = client.link_info(&drop.token)?;
    if !info.usable {
        return Err(Error::LinkUnusable { token: drop.token });
    }
    if info.needs_password && drop.password.is_none() && !info.authorized {
        return Err(Error::PasswordRequired);
    }

    let mut admitted = Vec::with_capacity(drop.files.len());
    let mut rejected = Vec::new();
    for file in drop.files {
        match entries::admit(&file.relative, file.source, info.allow_hidden) {
            Ok(entry) => admitted.push(entry),
            Err(reject) => rejected.push(reject),
        }
    }
    if let Some(first) = rejected.first() {
        return Err(Error::Rejected {
            count: rejected.len(),
            first: first.clone(),
        });
    }
    if admitted.is_empty() {
        return Err(Error::Empty);
    }
    if admitted.len() > info.max_entries {
        return Err(Error::TooManyEntries {
            limit: info.max_entries,
        });
    }
    // Refuse an oversized drop before hashing, as the web sender does; the
    // server would otherwise refuse it at begin after the whole hash.
    let mut total: u64 = 0;
    for entry in &admitted {
        total += std::fs::symlink_metadata(&entry.source)
            .map_err(|source| Error::Read {
                path: entry.source.clone(),
                source,
            })?
            .len();
    }
    if total > info.max_bytes {
        return Err(Error::TooLarge {
            total,
            limit: info.max_bytes,
        });
    }

    let staging: TempDir = tempfile::Builder::new()
        .prefix("votport-manifest-")
        .tempdir()?;
    let manifest_root = staging.path().join("manifest-root");
    let prepared = package::build(admitted, &manifest_root)?;

    Ok(Ready {
        client,
        token: drop.token,
        password: drop.password,
        info,
        prepared,
        _staging: staging,
    })
}

/// Sends `drop` to the votport at `base`, preferring push when the link offers
/// it and the receiver's carrier answers a probe, falling back to HTTP.
///
/// # Errors
/// An unusable or password-protected link, a refused file, an empty or
/// oversized drop, a build failure, or a transport error.
pub fn send(base: &str, drop: Drop, device: &Device, observer: &mut dyn Observer) -> Result<Sent> {
    let ready = prepare(base, drop)?;
    if ready.info.push {
        match send_push::try_push(
            &ready.client,
            &ready.token,
            ready.password.as_deref(),
            device,
            &ready.prepared,
            observer,
        )? {
            Outcome::Pushed => {
                return Ok(Sent::Push {
                    files: usize::try_from(ready.prepared.summary.entries).unwrap_or(usize::MAX),
                })
            }
            Outcome::Unreachable => {}
        }
    }
    let report = send_http::send(
        &ready.client,
        &ready.token,
        ready.password.as_deref(),
        &ready.prepared,
        observer,
    )?;
    Ok(Sent::Http(report))
}

/// Sends `drop` over the HTTP session path only, never push. The end-to-end
/// test drives this directly.
///
/// # Errors
/// The same as [`send`], minus the push path.
pub fn send_http(base: &str, drop: Drop, observer: &mut dyn Observer) -> Result<FinishReport> {
    let ready = prepare(base, drop)?;
    send_http::send(
        &ready.client,
        &ready.token,
        ready.password.as_deref(),
        &ready.prepared,
        observer,
    )
}
