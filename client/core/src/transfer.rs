//! One send, end to end: inspect the link, validate the drop, build the
//! manifest, and move the bytes over HTTP.
//!
//! The push path (a QUIC probe, a preflight, and a carrier) arrives in PR 2
//! behind the wire feature; this path is the fallback the web sender uses and
//! works against any votport.

use std::path::PathBuf;

use tempfile::TempDir;

use crate::api::{Client, FinishReport};
use crate::error::{Error, Result};
use crate::progress::Observer;
use crate::{entries, package, send_http};

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

/// Sends `drop` to the votport at `base` over the HTTP session path.
///
/// # Errors
/// An unusable or password-protected link, a refused file, an empty or
/// oversized drop, a build failure, or a transport error.
pub fn send_http(base: &str, drop: Drop, observer: &mut dyn Observer) -> Result<FinishReport> {
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

    // The manifest is the only thing the client writes: a seal and pages, no
    // object bytes. A temp directory holds it for the life of the send.
    let staging: TempDir = tempfile::Builder::new()
        .prefix("votport-manifest-")
        .tempdir()?;
    let manifest_root = staging.path().join("manifest-root");
    let prepared = package::build(admitted, &manifest_root)?;

    send_http::send(
        &client,
        &drop.token,
        drop.password.as_deref(),
        &prepared,
        observer,
    )
}
