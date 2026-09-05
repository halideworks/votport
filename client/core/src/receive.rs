//! The receive path: pull a votport delivery to a local directory.
//!
//! A delivery is a grant the operator published. [`receive`] prefers a QUIC
//! fetch (in `fetch.rs`) and falls back to the HTTP path here. The HTTP path
//! reads the delivery's metadata, proves a password if one is set, then
//! downloads each file while hashing its bytes; a file lands only after its
//! bytes hash to the root the delivery announced. The announced name is a
//! server value joined to a local directory, so it is validated as an entry
//! name before any byte is written, which is the one place a bad name could
//! escape the destination. The temp-then-rename and existence guards are
//! shared with the fetch path through [`write_verified`] and [`local_path_of`].

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use vot_manifest::{Component, PackagePath};
use vot_object::{ObjectBuilder, Suite};

use crate::api::Client;
use crate::entries::admit;
use crate::error::{Error, Result};
use crate::fetch::{try_fetch, Outcome};
use crate::identity::Device;
use crate::progress::{Event, Observer};

/// A delivery to fetch: the token from the share link and its password, if any.
pub struct Delivery {
    pub token: String,
    pub password: Option<String>,
}

/// What a receive landed: the files written, in delivery order.
#[derive(Debug, Clone)]
pub struct Received {
    pub files: Vec<PathBuf>,
}

/// The suite string the client fetches. The server reports `"blake3"` for
/// every delivery it builds.
const BLAKE3: &str = "blake3";

/// How much of a download is read at once before it is hashed and written.
const READ_CHUNK: usize = 64 * 1024;

/// Fetches `delivery` from `base` into `dest`, over QUIC when the delivery
/// offers a fetch endpoint and the serve answers, over HTTP otherwise.
///
/// # Errors
/// As [`receive_over_http`], plus a fetch failure once a fetch is committed.
pub fn receive(
    base: &str,
    delivery: Delivery,
    device: &Device,
    dest: &Path,
    observer: &mut dyn Observer,
) -> Result<Received> {
    let client = Client::new(base)?;
    match try_fetch(&client, &delivery, device, dest, observer)? {
        Outcome::Fetched(received) => Ok(received),
        Outcome::Unreachable => receive_over_http(base, delivery, dest, observer),
    }
}

/// Fetches `delivery` from `base` into `dest` over HTTP, verifying every file.
///
/// # Errors
/// A network failure, a missing or wrong password, a delivery whose suite the
/// client does not fetch, a name that would escape `dest`, a read or write
/// failure, or a file whose bytes do not hash to its announced root.
pub fn receive_over_http(
    base: &str,
    delivery: Delivery,
    dest: &Path,
    observer: &mut dyn Observer,
) -> Result<Received> {
    let client = Client::new(base)?;
    let mut metadata = client.outbound_metadata(&delivery.token, None)?;

    // The grant cookie a verify returns, echoed onto the reads and downloads
    // that follow. It is not kept in a jar, so a many-file delivery does not
    // accumulate the per-file lease cookies the downloads set.
    let mut cookie: Option<String> = None;
    if metadata.has_password && !metadata.authorized {
        let password = delivery
            .password
            .as_deref()
            .ok_or(Error::PasswordRequired)?;
        let granted = client.verify_outbound(&delivery.token, password)?;
        // The verified cookie authorizes a second read, which carries the
        // files the pre-password read withheld.
        metadata = client.outbound_metadata(&delivery.token, Some(&granted))?;
        cookie = Some(granted);
        if !metadata.authorized {
            return Err(Error::PasswordRequired);
        }
    }

    // Resolve, validate, and check every file before writing a byte, so the
    // whole delivery is refused up front rather than landing some files and
    // failing on a later one: a suite the client does not fetch, a root that
    // is not a 32-byte hash, a name that would escape the destination, or a
    // file already present that a receive would overwrite.
    let planned = metadata
        .files
        .iter()
        .map(|file| {
            if file.suite != BLAKE3 {
                return Err(Error::UnknownSuite {
                    suite: file.suite.clone(),
                });
            }
            let root = decode_root(&file.root)?;
            let path = local_path(dest, &file.name)?;
            Ok((file, path, root))
        })
        .collect::<Result<Vec<_>>>()?;
    for (_, path, _) in &planned {
        if path.exists() {
            return Err(Error::Exists { path: path.clone() });
        }
    }

    fs::create_dir_all(dest)?;
    let cookie = cookie.as_deref();
    let mut files = Vec::with_capacity(planned.len());
    for (index, (file, path, root)) in planned.into_iter().enumerate() {
        let mut response = client.download(&file.download_url, cookie)?;
        write_verified(
            &mut response,
            &path,
            root,
            &file.root,
            file.bytes,
            index,
            observer,
        )?;
        observer.event(Event::FileVerified {
            index,
            path: path.display().to_string(),
        });
        files.push(path);
    }
    observer.event(Event::Finished { files: files.len() });
    Ok(Received { files })
}

/// Streams `reader` into `destination`, hashing as it writes, and lands it
/// only if its `total` bytes hash to the announced root. The byte source is
/// abstract: an HTTP download for a receive, an object file for a fetch.
pub(crate) fn write_verified(
    reader: &mut dyn Read,
    destination: &Path,
    announced: [u8; 32],
    announced_hex: &str,
    total: u64,
    index: usize,
    observer: &mut dyn Observer,
) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write to a sibling temporary and rename on success, so a failed or
    // unverified stream never leaves a partial file at the real name. Every
    // failure path from here removes the temporary.
    let temporary = destination.with_extension(format!("part.{}", std::process::id()));
    let landed = (|| -> Result<()> {
        let mut builder = ObjectBuilder::new(Suite::Blake3Bao64, Some(total))?;
        let mut sink = File::create(&temporary).map_err(|source| Error::Read {
            path: temporary.clone(),
            source,
        })?;
        hash_copy(reader, &mut builder, &mut sink, total, index, observer)?;
        sink.sync_all()?;
        // The handle must close before the rename: Windows refuses to rename
        // a file that is still open.
        drop(sink);
        verify_and_rename(builder, destination, announced, announced_hex, &temporary)
    })();
    if landed.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    landed
}

/// Finishes the hash, checks it against the announced root, and renames the
/// temporary into place only if it matches and nothing has appeared at the
/// destination since the up-front check.
fn verify_and_rename(
    builder: ObjectBuilder,
    destination: &Path,
    announced: [u8; 32],
    announced_hex: &str,
    temporary: &Path,
) -> Result<()> {
    let prepared = builder.finish()?;
    let got = prepared.object_id().root;
    if !root_matches(&got, &announced) {
        return Err(Error::Verify {
            path: destination.to_path_buf(),
            announced: announced_hex.to_owned(),
            got: hex::encode(got),
        });
    }
    // The up-front check ran before any download; re-check here so a file that
    // appeared meanwhile (a case-insensitive sibling on macOS or Windows, or
    // another process) is not silently replaced by the clobbering rename.
    if destination.exists() {
        return Err(Error::Exists {
            path: destination.to_path_buf(),
        });
    }
    fs::rename(temporary, destination)?;
    Ok(())
}

/// Whether hashed bytes match the announced root. Split out so the compare is
/// exercised directly, not only through a full download that always matches.
fn root_matches(got: &[u8; 32], announced: &[u8; 32]) -> bool {
    got == announced
}

/// Reads `reader` in chunks, feeding each to the hasher and the file.
fn hash_copy(
    reader: &mut dyn Read,
    builder: &mut ObjectBuilder,
    sink: &mut File,
    total: u64,
    index: usize,
    observer: &mut dyn Observer,
) -> Result<()> {
    let mut buffer = vec![0u8; READ_CHUNK];
    let mut received = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        builder.update(chunk)?;
        sink.write_all(chunk)?;
        received = received.saturating_add(read as u64);
        observer.event(Event::Downloading {
            index,
            received,
            total,
        });
    }
    Ok(())
}

/// Joins a delivery-announced name to `dest`, refusing anything that would
/// escape it. The name is validated as an entry (no `..`, no separators in a
/// component, no reserved or non-portable shape) with hidden names allowed, so
/// a delivered dotfile lands while a traversal cannot.
pub(crate) fn local_path(dest: &Path, name: &str) -> Result<PathBuf> {
    let entry = admit(name, PathBuf::new(), true).map_err(|rejected| Error::BadName {
        name: name.to_owned(),
        reason: rejected.reason,
    })?;
    let mut path = dest.to_path_buf();
    for component in entry.path.iter() {
        match component {
            Component::Text(text) => path.push(text),
            Component::Bytes(_) => {
                return Err(Error::Other(format!(
                    "the delivery named a file whose path is not valid UTF-8: {name:?}"
                )))
            }
        }
    }
    Ok(path)
}

/// Joins a bundle manifest's package path to `dest`, refused the same way as a
/// delivery-announced name. A fetched manifest was built with the portable
/// profile but not votport's own name policy, so it is re-checked here.
pub(crate) fn local_path_of(dest: &Path, path: &PackagePath) -> Result<PathBuf> {
    let mut parts = Vec::new();
    for component in path.iter() {
        match component {
            Component::Text(text) => parts.push(text.clone()),
            Component::Bytes(_) => {
                return Err(Error::Other(
                    "the bundle named a file whose path is not valid UTF-8".to_owned(),
                ))
            }
        }
    }
    local_path(dest, &parts.join("/"))
}

fn decode_root(hex_root: &str) -> Result<[u8; 32]> {
    hex::decode(hex_root)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::Other(format!("{hex_root:?} is not a 32-byte root")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_name_lands_under_the_destination() {
        let dest = Path::new("/out");
        assert_eq!(
            local_path(dest, "clips/a.mov").unwrap(),
            Path::new("/out/clips/a.mov")
        );
        assert_eq!(
            local_path(dest, "note.txt").unwrap(),
            Path::new("/out/note.txt")
        );
    }

    #[test]
    fn the_root_compare_accepts_only_an_exact_match() {
        let root = [7u8; 32];
        assert!(root_matches(&root, &root));
        let mut off_by_one = root;
        off_by_one[31] ^= 1;
        assert!(!root_matches(&root, &off_by_one));
    }

    #[test]
    fn a_traversing_or_absolute_name_is_refused() {
        let dest = Path::new("/out");
        // A parent reference, a component that is a separator, and a reserved
        // staging name all fail before any byte is written.
        assert!(local_path(dest, "../escape").is_err());
        assert!(local_path(dest, "a/../../etc/passwd").is_err());
        assert!(local_path(dest, ".vot-tenants.stage").is_err());
        // An absolute path's leading empty component is dropped, so it cannot
        // reroot; what remains still lands under the destination.
        assert_eq!(
            local_path(dest, "/etc/passwd").unwrap(),
            Path::new("/out/etc/passwd")
        );
    }
}
