//! The QUIC fetch path: probe the delivery's serve, mint a capability, fetch
//! the bundle over the wire, and materialize its files into the destination.
//!
//! A probe runs before any mint so a network that will not carry QUIC costs
//! the client its budget and no reserved ticket on the server; the caller then
//! falls back to HTTP. Once a mint has reserved a ticket the fetch is
//! committed, and a failure is an error rather than a silent HTTP retry.
//!
//! votport builds every grant entry as a direct object, so the fetched bundle
//! holds one object file per entry. Materializing copies each object to its
//! loose path while re-hashing it to the announced root, reusing the receive
//! path's name, existence, and temp-then-rename guards: a QUIC fetch is a
//! different transport, not a different trust boundary.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use vot_cli::authz::Holder;
use vot_cli::{fetch_bundle_with, parse_rendezvous, Error as VotError, FetchOptions};

use crate::api::Client;
use crate::error::{Error, Result};
use crate::identity::Device;
use crate::package::read_manifest;
use crate::progress::{Event, Observer};
use crate::receive::{local_path, local_path_of, write_verified, Delivery, Received, Resumed};
use crate::send_push::{probe_any, Probe};

/// Rails dialled at once. Matches the push default until the listener cap lands.
const FETCH_RAILS: usize = 4;

/// The outcome of an attempted fetch.
pub enum Outcome {
    /// The delivery was fetched and materialized.
    Fetched(Received),
    /// The delivery does not serve, or the serve did not answer the probe; the
    /// caller should receive over HTTP instead.
    Unreachable,
}

/// Fetches `delivery` into `dest` over QUIC, erroring rather than falling back
/// when the delivery does not serve. The smart [`crate::receive`] falls back to
/// HTTP; this is the fetch-only entry point tests and callers use to require
/// the QUIC path.
///
/// # Errors
/// As [`try_fetch`], plus an error when the delivery serves no fetch endpoint.
pub fn receive_over_fetch(
    base: &str,
    delivery: Delivery,
    device: &Device,
    dest: &Path,
    observer: &mut dyn Observer,
) -> Result<Received> {
    let client = Client::new(base)?;
    match try_fetch(&client, &delivery, device, dest, observer)? {
        Outcome::Fetched(received) => Ok(received),
        Outcome::Unreachable => Err(Error::Other(
            "the delivery does not serve a QUIC fetch".to_owned(),
        )),
    }
}

/// Attempts to fetch `delivery` into `dest`.
///
/// Returns [`Outcome::Unreachable`] only before a ticket is minted, so the
/// caller can fall back to HTTP; after the mint the fetch is committed.
///
/// # Errors
/// A missing or wrong password, a serve identity mismatch, a mint refusal, a
/// fetch failure, or a materialize failure.
pub fn try_fetch(
    client: &Client,
    delivery: &Delivery,
    device: &Device,
    dest: &Path,
    observer: &mut dyn Observer,
) -> Result<Outcome> {
    let mut metadata = client.outbound_metadata(&delivery.token, None)?;

    // A password delivery serves nothing until the password is proven; the
    // grant cookie the verify returns also authorizes the mint.
    let mut cookie: Option<String> = None;
    if metadata.has_password && !metadata.authorized {
        let password = delivery
            .password
            .as_deref()
            .ok_or(Error::PasswordRequired)?;
        let granted = client.verify_outbound(&delivery.token, password)?;
        metadata = client.outbound_metadata(&delivery.token, Some(&granted))?;
        cookie = Some(granted);
        if !metadata.authorized {
            return Err(Error::PasswordRequired);
        }
    }

    // A delivery without a fetch endpoint does not serve: fall back to HTTP.
    let Some(endpoint) = metadata.fetch.as_ref() else {
        return Ok(Outcome::Unreachable);
    };

    // Refuse a receive that would overwrite before reserving a fetch ticket,
    // the way the HTTP path refuses before downloading: a mint counts an
    // undelivered ticket against the delivery's download cap for the
    // capability's lifetime, so a refusal after the mint would lock the
    // delivery out. materialize re-checks on the authoritative manifest names.
    for file in &metadata.files {
        let path = local_path(dest, &file.name)?;
        if path.exists() {
            return Err(Error::Exists { path });
        }
    }

    let probe_digest = decode_digest(&endpoint.certificate_digest)?;
    let Ok(addresses) = parse_rendezvous(&endpoint.address) else {
        return Ok(Outcome::Unreachable);
    };
    let reachable = match probe_any(&addresses, probe_digest) {
        Probe::Reachable(address) => address,
        Probe::Unreachable => return Ok(Outcome::Unreachable),
        Probe::Mismatch => return Err(Error::Package(VotError::ServeIdentityMismatch)),
    };

    // The serve answered, so mint a capability and commit to the fetch.
    let mint = client.mint_fetch(&delivery.token, &device.holder_key_hex(), cookie.as_deref())?;
    let capability = base64_decode(&mint.capability)?;
    let holder = Arc::new(
        Holder::new(capability, device.signing_key()).map_err(|error| {
            Error::Other(format!(
                "the device key does not match the capability: {error:?}"
            ))
        })?,
    );
    let identity = decode_digest(&mint.certificate_digest)?;
    let pin = decode_digest(&mint.package_root)?;

    // Fetch into a bundle staged beside the destination, so the objects land on
    // the same filesystem the files will.
    // ponytail: the bundle is a full second copy on disk; fetch-to-loose or a
    // hardlink materialize is the upgrade when a large sequence needs it.
    let staging_parent = dest
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(staging_parent)?;
    let bundle_home = tempfile::Builder::new()
        .prefix(".votport-fetch-")
        .tempdir_in(staging_parent)?;
    let bundle = bundle_home.path().join("bundle");

    fetch_bundle_with(
        FetchOptions {
            address: reachable,
            holder: Some(holder),
            serve_identity: Some(identity),
            pin: Some(pin),
            rails: FETCH_RAILS,
            provers: None,
            extensions: BTreeSet::new(),
            progress: None,
        },
        &bundle,
    )?;

    let received = materialize(&bundle, dest, observer)?;
    Ok(Outcome::Fetched(received))
}

/// Copies each object a fetched bundle holds to its loose path, re-hashing to
/// the announced root. Refuses the whole bundle before writing a byte on a
/// packed entry, a name that would escape `dest`, or a file already present.
fn materialize(bundle: &Path, dest: &Path, observer: &mut dyn Observer) -> Result<Received> {
    let entries = read_manifest(bundle)?;
    let objects = bundle.join("objects");

    let planned = entries
        .iter()
        .map(|entry| local_path_of(dest, &entry.path).map(|path| (path, entry.root, entry.length)))
        .collect::<Result<Vec<_>>>()?;
    for (path, _, _) in &planned {
        if path.exists() {
            return Err(Error::Exists { path: path.clone() });
        }
    }

    fs::create_dir_all(dest)?;
    let mut files = Vec::with_capacity(planned.len());
    for (index, (path, root, length)) in planned.into_iter().enumerate() {
        let object = objects.join(object_name(&root));
        let mut source = |offset: u64| -> Result<Resumed> {
            let mut file = File::open(&object).map_err(|source| Error::Read {
                path: object.clone(),
                source,
            })?;
            if offset > 0 {
                file.seek(SeekFrom::Start(offset))
                    .map_err(|source| Error::Read {
                        path: object.clone(),
                        source,
                    })?;
            }
            Ok(Resumed {
                reader: Box::new(file),
                start: offset,
            })
        };
        write_verified(
            &mut source,
            &path,
            root,
            &hex::encode(root),
            length,
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

/// The bundle object file name for a root, mirroring vot-cli's crate-private
/// `package::layout::object_name`: the lowercase hex root with a `.obj` suffix.
fn object_name(root: &[u8; 32]) -> String {
    format!("{}.obj", hex::encode(root))
}

fn decode_digest(hex_digest: &str) -> Result<[u8; 32]> {
    hex::decode(hex_digest)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::Other(format!("{hex_digest:?} is not a 32-byte digest")))
}

fn base64_decode(value: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| Error::Other(format!("the capability is not valid base64: {error}")))
}

#[cfg(test)]
mod tests {
    use super::object_name;

    #[test]
    fn object_name_is_the_hex_root_with_an_obj_suffix() {
        let mut root = [0u8; 32];
        root[0] = 0xab;
        root[31] = 0x01;
        let name = object_name(&root);
        assert_eq!(name.len(), 64 + ".obj".len());
        assert!(name.starts_with("ab00"), "{name}");
        assert!(name.ends_with("01.obj"), "{name}");
    }
}
