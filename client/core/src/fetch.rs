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
use crate::package::{package_path_string, read_manifest};
use crate::progress::{Event, Observer, PlannedFile};
use crate::receive::{local_path, local_path_of, write_verified, Delivery, Received, Resumed};
use crate::send_push::{probe_any, Probe};

/// Rails dialled at once. Matches the push default until the listener cap lands.
const FETCH_RAILS: usize = 4;

/// The resume store vot-cli writes inside a bundle while fetching and removes
/// once the bundle is whole. Its presence means a fetch owns the stage.
const RESUME_STORE: &str = "resume.vot";

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

    // Fetch into a stable bundle staged beside the destination, so the objects
    // land on the same filesystem the files will and a re-run resumes it. The
    // stage is keyed by the package root, so the same delivery resumes even
    // under a fresh capability after the old one expired. vot-cli keeps a
    // resume store in the stage until the bundle is whole and resumes from a
    // partial one; the stage is kept on failure for that resume and removed
    // once the files materialized.
    // ponytail: the bundle is a full second copy on disk; fetch-to-loose or a
    // hardlink materialize is the upgrade when a large sequence needs it.
    // ponytail: a stable stage name is what makes resume possible, but two
    // receives of the same delivery into the same destination running at once
    // now share it and can clear each other's bundle (a failed transfer, not
    // lost data: materialize never overwrites an existing file). A lock would
    // close it, at the cost of a stale lock blocking every retry after a crash;
    // the CLI is one receive per process, so this stays a documented edge.
    let staging_parent = dest
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(staging_parent)?;
    let stage = staging_parent.join(format!(".vot-fetch-{}.bundle", hex::encode(pin)));

    // A bundle a prior fetch finished but materialize did not clear would make
    // vot-cli refuse the stage (a non-empty dir with no resume store); remove
    // only that exact shape, never a fetch in progress or resuming.
    if stage_is_stale_complete(&stage) {
        fs::remove_dir_all(&stage)?;
    }

    if let Err(error) = fetch_bundle_with(
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
        &stage,
    ) {
        // A stage no retry can resume (no store, or a corrupt one) would refuse
        // every retry, and each retry mints a fresh ticket against the download
        // cap. Clear it so the next attempt starts clean; a transport failure
        // leaves a valid store and the stage is kept for resume.
        if stage_unresumable(&error) {
            let _ = fs::remove_dir_all(&stage);
        }
        return Err(error.into());
    }

    let received = materialize(&stage, dest, observer)?;
    // The files are on disk and verified; a failure to clear the stage must not
    // fail the receive. A leftover whole bundle is removed on the next run.
    let _ = fs::remove_dir_all(&stage);
    Ok(Outcome::Fetched(received))
}

/// Whether `stage` holds a bundle a prior fetch finished but a materialize did
/// not clear: no resume store, and every object the manifest names present at
/// its full length. vot-cli keeps the resume store until the bundle is whole,
/// so any in-progress or resuming fetch has it and is never seen as stale; a
/// stage with no readable manifest, or a short or missing object, is left for
/// vot-cli to resume rather than removed.
fn stage_is_stale_complete(stage: &Path) -> bool {
    if stage.join(RESUME_STORE).exists() {
        return false;
    }
    let Ok(entries) = read_manifest(stage) else {
        return false;
    };
    let objects = stage.join("objects");
    entries.iter().all(|entry| {
        fs::metadata(objects.join(object_name(&entry.root)))
            .map(|meta| meta.len() == entry.length)
            .unwrap_or(false)
    })
}

/// Whether a failed fetch left the stage in a state no retry can resume, so it
/// should be cleared rather than kept: an incomplete bundle with no resume
/// store (vot-cli refuses it), or a store vot-cli cannot resume from. Every
/// other failure, a dropped transport above all, leaves a valid store.
fn stage_unresumable(error: &VotError) -> bool {
    matches!(error, VotError::DestinationExists | VotError::InvalidBundle)
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
    observer.event(Event::Planned {
        files: entries
            .iter()
            .enumerate()
            .map(|(index, entry)| PlannedFile {
                index,
                path: package_path_string(&entry.path),
                bytes: entry.length,
            })
            .collect(),
    });

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
    use super::*;
    use crate::entries::admit;
    use crate::package::build;

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

    /// Builds a real manifest under `stage` and writes each object at its full
    /// length. The stale check reads only object lengths, so zero-filled files
    /// of the right size stand in for the fetched bytes.
    fn whole_bundle(stage: &Path) {
        let source = tempfile::tempdir().unwrap();
        let big = source.path().join("big.bin");
        let note = source.path().join("note.txt");
        fs::write(&big, vec![7u8; 200_000]).unwrap();
        fs::write(&note, b"a small note").unwrap();
        let entries = vec![
            admit("big.bin", big, false).unwrap(),
            admit("note.txt", note, false).unwrap(),
        ];
        build(entries, stage).expect("built the manifest");
        let objects = stage.join("objects");
        fs::create_dir_all(&objects).unwrap();
        for entry in read_manifest(stage).unwrap() {
            fs::write(
                objects.join(object_name(&entry.root)),
                vec![0u8; entry.length as usize],
            )
            .unwrap();
        }
    }

    #[test]
    fn a_whole_bundle_with_no_resume_store_is_stale() {
        let home = tempfile::tempdir().unwrap();
        let stage = home.path().join("s");
        whole_bundle(&stage);
        assert!(
            stage_is_stale_complete(&stage),
            "a finished bundle no materialize cleared is removable"
        );
    }

    #[test]
    fn a_resume_store_keeps_a_whole_bundle() {
        let home = tempfile::tempdir().unwrap();
        let stage = home.path().join("s");
        whole_bundle(&stage);
        fs::write(stage.join(RESUME_STORE), b"in progress").unwrap();
        assert!(
            !stage_is_stale_complete(&stage),
            "a fetch owns any stage that still has a resume store"
        );
    }

    #[test]
    fn a_short_object_is_not_stale() {
        let home = tempfile::tempdir().unwrap();
        let stage = home.path().join("s");
        whole_bundle(&stage);
        let objects = stage.join("objects");
        let first = &read_manifest(&stage).unwrap()[0];
        fs::write(
            objects.join(object_name(&first.root)),
            vec![0u8; first.length as usize - 1],
        )
        .unwrap();
        assert!(
            !stage_is_stale_complete(&stage),
            "a partial object means the fetch is not whole"
        );
    }

    #[test]
    fn a_stage_without_a_manifest_is_not_stale() {
        let home = tempfile::tempdir().unwrap();
        assert!(
            !stage_is_stale_complete(home.path()),
            "no readable manifest is left for vot-cli, not removed"
        );
    }

    #[test]
    fn only_stage_integrity_errors_clear_the_stage() {
        assert!(stage_unresumable(&VotError::DestinationExists));
        assert!(stage_unresumable(&VotError::InvalidBundle));
        // A transport or identity failure leaves a resumable store; the stage
        // is kept so the next attempt resumes rather than refetching.
        assert!(!stage_unresumable(&VotError::ServeIdentityMismatch));
    }
}
