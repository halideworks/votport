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
use crate::progress::{with_progress, Event, Observer, PlannedFile, Transport, PROGRESS_QUANTUM};
use crate::receive::{
    local_path_of, require_space, reusable_file, write_verified, Delivery, Received, Resumed,
};
use crate::send_push::{direct_rails, probe_any, Probe};

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
            "the delivery does not serve a QUIC fetch, or the destination cannot stage one"
                .to_owned(),
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
    try_fetch_with_resume(client, delivery, device, dest, observer, false)
}

pub(crate) fn try_fetch_with_resume(
    client: &Client,
    delivery: &Delivery,
    device: &Device,
    dest: &Path,
    observer: &mut dyn Observer,
    resume: bool,
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

    // The delivery's own file list, so a screen has rows while the carrier
    // moves the bundle; materialize announces the manifest's list after.
    observer.event(Event::Planned {
        files: metadata
            .files
            .iter()
            .enumerate()
            .map(|(index, file)| PlannedFile {
                index,
                path: file.name.clone(),
                bytes: file.bytes,
            })
            .collect(),
    });
    // Refuse a receive that would overwrite before reserving a fetch ticket,
    // the way the HTTP path refuses before downloading: a mint counts an
    // undelivered ticket against the delivery's download cap for the
    // capability's lifetime, so a refusal after the mint would lock the
    // delivery out. materialize re-checks on the authoritative manifest names.
    let mut remaining = 0u64;
    let paths =
        crate::receive::local_paths(dest, metadata.files.iter().map(|file| file.name.as_str()))?;
    for (file, path) in metadata.files.iter().zip(paths) {
        let path = path?;
        if file.suite != "blake3" {
            return Err(Error::UnknownSuite {
                suite: file.suite.clone(),
            });
        }
        if !reusable_file(
            &path,
            decode_digest(&file.root)?,
            file.bytes,
            resume,
            observer,
        )? {
            remaining = remaining.saturating_add(file.bytes);
        }
    }
    // The bundle is staged beside the destination and then copied into it,
    // so a fetch needs room for two copies until the stage is cleared. A
    // destination with room for one still fits over HTTP, which stages
    // nothing, so that is a fallback rather than a refusal.
    // ponytail: a stage a prior fetch left is not credited against the two
    // copies, so a nearly complete resume on a tight destination goes over
    // HTTP instead. vot-cli pre-sizes objects sparsely, so a stage's lengths
    // say nothing, and allocated blocks are unreliable too (ZFS compresses
    // and delays allocation; Windows reports none). A VOT accessor for the
    // resume store's verified coverage is the upgrade.
    // The stage's filesystem is the one asked, which is the destination's
    // parent: for a destination that is itself a mount root the two differ.
    let staging_parent = dest
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let total: u64 = metadata.files.iter().map(|file| file.bytes).sum();
    if require_space(staging_parent, total.saturating_add(remaining)).is_err() {
        return Ok(Outcome::Unreachable);
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

    if observer.cancelled() {
        return Err(Error::Cancelled);
    }
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
    fs::create_dir_all(staging_parent)?;
    let stage = staging_parent.join(format!(".vot-fetch-{}.bundle", hex::encode(pin)));

    // A bundle a prior fetch finished but materialize did not clear would make
    // vot-cli refuse the stage (a non-empty dir with no resume store); remove
    // only that exact shape, never a fetch in progress or resuming.
    if stage_is_stale_complete(&stage) {
        fs::remove_dir_all(&stage)?;
    }

    observer.event(Event::Transport(Transport::Fetch));
    // ponytail: once the ticket is minted a cancel is not honoured: vot-cli
    // removes the resume store when the bundle is whole, so stopping after
    // that would discard a complete download and mint a fresh ticket on the
    // next run. Threading vot-cli's CancellationHandle through FetchOptions
    // is the VOT change that makes a mid-fetch cancel possible.
    let fetched = with_progress(observer, |progress| {
        fetch_bundle_with(
            FetchOptions {
                address: reachable,
                holder: Some(holder),
                serve_identity: Some(identity),
                pin: Some(pin),
                rails: direct_rails(reachable, cfg!(target_os = "macos")),
                provers: None,
                extensions: BTreeSet::new(),
                progress: Some((PROGRESS_QUANTUM, progress)),
            },
            &stage,
        )
    });
    if let Err(error) = fetched {
        // A stage no retry can resume (no store, or a corrupt one) would refuse
        // every retry, and each retry mints a fresh ticket against the download
        // cap. Clear it so the next attempt starts clean; a transport failure
        // leaves a valid store and the stage is kept for resume.
        if stage_unresumable(&error) {
            let _ = fs::remove_dir_all(&stage);
        }
        return Err(error.into());
    }

    let received = materialize(&stage, dest, observer, resume)?;
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
fn materialize(
    bundle: &Path,
    dest: &Path,
    observer: &mut dyn Observer,
    resume: bool,
) -> Result<Received> {
    let entries = read_manifest(bundle)?;
    let objects = bundle.join("objects");
    #[cfg(windows)]
    let references = entries
        .iter()
        .fold(std::collections::HashMap::new(), |mut counts, entry| {
            *counts.entry(entry.root).or_insert(0usize) += 1;
            counts
        });

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

    let names = entries
        .iter()
        .map(|entry| crate::receive::package_name(&entry.path))
        .collect::<Result<Vec<_>>>()?;
    let paths = crate::receive::local_paths(dest, names.iter().map(String::as_str))?;
    let planned = entries
        .iter()
        .zip(paths)
        .map(|(entry, path)| {
            let path = path?;
            let complete = reusable_file(&path, entry.root, entry.length, resume, observer)?;
            Ok((path, entry.root, entry.length, complete))
        })
        .collect::<Result<Vec<_>>>()?;
    fs::create_dir_all(dest)?;
    let mut files = Vec::with_capacity(planned.len());
    #[cfg(target_os = "macos")]
    let mut pending = Vec::<(usize, std::path::PathBuf, crate::receive::PendingFile)>::new();
    for (index, (path, root, length, complete)) in planned.into_iter().enumerate() {
        if observer.cancelled() {
            return Err(Error::Cancelled);
        }
        if !complete {
            local_path_of(dest, &entries[index].path)?;
            let object = objects.join(object_name(&root));
            #[cfg(windows)]
            let linked = references[&root] == 1
                && link_verified_object(&object, dest, &path, root, length, observer)?;
            #[cfg(not(windows))]
            let linked = false;
            if !linked {
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
                #[cfg(target_os = "macos")]
                if length <= 64 * 1024 {
                    use std::os::unix::fs::MetadataExt as _;
                    let file = crate::receive::prepare_verified(
                        &mut source,
                        &path,
                        root,
                        &hex::encode(root),
                        length,
                        index,
                        observer,
                    )?;
                    if let Some((_, _, prior)) = pending.last() {
                        if prior.journal.metadata()?.dev() != file.journal.metadata()?.dev() {
                            publish_batch(&mut pending, dest, observer, &mut files)?;
                        }
                    }
                    rustix::fs::fsync(&file.journal).map_err(std::io::Error::from)?;
                    pending.push((index, path, file));
                    if pending.len() == 16 {
                        publish_batch(&mut pending, dest, observer, &mut files)?;
                    }
                    continue;
                }
                #[cfg(target_os = "macos")]
                publish_batch(&mut pending, dest, observer, &mut files)?;
                write_verified(
                    &mut source,
                    &path,
                    root,
                    &hex::encode(root),
                    length,
                    index,
                    observer,
                )?;
            }
        }
        #[cfg(target_os = "macos")]
        publish_batch(&mut pending, dest, observer, &mut files)?;
        observer.event(Event::FileVerified {
            index,
            path: path.display().to_string(),
        });
        files.push(path);
    }
    #[cfg(target_os = "macos")]
    publish_batch(&mut pending, dest, observer, &mut files)?;
    observer.event(Event::Finished { files: files.len() });
    Ok(Received { files })
}

// Each file reaches the drive before one full barrier flushes the same device.
// Keep at most 16 small-file builders and locked journals awaiting publication.
#[cfg(target_os = "macos")]
fn publish_batch(
    pending: &mut Vec<(usize, std::path::PathBuf, crate::receive::PendingFile)>,
    dest: &Path,
    observer: &mut dyn Observer,
    files: &mut Vec<std::path::PathBuf>,
) -> Result<()> {
    if observer.cancelled() {
        return Err(Error::Cancelled);
    }
    if let Some((_, _, last)) = pending.last() {
        last.journal.sync_all()?;
    }
    for (index, path, file) in pending.drain(..) {
        crate::receive::validate_parent(dest, &path)?;
        file.publish()?;
        observer.event(Event::FileVerified {
            index,
            path: path.display().to_string(),
        });
        files.push(path);
    }
    Ok(())
}

// A unique object can keep its durable bytes when published on NTFS. Shared
// roots stay independent copies so editing one delivered file cannot edit another.
#[cfg(windows)]
fn link_verified_object(
    source: &Path,
    destination_root: &Path,
    destination: &Path,
    root: [u8; 32],
    length: u64,
    observer: &mut dyn Observer,
) -> Result<bool> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_READ,
    };
    if !fs::symlink_metadata(source)?.file_type().is_file() {
        return Err(Error::Other(
            "the staged object is not a regular file".to_owned(),
        ));
    }
    // Deny writes and namespace swaps until the verified handle is linked.
    let held = fs::OpenOptions::new()
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(source)?;
    if !vot_platform_fs::same_file_handle(&held, source)? {
        return Err(Error::Other(
            "the staged object changed before verification".to_owned(),
        ));
    }
    if !reusable_file(source, root, length, true, observer)? {
        return Err(Error::Other("the staged object disappeared".to_owned()));
    }
    crate::receive::validate_parent(destination_root, destination)?;
    fs::create_dir_all(destination.parent().unwrap_or_else(|| Path::new(".")))?;
    crate::receive::validate_parent(destination_root, destination)?;
    match vot_platform_fs::link_file_handle(&held, source, destination) {
        Ok(()) => Ok(true),
        // ERROR_INVALID_FUNCTION, ERROR_NOT_SAME_DEVICE, ERROR_NOT_SUPPORTED.
        Err(error) if matches!(error.raw_os_error(), Some(1 | 17 | 50)) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(Error::Exists {
            path: destination.to_path_buf(),
        }),
        Err(error) => Err(error.into()),
    }
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
    fn resumed_materialize_verifies_existing_files_and_skips_their_objects() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("source");
        let stage = home.path().join("bundle");
        let dest = home.path().join("dest");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&dest).unwrap();
        let mut admitted = Vec::new();
        for (name, bytes) in [
            ("first", b"first".as_slice()),
            ("second", b"second".as_slice()),
        ] {
            let path = source.join(name);
            fs::write(&path, bytes).unwrap();
            admitted.push(admit(name, path, false).unwrap());
        }
        build(admitted, &stage).unwrap();
        fs::create_dir_all(stage.join("objects")).unwrap();
        for entry in read_manifest(&stage).unwrap() {
            if package_path_string(&entry.path) == "second" {
                fs::write(
                    stage.join("objects").join(object_name(&entry.root)),
                    b"second",
                )
                .unwrap();
            }
        }
        fs::write(dest.join("first"), b"wrong").unwrap();
        assert!(matches!(
            materialize(&stage, &dest, &mut crate::progress::Silent, true),
            Err(Error::Exists { .. })
        ));
        assert!(!dest.join("second").exists());
        fs::write(dest.join("first"), b"first").unwrap();
        assert!(matches!(
            materialize(&stage, &dest, &mut crate::progress::Silent, false),
            Err(Error::Exists { .. })
        ));
        let received = materialize(&stage, &dest, &mut crate::progress::Silent, true).unwrap();
        assert_eq!(received.files.len(), 2);
        assert_eq!(fs::read(dest.join("first")).unwrap(), b"first");
        assert_eq!(fs::read(dest.join("second")).unwrap(), b"second");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn small_file_batch_waits_for_barrier_and_preserves_collisions() {
        let home = tempfile::tempdir().unwrap();
        let dest = home.path().join("dest");
        fs::create_dir(&dest).unwrap();
        let payload = b"verified";
        let mut builder =
            vot_object::ObjectBuilder::new(vot_object::Suite::Blake3Bao64, Some(8)).unwrap();
        builder.update(payload).unwrap();
        let root = builder.finish().unwrap().object_id().root;
        let prepare = |name: &str| {
            let path = dest.join(name);
            let file = crate::receive::prepare_verified(
                &mut |_| {
                    Ok(Resumed {
                        reader: Box::new(std::io::Cursor::new(payload)),
                        start: 0,
                    })
                },
                &path,
                root,
                &hex::encode(root),
                8,
                0,
                &mut crate::progress::Silent,
            )
            .unwrap();
            rustix::fs::fsync(&file.journal).unwrap();
            (0, path, file)
        };
        let mut pending = vec![prepare("first"), prepare("second")];
        assert!(!dest.join("first").exists());
        assert!(!dest.join("second").exists());
        let mut files = Vec::new();
        publish_batch(
            &mut pending,
            &dest,
            &mut crate::progress::Silent,
            &mut files,
        )
        .unwrap();
        assert_eq!(files, [dest.join("first"), dest.join("second")]);
        assert_eq!(fs::read(&files[0]).unwrap(), payload);
        assert_eq!(fs::read(&files[1]).unwrap(), payload);
        let mut pending = vec![prepare("blocked"), prepare("failed-barrier")];
        pending[1].2.journal = File::open("/dev/null").unwrap();
        assert!(publish_batch(
            &mut pending,
            &dest,
            &mut crate::progress::Silent,
            &mut files
        )
        .is_err());
        assert!(!dest.join("blocked").exists());
        assert!(!dest.join("failed-barrier").exists());
        assert_eq!(files.len(), 2);
        let mut pending = vec![prepare("collision")];
        fs::write(dest.join("collision"), b"original").unwrap();
        assert!(publish_batch(
            &mut pending,
            &dest,
            &mut crate::progress::Silent,
            &mut files
        )
        .is_err());
        assert_eq!(fs::read(dest.join("collision")).unwrap(), b"original");
        assert_eq!(files.len(), 2);
        struct Cancelled;
        impl Observer for Cancelled {
            fn event(&mut self, _: Event) {}
            fn cancelled(&self) -> bool {
                true
            }
        }
        let mut pending = vec![prepare("cancelled")];
        assert!(matches!(
            publish_batch(&mut pending, &dest, &mut Cancelled, &mut files),
            Err(Error::Cancelled)
        ));
        assert!(!dest.join("cancelled").exists());
    }

    #[cfg(windows)]
    #[test]
    fn unique_staged_objects_link_without_aliasing_duplicate_files() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("source");
        let stage = home.path().join("stage");
        let dest = home.path().join("dest");
        fs::create_dir(&source).unwrap();
        let mut admitted = Vec::new();
        for (name, bytes) in [
            ("unique", b"unique".as_slice()),
            ("copy1", b"shared"),
            ("copy2", b"shared"),
        ] {
            let path = source.join(name);
            fs::write(&path, bytes).unwrap();
            admitted.push(admit(name, path, false).unwrap());
        }
        build(admitted, &stage).unwrap();
        fs::create_dir(stage.join("objects")).unwrap();
        let entries = read_manifest(&stage).unwrap();
        for entry in &entries {
            fs::copy(
                source.join(package_path_string(&entry.path)),
                stage.join("objects").join(object_name(&entry.root)),
            )
            .unwrap();
        }
        materialize(&stage, &dest, &mut crate::progress::Silent, false).unwrap();
        let unique = entries
            .iter()
            .find(|entry| package_path_string(&entry.path) == "unique")
            .unwrap();
        let object = stage.join("objects").join(object_name(&unique.root));
        assert!(vot_platform_fs::same_file_regular(&object, &dest.join("unique")).unwrap());
        assert!(
            !vot_platform_fs::same_file_regular(&dest.join("copy1"), &dest.join("copy2")).unwrap()
        );
        fs::write(dest.join("copy1"), b"edited").unwrap();
        assert_eq!(fs::read(dest.join("copy2")).unwrap(), b"shared");
        assert!(matches!(
            link_verified_object(
                &object,
                &dest,
                &dest.join("unique"),
                unique.root,
                unique.length,
                &mut crate::progress::Silent
            ),
            Err(Error::Exists { .. })
        ));
        fs::write(&object, b"wrong!").unwrap();
        assert!(link_verified_object(
            &object,
            &dest,
            &dest.join("corrupt"),
            unique.root,
            unique.length,
            &mut crate::progress::Silent
        )
        .is_err());
        assert!(!dest.join("corrupt").exists());
        fs::write(&object, b"unique").unwrap();
        struct WritesDenied(std::path::PathBuf);
        impl Observer for WritesDenied {
            fn event(&mut self, _: Event) {}
            fn cancelled(&self) -> bool {
                assert!(fs::write(&self.0, b"mutate").is_err());
                assert!(fs::remove_file(&self.0).is_err());
                false
            }
        }
        assert!(link_verified_object(
            &object,
            &dest,
            &dest.join("guarded"),
            unique.root,
            unique.length,
            &mut WritesDenied(object.clone())
        )
        .unwrap());
        fs::remove_dir_all(&stage).unwrap();
        assert_eq!(fs::read(dest.join("unique")).unwrap(), b"unique");
    }

    #[test]
    #[ignore = "same-rig materialization benchmark"]
    fn materialize_2000_files() {
        for trial in 0..3 {
            let home = tempfile::tempdir().unwrap();
            let source = home.path().join("source");
            let stage = home.path().join("stage");
            let dest = home.path().join("dest");
            fs::create_dir(&source).unwrap();
            let mut admitted = Vec::new();
            for index in 0..2000u64 {
                let name = format!("frame-{index:06}.bin");
                let path = source.join(&name);
                let mut bytes = [0; 256];
                bytes[..8].copy_from_slice(&index.to_le_bytes());
                fs::write(&path, bytes).unwrap();
                admitted.push(admit(&name, path, false).unwrap());
            }
            build(admitted, &stage).unwrap();
            fs::create_dir(stage.join("objects")).unwrap();
            for entry in read_manifest(&stage).unwrap() {
                let object = stage.join("objects").join(object_name(&entry.root));
                fs::copy(source.join(package_path_string(&entry.path)), &object).unwrap();
                fs::OpenOptions::new()
                    .write(true)
                    .open(object)
                    .unwrap()
                    .sync_all()
                    .unwrap();
            }
            let started = std::time::Instant::now();
            let received = materialize(&stage, &dest, &mut crate::progress::Silent, false).unwrap();
            let elapsed = started.elapsed();
            assert_eq!(received.files.len(), 2000);
            for index in 0..2000u64 {
                let bytes = fs::read(dest.join(format!("frame-{index:06}.bin"))).unwrap();
                assert_eq!(bytes.len(), 256);
                assert_eq!(&bytes[..8], &index.to_le_bytes());
            }
            eprintln!(
                "trial={trial} files=2000 materialize_ms={:.3}",
                elapsed.as_secs_f64() * 1000.0
            );
        }
    }

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
