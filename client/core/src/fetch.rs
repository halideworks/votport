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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use vot_cli::authz::Holder;
use vot_cli::{fetch_bundle_with_seams, parse_rendezvous, Error as VotError, FetchOptions};
use vot_object::ObjectId;

use crate::api::Client;
use crate::error::{Error, Result};
use crate::identity::Device;
use crate::package::{package_path_string, read_manifest, StoredEntry};
use crate::progress::{with_events, Event, Observer, PlannedFile, Transport, PROGRESS_QUANTUM};
use crate::receive::{
    local_path_of, require_space, reusable_file, write_verified, Delivery, Received, Resumed,
};
use crate::send_push::{direct_rails, probe_any, Probe};

/// The resume store vot-cli writes inside a bundle while fetching and removes
/// once the bundle is whole. Its presence means a fetch owns the stage.
const RESUME_STORE: &str = "resume.vot";
/// The signed capability that owns a resumable fetch. It is kept beside the
/// upstream resume store because the store intentionally contains no bearer
/// credentials, while an admitted ticket must be reused after a restart.
const CAPABILITY_EXTENSION: &str = "capability";

/// The outcome of an attempted fetch.
pub enum Outcome {
    /// The delivery was fetched and materialized.
    Fetched(Received),
    /// The delivery does not serve, or the serve did not answer the probe; the
    /// caller should receive over HTTP instead.
    Unreachable {
        metadata: Box<crate::api::OutboundMetadata>,
        cookie: Option<String>,
    },
}

fn mint_refusal_is_unreachable(error: &Error) -> bool {
    matches!(error, Error::Server { status: 404, .. })
}

enum FetchAttemptError {
    Client(Error),
    Vot(VotError),
}

impl From<Error> for FetchAttemptError {
    fn from(error: Error) -> Self {
        Self::Client(error)
    }
}

fn is_capability_refusal(error: &VotError) -> bool {
    matches!(
        error,
        VotError::PeerClosed(code) if *code == vot_cli::authz::REFUSAL_REASON
    )
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
        Outcome::Unreachable { .. } => Err(Error::Other(
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
/// A missing or wrong password, a serve identity mismatch, a mint failure
/// other than an unavailable reservation, a fetch failure, or a materialize
/// failure.
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
    try_fetch_with_resume_mode(client, delivery, device, dest, observer, resume, false)
}

fn try_fetch_with_resume_mode(
    client: &Client,
    delivery: &Delivery,
    device: &Device,
    dest: &Path,
    observer: &mut dyn Observer,
    resume: bool,
    renew_saved: bool,
) -> Result<Outcome> {
    let mut metadata = client.outbound_metadata_for_device(&delivery.token, None, Some(device))?;

    // A password delivery serves nothing until the password is proven; the
    // grant cookie the verify returns also authorizes the mint.
    let mut cookie: Option<String> = None;
    if metadata.has_password && !metadata.authorized {
        let password = delivery
            .password
            .as_deref()
            .ok_or(Error::PasswordRequired)?;
        let granted = client.verify_outbound(&delivery.token, password)?;
        metadata =
            client.outbound_metadata_for_device(&delivery.token, Some(&granted), Some(device))?;
        cookie = Some(granted);
        if !metadata.authorized {
            return Err(Error::PasswordRequired);
        }
    }

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
    let staging_parent = dest
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // A token hash keeps this name stable across process restarts while
    // preventing a server-controlled grant id from becoming a path.
    let stage = fetch_stage(staging_parent, client.base(), &delivery.token);
    let capability_path = stage.with_extension(CAPABILITY_EXTENSION);
    let has_stage_state = stage.exists() || capability_path.exists();
    if metadata.fetch.is_none() && !has_stage_state {
        return Ok(Outcome::Unreachable {
            metadata: Box::new(metadata),
            cookie,
        });
    }
    fs::create_dir_all(staging_parent)?;
    let _stage_lock = FetchLock::try_acquire(&stage)?;
    let saved_capability = load_saved_holder(
        &capability_path,
        device,
        client.base(),
        &delivery.token,
        &metadata,
    )?;
    let saved_holder = match &saved_capability {
        SavedCapabilityState::Valid(holder) if !renew_saved => Some(Arc::clone(holder)),
        SavedCapabilityState::Missing | SavedCapabilityState::Valid(_) => None,
    };
    let allow_reuse = resume || matches!(&saved_capability, SavedCapabilityState::Valid(_));

    // Refuse an unowned receive that would overwrite before reserving a fetch
    // ticket. A validated sidecar or explicit resume may reuse matching files;
    // materialize re-checks every name and root before publishing.
    let mut remaining = 0u64;
    let paths =
        crate::receive::local_paths(dest, metadata.files.iter().map(|file| file.name.as_str()))?;
    for (file, path) in metadata.files.iter().zip(paths) {
        let path = path?;
        let object = crate::receive::decode_object(&file.suite, &file.root, file.bytes)?;
        if !reusable_file(&path, &object, allow_reuse, observer)? {
            remaining = remaining.saturating_add(file.bytes);
        }
    }
    // The QUIC library removes its resume store immediately after the last
    // object is durable. If the process dies while our materializer is still
    // publishing those objects, the admitted ticket remains the only way to
    // retry safely. Finish that local materialization before considering a
    // new mint; a fresh capability would be refused after delivery. The
    // resume store may still be present when the transport completed, so an
    // owned stage must be checked by content rather than by its marker.
    if matches!(&saved_capability, SavedCapabilityState::Valid(_))
        && owned_stage_is_complete(&stage, &metadata, observer)?
    {
        let evidence = crate::evidence::prepare_receive(client, &metadata, Some(device), observer)?;
        observer.event(Event::Transport(Transport::Fetch));
        let received = materialize_complete_stage(&stage, &metadata, dest, observer, allow_reuse)?;
        let _ = fs::remove_dir_all(&stage);
        let _ = fs::remove_file(&capability_path);
        crate::evidence::complete(client.base(), evidence, observer);
        observer.event(Event::Finished {
            files: received.files.len(),
        });
        return Ok(Outcome::Fetched(received));
    }
    if matches!(&saved_capability, SavedCapabilityState::Missing) && stage_is_stale_complete(&stage)
    {
        fs::remove_dir_all(&stage)?;
        let _ = fs::remove_file(&capability_path);
    }

    // A delivery without a fetch endpoint does not serve: fall back to HTTP.
    // A saved capability means an earlier mint committed a reservation, so
    // sending this request through HTTP would bypass that reservation.
    let Some(endpoint) = metadata.fetch.as_ref() else {
        if !matches!(&saved_capability, SavedCapabilityState::Missing) {
            return Err(Error::Other(
                "the interrupted fetch has no QUIC endpoint; retry when serving is available"
                    .to_owned(),
            ));
        }
        return Ok(Outcome::Unreachable {
            metadata: Box::new(metadata),
            cookie,
        });
    };

    let total: u64 = metadata.files.iter().map(|file| file.bytes).sum();
    // ponytail: reserve the full stage plus remaining copies; credit verified
    // staged bytes when VOT exposes coverage. An owned retry cannot switch to HTTP.
    if require_space(staging_parent, total.saturating_add(remaining)).is_err() {
        if !matches!(&saved_capability, SavedCapabilityState::Missing) {
            return Err(Error::Other(
                "the interrupted fetch has insufficient staging space; retry later".to_owned(),
            ));
        }
        return Ok(Outcome::Unreachable {
            metadata: Box::new(metadata),
            cookie,
        });
    }

    let probe_digest = decode_digest(&endpoint.certificate_digest)?;
    let Ok(addresses) = parse_rendezvous(&endpoint.address) else {
        if !matches!(&saved_capability, SavedCapabilityState::Missing) {
            return Err(Error::Other(
                "the interrupted fetch has an invalid QUIC endpoint; retry later".to_owned(),
            ));
        }
        return Ok(Outcome::Unreachable {
            metadata: Box::new(metadata),
            cookie,
        });
    };
    let reachable = match probe_any(&addresses, probe_digest) {
        Probe::Reachable(address) => address,
        Probe::Unreachable if matches!(&saved_capability, SavedCapabilityState::Missing) => {
            return Ok(Outcome::Unreachable {
                metadata: Box::new(metadata),
                cookie,
            })
        }
        Probe::Unreachable => {
            return Err(Error::Other(
                "the interrupted fetch cannot reach its QUIC endpoint; retry later".to_owned(),
            ))
        }
        Probe::Mismatch => return Err(Error::Package(VotError::ServeIdentityMismatch)),
    };

    if observer.cancelled() {
        return Err(Error::Cancelled);
    }
    let (holder, identity, pin) = if let Some(holder) = saved_holder {
        // Reuse the capability that owns the persisted server ticket. The
        // resume store supplies the package pin after a manifest was received.
        (holder, decode_digest(&endpoint.certificate_digest)?, None)
    } else {
        // The serve answered, so mint a capability and commit to the fetch.
        let mint =
            match client.mint_fetch(&delivery.token, &device.holder_key_hex(), cookie.as_deref()) {
                // A missing serve does not reserve a ticket, so the HTTP path is
                // still safe and useful. Reservation conflicts stay errors: an
                // admitted QUIC ticket cannot be bypassed by HTTP.
                Err(error)
                    if matches!(&saved_capability, SavedCapabilityState::Missing)
                        && mint_refusal_is_unreachable(&error) =>
                {
                    return Ok(Outcome::Unreachable {
                        metadata: Box::new(metadata),
                        cookie,
                    })
                }
                Err(error) => return Err(error),
                Ok(mint) => mint,
            };
        let capability = base64_decode(&mint.capability)?;
        let holder = Arc::new(
            Holder::new(capability.clone(), device.signing_key()).map_err(|error| {
                Error::Other(format!(
                    "the device key does not match the capability: {error:?}"
                ))
            })?,
        );
        let saved = SavedCapability {
            origin: client.base().to_owned(),
            token: delivery.token.clone(),
            grant_id: metadata.grant_id.clone(),
            delivery_manifest: metadata.delivery_manifest.clone(),
            package_root: mint.package_root.clone(),
            holder: device.holder_key_hex(),
            capability: capability.clone(),
        };
        let saved = serde_json::to_vec(&saved)
            .map_err(|error| Error::Other(format!("encode saved fetch capability: {error}")))?;
        crate::identity::write_private(&capability_path, &saved)?;
        (
            holder,
            decode_digest(&mint.certificate_digest)?,
            Some(decode_digest(&mint.package_root)?),
        )
    };

    // Fetch into a stable bundle staged beside the destination, so the objects
    // land on the same filesystem the files will and a re-run resumes it. The
    // stage is stable for this delivery, and the capability sidecar keeps an
    // admitted ticket usable across process restarts. vot-cli keeps a resume
    // store in the stage until the bundle is whole and resumes from a partial
    // one; the stage is kept on failure for that resume and removed once the
    // files materialized.
    // ponytail: the bundle is a full second copy on disk; fetch-to-loose or a
    // hardlink materialize is the upgrade when a large sequence needs it.
    // A per-delivery lock keeps concurrent receives from clearing or writing
    // the same stage. The kernel releases it when an owner crashes, while the
    // lock file itself remains as harmless coordination state.
    let evidence = crate::evidence::prepare_receive(client, &metadata, Some(device), observer)?;
    observer.event(Event::Transport(Transport::Fetch));
    let expected: HashMap<_, _> = metadata
        .files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            Ok((
                file.name.clone(),
                (
                    index,
                    crate::receive::decode_object(&file.suite, &file.root, file.bytes)?,
                ),
            ))
        })
        .collect::<Result<_>>()?;
    let mut references = HashMap::new();
    for (_, object) in expected.values() {
        *references.entry(object.root).or_insert(0usize) += 1;
    }
    let cancellation = vot_cli::CancellationHandle::default();
    let received = with_events(
        |event| {
            if observer.cancelled() {
                cancellation.cancel();
            }
            if let Some(event) = event {
                observer.event(event);
            }
            if observer.cancelled() {
                cancellation.cancel();
            }
        },
        |sender| {
            std::thread::scope(
                |scope| -> std::result::Result<Received, FetchAttemptError> {
                    let state = StreamingSave {
                        bundle: stage.clone(),
                        dest: dest.to_path_buf(),
                        references,
                        pending: Vec::new(),
                        files: Vec::new(),
                        resume: allow_reuse,
                    };
                    let (ready, jobs) = std::sync::mpsc::sync_channel(16);
                    let mut save_observer = StreamObserver {
                        sender: sender.clone(),
                        cancellation: cancellation.clone(),
                    };
                    let saver = scope.spawn(move || state.run(jobs, &mut save_observer));
                    let expected = Arc::new(expected);
                    let manifest_expected = Arc::clone(&expected);
                    let progress_sender = sender.clone();
                    let seams = vot_cli::ReceiveSeams {
                        manifest: Some(Arc::new(move |_, _, entries| {
                            validate_stream_manifest(&manifest_expected, entries)
                        })),
                        complete: Some(Arc::new(move |_, object| {
                            for entry in &object.entries {
                                let (index, object) = expected
                                    .get(&package_path_string(&entry.path))
                                    .ok_or(VotError::InvalidBundle)?;
                                ready
                                    .send((
                                        *index,
                                        StoredEntry {
                                            path: entry.path.clone(),
                                            object: object.clone(),
                                        },
                                    ))
                                    .map_err(|_| VotError::InvalidBundle)?;
                            }
                            Ok(())
                        })),
                        cancellation: cancellation.clone(),
                        ..Default::default()
                    };
                    let fetched = fetch_bundle_with_seams(
                        FetchOptions {
                            address: reachable,
                            holder: Some(holder),
                            serve_identity: Some(identity),
                            pin,
                            rails: direct_rails(reachable, cfg!(target_os = "macos")),
                            provers: None,
                            extensions: BTreeSet::new(),
                            progress: Some((
                                PROGRESS_QUANTUM,
                                Box::new(move |moved, total| {
                                    let _ = progress_sender.send(Event::Bytes { moved, total });
                                }),
                            )),
                        },
                        &stage,
                        seams,
                    );
                    // A local saving failure must retain the stage even when its hook
                    // reports InvalidBundle through the transport's error type.
                    let received = saver.join().map_err(|_| {
                        FetchAttemptError::Client(Error::Other("the saving worker failed".into()))
                    })??;
                    let (_, moved) = match fetched {
                        Ok(fetched) => fetched,
                        Err(error) => {
                            if stage_unresumable(&error) {
                                let _ = fs::remove_dir_all(&stage);
                            }
                            return Err(FetchAttemptError::Vot(error));
                        }
                    };
                    let _ = sender.send(Event::Transferred { bytes: moved });
                    Ok(received)
                },
            )
        },
    );
    let received = match received {
        Ok(received) => received,
        Err(FetchAttemptError::Vot(error))
            if !renew_saved
                && matches!(&saved_capability, SavedCapabilityState::Valid(_))
                && is_capability_refusal(&error) =>
        {
            drop(_stage_lock);
            return try_fetch_with_resume_mode(
                client, delivery, device, dest, observer, resume, true,
            );
        }
        Err(FetchAttemptError::Vot(error)) => return Err(Error::from(error)),
        Err(FetchAttemptError::Client(error)) => return Err(error),
    };
    // The files are on disk and verified; a failure to clear the stage must not
    // fail the receive. A leftover whole bundle is removed on the next run.
    let _ = fs::remove_dir_all(&stage);
    let _ = fs::remove_file(&capability_path);
    crate::evidence::complete(client.base(), evidence, observer);
    observer.event(Event::Finished {
        files: received.files.len(),
    });
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
        fs::metadata(objects.join(object_name(&entry.object.root)))
            .map(|meta| meta.len() == entry.object.length)
            .unwrap_or(false)
    })
}

/// Checks a whole stage owned by a saved capability before selecting an
/// endpoint. A complete transport can leave its resume marker behind while
/// the saver is interrupted; every staged object must still prove its full
/// identity before that stage is materialized locally.
fn owned_stage_is_complete(
    stage: &Path,
    metadata: &crate::api::OutboundMetadata,
    observer: &mut dyn Observer,
) -> Result<bool> {
    if observer.cancelled() {
        return Err(Error::Cancelled);
    }
    let entries = match read_manifest(stage) {
        Ok(entries) => entries,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    validate_staged_manifest(metadata, &entries)?;
    let objects = stage.join("objects");
    let mut checked = HashSet::new();
    for entry in entries {
        let identity = (entry.object.suite, entry.object.root, entry.object.length);
        if !checked.insert(identity) {
            continue;
        }
        match reusable_file(
            &objects.join(object_name(&entry.object.root)),
            &entry.object,
            true,
            observer,
        ) {
            Ok(true) => {}
            Ok(false) | Err(Error::Exists { .. }) => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

fn fetch_stage(parent: &Path, origin: &str, token: &str) -> PathBuf {
    let digest = sha2::Sha256::digest(format!("{origin}\0{token}").as_bytes());
    parent.join(format!(".vot-fetch-{}.bundle", hex::encode(digest)))
}

#[derive(Debug, Deserialize, Serialize)]
struct SavedCapability {
    origin: String,
    token: String,
    grant_id: Option<String>,
    delivery_manifest: Option<String>,
    package_root: String,
    holder: String,
    capability: Vec<u8>,
}

enum SavedCapabilityState {
    Missing,
    Valid(Arc<Holder>),
}

fn load_saved_holder(
    path: &Path,
    device: &Device,
    origin: &str,
    token: &str,
    metadata: &crate::api::OutboundMetadata,
) -> Result<SavedCapabilityState> {
    let capability = match fs::read(path) {
        Ok(capability) => capability,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SavedCapabilityState::Missing)
        }
        Err(error) => return Err(error.into()),
    };
    let saved: SavedCapability = serde_json::from_slice(&capability).map_err(|error| {
        Error::Other(format!(
            "the saved fetch capability metadata is invalid: {error}"
        ))
    })?;
    let expected_package_root = metadata
        .package_root
        .as_deref()
        .filter(|root| !root.is_empty());
    if saved.origin != origin
        || saved.token != token
        || saved.grant_id != metadata.grant_id
        || saved.delivery_manifest != metadata.delivery_manifest
        || expected_package_root.is_some_and(|root| saved.package_root != root)
        || saved.holder != device.holder_key_hex()
    {
        return Err(Error::Other(
            "the saved fetch capability does not match this delivery".to_owned(),
        ));
    }
    let holder = Holder::new(saved.capability, device.signing_key()).map_err(|error| {
        Error::Other(format!(
            "the saved fetch capability is invalid for this device: {error:?}"
        ))
    })?;
    Ok(SavedCapabilityState::Valid(Arc::new(holder)))
}

struct FetchLock {
    file: File,
}

impl FetchLock {
    fn try_acquire(stage: &Path) -> Result<Self> {
        let path = stage.with_extension("lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        match fs4::FileExt::try_lock(&file) {
            Ok(()) => Ok(Self { file }),
            Err(fs4::TryLockError::WouldBlock) => Err(Error::Other(
                "another receive is already using this delivery; retry later".to_owned(),
            )),
            Err(fs4::TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

impl Drop for FetchLock {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.file);
    }
}

fn materialize_complete_stage(
    bundle: &Path,
    metadata: &crate::api::OutboundMetadata,
    dest: &Path,
    observer: &mut dyn Observer,
    resume: bool,
) -> Result<Received> {
    let entries = read_manifest(bundle)?;
    validate_staged_manifest(metadata, &entries)?;
    let references = entries.iter().fold(HashMap::new(), |mut counts, entry| {
        *counts.entry(entry.object.root).or_insert(0usize) += 1;
        counts
    });
    let entries: Vec<_> = entries.into_iter().enumerate().collect();
    let files = materialize_entries(bundle, dest, &entries, observer, resume, &references, false)?;
    Ok(Received { files })
}

fn validate_staged_manifest(
    metadata: &crate::api::OutboundMetadata,
    entries: &[StoredEntry],
) -> Result<()> {
    let expected: HashMap<_, _> = metadata
        .files
        .iter()
        .map(|file| {
            Ok((
                file.name.clone(),
                crate::receive::decode_object(&file.suite, &file.root, file.bytes)?,
            ))
        })
        .collect::<Result<_>>()?;
    if expected.len() != metadata.files.len() || entries.len() != expected.len() {
        return Err(Error::Other(
            "the staged manifest does not match the delivery".to_owned(),
        ));
    }
    let mut seen = BTreeSet::new();
    for entry in entries {
        let name = package_path_string(&entry.path);
        let Some(object) = expected.get(&name) else {
            return Err(Error::Other(
                "the staged manifest does not match the delivery".to_owned(),
            ));
        };
        if !seen.insert(name)
            || entry.object.suite != object.suite
            || entry.object.root != object.root
            || entry.object.length != object.length
        {
            return Err(Error::Other(
                "the staged manifest does not match the delivery".to_owned(),
            ));
        }
    }
    Ok(())
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
#[cfg(test)]
fn materialize(
    bundle: &Path,
    dest: &Path,
    observer: &mut dyn Observer,
    resume: bool,
) -> Result<Received> {
    let entries = read_manifest(bundle)?;
    let references = entries
        .iter()
        .fold(std::collections::HashMap::new(), |mut counts, entry| {
            *counts.entry(entry.object.root).or_insert(0usize) += 1;
            counts
        });

    observer.event(Event::Planned {
        files: entries
            .iter()
            .enumerate()
            .map(|(index, entry)| PlannedFile {
                index,
                path: package_path_string(&entry.path),
                bytes: entry.object.length,
            })
            .collect(),
    });

    let entries: Vec<_> = entries.into_iter().enumerate().collect();
    let files = materialize_entries(bundle, dest, &entries, observer, resume, &references, false)?;
    observer.event(Event::Finished { files: files.len() });
    Ok(Received { files })
}

fn materialize_entries(
    bundle: &Path,
    dest: &Path,
    entries: &[(usize, StoredEntry)],
    observer: &mut dyn Observer,
    resume: bool,
    references: &HashMap<[u8; 32], usize>,
    streaming: bool,
) -> Result<Vec<std::path::PathBuf>> {
    #[cfg(not(windows))]
    let _ = (references, streaming);
    let objects = bundle.join("objects");
    let names = entries
        .iter()
        .map(|(_, entry)| crate::receive::package_name(&entry.path))
        .collect::<Result<Vec<_>>>()?;
    let paths = crate::receive::local_paths(dest, names.iter().map(String::as_str))?;
    let planned = entries
        .iter()
        .zip(paths)
        .map(|((index, entry), path)| {
            let path = path?;
            let complete = reusable_file(&path, &entry.object, resume, observer)?;
            Ok((*index, &entry.path, path, &entry.object, complete))
        })
        .collect::<Result<Vec<_>>>()?;
    fs::create_dir_all(dest)?;
    let mut files = Vec::with_capacity(planned.len());
    #[cfg(target_os = "macos")]
    let mut pending = Vec::<(usize, std::path::PathBuf, crate::receive::PendingFile)>::new();
    for (index, package_path, path, identity, complete) in planned {
        let root = identity.root;
        #[cfg(target_os = "macos")]
        let length = identity.length;
        if observer.cancelled() {
            return Err(Error::Cancelled);
        }
        if !complete {
            local_path_of(dest, package_path)?;
            let object = objects.join(object_name(&root));
            #[cfg(windows)]
            let linked = references[&root] == 1
                && link_verified_object_during_fetch(
                    &object, dest, &path, identity, observer, streaming,
                )?;
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
                        identity,
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
                write_verified(&mut source, &path, identity, index, observer)?;
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
    Ok(files)
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
fn link_verified_object_during_fetch(
    source: &Path,
    destination_root: &Path,
    destination: &Path,
    identity: &ObjectId,
    observer: &mut dyn Observer,
    streaming: bool,
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
        .open(source);
    let held = match held {
        Ok(held) => held,
        Err(error) if streaming && error.raw_os_error() == Some(32) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !vot_platform_fs::same_file_handle(&held, source)? {
        return Err(Error::Other(
            "the staged object changed before verification".to_owned(),
        ));
    }
    if !reusable_file(source, identity, true, observer)? {
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

#[cfg(all(test, windows))]
fn link_verified_object(
    source: &Path,
    dest: &Path,
    path: &Path,
    identity: &ObjectId,
    observer: &mut dyn Observer,
) -> Result<bool> {
    link_verified_object_during_fetch(source, dest, path, identity, observer, false)
}

struct StreamObserver {
    sender: std::sync::mpsc::Sender<Event>,
    cancellation: vot_cli::CancellationHandle,
}

impl Observer for StreamObserver {
    fn event(&mut self, event: Event) {
        if !matches!(event, Event::Transferred { .. }) {
            let _ = self.sender.send(event);
        }
    }
    fn cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

struct StreamingSave {
    bundle: std::path::PathBuf,
    dest: std::path::PathBuf,
    references: HashMap<[u8; 32], usize>,
    pending: Vec<(usize, StoredEntry)>,
    files: Vec<(usize, std::path::PathBuf)>,
    resume: bool,
}

impl StreamingSave {
    fn run(
        mut self,
        jobs: std::sync::mpsc::Receiver<(usize, StoredEntry)>,
        observer: &mut dyn Observer,
    ) -> Result<Received> {
        loop {
            match jobs.recv_timeout(std::time::Duration::from_millis(25)) {
                Ok(job) => {
                    self.pending.push(job);
                    if self.pending.len() == 16 {
                        self.flush(observer)?;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if observer.cancelled() {
                        return Err(Error::Cancelled);
                    }
                    self.flush(observer)?;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        self.flush(observer)?;
        self.files.sort_unstable_by_key(|(index, _)| *index);
        Ok(Received {
            files: self.files.into_iter().map(|(_, path)| path).collect(),
        })
    }

    fn flush(&mut self, observer: &mut dyn Observer) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let files = materialize_entries(
            &self.bundle,
            &self.dest,
            &self.pending,
            observer,
            self.resume,
            &self.references,
            true,
        )?;
        self.files
            .extend(self.pending.iter().map(|(index, _)| *index).zip(files));
        self.pending.clear();
        Ok(())
    }
}

fn validate_stream_manifest(
    expected: &HashMap<String, (usize, ObjectId)>,
    entries: &[vot_cli::EntryRecord],
) -> std::result::Result<(), VotError> {
    if entries.len() != expected.len() {
        return Err(VotError::InvalidBundle);
    }
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        let name =
            crate::receive::package_name(&entry.path).map_err(|_| VotError::InvalidBundle)?;
        let Some((_, object)) = expected.get(&name) else {
            return Err(VotError::InvalidBundle);
        };
        if !seen.insert(name)
            || entry.logical_root != object.root
            || entry.logical_length != object.length
            || entry.storage != vot_cli::Storage::Direct
            || entry.suite.identifier() != object.suite
        {
            return Err(VotError::InvalidBundle);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entries::admit;
    use crate::package::build;

    #[test]
    fn mint_refusals_can_use_http_before_fetch_commit() {
        assert!(mint_refusal_is_unreachable(&Error::Server {
            status: 404,
            what: "mint fetch".into(),
            body: "serve unavailable".into(),
        }));
        for status in [409, 400, 401, 500] {
            assert!(!mint_refusal_is_unreachable(&Error::Server {
                status,
                what: "mint fetch".into(),
                body: "reservation unavailable".into(),
            }));
        }
    }

    #[test]
    fn only_an_explicit_capability_refusal_can_trigger_one_renewal() {
        assert!(is_capability_refusal(&VotError::PeerClosed(
            vot_cli::authz::REFUSAL_REASON,
        )));
        assert!(!is_capability_refusal(&VotError::PeerClosed(0)));
        assert!(!is_capability_refusal(&VotError::CarrierUnavailable));
    }

    #[test]
    fn an_admitted_capability_reloads_after_a_client_restart() {
        let home = tempfile::tempdir().unwrap();
        let device_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let device = Device::from_signing_key(device_key.clone());
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let capability = vot_cli::authz::issue(
            "votport",
            "test-audience",
            &issuer,
            device_key.verifying_key().to_bytes(),
            [9; 32],
            100,
            3600,
        )
        .unwrap();
        let origin = "https://test.example";
        let token = "delivery-token";
        let metadata = crate::api::OutboundMetadata {
            grant_id: Some("grant".into()),
            package_root: Some(hex::encode([9; 32])),
            delivery_manifest: Some("manifest".into()),
            evidence_authorization: None,
            receipt_key: None,
            has_password: false,
            authorized: true,
            label: None,
            files: Vec::new(),
            fetch: None,
        };
        let stage = fetch_stage(home.path(), origin, token);
        let capability_path = stage.with_extension(CAPABILITY_EXTENSION);
        let saved = SavedCapability {
            origin: origin.into(),
            token: token.into(),
            grant_id: metadata.grant_id.clone(),
            delivery_manifest: metadata.delivery_manifest.clone(),
            package_root: hex::encode([9; 32]),
            holder: hex::encode(device_key.verifying_key().to_bytes()),
            capability,
        };
        crate::identity::write_private(&capability_path, &serde_json::to_vec(&saved).unwrap())
            .unwrap();

        assert!(
            matches!(
                load_saved_holder(&capability_path, &device, origin, token, &metadata).unwrap(),
                SavedCapabilityState::Valid(_)
            ),
            "the minted holder must survive the first receive process"
        );
        let restarted = Device::from_signing_key(device_key);
        assert!(
            matches!(
                load_saved_holder(&capability_path, &restarted, origin, token, &metadata).unwrap(),
                SavedCapabilityState::Valid(_)
            ),
            "the same persisted device key must reuse the admitted holder"
        );
        let mut sidecar = serde_json::to_value(&saved).unwrap();
        sidecar["expires_at"] = serde_json::json!(0);
        crate::identity::write_private(&capability_path, &serde_json::to_vec(&sidecar).unwrap())
            .unwrap();
        assert!(matches!(
            load_saved_holder(&capability_path, &device, origin, token, &metadata).unwrap(),
            SavedCapabilityState::Valid(_)
        ));
        assert_ne!(stage, capability_path);
        assert_ne!(
            fetch_stage(home.path(), origin, "another-delivery"),
            stage,
            "each delivery keeps a separate stage and capability"
        );
    }

    #[test]
    fn an_admitted_complete_stage_resumes_materialization_after_interruption() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("source");
        let stage = home.path().join("stage");
        let dest = home.path().join("dest");
        fs::create_dir(&source).unwrap();
        for (name, bytes) in [("first", b"first".as_slice()), ("second", b"second")] {
            fs::write(source.join(name), bytes).unwrap();
        }
        build(
            ["first", "second"]
                .into_iter()
                .map(|name| admit(name, source.join(name), false).unwrap())
                .collect(),
            &stage,
        )
        .unwrap();
        let objects = stage.join("objects");
        fs::create_dir_all(&objects).unwrap();
        for entry in read_manifest(&stage).unwrap() {
            fs::copy(
                source.join(package_path_string(&entry.path)),
                objects.join(object_name(&entry.object.root)),
            )
            .unwrap();
        }
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("first"), b"first").unwrap();

        let entries = read_manifest(&stage).unwrap();
        let metadata = crate::api::OutboundMetadata {
            grant_id: Some("grant".into()),
            package_root: None,
            delivery_manifest: Some("manifest".into()),
            evidence_authorization: None,
            receipt_key: None,
            has_password: false,
            authorized: true,
            label: None,
            files: entries
                .iter()
                .map(|entry| crate::api::OutboundFile {
                    name: package_path_string(&entry.path),
                    suite: "blake3".into(),
                    root: hex::encode(entry.object.root),
                    bytes: entry.object.length,
                    download_url: String::new(),
                })
                .collect(),
            fetch: None,
        };
        fs::write(stage.join(RESUME_STORE), b"in progress").unwrap();
        assert!(owned_stage_is_complete(&stage, &metadata, &mut crate::progress::Silent).unwrap());
        let mut wrong_metadata = metadata.clone();
        wrong_metadata.files[0].root = hex::encode([3; 32]);
        assert!(materialize_complete_stage(
            &stage,
            &wrong_metadata,
            &dest,
            &mut crate::progress::Silent,
            true,
        )
        .is_err());
        let received = materialize_complete_stage(
            &stage,
            &metadata,
            &dest,
            &mut crate::progress::Silent,
            true,
        )
        .unwrap();
        assert_eq!(fs::read(dest.join("second")).unwrap(), b"second");
        assert_eq!(
            received.files,
            vec![dest.join("first"), dest.join("second")]
        );
    }

    #[test]
    fn owned_stage_check_rejects_partial_sparse_corrupt_and_wrong_stages() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("source");
        let stage = home.path().join("stage");
        fs::create_dir(&source).unwrap();
        for (name, bytes) in [("first", b"first".as_slice()), ("copy", b"first")] {
            fs::write(source.join(name), bytes).unwrap();
        }
        build(
            ["first", "copy"]
                .into_iter()
                .map(|name| admit(name, source.join(name), false).unwrap())
                .collect(),
            &stage,
        )
        .unwrap();
        let entries = read_manifest(&stage).unwrap();
        let objects = stage.join("objects");
        fs::create_dir_all(&objects).unwrap();
        for entry in &entries {
            fs::copy(
                source.join(package_path_string(&entry.path)),
                objects.join(object_name(&entry.object.root)),
            )
            .unwrap();
        }
        let metadata = crate::api::OutboundMetadata {
            grant_id: Some("grant".into()),
            package_root: None,
            delivery_manifest: Some("manifest".into()),
            evidence_authorization: None,
            receipt_key: None,
            has_password: false,
            authorized: true,
            label: None,
            files: entries
                .iter()
                .map(|entry| crate::api::OutboundFile {
                    name: package_path_string(&entry.path),
                    suite: "blake3".into(),
                    root: hex::encode(entry.object.root),
                    bytes: entry.object.length,
                    download_url: String::new(),
                })
                .collect(),
            fetch: None,
        };
        fs::write(stage.join(RESUME_STORE), b"in progress").unwrap();
        assert!(owned_stage_is_complete(&stage, &metadata, &mut crate::progress::Silent).unwrap());

        let first = &entries[0].object;
        let first_path = objects.join(object_name(&first.root));
        fs::write(&first_path, b"firs").unwrap();
        assert!(!owned_stage_is_complete(&stage, &metadata, &mut crate::progress::Silent).unwrap());
        fs::copy(source.join("first"), &first_path).unwrap();

        let file = fs::File::create(&first_path).unwrap();
        file.set_len(first.length).unwrap();
        assert!(!owned_stage_is_complete(&stage, &metadata, &mut crate::progress::Silent).unwrap());
        fs::copy(source.join("first"), &first_path).unwrap();

        fs::write(&first_path, b"wrong").unwrap();
        assert!(!owned_stage_is_complete(&stage, &metadata, &mut crate::progress::Silent).unwrap());
        fs::copy(source.join("first"), &first_path).unwrap();

        let mut wrong_metadata = metadata.clone();
        wrong_metadata.files[0].root = hex::encode([3; 32]);
        assert!(
            owned_stage_is_complete(&stage, &wrong_metadata, &mut crate::progress::Silent).is_err()
        );

        struct Cancelled;
        impl Observer for Cancelled {
            fn event(&mut self, _: Event) {}

            fn cancelled(&self) -> bool {
                true
            }
        }
        assert!(matches!(
            owned_stage_is_complete(&stage, &metadata, &mut Cancelled),
            Err(Error::Cancelled)
        ));
    }

    #[test]
    fn fetch_stage_lock_blocks_competing_cleanup() {
        let home = tempfile::tempdir().unwrap();
        let stage = fetch_stage(home.path(), "https://test.example", "delivery-token");
        let first = FetchLock::try_acquire(&stage).unwrap();
        let lock_path = stage.with_extension("lock");
        let second = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path)
            .unwrap();
        assert!(matches!(
            fs4::FileExt::try_lock(&second),
            Err(fs4::TryLockError::WouldBlock)
        ));
        drop(first);
        assert!(fs4::FileExt::try_lock(&second).is_ok());
    }

    #[test]
    fn saving_worker_publishes_before_input_closes_and_returns_delivery_order() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("source");
        let stage = home.path().join("bundle");
        let dest = home.path().join("dest");
        fs::create_dir(&source).unwrap();
        let mut admitted = Vec::new();
        for name in ["a", "b"] {
            let path = source.join(name);
            fs::write(&path, name.as_bytes()).unwrap();
            admitted.push(admit(name, path, false).unwrap());
        }
        build(admitted, &stage).unwrap();
        fs::create_dir(stage.join("objects")).unwrap();
        let entries = read_manifest(&stage).unwrap();
        for entry in &entries {
            fs::copy(
                source.join(package_path_string(&entry.path)),
                stage.join("objects").join(object_name(&entry.object.root)),
            )
            .unwrap();
        }
        let state = StreamingSave {
            bundle: stage,
            dest: dest.clone(),
            references: entries.iter().map(|e| (e.object.root, 1)).collect(),
            pending: Vec::new(),
            files: Vec::new(),
            resume: false,
        };
        let (ready, jobs) = std::sync::mpsc::sync_channel(16);
        let (events, reports) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            state
                .run(
                    jobs,
                    &mut StreamObserver {
                        sender: events,
                        cancellation: vot_cli::CancellationHandle::default(),
                    },
                )
                .expect("the saving worker publishes verified files")
        });
        ready.send((1, entries[1].clone())).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let event = reports
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("one ready file must publish while the next file is still downloading");
            if matches!(event, Event::FileVerified { index: 1, .. }) {
                break;
            }
        }
        assert_eq!(fs::read(dest.join("b")).unwrap(), b"b");
        assert!(!dest.join("a").exists());
        ready.send((0, entries[0].clone())).unwrap();
        drop(ready);
        let received = handle.join().unwrap();
        assert_eq!(received.files, vec![dest.join("a"), dest.join("b")]);
    }

    #[test]
    fn streaming_manifest_requires_exact_direct_file_membership() {
        let entry = vot_cli::EntryRecord {
            path: vot_manifest::PackagePath::portable(["a".to_owned()]).unwrap(),
            suite: vot_object::Suite::Blake3Bao64,
            logical_root: [7; 32],
            logical_length: 9,
            storage: vot_cli::Storage::Direct,
        };
        let expected = HashMap::from([(
            "a".into(),
            (
                0,
                ObjectId {
                    suite: 1,
                    root: [7; 32],
                    length: 9,
                },
            ),
        )]);
        assert!(validate_stream_manifest(&expected, std::slice::from_ref(&entry)).is_ok());
        assert!(validate_stream_manifest(&expected, &[]).is_err());
        for field in 0..5 {
            let mut changed = entry.clone();
            match field {
                0 => {
                    changed.path =
                        vot_manifest::PackagePath::portable(["other".to_owned()]).unwrap()
                }
                1 => changed.logical_root[0] ^= 1,
                2 => changed.logical_length += 1,
                3 => changed.suite = vot_object::Suite::Sha256Bep52,
                _ => {
                    changed.storage = vot_cli::Storage::Pack {
                        root: [8; 32],
                        length: 20,
                        offset: 0,
                    }
                }
            }
            assert!(validate_stream_manifest(&expected, &[changed]).is_err());
        }
        let expected = HashMap::from([
            (
                "a".into(),
                (
                    0,
                    ObjectId {
                        suite: 1,
                        root: [7; 32],
                        length: 9,
                    },
                ),
            ),
            (
                "b".into(),
                (
                    1,
                    ObjectId {
                        suite: 1,
                        root: [7; 32],
                        length: 9,
                    },
                ),
            ),
        ]);
        assert!(validate_stream_manifest(&expected, &[entry.clone(), entry]).is_err());
    }

    #[test]
    fn streaming_saves_available_files_before_the_bundle_is_whole_and_resumes() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("source");
        let stage = home.path().join("bundle");
        let dest = home.path().join("dest");
        fs::create_dir(&source).unwrap();
        let mut admitted = Vec::new();
        for (name, bytes) in [
            ("a", b"shared".as_slice()),
            ("b", b"shared"),
            ("empty", b""),
            ("later", b"later"),
        ] {
            let path = source.join(name);
            fs::write(&path, bytes).unwrap();
            admitted.push(admit(name, path, false).unwrap());
        }
        build(admitted, &stage).unwrap();
        fs::create_dir(stage.join("objects")).unwrap();
        let entries = read_manifest(&stage).unwrap();
        let mut references = HashMap::new();
        for entry in &entries {
            *references.entry(entry.object.root).or_insert(0) += 1;
        }
        let pending: Vec<_> = entries
            .iter()
            .cloned()
            .enumerate()
            .filter(|(_, e)| package_path_string(&e.path) != "later")
            .collect();
        for (_, entry) in &pending {
            fs::copy(
                source.join(package_path_string(&entry.path)),
                stage.join("objects").join(object_name(&entry.object.root)),
            )
            .unwrap();
        }
        let mut state = StreamingSave {
            bundle: stage.clone(),
            dest: dest.clone(),
            references,
            pending,
            files: Vec::new(),
            resume: false,
        };
        let mut events = Vec::new();
        state.flush(&mut |event| events.push(event)).unwrap();
        assert_eq!(state.files.len(), 3);
        assert!(!dest.join("later").exists());
        assert!(events
            .iter()
            .all(|event| !matches!(event, Event::Finished { .. } | Event::Planned { .. })));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::FileVerified { .. }))
                .count(),
            3
        );
        fs::write(dest.join("a"), b"edited").unwrap();
        assert_eq!(fs::read(dest.join("b")).unwrap(), b"shared");
        let later = entries
            .iter()
            .cloned()
            .enumerate()
            .find(|(_, e)| package_path_string(&e.path) == "later")
            .unwrap();
        state.pending.push(later.clone());
        assert!(state.flush(&mut crate::progress::Silent).is_err());
        assert!(stage.exists());
        assert!(!dest.join("later").exists());
        fs::copy(
            source.join("later"),
            stage
                .join("objects")
                .join(object_name(&later.1.object.root)),
        )
        .unwrap();
        state.flush(&mut crate::progress::Silent).unwrap();
        assert_eq!(fs::read(dest.join("later")).unwrap(), b"later");
        state.pending.push(later);
        state.resume = true;
        state.flush(&mut crate::progress::Silent).unwrap();
    }

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
                    stage.join("objects").join(object_name(&entry.object.root)),
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
                &ObjectId {
                    suite: 1,
                    root,
                    length: 8,
                },
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
                stage.join("objects").join(object_name(&entry.object.root)),
            )
            .unwrap();
        }
        materialize(&stage, &dest, &mut crate::progress::Silent, false).unwrap();
        let unique = entries
            .iter()
            .find(|entry| package_path_string(&entry.path) == "unique")
            .unwrap();
        let object = stage.join("objects").join(object_name(&unique.object.root));
        {
            let _writer = vot_platform_fs::guard_staging_file(&object).unwrap();
            assert!(!link_verified_object_during_fetch(
                &object,
                &dest,
                &dest.join("busy"),
                &unique.object,
                &mut crate::progress::Silent,
                true
            )
            .unwrap());
            assert!(!dest.join("busy").exists());
        }
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
                &unique.object,
                &mut crate::progress::Silent
            ),
            Err(Error::Exists { .. })
        ));
        fs::write(&object, b"wrong!").unwrap();
        assert!(link_verified_object(
            &object,
            &dest,
            &dest.join("corrupt"),
            &unique.object,
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
            &unique.object,
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
                let object = stage.join("objects").join(object_name(&entry.object.root));
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
                objects.join(object_name(&entry.object.root)),
                vec![0u8; entry.object.length as usize],
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
            objects.join(object_name(&first.object.root)),
            vec![0u8; first.object.length as usize - 1],
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
