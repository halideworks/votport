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
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use vot_manifest::{Component, PackagePath};
use vot_object::{ObjectBuilder, ObjectId, Suite};

use crate::api::Client;
use crate::entries::admit;
use crate::error::{Error, Result};
use crate::fetch::{try_fetch_with_resume, Outcome};
use crate::identity::Device;
use crate::progress::{Event, Observer, PlannedFile, Transport};

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

pub(crate) fn decode_object(suite: &str, root: &str, length: u64) -> Result<ObjectId> {
    let suite = match suite {
        "blake3" => Suite::Blake3Bao64,
        "sha256" => Suite::Sha256Bep52,
        _ => {
            return Err(Error::UnknownSuite {
                suite: suite.to_owned(),
            })
        }
    };
    Ok(ObjectId {
        suite: suite.identifier(),
        root: decode_root(root)?,
        length,
    })
}

/// How much of a download is read at once before it is hashed and written.
const READ_CHUNK: usize = 4 * 1024 * 1024;

fn receive_buffer(total: u64) -> Vec<u8> {
    vec![0; (total.min(READ_CHUNK as u64) as usize).max(1)]
}

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
    receive_inner(base, delivery, device, dest, observer, false)
}

fn receive_inner(
    base: &str,
    delivery: Delivery,
    device: &Device,
    dest: &Path,
    observer: &mut dyn Observer,
    resume: bool,
) -> Result<Received> {
    let client = Client::new(base)?;
    match try_fetch_with_resume(&client, &delivery, device, dest, observer, resume)? {
        Outcome::Fetched(received) => Ok(received),
        Outcome::Unreachable { metadata, cookie } => receive_over_http_inner(
            &client,
            delivery,
            Some(device),
            dest,
            observer,
            resume,
            Some((*metadata, cookie)),
        ),
    }
}

/// [`receive`] with this machine's device key, or over HTTP alone when the
/// state directory cannot hold one: the key is needed only for the QUIC fetch,
/// so an unwritable state directory should not fail the receive outright.
///
/// # Errors
/// As [`receive`].
pub fn receive_with_device_or_http(
    base: &str,
    delivery: Delivery,
    dest: &Path,
    observer: &mut dyn Observer,
) -> Result<Received> {
    receive_with_device_or_http_mode(base, delivery, dest, observer, false)
}

pub(crate) fn receive_with_device_or_http_mode(
    base: &str,
    delivery: Delivery,
    dest: &Path,
    observer: &mut dyn Observer,
    resume: bool,
) -> Result<Received> {
    match Device::load_or_create() {
        Ok(device) => receive_inner(base, delivery, &device, dest, observer, resume),
        Err(_) => receive_over_http_inner(
            &Client::new(base)?,
            delivery,
            None,
            dest,
            observer,
            resume,
            None,
        ),
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
    let device = Device::load_or_create().ok();
    receive_over_http_inner(
        &Client::new(base)?,
        delivery,
        device.as_ref(),
        dest,
        observer,
        false,
        None,
    )
}

fn receive_over_http_inner(
    client: &Client,
    delivery: Delivery,
    device: Option<&Device>,
    dest: &Path,
    observer: &mut dyn Observer,
    resume: bool,
    authorized: Option<(crate::api::OutboundMetadata, Option<String>)>,
) -> Result<Received> {
    let base = client.base();
    let (mut metadata, mut cookie) = match authorized {
        Some(authorized) => authorized,
        None => (
            client.outbound_metadata_for_device(&delivery.token, None, device)?,
            None,
        ),
    };

    // The grant cookie a verify returns, echoed onto the reads and downloads
    // that follow. It is not kept in a jar, so a many-file delivery never
    // carries more than this one cookie.
    if metadata.has_password && !metadata.authorized {
        let password = delivery
            .password
            .as_deref()
            .ok_or(Error::PasswordRequired)?;
        let granted = client.verify_outbound(&delivery.token, password)?;
        // The verified cookie authorizes a second read, which carries the
        // files the pre-password read withheld.
        metadata = client.outbound_metadata_for_device(&delivery.token, Some(&granted), device)?;
        cookie = Some(granted);
        if !metadata.authorized {
            return Err(Error::PasswordRequired);
        }
    }

    let evidence = crate::evidence::prepare_receive(client, &metadata, device, observer)?;
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

    // Resolve, validate, and check every file before writing a byte, so the
    // whole delivery is refused up front rather than landing some files and
    // failing on a later one: a suite the client does not fetch, a root that
    // is not a 32-byte hash, a name that would escape the destination, or a
    // file already present that a receive would overwrite.
    let paths = local_paths(dest, metadata.files.iter().map(|file| file.name.as_str()))?;
    let planned = metadata
        .files
        .iter()
        .zip(paths)
        .map(|(file, path)| {
            let path = path?;
            let object = decode_object(&file.suite, &file.root, file.bytes)?;
            let complete = reusable_file(&path, &object, resume, observer)?;
            Ok((file, path, object, complete))
        })
        .collect::<Result<Vec<_>>>()?;
    let needed: u64 = planned
        .iter()
        .filter(|(_, _, _, complete)| !complete)
        .map(|(file, _, _, _)| file.bytes)
        .sum();
    require_space(dest, needed)?;

    for (index, (_, path, _, complete)) in planned.iter().enumerate() {
        if *complete {
            observer.event(Event::FileVerified {
                index,
                path: path.display().to_string(),
            });
        }
    }

    observer.event(Event::Transport(Transport::Http));

    fs::create_dir_all(dest)?;
    let cookie = cookie.as_deref();
    let mut files = Vec::with_capacity(planned.len());
    for (index, (file, path, object, complete)) in planned.into_iter().enumerate() {
        if observer.cancelled() {
            return Err(Error::Cancelled);
        }
        if !complete {
            validate_parent(dest, &path)?;
            fs::create_dir_all(path.parent().unwrap_or(dest))?;
            let lease_path = part_path(&path).with_extension("lease");
            let mut lease_file = open_journal(&lease_path)?;
            let mut saved = Vec::new();
            (&mut lease_file).take(16 * 1024).read_to_end(&mut saved)?;
            let scope = format!("{}{}", base.trim_end_matches('/'), file.download_url);
            let mut lease = serde_json::from_slice::<(String, String, String)>(&saved)
                .ok()
                .filter(|(url, root, token)| {
                    // The saved URL is the scope the lease was minted for,
                    // optionally already carrying the lease query the
                    // admission redirect handed out.
                    (url == &scope
                        || url
                            .strip_prefix(scope.as_str())
                            .is_some_and(|rest| rest.starts_with("?download_lease=")))
                        && root == &file.root
                        && !token.is_empty()
                        && token
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() || byte == b'.')
                })
                .map(|(_, _, token)| token);
            let mut source = |offset: u64| -> Result<Resumed> {
                let (response, start) =
                    client.download(&file.download_url, cookie, &mut lease, offset, file.bytes)?;
                if let Some(value) = &lease {
                    let final_url = format!("{scope}?download_lease={value}");
                    let bytes =
                        serde_json::to_vec(&(&final_url, &file.root, value)).map_err(|error| {
                            Error::Other(format!("encoding download lease: {error}"))
                        })?;
                    if bytes != saved {
                        lease_file.rewind()?;
                        lease_file.write_all(&bytes)?;
                        lease_file.set_len(bytes.len() as u64)?;
                        lease_file.sync_all()?;
                        saved = bytes;
                    }
                }
                Ok(Resumed {
                    reader: Box::new(response),
                    start,
                })
            };
            write_verified(&mut source, &path, &object, index, observer)?;
            if vot_platform_fs::same_file_handle(&lease_file, &lease_path)? {
                fs::remove_file(&lease_path)?;
            }
            observer.event(Event::FileVerified {
                index,
                path: path.display().to_string(),
            });
        }
        files.push(path);
    }
    crate::evidence::complete(base, evidence, observer);
    observer.event(Event::Finished { files: files.len() });
    Ok(Received { files })
}

/// Refuses a receive whose files cannot fit at `dest`, before any byte or
/// ticket is spent. `dest` may not exist yet; the nearest existing ancestor
/// is asked, since that is the filesystem the files land on.
///
/// # Errors
/// [`Error::NoSpace`] when the free space is below `needed`.
pub(crate) fn require_space(dest: &Path, needed: u64) -> Result<()> {
    let Some(available) = available_space(dest) else {
        // No existing ancestor answered (an unmounted volume, say); the write
        // itself will report what is wrong.
        return Ok(());
    };
    if available < needed {
        return Err(Error::NoSpace {
            path: dest.to_path_buf(),
            needed,
            available,
        });
    }
    Ok(())
}

/// Free bytes on the filesystem holding `path`, or its nearest existing
/// ancestor.
fn available_space(path: &Path) -> Option<u64> {
    let mut probe = Some(path);
    while let Some(candidate) = probe {
        // A relative name's parent is the empty path: the working directory.
        let candidate = if candidate.as_os_str().is_empty() {
            Path::new(".")
        } else {
            candidate
        };
        if candidate.exists() {
            return fs4::available_space(candidate).ok();
        }
        probe = candidate.parent();
    }
    None
}

/// A byte source positioned to resume at a requested offset, with the offset
/// its bytes actually start at: the requested one, or 0 when the source could
/// only give the whole thing (a server that ignored the range).
pub(crate) struct Resumed {
    pub reader: Box<dyn Read>,
    pub start: u64,
}

/// Streams the bytes `source` gives into `destination`, hashing as it writes,
/// and lands the file only if its `total` bytes hash to the announced root.
///
/// A partial from an interrupted attempt is resumed: its bytes are hashed into
/// the builder and `source` is asked to continue past them. A stream that ends
/// short keeps the partial so the next run resumes it; a wrong root, a landed
/// file, or a rename failure removes it. `source` is called with the resume
/// offset and gives a reader plus where its bytes begin.
pub(crate) fn write_verified(
    source: &mut dyn FnMut(u64) -> Result<Resumed>,
    destination: &Path,
    announced: &ObjectId,
    index: usize,
    observer: &mut dyn Observer,
) -> Result<()> {
    let pending = prepare_verified(source, destination, announced, index, observer)?;
    pending.journal.sync_all()?;
    pending.publish()
}

pub(crate) struct PendingFile {
    pub(crate) journal: File,
    identity: File,
    identity_path: PathBuf,
    builder: ObjectBuilder,
    destination: PathBuf,
    announced: [u8; 32],
    announced_hex: String,
    temporary: PathBuf,
}

pub(crate) fn prepare_verified(
    source: &mut dyn FnMut(u64) -> Result<Resumed>,
    destination: &Path,
    announced: &ObjectId,
    index: usize,
    observer: &mut dyn Observer,
) -> Result<PendingFile> {
    let total = announced.length;
    let suite = Suite::try_from(announced.suite).map_err(|_| Error::UnknownSuite {
        suite: announced.suite.to_string(),
    })?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = part_path(destination);
    let mut journal = open_journal(&temporary)?;
    let identity_path = identity_path(destination);
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(Error::Exists {
                path: destination.to_owned(),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let (identity_file, prior_identity) = read_identity(&identity_path)?;

    // Only matching object identities can resume. Open the source before resetting
    // journal data or its companion identity.
    let mut builder = ObjectBuilder::new(suite, Some(total))?;
    let identity_matches = prior_identity.as_ref() == Some(announced);
    let mut resume_from = if identity_matches && journal.metadata()?.len() < total {
        feed_partial(&mut journal, &mut builder, total)?
    } else {
        0
    };
    let resumed = source(resume_from)?;
    if resumed.start != resume_from {
        if resumed.start != 0 {
            return Err(Error::Other(format!(
                "the source resumed at {} but {resume_from} was requested",
                resumed.start
            )));
        }
        // The source gave the whole file rather than the range: start over.
        builder = ObjectBuilder::new(suite, Some(total))?;
        resume_from = 0;
    }
    let mut reader = resumed.reader;

    // Use the inspected writable handle throughout. Create a missing companion
    // only after the source opens; never adopt an intervening file.
    let mut identity = match identity_file {
        Some(file) => file,
        None => open_receive_file_create_new(&identity_path)?,
    };
    if !identity_matches {
        if !vot_platform_fs::same_file_handle(&identity, &identity_path)? {
            return Err(Error::Other(
                "receive identity changed before reset".to_owned(),
            ));
        }
        journal.set_len(0)?;
        journal.sync_all()?;
        write_identity(&mut identity, &identity_path, announced)?;
    }

    // A stream failure keeps the partial for the next run to resume; only a
    // verification failure removes it.
    if let Err(error) = stream_to_temp(
        &mut journal,
        &mut *reader,
        &mut builder,
        resume_from,
        total,
        index,
        observer,
    ) {
        if !vot_platform_fs::same_file_handle(&journal, &temporary).unwrap_or(false)
            && vot_platform_fs::same_file_handle(&identity, &identity_path).unwrap_or(false)
        {
            let _ = fs::remove_file(&identity_path);
        }
        return Err(error);
    }
    Ok(PendingFile {
        journal,
        identity,
        identity_path,
        builder,
        destination: destination.to_owned(),
        announced: announced.root,
        announced_hex: hex::encode(announced.root),
        temporary,
    })
}

impl PendingFile {
    pub(crate) fn publish(self) -> Result<()> {
        let result = verify_and_rename(
            self.builder,
            &self.destination,
            self.announced,
            &self.announced_hex,
            &self.temporary,
            &self.journal,
        );
        match result {
            Ok(()) => {
                if vot_platform_fs::same_file_handle(&self.identity, &self.identity_path)
                    .unwrap_or(false)
                {
                    let _ = fs::remove_file(&self.identity_path);
                }
                Ok(())
            }
            Err(error) => {
                // Short streams retain their prefix and identity. Other publication failures
                // discard only the paths still owned by these opened handles.
                if !matches!(error, Error::Object(vot_object::Error::LengthMismatch)) {
                    if vot_platform_fs::same_file_handle(&self.journal, &self.temporary)
                        .unwrap_or(false)
                    {
                        let _ = fs::remove_file(&self.temporary);
                    }
                    if vot_platform_fs::same_file_handle(&self.identity, &self.identity_path)
                        .unwrap_or(false)
                    {
                        let _ = fs::remove_file(&self.identity_path);
                    }
                }
                Err(error)
            }
        }
    }
}

/// The reserved `.vot-<name>.journal` stores payload bytes beside the destination;
/// its `.id` companion binds resumable bytes to the announced object.
fn part_path(destination: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".vot-");
    name.push(destination.file_name().unwrap_or_default());
    name.push(".journal");
    match destination.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

const IDENTITY_MAGIC: &[u8; 4] = b"VOTI";
const IDENTITY_BYTES: usize = 4 + 2 + 32 + 8;

/// The fixed companion beside a receive journal binds its bytes to one object.
fn identity_path(destination: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".vot-");
    name.push(destination.file_name().unwrap_or_default());
    name.push(".id");
    match destination.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

fn encode_identity(object: &ObjectId) -> [u8; IDENTITY_BYTES] {
    let mut bytes = [0; IDENTITY_BYTES];
    bytes[..IDENTITY_MAGIC.len()].copy_from_slice(IDENTITY_MAGIC);
    bytes[4..6].copy_from_slice(&object.suite.to_le_bytes());
    bytes[6..38].copy_from_slice(&object.root);
    bytes[38..46].copy_from_slice(&object.length.to_le_bytes());
    bytes
}

fn decode_identity(bytes: &[u8]) -> Option<ObjectId> {
    if bytes.len() != IDENTITY_BYTES || &bytes[..IDENTITY_MAGIC.len()] != IDENTITY_MAGIC {
        return None;
    }
    Some(ObjectId {
        suite: u16::from_le_bytes(bytes[4..6].try_into().ok()?),
        root: bytes[6..38].try_into().ok()?,
        length: u64::from_le_bytes(bytes[38..46].try_into().ok()?),
    })
}

fn read_identity(path: &Path) -> Result<(Option<File>, Option<ObjectId>)> {
    let mut file = match open_existing_identity(path) {
        Ok(file) => file,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((None, None));
        }
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(Error::Other(
            "receive identity is not a regular file".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(IDENTITY_BYTES + 1);
    (&mut file)
        .take((IDENTITY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if !vot_platform_fs::same_file_handle(&file, path)? {
        return Err(Error::Other(
            "receive identity changed while reading".to_owned(),
        ));
    }
    let identity = decode_identity(&bytes);
    Ok((Some(file), identity))
}

fn write_identity(file: &mut File, path: &Path, object: &ObjectId) -> Result<()> {
    if !file.metadata()?.is_file() {
        return Err(Error::Other(
            "receive identity is not a regular file".to_owned(),
        ));
    }
    if !vot_platform_fs::same_file_handle(file, path)? {
        return Err(Error::Other(
            "receive identity changed before writing".to_owned(),
        ));
    }
    file.rewind()?;
    file.write_all(&encode_identity(object))?;
    file.set_len(IDENTITY_BYTES as u64)?;
    file.sync_all()?;
    if !vot_platform_fs::same_file_handle(file, path)? {
        return Err(Error::Other(
            "receive identity changed after writing".to_owned(),
        ));
    }
    Ok(())
}

fn open_receive_file(path: &Path, write: bool) -> Result<File> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(write)
        .create(write)
        .truncate(false);
    open_receive_file_with_options(path, options)
}

fn open_receive_file_create_new(path: &Path) -> Result<File> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .truncate(false);
    open_receive_file_with_options(path, options)
}

fn open_existing_identity(path: &Path) -> Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(false).truncate(false);
    open_receive_file_with_options(path, options)
}

fn open_receive_file_with_options(path: &Path, mut options: fs::OpenOptions) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    Ok(options.open(path)?)
}

fn open_journal(path: &Path) -> Result<File> {
    lock_journal(open_receive_file(path, true)?, path)
}

fn lock_journal(file: File, path: &Path) -> Result<File> {
    if !file.metadata()?.is_file() {
        return Err(Error::Other(
            "receive journal is not a regular file".to_owned(),
        ));
    }
    file.try_lock()
        .map_err(|error| Error::Other(format!("cannot lock receive journal: {error}")))?;
    if !vot_platform_fs::same_file_handle(&file, path)? {
        return Err(Error::Other(
            "receive journal changed while acquiring its lock".to_owned(),
        ));
    }
    Ok(file)
}

pub(crate) fn reusable_file(
    path: &Path,
    object: &ObjectId,
    resume: bool,
    observer: &mut dyn Observer,
) -> Result<bool> {
    let total = object.length;
    let suite = Suite::try_from(object.suite).map_err(|_| Error::UnknownSuite {
        suite: object.suite.to_string(),
    })?;
    let exists = || Error::Exists {
        path: path.to_owned(),
    };
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !resume || !metadata.is_file() {
        return Err(exists());
    }
    let mut file = open_receive_file(path, false)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != total {
        return Err(exists());
    }
    let mut builder = ObjectBuilder::new(suite, Some(total))?;
    let mut buffer = receive_buffer(total);
    let mut reader = (&mut file).take(total);
    for _ in 0..=total {
        if observer.cancelled() {
            return Err(Error::Cancelled);
        }
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        builder.update(&buffer[..read]).map_err(|_| exists())?;
    }
    let prepared = builder.finish().map_err(|_| exists())?;
    if file.metadata()?.len() != total
        || !root_matches(&prepared.object_id().root, &object.root)
        || !vot_platform_fs::same_file_handle(&file, path)?
    {
        return Err(exists());
    }
    Ok(true)
}

/// Hashes a usable prefix without changing the journal before a source opens.
fn feed_partial(file: &mut File, builder: &mut ObjectBuilder, total: u64) -> Result<u64> {
    let length = file.metadata()?.len();
    if length >= total {
        return Ok(0);
    }
    file.rewind()?;
    let mut buffer = receive_buffer(total);
    let mut fed = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        builder.update(&buffer[..read])?;
        fed = fed.saturating_add(read as u64);
    }
    Ok(fed)
}

/// Writes through the locked handle, restarting only after a source opens.
fn stream_to_temp(
    sink: &mut File,
    reader: &mut dyn Read,
    builder: &mut ObjectBuilder,
    resume_from: u64,
    total: u64,
    index: usize,
    observer: &mut dyn Observer,
) -> Result<()> {
    sink.set_len(resume_from)?;
    sink.seek(SeekFrom::Start(resume_from))?;
    hash_copy(reader, builder, sink, resume_from, total, index, observer)?;
    Ok(())
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
    journal: &File,
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
    if !vot_platform_fs::same_file_handle(journal, temporary)? {
        return Err(Error::Other(
            "receive journal changed before publication".to_owned(),
        ));
    }
    let mut path = tempfile::TempPath::try_from_path(temporary)?;
    path.disable_cleanup(true);
    path.persist_noclobber(destination).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Exists {
                path: destination.to_owned(),
            }
        } else {
            error.error.into()
        }
    })?;
    Ok(())
}

/// Whether hashed bytes match the announced root. Split out so the compare is
/// exercised directly, not only through a full download that always matches.
fn root_matches(got: &[u8; 32], announced: &[u8; 32]) -> bool {
    got == announced
}

/// Reads `reader` in chunks, feeding each to the hasher and the file. `base`
/// is the bytes already on disk from a resumed partial, so progress counts the
/// whole file, not just this run's tail.
fn hash_copy(
    reader: &mut dyn Read,
    builder: &mut ObjectBuilder,
    sink: &mut File,
    base: u64,
    total: u64,
    index: usize,
    observer: &mut dyn Observer,
) -> Result<()> {
    let mut buffer = receive_buffer(total);
    let mut received = base;
    loop {
        // A cancel keeps the partial for the next run to resume.
        if observer.cancelled() {
            return Err(Error::Cancelled);
        }
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        builder.update(chunk)?;
        sink.write_all(chunk)?;
        received = received.saturating_add(read as u64);
        observer.event(Event::Transferred { bytes: read as u64 });
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
    let path = joined_path(dest, name)?;
    validate_parent(dest, &path)?;
    Ok(path)
}

// This cache is only preflight; publication checks the current parent again.
pub(crate) fn local_paths<'a>(
    dest: &'a Path,
    names: impl IntoIterator<Item = &'a str> + 'a,
) -> Result<impl Iterator<Item = Result<PathBuf>> + 'a> {
    let anchor = resolve_directory(dest)?;
    let mut parents = std::collections::HashSet::new();
    Ok(names.into_iter().map(move |name| {
        let path = joined_path(dest, name)?;
        let parent = path.parent().unwrap_or(dest);
        if !parents.contains(parent) {
            validate_parent_under(&anchor, &path)?;
            parents.insert(parent.to_path_buf());
        }
        Ok(path)
    }))
}

fn joined_path(dest: &Path, name: &str) -> Result<PathBuf> {
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

pub(crate) fn validate_parent(dest: &Path, path: &Path) -> Result<()> {
    validate_parent_under(&resolve_directory(dest)?, path)
}

fn validate_parent_under(anchor: &Path, path: &Path) -> Result<()> {
    let parent = resolve_directory(path.parent().unwrap_or(anchor))?;
    if !parent.starts_with(anchor) {
        return Err(Error::Other(format!(
            "the parent directory of {:?} leaves the receive destination",
            path.display()
        )));
    }
    Ok(())
}

// Resolve existing directory links while retaining directories not created yet.
// The selected root is trusted; only a delivered path's parents are confined.
fn resolve_directory(path: &Path) -> Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(canonical) => {
            if !fs::metadata(&canonical)?.is_dir() {
                return Err(Error::Other(format!(
                    "{} is not a directory",
                    path.display()
                )));
            }
            return Ok(canonical);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let absolute = std::path::absolute(path)?;
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(_) => {
                resolved.push(component);
                continue;
            }
            std::path::Component::ParentDir => {
                resolved.pop();
            }
            std::path::Component::CurDir => continue,
            _ => resolved.push(component),
        }
        match fs::canonicalize(&resolved) {
            Ok(canonical) => {
                if !fs::metadata(&canonical)?.is_dir() {
                    return Err(Error::Other(format!(
                        "{} is not a directory",
                        resolved.display()
                    )));
                }
                resolved = canonical;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::symlink_metadata(&resolved) {
                    Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => return Err(error.into()),
                    Err(other) => return Err(other.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(resolved)
}

/// Joins a bundle manifest's package path to `dest`, refused the same way as a
/// delivery-announced name. A fetched manifest was built with the portable
/// profile but not votport's own name policy, so it is re-checked here.
pub(crate) fn local_path_of(dest: &Path, path: &PackagePath) -> Result<PathBuf> {
    local_path(dest, &package_name(path)?)
}

pub(crate) fn package_name(path: &PackagePath) -> Result<String> {
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
    Ok(parts.join("/"))
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
    fn metadata_identity_admits_supported_suites_and_rejects_invalid_values() {
        let root = hex::encode([9; 32]);
        for (name, suite) in [("blake3", 1), ("sha256", 2)] {
            assert_eq!(
                decode_object(name, &root, 7).unwrap(),
                ObjectId {
                    suite,
                    root: [9; 32],
                    length: 7
                }
            );
        }
        assert!(matches!(
            decode_object("md5", &root, 7),
            Err(Error::UnknownSuite { .. })
        ));
        assert!(decode_object("sha256", "not a digest", 7).is_err());
    }

    #[test]
    fn receive_buffers_bound_memory_and_still_read_past_empty_files() {
        for (total, expected) in [
            (0, 1),
            (1, 1),
            (256, 256),
            (4_194_304, 4_194_304),
            (u64::MAX, 4_194_304),
        ] {
            assert_eq!(receive_buffer(total).len(), expected);
        }
    }

    #[test]
    fn interrupted_download_keeps_only_the_current_files_lease() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        let bytes = b"a verified delivery";
        let mut builder = ObjectBuilder::new(Suite::Blake3Bao64, Some(bytes.len() as u64)).unwrap();
        builder.update(bytes).unwrap();
        let root = hex::encode(builder.finish().unwrap().object_id().root);
        let metadata = serde_json::json!({
            "has_password": true, "authorized": true,
            "files": ([0, 1].map(|index| serde_json::json!({
                "name": format!("file{index}"), "suite": "blake3", "root": root,
                "bytes": bytes.len(), "download_url": format!("/api/s/token/files/{index}")
            })))
        })
        .to_string();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for step in 0..11 {
                let mut stream = (0..1000)
                    .find_map(|_| match listener.accept() {
                        Ok((stream, _)) => Some(stream),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            None
                        }
                        Err(error) => panic!("accept: {error}"),
                    })
                    .expect("download request did not arrive");
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = String::new();
                let mut reader = BufReader::new(&stream);
                for _ in 0..64 {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    request.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let request = request.to_ascii_lowercase();
                if matches!(step, 2..=4 | 7..=10) {
                    assert!(
                        request.contains("votport_s_test=grant"),
                        "{step}: {request}"
                    );
                }
                let (status, extra, body, length) = match step {
                    0 | 5 => (
                        200,
                        String::new(),
                        b"{\"has_password\":true,\"authorized\":false}".to_vec(),
                        None,
                    ),
                    1 | 6 => (
                        200,
                        "Set-Cookie: votport_s_test=grant; Path=/\r\n".to_owned(),
                        b"{}".to_vec(),
                        None,
                    ),
                    2 | 7 => (200, String::new(), metadata.as_bytes().to_vec(), None),
                    // The tokenless first request is admitted with a
                    // same-origin redirect that carries the per-file lease
                    // in the URL query and no lease cookie at all.
                    3 => {
                        assert!(request.starts_with("get /api/s/token/files/0 http"));
                        assert!(!request.contains("download_lease"), "{request}");
                        assert!(!request.contains("range:"), "{request}");
                        (
                            307,
                            "Location: /api/s/token/files/0?download_lease=abcdef0123456789.0123456789abcdef\r\n"
                                .to_owned(),
                            Vec::new(),
                            Some(0),
                        )
                    }
                    4 => {
                        assert!(request.starts_with(
                            "get /api/s/token/files/0?download_lease=abcdef0123456789.0123456789abcdef http"
                        ), "{request}");
                        assert!(
                            !request.contains("votport_d_"),
                            "leases no longer ride cookies: {request}"
                        );
                        // Cut the body short: the transfer is interrupted
                        // with the lease already saved in the journal.
                        (200, String::new(), bytes[..5].to_vec(), Some(bytes.len()))
                    }
                    // The retry resumes from the journal's saved final URL.
                    8 => {
                        assert!(request.starts_with(
                            "get /api/s/token/files/0?download_lease=abcdef0123456789.0123456789abcdef http"
                        ), "{request}");
                        assert!(request.contains("range: bytes=5-"), "{request}");
                        assert!(!request.contains("votport_d_"), "{request}");
                        (
                            206,
                            format!(
                                "Content-Range: bytes 5-{}/{}\r\n",
                                bytes.len() - 1,
                                bytes.len()
                            ),
                            bytes[5..].to_vec(),
                            None,
                        )
                    }
                    9 => {
                        assert!(request.starts_with("get /api/s/token/files/1 http"));
                        assert!(
                            !request.contains("download_lease"),
                            "previous file's lease leaked: {request}"
                        );
                        assert!(!request.contains("range:"), "{request}");
                        (
                            307,
                            "Location: /api/s/token/files/1?download_lease=1234567890abcdef.fedcba9876543210\r\n"
                                .to_owned(),
                            Vec::new(),
                            Some(0),
                        )
                    }
                    10 => {
                        assert!(request.starts_with(
                            "get /api/s/token/files/1?download_lease=1234567890abcdef.fedcba9876543210 http"
                        ), "{request}");
                        (200, String::new(), bytes.to_vec(), None)
                    }
                    _ => unreachable!(),
                };
                write!(stream, "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n", length.unwrap_or(body.len())).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        let destination = tempfile::tempdir().unwrap();
        fs::write(destination.path().join(".vot-file0.lease"), b"{truncated").unwrap();
        fs::write(
            destination.path().join(".vot-file1.lease"),
            serde_json::to_vec(&(
                format!("{base}/api/s/token/files/0"),
                "wrong-root",
                "votport_d_test_0=lease",
            ))
            .unwrap(),
        )
        .unwrap();
        let target = destination.path().to_owned();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let interrupted = receive_over_http(
                &base,
                Delivery {
                    token: "token".to_owned(),
                    password: Some("password".to_owned()),
                },
                &target,
                &mut crate::progress::Silent,
            );
            assert!(interrupted.is_err(), "the first response was cut");
            let result = receive_over_http(
                &format!("{base}/"),
                Delivery {
                    token: "token".to_owned(),
                    password: Some("password".to_owned()),
                },
                &target,
                &mut crate::progress::Silent,
            );
            let _ = sender.send(result);
        });
        let result = receiver
            .recv_timeout(Duration::from_secs(15))
            .expect("receive stalled");
        assert_eq!(result.unwrap().files.len(), 2);
        server.join().unwrap();
        for index in 0..2 {
            assert_eq!(
                fs::read(destination.path().join(format!("file{index}"))).unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn resume_reuses_only_matching_regular_files() {
        for suite in [Suite::Blake3Bao64, Suite::Sha256Bep52] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("file");
            let bytes = b"completed";
            let mut builder = ObjectBuilder::new(suite, Some(bytes.len() as u64)).unwrap();
            builder.update(bytes).unwrap();
            let object = builder.finish().unwrap().object_id().clone();
            let root = object.root;
            let mut observer = crate::progress::Silent;
            assert!(!reusable_file(&path, &object, true, &mut observer).unwrap());
            fs::write(&path, bytes).unwrap();
            assert!(matches!(
                reusable_file(&path, &object, false, &mut observer),
                Err(Error::Exists { .. })
            ));
            assert!(reusable_file(&path, &object, true, &mut observer).unwrap());
            for (hash, length) in [(root, 8), (root, 10), ([0; 32], 9)] {
                assert!(matches!(
                    reusable_file(
                        &path,
                        &ObjectId {
                            suite: object.suite,
                            root: hash,
                            length
                        },
                        true,
                        &mut observer
                    ),
                    Err(Error::Exists { .. })
                ));
                assert_eq!(fs::read(&path).unwrap(), bytes);
            }
            assert!(matches!(
                reusable_file(dir.path(), &object, true, &mut observer),
                Err(Error::Exists { .. })
            ));
            #[cfg(unix)]
            {
                let link = dir.path().join("link");
                std::os::unix::fs::symlink(&path, &link).unwrap();
                assert!(matches!(
                    reusable_file(&link, &object, true, &mut observer),
                    Err(Error::Exists { .. })
                ));
                assert_eq!(fs::read(&path).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn resume_hashing_checks_cancellation_replacement_and_growth() {
        struct Change<'a> {
            path: &'a Path,
            action: u8,
            done: std::cell::Cell<bool>,
        }
        impl Observer for Change<'_> {
            fn event(&mut self, _: Event) {}
            fn cancelled(&self) -> bool {
                if !self.done.replace(true) {
                    match self.action {
                        0 => return true,
                        1 => {
                            fs::rename(self.path, self.path.with_extension("old")).unwrap();
                            fs::write(self.path, b"same").unwrap();
                        }
                        2 => {
                            use std::io::Write;
                            fs::OpenOptions::new()
                                .append(true)
                                .open(self.path)
                                .unwrap()
                                .write_all(b"extra")
                                .unwrap();
                        }
                        _ => unreachable!(),
                    }
                }
                false
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        let mut builder = ObjectBuilder::new(Suite::Blake3Bao64, Some(4)).unwrap();
        builder.update(b"same").unwrap();
        let root = builder.finish().unwrap().object_id().root;
        for action in 0..3 {
            fs::write(&path, b"same").unwrap();
            let result = reusable_file(
                &path,
                &ObjectId {
                    suite: 1,
                    root,
                    length: 4,
                },
                true,
                &mut Change {
                    path: &path,
                    action,
                    done: std::cell::Cell::new(false),
                },
            );
            if action == 0 {
                assert!(matches!(result, Err(Error::Cancelled)));
            } else {
                assert!(matches!(result, Err(Error::Exists { .. })), "{result:?}");
            }
        }
    }

    #[test]
    fn receive_paths_allow_missing_directories_and_reject_file_parents() {
        let home = tempfile::tempdir().unwrap();
        let dest = home.path().join("new/root");
        assert_eq!(
            local_path(&dest, "nested/file").unwrap(),
            dest.join("nested/file")
        );
        assert!(!dest.exists());
        assert_eq!(
            local_paths(&dest, ["nested/a", "nested/b", "other/c"])
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            [
                dest.join("nested/a"),
                dest.join("nested/b"),
                dest.join("other/c")
            ]
        );
        assert!(local_paths(&dest, ["nested/a", "../escape"])
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .is_err());
        fs::write(home.path().join("file"), b"untouched").unwrap();
        assert!(local_path(home.path(), "file/child").is_err());
        assert!(resolve_directory(&home.path().join("missing/../file")).is_err());
        assert_eq!(fs::read(home.path().join("file")).unwrap(), b"untouched");
    }

    #[cfg(unix)]
    #[test]
    fn receive_paths_confine_nested_links_but_allow_root_and_inside_aliases() {
        use std::os::unix::fs::symlink;
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("root");
        let outside = home.path().join("root-other");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        let alias = home.path().join("selected-alias");
        symlink(&root, &alias).unwrap();
        assert_eq!(
            local_path(&alias, "new/file").unwrap(),
            alias.join("new/file")
        );
        symlink(&outside, root.join("escape")).unwrap();
        let error = local_path(&root, "escape/file").unwrap_err();
        assert!(error.worth_retrying());
        let announced = admit("escape/file", PathBuf::new(), true).unwrap();
        assert!(local_path_of(&root, &announced.path).is_err());
        assert!(local_paths(&root, ["ok", "escape/file"])
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .is_err());
        fs::create_dir(root.join("real")).unwrap();
        symlink(root.join("real"), root.join("inside")).unwrap();
        assert_eq!(
            local_path(&root, "inside/new/file").unwrap(),
            root.join("inside/new/file")
        );
        symlink(outside.join("missing"), root.join("dangling")).unwrap();
        assert!(local_path(&root, "dangling/file").is_err());
        let unusual_root = root.join("missing/../inside");
        assert_eq!(
            resolve_directory(&unusual_root).unwrap(),
            fs::canonicalize(root.join("real")).unwrap()
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        let planned = local_paths(&root, ["real/a", "real/b"])
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        fs::remove_dir(root.join("real")).unwrap();
        symlink(&outside, root.join("real")).unwrap();
        assert!(validate_parent(&root, &planned[0]).is_err());
    }

    fn receive_from(
        destination: &Path,
        bytes: &[u8],
        source: &mut dyn FnMut(u64) -> Result<Resumed>,
    ) -> Result<()> {
        let mut builder = ObjectBuilder::new(Suite::Blake3Bao64, Some(bytes.len() as u64))?;
        builder.update(bytes)?;
        let root = builder.finish()?.object_id().root;
        write_verified(
            source,
            destination,
            &ObjectId {
                suite: 1,
                root,
                length: bytes.len() as u64,
            },
            0,
            &mut crate::progress::Silent,
        )
    }

    fn object_for(bytes: &[u8], suite: Suite) -> ObjectId {
        let mut builder = ObjectBuilder::new(suite, Some(bytes.len() as u64)).unwrap();
        builder.update(bytes).unwrap();
        builder.finish().unwrap().object_id().clone()
    }

    fn seed_partial(destination: &Path, object: &ObjectId, bytes: &[u8]) {
        fs::write(part_path(destination), bytes).unwrap();
        let mut identity = open_receive_file(&identity_path(destination), true).unwrap();
        write_identity(&mut identity, &identity_path(destination), object).unwrap();
    }

    fn stream(bytes: &[u8], start: u64) -> Resumed {
        Resumed {
            reader: Box::new(std::io::Cursor::new(bytes.to_vec())),
            start,
        }
    }

    #[test]
    fn a_second_writer_is_rejected_before_opening_its_source() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("file");
        receive_from(&destination, b"abcd", &mut |offset| {
            assert_eq!(offset, 0);
            let second = receive_from(&destination, b"abcd", &mut |_| {
                panic!("second writer opened its source")
            });
            assert!(matches!(second, Err(Error::Other(_))), "{second:?}");
            Ok(stream(b"abcd", 0))
        })
        .unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"abcd");
        assert!(!part_path(&destination).exists());
    }

    #[test]
    fn a_stale_open_handle_cannot_lock_a_replacement_journal() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("journal");
        let published = dir.path().join("published");
        fs::write(&journal, b"published bytes").unwrap();
        let stale = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&journal)
            .unwrap();
        fs::rename(&journal, &published).unwrap();
        fs::write(&journal, b"another writer").unwrap();
        assert!(lock_journal(stale, &journal).is_err());
        assert_eq!(fs::read(&published).unwrap(), b"published bytes");
        assert_eq!(fs::read(&journal).unwrap(), b"another writer");
    }

    #[test]
    fn resumes_and_full_responses_use_the_locked_journal() {
        for restart in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let destination = dir.path().join("file");
            seed_partial(
                &destination,
                &object_for(b"abcd", Suite::Blake3Bao64),
                b"ab",
            );
            receive_from(&destination, b"abcd", &mut |offset| {
                assert_eq!(offset, 2);
                Ok(if restart {
                    stream(b"abcd", 0)
                } else {
                    stream(b"cd", offset)
                })
            })
            .unwrap();
            assert_eq!(fs::read(destination).unwrap(), b"abcd");
        }
        for initial in [b"abcd".as_slice(), b"abcde"] {
            let dir = tempfile::tempdir().unwrap();
            let destination = dir.path().join("file");
            seed_partial(
                &destination,
                &object_for(b"abcd", Suite::Blake3Bao64),
                initial,
            );
            receive_from(&destination, b"abcd", &mut |offset| {
                assert_eq!(offset, 0);
                Ok(stream(b"abcd", 0))
            })
            .unwrap();
            assert_eq!(fs::read(destination).unwrap(), b"abcd");
        }
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("empty");
        receive_from(&destination, b"", &mut |offset| {
            assert_eq!(offset, 0);
            Ok(stream(b"", 0))
        })
        .unwrap();
        assert!(fs::read(destination).unwrap().is_empty());
    }

    #[test]
    fn source_errors_leave_existing_journal_bytes_unchanged() {
        for initial in [b"ab".as_slice(), b"abcd", b"abcde"] {
            let dir = tempfile::tempdir().unwrap();
            let destination = dir.path().join("file");
            let journal = part_path(&destination);
            let object = object_for(b"abcd", Suite::Blake3Bao64);
            seed_partial(&destination, &object, initial);
            let result = receive_from(&destination, b"abcd", &mut |offset| {
                assert_eq!(offset, if initial.len() < 4 { 2 } else { 0 });
                Err(Error::Other("source unavailable".to_owned()))
            });
            assert!(result.is_err());
            assert_eq!(fs::read(journal).unwrap(), initial);
        }
    }

    #[test]
    fn receive_identity_fits_the_existing_journal_filename_limit() {
        for name in ["a".repeat(242), format!("{}ab", "ア".repeat(80))] {
            let directory = tempfile::tempdir().unwrap();
            let destination = directory.path().join(name);
            receive_from(&destination, b"data", &mut |offset| {
                assert_eq!(offset, 0);
                Ok(stream(b"data", 0))
            })
            .unwrap();
            assert_eq!(fs::read(&destination).unwrap(), b"data");
            assert!(!identity_path(&destination).exists());
        }
    }

    #[test]
    fn partial_identity_restarts_other_objects_and_preserves_same_object_resume() {
        let object_a = object_for(b"aaaa", Suite::Blake3Bao64);
        let object_b = object_for(b"bbbb", Suite::Blake3Bao64);

        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("different");
        let result = write_verified(
            &mut |_| Ok(stream(b"aa", 0)),
            &destination,
            &object_a,
            0,
            &mut crate::progress::Silent,
        );
        assert!(matches!(
            result,
            Err(Error::Object(vot_object::Error::LengthMismatch))
        ));
        assert_eq!(fs::read(part_path(&destination)).unwrap(), b"aa");
        assert!(identity_path(&destination).is_file());
        let mut requested = Vec::new();
        write_verified(
            &mut |offset| {
                requested.push(offset);
                assert_eq!(offset, 0);
                Ok(stream(b"bbbb", 0))
            },
            &destination,
            &object_b,
            0,
            &mut crate::progress::Silent,
        )
        .unwrap();
        assert_eq!(requested, [0]);
        assert_eq!(fs::read(&destination).unwrap(), b"bbbb");
        assert!(!part_path(&destination).exists());
        assert!(!identity_path(&destination).exists());

        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("same");
        seed_partial(&destination, &object_a, b"aa");
        write_verified(
            &mut |offset| {
                assert_eq!(offset, 2);
                Ok(stream(b"aa", offset))
            },
            &destination,
            &object_a,
            0,
            &mut crate::progress::Silent,
        )
        .unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"aaaa");
        assert!(!identity_path(&destination).exists());

        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("source-error");
        let journal = part_path(&destination);
        let identity = identity_path(&destination);
        seed_partial(&destination, &object_a, b"aa");
        let old_identity = fs::read(&identity).unwrap();
        let result = write_verified(
            &mut |offset| {
                assert_eq!(offset, 0);
                Err(Error::Other("source unavailable".to_owned()))
            },
            &destination,
            &object_b,
            0,
            &mut crate::progress::Silent,
        );
        assert!(result.is_err());
        assert_eq!(fs::read(journal).unwrap(), b"aa");
        assert_eq!(fs::read(identity).unwrap(), old_identity);

        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("short");
        let result = write_verified(
            &mut |_| Ok(stream(b"aa", 0)),
            &destination,
            &object_a,
            0,
            &mut crate::progress::Silent,
        );
        assert!(matches!(
            result,
            Err(Error::Object(vot_object::Error::LengthMismatch))
        ));
        assert_eq!(fs::read(part_path(&destination)).unwrap(), b"aa");
        assert!(identity_path(&destination).is_file());

        struct Cancelled;
        impl Observer for Cancelled {
            fn event(&mut self, _: Event) {}
            fn cancelled(&self) -> bool {
                true
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("cancelled");
        let result = write_verified(
            &mut |_| Ok(stream(b"aaaa", 0)),
            &destination,
            &object_a,
            0,
            &mut Cancelled,
        );
        assert!(matches!(result, Err(Error::Cancelled)));
        assert!(part_path(&destination).is_file());
        assert!(identity_path(&destination).is_file());
    }

    #[test]
    fn identity_replacements_are_not_adopted_during_reset() {
        let object_a = object_for(b"aaaa", Suite::Blake3Bao64);
        let object_b = object_for(b"bbbb", Suite::Blake3Bao64);

        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("existing");
        let journal = part_path(&destination);
        let identity = identity_path(&destination);
        let moved = dir.path().join("moved-identity");
        seed_partial(&destination, &object_a, b"aa");
        let old_identity = fs::read(&identity).unwrap();
        let result = write_verified(
            &mut |_| {
                fs::rename(&identity, &moved).unwrap();
                fs::write(&identity, b"external owner").unwrap();
                Ok(stream(b"bbbb", 0))
            },
            &destination,
            &object_b,
            0,
            &mut crate::progress::Silent,
        );
        assert!(matches!(result, Err(Error::Other(_))), "{result:?}");
        assert_eq!(fs::read(&journal).unwrap(), b"aa");
        assert_eq!(fs::read(&moved).unwrap(), old_identity);
        assert_eq!(fs::read(&identity).unwrap(), b"external owner");
        assert!(!destination.exists());

        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("absent");
        let journal = part_path(&destination);
        let identity = identity_path(&destination);
        fs::write(&journal, b"aa").unwrap();
        let result = write_verified(
            &mut |_| {
                fs::write(&identity, b"external owner").unwrap();
                Ok(stream(b"bbbb", 0))
            },
            &destination,
            &object_b,
            0,
            &mut crate::progress::Silent,
        );
        assert!(
            matches!(result, Err(Error::Io(ref error)) if error.kind() == std::io::ErrorKind::AlreadyExists),
            "{result:?}"
        );
        assert_eq!(fs::read(&journal).unwrap(), b"aa");
        assert_eq!(fs::read(&identity).unwrap(), b"external owner");
        assert!(!destination.exists());
    }

    #[test]
    fn malformed_or_mismatched_partial_identity_starts_at_zero() {
        let object = object_for(b"abcd", Suite::Blake3Bao64);
        for identity_bytes in [
            b"bad identity".as_slice(),
            &encode_identity(&ObjectId {
                suite: 2,
                root: object.root,
                length: object.length,
            }),
            &encode_identity(&ObjectId {
                suite: object.suite,
                root: object.root,
                length: object.length + 1,
            }),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let destination = dir.path().join("file");
            fs::write(part_path(&destination), b"ab").unwrap();
            fs::write(identity_path(&destination), identity_bytes).unwrap();
            write_verified(
                &mut |offset| {
                    assert_eq!(offset, 0);
                    Ok(stream(b"abcd", 0))
                },
                &destination,
                &object,
                0,
                &mut crate::progress::Silent,
            )
            .unwrap();
            assert_eq!(fs::read(destination).unwrap(), b"abcd");
        }

        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("missing");
        fs::write(part_path(&destination), b"ab").unwrap();
        write_verified(
            &mut |offset| {
                assert_eq!(offset, 0);
                Ok(stream(b"abcd", 0))
            },
            &destination,
            &object,
            0,
            &mut crate::progress::Silent,
        )
        .unwrap();
        assert_eq!(fs::read(destination).unwrap(), b"abcd");
    }

    #[test]
    fn publication_refuses_a_destination_created_during_the_receive() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("file");
        let result = receive_from(&destination, b"abcd", &mut |_| {
            fs::write(&destination, b"other owner").unwrap();
            Ok(stream(b"abcd", 0))
        });
        assert!(matches!(result, Err(Error::Exists { .. })), "{result:?}");
        assert_eq!(fs::read(destination).unwrap(), b"other owner");
    }

    #[test]
    fn failed_publication_leaves_cleanup_to_the_locked_owner() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("file");
        let temporary = part_path(&destination);
        fs::write(&temporary, b"abcd").unwrap();
        fs::write(&destination, b"existing").unwrap();
        let journal = open_journal(&temporary).unwrap();
        let mut expected = ObjectBuilder::new(Suite::Blake3Bao64, Some(4)).unwrap();
        expected.update(b"abcd").unwrap();
        let root = expected.finish().unwrap().object_id().root;
        let mut builder = ObjectBuilder::new(Suite::Blake3Bao64, Some(4)).unwrap();
        builder.update(b"abcd").unwrap();
        let result = verify_and_rename(
            builder,
            &destination,
            root,
            "expected",
            &temporary,
            &journal,
        );
        assert!(matches!(result, Err(Error::Exists { .. })), "{result:?}");
        assert!(vot_platform_fs::same_file_handle(&journal, &temporary).unwrap());
        drop(journal);
        assert_eq!(fs::read(temporary).unwrap(), b"abcd");
        assert_eq!(fs::read(destination).unwrap(), b"existing");
    }

    #[test]
    fn publication_and_cleanup_do_not_take_a_replacement_journal() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("file");
        let journal = part_path(&destination);
        let moved = dir.path().join("moved");
        let result = receive_from(&destination, b"abcd", &mut |_| {
            fs::rename(&journal, &moved).unwrap();
            fs::write(&journal, b"another writer").unwrap();
            Ok(stream(b"abcd", 0))
        });
        assert!(matches!(result, Err(Error::Other(_))), "{result:?}");
        assert_eq!(fs::read(&journal).unwrap(), b"another writer");
        assert_eq!(fs::read(moved).unwrap(), b"abcd");
        assert!(!destination.exists());
    }

    #[test]
    fn a_wrong_root_removes_only_its_owned_journal() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("file");
        let result = receive_from(&destination, b"abcd", &mut |_| Ok(stream(b"wxyz", 0)));
        assert!(matches!(result, Err(Error::Verify { .. })), "{result:?}");
        assert!(!part_path(&destination).exists());
        assert!(!identity_path(&destination).exists());
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn journal_symlinks_and_nonregular_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("file");
        let victim = dir.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, part_path(&destination)).unwrap();
        assert!(receive_from(&destination, b"abcd", &mut |_| panic!(
            "symlink reached source"
        ))
        .is_err());
        assert_eq!(fs::read(victim).unwrap(), b"untouched");
        assert!(lock_journal(File::open(dir.path()).unwrap(), dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_destination_symlinks_are_never_overwritten() {
        for during_receive in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let destination = dir.path().join("file");
            let absent = dir.path().join("absent");
            if !during_receive {
                std::os::unix::fs::symlink(&absent, &destination).unwrap();
            }
            let result = receive_from(&destination, b"abcd", &mut |_| {
                assert!(during_receive, "existing destination reached source");
                std::os::unix::fs::symlink(&absent, &destination).unwrap();
                Ok(stream(b"abcd", 0))
            });
            assert!(matches!(result, Err(Error::Exists { .. })), "{result:?}");
            assert_eq!(fs::read_link(destination).unwrap(), absent);
        }
    }

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
