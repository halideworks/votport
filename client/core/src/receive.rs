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
use vot_object::{ObjectBuilder, Suite};

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
        Outcome::Unreachable => receive_over_http_inner(base, delivery, dest, observer, resume),
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
        Err(_) => receive_over_http_inner(base, delivery, dest, observer, resume),
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
    receive_over_http_inner(base, delivery, dest, observer, false)
}

fn receive_over_http_inner(
    base: &str,
    delivery: Delivery,
    dest: &Path,
    observer: &mut dyn Observer,
    resume: bool,
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
            let complete = reusable_file(&path, root, file.bytes, resume, observer)?;
            Ok((file, path, root, complete))
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
    for (index, (file, path, root, complete)) in planned.into_iter().enumerate() {
        if observer.cancelled() {
            return Err(Error::Cancelled);
        }
        if !complete {
            let mut source = |offset: u64| -> Result<Resumed> {
                let (response, start) =
                    client.download(&file.download_url, cookie, offset, file.bytes)?;
                Ok(Resumed {
                    reader: Box::new(response),
                    start,
                })
            };
            write_verified(
                &mut source,
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
        }
        files.push(path);
    }
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
    announced: [u8; 32],
    announced_hex: &str,
    total: u64,
    index: usize,
    observer: &mut dyn Observer,
) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = part_path(destination);
    let mut journal = open_journal(&temporary)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(Error::Exists {
                path: destination.to_owned(),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    // Resume: hash any prior partial into the builder and continue past it. A
    // partial that hashes to the wrong root fails at finish and is removed, so
    // the next run starts clean; a bad prefix cannot land silently.
    let mut builder = ObjectBuilder::new(Suite::Blake3Bao64, Some(total))?;
    let mut resume_from = feed_partial(&mut journal, &mut builder, total)?;
    let resumed = source(resume_from)?;
    if resumed.start != resume_from {
        if resumed.start != 0 {
            return Err(Error::Other(format!(
                "the source resumed at {} but {resume_from} was requested",
                resumed.start
            )));
        }
        // The source gave the whole file rather than the range: start over.
        builder = ObjectBuilder::new(Suite::Blake3Bao64, Some(total))?;
        resume_from = 0;
    }
    let mut reader = resumed.reader;

    // A stream failure keeps the partial for the next run to resume; only a
    // verification failure removes it.
    stream_to_temp(
        &mut journal,
        &mut *reader,
        &mut builder,
        resume_from,
        total,
        index,
        observer,
    )?;
    match verify_and_rename(
        builder,
        destination,
        announced,
        announced_hex,
        &temporary,
        &journal,
    ) {
        Ok(()) => Ok(()),
        // A stream that ended short (the builder's LengthMismatch) leaves a
        // usable prefix, so the partial stays to resume. Any other failure
        // means finish already produced a complete file: a wrong root is
        // poison, and a landed file or a rename race leaves a full-size partial
        // the next run would only discard, so all of these remove it.
        Err(error) => {
            if !matches!(error, Error::Object(vot_object::Error::LengthMismatch))
                && vot_platform_fs::same_file_handle(&journal, &temporary).unwrap_or(false)
            {
                let _ = fs::remove_file(&temporary);
            }
            Err(error)
        }
    }
}

/// The resumable temporary beside `destination`: a hidden `.vot-<name>.journal`
/// in its directory. That shape is one `admit` refuses, so no delivered file
/// lands on it, and no common tool produces it, so a browser's `<name>.part`
/// or a user's own file is never mistaken for votport's partial and destroyed.
fn part_path(destination: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".vot-");
    name.push(destination.file_name().unwrap_or_default());
    name.push(".journal");
    match destination.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

fn open_receive_file(path: &Path, write: bool) -> Result<File> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(write)
        .create(write)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
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
    root: [u8; 32],
    total: u64,
    resume: bool,
    observer: &mut dyn Observer,
) -> Result<bool> {
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
    let mut builder = ObjectBuilder::new(Suite::Blake3Bao64, Some(total))?;
    let mut buffer = vec![0u8; READ_CHUNK];
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
        || !root_matches(&prepared.object_id().root, &root)
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
    let mut buffer = vec![0u8; READ_CHUNK];
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
    sink.sync_all()?;
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
    let mut buffer = vec![0u8; READ_CHUNK];
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
    fn resume_reuses_only_matching_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        let bytes = b"completed";
        let mut builder = ObjectBuilder::new(Suite::Blake3Bao64, Some(bytes.len() as u64)).unwrap();
        builder.update(bytes).unwrap();
        let root = builder.finish().unwrap().object_id().root;
        let mut observer = crate::progress::Silent;
        assert!(!reusable_file(&path, root, 9, true, &mut observer).unwrap());
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            reusable_file(&path, root, 9, false, &mut observer),
            Err(Error::Exists { .. })
        ));
        assert!(reusable_file(&path, root, 9, true, &mut observer).unwrap());
        for (hash, length) in [(root, 8), (root, 10), ([0; 32], 9)] {
            assert!(matches!(
                reusable_file(&path, hash, length, true, &mut observer),
                Err(Error::Exists { .. })
            ));
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        assert!(matches!(
            reusable_file(dir.path(), root, 9, true, &mut observer),
            Err(Error::Exists { .. })
        ));
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(matches!(
                reusable_file(&link, root, 9, true, &mut observer),
                Err(Error::Exists { .. })
            ));
            assert_eq!(fs::read(&path).unwrap(), bytes);
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
                root,
                4,
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
            root,
            "expected",
            bytes.len() as u64,
            0,
            &mut crate::progress::Silent,
        )
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
            fs::write(part_path(&destination), b"ab").unwrap();
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
            fs::write(part_path(&destination), initial).unwrap();
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
            fs::write(&journal, initial).unwrap();
            let result = receive_from(&destination, b"abcd", &mut |offset| {
                assert_eq!(offset, if initial.len() < 4 { 2 } else { 0 });
                Err(Error::Other("source unavailable".to_owned()))
            });
            assert!(result.is_err());
            assert_eq!(fs::read(journal).unwrap(), initial);
        }
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
