//! One send, end to end: inspect the link, validate the drop, build the
//! manifest once, and move the bytes over push or HTTP.
//!
//! Push is tried first when the link offers it: a 2 second QUIC probe decides
//! whether the receiver's carrier is reachable before anything is reserved. A
//! network that will not carry QUIC falls back to the HTTP session path the
//! web sender uses.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tempfile::TempDir;

use crate::api::{Client, FinishReport, LinkInfo};
use crate::error::{Error, Result};
use crate::identity::{state_dir, Device};
use crate::package::{self, Prepared};
use crate::progress::{Event, Observer, PlannedFile};
use crate::send_push::Outcome;
use crate::{entries, send_http, send_push};

/// Where a send's staging lives: under the state directory, not the OS
/// temp dir. A manifest names every source path and object root, so a
/// package left by a killed send must not sit in a shared location.
fn staging_root() -> PathBuf {
    state_dir().join("staging")
}

/// A send that is killed skips `TempDir`'s Drop, so its staging directory
/// would otherwise outlive it forever. Directories older than a week are
/// from a run that died; no send holds one that long without finishing or
/// failing. Swept each time a send stages, which bounds the leftover's
/// life to the next launch of a send.
fn age_staging(now: SystemTime) {
    let week = Duration::from_secs(7 * 24 * 60 * 60);
    let Ok(entries) = std::fs::read_dir(staging_root()) else {
        return;
    };
    for entry in entries.flatten() {
        let expired = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| match now.duration_since(modified) {
                Ok(age) => age >= week,
                Err(_) => false,
            });
        if expired {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// A fresh staging directory for one send, under the state directory.
fn new_staging() -> Result<TempDir> {
    age_staging(SystemTime::now());
    std::fs::create_dir_all(staging_root())?;
    Ok(tempfile::Builder::new()
        .prefix("votport-manifest-")
        .tempdir_in(staging_root())?)
}

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

/// Collects the files under `path` into selections, as a Finder or Explorer
/// drop would: a file keeps its own name; a folder keeps its name as the top
/// component. Symlinks are refused as an argument and skipped inside a folder,
/// matching the manifest build's refusal of them.
///
/// # Errors
/// A symlink argument, a nameless folder, or a read failure.
pub fn collect(path: &Path, out: &mut Vec<Selected>) -> std::io::Result<()> {
    collect_for_link(path, out, true)
}

/// Collects a path using the request link's hidden-name policy.
///
/// # Errors
/// A symlink argument, a nameless folder, or a read failure.
pub fn collect_for_link(
    path: &Path,
    out: &mut Vec<Selected>,
    allow_hidden: bool,
) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        // A symlink arg would otherwise be neither file nor dir and yield
        // nothing silently.
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "symlinks are not sent",
        ));
    }
    if metadata.is_file() {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned());
        out.push(Selected {
            relative: name,
            source: path.to_path_buf(),
        });
        return Ok(());
    }
    if metadata.is_dir() {
        // `.` and `..` have no file name; canonicalize so the folder keeps its
        // real name instead of flattening into the drop root.
        let top = match path.file_name() {
            Some(name) => name.to_string_lossy().into_owned(),
            None => std::fs::canonicalize(path)?
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "the folder has no name")
                })?,
        };
        walk(path, &top, out, allow_hidden)?;
    }
    Ok(())
}

/// Recursively adds files under `dir`, each relative to `prefix`.
fn walk(
    dir: &Path,
    prefix: &str,
    out: &mut Vec<Selected>,
    allow_hidden: bool,
) -> std::io::Result<()> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<_>>()?;
    entries.sort();
    for entry in entries {
        let name = entry
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        if !allow_hidden && name.starts_with('.') {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&entry)?;
        let relative = format!("{prefix}/{name}");
        if metadata.file_type().is_symlink() {
            // Never follow a directory symlink. This also stops cycles before
            // traversal reaches them.
            continue;
        }
        if metadata.is_dir() {
            walk(&entry, &relative, out, allow_hidden)?;
        } else if metadata.is_file() {
            out.push(Selected {
                relative,
                source: entry,
            });
        }
    }
    Ok(())
}

/// How a drop was sent.
pub enum Sent {
    /// Over the HTTP session path, with its finish report.
    Http(FinishReport),
    /// Over the QUIC push path; `files` were pushed.
    Push { files: usize },
}

/// A journalled HTTP session to reconnect after a paused or retryable send.
pub struct HttpResume<'a> {
    pub session: &'a str,
    pub chunk_bytes: u64,
    pub root: &'a str,
    pub length: u64,
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

/// Inspects the link, validates the drop, and builds the manifest. The files
/// are announced to `observer` before the hash pass, in selection order, so a
/// screen lists them while hashing runs; the manifest's canonical order is
/// announced again once it is built.
fn prepare(base: &str, drop: Drop, observer: &mut dyn Observer) -> Result<Ready> {
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
    let mut selected = Vec::with_capacity(admitted.len());
    for (index, entry) in admitted.iter().enumerate() {
        let bytes = std::fs::symlink_metadata(&entry.source)
            .map_err(|source| Error::Read {
                path: entry.source.clone(),
                source,
            })?
            .len();
        total += bytes;
        selected.push(PlannedFile {
            index,
            path: package::package_path_string(&entry.path),
            bytes,
        });
    }
    if total > info.max_bytes {
        return Err(Error::TooLarge {
            total,
            limit: info.max_bytes,
        });
    }
    observer.event(Event::Selected { files: selected });

    let staging: TempDir = new_staging()?;
    let manifest_root = staging.path().join("manifest-root");
    let prepared = package::build(admitted, &manifest_root)?;
    // Hashing a large drop takes minutes and cannot be interrupted midway;
    // a Cancel or Pause pressed meanwhile takes effect here, before any
    // session is opened.
    if observer.cancelled() {
        return Err(Error::Cancelled);
    }

    Ok(Ready {
        client,
        token: drop.token,
        password: drop.password,
        info,
        prepared,
        _staging: staging,
    })
}

/// Announces the files the send will move, in begin order.
fn announce(prepared: &Prepared, observer: &mut dyn Observer) {
    observer.event(Event::Planned {
        files: prepared
            .objects
            .iter()
            .enumerate()
            .map(|(index, entry)| PlannedFile {
                index,
                path: entry.path.clone(),
                bytes: entry.object.length,
            })
            .collect(),
    });
}

/// Sends `drop` to the votport at `base`, preferring push when the link offers
/// it and the receiver's carrier answers a probe, falling back to HTTP.
///
/// # Errors
/// An unusable or password-protected link, a refused file, an empty or
/// oversized drop, a build failure, or a transport error.
pub fn send(base: &str, drop: Drop, device: &Device, observer: &mut dyn Observer) -> Result<Sent> {
    send_with_session(base, drop, device, observer, None, |_, _, _| Ok(false))
}

/// Sends a drop, reconnecting to `resume` when it names a previous HTTP
/// session. The callback durably records the session after its first begin.
pub fn send_with_session(
    base: &str,
    drop: Drop,
    device: &Device,
    observer: &mut dyn Observer,
    resume: Option<HttpResume<'_>>,
    mut on_http_begin: impl FnMut(&str, u64, &Prepared) -> Result<bool>,
) -> Result<Sent> {
    if let Some(resume) = resume.as_ref() {
        if !send_http::valid_resume_metadata(resume.session, resume.chunk_bytes) {
            return Err(Error::ResumeSessionInvalid);
        }
    }
    let ready = prepare(base, drop, observer)?;
    announce(&ready.prepared, observer);
    if let Some(resume) = resume {
        if resume.root != hex::encode(ready.prepared.summary.root)
            || resume.length != ready.prepared.summary.logical_length
        {
            return Err(Error::ResumeSourceChanged);
        }
        let report = send_http::send_with_session(
            &ready.client,
            &ready.token,
            ready.password.as_deref(),
            &ready.prepared,
            observer,
            Some((resume.session, resume.chunk_bytes)),
            &mut on_http_begin,
        )?;
        return Ok(Sent::Http(report));
    }
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
    let report = send_http::send_with_session(
        &ready.client,
        &ready.token,
        ready.password.as_deref(),
        &ready.prepared,
        observer,
        None,
        &mut on_http_begin,
    )?;
    Ok(Sent::Http(report))
}

/// Sends `drop` over the HTTP session path only, never push. The end-to-end
/// test drives this directly.
///
/// # Errors
/// The same as [`send`], minus the push path.
pub fn send_http(base: &str, drop: Drop, observer: &mut dyn Observer) -> Result<FinishReport> {
    let ready = prepare(base, drop, observer)?;
    announce(&ready.prepared, observer);
    send_http::send(
        &ready.client,
        &ready.token,
        ready.password.as_deref(),
        &ready.prepared,
        observer,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn collect_for_link_skips_hidden_descendants_only_when_disallowed() {
        let root = tempfile::tempdir().unwrap();
        let folder = root.path().join("folder");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("visible.txt"), b"visible").unwrap();
        std::fs::write(folder.join(".DS_Store"), b"metadata").unwrap();

        let mut selected = Vec::new();
        collect_for_link(&folder, &mut selected, false).unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|file| file.relative.as_str())
                .collect::<Vec<_>>(),
            ["folder/visible.txt"]
        );
        selected.clear();
        collect_for_link(&folder, &mut selected, true).unwrap();
        assert_eq!(selected.len(), 2);
        assert!(selected
            .iter()
            .any(|file| file.relative == "folder/.DS_Store"));

        let hidden_only = root.path().join("hidden-only");
        std::fs::create_dir(&hidden_only).unwrap();
        std::fs::write(hidden_only.join(".DS_Store"), b"metadata").unwrap();
        selected.clear();
        collect_for_link(&hidden_only, &mut selected, false).unwrap();
        assert!(selected.is_empty());
    }

    /// A killed send skips `TempDir`'s Drop, so the manifest it staged
    /// (every source path and object root) must land under the state
    /// directory, where a later send ages it out, not the OS temp dir.
    #[test]
    fn staging_lives_in_the_state_dir_and_a_killed_send_leftover_ages_out() {
        let root = tempfile::tempdir().unwrap();
        let _state = crate::identity::test_state_dir(root.path());

        // Staging lands under the state directory, never the OS temp dir.
        let staging = new_staging().unwrap();
        assert!(staging.path().starts_with(root.path()));

        // A send that was killed left its manifest behind, and a later
        // launch of a send sweeps it once it is old. A live send's fresh
        // staging survives the sweep.
        let leftover = staging_root().join("votport-manifest-killed");
        std::fs::create_dir_all(leftover.join("manifest-root")).unwrap();
        std::fs::write(
            leftover.join("manifest-root/0000000000000000.cbor"),
            b"paths",
        )
        .unwrap();
        #[cfg(unix)]
        {
            let killed = std::fs::File::open(&leftover).unwrap();
            let age = SystemTime::now() - Duration::from_secs(8 * 24 * 60 * 60);
            killed
                .set_times(std::fs::FileTimes::new().set_modified(age))
                .unwrap();
        }
        let live = staging_root().join("votport-manifest-live");
        std::fs::create_dir_all(&live).unwrap();
        age_staging(SystemTime::now());
        #[cfg(unix)]
        assert!(!leftover.exists(), "the killed send's manifest survived");
        assert!(live.exists(), "a running send's staging was swept");
        assert!(
            staging.path().exists(),
            "the active send's staging was swept"
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_refuses_symlink_arguments_and_skips_symlink_descendants() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let folder = root.path().join("folder");
        let outside = root.path().join("outside.txt");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("visible.txt"), b"visible").unwrap();
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, folder.join("outside.txt")).unwrap();
        symlink(&folder, folder.join("cycle")).unwrap();
        let argument = root.path().join("argument-link");
        symlink(&outside, &argument).unwrap();

        let mut selected = Vec::new();
        collect(&folder, &mut selected).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].relative, "folder/visible.txt");
        assert!(collect(&argument, &mut Vec::new()).is_err());
    }

    #[test]
    fn invalid_saved_http_metadata_is_rejected_before_prepare() {
        let device_dir = tempfile::tempdir().unwrap();
        let device = Device::load_or_create_in(device_dir.path()).unwrap();
        let mut observer = crate::progress::Silent;
        for (session, chunk_bytes) in [
            ("not-a-session", 65536),
            ("0123456789abcdef0123456789abcdef", 0),
            ("0123456789abcdef0123456789abcdef", 8 * 1024 * 1024 + 1),
        ] {
            let result = send_with_session(
                "http://127.0.0.1:1",
                Drop {
                    token: "token".to_owned(),
                    password: None,
                    files: Vec::new(),
                },
                &device,
                &mut observer,
                Some(HttpResume {
                    session,
                    chunk_bytes,
                    root: "root",
                    length: 1,
                }),
                |_, _, _| Ok(true),
            );
            assert!(matches!(result, Err(Error::ResumeSessionInvalid)));
        }
    }

    /// One request-link route with a `push` link and a push-identity endpoint
    /// whose reply the caller picks, plus a counted HTTP session creation, so
    /// a test can pin which transport the send decision ran. Serves until
    /// dropped; every request is answered immediately.
    struct MockLink {
        base: String,
        session_creates: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
    }

    impl std::ops::Drop for MockLink {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    fn spawn_link_mock(push_identity: (u16, &'static str)) -> MockLink {
        use std::io::{Read as _, Write as _};

        fn serve(
            mut stream: std::net::TcpStream,
            push_identity: (u16, &'static str),
            session_creates: &AtomicUsize,
        ) {
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8];
            while !request.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => request.push(byte[0]),
                    _ => return,
                }
                if request.len() > 8192 {
                    return;
                }
            }
            let head = String::from_utf8_lossy(&request).into_owned();
            let request_line = head.lines().next().unwrap_or_default();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_owned();
            let path = parts
                .next()
                .unwrap_or_default()
                .split('?')
                .next()
                .unwrap_or_default()
                .to_owned();
            let length = head
                .to_ascii_lowercase()
                .split("content-length:")
                .nth(1)
                .and_then(|rest| rest.split("\r\n").next())
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let mut body = vec![0; length];
            let _ = stream.read_exact(&mut body);
            let _ = body;
            let (status, reason, payload): (u16, &str, String) =
                match (method.as_str(), path.as_str()) {
                    ("GET", "/api/r/tok") => (
                        200,
                        "OK",
                        serde_json::json!({
                            "label": "decision", "usable": true, "needs_password": false,
                            "max_bytes": 1_048_576, "chunk_bytes": 65536, "allow_hidden": false,
                            "max_entries": 10, "push": true
                        })
                        .to_string(),
                    ),
                    ("GET", "/api/push-identity") => {
                        (push_identity.0, "Mock", push_identity.1.into())
                    }
                    ("POST", "/api/r/tok/session") => {
                        session_creates.fetch_add(1, Ordering::Relaxed);
                        (500, "Mock", "mock http receiver refused the session".into())
                    }
                    _ => (404, "Not Found", "unexpected request".into()),
                };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let session_creates = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::clone(&session_creates);
        let stopping = Arc::clone(&stop);
        std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => serve(stream, push_identity, &counters),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        MockLink {
            base,
            session_creates,
            stop,
        }
    }

    /// Sends one small file through the real decision in [`send_with_session`].
    fn send_one_file(base: &str) -> Result<Sent> {
        send_one_file_observed(base, &mut crate::progress::Silent)
    }

    fn send_one_file_observed(base: &str, observer: &mut dyn Observer) -> Result<Sent> {
        let device_dir = tempfile::tempdir().unwrap();
        // Staging lives under the state directory; pin a per-test one so a
        // concurrent test's state-dir teardown cannot sweep this send's
        // manifest out from under it.
        let _state = crate::identity::test_state_dir(device_dir.path());
        let device = Device::load_or_create_in(device_dir.path()).unwrap();
        let source = tempfile::tempdir().unwrap();
        let file = source.path().join("note.txt");
        std::fs::write(&file, b"decision payload").unwrap();
        send_with_session(
            base,
            Drop {
                token: "tok".to_owned(),
                password: None,
                files: vec![Selected {
                    relative: "note.txt".to_owned(),
                    source: file,
                }],
            },
            &device,
            observer,
            None,
            |_, _, _| Ok(false),
        )
    }

    /// A Cancel or Pause pressed while the drop hashes ends the send before
    /// any session is opened on the receiver.
    #[test]
    fn a_cancel_during_hashing_opens_no_session() {
        struct Cancelled;
        impl Observer for Cancelled {
            fn event(&mut self, _: crate::progress::Event) {}
            fn cancelled(&self) -> bool {
                true
            }
        }
        let mock = spawn_link_mock((404, "push is off"));
        let error = send_one_file_observed(&mock.base, &mut Cancelled)
            .err()
            .expect("a cancelled send must not complete");
        assert!(matches!(error, Error::Cancelled), "{error}");
        assert_eq!(mock.session_creates.load(Ordering::Relaxed), 0);
    }

    /// The prepare preflight succeeds (the mock link is usable with push on),
    /// then the push path fails: the error surfaces and no HTTP session is
    /// ever created, because a push error never falls back to HTTP.
    #[test]
    fn a_push_path_failure_surfaces_without_an_http_fallback() {
        let mock = spawn_link_mock((500, "push receiver is broken"));
        let error = send_one_file(&mock.base)
            .err()
            .expect("the broken push receiver must fail the send");
        assert!(
            matches!(&error, Error::Server { status: 500, what, .. } if what.as_str() == "push identity"),
            "{error}"
        );
        assert_eq!(
            mock.session_creates.load(Ordering::Relaxed),
            0,
            "a push failure must not retry over HTTP"
        );
    }

    /// The link offers push but the receiver answers 404 for its push
    /// identity: the decision treats the carrier as unreachable and the drop
    /// falls back to the HTTP session path exactly once.
    #[test]
    fn an_unreachable_push_falls_back_to_http() {
        let mock = spawn_link_mock((404, "push is off"));
        let error = send_one_file(&mock.base)
            .err()
            .expect("the mock http receiver refuses, but the fallback must run");
        assert!(
            matches!(&error, Error::Server { status: 500, what, .. } if what.as_str() == "create session"),
            "{error}"
        );
        assert_eq!(
            mock.session_creates.load(Ordering::Relaxed),
            1,
            "the HTTP fallback ran exactly once"
        );
    }
}
