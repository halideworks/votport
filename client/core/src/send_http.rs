//! The HTTP send path: create, seal, pages, begin, chunks, finish.
//!
//! One session per drop. Begin's reply is the resume authority: an entry it
//! reports complete is skipped, and every other entry resumes at the
//! `covered_bytes` it reports. A `rebegin` on any chunk, or a finish that says
//! the drop is not fully received, sends the sender back to begin.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::api::{Client, EntryInfo, FinishReport, PackageAnnouncement};
use crate::error::{Error, Result};
use crate::package::Prepared;
use crate::progress::{Event, Observer, Transport};

const MAX_REBEGINS: usize = 100;
const MAX_CHUNK_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) fn valid_session_id(session: &str) -> bool {
    session.len() == 32 && session.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn valid_chunk_bytes(chunk_bytes: u64) -> bool {
    (1..=MAX_CHUNK_BYTES).contains(&chunk_bytes)
}

pub(crate) fn valid_resume_metadata(session: &str, chunk_bytes: u64) -> bool {
    valid_session_id(session) && valid_chunk_bytes(chunk_bytes)
}

struct JournalBoundary<'a, F> {
    journalled: bool,
    reconnectable: bool,
    on_begin: &'a mut F,
}

/// Sends a prepared drop to `token` over the HTTP session protocol.
///
/// # Errors
/// A network failure, a server refusal, a read failure, or recovery exhaustion.
/// Chunk and finish rebegins share a limit of 100 recoveries per send.
pub fn send(
    client: &Client,
    token: &str,
    password: Option<&str>,
    prepared: &Prepared,
    observer: &mut dyn Observer,
) -> Result<FinishReport> {
    send_with_session(
        client,
        token,
        password,
        prepared,
        observer,
        None,
        |_, _, _| Ok(false),
    )
}

/// Sends a prepared drop, optionally reconnecting to a known HTTP session.
/// `on_begin` runs after the first successful begin, before any payload is
/// accepted, so a caller can durably associate the session with its journal.
pub fn send_with_session(
    client: &Client,
    token: &str,
    password: Option<&str>,
    prepared: &Prepared,
    observer: &mut dyn Observer,
    existing: Option<(&str, u64)>,
    mut on_begin: impl FnMut(&str, u64, &Prepared) -> Result<bool>,
) -> Result<FinishReport> {
    if let Some((session, chunk_bytes)) = existing {
        if !valid_resume_metadata(session, chunk_bytes) {
            return Err(Error::ResumeSessionInvalid);
        }
    }
    let (session, chunk_bytes, resume) = match existing {
        Some((session, chunk_bytes)) => (session.to_owned(), chunk_bytes, true),
        None => {
            let created = client.create_session(
                token,
                password,
                PackageAnnouncement {
                    suite: "blake3".to_owned(),
                    root: hex::encode(prepared.summary.root),
                    length: prepared.summary.logical_length,
                },
            )?;
            (created.session, created.chunk_bytes, created.resume)
        }
    };
    if !valid_resume_metadata(&session, chunk_bytes) {
        if existing.is_none() && valid_session_id(&session) && !client.is_route() {
            client.abort(&session);
        }
        return Err(Error::Other(
            "the server returned invalid HTTP session metadata".to_owned(),
        ));
    }
    observer.event(Event::SessionCreated {
        session: session.clone(),
    });
    observer.event(Event::Transport(Transport::Http));

    let mut journal = JournalBoundary {
        journalled: existing.is_some(),
        reconnectable: existing.is_some(),
        on_begin: &mut on_begin,
    };
    let result = drive(
        client,
        &session,
        chunk_bytes,
        prepared,
        observer,
        resume,
        &mut journal,
    );
    let preserve = result.as_ref().err().is_some_and(|error| {
        journal.reconnectable
            && ((matches!(error, Error::Cancelled) && observer.paused()) || error.worth_retrying())
    });
    if result.is_err() && existing.is_none() && !preserve && !client.is_route() {
        // Abort only terminal cancellation/failure. Pause and retryable
        // errors retain the session for the journalled resume path.
        client.abort(&session);
    }
    result
}

/// The seal, pages, and the begin/send/finish loop.
fn drive(
    client: &Client,
    session: &str,
    chunk_bytes: u64,
    prepared: &Prepared,
    observer: &mut dyn Observer,
    resume: bool,
    journal: &mut JournalBoundary<'_, impl FnMut(&str, u64, &Prepared) -> Result<bool>>,
) -> Result<FinishReport> {
    if !resume {
        let expected_pages = client.seal(session, prepared.seal_bytes.clone())?;
        let mut remaining = expected_pages;
        for page in &prepared.page_bytes {
            if observer.cancelled() {
                return Err(Error::Cancelled);
            }
            remaining = client.page(session, page.clone())?;
        }
        if remaining != 0 {
            return Err(Error::Other(format!(
                "the server still wants {remaining} manifest pages after all were sent"
            )));
        }
    }

    // Accepted chunks do not reset recovery: finish can still refuse forever.
    for _ in 0..=MAX_REBEGINS {
        if journal.journalled && observer.cancelled() {
            return Err(Error::Cancelled);
        }
        let entries = client.begin(session)?;
        if entries.len() != prepared.objects.len() {
            return Err(Error::Other(format!(
                "the server reported {} entries for a {}-entry drop",
                entries.len(),
                prepared.objects.len()
            )));
        }
        if !journal.journalled {
            journal.reconnectable = (journal.on_begin)(session, chunk_bytes, prepared)?;
            journal.journalled = true;
        }
        if observer.cancelled() {
            return Err(Error::Cancelled);
        }
        match send_entries(client, session, chunk_bytes, prepared, &entries, observer)? {
            Outcome::Rebegin => {
                observer.event(Event::Rebegin);
                continue;
            }
            Outcome::Sent => {}
        }
        if observer.cancelled() {
            return Err(Error::Cancelled);
        }
        match client.finish(session) {
            Ok(report) => {
                observer.event(Event::Finished {
                    files: report.files.len(),
                });
                return Ok(report);
            }
            Err(Error::Rebegin) => {
                observer.event(Event::Rebegin);
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(Error::Other(
        "the server repeatedly restarted the upload; try again later".to_owned(),
    ))
}

enum Outcome {
    Sent,
    Rebegin,
}

/// Sends every incomplete entry from its resume point. Returns [`Outcome::Rebegin`]
/// the moment the server asks for one, so the caller begins again.
fn send_entries(
    client: &Client,
    session: &str,
    chunk_bytes: u64,
    prepared: &Prepared,
    entries: &[EntryInfo],
    observer: &mut dyn Observer,
) -> Result<Outcome> {
    send_batches(entries, chunk_bytes, observer, |info, observer| {
        send_entry(client, session, chunk_bytes, prepared, info, observer)
    })
}

fn send_batches(
    entries: &[EntryInfo],
    chunk_bytes: u64,
    observer: &mut dyn Observer,
    send: impl Fn(&EntryInfo, &mut dyn Observer) -> Result<Outcome> + Sync,
) -> Result<Outcome> {
    for batch in entries.chunks(8) {
        if batch.len() == 1 || batch.iter().any(|entry| entry.bytes > chunk_bytes) {
            for info in batch {
                if matches!(send(info, observer)?, Outcome::Rebegin) {
                    return Ok(Outcome::Rebegin);
                }
            }
            continue;
        }
        let cancelled = std::sync::atomic::AtomicBool::new(observer.cancelled());
        let results = crate::progress::with_events(
            |event| {
                if let Some(event) = event {
                    observer.event(event);
                }
                if observer.cancelled() {
                    cancelled.store(true, std::sync::atomic::Ordering::Release);
                }
            },
            |sender| {
                std::thread::scope(|scope| {
                    let workers = batch
                        .iter()
                        .map(|info| {
                            let mut progress = BatchObserver {
                                sender: sender.clone(),
                                cancelled: &cancelled,
                            };
                            let send = &send;
                            scope.spawn(move || send(info, &mut progress))
                        })
                        .collect::<Vec<_>>();
                    workers
                        .into_iter()
                        .map(|worker| worker.join().expect("HTTP send worker panicked"))
                        .collect::<Vec<_>>()
                })
            },
        );
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        let outcomes = results.into_iter().collect::<Result<Vec<_>>>()?;
        if outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Rebegin))
        {
            return Ok(Outcome::Rebegin);
        }
    }
    Ok(Outcome::Sent)
}

struct BatchObserver<'a> {
    sender: std::sync::mpsc::Sender<Event>,
    cancelled: &'a std::sync::atomic::AtomicBool,
}

impl Observer for BatchObserver<'_> {
    fn event(&mut self, event: Event) {
        let _ = self.sender.send(event);
    }
    fn cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }
}

fn send_entry(
    client: &Client,
    session: &str,
    chunk_bytes: u64,
    prepared: &Prepared,
    info: &EntryInfo,
    observer: &mut dyn Observer,
) -> Result<Outcome> {
    if observer.cancelled() {
        return Err(Error::Cancelled);
    }
    if info.complete {
        observer.event(Event::EntryComplete {
            index: info.index,
            path: info.path.clone(),
        });
        return Ok(Outcome::Sent);
    }
    let entry = prepared
        .objects
        .get(info.index)
        .ok_or_else(|| Error::Other(format!("begin named entry {} the drop lacks", info.index)))?;
    let prover = entry.prover()?;
    let mut file = File::open(&entry.source).map_err(|source| Error::Read {
        path: entry.source.clone(),
        source,
    })?;
    // Begin's covered_bytes is the contiguous verified prefix, always on a
    // group boundary, so a resumed chunk stays 64 KiB-aligned.
    let mut offset = info.covered_bytes.min(entry.object.length);
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| Error::Read {
            path: entry.source.clone(),
            source,
        })?;
    while offset < entry.object.length {
        let length = chunk_bytes.min(entry.object.length - offset);
        let cover = prover.prove(offset, length)?;
        // The server verifies at the offset the sender sends, so the proof
        // must cover exactly the requested range from that offset.
        if cover.covered_offset() != offset || cover.covered_length() != length {
            return Err(Error::Other(format!(
                "proof covered {}..{} not the requested {offset}..{}",
                cover.covered_offset(),
                cover.covered_offset() + cover.covered_length(),
                offset + length
            )));
        }
        let mut data = vec![
            0u8;
            usize::try_from(length)
                .map_err(|_| Error::Other("chunk too large".to_owned()))?
        ];
        file.read_exact(&mut data).map_err(|source| Error::Read {
            path: entry.source.clone(),
            source,
        })?;
        if observer.cancelled() {
            return Err(Error::Cancelled);
        }
        let progress = client.chunk(session, info.index, offset, cover.proof(), &data)?;
        if progress.rebegin {
            return Ok(Outcome::Rebegin);
        }
        offset += length;
        observer.event(Event::Transferred { bytes: length });
        observer.event(Event::Chunk {
            index: info.index,
            covered: progress.covered_bytes,
            total: progress.total_bytes,
        });
        if progress.complete {
            observer.event(Event::EntryComplete {
                index: info.index,
                path: info.path.clone(),
            });
            break;
        }
    }
    Ok(Outcome::Sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn entries(count: usize, bytes: u64) -> Vec<EntryInfo> {
        (0..count)
            .map(|index| EntryInfo {
                index,
                path: index.to_string(),
                stored_as: index.to_string(),
                bytes,
                complete: false,
                covered_bytes: 0,
            })
            .collect()
    }

    fn exercise_rebegin(mode: &'static str) {
        use serde_json::json;
        use std::io::{BufRead as _, Write as _};
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("frame");
        let length = if mode == "resume" || mode == "existing" {
            65537
        } else {
            7
        };
        std::fs::write(&source, vec![7; length]).unwrap();
        let prepared = crate::package::build(
            vec![crate::entries::Entry {
                path: vot_manifest::PackagePath::portable(["frame".to_owned()]).unwrap(),
                source,
            }],
            &directory.path().join("manifest"),
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut begins = 0;
            let mut offsets = Vec::new();
            for _ in 0..400 {
                let mut stream = (0..2000)
                    .find_map(|_| match listener.accept() {
                        Ok((stream, _)) => Some(stream),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                            None
                        }
                        Err(error) => panic!("{error}"),
                    })
                    .expect("HTTP upload fixture did not receive a request");
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(&stream);
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                let path = first.split_whitespace().nth(1).unwrap();
                let mut body_length = 0;
                for _ in 0..64 {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        body_length = value.trim().parse::<usize>().unwrap();
                    }
                }
                assert!(body_length < 128 * 1024);
                reader.read_exact(&mut vec![0; body_length]).unwrap();
                let (status, body, done) = if path == "/api/r/token/session" {
                    (
                        200,
                        json!({"session":"0123456789abcdef0123456789abcdef", "chunk_bytes":65536, "resume":true}),
                        false,
                    )
                } else if path.ends_with("/begin") {
                    begins += 1;
                    if mode == "prebegin" {
                        (422, json!({"error":"fixture refused begin"}), false)
                    } else if begins > 101 {
                        (
                            400,
                            json!({"error":"fixture observed an excess begin"}),
                            false,
                        )
                    } else {
                        (
                            200,
                            json!({"entries":[{"index":0, "path":"frame", "stored_as":"frame", "bytes":length,
                            "complete":false, "covered_bytes":if (mode == "resume" || mode == "existing") && begins > 1 { 65536 } else { 0 }}]}),
                            false,
                        )
                    }
                } else if path.contains("/chunk?") {
                    let offset = path
                        .split("offset=")
                        .nth(1)
                        .unwrap()
                        .split('&')
                        .next()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap();
                    offsets.push(offset);
                    let rebegin = mode == "chunk"
                        || mode == "cancel"
                        || (mode == "mixed" && begins % 2 == 1)
                        || ((mode == "resume" || mode == "existing") && begins == 1);
                    (
                        200,
                        json!({"accepted":true, "replay":false, "covered_bytes":length,
                        "total_bytes":length, "complete":!rebegin, "received":length, "rebegin":rebegin}),
                        false,
                    )
                } else if path.ends_with("/finish") {
                    if mode == "resume" || mode == "existing" {
                        (
                            200,
                            json!({"upload_id":"finished", "files":[{"path":"frame"}]}),
                            true,
                        )
                    } else {
                        (422, json!({"error":"not fully received"}), false)
                    }
                } else {
                    assert!(path.ends_with("/abort"), "unexpected request: {first}");
                    (200, json!({"ok":true}), true)
                };
                let body = body.to_string();
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                if done {
                    return (begins, offsets);
                }
            }
            panic!("HTTP upload fixture exhausted its request bound");
        });
        struct CancelOnRebegin {
            enabled: bool,
            cancelled: bool,
        }
        impl Observer for CancelOnRebegin {
            fn event(&mut self, event: Event) {
                if self.enabled && matches!(event, Event::Rebegin) {
                    self.cancelled = true;
                }
            }
            fn cancelled(&self) -> bool {
                self.cancelled
            }
        }
        let client = Client::with_timeout(&url, Some(Duration::from_secs(2))).unwrap();
        let result = if mode == "journal" {
            send_with_session(
                &client,
                "token",
                None,
                &prepared,
                &mut crate::progress::Silent,
                None,
                |_, _, _| Err(Error::Other("journal write failed".into())),
            )
        } else if mode == "existing" {
            send_with_session(
                &client,
                "token",
                None,
                &prepared,
                &mut crate::progress::Silent,
                Some(("0123456789abcdef0123456789abcdef", 65536)),
                |_, _, _| panic!("existing-session resume rewrote its journal"),
            )
        } else {
            send(
                &client,
                "token",
                None,
                &prepared,
                &mut CancelOnRebegin {
                    enabled: mode == "cancel",
                    cancelled: false,
                },
            )
        };
        let (begins, offsets) = server.join().unwrap();
        match mode {
            "resume" | "existing" => {
                assert_eq!(result.unwrap().upload_id, "finished");
                assert_eq!(begins, 2);
                assert_eq!(offsets, [0, 65536]);
            }
            "cancel" => {
                assert!(matches!(result, Err(Error::Cancelled)));
                assert_eq!(begins, 1);
            }
            "prebegin" => {
                assert!(matches!(result, Err(Error::Server { status: 422, .. })));
                assert_eq!(begins, 1);
                assert!(offsets.is_empty());
            }
            "journal" => {
                assert!(
                    matches!(result, Err(Error::Other(ref message)) if message == "journal write failed")
                );
                assert_eq!(begins, 1);
                assert!(offsets.is_empty());
            }
            _ => {
                assert!(
                    matches!(result, Err(Error::Other(ref message)) if message == "the server repeatedly restarted the upload; try again later"),
                    "{mode}: {result:?}"
                );
                assert_eq!(begins, 101);
            }
        }
    }

    #[test]
    fn chunk_rebegins_have_a_total_recovery_budget() {
        exercise_rebegin("chunk");
    }

    #[test]
    fn finish_rebegins_have_a_total_recovery_budget() {
        exercise_rebegin("finish");
    }

    #[test]
    fn mixed_rebegins_share_the_total_recovery_budget() {
        exercise_rebegin("mixed");
    }

    #[test]
    fn a_rebegin_resumes_from_the_verified_prefix() {
        exercise_rebegin("resume");
    }

    #[test]
    fn an_existing_resume_skips_the_journal_callback() {
        exercise_rebegin("existing");
    }

    #[test]
    fn cancellation_after_rebegin_prevents_another_begin() {
        exercise_rebegin("cancel");
    }

    #[test]
    fn a_pre_begin_failure_still_aborts_an_unjournalled_session() {
        exercise_rebegin("prebegin");
    }

    #[test]
    fn a_journal_write_failure_aborts_the_new_session() {
        exercise_rebegin("journal");
    }

    #[test]
    fn small_file_batches_overlap_eight_and_keep_large_files_inline() {
        let parent = std::thread::current().id();
        let arrived = AtomicUsize::new(0);
        let mut events = Vec::new();
        let mut observer = |event| events.push(event);
        let sent = send_batches(&entries(9, 1), 1, &mut observer, |info, observer| {
            if info.index < 8 {
                assert_ne!(std::thread::current().id(), parent);
                arrived.fetch_add(1, Ordering::SeqCst);
                for _ in 0..1000 {
                    if arrived.load(Ordering::SeqCst) == 8 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                assert_eq!(
                    arrived.load(Ordering::SeqCst),
                    8,
                    "small files were serialized"
                );
            } else {
                assert_eq!(arrived.load(Ordering::SeqCst), 8);
                assert_eq!(std::thread::current().id(), parent);
            }
            observer.event(Event::EntryComplete {
                index: info.index,
                path: info.path.clone(),
            });
            Ok(Outcome::Sent)
        })
        .unwrap();
        assert!(matches!(sent, Outcome::Sent));
        let mut completed = events
            .iter()
            .map(|event| match event {
                Event::EntryComplete { index, .. } => *index,
                _ => panic!("unexpected event"),
            })
            .collect::<Vec<_>>();
        completed.sort_unstable();
        assert_eq!(completed, (0..9).collect::<Vec<_>>());
        send_batches(&entries(8, 2), 1, &mut crate::progress::Silent, |_, _| {
            assert_eq!(std::thread::current().id(), parent);
            Ok(Outcome::Sent)
        })
        .unwrap();
        assert!(matches!(
            send_batches(&[], 1, &mut crate::progress::Silent, |_, _| panic!(
                "empty batch dispatched"
            ))
            .unwrap(),
            Outcome::Sent
        ));
    }

    #[test]
    fn failed_or_restarted_batches_join_every_worker_before_returning() {
        for restart in [false, true] {
            let finished = AtomicUsize::new(0);
            let result = send_batches(
                &entries(9, 1),
                1,
                &mut crate::progress::Silent,
                |info, _| {
                    assert!(info.index < 8, "dispatched past the failed batch");
                    if info.index != 0 {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    finished.fetch_add(1, Ordering::SeqCst);
                    if info.index == 0 {
                        if restart {
                            Ok(Outcome::Rebegin)
                        } else {
                            Err(Error::Other("batch failure".into()))
                        }
                    } else {
                        Ok(Outcome::Sent)
                    }
                },
            );
            assert_eq!(finished.load(Ordering::SeqCst), 8);
            if restart {
                assert!(matches!(result, Ok(Outcome::Rebegin)));
            } else {
                assert!(matches!(result, Err(Error::Other(message)) if message == "batch failure"));
            }
        }
    }

    #[test]
    fn a_small_file_batch_polls_cancellation_during_silence() {
        struct CancelOnPoll(AtomicUsize);
        impl Observer for CancelOnPoll {
            fn event(&mut self, _: Event) {}
            fn cancelled(&self) -> bool {
                self.0.fetch_add(1, Ordering::SeqCst) > 0
            }
        }
        let finished = AtomicUsize::new(0);
        let result = send_batches(
            &entries(9, 1),
            1,
            &mut CancelOnPoll(AtomicUsize::new(0)),
            |info, observer| {
                assert!(info.index < 8);
                for _ in 0..1000 {
                    if observer.cancelled() {
                        finished.fetch_add(1, Ordering::SeqCst);
                        return Err(Error::Cancelled);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                panic!("cancellation did not reach the HTTP worker");
            },
        );
        assert!(matches!(result, Err(Error::Cancelled)));
        assert_eq!(finished.load(Ordering::SeqCst), 8);
        let result = send_batches(
            &entries(8, 1),
            1,
            &mut CancelOnPoll(AtomicUsize::new(0)),
            |info, observer| {
                observer.event(Event::EntryComplete {
                    index: info.index,
                    path: info.path.clone(),
                });
                Ok(Outcome::Sent)
            },
        );
        assert!(matches!(result, Err(Error::Cancelled)));
    }

    /// A cancel observed after the last chunk must stop the send before its
    /// finish request: the finish would publish a drop the caller asked to
    /// stop, and the abort path, not the finish path, owns the session then.
    #[test]
    fn a_cancelled_send_stops_before_its_finish_request() {
        use serde_json::json;
        use std::io::{BufRead, BufReader, Write as _};
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("frame");
        std::fs::write(&source, vec![7; 7]).unwrap();
        let prepared = crate::package::build(
            vec![crate::entries::Entry {
                path: vot_manifest::PackagePath::portable(["frame".to_owned()]).unwrap(),
                source,
            }],
            &directory.path().join("manifest"),
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut finish_seen = false;
            for round in 0..4 {
                let accepted = (0..400).find_map(|_| match listener.accept() {
                    Ok((stream, _)) => Some(stream),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        None
                    }
                    Err(error) => panic!("{error}"),
                });
                let Some(mut stream) = accepted else {
                    if round == 3 {
                        return finish_seen;
                    }
                    panic!("HTTP upload fixture did not receive a request");
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(&stream);
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                let path = first.split_whitespace().nth(1).unwrap().to_owned();
                let mut body_length = 0;
                for _ in 0..64 {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        body_length = value.trim().parse::<usize>().unwrap();
                    }
                }
                reader.read_exact(&mut vec![0; body_length]).unwrap();
                let (status, body) = if path == "/api/r/token/session" {
                    (
                        200,
                        json!({"session":"0123456789abcdef0123456789abcdef", "chunk_bytes":65536, "resume":true}),
                    )
                } else if path.ends_with("/begin") {
                    (
                        200,
                        json!({"entries":[{"index":0, "path":"frame", "stored_as":"frame", "bytes":7,
                        "complete":false, "covered_bytes":0}]}),
                    )
                } else if path.contains("/chunk?") {
                    (
                        200,
                        json!({"accepted":true, "replay":false, "covered_bytes":7,
                        "total_bytes":7, "complete":true, "received":7, "rebegin":false}),
                    )
                } else {
                    finish_seen = path.ends_with("/finish");
                    (
                        200,
                        json!({"ok": true, "upload_id": "finished", "files": []}),
                    )
                };
                let body = body.to_string();
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            finish_seen
        });
        struct CancelOnChunk {
            cancelled: bool,
        }
        impl Observer for CancelOnChunk {
            fn event(&mut self, event: Event) {
                if matches!(event, Event::Chunk { .. }) {
                    self.cancelled = true;
                }
            }
            fn cancelled(&self) -> bool {
                self.cancelled
            }
        }
        let client = Client::with_timeout(&url, Some(Duration::from_secs(2))).unwrap();
        let result = send(
            &client,
            "token",
            None,
            &prepared,
            &mut CancelOnChunk { cancelled: false },
        );
        let finish_seen = server.join().unwrap();
        assert!(
            matches!(result, Err(Error::Cancelled)),
            "a cancelled send must not report success: {result:?}"
        );
        assert!(
            !finish_seen,
            "a cancelled send must not reach its finish request"
        );
    }
}
