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

/// Sends a prepared drop to `token` over the HTTP session protocol.
///
/// # Errors
/// A network failure, a server refusal, or a read failure. A `rebegin` and a
/// not-fully-received finish are handled internally by beginning again.
pub fn send(
    client: &Client,
    token: &str,
    password: Option<&str>,
    prepared: &Prepared,
    observer: &mut dyn Observer,
) -> Result<FinishReport> {
    let created = client.create_session(
        token,
        password,
        PackageAnnouncement {
            suite: "blake3".to_owned(),
            root: hex::encode(prepared.summary.root),
            length: prepared.summary.logical_length,
        },
    )?;
    let session = created.session;
    observer.event(Event::SessionCreated {
        session: session.clone(),
    });
    observer.event(Event::Transport(Transport::Http));

    let result = drive(
        client,
        &session,
        created.chunk_bytes,
        prepared,
        observer,
        created.resume,
    );
    if result.is_err() && !client.is_route() {
        // Abort is best effort and safe on any failure path; it lets the
        // server record the session as cancelled rather than idle out.
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
) -> Result<FinishReport> {
    if !resume {
        let expected_pages = client.seal(session, prepared.seal_bytes.clone())?;
        let mut remaining = expected_pages;
        for page in &prepared.page_bytes {
            remaining = client.page(session, page.clone())?;
        }
        if remaining != 0 {
            return Err(Error::Other(format!(
                "the server still wants {remaining} manifest pages after all were sent"
            )));
        }
    }

    // Begin can ask for a re-begin after a chunk or at finish; the loop is
    // bounded by the drop making progress, which the server guarantees by
    // only re-beginning from a checkpointed prefix.
    loop {
        let entries = client.begin(session)?;
        if entries.len() != prepared.objects.len() {
            return Err(Error::Other(format!(
                "the server reported {} entries for a {}-entry drop",
                entries.len(),
                prepared.objects.len()
            )));
        }
        match send_entries(client, session, chunk_bytes, prepared, &entries, observer)? {
            Outcome::Rebegin => {
                observer.event(Event::Rebegin);
                continue;
            }
            Outcome::Sent => {}
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
    let object = prepared
        .objects
        .get(info.index)
        .ok_or_else(|| Error::Other(format!("begin named entry {} the drop lacks", info.index)))?;
    let prover = object.prover()?;
    let mut file = File::open(&object.source).map_err(|source| Error::Read {
        path: object.source.clone(),
        source,
    })?;
    // Begin's covered_bytes is the contiguous verified prefix, always on a
    // group boundary, so a resumed chunk stays 64 KiB-aligned.
    let mut offset = info.covered_bytes.min(object.length);
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| Error::Read {
            path: object.source.clone(),
            source,
        })?;
    while offset < object.length {
        let length = chunk_bytes.min(object.length - offset);
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
            path: object.source.clone(),
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
}
