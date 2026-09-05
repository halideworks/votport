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
use crate::progress::{Event, Observer};

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

    let result = drive(client, &session, created.chunk_bytes, prepared, observer);
    if result.is_err() {
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
) -> Result<FinishReport> {
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
    for info in entries {
        if info.complete {
            observer.event(Event::EntryComplete {
                index: info.index,
                path: info.path.clone(),
            });
            continue;
        }
        let object = prepared.objects.get(info.index).ok_or_else(|| {
            Error::Other(format!("begin named entry {} the drop lacks", info.index))
        })?;
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
            let progress = client.chunk(session, info.index, offset, cover.proof(), &data)?;
            if progress.rebegin {
                return Ok(Outcome::Rebegin);
            }
            offset += length;
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
    }
    Ok(Outcome::Sent)
}
