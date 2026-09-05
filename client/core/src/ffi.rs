//! The UniFFI surface the shells call: commands in, a change stream out.
//!
//! A shell holds no transfer logic. It hands a link, a password, and paths to
//! [`send`] or [`receive`], gets every tick back through a
//! [`ProgressListener`], and shows the plain records that come back. The
//! device key stays inside the core: it is loaded here, never handed out.
//!
//! Both commands block until the transfer ends, so a shell calls them off its
//! main thread. The listener is called from the core's thread; a shell hops to
//! its UI thread before touching a view.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::api::split_link;
use crate::error::Error;
use crate::identity::Device;
use crate::progress::{Event, Observer, PlannedFile};
use crate::receive::{receive_with_device_or_http, Delivery};
use crate::transfer::{self, Drop, Selected};

/// One file a transfer will move, announced before its first byte.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TransferFile {
    /// The index the later ticks for this file carry.
    pub index: u64,
    /// The package-relative path.
    pub path: String,
    pub bytes: u64,
}

impl From<PlannedFile> for TransferFile {
    fn from(file: PlannedFile) -> Self {
        Self {
            index: file.index as u64,
            path: file.path,
            bytes: file.bytes,
        }
    }
}

/// One tick of a transfer, as [`Event`] but with the widths the FFI carries.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum TransferEvent {
    /// The files the transfer will move, in index order, with their sizes.
    Planned { files: Vec<TransferFile> },
    /// The upload session was created.
    SessionCreated,
    /// A chunk was accepted; `covered` of `total` bytes of entry `index` are in.
    Chunk {
        index: u64,
        covered: u64,
        total: u64,
    },
    /// Entry `index` at `path` finished sending.
    EntryComplete { index: u64, path: String },
    /// The server asked the sender to begin again after a restart.
    Rebegin,
    /// The transfer finished; `files` were moved.
    Finished { files: u64 },
    /// A receive is pulling file `index`; `received` of `total` bytes are in.
    Downloading {
        index: u64,
        received: u64,
        total: u64,
    },
    /// A received file hashed to its announced root and landed at `path`.
    FileVerified { index: u64, path: String },
}

impl From<Event> for TransferEvent {
    fn from(event: Event) -> Self {
        match event {
            Event::Planned { files } => Self::Planned {
                files: files.into_iter().map(Into::into).collect(),
            },
            // The session id is the server's handle; no screen shows it.
            Event::SessionCreated { .. } => Self::SessionCreated,
            Event::Chunk {
                index,
                covered,
                total,
            } => Self::Chunk {
                index: index as u64,
                covered,
                total,
            },
            Event::EntryComplete { index, path } => Self::EntryComplete {
                index: index as u64,
                path,
            },
            Event::Rebegin => Self::Rebegin,
            Event::Finished { files } => Self::Finished {
                files: files as u64,
            },
            Event::Downloading {
                index,
                received,
                total,
            } => Self::Downloading {
                index: index as u64,
                received,
                total,
            },
            Event::FileVerified { index, path } => Self::FileVerified {
                index: index as u64,
                path,
            },
        }
    }
}

/// A shell's sink for [`TransferEvent`]s. Called from the core's thread.
#[uniffi::export(with_foreign)]
pub trait ProgressListener: Send + Sync {
    fn event(&self, event: TransferEvent);
}

/// How often a file's byte ticks cross the FFI. The core reports one per 64
/// KiB read or per HTTP chunk; a shell repaints a bar no faster than this.
const TICK_INTERVAL: Duration = Duration::from_millis(100);

/// Adapts a listener to the core's observer, coalescing byte ticks to one per
/// [`TICK_INTERVAL`] per file. A file's final tick always crosses.
struct Forward {
    listener: Arc<dyn ProgressListener>,
    last_tick: HashMap<usize, Instant>,
}

impl Forward {
    fn new(listener: Arc<dyn ProgressListener>) -> Self {
        Self {
            listener,
            last_tick: HashMap::new(),
        }
    }

    /// Whether a byte tick for `index` at `done` of `total` crosses now.
    fn admit(&mut self, index: usize, done: u64, total: u64, now: Instant) -> bool {
        if done >= total {
            self.last_tick.remove(&index);
            return true;
        }
        match self.last_tick.get(&index) {
            Some(last) if now.duration_since(*last) < TICK_INTERVAL => false,
            _ => {
                self.last_tick.insert(index, now);
                true
            }
        }
    }
}

impl Observer for Forward {
    fn event(&mut self, event: Event) {
        let crosses = match &event {
            Event::Chunk {
                index,
                covered,
                total,
            } => self.admit(*index, *covered, *total, Instant::now()),
            Event::Downloading {
                index,
                received,
                total,
            } => self.admit(*index, *received, *total, Instant::now()),
            _ => true,
        };
        if crosses {
            self.listener.event(event.into());
        }
    }
}

/// Which path carried a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Transport {
    Push,
    Http,
}

/// What a send did.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SendReport {
    pub transport: Transport,
    pub files: u64,
    /// The server's upload id, on the HTTP path only.
    pub upload_id: Option<String>,
}

/// What a receive landed: the files written, in delivery order.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ReceiveReport {
    pub files: Vec<String>,
}

/// The core's version, so a shell can show what it links.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Sends the files and folders at `paths` to the request `link`, over push
/// when the link offers it and the receiver's carrier answers, over HTTP
/// otherwise. A folder keeps its name as the top component. Blocks until done.
///
/// # Errors
/// A bad link, an unreadable path, or anything that stops a send.
#[uniffi::export]
pub fn send(
    link: String,
    password: Option<String>,
    paths: Vec<String>,
    listener: Arc<dyn ProgressListener>,
) -> std::result::Result<SendReport, Error> {
    let (base, token) = split_link(&link)?;
    let mut files: Vec<Selected> = Vec::new();
    for path in &paths {
        transfer::collect(Path::new(path), &mut files).map_err(|source| Error::Read {
            path: path.into(),
            source,
        })?;
    }
    let drop = Drop {
        token,
        password,
        files,
    };
    let device = Device::load_or_create()?;
    let mut observer = Forward::new(listener);
    Ok(match transfer::send(&base, drop, &device, &mut observer)? {
        transfer::Sent::Push { files } => SendReport {
            transport: Transport::Push,
            files: files as u64,
            upload_id: None,
        },
        transfer::Sent::Http(report) => SendReport {
            transport: Transport::Http,
            files: report.files.len() as u64,
            upload_id: Some(report.upload_id),
        },
    })
}

/// Receives the delivery at `link` into the directory `dest`, over a QUIC
/// fetch when the delivery offers one and the serve answers, over HTTP
/// otherwise. Every file is verified against its announced root before it
/// lands. Blocks until done.
///
/// # Errors
/// A bad link, a missing password, a file already present under `dest`, or
/// anything that stops a receive.
#[uniffi::export]
pub fn receive(
    link: String,
    password: Option<String>,
    dest: String,
    listener: Arc<dyn ProgressListener>,
) -> std::result::Result<ReceiveReport, Error> {
    let (base, token) = split_link(&link)?;
    let delivery = Delivery { token, password };
    let mut observer = Forward::new(listener);
    let received = receive_with_device_or_http(&base, delivery, Path::new(&dest), &mut observer)?;
    Ok(ReceiveReport {
        files: received
            .files
            .into_iter()
            .map(|path| path.display().to_string())
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Count(std::sync::Mutex<Vec<TransferEvent>>);

    impl ProgressListener for Count {
        fn event(&self, event: TransferEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[test]
    fn byte_ticks_coalesce_per_file_and_the_last_one_always_crosses() {
        let mut forward = Forward::new(Arc::new(Count(std::sync::Mutex::new(Vec::new()))));
        let start = Instant::now();
        // The first tick for a file crosses; a burst inside the interval does
        // not; another file is timed on its own; the final tick crosses even
        // inside the interval and forgets the file.
        assert!(forward.admit(0, 1, 10, start));
        assert!(!forward.admit(0, 2, 10, start + Duration::from_millis(50)));
        assert!(forward.admit(1, 1, 10, start + Duration::from_millis(50)));
        assert!(forward.admit(0, 3, 10, start + TICK_INTERVAL));
        assert!(forward.admit(0, 10, 10, start + TICK_INTERVAL + Duration::from_millis(1)));
        assert!(!forward.last_tick.contains_key(&0));
        assert!(forward.admit(0, 1, 10, start + TICK_INTERVAL + Duration::from_millis(2)));
    }

    #[test]
    fn everything_but_byte_ticks_crosses_untouched() {
        let count = Arc::new(Count(std::sync::Mutex::new(Vec::new())));
        let mut forward = Forward::new(count.clone());
        forward.event(Event::Planned { files: vec![] });
        forward.event(Event::Chunk {
            index: 0,
            covered: 1,
            total: 10,
        });
        forward.event(Event::Chunk {
            index: 0,
            covered: 2,
            total: 10,
        });
        forward.event(Event::EntryComplete {
            index: 0,
            path: "a".into(),
        });
        forward.event(Event::Finished { files: 1 });
        // The second chunk is dropped unless the clock stalled past the
        // interval between the two calls, so only the shape is asserted.
        let seen = count.0.lock().unwrap();
        assert!(matches!(seen[0], TransferEvent::Planned { .. }), "{seen:?}");
        assert!(
            matches!(seen[1], TransferEvent::Chunk { covered: 1, .. }),
            "{seen:?}"
        );
        let tail = &seen[seen.len() - 2..];
        assert!(
            matches!(tail[0], TransferEvent::EntryComplete { .. }),
            "{seen:?}"
        );
        assert!(
            matches!(tail[1], TransferEvent::Finished { files: 1 }),
            "{seen:?}"
        );
    }
}
