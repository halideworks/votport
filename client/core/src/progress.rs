//! The one progress stream a send reports through.
//!
//! The CLI prints it; a shell forwards it to its UI. Keeping every tick on one
//! observer means there is one place that knows what a transfer is doing.

/// One file a transfer will move, announced before its first byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedFile {
    /// The index the later ticks for this file carry.
    pub index: usize,
    /// The package-relative path.
    pub path: String,
    pub bytes: u64,
}

/// The path a transfer committed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Transport {
    /// A QUIC push to the receiver's listener.
    Push,
    /// The HTTP session path (send) or per-file downloads (receive).
    Http,
    /// A QUIC fetch from the delivery's serve.
    Fetch,
}

/// Something worth reporting during a send.
#[derive(Debug, Clone)]
pub enum Event {
    /// The transfer committed to a path. The QUIC paths report bytes only as
    /// [`Event::Bytes`]; the HTTP paths report them per file.
    Transport(Transport),
    /// Bytes a QUIC carrier moved so far, and the package length when the
    /// fetch knows it (a push never does).
    Bytes { moved: u64, total: Option<u64> },
    /// The files the transfer will move, in index order, with their sizes, so
    /// a view can name and size every later tick and sum the whole.
    Planned { files: Vec<PlannedFile> },
    /// The upload session was created and named.
    SessionCreated { session: String },
    /// A chunk was accepted; `covered` of `total` bytes of the entry are in.
    Chunk {
        index: usize,
        covered: u64,
        total: u64,
    },
    /// An entry finished, either just now or because begin reported it done.
    EntryComplete { index: usize, path: String },
    /// The server asked the sender to begin again after a restart.
    Rebegin,
    /// The drop finished; `files` were published.
    Finished { files: usize },
    /// A receive is pulling file `index`; `received` of `total` bytes are in.
    Downloading {
        index: usize,
        received: u64,
        total: u64,
    },
    /// A received file's bytes hashed to its announced root and landed at `path`.
    FileVerified { index: usize, path: String },
}

/// A sink for [`Event`]s. Implemented by the CLI and by each shell.
pub trait Observer {
    fn event(&mut self, event: Event);

    /// Whether the caller asked to stop. Polled between chunks and files; a
    /// transfer that sees `true` returns [`crate::Error::Cancelled`].
    fn cancelled(&self) -> bool {
        false
    }
}

/// Runs `work` with a vot-cli progress callback and forwards every report to
/// `observer` as [`Event::Bytes`]. vot-cli wants a `'static + Send` callback
/// and an observer is neither, so `work` runs on a scoped thread and this
/// thread drains a channel until the callback is dropped with the options.
pub(crate) fn with_progress<T: Send>(
    observer: &mut dyn Observer,
    work: impl FnOnce(vot_cli::Progress) -> T + Send,
) -> T {
    let (sender, receiver) = std::sync::mpsc::channel::<(u64, Option<u64>)>();
    let progress: vot_cli::Progress = Box::new(move |moved, total| {
        let _ = sender.send((moved, total));
    });
    std::thread::scope(|scope| {
        let handle = scope.spawn(move || work(progress));
        for (moved, total) in receiver {
            observer.event(Event::Bytes { moved, total });
        }
        handle
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

/// How many carrier bytes pass between two [`Event::Bytes`] reports.
pub(crate) const PROGRESS_QUANTUM: u64 = 1 << 20;

/// An observer that drops every event, for callers that do not want progress.
pub struct Silent;

impl Observer for Silent {
    fn event(&mut self, _event: Event) {}
}

impl<F: FnMut(Event)> Observer for F {
    fn event(&mut self, event: Event) {
        self(event);
    }
}
