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

/// Something worth reporting during a send.
#[derive(Debug, Clone)]
pub enum Event {
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
}

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
