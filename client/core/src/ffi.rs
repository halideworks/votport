//! The UniFFI surface the shells call: commands in, a view model out.
//!
//! A shell holds no transfer logic. It hands a link, a password, and paths to
//! [`send`] or [`receive`] with a [`Transfer`] handle it can cancel through,
//! and draws the [`TransferView`] the core hands its [`TransferListener`]
//! after every change: phase, transport, per-file rows, bytes, a rate over a
//! moving window, and an ETA once that rate has held. The device key stays
//! inside the core: it is loaded here, never handed out.
//!
//! Both commands block until the transfer ends, so a shell calls them off its
//! main thread. The listener is called from the core's thread; a shell hops to
//! its UI thread before touching a view.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::api::{split_link, split_link_as, LinkKind};
use crate::error::{human_bytes, human_seconds, Error};
use crate::identity::Device;
use crate::journal;
use crate::port;
use crate::progress::{Event, Observer, Transport};
use crate::receive::{receive_with_device_or_http, Delivery};
use crate::transfer::{self, Drop, Selected};

/// Where a transfer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Phase {
    /// Reading the link, checking the files, hashing them (send), or reading
    /// the delivery and probing the carrier (receive). No bytes move yet.
    Preparing,
    /// Bytes are moving over `transport`.
    Transferring,
    Done,
    Failed,
    Cancelled,
}

/// Where one file is. Over a QUIC path files stay `Waiting` while the carrier
/// moves the package as a whole, then land together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FileState {
    Waiting,
    Moving,
    /// The far side has the whole file (send) or it is on disk (receive).
    Landed,
    /// A received file's bytes hashed to the root the delivery announced.
    Verified,
}

/// One row of the transfer list.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FileView {
    pub index: u64,
    /// The package-relative path.
    pub path: String,
    pub bytes: u64,
    pub moved: u64,
    pub state: FileState,
    /// The words at the end of the row: the size, the bytes moved of the
    /// size, "landed", or "verified".
    pub label: String,
}

impl FileView {
    fn label(&self) -> String {
        match self.state {
            FileState::Waiting => human_bytes(self.bytes),
            FileState::Moving => {
                format!("{} of {}", human_bytes(self.moved), human_bytes(self.bytes))
            }
            FileState::Landed => "landed".to_owned(),
            FileState::Verified => "verified".to_owned(),
        }
    }
}

/// Everything a screen draws for one transfer. Computed here, never in a
/// shell.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TransferView {
    pub phase: Phase,
    /// Set once the transfer commits to a path.
    pub transport: Option<Transport>,
    pub files: Vec<FileView>,
    pub moved_bytes: u64,
    /// The package length, once known. A push never learns what the receiver
    /// still needs, so it stays the planned total.
    pub total_bytes: Option<u64>,
    /// Bytes per second over the last few seconds, once there are enough
    /// samples to say.
    pub rate_bytes_per_second: Option<u64>,
    /// Seconds left, shown only once the rate has held for a while.
    pub eta_seconds: Option<u64>,
    /// One plain sentence for the person when `phase` is `Failed`.
    pub headline: Option<String>,
    /// The full error text behind the headline, for a detail line or a log.
    pub detail: Option<String>,
    /// The one line a card shows under its subject, for every phase: what is
    /// happening, the bytes, the rate, the time left, or how it ended. The
    /// shells draw it as is.
    pub status: String,
    /// The path in the person's words, once `transport` is known.
    pub route: Option<String>,
    /// `rate_bytes_per_second` as text ("95 MB/s"), for a menu or tray line.
    pub rate_text: Option<String>,
}

/// The words for a transport: a QUIC path is the direct route, HTTP the
/// standard one.
fn route_name(transport: Transport) -> &'static str {
    match transport {
        Transport::Push | Transport::Fetch => "Direct route (QUIC)",
        Transport::Http => "Standard route (HTTP)",
    }
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

/// A shell's sink for view updates. Called from the core's thread.
#[uniffi::export(with_foreign)]
pub trait TransferListener: Send + Sync {
    fn update(&self, view: TransferView);
}

/// The handle a shell keeps for one transfer: its only control is cancel,
/// and it learns the transfer's journal id once the transfer is recorded.
#[derive(Debug, Default, uniffi::Object)]
pub struct Transfer {
    cancelled: AtomicBool,
    journal_id: Mutex<Option<String>>,
    journal_kept: AtomicBool,
    journal_needs_password: AtomicBool,
}

#[uniffi::export]
impl Transfer {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Asks the transfer to stop at its next chunk or file boundary. Whatever
    /// landed stays, and a partial file is kept for a later run to resume.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// The journal id of the transfer this handle ran, once it was recorded,
    /// so a shell can `forget` a failed transfer it removes from its list.
    pub fn journal_id(&self) -> Option<String> {
        self.journal_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Whether the journal still holds the transfer after it ended: only a
    /// failure that could go differently next time is kept, so a shell
    /// offers Retry exactly when this is true.
    pub fn journal_kept(&self) -> bool {
        self.journal_kept.load(Ordering::Acquire)
    }

    /// Whether the kept entry needs a password on its next run: it was
    /// started with one, or failed for the lack of one.
    pub fn journal_needs_password(&self) -> bool {
        self.journal_needs_password.load(Ordering::Acquire)
    }
}

impl Transfer {
    fn set_journal_id(&self, id: &str) {
        *self
            .journal_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(id.to_owned());
    }

    /// Settles the journal entry once the transfer ended: dropped when it
    /// ended well, was cancelled, or failed on its own input; kept for a
    /// failure that could go differently next time, and marked as needing
    /// a password when that is what was missing.
    fn settle(&self, entry: &journal::Entry, error: Option<&Error>) {
        let kept = error.is_some_and(Error::worth_retrying);
        let missing_password = matches!(error, Some(Error::PasswordRequired));
        if kept {
            if missing_password {
                journal::mark_needs_password(&entry.id);
            }
        } else {
            journal::forget(&entry.id);
        }
        self.journal_needs_password.store(
            kept && (entry.needs_password || missing_password),
            Ordering::Release,
        );
        self.journal_kept.store(kept, Ordering::Release);
    }
}

/// The journalled transfers, oldest first: those cut by a quit, a crash, or
/// a failure worth trying again, offered at the next launch.
#[uniffi::export]
pub fn pending() -> Vec<journal::Entry> {
    journal::pending()
}

/// Drops a transfer from the journal, for a failed or interrupted one the
/// person removed rather than resumed.
#[uniffi::export]
pub fn forget(id: String) {
    journal::forget(&id);
}

/// What a resumed transfer did: a send's report or a receive's.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum ResumeReport {
    Sent(SendReport),
    Received(ReceiveReport),
}

/// Runs a journalled transfer again under the same id: the same link and
/// paths or destination, with `password` supplied afresh. Whatever an
/// earlier run landed is kept and resumed where the path allows. Blocks
/// until done, like [`send`] and [`receive`].
///
/// # Errors
/// An id the journal does not hold, or anything [`send`] or [`receive`]
/// can fail with.
#[uniffi::export]
pub fn resume(
    id: String,
    password: Option<String>,
    transfer: Arc<Transfer>,
    listener: Arc<dyn TransferListener>,
) -> std::result::Result<ResumeReport, Error> {
    let entry = match journal::get(&id) {
        Ok(entry) => entry,
        Err(error) => {
            // The handle still names the id, and the journal does not hold
            // it, so a shell stops offering the resume.
            transfer.set_journal_id(&id);
            transfer.journal_kept.store(false, Ordering::Release);
            let mut forward = Forward::new(journal::Kind::Send, transfer, listener);
            forward.finish(Some(&error));
            return Err(error);
        }
    };
    match entry.kind {
        journal::Kind::Send => {
            run_send(entry, password, transfer, listener).map(ResumeReport::Sent)
        }
        journal::Kind::Receive => {
            run_receive(entry, password, transfer, listener).map(ResumeReport::Received)
        }
    }
}

/// One file a delivery holds, as its page lists it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PreviewFile {
    pub path: String,
    pub bytes: u64,
}

/// What a link is, read before anything is sent, minted, or reserved, so a
/// screen can show what a pasted link does and ask for a password only when
/// one is needed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LinkPreview {
    /// What the link is, once it parsed as one.
    pub kind: Option<LinkKind>,
    /// Why the link cannot be used as pasted, as one sentence for the
    /// person: not a votport link, closed, unreachable. `None` when it can.
    pub problem: Option<String>,
    /// The full error text behind `problem`.
    pub detail: Option<String>,
    /// The operator's label for the link, when the server shares one. A
    /// password delivery shares nothing until it is verified.
    pub label: Option<String>,
    pub needs_password: bool,
    /// Whether the link can be used as pasted: a request that still accepts
    /// drops, a delivery the server answered for. False whenever `problem`
    /// is set.
    pub usable: bool,
    /// The server offers a QUIC path: a push listener for a request, a fetch
    /// endpoint for a delivery. Whether the network carries it is decided by
    /// the transfer's probe. `None` until a password delivery is verified,
    /// since the server withholds everything before then.
    pub quic: Option<bool>,
    /// The largest drop a request link accepts.
    pub max_bytes: Option<u64>,
    /// The most files a request link accepts.
    pub max_entries: Option<u64>,
    /// A delivery's files, empty until a password delivery is verified.
    pub files: Vec<PreviewFile>,
    /// The sum of `files`, when they are known.
    pub total_bytes: Option<u64>,
    /// The one line a screen shows under the link field: the problem when
    /// there is one, otherwise the label, the size or the cap, whether a
    /// password is needed, and whether the direct route is offered. `None`
    /// when there is nothing to say.
    pub line: Option<String>,
}

impl LinkPreview {
    /// Fills `line` from the other fields.
    fn with_line(mut self) -> Self {
        if let Some(problem) = &self.problem {
            self.line = Some(problem.clone());
            return self;
        }
        let mut parts: Vec<String> = Vec::new();
        if let Some(label) = self.label.as_deref().filter(|label| !label.is_empty()) {
            parts.push(label.to_owned());
        }
        match self.kind {
            Some(LinkKind::Request) => {
                if let Some(max) = self.max_bytes {
                    parts.push(format!("accepts up to {}", human_bytes(max)));
                }
            }
            Some(LinkKind::Delivery) => {
                if let Some(total) = self.total_bytes {
                    let count = self.files.len();
                    let noun = if count == 1 { "file" } else { "files" };
                    parts.push(format!("{count} {noun}, {}", human_bytes(total)));
                }
            }
            None => {}
        }
        if self.needs_password {
            parts.push("password needed".to_owned());
        }
        if self.quic == Some(true) {
            parts.push("direct route offered".to_owned());
        }
        self.line = (!parts.is_empty()).then(|| parts.join(", "));
        self
    }
}

/// Reads what `link` is with the two unauthenticated GETs the transfer
/// paths start with. Nothing is verified, minted, or reserved: a preview
/// spends nothing on the server. Never fails: a link that cannot be used
/// comes back with `problem` set, so a screen shows it under the field. A
/// screen that takes one kind of link passes it as `expect`, so a delivery
/// link pasted into Send is named as such rather than previewed.
/// Blocks for the round trip: about two minutes against a host that never
/// connects (the connect timeout inside the retry budget), and with no bound
/// against one that connects and never answers, since the client sets no
/// read timeout (a transfer's reads are long by design). A shell runs it off
/// its main thread and ignores a result for a link the field no longer holds.
#[uniffi::export]
pub fn inspect(link: String, expect: Option<LinkKind>) -> LinkPreview {
    match preview(&link, expect) {
        Ok(preview) => preview,
        Err(error) => LinkPreview {
            kind: split_link(&link).ok().map(|link| link.kind),
            problem: Some(error.headline()),
            detail: Some(error.to_string()),
            label: None,
            needs_password: false,
            usable: false,
            quic: None,
            max_bytes: None,
            max_entries: None,
            files: Vec::new(),
            total_bytes: None,
            line: None,
        },
    }
    .with_line()
}

fn preview(link: &str, expect: Option<LinkKind>) -> std::result::Result<LinkPreview, Error> {
    let link = match expect {
        Some(kind) => split_link_as(link, kind)?,
        None => split_link(link)?,
    };
    let client = crate::api::Client::new(&link.base)?;
    if link.kind == LinkKind::Delivery {
        let metadata = client.outbound_metadata(&link.token, None)?;
        // Before the password is proven the server answers with the gate
        // alone, so nothing else in the reply is known.
        let known = metadata.authorized || !metadata.has_password;
        let files: Vec<PreviewFile> = if known {
            metadata
                .files
                .iter()
                .map(|file| PreviewFile {
                    path: file.name.clone(),
                    bytes: file.bytes,
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(LinkPreview {
            kind: Some(LinkKind::Delivery),
            problem: None,
            detail: None,
            label: metadata.label,
            needs_password: !known,
            usable: true,
            quic: known.then_some(metadata.fetch.is_some()),
            max_bytes: None,
            max_entries: None,
            total_bytes: known.then(|| files.iter().map(|file| file.bytes).sum()),
            files,
            line: None,
        })
    } else {
        let info = client.link_info(&link.token)?;
        let closed = (!info.usable).then(|| Error::LinkUnusable {
            token: link.token.clone(),
        });
        Ok(LinkPreview {
            kind: Some(LinkKind::Request),
            problem: closed.as_ref().map(Error::headline),
            detail: closed.as_ref().map(ToString::to_string),
            label: info.label,
            needs_password: info.needs_password && !info.authorized,
            usable: info.usable,
            quic: Some(info.push),
            max_bytes: Some(info.max_bytes),
            max_entries: Some(info.max_entries as u64),
            files: Vec::new(),
            total_bytes: None,
            line: None,
        })
    }
}

/// The port the operator is signed in to, from the stored session, without
/// a round trip. `None` when nobody is signed in.
#[uniffi::export]
pub fn port() -> Option<port::Port> {
    port::current()
}

/// Signs in to the votport at `base` with the admin password. Blocks for
/// the round trips; a shell runs it off its main thread.
///
/// # Errors
/// A base that is not an origin, a wrong password, too many tries, or an
/// unreachable server.
#[uniffi::export]
pub fn sign_in(base: String, password: String) -> std::result::Result<port::Port, Error> {
    port::sign_in(&base, &password)
}

/// Asks the server whether the stored session still holds; a session it no
/// longer honours is dropped and `None` comes back. Blocks for the round
/// trip, and through the retry budget while the server restarts; a shell
/// runs it off its main thread.
///
/// # Errors
/// An unreachable server.
#[uniffi::export]
pub fn check_port() -> std::result::Result<Option<port::Port>, Error> {
    port::check()
}

/// Ends the session and forgets it.
#[uniffi::export]
pub fn sign_out() {
    port::sign_out();
}

/// The port's open request links.
///
/// # Errors
/// Not signed in, or an unreachable server.
#[uniffi::export]
pub fn requests() -> std::result::Result<Vec<port::RequestLink>, Error> {
    port::requests()
}

/// Issues a request link on the port.
///
/// # Errors
/// Not signed in, a refused spec, or an unreachable server.
#[uniffi::export]
pub fn issue_request(spec: port::RequestSpec) -> std::result::Result<port::RequestLink, Error> {
    port::issue_request(spec)
}

/// Closes a request link.
///
/// # Errors
/// Not signed in, or an unreachable server.
#[uniffi::export]
pub fn close_request(id: String) -> std::result::Result<(), Error> {
    port::close_request(&id)
}

/// The port's deliveries.
///
/// # Errors
/// Not signed in, or an unreachable server.
#[uniffi::export]
pub fn deliveries() -> std::result::Result<Vec<port::Delivery>, Error> {
    port::deliveries()
}

/// Revokes a delivery.
///
/// # Errors
/// Not signed in, or an unreachable server.
#[uniffi::export]
pub fn revoke_delivery(id: String) -> std::result::Result<(), Error> {
    port::revoke_delivery(&id)
}

/// One directory of the port's library (`""` for the root).
///
/// # Errors
/// Not signed in, a refused directory, or an unreachable server.
#[uniffi::export]
pub fn library(directory: String) -> std::result::Result<port::Library, Error> {
    port::library(&directory)
}

/// Issues a delivery of library files; the reply carries the one link the
/// server ever shows for it.
///
/// # Errors
/// Not signed in, a refused spec, or an unreachable server.
#[uniffi::export]
pub fn issue_delivery(
    spec: port::DeliverySpec,
) -> std::result::Result<port::IssuedDelivery, Error> {
    port::issue_delivery(spec)
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
/// A bad link, an unreadable path, a cancel, or anything that stops a send.
#[uniffi::export]
pub fn send(
    link: String,
    password: Option<String>,
    paths: Vec<String>,
    transfer: Arc<Transfer>,
    listener: Arc<dyn TransferListener>,
) -> std::result::Result<SendReport, Error> {
    let entry = journal::record(journal::Kind::Send, &link, paths, None, password.is_some());
    run_send(entry, password, transfer, listener)
}

/// Runs a journalled send. The entry is dropped from the journal when the
/// send ends well or is cancelled, and kept when it fails, so the next
/// launch can offer it again.
fn run_send(
    entry: journal::Entry,
    password: Option<String>,
    transfer: Arc<Transfer>,
    listener: Arc<dyn TransferListener>,
) -> std::result::Result<SendReport, Error> {
    transfer.set_journal_id(&entry.id);
    let handle = Arc::clone(&transfer);
    let mut forward = Forward::new(journal::Kind::Send, transfer, listener);
    let result = (|| {
        let link = split_link_as(&entry.link, LinkKind::Request)?;
        let mut files: Vec<Selected> = Vec::new();
        for path in &entry.paths {
            transfer::collect(Path::new(path), &mut files).map_err(|source| Error::Read {
                path: path.into(),
                source,
            })?;
        }
        let drop = Drop {
            token: link.token,
            password,
            files,
        };
        let device = Device::load_or_create()?;
        Ok(
            match transfer::send(&link.base, drop, &device, &mut forward)? {
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
            },
        )
    })();
    handle.settle(&entry, result.as_ref().err());
    forward.finish(result.as_ref().err());
    result
}

/// Receives the delivery at `link` into the directory `dest`, over a QUIC
/// fetch when the delivery offers one and the serve answers, over HTTP
/// otherwise. Every file is verified against its announced root before it
/// lands. Blocks until done.
///
/// # Errors
/// A bad link, a missing password, a file already present under `dest`, a
/// cancel, or anything that stops a receive.
#[uniffi::export]
pub fn receive(
    link: String,
    password: Option<String>,
    dest: String,
    transfer: Arc<Transfer>,
    listener: Arc<dyn TransferListener>,
) -> std::result::Result<ReceiveReport, Error> {
    let entry = journal::record(
        journal::Kind::Receive,
        &link,
        Vec::new(),
        Some(dest),
        password.is_some(),
    );
    run_receive(entry, password, transfer, listener)
}

/// Runs a journalled receive; the entry's fate is as for [`run_send`].
fn run_receive(
    entry: journal::Entry,
    password: Option<String>,
    transfer: Arc<Transfer>,
    listener: Arc<dyn TransferListener>,
) -> std::result::Result<ReceiveReport, Error> {
    transfer.set_journal_id(&entry.id);
    let handle = Arc::clone(&transfer);
    let mut forward = Forward::new(journal::Kind::Receive, transfer, listener);
    let result = (|| {
        let link = split_link_as(&entry.link, LinkKind::Delivery)?;
        let dest = entry
            .dest
            .as_deref()
            .ok_or_else(|| Error::UnknownTransfer {
                id: entry.id.clone(),
            })?;
        let delivery = Delivery {
            token: link.token,
            password,
        };
        let received =
            receive_with_device_or_http(&link.base, delivery, Path::new(dest), &mut forward)?;
        Ok(ReceiveReport {
            files: received
                .files
                .into_iter()
                .map(|path| path.display().to_string())
                .collect(),
        })
    })();
    handle.settle(&entry, result.as_ref().err());
    forward.finish(result.as_ref().err());
    result
}

/// The rate is measured over this much recent history.
const RATE_WINDOW: Duration = Duration::from_secs(5);
/// The ETA appears once the rate has been above zero for this long.
const ETA_AFTER: Duration = Duration::from_secs(10);
/// How often a view crosses the FFI while bytes move.
const UPDATE_INTERVAL: Duration = Duration::from_millis(100);
/// How often the rate is re-measured while nothing arrives, so a stall reads
/// as a rate falling to zero rather than the last number frozen.
const TICK: Duration = Duration::from_secs(1);

/// The view model: folds [`Event`]s into a [`TransferView`].
struct Model {
    kind: journal::Kind,
    view: TransferView,
    /// Sum of the planned sizes, the total on the HTTP paths and the push.
    planned_total: Option<u64>,
    /// Whether a carrier reports bytes for the whole package (QUIC), in which
    /// case the per-file `moved` fields do not sum to `moved_bytes`.
    carrier_bytes: bool,
    /// (when, moved_bytes) samples inside the rate window.
    samples: VecDeque<(Instant, u64)>,
    /// When the rate first became positive and has stayed so.
    rate_since: Option<Instant>,
}

impl Model {
    fn new(kind: journal::Kind) -> Self {
        Self {
            kind,
            view: TransferView {
                phase: Phase::Preparing,
                transport: None,
                files: Vec::new(),
                moved_bytes: 0,
                total_bytes: None,
                rate_bytes_per_second: None,
                eta_seconds: None,
                headline: None,
                detail: None,
                status: String::new(),
                route: None,
                rate_text: None,
            },
            planned_total: None,
            carrier_bytes: false,
            samples: VecDeque::new(),
            rate_since: None,
        }
    }

    /// Folds one event in at time `now`. Returns whether a phase changed,
    /// which always crosses the FFI regardless of the update interval.
    fn apply(&mut self, event: Event, now: Instant) -> bool {
        let before = self.view.phase;
        match event {
            Event::Selected { files } | Event::Planned { files } => {
                self.view.files = files
                    .into_iter()
                    .map(|file| FileView {
                        index: file.index as u64,
                        path: file.path,
                        bytes: file.bytes,
                        moved: 0,
                        state: FileState::Waiting,
                        label: String::new(),
                    })
                    .collect();
                let total = self.view.files.iter().map(|file| file.bytes).sum();
                self.planned_total = Some(total);
                self.view.total_bytes = Some(total);
            }
            Event::Transport(transport) => {
                self.view.transport = Some(transport);
                self.view.phase = Phase::Transferring;
            }
            Event::SessionCreated { .. } | Event::Rebegin => {}
            Event::Bytes { moved, total } => {
                self.carrier_bytes = true;
                // A push counts framing too, so it can run past the package.
                let cap = total.or(self.planned_total).unwrap_or(u64::MAX);
                self.view.moved_bytes = moved.min(cap);
                if total.is_some() {
                    self.view.total_bytes = total;
                }
            }
            Event::Chunk {
                index,
                covered,
                total,
            }
            | Event::Downloading {
                index,
                received: covered,
                total,
            } => {
                if let Some(file) = self.file_mut(index) {
                    file.moved = covered.min(total);
                    file.bytes = total;
                    file.state = FileState::Moving;
                }
                self.sum_files();
            }
            Event::EntryComplete { index, .. } => {
                if let Some(file) = self.file_mut(index) {
                    file.moved = file.bytes;
                    file.state = FileState::Landed;
                }
                self.sum_files();
            }
            Event::FileVerified { index, .. } => {
                if let Some(file) = self.file_mut(index) {
                    file.moved = file.bytes;
                    file.state = FileState::Verified;
                }
                self.sum_files();
            }
            Event::Finished { .. } => {
                // A push reports no per-file completion; the whole package is
                // at the receiver once the carrier finished.
                for file in &mut self.view.files {
                    file.moved = file.bytes;
                    if file.state != FileState::Verified {
                        file.state = FileState::Landed;
                    }
                }
                if let Some(total) = self.view.total_bytes {
                    self.view.moved_bytes = total;
                }
                self.view.phase = Phase::Done;
            }
        }
        self.measure(now);
        before != self.view.phase
    }

    fn file_mut(&mut self, index: usize) -> Option<&mut FileView> {
        self.view
            .files
            .iter_mut()
            .find(|file| file.index == index as u64)
    }

    fn sum_files(&mut self) {
        if !self.carrier_bytes {
            self.view.moved_bytes = self.view.files.iter().map(|file| file.moved).sum();
        }
    }

    /// Recomputes the rate over the window and the ETA once the rate held.
    fn measure(&mut self, now: Instant) {
        if self.view.phase != Phase::Transferring {
            self.view.rate_bytes_per_second = None;
            self.view.eta_seconds = None;
            return;
        }
        self.samples.push_back((now, self.view.moved_bytes));
        // Keep the newest sample older than the window as the floor, so a
        // stall reads as a rate falling to zero rather than no rate.
        while let Some(&(second, _)) = self.samples.get(1) {
            if now.duration_since(second) > RATE_WINDOW {
                self.samples.pop_front();
            } else {
                break;
            }
        }
        let (first_when, first_bytes) = self.samples[0];
        let span = now.duration_since(first_when);
        let rate = if span >= Duration::from_secs(1) {
            let moved = self.view.moved_bytes.saturating_sub(first_bytes) as f64;
            Some((moved / span.as_secs_f64()) as u64)
        } else {
            None
        };
        self.view.rate_bytes_per_second = rate;
        match rate {
            Some(rate) if rate > 0 => {
                let since = *self.rate_since.get_or_insert(now);
                let held = now.duration_since(since) >= ETA_AFTER;
                self.view.eta_seconds = match self.view.total_bytes {
                    Some(total) if held => {
                        Some(total.saturating_sub(self.view.moved_bytes).div_ceil(rate))
                    }
                    _ => None,
                };
            }
            _ => {
                self.rate_since = None;
                self.view.eta_seconds = None;
            }
        }
    }

    /// The view as a shell draws it, with the status line and the route
    /// written for the current state.
    fn snapshot(&mut self) -> TransferView {
        self.view.route = self.view.transport.map(|via| route_name(via).to_owned());
        self.view.rate_text = self
            .view
            .rate_bytes_per_second
            .map(|rate| format!("{}/s", human_bytes(rate)));
        for file in &mut self.view.files {
            file.label = file.label();
        }
        self.view.status = self.status();
        self.view.clone()
    }

    /// The one line under a card's subject. The web pages' words: files are
    /// checked, shipped, and landed; what verifies is said so.
    fn status(&self) -> String {
        let view = &self.view;
        let sending = self.kind == journal::Kind::Send;
        match view.phase {
            Phase::Preparing => {
                if sending {
                    "Checking the files".to_owned()
                } else {
                    "Getting ready".to_owned()
                }
            }
            Phase::Transferring => {
                let mut parts = vec![if sending { "Shipping" } else { "Receiving" }.to_owned()];
                if let Some(total) = view.total_bytes {
                    parts.push(format!(
                        "{} of {}",
                        human_bytes(view.moved_bytes),
                        human_bytes(total)
                    ));
                }
                if let Some(rate) = view.rate_bytes_per_second {
                    parts.push(format!("{}/s", human_bytes(rate)));
                }
                if let Some(eta) = view.eta_seconds {
                    parts.push(format!("about {} left", human_seconds(eta)));
                }
                parts.join(", ")
            }
            Phase::Done => {
                let count = view.files.len();
                let noun = if count == 1 { "file" } else { "files" };
                if sending {
                    format!("Shipped and verified, {count} {noun}")
                } else {
                    format!("Landed and verified, {count} {noun}")
                }
            }
            Phase::Cancelled => "Cancelled".to_owned(),
            Phase::Failed => view.headline.clone().unwrap_or_else(|| "Failed".to_owned()),
        }
    }

    /// Ends the transfer: the phase from the outcome, with a headline and the
    /// error's detail on a failure.
    fn end(&mut self, error: Option<&Error>) {
        self.view.phase = match error {
            None => Phase::Done,
            Some(Error::Cancelled) => Phase::Cancelled,
            Some(error) => {
                self.view.headline = Some(error.headline());
                self.view.detail = Some(error.to_string());
                Phase::Failed
            }
        };
        self.view.rate_bytes_per_second = None;
        self.view.eta_seconds = None;
    }
}

/// Adapts a listener and a handle to the core's observer: folds every event
/// into the model and hands the listener a fresh view on every phase change
/// and otherwise at most once per [`UPDATE_INTERVAL`]. While bytes move a
/// ticker thread re-measures every [`TICK`] so a stall shows.
struct Forward {
    transfer: Arc<Transfer>,
    listener: Arc<dyn TransferListener>,
    model: Arc<Mutex<Model>>,
    last_update: Option<Instant>,
    ticking: bool,
}

impl Forward {
    fn new(
        kind: journal::Kind,
        transfer: Arc<Transfer>,
        listener: Arc<dyn TransferListener>,
    ) -> Self {
        Self {
            transfer,
            listener,
            model: Arc::new(Mutex::new(Model::new(kind))),
            last_update: None,
            ticking: false,
        }
    }

    fn push(&mut self, model: &mut Model, now: Instant) {
        self.last_update = Some(now);
        self.listener.update(model.snapshot());
    }

    /// Spawns the ticker once the transfer is moving. It stops itself when
    /// the phase leaves Transferring, so a finished transfer never hears from
    /// it: `finish` ends the phase and pushes under the same lock.
    fn start_ticker(&mut self) {
        if self.ticking {
            return;
        }
        self.ticking = true;
        // Weak, so a Forward that unwinds past finish (a panic the FFI
        // boundary turns into an error) takes its ticker with it.
        let model = Arc::downgrade(&self.model);
        let listener = Arc::clone(&self.listener);
        std::thread::spawn(move || loop {
            std::thread::sleep(TICK);
            let Some(model) = model.upgrade() else {
                return;
            };
            let mut model = model
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if model.view.phase != Phase::Transferring {
                return;
            }
            model.measure(Instant::now());
            listener.update(model.snapshot());
        });
    }

    /// The final view after the command returned.
    fn finish(&mut self, error: Option<&Error>) {
        let model = Arc::clone(&self.model);
        let mut model = model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        model.end(error);
        self.push(&mut model, Instant::now());
    }
}

impl Observer for Forward {
    fn event(&mut self, event: Event) {
        let now = Instant::now();
        let model = Arc::clone(&self.model);
        let mut model = model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let phase_changed = model.apply(event, now);
        let due = self
            .last_update
            .is_none_or(|last| now.duration_since(last) >= UPDATE_INTERVAL);
        if phase_changed || due {
            self.push(&mut model, now);
        }
        if model.view.phase == Phase::Transferring {
            self.start_ticker();
        }
    }

    fn cancelled(&self) -> bool {
        self.transfer.is_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::PlannedFile;

    fn planned(sizes: &[u64]) -> Event {
        Event::Planned {
            files: sizes
                .iter()
                .enumerate()
                .map(|(index, &bytes)| PlannedFile {
                    index,
                    path: format!("f{index}"),
                    bytes,
                })
                .collect(),
        }
    }

    #[test]
    fn http_ticks_sum_per_file_and_finish_lands_everything() {
        let t0 = Instant::now();
        let mut model = Model::new(journal::Kind::Send);
        assert!(!model.apply(planned(&[100, 50]), t0));
        assert_eq!(model.view.phase, Phase::Preparing);
        assert_eq!(model.view.total_bytes, Some(150));
        assert!(model.apply(Event::Transport(Transport::Http), t0));
        assert_eq!(model.view.phase, Phase::Transferring);
        model.apply(
            Event::Chunk {
                index: 0,
                covered: 40,
                total: 100,
            },
            t0,
        );
        assert_eq!(model.view.moved_bytes, 40);
        assert_eq!(model.view.files[0].state, FileState::Moving);
        model.apply(
            Event::EntryComplete {
                index: 0,
                path: "f0".into(),
            },
            t0,
        );
        assert_eq!(model.view.moved_bytes, 100);
        assert_eq!(model.view.files[0].state, FileState::Landed);
        assert!(model.apply(Event::Finished { files: 2 }, t0));
        assert_eq!(model.view.phase, Phase::Done);
        assert_eq!(model.view.moved_bytes, 150);
        assert!(model
            .view
            .files
            .iter()
            .all(|file| file.state == FileState::Landed && file.moved == file.bytes));
    }

    #[test]
    fn carrier_bytes_drive_the_whole_and_are_capped_at_the_plan() {
        let t0 = Instant::now();
        let mut model = Model::new(journal::Kind::Send);
        model.apply(planned(&[100]), t0);
        model.apply(Event::Transport(Transport::Push), t0);
        model.apply(
            Event::Bytes {
                moved: 60,
                total: None,
            },
            t0,
        );
        assert_eq!(model.view.moved_bytes, 60);
        assert_eq!(model.view.files[0].state, FileState::Waiting);
        // Push framing runs past the package; the bar never does.
        model.apply(
            Event::Bytes {
                moved: 130,
                total: None,
            },
            t0,
        );
        assert_eq!(model.view.moved_bytes, 100);
        // A fetch knows the package length and reports it.
        model.apply(
            Event::Bytes {
                moved: 130,
                total: Some(200),
            },
            t0,
        );
        assert_eq!(
            (model.view.moved_bytes, model.view.total_bytes),
            (130, Some(200))
        );
    }

    #[test]
    fn rate_needs_a_second_and_eta_needs_ten_held() {
        let t0 = Instant::now();
        let mut model = Model::new(journal::Kind::Send);
        model.apply(planned(&[10_000]), t0);
        model.apply(Event::Transport(Transport::Http), t0);
        let tick = |model: &mut Model, at: Duration, covered: u64| {
            model.apply(
                Event::Chunk {
                    index: 0,
                    covered,
                    total: 10_000,
                },
                t0 + at,
            );
        };
        tick(&mut model, Duration::from_millis(500), 50);
        assert_eq!(model.view.rate_bytes_per_second, None, "under a second");
        tick(&mut model, Duration::from_secs(2), 200);
        assert_eq!(model.view.rate_bytes_per_second, Some(100));
        assert_eq!(model.view.eta_seconds, None, "rate not yet held");
        for second in 3..=11 {
            tick(&mut model, Duration::from_secs(second), second * 100);
        }
        assert_eq!(model.view.rate_bytes_per_second, Some(100));
        assert_eq!(model.view.eta_seconds, None, "held nine seconds only");
        tick(&mut model, Duration::from_secs(12), 1_200);
        assert_eq!(model.view.eta_seconds, Some(88), "(10000 - 1200) / 100");
        // The window drops old samples: a stall shows as a falling rate,
        // then the ETA goes away once the rate reaches zero.
        tick(&mut model, Duration::from_secs(20), 1_200);
        assert_eq!(model.view.rate_bytes_per_second, Some(0));
        assert_eq!(model.view.eta_seconds, None);
        assert!(model.rate_since.is_none(), "holding restarts after a stall");
        model.end(None);
        assert_eq!(model.view.phase, Phase::Done);
        assert_eq!(model.view.rate_bytes_per_second, None);
    }

    #[test]
    fn status_says_what_a_card_shows_in_every_phase() {
        let t0 = Instant::now();
        let mut model = Model::new(journal::Kind::Send);
        assert_eq!(model.snapshot().status, "Checking the files");
        model.apply(planned(&[10_000]), t0);
        model.apply(Event::Transport(Transport::Push), t0);
        let view = model.snapshot();
        assert_eq!(view.status, "Shipping, 0 bytes of 10.0 KB");
        assert_eq!(view.route.as_deref(), Some("Direct route (QUIC)"));
        assert_eq!(view.files[0].label, "10.0 KB");
        model.view.rate_bytes_per_second = Some(1_000);
        model.view.eta_seconds = Some(200);
        let view = model.snapshot();
        assert_eq!(
            view.status,
            "Shipping, 0 bytes of 10.0 KB, 1.0 KB/s, about 3 min 20 s left"
        );
        assert_eq!(view.rate_text.as_deref(), Some("1.0 KB/s"));
        model.apply(
            Event::Bytes {
                moved: 4_000,
                total: None,
            },
            t0,
        );
        model.apply(Event::Finished { files: 1 }, t0);
        model.end(None);
        let view = model.snapshot();
        assert_eq!(view.status, "Shipped and verified, 1 file");
        assert_eq!(view.rate_text, None);
        assert_eq!(view.files[0].label, "landed");

        let mut model = Model::new(journal::Kind::Receive);
        assert_eq!(model.snapshot().status, "Getting ready");
        model.apply(planned(&[1, 2]), t0);
        model.apply(Event::Transport(Transport::Http), t0);
        let view = model.snapshot();
        assert!(view.status.starts_with("Receiving, "), "{}", view.status);
        assert_eq!(view.route.as_deref(), Some("Standard route (HTTP)"));
        model.end(None);
        assert_eq!(model.snapshot().status, "Landed and verified, 2 files");
        model.end(Some(&Error::Cancelled));
        assert_eq!(model.snapshot().status, "Cancelled");
        model.end(Some(&Error::PasswordRequired));
        assert_eq!(model.snapshot().status, "This link needs a password.");
    }

    #[test]
    fn preview_line_reads_the_way_the_field_shows_it() {
        let base = LinkPreview {
            kind: Some(LinkKind::Request),
            problem: None,
            detail: None,
            label: Some("Dailies".to_owned()),
            needs_password: true,
            usable: true,
            quic: Some(true),
            max_bytes: Some(4_000_000_000),
            max_entries: Some(10),
            files: Vec::new(),
            total_bytes: None,
            line: None,
        };
        assert_eq!(
            base.clone().with_line().line.as_deref(),
            Some("Dailies, accepts up to 4.0 GB, password needed, direct route offered")
        );
        let problem = LinkPreview {
            problem: Some("That link is closed.".to_owned()),
            ..base.clone()
        };
        assert_eq!(
            problem.with_line().line.as_deref(),
            Some("That link is closed.")
        );
        let delivery = LinkPreview {
            kind: Some(LinkKind::Delivery),
            label: None,
            needs_password: false,
            quic: Some(false),
            files: vec![PreviewFile {
                path: "a".to_owned(),
                bytes: 5,
            }],
            total_bytes: Some(5),
            ..base
        };
        assert_eq!(
            delivery.with_line().line.as_deref(),
            Some("1 file, 5 bytes")
        );
        let empty = LinkPreview {
            kind: None,
            problem: None,
            detail: None,
            label: None,
            needs_password: false,
            usable: false,
            quic: None,
            max_bytes: None,
            max_entries: None,
            files: Vec::new(),
            total_bytes: None,
            line: None,
        };
        assert_eq!(empty.with_line().line, None);
    }

    #[test]
    fn end_maps_the_outcome_to_a_phase_with_the_headline_and_detail() {
        let mut model = Model::new(journal::Kind::Send);
        model.end(Some(&Error::Cancelled));
        assert_eq!(model.view.phase, Phase::Cancelled);
        assert_eq!((model.view.headline, model.view.detail), (None, None));
        let mut model = Model::new(journal::Kind::Send);
        model.end(Some(&Error::PasswordRequired));
        assert_eq!(model.view.phase, Phase::Failed);
        assert_eq!(
            model.view.headline.as_deref(),
            Some("This link needs a password.")
        );
        assert_eq!(
            model.view.detail.as_deref(),
            Some("this link needs a password")
        );
    }

    struct Count(std::sync::Mutex<Vec<TransferView>>);

    impl TransferListener for Count {
        fn update(&self, view: TransferView) {
            self.0.lock().unwrap().push(view);
        }
    }

    #[test]
    fn phase_changes_always_cross_and_byte_ticks_are_paced() {
        let count = Arc::new(Count(std::sync::Mutex::new(Vec::new())));
        let transfer = Transfer::new();
        let mut forward = Forward::new(journal::Kind::Send, transfer.clone(), count.clone());
        forward.event(planned(&[10]));
        forward.event(Event::Transport(Transport::Http));
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
        assert!(!forward.cancelled());
        transfer.cancel();
        assert!(forward.cancelled());
        forward.finish(Some(&Error::Cancelled));
        let seen = count.0.lock().unwrap();
        // Planned (first ever), Transport (phase change), the cancel; the two
        // chunks inside the interval are paced out unless the clock stalled.
        assert!(matches!(seen[0].phase, Phase::Preparing), "{seen:?}");
        assert!(matches!(seen[1].phase, Phase::Transferring), "{seen:?}");
        assert!(
            matches!(seen.last().unwrap().phase, Phase::Cancelled),
            "{seen:?}"
        );
    }

    #[test]
    fn a_stall_is_re_measured_by_the_ticker_and_the_end_silences_it() {
        let count = Arc::new(Count(std::sync::Mutex::new(Vec::new())));
        let mut forward = Forward::new(journal::Kind::Receive, Transfer::new(), count.clone());
        forward.event(planned(&[10]));
        forward.event(Event::Transport(Transport::Http));
        forward.event(Event::Chunk {
            index: 0,
            covered: 5,
            total: 10,
        });
        let before = count.0.lock().unwrap().len();
        std::thread::sleep(TICK + Duration::from_millis(300));
        let after = count.0.lock().unwrap().len();
        assert!(after > before, "the ticker pushed a view during the stall");
        forward.finish(None);
        let final_count = count.0.lock().unwrap().len();
        std::thread::sleep(TICK + Duration::from_millis(300));
        let seen = count.0.lock().unwrap();
        assert_eq!(seen.len(), final_count, "nothing after the final view");
        assert_eq!(seen.last().unwrap().phase, Phase::Done);
    }

    #[test]
    fn a_dropped_forward_takes_its_ticker_with_it() {
        let count = Arc::new(Count(std::sync::Mutex::new(Vec::new())));
        let mut forward = Forward::new(journal::Kind::Receive, Transfer::new(), count.clone());
        forward.event(planned(&[10]));
        forward.event(Event::Transport(Transport::Http));
        // Dropped mid-transfer without finish, as an unwinding panic would.
        drop(forward);
        let before = count.0.lock().unwrap().len();
        std::thread::sleep(TICK + Duration::from_millis(300));
        assert_eq!(
            count.0.lock().unwrap().len(),
            before,
            "no view after the drop"
        );
    }
}
