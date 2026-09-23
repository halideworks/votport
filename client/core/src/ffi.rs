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

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::api::{split_link, split_link_as, Client, LinkKind};
use crate::error::{human_bytes, human_seconds, Error};
use crate::identity::Device;
use crate::journal;
use crate::port;
use crate::progress::{Event, Observer, Transport};
use crate::receive::Delivery;
use crate::transfer::{self, Drop, Selected};
use crate::watch;

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
    /// Stopped by the person with the journal entry kept, so Resume picks
    /// it up where the partial left off.
    Paused,
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
    /// A full bar means publication completed, including empty files.
    pub progress_percent: u8,
    pub state: FileState,
    /// The words at the end of the row: the size, the bytes moved of the
    /// size, "landed", or "verified".
    pub label: String,
}

impl FileView {
    fn progress_percent(&self) -> u8 {
        if matches!(self.state, FileState::Landed | FileState::Verified) {
            100
        } else if self.bytes == 0 {
            0
        } else {
            (u128::from(self.moved) * 100 / u128::from(self.bytes)).min(99) as u8
        }
    }

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
    pub evidence_status: Option<String>,
    pub phase: Phase,
    /// Set once the transfer commits to a path.
    pub transport: Option<Transport>,
    /// Replace the file list when true; otherwise merge these rows by index.
    pub files_reset: bool,
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
    /// Completion time for formatting in the shell's local timezone.
    pub finished_unix_seconds: Option<u64>,
    pub finishing: bool,
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
    paused: AtomicBool,
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

    /// Stops the transfer like [`Transfer::cancel`] but keeps its journal
    /// entry, so the card ends as Paused with Resume rather than Cancelled.
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Release);
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
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
        let paused = matches!(error, Some(Error::Cancelled)) && self.is_paused();
        let kept = paused || error.is_some_and(Error::worth_retrying);
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
    crate::evidence::start_retry_worker();
    // A send another process (the CLI, or the app beside it) is running is
    // live, not interrupted: listing it would offer Resume and Remove, and
    // Remove aborts its server session.
    journal::pending()
        .into_iter()
        .filter(
            |entry| !matches!(entry.paths.as_slice(), [only] if watch::shipping_elsewhere(only)),
        )
        .collect()
}

/// Drops a transfer from the journal, for a failed or interrupted one the
/// person removed rather than resumed.
#[uniffi::export]
pub fn forget(id: String) {
    let entry = journal::get(&id).ok();
    journal::forget(&id);
    if let Some(entry) = entry {
        if entry.http.is_some() {
            let _ = std::thread::Builder::new()
                .name("votport-http-cleanup".to_owned())
                .spawn(move || abort_saved_http(&entry));
        }
    }
}

/// Releases a retained ordinary HTTP upload after its journal entry is being
/// discarded. This runs on a worker for UI-triggered forgets; ship already
/// runs off the UI thread and calls it inline before removing a replacement.
fn abort_saved_http(entry: &journal::Entry) {
    let Some(http) = entry.http.as_ref() else {
        return;
    };
    if !crate::send_http::valid_session_id(&http.session) {
        return;
    }
    let Ok(link) = split_link(&entry.link) else {
        return;
    };
    let Ok(client) = Client::with_timeout(&link.base, Some(Duration::from_secs(5))) else {
        return;
    };
    client.abort(&http.session);
}

fn resume_error_needs_abort(error: &Error, paused: bool) -> bool {
    match error {
        Error::Cancelled => !paused,
        Error::ResumeSourceChanged => true,
        Error::ResumeSessionInvalid => true,
        Error::ResumeSessionExpired => false,
        Error::Server {
            status: 404 | 410,
            what,
            ..
        } if what != "link info" => false,
        _ => !error.worth_retrying(),
    }
}

/// What a resumed transfer did: a send's report or a receive's.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum ResumeReport {
    Sent(SendReport),
    Received(ReceiveReport),
}

/// Runs a journalled transfer again under the same id: the same link and
/// paths, with `password` supplied afresh. A receive's `dest` overrides the
/// journalled folder for this run and is journalled as its folder, so a
/// retry can land in an empty one after a refusal like an existing file;
/// `None` runs where the entry points. Whatever an earlier run landed is
/// kept and resumed where the path allows. Blocks until done, like [`send`]
/// and [`receive`].
///
/// # Errors
/// An id the journal does not hold, or anything [`send`] or [`receive`]
/// can fail with.
#[uniffi::export]
pub fn resume(
    id: String,
    password: Option<String>,
    dest: Option<String>,
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
            // A watch ship moves its drop into the folder's `shipped`
            // subfolder only once the send ends well. A resume runs the
            // same journalled send, so it parks a drop that starts in a
            // watched folder the same way; left in place, the next watch
            // run would ship what this run just delivered. A send that
            // does not start in a watched folder is left alone, and a
            // failed park leaves the drop for the next watch run, whose
            // ship the server's dedupe keeps short, as in `ship`.
            let drop = entry.paths.first().cloned();
            let before = drop
                .as_deref()
                .and_then(|path| watch::fingerprint(Path::new(path)));
            let listener = LastView::wrap(listener);
            let sent = run_send(entry, password, transfer, listener.clone(), false, None);
            if sent.is_ok() {
                if let Some(path) = drop {
                    if watch::is_watched_drop(Path::new(&path)) {
                        if let Err(error) = watch::park_if_unchanged(Path::new(&path), before) {
                            listener.note(&error);
                        }
                    }
                }
            }
            sent.map(|(report, _flight)| ResumeReport::Sent(report))
        }
        journal::Kind::Receive => {
            let dest = dest.map(|dest| journal::absolute(&dest));
            run_receive(entry, password, transfer, listener, true, dest).map(ResumeReport::Received)
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
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record, Default)]
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
/// Blocks for at most the preview request timeout against a host that accepts
/// but never answers. Preview requests make one attempt; transfer requests
/// keep their longer retry budget. A shell runs it off its main thread and
/// ignores a result for a link the field no longer holds.
#[uniffi::export]
pub fn inspect(link: String, expect: Option<LinkKind>) -> LinkPreview {
    match preview(&link, expect) {
        Ok(preview) => preview,
        Err(error) => LinkPreview {
            kind: split_link(&link).ok().map(|link| link.kind),
            problem: Some(error.headline()),
            detail: Some(error.to_string()),
            ..LinkPreview::default()
        },
    }
    .with_line()
}

fn preview(link: &str, expect: Option<LinkKind>) -> std::result::Result<LinkPreview, Error> {
    let link = match expect {
        Some(kind) => split_link_as(link, kind)?,
        None => split_link(link)?,
    };
    let client = crate::api::Client::for_preview(&link.base)?;
    if link.kind == LinkKind::Delivery {
        let metadata = client.outbound_metadata_for_preview(&link.token, None)?;
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
            label: metadata.label,
            needs_password: !known,
            usable: true,
            quic: known.then_some(metadata.fetch.is_some()),
            total_bytes: known.then(|| files.iter().map(|file| file.bytes).sum()),
            files,
            ..LinkPreview::default()
        })
    } else {
        let info = client.link_info_for_preview(&link.token)?;
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
            ..LinkPreview::default()
        })
    }
}

/// The port the operator is signed in to, from the stored session, without
/// a round trip. `None` when nobody is signed in.
#[uniffi::export]
pub fn port() -> Option<port::Port> {
    port::current()
}

/// Starts a browser sign-in bound to this app and port. Blocks for the
/// availability check; the shell opens the returned authorization URL.
#[uniffi::export]
pub fn begin_sso(base: String) -> std::result::Result<Arc<port::SsoLogin>, port::PortError> {
    port::begin_sso(&base).map_err(port::PortError::sign_in)
}

/// Signs in to the votport at `base` with the admin password. Blocks for
/// the round trips; a shell runs it off its main thread.
///
/// # Errors
/// A base that is not an origin, a wrong password, too many tries, or an
/// unreachable server.
#[uniffi::export]
pub fn sign_in(base: String, password: String) -> std::result::Result<port::Port, port::PortError> {
    port::sign_in(&base, &password).map_err(port::PortError::from)
}

/// Asks the server whether the stored session still holds; a session it no
/// longer honours is dropped and `None` comes back. Blocks for the round
/// trip, and through the retry budget while the server restarts; a shell
/// runs it off its main thread.
///
/// # Errors
/// An unreachable server.
#[uniffi::export]
pub fn check_port() -> std::result::Result<Option<port::Port>, port::PortError> {
    port::check().map_err(port::PortError::from)
}

/// Ends the session and forgets it.
#[uniffi::export]
pub fn sign_out() {
    port::sign_out();
}

/// Removes every piece of local client data: the stored port session, the
/// watch list with its saved passwords, the transfer journal, the evidence
/// outbox, and the device key. A shell offers this as "Remove local data"
/// in Settings, so an uninstall leaves nothing behind. Blocks for the
/// removal; a shell runs it off its main thread.
///
/// # Errors
/// A state directory that cannot be removed.
#[uniffi::export]
pub fn forget_everything() -> std::result::Result<(), port::PortError> {
    crate::identity::forget_everything().map_err(port::PortError::from)
}

/// The port's open request links.
///
/// # Errors
/// Not signed in, or an unreachable server.
#[uniffi::export]
pub fn requests() -> std::result::Result<Vec<port::RequestLink>, port::PortError> {
    port::requests().map_err(port::PortError::from)
}

/// Issues a request link on the port.
///
/// # Errors
/// Not signed in, a refused spec, or an unreachable server.
#[uniffi::export]
pub fn issue_request(
    spec: port::RequestSpec,
) -> std::result::Result<port::RequestLink, port::PortError> {
    port::issue_request(spec).map_err(port::PortError::from)
}

/// Closes a request link.
///
/// # Errors
/// Not signed in, or an unreachable server.
#[uniffi::export]
pub fn close_request(id: String) -> std::result::Result<(), port::PortError> {
    port::close_request(&id).map_err(port::PortError::from)
}

/// The port's deliveries.
///
/// # Errors
/// Not signed in, or an unreachable server.
#[uniffi::export]
pub fn deliveries() -> std::result::Result<Vec<port::Delivery>, port::PortError> {
    port::deliveries().map_err(port::PortError::from)
}

/// Revokes a delivery.
///
/// # Errors
/// Not signed in, or an unreachable server.
#[uniffi::export]
pub fn revoke_delivery(id: String) -> std::result::Result<(), port::PortError> {
    port::revoke_delivery(&id).map_err(port::PortError::from)
}

/// One directory of the port's library (`""` for the root).
///
/// # Errors
/// Not signed in, a refused directory, or an unreachable server.
#[uniffi::export]
pub fn library(
    directory: String,
    after: Option<String>,
) -> std::result::Result<port::Library, port::PortError> {
    port::library(&directory, after.as_deref()).map_err(port::PortError::from)
}

/// Uploads a drop of files and folders into the port's library under `into`
/// (the UTC date when empty; a shell passes the local day), reporting
/// progress to `listener` with one view across the whole drop, and returns
/// the library files made, ready for [`issue_delivery`]. Blocks until done,
/// so a shell calls it off its main thread; `transfer` cancels it.
///
/// # Errors
/// Not signed in, a path the library already holds, a file over the port's
/// limit, a cancel, or an unreachable server.
#[uniffi::export]
pub fn upload(
    paths: Vec<String>,
    into: String,
    transfer: Arc<Transfer>,
    listener: Arc<dyn port::UploadListener>,
) -> std::result::Result<Vec<port::LibraryFile>, port::PortError> {
    port::upload(
        &paths,
        &into,
        &|| transfer.is_cancelled(),
        listener.as_ref(),
    )
    .map_err(port::PortError::from)
}

/// Issues a delivery of library files; the reply carries the one link the
/// server ever shows for it.
///
/// # Errors
/// Not signed in, a refused spec, or an unreachable server.
#[uniffi::export]
pub fn issue_delivery(
    spec: port::DeliverySpec,
) -> std::result::Result<port::IssuedDelivery, port::PortError> {
    port::issue_delivery(spec).map_err(port::PortError::from)
}

/// The watched folders.
#[uniffi::export]
pub fn watches() -> Vec<watch::Watch> {
    watch::watches()
}

/// Watches `dir`: its settled drops ship to the request `link`.
///
/// # Errors
/// A `dir` that is not a folder, or a link that is not a request link,
/// as a [`port::PortError`] so a settings screen shows the headline.
#[uniffi::export]
pub fn add_watch(
    dir: String,
    link: String,
    password: Option<String>,
) -> std::result::Result<watch::Watch, port::PortError> {
    watch::add_watch(&dir, &link, password).map_err(port::PortError::from)
}

/// Stops watching; nothing in the folder changes.
///
/// # Errors
/// A write failure.
#[uniffi::export]
pub fn remove_watch(id: String) -> std::result::Result<(), port::PortError> {
    watch::remove_watch(&id).map_err(port::PortError::from)
}

/// What a watch ship did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ShipReport {
    pub files: u64,
    /// The drop moved into the folder's `shipped` subfolder.
    pub parked: bool,
    /// Why it could not be moved, when it could not. The send itself ended
    /// well; the drop stays in the folder and ships again at the next
    /// launch, which the server's dedupe on a known root keeps short.
    pub park_problem: Option<String>,
}

/// Ships one settled drop of a watched folder, as [`send`] would, and moves
/// it into the folder's `shipped` subfolder when the send ends well. One
/// ship per path at a time: a second call for a path still shipping fails
/// at once. A journal entry an earlier cut send left for the same path is
/// forgotten first, since this send starts afresh. A drop that fails stays
/// where it is with its journal entry, so a Retry runs it again; ponytail:
/// a retried drop is not moved afterwards.
///
/// # Errors
/// An unknown watch, a path already shipping, or anything [`send`] can
/// fail with.
#[uniffi::export]
pub fn ship(
    watch_id: String,
    path: String,
    admission: Arc<watch::WatchAdmission>,
    transfer: Arc<Transfer>,
    listener: Arc<dyn TransferListener>,
) -> std::result::Result<ShipReport, Error> {
    let flight = admission.take(&watch_id, &path)?;
    let (link, password) = watch::credentials(&watch_id)?;
    journal::forget_send_of(&path, abort_saved_http);
    let entry = journal::record(
        journal::Kind::Send,
        &link,
        vec![path.clone()],
        None,
        password.is_some(),
    );
    let sent = watch::fingerprint(Path::new(&path));
    let listener = LastView::wrap(listener);
    let (report, _flight) = run_send(
        entry,
        password,
        transfer,
        listener.clone(),
        true,
        Some(flight),
    )?;
    let parked = watch::park_if_unchanged(Path::new(&path), sent);
    if let Err(error) = &parked {
        listener.note(error);
    }
    Ok(ShipReport {
        files: report.files,
        parked: parked.is_ok(),
        park_problem: parked.err().map(|error| error.headline()),
    })
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
    run_send(entry, password, transfer, listener, true, None).map(|(report, _)| report)
}

/// Runs a journalled send. The entry is dropped from the journal when the
/// send ends well or a terminal cancel occurs, and kept for Pause or a
/// retryable failure so the next launch can offer the same session again.
fn run_send(
    entry: journal::Entry,
    password: Option<String>,
    transfer: Arc<Transfer>,
    listener: Arc<dyn TransferListener>,
    new_journal: bool,
    claimed_flight: Option<watch::Flight>,
) -> std::result::Result<(SendReport, Option<watch::Flight>), Error> {
    let existing_http = entry.http.clone();
    let resume = existing_http.as_ref().map(|http| transfer::HttpResume {
        session: &http.session,
        chunk_bytes: http.chunk_bytes,
        root: &http.root,
        length: http.length,
    });
    let handle = Arc::clone(&transfer);
    let mut forward = Forward::new(journal::Kind::Send, transfer, listener);
    if new_journal {
        handle.set_journal_id(&entry.id);
    }
    // The claim goes back to the caller with the report, so a ship or
    // resume keeps the drop claimed until it has been parked.
    let flight = if let Some(flight) = claimed_flight {
        Some(flight)
    } else {
        match entry.paths.as_slice() {
            [only] => match watch::single_flight(only) {
                Ok(flight) => Some(flight),
                Err(error) => {
                    let result = Err(error);
                    if new_journal {
                        handle.settle(&entry, result.as_ref().err());
                    }
                    forward.finish(result.as_ref().err());
                    return result;
                }
            },
            _ => None,
        }
    };
    if !new_journal {
        handle.set_journal_id(&entry.id);
    }
    let result = (|| {
        let link = split_link_as(&entry.link, LinkKind::Request)?;
        let info = Client::new(&link.base)?.link_info(&link.token)?;
        let mut files: Vec<Selected> = Vec::new();
        for path in &entry.paths {
            transfer::collect_for_link(Path::new(path), &mut files, info.allow_hidden).map_err(
                |source| Error::Read {
                    path: path.into(),
                    source,
                },
            )?;
        }
        let drop = Drop {
            token: link.token,
            password,
            files,
        };
        let device = Device::load_or_create()?;
        Ok(
            match transfer::send_with_session(
                &link.base,
                drop,
                &device,
                &mut forward,
                resume,
                |session, chunk_bytes, prepared| {
                    journal::mark_http(
                        &entry,
                        journal::HttpResume {
                            session: session.to_owned(),
                            chunk_bytes,
                            root: hex::encode(prepared.summary.root),
                            length: prepared.summary.logical_length,
                        },
                    )
                    .map(|()| true)
                },
            )? {
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
    if existing_http.is_some() {
        if let Some(error) = result.as_ref().err() {
            if resume_error_needs_abort(error, handle.is_paused()) {
                abort_saved_http(&entry);
            }
        }
    }
    let result = match result {
        Err(Error::Server {
            status: 404 | 410,
            ref what,
            ..
        }) if existing_http.is_some() && what != "link info" => {
            Err(clear_resume_error(&entry.id, Error::ResumeSessionExpired))
        }
        Err(Error::ResumeSourceChanged) if existing_http.is_some() => {
            Err(clear_resume_error(&entry.id, Error::ResumeSourceChanged))
        }
        Err(Error::ResumeSessionInvalid) if existing_http.is_some() => {
            Err(clear_resume_error(&entry.id, Error::ResumeSessionInvalid))
        }
        result => result,
    };
    handle.settle(&entry, result.as_ref().err());
    forward.finish(result.as_ref().err());
    result.map(|report| (report, flight))
}

fn clear_resume_error(id: &str, error: Error) -> Error {
    match journal::clear_http(id) {
        Ok(()) => error,
        Err(clear) => Error::Other(format!(
            "{error}; could not clear the saved session for a fresh retry: {clear}"
        )),
    }
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
    run_receive(entry, password, transfer, listener, false, None)
}

/// Runs a journalled receive; the entry's fate is as for [`run_send`].
/// `dest_override` repoints the run at another, already-absolute folder and
/// journals it, so a retry re-asked for the folder lands there and every
/// later offer follows.
fn run_receive(
    mut entry: journal::Entry,
    password: Option<String>,
    transfer: Arc<Transfer>,
    listener: Arc<dyn TransferListener>,
    resume: bool,
    dest_override: Option<String>,
) -> std::result::Result<ReceiveReport, Error> {
    transfer.set_journal_id(&entry.id);
    let handle = Arc::clone(&transfer);
    let mut forward = Forward::new(journal::Kind::Receive, transfer, listener);
    let result = (|| {
        let link = split_link_as(&entry.link, LinkKind::Delivery)?;
        if let Some(dest) = dest_override {
            journal::set_dest(&entry.id, &dest);
            entry.dest = Some(dest);
        }
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
        let received = crate::receive::receive_with_device_or_http_mode(
            &link.base,
            delivery,
            Path::new(dest),
            &mut forward,
            resume,
        )?;
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
    started: Instant,
    elapsed: Option<Duration>,
    attempt_bytes: u64,
    files: Vec<FileView>,
    positions: HashMap<u64, usize>,
    dirty: HashSet<usize>,
    files_reset: bool,
    file_moved: u128,
    files_complete: usize,
    /// Sum of the planned sizes, the total on the HTTP paths and the push.
    planned_total: Option<u64>,
    /// Whether a carrier reports bytes for the whole package (QUIC), in which
    /// case the per-file `moved` fields do not sum to `moved_bytes`.
    carrier_bytes: bool,
    /// (when, rate bytes) samples inside the rate window.
    samples: VecDeque<(Instant, u64)>,
    /// When the rate first became positive and has stayed so.
    rate_since: Option<Instant>,
}

impl Model {
    fn new(kind: journal::Kind) -> Self {
        Self {
            kind,
            view: TransferView {
                evidence_status: None,
                phase: Phase::Preparing,
                transport: None,
                files_reset: true,
                files: Vec::new(),
                moved_bytes: 0,
                total_bytes: None,
                rate_bytes_per_second: None,
                eta_seconds: None,
                finished_unix_seconds: None,
                finishing: false,
                headline: None,
                detail: None,
                status: String::new(),
                route: None,
                rate_text: None,
            },
            started: Instant::now(),
            elapsed: None,
            attempt_bytes: 0,
            files: Vec::new(),
            positions: HashMap::new(),
            dirty: HashSet::new(),
            files_reset: true,
            file_moved: 0,
            files_complete: 0,
            planned_total: None,
            carrier_bytes: false,
            samples: VecDeque::new(),
            rate_since: None,
        }
    }

    /// Folds one event in at time `now`. Phase and finishing transitions
    /// always cross the FFI regardless of the update interval.
    fn apply(&mut self, event: Event, now: Instant) -> bool {
        let before = (self.view.phase, self.finishing());
        match event {
            Event::Evidence { status } => {
                self.view.evidence_status = Some(
                    match status.as_str() {
                        "recorded" => "Verification reported",
                        "pending" => "Verification report queued for retry",
                        _ => "Verification report unavailable",
                    }
                    .to_owned(),
                );
                return true;
            }
            Event::Transferred { bytes } => {
                self.attempt_bytes = self.attempt_bytes.saturating_add(bytes);
            }
            Event::Selected { files } | Event::Planned { files } => {
                self.files = files
                    .into_iter()
                    .map(|file| FileView {
                        index: file.index as u64,
                        path: file.path,
                        bytes: file.bytes,
                        moved: 0,
                        progress_percent: 0,
                        state: FileState::Waiting,
                        label: String::new(),
                    })
                    .collect();
                self.positions.clear();
                for (position, file) in self.files.iter().enumerate() {
                    self.positions.entry(file.index).or_insert(position);
                }
                self.dirty.clear();
                self.files_reset = true;
                self.file_moved = 0;
                self.files_complete = 0;
                self.carrier_bytes = false;
                self.view.moved_bytes = 0;
                self.attempt_bytes = 0;
                self.samples.clear();
                self.rate_since = None;
                let total = self
                    .files
                    .iter()
                    .map(|file| u128::from(file.bytes))
                    .sum::<u128>()
                    .min(u128::from(u64::MAX)) as u64;
                self.planned_total = Some(total);
                self.view.total_bytes = Some(total);
            }
            Event::Transport(transport) => {
                self.view.transport = Some(transport);
                self.view.phase = Phase::Transferring;
            }
            Event::SessionCreated { .. } | Event::Rebegin => {}
            Event::Bytes { moved, total } => {
                if self.view.transport == Some(Transport::Push) {
                    self.attempt_bytes = moved;
                }
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
                self.update_file(index, |file| {
                    file.moved = covered.min(total);
                    file.bytes = total;
                    file.state = FileState::Moving;
                });
            }
            Event::EntryComplete { index, .. } => {
                self.update_file(index, |file| {
                    file.moved = file.bytes;
                    file.state = FileState::Landed;
                });
            }
            Event::FileVerified { index, .. } => {
                self.update_file(index, |file| {
                    file.moved = file.bytes;
                    file.state = FileState::Verified;
                });
            }
            Event::Finished { .. } => {
                // A push reports no per-file completion; the whole package is
                // at the receiver once the carrier finished.
                for file in &mut self.files {
                    file.moved = file.bytes;
                    if file.state != FileState::Verified {
                        file.state = FileState::Landed;
                    }
                }
                self.file_moved = self.files.iter().map(|file| u128::from(file.moved)).sum();
                self.files_complete = self.files.len();
                self.dirty.extend(0..self.files.len());
                if let Some(total) = self.view.total_bytes {
                    self.view.moved_bytes = total;
                }
                self.view.phase = Phase::Done;
                self.finish(now);
            }
        }
        self.measure(now);
        before != (self.view.phase, self.finishing())
    }

    fn finishing(&self) -> bool {
        self.view.phase == Phase::Transferring
            && self
                .view
                .total_bytes
                .is_some_and(|total| self.view.moved_bytes >= total)
    }

    fn update_file(&mut self, index: usize, update: impl FnOnce(&mut FileView)) {
        if let Some(&position) = self.positions.get(&(index as u64)) {
            let file = &mut self.files[position];
            self.files_complete -= usize::from(matches!(
                file.state,
                FileState::Landed | FileState::Verified
            ));
            self.file_moved -= u128::from(file.moved);
            update(file);
            self.file_moved += u128::from(file.moved);
            self.files_complete += usize::from(matches!(
                file.state,
                FileState::Landed | FileState::Verified
            ));
            self.dirty.insert(position);
            if !self.carrier_bytes {
                self.view.moved_bytes = self.file_moved.min(u128::from(u64::MAX)) as u64;
            }
        }
    }

    /// Recomputes the rate over the window and the ETA once the rate held.
    fn measure(&mut self, now: Instant) {
        if self.view.phase != Phase::Transferring {
            self.view.rate_bytes_per_second = None;
            self.view.eta_seconds = None;
            return;
        }
        // Audit finding 567: the rate samples this attempt's bytes only.
        // The carrier's live count includes the retained prefix of a resumed
        // fetch, and crediting that inside the window read as hundreds of
        // MB/s; attempt_bytes tracks this attempt alone.
        let rate_bytes = self.attempt_bytes;
        self.samples.push_back((now, rate_bytes));
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
            let moved = rate_bytes.saturating_sub(first_bytes) as f64;
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
                    Some(total) if held && self.view.moved_bytes < total => {
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
        self.view.finishing = self.finishing();
        self.view.route = self.view.transport.map(|via| route_name(via).to_owned());
        self.view.rate_text = self
            .view
            .rate_bytes_per_second
            .map(|rate| format!("{}/s", human_bytes(rate)));
        self.view.status = self.status();
        let mut view = self.view.clone();
        view.files_reset = std::mem::take(&mut self.files_reset);
        if view.files_reset {
            for file in &mut self.files {
                file.label = file.label();
                file.progress_percent = file.progress_percent();
            }
            view.files = self.files.clone();
            self.dirty.clear();
        } else {
            view.files = self
                .dirty
                .drain()
                .map(|position| {
                    let file = &mut self.files[position];
                    file.label = file.label();
                    file.progress_percent = file.progress_percent();
                    file.clone()
                })
                .collect();
        }
        view
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
                let count = self.files.len();
                let noun = if count == 1 { "file" } else { "files" };
                let fetching = view.transport == Some(Transport::Fetch);
                let mut parts = vec![if view.finishing {
                    "Verifying and finishing"
                } else if sending {
                    "Shipping"
                } else {
                    "Receiving"
                }
                .to_owned()];
                let action = if fetching { "complete" } else { "verified" };
                if view.transport == Some(Transport::Push) && !view.finishing {
                    parts[0] = format!("Shipping {count} {noun}");
                } else {
                    parts.push(format!(
                        "{} of {count} {noun} {action}",
                        self.files_complete
                    ));
                }
                if let Some(total) = view.total_bytes {
                    parts.push(format!(
                        "{} of {}",
                        human_bytes(view.moved_bytes),
                        human_bytes(total)
                    ));
                }
                if let Some(rate) = view.rate_bytes_per_second.filter(|_| !view.finishing) {
                    parts.push(format!("{}/s", human_bytes(rate)));
                }
                if let Some(eta) = view.eta_seconds {
                    parts.push(format!("about {} left", human_seconds(eta)));
                }
                parts.join(", ")
            }
            Phase::Done => {
                let count = self.files.len();
                let noun = if count == 1 { "file" } else { "files" };
                let action = if sending {
                    "Shipped and verified"
                } else {
                    "Landed and verified"
                };
                let bytes = self.planned_total.unwrap_or(view.moved_bytes);
                let elapsed = self.elapsed.unwrap_or_default();
                format!(
                    "{action}, {count} {noun}, {}, {}",
                    human_bytes(bytes),
                    human_seconds(elapsed.as_secs())
                )
            }
            Phase::Cancelled => "Cancelled".to_owned(),
            Phase::Paused => match view.total_bytes {
                Some(total) => format!(
                    "Paused, {} of {}",
                    human_bytes(view.moved_bytes),
                    human_bytes(total)
                ),
                None => "Paused".to_owned(),
            },
            Phase::Failed => view.headline.clone().unwrap_or_else(|| "Failed".to_owned()),
        }
    }

    fn finish(&mut self, now: Instant) {
        if self.elapsed.is_none() {
            self.elapsed = Some(now.saturating_duration_since(self.started));
            self.view.finished_unix_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|time| time.as_secs());
        }
    }

    /// Ends the transfer: the phase from the outcome, with a headline and the
    /// error's detail on a failure.
    fn end(&mut self, error: Option<&Error>, paused: bool) {
        self.view.phase = match error {
            None => Phase::Done,
            Some(Error::Cancelled) if paused => Phase::Paused,
            Some(Error::Cancelled) => Phase::Cancelled,
            Some(error) => {
                self.view.headline = Some(error.headline());
                self.view.detail = Some(error.to_string());
                Phase::Failed
            }
        };
        if error.is_none() {
            self.finish(Instant::now());
        }
        self.view.rate_bytes_per_second = None;
        self.view.eta_seconds = None;
    }
}

/// Forwards a transfer's views and keeps the last, so a note that lands
/// after the send itself (a drop that could not be parked) still reaches
/// the card as its detail line.
struct LastView {
    inner: Arc<dyn TransferListener>,
    last: Mutex<Option<TransferView>>,
}

impl LastView {
    fn wrap(inner: Arc<dyn TransferListener>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            last: Mutex::new(None),
        })
    }

    fn note(&self, park_problem: &Error) {
        let last = self
            .last
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(mut view) = last {
            view.detail = Some(format!(
                "Sent. It was not moved into shipped: {park_problem}"
            ));
            self.inner.update(view);
        }
    }
}

impl TransferListener for LastView {
    fn update(&self, view: TransferView) {
        *self
            .last
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(view.clone());
        self.inner.update(view);
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
        model.end(error, self.transfer.is_paused());
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
        let state_changed = model.apply(event, now);
        let due = self
            .last_update
            .is_none_or(|last| now.duration_since(last) >= UPDATE_INTERVAL);
        if state_changed || due {
            self.push(&mut model, now);
        }
        if model.view.phase == Phase::Transferring {
            self.start_ticker();
        }
    }

    fn cancelled(&self) -> bool {
        self.transfer.is_cancelled()
    }

    fn paused(&self) -> bool {
        self.transfer.is_paused()
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
    fn row_bar_finishes_only_after_publication_including_empty_files() {
        let now = Instant::now();
        let mut model = Model::new(journal::Kind::Receive);
        model.apply(planned(&[0, 100]), now);
        let initial = model.snapshot();
        assert_eq!(initial.files[0].progress_percent, 0);
        model.apply(
            Event::Downloading {
                index: 1,
                received: 100,
                total: 100,
            },
            now,
        );
        assert_eq!(model.snapshot().files[0].progress_percent, 99);
        for index in [0, 1] {
            model.apply(
                Event::FileVerified {
                    index,
                    path: index.to_string(),
                },
                now,
            );
        }
        let saved = model.snapshot();
        assert!(saved.files.iter().all(|file| file.progress_percent == 100));
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
        assert_eq!(model.files[0].state, FileState::Moving);
        model.apply(
            Event::EntryComplete {
                index: 0,
                path: "f0".into(),
            },
            t0,
        );
        assert_eq!(model.view.moved_bytes, 100);
        assert_eq!(model.files[0].state, FileState::Landed);
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
        assert_eq!(model.files[0].state, FileState::Waiting);
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
    fn file_updates_reset_merge_and_preserve_aggregate() {
        let now = Instant::now();
        let mut model = Model::new(journal::Kind::Receive);
        assert!(model.snapshot().files_reset);
        model.apply(planned(&[100, 200]), now);
        let initial = model.snapshot();
        assert!(initial.files_reset);
        assert_eq!(initial.files.len(), 2);
        for received in [80, 20, 50] {
            model.apply(
                Event::Downloading {
                    index: 1,
                    received,
                    total: 200,
                },
                now,
            );
        }
        model.apply(
            Event::Downloading {
                index: 99,
                received: 90,
                total: 100,
            },
            now,
        );
        let delta = model.snapshot();
        assert!(!delta.files_reset);
        assert_eq!(delta.files.len(), 1);
        assert_eq!(
            (
                delta.files[0].index,
                delta.files[0].moved,
                delta.moved_bytes
            ),
            (1, 50, 50)
        );
        assert_eq!(delta.files[0].label, "50 bytes of 200 bytes");
        assert!(model.snapshot().files.is_empty());
        model.apply(
            Event::Bytes {
                moved: 17,
                total: Some(300),
            },
            now,
        );
        model.apply(
            Event::FileVerified {
                index: 0,
                path: "0".into(),
            },
            now,
        );
        assert_eq!(model.snapshot().moved_bytes, 17);
        model.apply(Event::Transport(Transport::Fetch), now);
        assert!(model
            .snapshot()
            .status
            .contains("Receiving, 1 of 2 files complete"));
        model.apply(
            Event::FileVerified {
                index: 0,
                path: "0".into(),
            },
            now,
        );
        assert!(model.snapshot().status.contains("1 of 2 files complete"));
        model.apply(
            Event::Downloading {
                index: 0,
                received: 4,
                total: 100,
            },
            now,
        );
        assert!(model
            .snapshot()
            .status
            .contains("Receiving, 0 of 2 files complete"));
        model.apply(
            Event::FileVerified {
                index: 0,
                path: "0".into(),
            },
            now,
        );
        model.apply(Event::Finished { files: 2 }, now);
        let done = model.snapshot();
        assert_eq!(done.files.len(), 2);
        assert_eq!(done.moved_bytes, 300);
        assert_eq!(model.files[0].state, FileState::Verified);
        assert_eq!(model.files[1].state, FileState::Landed);
        assert!(model.snapshot().files.is_empty());
        model.apply(planned(&[10]), now);
        let reset = model.snapshot();
        assert!(reset.files_reset);
        assert_eq!(reset.files.len(), 1);
        assert_eq!(reset.moved_bytes, 0);
        model.apply(
            Event::Downloading {
                index: 0,
                received: 4,
                total: 10,
            },
            now,
        );
        assert_eq!(model.snapshot().moved_bytes, 4);
    }

    #[test]
    fn fetch_keeps_one_completion_counter_while_receiving() {
        let now = Instant::now();
        let mut model = Model::new(journal::Kind::Receive);
        model.apply(planned(&[100, 200]), now);
        model.apply(Event::Transport(Transport::Fetch), now);
        assert!(model
            .snapshot()
            .status
            .starts_with("Receiving, 0 of 2 files complete"));
        model.apply(
            Event::Bytes {
                moved: 300,
                total: Some(300),
            },
            now,
        );
        assert!(model
            .snapshot()
            .status
            .starts_with("Verifying and finishing, 0 of 2 files complete"));
        model.apply(
            Event::FileVerified {
                index: 0,
                path: "0".into(),
            },
            now,
        );
        assert!(model
            .snapshot()
            .status
            .starts_with("Verifying and finishing, 1 of 2 files complete"));
        model.apply(Event::Transport(Transport::Http), now);
        assert!(model
            .snapshot()
            .status
            .starts_with("Verifying and finishing, 1 of 2 files verified"));
    }

    #[test]
    fn rate_counts_only_bytes_transferred_in_this_attempt() {
        let t0 = Instant::now();
        let mut model = Model::new(journal::Kind::Receive);
        model.apply(planned(&[10_000]), t0);
        model.apply(Event::Transport(Transport::Http), t0);
        let mut previous = 0;
        let mut tick = |at: Duration, covered: u64| {
            model.apply(
                Event::Transferred {
                    bytes: covered.saturating_sub(previous),
                },
                t0 + at,
            );
            model.apply(
                Event::Downloading {
                    index: 0,
                    received: 8_000 + covered,
                    total: 10_000,
                },
                t0 + at,
            );
            previous = covered;
            (
                model.view.rate_bytes_per_second,
                model.view.eta_seconds,
                model.view.moved_bytes,
            )
        };
        let (rate, eta, moved) = tick(Duration::from_millis(500), 50);
        assert_eq!(rate, None, "under a second");
        assert_eq!(eta, None);
        assert_eq!(moved, 8_050);
        let (rate, eta, moved) = tick(Duration::from_secs(2), 200);
        assert_eq!(rate, Some(100));
        assert_eq!(eta, None, "rate not yet held");
        assert_eq!(moved, 8_200);
        for second in 3..=10 {
            tick(Duration::from_secs(second), second * 100);
        }
        let (rate, eta, moved) = tick(Duration::from_secs(11), 1_100);
        assert_eq!(rate, Some(100));
        assert_eq!(eta, None, "held nine seconds only");
        assert_eq!(moved, 9_100);
        let (rate, eta, moved) = tick(Duration::from_secs(12), 1_200);
        assert_eq!(rate, Some(100));
        assert_eq!(eta, Some(8), "(10000 - (8000 + 1200)) / 100");
        assert_eq!(moved, 9_200);
        // The window drops old samples: a stall shows as a falling rate,
        // then the ETA goes away once the rate reaches zero.
        model.measure(t0 + Duration::from_secs(20));
        assert_eq!(model.view.rate_bytes_per_second, Some(0));
        assert_eq!(model.view.eta_seconds, None);
        assert!(model.rate_since.is_none(), "holding restarts after a stall");
        model.end(None, false);
        assert_eq!(model.view.phase, Phase::Done);
        assert_eq!(model.view.rate_bytes_per_second, None);
    }

    /// Audit finding 567: a resumed fetch's carrier progress credits the
    /// retained prefix inside the rate window, so the window must read this
    /// attempt's bytes, not the prefix-jumping carrier count.
    #[test]
    fn resumed_fetch_rate_counts_this_attempt_not_the_retained_prefix() {
        let t0 = Instant::now();
        let mut model = Model::new(journal::Kind::Receive);
        model.apply(planned(&[10_000]), t0);
        model.apply(Event::Transport(Transport::Fetch), t0);
        model.apply(
            Event::Bytes {
                moved: 8_050,
                total: Some(10_000),
            },
            t0 + Duration::from_millis(500),
        );
        assert_eq!(model.view.rate_bytes_per_second, None, "under a second");
        // 8.15 KB of retained prefix lands inside the window; the attempt has
        // transferred nothing the dependency reports yet, so the window must
        // not read the prefix as a 603 MB/s-class jump.
        model.apply(
            Event::Bytes {
                moved: 9_500,
                total: Some(10_000),
            },
            t0 + Duration::from_secs(2),
        );
        assert_eq!(model.view.rate_bytes_per_second, Some(0));
        // The completion reports exact attempt bytes; the rate follows them,
        // never the carrier total that includes the prefix. The window runs
        // from the Transport event's seeded sample at t0, so 1450 bytes over
        // 2 s reads as 725.
        model.apply(
            Event::Transferred { bytes: 1_450 },
            t0 + Duration::from_secs(2),
        );
        assert_eq!(model.view.rate_bytes_per_second, Some(725));
        assert_eq!(model.view.moved_bytes, 9_500);
    }

    #[test]
    fn completion_summary_includes_publication_time_and_stays_fixed() {
        let mut model = Model::new(journal::Kind::Receive);
        let start = model.started;
        model.apply(planned(&[12_000_000_000]), start);
        model.apply(Event::Transport(Transport::Fetch), start);
        model.apply(
            Event::Bytes {
                moved: 6_000_000_000,
                total: Some(12_000_000_000),
            },
            start + Duration::from_secs(5),
        );
        model.apply(
            Event::Bytes {
                moved: 12_000_000_000,
                total: Some(12_000_000_000),
            },
            start + Duration::from_secs(10),
        );
        assert_eq!(model.view.eta_seconds, None);
        assert_eq!(model.view.finished_unix_seconds, None);
        let finishing = model.snapshot();
        assert!(finishing.finishing);
        assert!(finishing.status.starts_with("Verifying and finishing"));
        model.apply(
            Event::Transferred {
                bytes: 12_000_000_000,
            },
            start + Duration::from_secs(60),
        );
        model.apply(
            Event::Finished { files: 1 },
            start + Duration::from_secs(60),
        );
        let done = model.snapshot();
        assert_eq!(
            done.status,
            "Landed and verified, 1 file, 12.0 GB, 1 min 0 s"
        );
        assert!(done.finished_unix_seconds.is_some());
        model.end(None, false);
        assert_eq!(model.snapshot().status, done.status);
        assert_eq!(model.view.finished_unix_seconds, done.finished_unix_seconds);
    }

    #[test]
    fn completion_summary_omits_attempt_average() {
        let mut model = Model::new(journal::Kind::Receive);
        let start = model.started;
        model.apply(planned(&[12_000_000_000]), start);
        model.apply(Event::Transport(Transport::Fetch), start);
        model.apply(
            Event::Bytes {
                moved: 12_000_000_000,
                total: Some(12_000_000_000),
            },
            start + Duration::from_secs(10),
        );
        model.apply(Event::Transferred { bytes: 600_000_000 }, start);
        model.apply(
            Event::Finished { files: 1 },
            start + Duration::from_secs(60),
        );
        assert_eq!(
            model.snapshot().status,
            "Landed and verified, 1 file, 12.0 GB, 1 min 0 s"
        );
        assert!(!model.snapshot().finishing);
    }

    #[test]
    fn status_says_what_a_card_shows_in_every_phase() {
        let t0 = Instant::now();
        let mut model = Model::new(journal::Kind::Send);
        assert_eq!(model.snapshot().status, "Checking the files");
        model.apply(planned(&[10_000]), t0);
        model.apply(Event::Transport(Transport::Push), t0);
        let view = model.snapshot();
        assert_eq!(view.status, "Shipping 1 file, 0 bytes of 10.0 KB");
        assert_eq!(view.route.as_deref(), Some("Direct route (QUIC)"));
        assert_eq!(view.files[0].label, "10.0 KB");
        model.view.rate_bytes_per_second = Some(1_000);
        model.view.eta_seconds = Some(200);
        let view = model.snapshot();
        assert_eq!(
            view.status,
            "Shipping 1 file, 0 bytes of 10.0 KB, 1.0 KB/s, about 3 min 20 s left"
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
        model.end(None, false);
        let view = model.snapshot();
        assert!(view
            .status
            .starts_with("Shipped and verified, 1 file, 10.0 KB, "));
        assert_eq!(view.rate_text, None);
        assert_eq!(view.files[0].label, "landed");

        let mut model = Model::new(journal::Kind::Receive);
        assert_eq!(model.snapshot().status, "Getting ready");
        model.apply(planned(&[1, 2]), t0);
        model.apply(Event::Transport(Transport::Http), t0);
        let view = model.snapshot();
        assert!(view.status.starts_with("Receiving, "), "{}", view.status);
        assert_eq!(view.route.as_deref(), Some("Standard route (HTTP)"));
        model.end(None, false);
        assert!(model
            .snapshot()
            .status
            .starts_with("Landed and verified, 2 files, 3 bytes, "));
        model.end(Some(&Error::Cancelled), false);
        assert_eq!(model.snapshot().status, "Cancelled");
        model.end(Some(&Error::Cancelled), true);
        let view = model.snapshot();
        assert_eq!(view.phase, Phase::Paused);
        assert_eq!(view.status, "Paused, 0 bytes of 3 bytes");
        model.end(Some(&Error::PasswordRequired), false);
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
    fn exported_inspect_bounds_stalled_request_and_delivery_previews() {
        use std::io::{self, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;

        for (path, kind) in [("r", LinkKind::Request), ("s", LinkKind::Delivery)] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let (accepted_tx, accepted_rx) = mpsc::channel();
            let server = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(8);
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            accepted_tx.send(()).unwrap();
                            // Outlast the preview timeout, then release the
                            // stream so the owned server thread can join.
                            std::thread::sleep(Duration::from_secs(6));
                            let mut stream = stream;
                            let _ = stream.write_all(
                                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                            drop(stream);
                            if let Ok((mut retry_stream, _)) = listener.accept() {
                                accepted_tx.send(()).unwrap();
                                let _ = retry_stream.write_all(
                                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                );
                            }
                            return true;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return false;
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("preview listener failed: {error}"),
                    }
                }
            });
            let link = format!("{base}/{path}/{}", "ab".repeat(16));
            let started = Instant::now();
            let preview = inspect(link, Some(kind));
            let elapsed = started.elapsed();
            assert!(server.join().unwrap(), "inspect did not reach the listener");
            assert_eq!(accepted_rx.try_iter().count(), 1, "preview was retried");
            assert_eq!(preview.kind, Some(kind), "{preview:?}");
            assert!(!preview.usable, "{preview:?}");
            assert!(
                elapsed < crate::api::PREVIEW_TIMEOUT + Duration::from_millis(500),
                "stalled {kind:?} preview took {elapsed:?}"
            );
        }
    }

    /// A connect refusal is exactly the first-attempt failure audit 476
    /// named: the preview makes its one attempt and answers at once instead
    /// of riding the 90 s transfer retry budget.
    #[test]
    fn inspect_makes_one_attempt_against_a_refusing_server() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let link = format!("{base}/r/{}", "ab".repeat(16));
        let started = Instant::now();
        let preview = inspect(link, Some(LinkKind::Request));
        let elapsed = started.elapsed();
        assert!(
            elapsed < crate::api::PREVIEW_TIMEOUT,
            "refused preview took {elapsed:?}"
        );
        assert!(!preview.usable, "{preview:?}");
        assert!(preview.problem.is_some(), "{preview:?}");
    }

    #[test]
    fn a_paused_transfer_keeps_its_journal_entry_and_a_cancelled_one_does_not() {
        let state = tempfile::tempdir().unwrap();
        // The journal is process-wide; scope it to this temporary directory
        // so the test is isolated on every supported platform.
        let _state_scope = crate::identity::test_state_dir(state.path());
        let entry = journal::record(
            journal::Kind::Send,
            "https://d/r/t",
            vec!["/drops/a".to_owned()],
            None,
            false,
        );
        let transfer = Transfer::new();
        transfer.pause();
        assert!(transfer.is_cancelled() && transfer.is_paused());
        transfer.settle(&entry, Some(&Error::Cancelled));
        assert!(transfer.journal_kept());
        assert!(journal::get(&entry.id).is_ok(), "kept for Resume");

        let plain = Transfer::new();
        plain.cancel();
        plain.settle(&entry, Some(&Error::Cancelled));
        assert!(!plain.journal_kept());
        assert!(journal::get(&entry.id).is_err(), "a plain cancel forgets");
    }

    #[test]
    fn end_maps_the_outcome_to_a_phase_with_the_headline_and_detail() {
        let mut model = Model::new(journal::Kind::Send);
        model.end(Some(&Error::Cancelled), false);
        assert_eq!(model.view.phase, Phase::Cancelled);
        assert_eq!((model.view.headline, model.view.detail), (None, None));
        let mut model = Model::new(journal::Kind::Send);
        model.end(Some(&Error::PasswordRequired), false);
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

    /// A drop that could not be parked says so on its card: the last view
    /// is sent again with the reason as its detail line.
    #[test]
    fn a_park_problem_reaches_the_card_as_its_detail() {
        let count = Arc::new(Count(std::sync::Mutex::new(Vec::new())));
        let remember = LastView::wrap(count.clone());
        remember.note(&Error::Other("ignored before any view".into()));
        assert!(count.0.lock().unwrap().is_empty());
        let mut done = Model::new(journal::Kind::Send).view;
        done.phase = Phase::Done;
        remember.update(done);
        remember.note(&Error::Other("it changed while it was sending".into()));
        let views = count.0.lock().unwrap();
        assert_eq!(views.len(), 2);
        assert_eq!(views[1].phase, Phase::Done);
        assert!(views[1]
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("it changed while it was sending")));
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
        forward.event(Event::Chunk {
            index: 0,
            covered: 10,
            total: 10,
        });
        assert!(count.0.lock().unwrap().last().unwrap().finishing);
        assert!(!forward.cancelled());
        transfer.cancel();
        assert!(forward.cancelled());
        forward.finish(Some(&Error::Cancelled));
        let seen = count.0.lock().unwrap();
        // Planned, Transport, finishing, and cancel always cross; the two
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

#[cfg(test)]
mod large_sequence_benchmark {
    use super::*;
    use crate::progress::PlannedFile;

    #[test]
    #[ignore = "benchmark; run explicitly with --release --nocapture"]
    fn native_progress_100k() {
        for run in 1..=3 {
            let mut model = Model::new(journal::Kind::Receive);
            let now = Instant::now();
            model.apply(
                Event::Planned {
                    files: (0..100_000)
                        .map(|index| PlannedFile {
                            index,
                            path: format!("sequence/frame-{index:06}.exr"),
                            bytes: 1024,
                        })
                        .collect(),
                },
                now,
            );
            model.apply(Event::Transport(Transport::Http), now);
            assert_eq!(model.snapshot().files.len(), 100_000);
            let mut expected = vec![0_u64; 100_000];
            let start = Instant::now();
            for update in 0..20_000 {
                let index = update * 7919 % 100_000;
                model.apply(
                    Event::Downloading {
                        index,
                        received: 512,
                        total: 1024,
                    },
                    now + Duration::from_millis(update as u64),
                );
                expected[index] = 512;
            }
            let events_ms = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(model.view.moved_bytes, expected.iter().sum::<u64>());
            let _ = std::hint::black_box(model.snapshot());
            let start = Instant::now();
            let mut snapshot_rows = 0;
            for (update, expected_moved) in expected.iter_mut().enumerate().take(100) {
                model.apply(
                    Event::Downloading {
                        index: update,
                        received: 768,
                        total: 1024,
                    },
                    now + Duration::from_millis(20_000 + update as u64),
                );
                *expected_moved = 768;
                let snapshot = std::hint::black_box(model.snapshot());
                snapshot_rows += snapshot.files.len();
            }
            let snapshots_ms = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(model.view.moved_bytes, expected.iter().sum::<u64>());
            println!("run={run} files=100000 events=20000 events_ms={events_ms:.3} snapshots=100 snapshots_ms={snapshots_ms:.3} snapshot_rows={snapshot_rows}");
        }
    }
}

#[uniffi::export]
pub fn automation_tokens() -> std::result::Result<Vec<port::AutomationToken>, port::PortError> {
    port::automation_tokens().map_err(port::PortError::from)
}

#[uniffi::export]
pub fn create_automation_token(
    spec: port::AutomationTokenSpec,
) -> std::result::Result<port::IssuedAutomationToken, port::PortError> {
    port::create_automation_token(spec).map_err(port::PortError::from)
}

#[uniffi::export]
pub fn revoke_automation_token(id: String) -> std::result::Result<(), port::PortError> {
    port::revoke_automation_token(&id).map_err(port::PortError::from)
}

#[uniffi::export]
pub fn automation_mcp_config(command: String, base: String, token: String) -> String {
    serde_json::to_string_pretty(&serde_json::json!({"mcpServers": {"votport": {"command": command, "args": ["mcp"], "env": {"VOTPORT_URL": base, "VOTPORT_AUTOMATION_TOKEN": token}}}})).unwrap()
}
