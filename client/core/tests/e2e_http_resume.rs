//! End-to-end coverage for a journalled HTTP send pause and same-session resume.
//!
//! The test uses the real UniFFI surface and a private server fixture. Without
//! `VOTPORT_BIN` it is inert, like the other client e2e binaries.

#![cfg(target_os = "linux")]

mod common;

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use votport_client_core::ffi::{self, Phase, Transfer, TransferListener, TransferView};
use votport_client_core::journal;
use votport_client_core::{api, Error, LinkKind};

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn isolate_state() -> tempfile::TempDir {
    let state = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_DATA_HOME", state.path());
    state
}

#[derive(Default)]
struct Recorder(Mutex<Vec<TransferView>>);

impl TransferListener for Recorder {
    fn update(&self, view: TransferView) {
        self.0.lock().unwrap().push(view);
    }
}

struct MoveJournal {
    journal: PathBuf,
    moved: PathBuf,
    moved_once: AtomicBool,
}

impl TransferListener for MoveJournal {
    fn update(&self, view: TransferView) {
        if view.phase == Phase::Preparing && !self.moved_once.swap(true, Ordering::AcqRel) {
            std::fs::rename(&self.journal, &self.moved).unwrap();
        }
    }
}

struct HoldFirstResume {
    started: Sender<()>,
    release_transfer: Mutex<Receiver<()>>,
    transfer_held: AtomicBool,
    settled: Sender<()>,
    release_settlement: Mutex<Receiver<()>>,
    settlement_held: AtomicBool,
}

impl TransferListener for HoldFirstResume {
    fn update(&self, view: TransferView) {
        if view.phase == Phase::Transferring && !self.transfer_held.swap(true, Ordering::AcqRel) {
            self.started.send(()).unwrap();
            self.release_transfer
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .expect("concurrent-resume test did not release transfer");
        }
        if view.phase == Phase::Paused && !self.settlement_held.swap(true, Ordering::AcqRel) {
            self.settled.send(()).unwrap();
            self.release_settlement
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .expect("concurrent-resume test did not release settlement");
        }
    }
}

struct PauseAfterProgress {
    transfer: Arc<Transfer>,
    paused: AtomicBool,
}

impl TransferListener for PauseAfterProgress {
    fn update(&self, view: TransferView) {
        if view.phase == Phase::Transferring && view.moved_bytes == 0 {
            // Keep the regular progress ticker from finishing the tiny
            // fixture before it delivers a positive sample to this listener.
            std::thread::sleep(Duration::from_millis(150));
        }
        if view.phase == Phase::Transferring
            && view.moved_bytes > 0
            && !self.paused.swap(true, Ordering::AcqRel)
        {
            self.transfer.pause();
        }
    }
}

struct PausedHttp {
    _state: tempfile::TempDir,
    server: common::Server,
    _source: tempfile::TempDir,
    path: std::path::PathBuf,
    token: String,
    journal_id: String,
    http: journal::HttpResume,
}

fn pause_http_send(bin: &str) -> PausedHttp {
    let state = isolate_state();
    let server = common::start_server(bin, &[]);
    let token = common::create_link(&server.base);
    let source = tempfile::tempdir().unwrap();
    const BYTES: u64 = 16 * 1024 * 1024;
    let path = source.path().join("pause.bin");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(BYTES)
        .unwrap();

    let transfer = Transfer::new();
    let listener = Arc::new(PauseAfterProgress {
        transfer: transfer.clone(),
        paused: AtomicBool::new(false),
    });
    let result = ffi::send(
        format!("{}/r/{token}", server.base),
        None,
        vec![path.display().to_string()],
        transfer.clone(),
        listener.clone(),
    );
    assert!(matches!(result, Err(Error::Cancelled)), "{result:?}");
    assert!(listener.paused.load(Ordering::Acquire));

    let journal_id = transfer.journal_id().expect("the send journal id");
    let entry = journal::get(&journal_id).expect("pause keeps the journal");
    let http = entry.http.expect("pause records the HTTP session");
    assert_eq!(entry.kind, journal::Kind::Send);
    assert_eq!(http.length, BYTES);

    PausedHttp {
        _state: state,
        server,
        _source: source,
        path,
        token,
        journal_id,
        http,
    }
}

#[test]
fn a_paused_http_send_resumes_the_same_session_prefix() {
    let _test_lock = TEST_LOCK.lock().unwrap();
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the HTTP pause/resume e2e");
        return;
    };
    let paused = pause_http_send(&bin);
    let server = &paused.server;
    let path = &paused.path;
    let journal_id = &paused.journal_id;
    let http = &paused.http;
    let client = api::Client::new(&server.base).unwrap();
    let entries = client
        .begin(&http.session)
        .expect("the paused session remains live");
    assert_eq!(entries.len(), 1);
    assert!(entries[0].covered_bytes > 0, "the pause retained a prefix");
    let retained = entries[0].covered_bytes;

    let resumed_handle = Transfer::new();
    let resumed_listener = Arc::new(Recorder::default());
    let resumed = ffi::resume(
        journal_id.clone(),
        None,
        resumed_handle,
        resumed_listener.clone(),
    )
    .expect("the paused send resumes");
    let ffi::ResumeReport::Sent(report) = resumed else {
        panic!("a send journal resumed as a receive");
    };
    assert_eq!(report.transport, votport_client_core::Transport::Http);
    assert!(
        client.begin(&http.session).is_err(),
        "the original session was completed rather than replaced"
    );
    assert_eq!(std::fs::metadata(path).unwrap().len(), http.length);
    assert_eq!(
        std::fs::metadata(common::find_file(&server.received, "pause.bin").unwrap())
            .unwrap()
            .len(),
        http.length
    );
    assert!(
        journal::get(journal_id).is_err(),
        "a finished resume clears the journal"
    );

    let first_resume_mark = resumed_listener
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|view| view.phase == Phase::Transferring && view.moved_bytes > 0)
        .map(|view| view.moved_bytes)
        .next()
        .expect("the resumed send reports bytes");
    assert!(
        first_resume_mark >= retained,
        "resume did not start at the retained prefix"
    );

    // The request link was the ordinary HTTP path, so a QUIC route cannot hide
    // a fresh session allocation in this regression.
    assert_eq!(
        ffi::inspect(
            format!("{}/r/{}", server.base, paused.token),
            Some(LinkKind::Request)
        )
        .quic,
        Some(false)
    );
}

#[test]
fn forgetting_a_paused_http_send_aborts_its_owned_session() {
    let _test_lock = TEST_LOCK.lock().unwrap();
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the HTTP forget e2e");
        return;
    };
    let paused = pause_http_send(&bin);
    let client = api::Client::new(&paused.server.base).unwrap();
    assert!(client.begin(&paused.http.session).is_ok());

    ffi::forget(paused.journal_id.clone());
    assert!(journal::get(&paused.journal_id).is_err());
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && client.begin(&paused.http.session).is_ok() {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        client.begin(&paused.http.session).is_err(),
        "forget left the retained session live"
    );
}

#[test]
fn watch_ship_replacement_aborts_the_old_http_session() {
    let _test_lock = TEST_LOCK.lock().unwrap();
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the watch replacement e2e");
        return;
    };
    let paused = pause_http_send(&bin);
    let old_session = paused.http.session.clone();
    let client = api::Client::new(&paused.server.base).unwrap();
    let watch = ffi::add_watch(
        paused._source.path().display().to_string(),
        format!("{}/r/{}", paused.server.base, paused.token),
        None,
    )
    .unwrap();

    let result = ffi::ship(
        watch.id.clone(),
        paused.path.display().to_string(),
        Transfer::new(),
        Arc::new(Recorder::default()),
    )
    .expect("the watch replacement ships");
    assert_eq!((result.files, result.parked), (1, true));
    assert!(journal::get(&paused.journal_id).is_err());
    assert!(paused._source.path().join("shipped/pause.bin").is_file());
    assert!(client.begin(&old_session).is_err());
    ffi::remove_watch(watch.id).unwrap();
}

#[test]
fn a_concurrent_resume_cannot_take_ownership_from_the_first_run() {
    let _test_lock = TEST_LOCK.lock().unwrap();
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the concurrent resume e2e");
        return;
    };
    let paused = pause_http_send(&bin);
    let old_session = paused.http.session.clone();
    let client = api::Client::new(&paused.server.base).unwrap();
    let (started_tx, started) = mpsc::channel();
    let (release_transfer, transfer_rx) = mpsc::channel();
    let (settled_tx, settled) = mpsc::channel();
    let (release_settlement, settlement_rx) = mpsc::channel();
    let listener = Arc::new(HoldFirstResume {
        started: started_tx,
        release_transfer: Mutex::new(transfer_rx),
        transfer_held: AtomicBool::new(false),
        settled: settled_tx,
        release_settlement: Mutex::new(settlement_rx),
        settlement_held: AtomicBool::new(false),
    });
    let first_handle = Transfer::new();
    let first_id = paused.journal_id.clone();
    let first = std::thread::spawn({
        let listener = listener.clone();
        let first_handle = first_handle.clone();
        move || ffi::resume(first_id, None, first_handle, listener)
    });
    started
        .recv_timeout(Duration::from_secs(10))
        .expect("first resume did not acquire its flight");

    let duplicate_handle = Transfer::new();
    let duplicate = ffi::send(
        format!("{}/r/{}", paused.server.base, paused.token),
        None,
        vec![paused.path.display().to_string()],
        duplicate_handle.clone(),
        Arc::new(Recorder::default()),
    );
    assert!(matches!(duplicate, Err(Error::AlreadyShipping { .. })));
    assert!(journal::get(&duplicate_handle.journal_id().unwrap()).is_err());

    let refused_handle = Transfer::new();
    let refused = ffi::resume(
        paused.journal_id.clone(),
        None,
        refused_handle.clone(),
        Arc::new(Recorder::default()),
    );
    assert!(matches!(refused, Err(Error::AlreadyShipping { .. })));
    assert_eq!(refused_handle.journal_id(), None);
    assert!(!refused_handle.journal_kept());
    assert_eq!(
        journal::get(&paused.journal_id).unwrap().http,
        Some(paused.http.clone())
    );
    assert!(client.begin(&old_session).is_ok());

    first_handle.pause();
    release_transfer.send(()).unwrap();
    settled
        .recv_timeout(Duration::from_secs(10))
        .expect("first resume did not settle");
    assert_eq!(
        journal::get(&paused.journal_id).unwrap().http,
        Some(paused.http.clone())
    );
    let refused_during_settlement = ffi::resume(
        paused.journal_id.clone(),
        None,
        Transfer::new(),
        Arc::new(Recorder::default()),
    );
    assert!(matches!(
        refused_during_settlement,
        Err(Error::AlreadyShipping { .. })
    ));
    assert!(client.begin(&old_session).is_ok());

    release_settlement.send(()).unwrap();
    assert!(matches!(first.join().unwrap(), Err(Error::Cancelled)));
    assert_eq!(
        journal::get(&paused.journal_id).unwrap().http,
        Some(paused.http.clone())
    );

    let resumed = ffi::resume(
        paused.journal_id.clone(),
        None,
        Transfer::new(),
        Arc::new(Recorder::default()),
    )
    .expect("the next owner can resume after the first run releases");
    assert!(matches!(resumed, ffi::ResumeReport::Sent(_)));
    assert!(journal::get(&paused.journal_id).is_err());
}

fn rewrite_saved_http(id: &str, update: impl FnOnce(&mut serde_json::Value)) {
    let path = journal::dir().join(format!("{id}.json"));
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    update(value.get_mut("http").unwrap());
    std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

#[test]
fn paused_http_resume_clears_invalid_expired_and_changed_sessions() {
    let _test_lock = TEST_LOCK.lock().unwrap();
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the HTTP resume lifecycle e2e");
        return;
    };

    {
        let paused = pause_http_send(&bin);
        let old_session = paused.http.session.clone();
        rewrite_saved_http(&paused.journal_id, |http| {
            http["session"] = serde_json::json!("unsafe");
        });
        assert!(matches!(
            ffi::resume(
                paused.journal_id.clone(),
                None,
                Transfer::new(),
                Arc::new(Recorder::default()),
            ),
            Err(Error::ResumeSessionInvalid)
        ));
        assert!(journal::get(&paused.journal_id).unwrap().http.is_none());
        assert!(api::Client::new(&paused.server.base)
            .unwrap()
            .begin(&old_session)
            .is_ok());
    }

    {
        let paused = pause_http_send(&bin);
        let client = api::Client::new(&paused.server.base).unwrap();
        rewrite_saved_http(&paused.journal_id, |http| {
            http["chunk_bytes"] = serde_json::json!(0);
        });
        assert!(matches!(
            ffi::resume(
                paused.journal_id.clone(),
                None,
                Transfer::new(),
                Arc::new(Recorder::default()),
            ),
            Err(Error::ResumeSessionInvalid)
        ));
        assert!(journal::get(&paused.journal_id).unwrap().http.is_none());
        assert!(client.begin(&paused.http.session).is_err());
    }

    {
        let paused = pause_http_send(&bin);
        let client = api::Client::new(&paused.server.base).unwrap();
        client.abort(&paused.http.session);
        assert!(matches!(
            ffi::resume(
                paused.journal_id.clone(),
                None,
                Transfer::new(),
                Arc::new(Recorder::default()),
            ),
            Err(Error::ResumeSessionExpired)
        ));
        assert!(journal::get(&paused.journal_id).unwrap().http.is_none());
    }

    {
        let paused = pause_http_send(&bin);
        let client = api::Client::new(&paused.server.base).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&paused.path)
            .unwrap()
            .write_all(&[1])
            .unwrap();
        assert!(matches!(
            ffi::resume(
                paused.journal_id.clone(),
                None,
                Transfer::new(),
                Arc::new(Recorder::default()),
            ),
            Err(Error::ResumeSourceChanged)
        ));
        assert!(journal::get(&paused.journal_id).unwrap().http.is_none());
        assert!(client.begin(&paused.http.session).is_err());
    }

    {
        let paused = pause_http_send(&bin);
        let client = api::Client::new(&paused.server.base).unwrap();
        let transfer = Transfer::new();
        transfer.cancel();
        assert!(matches!(
            ffi::resume(
                paused.journal_id.clone(),
                None,
                transfer,
                Arc::new(Recorder::default()),
            ),
            Err(Error::Cancelled)
        ));
        assert!(journal::get(&paused.journal_id).is_err());
        assert!(client.begin(&paused.http.session).is_err());
    }
}

#[test]
fn a_clear_failure_is_reported_and_retains_the_saved_session() {
    let _test_lock = TEST_LOCK.lock().unwrap();
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the clear failure e2e");
        return;
    };
    let paused = pause_http_send(&bin);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&paused.path)
        .unwrap()
        .write_all(&[1])
        .unwrap();

    let journal = journal::dir();
    let moved = journal.with_extension("held");
    let listener = Arc::new(MoveJournal {
        journal: journal.clone(),
        moved: moved.clone(),
        moved_once: AtomicBool::new(false),
    });
    let transfer = Transfer::new();
    let result = ffi::resume(
        paused.journal_id.clone(),
        None,
        transfer.clone(),
        listener.clone(),
    );
    let error = result.expect_err("a changed source must fail");
    assert!(
        matches!(error, Error::Other(ref message) if message.contains("could not clear the saved session for a fresh retry")),
        "{error:?}"
    );
    assert!(listener.moved_once.load(Ordering::Acquire));
    assert!(transfer.journal_kept());

    std::fs::rename(&moved, &journal).unwrap();
    let restored = journal::get(&paused.journal_id).unwrap();
    assert_eq!(restored.http, Some(paused.http));
}
