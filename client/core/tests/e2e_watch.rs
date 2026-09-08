//! End-to-end for a watch folder: a drop placed in a watched folder settles,
//! is handed to the listener, ships to the request link through `ship`,
//! and moves into the folder's `shipped` subfolder; the server holds it.
//!
//! Without `VOTPORT_BIN` the test returns early. The state directory is
//! pointed at a temporary directory through `XDG_DATA_HOME`; Linux only.

#![cfg(target_os = "linux")]

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use votport_client_core::ffi::{self, Phase, ShipReport, Transfer, TransferListener, TransferView};
use votport_client_core::port::PortError;
use votport_client_core::watch::{self, WatchListener};
use votport_client_core::Error;

#[derive(Default)]
struct Recorder(Mutex<Vec<TransferView>>);

impl TransferListener for Recorder {
    fn update(&self, view: TransferView) {
        self.0.lock().unwrap().push(view);
    }
}

/// One shipped drop: its path, the file count or the error, the final view.
type Shipped = (String, Result<ShipReport, Error>, TransferView);

/// Ships every settled drop on the watcher's thread, as the CLI does, and
/// keeps the final view of each.
struct Shipper(Mutex<Vec<Shipped>>);

impl WatchListener for Shipper {
    fn ready(&self, watch_id: String, path: String) {
        let recorder = Arc::new(Recorder::default());
        let result = ffi::ship(watch_id, path.clone(), Transfer::new(), recorder.clone());
        let last = recorder.0.lock().unwrap().last().cloned().unwrap();
        self.0.lock().unwrap().push((path, result, last));
    }
}

#[test]
fn a_watched_folder_ships_what_settles_in_it() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the watch e2e");
        return;
    };
    let state = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_DATA_HOME", state.path());
    let server = common::start_server(&bin, &[]);
    let token = common::create_link(&server.base);
    let link = format!("{}/r/{token}", server.base);
    let folder = tempfile::tempdir().unwrap();

    // Not a folder, not a request link, then a real watch. The refusals
    // carry the core's headline for the settings screen.
    let headline = |result: Result<watch::Watch, PortError>| match result {
        Err(PortError::Failed { headline, .. }) => headline,
        other => panic!("expected a refusal, got {other:?}"),
    };
    assert_eq!(
        headline(ffi::add_watch(
            "/nonexistent/x".to_owned(),
            link.clone(),
            None
        )),
        "\"x\" could not be read."
    );
    assert_eq!(
        headline(ffi::add_watch(
            folder.path().to_string_lossy().into_owned(),
            format!("{}/s/{token}", server.base),
            None
        )),
        Error::WrongLink {
            link: String::new(),
            kind: votport_client_core::LinkKind::Delivery
        }
        .headline()
    );
    let added = ffi::add_watch(
        folder.path().to_string_lossy().into_owned(),
        link.clone(),
        None,
    )
    .unwrap();
    assert_eq!(ffi::watches(), vec![added.clone()]);
    assert!(!added.has_password);
    // The same folder again replaces the watch rather than doubling it.
    let again = ffi::add_watch(
        folder.path().to_string_lossy().into_owned(),
        link.clone(),
        Some("pw".to_owned()),
    )
    .unwrap();
    assert_eq!(ffi::watches().len(), 1);
    assert!(again.has_password);
    ffi::add_watch(folder.path().to_string_lossy().into_owned(), link, None).unwrap();

    let shipper = Arc::new(Shipper(Mutex::new(Vec::new())));
    let watcher = watch::watch_with(
        Duration::from_millis(300),
        Duration::from_millis(100),
        shipper.clone(),
    );
    // A dotfile is ignored; a folder drop ships as one unit once it holds
    // still for the settle window.
    std::fs::write(folder.path().join(".DS_Store"), b"x").unwrap();
    let drop = folder.path().join("reel");
    std::fs::create_dir(&drop).unwrap();
    std::fs::write(drop.join("plate.bin"), vec![3u8; 200_000]).unwrap();
    std::fs::write(drop.join("note.txt"), b"hello").unwrap();

    let deadline = Instant::now() + Duration::from_secs(20);
    while shipper.0.lock().unwrap().is_empty() {
        assert!(Instant::now() < deadline, "the drop never shipped");
        std::thread::sleep(Duration::from_millis(100));
    }
    watcher.stop();
    let shipped = shipper.0.lock().unwrap();
    assert_eq!(shipped.len(), 1, "{shipped:?}");
    let (path, result, last) = &shipped[0];
    assert_eq!(path, &drop.to_string_lossy());
    let report = result.as_ref().unwrap();
    assert_eq!(
        (report.files, report.parked, report.park_problem.as_deref()),
        (2, true, None)
    );
    assert_eq!(last.phase, Phase::Done);
    assert!(last.status.starts_with("Shipped and verified, 2 files, "));
    // Moved into shipped/, and on the server.
    assert!(!drop.exists());
    assert!(folder
        .path()
        .join(watch::SHIPPED)
        .join("reel/plate.bin")
        .is_file());
    let received =
        common::find_file(&server.received, "plate.bin").expect("received on the server");
    assert_eq!(std::fs::read(received).unwrap(), vec![3u8; 200_000]);
    assert!(ffi::pending().is_empty(), "nothing left in the journal");
    assert!(
        folder.path().join(".DS_Store").is_file(),
        "the dotfile stayed"
    );
    assert!(!folder
        .path()
        .join(watch::SHIPPED)
        .join(".DS_Store")
        .exists());

    ffi::remove_watch(shipped_id(&ffi::watches())).unwrap();
    assert!(ffi::watches().is_empty());
}

fn shipped_id(watches: &[watch::Watch]) -> String {
    watches[0].id.clone()
}
