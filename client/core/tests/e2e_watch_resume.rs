//! End-to-end for resuming a watch-shaped send: the journalled send a cut
//! watch ship leaves behind delivers on `resume`, and the drop is parked
//! into the folder's `shipped` subfolder, so the next watch run does not
//! ship what the resume delivered.
//!
//! Local runs may skip without `VOTPORT_BIN`; CI requires it. The state
//! directory is pointed at a temporary directory through `XDG_DATA_HOME`;
//! Linux only.

#![cfg(target_os = "linux")]

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use votport_client_core::ffi::{self, Transfer, TransferListener, TransferView};
use votport_client_core::journal;
use votport_client_core::watch;

#[derive(Default)]
struct Recorder(Mutex<Vec<TransferView>>);

impl TransferListener for Recorder {
    fn update(&self, view: TransferView) {
        self.0.lock().unwrap().push(view);
    }
}

#[test]
fn resuming_a_watch_send_parks_its_drop_but_a_plain_send_stays() {
    let Some(bin) = common::server_binary() else {
        return;
    };
    let state = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_DATA_HOME", state.path());
    let server = common::start_server(&bin, &[]);
    let token = common::create_link(&server.base);
    let link = format!("{}/r/{token}", server.base);
    let folder = tempfile::tempdir().unwrap();

    // The folder is watched, as the ship that journalled this send implies;
    // the drop path is spelled the way the watcher hands it over, under the
    // watch's own dir.
    let added = ffi::add_watch(
        folder.path().to_string_lossy().into_owned(),
        link.clone(),
        None,
    )
    .unwrap();
    let watched = Path::new(&added.dir).join("reel");
    std::fs::create_dir(&watched).unwrap();
    std::fs::write(watched.join("plate.bin"), vec![7u8; 50_000]).unwrap();

    // The entry a failed watch ship leaves: one drop path, kept for a retry.
    let entry = journal::record(
        journal::Kind::Send,
        &link,
        vec![watched.to_string_lossy().into_owned()],
        None,
        false,
    );
    let resumed = ffi::resume(
        entry.id.clone(),
        None,
        None,
        Transfer::new(),
        Arc::new(Recorder::default()),
    )
    .expect("the watch send resumes");
    let ffi::ResumeReport::Sent(report) = resumed else {
        panic!("a send journal resumed as a receive");
    };
    assert_eq!(report.files, 1);

    // Parked like `ship` parks, so the next watch run finds nothing to
    // ship again.
    assert!(!watched.exists(), "the delivered drop stayed in the folder");
    assert!(folder
        .path()
        .join(watch::SHIPPED)
        .join("reel/plate.bin")
        .is_file());
    let received =
        common::find_file(&server.received, "plate.bin").expect("received on the server");
    assert_eq!(std::fs::read(received).unwrap(), vec![7u8; 50_000]);
    assert!(ffi::pending().is_empty(), "nothing left in the journal");

    // A send that does not start in a watched folder is not parked.
    let plain_dir = tempfile::tempdir().unwrap();
    let plain = plain_dir.path().join("note.txt");
    std::fs::write(&plain, b"a plain send").unwrap();
    let plain_entry = journal::record(
        journal::Kind::Send,
        &link,
        vec![plain.to_string_lossy().into_owned()],
        None,
        false,
    );
    ffi::resume(
        plain_entry.id,
        None,
        None,
        Transfer::new(),
        Arc::new(Recorder::default()),
    )
    .expect("the plain send resumes");
    assert!(
        plain.exists(),
        "a plain send's source must stay where it is"
    );
    assert!(ffi::pending().is_empty());
}
