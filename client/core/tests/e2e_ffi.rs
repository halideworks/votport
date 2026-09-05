//! End-to-end over the UniFFI surface: the same functions a shell calls, with
//! a Rust listener standing in for the shell's, against a real votport.
//!
//! Without `VOTPORT_BIN` the test returns early. The send loads this
//! machine's device key from the real state directory, as the CLI does.

mod common;

use std::sync::{Arc, Mutex};

use votport_client_core::ffi::{self, ProgressListener, TransferEvent};
use votport_client_core::Error;

/// Records every event the core reports, as a shell's view model would.
#[derive(Default)]
struct Recorder(Mutex<Vec<TransferEvent>>);

impl ProgressListener for Recorder {
    fn event(&self, event: TransferEvent) {
        self.0.lock().unwrap().push(event);
    }
}

#[test]
fn a_shell_sends_a_folder_and_receives_a_delivery_with_progress() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the FFI e2e");
        return;
    };
    let server = common::start_server(&bin, &[]);

    // Send: a folder dropped as a path keeps its name as the top component.
    let token = common::create_link(&server.base);
    let source = tempfile::tempdir().unwrap();
    let folder = source.path().join("plates");
    std::fs::create_dir(&folder).unwrap();
    let big: Vec<u8> = (0..9u32 * 1024 * 1024).map(|index| index as u8).collect();
    std::fs::write(folder.join("big.bin"), &big).unwrap();
    std::fs::write(folder.join("note.txt"), b"beside the plate").unwrap();

    let sent = Arc::new(Recorder::default());
    let report = ffi::send(
        format!("{}/r/{token}", server.base),
        None,
        vec![folder.display().to_string()],
        sent.clone(),
    )
    .expect("the folder sends");
    assert_eq!(report.files, 2);
    let landed = common::find_file(&server.received, "big.bin").expect("big.bin landed");
    assert_eq!(std::fs::read(landed).unwrap(), big);
    let events = sent.0.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TransferEvent::EntryComplete { path, .. } if path == "plates/big.bin")),
        "the shell saw the folder's file complete under the folder's name: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TransferEvent::Finished { files: 2 })),
        "the shell saw the send finish: {events:?}"
    );
    assert!(
        matches!(events[0], TransferEvent::Planned { .. }),
        "the plan comes first: {events:?}"
    );
    let TransferEvent::Planned { files: planned } = &events[0] else {
        unreachable!()
    };
    assert_eq!(planned.len(), 2);
    let big_planned = planned
        .iter()
        .find(|file| file.path == "plates/big.bin")
        .expect("big.bin in the plan");
    assert_eq!(big_planned.bytes, big.len() as u64);
    drop(events);

    // Receive: the delivery is planned, downloaded, verified, and finished.
    let note = b"delivered beside the plate".to_vec();
    let token = common::deliver(&server.base, &[("note.txt", note.clone())], None, None);
    let dest = tempfile::tempdir().unwrap();
    let got = Arc::new(Recorder::default());
    let report = ffi::receive(
        format!("{}/s/{token}", server.base),
        None,
        dest.path().display().to_string(),
        got.clone(),
    )
    .expect("the delivery lands");
    assert_eq!(report.files.len(), 1);
    assert_eq!(std::fs::read(&report.files[0]).unwrap(), note);
    let events = got.0.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TransferEvent::FileVerified { index: 0, .. })),
        "the shell saw the file verify: {events:?}"
    );
    assert!(
        matches!(&events[0], TransferEvent::Planned { files }
            if files.len() == 1 && files[0].path == "note.txt" && files[0].bytes == note.len() as u64),
        "the plan names and sizes the file: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TransferEvent::Downloading { index: 0, .. })),
        "the shell saw a download tick: {events:?}"
    );
    assert!(
        matches!(events.last(), Some(TransferEvent::Finished { files: 1 })),
        "the receive ends with Finished: {events:?}"
    );
    drop(events);

    // The errors a screen branches on arrive as their variant.
    let again = ffi::receive(
        format!("{}/s/{token}", server.base),
        None,
        dest.path().display().to_string(),
        Arc::new(Recorder::default()),
    );
    assert!(matches!(again, Err(Error::Exists { .. })), "{again:?}");
    let bad = ffi::send(
        "not a link".into(),
        None,
        vec![],
        Arc::new(Recorder::default()),
    );
    assert!(matches!(bad, Err(Error::BadLink { .. })), "{bad:?}");
}
