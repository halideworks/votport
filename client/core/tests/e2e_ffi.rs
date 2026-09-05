//! End-to-end over the UniFFI surface: the same functions a shell calls, with
//! a Rust listener standing in for the shell's, against a real votport.
//!
//! Without `VOTPORT_BIN` the test returns early. The send loads this
//! machine's device key from the real state directory, as the CLI does.

mod common;

use std::sync::{Arc, Mutex};

use votport_client_core::ffi::{self, FileState, Phase, Transfer, TransferListener, TransferView};
use votport_client_core::{Error, LinkKind, Transport};

/// Records every view the core hands over, as a shell would draw them.
#[derive(Default)]
struct Recorder(Mutex<Vec<TransferView>>);

impl TransferListener for Recorder {
    fn update(&self, view: TransferView) {
        self.0.lock().unwrap().push(view);
    }
}

/// Cancels its transfer as soon as it starts moving bytes, then keeps
/// recording.
struct CancelOnTransferring {
    transfer: Arc<Transfer>,
    views: Mutex<Vec<TransferView>>,
}

impl TransferListener for CancelOnTransferring {
    fn update(&self, view: TransferView) {
        if view.phase == Phase::Transferring && !self.transfer.is_cancelled() {
            self.transfer.cancel();
        }
        self.views.lock().unwrap().push(view);
    }
}

#[test]
fn a_shell_sends_a_folder_and_receives_a_delivery_through_the_view_model() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the FFI e2e");
        return;
    };
    let server = common::start_server(&bin, &[]);

    // A pasted link is previewed before anything moves: what it is, whether
    // it needs a password, and what it accepts.
    let token = common::create_link(&server.base);
    let preview = ffi::inspect(format!("{}/r/{token}", server.base));
    assert_eq!(
        (preview.kind, preview.problem.as_deref()),
        (Some(LinkKind::Request), None)
    );
    assert_eq!(preview.label.as_deref(), Some("e2e"));
    assert!(preview.usable && !preview.needs_password, "{preview:?}");
    assert_eq!(preview.quic, Some(false));
    assert_eq!(preview.max_bytes, Some(1u64 << 32));
    assert!(preview.max_entries.is_some_and(|n| n > 0) && preview.files.is_empty());
    // The other kind of link is refused by name, not sent to.
    let wrong = ffi::send(
        format!("{}/s/{token}", server.base),
        None,
        vec![],
        Transfer::new(),
        Arc::new(Recorder::default()),
    );
    assert!(
        matches!(
            wrong,
            Err(Error::WrongLink {
                kind: LinkKind::Delivery,
                ..
            })
        ),
        "{wrong:?}"
    );

    // Send: a folder dropped as a path keeps its name as the top component.
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
        Transfer::new(),
        sent.clone(),
    )
    .expect("the folder sends");
    assert_eq!(report.files, 2);
    let landed = common::find_file(&server.received, "big.bin").expect("big.bin landed");
    assert_eq!(std::fs::read(landed).unwrap(), big);
    let views = sent.0.lock().unwrap();
    let first = &views[0];
    assert_eq!(first.phase, Phase::Preparing, "{first:?}");
    assert_eq!(first.total_bytes, Some(big.len() as u64 + 16));
    let plate = first
        .files
        .iter()
        .find(|file| file.path == "plates/big.bin")
        .expect("the folder's file under the folder's name");
    assert_eq!(
        (plate.bytes, plate.state),
        (big.len() as u64, FileState::Waiting)
    );
    // Loopback moves the drop inside one update interval, so byte-carrying
    // views are not guaranteed to cross; the phases and the transport are.
    assert!(
        views
            .iter()
            .any(|view| view.phase == Phase::Transferring
                && view.transport == Some(report.transport)),
        "the Transferring phase names the transport: {views:?}"
    );
    assert!(
        views
            .windows(2)
            .all(|pair| pair[0].moved_bytes <= pair[1].moved_bytes),
        "moved bytes never go backwards: {views:?}"
    );
    let last = views.last().unwrap();
    assert_eq!(last.phase, Phase::Done, "{last:?}");
    assert_eq!(last.moved_bytes, last.total_bytes.unwrap());
    assert!(last
        .files
        .iter()
        .all(|file| file.state == FileState::Landed));
    assert_eq!((last.rate_bytes_per_second, last.eta_seconds), (None, None));
    drop(views);

    // A closed request link previews as closed, with the sentence under the
    // field and the primary action disabled.
    common::close_link(&server.base, &token);
    let closed = ffi::inspect(format!("{}/r/{token}", server.base));
    assert_eq!(
        (closed.kind, closed.usable, closed.problem.as_deref()),
        (Some(LinkKind::Request), false, Some("This link is closed."))
    );

    // A delivery previews its files and total; a password delivery previews
    // only that it needs one, and an unknown one is closed.
    let token = common::deliver(
        &server.base,
        &[("gated.txt", b"x".to_vec())],
        Some("pw"),
        None,
    );
    let gated = ffi::inspect(format!("{}/s/{token}", server.base));
    assert_eq!(
        (gated.kind, gated.problem.as_deref()),
        (Some(LinkKind::Delivery), None)
    );
    assert!(gated.needs_password && gated.files.is_empty(), "{gated:?}");
    assert_eq!(
        (gated.total_bytes, gated.quic, gated.label.as_deref()),
        (None, None, None)
    );
    let unknown = ffi::inspect(format!("{}/s/not-a-token", server.base));
    assert_eq!(
        unknown.problem.as_deref(),
        Some("This link is closed or has expired.")
    );
    assert!(
        unknown.detail.as_deref().is_some_and(|d| d.contains("404")),
        "{unknown:?}"
    );
    assert!(!unknown.usable);
    let nonsense = ffi::inspect("not a link".into());
    assert_eq!(
        (nonsense.kind, nonsense.problem.as_deref()),
        (None, Some("That is not a votport link."))
    );

    // Receive: the delivery is planned, downloaded, verified, and done.
    let note = b"delivered beside the plate".to_vec();
    let token = common::deliver(&server.base, &[("note.txt", note.clone())], None, None);
    let open = ffi::inspect(format!("{}/s/{token}", server.base));
    assert!(!open.needs_password && open.problem.is_none(), "{open:?}");
    // This server binds no serve listener, so the delivery offers no QUIC.
    assert_eq!(open.quic, Some(false), "{open:?}");
    assert_eq!(open.label.as_deref(), Some("e2e delivery"));
    assert_eq!(open.total_bytes, Some(note.len() as u64));
    assert_eq!(
        (open.files[0].path.as_str(), open.files[0].bytes),
        ("note.txt", note.len() as u64)
    );
    let dest = tempfile::tempdir().unwrap();
    let got = Arc::new(Recorder::default());
    let report = ffi::receive(
        format!("{}/s/{token}", server.base),
        None,
        dest.path().display().to_string(),
        Transfer::new(),
        got.clone(),
    )
    .expect("the delivery lands");
    assert_eq!(report.files.len(), 1);
    assert_eq!(std::fs::read(&report.files[0]).unwrap(), note);
    let views = got.0.lock().unwrap();
    assert_eq!(views[0].phase, Phase::Preparing);
    assert_eq!(views[0].files[0].path, "note.txt");
    assert_eq!(views[0].files[0].bytes, note.len() as u64);
    let last = views.last().unwrap();
    assert_eq!(last.phase, Phase::Done, "{last:?}");
    assert!(
        matches!(last.transport, Some(Transport::Http | Transport::Fetch)),
        "{last:?}"
    );
    assert_eq!(last.files[0].state, FileState::Verified);
    drop(views);

    // The errors a screen branches on arrive as their variant, and as the
    // Failed phase with a headline for the person and the detail behind it.
    let again = Arc::new(Recorder::default());
    let refused = ffi::receive(
        format!("{}/s/{token}", server.base),
        None,
        dest.path().display().to_string(),
        Transfer::new(),
        again.clone(),
    );
    assert!(matches!(refused, Err(Error::Exists { .. })), "{refused:?}");
    let last = again.0.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last.phase, Phase::Failed);
    assert_eq!(
        last.headline.as_deref(),
        Some("\"note.txt\" is already in that folder. Choose an empty one.")
    );
    assert!(
        last.detail
            .as_deref()
            .is_some_and(|m| m.contains("already exists")),
        "{last:?}"
    );
    let bad = ffi::send(
        "not a link".into(),
        None,
        vec![],
        Transfer::new(),
        Arc::new(Recorder::default()),
    );
    assert!(matches!(bad, Err(Error::BadLink { .. })), "{bad:?}");
}

#[test]
fn a_cancel_before_the_download_lands_nothing_and_a_partial_resumes_next_time() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the FFI cancel e2e");
        return;
    };
    // The server serves QUIC fetches only when VOTPORT_SERVE_BIND is set, so
    // this receive takes the HTTP path, whose cancel is per read; the fetch
    // path honours a cancel only before its ticket is minted.
    let server = common::start_server(&bin, &[]);
    let big: Vec<u8> = (0..24u32 * 1024 * 1024)
        .map(|index| (index / 7) as u8)
        .collect();
    let token = common::deliver(&server.base, &[("plate.bin", big.clone())], None, None);
    let dest = tempfile::tempdir().unwrap();
    let link = format!("{}/s/{token}", server.base);

    let transfer = Transfer::new();
    let listener = Arc::new(CancelOnTransferring {
        transfer: transfer.clone(),
        views: Mutex::new(Vec::new()),
    });
    let stopped = ffi::receive(
        link.clone(),
        None,
        dest.path().display().to_string(),
        transfer,
        listener.clone(),
    );
    assert!(matches!(stopped, Err(Error::Cancelled)), "{stopped:?}");
    let views = listener.views.lock().unwrap();
    let last = views.last().unwrap();
    assert_eq!(last.phase, Phase::Cancelled, "{last:?}");
    assert_eq!(last.moved_bytes, 0, "the cancel came before the first read");
    drop(views);
    assert!(!dest.path().join("plate.bin").exists(), "nothing landed");

    // A partial is resumed, not discarded: 5 MiB of wrong bytes in the
    // journal make the resumed file fail verification, which a fresh
    // download would not, and the poisoned partial is removed.
    let partial = dest.path().join(".vot-plate.bin.journal");
    std::fs::write(&partial, vec![0xffu8; 5 * 1024 * 1024]).unwrap();
    let poisoned = ffi::receive(
        link.clone(),
        None,
        dest.path().display().to_string(),
        Transfer::new(),
        Arc::new(Recorder::default()),
    );
    assert!(
        matches!(poisoned, Err(Error::Verify { .. })),
        "{poisoned:?}"
    );
    assert!(!partial.exists(), "a partial that hashes wrong is removed");

    // A partial from an interrupted run (the first 5 MiB, as a dropped
    // connection leaves it) is resumed by the next run and lands whole.
    std::fs::write(&partial, &big[..5 * 1024 * 1024]).unwrap();
    let resumed = Arc::new(Recorder::default());
    let report = ffi::receive(
        link,
        None,
        dest.path().display().to_string(),
        Transfer::new(),
        resumed.clone(),
    )
    .expect("the resumed receive lands");
    assert_eq!(std::fs::read(&report.files[0]).unwrap(), big);
    assert!(!partial.exists(), "the partial became the file");
    let last = resumed.0.lock().unwrap().last().cloned().unwrap();
    assert_eq!(last.phase, Phase::Done);
    assert_eq!(last.files[0].state, FileState::Verified);
}
