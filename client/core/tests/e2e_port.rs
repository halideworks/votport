//! End-to-end for the operator session: sign in to a real votport, issue
//! and close a request link, browse the library, issue a delivery and
//! receive it through the FFI, revoke it, sign out.
//!
//! Without `VOTPORT_BIN` the test returns early. The state directory (the
//! device key, the journal, the stored session) is pointed at a temporary
//! directory through `XDG_DATA_HOME`, so the test never touches this
//! machine's session; the e2e runs on Linux only.

#![cfg(target_os = "linux")]

mod common;

use std::cell::Cell;
use std::sync::{Arc, Mutex};

use votport_client_core::ffi::{self, Transfer, TransferListener, TransferView};
use votport_client_core::port::{
    self, DeliverySpec, PortError, RequestSpec, UploadListener, UploadView,
};
use votport_client_core::Error;

/// The headline and the signed-out flag of a failed operator call.
fn failed<T: std::fmt::Debug>(result: Result<T, PortError>) -> (String, bool) {
    match result {
        Err(PortError::Failed {
            headline,
            signed_out,
            ..
        }) => (headline, signed_out),
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[derive(Default)]
struct Uploads(Mutex<Vec<UploadView>>);

impl UploadListener for Uploads {
    fn update(&self, view: UploadView) {
        self.0.lock().unwrap().push(view);
    }
}

#[derive(Default)]
struct Recorder(Mutex<Vec<TransferView>>);

impl TransferListener for Recorder {
    fn update(&self, view: TransferView) {
        self.0.lock().unwrap().push(view);
    }
}

#[test]
fn an_operator_runs_the_port_from_the_core() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the port e2e");
        return;
    };
    let state = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_DATA_HOME", state.path());
    let server = common::start_server(&bin, &[]);

    // Nobody is signed in: the stored port is empty and every operator call
    // says so without a round trip.
    assert_eq!(ffi::port(), None);
    assert_eq!(
        failed(ffi::requests()),
        ("Sign in to your votport first.".to_owned(), true)
    );

    // A base that is not an origin, and one wrong password (the server
    // throttles by address, so only one).
    assert_eq!(
        failed(ffi::sign_in("drop.example".to_owned(), "x".to_owned())),
        (
            Error::BadLink {
                link: "drop.example".to_owned()
            }
            .headline(),
            false
        )
    );
    assert_eq!(
        failed(ffi::sign_in(
            server.base.clone(),
            "not-the-password".to_owned()
        )),
        ("That password is wrong.".to_owned(), false)
    );

    let port = ffi::sign_in(
        format!("{}/", server.base),
        common::ADMIN_PASSWORD.to_owned(),
    )
    .expect("sign in");
    assert_eq!(port.base, server.base);
    assert_eq!(port.tenant, "");
    assert_eq!(ffi::port(), Some(port.clone()));
    assert_eq!(ffi::check_port().unwrap(), Some(port));
    // The session file never holds the password.
    let stored = std::fs::read_to_string(state.path().join("votport/port.json")).unwrap();
    assert!(stored.contains("votport_admin="), "{stored}");
    assert!(!stored.contains(common::ADMIN_PASSWORD));

    // Request links: none, then one issued with a cap, listed as open with
    // its URL, then closed and gone from the open list.
    assert!(ffi::requests().unwrap().is_empty());
    let issued = ffi::issue_request(RequestSpec {
        label: "Dailies drop".to_owned(),
        password: None,
        expires_days: Some(3),
        max_bytes: Some(1 << 30),
    })
    .unwrap();
    assert_eq!(issued.label, "Dailies drop");
    assert!(
        issued.url.starts_with(&format!("{}/r/", server.base)),
        "{}",
        issued.url
    );
    assert!(issued.usable && issued.active && !issued.has_password);
    assert_eq!(issued.max_bytes, Some(1 << 30));
    assert_eq!((issued.drops, issued.receiving), (0, 0));
    let open = ffi::requests().unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0], issued);
    // The issued link previews as a request a sender can ship to.
    let preview = ffi::inspect(issued.url.clone(), None);
    assert!(preview.usable, "{preview:?}");
    assert_eq!(preview.label.as_deref(), Some("Dailies drop"));
    ffi::close_request(issued.id.clone()).unwrap();
    assert!(ffi::requests().unwrap().is_empty());
    let closed = ffi::inspect(issued.url.clone(), None);
    assert!(!closed.usable, "{closed:?}");
    assert_eq!(
        closed.problem.as_deref(),
        Some("This link is closed."),
        "{closed:?}"
    );

    // A refused spec carries the server's own reason as the headline.
    let refused = ffi::issue_request(RequestSpec {
        label: String::new(),
        password: None,
        expires_days: None,
        max_bytes: None,
    });
    assert_eq!(
        failed(refused),
        ("Label must be 1..=200 characters.".to_owned(), false)
    );

    // The library: a file uploaded through the admin API shows up at the
    // root, and a delivery issued from it carries the one link it ever
    // shows, which the core then receives.
    let _seed = common::deliver(
        &server.base,
        &[("plate.bin", vec![7u8; 100_000])],
        None,
        None,
    );
    let root = ffi::library(String::new()).unwrap();
    assert_eq!(root.directory, "");
    assert_eq!(
        root.files
            .iter()
            .map(|f| (f.path.as_str(), f.bytes, f.size.as_str()))
            .collect::<Vec<_>>(),
        vec![("plate.bin", 100_000, "100 KB")]
    );
    assert!(!root.truncated);
    let before = ffi::deliveries().unwrap().len();
    let delivery = ffi::issue_delivery(DeliverySpec {
        paths: vec!["plate.bin".to_owned()],
        label: "For Alex".to_owned(),
        password: None,
        expires_days: 2,
        max_downloads: Some(5),
    })
    .unwrap();
    assert!(
        delivery.url.starts_with(&format!("{}/s/", server.base)),
        "{}",
        delivery.url
    );
    assert_eq!(delivery.delivery.label.as_deref(), Some("For Alex"));
    assert_eq!(delivery.delivery.max_downloads, Some(5));
    assert_eq!(delivery.delivery.file_count, 1);
    assert_eq!(
        delivery.delivery.summary,
        "1 file, 0 downloads, of 5 allowed"
    );
    assert_eq!(issued.summary, "0 drops");
    assert_eq!(ffi::deliveries().unwrap().len(), before + 1);

    let dest = tempfile::tempdir().unwrap();
    let recorder = Arc::new(Recorder::default());
    let report = ffi::receive(
        delivery.url.clone(),
        None,
        dest.path().to_string_lossy().into_owned(),
        Transfer::new(),
        recorder.clone(),
    )
    .expect("receive the issued delivery");
    assert_eq!(report.files.len(), 1);
    assert_eq!(std::fs::read(&report.files[0]).unwrap(), vec![7u8; 100_000]);
    let last = recorder.0.lock().unwrap().last().cloned().unwrap();
    assert!(last
        .status
        .starts_with("Landed and verified, 1 file, 100 KB, "));

    // Uploading from this machine: a folder with a file over one chunk and an
    // empty file goes up under the named folder, the listener hears the
    // bytes move and the final line, the library lists both, and a delivery
    // of the upload comes back byte for byte. The same upload again is
    // refused as already on the port.
    let local = tempfile::tempdir().unwrap();
    let shots = local.path().join("shots");
    std::fs::create_dir(&shots).unwrap();
    let reel: Vec<u8> = (0..9 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(shots.join("reel.bin"), &reel).unwrap();
    std::fs::write(shots.join("empty.txt"), b"").unwrap();
    let slate = local.path().join("slate.txt");
    std::fs::write(&slate, b"scene 4 take 2").unwrap();
    let uploads = Arc::new(Uploads::default());
    // One call takes the whole drop: a folder and a loose file.
    let made = ffi::upload(
        vec![
            shots.to_string_lossy().into_owned(),
            slate.to_string_lossy().into_owned(),
        ],
        "dailies".to_owned(),
        Transfer::new(),
        uploads.clone(),
    )
    .expect("upload the folder");
    assert_eq!(
        made.iter()
            .map(|f| (f.path.as_str(), f.bytes))
            .collect::<Vec<_>>(),
        vec![
            ("dailies/shots/empty.txt", 0),
            ("dailies/shots/reel.bin", reel.len() as u64),
            ("dailies/slate.txt", 14),
        ]
    );
    let heard = uploads.0.lock().unwrap().clone();
    assert!(heard[..heard.len() - 1]
        .iter()
        .all(|view| view.landed.is_empty()));
    assert!(
        heard.iter().any(|v| v
            .status
            .starts_with("Uploading reel.bin, 8.4 MB of 9.4 MB (2 of 3 files)")),
        "{heard:?}"
    );
    assert_eq!(
        heard.last().unwrap().status,
        "Added 3 files to the port, 9.4 MB"
    );
    assert_eq!(heard.last().unwrap().moved_bytes, reel.len() as u64 + 14);
    assert_eq!(
        heard.last().unwrap().landed,
        vec![
            "dailies/shots/empty.txt",
            "dailies/shots/reel.bin",
            "dailies/slate.txt"
        ]
    );
    let listed = ffi::library("dailies/shots".to_owned()).unwrap();
    assert_eq!(
        listed
            .files
            .iter()
            .map(|f| (f.path.as_str(), f.bytes))
            .collect::<Vec<_>>(),
        vec![
            ("dailies/shots/empty.txt", 0),
            ("dailies/shots/reel.bin", reel.len() as u64)
        ]
    );
    assert_eq!(
        failed(ffi::upload(
            vec![shots.join("reel.bin").to_string_lossy().into_owned()],
            "dailies/shots".to_owned(),
            Transfer::new(),
            uploads.clone(),
        )),
        ("\"reel.bin\" is already on the port.".to_owned(), false)
    );
    let first = local.path().join("first-before-stop.txt");
    std::fs::write(&first, b"first").unwrap();
    for cancelled in [false, true] {
        let heard = Uploads::default();
        let checks = Cell::new(0);
        let folder = if cancelled {
            "cancel-sequence"
        } else {
            "dailies/shots"
        };
        let result = port::upload(
            &[
                first.to_string_lossy().into_owned(),
                shots.join("reel.bin").to_string_lossy().into_owned(),
            ],
            folder,
            &|| {
                let previous = checks.get();
                checks.set(previous + 1);
                cancelled && previous > 0
            },
            &heard,
        );
        assert!(
            matches!(result, Err(Error::Cancelled)) == cancelled,
            "{result:?}"
        );
        assert!(result.is_err());
        let views = heard.0.lock().unwrap();
        assert!(views[..views.len() - 1]
            .iter()
            .all(|view| view.landed.is_empty()));
        assert_eq!(
            views.last().unwrap().landed,
            vec![format!("{folder}/first-before-stop.txt")]
        );
        assert_eq!(views.last().unwrap().files_done, 1);
    }
    let uploaded = ffi::issue_delivery(DeliverySpec {
        paths: vec!["dailies/shots/reel.bin".to_owned()],
        label: "Reel".to_owned(),
        password: None,
        expires_days: 1,
        max_downloads: None,
    })
    .unwrap();
    let landing = tempfile::tempdir().unwrap();
    let report = ffi::receive(
        uploaded.url.clone(),
        None,
        landing.path().to_string_lossy().into_owned(),
        Transfer::new(),
        Arc::new(Recorder::default()),
    )
    .expect("receive the uploaded reel");
    assert_eq!(std::fs::read(&report.files[0]).unwrap(), reel);

    let source = shots.join("reel.bin");
    let original_modified = std::fs::metadata(&source).unwrap().modified().unwrap();
    let stopped = Cell::new(false);
    assert!(matches!(
        port::upload(
            &[source.to_string_lossy().into_owned()],
            "attempts",
            &|| stopped.replace(true),
            &Uploads::default(),
        ),
        Err(Error::Cancelled)
    ));
    let replacement = vec![42; reel.len()];
    std::fs::write(&source, &replacement).unwrap();
    std::fs::File::open(&source)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(original_modified))
        .unwrap();
    let made = port::upload(
        &[source.to_string_lossy().into_owned()],
        "attempts",
        &|| false,
        &Uploads::default(),
    )
    .expect("a changed file starts a fresh upload even when size and timestamp match");
    let issued = ffi::issue_delivery(DeliverySpec {
        paths: made.into_iter().map(|file| file.path).collect(),
        label: "Replacement".to_owned(),
        password: None,
        expires_days: 1,
        max_downloads: None,
    })
    .unwrap();
    let dest = tempfile::tempdir().unwrap();
    let report = ffi::receive(
        issued.url,
        None,
        dest.path().to_string_lossy().into_owned(),
        Transfer::new(),
        Arc::new(Recorder::default()),
    )
    .unwrap();
    assert!(
        std::fs::read(&report.files[0]).unwrap() == replacement,
        "replacement contains bytes from the cancelled upload"
    );

    ffi::revoke_delivery(delivery.delivery.id.clone()).unwrap();
    let revoked = ffi::deliveries()
        .unwrap()
        .into_iter()
        .find(|d| d.id == delivery.delivery.id)
        .expect("the revoked delivery is still listed");
    assert!(revoked.revoked_at.is_some());
    let gone = ffi::inspect(delivery.url, None);
    assert_eq!(
        gone.problem.as_deref(),
        Some("This link is closed or has expired."),
        "{gone:?}"
    );

    // Sign out ends it here and on the server; a stale session file is
    // dropped by the next check.
    ffi::sign_out();
    assert_eq!(ffi::port(), None);
    assert!(failed(ffi::deliveries()).1, "signed out");
    std::fs::write(
        state.path().join("votport/port.json"),
        format!(
            "{{\"base\":\"{}\",\"cookie\":\"votport_admin=stale\",\"tenant\":\"\"}}",
            server.base
        ),
    )
    .unwrap();
    assert!(ffi::port().is_some());
    assert_eq!(ffi::check_port().unwrap(), None);
    assert_eq!(ffi::port(), None);
}
