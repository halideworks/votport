//! End-to-end QUIC fetch against a real votport server with a serve listener.
//!
//! The server serves fetches only when `VOTPORT_SERVE_BIND` is set; it
//! generates its own certificate, the twin of the push one. Local runs may skip
//! without `VOTPORT_BIN`; CI requires it. Unix-only, matching the push e2e.

#![cfg(unix)]

mod common;

use std::time::{Duration, Instant};

use votport_client_core::progress::{Event, Observer, Silent};
use votport_client_core::{receive, receive_over_fetch, Delivery, Device, Error};

struct CancelAfterFirstFile {
    saw_first: bool,
    cancel: bool,
    deadline: Instant,
}

struct Deadline(Instant);

impl Observer for Deadline {
    fn event(&mut self, _: Event) {}

    fn cancelled(&self) -> bool {
        Instant::now() >= self.0
    }
}

impl Observer for CancelAfterFirstFile {
    fn event(&mut self, event: Event) {
        if matches!(event, Event::FileVerified { index: 0, .. }) {
            self.saw_first = true;
            self.cancel = true;
        }
    }

    fn cancelled(&self) -> bool {
        self.cancel || Instant::now() >= self.deadline
    }
}

#[test]
fn a_delivery_is_fetched_over_quic_and_materialized() {
    let Some(bin) = common::server_binary() else {
        return;
    };
    let serve_port = common::free_port();
    let server = common::start_server(
        &bin,
        &[
            ("VOTPORT_SERVE_BIND", format!("127.0.0.1:{serve_port}")),
            // A hostname advertise, so the client resolves it (the real shape).
            ("VOTPORT_SERVE_ADVERTISE", format!("localhost:{serve_port}")),
        ],
    );

    // A file larger than one object group, a small one, a nested one, and an
    // empty one, so materialize exercises multi-group, one-group, subdirs, and
    // the empty object.
    let big: Vec<u8> = (0..20u32 * 1024 * 1024).map(|index| index as u8).collect();
    let note = b"fetched over quic".to_vec();
    let clip = vec![3u8; 4096];
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("big.bin", big.clone()),
        ("note.txt", note.clone()),
        ("clips/a.mov", clip.clone()),
        ("empty.bin", Vec::new()),
    ];

    let token = common::deliver(&server.base, &files, None, None);
    let state = tempfile::tempdir().unwrap();
    let device = Device::load_or_create_in(state.path()).expect("a device key");
    // The destination sits under a controlled parent, so the assertion below can
    // check that the fetch stage staged beside it was cleaned up.
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("out");

    let received = receive_over_fetch(
        &server.base,
        Delivery {
            token: token.clone(),
            password: None,
        },
        &device,
        &dest,
        &mut Silent,
    )
    .expect("the delivery fetches over quic");
    assert_eq!(received.files.len(), files.len(), "every file materialized");

    for (name, expected) in &files {
        let path = dest.join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|_| panic!("{name} was not fetched"));
        assert_eq!(&bytes, expected, "{name} bytes differ");
    }

    // The fetch stages the bundle beside the destination and removes it once the
    // files are materialized. The lock file remains as harmless coordination state.
    let leftover = std::fs::read_dir(home.path())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .find(|entry| {
            let path = entry.path();
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".vot-fetch-"))
                && path.extension().and_then(|ext| ext.to_str()) != Some("lock")
        });
    assert!(
        leftover.is_none(),
        "the fetch stage was cleaned up, found {leftover:?}"
    );

    // A second fetch into the same directory is refused before a ticket is
    // minted, so a refused receive does not burn the delivery's download cap.
    let again = receive_over_fetch(
        &server.base,
        Delivery {
            token,
            password: None,
        },
        &device,
        &dest,
        &mut Silent,
    );
    assert!(
        matches!(again, Err(Error::Exists { .. })),
        "a second fetch into the same directory is refused, got {again:?}"
    );
}

#[test]
fn a_refused_fetch_does_not_burn_a_download_ticket() {
    let Some(bin) = common::server_binary() else {
        return;
    };
    let serve_port = common::free_port();
    let server = common::start_server(
        &bin,
        &[
            ("VOTPORT_SERVE_BIND", format!("127.0.0.1:{serve_port}")),
            ("VOTPORT_SERVE_ADVERTISE", format!("localhost:{serve_port}")),
        ],
    );

    // One deliverable, and a delivery that serves exactly one download.
    let note = b"one shot".to_vec();
    let files: Vec<(&str, Vec<u8>)> = vec![("once.bin", note.clone())];
    let token = common::deliver(&server.base, &files, None, Some(1));

    let state = tempfile::tempdir().unwrap();
    let device = Device::load_or_create_in(state.path()).expect("a device key");

    // A destination that already holds the file. The fetch must refuse here
    // before minting, so the single download ticket is not spent.
    let occupied = tempfile::tempdir().unwrap();
    std::fs::write(occupied.path().join("once.bin"), b"in the way").unwrap();
    let refused = receive_over_fetch(
        &server.base,
        Delivery {
            token: token.clone(),
            password: None,
        },
        &device,
        occupied.path(),
        &mut Silent,
    );
    assert!(
        matches!(refused, Err(Error::Exists { .. })),
        "the fetch is refused before minting, got {refused:?}"
    );

    // The ticket was not spent, so a fetch into a fresh directory still works.
    let fresh = tempfile::tempdir().unwrap();
    let received = receive_over_fetch(
        &server.base,
        Delivery {
            token,
            password: None,
        },
        &device,
        fresh.path(),
        &mut Silent,
    )
    .expect("the one remaining download is still available");
    assert_eq!(received.files.len(), 1);
    assert_eq!(std::fs::read(fresh.path().join("once.bin")).unwrap(), note);
}

#[test]
fn an_admitted_fetch_retries_with_its_original_capability_after_cancellation() {
    let Some(bin) = common::server_binary() else {
        return;
    };
    let serve_port = common::free_port();
    let server = common::start_server(
        &bin,
        &[
            ("VOTPORT_SERVE_BIND", format!("127.0.0.1:{serve_port}")),
            ("VOTPORT_SERVE_ADVERTISE", format!("localhost:{serve_port}")),
        ],
    );

    let first = b"first file".to_vec();
    let second = vec![7u8; 4 * 1024 * 1024];
    let token = common::deliver(
        &server.base,
        &[("first.bin", first.clone()), ("second.bin", second.clone())],
        None,
        Some(1),
    );
    let state = tempfile::tempdir().unwrap();
    let device = Device::load_or_create_in(state.path()).expect("a device key");
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("out");

    let mut interrupted = CancelAfterFirstFile {
        saw_first: false,
        cancel: false,
        deadline: Instant::now() + Duration::from_secs(10),
    };
    let first_result = receive(
        &server.base,
        Delivery {
            token: token.clone(),
            password: None,
        },
        &device,
        &dest,
        &mut interrupted,
    );
    assert!(
        interrupted.saw_first,
        "the first file published before cancellation"
    );
    assert!(first_result.is_err(), "the first fetch must be interrupted");
    assert_eq!(std::fs::read(dest.join("first.bin")).unwrap(), first);

    // An old sidecar expiry must not veto the still-valid server capability.
    let capability = std::fs::read_dir(home.path())
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("capability"));
    if let Some(capability) = capability {
        let mut sidecar: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&capability).unwrap()).unwrap();
        sidecar["expires_at"] = serde_json::json!(0);
        std::fs::write(&capability, serde_json::to_vec(&sidecar).unwrap()).unwrap();
    }

    if !dest.join("second.bin").exists() {
        // The retry can only succeed by reusing the capability that owns the
        // admitted ticket: minting a new one is refused by max_downloads=1.
        let received = receive(
            &server.base,
            Delivery {
                token,
                password: None,
            },
            &device,
            &dest,
            &mut Deadline(Instant::now() + Duration::from_secs(10)),
        )
        .expect("an admitted fetch resumes after interruption");
        assert_eq!(
            received.files,
            vec![dest.join("first.bin"), dest.join("second.bin")]
        );
    }
    assert_eq!(std::fs::read(dest.join("first.bin")).unwrap(), first);
    assert_eq!(std::fs::read(dest.join("second.bin")).unwrap(), second);
}

#[test]
fn an_admitted_manifest_cancellation_retries_over_quic_with_its_original_capability() {
    let Some(bin) = common::server_binary() else {
        return;
    };
    let serve_port = common::free_port();
    let server = common::start_server(
        &bin,
        &[
            ("VOTPORT_SERVE_BIND", format!("127.0.0.1:{serve_port}")),
            ("VOTPORT_SERVE_ADVERTISE", format!("localhost:{serve_port}")),
        ],
    );

    use base64::Engine as _;
    use sha2::Digest as _;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    let first = b"first file".to_vec();
    let second = b"second file".to_vec();
    let token = common::deliver(
        &server.base,
        &[("first.bin", first.clone()), ("second.bin", second.clone())],
        None,
        Some(1),
    );
    let state = tempfile::tempdir().unwrap();
    let device = Device::load_or_create_in(state.path()).expect("a device key");
    let home = tempfile::tempdir().unwrap();
    let dest = home.path().join("out");

    let client = votport_client_core::api::Client::new(&server.base).unwrap();
    let metadata = client
        .outbound_metadata_for_device(&token, None, Some(&device))
        .unwrap();
    let mint = client
        .mint_fetch(&token, &device.holder_key_hex(), None)
        .unwrap();
    let capability = base64::engine::general_purpose::STANDARD
        .decode(&mint.capability)
        .unwrap();
    let stage = home.path().join(format!(
        ".vot-fetch-{}.bundle",
        hex::encode(sha2::Sha256::digest(
            format!("{}\0{}", server.base, token).as_bytes()
        ))
    ));
    let sidecar = serde_json::json!({
        "origin": server.base, "token": token, "grant_id": metadata.grant_id,
        "delivery_manifest": metadata.delivery_manifest, "package_root": mint.package_root,
        "holder": device.holder_key_hex(), "capability": capability,
    });
    std::fs::write(
        stage.with_extension("capability"),
        serde_json::to_vec(&sidecar).unwrap(),
    )
    .unwrap();
    let cancellation = vot_cli::CancellationHandle::default();
    let manifest_seen = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&manifest_seen);
    let stop_at_manifest = cancellation.clone();
    let seams = vot_cli::ReceiveSeams {
        manifest: Some(Arc::new(move |_, _, _| {
            seen.store(true, Ordering::Release);
            stop_at_manifest.cancel();
            Ok(())
        })),
        cancellation: cancellation.clone(),
        ..Default::default()
    };
    let options = vot_cli::FetchOptions {
        address: format!("127.0.0.1:{serve_port}").parse().unwrap(),
        holder: Some(Arc::new(
            vot_cli::authz::Holder::new(capability, device.signing_key()).unwrap(),
        )),
        serve_identity: Some(
            hex::decode(mint.certificate_digest)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        pin: Some(hex::decode(mint.package_root).unwrap().try_into().unwrap()),
        rails: 1,
        provers: None,
        extensions: Default::default(),
        progress: None,
    };
    let (done, finished) = std::sync::mpsc::channel();
    let interrupted = std::thread::scope(|scope| {
        scope.spawn(move || {
            if finished.recv_timeout(Duration::from_secs(10)).is_err() {
                cancellation.cancel();
            }
        });
        let result = vot_cli::fetch_bundle_with_seams(options, &stage, seams);
        let _ = done.send(());
        result
    });
    assert!(
        manifest_seen.load(Ordering::Acquire),
        "the server admitted the fetch and sent its manifest"
    );
    assert!(interrupted.is_err(), "{interrupted:?}");
    assert!(stage.join("resume.vot").is_file());
    assert!(!dest.exists());
    for entry in votport_client_core::package::read_manifest(&stage).unwrap() {
        assert!(!stage
            .join("objects")
            .join(format!("{}.obj", hex::encode(entry.object.root)))
            .exists());
    }
    assert!(matches!(
        client.mint_fetch(&token, &device.holder_key_hex(), None),
        Err(Error::Server { status: 409, .. })
    ));

    let received = receive_over_fetch(
        &server.base,
        Delivery {
            token,
            password: None,
        },
        &device,
        &dest,
        &mut Deadline(Instant::now() + Duration::from_secs(10)),
    )
    .expect("an admitted fetch retries over QUIC after early cancellation");
    assert_eq!(received.files.len(), 2);
    assert_eq!(std::fs::read(dest.join("first.bin")).unwrap(), first);
    assert_eq!(std::fs::read(dest.join("second.bin")).unwrap(), second);
}
