//! End-to-end QUIC fetch against a real votport server with a serve listener.
//!
//! The server serves fetches only when `VOTPORT_SERVE_BIND` is set; it
//! generates its own certificate, the twin of the push one. Without
//! `VOTPORT_BIN` this returns early. Unix-only, matching the push e2e.

#![cfg(unix)]

mod common;

use votport_client_core::progress::Silent;
use votport_client_core::{receive_over_fetch, Delivery, Device, Error};

#[test]
fn a_delivery_is_fetched_over_quic_and_materialized() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the QUIC fetch e2e");
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
    let dest = tempfile::tempdir().unwrap();

    let received = receive_over_fetch(
        &server.base,
        Delivery {
            token: token.clone(),
            password: None,
        },
        &device,
        dest.path(),
        &mut Silent,
    )
    .expect("the delivery fetches over quic");
    assert_eq!(received.files.len(), files.len(), "every file materialized");

    for (name, expected) in &files {
        let path = dest.path().join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|_| panic!("{name} was not fetched"));
        assert_eq!(&bytes, expected, "{name} bytes differ");
    }

    // A second fetch into the same directory is refused before a ticket is
    // minted, so a refused receive does not burn the delivery's download cap.
    let again = receive_over_fetch(
        &server.base,
        Delivery {
            token,
            password: None,
        },
        &device,
        dest.path(),
        &mut Silent,
    );
    assert!(
        matches!(again, Err(Error::Exists { .. })),
        "a second fetch into the same directory is refused, got {again:?}"
    );
}

#[test]
fn a_refused_fetch_does_not_burn_a_download_ticket() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the fetch ticket-burn e2e");
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
