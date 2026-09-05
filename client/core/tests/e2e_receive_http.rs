//! End-to-end HTTP receive against a real votport server.
//!
//! Without `VOTPORT_BIN` the test returns early, so it is inert where no server
//! binary exists and real where the client CI job builds one.

mod common;

use std::path::PathBuf;

use votport_client_core::progress::Silent;
use votport_client_core::{receive_over_http, Delivery, Error};

#[test]
fn a_delivery_is_received_and_verified_into_a_local_directory() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the HTTP receive e2e");
        return;
    };
    let server = common::start_server(&bin, &[]);

    // A file larger than one download read (proved over many groups), a small
    // one, a nested one (its parent directory is created under the
    // destination), and an empty one.
    let big: Vec<u8> = (0..20u32 * 1024 * 1024).map(|index| index as u8).collect();
    let note = b"delivered beside the plate".to_vec();
    let clip = vec![5u8; 4096];
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("big.bin", big.clone()),
        ("note.txt", note.clone()),
        ("clips/a.mov", clip.clone()),
        ("empty.bin", Vec::new()),
    ];

    let token = common::deliver(&server.base, &files, None);
    let dest = tempfile::tempdir().unwrap();
    let delivery = Delivery {
        token: token.clone(),
        password: None,
    };
    let received =
        receive_over_http(&server.base, delivery, dest.path(), &mut Silent).expect("received");
    assert_eq!(received.files.len(), files.len(), "every file landed");

    for (name, expected) in &files {
        let path: PathBuf = dest.path().join(name);
        let bytes = std::fs::read(&path).unwrap_or_else(|_| panic!("{name} was not received"));
        assert_eq!(&bytes, expected, "{name} bytes differ");
    }

    // Receiving the same delivery into the same directory refuses rather than
    // overwriting the files already there.
    let again = receive_over_http(
        &server.base,
        Delivery {
            token,
            password: None,
        },
        dest.path(),
        &mut Silent,
    );
    assert!(
        matches!(again, Err(Error::Exists { .. })),
        "a second receive into the same directory is refused, got {again:?}"
    );
}

#[test]
fn a_password_delivery_needs_the_password() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the HTTP receive password e2e");
        return;
    };
    let server = common::start_server(&bin, &[]);

    let note = b"for authorized eyes".to_vec();
    let files: Vec<(&str, Vec<u8>)> = vec![("secret.txt", note.clone())];
    let token = common::deliver(&server.base, &files, Some("open-sesame"));

    // Without the password the receive stops before any byte is written.
    let dest = tempfile::tempdir().unwrap();
    let refused = receive_over_http(
        &server.base,
        Delivery {
            token: token.clone(),
            password: None,
        },
        dest.path(),
        &mut Silent,
    );
    assert!(
        matches!(refused, Err(Error::PasswordRequired)),
        "a password delivery is refused without the password, got {refused:?}"
    );

    // With it, the file lands and verifies.
    let dest = tempfile::tempdir().unwrap();
    let received = receive_over_http(
        &server.base,
        Delivery {
            token,
            password: Some("open-sesame".to_owned()),
        },
        dest.path(),
        &mut Silent,
    )
    .expect("received with the password");
    assert_eq!(received.files.len(), 1);
    assert_eq!(
        std::fs::read(dest.path().join("secret.txt")).unwrap(),
        note,
        "the delivered bytes match"
    );
}
