//! End-to-end HTTP receive against a real votport server.
//!
//! Without `VOTPORT_BIN` the test returns early, so it is inert where no server
//! binary exists and real where the client CI job builds one.

mod common;

use std::path::PathBuf;

use votport_client_core::progress::{Event, Silent};
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

#[test]
fn an_interrupted_download_resumes_from_the_partial() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the HTTP resume e2e");
        return;
    };
    let server = common::start_server(&bin, &[]);

    // A multi-group file, and a partial already on disk from a prior
    // interrupted attempt. The prefix is deliberately not group-aligned, so the
    // resume exercises a byte-exact range append, not only a group boundary.
    const PREFIX: usize = 5 * 1024 * 1024 + 12345;
    let movie: Vec<u8> = (0..8u32 * 1024 * 1024).map(|index| index as u8).collect();
    let files: Vec<(&str, Vec<u8>)> = vec![("movie.bin", movie.clone())];
    let token = common::deliver(&server.base, &files, None);

    let dest = tempfile::tempdir().unwrap();
    // The temporary a receive resumes is a hidden `.vot-<name>.journal`.
    std::fs::write(dest.path().join(".vot-movie.bin.journal"), &movie[..PREFIX]).unwrap();

    // Record progress so the test can prove the download resumed rather than
    // restarting from zero.
    let mut received_marks: Vec<u64> = Vec::new();
    {
        let mut observer = |event: Event| {
            if let Event::Downloading { received, .. } = event {
                received_marks.push(received);
            }
        };
        receive_over_http(
            &server.base,
            Delivery {
                token,
                password: None,
            },
            dest.path(),
            &mut observer,
        )
        .expect("the interrupted download resumes and completes");
    }

    let landed = std::fs::read(dest.path().join("movie.bin")).unwrap();
    assert_eq!(landed, movie, "the resumed file is byte-identical");

    // The first progress mark is past the prefix, so the download continued
    // from the partial; a full re-download would report the first chunk near
    // zero, well under the prefix.
    let first = *received_marks.first().expect("a Downloading event");
    assert!(
        first > PREFIX as u64,
        "resumed from {PREFIX}, but the first mark was {first}"
    );
}
