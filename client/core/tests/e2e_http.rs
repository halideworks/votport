//! End-to-end HTTP send against a real votport server.
//!
//! Without `VOTPORT_BIN` the test returns early, so it is inert where no server
//! binary exists and real where the client CI job builds one.

mod common;

use std::io::Read;
use std::path::PathBuf;

use votport_client_core::progress::Silent;
use votport_client_core::{send_over_http, Drop, Selected};

#[test]
fn a_drop_sends_over_http_and_lands_in_the_receive_directory() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the HTTP e2e");
        return;
    };
    let server = common::start_server(&bin, &[]);
    let token = common::create_link(&server.base);

    // A drop that exercises every path: an object larger than one 8 MiB chunk
    // (proved from kept leaves, sent as several 64 KiB-aligned chunks), a
    // small one (proved from bytes), an empty one (published at begin with no
    // chunk), a byte-identical twin of the small one (deduped to one object),
    // and a nested folder.
    let source = tempfile::tempdir().unwrap();
    let big: Vec<u8> = (0..20u32 * 1024 * 1024).map(|index| index as u8).collect();
    let note = b"a small note beside the plate".to_vec();
    let clip = vec![9u8; 1000];
    std::fs::write(source.path().join("big.bin"), &big).unwrap();
    std::fs::write(source.path().join("note.txt"), &note).unwrap();
    std::fs::write(source.path().join("twin.txt"), &note).unwrap();
    std::fs::write(source.path().join("empty.bin"), b"").unwrap();
    std::fs::create_dir(source.path().join("clips")).unwrap();
    std::fs::write(source.path().join("clips").join("a.mov"), &clip).unwrap();

    let files: Vec<(&str, PathBuf, Vec<u8>)> = vec![
        ("big.bin", source.path().join("big.bin"), big.clone()),
        ("note.txt", source.path().join("note.txt"), note.clone()),
        ("twin.txt", source.path().join("twin.txt"), note.clone()),
        ("empty.bin", source.path().join("empty.bin"), Vec::new()),
        (
            "clips/a.mov",
            source.path().join("clips").join("a.mov"),
            clip.clone(),
        ),
    ];
    let drop = Drop {
        token,
        password: None,
        files: files
            .iter()
            .map(|(relative, disk, _)| Selected {
                relative: (*relative).to_owned(),
                source: disk.clone(),
            })
            .collect(),
    };

    let report = send_over_http(&server.base, drop, &mut Silent).expect("the drop sends");
    assert_eq!(report.files.len(), files.len(), "every file published");

    for (relative, _, expected) in &files {
        let name = relative.rsplit('/').next().unwrap();
        let landed = common::find_file(&server.received, name)
            .unwrap_or_else(|| panic!("{relative} was not received"));
        let mut received_bytes = Vec::new();
        std::fs::File::open(&landed)
            .unwrap()
            .read_to_end(&mut received_bytes)
            .unwrap();
        assert_eq!(&received_bytes, expected, "{relative} bytes differ");
    }
}
