//! End-to-end HTTP send against a real votport server.
//!
//! Local runs may skip without `VOTPORT_BIN`; CI requires the server binary.

mod common;

use std::io::Read;
use std::path::PathBuf;

use votport_client_core::progress::Silent;
use votport_client_core::{send_over_http, Drop, Selected};

#[test]
fn a_drop_sends_over_http_and_lands_in_the_receive_directory() {
    let Some(bin) = common::server_binary() else {
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

    let mut files: Vec<(&str, PathBuf, Vec<u8>)> = vec![
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
    let sequence = (0..16)
        .map(|index| format!("sequence-{index:02}.exr"))
        .collect::<Vec<_>>();
    for (index, name) in sequence.iter().enumerate() {
        let bytes = vec![index as u8; 1024 + index];
        let path = source.path().join(name);
        std::fs::write(&path, &bytes).unwrap();
        files.push((name.as_str(), path, bytes));
    }
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

#[test]
fn server_fixture_is_required_in_ci() {
    const PROBE: &str = "VOTPORT_TEST_SERVER_FIXTURE_PROBE";
    if let Ok(expected) = std::env::var(PROBE) {
        assert_eq!(
            common::server_binary().as_deref(),
            (!expected.is_empty()).then_some(expected.as_str())
        );
        return;
    }
    for (ci, binary, succeeds) in [
        (None, None, true),
        (Some("true"), None, false),
        (Some(""), None, false),
        (Some("true"), Some("fixture-server"), true),
        (None, Some("fixture-server"), true),
    ] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "server_fixture_is_required_in_ci", "--nocapture"])
            .env(PROBE, binary.unwrap_or_default())
            .env_remove("CI")
            .env_remove("VOTPORT_BIN");
        if let Some(ci) = ci {
            child.env("CI", ci);
        }
        if let Some(binary) = binary {
            child.env("VOTPORT_BIN", binary);
        }
        let output = child.output().unwrap();
        assert_eq!(
            output.status.success(),
            succeeds,
            "CI={ci:?}, VOTPORT_BIN={binary:?}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !succeeds {
            assert!(String::from_utf8_lossy(&output.stderr)
                .contains("VOTPORT_BIN must name the integration-test server"));
        }
    }
}
