//! End-to-end push send against a real votport server with push enabled.
//!
//! Push receive is Unix-only. Local runs may skip without `VOTPORT_BIN`; CI
//! requires it. The server is started with a push listener and a loopback
//! advertise address; it generates its own push certificate.

#![cfg(unix)]

mod common;

use std::io::Read;

use votport_client_core::progress::Silent;
use votport_client_core::{send, Device, Drop, Selected, Sent};

#[test]
fn a_drop_pushes_over_quic_and_lands_in_the_receive_directory() {
    let Some(bin) = common::server_binary() else {
        return;
    };
    let push_port = common::free_port();
    let server = common::start_server(
        &bin,
        &[
            ("VOTPORT_PUSH_BIND", format!("127.0.0.1:{push_port}")),
            // A hostname advertise, so the client exercises DNS resolution (the
            // real deployment shape). localhost resolves to 127.0.0.1, which
            // the server binds; where it also maps to ::1, the probe tries that
            // first, finds nothing, and moves on (costing its 2 s budget).
            ("VOTPORT_PUSH_ADVERTISE", format!("localhost:{push_port}")),
        ],
    );
    let token = common::create_link(&server.base);

    let source = tempfile::tempdir().unwrap();
    let big: Vec<u8> = (0..20u32 * 1024 * 1024).map(|index| index as u8).collect();
    let note = b"a note pushed over quic".to_vec();
    std::fs::write(source.path().join("big.bin"), &big).unwrap();
    std::fs::write(source.path().join("note.txt"), &note).unwrap();
    std::fs::create_dir(source.path().join("clips")).unwrap();
    std::fs::write(source.path().join("clips").join("a.mov"), &note).unwrap();

    let files = [
        ("big.bin", source.path().join("big.bin"), big.clone()),
        ("note.txt", source.path().join("note.txt"), note.clone()),
        (
            "clips/a.mov",
            source.path().join("clips").join("a.mov"),
            note.clone(),
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

    // A device key kept in a temp state dir, so the real home is untouched.
    let state = tempfile::tempdir().unwrap();
    let device = Device::load_or_create_in(state.path()).expect("a device key");

    let sent = send(&server.base, drop, &device, &mut Silent).expect("the drop sends");
    match sent {
        Sent::Push { files: pushed } => assert_eq!(pushed, files.len(), "every file pushed"),
        Sent::Http(_) => {
            panic!("the drop fell back to HTTP; the probe should have reached loopback")
        }
    }

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
fn cancellation_after_preflight_and_during_push_leaves_a_resumable_transfer() {
    use votport_client_core::progress::{Event, Observer, Transport};
    struct Cancel {
        during_transfer: bool,
        session: Option<String>,
        stopped: bool,
        transports: Vec<Transport>,
    }
    impl Observer for Cancel {
        fn event(&mut self, event: Event) {
            match event {
                Event::SessionCreated { session } => {
                    self.session = Some(session);
                    self.stopped = !self.during_transfer;
                }
                Event::Bytes { moved, .. } if moved > 0 => self.stopped = true,
                Event::Transport(transport) => self.transports.push(transport),
                Event::Finished { .. } => panic!("a cancelled push reported completion"),
                _ => {}
            }
        }
        fn cancelled(&self) -> bool {
            self.stopped
        }
    }
    let Some(bin) = common::server_binary() else {
        return;
    };
    let push_port = common::free_port();
    let server = common::start_server(
        &bin,
        &[
            ("VOTPORT_PUSH_BIND", format!("127.0.0.1:{push_port}")),
            ("VOTPORT_PUSH_ADVERTISE", format!("127.0.0.1:{push_port}")),
        ],
    );
    let token = common::create_link(&server.base);
    let source = tempfile::tempdir().unwrap();
    let path = source.path().join("cancel.bin");
    std::fs::write(&path, vec![37; 20 * 1024 * 1024]).unwrap();
    let state = tempfile::tempdir().unwrap();
    let device = Device::load_or_create_in(state.path()).unwrap();
    for during_transfer in [false, true] {
        let mut observer = Cancel {
            during_transfer,
            session: None,
            stopped: false,
            transports: Vec::new(),
        };
        let result = send(
            &server.base,
            Drop {
                token: token.clone(),
                password: None,
                files: vec![Selected {
                    relative: "cancel.bin".into(),
                    source: path.clone(),
                }],
            },
            &device,
            &mut observer,
        );
        assert!(
            matches!(result, Err(votport_client_core::Error::Cancelled)),
            "expected cancellation, got {:?}",
            result.err()
        );
        assert!(observer.stopped);
        assert_eq!(observer.transports, [Transport::Push]);
        assert!(observer.session.is_some());
    }
    let sent = send(
        &server.base,
        Drop {
            token,
            password: None,
            files: vec![Selected {
                relative: "cancel.bin".into(),
                source: path,
            }],
        },
        &device,
        &mut Silent,
    )
    .expect("resume after cancellation");
    assert!(matches!(sent, Sent::Push { files: 1 }));
    let landed = common::find_file(&server.received, "cancel.bin").unwrap();
    assert_eq!(std::fs::read(landed).unwrap(), vec![37; 20 * 1024 * 1024]);
}
