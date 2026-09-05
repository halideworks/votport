//! End-to-end HTTP send against a real votport server.
//!
//! Spawns the server binary named by `VOTPORT_BIN`, creates a request link
//! through the admin API, and sends a drop with [`send_over_http`]. Without
//! `VOTPORT_BIN` the test returns early, so it is inert in environments that
//! have no server binary and real where the client CI job builds one.

use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use votport_client_core::progress::Silent;
use votport_client_core::{send_over_http, Drop as DropSpec, Selected};

const ADMIN_PASSWORD: &str = "e2e-http-password";

struct Server {
    child: Child,
    base: String,
    received: PathBuf,
    _data: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Absolute path to the repo's `web` directory, which the server needs as its
/// web root even when only the API is exercised.
fn web_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../web")
        .canonicalize()
        .expect("the votport web directory")
}

fn start_server(bin: &str) -> Server {
    let data = tempfile::tempdir().unwrap();
    let received = data.path().join("received");
    let outbound = data.path().join("outbound");
    std::fs::create_dir_all(&received).unwrap();
    std::fs::create_dir_all(&outbound).unwrap();
    let port = free_port();
    let child = Command::new(bin)
        .env("VOTPORT_BIND", format!("127.0.0.1:{port}"))
        .env("VOTPORT_DATA_DIR", data.path().join("data"))
        .env("VOTPORT_RECEIVE_DIR", &received)
        .env("VOTPORT_OUTBOUND_DIR", &outbound)
        .env("VOTPORT_WEB_ROOT", web_root())
        .env("VOTPORT_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .env("VOTPORT_MAX_UPLOAD_BYTES", (1u64 << 32).to_string())
        .spawn()
        .expect("spawn the votport server");

    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::blocking::Client::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if client.get(format!("{base}/healthz")).send().is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "server did not come up");
        std::thread::sleep(Duration::from_millis(100));
    }
    Server {
        child,
        base,
        received,
        _data: data,
    }
}

/// Logs in as admin and creates a request link, returning its token.
fn create_link(base: &str) -> String {
    let admin = reqwest::blocking::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let login = admin
        .post(format!("{base}/api/admin/login"))
        .json(&serde_json::json!({ "password": ADMIN_PASSWORD }))
        .send()
        .unwrap();
    assert!(login.status().is_success(), "admin login failed");

    let created = admin
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&serde_json::json!({ "label": "e2e" }))
        .send()
        .unwrap();
    assert!(created.status().is_success(), "create link failed");
    let body: serde_json::Value = created.json().unwrap();
    body["link"]["id"].as_str().expect("a link id").to_owned()
}

#[test]
fn a_drop_sends_over_http_and_lands_in_the_receive_directory() {
    let Ok(bin) = std::env::var("VOTPORT_BIN") else {
        eprintln!("VOTPORT_BIN unset; skipping the HTTP e2e");
        return;
    };
    let server = start_server(&bin);
    let token = create_link(&server.base);

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
    let drop = DropSpec {
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

    // Every file landed byte for byte somewhere under the receive dir.
    for (relative, _, expected) in &files {
        let name = relative.rsplit('/').next().unwrap();
        let landed = find_file(&server.received, name)
            .unwrap_or_else(|| panic!("{relative} was not received"));
        let mut received_bytes = Vec::new();
        std::fs::File::open(&landed)
            .unwrap()
            .read_to_end(&mut received_bytes)
            .unwrap();
        assert_eq!(&received_bytes, expected, "{relative} bytes differ");
    }
}

/// Finds a file by name anywhere under `root`.
fn find_file(root: &Path, name: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(root).ok()? {
        let path = entry.ok()?.path();
        if path.is_dir() {
            if let Some(found) = find_file(&path, name) {
                return Some(found);
            }
        } else if path.file_name().is_some_and(|file| file == name) {
            return Some(path);
        }
    }
    None
}
