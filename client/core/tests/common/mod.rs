//! Shared harness for the end-to-end tests: spawn the server binary named by
//! `VOTPORT_BIN`, create a request link or a delivery through the admin API,
//! and find a received file.
//!
//! Each e2e is its own test binary that includes this module, so a helper used
//! by only some of them is dead code in the others; the harness allows that.
#![allow(dead_code)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

pub const ADMIN_PASSWORD: &str = "e2e-password";

/// A running server, killed on drop.
pub struct Server {
    child: Child,
    pub base: String,
    pub received: PathBuf,
    _data: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A free loopback TCP port.
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Absolute path to the repo's `web` directory, the server's web root.
fn web_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../web")
        .canonicalize()
        .expect("the votport web directory")
}

/// Starts the server binary with `extra_env` on top of the base configuration
/// and waits for it to answer `/healthz`.
pub fn start_server(bin: &str, extra_env: &[(&str, String)]) -> Server {
    let data = tempfile::tempdir().unwrap();
    let received = data.path().join("received");
    let outbound = data.path().join("outbound");
    std::fs::create_dir_all(&received).unwrap();
    std::fs::create_dir_all(&outbound).unwrap();
    let port = free_port();
    let mut command = Command::new(bin);
    command
        .env("VOTPORT_BIND", format!("127.0.0.1:{port}"))
        .env("VOTPORT_DATA_DIR", data.path().join("data"))
        .env("VOTPORT_RECEIVE_DIR", &received)
        .env("VOTPORT_OUTBOUND_DIR", &outbound)
        .env("VOTPORT_WEB_ROOT", web_root())
        .env("VOTPORT_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .env("VOTPORT_MAX_UPLOAD_BYTES", (1u64 << 32).to_string());
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let child = command.spawn().expect("spawn the votport server");

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
pub fn create_link(base: &str) -> String {
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

/// Closes the request link `token`, so it no longer accepts drops.
pub fn close_link(base: &str, token: &str) {
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
    let closed = admin
        .patch(format!("{base}/api/admin/links/{token}"))
        .header("X-Votport", "1")
        .json(&serde_json::json!({ "active": false }))
        .send()
        .unwrap();
    assert!(
        closed.status().is_success(),
        "close link failed: {}",
        closed.status()
    );
}

/// Uploads `files` into the outbound library and creates a delivery grant over
/// them, returning the delivery token parsed from its `/s/{token}` url. Each
/// pair is a library-relative path (which may nest) and its bytes. `password`
/// gates the delivery; `max_downloads` caps how many deliveries it serves.
pub fn deliver(
    base: &str,
    files: &[(&str, Vec<u8>)],
    password: Option<&str>,
    max_downloads: Option<u64>,
) -> String {
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

    for (name, bytes) in files {
        let uploaded = admin
            .post(format!("{base}/api/admin/outbound-files"))
            .query(&[("path", name)])
            .header("X-Votport", "1")
            .body(bytes.clone())
            .send()
            .unwrap();
        assert!(
            uploaded.status().is_success(),
            "upload {name} failed: {}",
            uploaded.status()
        );
    }

    let mut body = serde_json::json!({
        "paths": files.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        "label": "e2e delivery",
        "expires_days": 7,
    });
    if let Some(password) = password {
        body["password"] = serde_json::json!(password);
    }
    if let Some(max_downloads) = max_downloads {
        body["max_downloads"] = serde_json::json!(max_downloads);
    }
    let created = admin
        .post(format!("{base}/api/admin/outbound-grants"))
        .header("X-Votport", "1")
        .json(&body)
        .send()
        .unwrap();
    assert!(
        created.status().is_success(),
        "create grant failed: {}",
        created.status()
    );
    let created: serde_json::Value = created.json().unwrap();
    let url = created["url"].as_str().expect("a delivery url");
    url.rsplit("/s/")
        .next()
        .expect("a token in the delivery url")
        .to_owned()
}

/// Finds a file by name anywhere under `root`.
pub fn find_file(root: &Path, name: &str) -> Option<PathBuf> {
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
