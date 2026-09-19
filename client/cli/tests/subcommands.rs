//! CLI subcommands against the real server fixture: a full send path, a full
//! receive path, and a refused send. Requires `VOTPORT_BIN` pointing at a
//! server build (the gate sets it); local runs without it skip quietly.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const ADMIN_PASSWORD: &str = "e2e-password";
const CLI_TIMEOUT: Duration = Duration::from_secs(30);
const SERVER_TIMEOUT: Duration = Duration::from_secs(30);

fn server_binary() -> Option<String> {
    match std::env::var("VOTPORT_BIN") {
        Ok(path) if Path::new(&path).exists() => Some(path),
        _ => None,
    }
}

/// A temp directory that removes itself; std-only because this crate has no
/// tempfile dependency.
struct UniqueDir(PathBuf);

impl UniqueDir {
    fn new(kind: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "votport-cli-subcommands-{}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            kind
        ));
        std::fs::create_dir_all(&path).unwrap();
        UniqueDir(path)
    }
}

impl Drop for UniqueDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Server {
    child: std::process::Child,
    base: String,
    received: PathBuf,
    _data: UniqueDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_server(binary: &str) -> Server {
    let data = UniqueDir::new("server-data");
    let received = data.0.join("received");
    let outbound = data.0.join("outbound");
    std::fs::create_dir_all(&outbound).unwrap();
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let web_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../web")
        .canonicalize()
        .expect("the votport web directory");
    let mut child = Command::new(binary)
        .env("VOTPORT_BIND", format!("127.0.0.1:{port}"))
        .env("VOTPORT_PUBLIC_URL", format!("http://127.0.0.1:{port}"))
        .env("VOTPORT_DATA_DIR", data.0.join("data"))
        .env("VOTPORT_RECEIVE_DIR", &received)
        .env("VOTPORT_OUTBOUND_DIR", &outbound)
        .env("VOTPORT_WEB_ROOT", web_root)
        .env("VOTPORT_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .env("VOTPORT_MAX_UPLOAD_BYTES", (1u64 << 32).to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the votport server");
    let base = format!("http://127.0.0.1:{port}");
    let deadline = Instant::now() + SERVER_TIMEOUT;
    loop {
        if child.try_wait().unwrap().is_some() {
            panic!("the server exited before serving {base}");
        }
        let authority = format!("127.0.0.1:{port}");
        if let Ok(mut stream) = TcpStream::connect(&authority) {
            let request =
                format!("GET /healthz HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
            if stream.write_all(request.as_bytes()).is_ok() {
                let mut response = String::new();
                let _ = stream.read_to_string(&mut response);
                if response.starts_with("HTTP/1.1 200") {
                    return Server {
                        child,
                        base,
                        received,
                        _data: data,
                    };
                }
            }
        }
        assert!(Instant::now() < deadline, "the server did not come up");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Runs one CLI subcommand with isolated state, bounded so a wedge fails the
/// test instead of hanging the suite.
fn cli(state: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_votport"))
        .args(args)
        .env("XDG_DATA_HOME", state)
        .env("HOME", state)
        .env("APPDATA", state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + CLI_TIMEOUT;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "votport {args:?} did not finish in time"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn output_text(output: &Output) -> String {
    format!(
        "--- stdout ---\n{}--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The `--json` observers print one JSON value per line; the summary is last.
fn last_json_line(stdout: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(stdout);
    let line = text.lines().last().expect("the command printed nothing");
    serde_json::from_str(line)
        .unwrap_or_else(|error| panic!("the last line was not JSON ({error}): {line}"))
}

fn find_file(directory: &Path, name: &str) -> Option<PathBuf> {
    let mut results = Vec::new();
    let mut stack = vec![directory.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else if entry.file_name() == name {
                results.push(entry.path());
            }
        }
    }
    results.pop()
}

fn sign_in(state: &Path, base: &str) {
    let output = cli(state, &["signin", base, "--password", ADMIN_PASSWORD]);
    assert!(
        output.status.success(),
        "signin failed:\n{}",
        output_text(&output)
    );
}

fn find_json_field(value: &serde_json::Value, field: &str) -> String {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("no string {field} in {value}"))
        .to_owned()
}

/// The full send path: sign in, publish a request link, and drop a file into
/// it; the drop must travel over HTTP and land in the server's receive tree
/// with its bytes intact.
#[test]
fn send_publishes_a_drop_to_the_real_server() {
    let Some(binary) = server_binary() else {
        return;
    };
    let server = start_server(&binary);
    let state = UniqueDir::new("send-state");
    let source = UniqueDir::new("send-source");
    let note = b"a note sent by the cli".to_vec();
    let file = source.0.join("note.txt");
    std::fs::write(&file, &note).unwrap();

    sign_in(&state.0, &server.base);
    let created = cli(&state.0, &["issue-request", "cli send", "--json"]);
    assert!(
        created.status.success(),
        "issue-request failed:\n{}",
        output_text(&created)
    );
    let link: serde_json::Value = last_json_line(&created.stdout);
    let url = find_json_field(&link, "url");

    let sent = cli(&state.0, &["send", &url, file.to_str().unwrap(), "--json"]);
    assert!(
        sent.status.success(),
        "send failed:\n{}",
        output_text(&sent)
    );
    let summary = last_json_line(&sent.stdout);
    assert_eq!(summary["event"], "done");
    assert_eq!(summary["via"], "http");
    assert_eq!(summary["files"], 1);

    let landed = find_file(&server.received, "note.txt").expect("the drop landed on the server");
    assert_eq!(std::fs::read(&landed).unwrap(), note);
}

/// The full receive path: sign in, upload a file into the library, issue a
/// delivery link, and receive it into a directory; the bytes must arrive.
#[test]
fn receive_delivers_a_grant_into_a_directory() {
    let Some(binary) = server_binary() else {
        return;
    };
    let server = start_server(&binary);
    let state = UniqueDir::new("receive-state");
    let source = UniqueDir::new("receive-source");
    let note = b"a note received by the cli".to_vec();
    let file = source.0.join("note.txt");
    std::fs::write(&file, &note).unwrap();
    let destination = UniqueDir::new("receive-dest");

    sign_in(&state.0, &server.base);
    let uploaded = cli(&state.0, &["upload", file.to_str().unwrap(), "--json"]);
    assert!(
        uploaded.status.success(),
        "upload failed:\n{}",
        output_text(&uploaded)
    );
    let library: serde_json::Value = last_json_line(&uploaded.stdout);
    let library_path = library[0]["path"]
        .as_str()
        .unwrap_or_else(|| panic!("no library path in {library}"))
        .to_owned();

    let issued = cli(
        &state.0,
        &["issue-delivery", "cli delivery", &library_path, "--json"],
    );
    assert!(
        issued.status.success(),
        "issue-delivery failed:\n{}",
        output_text(&issued)
    );
    let link: serde_json::Value = last_json_line(&issued.stdout);
    let url = find_json_field(&link, "url");

    let received = cli(
        &state.0,
        &["receive", &url, destination.0.to_str().unwrap()],
    );
    assert!(
        received.status.success(),
        "receive failed:\n{}",
        output_text(&received)
    );
    assert!(
        String::from_utf8_lossy(&received.stdout).contains("done: 1 file received into"),
        "unexpected receive output:\n{}",
        output_text(&received)
    );
    let landed = find_file(&destination.0, "note.txt").expect("the delivery landed");
    assert_eq!(std::fs::read(&landed).unwrap(), note);
}

/// A failure path: closing the request link must make the next send fail with
/// a non-zero exit and a machine-readable error event on stdout.
#[test]
fn a_closed_request_link_refuses_a_send() {
    let Some(binary) = server_binary() else {
        return;
    };
    let server = start_server(&binary);
    let state = UniqueDir::new("closed-state");
    let source = UniqueDir::new("closed-source");
    let file = source.0.join("note.txt");
    std::fs::write(&file, b"never delivered").unwrap();

    sign_in(&state.0, &server.base);
    let created = cli(&state.0, &["issue-request", "doomed link", "--json"]);
    assert!(
        created.status.success(),
        "issue-request failed:\n{}",
        output_text(&created)
    );
    let link: serde_json::Value = last_json_line(&created.stdout);
    let url = find_json_field(&link, "url");
    let id = find_json_field(&link, "id");

    let closed = cli(&state.0, &["close-request", &id]);
    assert!(
        closed.status.success(),
        "close-request failed:\n{}",
        output_text(&closed)
    );

    let refused = cli(&state.0, &["send", &url, file.to_str().unwrap(), "--json"]);
    assert!(
        !refused.status.success(),
        "a closed link must refuse the send:\n{}",
        output_text(&refused)
    );
    assert_eq!(refused.status.code(), Some(1));
    let error = last_json_line(&refused.stdout);
    assert!(error["error"].is_string());
    assert_eq!(error["code"], "command_failed");
    assert_eq!(error["retryable"], false);
}
