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

/// Audit finding 470: the CLI's send and receive route through the core's
/// journalled FFI paths, so a transfer refused for a missing password (a
/// retry-worthy failure) leaves a resume record that `votport status` lists
/// and `votport resume` finishes; a transfer that ends well leaves nothing.
#[test]
fn interrupted_cli_transfers_leave_a_resume_record() {
    let Some(binary) = server_binary() else {
        return;
    };
    let server = start_server(&binary);
    let state = UniqueDir::new("journal-state");
    let source = UniqueDir::new("journal-source");
    let note = b"a note the cli journalled".to_vec();
    let file = source.0.join("note.txt");
    std::fs::write(&file, &note).unwrap();
    let destination = UniqueDir::new("journal-dest");

    sign_in(&state.0, &server.base);

    // A password request link refuses a passwordless send; the core keeps
    // the journalled entry because the failure could go differently next
    // time.
    let created = cli(
        &state.0,
        &[
            "issue-request",
            "journalled send",
            "--password",
            "hush",
            "--json",
        ],
    );
    assert!(
        created.status.success(),
        "issue-request failed:\n{}",
        output_text(&created)
    );
    let link: serde_json::Value = last_json_line(&created.stdout);
    let url = find_json_field(&link, "url");

    let refused = cli(&state.0, &["send", &url, file.to_str().unwrap()]);
    assert!(
        !refused.status.success(),
        "a password link must refuse a passwordless send:\n{}",
        output_text(&refused)
    );

    let listed = cli(&state.0, &["status"]);
    assert!(
        listed.status.success(),
        "status failed:\n{}",
        output_text(&listed)
    );
    let entry = journal_entry(&listed, "send");
    assert_eq!(entry["needs_password"], true);
    assert!(entry["paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|path| path.as_str().unwrap().ends_with("note.txt")));
    let id = find_json_field(&entry, "id");

    // The record resumes: the same id completes with the password, the drop
    // lands, and the journal empties.
    let resumed = cli(&state.0, &["resume", &id, "--password", "hush", "--json"]);
    assert!(
        resumed.status.success(),
        "resume failed:\n{}",
        output_text(&resumed)
    );
    let summary = last_json_line(&resumed.stdout);
    assert_eq!(summary["event"], "done");
    assert_eq!(summary["kind"], "send");
    let landed = find_file(&server.received, "note.txt").expect("the resumed drop landed");
    assert_eq!(std::fs::read(&landed).unwrap(), note);

    // The same for receive: a password delivery refused without a password
    // keeps a receive entry, and its resume lands the delivery.
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
        &[
            "issue-delivery",
            "journalled delivery",
            &library_path,
            "--password",
            "hush",
            "--json",
        ],
    );
    assert!(
        issued.status.success(),
        "issue-delivery failed:\n{}",
        output_text(&issued)
    );
    let link: serde_json::Value = last_json_line(&issued.stdout);
    let url = find_json_field(&link, "url");

    let refused = cli(
        &state.0,
        &["receive", &url, destination.0.to_str().unwrap()],
    );
    assert!(
        !refused.status.success(),
        "a password delivery must refuse a passwordless receive:\n{}",
        output_text(&refused)
    );

    let listed = cli(&state.0, &["status"]);
    let entry = journal_entry(&listed, "receive");
    assert_eq!(entry["needs_password"], true);
    let id = find_json_field(&entry, "id");

    let resumed = cli(&state.0, &["resume", &id, "--password", "hush", "--json"]);
    assert!(
        resumed.status.success(),
        "receive resume failed:\n{}",
        output_text(&resumed)
    );
    let summary = last_json_line(&resumed.stdout);
    assert_eq!(summary["event"], "done");
    assert_eq!(summary["kind"], "receive");
    let landed = find_file(&destination.0, "note.txt").expect("the resumed delivery landed");
    assert_eq!(std::fs::read(&landed).unwrap(), note);

    // Both transfers ended well, so the journal is empty again.
    let listed = cli(&state.0, &["status"]);
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout).trim(),
        "",
        "a finished transfer must not stay in the journal:\n{}",
        output_text(&listed)
    );
}

/// The one journal entry of `kind` in a `votport status` run.
fn journal_entry(listed: &Output, kind: &str) -> serde_json::Value {
    let text = String::from_utf8_lossy(&listed.stdout);
    text.lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|error| panic!("status line was not JSON ({error}): {line}"))
        })
        .find(|entry| entry["kind"] == kind)
        .unwrap_or_else(|| panic!("no {kind} entry in the journal:\n{text}"))
}

/// A send pasted the wrong link kind reads as one sentence with the raw
/// text behind it, like every port command: the raw `to_string` used to
/// print the link variant alone.
#[test]
fn send_failures_print_the_headline_with_the_detail() {
    let state = UniqueDir::new("human-send-state");
    // No server needed: a delivery link in send refuses before anything
    // is read or reached.
    let output = cli(
        &state.0,
        &["send", "https://drop.example/s/token", "missing.bin"],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("votport: That is a delivery link. Paste it into Receive. ("),
        "the headline with its detail is missing:\n{stderr}"
    );
}

/// A resume the journal does not hold reads as one sentence, not the raw
/// error variant.
#[test]
fn resume_failures_print_the_headline_with_the_detail() {
    let state = UniqueDir::new("human-resume-state");
    let output = cli(&state.0, &["resume", "gone"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("votport: That transfer is no longer on record. ("),
        "the headline with its detail is missing:\n{stderr}"
    );
}

/// Piping into a filter that walks away (`| head`) must end the output
/// quietly: a broken pipe on stdout used to panic with exit 101, which
/// aborts a send mid-transfer because a downstream filter closed.
#[test]
fn a_closed_stdout_pipe_ends_quietly_instead_of_panicking() {
    // `status` prints the journal locally, no server needed. Enough fat
    // entries to hold far more than the pipe buffer, so the process is
    // still writing when the reader leaves.
    let state = UniqueDir::new("pipe-state");
    let journal = state.0.join("votport/journal");
    std::fs::create_dir_all(&journal).unwrap();
    let filler = "x".repeat(400);
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for index in 0..400 {
        let entry = serde_json::json!({
            "id": format!("pipe-{index}"),
            "kind": "send",
            "link": format!("https://drop.example/r/{filler}"),
            "paths": [format!("/shots/{filler}.bin")],
            "needs_password": false,
            "started_unix": started,
        });
        std::fs::write(
            journal.join(format!("pipe-{index}.json")),
            entry.to_string(),
        )
        .unwrap();
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_votport"))
        .arg("status")
        .env("XDG_DATA_HOME", &state.0)
        .env("HOME", &state.0)
        .env("APPDATA", &state.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    std::io::BufRead::read_line(&mut stdout, &mut first).expect("one status line");
    drop(stdout); // The reader walks away, as `head` does after its lines.
    let deadline = Instant::now() + CLI_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "votport status did not finish");
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr).unwrap();
    }
    assert!(
        status.success(),
        "exit {:?} with stderr:\n{stderr}",
        status.code()
    );
    assert!(
        !stderr.contains("panicked"),
        "a closed pipe must not panic:\n{stderr}"
    );
}
