use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn inspect(link: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_votport"))
        .args(["inspect", link])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "inspect timed out: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn inspect_exit_status_matches_the_printed_link_state() {
    for (status, usable, password) in [
        (200, true, false),
        (200, true, true),
        (200, false, false),
        (404, false, false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let link = format!("http://{}/r/fixture", listener.local_addr().unwrap());
        let output = std::thread::scope(|scope| {
            scope.spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("inspect fixture accept: {error}"),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                assert!(request.starts_with(b"GET /api/r/fixture "));
                let body = serde_json::json!({"label":"fixture", "usable":usable, "needs_password":password,
                    "max_bytes":1, "max_entries":1, "chunk_bytes":1, "allow_hidden":false, "push":false}).to_string();
                write!(socket, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            });
            inspect(&link)
        });
        assert_eq!(output.status.code(), Some(if usable { 0 } else { 1 }));
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["usable"], usable);
        assert_eq!(json["needs_password"], password);
        assert_eq!(String::from_utf8_lossy(&output.stdout).lines().count(), 1);
    }
    let output = inspect("not a link");
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["usable"], false);
    assert_eq!(String::from_utf8_lossy(&output.stdout).lines().count(), 1);
    // Audit 481: a flag on an optionless command draws the usage error
    // naming the flag, not an inspection of the flag as if it were a link.
    let output = inspect("--json");
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json["error"].as_str().unwrap().contains("no options"));
    assert!(json["error"].as_str().unwrap().contains("--json"));
}
