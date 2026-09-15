use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt as _;

fn clear_votport_environment(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("VOTPORT_") {
            command.env_remove(key);
        }
    }
}

fn http_get(address: SocketAddr, path: &str) -> Option<String> {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) else {
        return None;
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

fn health_check(address: SocketAddr) -> bool {
    http_get(address, "/healthz").is_some_and(|response| response.starts_with("HTTP/1.1 200"))
}

#[test]
fn startup_warns_once_for_unknown_names_without_values() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let receive = root.path().join("receive");
    let outbound = root.path().join("outbound");
    for directory in [&data, &receive, &outbound] {
        std::fs::create_dir(directory).unwrap();
        set_private(directory);
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    const SENTINEL: &str = "unknown-environment-secret-7f8a";
    let mut command = Command::new(env!("CARGO_BIN_EXE_votport"));
    clear_votport_environment(&mut command);
    command
        .env("RUST_LOG", "info")
        .env("VOTPORT_LOG_FORMAT", "json")
        .env("VOTPORT_ADMIN_PASSWORD", "correct-horse-battery")
        .env("VOTPORT_BIND", address.to_string())
        .env("VOTPORT_DATA_DIR", &data)
        .env("VOTPORT_RECEIVE_DIR", &receive)
        .env("VOTPORT_OUTBOUND_DIR", &outbound)
        .env("VOTPORT_METRICS_TOKEN", "metrics-fixture-token")
        .env("VOTPORT_TRUSTED_PROXIES", "127.0.0.1")
        .env("VOTPORT_STORAGE_MEDIA_ACCESS_KEY_ID", "fixture-access")
        .env("VOTPORT_STORAGE_MEDIA_SECRET_ACCESS_KEY", "fixture-secret")
        .env("VOTPORT_STORAGE_MEDIA_SESSION_TOKEN", "fixture-session")
        .env("VOTPORT_NOTIFY_SMTP_TO", SENTINEL)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.env(
        "UNRELATED_NONUNICODE",
        std::ffi::OsString::from_vec(vec![0xff]),
    );
    let mut child = command.spawn().unwrap();
    let mut ready = false;
    for _ in 0..100 {
        if health_check(address) {
            ready = true;
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(ready, "disposable server did not become healthy:\n{logs}");
    assert_eq!(
        logs.matches("unknown environment setting ignored").count(),
        1,
        "{logs}"
    );
    check_build_identity(&logs);
    assert!(logs.contains("VOTPORT_NOTIFY_SMTP_TO"), "{logs}");
    assert!(!logs.contains(SENTINEL), "unknown value leaked into logs");
}

#[test]
fn standby_startup_warns_for_unknown_names_before_pulling() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    std::fs::create_dir(&data).unwrap();
    set_private(&data);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    const SENTINEL: &str = "standby-unknown-environment-secret-4b2c";
    let mut command = Command::new(env!("CARGO_BIN_EXE_votport"));
    clear_votport_environment(&mut command);
    command
        .arg("standby")
        .env("RUST_LOG", "info")
        .env("VOTPORT_LOG_FORMAT", "json")
        .env("VOTPORT_STANDBY_SOURCE", "http://127.0.0.1:9")
        .env("VOTPORT_REPLICA_TOKEN", "standby-fixture-token")
        .env("VOTPORT_STANDBY_INTERVAL_SECS", "60")
        .env("VOTPORT_BIND", address.to_string())
        .env("VOTPORT_DATA_DIR", &data)
        .env("VOTPORT_NOTIFY_SMTP_TO", SENTINEL)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let mut pull_observed = false;
    for _ in 0..100 {
        if let Some(response) = http_get(address, "/readyz") {
            if response.contains("\"last_error\":\"replica request") {
                pull_observed = true;
                break;
            }
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        pull_observed,
        "standby did not report a bounded pull attempt:\n{logs}"
    );
    assert_eq!(
        logs.matches("unknown environment setting ignored").count(),
        1,
        "{logs}"
    );
    check_build_identity(&logs);
    assert!(logs.contains("VOTPORT_NOTIFY_SMTP_TO"), "{logs}");
    assert!(!logs.contains(SENTINEL), "unknown value leaked into logs");
}

fn check_build_identity(logs: &str) {
    let entries: Vec<serde_json::Value> = logs
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .filter(|entry: &serde_json::Value| entry["fields"]["message"] == "votport starting")
        .collect();
    assert_eq!(entries.len(), 1, "{logs}");
    assert_eq!(
        entries[0]["fields"]["version"],
        option_env!("VOTPORT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(
        entries[0]["fields"]["revision"],
        option_env!("VOTPORT_REVISION").unwrap_or("unknown")
    );
}

#[test]
fn version_uses_compiled_identity_without_loading_configuration() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("must-not-exist");
    let mut command = Command::new(env!("CARGO_BIN_EXE_votport"));
    clear_votport_environment(&mut command);
    let output = command
        .arg("--version")
        .env("VOTPORT_BIND", "invalid-address")
        .env("VOTPORT_DATA_DIR", &data)
        .env("VOTPORT_VERSION", "runtime-version-must-not-win")
        .env("VOTPORT_REVISION", "runtime-revision-must-not-win")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "votport {} ({})\n",
            option_env!("VOTPORT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
            option_env!("VOTPORT_REVISION").unwrap_or("unknown")
        )
    );
    assert!(output.stderr.is_empty());
    assert!(!data.exists());
}

#[cfg(unix)]
fn set_private(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
fn set_private(_path: &std::path::Path) {}
