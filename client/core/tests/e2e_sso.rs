//! Browser handoffs stay bound to the original port and cannot replace a
//! saved session after cancellation or a refused exchange.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;
use votport_client_core::{ffi, port::PortError};

fn accept(listener: &TcpListener) -> TcpStream {
    for _ in 0..5000 {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    }
    panic!("SSO request timed out");
}

fn request(stream: &mut TcpStream) -> String {
    let mut headers = Vec::new();
    for _ in 0..16 * 1024 {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(headers.ends_with(b"\r\n\r\n"));
    let headers = String::from_utf8(headers).unwrap();
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    assert!(length < 4096);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    headers
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) {
    write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nLocation: http://127.0.0.1:1/forbidden\r\n\r\n{body}", body.len()).unwrap();
}

#[test]
fn browser_handoffs_preserve_existing_credentials_on_failure() {
    let state = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_DATA_HOME", state.path());
    let path = state.path().join("votport/port.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = br#"{"base":"https://existing.example","cookie":"votport_admin=existing","tenant":"existing"}"#;
    for scenario in [
        "availability",
        "exchange",
        "session",
        "redirect",
        "cancel",
        "success",
    ] {
        std::fs::write(&path, original).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (arrived, ready) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let mut stream = accept(&listener);
            assert!(request(&mut stream).starts_with("GET /api/admin/sso HTTP/"));
            if scenario == "availability" {
                respond(&mut stream, 401, "{}");
                return;
            }
            respond(&mut stream, 200, r#"{"available":true}"#);
            let mut stream = accept(&listener);
            assert!(request(&mut stream).starts_with("POST /api/admin/sso/exchange HTTP/"));
            if scenario == "exchange" {
                respond(&mut stream, 401, "{}");
                return;
            }
            if scenario == "redirect" {
                respond(&mut stream, 307, "{}");
                return;
            }
            respond(&mut stream, 200, r#"{"cookie":"votport_admin=new"}"#);
            let mut stream = accept(&listener);
            let headers = request(&mut stream);
            assert!(headers.starts_with("GET /api/admin/session HTTP/"));
            assert!(headers
                .to_ascii_lowercase()
                .contains("cookie: votport_admin=new"));
            if scenario == "session" {
                respond(&mut stream, 401, "{}");
                return;
            }
            if scenario == "cancel" {
                arrived.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            respond(&mut stream, 200, r#"{"tenant":"new"}"#);
        });
        let result = match ffi::begin_sso(base.clone()) {
            Err(error) => Err(error),
            Ok(login) => {
                let url = reqwest::Url::parse(&login.authorization_url()).unwrap();
                assert_eq!(url.origin().ascii_serialization(), base);
                let nonce = url
                    .query_pairs()
                    .find(|(name, _)| name == "desktop_state")
                    .unwrap()
                    .1
                    .into_owned();
                let callback = format!("votport://signin/{}?state={nonce}", "ab".repeat(16));
                let completing = std::sync::Arc::clone(&login);
                let worker = std::thread::spawn(move || completing.complete(callback));
                if scenario == "cancel" {
                    ready.recv_timeout(Duration::from_secs(5)).unwrap();
                    login.cancel();
                    release.send(()).unwrap();
                }
                worker.join().unwrap()
            }
        };
        server.join().unwrap();
        if scenario == "success" {
            let port = result.unwrap();
            assert_eq!(port.base, base);
            assert_eq!(port.tenant, "new");
            assert_eq!(ffi::port(), Some(port));
        } else {
            assert!(
                matches!(
                    result,
                    Err(PortError::Failed {
                        signed_out: false,
                        ..
                    })
                ),
                "{scenario}: {result:?}"
            );
            assert_eq!(std::fs::read(&path).unwrap(), original, "{scenario}");
        }
    }
}
