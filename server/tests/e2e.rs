//! Full-protocol test: a vot-sdk client (standing in for the browser wasm)
//! drives the votport HTTP API end to end, and the received files are
//! checked byte for byte on disk.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};

use vot_sdk::object::{InMemoryObjectBuilder, InMemoryPreparedObject, Suite};
use vot_sdk::package::{PackageBuilder, PackageEntry};

use votport::config::Config;
use votport::{app, auth, session};

const ADMIN_PASSWORD: &str = "test-admin-password";
const LINK_PASSWORD: &str = "hunter2";
const CHUNK: u64 = session::CHUNK_BYTES;

struct TestServer {
    base: String,
    receive_dir: PathBuf,
    _data: tempfile::TempDir,
    _received: tempfile::TempDir,
}

async fn start_server() -> TestServer {
    start_server_with_cap(64 * 1024 * 1024).await
}

async fn start_server_with_cap(max_upload_bytes: u64) -> TestServer {
    let data = tempfile::tempdir().expect("data dir");
    let received = tempfile::tempdir().expect("receive dir");
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: data.path().to_path_buf(),
        receive_dir: received.path().to_path_buf(),
        web_root: PathBuf::from("./web"),
        admin_password_hash: auth::hash_password(ADMIN_PASSWORD).unwrap(),
        admin_token_tag: String::new(),
        notify_webhook: None,
        notify_ntfy: None,
        notify_ntfy_token: None,
        notify_pushover: None,
        smtp_host: None,
        smtp_port: 587,
        smtp_starttls: true,
        smtp_username: None,
        smtp_password: None,
        smtp_from: None,
        smtp_to: None,
        public_url: None,
        max_upload_bytes,
        allow_hidden: false,
        session_idle_secs: 600,
        audit_retention_days: 400,
        upload_retention_days: 0,
        default_max_total_bytes: None,
        default_max_links: None,
        default_max_sessions: None,
        public_password_login: true,
        metrics_token: None,
        trusted_proxies: Vec::new(),
        oidc: None,
    };
    let application = app::build(config).expect("app builds");
    let router = app::router(Arc::clone(&application));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    TestServer {
        base: format!("http://{addr}"),
        receive_dir: received.path().to_path_buf(),
        _data: data,
        _received: received,
    }
}

struct ClientFile {
    path: Vec<&'static str>,
    bytes: Vec<u8>,
    prepared: InMemoryPreparedObject,
}

fn prepare(path: Vec<&'static str>, bytes: Vec<u8>) -> ClientFile {
    let mut builder = InMemoryObjectBuilder::new(
        Suite::Blake3Bao64,
        Some(bytes.len() as u64),
        bytes.len().max(1) as u64,
    )
    .expect("builder");
    builder.update(&bytes).expect("update");
    ClientFile {
        path,
        bytes,
        prepared: builder.finish().expect("finish"),
    }
}

/// Builds the manifest exactly as the browser does: entries in canonical
/// order, page drafts finalized into encoded pages plus a seal.
fn build_package(files: &[ClientFile]) -> (Value, Vec<Vec<u8>>, Vec<u8>) {
    let mut builder = PackageBuilder::new().expect("package builder");
    let mut drafts = Vec::new();
    for file in files {
        let entry = PackageEntry::direct(
            file.path.iter().map(|s| (*s).to_owned()).collect(),
            file.prepared.object_id(),
        )
        .expect("entry");
        if let Some(draft) = builder.push(&entry).expect("push") {
            drafts.push(draft);
        }
    }
    let (summary, final_page, mut finalizer) = builder.finish().expect("finish").into_parts();
    drafts.push(final_page);
    let mut pages = Vec::new();
    for draft in drafts {
        pages.push(finalizer.push(draft).expect("finalize page").into_bytes());
    }
    let seal = finalizer.finish().expect("seal").into_bytes();
    let object = summary.object_id();
    let announcement = json!({
        "suite": "blake3",
        "root": hex::encode(object.root),
        "length": object.length,
    });
    (announcement, pages, seal)
}

async fn upload_chunks(
    client: &reqwest::Client,
    base: &str,
    session: &str,
    entry: u64,
    file: &ClientFile,
) {
    let mut requests = tokio::task::JoinSet::new();
    let mut offset = 0;
    while offset < file.bytes.len() as u64 {
        let proof = file
            .prepared
            .prove(offset, CHUNK.min(file.bytes.len() as u64 - offset))
            .expect("prove");
        let start = proof.covered_offset() as usize;
        let end = start + proof.covered_length() as usize;
        let mut body = proof.proof().to_vec();
        let proof_len = body.len();
        body.extend_from_slice(&file.bytes[start..end]);
        let client = client.clone();
        let url = format!("{base}/api/session/{session}/chunk?entry={entry}&offset={start}");
        requests.spawn(async move {
            client
                .post(url)
                .header("X-Votport-Proof", proof_len.to_string())
                .body(body)
                .send()
                .await
        });
        offset = proof.covered_offset() + proof.covered_length();
    }
    while let Some(response) = requests.join_next().await {
        let response = response.expect("chunk task").expect("chunk request");
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    }
}

/// Sends at most `max_chunks` ranges starting at `from`, and returns the
/// offset reached. Stopping short stands in for a client that lost its
/// connection mid-file.
async fn upload_chunks_from(
    client: &reqwest::Client,
    base: &str,
    session: &str,
    entry: u64,
    file: &ClientFile,
    from: u64,
    max_chunks: usize,
) -> u64 {
    let length = file.bytes.len() as u64;
    let mut offset = from;
    let mut sent = 0usize;
    while offset < length && sent < max_chunks {
        sent += 1;
        let want = CHUNK.min(length - offset);
        let proof = file.prepared.prove(offset, want).expect("prove");
        let start = proof.covered_offset() as usize;
        let end = start + proof.covered_length() as usize;
        let mut body = proof.proof().to_vec();
        let proof_len = body.len();
        body.extend_from_slice(&file.bytes[start..end.min(file.bytes.len())]);
        let response = client
            .post(format!(
                "{base}/api/session/{session}/chunk?entry={entry}&offset={start}"
            ))
            .header("X-Votport-Proof", proof_len.to_string())
            .body(body)
            .send()
            .await
            .expect("chunk request");
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
        offset = proof.covered_offset() + proof.covered_length();
    }
    offset
}

async fn run_upload(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    password: &str,
    files: &[ClientFile],
) -> Value {
    let (announcement, pages, seal) = build_package(files);
    let response = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": password, "package": announcement }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let session = response.json::<Value>().await.unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = client
        .post(format!("{base}/api/session/{session}/seal"))
        .body(seal)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    for page in pages {
        let response = client
            .post(format!("{base}/api/session/{session}/page"))
            .body(page)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    }
    let response = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let begin = response.json::<Value>().await.unwrap();
    let entries = begin["entries"].as_array().unwrap().clone();
    assert_eq!(entries.len(), files.len());

    for entry in &entries {
        let path = entry["path"].as_str().unwrap();
        let index = entry["index"].as_u64().unwrap();
        let complete = entry["complete"].as_bool().unwrap();
        let file = files
            .iter()
            .find(|file| file.path.join("/") == path)
            .expect("entry matches a file");
        if complete {
            // Empty files and deduped re-sends are complete at begin.
            continue;
        }
        upload_chunks(client, base, &session, index, file).await;
    }

    let response = client
        .post(format!("{base}/api/session/{session}/finish"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    response.json::<Value>().await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn full_protocol_end_to_end() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    // --- admin sign-in ----------------------------------------------------
    let response = client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": "wrong" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    let response = client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // --- link management --------------------------------------------------
    // Mutations without the CSRF header are refused even when signed in.
    let response = client
        .post(format!("{base}/api/admin/links"))
        .json(&json!({ "label": "no header" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);

    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({
            "label": "files from tests",
            "dest": "inbox",
            "password": LINK_PASSWORD,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let link = response.json::<Value>().await.unwrap()["link"].clone();
    let token = link["id"].as_str().unwrap().to_owned();
    assert!(link["url"]
        .as_str()
        .unwrap()
        .ends_with(&format!("/r/{token}")));

    // Destination traversal is rejected at creation time.
    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "bad", "dest": "../escape" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);

    // --- public link info ---------------------------------------------------
    let info = client
        .get(format!("{base}/api/r/{token}"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(info["needs_password"], json!(true));
    assert_eq!(info["usable"], json!(true));

    // --- uploader ----------------------------------------------------------
    let mut big = vec![0u8; 5 * 1024 * 1024 + 12_345];
    for (index, byte) in big.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    // Canonical order of the folded path keys:
    // "b.txt" < "empty.txt" < "résumé draft.pdf" < "sub\0data.bin".
    let files = vec![
        prepare(vec!["b.txt"], b"hello votport".to_vec()),
        prepare(vec!["empty.txt"], Vec::new()),
        prepare(vec!["Résumé Draft.pdf"], b"unicode names travel".to_vec()),
        prepare(vec!["sub", "data.bin"], big.clone()),
    ];

    // Wrong link password is refused before any state is created.
    let (announcement, _, _) = build_package(&files);
    let response = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": "nope", "package": announcement }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    // A tampered chunk is rejected; the honest retry then succeeds.
    let report = run_upload(&client, &base, &token, LINK_PASSWORD, &files).await;
    let reported: Vec<&str> = report["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["stored_as"].as_str().unwrap())
        .collect();
    assert_eq!(
        reported,
        [
            "inbox/b.txt",
            "inbox/empty.txt",
            "inbox/Résumé Draft.pdf",
            "inbox/sub/data.bin"
        ]
    );

    assert_eq!(
        std::fs::read(server.receive_dir.join("inbox/b.txt")).unwrap(),
        b"hello votport"
    );
    assert_eq!(
        std::fs::read(server.receive_dir.join("inbox/Résumé Draft.pdf")).unwrap(),
        b"unicode names travel"
    );
    assert_eq!(
        std::fs::read(server.receive_dir.join("inbox/empty.txt")).unwrap(),
        Vec::<u8>::new()
    );
    assert_eq!(
        std::fs::read(server.receive_dir.join("inbox/sub/data.bin")).unwrap(),
        big
    );

    // --- identical content again: deduped onto the existing copies ----------
    let report = run_upload(&client, &base, &token, LINK_PASSWORD, &files).await;
    let reported: Vec<&str> = report["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["stored_as"].as_str().unwrap())
        .collect();
    assert_eq!(
        reported,
        [
            "inbox/b.txt",
            "inbox/empty.txt",
            "inbox/Résumé Draft.pdf",
            "inbox/sub/data.bin"
        ]
    );
    assert!(
        !server.receive_dir.join("inbox/b-1.txt").exists(),
        "identical re-send must not leave a suffixed copy"
    );

    // --- same name, different content: suffixed, nothing overwritten --------
    let changed = vec![prepare(vec!["b.txt"], b"changed content".to_vec())];
    let report = run_upload(&client, &base, &token, LINK_PASSWORD, &changed).await;
    assert_eq!(report["files"][0]["stored_as"], json!("inbox/b-1.txt"));
    assert_eq!(
        std::fs::read(server.receive_dir.join("inbox/b.txt")).unwrap(),
        b"hello votport",
        "original files stay untouched"
    );
    assert_eq!(
        std::fs::read(server.receive_dir.join("inbox/b-1.txt")).unwrap(),
        b"changed content"
    );

    // --- upload records are visible to the admin ----------------------------
    let links = client
        .get(format!("{base}/api/admin/links"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let uploads = links["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == json!(token))
        .unwrap()["uploads"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(uploads.len(), 3);
    assert_eq!(uploads[0]["files"].as_array().unwrap().len(), 4);
    let events = links["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == json!(token))
        .unwrap()["events"]
        .as_array()
        .unwrap()
        .clone();
    assert!(events.is_empty(), "clean uploads must not record events");
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupted_chunks_are_refused() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "open link" }))
        .send()
        .await
        .unwrap();
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let files = vec![prepare(vec!["payload.bin"], vec![7u8; 200_000])];
    let (announcement, pages, seal) = build_package(&files);
    let session = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "package": announcement }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = client
        .post(format!("{base}/api/session/{session}/seal"))
        .body(seal)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    for page in pages {
        let response = client
            .post(format!("{base}/api/session/{session}/page"))
            .body(page)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    }
    let response = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());

    // Flip one byte: verification must refuse the range.
    let file = &files[0];
    let proof = file.prepared.prove(0, file.bytes.len() as u64).unwrap();
    let mut tampered = file.bytes.clone();
    tampered[1000] ^= 0x01;
    let mut body = proof.proof().to_vec();
    let proof_len = body.len();
    body.extend_from_slice(&tampered);
    let response = client
        .post(format!(
            "{base}/api/session/{session}/chunk?entry=0&offset=0"
        ))
        .header("X-Votport-Proof", proof_len.to_string())
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    assert!(
        !server.receive_dir.join("payload.bin").exists(),
        "nothing is published for refused data"
    );

    // The honest bytes still go through afterwards.
    upload_chunks(&client, &base, &session, 0, file).await;
    let response = client
        .post(format!("{base}/api/session/{session}/finish"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        std::fs::read(server.receive_dir.join("payload.bin")).unwrap(),
        file.bytes
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn begin_store_failure_creates_no_destination() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    let token = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "broken store", "dest": "failed" }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let files = vec![prepare(vec!["untracked.bin"], vec![7u8; 1024])];
    let (announcement, pages, seal) = build_package(&files);
    let session = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "package": announcement }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();
    client
        .post(format!("{base}/api/session/{session}/seal"))
        .body(seal)
        .send()
        .await
        .unwrap();
    for page in pages {
        client
            .post(format!("{base}/api/session/{session}/page"))
            .body(page)
            .send()
            .await
            .unwrap();
    }
    rusqlite::Connection::open(server._data.path().join("votport.db"))
        .unwrap()
        .execute_batch("DROP TABLE links")
        .unwrap();

    let response = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 500);
    assert!(!server.receive_dir.join("failed").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_api_requires_sign_in() {
    let server = start_server().await;
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/api/admin/links", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

/// An interrupted transfer must not have to re-send bytes the server already
/// verified: `begin` is idempotent and reports per-entry coverage, and the
/// client picks up from exactly that offset.
#[tokio::test(flavor = "multi_thread")]
async fn interrupted_transfer_resumes_from_reported_coverage() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "resume", "dest": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Six advertised chunks make "half sent" unambiguous at any chunk size.
    let bytes: Vec<u8> = (0..u32::try_from(6 * CHUNK).unwrap())
        .map(|index| (index.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let length = bytes.len() as u64;
    let files = [prepare(vec!["resume.bin"], bytes.clone())];
    let (announcement, pages, seal) = build_package(&files);

    let response = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": null, "package": announcement }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let session = response.json::<Value>().await.unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = client
        .post(format!("{base}/api/session/{session}/seal"))
        .body(seal)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    for page in pages {
        let response = client
            .post(format!("{base}/api/session/{session}/page"))
            .body(page)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    }

    let begin = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(begin["entries"][0]["covered_bytes"].as_u64().unwrap(), 0);
    let index = begin["entries"][0]["index"].as_u64().unwrap();

    // --- the client dies three chunks in ----------------------------------
    let stopped = upload_chunks_from(&client, &base, &session, index, &files[0], 0, 3).await;
    assert!(stopped > 0 && stopped < length, "stopped at {stopped}");

    // --- it comes back and asks how far it got ----------------------------
    let response = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "begin must be idempotent for a reconnecting client"
    );
    let again = response.json::<Value>().await.unwrap();
    assert_eq!(
        again["entries"][0]["covered_bytes"].as_u64().unwrap(),
        stopped,
        "coverage must match what the client actually sent"
    );
    assert!(!again["entries"][0]["complete"].as_bool().unwrap());

    // --- and resumes from exactly there, re-sending nothing ---------------
    let finished = upload_chunks_from(
        &client,
        &base,
        &session,
        index,
        &files[0],
        stopped,
        usize::MAX,
    )
    .await;
    assert_eq!(finished, length);

    let response = client
        .post(format!("{base}/api/session/{session}/finish"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let report = response.json::<Value>().await.unwrap();
    assert_eq!(report["files"][0]["bytes"].as_u64().unwrap(), length);

    let landed = std::fs::read(server.receive_dir.join("resume.bin")).expect("published file");
    assert_eq!(landed, bytes, "resumed file must be byte-identical");
}

/// Chunks land out of order, so begin must report the contiguous prefix as
/// the resume offset, not the total accepted bytes: a client restarting from
/// the total would skip the hole and the file could never complete.
#[tokio::test(flavor = "multi_thread")]
async fn out_of_order_chunks_resume_from_the_contiguous_prefix() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "holes" }))
        .send()
        .await
        .unwrap();
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let bytes: Vec<u8> = (0..u32::try_from(6 * CHUNK).unwrap())
        .map(|index| (index.wrapping_mul(2_246_822_519) >> 11) as u8)
        .collect();
    let length = bytes.len() as u64;
    let files = [prepare(vec!["holes.bin"], bytes)];
    let (announcement, pages, seal) = build_package(&files);

    let session = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "package": announcement }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = client
        .post(format!("{base}/api/session/{session}/seal"))
        .body(seal)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    for page in pages {
        let response = client
            .post(format!("{base}/api/session/{session}/page"))
            .body(page)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    }
    let begin = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let index = begin["entries"][0]["index"].as_u64().unwrap();

    // Two chunks land beyond a hole at the front.
    upload_chunks_from(&client, &base, &session, index, &files[0], 2 * CHUNK, 2).await;
    let again = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        again["entries"][0]["covered_bytes"].as_u64().unwrap(),
        0,
        "resume offset must stop at the hole, not count the accepted extents"
    );

    // Filling the front merges through the accepted extents.
    upload_chunks_from(&client, &base, &session, index, &files[0], 0, 2).await;
    let again = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        again["entries"][0]["covered_bytes"].as_u64().unwrap(),
        4 * CHUNK
    );

    upload_chunks_from(
        &client,
        &base,
        &session,
        index,
        &files[0],
        4 * CHUNK,
        usize::MAX,
    )
    .await;
    let response = client
        .post(format!("{base}/api/session/{session}/finish"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let report = response.json::<Value>().await.unwrap();
    assert_eq!(report["files"][0]["bytes"].as_u64().unwrap(), length);
}

/// The link password throttle is per client IP and separate from the admin
/// throttle, and a verified password sets a cookie that stands in for it.
#[tokio::test(flavor = "multi_thread")]
async fn link_password_throttles_per_ip_without_locking_the_admin() {
    let server = start_server().await;
    let base = server.base.clone();
    let admin = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    admin
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    let response = admin
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "guarded", "password": "sesame-pass-123" }))
        .send()
        .await
        .unwrap();
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let stranger = reqwest::Client::new();
    for _ in 0..5 {
        let response = stranger
            .post(format!("{base}/api/r/{token}/verify"))
            .json(&json!({ "password": "wrong" }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
    }
    let response = stranger
        .post(format!("{base}/api/r/{token}/verify"))
        .json(&json!({ "password": "sesame-pass-123" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 429, "five failures lock the client IP");

    // The lockout is the stranger's, not the admin's.
    let response = reqwest::Client::new()
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "admin login is not affected");
}

/// A verified link password sets a cookie that authorizes later visits, and a
/// closed link stops revealing its label.
#[tokio::test(flavor = "multi_thread")]
async fn verified_password_cookie_survives_and_closed_links_hide_the_label() {
    let server = start_server().await;
    let base = server.base.clone();
    let admin = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    admin
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    let response = admin
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "guarded", "password": "sesame-pass-123" }))
        .send()
        .await
        .unwrap();
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let sender = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let info = sender
        .get(format!("{base}/api/r/{token}"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(info["label"].as_str().unwrap(), "guarded");
    assert!(info["needs_password"].as_bool().unwrap());
    assert!(!info["authorized"].as_bool().unwrap());

    let response = sender
        .post(format!("{base}/api/r/{token}/verify"))
        .json(&json!({ "password": "sesame-pass-123" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let info = sender
        .get(format!("{base}/api/r/{token}"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(info["authorized"].as_bool().unwrap(), "cookie authorizes");

    // The cookie also stands in for the password when a session is created.
    let files = [prepare(vec!["small.bin"], vec![9u8; 1000])];
    let (announcement, _pages, _seal) = build_package(&files);
    let response = sender
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": null, "package": announcement }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());

    let response = admin
        .post(format!("{base}/api/admin/links/{token}"))
        .header("X-Votport", "1")
        .json(&json!({ "active": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let info = sender
        .get(format!("{base}/api/r/{token}"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(info["label"].is_null(), "closed links hide the label");
    assert!(!info["usable"].as_bool().unwrap());
}

/// Changing the admin password invalidates every other session's token but
/// reissues a cookie to the session that made the change.
#[tokio::test(flavor = "multi_thread")]
async fn changing_the_admin_password_evicts_other_sessions_but_not_the_actor() {
    let server = start_server().await;
    let base = server.base.clone();
    let actor = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let other = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    for client in [&actor, &other] {
        let response = client
            .post(format!("{base}/api/admin/login"))
            .json(&json!({ "password": ADMIN_PASSWORD }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    let response = actor
        .post(format!("{base}/api/admin/password"))
        .header("X-Votport", "1")
        .json(&json!({ "current": ADMIN_PASSWORD, "new": "a-new-password-123" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());

    let response = actor
        .get(format!("{base}/api/admin/session"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "the acting admin stays signed in");
    let response = other
        .get(format!("{base}/api/admin/session"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401, "other sessions are evicted");
}

/// Every published file gets a signed receipt sidecar that verifies against
/// the advertised key, and the admin can delete files and clear history.
#[tokio::test(flavor = "multi_thread")]
async fn receipts_are_written_and_files_are_manageable() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "receipts" }))
        .send()
        .await
        .unwrap();
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let files = [prepare(vec!["receipted.bin"], vec![5u8; 300_000])];
    let report = run_upload(&client, &base, &token, "", &files).await;
    assert!(
        report["files"][0]["receipt"].as_bool().unwrap(),
        "finish reports the sidecar"
    );

    let sidecar = server.receive_dir.join("receipted.bin.vot-receipt");
    let listing = client
        .get(format!("{base}/api/admin/links"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let key_hex = listing["receipt_key"].as_str().unwrap();
    let bytes = std::fs::read(&sidecar).expect("sidecar exists");
    let decoded = vot_receipt::decode_authenticated(&bytes).expect("sidecar decodes");
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(&hex::decode(key_hex).unwrap().try_into().unwrap())
            .unwrap();
    let verified = vot_receipt::verify_ed25519(&decoded, &key).expect("receipt verifies");
    assert_eq!(
        hex::encode(verified.receipt().subject_digest),
        report["files"][0]["root"].as_str().unwrap(),
        "receipt attests the exact object"
    );

    let link = listing["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == json!(token))
        .unwrap();
    let upload = &link["uploads"][0];
    assert!(upload["files"][0]["exists"].as_bool().unwrap());
    assert!(upload["files"][0]["receipt"].as_bool().unwrap());
    let upload_id = upload["id"].as_str().unwrap();

    let response = client
        .delete(format!(
            "{base}/api/admin/links/{token}/uploads/{upload_id}/files/0"
        ))
        .header("X-Votport", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    assert!(!server.receive_dir.join("receipted.bin").exists());
    assert!(!sidecar.exists(), "sidecar is deleted with the file");
    // Deleting again is fine: the file is already gone.
    let response = client
        .delete(format!(
            "{base}/api/admin/links/{token}/uploads/{upload_id}/files/0"
        ))
        .header("X-Votport", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let response = client
        .delete(format!(
            "{base}/api/admin/links/{token}/uploads/{upload_id}"
        ))
        .header("X-Votport", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let listing = client
        .get(format!("{base}/api/admin/links"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let link = listing["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == json!(token))
        .unwrap();
    assert!(
        link["uploads"].as_array().unwrap().is_empty(),
        "history cleared"
    );

    // The QR endpoint answers with an SVG for the admin.
    let response = client
        .get(format!("{base}/api/admin/links/{token}/qr"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.text().await.unwrap().contains("<svg"));
}

/// An aborted session must leave a "cancelled" event on the link, carrying
/// how far it got and the replay counter.
#[tokio::test(flavor = "multi_thread")]
async fn aborted_sessions_record_a_cancelled_event() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "abort", "dest": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let bytes: Vec<u8> = (0..u32::try_from(4 * CHUNK).unwrap())
        .map(|index| (index.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect();
    let files = [prepare(vec!["abort.bin"], bytes)];
    let (announcement, pages, seal) = build_package(&files);

    let response = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": null, "package": announcement }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let session = response.json::<Value>().await.unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = client
        .post(format!("{base}/api/session/{session}/seal"))
        .body(seal)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    for page in pages {
        let response = client
            .post(format!("{base}/api/session/{session}/page"))
            .body(page)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    }
    let begin = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let index = begin["entries"][0]["index"].as_u64().unwrap();

    // Two chunks land, then the first is re-sent (a lost response on the
    // sender's side), then the sender gives up.
    let stopped = upload_chunks_from(&client, &base, &session, index, &files[0], 0, 2).await;
    assert!(stopped > 0);
    upload_chunks_from(&client, &base, &session, index, &files[0], 0, 1).await;

    let response = client
        .post(format!("{base}/api/session/{session}/abort"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let links = client
        .get(format!("{base}/api/admin/links"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let events = links["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == json!(token))
        .unwrap()["events"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["outcome"], json!("cancelled"));
    assert_eq!(events[0]["received_bytes"].as_u64().unwrap(), stopped);
    assert_eq!(events[0]["replayed_chunks"].as_u64().unwrap(), 1);
    assert_eq!(events[0]["rejected_chunks"].as_u64().unwrap(), 0);
    assert!(events[0]["expected_bytes"].as_u64().unwrap() > stopped);
}

/// Named tenants use a private subtree, so a default-tenant file may have the
/// same name even when the tenant is created during the transfer.
#[tokio::test(flavor = "multi_thread")]
async fn a_root_link_can_publish_a_file_named_after_a_tenant() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "root", "dest": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // One top-level file named exactly like the tenant created below.
    let files = [prepare(vec!["acme"], b"a plain file".to_vec())];
    let (announcement, pages, seal) = build_package(&files);

    let response = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": null, "package": announcement }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let session = response.json::<Value>().await.unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = client
        .post(format!("{base}/api/session/{session}/seal"))
        .body(seal)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    for page in pages {
        let response = client
            .post(format!("{base}/api/session/{session}/page"))
            .body(page)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    }
    // begin passes: no tenant exists yet, and nothing on disk is claimed.
    let response = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let entries = response.json::<Value>().await.unwrap();
    let entry = entries["entries"][0]["index"].as_u64().unwrap();

    // The tenant appears mid-transfer, which is the window this covers.
    let response = client
        .post(format!("{base}/api/admin/tenants"))
        .header("X-Votport", "1")
        .json(&json!({ "key": "acme", "label": "acme" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());

    // Sending the only chunk completes and publishes the object.
    let file = &files[0];
    let proof = file
        .prepared
        .prove(0, file.bytes.len() as u64)
        .expect("prove");
    let mut body = proof.proof().to_vec();
    let proof_len = body.len();
    body.extend_from_slice(&file.bytes);
    let response = client
        .post(format!(
            "{base}/api/session/{session}/chunk?entry={entry}&offset=0"
        ))
        .header("X-Votport-Proof", proof_len.to_string())
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    assert_eq!(
        std::fs::read(server.receive_dir.join("acme")).unwrap(),
        b"a plain file"
    );
}

/// A tenant's own link publishes under its prefix already, so a package whose
/// top-level folder happens to match the tenant key resolves to
/// receive/.vot-tenants.stage/<key>/<key>/... and is nobody else's business.
#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_may_upload_a_folder_named_like_its_own_key() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let response = client
        .post(format!("{base}/api/admin/tenants"))
        .header("X-Votport", "1")
        .json(&json!({ "key": "acme", "label": "acme" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());

    // Act inside the tenant so the link belongs to it.
    let response = client
        .post(format!("{base}/api/admin/tenant"))
        .header("X-Votport", "1")
        .json(&json!({ "tenant": "acme" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());

    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "tenant inbox", "dest": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let files = [prepare(vec!["acme", "report.bin"], b"mine".to_vec())];
    let (announcement, pages, seal) = build_package(&files);

    let response = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": null, "package": announcement }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let session = response.json::<Value>().await.unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = client
        .post(format!("{base}/api/session/{session}/seal"))
        .body(seal)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    for page in pages {
        let response = client
            .post(format!("{base}/api/session/{session}/page"))
            .body(page)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    }
    let response = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        200,
        "a tenant may name a folder after itself: {}",
        response.text().await.unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_root_link_can_upload_a_folder_named_after_a_tenant() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let response = client
        .post(format!("{base}/api/admin/tenants"))
        .header("X-Votport", "1")
        .json(&json!({ "key": "acme", "label": "acme" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());

    // A link at the receive root. Its dest names no tenant, so both creation
    // checks pass; the collision only exists in the file's own path.
    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "root", "dest": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let files = [prepare(vec!["acme", "invoice.pdf"], b"not yours".to_vec())];
    let (announcement, pages, seal) = build_package(&files);

    let response = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": null, "package": announcement }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let session = response.json::<Value>().await.unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = client
        .post(format!("{base}/api/session/{session}/seal"))
        .body(seal)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    for page in pages {
        let response = client
            .post(format!("{base}/api/session/{session}/page"))
            .body(page)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    }
    let response = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let entry = response.json::<Value>().await.unwrap()["entries"][0]["index"]
        .as_u64()
        .unwrap();
    let file = &files[0];
    let proof = file
        .prepared
        .prove(0, file.bytes.len() as u64)
        .expect("prove");
    let mut body = proof.proof().to_vec();
    let proof_len = body.len();
    body.extend_from_slice(&file.bytes);
    let response = client
        .post(format!(
            "{base}/api/session/{session}/chunk?entry={entry}&offset=0"
        ))
        .header("X-Votport-Proof", proof_len.to_string())
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    assert_eq!(
        std::fs::read(server.receive_dir.join("acme/invoice.pdf")).unwrap(),
        b"not yours"
    );
    assert!(!server
        .receive_dir
        .join(".vot-tenants.stage/acme/invoice.pdf")
        .exists());
}

/// A package refused at begin (hidden path here) consumes the session, so
/// the worker must record a "rejected" event rather than exiting silently.
#[tokio::test(flavor = "multi_thread")]
async fn begin_rejection_records_an_event() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "reject", "dest": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let files = [prepare(vec![".hidden"], b"dotfile".to_vec())];
    let (announcement, pages, seal) = build_package(&files);

    let response = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": null, "package": announcement }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let session = response.json::<Value>().await.unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = client
        .post(format!("{base}/api/session/{session}/seal"))
        .body(seal)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    for page in pages {
        let response = client
            .post(format!("{base}/api/session/{session}/page"))
            .body(page)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    }
    let response = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422, "{}", response.text().await.unwrap());

    let links = client
        .get(format!("{base}/api/admin/links"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let events = links["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == json!(token))
        .unwrap()["events"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["outcome"], json!("rejected"));
    assert!(
        events[0]["detail"].as_str().unwrap().contains("hidden"),
        "{events:?}"
    );
}

/// A re-sent file whose object root the link already delivered, and which is
/// still on disk, is skipped: begin reports it complete, no bytes move, and
/// no suffixed second copy appears. A genuinely new file in the same package
/// still transfers.
#[tokio::test(flavor = "multi_thread")]
async fn identical_resend_is_deduped_not_suffixed() {
    let server = start_server().await;
    let base = server.base.clone();
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "dedupe", "dest": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let dup_bytes: Vec<u8> = (0..u32::try_from(2 * CHUNK).unwrap())
        .map(|index| (index.wrapping_mul(2_654_435_761) >> 9) as u8)
        .collect();
    let first = [prepare(vec!["dup.bin"], dup_bytes.clone())];
    run_upload(&client, &base, &token, "", &first).await;

    // --- the same file again, plus a new one --------------------------------
    let second = [
        prepare(vec!["dup.bin"], dup_bytes.clone()),
        prepare(vec!["new.bin"], b"fresh content".to_vec()),
    ];
    let (announcement, pages, seal) = build_package(&second);
    let response = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": null, "package": announcement }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let session = response.json::<Value>().await.unwrap()["session"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = client
        .post(format!("{base}/api/session/{session}/seal"))
        .body(seal)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    for page in pages {
        let response = client
            .post(format!("{base}/api/session/{session}/page"))
            .body(page)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    }
    let begin = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let entries = begin["entries"].as_array().unwrap();
    let dup = entries
        .iter()
        .find(|entry| entry["path"] == json!("dup.bin"))
        .unwrap();
    assert!(dup["complete"].as_bool().unwrap(), "{dup:?}");
    assert_eq!(
        dup["covered_bytes"].as_u64().unwrap(),
        dup_bytes.len() as u64
    );
    assert_eq!(dup["stored_as"], json!("dup.bin"));
    let fresh = entries
        .iter()
        .find(|entry| entry["path"] == json!("new.bin"))
        .unwrap();
    assert!(!fresh["complete"].as_bool().unwrap());

    upload_chunks(
        &client,
        &base,
        &session,
        fresh["index"].as_u64().unwrap(),
        &second[1],
    )
    .await;
    let response = client
        .post(format!("{base}/api/session/{session}/finish"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let report = response.json::<Value>().await.unwrap();
    assert_eq!(report["files"].as_array().unwrap().len(), 2);

    assert!(
        !server.receive_dir.join("dup-1.bin").exists(),
        "dedupe must not publish a suffixed second copy"
    );
    let landed = std::fs::read(server.receive_dir.join("dup.bin")).unwrap();
    assert_eq!(landed, dup_bytes);
    assert_eq!(
        std::fs::read(server.receive_dir.join("new.bin")).unwrap(),
        b"fresh content"
    );

    // --- the copy is deleted: the next re-send transfers for real -----------
    std::fs::remove_file(server.receive_dir.join("dup.bin")).unwrap();
    let again = [prepare(vec!["dup.bin"], dup_bytes.clone())];
    run_upload(&client, &base, &token, "", &again).await;
    assert_eq!(
        std::fs::read(server.receive_dir.join("dup.bin")).unwrap(),
        dup_bytes,
        "a record whose file is gone must not dedupe; the transfer redelivers"
    );
    assert!(!server.receive_dir.join("dup-1.bin").exists());

    // --- admin deletes the file, different same-length content reuses the
    // name: the old root must not dedupe onto the impostor ------------------
    let links = client
        .get(format!("{base}/api/admin/links"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let uploads = links["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == json!(token))
        .unwrap()["uploads"]
        .as_array()
        .unwrap()
        .clone();
    let (upload_id, file_index) = uploads
        .iter()
        .find_map(|upload| {
            upload["files"]
                .as_array()
                .unwrap()
                .iter()
                .position(|file| file["stored_as"] == json!("dup.bin"))
                .map(|index| (upload["id"].as_str().unwrap().to_owned(), index))
        })
        .expect("a record for dup.bin");
    let response = client
        .delete(format!(
            "{base}/api/admin/links/{token}/uploads/{upload_id}/files/{file_index}"
        ))
        .header("X-Votport", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    assert!(!server.receive_dir.join("dup.bin").exists());

    // Different bytes, same length and name, land at the freed path.
    let impostor_bytes: Vec<u8> = dup_bytes.iter().map(|byte| byte.wrapping_add(1)).collect();
    let impostor = [prepare(vec!["dup.bin"], impostor_bytes.clone())];
    run_upload(&client, &base, &token, "", &impostor).await;
    assert_eq!(
        std::fs::read(server.receive_dir.join("dup.bin")).unwrap(),
        impostor_bytes
    );

    // Re-announcing the original root must transfer for real and publish
    // beside the impostor, never claim its bytes as delivered.
    let original = [prepare(vec!["dup.bin"], dup_bytes.clone())];
    run_upload(&client, &base, &token, "", &original).await;
    assert_eq!(
        std::fs::read(server.receive_dir.join("dup-1.bin")).unwrap(),
        dup_bytes
    );
    assert_eq!(
        std::fs::read(server.receive_dir.join("dup.bin")).unwrap(),
        impostor_bytes,
        "the impostor stays untouched"
    );
}

/// Throughput baseline, run explicitly: `cargo test --test e2e -- --ignored
/// --nocapture throughput_baseline`. Times local hashing and the full upload
/// of one 256 MiB object through the real HTTP protocol so optimization work
/// has before/after numbers from a fixed method.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark; run explicitly"]
async fn throughput_baseline() {
    let server = start_server_with_cap(512 * 1024 * 1024).await;
    let base = &server.base;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let response = client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("x-votport", "1")
        .json(&json!({ "label": "benchmark" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    const MIB: usize = 1024 * 1024;
    let mut bytes = vec![0u8; 256 * MIB];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index * 7 % 251) as u8;
    }

    let started = std::time::Instant::now();
    let file = prepare(vec!["benchmark.bin"], bytes);
    let hashed = started.elapsed();

    let started = std::time::Instant::now();
    run_upload(&client, base, &token, "", &[file]).await;
    let uploaded = started.elapsed();

    let mib = |seconds: std::time::Duration| format!("{:.0} MiB/s", 256.0 / seconds.as_secs_f64());
    println!("hash+package 256 MiB: {hashed:.3?} ({})", mib(hashed));
    println!("upload       256 MiB: {uploaded:.3?} ({})", mib(uploaded));
}

#[tokio::test]
async fn public_verify_checks_sidecars() {
    let server = start_server().await;
    let base = &server.base;

    // Admin session only to create a link and produce a real sidecar.
    let admin = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    admin
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    let response = admin
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&json!({ "label": "verify" }))
        .send()
        .await
        .unwrap();
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let report = run_upload(
        &admin,
        base,
        &token,
        "",
        &[prepare(vec!["receipted.bin"], vec![5u8; 300_000])],
    )
    .await;
    let root = report["files"][0]["root"].as_str().unwrap().to_owned();

    // The key GET is public: no cookies, no X-Votport.
    let anon = reqwest::Client::new();
    let response = anon
        .get(format!("{base}/api/receipt-key"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    let receipt_key = response.json::<Value>().await.unwrap()["receipt_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(receipt_key.len(), 64, "64 lowercase hex");

    let post = |body: Vec<u8>| {
        let anon = &anon;
        async move {
            anon.post(format!("{base}/api/verify"))
                .header("Content-Type", "application/octet-stream")
                .body(body)
                .send()
                .await
                .unwrap()
        }
    };

    // A valid sidecar checks out with lowercase JSON enum names.
    let sidecar = std::fs::read(server.receive_dir.join("receipted.bin.vot-receipt"))
        .expect("sidecar exists");
    let response = post(sidecar.clone()).await;
    assert_eq!(response.status(), 200);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["ok"], json!(true));
    assert_eq!(body["suite"], json!("blake3"));
    assert_eq!(body["root"], json!(root));
    assert_eq!(body["length"], json!(300_000u64));
    assert_eq!(body["subject_kind"], json!("object"));
    assert_eq!(body["assurance"], json!("published"));
    assert_eq!(body["profile"], json!("balanced"));
    assert!(!body["observed_at"].as_str().unwrap().is_empty());

    // Truncated and garbage envelopes are not receipts. Budget is consumed
    // either way, so these count toward the rate limit below.
    for malformed in [sidecar[..8].to_vec(), vec![0xff; 64]] {
        let response = post(malformed).await;
        assert_eq!(response.status(), 422);
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"],
            json!("This is not a vot-receipt.")
        );
    }

    // A receipt signed by another key is well-formed but not ours.
    let stranger = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let receipt = vot_receipt::Receipt {
        subject_kind: vot_receipt::SubjectKind::Object,
        suite_id: 1,
        subject_digest: [7; 32],
        subject_length: 300_000,
        assurance: vot_receipt::AssuranceLevel::Published,
        profile: vot_receipt::CommitProfile::Balanced,
        actual_predecessor: vot_receipt::required_predecessor(vot_receipt::CommitProfile::Balanced),
        provider: 1,
        provider_version: [0, 1, 0],
        session_id: [0; 16],
        incarnation_id: [0; 16],
        sequence: 1,
        observed_at: "2026-08-22T00:00:00Z".to_owned(),
        clock_source: 1,
        flags: 0,
        previous: None,
    };
    let authenticated =
        vot_receipt::sign_ed25519(receipt, &stranger.verifying_key().to_bytes(), &stranger)
            .unwrap();
    let foreign = vot_receipt::encode_authenticated(&authenticated).unwrap();
    let response = post(foreign).await;
    assert_eq!(response.status(), 422);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        json!("This receipt was not issued by this server.")
    );

    // One byte over the cap is rejected by the router without reaching the
    // handler (no rate budget spent).
    let response = post(vec![0u8; 65_537]).await;
    assert_eq!(response.status(), 413, "payload limit");

    // 20 POSTs per IP per window; the 21st is refused even though every body
    // so far was legitimate or at worst a small malformed one.
    for _ in 4..20 {
        let response = post(sidecar.clone()).await;
        assert_eq!(response.status(), 200);
    }
    let response = post(sidecar).await;
    assert_eq!(response.status(), 429);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        json!("too many checks from your address; try again later")
    );
}
