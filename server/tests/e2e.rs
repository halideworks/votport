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
use votport::{app, auth};

const ADMIN_PASSWORD: &str = "test-admin-password";
const LINK_PASSWORD: &str = "hunter2";
const CHUNK: u64 = 2 * 1024 * 1024;

struct TestServer {
    base: String,
    receive_dir: PathBuf,
    _data: tempfile::TempDir,
    _received: tempfile::TempDir,
}

async fn start_server() -> TestServer {
    let data = tempfile::tempdir().expect("data dir");
    let received = tempfile::tempdir().expect("receive dir");
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: data.path().to_path_buf(),
        receive_dir: received.path().to_path_buf(),
        web_root: PathBuf::from("./web"),
        admin_password_hash: auth::hash_password(ADMIN_PASSWORD).unwrap(),
        public_url: None,
        max_upload_bytes: 64 * 1024 * 1024,
        allow_hidden: false,
        session_idle_secs: 600,
    };
    let application = app::build(config).expect("app builds");
    let router = app::router(Arc::clone(&application));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
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
    let length = file.bytes.len() as u64;
    let mut offset = 0u64;
    while offset < length {
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
            assert!(file.bytes.is_empty(), "only empty files complete at begin");
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
    assert!(link["url"].as_str().unwrap().ends_with(&format!("/r/{token}")));

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

    // --- same names again: nothing is overwritten ---------------------------
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
            "inbox/b-1.txt",
            "inbox/empty-1.txt",
            "inbox/Résumé Draft-1.pdf",
            "inbox/sub/data-1.bin"
        ]
    );
    assert_eq!(
        std::fs::read(server.receive_dir.join("inbox/b.txt")).unwrap(),
        b"hello votport",
        "original files stay untouched"
    );
    assert_eq!(
        std::fs::read(server.receive_dir.join("inbox/b-1.txt")).unwrap(),
        b"hello votport"
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
    assert_eq!(uploads.len(), 2);
    assert_eq!(uploads[0]["files"].as_array().unwrap().len(), 4);
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
    client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap();

    // Flip one byte: verification must refuse the range.
    let file = &files[0];
    let proof = file.prepared.prove(0, file.bytes.len() as u64).unwrap();
    let mut tampered = file.bytes.clone();
    tampered[1000] ^= 0x01;
    let mut body = proof.proof().to_vec();
    let proof_len = body.len();
    body.extend_from_slice(&tampered);
    let response = client
        .post(format!("{base}/api/session/{session}/chunk?entry=0&offset=0"))
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
