//! Full-protocol test: a vot-sdk client (standing in for the browser wasm)
//! drives the votport HTTP API end to end, and the received files are
//! checked byte for byte on disk.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
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
    application: Arc<app::App>,
    push_address: Option<SocketAddr>,
    push_certificate_digest: Option<[u8; 32]>,
    _data: tempfile::TempDir,
    _received: tempfile::TempDir,
}

async fn start_server() -> TestServer {
    start_server_with_cap(64 * 1024 * 1024).await
}

async fn start_server_with_cap(max_upload_bytes: u64) -> TestServer {
    start_server_inner(max_upload_bytes, false).await
}

async fn start_push_server() -> TestServer {
    start_server_inner(64 * 1024 * 1024, true).await
}

async fn start_push_server_with_cap(max_upload_bytes: u64) -> TestServer {
    start_server_inner(max_upload_bytes, true).await
}

async fn start_push_server_with_idle(session_idle_secs: u64) -> TestServer {
    start_server_inner_with_idle(64 * 1024 * 1024, true, session_idle_secs).await
}

async fn start_server_inner(max_upload_bytes: u64, enable_push: bool) -> TestServer {
    start_server_inner_with_idle(max_upload_bytes, enable_push, 600).await
}

async fn start_server_inner_with_idle(
    max_upload_bytes: u64,
    enable_push: bool,
    session_idle_secs: u64,
) -> TestServer {
    start_server_custom(max_upload_bytes, enable_push, session_idle_secs, 32).await
}

async fn start_server_custom(
    max_upload_bytes: u64,
    enable_push: bool,
    session_idle_secs: u64,
    max_total_sessions: usize,
) -> TestServer {
    let data = tempfile::tempdir().expect("data dir");
    let received = tempfile::tempdir().expect("receive dir");
    start_server_in(
        data,
        received,
        max_upload_bytes,
        enable_push,
        session_idle_secs,
        max_total_sessions,
    )
    .await
}

impl TestServer {
    /// Shuts the server down the way main does, suspending in-flight upload
    /// sessions, and hands back its directories for [`boot`].
    async fn suspend(self) -> (tempfile::TempDir, tempfile::TempDir) {
        app::suspend_sessions(&self.application).await;
        (self._data, self._received)
    }

    async fn restart(self) -> TestServer {
        let (data, received) = self.suspend().await;
        boot(data, received).await
    }
}

/// Boots a fresh server over an earlier server's directories.
async fn boot(data: tempfile::TempDir, received: tempfile::TempDir) -> TestServer {
    start_server_in(data, received, 64 * 1024 * 1024, false, 600, 32).await
}

async fn start_server_in(
    data: tempfile::TempDir,
    received: tempfile::TempDir,
    max_upload_bytes: u64,
    enable_push: bool,
    session_idle_secs: u64,
    max_total_sessions: usize,
) -> TestServer {
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        push_bind: enable_push.then(|| "127.0.0.1:0".parse().unwrap()),
        push_certificate: None,
        push_private_key: None,
        push_advertise: None,
        data_dir: data.path().to_path_buf(),
        receive_dir: received.path().to_path_buf(),
        outbound_dir: data.path().join("outbound"),
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
        session_idle_secs,
        audit_retention_days: 400,
        upload_retention_days: 0,
        default_max_total_bytes: None,
        default_max_links: None,
        default_max_sessions: None,
        public_password_login: true,
        metrics_token: None,
        max_total_sessions,
        max_link_sessions: 8,
        sso_session_secs: 7 * 24 * 3600,
        trusted_proxies: Vec::new(),
        oidc: None,
    };
    let application = app::build(config).expect("app builds");
    if enable_push {
        app::start_push_receiver(Arc::clone(&application));
    }
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
    let (push_address, push_certificate_digest) = if enable_push {
        let identity = reqwest::Client::new()
            .get(format!("http://{addr}/api/push-identity"))
            .send()
            .await
            .expect("push identity request")
            .error_for_status()
            .expect("push identity status")
            .json::<Value>()
            .await
            .expect("push identity JSON");
        let address = identity["address"]
            .as_str()
            .expect("numeric push address")
            .parse()
            .expect("push address parses");
        let digest = hex::decode(
            identity["certificate_digest"]
                .as_str()
                .expect("push certificate digest"),
        )
        .expect("push certificate digest hex")
        .try_into()
        .expect("32-byte push certificate digest");
        (Some(address), Some(digest))
    } else {
        (None, None)
    };
    TestServer {
        base: format!("http://{addr}"),
        receive_dir: received.path().to_path_buf(),
        application,
        push_address,
        push_certificate_digest,
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

fn push_fixture(
    root: &std::path::Path,
    marker: u8,
) -> (PathBuf, vot_cli::PackageSummary, Vec<(String, Vec<u8>)>) {
    let source = root.join(format!("push-source-{marker}"));
    std::fs::create_dir_all(source.join("nested")).unwrap();
    let files = vec![
        ("a.bin".to_owned(), vec![marker; 300_000]),
        (
            "nested/b.bin".to_owned(),
            vec![marker.wrapping_add(1); 300_001],
        ),
    ];
    for (path, bytes) in &files {
        std::fs::write(source.join(path), bytes).unwrap();
    }
    let bundle = root.join(format!("push-bundle-{marker}"));
    let summary = vot_cli::build_bundle(&source, &bundle).unwrap();
    assert_eq!(summary.entries, files.len() as u64);
    (bundle, summary, files)
}

fn write_push_credentials(
    root: &std::path::Path,
    response: &Value,
    holder: &ed25519_dalek::SigningKey,
) -> (PathBuf, PathBuf) {
    let capability = root.join("capability.cbor");
    let holder_key = root.join("holder.key");
    let encoded = response["capability"].as_str().unwrap();
    std::fs::write(
        &capability,
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap(),
    )
    .unwrap();
    std::fs::write(
        &holder_key,
        format!("ed25519-secret:{}", hex::encode(holder.to_bytes())),
    )
    .unwrap();
    (capability, holder_key)
}

async fn push_bundle_blocking(
    server: &TestServer,
    bundle: &std::path::Path,
    capability: &std::path::Path,
    holder_key: &std::path::Path,
) -> Result<vot_cli::PackageSummary, String> {
    let address = server.push_address.expect("push address");
    let identity = server
        .push_certificate_digest
        .expect("push certificate digest");
    let bundle = bundle.to_owned();
    let capability = capability.to_owned();
    let holder_key = holder_key.to_str().unwrap().to_owned();
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            vot_cli::push_bundle(&bundle, address, &capability, &holder_key, identity)
                .map_err(|error| format!("{error:?}"))
        }),
    )
    .await
    .map_err(|_| "push timed out".to_owned())?
    .map_err(|error| format!("push task failed: {error}"))?
}

async fn create_open_link(
    client: &reqwest::Client,
    base: &str,
    label: &str,
    dest: &str,
    max_bytes: Option<u64>,
) -> String {
    let response = client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = match max_bytes {
        Some(max_bytes) => json!({ "label": label, "dest": dest, "max_bytes": max_bytes }),
        None => json!({ "label": label, "dest": dest }),
    };
    let response = client
        .post(format!("{base}/api/admin/links"))
        .header("X-Votport", "1")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn preflight_push(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    holder: &ed25519_dalek::SigningKey,
    summary: vot_cli::PackageSummary,
) -> Value {
    let response = client
        .post(format!("{base}/api/r/{token}/push"))
        .json(&json!({
            "holder_key": hex::encode(holder.verifying_key().to_bytes()),
            "package": {
                "suite": 1,
                "root": hex::encode(summary.root),
                "length": summary.logical_length,
                "entries": summary.entries,
            }
        }))
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
    assert!(server
        .application
        .store
        .link_by_id(&token)
        .unwrap()
        .unwrap()
        .uploads
        .iter()
        .all(|upload| upload.transport.as_deref() == Some("http")));
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
async fn corrupt_events_fail_begin_before_destination() {
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
        .execute(
            "UPDATE links SET events_json = 'broken' WHERE id = ?1",
            [&token],
        )
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

/// Many small distinct ranges of one file, all in flight at once, must
/// reassemble byte for byte. This drives the parallel accept path: the
/// worker batches the flooded chunk channel and verifies plus writes the
/// ranges across scoped threads, so a batch of distinct ranges corrupting
/// the staged object or the published bytes fails here.
#[tokio::test(flavor = "multi_thread")]
async fn upload_session_is_recorded_at_begin_and_forgotten_at_finish() {
    let server = start_server().await;
    let base = &server.base;
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
        .header("x-votport", "1")
        .json(&json!({ "label": "resume" }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let bytes: Vec<u8> = (0..512 * 1024).map(|index| (index % 251) as u8).collect();
    let files = [prepare(vec!["resume.bin"], bytes)];
    let (announcement, pages, seal) = build_package(&files);
    let session = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": "", "package": announcement }))
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

    // Begin recorded the session so a restart could re-attach it.
    let recorded = server.application.store.load_upload_sessions().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].id, session);
    assert_eq!(recorded[0].link_id, token);
    assert_eq!(recorded[0].files.len(), 1);
    assert!(!recorded[0].files[0].published);

    upload_chunks(&client, base, &session, 0, &files[0]).await;
    let response = client
        .post(format!("{base}/api/session/{session}/finish"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    // A finished session leaves no resume record behind.
    assert!(server
        .application
        .store
        .load_upload_sessions()
        .unwrap()
        .is_empty());
}

/// Creates a link and a session, and pushes the seal and pages so the next
/// call is begin. Returns the link token and session id.
async fn open_session(
    client: &reqwest::Client,
    base: &str,
    label: &str,
    files: &[ClientFile],
) -> (String, String) {
    client
        .post(format!("{base}/api/admin/login"))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap();
    let token = client
        .post(format!("{base}/api/admin/links"))
        .header("x-votport", "1")
        .json(&json!({ "label": label }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (announcement, pages, seal) = build_package(files);
    let session = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": "", "package": announcement }))
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
    (token, session)
}

async fn begin(client: &reqwest::Client, base: &str, session: &str) -> (u16, Value) {
    let response = client
        .post(format!("{base}/api/session/{session}/begin"))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (
        status,
        response.json::<Value>().await.unwrap_or(Value::Null),
    )
}

/// Posts the one range of entry 0 starting at `offset`; returns status and body.
async fn post_chunk(
    client: &reqwest::Client,
    base: &str,
    session: &str,
    file: &ClientFile,
    offset: u64,
) -> (u16, Value) {
    post_chunk_entry(client, base, session, 0, file, offset).await
}

async fn post_chunk_entry(
    client: &reqwest::Client,
    base: &str,
    session: &str,
    entry: u64,
    file: &ClientFile,
    offset: u64,
) -> (u16, Value) {
    let length = file.bytes.len() as u64;
    let proof = file
        .prepared
        .prove(offset, CHUNK.min(length - offset))
        .unwrap();
    let start = proof.covered_offset() as usize;
    let end = start + proof.covered_length() as usize;
    let mut body = proof.proof().to_vec();
    let proof_len = body.len();
    body.extend_from_slice(&file.bytes[start..end]);
    let response = client
        .post(format!(
            "{base}/api/session/{session}/chunk?entry={entry}&offset={start}"
        ))
        .header("X-Votport-Proof", proof_len.to_string())
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (
        status,
        response.json::<Value>().await.unwrap_or(Value::Null),
    )
}

fn twenty_mib() -> ClientFile {
    let bytes: Vec<u8> = (0..20 * 1024 * 1024)
        .map(|index| (index * 7 % 251) as u8)
        .collect();
    prepare(vec!["resume.bin"], bytes)
}

fn staging_files(root: &std::path::Path) -> Vec<PathBuf> {
    std::fs::read_dir(root)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".vot-"))
        })
        .collect()
}

/// A restart keeps the contiguous prefix of an in-flight upload: the sender
/// learns it from begin (and from the rebegin flag on any earlier range
/// reply), re-sends from there, and the file publishes byte for byte.
#[tokio::test(flavor = "multi_thread")]
async fn upload_session_survives_a_restart() {
    let server = start_server().await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let files = [twenty_mib()];
    let file = &files[0];
    let (token, session) = open_session(&client, &server.base, "restart", &files).await;
    let base = server.base.clone();
    assert_eq!(begin(&client, &base, &session).await.0, 200);
    // Ranges 0 and 2 land; range 1 is still in flight when the server stops,
    // so the contiguous prefix is one range and range 2 is a hole.
    assert_eq!(post_chunk(&client, &base, &session, file, 0).await.0, 200);
    assert_eq!(
        post_chunk(&client, &base, &session, file, 2 * CHUNK)
            .await
            .0,
        200
    );
    let receive_dir = server.receive_dir.clone();
    assert_eq!(staging_files(&receive_dir).len(), 2, "staging and journal");

    let server = server.restart().await;
    let base = server.base.clone();
    assert_eq!(
        staging_files(&receive_dir).len(),
        2,
        "re-attached staging survives the boot sweep"
    );
    // The retried in-flight range is accepted and flagged: the session was
    // re-attached and the sender must begin again.
    let (status, progress) = post_chunk(&client, &base, &session, file, CHUNK).await;
    assert_eq!(status, 200, "{progress}");
    assert_eq!(progress["rebegin"], true);
    let (status, body) = begin(&client, &base, &session).await;
    assert_eq!(status, 200, "{body}");
    // The prefix is ranges 0 and 1; the hole at range 2 was dropped.
    assert_eq!(body["entries"][0]["covered_bytes"], 2 * CHUNK);
    assert_eq!(body["entries"][0]["complete"], false);
    let (status, progress) = post_chunk(&client, &base, &session, file, 2 * CHUNK).await;
    assert_eq!(status, 200, "{progress}");
    assert_eq!(progress["rebegin"], false);
    assert_eq!(progress["complete"], true);
    let finish = client
        .post(format!("{base}/api/session/{session}/finish"))
        .send()
        .await
        .unwrap();
    assert_eq!(finish.status(), 200, "{}", finish.text().await.unwrap());

    assert_eq!(
        std::fs::read(receive_dir.join("resume.bin")).unwrap(),
        file.bytes
    );
    assert!(receive_dir.join("resume.bin.vot-receipt").is_file());
    assert!(staging_files(&receive_dir).is_empty());
    assert!(server
        .application
        .store
        .load_upload_sessions()
        .unwrap()
        .is_empty());
    let uploads = server
        .application
        .store
        .uploads_by_id(&token)
        .unwrap()
        .unwrap();
    assert_eq!(uploads.len(), 1);
    assert!(uploads[0].files[0].receipt);
}

/// Staging corrupted while the process was down cannot publish: the resume
/// trusts the checkpointed prefix only as bookkeeping, and publish re-hashes
/// the staged object first.
#[tokio::test(flavor = "multi_thread")]
async fn restart_refuses_corrupted_staging() {
    let server = start_server().await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let files = [twenty_mib()];
    let file = &files[0];
    let (_token, session) = open_session(&client, &server.base, "corrupt", &files).await;
    let base = server.base.clone();
    assert_eq!(begin(&client, &base, &session).await.0, 200);
    assert_eq!(post_chunk(&client, &base, &session, file, 0).await.0, 200);
    let receive_dir = server.receive_dir.clone();
    let staging = server.application.store.load_upload_sessions().unwrap()[0].files[0]
        .staging_path
        .clone();

    let (data, received) = server.suspend().await;
    // Flip one byte inside the checkpointed prefix.
    let mut bytes = std::fs::read(&staging).unwrap();
    bytes[1024 * 1024] ^= 0xff;
    std::fs::write(&staging, &bytes).unwrap();
    let server = boot(data, received).await;
    let base = server.base.clone();

    let (status, body) = begin(&client, &base, &session).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["entries"][0]["covered_bytes"], CHUNK);
    assert_eq!(
        post_chunk(&client, &base, &session, file, CHUNK).await.0,
        200
    );
    // The last range completes coverage and triggers publish, which the
    // rehash refuses.
    let (status, body) = post_chunk(&client, &base, &session, file, 2 * CHUNK).await;
    assert_ne!(status, 200, "{body}");
    assert!(
        body["error"].as_str().unwrap_or("").contains("publish"),
        "{body}"
    );
    assert!(!receive_dir.join("resume.bin").exists());
    let finish = client
        .post(format!("{base}/api/session/{session}/finish"))
        .send()
        .await
        .unwrap();
    assert_ne!(finish.status(), 200);
}

/// A two-file session where the first file published before the restart:
/// the re-attach skips it, the second file resumes from its prefix, and the
/// finished upload records both files with receipts.
#[tokio::test(flavor = "multi_thread")]
async fn multi_file_session_survives_a_restart_after_one_file_published() {
    let server = start_server().await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let small: Vec<u8> = (0..3 * 1024 * 1024)
        .map(|index| (index % 239) as u8)
        .collect();
    let files = [prepare(vec!["first.bin"], small), twenty_mib()];
    let (token, session) = open_session(&client, &server.base, "multi", &files).await;
    let base = server.base.clone();
    assert_eq!(begin(&client, &base, &session).await.0, 200);
    // Entry 0 completes and publishes; entry 1 gets its first range only.
    upload_chunks(&client, &base, &session, 0, &files[0]).await;
    let receive_dir = server.receive_dir.clone();
    assert!(receive_dir.join("first.bin").is_file());
    let (status, progress) = post_chunk_entry(&client, &base, &session, 1, &files[1], 0).await;
    assert_eq!(status, 200, "{progress}");

    let server = server.restart().await;
    let base = server.base.clone();
    let (status, body) = begin(&client, &base, &session).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["entries"][0]["complete"], true);
    assert_eq!(body["entries"][1]["complete"], false);
    assert_eq!(body["entries"][1]["covered_bytes"], CHUNK);
    for offset in [CHUNK, 2 * CHUNK] {
        let (status, progress) =
            post_chunk_entry(&client, &base, &session, 1, &files[1], offset).await;
        assert_eq!(status, 200, "{progress}");
    }
    let finish = client
        .post(format!("{base}/api/session/{session}/finish"))
        .send()
        .await
        .unwrap();
    assert_eq!(finish.status(), 200, "{}", finish.text().await.unwrap());
    assert_eq!(
        std::fs::read(receive_dir.join("resume.bin")).unwrap(),
        files[1].bytes
    );
    let uploads = server
        .application
        .store
        .uploads_by_id(&token)
        .unwrap()
        .unwrap();
    assert_eq!(uploads.len(), 1);
    assert_eq!(uploads[0].files.len(), 2);
    assert!(uploads[0].files.iter().all(|file| file.receipt));
    assert!(staging_files(&receive_dir).is_empty());
}

/// A staging file shorter than its checkpointed prefix (power loss before
/// the data reached disk) is refused at boot: the record and staging go,
/// and the sender starts a fresh session.
#[tokio::test(flavor = "multi_thread")]
async fn restart_drops_a_truncated_staging_session() {
    let server = start_server().await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let files = [twenty_mib()];
    let file = &files[0];
    let (token, session) = open_session(&client, &server.base, "truncated", &files).await;
    let base = server.base.clone();
    assert_eq!(begin(&client, &base, &session).await.0, 200);
    assert_eq!(post_chunk(&client, &base, &session, file, 0).await.0, 200);
    let receive_dir = server.receive_dir.clone();
    let staging = server.application.store.load_upload_sessions().unwrap()[0].files[0]
        .staging_path
        .clone();

    let (data, received) = server.suspend().await;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&staging)
        .unwrap()
        .set_len(1024 * 1024)
        .unwrap();
    let server = boot(data, received).await;
    let base = server.base.clone();

    assert!(server
        .application
        .store
        .load_upload_sessions()
        .unwrap()
        .is_empty());
    assert!(
        staging_files(&receive_dir).is_empty(),
        "refused staging is swept"
    );
    assert_eq!(begin(&client, &base, &session).await.0, 404);
    // A fresh session over the same link completes normally.
    run_upload(&client, &base, &token, "", &files).await;
    assert_eq!(
        std::fs::read(receive_dir.join("resume.bin")).unwrap(),
        file.bytes
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_distinct_ranges_reassemble_byte_for_byte() {
    let server = start_server().await;
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
        .json(&json!({ "label": "parallel" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let token = response.json::<Value>().await.unwrap()["link"]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let mut bytes = vec![0u8; 4 * 1024 * 1024];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index * 31 % 250) as u8;
    }
    let files = [prepare(vec!["parallel.bin"], bytes.clone())];
    let (announcement, pages, seal) = build_package(&files);
    let session = client
        .post(format!("{base}/api/r/{token}/session"))
        .json(&json!({ "password": "", "package": announcement }))
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

    // 512 KiB ranges over a 4 MiB file flood the eight-deep channel, so the
    // worker sees full batches and accepts distinct ranges in parallel.
    let file = &files[0];
    let length = file.bytes.len() as u64;
    let mut requests = tokio::task::JoinSet::new();
    let mut offset = 0u64;
    while offset < length {
        let want = (512 * 1024u64).min(length - offset);
        let proof = file.prepared.prove(offset, want).expect("prove");
        let start = proof.covered_offset() as usize;
        let end = start + proof.covered_length() as usize;
        let mut body = proof.proof().to_vec();
        let proof_len = body.len();
        body.extend_from_slice(&file.bytes[start..end]);
        let client = client.clone();
        let url = format!("{base}/api/session/{session}/chunk?entry=0&offset={start}");
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
    let response = client
        .post(format!("{base}/api/session/{session}/finish"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
    assert_eq!(
        std::fs::read(server.receive_dir.join("parallel.bin")).unwrap(),
        bytes,
        "the file reassembled from parallel ranges matches the original"
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

/// Outbound throughput baseline, run explicitly. Uploads one 256 MiB library
/// file, issues a grant, and times the real HTTP download.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark; run explicitly"]
async fn throughput_outbound() {
    const MIB: usize = 1024 * 1024;
    let server = start_server_with_cap(512 * MIB as u64).await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    client
        .post(format!("{}/api/admin/login", server.base))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let mut bytes = vec![0u8; 256 * MIB];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index * 7 % 251) as u8;
    }
    let upload_started = std::time::Instant::now();
    client
        .post(format!(
            "{}/api/admin/outbound-files?path=benchmark.bin",
            server.base
        ))
        .header("x-votport", "1")
        .body(bytes)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let uploaded = upload_started.elapsed();
    let grant = client
        .post(format!("{}/api/admin/outbound-grants", server.base))
        .header("x-votport", "1")
        .json(&json!({ "paths": ["benchmark.bin"], "expires_days": 1 }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let token = grant["url"]
        .as_str()
        .and_then(|url| url.rsplit('/').next())
        .unwrap();
    let started = std::time::Instant::now();
    let response = client
        .get(format!("{}/api/s/{token}/file", server.base))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let received = response.bytes().await.unwrap();
    let downloaded = started.elapsed();
    let mib = |elapsed: std::time::Duration| format!("{:.0} MiB/s", 256.0 / elapsed.as_secs_f64());
    assert_eq!(received.len(), 256 * MIB);
    println!(
        "outbound upload 256 MiB: {uploaded:.3?} ({})",
        mib(uploaded)
    );
    println!(
        "outbound download 256 MiB: {downloaded:.3?} ({})",
        mib(downloaded)
    );
}

/// Batch counterpart to `throughput_outbound`: the same 256 MiB split across
/// VOTPORT_BENCH_FILES library files (default 1024), granted as a directory
/// and fetched through /batch twice, so the multi-file path can be compared
/// against the single-file number on the same host.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark; run explicitly"]
async fn throughput_outbound_batch() {
    const MIB: usize = 1024 * 1024;
    let count = load_knob("VOTPORT_BENCH_FILES", 1024);
    let each = 256 * MIB / count;
    let total = each * count;
    let server = start_server_with_cap(512 * MIB as u64).await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    client
        .post(format!("{}/api/admin/login", server.base))
        .json(&json!({ "password": ADMIN_PASSWORD }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let upload_started = std::time::Instant::now();
    for index in 0..count {
        let bytes: Vec<u8> = (0..each).map(|i| ((i + index) * 7 % 251) as u8).collect();
        client
            .post(format!(
                "{}/api/admin/outbound-files?path=batch/f{index:05}.bin",
                server.base
            ))
            .header("x-votport", "1")
            .body(bytes)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }
    let uploaded = upload_started.elapsed();
    let grant = client
        .post(format!("{}/api/admin/outbound-grants", server.base))
        .header("x-votport", "1")
        .json(&json!({ "directory": "batch", "expires_days": 1 }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let token = grant["url"]
        .as_str()
        .and_then(|url| url.rsplit('/').next())
        .unwrap();
    let mib = |elapsed: std::time::Duration| {
        format!(
            "{:.0} MiB/s",
            total as f64 / MIB as f64 / elapsed.as_secs_f64()
        )
    };
    println!(
        "outbound upload {count} x {} KiB: {uploaded:.3?} ({})",
        each / 1024,
        mib(uploaded)
    );
    for run in 1..=2 {
        let started = std::time::Instant::now();
        let mut response = client
            .get(format!("{}/api/s/{token}/batch", server.base))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let first = started.elapsed();
        let mut received = 0usize;
        while let Some(chunk) = response.chunk().await.unwrap() {
            received += chunk.len();
        }
        let downloaded = started.elapsed();
        assert_eq!(received, total);
        println!(
            "outbound batch run {run} {count} files {} MiB: first byte {first:.3?}, total {downloaded:.3?} ({})",
            total / MIB,
            mib(downloaded)
        );
    }
}

/// Native-push counterpart to `throughput_baseline`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark; run explicitly"]
async fn throughput_push() {
    const MIB: usize = 1024 * 1024;
    let server = start_push_server_with_cap(512 * MIB as u64).await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let source = fixture.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let mut bytes = vec![0u8; 256 * MIB];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index * 7 % 251) as u8;
    }
    std::fs::write(source.join("benchmark.bin"), bytes).unwrap();

    let bundle = fixture.path().join("bundle");
    let started = std::time::Instant::now();
    let summary = vot_cli::build_bundle(&source, &bundle).unwrap();
    let packaged = started.elapsed();

    let token = create_open_link(&client, &server.base, "push benchmark", "", None).await;
    let holder = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    let response = preflight_push(&client, &server.base, &token, &holder, summary).await;
    let (capability, holder_key) = write_push_credentials(fixture.path(), &response, &holder);
    let started = std::time::Instant::now();
    push_bundle_blocking(&server, &bundle, &capability, &holder_key)
        .await
        .expect("native push succeeds");
    let pushed = started.elapsed();

    let mib = |elapsed: std::time::Duration| format!("{:.0} MiB/s", 256.0 / elapsed.as_secs_f64());
    println!("build bundle 256 MiB: {packaged:.3?} ({})", mib(packaged));
    println!("native push  256 MiB: {pushed:.3?} ({})", mib(pushed));
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

#[tokio::test(flavor = "multi_thread")]
async fn native_push_matches_http_storage_and_is_single_use() {
    let server = start_push_server().await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let (bundle, summary, files) = push_fixture(fixture.path(), 31);
    let token = create_open_link(&client, &server.base, "native push", "inbox", None).await;
    let holder = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
    let response = preflight_push(&client, &server.base, &token, &holder, summary).await;
    assert_eq!(
        response["address"],
        server.push_address.unwrap().to_string()
    );
    assert_eq!(
        response["certificate_digest"],
        hex::encode(server.push_certificate_digest.unwrap())
    );
    let metrics = client
        .get(format!("{}/metrics", server.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("votport_push_sessions_active 1\n"));
    let (capability, holder_key) = write_push_credentials(fixture.path(), &response, &holder);

    let pushed = push_bundle_blocking(&server, &bundle, &capability, &holder_key)
        .await
        .unwrap_or_else(|error| {
            let link = server.application.store.link_by_id(&token).unwrap();
            panic!(
                "native push succeeds: {error}; sessions={}; events={:?}",
                server.application.sessions.total(),
                link.map(|link| link.events)
            )
        });
    assert_eq!(pushed, summary);

    let link = server
        .application
        .store
        .link_by_id(&token)
        .unwrap()
        .unwrap();
    assert_eq!(link.uploads.len(), 1);
    let upload = &link.uploads[0];
    assert_eq!(upload.transport.as_deref(), Some("push"));
    assert_eq!(upload.package_root, hex::encode(summary.root));
    assert_eq!(upload.total_bytes, summary.logical_length);
    assert_eq!(upload.replayed_chunks, 0);
    assert_eq!(upload.rejected_chunks, 0);
    assert_eq!(upload.files.len(), files.len());
    let transferred_bytes = files
        .iter()
        .map(|(_, bytes)| bytes.len() as u64)
        .sum::<u64>();
    let metrics = client
        .get(format!("{}/metrics", server.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("votport_push_sessions_active 0\n"));
    assert!(metrics.contains(&format!("votport_push_bytes_total {transferred_bytes}\n")));
    for (path, bytes) in files {
        let record = upload
            .files
            .iter()
            .find(|record| record.path == path)
            .expect("file record");
        assert_eq!(record.stored_as, format!("inbox/{path}"));
        assert_eq!(record.bytes, bytes.len() as u64);
        assert!(record.receipt);
        assert!(!record.deleted);

        let destination = server.receive_dir.join(&record.stored_as);
        assert_eq!(std::fs::read(&destination).unwrap(), bytes);
        let sidecar = PathBuf::from(format!("{}.vot-receipt", destination.display()));
        let receipt = vot_receipt::decode_authenticated(&std::fs::read(sidecar).unwrap())
            .expect("receipt decodes");
        let verified =
            vot_receipt::verify_ed25519(&receipt, &server.application.signer.verifying_key())
                .expect("receipt verifies");
        assert_eq!(
            record.suite,
            match verified.receipt().suite_id {
                1 => "blake3",
                2 => "sha256",
                suite => panic!("unexpected suite {suite}"),
            }
        );
        assert_eq!(hex::encode(verified.receipt().subject_digest), record.root);
        assert_eq!(verified.receipt().subject_length, record.bytes);
    }

    let reused = push_bundle_blocking(&server, &bundle, &capability, &holder_key).await;
    assert!(reused.is_err(), "a push capability is single use");
    let metrics = client
        .get(format!("{}/metrics", server.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("votport_push_refused_total{reason=\"spent\"} 1\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn native_push_expired_capability_increments_metric() {
    let server = start_push_server_with_idle(1).await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let (bundle, summary, _) = push_fixture(fixture.path(), 81);
    let token = create_open_link(&client, &server.base, "expired push", "inbox", None).await;
    let holder = ed25519_dalek::SigningKey::from_bytes(&[81; 32]);
    let response = preflight_push(&client, &server.base, &token, &holder, summary).await;
    let (capability, holder_key) = write_push_credentials(fixture.path(), &response, &holder);

    tokio::time::sleep(Duration::from_secs(2)).await;
    let expired = push_bundle_blocking(&server, &bundle, &capability, &holder_key).await;
    assert!(expired.is_err(), "an expired push capability is refused");

    let metrics = client
        .get(format!("{}/metrics", server.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("votport_push_refused_total{reason=\"expired\"} 1\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn native_push_foreign_capability_increments_metric() {
    let server = start_push_server().await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let (bundle, summary, _) = push_fixture(fixture.path(), 82);
    let holder = ed25519_dalek::SigningKey::from_bytes(&[82; 32]);
    let foreign_issuer = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
    let foreign = vot_cli::authz::issue_push(
        "votport",
        &format!("votport:{}", server.push_address.unwrap()),
        &foreign_issuer,
        holder.verifying_key().to_bytes(),
        summary.root,
        summary.logical_length,
        vot_cli::authz::now_seconds().unwrap(),
        600,
    )
    .unwrap();
    let foreign_response = json!({
        "capability": base64::engine::general_purpose::STANDARD.encode(foreign),
    });
    let (capability, holder_key) =
        write_push_credentials(fixture.path(), &foreign_response, &holder);

    let refused = push_bundle_blocking(&server, &bundle, &capability, &holder_key).await;
    assert!(refused.is_err(), "a foreign capability is refused");

    let metrics = client
        .get(format!("{}/metrics", server.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("votport_push_refused_total{reason=\"capability\"} 1\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn native_push_root_mismatch_cleans_up_and_releases_quota() {
    let server = start_push_server().await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let (_bundle, summary, files) = push_fixture(fixture.path(), 51);
    let (wrong_bundle, wrong_summary, _) = push_fixture(fixture.path(), 61);
    assert_eq!(wrong_summary.logical_length, summary.logical_length);
    let token = create_open_link(
        &client,
        &server.base,
        "bad native push",
        "inbox",
        Some(summary.logical_length),
    )
    .await;
    let holder = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let response = preflight_push(&client, &server.base, &token, &holder, summary).await;
    let session = response["session"].as_str().unwrap().to_owned();
    let (capability, holder_key) = write_push_credentials(fixture.path(), &response, &holder);

    let failed = push_bundle_blocking(&server, &wrong_bundle, &capability, &holder_key).await;
    assert!(failed.is_err(), "a bundle with the wrong root is refused");

    let staging = server
        .receive_dir
        .join("inbox")
        .join(format!(".vot-push-{session}"));
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let link = server
                .application
                .store
                .link_by_id(&token)
                .unwrap()
                .unwrap();
            if server.application.sessions.total() == 0
                && link.uploads.is_empty()
                && !staging.exists()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("push cleanup completes");
    assert!(server
        .application
        .store
        .link_by_id(&token)
        .unwrap()
        .unwrap()
        .uploads
        .is_empty());
    for (path, _) in files {
        assert!(!server.receive_dir.join("inbox").join(path).exists());
    }
    assert!(!staging.exists());

    // The exact link cap was occupied by the failed session. A new preflight
    // succeeding proves both the session and its reserved bytes were released.
    let retry = preflight_push(&client, &server.base, &token, &holder, summary).await;
    let retry_session = retry["session"].as_str().unwrap();
    let response = client
        .post(format!("{}/api/session/{retry_session}/abort", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn native_push_abort_removes_partial_transfer() {
    let server = start_push_server().await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let source = fixture.path().join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("a-first.bin"), vec![83_u8; 1024 * 1024]).unwrap();
    std::fs::write(source.join("z-later.bin"), vec![84_u8; 32 * 1024 * 1024]).unwrap();
    let bundle = fixture.path().join("bundle");
    let summary = vot_cli::build_bundle(&source, &bundle).unwrap();
    let token = create_open_link(&client, &server.base, "aborted push", "inbox", None).await;
    let holder = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
    let response = preflight_push(&client, &server.base, &token, &holder, summary).await;
    let session = response["session"].as_str().unwrap().to_owned();
    let (capability, holder_key) = write_push_credentials(fixture.path(), &response, &holder);
    let staging = server
        .receive_dir
        .join("inbox")
        .join(format!(".vot-push-{session}"));

    let abort = async {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let first_complete = std::fs::read_dir(staging.join("objects"))
                    .into_iter()
                    .flatten()
                    .flatten()
                    .find(|entry| entry.metadata().is_ok_and(|meta| meta.len() == 1024 * 1024))
                    .and_then(|entry| std::fs::read(entry.path()).ok())
                    .is_some_and(|bytes| bytes.iter().all(|byte| *byte == 83));
                if first_complete {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("native push connects");
        client
            .post(format!("{}/api/session/{session}/abort", server.base))
            .send()
            .await
            .unwrap()
    };
    let (pushed, aborted) = tokio::join!(
        push_bundle_blocking(&server, &bundle, &capability, &holder_key),
        abort
    );
    assert_eq!(aborted.status(), 200);
    assert!(pushed.is_err(), "aborted push stops the sender");

    tokio::time::timeout(Duration::from_secs(10), async {
        while server.application.sessions.total() != 0 || staging.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("aborted push cleanup completes");
    let link = server
        .application
        .store
        .link_by_id(&token)
        .unwrap()
        .unwrap();
    assert!(link.uploads.is_empty());
    assert_eq!(link.events.last().unwrap().outcome, "cancelled");
    assert!(link.events.last().unwrap().received_bytes > 0);
    assert!(!server.receive_dir.join("inbox/a-first.bin").exists());
    assert!(!server.receive_dir.join("inbox/z-later.bin").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn native_push_store_failure_rolls_back_published_files() {
    let server = start_push_server().await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let fixture = tempfile::tempdir().unwrap();
    let (bundle, summary, files) = push_fixture(fixture.path(), 91);
    let token = create_open_link(&client, &server.base, "failed push commit", "inbox", None).await;
    let holder = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
    let response = preflight_push(&client, &server.base, &token, &holder, summary).await;
    let session = response["session"].as_str().unwrap().to_owned();
    let (capability, holder_key) = write_push_credentials(fixture.path(), &response, &holder);
    rusqlite::Connection::open(server._data.path().join("votport.db"))
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_push_record
             BEFORE UPDATE OF uploads_json ON links
             BEGIN SELECT RAISE(FAIL, 'blocked push record'); END;",
        )
        .unwrap();

    let pushed = push_bundle_blocking(&server, &bundle, &capability, &holder_key).await;
    assert!(pushed.is_err(), "store failure rejects native push");

    let staging = server
        .receive_dir
        .join("inbox")
        .join(format!(".vot-push-{session}"));
    tokio::time::timeout(Duration::from_secs(10), async {
        while server.application.sessions.total() != 0 || staging.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("failed push cleanup completes");
    assert!(server
        .application
        .store
        .link_by_id(&token)
        .unwrap()
        .unwrap()
        .uploads
        .is_empty());
    for (path, _) in files {
        let destination = server.receive_dir.join("inbox").join(path);
        assert!(!destination.exists());
        assert!(!PathBuf::from(format!("{}.vot-receipt", destination.display())).exists());
    }
}

// ---------------------------------------------------------------------------
// Concurrent load rig. `throughput_baseline` above stays the single-stream
// regression baseline; this test is the concurrency instrument. See
// docs/load-testing.md for how to run it and read the output.
// ---------------------------------------------------------------------------

/// Per-worker timings: time to the first server response, then to completion.
type WorkerResult = Result<(Duration, Duration), String>;

/// Workers tagged by direction so the mixed phase reports both sides.
type LoadSet = tokio::task::JoinSet<(bool, WorkerResult)>;

/// A hashed file with its announcement, pages, and seal, keyed by worker.
type PreparedUpload = (usize, ClientFile, (Value, Vec<Vec<u8>>, Vec<u8>));

fn load_knob(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be an integer, got {value:?}")),
        Err(_) => default,
    }
}

/// Deterministic per-run content: a rolling pattern with the salt stamped
/// into the first bytes, so no two workers (or runs) ever share a root and
/// dedupe-at-begin cannot skip the transfer.
fn load_pattern(mib: usize, salt: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; mib * 1024 * 1024];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = ((index as u64).wrapping_add(salt) % 251) as u8;
    }
    bytes[..8].copy_from_slice(&salt.to_le_bytes());
    bytes
}

/// Synthetic sender address, honored when the server sees a private or
/// loopback peer and no proxy appended its own entry. Spreads workers across
/// the per-IP session-creation throttle so the rig measures contention, not
/// the rate limiter.
fn load_ip(worker: usize) -> String {
    format!("10.108.{}.{}", worker / 250, worker % 250 + 1)
}

async fn ok200(request: reqwest::RequestBuilder, phase: &str) -> Result<reqwest::Response, String> {
    let response = request
        .send()
        .await
        .map_err(|error| format!("{phase}: {error}"))?;
    let status = response.status();
    if status != reqwest::StatusCode::OK {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("{phase}: {status} {body}"));
    }
    Ok(response)
}

/// One upload session: create, seal, pages, begin, chunks with eight ranges
/// in flight (matching the real sender), finish. First response time is the
/// session create; a failed session is aborted so it does not linger against
/// the target's caps.
async fn load_upload_session(
    client: reqwest::Client,
    base: String,
    token: String,
    ip: String,
    file: ClientFile,
    package: (Value, Vec<Vec<u8>>, Vec<u8>),
) -> WorkerResult {
    let (announcement, pages, seal) = package;
    let started = std::time::Instant::now();
    let response = ok200(
        client
            .post(format!("{base}/api/r/{token}/session"))
            .header("x-forwarded-for", &ip)
            .json(&json!({ "package": announcement })),
        "session create",
    )
    .await?;
    let first_response = started.elapsed();
    let session = response
        .json::<Value>()
        .await
        .map_err(|error| format!("session create: {error}"))?["session"]
        .as_str()
        .ok_or("session create: no session id")?
        .to_owned();

    let transfer = async {
        ok200(
            client
                .post(format!("{base}/api/session/{session}/seal"))
                .body(seal),
            "seal",
        )
        .await?;
        for page in pages {
            ok200(
                client
                    .post(format!("{base}/api/session/{session}/page"))
                    .body(page),
                "page",
            )
            .await?;
        }
        let begin = ok200(
            client.post(format!("{base}/api/session/{session}/begin")),
            "begin",
        )
        .await?
        .json::<Value>()
        .await
        .map_err(|error| format!("begin: {error}"))?;
        let entry = &begin["entries"][0];
        if entry["complete"].as_bool() == Some(true) {
            return Err("entry complete at begin (deduped); no bytes moved".to_owned());
        }
        let index = entry["index"].as_u64().ok_or("begin: no entry index")?;

        let length = file.bytes.len() as u64;
        let mut offset = 0u64;
        let mut inflight = tokio::task::JoinSet::new();
        loop {
            while offset < length && inflight.len() < 8 {
                let want = CHUNK.min(length - offset);
                let proof = file
                    .prepared
                    .prove(offset, want)
                    .map_err(|error| format!("prove: {error:?}"))?;
                let start = proof.covered_offset() as usize;
                let end = start + proof.covered_length() as usize;
                let mut body = proof.proof().to_vec();
                let proof_len = body.len();
                body.extend_from_slice(&file.bytes[start..end]);
                let request = client
                    .post(format!(
                        "{base}/api/session/{session}/chunk?entry={index}&offset={start}"
                    ))
                    .header("X-Votport-Proof", proof_len.to_string())
                    .body(body);
                inflight.spawn(async move { ok200(request, "chunk").await });
                offset = proof.covered_offset() + proof.covered_length();
            }
            match inflight.join_next().await {
                None => break,
                Some(joined) => {
                    joined.map_err(|error| format!("chunk task: {error}"))??;
                }
            }
        }
        ok200(
            client.post(format!("{base}/api/session/{session}/finish")),
            "finish",
        )
        .await?;
        Ok(())
    }
    .await;
    if transfer.is_err() {
        let _ = client
            .post(format!("{base}/api/session/{session}/abort"))
            .send()
            .await;
    }
    transfer.map(|()| (first_response, started.elapsed()))
}

/// One grant download, streamed and counted rather than buffered. First
/// response time is the arrival of the response headers.
async fn load_download(
    client: reqwest::Client,
    base: String,
    token: String,
    expected: u64,
    bound: Duration,
) -> WorkerResult {
    let started = std::time::Instant::now();
    let mut response = client
        .get(format!("{base}/api/s/{token}/file"))
        .timeout(bound)
        .send()
        .await
        .map_err(|error| format!("download: {error}"))?;
    if response.status() != reqwest::StatusCode::OK {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("download: {status} {body}"));
    }
    let first_response = started.elapsed();
    let mut received = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("download body: {error}"))?
    {
        received += chunk.len() as u64;
    }
    if received != expected {
        return Err(format!(
            "download: got {received} bytes, expected {expected}"
        ));
    }
    Ok((first_response, started.elapsed()))
}

#[derive(Default)]
struct PhaseStats {
    first_response: Vec<Duration>,
    complete: Vec<Duration>,
    errors: Vec<String>,
}

impl PhaseStats {
    fn record(&mut self, result: WorkerResult) {
        match result {
            Ok((first_response, complete)) => {
                self.first_response.push(first_response);
                self.complete.push(complete);
            }
            Err(error) => self.errors.push(error),
        }
    }
}

/// Joins every worker under one deadline. A wedged server fails the phase
/// here with a count of who finished, instead of hanging the test; the
/// error propagates so the caller can clean up before surfacing it.
async fn drain_phase(
    name: &str,
    mut set: LoadSet,
    deadline: Duration,
) -> Result<(PhaseStats, PhaseStats), String> {
    let total = set.len();
    let mut finished = 0usize;
    let started = std::time::Instant::now();
    let mut uploads = PhaseStats::default();
    let mut downloads = PhaseStats::default();
    loop {
        let stalled = || {
            format!(
                "{name} phase stalled: {finished}/{total} workers finished within \
                 {deadline:?}; the server is likely wedged (check votport_sessions_active \
                 and votport_http_requests_in_flight on /metrics)"
            )
        };
        let Some(remaining) = deadline.checked_sub(started.elapsed()) else {
            return Err(stalled());
        };
        match tokio::time::timeout(remaining, set.join_next()).await {
            Err(_) => return Err(stalled()),
            Ok(None) => break,
            Ok(Some(joined)) => {
                finished += 1;
                let (is_upload, result) = joined.expect("load worker task");
                if is_upload {
                    uploads.record(result);
                } else {
                    downloads.record(result);
                }
            }
        }
    }
    Ok((uploads, downloads))
}

fn print_phase(label: &str, workers: usize, file_mib: usize, wall: Duration, stats: &PhaseStats) {
    let percentile = |values: &[Duration], pct: usize| -> Duration {
        let mut sorted = values.to_vec();
        sorted.sort();
        sorted
            .get((sorted.len().saturating_sub(1)) * pct / 100)
            .copied()
            .unwrap_or(Duration::ZERO)
    };
    let ok = stats.complete.len();
    let rate = ok as f64 * file_mib as f64 / wall.as_secs_f64();
    println!(
        "{label:<14} {workers:>3} x {file_mib} MiB: {wall:.2?} wall, {rate:.1} MiB/s aggregate, \
         first-response p50 {:.1?} p95 {:.1?}, complete p50 {:.1?} p95 {:.1?}, {}/{workers} errors",
        percentile(&stats.first_response, 50),
        percentile(&stats.first_response, 95),
        percentile(&stats.complete, 50),
        percentile(&stats.complete, 95),
        stats.errors.len(),
    );
    for error in stats.errors.iter().take(3) {
        println!("    error: {error}");
    }
    if stats.errors.len() > 3 {
        println!("    ... and {} more", stats.errors.len() - 3);
    }
}

/// Hashes and packages one distinct file per worker, in parallel, before the
/// clock starts.
async fn prepare_load_files(
    sessions: usize,
    file_mib: usize,
    seed: u64,
    phase: u64,
) -> Vec<PreparedUpload> {
    let mut prep = tokio::task::JoinSet::new();
    for worker in 0..sessions {
        let salt = seed ^ (phase << 56) ^ ((worker as u64) << 40);
        // Distinct names: concurrent same-name uploads race on the suffix
        // and fail with 409, which would drown the numbers this rig is
        // after. The leak is a few bytes per worker in a test binary.
        let name: &'static str = Box::leak(format!("load-{phase}-{worker}.bin").into_boxed_str());
        prep.spawn_blocking(move || {
            let file = prepare(vec![name], load_pattern(file_mib, salt));
            let package = build_package(std::slice::from_ref(&file));
            (worker, file, package)
        });
    }
    let mut files = Vec::with_capacity(sessions);
    while let Some(joined) = prep.join_next().await {
        files.push(joined.expect("prepare task"));
    }
    files
}

/// What the run has created on the target so far, so cleanup can run even
/// when setup or a phase fails partway.
#[derive(Default)]
struct LoadArtifacts {
    links: Vec<String>,
    outbound_path: Option<String>,
    grant_ids: Vec<String>,
}

/// Removes what the run created on the target, on failed and stalled runs
/// included: revokes the grants, deletes the outbound file, the received
/// copies, and every seeded link. Best effort; a failure is printed, not
/// fatal.
async fn load_cleanup(admin: &reqwest::Client, base: &str, artifacts: &LoadArtifacts) {
    let mut failures = 0usize;
    let mut check = |ok: bool| {
        if !ok {
            failures += 1;
        }
    };
    for id in &artifacts.grant_ids {
        let response = admin
            .delete(format!("{base}/api/admin/outbound-grants/{id}"))
            .header("X-Votport", "1")
            .send()
            .await;
        check(response.is_ok_and(|response| response.status() == 200));
    }
    if let Some(outbound_path) = &artifacts.outbound_path {
        let response = admin
            .delete(format!(
                "{base}/api/admin/outbound-files?path={outbound_path}"
            ))
            .header("X-Votport", "1")
            .send()
            .await;
        check(response.is_ok_and(|response| response.status() == 200));
    }
    if !artifacts.links.is_empty() {
        // Received copies first, then the link records.
        let listing = match admin
            .get(format!("{base}/api/admin/links"))
            .send()
            .await
            .and_then(|response| response.error_for_status())
        {
            Ok(response) => response.json::<Value>().await.unwrap_or(Value::Null),
            Err(_) => Value::Null,
        };
        for link in &artifacts.links {
            let uploads = listing["links"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|entry| entry["id"] == json!(link))
                .and_then(|entry| entry["uploads"].as_array())
                .cloned()
                .unwrap_or_default();
            for upload in uploads {
                let Some(id) = upload["id"].as_str() else {
                    continue;
                };
                let count = upload["files"].as_array().map_or(0, Vec::len);
                for index in 0..count {
                    let response = admin
                        .delete(format!(
                            "{base}/api/admin/links/{link}/uploads/{id}/files/{index}"
                        ))
                        .header("X-Votport", "1")
                        .send()
                        .await;
                    check(response.is_ok_and(|response| response.status() == 200));
                }
            }
            let response = admin
                .delete(format!("{base}/api/admin/links/{link}"))
                .header("X-Votport", "1")
                .send()
                .await;
            check(response.is_ok_and(|response| response.status() == 200));
        }
    }
    if failures > 0 {
        println!("cleanup: {failures} deletions failed; artifacts may remain on the target");
    }
}

/// Concurrency instrument, run explicitly:
/// `cargo test --release --test e2e -- --ignored --nocapture concurrent_load`.
/// Three phases against one target: N concurrent upload sessions, M
/// concurrent grant downloads, then both at once. Knobs (all env):
/// VOTPORT_LOAD_TARGET (base URL; unset runs an in-process server),
/// VOTPORT_LOAD_ADMIN_PASSWORD (required with a target),
/// VOTPORT_LOAD_SESSIONS (16), VOTPORT_LOAD_DOWNLOADS (8),
/// VOTPORT_LOAD_FILE_MIB (64), VOTPORT_LOAD_TIMEOUT_SECS (600 per phase).
/// Errors are data (a 429 near the cap is the measurement, not a failure);
/// the test fails only when a phase stalls past its deadline or every worker
/// in a phase fails.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "load rig; run explicitly"]
async fn concurrent_load() {
    const MIB: u64 = 1024 * 1024;
    let sessions = load_knob("VOTPORT_LOAD_SESSIONS", 16);
    let downloads = load_knob("VOTPORT_LOAD_DOWNLOADS", 8);
    let file_mib = load_knob("VOTPORT_LOAD_FILE_MIB", 64).max(1);
    let deadline = Duration::from_secs(load_knob("VOTPORT_LOAD_TIMEOUT_SECS", 600) as u64);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos() as u64;

    let (base, admin_password, _local) = match std::env::var("VOTPORT_LOAD_TARGET") {
        Ok(target) => {
            let password = std::env::var("VOTPORT_LOAD_ADMIN_PASSWORD")
                .expect("VOTPORT_LOAD_ADMIN_PASSWORD is required when VOTPORT_LOAD_TARGET is set");
            (target.trim_end_matches('/').to_owned(), password, None)
        }
        Err(_) => {
            let server =
                start_server_custom((file_mib as u64 * 2 + 16) * MIB, false, 600, sessions + 8)
                    .await;
            let base = server.base.clone();
            (base, ADMIN_PASSWORD.to_owned(), Some(server))
        }
    };
    println!(
        "concurrent load target: {base} ({})",
        if _local.is_some() {
            "in-process"
        } else {
            "remote"
        }
    );

    let admin = reqwest::Client::builder()
        .cookie_store(true)
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap();
    let load = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap();

    let params = LoadParams {
        sessions,
        downloads,
        file_mib,
        deadline,
        seed,
    };
    let mut artifacts = LoadArtifacts::default();
    let result = run_load(
        &admin,
        &load,
        &base,
        &admin_password,
        &params,
        &mut artifacts,
    )
    .await;
    // Cleanup runs whatever happened, stall included; then the original
    // diagnosis surfaces.
    load_cleanup(&admin, &base, &artifacts).await;
    if let Err(error) = result {
        panic!("{error}");
    }
}

struct LoadParams {
    sessions: usize,
    downloads: usize,
    file_mib: usize,
    deadline: Duration,
    seed: u64,
}

/// The whole run against a chosen target, returning instead of panicking so
/// the caller can always clean up first.
async fn run_load(
    admin: &reqwest::Client,
    load: &reqwest::Client,
    base: &str,
    admin_password: &str,
    params: &LoadParams,
    artifacts: &mut LoadArtifacts,
) -> Result<(), String> {
    let LoadParams {
        sessions,
        downloads,
        file_mib,
        deadline,
        seed,
    } = *params;

    // --- setup: link for uploads, outbound file plus one grant per stream --
    ok200(
        admin
            .post(format!("{base}/api/admin/login"))
            .json(&json!({ "password": admin_password })),
        "admin login",
    )
    .await?;
    // One link per eight upload workers: sessions are capped at eight
    // concurrent per link, and the rig is after the process-wide cap, not
    // the per-link one.
    let mut links = Vec::new();
    for index in 0..sessions.div_ceil(8).max(1) {
        let link = ok200(
            admin
                .post(format!("{base}/api/admin/links"))
                .header("X-Votport", "1")
                .json(&json!({ "label": format!("load rig {index}"), "dest": "load-test" })),
            "create link",
        )
        .await?
        .json::<Value>()
        .await
        .map_err(|error| format!("create link: {error}"))?["link"]["id"]
            .as_str()
            .ok_or("create link: no id in response")?
            .to_owned();
        artifacts.links.push(link.clone());
        links.push(link);
    }

    let outbound_path = format!("load-rig-{seed:016x}.bin");
    let outbound_bytes = load_pattern(file_mib, seed ^ (2 << 56));
    let expected = outbound_bytes.len() as u64;
    ok200(
        admin
            .post(format!(
                "{base}/api/admin/outbound-files?path={outbound_path}"
            ))
            .header("X-Votport", "1")
            .timeout(deadline)
            .body(outbound_bytes),
        "outbound upload",
    )
    .await?;
    artifacts.outbound_path = Some(outbound_path.clone());
    let mut grants = Vec::with_capacity(downloads);
    for _ in 0..downloads {
        let created = ok200(
            admin
                .post(format!("{base}/api/admin/outbound-grants"))
                .header("X-Votport", "1")
                .json(&json!({ "paths": [outbound_path], "expires_days": 1 })),
            "create grant",
        )
        .await?
        .json::<Value>()
        .await
        .map_err(|error| format!("create grant: {error}"))?;
        artifacts.grant_ids.push(
            created["grant"]["id"]
                .as_str()
                .ok_or("create grant: no id in response")?
                .to_owned(),
        );
        grants.push(
            created["url"]
                .as_str()
                .and_then(|url| url.rsplit('/').next())
                .ok_or("create grant: no url in response")?
                .to_owned(),
        );
    }

    let spawn_uploads = |set: &mut LoadSet, files: Vec<PreparedUpload>, ip_offset: usize| {
        for (worker, file, package) in files {
            let client = load.clone();
            let base = base.to_owned();
            let token = links[worker % links.len()].clone();
            let ip = load_ip(ip_offset + worker);
            set.spawn(async move {
                (
                    true,
                    load_upload_session(client, base, token, ip, file, package).await,
                )
            });
        }
    };
    let spawn_downloads = |set: &mut LoadSet| {
        for token in &grants {
            let client = load.clone();
            let base = base.to_owned();
            let token = token.clone();
            set.spawn(async move {
                (
                    false,
                    load_download(client, base, token, expected, deadline).await,
                )
            });
        }
    };

    // --- phase 1: uploads ---------------------------------------------------
    let files = prepare_load_files(sessions, file_mib, seed, 0).await;
    let mut set = LoadSet::new();
    spawn_uploads(&mut set, files, 0);
    let started = std::time::Instant::now();
    let (up, _) = drain_phase("upload", set, deadline).await?;
    print_phase("upload", sessions, file_mib, started.elapsed(), &up);

    // --- phase 2: downloads -------------------------------------------------
    let mut set = LoadSet::new();
    spawn_downloads(&mut set);
    let started = std::time::Instant::now();
    let (_, down) = drain_phase("download", set, deadline).await?;
    print_phase("download", downloads, file_mib, started.elapsed(), &down);

    // --- phase 3: both at once ----------------------------------------------
    let files = prepare_load_files(sessions, file_mib, seed, 1).await;
    let mut set = LoadSet::new();
    spawn_uploads(&mut set, files, sessions);
    spawn_downloads(&mut set);
    let started = std::time::Instant::now();
    let (mixed_up, mixed_down) = drain_phase("mixed", set, deadline).await?;
    let wall = started.elapsed();
    print_phase("mixed upload", sessions, file_mib, wall, &mixed_up);
    print_phase("mixed download", downloads, file_mib, wall, &mixed_down);

    for (phase, workers, stats) in [
        ("upload", sessions, &up),
        ("download", downloads, &down),
        ("mixed upload", sessions, &mixed_up),
        ("mixed download", downloads, &mixed_down),
    ] {
        if workers > 0 && stats.complete.is_empty() {
            return Err(format!(
                "{phase} phase: every worker failed; first error: {:?}",
                stats.errors.first()
            ));
        }
    }
    Ok(())
}
