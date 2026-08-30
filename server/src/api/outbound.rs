//! Verified, administrator-selected outbound files.

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::{ConnectInfo, Path as AxumPath, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, ReadBuf};
use tokio_util::io::ReaderStream;
use vot_receipt::SubjectKind;
use vot_sdk::object::{InMemoryObjectBuilder, ObjectId, Suite};

use super::{ApiError, ApiResult};
use crate::api::admin;
use crate::app::App;
use crate::auth;
use crate::store::{now_unix, OutboundGrant};

const MAX_ACTIVE: usize = 8;
const CHUNK: usize = 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;

#[derive(Deserialize)]
pub struct CreateOutboundRequest {
    link_id: String,
    upload_id: String,
    file_index: usize,
    #[serde(default)]
    label: Option<String>,
    #[serde(default = "default_expiry")]
    expires_days: u64,
}

const fn default_expiry() -> u64 {
    7
}

pub async fn list_outbound_grants(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_admin(&app, &headers)?;
    let grants = app
        .store
        .outbound_grants(&identity.tenant)
        .map_err(super::store_unavailable)?;
    Ok(Json(
        json!({ "grants": grants.into_iter().map(public_grant).collect::<Vec<_>>() }),
    ))
}

pub async fn create_outbound_grant(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<CreateOutboundRequest>,
) -> ApiResult<Response> {
    let identity = admin::require_admin(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    if !(1..=30).contains(&request.expires_days) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "expires_days must be 1..=30",
        ));
    }
    let _pin = app
        .sessions
        .try_pin_link(&request.link_id)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "link lifecycle update in progress"))?;
    let link = app
        .store
        .link(&identity.tenant, &request.link_id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let upload = link
        .uploads
        .iter()
        .find(|upload| upload.id == request.upload_id)
        .ok_or_else(ApiError::not_found)?;
    let file = upload
        .files
        .get(request.file_index)
        .ok_or_else(ApiError::not_found)?;
    if upload.completed_at == 0 || file.deleted || !file.receipt {
        return Err(ApiError::not_found());
    }
    let source = admin::stored_path(&app, &identity.tenant, &file.stored_as)
        .ok_or_else(ApiError::not_found)?;
    if !source.is_file() || !receipt_path(&source).is_file() {
        return Err(ApiError::not_found());
    }
    let label = request
        .label
        .unwrap_or_else(|| file.path.clone())
        .trim()
        .to_owned();
    if label.is_empty() || label.len() > 200 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "label must be 1..=200 characters",
        ));
    }
    let token = auth::random_token();
    let token_hash = hash_token(&token);
    let created_at = now_unix();
    let grant = OutboundGrant {
        id: auth::random_token(),
        tenant: identity.tenant.clone(),
        link_id: request.link_id,
        upload_id: request.upload_id,
        package_root: upload.package_root.clone(),
        name: file.path.clone(),
        suite: file.suite.clone(),
        root: file.root.clone(),
        file_index: request.file_index,
        bytes: file.bytes,
        label,
        token_hash,
        created_at,
        expires_at: created_at.saturating_add(request.expires_days * 86_400),
        revoked_at: None,
        downloads: 0,
    };
    app.store
        .insert_outbound_grant(grant.clone())
        .map_err(ApiError::internal)?;
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "outbound_grant_created",
        &grant.id,
        &json!({ "link": grant.link_id, "upload": grant.upload_id, "file_index": grant.file_index }),
    );
    let base = admin::base_url(&app, &headers);
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "grant": public_grant(grant), "url": format!("{base}/s/{token}") })),
    )
        .into_response())
}

pub async fn delete_outbound_grant(
    State(app): State<Arc<App>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = admin::require_admin(&app, &headers)?;
    admin::require_admin_write(&headers, &identity)?;
    if !app
        .store
        .revoke_outbound_grant(&identity.tenant, &id, now_unix())
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found());
    }
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "outbound_grant_revoked",
        &id,
        &json!({}),
    );
    Ok(Json(json!({ "ok": true })))
}

pub async fn outbound_metadata(
    State(app): State<Arc<App>>,
    AxumPath(token): AxumPath<String>,
) -> ApiResult<Response> {
    let grant = active_grant(&app, &token)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "label": grant.label,
            "name": grant.name,
            "suite": grant.suite,
            "root": grant.root,
            "bytes": grant.bytes,
            "length": grant.bytes,
            "package_root": grant.package_root,
            "expires_at": grant.expires_at,
            "downloads": grant.downloads,
            "receipt_key": app.signer.public_hex,
            "receipt_url": format!("/api/s/{token}/receipt"),
            "download_url": format!("/api/s/{token}/file")
        })),
    )
        .into_response())
}

pub async fn outbound_receipt(
    State(app): State<Arc<App>>,
    AxumPath(token): AxumPath<String>,
) -> ApiResult<Response> {
    let grant = active_grant(&app, &token)?;
    let source = source_info(&app, &grant)?;
    let path = receipt_path(&source.path);
    let mut bytes = Vec::new();
    tokio::fs::File::open(path)
        .await
        .map_err(|_| ApiError::not_found())?
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ApiError::not_found())?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(ApiError::not_found());
    }
    verify_receipt(&app, &bytes, &source.object).map_err(|_| ApiError::not_found())?;
    let filename = format!("{}.vot-receipt", safe_filename(&source.name));
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/cbor"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::try_from(format!("attachment; filename=\"{filename}\""))
            .map_err(|_| ApiError::internal("receipt filename invalid"))?,
    );
    Ok(response)
}

pub async fn outbound_file(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
) -> ApiResult<Response> {
    let grant = active_grant(&app, &token)?;
    let ip = super::client_ip(&headers, &peer, &app.config.trusted_proxies);
    if !app.outbound_rate.allow(&ip) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many downloads; try again later",
        ));
    }
    let active = ActiveDownload::claim(Arc::clone(&app), &grant.token_hash)?;
    let (stage, source) = prepare(&app, &grant).await?;
    let file = tokio::fs::File::open(&stage.path)
        .await
        .map_err(|_| ApiError::internal("open staged file failed"))?;
    if app.store.record_outbound_download(&grant.id).is_err() {
        return Err(ApiError::internal("record download failed"));
    }
    let stream = ReaderStream::new(OutboundReader {
        file,
        _stage: stage,
        _active: active,
    });
    let filename = safe_filename(&source.name);
    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("none"));
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(source.object.length),
    );
    let disposition = format!("attachment; filename=\"{filename}\"");
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::try_from(disposition)
            .map_err(|_| ApiError::internal("download filename invalid"))?,
    );
    Ok(response)
}

fn active_grant(app: &App, token: &str) -> ApiResult<OutboundGrant> {
    if !valid_token(token) {
        return Err(ApiError::not_found());
    }
    let grant = app
        .store
        .outbound_grant_by_token_hash(&hash_token(token))
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if grant.revoked_at.is_some() || grant.expires_at <= now_unix() {
        return Err(ApiError::not_found());
    }
    Ok(grant)
}

struct Source {
    path: PathBuf,
    object: ObjectId,
    name: String,
}

fn source_info(app: &App, grant: &OutboundGrant) -> ApiResult<Source> {
    let link = app
        .store
        .link(&grant.tenant, &grant.link_id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let upload = link
        .uploads
        .iter()
        .find(|upload| upload.id == grant.upload_id)
        .ok_or_else(ApiError::not_found)?;
    let file = upload
        .files
        .get(grant.file_index)
        .ok_or_else(ApiError::not_found)?;
    if upload.completed_at == 0
        || file.deleted
        || upload.package_root != grant.package_root
        || file.path != grant.name
        || file.suite != grant.suite
        || file.root != grant.root
        || file.bytes != grant.bytes
    {
        return Err(ApiError::not_found());
    }
    let root: [u8; 32] = hex::decode(&file.root)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(ApiError::not_found)?;
    let suite = match file.suite.as_str() {
        "blake3" => 1,
        "sha256" => 2,
        _ => return Err(ApiError::not_found()),
    };
    let path =
        admin::stored_path(app, &grant.tenant, &file.stored_as).ok_or_else(ApiError::not_found)?;
    Ok(Source {
        path,
        object: ObjectId {
            suite,
            root,
            length: file.bytes,
        },
        name: file.path.clone(),
    })
}

async fn prepare(app: &Arc<App>, grant: &OutboundGrant) -> ApiResult<(StagedFile, Source)> {
    let _pin = app
        .sessions
        .try_pin_link(&grant.link_id)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "link lifecycle update in progress"))?;
    if app.sessions.active_for_link(&grant.link_id) > 0 {
        return Err(ApiError::new(StatusCode::CONFLICT, "uploads are in flight"));
    }
    let source = source_info(app, grant)?;
    let stage_dir = app
        .config
        .data_dir
        .join("outbound.stage")
        .join(format!(".vot-outbound-{}", auth::random_token()));
    std::fs::create_dir_all(&stage_dir)
        .map_err(|_| ApiError::internal("create outbound stage failed"))?;
    let stage = StagedFile {
        path: stage_dir.join("file"),
    };
    let source_path = source.path.clone();
    let expected = source.object.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        let receipt = copy_verify(&source_path, &stage.path, expected)?;
        Ok::<_, io::Error>((stage, receipt))
    })
    .await
    .map_err(|_| ApiError::internal("outbound preparation failed"))?
    .map_err(|error| {
        tracing::warn!(%error, "outbound source verification failed");
        ApiError::not_found()
    })?;
    let (stage, receipt) = prepared;
    if verify_receipt(app, &receipt, &source.object).is_err() {
        return Err(ApiError::not_found());
    }
    Ok((stage, source))
}

fn copy_verify(source: &Path, stage: &Path, expected: ObjectId) -> io::Result<Vec<u8>> {
    use std::io::{Read, Write};
    let mut input = std::fs::File::open(source)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options.open(stage)?;
    let suite = Suite::try_from(expected.suite).map_err(|_| io::Error::other("suite"))?;
    let mut builder = InMemoryObjectBuilder::new(suite, Some(expected.length), expected.length)
        .map_err(|_| io::Error::other("builder"))?;
    let mut buf = vec![0u8; CHUNK];
    let mut receipt = Vec::new();
    loop {
        let count = input.read(&mut buf)?;
        if count == 0 {
            break;
        }
        builder
            .update(&buf[..count])
            .map_err(|_| io::Error::other("object"))?;
        output.write_all(&buf[..count])?;
    }
    let actual = builder.finish().map_err(|_| io::Error::other("object"))?;
    if actual.object_id() != &expected {
        return Err(io::Error::other("source mismatch"));
    }
    let mut sidecar = source.as_os_str().to_os_string();
    sidecar.push(".vot-receipt");
    std::fs::File::open(sidecar)?
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut receipt)?;
    if receipt.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(io::Error::other("receipt too large"));
    }
    Ok(receipt)
}

fn verify_receipt(app: &App, bytes: &[u8], object: &ObjectId) -> Result<(), ()> {
    let decoded = vot_receipt::decode_authenticated(bytes).map_err(|_| ())?;
    let verified =
        vot_receipt::verify_ed25519(&decoded, &app.signer.verifying_key()).map_err(|_| ())?;
    let receipt = verified.receipt();
    if receipt.subject_kind != SubjectKind::Object
        || receipt.suite_id != object.suite
        || receipt.subject_digest != object.root
        || receipt.subject_length != object.length
    {
        return Err(());
    }
    Ok(())
}

fn receipt_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".vot-receipt");
    value.into()
}
fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
fn valid_token(token: &str) -> bool {
    token.len() == 32 && token.as_bytes().iter().all(u8::is_ascii_hexdigit)
}
fn safe_filename(name: &str) -> String {
    let name = name.rsplit('/').next().unwrap_or(name);
    let mut value: String = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ' ') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if value.is_empty() || value == "." || value == ".." {
        value = "download.bin".to_owned();
    }
    value.chars().take(180).collect()
}
fn public_grant(grant: OutboundGrant) -> serde_json::Value {
    json!({ "id": grant.id, "tenant": grant.tenant, "link_id": grant.link_id, "upload_id": grant.upload_id, "file_index": grant.file_index, "name": grant.name, "label": grant.label, "created_at": grant.created_at, "expires_at": grant.expires_at, "revoked_at": grant.revoked_at, "downloads": grant.downloads })
}

struct ActiveDownload {
    app: Arc<App>,
    key: String,
}
impl ActiveDownload {
    fn claim(app: Arc<App>, key: &str) -> ApiResult<Self> {
        let mut active = app
            .outbound_active
            .lock()
            .expect("outbound active poisoned");
        if active.contains(key) || active.len() >= MAX_ACTIVE {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too many downloads in progress",
            ));
        }
        active.insert(key.to_owned());
        drop(active);
        Ok(Self {
            app,
            key: key.to_owned(),
        })
    }
}
impl Drop for ActiveDownload {
    fn drop(&mut self) {
        self.app
            .outbound_active
            .lock()
            .expect("outbound active poisoned")
            .remove(&self.key);
    }
}

struct StagedFile {
    path: PathBuf,
}
impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

struct OutboundReader {
    file: tokio::fs::File,
    _stage: StagedFile,
    _active: ActiveDownload,
}
impl AsyncRead for OutboundReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    use vot_sdk_file::PublishObservation;

    fn admin_cookie(app: &App) -> String {
        let token = auth::issue_admin_token(
            &app.secret,
            &auth::AdminIdentity::local_admin(),
            &app.config.admin_token_tag,
        );
        format!("votport_admin={token}")
    }

    async fn body(response: Response) -> serde_json::Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    async fn fixture() -> (tempfile::TempDir, Arc<App>, String, Vec<u8>) {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let bytes = b"outbound fixture".to_vec();
        let mut builder = InMemoryObjectBuilder::new(
            Suite::try_from(1).unwrap(),
            Some(bytes.len() as u64),
            bytes.len() as u64,
        )
        .unwrap();
        builder.update(&bytes).unwrap();
        let object = builder.finish().unwrap().object_id().clone();
        let source = app.config.receive_dir.join("received.bin");
        std::fs::write(&source, &bytes).unwrap();
        app.signer
            .write_sidecar(
                &source,
                &object,
                [1; 16],
                PublishObservation {
                    incarnation: [2; 16],
                    sequence: 1,
                },
            )
            .unwrap();
        app.store
            .insert_link(crate::store::Link {
                id: "link".to_owned(),
                label: "link".to_owned(),
                tenant: String::new(),
                dest: String::new(),
                password_hash: None,
                created_at: 1,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,
                uploads: vec![crate::store::UploadRecord {
                    id: "upload".to_owned(),
                    started_at: 1,
                    completed_at: 2,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: Some("http".to_owned()),
                    package_root: "package-root".to_owned(),
                    total_bytes: bytes.len() as u64,
                    files: vec![crate::store::FileRecord {
                        path: "received.bin".to_owned(),
                        stored_as: "received.bin".to_owned(),
                        bytes: object.length,
                        suite: "blake3".to_owned(),
                        root: hex::encode(object.root),
                        receipt: true,
                        deleted: false,
                    }],
                }],
                events: Vec::new(),
            })
            .unwrap();
        (directory, app.clone(), admin_cookie(&app), bytes)
    }

    #[test]
    fn tokens_are_strict() {
        assert!(valid_token(&"a".repeat(32)));
        assert!(!valid_token("x"));
        assert!(!valid_token(&"g".repeat(32)));
    }
    #[test]
    fn hashes_are_not_raw_tokens() {
        assert_ne!(hash_token("a"), "a");
    }
    #[test]
    fn filenames_are_single_safe_components() {
        assert_eq!(safe_filename("../a/b?.txt"), "b_.txt");
    }
    #[test]
    fn source_identity_mismatch_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let stage = directory.path().join("stage");
        std::fs::write(&source, b"payload").unwrap();
        let expected = ObjectId {
            suite: 1,
            root: [0; 32],
            length: 7,
        };
        assert!(copy_verify(&source, &stage, expected).is_err());
    }
    #[test]
    fn drop_guards_remove_stage_and_active_grant() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let stage = directory.path().join("stage").join("file");
        std::fs::create_dir_all(stage.parent().unwrap()).unwrap();
        std::fs::write(&stage, b"payload").unwrap();
        let staged = StagedFile {
            path: stage.clone(),
        };
        let active = ActiveDownload::claim(Arc::clone(&app), "grant").unwrap();
        drop((staged, active));
        assert!(!stage.exists());
        assert!(!app.outbound_active.lock().unwrap().contains("grant"));
    }

    #[tokio::test]
    async fn grant_flow_serves_verified_file_and_receipt_then_revokes() {
        let (_directory, app, cookie, expected_bytes) = fixture().await;
        let create = Request::post("/api/admin/outbound-grants")
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"link_id":"link","upload_id":"upload","file_index":0,"label":"fixture","expires_days":7}"#,
            ))
            .unwrap();
        let response = crate::app::router(app.clone())
            .oneshot(create)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let created = body(response).await;
        assert_eq!(created["grant"]["file_index"], 0);
        assert!(created["grant"].get("token_hash").is_none());
        let url = created["url"].as_str().unwrap();
        let token = url.rsplit('/').next().unwrap();
        assert_eq!(url, format!("https://drop.example.com/s/{token}"));
        let id = created["grant"]["id"].as_str().unwrap().to_owned();

        let metadata = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metadata.status(), StatusCode::OK);
        assert_eq!(metadata.headers()[header::CACHE_CONTROL], "no-store");
        let metadata = body(metadata).await;
        assert_eq!(metadata["bytes"], expected_bytes.len());
        assert_eq!(metadata["length"], expected_bytes.len());
        assert_eq!(metadata["suite"], "blake3");
        assert_eq!(metadata["name"], "received.bin");
        assert_eq!(metadata["root"].as_str().unwrap().len(), 64);
        assert_eq!(metadata["receipt_key"], app.signer.public_hex);
        assert_eq!(metadata["receipt_url"], format!("/api/s/{token}/receipt"));
        assert_eq!(metadata["download_url"], format!("/api/s/{token}/file"));

        let receipt = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/receipt"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(receipt.status(), StatusCode::OK);
        assert_eq!(
            receipt.into_body().collect().await.unwrap().to_bytes(),
            std::fs::read(app.config.receive_dir.join("received.bin.vot-receipt")).unwrap()
        );

        let file = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(file.status(), StatusCode::OK);
        assert_eq!(
            file.headers()[header::CONTENT_LENGTH],
            expected_bytes.len().to_string()
        );
        assert_eq!(
            file.into_body().collect().await.unwrap().to_bytes(),
            expected_bytes
        );

        std::fs::write(
            app.config.receive_dir.join("received.bin"),
            b"tampered fixture",
        )
        .unwrap();
        let tampered = crate::app::router(app.clone())
            .oneshot(
                Request::get(format!("/api/s/{token}/file"))
                    .extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 2))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tampered.status(), StatusCode::NOT_FOUND);
        assert!(app.outbound_active.lock().unwrap().is_empty());

        let conflict = crate::app::router(app.clone())
            .oneshot(
                Request::delete("/api/admin/links/link/uploads/upload/files/0")
                    .header("cookie", &cookie)
                    .header("x-votport", "1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

        let revoke = Request::delete(format!("/api/admin/outbound-grants/{id}"))
            .header("cookie", &cookie)
            .header("x-votport", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            crate::app::router(app.clone())
                .oneshot(revoke)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        for suffix in ["", "/receipt", "/file"] {
            let mut request = Request::get(format!("/api/s/{token}{suffix}"));
            if suffix == "/file" {
                request =
                    request.extension(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 1))));
            }
            assert_eq!(
                crate::app::router(app.clone())
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
    }
}
