//! The live instance's side of standby replication: a fresh backup archive
//! (database snapshot plus identity files) for a bearer the standby holds.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio_util::io::ReaderStream;

use crate::app::App;

use super::{ApiError, ApiResult};

pub const SCHEMA_HEADER: &str = "x-votport-schema-version";
pub const CREATED_HEADER: &str = "x-votport-archive-created-at";

/// Checks the replica bearer against the stored token, counting failures
/// per client like the SCIM bearer.
fn authorize(app: &App, headers: &HeaderMap, ip: &str) -> ApiResult<()> {
    let bucket = super::throttle_key(ip);
    let settings = app
        .store
        .resolved_settings(&app.config)
        .map_err(super::store_unavailable)?;
    if app.replica_throttle.locked(&bucket) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; wait a minute",
        ));
    }
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let ok = match (settings.replica_token.as_deref(), presented) {
        (Some(stored), Some(presented)) => super::scim::bearer_matches(stored, presented),
        _ => false,
    };
    if !ok {
        app.replica_throttle.claim(&bucket);
        tracing::warn!(target: "audit", event = "replica_unauthorized", %ip, "replica bearer refused");
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid bearer"));
    }
    app.replica_throttle.succeeded(&bucket);
    Ok(())
}

/// Streams a just-built archive. The file is unlinked once open so nothing
/// is left behind however the transfer ends.
pub async fn replica_archive(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
) -> ApiResult<Response> {
    let ip = super::client_ip(&headers, &peer, &app.config.trusted_proxies);
    authorize(&app, &headers, &ip)?;
    let guard = Arc::clone(&app.backup_lock)
        .try_lock_owned()
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "backup already running"))?;
    let stage = app.config.data_dir.join(format!(
        ".votport-replica-{}.tar",
        crate::auth::random_token()
    ));
    let store = Arc::clone(&app.store);
    let data_dir = app.config.data_dir.clone();
    // Build, open, and unlink in one blocking step that owns the lock: a
    // client that gives up mid-build cannot leave the archive (every
    // identity key in the clear) on disk or free the lock while the
    // snapshot is still being written.
    let (manifest, file) = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let manifest =
            crate::backup::create_archive(&store, &data_dir, &stage, crate::store::SCHEMA_VERSION)?;
        let file = std::fs::File::open(&stage).map_err(|error| format!("open archive: {error}"));
        let _ = std::fs::remove_file(&stage);
        Ok::<_, String>((manifest, file?))
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?
    .map_err(ApiError::internal)?;
    let file = tokio::fs::File::from_std(file);
    let len = file
        .metadata()
        .await
        .map_err(|error| ApiError::internal(format!("archive metadata: {error}")))?
        .len();
    tracing::info!(target: "audit", event = "replica_pulled", %ip, bytes = len, "replica archive served");
    app.store.audit(
        "",
        "replica",
        "replica_pulled",
        &ip,
        &json!({ "bytes": len, "created_at": manifest.created_at }),
    );
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-tar".to_owned()),
            (header::CONTENT_LENGTH, len.to_string()),
            (
                header::HeaderName::from_static(SCHEMA_HEADER),
                manifest.schema_version.to_string(),
            ),
            (
                header::HeaderName::from_static(CREATED_HEADER),
                manifest.created_at.to_string(),
            ),
        ],
        Body::from_stream(ReaderStream::new(file)),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use crate::api::testing;
    use crate::store::SettingWrite;

    const TOKEN: &str = "replica-secret";

    async fn pull(
        app: &Arc<App>,
        peer: [u8; 4],
        bearer: Option<&str>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::get("/api/replica")
            .extension(ConnectInfo(std::net::SocketAddr::from((peer, 4321))));
        if let Some(bearer) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        let response = crate::app::router(Arc::clone(app))
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, bytes.to_vec())
    }

    #[tokio::test]
    async fn replica_is_bearer_gated_throttled_and_streams_a_valid_archive() {
        let directory = tempfile::tempdir().unwrap();
        let app = testing::build(directory.path());
        let (status, _, _) = pull(&app, [10, 3, 0, 1], Some(TOKEN)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no token configured");
        app.store
            .put_settings(
                "test",
                &[(
                    "replica_token".to_owned(),
                    SettingWrite::Set(crate::api::scim::hash_bearer(TOKEN)),
                )],
            )
            .unwrap();
        let (status, _, _) = pull(&app, [10, 3, 0, 1], None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let mut seen_429 = false;
        for _ in 0..10 {
            let (status, _, _) = pull(&app, [10, 3, 0, 2], Some("wrong")).await;
            if status == StatusCode::TOO_MANY_REQUESTS {
                seen_429 = true;
                break;
            }
        }
        assert!(seen_429);

        let (status, headers, bytes) = pull(&app, [10, 3, 0, 1], Some(TOKEN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers[SCHEMA_HEADER].to_str().unwrap(),
            crate::store::SCHEMA_VERSION.to_string()
        );
        assert_eq!(
            headers[header::CONTENT_LENGTH].to_str().unwrap(),
            bytes.len().to_string()
        );
        let archive = directory.path().join("pulled.tar");
        std::fs::write(&archive, &bytes).unwrap();
        let extracted = directory.path().join(".votport-restore-stage-test");
        std::fs::create_dir(&extracted).unwrap();
        let manifest =
            crate::backup::validate_and_extract(&archive, &extracted, crate::store::SCHEMA_VERSION)
                .unwrap();
        assert!(manifest
            .entries
            .iter()
            .any(|entry| entry.name == "votport.db"));
        assert!(std::fs::read_dir(&app.config.data_dir)
            .unwrap()
            .flatten()
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".votport-replica-")));
        let rows = app.store.audit_export("", 0, 0, 100).unwrap();
        assert!(rows
            .iter()
            .any(|row| row.event == "replica_pulled" && row.subject == "10.3.0.1"));
    }
}
