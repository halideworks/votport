//! `votport standby`: keeps a warm copy of a live instance's data directory.
//!
//! On an interval it pulls the live instance's replica archive (database
//! snapshot plus identity files), validates it, and stages it as the
//! pending restore that the next normal boot applies. Promotion is therefore
//! an ordinary `votport` start over this data directory. The standby never
//! opens the database or touches the receive root, so it holds neither
//! fence; the lease on the receive root is what stops it from being
//! promoted while the live instance is still serving.
//!
//! The RPO is the pull interval: links, settings, and resume records
//! written on the live instance after the last pull are lost on promotion,
//! and uploads in that window start over.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt as _;

pub const STATUS_FILE: &str = ".votport-standby-status.json";
const DEFAULT_INTERVAL_SECS: u64 = 60;

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub bind: std::net::SocketAddr,
    /// The live instance's public URL, scheme and host, no path.
    pub source: String,
    pub token: String,
    pub interval: Duration,
}

pub fn config_from_env() -> Result<Config, String> {
    config_from(|name| std::env::var(name).ok())
}

/// The bearer hands out the database and every identity key, so the source
/// must be https unless it is loopback.
fn admit_source(source: &str) -> Result<String, String> {
    let source = source.trim().trim_end_matches('/');
    // Userinfo would let a loopback-looking authority resolve elsewhere.
    if source.contains('@') {
        return Err("VOTPORT_STANDBY_SOURCE must not carry credentials".to_owned());
    }
    if source.starts_with("https://") {
        return Ok(source.to_owned());
    }
    let host = source
        .strip_prefix("http://")
        .ok_or("VOTPORT_STANDBY_SOURCE must be an https URL")?;
    let host = host.split('/').next().unwrap_or("");
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.split(']').next())
        .unwrap_or_else(|| host.split(':').next().unwrap_or(""));
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        Ok(source.to_owned())
    } else {
        Err("VOTPORT_STANDBY_SOURCE must be an https URL (plain http only for loopback)".to_owned())
    }
}

pub fn config_from(lookup: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
    let env = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());
    let source = env("VOTPORT_STANDBY_SOURCE")
        .ok_or("VOTPORT_STANDBY_SOURCE (the live instance's https URL) is required")?;
    let source = admit_source(&source)?;
    let token = env("VOTPORT_REPLICA_TOKEN")
        .ok_or("VOTPORT_REPLICA_TOKEN (the live instance's replica bearer) is required")?;
    let bind = env("VOTPORT_BIND")
        .unwrap_or_else(|| "0.0.0.0:8080".to_owned())
        .parse()
        .map_err(|error| format!("VOTPORT_BIND is not a socket address: {error}"))?;
    let interval =
        match env("VOTPORT_STANDBY_INTERVAL_SECS") {
            Some(value) => value.parse::<u64>().ok().filter(|secs| *secs >= 5).ok_or(
                "VOTPORT_STANDBY_INTERVAL_SECS must be a whole number of seconds, 5 or more",
            )?,
            None => DEFAULT_INTERVAL_SECS,
        };
    Ok(Config {
        data_dir: PathBuf::from(env("VOTPORT_DATA_DIR").unwrap_or_else(|| "/data".to_owned())),
        bind,
        source,
        token,
        interval: Duration::from_secs(interval),
    })
}

/// What the standby knows about its copy; written beside the data so a
/// promotion or an operator can read it, and served on /readyz.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Status {
    pub source: String,
    pub last_attempt_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub last_error: Option<String>,
    /// When the live instance built the copy that is staged now.
    pub archive_created_at: Option<u64>,
    pub schema_version: Option<u64>,
}

fn write_status(data_dir: &Path, status: &Status) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(status).map_err(|error| error.to_string())?;
    let temporary = data_dir.join(format!("{STATUS_FILE}.{}.tmp", crate::auth::random_token()));
    std::fs::write(&temporary, bytes)
        .and_then(|()| std::fs::rename(&temporary, data_dir.join(STATUS_FILE)))
        .map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            format!("write standby status: {error}")
        })
}

pub fn read_status(data_dir: &Path) -> Option<Status> {
    let bytes = std::fs::read(data_dir.join(STATUS_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// One pull: download, validate, replace the pending restore. Returns the
/// archive's manifest.
pub async fn pull_once(
    client: &reqwest::Client,
    config: &Config,
) -> Result<crate::backup::Manifest, String> {
    let mut response = client
        .get(format!("{}/api/replica", config.source))
        .bearer_auth(&config.token)
        .send()
        .await
        .map_err(|error| format!("replica request: {error}"))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!(
            "replica request answered {}",
            response.status().as_u16()
        ));
    }
    let download = config.data_dir.join(format!(
        ".votport-restore-{}.download",
        crate::auth::random_token()
    ));
    let _download_cleanup = crate::backup::CleanupPath::new(download.clone());
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&download)
        .await
        .map_err(|error| format!("create download: {error}"))?;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("replica download: {error}"))?
    {
        file.write_all(&chunk)
            .await
            .map_err(|error| format!("write download: {error}"))?;
    }
    file.sync_all()
        .await
        .map_err(|error| format!("sync download: {error}"))?;
    drop(file);

    let stage = config.data_dir.join(format!(
        ".votport-restore-stage-{}",
        crate::auth::random_token()
    ));
    std::fs::create_dir(&stage).map_err(|error| format!("create stage: {error}"))?;
    let mut stage_cleanup = crate::backup::CleanupPath::directory(stage.clone());
    crate::paths::tighten_private_dir(&stage)?;
    let manifest = {
        let download = download.clone();
        let stage = stage.clone();
        tokio::task::spawn_blocking(move || {
            crate::backup::validate_and_extract(&download, &stage, crate::store::SCHEMA_VERSION)
        })
        .await
        .map_err(|error| error.to_string())??
    };
    // The previous pull's stage is replaced, never applied twice.
    crate::backup::clear_pending_restore(&config.data_dir)?;
    crate::backup::write_pending_restore(&config.data_dir, &stage, manifest.clone())?;
    stage_cleanup.keep();
    Ok(manifest)
}

/// Removes what a pull killed mid-way left behind: downloads, and stage
/// directories the pending marker does not point at. The marker's own
/// stage is never touched, whatever phase it is in.
pub fn sweep_orphans(data_dir: &Path) -> Result<usize, String> {
    let keep = crate::backup::pending_restore_stage(data_dir);
    let mut removed = 0;
    for entry in std::fs::read_dir(data_dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir()
            && name.starts_with(".votport-restore-stage-")
            && keep.as_deref() != Some(name.as_str())
        {
            std::fs::remove_dir_all(entry.path()).map_err(|error| error.to_string())?;
            removed += 1;
        } else if kind.is_file()
            && name.starts_with(".votport-restore-")
            && name.ends_with(".download")
        {
            std::fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Runs pulls forever and serves /healthz and /readyz on the bind address.
pub async fn run(config: Config) -> Result<(), String> {
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|error| format!("create {}: {error}", config.data_dir.display()))?;
    crate::paths::tighten_private_dir(&config.data_dir).map_err(|error| error.to_string())?;
    match sweep_orphans(&config.data_dir) {
        Ok(0) => {}
        Ok(count) => tracing::info!(count, "removed leftovers of an interrupted pull"),
        Err(error) => tracing::warn!(%error, "leftover sweep failed"),
    }
    let status = Arc::new(Mutex::new(
        read_status(&config.data_dir).unwrap_or_default(),
    ));
    status.lock().expect("status poisoned").source = config.source.clone();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|error| format!("http client: {error}"))?;
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|error| format!("bind {}: {error}", config.bind))?;
    tracing::info!(
        source = %config.source,
        interval_secs = config.interval.as_secs(),
        "standby pulling replicas into {}",
        config.data_dir.display()
    );
    let server = axum::serve(
        listener,
        status_router(Arc::clone(&status), config.interval),
    );
    let puller = {
        let config = config.clone();
        let status = Arc::clone(&status);
        async move {
            let mut tick = tokio::time::interval(config.interval);
            loop {
                tick.tick().await;
                let now = crate::store::now_unix();
                {
                    let mut status = status.lock().expect("status poisoned");
                    status.last_attempt_at = Some(now);
                }
                match pull_once(&client, &config).await {
                    Ok(manifest) => {
                        tracing::info!(
                            created_at = manifest.created_at,
                            schema_version = manifest.schema_version,
                            "replica staged"
                        );
                        let mut status = status.lock().expect("status poisoned");
                        status.last_success_at = Some(crate::store::now_unix());
                        status.last_error = None;
                        status.archive_created_at = Some(manifest.created_at);
                        status.schema_version = Some(manifest.schema_version);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "replica pull failed");
                        status.lock().expect("status poisoned").last_error =
                            Some(error.chars().take(512).collect());
                    }
                }
                let snapshot = status.lock().expect("status poisoned").clone();
                if let Err(error) = write_status(&config.data_dir, &snapshot) {
                    tracing::warn!(%error, "standby status not written");
                }
            }
        }
    };
    tokio::select! {
        result = server => result.map_err(|error| format!("standby status server: {error}")),
        _ = puller => Ok(()),
    }
}

#[derive(Clone)]
struct StatusState {
    status: Arc<Mutex<Status>>,
    interval: Duration,
}

/// /healthz answers 200 while pulls are landing (within two intervals of
/// the last success); /readyz is always 503 with the copy's age, since a
/// standby never takes traffic.
pub fn status_router(status: Arc<Mutex<Status>>, interval: Duration) -> Router {
    Router::new()
        .route("/healthz", get(standby_healthz))
        .route("/readyz", get(standby_readyz))
        .with_state(StatusState { status, interval })
}

fn healthy(status: &Status, interval: Duration, now: u64) -> bool {
    status
        .last_success_at
        .is_some_and(|at| now.saturating_sub(at) <= interval.as_secs() * 2)
}

async fn standby_healthz(State(state): State<StatusState>) -> Response {
    let status = state.status.lock().expect("status poisoned").clone();
    if healthy(&status, state.interval, crate::store::now_unix()) {
        StatusCode::OK.into_response()
    } else {
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}

async fn standby_readyz(State(state): State<StatusState>) -> Response {
    let status = state.status.lock().expect("status poisoned").clone();
    let now = crate::store::now_unix();
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "ready": false,
            "standby": true,
            "source": status.source,
            "healthy": healthy(&status, state.interval, now),
            "last_success_at": status.last_success_at,
            "last_error": status.last_error,
            "archive_created_at": status.archive_created_at,
            "replica_lag_secs": status.archive_created_at.map(|at| now.saturating_sub(at)),
            "schema_version": status.schema_version,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    #[test]
    fn orphan_sweep_keeps_the_marked_stage_and_removes_the_rest() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path();
        std::fs::create_dir(data.join(".votport-restore-stage-live")).unwrap();
        std::fs::create_dir(data.join(".votport-restore-stage-orphan")).unwrap();
        std::fs::write(data.join(".votport-restore-abc.download"), b"x").unwrap();
        std::fs::write(data.join("keep.txt"), b"x").unwrap();
        let manifest = crate::backup::Manifest {
            version: crate::backup::VERSION,
            created_at: 1,
            schema_version: 1,
            entries: Vec::new(),
        };
        crate::backup::write_pending_restore(
            data,
            &data.join(".votport-restore-stage-live"),
            manifest,
        )
        .unwrap();
        assert_eq!(sweep_orphans(data).unwrap(), 2);
        assert!(data.join(".votport-restore-stage-live").exists());
        assert!(!data.join(".votport-restore-stage-orphan").exists());
        assert!(!data.join(".votport-restore-abc.download").exists());
        assert!(data.join("keep.txt").exists());
        assert_eq!(sweep_orphans(data).unwrap(), 0);
    }

    #[tokio::test]
    async fn status_routes_follow_the_last_success() {
        let status = Arc::new(Mutex::new(Status {
            source: "https://live.example".to_owned(),
            ..Status::default()
        }));
        let router = status_router(Arc::clone(&status), Duration::from_secs(60));
        let response = router
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "never pulled"
        );

        let now = crate::store::now_unix();
        {
            let mut status = status.lock().unwrap();
            status.last_success_at = Some(now - 30);
            status.archive_created_at = Some(now - 45);
            status.schema_version = Some(crate::store::SCHEMA_VERSION);
        }
        let response = router
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = router
            .clone()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["standby"], true);
        assert_eq!(json["healthy"], true);
        assert_eq!(json["archive_created_at"], now - 45);
        assert!(json["replica_lag_secs"].as_u64().unwrap() >= 45);

        status.lock().unwrap().last_success_at = Some(now - 121);
        let response = router
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "two intervals stale"
        );
    }

    #[test]
    fn config_needs_source_and_token_and_bounds_the_interval() {
        let parse = |pairs: &[(&str, &str)]| {
            let map: std::collections::HashMap<String, String> = pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect();
            config_from(|name| map.get(name).cloned())
        };
        let base = [
            ("VOTPORT_STANDBY_SOURCE", "https://live.example/"),
            ("VOTPORT_REPLICA_TOKEN", "t"),
        ];
        let config = parse(&base).unwrap();
        assert_eq!(
            config.source, "https://live.example",
            "trailing slash trimmed"
        );
        assert_eq!(config.interval, Duration::from_secs(60));
        assert_eq!(config.data_dir, PathBuf::from("/data"));

        assert!(parse(&[("VOTPORT_REPLICA_TOKEN", "t")])
            .unwrap_err()
            .contains("VOTPORT_STANDBY_SOURCE"));
        assert!(parse(&[("VOTPORT_STANDBY_SOURCE", "https://x")])
            .unwrap_err()
            .contains("VOTPORT_REPLICA_TOKEN"));
        for bad in [
            "ftp://x",
            "http://live.internal:8080",
            "http://10.0.0.5",
            "live.example",
            "http://127.0.0.1:8080@evil.example",
            "https://user:pass@live.example",
        ] {
            assert!(
                parse(&[
                    ("VOTPORT_STANDBY_SOURCE", bad),
                    ("VOTPORT_REPLICA_TOKEN", "t")
                ])
                .is_err(),
                "{bad}"
            );
        }
        for loopback in [
            "http://127.0.0.1:18080",
            "http://localhost",
            "http://[::1]:8080/",
        ] {
            assert!(
                parse(&[
                    ("VOTPORT_STANDBY_SOURCE", loopback),
                    ("VOTPORT_REPLICA_TOKEN", "t")
                ])
                .is_ok(),
                "{loopback}"
            );
        }
        let with_interval = |value: &str| {
            let mut pairs = base.to_vec();
            pairs.push(("VOTPORT_STANDBY_INTERVAL_SECS", value));
            parse(&pairs)
        };
        assert!(with_interval("4").is_err());
        assert!(with_interval("x").is_err());
        assert_eq!(with_interval("5").unwrap().interval, Duration::from_secs(5));

        let directory = tempfile::tempdir().unwrap();
        let status = Status {
            source: "s".to_owned(),
            last_error: Some("e".to_owned()),
            ..Status::default()
        };
        write_status(directory.path(), &status).unwrap();
        assert_eq!(
            read_status(directory.path()).unwrap().last_error.as_deref(),
            Some("e")
        );
        assert!(std::fs::read_dir(directory.path())
            .unwrap()
            .flatten()
            .all(|entry| entry.file_name() == STATUS_FILE));
    }
}
