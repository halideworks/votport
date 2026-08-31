//! votport: a password-protected file receive portal built on VOT.
//!
//! Copyright (c) 2026 David Torcivia. All rights reserved.
//!
//! This program is proprietary commercial software. See the VOTPORT
//! PROPRIETARY LICENSE for the applicable terms and lack of warranty.

use votport::{app, config};

#[tokio::main]
async fn main() {
    let mut arguments = std::env::args().skip(1);
    if arguments.next().as_deref() == Some("share") {
        if let Err(error) = share(arguments.collect()).await {
            eprintln!("{error}");
            std::process::exit(2);
        }
        return;
    }
    tracing_subscriber::fmt()
        // RUST_LOG wins; info is the right default for a deployed server.
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let config = match config::from_env() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!("{error}");
            std::process::exit(2);
        }
    };
    let bind = config.bind;
    let application = match app::build(config) {
        Ok(application) => application,
        Err(error) => {
            tracing::error!("{error}");
            std::process::exit(2);
        }
    };
    app::start_push_receiver(application.clone());
    tokio::spawn(app::session_sweeper(application.clone()));
    tokio::spawn(votport::backup::scheduler(application.clone()));
    let router = app::router(application.clone());
    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("bind {bind}: {error}");
            std::process::exit(2);
        }
    };
    tracing::info!(
        "votport listening on {bind}; receiving into {}",
        application.config.receive_dir.display()
    );
    // ConnectInfo carries the peer address to the per-IP link throttle.
    if let Err(error) = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(application.clone()))
    .await
    {
        tracing::error!("server error: {error}");
        std::process::exit(1);
    }
}

#[derive(Debug, PartialEq)]
struct ShareArgs {
    directory: String,
    expires_days: u64,
    label: Option<String>,
    max_downloads: Option<u64>,
}

fn parse_share_args(arguments: Vec<String>) -> Result<ShareArgs, String> {
    let mut directory = None;
    let mut expires_days = 7;
    let mut label = None;
    let mut max_downloads = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--expires" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--expires requires a value such as 7d".to_owned())?;
                let value = value.strip_suffix('d').unwrap_or(&value);
                expires_days = value
                    .parse::<u64>()
                    .map_err(|_| "--expires must be 1d through 30d".to_owned())?;
                if !(1..=30).contains(&expires_days) {
                    return Err("--expires must be 1d through 30d".to_owned());
                }
            }
            "--label" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--label requires a value".to_owned())?;
                if value.trim().is_empty() || value.len() > 200 {
                    return Err("--label must be 1 through 200 characters".to_owned());
                }
                label = Some(value);
            }
            "--max-downloads" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--max-downloads requires a value".to_owned())?;
                let value = value
                    .parse::<u64>()
                    .map_err(|_| "--max-downloads must be 1 through 10000".to_owned())?;
                if !(1..=10_000).contains(&value) {
                    return Err("--max-downloads must be 1 through 10000".to_owned());
                }
                max_downloads = Some(value);
            }
            value if value.starts_with('-') => return Err(format!("unknown option: {value}")),
            value if directory.is_none() => {
                if std::path::Path::new(value).is_absolute() {
                    return Err("share directory must be relative and cannot contain ..".to_owned());
                }
                directory = Some(value.trim_end_matches('/').to_owned());
            }
            _ => return Err("share accepts one server-relative directory".to_owned()),
        }
    }
    let directory = directory.filter(|value| !value.is_empty()).ok_or_else(|| {
        "usage: votport share <server-relative-directory> [--expires 7d] [--label LABEL] [--max-downloads N]".to_owned()
    })?;
    if std::path::Path::new(&directory)
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("share directory must be relative and cannot contain ..".to_owned());
    }
    Ok(ShareArgs {
        directory,
        expires_days,
        label,
        max_downloads,
    })
}

fn automation_url() -> Result<reqwest::Url, String> {
    let base = std::env::var("VOTPORT_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned());
    automation_url_from(&base)
}

fn automation_url_from(base: &str) -> Result<reqwest::Url, String> {
    let base =
        reqwest::Url::parse(base).map_err(|_| "VOTPORT_URL is not a valid URL".to_owned())?;
    let loopback_http = base.scheme() == "http"
        && base.host_str().is_some_and(|host| {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if (base.scheme() != "https" && !loopback_http)
        || !base.username().is_empty()
        || base.password().is_some()
    {
        return Err(
            "VOTPORT_URL must have no credentials and use HTTPS unless it is loopback".to_owned(),
        );
    }
    base.join("/api/automation/share")
        .map_err(|_| "VOTPORT_URL cannot form the share endpoint".to_owned())
}

async fn share(arguments: Vec<String>) -> Result<(), String> {
    let request = parse_share_args(arguments)?;
    let token = std::env::var("VOTPORT_AUTOMATION_TOKEN")
        .map_err(|_| "VOTPORT_AUTOMATION_TOKEN is required".to_owned())?;
    if token.len() != 32 || !token.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err("VOTPORT_AUTOMATION_TOKEN is invalid".to_owned());
    }
    let password = std::env::var("VOTPORT_SHARE_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30 * 60))
        .build()
        .map_err(|error| format!("create HTTP client: {error}"))?;
    let response = client
        .post(automation_url()?)
        .bearer_auth(token)
        .json(&serde_json::json!({
            "directory": request.directory,
            "expires_days": request.expires_days,
            "label": request.label,
            "password": password,
            "max_downloads": request.max_downloads,
        }))
        .send()
        .await
        .map_err(|error| format!("share request failed: {error}"))?;
    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|error| format!("share response was not JSON: {error}"))?;
    if !status.is_success() {
        return Err(body["error"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("share request failed ({status})")));
    }
    let url = body["url"]
        .as_str()
        .ok_or_else(|| "share response did not include a URL".to_owned())?;
    println!("{url}");
    Ok(())
}

async fn shutdown_signal(application: std::sync::Arc<votport::app::App>) {
    // Docker and systemd stop the process with SIGTERM; ctrl_c is SIGINT
    // only. Without this a container stop skips graceful shutdown entirely.
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
        _ = application.shutdown.notified() => {},
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn share_arguments_parse_the_documented_command() {
        assert_eq!(
            parse_share_args(vec![
                "project/render".to_owned(),
                "--expires".to_owned(),
                "14d".to_owned(),
                "--label".to_owned(),
                "Client delivery".to_owned(),
            ])
            .unwrap(),
            ShareArgs {
                directory: "project/render".to_owned(),
                expires_days: 14,
                label: Some("Client delivery".to_owned()),
                max_downloads: None,
            }
        );
    }

    #[test]
    fn share_arguments_reject_escape_and_bad_expiry() {
        assert!(parse_share_args(vec!["../project".to_owned()]).is_err());
        assert!(parse_share_args(vec!["/project".to_owned()]).is_err());
        assert!(parse_share_args(vec![
            "project".to_owned(),
            "--expires".to_owned(),
            "31d".to_owned(),
        ])
        .is_err());
        assert_eq!(
            parse_share_args(vec![
                "project".to_owned(),
                "--max-downloads".to_owned(),
                "1".to_owned(),
            ])
            .unwrap()
            .max_downloads,
            Some(1)
        );
        assert!(parse_share_args(vec![
            "project".to_owned(),
            "--max-downloads".to_owned(),
            "10001".to_owned(),
        ])
        .is_err());
    }

    #[test]
    fn automation_url_requires_https_except_on_loopback() {
        assert!(automation_url_from("https://files.example.com").is_ok());
        assert!(automation_url_from("http://127.0.0.1:8080").is_ok());
        assert!(automation_url_from("http://[::1]:8080").is_ok());
        assert!(automation_url_from("http://files.example.com").is_err());
        assert!(automation_url_from("https://user@files.example.com").is_err());
    }
}
