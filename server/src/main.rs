//! votport: a password-protected file receive portal built on VOT.
//!
//! Copyright (c) 2026 David Torcivia. All rights reserved.
//!
//! This program is proprietary commercial software. See the VOTPORT
//! PROPRIETARY LICENSE for the applicable terms and lack of warranty.

use votport::{app, config};

const BUILD_VERSION: &str = match option_env!("VOTPORT_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
const BUILD_REVISION: &str = match option_env!("VOTPORT_REVISION") {
    Some(revision) => revision,
    None => "unknown",
};

const HTTP_NATIVE_DRAIN: std::time::Duration = std::time::Duration::from_secs(240);

#[tokio::main]
async fn main() {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next();
    if command.as_deref() == Some("--version") {
        println!("votport {BUILD_VERSION} ({BUILD_REVISION})");
        return;
    }
    // Audit finding 407: a dead RTC boots before chrony corrects it, and
    // from that state every clock helper reads 0, every expiry test admits
    // anything, and healthz answers 200. The build date is a floor the wall
    // clock can never honestly predate, so refuse to start until the clock
    // is corrected; the supervisor restarts into a working clock.
    if votport::store::clock_predates_build(std::time::SystemTime::now()) {
        eprintln!(
            "the system clock reads earlier than this build ({} unix seconds); \
             refusing to start until the clock is corrected",
            votport::store::BUILD_UNIX_SECS
        );
        std::process::exit(2);
    }
    if command.as_deref() == Some("convert-schema35") {
        if let Err(error) = votport::store::conversion::command(arguments.collect()) {
            eprintln!("{error}");
            std::process::exit(2);
        }
        return;
    }
    if command.as_deref() == Some("share") {
        let arguments: Vec<String> = arguments.collect();
        let json = arguments.iter().any(|arg| arg == "--json");
        if let Err(error) = share(arguments).await {
            if json {
                println!("{}", error.json);
            } else {
                eprintln!("{}", error.human);
            }
            std::process::exit(error.exit_code);
        }
        return;
    }
    // RUST_LOG wins over the default (info with the audit target pinned).
    // VOTPORT_LOG_FORMAT=json emits one JSON object per line for log
    // pipelines; anything else keeps the human format. AUDIT_LOG routes
    // audit-target events to a dedicated append-only file instead of stdout.
    votport::logging::init();
    tracing::info!(
        version = BUILD_VERSION,
        revision = BUILD_REVISION,
        "votport starting"
    );
    config::warn_unknown_environment();
    if command.as_deref() == Some("standby") {
        let result = match votport::standby::config_from_env() {
            Ok(config) => votport::standby::run(config).await,
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            tracing::error!("{error}");
            std::process::exit(2);
        }
        return;
    }
    let config = match config::from_env() {
        Ok(config) => config,
        Err(error) => {
            tracing::error!("{error}");
            std::process::exit(2);
        }
    };
    let bind = config.bind;
    // Audit finding 553: bind before app::build opens the store. A long
    // migration then holds connections in the listen backlog and healthz
    // answers as soon as serving starts, instead of the port refusing
    // connections for the whole startup.
    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("bind {bind}: {error}");
            std::process::exit(2);
        }
    };
    let application = match app::build(config) {
        Ok(application) => application,
        Err(error) => {
            tracing::error!("{error}");
            std::process::exit(2);
        }
    };
    app::start_push_receiver(application.clone());
    app::start_serve(application.clone());
    tokio::spawn(app::session_sweeper(application.clone()));
    tokio::spawn(app::lease_keeper(application.clone()));
    tokio::spawn(app::upload_ended_notifier(application.clone()));
    tokio::spawn(votport::backup::scheduler(application.clone()));
    tokio::spawn(votport::api::trade::worker(application.clone()));
    tokio::spawn(votport::api::outbound::workflows::worker(
        application.clone(),
    ));
    tokio::spawn(votport::api::outbound::workflows::event_worker(
        application.clone(),
    ));
    tokio::spawn(votport::api::outbound::workflows::routes::control_worker(
        application.clone(),
    ));
    let router = app::router(application.clone());
    tracing::info!(
        "votport listening on {bind}; receiving into {}",
        application.config.receive_dir.display()
    );
    // ConnectInfo carries the peer address to the per-IP link throttle.
    // Keep the serve future owned while the same deadline also gives native
    // transfers a chance to finish. Tokio can bound cooperative waiting, but
    // it cannot interrupt a blocking VOT listener; process::exit below keeps
    // runtime destruction from joining those threads.
    let server = serve_http(listener, router, application.clone());
    if let Err(error) =
        app::drain_and_checkpoint(application.clone(), server, HTTP_NATIVE_DRAIN).await
    {
        tracing::error!("server error: {error}");
        std::process::exit(1);
    }
    // The shared helper kept the server future owned through native drain and
    // the checkpoint. Process exit releases both kernel locks without waiting
    // for NAS cleanup or blocking workers.
    std::process::exit(0);
}

/// Audit finding 280: the budget for receiving one request's head (request
/// line and headers). Slowloris-style half-sent requests are cut at this
/// deadline instead of holding the connection open forever.
const HTTP_HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Audit finding 280: axum::serve pins hyper's timeouts at their defaults,
/// so the accept loop is spelled out here. hyper 1.11's HTTP/1 server layer
/// exposes exactly one timeout knob, the header read deadline above; read,
/// write, and idle timeouts are enforced by the reverse proxy (see
/// Caddyfile.example) and by upload-session idleness. Peer addresses still
/// reach handlers as ConnectInfo, and the stop signal still drains live
/// connections gracefully through the same drain budget.
async fn serve_http(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    application: std::sync::Arc<votport::app::App>,
) -> Result<(), String> {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto;
    use hyper_util::service::TowerToHyperService;
    use tower::ServiceExt as _;

    let mut stopped = std::pin::pin!(app::shutdown_signal(application));
    let (signal_tx, signal_rx) = tokio::sync::watch::channel(());
    // Every accepted connection registers here so the stop branch can wait
    // for in-flight responses. The caller exits the process right after
    // serve_http returns, and handlers like the backup-restore POST answer
    // their own request_shutdown with a 200 that must reach the client first.
    let connections = tokio_util::task::TaskTracker::new();
    loop {
        tokio::select! {
            _ = stopped.as_mut() => {
                // Wake every connection's graceful shutdown (each clone has
                // already marked the initial value seen), then hold serve_http
                // open until each connection finishes its current response.
                // The drain budget bounds a stalled client; whatever is left
                // is abandoned to the process exit that follows.
                let _ = signal_tx.send(());
                connections.close();
                if tokio::time::timeout(HTTP_NATIVE_DRAIN, connections.wait())
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        remaining = connections.len(),
                        "graceful drain timed out; abandoning stalled connections"
                    );
                }
                return Ok(());
            }
            accepted = listener.accept() => {
                let (socket, peer) = accepted.map_err(|error| error.to_string())?;
                let mut stopped = signal_rx.clone();
                // A fresh watch clone has not observed the channel's initial
                // value, so changed() would resolve immediately and shut every
                // connection down at once. Mark the current value seen.
                let _ = stopped.borrow_and_update();
                let router = router.clone();
                connections.spawn(async move {
                    let mut builder = auto::Builder::new(TokioExecutor::new());
                    builder
                        .http1()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HTTP_HEADER_READ_TIMEOUT);
                    let service = TowerToHyperService::new(
                        router.map_request(move |mut request: hyper::Request<hyper::body::Incoming>| {
                            request
                                .extensions_mut()
                                .insert(axum::extract::ConnectInfo(peer));
                            request.map(axum::body::Body::new)
                        }),
                    );
                    let mut connection =
                        std::pin::pin!(builder.serve_connection_with_upgrades(
                            TokioIo::new(socket),
                            service
                        ));
                    loop {
                        tokio::select! {
                            result = connection.as_mut() => {
                                if let Err(error) = result {
                                    tracing::debug!(%peer, %error, "http connection error");
                                }
                                break;
                            }
                            _ = stopped.changed() => {
                                connection.as_mut().graceful_shutdown();
                            }
                        }
                    }
                });
            }
        }
    }
}

#[derive(Debug, PartialEq)]
struct ShareArgs {
    directory: String,
    expires_days: u64,
    label: Option<String>,
    max_downloads: Option<u64>,
    operation_id: Option<String>,
    json: bool,
}

fn parse_share_args(arguments: Vec<String>) -> Result<ShareArgs, String> {
    let mut directory = None;
    let mut expires_days = 7;
    let mut label = None;
    let mut max_downloads = None;
    let mut operation_id = None;
    let mut json = false;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--json" => json = true,
            "--operation-id" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--operation-id requires a value".to_owned())?;
                if value.is_empty()
                    || value.len() > 128
                    || matches!(value.as_str(), "." | "..")
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                {
                    return Err("--operation-id must contain 1..=128 letters, digits, dots, hyphens or underscores".to_owned());
                }
                operation_id = Some(value);
            }

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
        "usage: votport share <server-relative-directory> [--expires 7d] [--label LABEL] [--max-downloads N] [--operation-id ID] [--json]".to_owned()
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
        operation_id,
        json,
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

/// Share failures split into the two exit classes automation can act on:
/// a refusal (a local usage error or a 4xx-class server response) exits 1
/// because the request will not succeed as given, and a transport or
/// 5xx-class server failure exits 2 because a retry may succeed; success
/// stays 0. In `--json` mode a JSON error envelope is printed to stdout:
/// the server's response body verbatim when it answered, so its `error`,
/// `code`, `retryable` and `retry_after_seconds` fields survive; otherwise
/// an envelope with the same keys is minted locally.
struct ShareFailure {
    human: String,
    json: String,
    exit_code: i32,
}

impl ShareFailure {
    /// A usage error or missing credential: nothing was sent, or the server
    /// refused the request as malformed (4xx-class).
    fn refused(human: String) -> Self {
        let json = serde_json::json!({
            "error": human,
            "code": "invalid_request",
            "retryable": false,
        })
        .to_string();
        Self {
            human,
            json,
            exit_code: 1,
        }
    }

    /// The server could not be reached or answered outside the 4xx class.
    fn transport(human: String) -> Self {
        let json = serde_json::json!({
            "error": human,
            "code": "network_error",
            "retryable": true,
        })
        .to_string();
        Self {
            human,
            json,
            exit_code: 2,
        }
    }

    /// The server answered with an error status: print its body verbatim in
    /// `--json` mode, or wrap a non-JSON body in the same envelope shape.
    fn server_response(status: reqwest::StatusCode, body: String) -> Self {
        let parsed: Option<serde_json::Value> = serde_json::from_str(&body).ok();
        let json = parsed.as_ref().map(|_| body.clone()).unwrap_or_else(|| {
            serde_json::json!({
                "error": body,
                "code": "request_failed",
                "retryable": !status.is_client_error(),
            })
            .to_string()
        });
        let human = parsed
            .as_ref()
            .and_then(|value| value["error"].as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("share request failed ({status})"));
        let exit_code = if status.is_client_error() { 1 } else { 2 };
        Self {
            human,
            json,
            exit_code,
        }
    }
}

async fn share(arguments: Vec<String>) -> Result<(), ShareFailure> {
    let request = parse_share_args(arguments).map_err(ShareFailure::refused)?;
    let token = std::env::var("VOTPORT_AUTOMATION_TOKEN")
        .map_err(|_| ShareFailure::refused("VOTPORT_AUTOMATION_TOKEN is required".to_owned()))?;
    if !votport::auth::valid_hex(&token, 32) {
        return Err(ShareFailure::refused(
            "VOTPORT_AUTOMATION_TOKEN is invalid".to_owned(),
        ));
    }
    let password = std::env::var("VOTPORT_SHARE_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty());
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30 * 60))
        .build()
        .map_err(|error| ShareFailure::transport(format!("create HTTP client: {error}")))?;
    let response = client
        .post(automation_url().map_err(ShareFailure::refused)?)
        .bearer_auth(token)
        .json(&serde_json::json!({
            "directory": request.directory,
            "expires_days": request.expires_days,
            "label": request.label,
            "password": password,
            "max_downloads": request.max_downloads,
            "operation_id": request.operation_id,
        }))
        .send()
        .await
        .map_err(|error| ShareFailure::transport(format!("share request failed: {error}")))?;
    let status = response.status();
    let body = response.text().await.map_err(|error| {
        ShareFailure::transport(format!("share response was unreadable: {error}"))
    })?;
    if !status.is_success() {
        return Err(ShareFailure::server_response(status, body));
    }
    let reply: serde_json::Value = serde_json::from_str(&body).map_err(|error| {
        ShareFailure::transport(format!("share response was not JSON: {error}"))
    })?;
    let url = reply["url"].as_str().ok_or_else(|| {
        ShareFailure::transport("share response did not include a URL".to_owned())
    })?;
    if request.json {
        println!("{reply}");
    } else {
        println!("{url}");
    }
    Ok(())
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
                "--operation-id".to_owned(),
                "render-001".to_owned(),
                "--json".to_owned(),
            ])
            .unwrap(),
            ShareArgs {
                directory: "project/render".to_owned(),
                expires_days: 14,
                label: Some("Client delivery".to_owned()),
                max_downloads: None,
                operation_id: Some("render-001".to_owned()),
                json: true,
            }
        );
    }

    #[test]
    fn share_usage_names_operation_id_and_json() {
        // Audit 483: both flags are implemented, so the usage error must
        // name them alongside the rest.
        let error = parse_share_args(Vec::new()).unwrap_err();
        assert!(error.contains("--operation-id"), "{error}");
        assert!(error.contains("--json"), "{error}");
    }

    #[test]
    fn share_arguments_reject_escape_and_bad_expiry() {
        for id in ["", ".", "..", "x/y", "has space", &"a".repeat(129)] {
            assert!(parse_share_args(vec![
                "project".to_owned(),
                "--operation-id".to_owned(),
                id.to_owned(),
            ])
            .is_err());
        }
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

    #[test]
    fn share_failures_split_refusals_from_transport_failures() {
        // A 4xx-class refusal keeps the server envelope verbatim and exits 1.
        let refused = ShareFailure::server_response(
            reqwest::StatusCode::BAD_REQUEST,
            r#"{"error":"unknown directory","code":"not_found","retryable":false}"#.to_owned(),
        );
        assert_eq!(refused.exit_code, 1);
        assert_eq!(
            refused.json,
            r#"{"error":"unknown directory","code":"not_found","retryable":false}"#
        );
        assert_eq!(refused.human, "unknown directory");

        // A 5xx-class failure exits 2 and still prints the envelope.
        let server = ShareFailure::server_response(
            reqwest::StatusCode::BAD_GATEWAY,
            serde_json::json!({
                "error": "overloaded",
                "retryable": true,
                "retry_after_seconds": 30
            })
            .to_string(),
        );
        assert_eq!(server.exit_code, 2);
        assert!(server.json.contains("retry_after_seconds"));

        // A non-JSON body is wrapped in the documented envelope shape.
        let wrapped = ShareFailure::server_response(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "upstream unavailable".to_owned(),
        );
        assert_eq!(wrapped.exit_code, 2);
        let parsed: serde_json::Value = serde_json::from_str(&wrapped.json).unwrap();
        assert_eq!(parsed["code"], "request_failed");
        assert_eq!(parsed["retryable"], serde_json::json!(true));

        // Local usage refusals exit 1 with the documented envelope.
        let local = ShareFailure::refused("bad arguments".to_owned());
        assert_eq!(local.exit_code, 1);
        let parsed: serde_json::Value = serde_json::from_str(&local.json).unwrap();
        assert_eq!(parsed["code"], "invalid_request");
        assert_eq!(parsed["retryable"], serde_json::json!(false));

        // Transport failures exit 2 with the network envelope.
        let transport = ShareFailure::transport("connection reset".to_owned());
        assert_eq!(transport.exit_code, 2);
        let parsed: serde_json::Value = serde_json::from_str(&transport.json).unwrap();
        assert_eq!(parsed["code"], "network_error");
        assert_eq!(parsed["retryable"], serde_json::json!(true));
    }
}

/// Regression for the shutdown race behind the S3 CI flake: serve_http used
/// to return the moment the stop signal resolved, and the process exit that
/// follows cut the in-flight response off before it flushed. The connection
/// here parks inside the restore route's Json extractor (the same route whose
/// handler calls request_shutdown beside its 200) with its body half-sent
/// while the stop fires; the response must still be delivered in full, and
/// only then may serve_http resolve.
#[cfg(test)]
mod serve_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use votport::{app, auth, config};

    #[tokio::test]
    async fn serve_http_delivers_the_in_flight_response_through_a_graceful_stop() {
        let root = tempfile::tempdir().unwrap();
        let application = app::build(config::Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            push_bind: None,
            push_certificate: None,
            push_private_key: None,
            push_advertise: None,
            serve_bind: None,
            serve_advertise: None,
            data_dir: root.path().join("data"),
            receive_dir: root.path().join("received"),
            outbound_dir: root.path().join("outbound"),
            web_root: root.path().join("web"),
            admin_password_hash: auth::hash_password("correct-horse-battery").unwrap(),
            admin_token_tag: String::new(),
            smtp_host: None,
            smtp_port: 587,
            smtp_starttls: true,
            smtp_username: None,
            smtp_password: None,
            scim_token: None,
            replica_token: None,
            smtp_from: None,
            public_url: None,
            max_upload_bytes: 1024 * 1024,
            workflow_snapshot_bytes: 4 * 1024 * 1024,
            allow_hidden: false,
            session_idle_secs: 60,
            audit_retention_days: 400,
            upload_retention_days: 0,
            default_max_total_bytes: None,
            default_max_links: None,
            default_max_sessions: None,
            public_password_login: true,
            require_provisioning: false,
            metrics_token: None,
            max_total_sessions: 32,
            max_link_sessions: 8,
            sso_session_secs: 7 * 24 * 3600,
            trusted_proxies: Vec::new(),
            tenant_private_networks: Vec::new(),
            oidc: None,
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = app::router(Arc::clone(&application));
        let mut server = tokio::spawn(serve_http(listener, router, Arc::clone(&application)));

        // Half of a valid restore request: the extractor waits for the rest,
        // so the request is still in flight when the stop fires below.
        let mut connection = tokio::net::TcpStream::connect(address).await.unwrap();
        let body = br#"{"id":"x","source":"local"}"#;
        let (sent, withheld) = body.split_at(body.len() / 2);
        let request = format!(
            "POST /api/admin/backups/restore HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n",
            body.len()
        );
        connection.write_all(request.as_bytes()).await.unwrap();
        connection.write_all(sent).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        application.request_shutdown();
        // serve_http must still be draining the parked connection, not have
        // returned the instant the stop signal resolved.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut server)
                .await
                .is_err(),
            "serve_http returned while a connection was still in flight"
        );
        connection.write_all(withheld).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            connection.read_to_end(&mut response),
        )
        .await
        .expect("response did not complete after the stop")
        .unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 4"),
            "expected the request's own response, got: {response}"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .expect("serve_http did not finish after the drain")
                .is_ok(),
            "serve_http failed"
        );
    }
}
