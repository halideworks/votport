//! Application state and router assembly.

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::response::{Html, IntoResponse as _};
use axum::routing::{get, post};
use axum::Router;
use tower_http::services::ServeDir;

use crate::api;
use crate::auth::LoginThrottle;
use crate::config::Config;
use crate::session::{self, Sessions};
use crate::store::Store;

pub struct App {
    pub config: Config,
    pub store: Arc<Store>,
    pub sessions: Sessions,
    pub secret: [u8; 32],
    /// Global throttle for the admin password endpoints.
    pub throttle: LoginThrottle,
    /// Per-IP throttle for public link password checks.
    pub link_throttle: crate::auth::IpThrottle,
}

pub fn build(config: Config) -> Result<Arc<App>, String> {
    // VOT refuses to stage files under a group-writable directory. On hosts
    // with umask 002 (Ubuntu user groups) every directory votport creates
    // would be 0775 and every upload would fail, so pin the umask here.
    #[cfg(unix)]
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
    std::fs::create_dir_all(&config.receive_dir)
        .map_err(|error| format!("create {}: {error}", config.receive_dir.display()))?;
    crate::paths::tighten_dir(&config.receive_dir);
    let store = Arc::new(Store::open(&config.data_dir)?);
    let secret = crate::auth::load_secret(&config.data_dir)?;
    Ok(Arc::new(App {
        store,
        sessions: Sessions::new(),
        secret,
        throttle: LoginThrottle::new(),
        link_throttle: crate::auth::IpThrottle::new(),
        config,
    }))
}

pub fn router(app: Arc<App>) -> Router {
    let web_root = app.config.web_root.clone();
    let admin_page = web_root.join("index.html");
    let request_page = web_root.join("request.html");

    let serve_page = |path: std::path::PathBuf| {
        get(move || {
            let path = path.clone();
            async move {
                match tokio::fs::read_to_string(&path).await {
                    Ok(contents) => Html(contents).into_response(),
                    Err(_) => (
                        axum::http::StatusCode::NOT_FOUND,
                        "page not found; is VOTPORT_WEB_ROOT set correctly?",
                    )
                        .into_response(),
                }
            }
        })
    };

    Router::new()
        // Pages.
        .route("/", serve_page(admin_page))
        .route("/r/{token}", serve_page(request_page))
        // no-cache means revalidate, not never-cache: repeat visits answer
        // conditional GETs with 304s instead of re-downloading the wasm and
        // the hero image, while a redeploy still takes effect immediately.
        .nest_service(
            "/assets",
            tower::ServiceBuilder::new()
                .layer(
                    tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                        axum::http::header::CACHE_CONTROL,
                        axum::http::HeaderValue::from_static("no-cache"),
                    ),
                )
                .service(ServeDir::new(web_root.join("assets"))),
        )
        // Admin API.
        .route("/api/admin/login", post(api::admin_login))
        .route("/api/admin/logout", post(api::admin_logout))
        .route("/api/admin/session", get(api::admin_session))
        .route("/api/admin/password", post(api::admin_change_password))
        .route(
            "/api/admin/links",
            get(api::list_links).post(api::create_link),
        )
        .route(
            "/api/admin/links/{id}",
            post(api::update_link).delete(api::delete_link),
        )
        // Public upload API.
        .route("/api/r/{token}", get(api::link_info))
        .route("/api/r/{token}/verify", post(api::verify_link_password))
        .route("/api/r/{token}/session", post(api::create_session))
        .route(
            "/api/session/{sid}/seal",
            post(api::upload_seal).layer(DefaultBodyLimit::max(session::MAX_SEAL_BYTES + 1024)),
        )
        .route(
            "/api/session/{sid}/page",
            post(api::upload_page).layer(DefaultBodyLimit::max(session::MAX_PAGE_BYTES + 1024)),
        )
        .route("/api/session/{sid}/begin", post(api::upload_begin))
        .route(
            "/api/session/{sid}/chunk",
            post(api::upload_chunk).layer(DefaultBodyLimit::max(session::MAX_CHUNK_BODY_BYTES)),
        )
        .route("/api/session/{sid}/finish", post(api::upload_finish))
        .route("/api/session/{sid}/abort", post(api::upload_abort))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(app)
}

/// Discards idle upload sessions so abandoned staging files get cleaned up.
pub async fn session_sweeper(app: Arc<App>) {
    let idle = app.config.session_idle_secs;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        app.sessions.sweep(idle);
    }
}
