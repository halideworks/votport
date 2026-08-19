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
    pub throttle: LoginThrottle,
}

pub fn build(config: Config) -> Result<Arc<App>, String> {
    std::fs::create_dir_all(&config.receive_dir)
        .map_err(|error| format!("create {}: {error}", config.receive_dir.display()))?;
    let store = Arc::new(Store::open(&config.data_dir)?);
    let secret = crate::auth::load_secret(&config.data_dir)?;
    Ok(Arc::new(App {
        store,
        sessions: Sessions::new(),
        secret,
        throttle: LoginThrottle::new(),
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
        .nest_service("/assets", ServeDir::new(web_root.join("assets")))
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
            post(api::upload_seal)
                .layer(DefaultBodyLimit::max(session::MAX_SEAL_BYTES + 1024)),
        )
        .route(
            "/api/session/{sid}/page",
            post(api::upload_page)
                .layer(DefaultBodyLimit::max(session::MAX_PAGE_BYTES + 1024)),
        )
        .route("/api/session/{sid}/begin", post(api::upload_begin))
        .route(
            "/api/session/{sid}/chunk",
            post(api::upload_chunk)
                .layer(DefaultBodyLimit::max(session::MAX_CHUNK_BODY_BYTES)),
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
