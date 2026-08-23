//! Application state and router assembly.

use std::sync::{Arc, Mutex};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse as _, Response};
use axum::routing::{get, post};
use axum::Router;
use std::fmt::Write as _;
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
    /// Counter for `admin_change_password`, which refuses when tripped.
    /// Reaching that endpoint needs a valid session, so a global bound there
    /// cannot be used to deny anyone. Sign-in has no global counter: refusing
    /// or delaying there was how the break-glass credential got denied.
    pub change_password_throttle: LoginThrottle,
    /// Per-IP throttle for admin sign-in. A separate map from
    /// `link_throttle` so public link guessing cannot consume an operator's
    /// sign-in budget, or the reverse.
    pub login_throttle: crate::auth::IpThrottle,
    /// argon2 budget for admin sign-in. Separate from the link budget below:
    /// sharing one meant a flood of link password guesses queued ahead of the
    /// operator, which is a lockout with extra steps. Holding the whole
    /// process to a few concurrent verifications is also the bound on guess
    /// rate, and unlike a counter it does not depend on the throttle key or
    /// refuse anybody.
    pub login_permits: Arc<tokio::sync::Semaphore>,
    /// argon2 budget for public link password checks.
    pub link_verify_permits: Arc<tokio::sync::Semaphore>,
    /// Per-IP throttle for public link password checks.
    pub link_throttle: crate::auth::IpThrottle,
    /// Per-IP rate limit on upload-session creation.
    pub session_rate: crate::api::session_rate::SessionRate,
    /// Per-IP rate limit on public receipt checks; a separate map so a
    /// verifier cannot starve upload creates and vice versa.
    pub verify_rate: crate::api::session_rate::SessionRate,
    /// Signs the `.vot-receipt` sidecars written next to received files.
    pub signer: Arc<crate::receipt::ReceiptSigner>,
    /// Outbound client for upload notifications.
    pub http: reqwest::Client,
    /// OIDC configuration when SSO is enabled; the client discovers lazily.
    pub sso_config: Option<crate::config::OidcConfig>,
    pub sso_client: SsoSlot,
}

const SSO_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

/// Concurrent argon2 verifications allowed per unauthenticated password path.
const VERIFY_PERMITS: usize = 2;

/// Process-local OIDC client. Success is sticky; failure cools down 30s.
pub struct SsoSlot<T = crate::api::sso::SsoClient> {
    inner: Mutex<SsoSlotState<T>>,
}

enum SsoSlotState<T> {
    Empty,
    Discovering,
    Ready(Arc<T>),
    Failed { at: std::time::Instant },
}

/// If the claiming task is cancelled mid-await, Discovering would stick
/// until restart. Drop records Failed so the next caller can retry.
struct DiscoveringClaim<'a, T> {
    slot: &'a SsoSlot<T>,
}

impl<T> Drop for DiscoveringClaim<'_, T> {
    fn drop(&mut self) {
        let mut guard = self.slot.inner.lock().expect("sso slot poisoned");
        if matches!(*guard, SsoSlotState::Discovering) {
            *guard = SsoSlotState::Failed {
                at: std::time::Instant::now(),
            };
        }
    }
}

impl<T> Default for SsoSlot<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SsoSlot<T> {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SsoSlotState::Empty),
        }
    }

    /// Non-blocking. Healthy only for Ready. Busy lock is not healthy.
    pub fn health_peek(&self) -> bool {
        self.inner
            .try_lock()
            .map(|guard| matches!(*guard, SsoSlotState::Ready(_)))
            .unwrap_or(false)
    }

    /// IdP await must not hold the slot lock.
    pub(crate) async fn get_or_discover_with<F, Fut>(&self, discover: F) -> Result<Arc<T>, ()>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, String>>,
    {
        {
            let mut guard = self.inner.lock().expect("sso slot poisoned");
            match &*guard {
                SsoSlotState::Ready(client) => return Ok(Arc::clone(client)),
                SsoSlotState::Failed { at } if at.elapsed() < SSO_COOLDOWN => return Err(()),
                SsoSlotState::Discovering => return Err(()),
                SsoSlotState::Empty | SsoSlotState::Failed { .. } => {
                    *guard = SsoSlotState::Discovering;
                }
            }
        }

        let _claim = DiscoveringClaim { slot: self };
        let result = discover().await;

        let mut guard = self.inner.lock().expect("sso slot poisoned");
        match result {
            Ok(client) => {
                if let SsoSlotState::Ready(existing) = &*guard {
                    return Ok(Arc::clone(existing));
                }
                let client = Arc::new(client);
                *guard = SsoSlotState::Ready(Arc::clone(&client));
                Ok(client)
            }
            Err(error) => {
                tracing::error!("SSO discovery failed: {error}");
                if let SsoSlotState::Ready(existing) = &*guard {
                    return Ok(Arc::clone(existing));
                }
                *guard = SsoSlotState::Failed {
                    at: std::time::Instant::now(),
                };
                Err(())
            }
        }
    }
}

impl SsoSlot {
    pub async fn get_or_discover(
        &self,
        config: &crate::config::OidcConfig,
        public_url: &str,
    ) -> Result<Arc<crate::api::sso::SsoClient>, ()> {
        self.get_or_discover_with(|| discover_sso(config, public_url))
            .await
    }
}

async fn discover_sso(
    config: &crate::config::OidcConfig,
    public_url: &str,
) -> Result<crate::api::sso::SsoClient, String> {
    let redirect = format!("{public_url}/api/admin/callback");
    crate::api::sso::SsoClient::discover(
        &config.issuer,
        &config.client_id,
        &config.client_secret,
        &redirect,
    )
    .await
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
    // Staging files from a previous crash or kill have no live session to
    // sweep them; remove them once at startup.
    crate::paths::clean_staging(&config.receive_dir);
    let store = Arc::new(Store::open(&config.data_dir)?);
    let secret = crate::auth::load_secret(&config.data_dir)?;
    let signer = Arc::new(crate::receipt::ReceiptSigner::load_or_create(
        &config.data_dir,
    )?);
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| format!("http client: {error}"))?;
    Ok(Arc::new(App {
        store,
        sessions: Sessions::new(),
        secret,
        change_password_throttle: LoginThrottle::new(),
        login_throttle: crate::auth::IpThrottle::new(),
        login_permits: Arc::new(tokio::sync::Semaphore::new(VERIFY_PERMITS)),
        link_verify_permits: Arc::new(tokio::sync::Semaphore::new(VERIFY_PERMITS)),
        link_throttle: crate::auth::IpThrottle::new(),
        session_rate: crate::api::session_rate::SessionRate::new(),
        verify_rate: crate::api::session_rate::SessionRate::new(),
        signer,
        http,
        sso_config: config.oidc.clone(),
        sso_client: SsoSlot::new(),
        config,
    }))
}

pub fn router(app: Arc<App>) -> Router {
    let web_root = app.config.web_root.clone();
    let admin_page = web_root.join("index.html");
    let request_page = web_root.join("request.html");
    let page = |name: &str| web_root.join(format!("{name}.html"));

    // Everything the pages load is same-origin (fonts are self-hosted in
    // /assets/fonts). wasm-unsafe-eval is what lets the browser compile the
    // verification engine; there is no JS eval anywhere.
    const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
        style-src 'self'; font-src 'self'; connect-src 'self'; \
        img-src 'self' data:; worker-src 'self'; \
        frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    // Request pages carry the secret link token in the URL; never let the
    // browser forward it as a referrer.
    const REFERRER_POLICY: &str = "no-referrer";

    let serve_page = |path: std::path::PathBuf| {
        get(move || {
            let path = path.clone();
            async move {
                match tokio::fs::read_to_string(&path).await {
                    Ok(contents) => (
                        [
                            (axum::http::header::CONTENT_SECURITY_POLICY, CSP),
                            (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                            (axum::http::header::REFERRER_POLICY, REFERRER_POLICY),
                            // Same policy as /assets: revalidate every visit so
                            // a redeploy takes effect immediately. Without any
                            // cache header a browser may replay a stale page,
                            // error card and all.
                            (axum::http::header::CACHE_CONTROL, "no-cache"),
                        ],
                        Html(contents),
                    )
                        .into_response(),
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
        .route("/verify", serve_page(page("verify")))
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
                .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
                    axum::http::header::REFERRER_POLICY,
                    axum::http::HeaderValue::from_static("no-referrer"),
                ))
                .service(ServeDir::new(web_root.join("assets"))),
        )
        // Admin API.
        .route("/api/admin/login", post(api::admin_login))
        .route("/api/admin/logout", post(api::admin_logout))
        .route("/api/admin/session", get(api::admin_session))
        .route("/api/admin/audit", get(api::admin_audit_export))
        .route("/api/admin/backup", get(api::backup_database))
        .route(
            "/api/admin/tenants",
            get(api::list_tenants).post(api::create_tenant),
        )
        .route(
            "/api/admin/settings",
            get(api::get_settings).put(api::put_settings),
        )
        .route(
            "/api/admin/tenants/{key}",
            axum::routing::patch(api::update_tenant).delete(api::delete_tenant),
        )
        .route("/api/admin/tenant", post(api::switch_tenant))
        .route("/api/admin/principals/revoke", post(api::revoke_principal))
        .route(
            "/api/admin/principals/unblock",
            post(api::unblock_principal),
        )
        .route("/api/admin/password", post(api::admin_change_password))
        .route(
            "/api/admin/links",
            get(api::list_links).post(api::create_link),
        )
        .route(
            "/api/admin/links/{id}",
            post(api::update_link).delete(api::delete_link),
        )
        .route("/api/admin/links/{id}/qr", get(api::link_qr))
        .route(
            "/api/admin/links/{id}/uploads/{upload}",
            axum::routing::delete(api::delete_upload_record),
        )
        .route(
            "/api/admin/links/{id}/uploads/{upload}/files/{index}",
            axum::routing::delete(api::delete_received_file),
        )
        .route("/metrics", axum::routing::get(metrics))
        // Multi-page admin: static shells; authz is enforced per API call.
        .route("/links", serve_page(page("links")))
        .route("/tenants", serve_page(page("tenants")))
        .route("/audit", serve_page(page("audit")))
        .route("/system", serve_page(page("system")))
        // SSO sign-in (phase 3 of docs/multi-tenancy.md).
        .route("/api/admin/sso", get(api::sso_available))
        .route("/api/admin/sso/start", get(api::sso_start))
        .route("/api/admin/callback", get(api::sso_callback))
        // Public upload API.
        .route("/api/r/{token}", get(api::link_info))
        .route("/api/receipt-key", get(api::receipt_key))
        .route(
            "/api/verify",
            post(api::verify_receipt).layer(DefaultBodyLimit::max(64 * 1024)),
        )
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

/// Prometheus-style plain-text metrics: counts only, no secrets. When
/// VOTPORT_METRICS_TOKEN is set, requests must carry it as a bearer token;
/// expose the route on an internal interface regardless.
async fn metrics(State(app): State<std::sync::Arc<App>>, headers: HeaderMap) -> Response {
    if let Some(expected) = &app.config.metrics_token {
        let authorized = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|token| crate::auth::ct_eq(token.as_bytes(), expected.as_bytes()));
        if !authorized {
            return (StatusCode::UNAUTHORIZED, "metrics token required").into_response();
        }
    }
    let app = Arc::clone(&app);
    let body = match tokio::task::spawn_blocking(move || metrics_text(&app)).await {
        Ok(body) => body,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "metrics unavailable").into_response()
        }
    };
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}

fn metrics_text(app: &App) -> String {
    let tenants = app.store.tenants();
    let mut body = format!(
        "# TYPE votport_tenants gauge\nvotport_tenants {}\n",
        tenants.len()
    );
    for tenant in &tenants {
        let links = app.store.links(&tenant.key);
        let bytes: u64 = links
            .iter()
            .flat_map(|link| link.uploads.iter().flat_map(|upload| &upload.files))
            .filter(|file| !file.deleted)
            .map(|file| file.bytes)
            .sum();
        let key = &tenant.key;
        let _ = write!(
            body,
            "votport_links{{tenant=\"{key}\"}} {}\nvotport_received_bytes{{tenant=\"{key}\"}} {bytes}\n",
            links.len()
        );
    }
    let default_links = app.store.links("");
    let _ = writeln!(
        body,
        "votport_links{{tenant=\"default\"}} {}",
        default_links.len()
    );
    let _ = write!(
        body,
        "# TYPE votport_sessions_active gauge\nvotport_sessions_active {}\n",
        app.sessions.total()
    );
    let _ = write!(
        body,
        "# TYPE votport_audit_rows gauge\nvotport_audit_rows {}\n",
        app.store.audit_count()
    );
    body
}

/// Discards idle upload sessions and expired audit rows.
pub async fn session_sweeper(app: Arc<App>) {
    let idle = app.config.session_idle_secs;
    let mut day = tokio::time::interval(std::time::Duration::from_secs(86_400));
    loop {
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                app.sessions.sweep(idle);
            }
            _ = day.tick() => {
                let settings = app.store.resolved_settings(&app.config);
                if settings.audit_retention_days > 0 {
                    let cutoff =
                        crate::store::now_unix().saturating_sub(settings.audit_retention_days.saturating_mul(86_400));
                    match app.store.audit_prune(cutoff) {
                        Ok(count) if count > 0 => {
                            tracing::info!(count, "pruned expired audit rows");
                        }
                        Ok(_) => {}
                        Err(error) => tracing::warn!("audit prune failed: {error}"),
                    }
                }
                // Snapshots from /api/admin/backup accumulate on disk;
                // keep the newest month's worth.
                let backup_dir = app.config.data_dir.join("backups");
                let cutoff_modified =
                    std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 86_400);
                if let Ok(entries) = std::fs::read_dir(&backup_dir) {
                    for entry in entries.flatten() {
                        let expired = entry
                            .metadata()
                            .and_then(|meta| meta.modified())
                            .map(|modified| modified < cutoff_modified)
                            .unwrap_or(false);
                        if expired {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }

                // Received-content lifecycle: delete expired uploads from
                // disk and tombstone their records, per tenant. Only records
                // whose bytes were actually removed are tombstoned; a failed
                // disk delete leaves the record live so the sweep retries.
                if settings.upload_retention_days > 0 {
                    let cutoff = crate::store::now_unix()
                        .saturating_sub(settings.upload_retention_days.saturating_mul(86_400));
                    for link in app.store.all_links() {
                        for upload in &link.uploads {
                            // completed_at == 0 marks pre-field records; never
                            // treat those as infinitely expired.
                            if upload.completed_at == 0 || upload.completed_at >= cutoff {
                                continue;
                            }
                            let mut removed: Vec<String> = Vec::new();
                            for file in &upload.files {
                                if file.deleted {
                                    continue;
                                }
                                let components: Vec<String> = file
                                    .stored_as
                                    .split('/')
                                    .filter(|part| !part.is_empty())
                                    .map(str::to_owned)
                                    .collect();
                                let Ok(path) =
                                    crate::paths::join_under(&app.config.receive_dir, &components)
                                else {
                                    continue;
                                };
                                let _ = tokio::fs::remove_file(format!(
                                    "{}.vot-receipt",
                                    path.display()
                                ))
                                .await;
                                match tokio::fs::remove_file(&path).await {
                                    Ok(()) => removed.push(file.stored_as.clone()),
                                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                        removed.push(file.stored_as.clone())
                                    }
                                    Err(error) => {
                                        tracing::warn!(path = %path.display(), %error, "could not delete expired file");
                                    }
                                }
                            }
                            if removed.is_empty() {
                                continue;
                            }
                            let _ = app.store.update_link(
                                &link.tenant,
                                &link.id,
                                |link| {
                                    for upload in &mut link.uploads {
                                        for file in &mut upload.files {
                                            if removed.contains(&file.stored_as) {
                                                file.deleted = true;
                                            }
                                        }
                                    }
                                },
                            );
                            tracing::info!(
                                target: "audit",
                                event = "uploads_expired",
                                link = %link.id,
                                tenant = %link.tenant,
                                files = removed.len(),
                                "expired received files deleted"
                            );
                            app.store.audit(
                                &link.tenant,
                                "",
                                "uploads_expired",
                                &link.id,
                                &serde_json::json!({
                                    "tenant": link.tenant,
                                    "files": removed.len()
                                }),
                            );
                        }
                    }
                }
            }


        }
    }
}

#[cfg(test)]
mod sso_slot_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    fn force_failed_at(slot: &SsoSlot<u8>, at: Instant) {
        *slot.inner.lock().expect("sso slot poisoned") = SsoSlotState::Failed { at };
    }

    fn past_cooldown() -> Option<Instant> {
        Instant::now().checked_sub(SSO_COOLDOWN + Duration::from_secs(1))
    }

    #[tokio::test]
    async fn health_peek_is_true_only_for_ready() {
        let empty = SsoSlot::<u8>::new();
        assert!(!empty.health_peek());

        let failed = SsoSlot::<u8>::new();
        let _ = failed
            .get_or_discover_with(|| async { Err("down".to_owned()) })
            .await;
        assert!(!failed.health_peek());

        let ready = SsoSlot::<u8>::new();
        let client = ready
            .get_or_discover_with(|| async { Ok(7u8) })
            .await
            .expect("discover");
        assert_eq!(*client, 7);
        assert!(ready.health_peek());

        let guard = ready.inner.lock().expect("sso slot poisoned");
        assert!(!ready.health_peek());
        drop(guard);
        assert!(ready.health_peek());
    }

    #[tokio::test]
    async fn failed_discovery_cools_down() {
        let slot = SsoSlot::<u8>::new();
        let hits = Arc::new(AtomicU32::new(0));
        let first = slot
            .get_or_discover_with({
                let hits = Arc::clone(&hits);
                move || {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Err("down".to_owned())
                    }
                }
            })
            .await;
        assert_eq!(first, Err(()));
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let second = slot
            .get_or_discover_with({
                let hits = Arc::clone(&hits);
                move || {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Ok(1u8)
                    }
                }
            })
            .await;
        assert_eq!(second, Err(()));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(!slot.health_peek());
    }

    #[tokio::test]
    async fn elapsed_cooldown_retries_discovery() {
        let slot = SsoSlot::<u8>::new();
        let Some(at) = past_cooldown() else {
            return;
        };
        force_failed_at(&slot, at);
        let hits = Arc::new(AtomicU32::new(0));
        let result = slot
            .get_or_discover_with({
                let hits = Arc::clone(&hits);
                move || {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Ok(3u8)
                    }
                }
            })
            .await
            .expect("retry after cooldown");
        assert_eq!(*result, 3);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(slot.health_peek());

        let again = slot
            .get_or_discover_with({
                let hits = Arc::clone(&hits);
                move || {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        Ok(9u8)
                    }
                }
            })
            .await
            .expect("ready is sticky");
        assert_eq!(*again, 3);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_empty_callers_share_one_discover() {
        let slot = Arc::new(SsoSlot::<u8>::new());
        let hits = Arc::new(AtomicU32::new(0));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let entered_tx = std::sync::Mutex::new(Some(entered_tx));
        let release_rx = std::sync::Mutex::new(Some(release_rx));

        let slot_a = Arc::clone(&slot);
        let hits_a = Arc::clone(&hits);
        let first = tokio::spawn(async move {
            slot_a
                .get_or_discover_with(|| {
                    let hits = Arc::clone(&hits_a);
                    let entered_tx = entered_tx.lock().unwrap().take();
                    let release_rx = release_rx.lock().unwrap().take();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        if let Some(tx) = entered_tx {
                            let _ = tx.send(());
                        }
                        if let Some(rx) = release_rx {
                            let _ = rx.await;
                        }
                        Ok(7u8)
                    }
                })
                .await
        });

        entered_rx.await.unwrap();
        assert!(!slot.health_peek());

        let slot_b = Arc::clone(&slot);
        let hits_b = Arc::clone(&hits);
        let second = slot_b
            .get_or_discover_with(|| {
                let hits = Arc::clone(&hits_b);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Ok(8u8)
                }
            })
            .await;
        assert_eq!(second, Err(()));
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let _ = release_tx.send(());
        let first = first.await.unwrap().expect("first discover");
        assert_eq!(*first, 7);
        assert!(slot.health_peek());
    }

    #[tokio::test]
    async fn cancelled_discover_does_not_stick_discovering() {
        let slot = Arc::new(SsoSlot::<u8>::new());
        let hits = Arc::new(AtomicU32::new(0));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let entered_tx = std::sync::Mutex::new(Some(entered_tx));
        let release_rx = std::sync::Mutex::new(Some(release_rx));

        let slot_a = Arc::clone(&slot);
        let hits_a = Arc::clone(&hits);
        let first = tokio::spawn(async move {
            slot_a
                .get_or_discover_with(|| {
                    let hits = Arc::clone(&hits_a);
                    let entered_tx = entered_tx.lock().unwrap().take();
                    let release_rx = release_rx.lock().unwrap().take();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        if let Some(tx) = entered_tx {
                            let _ = tx.send(());
                        }
                        if let Some(rx) = release_rx {
                            let _ = rx.await;
                        }
                        Ok(1u8)
                    }
                })
                .await
        });

        entered_rx.await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        drop(release_tx);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        {
            let guard = slot.inner.lock().expect("sso slot poisoned");
            assert!(matches!(*guard, SsoSlotState::Failed { .. }));
        }

        let second = slot
            .get_or_discover_with(|| {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Ok(2u8)
                }
            })
            .await;
        assert_eq!(second, Err(()));
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let Some(at) = past_cooldown() else {
            return;
        };
        force_failed_at(&slot, at);
        let third = slot
            .get_or_discover_with(|| {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    Ok(3u8)
                }
            })
            .await
            .expect("retry after cancelled claim");
        assert_eq!(*third, 3);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(slot.health_peek());
    }
}
