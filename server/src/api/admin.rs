//! Admin management API: sign-in, request links, received-file management.

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::io::ReaderStream;

use crate::app::App;
use crate::auth;
use crate::config::MAX_SSO_SESSION_SECS;
use crate::paths;
use crate::store::{now_unix, AuditFilters, Link, LinkCursor};

use super::{cookie_attributes, ApiError, ApiResult};

const ADMIN_COOKIE: &str = "votport_admin";
const MAX_PASSWORD_BYTES: usize = 256;
const PRINCIPAL_PAGE_DEFAULT: usize = 50;
const PRINCIPAL_PAGE_MAX: usize = 100;

/// The session behind `require_admin` for sibling test modules, which
/// cannot destructure the opaque `AuditorIdentity` newtype.
#[cfg(test)]
pub(crate) fn test_require_admin(app: &App, headers: &HeaderMap) -> ApiResult<AdminSession> {
    require_admin_session(app, headers).map(|(session, _)| session)
}

/// Signed admin cookie for a test identity; the shared body behind each
/// test module's `cookie_for`.
#[cfg(test)]
pub(crate) fn test_admin_cookie(app: &App, identity: &auth::AdminIdentity) -> String {
    let mut identity = identity.clone();
    for grant in &mut identity.grants {
        if !grant.tenant.is_empty() {
            grant.incarnation = app
                .store
                .tenant(&grant.tenant)
                .unwrap()
                .map(|tenant| tenant.incarnation);
        }
    }
    format!(
        "votport_admin={}; Path=/",
        auth::issue_admin_token(&app.secret, &identity, &admin_token_phc(app).unwrap())
    )
}

/// Credential tag bound into admin token MACs: the stored hash when the
/// UI has set one, else the stable tag derived from the environment
/// credential. Either way, rotating the credential evicts sessions and a
/// plain restart does not.
fn admin_token_phc(app: &App) -> ApiResult<String> {
    Ok(app
        .store
        .admin_password_hash()
        .map_err(super::store_unavailable)?
        .unwrap_or_else(|| app.config.admin_token_tag.clone()))
}

#[derive(Clone)]
pub(crate) struct AdminSession {
    pub(crate) identity: auth::AdminIdentity,
    pub(crate) operation: Arc<crate::session::OwnedOutboundOperation>,
}

impl std::ops::Deref for AdminSession {
    type Target = auth::AdminIdentity;

    fn deref(&self) -> &Self::Target {
        &self.identity
    }
}

impl std::fmt::Debug for AdminSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.identity.fmt(formatter)
    }
}

fn tenant_operation(
    app: &App,
    tenant: &str,
) -> ApiResult<Arc<crate::session::OwnedOutboundOperation>> {
    app.sessions
        .try_begin_outbound_owned(tenant)
        .map(Arc::new)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "tenant deletion is in progress"))
}

/// An authenticated admin principal whose auditor status is unchecked. The
/// field is private, so no code outside this module can reach the session
/// at all, and only the two gates below unwrap it inside the module: a
/// handler that calls bare `require_admin` gets a value it cannot use.
/// Compile-time replacement for the old source-scanning lint.
pub(crate) struct AuditorIdentity(AdminSession);

/// Returns the authenticated principal, or unauthorized. The result is an
/// opaque [`AuditorIdentity`]; unwrap it only through `require_operator`
/// or `require_platform_admin`, which enforce the auditor restrictions.
pub(crate) fn require_admin(app: &App, headers: &HeaderMap) -> ApiResult<AuditorIdentity> {
    require_admin_session(app, headers).map(|(identity, _)| AuditorIdentity(identity))
}

fn require_admin_session(app: &App, headers: &HeaderMap) -> ApiResult<(AdminSession, u64)> {
    let token = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| auth::cookie_value(cookies, ADMIN_COOKIE));
    let (mut identity, expires) = auth::verify_admin_token(
        &app.secret,
        &admin_token_phc(app)?,
        token.unwrap_or_default(),
    )
    .ok_or_else(ApiError::unauthorized)?;
    if identity.subject != "local"
        && !app
            .store
            .principal_allows(&identity.subject, identity.credential_version)
    {
        return Err(ApiError::unauthorized());
    }
    let operation = tenant_operation(app, &identity.tenant)?;
    if identity.subject == "local" {
        let tenants = app.store.tenants().map_err(super::store_unavailable)?;
        identity.grants = local_admin_grants(&tenants);
        if !identity
            .grants
            .iter()
            .any(|grant| grant.tenant == identity.tenant)
        {
            identity.tenant = String::new();
            identity.role = "admin".to_owned();
        }
    } else {
        let incarnations = app
            .store
            .tenant_incarnations(
                identity
                    .grants
                    .iter()
                    .filter(|grant| !grant.tenant.is_empty())
                    .map(|grant| grant.tenant.as_str()),
            )
            .map_err(super::store_unavailable)?;
        identity.grants.retain(|grant| {
            if grant.tenant.is_empty() {
                grant.incarnation.is_none()
            } else {
                grant.incarnation.as_deref().is_some_and(|generation| {
                    incarnations.get(grant.tenant.as_str()).map(String::as_str) == Some(generation)
                })
            }
        });
        if !identity
            .grants
            .iter()
            .any(|grant| grant.tenant == identity.tenant && grant.role == identity.role)
        {
            return Err(ApiError::unauthorized());
        }
    }
    Ok((
        AdminSession {
            identity,
            operation,
        },
        expires,
    ))
}

/// Read routes for operators: admins and viewers pass, auditors do not.
/// The auditor role sees only its own session and the audit trail; every
/// link, file, grant, and settings route goes through this gate instead of
/// bare `require_admin`.
pub(crate) fn require_operator(app: &App, headers: &HeaderMap) -> ApiResult<AdminSession> {
    let AuditorIdentity(identity) = require_admin(app, headers)?;
    if identity.role == "auditor" {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "audit-only session"));
    }
    Ok(identity)
}

fn local_admin_grants(tenants: &[crate::store::Tenant]) -> Vec<auth::TenantGrant> {
    let mut grants = vec![auth::TenantGrant {
        incarnation: None,
        tenant: String::new(),
        role: "admin".to_owned(),
    }];
    grants.extend(tenants.iter().map(|tenant| auth::TenantGrant {
        incarnation: Some(tenant.incarnation.clone()),
        tenant: tenant.key.clone(),
        role: "admin".to_owned(),
    }));
    grants
}

/// Default-tenant admin only. Same gate as database backup: viewers and
/// named-tenant admins cannot read platform configuration.
fn require_platform_admin(app: &App, headers: &HeaderMap) -> ApiResult<AdminSession> {
    let AuditorIdentity(identity) = require_admin(app, headers)?;
    if !identity.tenant.is_empty() || identity.role != "admin" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "default-tenant admin required",
        ));
    }
    Ok(identity)
}

/// Mutating admin routes require the admin role AND a custom header;
/// cross-site forms cannot set one, which closes CSRF without token
/// bookkeeping. Viewers (SSO principals outside the admin group) get
/// read-only access.
pub(crate) fn require_admin_write(
    headers: &HeaderMap,
    identity: &auth::AdminIdentity,
) -> ApiResult<()> {
    if identity.role != "admin" {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "read-only session"));
    }
    require_csrf_header(headers)
}

/// Platform admin AND mutating: the combined gate for default-tenant write
/// routes, so a handler cannot pass one check and miss the other.
fn require_platform_admin_write(app: &App, headers: &HeaderMap) -> ApiResult<AdminSession> {
    let identity = require_platform_admin(app, headers)?;
    require_admin_write(headers, &identity)?;
    Ok(identity)
}

/// Operator AND mutating: the combined gate for tenant write routes.
pub(crate) fn require_operator_write(app: &App, headers: &HeaderMap) -> ApiResult<AdminSession> {
    let identity = require_operator(app, headers)?;
    require_admin_write(headers, &identity)?;
    Ok(identity)
}

fn require_csrf_header(headers: &HeaderMap) -> ApiResult<()> {
    if !headers.contains_key("x-votport") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "missing X-Votport header",
        ));
    }
    Ok(())
}

/// The admin password in force: a hash stored by "change password" wins over
/// the one derived from the environment at startup, so a restart does not roll
/// the password back to VOTPORT_ADMIN_PASSWORD.
fn admin_hash(app: &App) -> ApiResult<String> {
    Ok(app
        .store
        .admin_password_hash()
        .map_err(super::store_unavailable)?
        .unwrap_or_else(|| app.config.admin_password_hash.clone()))
}

/// Builds the signed admin session cookie value for `identity`. The local
/// break-glass subject keeps the fixed 7-day lifetime; SSO identities use
/// the adjustable one (VOTPORT_SSO_SESSION_SECS, overridable live from the
/// System page) so IdP-side offboarding latency is a policy knob. Switching
/// supplies the authenticated expiry to prevent extending that deadline.
pub(crate) fn issue_admin_cookie(
    app: &App,
    identity: &auth::AdminIdentity,
    expires_at: Option<u64>,
) -> ApiResult<String> {
    let ttl = if identity.subject == "local" {
        7 * 24 * 3600
    } else {
        app.store
            .overlay(&app.config)
            .map_err(super::store_unavailable)?
            .resolved
            .sso_session_secs
    };
    let now = now_unix();
    let expires = expires_at.unwrap_or(u64::MAX).min(now.saturating_add(ttl));
    let ttl = expires.saturating_sub(now);
    let token =
        auth::issue_admin_token_until(&app.secret, identity, &admin_token_phc(app)?, expires);
    Ok(format!(
        "{ADMIN_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={ttl}{}",
        cookie_attributes(app)
    ))
}

/// Cookie attributes for non-admin cookies too (Secure behind https).
pub(crate) fn sso_cookie_attributes(app: &App) -> &'static str {
    cookie_attributes(app)
}

#[derive(Deserialize)]
pub struct LoginRequest {
    password: String,
}

pub async fn admin_login(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Response> {
    // Per IP first, because it is precise: a wrong password locks out the
    // address that typed it and nobody else. It cannot be the only bound,
    // because the key comes from a header a caller behind a private peer can
    // choose, and because one IPv6 client holds a whole prefix.
    let ip = super::client_ip(&headers, &peer, &app.config.trusted_proxies);
    let bucket = super::throttle_key(&ip);
    // Counted before the verify, not after: checking and then recording lets
    // any number of concurrent attempts pass the check together, which turns
    // five per window into five per connection the caller opens.
    if !app.login_throttle.claim(&bucket) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; wait a minute",
        )
        .with_retry_after(60));
    }
    // Sign-in's own argon2 budget, and nothing global that can refuse or
    // delay a correct password. The permit moves into the blocking task, so
    // it is held for exactly as long as the verification runs: a client that
    // disconnects mid-verify would otherwise release it while the work, and
    // its memory, carried on.
    let permit = Arc::clone(&app.login_permits)
        .acquire_owned()
        .await
        .map_err(|_| ApiError::internal("login semaphore closed"))?;
    let ok = tokio::task::spawn_blocking({
        let hash = admin_hash(&app)?;
        move || {
            let _permit = permit;
            auth::verify_password(&request.password, &hash)
        }
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?;
    if ok {
        app.login_throttle.succeeded(&bucket);
    }
    if !ok {
        // peer is the socket address; ip is what the forwarded header named,
        // when it was believed. VOTPORT_TRUSTED_PROXIES wants the peer.
        tracing::warn!(target: "audit", event = "admin_login_failed", %ip, peer = %peer.ip(), "admin login refused");
        app.store
            .audit("", "", "admin_login_failed", &ip, &serde_json::json!({}));
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "wrong password"));
    }
    tracing::info!(target: "audit", event = "admin_login", %ip, "admin signed in");
    app.store
        .audit("", "", "admin_login", &ip, &serde_json::json!({}));
    let cookie = issue_admin_cookie(&app, &auth::AdminIdentity::local_admin(), None)?;
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

pub async fn admin_logout(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Response> {
    // A cross-site form POST can force a logout (denial of convenience, not
    // of security); the CSRF header closes even that.
    let (identity, _) = require_admin_session(&app, &headers)?;
    require_csrf_header(&headers)?;
    tracing::info!(
        target: "audit", event = "admin_signed_out", subject = %identity.subject,
        "admin signed out"
    );
    app.store.audit(
        "",
        &identity.subject,
        "admin_signed_out",
        "",
        &serde_json::json!({}),
    );
    let cookie = format!(
        "{ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        cookie_attributes(&app)
    );
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

fn audit_tenant(identity: &auth::AdminIdentity) -> Option<&str> {
    if identity.tenant.is_empty() && matches!(identity.role.as_str(), "admin" | "auditor") {
        None
    } else {
        Some(&identity.tenant)
    }
}

/// Returns a bounded JSONL page. `since`/`after_rowid` is oldest-first;
/// `before_rowid` opts into recent-first pagination.
pub async fn admin_audit_export(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Response> {
    let (identity, _) = require_admin_session(&app, &headers)?;
    if query.before_rowid.is_some() && (query.since.is_some() || query.after_rowid.is_some()) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "before_rowid cannot be combined with since or after_rowid",
        ));
    }
    let limit = query
        .limit
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| {
            ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "limit must be between 1 and 10000",
            )
        })?
        .unwrap_or(1000);
    if !(1..=10_000).contains(&limit) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "limit must be between 1 and 10000",
        ));
    }
    let event = validate_audit_filter(query.event, "event")?;
    let search = validate_audit_filter(query.q, "q")?;
    let since = query.since;
    let after_rowid = query.after_rowid;
    let before_rowid = query.before_rowid;
    let store = Arc::clone(&app.store);
    let _operation = Arc::clone(&identity.operation);
    let rows = tokio::task::spawn_blocking(move || {
        let tenant_filter = audit_tenant(&identity);
        let filters = AuditFilters {
            event: event.as_deref(),
            query: search.as_deref(),
        };
        if let Some(before_rowid) = before_rowid {
            store.audit_recent_filtered(tenant_filter, before_rowid, limit, filters)
        } else {
            store.audit_export_filtered(
                tenant_filter,
                since.unwrap_or(0),
                after_rowid.unwrap_or(0),
                limit,
                filters,
            )
        }
    })
    .await
    .map_err(|_| ApiError::internal("audit query worker failed"))?
    .map_err(ApiError::internal)?;
    let cursor = rows.last().map(|row| format!("{},{}", row.at, row.rowid));
    use std::fmt::Write as _;
    let mut body = String::new();
    for row in rows {
        let detail = row.detail;
        writeln!(
            body,
            "{}",
            serde_json::json!({
                "rowid": row.rowid,
                "at": row.at,
                "tenant": row.tenant,
                "actor": row.actor,
                "event": row.event,
                "subject": row.subject,
                "detail": detail,
            })
        )
        .map_err(|error| ApiError::internal(error.to_string()))?;
    }
    let mut response = (
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/x-ndjson; charset=utf-8",
            ),
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"audit.jsonl\"",
            ),
        ],
        body,
    )
        .into_response();
    if let Some(cursor) = cursor {
        response.headers_mut().insert(
            "x-votport-audit-cursor",
            HeaderValue::try_from(cursor)
                .map_err(|_| ApiError::internal("audit cursor header invalid"))?,
        );
    }
    Ok(response)
}

/// Platform-wide link and live-byte totals without loading upload history.
pub async fn holdings(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    require_platform_admin(&app, &headers)?;
    let holdings = app.store.tenant_usage().map_err(ApiError::internal)?;
    Ok(Json(json!({ "holdings": holdings })))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    since: Option<u64>,
    /// Cursor for rows sharing `since`'s second (from the previous page's
    /// final `rowid`).
    after_rowid: Option<u64>,
    before_rowid: Option<u64>,
    limit: Option<String>,
    event: Option<String>,
    q: Option<String>,
}

fn validate_audit_filter(value: Option<String>, name: &str) -> ApiResult<Option<String>> {
    let Some(value) = value else { return Ok(None) };
    if value.chars().count() > 100 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{name} must be at most 100 characters"),
        ));
    }
    let value = value.trim().to_owned();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

#[derive(Deserialize)]
pub struct StatusQuery {
    /// Start of the operator's day in unix seconds; the client knows its
    /// timezone, the server does not.
    since: Option<u64>,
}

const ADMIN_STATUS_TTL: Duration = Duration::from_secs(60);
const ADMIN_STATUS_WAIT: Duration = Duration::from_secs(1);
const ADMIN_STATUS_CACHE_ENTRIES: usize = 64;
const ADMIN_STATUS_SPOOL_LINE_MAX: usize = 2 * 1024 * 1024;
#[cfg(test)]
const ADMIN_STATUS_TEST_WAIT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Eq, PartialEq)]
struct StatusKey {
    tenant: String,
    incarnation: Option<String>,
    since: Option<u64>,
}

#[derive(Clone)]
struct StatusSnapshot {
    sampled_at: u64,
    started: Instant,
    today_uploads: u64,
    today_bytes: u64,
    stored: serde_json::Value,
    receive_disk: Option<serde_json::Value>,
    outbound: crate::store::OutboundSummary,
    outbound_disk: Option<serde_json::Value>,
    since: u64,
    warning: Option<String>,
}

struct StatusEntry {
    key: StatusKey,
    snapshot: Option<StatusSnapshot>,
    error: Option<String>,
    // Completion time throttles the next scan independently of sample age.
    last_refresh: Option<Instant>,
}

#[derive(Default)]
struct StatusCacheState {
    entries: Vec<StatusEntry>,
    running: bool,
}

/// Bounded, single-flight cache for the status strip's expensive reads.
pub(crate) struct AdminStatusCache {
    state: std::sync::Mutex<StatusCacheState>,
    changed: tokio::sync::Notify,
    #[cfg(test)]
    refreshes: AtomicU64,
    #[cfg(test)]
    scan_gate: std::sync::Mutex<Option<Arc<StatusScanGate>>>,
}

#[cfg(test)]
struct StatusScanGate {
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl Default for AdminStatusCache {
    fn default() -> Self {
        Self {
            state: std::sync::Mutex::new(StatusCacheState::default()),
            changed: tokio::sync::Notify::new(),
            #[cfg(test)]
            refreshes: AtomicU64::new(0),
            #[cfg(test)]
            scan_gate: std::sync::Mutex::new(None),
        }
    }
}

impl StatusEntry {
    fn needs_refresh(&self, now: Instant) -> bool {
        self.last_refresh
            .is_none_or(|last_refresh| now.duration_since(last_refresh) >= ADMIN_STATUS_TTL)
    }
}

impl AdminStatusCache {
    fn fresh(snapshot: &StatusSnapshot) -> bool {
        snapshot.started.elapsed() < ADMIN_STATUS_TTL
    }

    fn start_refresh(&self, app: &Arc<App>, key: StatusKey) -> bool {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(_) => return false,
        };
        if state.running {
            return false;
        }
        let now = Instant::now();
        let index = state.entries.iter().position(|entry| entry.key == key);
        let index = index.unwrap_or_else(|| {
            if state.entries.len() == ADMIN_STATUS_CACHE_ENTRIES {
                state.entries.remove(0);
            }
            state.entries.push(StatusEntry {
                key: key.clone(),
                snapshot: None,
                error: None,
                last_refresh: None,
            });
            state.entries.len() - 1
        });
        if !state.entries[index].needs_refresh(now) {
            return false;
        }
        state.entries[index].error = None;
        state.running = true;
        drop(state);

        let app = Arc::clone(app);
        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking({
                let app = Arc::clone(&app);
                let key = key.clone();
                move || refresh_status_sync(&app, &key)
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
            app.admin_status.finish_refresh(key, result);
        });
        true
    }

    fn finish_refresh(&self, key: StatusKey, result: Result<StatusSnapshot, String>) {
        let mut state = self.state.lock().expect("admin status cache poisoned");
        if let Some(entry) = state.entries.iter_mut().find(|entry| entry.key == key) {
            entry.last_refresh = Some(Instant::now());
            match result {
                Ok(snapshot) => {
                    entry.snapshot = Some(snapshot);
                    entry.error = None;
                }
                Err(error) => entry.error = Some(error),
            }
        }
        state.running = false;
        drop(state);
        self.changed.notify_waiters();
    }

    async fn snapshot(
        &self,
        app: &Arc<App>,
        key: StatusKey,
    ) -> (
        Option<(StatusSnapshot, bool, Option<String>)>,
        Option<String>,
    ) {
        let deadline = Instant::now() + ADMIN_STATUS_WAIT;
        loop {
            let notified = self.changed.notified();
            let (snapshot, error, running, needs_refresh) = {
                let Some(state) = self.state.try_lock().ok() else {
                    return (None, Some("status cache is busy".to_owned()));
                };
                match state.entries.iter().find(|entry| entry.key == key) {
                    Some(entry) => (
                        entry.snapshot.clone(),
                        entry.error.clone(),
                        state.running,
                        entry.needs_refresh(Instant::now()),
                    ),
                    None => (None, None, state.running, true),
                }
            };
            let started = needs_refresh && !running && self.start_refresh(app, key.clone());
            if let Some(snapshot) = snapshot {
                let warning = snapshot.warning.clone();
                let sample_error = if snapshot.started.elapsed() >= ADMIN_STATUS_TTL {
                    Some("cached status is older than its refresh window".to_owned())
                } else {
                    None
                };
                let error = error.or(warning).or(sample_error);
                let stale = !Self::fresh(&snapshot) || error.is_some();
                return (Some((snapshot, stale, error)), None);
            }
            if !running && !started {
                return (None, error);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || tokio::time::timeout(remaining, notified).await.is_err() {
                return (
                    None,
                    Some("status refresh did not finish in time".to_owned()),
                );
            }
        }
    }
}

/// Free and total bytes on the volume holding `root`.
pub(crate) fn disk_of(root: &std::path::Path) -> Option<(u64, u64)> {
    rustix::fs::statvfs(root).ok().map(|stat| {
        (
            stat.f_bavail.saturating_mul(stat.f_frsize),
            stat.f_blocks.saturating_mul(stat.f_frsize),
        )
    })
}

#[derive(Default)]
struct StoredCounts {
    files: u64,
    bytes: u64,
    missing_files: u64,
    missing_bytes: u64,
}

/// Adds one live file record to the on-disk or missing bucket. A record with
/// no stored path cannot be checked and counts as present.
fn add_stored_count(
    app: &App,
    tenant: &str,
    stored_as: &str,
    size: u64,
    counts: &mut StoredCounts,
) {
    let present = stored_as.is_empty()
        || stored_path(app, tenant, stored_as).is_some_and(|path| path.is_file());
    if present {
        counts.files += 1;
        counts.bytes = counts.bytes.saturating_add(size);
    } else {
        counts.missing_files += 1;
        counts.missing_bytes = counts.missing_bytes.saturating_add(size);
    }
}

fn read_spool_line<R: std::io::BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> Result<bool, String> {
    line.clear();
    loop {
        let available = reader.fill_buf().map_err(|error| error.to_string())?;
        if available.is_empty() {
            return Ok(!line.is_empty());
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > ADMIN_STATUS_SPOOL_LINE_MAX {
            return Err("admin status metadata row is too large".to_owned());
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(true);
        }
    }
}

/// Runs the one grouped Store scan into a private metadata spool, then reads
/// it back while checking paths. The Store lock is released before any NAS
/// metadata calls, and only one JSON line is held in memory at a time.
fn stored_counts_from_spool(app: &App, tenant: &str) -> Result<StoredCounts, String> {
    use std::io::{BufReader, BufWriter, Seek as _, Write as _};
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    let path = app
        .config
        .data_dir
        .join(format!(".admin-status-{}.tmp", auth::random_token()));
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(&path).map_err(|error| error.to_string())?;
    // Keep the descriptor private and unlink the name immediately so a
    // cancelled or panicking worker cannot leave a spool behind.
    std::fs::remove_file(&path).map_err(|error| error.to_string())?;
    let mut writer = BufWriter::new(file);
    // ponytail: SQLite may keep this GROUP BY temp B-tree in MEMORY; this
    // focused task bounds the Rust side and leaves index/schema work separate.
    app.store.write_tenant_live_files(tenant, &mut writer)?;
    writer.flush().map_err(|error| error.to_string())?;
    let mut file = writer
        .into_inner()
        .map_err(|error| error.into_error().to_string())?;
    file.rewind().map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut counts = StoredCounts::default();
    while read_spool_line(&mut reader, &mut line)? {
        let line = line.strip_suffix(b"\n").unwrap_or(&line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let (stored_as, size) =
            serde_json::from_slice::<(String, u64)>(line).map_err(|error| error.to_string())?;
        add_stored_count(app, tenant, &stored_as, size, &mut counts);
    }
    Ok(counts)
}

impl StoredCounts {
    fn json(&self) -> serde_json::Value {
        json!({
            "files": self.files,
            "bytes": self.bytes,
            "missing_files": self.missing_files,
            "missing_bytes": self.missing_bytes,
        })
    }
}

/// Downloads in flight are keyed by the grant's hex token hash, a colon, and
/// one or two stream segments; the part before the first colon is the grant,
/// so one recipient with several streams open counts once.
fn active_grant_hashes<'a>(keys: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut hashes: Vec<String> = keys
        .map(|key| key.split_once(':').map_or(key, |(hash, _)| hash).to_owned())
        .collect();
    hashes.sort();
    hashes.dedup();
    hashes
}

fn status_key(identity: &auth::AdminIdentity, since: Option<u64>) -> StatusKey {
    StatusKey {
        tenant: identity.tenant.clone(),
        incarnation: identity
            .grants
            .iter()
            .find(|grant| grant.tenant == identity.tenant)
            .and_then(|grant| grant.incarnation.clone()),
        since,
    }
}

fn status_key_is_current(app: &App, key: &StatusKey) -> Result<bool, String> {
    if key.tenant.is_empty() {
        return Ok(true);
    }
    Ok(app
        .store
        .tenant(&key.tenant)?
        .is_some_and(|tenant| key.incarnation.as_deref() == Some(tenant.incarnation.as_str())))
}

fn disk_json(root: &std::path::Path) -> Option<serde_json::Value> {
    disk_of(root).map(|(free, total)| json!({ "free_bytes": free, "total_bytes": total }))
}

fn refresh_status_sync(app: &Arc<App>, key: &StatusKey) -> Result<StatusSnapshot, String> {
    #[cfg(test)]
    app.admin_status.refreshes.fetch_add(1, Ordering::Relaxed);
    let _operation = app
        .sessions
        .try_begin_outbound_owned(&key.tenant)
        .ok_or_else(|| "tenant operation unavailable".to_owned())?;
    #[cfg(test)]
    if let Some(gate) = app.admin_status.scan_gate.lock().unwrap().clone() {
        gate.entered
            .send(())
            .map_err(|_| "status scan gate closed".to_owned())?;
        gate.release
            .lock()
            .map_err(|_| "status scan gate poisoned".to_owned())?
            .recv_timeout(ADMIN_STATUS_TEST_WAIT)
            .map_err(|_| "status scan gate release timed out".to_owned())?;
    }
    if !status_key_is_current(app, key)? {
        return Err("status changed while refreshing".to_owned());
    }
    let sample_started = Instant::now();
    let sample_time = now_unix();
    let since = key
        .since
        .unwrap_or_else(|| sample_time.saturating_sub(86_400));
    let (today_uploads, today_bytes) = app.store.uploads_since(&key.tenant, since)?;
    let stored_counts = stored_counts_from_spool(app, &key.tenant)?;
    let outbound = app.store.outbound_summary(&key.tenant, sample_time, &[])?;
    let receive_disk = disk_json(&app.config.receive_dir);
    let outbound_disk = disk_json(&app.config.outbound_dir);
    if !status_key_is_current(app, key)? {
        return Err("status changed while refreshing".to_owned());
    }
    let warning = match (receive_disk.is_none(), outbound_disk.is_none()) {
        (true, true) => Some("receive and outbound disk statistics unavailable".to_owned()),
        (true, false) => Some("receive disk statistics unavailable".to_owned()),
        (false, true) => Some("outbound disk statistics unavailable".to_owned()),
        (false, false) => None,
    };
    Ok(StatusSnapshot {
        sampled_at: sample_time,
        started: sample_started,
        today_uploads,
        today_bytes,
        stored: stored_counts.json(),
        receive_disk,
        outbound,
        outbound_disk,
        since,
        warning,
    })
}

/// The Receive and Deliver status strips: what is arriving now, what landed
/// today, what is stored, what is being served, and room on both volumes.
pub async fn admin_status(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<StatusQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    let receiving = app.sessions.active_transfers(&identity.tenant);
    let bytes_in_flight: u64 = receiving.iter().map(|transfer| transfer.received).sum();
    let since = query.since;
    let now = now_unix();
    // Downloads in flight are kept in a bounded process registry. Query only
    // those current hashes here, so a slow status sweep cannot hide them.
    let active_hashes = {
        let active = app
            .outbound_active
            .lock()
            .expect("outbound active poisoned");
        active_grant_hashes(active.iter().map(String::as_str))
    };
    let current_active = if active_hashes.is_empty() {
        Some(0)
    } else {
        let app_for_query = Arc::clone(&app);
        let tenant = identity.tenant.clone();
        tokio::task::spawn_blocking(move || {
            app_for_query
                .store
                .outbound_active_count(&tenant, &active_hashes)
        })
        .await
        .ok()
        .and_then(Result::ok)
    };
    let key = status_key(&identity, since);
    let (cached, cache_error) = app.admin_status.snapshot(&app, key).await;
    let (today, stored, disk, outbound, sampled_at, stale, mut stale_error) =
        if let Some((snapshot, snapshot_stale, error)) = cached {
            let active = current_active;
            let stale_error = error.or_else(|| {
                active
                    .is_none()
                    .then(|| "active download count unavailable".to_owned())
            });
            (
                Some(json!({
                    "uploads": snapshot.today_uploads,
                    "bytes": snapshot.today_bytes,
                    "since": snapshot.since,
                })),
                Some(snapshot.stored),
                snapshot.receive_disk,
                json!({
                    "active": active,
                    "open_grants": snapshot.outbound.open_grants,
                    "deliveries": snapshot.outbound.deliveries,
                    "disk": snapshot.outbound_disk,
                }),
                Some(snapshot.sampled_at),
                snapshot_stale || active.is_none(),
                stale_error,
            )
        } else {
            (
                None,
                None,
                None,
                json!({
                    "active": current_active,
                    "open_grants": null,
                    "deliveries": null,
                    "disk": null,
                }),
                None,
                true,
                cache_error.or_else(|| Some("status refresh unavailable".to_owned())),
            )
        };
    if stale_error.is_none() && stale {
        stale_error = Some("cached status is older than its refresh window".to_owned());
    }
    let health = crate::app::health_status(&app).await;
    Ok(Json(json!({
        "now": now,
        "sessions_active": receiving.len(),
        "bytes_in_flight": bytes_in_flight,
        "receiving": receiving,
        "today": today,
        "stored": stored,
        "disk": disk,
        "outbound": outbound,
        "sampled_at": sampled_at,
        "stale": stale,
        "stale_error": stale_error,
        "health": health["healthy"].clone(),
        "ready": health["ready"].clone(),
        "draining": health["draining"].clone(),
        "lease": health["lease"].clone(),
        "mount": health["mount"].clone(),
    })))
}

#[derive(Deserialize)]
pub struct SearchQuery {
    q: Option<String>,
}

/// The masthead search: requests, downloads, and received files matching a
/// phrase, five of each, scoped like the pages that show them.
pub async fn admin_search(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    let phrase = query.q.unwrap_or_default();
    let phrase = phrase.trim();
    let length = phrase.chars().count();
    if !(2..=200).contains(&length) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "search needs between 2 and 200 characters",
        ));
    }
    let mut results = app
        .store
        .search(&identity.tenant, phrase, 5)
        .map_err(super::store_unavailable)?;
    // Workflow job grants follow their project's membership, as on Deliver.
    if identity.role != "admin" {
        let mut visible = Vec::with_capacity(results.downloads.len());
        for download in results.downloads {
            if super::outbound::grant_visible(&app, &identity, &download.id)? {
                visible.push(download);
            }
        }
        results.downloads = visible;
    }
    Ok(Json(json!({
        "requests": results.requests,
        "downloads": results.downloads,
        "files": results.files,
    })))
}

pub async fn admin_session(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let (identity, _) = require_admin_session(&app, &headers)?;
    Ok(Json(admin_session_view(&identity)))
}

pub(crate) fn admin_page_session(app: &App, headers: &HeaderMap) -> Option<AdminSession> {
    require_admin_session(app, headers)
        .ok()
        .map(|(session, _)| session)
}

pub(crate) fn admin_session_view(identity: &auth::AdminIdentity) -> serde_json::Value {
    // Which dashboard pages this principal may open. Named tenants get their
    // own links plus a tenant-filtered audit view; only the Branding view of
    // Tenants is available outside the default-tenant platform admin.
    let mut pages = if identity.role == "auditor" {
        vec!["audit"]
    } else {
        vec![
            "receive",
            "deliver",
            "workflows",
            "trade-routes",
            "storage",
            "automation",
            "notifications",
            "audit",
        ]
    };
    if identity.role == "admin" {
        pages.push("tenants");
    }
    if identity.tenant.is_empty() && identity.role == "admin" {
        pages.push("system");
    }
    json!({
        "ok": true,
        "subject": identity.subject,
        "tenant": identity.tenant,
        "grants": identity.grants,
        "role": identity.role,
        "pages": pages,
    })
}

#[derive(Deserialize)]
pub struct CreateTenantRequest {
    key: String,
    label: String,
    #[serde(default)]
    admin_group: Option<String>,
    #[serde(default)]
    max_total_bytes: Option<u64>,
    #[serde(default)]
    max_links: Option<u64>,
    #[serde(default)]
    max_sessions: Option<u64>,
    /// Finding 378: tenant-scoped upload retention; 0 is treated as unset at
    /// creation, matching the quota fields.
    #[serde(default)]
    retention_days: Option<u64>,
}

/// Admits a tenant key for lookup: destination rules plus the reserved names.
/// Multi-segment keys pass here so a namespace stored before
/// [`admit_tenant_key`] existed can still be deleted.
fn admit_tenant_ref(key: &str) -> ApiResult<String> {
    let key = paths::admit_dest(key)
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    if key.is_empty() || key == "default" {
        // "default" would collide with the hard-coded metrics series for the
        // built-in namespace.
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "that tenant key is reserved",
        ));
    }
    Ok(key)
}

/// Admits a portable tenant key for creation. Legacy keys remain addressable
/// through `admit_tenant_ref`, but new on-disk namespaces are lowercase ASCII
/// so case-insensitive and normalization-insensitive filesystems agree.
fn admit_tenant_key(key: &str) -> ApiResult<String> {
    let key = admit_tenant_ref(key)?;
    if !paths::portable_tenant_key(&key) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "tenant key must use lowercase ASCII letters, digits, '-' or '_'",
        ));
    }
    Ok(key)
}

/// Creates a tenant namespace. Admins only; the key becomes a folder name in
/// the reserved tenant-storage subtree.
pub async fn create_tenant(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<CreateTenantRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    let key = admit_tenant_key(&request.key)?;
    let _pin = app.sessions.try_pin_tenant(&key).ok_or_else(|| {
        ApiError::new(StatusCode::CONFLICT, "tenant mutation already in progress")
    })?;
    #[cfg(test)]
    app.sessions.wait_delete_stall().await;
    let defaults = app
        .store
        .resolved_settings(&app.config)
        .map_err(super::store_unavailable)?;
    let tenant = crate::store::Tenant {
        incarnation: String::new(),
        key: key.clone(),
        label: request.label.trim().to_owned(),
        admin_group: request.admin_group.filter(|group| !group.trim().is_empty()),
        max_total_bytes: request
            .max_total_bytes
            .or(defaults.default_max_total_bytes)
            .filter(|&bytes| bytes > 0),
        max_links: request
            .max_links
            .or(defaults.default_max_links)
            .filter(|&links| links > 0),
        max_sessions: request
            .max_sessions
            .or(defaults.default_max_sessions)
            .filter(|&sessions| sessions > 0),
        retention_days: request.retention_days.filter(|&days| days > 0),
        created_at: now_unix(),
    };
    let detail = json!({
        "label": tenant.label,
        "admin_group": tenant.admin_group,
        "max_total_bytes": tenant.max_total_bytes,
        "max_links": tenant.max_links,
        "max_sessions": tenant.max_sessions,
        "retention_days": tenant.retention_days,
    });
    app.store
        .insert_tenant(tenant)
        .map_err(|error| match error {
            crate::store::InsertTenantError::AlreadyExists => {
                ApiError::new(StatusCode::CONFLICT, "tenant already exists")
            }
            crate::store::InsertTenantError::Store(message) => ApiError::internal(message),
        })?;
    tracing::info!(target: "audit", event = "tenant_created", key = %key, "tenant namespace created");
    app.store
        .audit("", &identity.subject, "tenant_created", &key, &detail);
    Ok(Json(json!({ "key": key })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantsPage {
    after: Option<String>,
    limit: Option<usize>,
}

pub async fn list_tenants(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(page): Query<TenantsPage>,
) -> ApiResult<Json<serde_json::Value>> {
    let _identity = require_platform_admin(&app, &headers)?;
    let limit = page.limit.unwrap_or(PRINCIPAL_PAGE_DEFAULT);
    if !(1..=PRINCIPAL_PAGE_MAX).contains(&limit)
        || page.after.as_ref().is_some_and(|after| after.len() > 100)
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid tenant page",
        ));
    }
    let (principals, total) = app
        .store
        .principals_page(PRINCIPAL_PAGE_DEFAULT, 0, None)
        .map_err(super::store_unavailable)?;
    let mut tenants = app
        .store
        .tenants_page(page.after.as_deref().unwrap_or(""), limit + 1)
        .map_err(super::store_unavailable)?;
    let more = tenants.len() > limit;
    tenants.truncate(limit);
    let next = more
        .then(|| tenants.last().map(|tenant| tenant.key.clone()))
        .flatten();
    Ok(Json(json!({
        "tenants": tenants,
        "tenants_next": next,
        "principals": principals,
        "principals_truncated": total > PRINCIPAL_PAGE_DEFAULT as u64,
    })))
}

#[derive(Deserialize)]
pub struct PrincipalsQuery {
    limit: Option<String>,
    offset: Option<String>,
    q: Option<String>,
}

pub async fn list_principals(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<PrincipalsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let _identity = require_platform_admin(&app, &headers)?;
    let limit = super::page_limit(
        query.limit.as_deref(),
        PRINCIPAL_PAGE_DEFAULT,
        PRINCIPAL_PAGE_MAX,
    )?;
    let offset = super::page_offset(query.offset.as_deref())?;
    let query = query.q.filter(|value| !value.is_empty());
    if query
        .as_ref()
        .is_some_and(|value| value.chars().count() > 100)
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "q must be at most 100 characters",
        ));
    }
    let (principals, total) = app
        .store
        .principals_page(limit, offset, query.as_deref())
        .map_err(super::store_unavailable)?;
    let has_more = u64::try_from(offset)
        .unwrap_or(u64::MAX)
        .saturating_add(principals.len() as u64)
        < total;
    Ok(Json(json!({
        "principals": principals,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
    })))
}

#[derive(Deserialize)]
pub struct PrincipalSubjectRequest {
    subject: String,
}

pub async fn revoke_principal(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<PrincipalSubjectRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    mutate_principal(&app, &identity.subject, &request.subject, true)
}

/// Erases a revoked principal: the identity row and its SCIM memberships
/// are deleted, so nothing about the person persists in the store. Only a
/// blocked principal can be purged, and the store call re-checks that, so a
/// race with an unblock cannot erase an active identity.
pub async fn purge_principal(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<PrincipalSubjectRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    let subject = subject_for_mutation(&request.subject, "purge")?;
    let existing = app.store.principal(subject).map_err(ApiError::internal)?;
    match existing {
        None => return Err(ApiError::not_found()),
        Some(principal) if !principal.blocked => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "revoke the principal before purging it",
            ));
        }
        Some(_) => {}
    }
    let changed = app
        .store
        .purge_principal(subject)
        .map_err(ApiError::internal)?;
    if !changed {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "principal_purged", subject = %crate::logging::reduce_subject(subject), "principal erased");
    app.store.audit(
        "",
        &identity.subject,
        "principal_purged",
        subject,
        &json!({}),
    );
    Ok(Json(json!({ "ok": true })))
}

pub async fn unblock_principal(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<PrincipalSubjectRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    mutate_principal(&app, &identity.subject, &request.subject, false)
}

/// The trimmed subject every principal mutation acts on, rejecting an
/// empty subject and naming the action that the local administrator resists.
fn subject_for_mutation<'a>(subject: &'a str, action: &str) -> ApiResult<&'a str> {
    let subject = subject.trim();
    if subject.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "subject is required",
        ));
    }
    if subject == "local" {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("cannot {action} the local administrator"),
        ));
    }
    Ok(subject)
}

fn mutate_principal(
    app: &App,
    actor: &str,
    subject: &str,
    revoke: bool,
) -> ApiResult<Json<serde_json::Value>> {
    let subject = subject_for_mutation(subject, if revoke { "revoke" } else { "unblock" })?;
    let changed = if revoke {
        app.store.revoke_principal(subject)
    } else {
        app.store.unblock_principal(subject)
    }
    .map_err(ApiError::internal)?;
    if !changed {
        return Err(ApiError::not_found());
    }
    let event = if revoke {
        "principal_revoked"
    } else {
        "principal_unblocked"
    };
    tracing::info!(target: "audit", event, subject = %crate::logging::reduce_subject(subject), "principal updated");
    app.store.audit("", actor, event, subject, &json!({}));
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_tenant(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    let key = admit_tenant_ref(&key)?;
    let pin = app.sessions.try_pin_tenant(&key).ok_or_else(|| {
        ApiError::new(StatusCode::CONFLICT, "tenant mutation already in progress")
    })?;
    let count = app
        .store
        .tenant_link_count(&key)
        .map_err(super::store_unavailable)?;
    if count > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("{count} link(s) still reference this tenant; delete them first"),
        ));
    }
    let active = app.sessions.active_for_tenant(&key);
    let outbound_active = app.sessions.active_outbound_for_tenant(&key);
    if active > 0 || outbound_active > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!(
                "{} operation(s) are in flight; try again when they finish",
                active + outbound_active
            ),
        ));
    }
    let destinations = app
        .receiving_destinations_async()
        .await
        .map_err(|e| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, e))?;
    // The subtrees this delete would purge, if there are any. A key with a
    // separator was never usable as a namespace, and neither root is valid.
    let purge_targets = if purges_tenant_subtrees(&key) {
        let receive =
            tenant_receive_dir(&app.config.receive_dir, &key).map_err(ApiError::internal)?;
        let outbound =
            tenant_outbound_dir(&app.config.outbound_dir, &key).map_err(ApiError::internal)?;
        (
            receive.is_dir().then_some(receive),
            outbound.is_dir().then_some(outbound),
        )
    } else {
        (None, None)
    };
    // Read before the row delete cascades the branding row away.
    let logo_ext = app
        .store
        .branding(&key)
        .ok()
        .flatten()
        .map(|branding| branding.logo_ext)
        .filter(|ext| !ext.is_empty());
    use crate::store::TenantRemoval;
    let row_deleted = match app.store.remove_tenant(&key) {
        Ok(TenantRemoval::HasRoutes) => {
            return Err(ApiError::new(StatusCode::CONFLICT, "cancel this tenant's trade routes and wait for destination acknowledgements before deleting it"));
        }
        Ok(TenantRemoval::Deleted) => true,
        Ok(TenantRemoval::HasLinks) => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "a link was created concurrently; delete them first",
            ));
        }
        Ok(TenantRemoval::Absent) => {
            if purge_targets.0.is_none() && purge_targets.1.is_none() {
                return Err(ApiError::not_found());
            }
            false
        }
        Err(error) => {
            return Err(ApiError::internal(error));
        }
    };
    let purged_receive = purge_targets.0.is_some();
    let purged_outbound = purge_targets.1.is_some();
    #[cfg(test)]
    if purged_receive {
        app.sessions.wait_delete_stall().await;
    }
    let app_for_purge = Arc::clone(&app);
    let purge_key = key.clone();
    tokio::task::spawn_blocking(move || {
        let _pin = pin;
        let app = app_for_purge;
        #[cfg(test)]
        app.sessions.wait_tenant_purge_stall();
        for (name, path) in [("receive", purge_targets.0), ("outbound", purge_targets.1)] {
            let Some(path) = path else { continue };
            let purge = if name == "receive" {
                destinations.remove_tree(&paths::tenant_prefix(&purge_key))
                    .map_err(std::io::Error::other)
            } else {
                std::fs::remove_dir_all(&path)
            };
            match purge {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && row_deleted => {}
                Err(error) => {
                    tracing::error!(key = %purge_key, subtree = name, %error, "tenant subtree purge failed");
                    return Err(ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "tenant subtree purge failed; retry DELETE"));
                }
            }
        }
        if row_deleted {
            if let Some(ext) = logo_ext {
                let stale = paths::branding_logo_path(&app.config.data_dir, &purge_key, &ext);
                let _ = std::fs::remove_file(stale);
            }
        }
        Ok(())
    }).await.map_err(|error| {
        tracing::error!(key = %key, %error, "tenant subtree purge worker failed");
        ApiError::internal("tenant subtree purge failed; retry DELETE")
    })??;
    tracing::info!(target: "audit", event = "tenant_deleted", key = %key, "tenant namespace deleted");
    app.store.audit(
        "",
        &identity.subject,
        "tenant_deleted",
        &key,
        &json!({
            "purged_receive": purged_receive,
            "purged_outbound": purged_outbound,
            "row_deleted": row_deleted
        }),
    );
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct PatchTenantRequest {
    #[serde(default)]
    label: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    admin_group: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    max_total_bytes: Option<Option<u64>>,
    #[serde(default, deserialize_with = "double_option")]
    max_links: Option<Option<u64>>,
    #[serde(default, deserialize_with = "double_option")]
    max_sessions: Option<Option<u64>>,
    #[serde(default, deserialize_with = "double_option")]
    retention_days: Option<Option<u64>>,
}

fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(deserializer)?))
}

fn patch_quota(field: &str, value: Option<u64>) -> ApiResult<Option<u64>> {
    match value {
        None => Ok(None),
        Some(0) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{field} must be greater than zero"),
        )),
        Some(n) => Ok(Some(n)),
    }
}

/// Updates label, admin group, or quotas on an existing tenant. The key is
/// a folder name and cannot be renamed here.
pub async fn update_tenant(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PatchTenantRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    let Some(mut tenant) = app.store.tenant(&key).map_err(super::store_unavailable)? else {
        return Err(ApiError::not_found());
    };
    if let Some(label) = request.label {
        tenant.label = label.trim().to_owned();
    }
    if let Some(group) = request.admin_group {
        tenant.admin_group = group
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_owned());
    }
    if let Some(bytes) = request.max_total_bytes {
        tenant.max_total_bytes = patch_quota("max_total_bytes", bytes)?;
    }
    if let Some(links) = request.max_links {
        tenant.max_links = patch_quota("max_links", links)?;
    }
    if let Some(sessions) = request.max_sessions {
        tenant.max_sessions = patch_quota("max_sessions", sessions)?;
    }
    if let Some(days) = request.retention_days {
        tenant.retention_days = patch_quota("retention_days", days)?;
    }
    if !app
        .store
        .update_tenant(&tenant)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "tenant_updated", key = %key, "tenant namespace updated");
    app.store.audit(
        "",
        &identity.subject,
        "tenant_updated",
        &key,
        &json!({
            "label": tenant.label,
            "admin_group": tenant.admin_group,
            "max_total_bytes": tenant.max_total_bytes,
            "max_links": tenant.max_links,
            "max_sessions": tenant.max_sessions,
            "retention_days": tenant.retention_days,
        }),
    );
    Ok(Json(json!({ "ok": true })))
}

/// Hard cap on stored logo bytes; the route body limit adds header slack.
pub(crate) const MAX_LOGO_BYTES: usize = 512 * 1024;

/// Maps the branding path key to a stored tenant: "default" is the default
/// tenant (""), anything else must name an existing tenant row.
fn branding_tenant(
    app: &App,
    key: &str,
    identity: &auth::AdminIdentity,
) -> ApiResult<(String, Arc<crate::session::OwnedOutboundOperation>)> {
    let tenant = if key == "default" {
        String::new()
    } else {
        admit_tenant_ref(key)?
    };
    // Grant check before the store lookup: a foreign admin learns nothing
    // about which tenant keys exist. The active tenant gates: a
    // default-tenant grant is platform authority only while the session is
    // switched to the default tenant, and a session switched into a named
    // tenant manages that tenant's branding only.
    let admin_grant_for = |tenant: &str| {
        identity
            .grants
            .iter()
            .any(|grant| grant.role == "admin" && grant.tenant == tenant)
    };
    let permitted = if identity.tenant.is_empty() {
        admin_grant_for("")
    } else {
        tenant == identity.tenant && admin_grant_for(&tenant)
    };
    if !permitted {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "no admin access to that tenant",
        ));
    }
    let operation = tenant_operation(app, &tenant)?;
    if !tenant.is_empty() {
        let current = app
            .store
            .tenant(&tenant)
            .map_err(super::store_unavailable)?
            .ok_or_else(ApiError::not_found)?;
        let platform = identity
            .grants
            .iter()
            .any(|grant| grant.tenant.is_empty() && grant.role == "admin");
        if identity.subject != "local"
            && !platform
            && !identity.grants.iter().any(|grant| {
                grant.tenant == tenant
                    && grant.role == "admin"
                    && grant.incarnation.as_deref() == Some(current.incarnation.as_str())
            })
        {
            return Err(ApiError::unauthorized());
        }
    }
    Ok((tenant, operation))
}

fn admit_brand_color(color: &str) -> ApiResult<()> {
    let valid = color.is_empty()
        || (color.len() == 7
            && color.starts_with('#')
            && color.bytes().skip(1).all(|byte| byte.is_ascii_hexdigit()));
    if valid {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "color must be empty or #rrggbb",
        ))
    }
}

/// Audit subject for branding events; the default tenant has no key to name.
fn branding_subject(tenant: &str) -> &str {
    if tenant.is_empty() {
        "default"
    } else {
        tenant
    }
}

/// Current branding for the admin form. Empty fields when no row exists.
pub async fn get_branding(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    let (tenant, _target_operation) = branding_tenant(&app, &key, &identity)?;
    let branding = app
        .store
        .branding(&tenant)
        .map_err(super::store_unavailable)?;
    Ok(Json(match branding {
        Some(branding) => json!({
            "name": branding.name,
            "color": branding.color,
            "has_logo": !branding.logo_ext.is_empty(),
            "footer_text": branding.footer_text,
            "footer_link_label": branding.footer_link_label,
            "footer_link_url": branding.footer_link_url,
        }),
        None => json!({ "name": "", "color": "", "has_logo": false }),
    }))
}

#[derive(Deserialize)]
pub struct PutBrandingRequest {
    name: String,
    #[serde(default)]
    color: String,
    footer_text: Option<String>,
    footer_link_label: Option<String>,
    footer_link_url: Option<String>,
}

/// Sets a tenant's recipient-facing name and accent color. The logo has its
/// own PUT; its stored extension survives this write.
pub async fn put_branding(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PutBrandingRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator_write(&app, &headers)?;
    let (tenant, _target_operation) = branding_tenant(&app, &key, &identity)?;
    admit_brand_color(&request.color)?;
    let previous = app
        .store
        .branding(&tenant)
        .map_err(super::store_unavailable)?
        .unwrap_or_default();
    let mut branding = crate::store::Branding {
        tenant: tenant.clone(),
        name: request.name.trim().to_owned(),
        color: request.color,
        footer_text: request
            .footer_text
            .unwrap_or(previous.footer_text)
            .trim()
            .into(),
        footer_link_label: request
            .footer_link_label
            .unwrap_or(previous.footer_link_label)
            .trim()
            .into(),
        footer_link_url: request
            .footer_link_url
            .unwrap_or(previous.footer_link_url)
            .trim()
            .into(),
        logo_ext: previous.logo_ext,
        updated_at: now_unix(),
    };
    admit_footer(&branding)?;
    if !branding.footer_link_url.is_empty() {
        branding.footer_link_url = reqwest::Url::parse(&branding.footer_link_url)
            .expect("validated footer URL")
            .to_string();
        admit_footer(&branding)?;
    }
    app.store
        .set_branding(&branding)
        .map_err(ApiError::internal)?;
    tracing::info!(target: "audit", event = "branding_updated", tenant = %tenant, "tenant branding updated");
    app.store.audit(
        &tenant,
        &identity.subject,
        "branding_updated",
        branding_subject(&tenant),
        &json!({ "name": branding.name, "color": branding.color }),
    );
    Ok(Json(json!({ "ok": true })))
}

fn admit_footer(branding: &crate::store::Branding) -> ApiResult<()> {
    for (value, limit) in [
        (&branding.footer_text, 160),
        (&branding.footer_link_label, 40),
        (&branding.footer_link_url, 2048),
    ] {
        if value.chars().count() > limit || value.chars().any(char::is_control) {
            return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "Footer text is limited to 160 characters, link labels to 40, and URLs to 2048; use a single line"));
        }
    }
    if branding.footer_link_url.is_empty() != branding.footer_link_label.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Provide both a footer link label and URL, or leave both blank",
        ));
    }
    if !branding.footer_link_url.is_empty()
        && reqwest::Url::parse(&branding.footer_link_url)
            .ok()
            .is_none_or(|url| {
                !["https", "http"].contains(&url.scheme())
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
            })
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Footer links must use an HTTP or HTTPS address without embedded credentials",
        ));
    }
    Ok(())
}

async fn remove_branding_file(
    path: std::path::PathBuf,
    operation: Arc<crate::session::OwnedOutboundOperation>,
) {
    let _ = tokio::task::spawn_blocking(move || {
        let _operation = operation;
        std::fs::remove_file(path)
    })
    .await;
}

/// Removes a tenant's branding row and any stored logo file.
pub async fn delete_branding(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator_write(&app, &headers)?;
    let (tenant, _target_operation) = branding_tenant(&app, &key, &identity)?;
    let logo_ext = app
        .store
        .branding(&tenant)
        .map_err(super::store_unavailable)?
        .map(|branding| branding.logo_ext)
        .ok_or_else(ApiError::not_found)?;
    app.store
        .delete_branding(&tenant)
        .map_err(ApiError::internal)?;
    if !logo_ext.is_empty() {
        let path = paths::branding_logo_path(&app.config.data_dir, &tenant, &logo_ext);
        remove_branding_file(path, Arc::clone(&_target_operation)).await;
    }
    tracing::info!(target: "audit", event = "branding_deleted", tenant = %tenant, "tenant branding removed");
    app.store.audit(
        &tenant,
        &identity.subject,
        "branding_deleted",
        branding_subject(&tenant),
        &json!({}),
    );
    Ok(Json(json!({ "ok": true })))
}

/// Declared logo type checked against the leading bytes. SVG has no magic
/// and is stored as declared; the serving CSP is what keeps it inert.
fn admit_logo(headers: &HeaderMap, bytes: &[u8]) -> ApiResult<&'static str> {
    let declared = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or(value).trim().to_owned())
        .unwrap_or_default();
    let (ext, sniffed) = match declared.as_str() {
        "image/png" => ("png", bytes.starts_with(b"\x89PNG\r\n\x1a\n")),
        "image/jpeg" => ("jpg", bytes.starts_with(b"\xff\xd8\xff")),
        "image/svg+xml" => ("svg", true),
        _ => {
            return Err(ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "logo must be image/png, image/jpeg, or image/svg+xml",
            ));
        }
    };
    if !sniffed {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "logo bytes do not match the declared type",
        ));
    }
    Ok(ext)
}

/// Stores a tenant logo, replacing any previous one atomically.
pub async fn put_branding_logo(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator_write(&app, &headers)?;
    let (tenant, _target_operation) = branding_tenant(&app, &key, &identity)?;
    if body.len() > MAX_LOGO_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "logo exceeds 512 KiB",
        ));
    }
    if body.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "logo body is empty",
        ));
    }
    let ext = admit_logo(&headers, &body)?;
    let target = paths::branding_logo_path(&app.config.data_dir, &tenant, ext);
    let directory = target.parent().expect("logo path has a parent").to_owned();
    let staged = target.with_extension(format!("{ext}.tmp"));
    let bytes = body.to_vec();
    let written: Result<(), String> = tokio::task::spawn_blocking({
        let target = target.clone();
        let operation = Arc::clone(&_target_operation);
        move || {
            let _operation = operation;
            std::fs::create_dir_all(&directory)
                .map_err(|error| format!("create {}: {error}", directory.display()))?;
            paths::tighten_private_dir(&directory)?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options
                .open(&staged)
                .map_err(|error| format!("create {}: {error}", staged.display()))?;
            use std::io::Write as _;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("write {}: {error}", staged.display()))?;
            drop(file);
            paths::tighten_private_file(&staged)?;
            std::fs::rename(&staged, &target)
                .map_err(|error| format!("publish {}: {error}", target.display()))
        }
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?;
    written.map_err(ApiError::internal)?;
    let previous = app
        .store
        .branding(&tenant)
        .map_err(super::store_unavailable)?;
    let previous_ext = previous
        .as_ref()
        .map(|branding| branding.logo_ext.clone())
        .unwrap_or_default();
    let branding = crate::store::Branding {
        tenant: tenant.clone(),
        logo_ext: ext.to_owned(),
        updated_at: now_unix(),
        ..previous.unwrap_or_default()
    };
    app.store
        .set_branding(&branding)
        .map_err(ApiError::internal)?;
    if !previous_ext.is_empty() && previous_ext != ext {
        let stale = paths::branding_logo_path(&app.config.data_dir, &tenant, &previous_ext);
        remove_branding_file(stale, Arc::clone(&_target_operation)).await;
    }
    tracing::info!(target: "audit", event = "branding_logo_updated", tenant = %tenant, "tenant logo stored");
    app.store.audit(
        &tenant,
        &identity.subject,
        "branding_logo_updated",
        branding_subject(&tenant),
        &json!({ "ext": ext, "bytes": body.len() }),
    );
    Ok(Json(json!({ "ok": true })))
}

/// Removes a tenant logo; the name and color survive.
pub async fn delete_branding_logo(
    State(app): State<Arc<App>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator_write(&app, &headers)?;
    let (tenant, _target_operation) = branding_tenant(&app, &key, &identity)?;
    let branding = app
        .store
        .branding(&tenant)
        .map_err(super::store_unavailable)?
        .filter(|branding| !branding.logo_ext.is_empty())
        .ok_or_else(ApiError::not_found)?;
    let path = paths::branding_logo_path(&app.config.data_dir, &tenant, &branding.logo_ext);
    app.store
        .set_branding(&crate::store::Branding {
            logo_ext: String::new(),
            updated_at: now_unix(),
            ..branding
        })
        .map_err(ApiError::internal)?;
    remove_branding_file(path, Arc::clone(&_target_operation)).await;
    tracing::info!(target: "audit", event = "branding_logo_deleted", tenant = %tenant, "tenant logo removed");
    app.store.audit(
        &tenant,
        &identity.subject,
        "branding_logo_deleted",
        branding_subject(&tenant),
        &json!({}),
    );
    Ok(Json(json!({ "ok": true })))
}

/// Whether deleting `key` may remove tenant subtrees. A key with a
/// separator was never usable as a namespace: `Tenant::path_prefix` hands the
/// whole key to `join_under` as one component, so no upload ever published
/// beneath it, and anything at that path belongs to a default-tenant link
/// whose dest is that string.
fn purges_tenant_subtrees(key: &str) -> bool {
    !key.contains('/')
}

fn tenant_receive_dir(
    receive_dir: &std::path::Path,
    key: &str,
) -> Result<std::path::PathBuf, String> {
    let path = paths::join_under(receive_dir, &paths::tenant_prefix(key))?;
    if path == *receive_dir {
        return Err("refusing to purge the receive root".to_owned());
    }
    Ok(path)
}

fn tenant_outbound_dir(
    outbound_dir: &std::path::Path,
    key: &str,
) -> Result<std::path::PathBuf, String> {
    let path = paths::join_under(outbound_dir, &paths::tenant_prefix(key))?;
    if path == *outbound_dir {
        return Err("refusing to purge the outbound root".to_owned());
    }
    Ok(path)
}

/// Builds the snapshot file for [`backup_database`]. Audit finding 500: a
/// failed export used to leave SQLite's partial, world-readable destination
/// in data/backups where only the 30-day legacy prune would take it; the
/// cleanup guard removes it unless the snapshot opens whole.
fn export_database_snapshot(
    store: &crate::store::Store,
    backups: &std::path::Path,
    destination: &std::path::Path,
) -> Result<std::fs::File, String> {
    let mut cleanup = crate::backup::CleanupPath::new(destination.to_path_buf());
    let Some(_root_lock) = crate::backup::try_lock_backup_root(backups)? else {
        return Err("backup root is busy".to_owned());
    };
    store.backup_into(destination)?;
    let file =
        std::fs::File::open(destination).map_err(|error| format!("open snapshot: {error}"))?;
    cleanup.keep();
    Ok(file)
}

/// Streams a consistent SQLite snapshot as a download. It writes a snapshot
/// file and an audit row, so it takes the CSRF header like every other
/// mutating route; the System page fetches it with the header and saves the
/// body itself.
pub async fn backup_database(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let identity = require_platform_admin_write(&app, &headers)?;
    let guard = Arc::clone(&app.backup_lock)
        .try_lock_owned()
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "backup already running"))?;
    let backups = app.config.data_dir.join("backups");
    let name = crate::backup::legacy_snapshot_filename();
    let destination = backups.join(&name);
    let store = Arc::clone(&app.store);
    let destination_clone = destination.clone();
    let file = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        export_database_snapshot(&store, &backups, &destination_clone)
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?
    .map_err(|error| {
        if error == "backup root is busy" {
            ApiError::new(StatusCode::CONFLICT, error)
        } else {
            ApiError::internal(error)
        }
    })?;
    let file = tokio::fs::File::from_std(file);
    let len = file
        .metadata()
        .await
        .map_err(|error| ApiError::internal(format!("snapshot metadata: {error}")))?
        .len();
    tracing::info!(target: "audit", event = "backup_created", file = %name, bytes = len, "database snapshot exported");
    app.store.audit(
        "",
        &identity.subject,
        "backup_created",
        &name,
        &json!({ "bytes": len }),
    );
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
            (header::CONTENT_LENGTH, len.to_string()),
        ],
        Body::from_stream(ReaderStream::new(file)),
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupConfigRequest {
    #[serde(flatten)]
    pub config: crate::backup::BackupConfig,
    #[serde(default, deserialize_with = "double_option")]
    pub access_key_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub secret_access_key: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub passphrase: Option<Option<String>>,
}

pub async fn get_backups(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let _identity = require_platform_admin(&app, &headers)?;
    let guard = app.backup_lock.try_lock().ok();
    let busy = guard.is_none();
    let paused_reason = crate::backup::ensure_no_pending_restore(&app.config.data_dir).err();
    let config = crate::backup::decode_config(
        app.store
            .setting(crate::backup::SETTING_KEY)
            .map_err(super::store_unavailable)?,
    )
    .map_err(ApiError::internal)?;
    let secrets = crate::backup::read_secrets(&app.config.data_dir).map_err(ApiError::internal)?;
    let local_root = config
        .local_root(&app.config.data_dir)
        .map_err(ApiError::internal)?;
    let (mut inventory, mut inventory_error) =
        match crate::backup::inventory_local_root(&local_root, &app.config.data_dir) {
            Ok(inventory) => (inventory, None),
            Err(error) => (Vec::new(), Some(error)),
        };
    if !busy
        && paused_reason.is_none()
        && matches!(
            config.destination,
            crate::backup::Destination::S3 | crate::backup::Destination::Both
        )
        && secrets.access_key_id.is_some()
        && secrets.secret_access_key.is_some()
    {
        match crate::backup::inventory_s3(&config, &secrets).await {
            Ok(remote) => inventory.extend(remote),
            Err(error) => inventory_error = Some(error),
        }
    }
    let mut status =
        crate::backup::read_status(&app.config.data_dir).map_err(ApiError::internal)?;
    status.running = busy;
    Ok(Json(json!({
        "config": config.public(&secrets),
        "schema_version": crate::store::SCHEMA_VERSION,
        "inventory": inventory,
        "inventory_error": inventory_error.map(|error| error.chars().take(512).collect::<String>()),
        "status": status,
        "paused_reason": paused_reason
    })))
}

pub async fn put_backups_config(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(mut body): Json<BackupConfigRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    for value in [
        &mut body.config.local_path,
        &mut body.config.s3_endpoint,
        &mut body.config.s3_region,
        &mut body.config.s3_bucket,
        &mut body.config.s3_prefix,
    ] {
        if value.as_deref().is_some_and(str::is_empty) {
            *value = None;
        }
    }
    for value in [
        body.access_key_id.as_ref().and_then(Option::as_ref),
        body.secret_access_key.as_ref().and_then(Option::as_ref),
        body.passphrase.as_ref().and_then(Option::as_ref),
    ] {
        if value.is_some_and(|value| value.is_empty()) {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "backup secrets must not be empty",
            ));
        }
        if value.is_some_and(|value| value.len() > 4096) {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "backup secret is too long",
            ));
        }
    }
    body.config
        .validate(&app.config.data_dir)
        .map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let _guard = app
        .backup_lock
        .try_lock()
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "backup already running"))?;
    let mut secrets =
        crate::backup::read_secrets(&app.config.data_dir).map_err(ApiError::internal)?;
    if let Some(value) = body.access_key_id {
        secrets.access_key_id = value;
    }
    if let Some(value) = body.secret_access_key {
        secrets.secret_access_key = value;
    }
    if let Some(value) = body.passphrase {
        secrets.passphrase = value;
    }
    secrets
        .validate()
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    if matches!(
        body.config.destination,
        crate::backup::Destination::S3 | crate::backup::Destination::Both
    ) && (secrets.access_key_id.is_none() || secrets.secret_access_key.is_none())
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "S3 credentials are required",
        ));
    }
    if body.config.encrypt && secrets.passphrase.is_none() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "encryption passphrase is required",
        ));
    }
    let mut disabled = body.config.clone();
    disabled.enabled = false;
    let disabled_value =
        serde_json::to_string(&disabled).map_err(|error| ApiError::internal(error.to_string()))?;
    app.store
        .put_settings(
            &identity.subject,
            &[(
                crate::backup::SETTING_KEY.to_owned(),
                crate::store::SettingWrite::Set(disabled_value),
            )],
        )
        .map_err(ApiError::internal)?;
    crate::backup::write_secrets(&app.config.data_dir, &secrets).map_err(ApiError::internal)?;
    if body.config.enabled {
        let value = serde_json::to_string(&body.config)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        app.store
            .put_settings(
                &identity.subject,
                &[(
                    crate::backup::SETTING_KEY.to_owned(),
                    crate::store::SettingWrite::Set(value),
                )],
            )
            .map_err(ApiError::internal)?;
    }
    app.store
        .audit("", &identity.subject, "backups_configured", "", &json!({}));
    Ok(Json(json!({ "config": body.config.public(&secrets) })))
}

pub async fn create_backup(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    let guard = Arc::clone(&app.backup_lock)
        .try_lock_owned()
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "backup already running"))?;
    crate::backup::ensure_no_pending_restore(&app.config.data_dir)
        .map_err(|error| ApiError::new(StatusCode::CONFLICT, error))?;
    let config = crate::backup::parse_config(
        app.store
            .setting(crate::backup::SETTING_KEY)
            .map_err(super::store_unavailable)?,
        &app.config.data_dir,
    )
    .map_err(ApiError::internal)?;
    let secrets = crate::backup::read_secrets(&app.config.data_dir).map_err(ApiError::internal)?;
    let id = crate::backup::run_with_guard(Arc::clone(&app), config, secrets, guard)
        .await
        .map_err(|error| {
            if error == "backup root is busy" {
                ApiError::new(StatusCode::CONFLICT, error)
            } else {
                ApiError::internal(error)
            }
        })?;
    app.store
        .audit("", &identity.subject, "backup_created", &id, &json!({}));
    Ok(Json(json!({ "id": id })))
}

/// Audit finding 371: without this route no control could discard a backup
/// copy, so pre-erasure archives holding the full database lived forever.
/// Source-scoped because an id can exist in both the local root and S3.
pub async fn delete_backup(
    State(app): State<Arc<App>>,
    Path((source, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    crate::backup::validate_id(&id)
        .map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let _guard = Arc::clone(&app.backup_lock)
        .try_lock_owned()
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "backup already running"))?;
    crate::backup::ensure_no_pending_restore(&app.config.data_dir)
        .map_err(|error| ApiError::new(StatusCode::CONFLICT, error))?;
    let config = crate::backup::parse_config(
        app.store
            .setting(crate::backup::SETTING_KEY)
            .map_err(super::store_unavailable)?,
        &app.config.data_dir,
    )
    .map_err(ApiError::internal)?;
    let deleted = match source.as_str() {
        "local" => {
            let root = config
                .local_root(&app.config.data_dir)
                .map_err(ApiError::internal)?;
            crate::backup::delete_local_backup(&root, &id).map_err(ApiError::internal)?
        }
        "s3" => {
            if !matches!(
                config.destination,
                crate::backup::Destination::S3 | crate::backup::Destination::Both
            ) {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "S3 backups are not configured",
                ));
            }
            let secrets =
                crate::backup::read_secrets(&app.config.data_dir).map_err(ApiError::internal)?;
            if secrets.access_key_id.is_none() || secrets.secret_access_key.is_none() {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "S3 credentials are required",
                ));
            }
            crate::backup::delete_s3_backup(&config, &secrets, &id)
                .await
                .map_err(ApiError::internal)?
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "source must be local or s3",
            ))
        }
    };
    if !deleted {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "backup_deleted", id = %id, source = %source, "request backup copy deleted");
    app.store.audit(
        "",
        &identity.subject,
        "backup_deleted",
        &id,
        &json!({ "source": source }),
    );
    Ok(Json(json!({ "ok": true })))
}

pub async fn restore_backup(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<crate::backup::RestoreRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    crate::backup::validate_id(&body.id)
        .map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let guard = Arc::clone(&app.backup_lock)
        .try_lock_owned()
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "backup already running"))?;
    let subject = identity.subject.clone();
    tokio::spawn(restore_backup_operation(app, body, subject, guard))
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
}

async fn restore_backup_operation(
    app: Arc<App>,
    body: crate::backup::RestoreRequest,
    subject: String,
    _guard: tokio::sync::OwnedMutexGuard<()>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::backup::ensure_no_pending_restore(&app.config.data_dir)
        .map_err(|error| ApiError::new(StatusCode::CONFLICT, error))?;
    let config = crate::backup::parse_config(
        app.store
            .setting(crate::backup::SETTING_KEY)
            .map_err(super::store_unavailable)?,
        &app.config.data_dir,
    )
    .map_err(ApiError::internal)?;
    let secrets = crate::backup::read_secrets(&app.config.data_dir).map_err(ApiError::internal)?;
    let stage = app.config.data_dir.join(format!(
        ".votport-restore-stage-{}",
        crate::auth::random_token()
    ));
    std::fs::create_dir(&stage).map_err(|e| ApiError::internal(e.to_string()))?;
    paths::tighten_private_dir(&stage).map_err(ApiError::internal)?;
    let stage_cleanup = crate::backup::CleanupPath::directory(stage.clone());
    let incoming = app.config.data_dir.join(format!(
        ".votport-restore-{}.download",
        crate::auth::random_token()
    ));
    let _incoming_cleanup = crate::backup::CleanupPath::new(incoming.clone());
    let root_lock = if body.source == "local" {
        let local_root = config
            .local_root(&app.config.data_dir)
            .map_err(ApiError::internal)?;
        let Some(lock) =
            crate::backup::try_lock_backup_root(&local_root).map_err(ApiError::internal)?
        else {
            return Err(ApiError::new(StatusCode::CONFLICT, "backup root is busy"));
        };
        Some(lock)
    } else {
        None
    };
    if body.source == "local" {
        let local_root = config
            .local_root(&app.config.data_dir)
            .map_err(ApiError::internal)?;
        let source = local_root.join(&body.id);
        let source_meta = std::fs::symlink_metadata(&source)
            .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "backup not found"))?;
        if source_meta.file_type().is_symlink() || !source_meta.file_type().is_file() {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "backup not found"));
        }
        let output = incoming.clone();
        let root_file = root_lock.as_ref().map(|lock| Arc::clone(&lock.file));
        tokio::task::spawn_blocking(move || {
            let _root_file = root_file;
            crate::backup::copy_private_file(&source, &output)
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(ApiError::internal)?;
    } else if body.source == "s3" {
        crate::backup::download_s3(&config, &secrets, &body.id, &incoming)
            .await
            .map_err(ApiError::internal)?;
    } else {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "source must be local or s3",
        ));
    }
    let tar_path = app.config.data_dir.join(format!(
        ".votport-restore-{}.tar",
        crate::auth::random_token()
    ));
    let _tar_cleanup = crate::backup::CleanupPath::new(tar_path.clone());
    if body.id.ends_with(".age") {
        let pass = secrets
            .passphrase
            .as_deref()
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "encryption passphrase is not configured",
                )
            })?
            .to_owned();
        let input = incoming.clone();
        let output = tar_path.clone();
        tokio::task::spawn_blocking(move || crate::backup::decrypt_file(&input, &output, &pass))
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
            .map_err(ApiError::internal)?;
    } else {
        tokio::fs::rename(&incoming, &tar_path)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    }
    let extracted = stage.clone();
    let tar_for_extract = tar_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        crate::backup::validate_and_extract(
            &tar_for_extract,
            &extracted,
            crate::store::SCHEMA_VERSION,
        )
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
    .map_err(|_| {
        // Findings 551 and 555: an unreadable archive (raw tar-parser text)
        // and a newer-schema or archive-format refusal are the caller's
        // input, not server faults, so one fixed sentence answers 422
        // instead of a retryable 500 quoting the parser.
        ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "This file is not a votport backup this server can restore.",
        )
    })?;
    crate::backup::write_pending_restore(
        &app.config.data_dir,
        stage_cleanup,
        result.clone(),
        crate::backup::RestoreMode::Historical,
        Some(&body.id),
    )
    .map_err(ApiError::internal)?;
    app.store.audit(
        "",
        &subject,
        "backup_restore_pending",
        &body.id,
        &json!({ "version": result.version }),
    );
    tracing::info!(
        target: "audit",
        event = "backup_restore_pending",
        id = %body.id,
        source = %body.source,
        version = result.version,
        "backup restore staged"
    );
    app.request_shutdown();
    Ok(Json(json!({ "pending": true, "restart_required": true })))
}

const SETTINGS_KEYS: &[&str] = &[
    "smtp_host",
    "smtp_port",
    "smtp_starttls",
    "smtp_username",
    "smtp_password",
    "smtp_from",
    "audit_retention_days",
    "upload_retention_days",
    "default_max_total_bytes",
    "default_max_links",
    "default_max_sessions",
    "public_password_login",
    "sso_session_secs",
    "scim_token",
    "scim_token_previous",
    "replica_token",
    "require_provisioning",
    "draining",
];

pub async fn get_settings(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    settings_response(app, identity).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionClockAcknowledgement {
    pub observed_at: u64,
}

pub async fn acknowledge_retention_clock(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<RetentionClockAcknowledgement>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    match app.acknowledge_retention_clock_at(&identity.subject, request.observed_at, now_unix()) {
        Ok(()) => {}
        Err(crate::app::RetentionClockAcknowledgementError::FutureObservation) => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "displayed server time is in the future; refresh settings before confirming it",
            ));
        }
        Err(crate::app::RetentionClockAcknowledgementError::Store(error)) => {
            return Err(super::store_unavailable(error));
        }
    }
    settings_response(app, identity).await
}

pub async fn get_receiving_storage(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin(&app, &headers)?;
    let permit = Arc::clone(&app.receiving_permits)
        .acquire_owned()
        .await
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "receiving storage stopped"))?;
    tokio::task::spawn_blocking(move || {
        let (_identity, _permit) = (identity, permit);
        receiving_storage_json(&app).map(Json)
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?
}

fn receiving_storage_json(app: &App) -> ApiResult<serde_json::Value> {
    let storage = crate::receiving::storage_identity(&app.config.receive_dir);
    let active = app.receiving_destinations();
    let saved =
        crate::receiving::saved_qualification(&app.store).map_err(super::store_unavailable)?;
    let nas = storage_is_nas(storage.as_ref().ok());
    Ok(json!({
        "path": app.config.receive_dir,
        "storage": storage.as_ref().ok(),
        "qualified": saved,
        "ready": active.is_ok(),
        "error": storage.err().or_else(|| active.err()),
        "nas": nas,
    }))
}

fn storage_is_nas(storage: Option<&crate::receiving::StorageIdentity>) -> bool {
    storage.is_some_and(|storage| {
        matches!(
            storage.filesystem.as_str(),
            "cifs" | "smb3" | "nfs" | "nfs4"
        )
    })
}

fn save_nas_qualification(
    store: &crate::store::Store,
    actor: &str,
    storage: crate::receiving::StorageIdentity,
    qualified_at: u64,
) -> Result<(), String> {
    let qualification = crate::receiving::Qualification {
        storage,
        qualified_at,
        qualified_by: actor.to_owned(),
    };
    let value = serde_json::to_string(&qualification).map_err(|error| error.to_string())?;
    store.put_settings(
        actor,
        &[(
            crate::receiving::SETTING_KEY.to_owned(),
            crate::store::SettingWrite::Set(value),
        )],
    )?;
    let detail = json!({
        "storage": qualification.storage,
        "qualified_at": qualification.qualified_at,
    });
    tracing::info!(
        target: "audit",
        event = "receiving_nas_qualification_saved",
        actor = %actor,
        storage = %qualification.storage.path.display(),
        qualified_at = qualification.qualified_at,
        "NAS qualification saved"
    );
    store.audit(
        "",
        actor,
        "receiving_nas_qualification_saved",
        crate::receiving::SETTING_KEY,
        &detail,
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivingStorageCheck {
    storage: crate::receiving::StorageIdentity,
    #[serde(default)]
    enable: bool,
    #[serde(default)]
    stable_acknowledgments: bool,
    #[serde(default)]
    private_namespace: bool,
}

pub async fn check_receiving_storage(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<ReceivingStorageCheck>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    let permit = Arc::clone(&app.receiving_reconfigure)
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::new(
                StatusCode::CONFLICT,
                "Storage is already being checked or is stopped.",
            )
        })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let conflict = |message| ApiError::new(StatusCode::CONFLICT, message);
        app.config
            .validate_storage_roots()
            .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
        let current = app.receiving.lock().expect("receiving state poisoned").clone();
        if crate::receiving::storage_identity(&app.config.receive_dir).map_err(ApiError::internal)? != request.storage {
            return Err(conflict("Storage changed. Refresh this page and review the current mount."));
        }
        if let Ok(active) = current.as_ref() {
            active.destinations.probe().map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
        } else {
            let nas = storage_is_nas(Some(&request.storage));
            if nas && (!request.enable || !request.stable_acknowledgments || !request.private_namespace) {
                return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY,
                    "Review the NAS server's stable acknowledgements and private namespace before enabling receiving."));
            }
            if app.lease_lost.load(std::sync::atomic::Ordering::Relaxed) || app.sessions.total() != 0 {
                return Err(conflict("Receiving ownership changed or transfers are active. Restart before reconfiguring storage."));
            }
            if !nas && crate::receiving::saved_qualification(&app.store).map_err(super::store_unavailable)?.is_some() {
                return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "The qualified NAS is missing. Restore its mount before enabling receiving."));
            }
            let contract = if nas { vot_sdk_file::NasContract::ServerAcknowledged } else { vot_sdk_file::NasContract::Unqualified };
            let destinations = crate::receiving::Destinations::open(&app.config.receive_dir, contract)
                .map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
            if destinations.identity().map_err(ApiError::internal)? != request.storage {
                return Err(conflict("Storage changed while checking it. Refresh and retry."));
            }
            let active = crate::receiving::Active::open(destinations, &app.lease_holder)
                .map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, e))?;
            if nas {
                save_nas_qualification(&app.store, &identity.subject, request.storage, now_unix())
                    .map_err(super::store_unavailable)?;
            }
            if let Err(error) = app.resume_receiving(&active) {
                app.lease_lost.store(true, std::sync::atomic::Ordering::Release);
                return Err(super::store_unavailable(error));
            }
            let mut state = app.receiving.lock().expect("receiving state poisoned");
            if app.lease_lost.load(std::sync::atomic::Ordering::Acquire) || state.is_ok() {
                drop(state);
                return Err(conflict("Receiving ownership changed or transfers are active. Restart before reconfiguring storage."));
            }
            *state = Ok(Arc::new(active));
        }
        receiving_storage_json(&app).map(Json)
    }).await.map_err(|e| ApiError::internal(e.to_string()))?
}

fn deployment_commit_profile(root: &std::path::Path) -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        match paths::commit_profile(&root.join(".vot-profile.stage")) {
            Ok(vot_sdk_file::CommitProfile::Fast) => Some("fast"),
            Ok(vot_sdk_file::CommitProfile::Balanced) => Some("balanced"),
            _ => None,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        None
    }
}

async fn settings_response(
    app: Arc<App>,
    identity: AdminSession,
) -> ApiResult<Json<serde_json::Value>> {
    let permit = Arc::clone(&app.receiving_permits)
        .acquire_owned()
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "receiving storage is stopped",
            )
        })?;
    tokio::task::spawn_blocking(move || {
        let (_identity, _permit) = (identity, permit);
        settings_json(&app).map(Json)
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?
}

fn settings_json(app: &App) -> ApiResult<serde_json::Value> {
    let overlay = app
        .store
        .overlay(&app.config)
        .map_err(super::store_unavailable)?;
    let resolved = &overlay.resolved;
    let oidc = app.config.oidc.as_ref();
    let deployment = json!({
        // Deployment values are intentionally read-only. Secret-bearing
        // values are represented by a configured flag, never their contents.
        "bind": app.config.bind.to_string(),
        "public_url": app.config.public_url,
        "data_dir": app.config.data_dir,
        "receive_dir": app.config.receive_dir,
        "receive_commit_profile": app.receiving_destinations().ok().map(|_| "balanced"),
        "outbound_dir": app.config.outbound_dir,
        "outbound_filesystem_profile": deployment_commit_profile(&app.config.outbound_dir),
        "web_root": app.config.web_root,
        "max_upload_bytes": app.config.max_upload_bytes,
        "allow_hidden": app.config.allow_hidden,
        "session_idle_secs": app.config.session_idle_secs,
        "max_total_sessions": app.config.max_total_sessions,
        "max_link_sessions": app.config.max_link_sessions,
        "trusted_proxies": app.config.trusted_proxies.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "metrics_configured": app.config.metrics_token.is_some(),
        "push_bind": app.config.push_bind.map(|value| value.to_string()),
        "push_advertise": app.config.push_advertise,
        "push_certificate": app.config.push_certificate,
        "push_certificate_configured": app.config.push_certificate.is_some(),
        "push_private_key_configured": app.config.push_private_key.is_some(),
        "push_configured": app.config.push_bind.is_some(),
        "oidc_issuer": oidc.map(|value| value.issuer.clone()),
        "oidc_client_id": oidc.map(|value| value.client_id.clone()),
        "oidc_admin_group": oidc.and_then(|value| value.admin_group.clone()),
        "oidc_client_secret_configured": oidc.is_some_and(|value| !value.client_secret.is_empty()),
        "oidc_configured": oidc.is_some(),
    });
    Ok(json!({
        "overridden_keys": overlay.overridden_keys,
        "smtp_host": overlay.smtp_host,
        "smtp_port": overlay.smtp_port,
        "smtp_starttls": overlay.smtp_starttls,
        "smtp_username": overlay.smtp_username,
        "smtp_password_set": overlay.smtp_password_set,
        "smtp_from": overlay.smtp_from,
        "audit_retention_days": resolved.audit_retention_days,
        "upload_retention_days": resolved.upload_retention_days,
        "default_max_total_bytes": resolved.default_max_total_bytes,
        "default_max_links": resolved.default_max_links,
        "default_max_sessions": resolved.default_max_sessions,
        "public_password_login": resolved.public_password_login,
        "sso_session_secs": resolved.sso_session_secs,
        "scim_token_set": overlay.scim_token_set,
        "scim_token_previous_set": overlay.scim_token_previous_set,
        "replica_token_set": overlay.replica_token_set,
        "require_provisioning": resolved.require_provisioning,
        "draining": resolved.draining,
        "retention_clock": app.retention_clock_status(),
        "sso_configured": app.sso_config.is_some(),
        "deployment": deployment,
    }))
}

pub(crate) fn write_url(
    key: &str,
    value: &serde_json::Value,
) -> ApiResult<crate::store::SettingWrite> {
    match value {
        serde_json::Value::Null => Ok(crate::store::SettingWrite::Reset),
        serde_json::Value::String(text) if text.is_empty() => {
            Ok(crate::store::SettingWrite::Set(String::new()))
        }
        serde_json::Value::String(text)
            if text.len() <= 8192 && !text.chars().any(char::is_control)
                && reqwest::Url::parse(text).is_ok_and(|url| {
                    matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
                        && url.username().is_empty() && url.password().is_none() && url.fragment().is_none()
                }) =>
        {
            Ok(crate::store::SettingWrite::Set(text.clone()))
        }
        serde_json::Value::String(_) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be an http:// or https:// URL of at most 8192 bytes, without credentials, fragments or control characters"),
        )),
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be a string or null"),
        )),
    }
}

fn write_secret(key: &str, value: &serde_json::Value) -> ApiResult<crate::store::SettingWrite> {
    match value {
        serde_json::Value::Null => Ok(crate::store::SettingWrite::Reset),
        serde_json::Value::String(text) => Ok(crate::store::SettingWrite::Set(text.clone())),
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be a string or null"),
        )),
    }
}

fn write_u64(
    key: &str,
    value: &serde_json::Value,
    allow_zero: bool,
    max: Option<u64>,
) -> ApiResult<crate::store::SettingWrite> {
    match value {
        serde_json::Value::Null => Ok(crate::store::SettingWrite::Reset),
        serde_json::Value::Number(number) => {
            let Some(parsed) = number.as_u64() else {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("{key} must be a non-negative integer"),
                ));
            };
            if !allow_zero && parsed == 0 {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("{key} must be greater than zero"),
                ));
            }
            if let Some(max) = max {
                if parsed > max {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("{key} must be at most {max}"),
                    ));
                }
            }
            Ok(crate::store::SettingWrite::Set(parsed.to_string()))
        }
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be a number or null"),
        )),
    }
}

fn write_smtp_port(key: &str, value: &serde_json::Value) -> ApiResult<crate::store::SettingWrite> {
    match value {
        serde_json::Value::Null => Ok(crate::store::SettingWrite::Reset),
        serde_json::Value::Number(number) => {
            let Some(parsed) = number.as_u64() else {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("{key} must be a non-negative integer"),
                ));
            };
            if !(1..=65535).contains(&parsed) {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("{key} must be 1..=65535"),
                ));
            }
            Ok(crate::store::SettingWrite::Set(parsed.to_string()))
        }
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be a number or null"),
        )),
    }
}

fn write_bool(key: &str, value: &serde_json::Value) -> ApiResult<crate::store::SettingWrite> {
    match value {
        serde_json::Value::Null => Ok(crate::store::SettingWrite::Reset),
        serde_json::Value::Bool(true) => Ok(crate::store::SettingWrite::Set("1".to_owned())),
        serde_json::Value::Bool(false) => Ok(crate::store::SettingWrite::Set("0".to_owned())),
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{key} must be a boolean or null"),
        )),
    }
}

pub async fn put_settings(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_platform_admin_write(&app, &headers)?;
    let object = body
        .as_object()
        .ok_or_else(|| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "expected a JSON object"))?;
    for key in object.keys() {
        if !SETTINGS_KEYS.contains(&key.as_str()) {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("unknown setting {key}"),
            ));
        }
    }
    let mut writes = Vec::new();
    let mut keys = Vec::new();
    let mut reset = Vec::new();
    // Old and new values for the audit trail. Secret-bearing settings record
    // only that the value moved, never the value itself.
    const SENSITIVE_SETTINGS: &[&str] = &[
        "smtp_password",
        "scim_token",
        "scim_token_previous",
        "replica_token",
    ];
    let current = app.store.settings_map().map_err(ApiError::internal)?;
    let mut changes = serde_json::Map::new();
    fn record_change(
        key: &str,
        old: Option<&String>,
        new: Option<&str>,
        changes: &mut serde_json::Map<String, serde_json::Value>,
    ) {
        changes.insert(
            key.to_owned(),
            if SENSITIVE_SETTINGS.contains(&key) {
                json!({
                    "changed": old.map(String::as_str) != new,
                    "from_set": old.is_some(),
                    "to_set": new.is_some(),
                })
            } else {
                json!({ "from": old, "to": new })
            },
        );
    }
    for key in SETTINGS_KEYS {
        let Some(value) = object.get(*key) else {
            continue;
        };
        let write = match *key {
            "smtp_host"
            | "smtp_username"
            | "smtp_password"
            | "smtp_from"
            | "scim_token"
            | "scim_token_previous"
            | "replica_token" => write_secret(key, value)?,
            "audit_retention_days" | "upload_retention_days" => write_u64(key, value, true, None)?,
            "default_max_total_bytes" | "default_max_links" | "default_max_sessions" => {
                write_u64(key, value, false, None)?
            }
            "sso_session_secs" => write_u64(key, value, false, Some(MAX_SSO_SESSION_SECS))?,
            "public_password_login" | "smtp_starttls" | "draining" | "require_provisioning" => {
                write_bool(key, value)?
            }
            "smtp_port" => write_smtp_port(key, value)?,
            _ => unreachable!(),
        };
        // SCIM bearers are stored hashed, and saving a new one keeps the
        // one it replaces valid as scim_token_previous until it is cleared.
        let write = match (*key, write) {
            (
                "scim_token" | "scim_token_previous" | "replica_token",
                crate::store::SettingWrite::Set(text),
            ) if !text.is_empty() => {
                if *key == "scim_token" {
                    if let Some(previous) = app
                        .store
                        .setting("scim_token")
                        .map_err(ApiError::internal)?
                    {
                        if !previous.is_empty() && !object.contains_key("scim_token_previous") {
                            record_change(
                                "scim_token_previous",
                                current.get("scim_token_previous"),
                                Some(previous.as_str()),
                                &mut changes,
                            );
                            writes.push((
                                "scim_token_previous".to_owned(),
                                crate::store::SettingWrite::Set(previous),
                            ));
                            keys.push("scim_token_previous".to_owned());
                        }
                    }
                }
                crate::store::SettingWrite::Set(super::scim::hash_bearer(&text))
            }
            (_, write) => write,
        };
        match &write {
            crate::store::SettingWrite::Reset => reset.push((*key).to_owned()),
            crate::store::SettingWrite::Set(_) => keys.push((*key).to_owned()),
        }
        record_change(
            key,
            current.get(*key),
            match &write {
                crate::store::SettingWrite::Set(value) => Some(value.as_str()),
                crate::store::SettingWrite::Reset => None,
            },
            &mut changes,
        );
        writes.push(((*key).to_owned(), write));
    }
    if !writes.is_empty() {
        app.store
            .put_settings(&identity.subject, &writes)
            .map_err(ApiError::internal)?;
        tracing::info!(
            target: "audit",
            event = "settings_updated",
            keys = keys.len(),
            reset = reset.len(),
            "admin settings updated"
        );
        app.store.audit(
            "",
            &identity.subject,
            "settings_updated",
            "",
            &json!({ "keys": keys, "reset": reset, "changes": changes }),
        );
    }
    settings_response(app, identity).await
}

#[derive(Deserialize)]
pub struct SwitchTenantRequest {
    tenant: String,
}

/// Switches the active tenant, reissuing the session cookie. SSO sessions
/// honor grants already in the cookie; local sessions use live grants from
/// `store.tenants()`.
pub async fn switch_tenant(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<SwitchTenantRequest>,
) -> ApiResult<Response> {
    let (identity, expires) = require_admin_session(&app, &headers)?;
    require_csrf_header(&headers)?;
    let Some(grant) = identity
        .grants
        .iter()
        .find(|grant| grant.tenant == request.tenant)
    else {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "no access to that tenant",
        ));
    };
    let _target_operation = tenant_operation(&app, &grant.tenant)?;
    if !grant.tenant.is_empty() {
        let current = app
            .store
            .tenant(&grant.tenant)
            .map_err(super::store_unavailable)?
            .ok_or_else(ApiError::unauthorized)?;
        if grant.incarnation.as_deref() != Some(current.incarnation.as_str()) {
            return Err(ApiError::unauthorized());
        }
    }
    let switched = auth::AdminIdentity {
        tenant: grant.tenant.clone(),
        role: grant.role.clone(),
        credential_version: identity.credential_version,
        // The local admin's grants are recomputed from the store on every
        // request, so the cookie never needs to carry them; with many tenants
        // they push the cookie past the 4096-byte limit browsers accept and
        // the switch silently no-ops. Non-local identities keep their
        // self-contained grants because the incarnation checks read them.
        grants: if identity.subject == "local" {
            Vec::new()
        } else {
            identity.grants.clone()
        },
        subject: identity.subject.clone(),
    };
    tracing::info!(
        target: "audit", event = "tenant_switched",
        subject = %identity.subject, from = %identity.tenant, to = %switched.tenant,
        "admin switched active tenant"
    );
    app.store.audit(
        &switched.tenant,
        &identity.subject,
        "tenant_switched",
        &switched.tenant,
        &json!({ "from": identity.tenant }),
    );
    let cookie = issue_admin_cookie(&app, &switched, Some(expires))?;
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    current: String,
    new: String,
}

/// Replaces the admin password. The new hash is persisted in the store, which
/// from then on takes precedence over the environment. Token MACs cover that
/// hash, so every outstanding admin session is invalidated by the change; the
/// response reissues a cookie under the new hash so the acting admin stays
/// signed in.
pub async fn admin_change_password(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> ApiResult<Response> {
    let identity = require_operator_write(&app, &headers)?;
    // Read while the old cookie still verifies: the new hash ends it.
    let (_, session_expires) = require_admin_session(&app, &headers)?;
    // The local password is the break-glass credential for the platform;
    // SSO tenant admins rotate access at their identity provider instead.
    if !identity.tenant.is_empty() || identity.role != "admin" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "the local administrator password is managed by the default-tenant admin",
        ));
    }
    // Validate before claiming. A request rejected on its own shape never
    // reaches a password, so charging it against the guess budget would let a
    // script with a too-short new password lock every admin out of rotation.
    if request.new.chars().count() < crate::config::MIN_ADMIN_PASSWORD_CHARS {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "new password must be at least {} characters",
                crate::config::MIN_ADMIN_PASSWORD_CHARS
            ),
        ));
    }
    // Claimed before the verify, like sign-in: a caller holding a session
    // could otherwise fire many concurrent guesses that all pass the check
    // together, making this the oracle the throttle exists to prevent.
    if !app.change_password_throttle.claim() {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed attempts; wait a minute",
        )
        .with_retry_after(60));
    }
    // Its own budget, not the sign-in one: rotating the password is what an
    // operator does while under attack, so an anonymous sign-in flood must
    // not queue ahead of it.
    let permit = Arc::clone(&app.change_password_permits)
        .acquire_owned()
        .await
        .map_err(|_| ApiError::internal("login semaphore closed"))?;
    let current_ok = tokio::task::spawn_blocking({
        let hash = admin_hash(&app)?;
        let current = request.current.clone();
        move || {
            let _permit = permit;
            auth::verify_password(&current, &hash)
        }
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?;
    // Its own counter: sharing the sign-in one let anonymous login failures
    // keep an operator from rotating the password.
    if current_ok {
        app.change_password_throttle.succeeded();
    }
    if !current_ok {
        // Same disclosure as the sign-in failure row: the address and the
        // fact that the check failed, never the password material.
        let ip = super::client_ip(&headers, &peer, &app.config.trusted_proxies);
        tracing::warn!(
            target: "audit", event = "admin_password_change_failed", %ip,
            "admin password change refused"
        );
        app.store.audit(
            "",
            "",
            "admin_password_change_failed",
            &ip,
            &serde_json::json!({}),
        );
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "current password is wrong",
        ));
    }
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&request.new))
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .map_err(ApiError::internal)?;
    app.store
        .set_admin_password_hash(hash)
        .map_err(ApiError::internal)?;
    tracing::info!(target: "audit", event = "admin_password_changed", subject = %identity.subject, "admin password changed; outstanding sessions invalidated");
    app.store.audit(
        "",
        &identity.subject,
        "admin_password_changed",
        "",
        &serde_json::json!({}),
    );
    // The caller keeps their own identity: an SSO admin who rotates the
    // break-glass password stays attributable and revocable, with the
    // session end their sign-in already had.
    // The local session keeps its single-grant shape: its verified grants
    // list every tenant, which can push the cookie past what browsers keep.
    let (reissued, expires) = if identity.subject == "local" {
        (auth::AdminIdentity::local_admin(), None)
    } else {
        (identity.identity.clone(), Some(session_expires))
    };
    let cookie = issue_admin_cookie(&app, &reissued, expires)?;
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

// ------------------------------------------------------------ link management

#[derive(Serialize)]
struct LinkView {
    id: String,
    label: String,
    dest: String,
    url: String,
    has_password: bool,
    created_at: u64,
    expires_at: Option<u64>,
    max_bytes: Option<u64>,
    active: bool,
    legal_hold: bool,

    notifications: Option<crate::store::NotificationPolicy>,
    /// Finding 378: link-scoped upload retention in days, if any.
    retention_days: Option<u64>,
    /// Finding 24: requested publication verification level.
    verification: String,
    usable: bool,
    upload_count: u64,
    upload_bytes: u64,
    events: Vec<crate::store::SessionEvent>,
    /// Sessions receiving into this link right now.
    receiving: Vec<crate::session::ActiveTransfer>,
    workflow: Option<crate::workflow::ReceiveWorkflow>,
}

#[derive(Serialize)]
struct UploadView {
    position: i64,
    file_count: usize,
    route: Option<serde_json::Value>,
    id: String,
    started_at: u64,
    completed_at: u64,
    transport: String,
    replayed_chunks: u64,
    rejected_chunks: u64,
    package_root: String,
    total_bytes: u64,
    partial: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    log: Option<Vec<crate::store::LogEvent>>,
}

#[derive(Serialize)]
struct FileView {
    file_index: usize,
    path: String,
    stored_as: String,
    bytes: u64,
    suite: String,
    root: String,
    receipt: bool,
    /// Whether the stored file is still on disk right now.
    exists: bool,
}

#[derive(Deserialize)]
pub struct LinkQuery {
    limit: Option<u64>,
    search: Option<String>,
    status: Option<String>,
    before_created_at: Option<u64>,
    before_id: Option<String>,
    #[serde(default)]
    route_eligible: bool,
}

pub(crate) fn base_url(app: &App, headers: &HeaderMap) -> String {
    if let Some(url) = &app.config.public_url {
        return url.clone();
    }
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("http");
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    format!("{proto}://{host}")
}

/// The on-disk path a file record points at, from server-recorded components
/// only; client input never reaches this. None when a stored record fails the
/// join guard (a corrupted record), which the display treats as "missing".
pub(crate) fn stored_path(app: &App, tenant: &str, stored_as: &str) -> Option<std::path::PathBuf> {
    // stored_as is relative to the tenant's own subtree: the session builds
    // it from the link dest, while the tenant prefix is added separately when
    // the destination directory is assembled. Joining it straight under the
    // receive root resolves a tenant's file to the default tenant's path,
    // which is one namespace reading and deleting another's bytes.
    let mut components = paths::tenant_prefix(tenant);
    components.extend(
        stored_as
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned),
    );
    paths::join_under(&app.config.receive_dir, &components).ok()
}

fn link_view(
    app: &App,
    link: Link,
    base: &str,
    transfers: &[crate::session::ActiveTransfer],
    totals: (u64, u64),
) -> ApiResult<LinkView> {
    let workflow = app
        .store
        .receive_workflow(&link.tenant, &link.id)
        .map_err(super::store_unavailable)?;
    let receiving = transfers
        .iter()
        .filter(|transfer| transfer.link_id == link.id)
        .cloned()
        .collect();
    Ok(LinkView {
        workflow,
        url: format!("{base}/r/{}", link.id),
        usable: link.usable_now(),
        receiving,
        id: link.id,
        label: link.label,
        dest: link.dest,
        has_password: link.password_hash.is_some(),
        created_at: link.created_at,
        expires_at: link.expires_at,
        max_bytes: link.max_bytes,
        active: link.active,
        legal_hold: link.legal_hold,
        notifications: link.notifications,
        retention_days: link.retention_days,
        verification: link.verification,
        upload_count: totals.0,
        upload_bytes: totals.1,
        events: link.events,
    })
}

fn upload_view(header: crate::store::UploadHeader, include_log: bool) -> UploadView {
    let upload = header.upload;
    UploadView {
        position: header.position,
        file_count: header.file_count,
        route: header.route,
        id: upload.id,
        started_at: upload.started_at,
        completed_at: upload.completed_at,
        transport: upload.transport.unwrap_or_else(|| "http".to_owned()),
        replayed_chunks: upload.replayed_chunks,
        rejected_chunks: upload.rejected_chunks,
        package_root: upload.package_root,
        total_bytes: upload.total_bytes,
        partial: upload.partial,
        log: include_log.then_some(upload.log),
    }
}

fn file_view(app: &App, tenant: &str, index: usize, file: crate::store::FileRecord) -> FileView {
    FileView {
        file_index: index,
        exists: !file.deleted
            && stored_path(app, tenant, &file.stored_as)
                .and_then(|path| std::fs::symlink_metadata(path).ok())
                .is_some_and(|metadata| metadata.is_file() && metadata.len() == file.bytes),
        path: file.path,
        stored_as: file.stored_as,
        bytes: file.bytes,
        suite: file.suite,
        root: file.root,
        receipt: file.receipt,
    }
}

pub async fn list_links(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<LinkQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    let base = base_url(&app, &headers);
    let limit = query.limit.unwrap_or(50);
    validate_page_limit(limit)?;
    let status = query
        .status
        .as_deref()
        .unwrap_or("all")
        .to_ascii_lowercase();
    if !matches!(status.as_str(), "all" | "open" | "closed") {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "status must be all, open, or closed",
        ));
    }
    let cursor = match (query.before_created_at, query.before_id) {
        (Some(created_at), Some(id)) if created_at <= i64::MAX as u64 && id.len() <= 128 => {
            Some(LinkCursor { created_at, id })
        }
        (None, None) => None,
        _ => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "before_created_at and before_id must be supplied together and be valid",
            ))
        }
    };
    let search = validate_audit_filter(query.search, "search")?.unwrap_or_default();
    tokio::task::spawn_blocking(move || {
        let page = app
            .store
            .links_page(
                &identity.tenant,
                limit,
                cursor.as_ref(),
                &search,
                &status,
                now_unix(),
                query.route_eligible,
            )
            .map_err(super::store_unavailable)?;
        let mut totals = app
            .store
            .link_upload_totals(
                &identity.tenant,
                &page
                    .links
                    .iter()
                    .map(|link| link.id.clone())
                    .collect::<Vec<_>>(),
            )
            .map_err(super::store_unavailable)?;
        let transfers = app.sessions.active_transfers(&identity.tenant);
        let links = page
            .links
            .into_iter()
            .map(|link| {
                let counts = totals.remove(&link.id).unwrap_or_default();
                link_view(&app, link, &base, &transfers, counts)
            })
            .collect::<ApiResult<Vec<_>>>()?;
        Ok(Json(
            json!({"links":links,"receive_dir":app.config.receive_dir,
            "receipt_key":app.signer.public_hex,"next_cursor":page.next_cursor}),
        ))
    })
    .await
    .map_err(|_| ApiError::internal("request query worker failed"))?
}

pub async fn get_link(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    let base = base_url(&app, &headers);
    tokio::task::spawn_blocking(move || {
        let link = app
            .store
            .link_metadata(&identity.tenant, &id)
            .map_err(super::store_unavailable)?
            .ok_or_else(ApiError::not_found)?;
        let totals = app
            .store
            .link_upload_totals(&identity.tenant, std::slice::from_ref(&id))
            .map_err(super::store_unavailable)?
            .remove(&id)
            .unwrap_or_default();
        let transfers = app.sessions.active_transfers(&identity.tenant);
        Ok(Json(
            json!({"link":link_view(&app, link, &base, &transfers, totals)?}),
        ))
    })
    .await
    .map_err(|_| ApiError::internal("request query worker failed"))?
}

fn validate_page_limit(limit: u64) -> ApiResult<()> {
    if !(1..=100).contains(&limit) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "limit must be between 1 and 100",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct UploadQuery {
    limit: Option<u64>,
    before_position: Option<i64>,
}

pub async fn list_link_uploads(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<UploadQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    let limit = query.limit.unwrap_or(20);
    validate_page_limit(limit)?;
    if query.before_position.is_some_and(|position| position <= 0) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "before_position must be positive",
        ));
    }
    tokio::task::spawn_blocking(move || {
        let page = app.store.upload_headers_page(&identity.tenant, &id, query.before_position, limit as usize)
            .map_err(super::store_unavailable)?.ok_or_else(ApiError::not_found)?;
        Ok(Json(json!({"uploads":page.uploads.into_iter().map(|header| upload_view(header, false)).collect::<Vec<_>>(),
            "next_position":page.next_position})))
    }).await.map_err(|_| ApiError::internal("upload query worker failed"))?
}

pub async fn get_link_upload(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((id, upload)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    tokio::task::spawn_blocking(move || {
        let header = app
            .store
            .upload_header(&identity.tenant, &id, &upload)
            .map_err(super::store_unavailable)?
            .ok_or_else(ApiError::not_found)?;
        Ok(Json(json!({"upload":upload_view(header, true)})))
    })
    .await
    .map_err(|_| ApiError::internal("upload query worker failed"))?
}

#[derive(Deserialize)]
pub struct UploadFilesQuery {
    limit: Option<u64>,
    offset: Option<u64>,
}

pub async fn list_upload_files(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((id, upload)): Path<(String, String)>,
    Query(query): Query<UploadFilesQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator(&app, &headers)?;
    let limit = query.limit.unwrap_or(100);
    validate_page_limit(limit)?;
    let offset = query.offset.unwrap_or(0);
    if offset > i64::MAX as u64 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "offset is too large",
        ));
    }
    tokio::task::spawn_blocking(move || {
        let crate::store::UploadFilesPage { header, files } = app
            .store
            .upload_files_page(
                &identity.tenant,
                &id,
                &upload,
                offset as usize,
                limit as usize,
            )
            .map_err(super::store_unavailable)?
            .ok_or_else(ApiError::not_found)?;
        let next = offset.saturating_add(files.len() as u64);
        let next_offset = (next < header.file_count as u64).then_some(next);
        let files = files
            .into_iter()
            .map(|(index, file)| file_view(&app, &identity.tenant, index, file))
            .collect::<Vec<_>>();
        Ok(Json(
            json!({"files":files,"file_count":header.file_count,"next_offset":next_offset}),
        ))
    })
    .await
    .map_err(|_| ApiError::internal("file query worker failed"))?
}

pub async fn export_upload_timeline(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((id, upload)): Path<(String, String)>,
) -> ApiResult<Response> {
    use futures_util::StreamExt as _;
    use std::io::{Seek as _, Write as _};
    use std::os::unix::fs::OpenOptionsExt as _;
    let identity = require_operator(&app, &headers)?;
    let disposition =
        super::outbound::attachment_filename(&format!("votport-transfer-{upload}.json"))?;
    let operation = Arc::clone(&identity.operation);
    let (file, length) = tokio::task::spawn_blocking(move || {
        let path = app
            .config
            .data_dir
            .join(format!(".timeline-{}.tmp", auth::random_token()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| ApiError::internal(error.to_string()))?;
        // An unlinked spool is removed when its last descriptor closes, including cancelled requests.
        std::fs::remove_file(&path).map_err(|error| ApiError::internal(error.to_string()))?;
        let mut writer = std::io::BufWriter::new(file);
        if !app
            .store
            .write_upload_timeline(&identity.tenant, &id, &upload, &mut writer)
            .map_err(super::store_unavailable)?
        {
            return Err(ApiError::not_found());
        }
        writer
            .flush()
            .map_err(|error| ApiError::internal(error.to_string()))?;
        let mut file = writer
            .into_inner()
            .map_err(|error| ApiError::internal(error.to_string()))?;
        file.rewind()
            .map_err(|error| ApiError::internal(error.to_string()))?;
        let length = file
            .metadata()
            .map_err(|error| ApiError::internal(error.to_string()))?
            .len();
        Ok::<_, ApiError>((file, length))
    })
    .await
    .map_err(|_| ApiError::internal("timeline export worker failed"))??;
    let stream = ReaderStream::new(tokio::fs::File::from_std(file)).map(move |chunk| {
        let _guard = &operation;
        chunk
    });
    let mut response = (
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::CONTENT_LENGTH, length.to_string()),
        ],
        Body::from_stream(stream),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_DISPOSITION, disposition);
    Ok(response)
}

#[derive(Deserialize)]
pub struct CreateLinkRequest {
    label: String,
    #[serde(default)]
    dest: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    expires_days: Option<u32>,
    #[serde(default)]
    max_bytes: Option<u64>,
    /// Finding 378: optional link-scoped upload retention in days.
    #[serde(default)]
    retention_days: Option<u64>,
    /// Finding 24: requested publication verification level; absent means
    /// "default", the platform's mount-based choice.
    #[serde(default)]
    verification: String,
    #[serde(default)]
    notifications: Option<crate::store::NotificationPolicy>,
    workflow: Option<crate::workflow::ReceiveWorkflow>,
}

const MAX_REQUEST_LINK_EXPIRY_DAYS: u32 = 3650;

pub async fn create_link(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(request): Json<CreateLinkRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator_write(&app, &headers)?;
    let label = request.label.trim().to_owned();
    if label.is_empty() || label.len() > 200 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "label must be 1..=200 characters",
        ));
    }
    let dest = paths::admit_dest(&request.dest)
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error))?;
    if let Some(max_bytes) = request.max_bytes {
        if max_bytes == 0 || max_bytes > app.config.max_upload_bytes {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "max_bytes must be between 1 and {} bytes",
                    app.config.max_upload_bytes
                ),
            ));
        }
    }
    if request
        .expires_days
        .is_some_and(|days| !(1..=MAX_REQUEST_LINK_EXPIRY_DAYS).contains(&days))
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("expires_days must be between 1 and {MAX_REQUEST_LINK_EXPIRY_DAYS}"),
        ));
    }
    // Finding 378: the retention window shares the expiry cap so no stored
    // day count can overflow the sweep math.
    if request
        .retention_days
        .is_some_and(|days| !(1..=u64::from(MAX_REQUEST_LINK_EXPIRY_DAYS)).contains(&days))
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("retention_days must be between 1 and {MAX_REQUEST_LINK_EXPIRY_DAYS}"),
        ));
    }
    // Finding 24: an absent level (serialized as empty) means "default",
    // and anything outside the known names is a bad request, never a silent
    // substitution.
    let verification = if request.verification.is_empty() {
        "default".to_owned()
    } else {
        request.verification.clone()
    };
    if !paths::VERIFICATION_LEVELS.contains(&verification.as_str()) {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "verification must be one of {}",
                paths::VERIFICATION_LEVELS.join(", ")
            ),
        ));
    }
    let password_hash = match request.password.as_deref().filter(|p| !p.is_empty()) {
        Some(password) if password.len() <= MAX_PASSWORD_BYTES => {
            Some(auth::hash_password(password).map_err(ApiError::internal)?)
        }
        Some(_) => {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "password must be at most 256 bytes",
            ));
        }
        None => None,
    };
    let tenant = identity.tenant.clone();
    // A cookie can outlive its tenant's deletion; without this check the
    // link would be created under a namespace nothing manages anymore.
    let tenant_row = if tenant.is_empty() {
        None
    } else {
        match app
            .store
            .tenant(&tenant)
            .map_err(super::store_unavailable)?
        {
            Some(tenant) => Some(tenant),
            None => {
                return Err(ApiError::new(
                    StatusCode::GONE,
                    "this session's tenant no longer exists; sign in again",
                ));
            }
        }
    };
    let (_, max_links, _) = app
        .store
        .quotas_for(&tenant, &app.config)
        .map_err(super::store_unavailable)?;
    if let Some(max_links) = max_links {
        let count = app
            .store
            .tenant_link_count(&tenant)
            .map_err(super::store_unavailable)?;
        if count >= max_links {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("this tenant allows at most {max_links} request links"),
            ));
        }
    }
    let notifications = super::notifications::creation_policy(
        &app,
        &identity.tenant,
        request.notifications,
        &super::notifications::UPLOAD_EVENTS,
    )?;
    if let Some(policy) = request
        .workflow
        .as_ref()
        .and_then(|w| w.notifications.as_ref())
    {
        super::notifications::validate_policy(
            &app,
            &identity.tenant,
            policy,
            &super::notifications::WORKFLOW_EVENTS,
        )?;
    }
    // Finding 24: refuse a level the destination's filesystem cannot honor
    // instead of silently downgrading at publication time. The destination
    // resolves exactly as a session's will (tenant prefix, then dest).
    let mut dest_components = tenant_row
        .as_ref()
        .map_or_else(Vec::new, |tenant| tenant.path_prefix());
    dest_components.extend(
        dest.split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned),
    );
    let destination =
        paths::join_under(&app.config.receive_dir, &dest_components).map_err(ApiError::internal)?;
    paths::verification_profile(&destination, &verification)
        .map_err(|message| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, message))?;
    let created_at = now_unix();
    let link = Link {
        id: auth::random_token(),
        tenant,
        label,
        dest,
        password_hash,
        created_at,
        expires_at: request
            .expires_days
            .map(|days| created_at.saturating_add(u64::from(days) * 86_400)),
        max_bytes: request.max_bytes,
        active: true,
        legal_hold: false,

        retention_days: request.retention_days,
        verification,
        notifications,
        uploads: Vec::new(),
        events: Vec::new(),
    };
    let base = base_url(&app, &headers);
    let mut view = link_view(&app, link.clone(), &base, &[], (0, 0))?;
    view.workflow = request.workflow.clone();
    app.store
        .insert_link_with_workflow(link, request.workflow.as_ref())
        .map_err(|error| match error {
            crate::store::InsertLinkError::NamedTenantGone => ApiError::new(
                StatusCode::GONE,
                "this session's tenant no longer exists; sign in again",
            ),
            crate::store::InsertLinkError::Store(message) => ApiError::internal(message),
        })?;
    tracing::info!(target: "audit", event = "link_created", id = %view.id, label = %view.label, dest = %view.dest, "request link created");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "link_created",
        &view.id,
        &serde_json::json!({
            "label": view.label,
            "dest": view.dest,
            "tenant": identity.tenant,
            "notifications": view.notifications,
            "has_password": view.has_password,
            "expires_at": view.expires_at,
            "max_bytes": view.max_bytes,
            "retention_days": view.retention_days,
            "verification": view.verification,
        }),
    );
    Ok(Json(json!({ "link": view })))
}

#[derive(Deserialize)]
pub struct UpdateLinkRequest {
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    legal_hold: Option<bool>,
    /// Finding 378: null to clear, n to set the link-scoped upload
    /// retention window in days.
    #[serde(default, deserialize_with = "double_option")]
    retention_days: Option<Option<u64>>,
    #[serde(default)]
    notifications: Option<crate::store::NotificationPolicy>,
    workflow: Option<crate::workflow::ReceiveWorkflow>,
}

pub async fn update_link(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateLinkRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator_write(&app, &headers)?;
    let fields = [
        request.active.is_some(),
        request.legal_hold.is_some(),
        request.notifications.is_some(),
        request.workflow.is_some(),
        request.retention_days.is_some(),
    ];
    if fields.iter().filter(|field| **field).count() != 1 {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "exactly one link lifecycle or policy field is required",
        ));
    }
    if let Some(workflow) = request.workflow {
        if let Some(policy) = &workflow.notifications {
            super::notifications::validate_policy(
                &app,
                &identity.tenant,
                policy,
                &super::notifications::WORKFLOW_EVENTS,
            )?;
        }
        app.store
            .set_receive_workflow(&identity.tenant, &id, &workflow)
            .map_err(|error| ApiError::new(StatusCode::CONFLICT, error))?;
        app.store.audit(
            &identity.tenant,
            &identity.subject,
            "receive_workflow_changed",
            &id,
            &json!({"project_id":workflow.project_id}),
        );
        return Ok(Json(json!({"ok":true})));
    }
    if let Some(legal_hold) = request.legal_hold {
        if app
            .store
            .link_metadata(&identity.tenant, &id)
            .map_err(super::store_unavailable)?
            .is_none()
        {
            return Err(ApiError::not_found());
        }
        let _pin = app.sessions.try_pin_link(&id).ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "link lifecycle update in progress; try again",
            )
        })?;
        // The marker goes down before the flag and comes off only after the
        // flag is cleared: a crash can leave a hold active, never dropped.
        if legal_hold {
            app.set_link_hold_pin(&id, true)
                .map_err(|error| ApiError::internal(error.to_string()))?;
        }
        let found = app
            .store
            .set_link_legal_hold(&identity.tenant, &id, legal_hold, &identity.subject)
            .map_err(super::store_unavailable)?;
        if !found {
            app.set_link_hold_pin(&id, false)
                .map_err(|error| ApiError::internal(format!("stale legal hold marker: {error}")))?;
            return Err(ApiError::not_found());
        }
        if !legal_hold {
            app.set_link_hold_pin(&id, false)
                .map_err(|error| ApiError::internal(error.to_string()))?;
        }
        tracing::info!(target: "audit", event = "link_legal_hold_changed", id = %id, legal_hold, "request link legal hold changed");
        return Ok(Json(json!({ "ok": true })));
    }

    if let Some(policy) = request.notifications {
        super::notifications::validate_policy(
            &app,
            &identity.tenant,
            &policy,
            &super::notifications::UPLOAD_EVENTS,
        )?;
        if !app
            .store
            .update_link(&identity.tenant, &id, |link| {
                link.notifications = Some(policy.clone());
            })
            .map_err(super::store_unavailable)?
        {
            return Err(ApiError::not_found());
        }
        app.store.audit(
            &identity.tenant,
            &identity.subject,
            "link_notifications_changed",
            &id,
            &json!({}),
        );
        return Ok(Json(json!({"ok":true})));
    }

    if let Some(days) = request.retention_days {
        // Finding 378: the same positive window the create path validates;
        // a stored value can never be zero or overflow the sweep math.
        if days.is_some_and(|days| !(1..=u64::from(MAX_REQUEST_LINK_EXPIRY_DAYS)).contains(&days)) {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("retention_days must be between 1 and {MAX_REQUEST_LINK_EXPIRY_DAYS}"),
            ));
        }
        if !app
            .store
            .update_link(&identity.tenant, &id, |link| {
                link.retention_days = days;
            })
            .map_err(super::store_unavailable)?
        {
            return Err(ApiError::not_found());
        }
        tracing::info!(target: "audit", event = "link_retention_changed", id = %id, retention_days = ?days, "request link retention changed");
        app.store.audit(
            &identity.tenant,
            &identity.subject,
            "link_retention_changed",
            &id,
            &json!({"retention_days": days}),
        );
        return Ok(Json(json!({"ok":true})));
    }
    let active = request.active.expect("validated above");
    let found = app
        .store
        .update_link(&identity.tenant, &id, |link| link.active = active)
        .map_err(ApiError::internal)?;
    if !found {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "link_active_changed", id = %id, active, "request link toggled");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "link_active_changed",
        &id,
        &serde_json::json!({ "active": active }),
    );
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_link(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator_write(&app, &headers)?;
    if app
        .store
        .link_metadata(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .is_none()
    {
        return Err(ApiError::not_found());
    }
    let _pin = app
        .sessions
        .try_pin_link(&id)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "link delete already in progress"))?;
    let link = app
        .store
        .link_metadata(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    // Finding 376: a marker outside the database also holds, so a restore
    // predating the flag cannot clear the hold.
    if link.legal_hold || app.link_hold_pinned(&id) {
        return Err(ApiError::new(StatusCode::CONFLICT, "link is on legal hold"));
    }
    if app.sessions.active_for_link(&id) > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "uploads are in flight; try again when they finish",
        ));
    }
    if app
        .store
        .receive_workflow_pending(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "incoming workflows still use these files; wait for their deliveries to be archived before deleting them",
        ));
    }
    if app
        .store
        .link_has_active_outbound_grants(&identity.tenant, &id, now_unix())
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "active download links must be revoked first",
        ));
    }
    if app
        .store
        .link_has_existing_files(&identity.tenant, &id)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "files still exist for this request; delete them first, because removing the record would leave their stored paths unnamed",
        ));
    }
    let removed = app
        .store
        .remove_link(&identity.tenant, &id)
        .map_err(ApiError::internal)?;
    if !removed {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "link_deleted", id = %id, "request link deleted");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "link_deleted",
        &id,
        &serde_json::json!({}),
    );
    Ok(Json(json!({ "ok": true })))
}

/// The request link as a scannable SVG, for senders on phones.
pub async fn link_qr(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let identity = require_operator(&app, &headers)?;
    let link = app
        .store
        .link_metadata(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let url = format!("{}/r/{}", base_url(&app, &headers), link.id);
    let code = qrcode::QrCode::new(url.as_bytes())
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(([(header::CONTENT_TYPE, "image/svg+xml")], svg).into_response())
}

/// Removes one upload from a link's history. Refused while any of its files
/// still exists: the record is the only registry of each payload's stored
/// path, so clearing it first would orphan the file and its sidecar on disk.
pub async fn delete_upload_record(
    State(app): State<Arc<App>>,
    Path((id, upload)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator_write(&app, &headers)?;
    if app
        .store
        .link_metadata(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .is_none()
    {
        return Err(ApiError::not_found());
    }
    let _pin = app
        .sessions
        .try_pin_link(&id)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "link update already in progress"))?;
    if app.sessions.active_for_link(&id) > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "uploads are in flight; try again when they finish",
        ));
    }
    if app
        .store
        .receive_workflow_pending(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "incoming workflows still use these files; wait for their deliveries to be archived before deleting them",
        ));
    }
    let link = app
        .store
        .link_metadata(&identity.tenant, &id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if link.legal_hold || app.link_hold_pinned(&id) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "received records cannot be deleted while the link is on legal hold",
        ));
    }
    let record = app
        .store
        .link_upload(&identity.tenant, &id, &upload)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if app
        .store
        .upload_has_existing_files(&identity.tenant, &id, &upload)
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "files still exist for this upload; delete them first, because removing the record would leave their stored paths unnamed",
        ));
    }
    for index in 0..record.files.len() {
        if app
            .store
            .has_active_outbound_grant(&identity.tenant, &id, &upload, index, now_unix())
            .map_err(ApiError::internal)?
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "active download links must be revoked first",
            ));
        }
    }
    let found = app
        .store
        .remove_upload(&identity.tenant, &id, &upload)
        .map_err(ApiError::internal)?;
    if !found {
        return Err(ApiError::not_found());
    }
    tracing::info!(target: "audit", event = "upload_record_cleared", link = %id, upload = %upload, "upload record cleared from history");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "upload_record_cleared",
        &id,
        &serde_json::json!({ "upload": upload }),
    );
    Ok(Json(json!({ "ok": true })))
}

/// Deletes one received file (and its receipt sidecar) from disk. The path
/// comes from the stored record, never from the client. Already-gone files
/// succeed: the record's existence flag is the display of truth.
pub async fn delete_received_file(
    State(app): State<Arc<App>>,
    Path((id, upload, index)): Path<(String, String, usize)>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = require_operator_write(&app, &headers)?;
    tokio::task::spawn_blocking(move || {
        delete_received_file_sync(&app, &identity, &id, &upload, index)
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?
}

fn delete_received_file_sync(
    app: &App,
    identity: &auth::AdminIdentity,
    id: &str,
    upload: &str,
    index: usize,
) -> ApiResult<Json<serde_json::Value>> {
    let destinations = app
        .receiving_destinations()
        .map_err(|e| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, e))?;
    if app
        .store
        .link_metadata(&identity.tenant, id)
        .map_err(super::store_unavailable)?
        .is_none()
    {
        return Err(ApiError::not_found());
    }
    let _pin = app
        .sessions
        .try_pin_link(id)
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "file deletion already in progress"))?;
    if app.sessions.active_for_link(id) > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "uploads are in flight; try again when they finish",
        ));
    }
    if app
        .store
        .receive_workflow_pending(&identity.tenant, id)
        .map_err(super::store_unavailable)?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "incoming workflows still use these files; wait for their deliveries to be archived before deleting them",
        ));
    }
    let link = app
        .store
        .link_metadata(&identity.tenant, id)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    if link.legal_hold || app.link_hold_pinned(id) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "received files cannot be deleted while the link is on legal hold",
        ));
    }
    let selected = app
        .store
        .link_upload(&identity.tenant, id, upload)
        .map_err(super::store_unavailable)?
        .ok_or_else(ApiError::not_found)?;
    let record = selected.files.get(index).ok_or_else(ApiError::not_found)?;
    if record.deleted {
        return Ok(Json(json!({ "ok": true })));
    }
    let active = app
        .store
        .active_outbound_file_keys(&identity.tenant, id, now_unix())
        .map_err(ApiError::internal)?;
    for (upload_id, file_index) in active {
        let protected_upload = app
            .store
            .link_upload(&identity.tenant, id, &upload_id)
            .map_err(super::store_unavailable)?;
        let protected = protected_upload
            .as_ref()
            .and_then(|upload| upload.files.get(file_index));
        if protected.is_none_or(|file| file.stored_as == record.stored_as) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "active download links must be revoked first",
            ));
        }
    }
    let mut components = paths::tenant_prefix(&identity.tenant);
    components.extend(record.stored_as.split('/').map(str::to_owned));
    let prepared = destinations
        .prepare_received_removal(&components, record, &app.signer)
        .map_err(|error| ApiError::new(StatusCode::CONFLICT, error))?;
    if !app
        .store
        .tombstone_files(
            &identity.tenant,
            id,
            &std::collections::HashSet::from([record.stored_as.as_str()]),
        )
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "request disappeared during deletion; files were retained",
        ));
    }
    prepared
        .remove(&destinations)
        .map_err(|error| ApiError::new(StatusCode::CONFLICT, error))?;
    // Audit finding 105: kill the process in the crash window between the
    // filesystem unlink and the next store commit (the audit row). The
    // tombstone that carries the quota update committed before the unlink, so
    // the window proves the store never counts an unlinked file's bytes.
    // Test-only: the gate compiles away in every non-test build.
    #[cfg(test)]
    if std::env::var_os("FAIL_AFTER_UNLINK").is_some() {
        eprintln!("FAIL_AFTER_UNLINK: received file unlinked; aborting before the store commit");
        std::process::abort();
    }
    let stored_as = &record.stored_as;
    tracing::info!(target: "audit", event = "received_file_deleted", link = %id, stored_as = %stored_as, "received file deleted from disk");
    app.store.audit(
        &identity.tenant,
        &identity.subject,
        "received_file_deleted",
        id,
        &serde_json::json!({ "stored_as": stored_as }),
    );
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
#[cfg(test)]
pub(crate) mod tests;
