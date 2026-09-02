//! Application state and router assembly.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse as _, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use rand::RngCore as _;
use std::fmt::Write as _;
use tower_http::services::ServeDir;
use tracing::Instrument as _;

use crate::api;
use crate::auth::LoginThrottle;
use crate::config::Config;
use crate::session::{self, FinishReport, Sessions};
use crate::store::{now_unix, Store};

/// Native push transport state retained for the process lifetime.
pub struct PushState {
    #[allow(dead_code)]
    pub(crate) listener: Mutex<vot_cli::Listener>,
    pub(crate) issuer: ed25519_dalek::SigningKey,
    pub(crate) address: String,
    pub(crate) audience: String,
    pub(crate) certificate_digest: [u8; 32],
}

/// One admitted native-push capability, retained until its session ends.
pub(crate) struct PushTicket {
    pub(crate) session_id: String,
    pub(crate) expires_at: u64,
    pub(crate) expected_package: vot_sdk::object::ObjectId,
    pub(crate) directory: std::path::PathBuf,
    pub(crate) setup: Option<session::WorkerSetup>,
    pub(crate) seams: Option<session::PushSeamHandle>,
    pub(crate) control: session::PushControl,
}

pub struct App {
    pub config: Config,
    pub store: Arc<Store>,
    pub sessions: Sessions,
    /// Content hash of the served sender assets, so a page loaded before a
    /// deploy can tell it is stale and reload instead of failing on a changed
    /// contract.
    pub web_build: String,
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
    /// argon2 budget for password rotation. Separate again: rotation is what
    /// an operator reaches for while under attack.
    pub change_password_permits: Arc<tokio::sync::Semaphore>,
    /// Per-IP throttle for public link password checks.
    pub link_throttle: crate::auth::IpThrottle,
    /// Per-IP rate limit on upload-session creation.
    pub session_rate: crate::api::session_rate::SessionRate,
    /// Per-IP rate limit on public receipt checks; a separate map so a
    /// verifier cannot starve upload creates and vice versa.
    pub verify_rate: crate::api::session_rate::SessionRate,
    /// Per-IP native-push rail limit, separate from HTTP session creation.
    pub push_rate: crate::api::session_rate::SessionRate,
    /// Per-grant rate limit on outbound preparation and downloads.
    pub outbound_rate: crate::api::session_rate::SessionRate,
    /// Per-IP rate limit on automation share creation.
    pub automation_rate: crate::api::session_rate::SessionRate,
    /// Grants currently preparing or streaming, capped globally and per grant.
    pub outbound_active: Mutex<HashSet<String>>,
    /// Concurrent byte reservations for outbound staging on the data filesystem.
    pub outbound_stage_budget: Arc<crate::api::outbound::StageBudget>,
    /// Bounds concurrent batch staging tasks across every download stream.
    pub staging_permits: Arc<tokio::sync::Semaphore>,
    /// Bounded locks for serializing outbound library publication paths.
    pub outbound_upload_locks: [tokio::sync::Mutex<()>; 64],
    /// Signs the `.vot-receipt` sidecars written next to received files.
    pub signer: Arc<crate::receipt::ReceiptSigner>,
    /// Outbound client for upload notifications.
    pub http: reqwest::Client,
    /// OIDC configuration when SSO is enabled; the client discovers lazily.
    pub sso_config: Option<crate::config::OidcConfig>,
    pub sso_client: SsoSlot,
    pub push: Option<PushState>,
    pub(crate) push_metrics: PushMetrics,
    pub(crate) request_metrics: RequestMetrics,
    /// Every session worker reports here when it ends without publishing.
    pub(crate) session_ended: tokio::sync::mpsc::UnboundedSender<session::SessionEnded>,
    /// Taken once by [`upload_ended_notifier`].
    pub session_ended_rx:
        Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<session::SessionEnded>>>,
    pub(crate) push_tickets: Mutex<HashMap<[u8; 16], PushTicket>>,
    /// A process-wide maintenance lock: an operator click and the scheduler
    /// must never produce two snapshots or apply two restores concurrently.
    pub backup_lock: Arc<tokio::sync::Mutex<()>>,
    pub shutdown: Arc<tokio::sync::Notify>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PushRefusalReason {
    Rate,
    Capability,
    Expired,
    Spent,
}

impl PushRefusalReason {
    const ALL: [Self; 4] = [Self::Rate, Self::Capability, Self::Expired, Self::Spent];

    const fn label(self) -> &'static str {
        match self {
            Self::Rate => "rate",
            Self::Capability => "capability",
            Self::Expired => "expired",
            Self::Spent => "spent",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Rate => 0,
            Self::Capability => 1,
            Self::Expired => 2,
            Self::Spent => 3,
        }
    }
}

#[derive(Default)]
pub(crate) struct PushMetrics {
    bytes_total: AtomicU64,
    refused: [AtomicU64; 4],
}

impl PushMetrics {
    pub(crate) fn add_bytes(&self, bytes: u64) {
        self.bytes_total.fetch_add(bytes, Ordering::Relaxed);
    }

    fn refuse(&self, reason: PushRefusalReason) {
        self.refused[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    fn bytes(&self) -> u64 {
        self.bytes_total.load(Ordering::Relaxed)
    }

    fn refusals(&self, reason: PushRefusalReason) -> u64 {
        self.refused[reason.index()].load(Ordering::Relaxed)
    }
}

const REQUEST_STATUS_CLASSES: [&str; 5] = ["2xx", "3xx", "4xx", "5xx", "other"];
const REQUEST_LATENCY_BUCKETS_NS: [u64; 7] = [
    10_000_000,
    50_000_000,
    100_000_000,
    500_000_000,
    1_000_000_000,
    5_000_000_000,
    u64::MAX,
];
const REQUEST_LATENCY_BUCKET_LABELS: [&str; 7] = ["0.01", "0.05", "0.1", "0.5", "1", "5", "+Inf"];

const TRANSFER_OUTCOMES: [&str; 4] = ["published", "rejected", "cancelled", "interrupted"];
const UPLOAD_BYTES_BUCKETS: [u64; 7] = [
    1 << 20,
    16 << 20,
    256 << 20,
    1 << 30,
    4 << 30,
    16 << 30,
    u64::MAX,
];
const UPLOAD_BYTES_BUCKET_LABELS: [&str; 7] = [
    "1048576",
    "16777216",
    "268435456",
    "1073741824",
    "4294967296",
    "17179869184",
    "+Inf",
];
const UPLOAD_DURATION_BUCKETS_S: [u64; 7] = [1, 10, 60, 600, 3600, 21600, u64::MAX];
const UPLOAD_DURATION_BUCKET_LABELS: [&str; 7] = ["1", "10", "60", "600", "3600", "21600", "+Inf"];

fn transfer_outcome_index(outcome: &str) -> Option<usize> {
    TRANSFER_OUTCOMES.iter().position(|known| *known == outcome)
}

/// Cumulative bucket increments: every bucket whose bound holds the value.
fn observe_bucketed(buckets: &[AtomicU64; 7], bounds: [u64; 7], value: u64) {
    for (bucket, bound) in buckets.iter().zip(bounds) {
        if value <= bound {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn write_histogram(
    body: &mut String,
    name: &str,
    help: &str,
    buckets: &[AtomicU64; 7],
    labels: [&str; 7],
    sum: f64,
) {
    let _ = writeln!(body, "# HELP {name} {help}\n# TYPE {name} histogram");
    for (bucket, label) in buckets.iter().zip(labels) {
        let _ = writeln!(
            body,
            "{name}_bucket{{le=\"{label}\"}} {}",
            bucket.load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        body,
        "{name}_count {}\n{name}_sum {sum}",
        buckets[6].load(Ordering::Relaxed)
    );
}

/// Upload session outcomes and the size and duration of published uploads.
/// A static because the session worker is an OS thread with no `App`.
pub(crate) struct TransferMetrics {
    ended: [AtomicU64; 4],
    bytes_buckets: [AtomicU64; 7],
    bytes_sum: AtomicU64,
    duration_buckets: [AtomicU64; 7],
    duration_sum_s: AtomicU64,
}

pub(crate) static TRANSFERS: TransferMetrics = TransferMetrics::new();

impl TransferMetrics {
    const fn new() -> Self {
        Self {
            ended: [const { AtomicU64::new(0) }; 4],
            bytes_buckets: [const { AtomicU64::new(0) }; 7],
            bytes_sum: AtomicU64::new(0),
            duration_buckets: [const { AtomicU64::new(0) }; 7],
            duration_sum_s: AtomicU64::new(0),
        }
    }

    /// Counts a session end; an outcome outside the fixed table is dropped
    /// rather than opening a new series.
    pub(crate) fn ended(&self, outcome: &str) {
        if let Some(index) = transfer_outcome_index(outcome) {
            self.ended[index].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn published(&self, bytes: u64, seconds: u64) {
        self.ended("published");
        self.bytes_sum.fetch_add(bytes, Ordering::Relaxed);
        observe_bucketed(&self.bytes_buckets, UPLOAD_BYTES_BUCKETS, bytes);
        self.duration_sum_s.fetch_add(seconds, Ordering::Relaxed);
        observe_bucketed(&self.duration_buckets, UPLOAD_DURATION_BUCKETS_S, seconds);
    }

    #[cfg(test)]
    fn ended_count(&self, outcome: &str) -> u64 {
        transfer_outcome_index(outcome).map_or(0, |index| self.ended[index].load(Ordering::Relaxed))
    }

    fn prometheus(&self) -> String {
        let mut body = String::from(
            "# HELP votport_upload_sessions_ended_total Upload sessions ended by fixed outcome.\n# TYPE votport_upload_sessions_ended_total counter\n",
        );
        for (index, outcome) in TRANSFER_OUTCOMES.iter().enumerate() {
            let _ = writeln!(
                body,
                "votport_upload_sessions_ended_total{{outcome=\"{outcome}\"}} {}",
                self.ended[index].load(Ordering::Relaxed)
            );
        }
        write_histogram(
            &mut body,
            "votport_upload_bytes",
            "Bytes per published upload.",
            &self.bytes_buckets,
            UPLOAD_BYTES_BUCKET_LABELS,
            self.bytes_sum.load(Ordering::Relaxed) as f64,
        );
        write_histogram(
            &mut body,
            "votport_upload_duration_seconds",
            "Seconds from session creation to publication.",
            &self.duration_buckets,
            UPLOAD_DURATION_BUCKET_LABELS,
            self.duration_sum_s.load(Ordering::Relaxed) as f64,
        );
        body
    }
}

#[derive(Default)]
pub(crate) struct RequestMetrics {
    in_flight: AtomicU64,
    status: [AtomicU64; 5],
    latency_buckets: [AtomicU64; 7],
    latency_sum_ns: AtomicU64,
    outbound_upload_latency_buckets: [AtomicU64; 7],
    outbound_upload_latency_sum_ns: AtomicU64,
}

impl RequestMetrics {
    fn begin(&self) -> RequestInFlight<'_> {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        RequestInFlight(self)
    }

    fn observe(&self, status: StatusCode, elapsed: std::time::Duration) {
        self.status[request_status_index(status)].fetch_add(1, Ordering::Relaxed);
        let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        self.latency_sum_ns.fetch_add(nanos, Ordering::Relaxed);
        for (bucket, bound) in self.latency_buckets.iter().zip(REQUEST_LATENCY_BUCKETS_NS) {
            if nanos <= bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn observe_outbound_upload(&self, elapsed: std::time::Duration) {
        let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        self.outbound_upload_latency_sum_ns
            .fetch_add(nanos, Ordering::Relaxed);
        for (bucket, bound) in self
            .outbound_upload_latency_buckets
            .iter()
            .zip(REQUEST_LATENCY_BUCKETS_NS)
        {
            if nanos <= bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn prometheus(&self) -> String {
        let mut body = String::new();
        let _ = writeln!(
            body,
            "# HELP votport_http_requests_in_flight Current HTTP request handlers producing responses.\n# TYPE votport_http_requests_in_flight gauge\nvotport_http_requests_in_flight {}",
            self.in_flight.load(Ordering::Relaxed)
        );
        body.push_str(
            "# HELP votport_http_requests_total Total HTTP requests by fixed response status class.\n# TYPE votport_http_requests_total counter\n",
        );
        for (index, class) in REQUEST_STATUS_CLASSES.iter().enumerate() {
            let _ = writeln!(
                body,
                "votport_http_requests_total{{status=\"{class}\"}} {}",
                self.status[index].load(Ordering::Relaxed)
            );
        }
        body.push_str(
            "# HELP votport_http_request_duration_seconds HTTP time to response headers in seconds; streamed body transfer time is excluded.\n# TYPE votport_http_request_duration_seconds histogram\n",
        );
        for (bucket, label) in self
            .latency_buckets
            .iter()
            .zip(REQUEST_LATENCY_BUCKET_LABELS)
            .take(REQUEST_LATENCY_BUCKET_LABELS.len() - 1)
        {
            let _ = writeln!(
                body,
                "votport_http_request_duration_seconds_bucket{{le=\"{label}\"}} {}",
                bucket.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            body,
            "votport_http_request_duration_seconds_bucket{{le=\"+Inf\"}} {}\nvotport_http_request_duration_seconds_count {}\nvotport_http_request_duration_seconds_sum {:.9}",
            self.latency_buckets[6].load(Ordering::Relaxed),
            self.latency_buckets[6].load(Ordering::Relaxed),
            self.latency_sum_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
        );
        body.push_str(
            "# HELP votport_http_outbound_upload_duration_seconds HTTP time to response headers for outbound library uploads in seconds.\n# TYPE votport_http_outbound_upload_duration_seconds histogram\n",
        );
        for (bucket, label) in self
            .outbound_upload_latency_buckets
            .iter()
            .zip(REQUEST_LATENCY_BUCKET_LABELS)
            .take(REQUEST_LATENCY_BUCKET_LABELS.len() - 1)
        {
            let _ = writeln!(
                body,
                "votport_http_outbound_upload_duration_seconds_bucket{{le=\"{label}\"}} {}",
                bucket.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            body,
            "votport_http_outbound_upload_duration_seconds_bucket{{le=\"+Inf\"}} {}\nvotport_http_outbound_upload_duration_seconds_count {}\nvotport_http_outbound_upload_duration_seconds_sum {:.9}",
            self.outbound_upload_latency_buckets[6].load(Ordering::Relaxed),
            self.outbound_upload_latency_buckets[6].load(Ordering::Relaxed),
            self.outbound_upload_latency_sum_ns.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
        );
        body
    }
}

struct RequestInFlight<'a>(&'a RequestMetrics);

impl Drop for RequestInFlight<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

fn request_status_index(status: StatusCode) -> usize {
    match status.as_u16() {
        200..=299 => 0,
        300..=399 => 1,
        400..=499 => 2,
        500..=599 => 3,
        _ => 4,
    }
}

fn request_id(request: &Request<axum::body::Body>) -> String {
    request
        .headers()
        .get("x-request-id")
        .map(|value| value.as_bytes())
        .filter(|value| {
            (1..=64).contains(&value.len())
                && value
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
        .map(|value| String::from_utf8(value.to_vec()).expect("request id is ASCII"))
        .unwrap_or_else(crate::auth::random_token)
}

fn is_outbound_upload(request: &Request<axum::body::Body>) -> bool {
    request.method() == Method::POST && request.uri().path() == "/api/admin/outbound-files"
}

async fn request_observability(
    State(app): State<Arc<App>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let id = request_id(&request);
    let outbound_upload = is_outbound_upload(&request);
    let started = std::time::Instant::now();
    let _in_flight = app.request_metrics.begin();
    let span = tracing::info_span!("http_request", request_id = %id);
    let mut response = next.run(request).instrument(span).await;
    let elapsed = started.elapsed();
    app.request_metrics.observe(response.status(), elapsed);
    if outbound_upload {
        app.request_metrics.observe_outbound_upload(elapsed);
    }
    response.headers_mut().insert(
        "x-request-id",
        axum::http::HeaderValue::from_str(&id).expect("generated request id is valid"),
    );
    response
}

fn refuse_push(
    app: &App,
    reason: PushRefusalReason,
    peer: std::net::SocketAddr,
) -> Option<vot_cli::PushAdmission> {
    app.push_metrics.refuse(reason);
    tracing::warn!(target: "audit", event = "push_refused", %peer, reason = reason.label(), "native push refused");
    None
}

/// Remove any native-push ticket belonging to a completed or aborted session.
pub(crate) fn remove_push_ticket(app: &Arc<App>, session_id: &str) {
    app.push_tickets
        .lock()
        .expect("push tickets poisoned")
        .retain(|_, ticket| ticket.session_id != session_id);
}

/// Apply the completion side effects shared by HTTP and native push uploads.
pub(crate) fn upload_completed(
    app: &Arc<App>,
    session_id: &str,
    link_id: Option<String>,
    report: &FinishReport,
    runtime: &tokio::runtime::Handle,
) {
    tracing::info!(
        target: "audit", event = "upload_completed", session = %session_id,
        files = report.files.len(), bytes = report.files.iter().map(|file| file.bytes).sum::<u64>(),
        "upload finished and recorded"
    );
    let link = link_id.and_then(|id| {
        app.store
            .upload_link(&id)
            .inspect_err(|error| tracing::warn!(%error, "link read failed after upload"))
            .ok()
            .flatten()
    });
    let completed_tenant = link
        .as_ref()
        .map(|link| link.tenant.as_str())
        .unwrap_or_default();
    app.store.audit(
        completed_tenant,
        "",
        "upload_completed",
        &session_id[..8.min(session_id.len())],
        &serde_json::json!({
            "files": report.files.len(),
            "bytes": report.files.iter().map(|file| file.bytes).sum::<u64>()
        }),
    );
    if let Some(link) = link.filter(|link| link.notify_on_upload) {
        let app = Arc::clone(app);
        let report = report.clone();
        runtime.spawn(async move {
            crate::notify::uploaded(app, link.tenant, link.label, report).await;
        });
    }
    let started_at = app
        .sessions
        .remove(session_id)
        .map_or(now_unix(), |handle| handle.started_at);
    TRANSFERS.published(
        report.files.iter().map(|file| file.bytes).sum::<u64>(),
        now_unix().saturating_sub(started_at),
    );
    remove_push_ticket(app, session_id);
}

/// Drains the session-ended channel and sends the failure notification for
/// links that asked for one. Spawned once at startup; a second call returns.
pub async fn upload_ended_notifier(app: Arc<App>) {
    let Some(mut receiver) = app
        .session_ended_rx
        .lock()
        .expect("notifier poisoned")
        .take()
    else {
        return;
    };
    while let Some(ended) = receiver.recv().await {
        if ended.notify && ended_notifies(&ended.event) {
            tokio::spawn(crate::notify::upload_ended(Arc::clone(&app), ended));
        }
    }
}

/// Which session ends are worth a notification: a begin refused outright,
/// or a transfer that stopped after bytes had arrived. A cancel is the
/// sender's choice, and an interrupted session with nothing received is
/// churn (a retried create that orphaned its first session, a create
/// refused mid-flight, an idle session swept) that the link's event list
/// already keeps.
fn ended_notifies(event: &crate::store::SessionEvent) -> bool {
    match event.outcome.as_str() {
        "rejected" => true,
        "interrupted" => event.received_bytes > 0,
        _ => false,
    }
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
    if config.push_bind.is_some() && config.session_idle_secs == 0 {
        return Err(
            "VOTPORT_SESSION_IDLE_SECS must be greater than zero when native push is enabled"
                .to_owned(),
        );
    }
    // VOT refuses to stage files under a group-writable directory. On hosts
    // with umask 002 (Ubuntu user groups) every directory votport creates
    // would be 0775 and every upload would fail, so pin the umask here.
    #[cfg(unix)]
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
    std::fs::create_dir_all(&config.receive_dir)
        .map_err(|error| format!("create {}: {error}", config.receive_dir.display()))?;
    crate::paths::tighten_dir(&config.receive_dir);
    std::fs::create_dir_all(&config.outbound_dir)
        .map_err(|error| format!("create {}: {error}", config.outbound_dir.display()))?;
    crate::paths::tighten_dir(&config.outbound_dir);
    crate::paths::probe_landing_dir(&config.receive_dir, "VOTPORT_RECEIVE_DIR", true)?;
    crate::paths::probe_landing_dir(&config.outbound_dir, "VOTPORT_OUTBOUND_DIR", false)?;
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|error| format!("create {}: {error}", config.data_dir.display()))?;
    crate::paths::tighten_private_dir(&config.data_dir).map_err(|error| error.to_string())?;
    crate::backup::apply_pending_restore(&config.data_dir, crate::store::SCHEMA_VERSION)?;
    crate::paths::clean_staging(&config.outbound_dir, &HashSet::new());
    let store = Arc::new(Store::open(&config.data_dir)?);
    clean_outbound_stage(&config.data_dir);
    clean_outbound_proof_stages(&config.data_dir);
    clean_outbound_proofs(&config.data_dir, &store, now_unix());
    store.migrate_tenant_storage(&config.receive_dir)?;
    let secret = crate::auth::load_secret(&config.data_dir)?;
    let signer = Arc::new(crate::receipt::ReceiptSigner::load_or_create(
        &config.data_dir,
    )?);
    // Upload sessions suspended by the last shutdown re-attach their
    // staging; every other staging file from a crash or kill has no live
    // session to sweep it, so remove those once at startup.
    let sessions = Sessions::new();
    let (session_ended, session_ended_rx) = tokio::sync::mpsc::unbounded_channel();
    let kept = resume_upload_sessions(&config, &store, &signer, &sessions, &session_ended);
    crate::paths::clean_staging(&config.receive_dir, &kept);
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| format!("http client: {error}"))?;
    let push = config
        .push_bind
        .map(|address| build_push_state(&config, address))
        .transpose()?;
    let web_build = web_build(&config.web_root);
    Ok(Arc::new(App {
        store,
        sessions,
        secret,
        web_build,
        change_password_throttle: LoginThrottle::new(),
        login_throttle: crate::auth::IpThrottle::new(),
        login_permits: Arc::new(tokio::sync::Semaphore::new(VERIFY_PERMITS)),
        link_verify_permits: Arc::new(tokio::sync::Semaphore::new(VERIFY_PERMITS)),
        change_password_permits: Arc::new(tokio::sync::Semaphore::new(VERIFY_PERMITS)),
        link_throttle: crate::auth::IpThrottle::new(),
        session_rate: crate::api::session_rate::SessionRate::new(),
        verify_rate: crate::api::session_rate::SessionRate::new(),
        // Twenty admitted sessions can each use VOT's eight default rails;
        // leave room for refused or retried rails in the same ten-minute window.
        push_rate: crate::api::session_rate::SessionRate::with_limit(200),
        outbound_rate: crate::api::session_rate::SessionRate::with_limit(2000),
        automation_rate: crate::api::session_rate::SessionRate::with_limit(60),
        outbound_active: Mutex::new(HashSet::new()),
        outbound_stage_budget: Arc::new(crate::api::outbound::StageBudget::new()),
        staging_permits: Arc::new(tokio::sync::Semaphore::new(
            crate::api::outbound::STAGING_CONCURRENCY,
        )),
        outbound_upload_locks: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
        signer,
        http,
        sso_config: config.oidc.clone(),
        sso_client: SsoSlot::new(),
        push,
        push_metrics: PushMetrics::default(),
        request_metrics: RequestMetrics::default(),
        session_ended,
        session_ended_rx: Mutex::new(Some(session_ended_rx)),
        push_tickets: Mutex::new(HashMap::new()),
        backup_lock: Arc::new(tokio::sync::Mutex::new(())),
        shutdown: Arc::new(tokio::sync::Notify::new()),
        config,
    }))
}

impl App {
    pub fn request_shutdown(&self) {
        self.shutdown.notify_waiters();
    }
}

/// Suspends every HTTP upload session for a restart: each worker
/// checkpoints and leaves its staging on disk for [`build`] to re-attach.
/// Called once the server has stopped serving, so no handler can reach a
/// session. A worker that does not answer in time is left to the process
/// exit, which is the crash path the checkpoint already covers.
pub async fn suspend_sessions(app: &App) {
    let senders = app.sessions.take_http();
    let mut replies = Vec::with_capacity(senders.len());
    for sender in senders {
        let (reply, done) = tokio::sync::oneshot::channel();
        if sender.send(session::Cmd::Suspend { reply }).await.is_ok() {
            replies.push(done);
        }
    }
    let count = replies.len();
    if count == 0 {
        return;
    }
    let all = futures_util::future::join_all(replies);
    match tokio::time::timeout(std::time::Duration::from_secs(30), all).await {
        Ok(_) => tracing::info!(count, "suspended upload sessions for restart"),
        Err(_) => tracing::warn!(count, "suspending upload sessions timed out"),
    }
}

/// Re-attaches the upload sessions the last shutdown suspended, and returns
/// the staging paths they own. A session that cannot be re-attached (its
/// link is gone, its staging is missing or short, its journal moved on) is
/// dropped: the record goes and its staging falls to the sweep.
fn resume_upload_sessions(
    config: &Config,
    store: &Arc<Store>,
    signer: &Arc<crate::receipt::ReceiptSigner>,
    sessions: &Sessions,
    ended: &tokio::sync::mpsc::UnboundedSender<session::SessionEnded>,
) -> HashSet<std::path::PathBuf> {
    let persisted = match store.load_upload_sessions() {
        Ok(persisted) => persisted,
        Err(error) => {
            tracing::warn!(%error, "loading suspended upload sessions failed");
            return HashSet::new();
        }
    };
    let mut kept = HashSet::new();
    for mut session in persisted {
        let session_tag = session.id.get(..8).unwrap_or(&session.id).to_owned();
        match resume_upload_session(config, store, signer, sessions, ended, &mut session) {
            Ok(paths) => {
                tracing::info!(
                    target: "audit", event = "upload_session_resumed", link = %session.link_id,
                    session_tag = %session_tag, files = session.files.len(),
                    "re-attached upload session after restart"
                );
                kept.extend(paths);
            }
            Err(error) => {
                tracing::warn!(session_tag = %session_tag, %error, "dropped suspended upload session");
                // Every Err above comes before the worker is spawned
                // (resume_worker fails before spawn; insert_resumed cannot
                // fail at boot with unbounded caps and empty pins), so no
                // worker will write a second partial record for these files.
                session::commit_persisted_partial(store, &session);
                if let Err(error) = store.delete_upload_session(&session.id) {
                    tracing::warn!(session_tag = %session_tag, %error, "delete upload session failed");
                }
            }
        }
    }
    kept
}

fn resume_upload_session(
    config: &Config,
    store: &Arc<Store>,
    signer: &Arc<crate::receipt::ReceiptSigner>,
    sessions: &Sessions,
    ended: &tokio::sync::mpsc::UnboundedSender<session::SessionEnded>,
    session: &mut crate::store::PersistedUploadSession,
) -> Result<Vec<std::path::PathBuf>, String> {
    let link = store
        .upload_link(&session.link_id)?
        .ok_or_else(|| "link no longer exists".to_owned())?;
    if link.tenant != session.tenant || !link.usable_now() {
        return Err("link is no longer accepting uploads".to_owned());
    }
    let session_id: [u8; 16] = hex::decode(&session.id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "session id shape".to_owned())?;
    let setup = session::WorkerSetup {
        store: Arc::clone(store),
        link_id: session.link_id.clone(),
        tenant: session.tenant.clone(),
        dest_dir: session.dest_dir.clone(),
        dest_rel: session.dest_rel.clone(),
        expected_package: session.package.clone(),
        max_total_bytes: session.max_total_bytes.unwrap_or(u64::MAX),
        allow_hidden: config.allow_hidden,
        signer: Arc::clone(signer),
        session_id,
        started_at: session.started_at,
        quiet_after_secs: session::quiet_after_secs(config.session_idle_secs),
        ended: ended.clone(),
    };
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    let (kept, already) = session::resume_worker(setup, receiver, session)?;
    sessions
        .insert_resumed(
            session.id.clone(),
            session.link_id.clone(),
            session.tenant.clone(),
            session.package.length,
            sender,
        )
        .map_err(|error| format!("register session: {error:?}"))?;
    sessions.seed_resumed(&session.id, session.started_at, already);
    Ok(kept)
}

/// First 16 hex of the SHA-256 over every .js and .wasm file under
/// assets/ and assets/vendor/ (sorted by path), or "unknown" when the web
/// root is missing (tests without one). Computed once at startup: with a
/// web root served from disk, an edit without a restart keeps the old hash.
fn web_build(web_root: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let assets = web_root.join("assets");
    let mut paths = Vec::new();
    for dir in [assets.clone(), assets.join("vendor")] {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|ext| ext.to_str());
            if path.is_file() && matches!(ext, Some("js" | "wasm")) {
                paths.push(path);
            }
        }
    }
    if paths.is_empty() {
        return "unknown".to_owned();
    }
    paths.sort();
    let mut hasher = Sha256::new();
    for path in paths {
        // Relative to the web root so the same assets hash the same under
        // any install path.
        let name = path.strip_prefix(web_root).unwrap_or(&path);
        hasher.update(name.to_string_lossy().as_bytes());
        hasher.update(std::fs::read(&path).unwrap_or_default());
    }
    hex::encode(hasher.finalize())[..16].to_owned()
}

/// Remove only VOTPORT-owned outbound staging entries. `symlink_metadata` and
/// per-entry removal keep cleanup from traversing an operator-created link.
fn clean_outbound_stage(data_dir: &std::path::Path) {
    let root = data_dir.join("outbound.stage");
    let Ok(root_meta) = std::fs::symlink_metadata(&root) else {
        return;
    };
    if !root_meta.file_type().is_dir() || root_meta.file_type().is_symlink() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(".vot-outbound-") {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            let _ = std::fs::remove_file(path);
            continue;
        }
        let Ok(children) = std::fs::read_dir(&path) else {
            continue;
        };
        for child in children.flatten() {
            let child_path = child.path();
            let Ok(child_meta) = std::fs::symlink_metadata(&child_path) else {
                continue;
            };
            if child_meta.file_type().is_dir() && !child_meta.file_type().is_symlink() {
                let _ = std::fs::remove_dir(child_path);
            } else {
                let _ = std::fs::remove_file(child_path);
            }
        }
        let _ = std::fs::remove_dir(path);
    }
}

fn clean_outbound_proof_stages(data_dir: &std::path::Path) {
    let root = data_dir.join("outbound.proofs");
    let Ok(meta) = std::fs::symlink_metadata(&root) else {
        return;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !owned_catalog_stage_name(&name) {
            continue;
        }
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_file() && !meta.file_type().is_symlink() {
                if let Err(error) = std::fs::remove_file(path) {
                    tracing::warn!(%error, stage = %name, "outbound catalog stage cleanup failed");
                }
            }
        }
    }
}

fn active_catalog_names(keys: Vec<(String, String, u64)>) -> HashSet<String> {
    keys.into_iter()
        .filter_map(|(suite, root, length)| {
            let suite = match suite.as_str() {
                "blake3" => 1,
                "sha256" => 2,
                _ => return None,
            };
            let bytes = hex::decode(root).ok()?;
            let root = <[u8; 32]>::try_from(bytes).ok().map(hex::encode)?;
            Some(format!("{suite}-{root}-{length}.vot-catalog"))
        })
        .collect()
}

fn canonical_catalog_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".vot-catalog") else {
        return false;
    };
    let Some((suite, rest)) = stem.split_once('-') else {
        return false;
    };
    if !matches!(suite, "1" | "2") {
        return false;
    }
    let Some((root, length)) = rest.rsplit_once('-') else {
        return false;
    };
    if root.len() != 64
        || !root
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return false;
    }
    let Ok(length_value) = length.parse::<u64>() else {
        return false;
    };
    length == length_value.to_string()
        && name == format!("{suite}-{root}-{length_value}.vot-catalog")
}

fn owned_catalog_stage_name(name: &str) -> bool {
    let Some(name) = name.strip_prefix('.') else {
        return false;
    };
    let Some((catalog, token)) = name.rsplit_once(".stage-") else {
        return false;
    };
    canonical_catalog_name(catalog)
        && token.len() == 32
        && token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn clean_outbound_proofs(data_dir: &std::path::Path, store: &Store, now: u64) {
    let root = data_dir.join("outbound.proofs");
    let Ok(meta) = std::fs::symlink_metadata(&root) else {
        return;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return;
    }
    let keys = match store.active_outbound_object_keys(now) {
        Ok(keys) => active_catalog_names(keys),
        Err(error) => {
            tracing::error!(%error, "outbound catalog references unavailable; skipping prune");
            return;
        }
    };
    prune_outbound_proofs(&root, &keys);
}

fn prune_outbound_proofs(root: &std::path::Path, keys: &HashSet<String>) {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(%error, "outbound catalog directory read failed");
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !canonical_catalog_name(&name) || keys.contains(&name) {
            continue;
        }
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_file() && !meta.file_type().is_symlink() {
                if let Err(error) = std::fs::remove_file(path) {
                    tracing::warn!(%error, catalog = %name, "outbound catalog prune failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod outbound_stage_tests {
    use super::*;

    #[test]
    fn catalog_prune_keeps_active_and_foreign_entries() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("outbound.proofs");
        std::fs::create_dir_all(&root).unwrap();
        let active_root = "00".repeat(32);
        let active = format!("1-{active_root}-10.vot-catalog");
        let stale = format!("2-{}-11.vot-catalog", "11".repeat(32));
        let foreign =
            "1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-12.vot-catalog";
        std::fs::write(root.join(&active), b"active").unwrap();
        std::fs::write(root.join(&stale), b"stale").unwrap();
        std::fs::write(root.join(foreign), b"foreign").unwrap();
        std::fs::write(root.join("operator.txt"), b"operator").unwrap();
        let foreign_stage = root.join(".1-operator.vot-catalog.stage-foreign");
        std::fs::write(&foreign_stage, b"operator").unwrap();
        let owned_stage = root.join(format!(".{active}.stage-{}", "aa".repeat(16)));
        std::fs::write(&owned_stage, b"owned").unwrap();
        #[cfg(unix)]
        {
            let stage_link = root.join(format!(".{active}.stage-{}", "bb".repeat(16)));
            std::os::unix::fs::symlink(&owned_stage, &stage_link).unwrap();
            std::os::unix::fs::symlink(
                &stale,
                root.join(format!("2-{}-12.vot-catalog", "22".repeat(32))),
            )
            .unwrap();
        }
        let keys = active_catalog_names(vec![("blake3".to_owned(), active_root, 10)]);

        prune_outbound_proofs(&root, &keys);

        assert!(root.join(&active).exists());
        assert!(!root.join(stale).exists());
        assert!(root.join(foreign).exists());
        assert!(root.join("operator.txt").exists());
        clean_outbound_proof_stages(directory.path());
        assert!(foreign_stage.exists());
        assert!(!owned_stage.exists());
        #[cfg(unix)]
        assert!(std::fs::symlink_metadata(
            root.join(format!("2-{}-12.vot-catalog", "22".repeat(32)))
        )
        .is_ok());
        #[cfg(unix)]
        assert!(std::fs::symlink_metadata(
            root.join(format!(".{active}.stage-{}", "bb".repeat(16)))
        )
        .is_ok());
    }

    #[test]
    fn startup_cleanup_removes_only_outbound_stage_entries() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("outbound.stage");
        let owned = root.join(".vot-outbound-dead");
        let unrelated = root.join("keep");
        std::fs::create_dir_all(&owned).unwrap();
        std::fs::create_dir_all(&unrelated).unwrap();
        std::fs::write(owned.join("file"), b"staged").unwrap();
        std::fs::write(unrelated.join("file"), b"operator").unwrap();

        clean_outbound_stage(directory.path());

        assert!(!owned.exists());
        assert!(unrelated.join("file").exists());
    }

    #[test]
    fn startup_cleanup_removes_orphaned_outbound_library_stages() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let stage = app.config.outbound_dir.join(".vot-crash.stage");
        std::fs::write(&stage, b"staged").unwrap();
        drop(app);

        let _app = crate::api::testing::build(directory.path());
        assert!(!stage.exists());
    }
}

fn build_push_state(config: &Config, address: std::net::SocketAddr) -> Result<PushState, String> {
    let (certificate, key) = push_credentials(config)?;
    let credentials = vot_cli::Credentials::Files { certificate, key };
    let (listener, certificate_digest) = vot_cli::bind_push_listener(address, &credentials)
        .map_err(|error| format!("bind native push listener: {error:?}"))?;
    let issuer = load_push_issuer(&config.data_dir)?;
    let address = config
        .push_advertise
        .clone()
        .unwrap_or_else(|| listener.local_address().to_string());
    let audience = push_audience(config.public_url.as_deref(), &address)?;
    tracing::info!(
        address = %listener.local_address(),
        certificate_digest = %hex::encode(certificate_digest),
        "native push listener bound"
    );
    Ok(PushState {
        listener: Mutex::new(listener),
        issuer,
        address,
        audience,
        certificate_digest,
    })
}

fn push_audience(public_url: Option<&str>, address: &str) -> Result<String, String> {
    let audience = format!("votport:{}", public_url.unwrap_or(address));
    let (low, high) = vot_capability::bounds::IDENTITY;
    if !(low..=high).contains(&audience.len()) || audience.chars().any(char::is_control) {
        return Err(format!(
            "native push capability audience must be {low}..={high} bytes without control characters"
        ));
    }
    Ok(audience)
}

/// Starts the process-lifetime VOT receiver when native push is enabled.
pub fn start_push_receiver(app: Arc<App>) {
    if app.push.is_none() {
        return;
    }
    let runtime = tokio::runtime::Handle::current();
    std::thread::Builder::new()
        .name("votport-push-receiver".to_owned())
        .spawn(move || {
            let push = app.push.as_ref().expect("push state disappeared");
            let verifying_key = push.issuer.verifying_key();
            let requirement = vot_cli::authz::PushRequirement::new(
                "votport",
                vot_cli::authz::key_id_of(&verifying_key),
                verifying_key,
                &push.audience,
            );
            let listener = push.listener.lock().expect("push listener poisoned");
            if let Err(error) = vot_cli::receive_push_on(&listener, |presentation| {
                admit_push(&app, &requirement, presentation, &runtime)
            }) {
                tracing::error!(?error, "native push receiver stopped");
            }
        })
        .expect("spawn native push receiver");
}

fn admit_push(
    app: &Arc<App>,
    requirement: &vot_cli::authz::PushRequirement,
    presentation: vot_cli::PushPresentation<'_>,
    runtime: &tokio::runtime::Handle,
) -> Option<vot_cli::PushAdmission> {
    if !app.push_rate.allow(&presentation.peer.ip().to_string()) {
        return refuse_push(app, PushRefusalReason::Rate, presentation.peer);
    }
    let Some(scope) = requirement.decide(
        presentation.challenge,
        presentation.open,
        presentation.channel_binding,
        presentation.now,
    ) else {
        return refuse_push(
            app,
            capability_refusal_reason(requirement, &presentation),
            presentation.peer,
        );
    };
    // `decide` already decoded and authenticated these exact bytes.
    let signed = match vot_capability::decode(&presentation.open.capability) {
        Ok(signed) => signed,
        Err(_) => return refuse_push(app, PushRefusalReason::Capability, presentation.peer),
    };
    let capability = match vot_capability::Capability::from_canonical_bytes(&signed.capability) {
        Ok(capability) => capability,
        Err(_) => return refuse_push(app, PushRefusalReason::Capability, presentation.peer),
    };
    if capability.expiry <= presentation.now {
        return refuse_push(app, PushRefusalReason::Expired, presentation.peer);
    }
    let token_id = capability.token_id;
    let (session_id, directory, seams, joined) = {
        let mut tickets = app.push_tickets.lock().expect("push tickets poisoned");
        let Some(ticket) = tickets.get_mut(&token_id) else {
            return refuse_push(app, PushRefusalReason::Spent, presentation.peer);
        };
        if ticket.expires_at <= presentation.now {
            return refuse_push(app, PushRefusalReason::Expired, presentation.peer);
        }
        if capability.expiry != ticket.expires_at {
            return refuse_push(app, PushRefusalReason::Capability, presentation.peer);
        }
        if !scope_matches(&scope, &ticket.expected_package) {
            return refuse_push(app, PushRefusalReason::Capability, presentation.peer);
        }
        if !app.sessions.contains_push(&ticket.session_id) || ticket.control.is_cancelled() {
            return refuse_push(app, PushRefusalReason::Spent, presentation.peer);
        }
        let seams = match live_ticket_seams(ticket) {
            Ok(seams) => seams,
            Err(reason) => return refuse_push(app, reason, presentation.peer),
        };
        if let Some(seams) = seams {
            (
                ticket.session_id.clone(),
                ticket.directory.clone(),
                seams,
                true,
            )
        } else {
            let setup = match ticket_setup(ticket) {
                Ok(setup) => setup,
                Err(reason) => return refuse_push(app, reason, presentation.peer),
            };
            if let Err(error) = std::fs::create_dir_all(&setup.dest_dir) {
                tracing::error!(path = %setup.dest_dir.display(), %error, "create native push destination");
                return None;
            }
            crate::paths::tighten_dir(&setup.dest_dir);
            if !ticket.control.connect() {
                return refuse_push(app, PushRefusalReason::Spent, presentation.peer);
            }
            let setup = match ticket.setup.take() {
                Some(setup) => setup,
                None => return refuse_push(app, PushRefusalReason::Spent, presentation.peer),
            };
            let (seams, handle) = session::push_seams(
                Arc::clone(app),
                setup,
                ticket.control.clone(),
                runtime.clone(),
            );
            ticket.seams = Some(handle);
            (
                ticket.session_id.clone(),
                ticket.directory.clone(),
                seams,
                false,
            )
        }
    };
    if joined {
        tracing::debug!(peer = %presentation.peer, session = %session_id, "native push rail joined");
    } else {
        tracing::info!(
            target: "audit", event = "push_connected", peer = %presentation.peer,
            session_tag = %session_id.get(..8).unwrap_or(&session_id),
            "native push session connected"
        );
        let tenant = app
            .sessions
            .link_id(&session_id)
            .and_then(|link_id| app.store.upload_link(&link_id).ok().flatten())
            .map(|link| link.tenant)
            .unwrap_or_default();
        app.store.audit(
            &tenant,
            "",
            "push_connected",
            &session_id,
            &serde_json::json!({ "peer": presentation.peer.to_string() }),
        );
    }
    Some(vot_cli::PushAdmission {
        scope,
        directory,
        seams,
    })
}

fn scope_matches(scope: &vot_capability::Scope, expected: &vot_sdk::object::ObjectId) -> bool {
    scope.suite == expected.suite
        && scope.root == expected.root
        && scope.length == Some(expected.length)
        && scope.ranges.is_empty()
}

fn live_ticket_seams(
    ticket: &PushTicket,
) -> Result<Option<vot_cli::ReceiveSeams>, PushRefusalReason> {
    match ticket.seams.as_ref() {
        Some(handle) => handle.seams().map(Some).ok_or(PushRefusalReason::Spent),
        None => Ok(None),
    }
}

fn ticket_setup(ticket: &PushTicket) -> Result<&session::WorkerSetup, PushRefusalReason> {
    ticket.setup.as_ref().ok_or(PushRefusalReason::Spent)
}

fn capability_is_expired(
    requirement: &vot_cli::authz::PushRequirement,
    presentation: &vot_cli::PushPresentation<'_>,
) -> bool {
    let Ok(signed) = vot_capability::decode(&presentation.open.capability) else {
        return false;
    };
    let Ok(capability) = vot_capability::Capability::from_canonical_bytes(&signed.capability)
    else {
        return false;
    };
    if capability.expiry == 0 || capability.expiry > presentation.now {
        return false;
    }
    let probe_now = capability
        .not_before
        .max(capability.expiry.saturating_sub(1));
    requirement
        .decide(
            presentation.challenge,
            presentation.open,
            presentation.channel_binding,
            probe_now,
        )
        .is_some()
}

fn capability_refusal_reason(
    requirement: &vot_cli::authz::PushRequirement,
    presentation: &vot_cli::PushPresentation<'_>,
) -> PushRefusalReason {
    if capability_is_expired(requirement, presentation) {
        PushRefusalReason::Expired
    } else {
        PushRefusalReason::Capability
    }
}

fn load_push_issuer(data_dir: &std::path::Path) -> Result<ed25519_dalek::SigningKey, String> {
    let path = data_dir.join("push-issuer.key");
    crate::paths::tighten_private_file(&path)?;
    let create = || {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        publish_private(&path, &bytes)
            .map(|()| bytes.to_vec())
            .map_err(|error| format!("write {}: {error}", path.display()))
    };
    let bytes = match std::fs::read(&path) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        Ok(_) => {
            std::fs::remove_file(&path)
                .map_err(|error| format!("remove {}: {error}", path.display()))?;
            create()?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create()?,
        Err(error) => return Err(format!("read {}: {error}", path.display())),
    };
    let mut bytes32 = [0u8; 32];
    bytes32.copy_from_slice(&bytes);
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes32))
}

fn push_credentials(config: &Config) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
    let certificate = config
        .push_certificate
        .clone()
        .unwrap_or_else(|| config.data_dir.join("push.crt"));
    let key = config
        .push_private_key
        .clone()
        .unwrap_or_else(|| config.data_dir.join("push.key"));
    let managed = config.push_certificate.is_none() && config.push_private_key.is_none();
    match (certificate.exists(), key.exists()) {
        (true, true) => {
            if managed {
                crate::paths::tighten_private_file(&certificate)?;
                crate::paths::tighten_private_file(&key)?;
            }
            return Ok((certificate, key));
        }
        (true, false) | (false, true) => {
            if !managed {
                return Err(format!(
                    "native push certificate and key must both exist: {} and {}",
                    certificate.display(),
                    key.display()
                ));
            }
            for path in [&certificate, &key] {
                match std::fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!("remove {}: {error}", path.display()));
                    }
                }
            }
        }
        (false, false) if !managed => {
            return Err(format!(
                "native push certificate and key not found: {} and {}",
                certificate.display(),
                key.display()
            ));
        }
        (false, false) => {}
    }

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|error| format!("generate native push key: {error}"))?;
    let mut parameters = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .map_err(|error| format!("create native push certificate: {error}"))?;
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let certificate_pem = parameters
        .self_signed(&key_pair)
        .map_err(|error| format!("create native push certificate: {error}"))?;
    publish_private(&certificate, certificate_pem.pem().as_bytes())
        .map_err(|error| format!("write {}: {error}", certificate.display()))?;
    if let Err(error) = publish_private(&key, key_pair.serialize_pem().as_bytes()) {
        let _ = std::fs::remove_file(&certificate);
        return Err(format!("write {}: {error}", key.display()));
    }
    Ok((certificate, key))
}

fn publish_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("key");
    let mut suffix = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let temporary = parent.join(format!(".{name}.tmp-{}", hex::encode(suffix)));
    let result = crate::auth::write_private(&temporary, bytes)
        .and_then(|()| std::fs::hard_link(&temporary, path));
    let cleanup = std::fs::remove_file(&temporary);
    match result {
        Ok(()) => cleanup,
        Err(error) => Err(error),
    }
}

/// The store and both storage roots answer; what /healthz and the admin
/// status strip report.
pub(crate) fn check_health(app: &App) -> Result<(), String> {
    app.store
        .health_check()
        .and_then(|()| health_probe(&app.config.receive_dir, "receive"))
        .and_then(|()| health_probe(&app.config.outbound_dir, "outbound"))
}

fn health_probe(root: &std::path::Path, label: &str) -> Result<(), String> {
    let path = root.join(format!(
        ".votport-health-{label}-{}",
        crate::auth::random_token()
    ));
    let mut created = false;
    let result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("create {}: {error}", path.display()))
        .map(|_| {
            created = true;
        });
    let cleanup = if created {
        std::fs::remove_file(&path).map_err(|error| format!("remove {}: {error}", path.display()))
    } else {
        Ok(())
    };
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
    }
}

async fn healthz(State(app): State<Arc<App>>) -> Response {
    if let Err(error) = check_health(&app) {
        tracing::error!(%error, "health check failed");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    StatusCode::OK.into_response()
}

#[cfg(test)]
mod health_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn healthz_is_public_and_probes_database_and_directories() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let receive = app.config.receive_dir.clone();
        let outbound = app.config.outbound_dir.clone();
        let response = router(app)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert!(std::fs::read_dir(receive)
            .unwrap()
            .flatten()
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".votport-health-")));
        assert!(std::fs::read_dir(outbound)
            .unwrap()
            .flatten()
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".votport-health-")));
    }

    #[tokio::test]
    async fn healthz_returns_generic_unavailable_when_storage_cannot_be_probed() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let outbound = app.config.outbound_dir.clone();
        std::fs::remove_dir_all(&outbound).unwrap();
        std::fs::write(&outbound, b"not a directory").unwrap();

        let response = router(app)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
    }

    #[tokio::test]
    async fn healthz_returns_unavailable_when_database_schema_cannot_be_read() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let connection =
            rusqlite::Connection::open(app.config.data_dir.join("votport.db")).unwrap();
        connection.execute_batch("DROP TABLE meta").unwrap();

        let response = router(app)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[cfg(test)]
mod asset_cache_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    async fn fetch(path: &str) -> Response {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        router(app)
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn unstamped_assets_revalidate_and_stamped_assets_are_immutable() {
        let plain = fetch("/assets/fonts.css").await;
        assert_eq!(plain.status(), StatusCode::OK);
        assert_eq!(plain.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(plain.headers()[header::REFERRER_POLICY], "no-referrer");

        let stamped = fetch("/assets/favicon.png?v=0011223344556677").await;
        assert_eq!(stamped.status(), StatusCode::OK);
        assert_eq!(
            stamped.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(stamped.headers()[header::REFERRER_POLICY], "no-referrer");

        let missing = fetch("/assets/no-such-file.png?v=0011223344556677").await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(missing.headers()[header::CACHE_CONTROL], "no-cache");
    }
}

/// Asset URLs stamped with a content hash (?v=) never change meaning, so
/// successful responses to them are safe to cache forever. Everything else
/// under /assets keeps no-cache and revalidates.
async fn asset_cache_control(request: Request<axum::body::Body>, next: Next) -> Response {
    let stamped = request
        .uri()
        .query()
        .is_some_and(|query| query.split('&').any(|pair| pair.starts_with("v=")));
    let mut response = next.run(request).await;
    if stamped && (response.status().is_success() || response.status() == StatusCode::NOT_MODIFIED)
    {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    }
    response
}

pub fn router(app: Arc<App>) -> Router {
    let web_root = app.config.web_root.clone();
    let admin_page = web_root.join("index.html");
    let request_page = web_root.join("request.html");
    let outbound_page = web_root.join("send.html");
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
        .route("/healthz", get(healthz))
        // Pages.
        .route("/", serve_page(admin_page))
        .route("/r/{token}", serve_page(request_page))
        .route("/s/{token}", serve_page(outbound_page))
        .route("/verify", serve_page(page("verify")))
        // no-cache means revalidate, not never-cache: repeat visits answer
        // conditional GETs with 304s instead of re-downloading the wasm and
        // the hero image, while a redeploy still takes effect immediately.
        // Content-stamped requests (?v=<hash>) skip even the revalidation;
        // asset_cache_control marks those immutable.
        .nest_service(
            "/assets",
            Router::new()
                .fallback_service(ServeDir::new(web_root.join("assets")))
                .layer(
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
                        .layer(axum::middleware::from_fn(asset_cache_control)),
                ),
        )
        // Admin API.
        .route("/api/admin/login", post(api::admin_login))
        .route("/api/admin/logout", post(api::admin_logout))
        .route("/api/admin/session", get(api::admin_session))
        .route("/api/admin/status", get(api::admin_status))
        .route("/api/admin/search", get(api::admin_search))
        .route("/api/admin/audit", get(api::admin_audit_export))
        .route("/api/admin/holdings", get(api::holdings))
        .route("/api/admin/backup", get(api::backup_database))
        .route(
            "/api/admin/backups",
            get(api::get_backups)
                .put(api::put_backups_config)
                .post(api::create_backup),
        )
        .route("/api/admin/backups/restore", post(api::restore_backup))
        .route(
            "/api/admin/tenants",
            get(api::list_tenants).post(api::create_tenant),
        )
        .route("/api/admin/principals", get(api::list_principals))
        .route(
            "/api/admin/settings",
            get(api::get_settings).put(api::put_settings),
        )
        .route(
            "/api/admin/notifications/test",
            post(api::test_notifications),
        )
        .route(
            "/api/admin/tenants/{key}",
            axum::routing::patch(api::update_tenant).delete(api::delete_tenant),
        )
        .route(
            "/api/admin/branding/{key}",
            get(api::get_branding)
                .put(api::put_branding)
                .delete(api::delete_branding),
        )
        .route(
            "/api/admin/branding/{key}/logo",
            axum::routing::put(api::put_branding_logo)
                .delete(api::delete_branding_logo)
                .layer(DefaultBodyLimit::max(api::admin::MAX_LOGO_BYTES + 1024)),
        )
        .route("/api/admin/tenant", post(api::switch_tenant))
        .route("/api/admin/principals/revoke", post(api::revoke_principal))
        .route(
            "/api/admin/principals/unblock",
            post(api::unblock_principal),
        )
        .route(
            "/api/admin/outbound-grants",
            get(api::list_outbound_grants).post(api::create_outbound_grant),
        )
        .route(
            "/api/admin/outbound-grants/{id}",
            axum::routing::patch(api::update_outbound_grant).delete(api::delete_outbound_grant),
        )
        .route(
            "/api/admin/automation-tokens",
            get(api::list_automation_tokens).post(api::create_automation_token),
        )
        .route(
            "/api/admin/automation-tokens/{id}",
            axum::routing::delete(api::delete_automation_token),
        )
        .route(
            "/api/admin/outbound-files",
            get(api::list_outbound_files)
                .post(api::upload_outbound_file)
                .delete(api::delete_outbound_file),
        )
        .route("/api/admin/password", post(api::admin_change_password))
        .route(
            "/api/admin/links",
            get(api::list_links).post(api::create_link),
        )
        .route(
            "/api/admin/links/{id}",
            post(api::update_link)
                .patch(api::update_link)
                .delete(api::delete_link),
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
        .route("/receive", serve_page(page("receive")))
        .route("/deliver", serve_page(page("deliver")))
        .route("/links", serve_page(page("receive")))
        .route("/tenants", serve_page(page("tenants")))
        .route("/audit", serve_page(page("audit")))
        .route("/system", serve_page(page("system")))
        // SSO sign-in (phase 3 of docs/multi-tenancy.md).
        .route("/api/admin/sso", get(api::sso_available))
        .route("/api/admin/sso/start", get(api::sso_start))
        .route("/api/admin/callback", get(api::sso_callback))
        // Public upload API.
        .route("/api/push-identity", get(push_identity))
        .route("/api/r/{token}", get(api::link_info))
        .route("/api/receipt-key", get(api::receipt_key))
        .route(
            "/api/verify",
            post(api::verify_receipt).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/api/r/{token}/logo", get(api::link_logo))
        .route("/api/r/{token}/verify", post(api::verify_link_password))
        .route("/api/r/{token}/push", post(api::create_push_session))
        .route("/api/r/{token}/session", post(api::create_session))
        .route("/api/s/{token}", get(api::outbound_metadata))
        .route("/api/s/{token}/logo", get(api::outbound_logo))
        .route("/api/s/{token}/verify", post(api::verify_outbound_password))
        .route("/api/s/{token}/bundle", get(api::outbound::outbound_bundle))
        .route("/api/s/{token}/batch", get(api::outbound::outbound_batch))
        .route("/api/automation/share", post(api::automation_share))
        .route("/api/s/{token}/receipt", get(api::outbound_receipt))
        .route(
            "/api/s/{token}/file",
            get(api::outbound_file).head(api::outbound_file_head),
        )
        .route(
            "/api/s/{token}/files/{index}",
            get(api::outbound_file_indexed).head(api::outbound_file_indexed_head),
        )
        .route(
            "/api/s/{token}/receipts/{index}",
            get(api::outbound_receipt_indexed),
        )
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
        .layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::X_CONTENT_TYPE_OPTIONS,
                axum::http::HeaderValue::from_static("nosniff"),
            ),
        )
        .layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::REFERRER_POLICY,
                axum::http::HeaderValue::from_static("no-referrer"),
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&app),
            request_observability,
        ))
        .with_state(app)
}

async fn push_identity(State(app): State<Arc<App>>) -> Response {
    let Some(push) = app.push.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Json(serde_json::json!({
        "address": push.address,
        "certificate_digest": hex::encode(push.certificate_digest),
        "issuer_public_key": hex::encode(push.issuer.verifying_key().to_bytes()),
    }))
    .into_response()
}

#[cfg(test)]
mod push_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    fn push_config(directory: &std::path::Path) -> Config {
        let mut config = crate::api::testing::config(directory);
        config.push_bind = Some("127.0.0.1:0".parse().unwrap());
        config.push_advertise = Some("push.example.test:8322".to_owned());
        config
    }

    async fn identity(app: Arc<App>) -> serde_json::Value {
        let response = router(app)
            .oneshot(
                Request::builder()
                    .uri("/api/push-identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    #[tokio::test]
    async fn push_identity_is_public_and_stable_across_restarts() {
        let directory = tempfile::tempdir().unwrap();
        let first = build(push_config(directory.path())).unwrap();
        let first_identity = identity(first).await;
        assert_eq!(first_identity["address"], "push.example.test:8322");
        assert_eq!(
            first_identity["certificate_digest"].as_str().unwrap().len(),
            64
        );
        assert_eq!(
            first_identity["issuer_public_key"].as_str().unwrap().len(),
            64
        );
        let certificate = std::fs::read(directory.path().join("data/push.crt")).unwrap();
        let key = std::fs::read(directory.path().join("data/push.key")).unwrap();
        let issuer = std::fs::read(directory.path().join("data/push-issuer.key")).unwrap();

        let second = build(push_config(directory.path())).unwrap();
        assert_eq!(identity(second).await, first_identity);
        assert_eq!(
            std::fs::read(directory.path().join("data/push.crt")).unwrap(),
            certificate
        );
        assert_eq!(
            std::fs::read(directory.path().join("data/push.key")).unwrap(),
            key
        );
        assert_eq!(
            std::fs::read(directory.path().join("data/push-issuer.key")).unwrap(),
            issuer
        );
    }

    #[tokio::test]
    async fn push_identity_is_not_exposed_when_disabled() {
        let directory = tempfile::tempdir().unwrap();
        let response = router(crate::api::testing::build(directory.path()))
            .oneshot(
                Request::builder()
                    .uri("/api/push-identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn native_push_requires_a_nonzero_session_lifetime() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = push_config(directory.path());
        config.session_idle_secs = 0;

        assert_eq!(
            build(config).err().unwrap(),
            "VOTPORT_SESSION_IDLE_SECS must be greater than zero when native push is enabled"
        );
    }

    #[test]
    fn native_push_audience_obeys_capability_identity_bounds() {
        let exact = "x".repeat(vot_capability::bounds::IDENTITY.1 - "votport:".len());
        assert_eq!(
            push_audience(Some(&exact), "unused").unwrap().len(),
            vot_capability::bounds::IDENTITY.1
        );
        assert!(push_audience(Some(&format!("{exact}x")), "unused").is_err());
        assert!(push_audience(Some("drop.example\ninvalid"), "unused").is_err());
    }

    #[test]
    fn stale_push_setup_and_seams_are_spent() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        let missing_setup = PushTicket {
            session_id: "stale-setup".to_owned(),
            expires_at: u64::MAX,
            expected_package: vot_sdk::object::ObjectId {
                suite: 1,
                root: [78; 32],
                length: 1,
            },
            directory: directory.path().to_owned(),
            setup: None,
            seams: None,
            control: session::PushControl::new(),
        };
        assert!(matches!(
            ticket_setup(&missing_setup),
            Err(PushRefusalReason::Spent)
        ));

        let setup = session::WorkerSetup {
            store: Arc::clone(&application.store),
            link_id: "stale-seams".to_owned(),
            tenant: String::new(),
            dest_dir: directory.path().join("destination"),
            dest_rel: String::new(),
            expected_package: missing_setup.expected_package.clone(),
            max_total_bytes: 1,
            allow_hidden: false,
            signer: Arc::clone(&application.signer),
            session_id: [79; 16],
            started_at: crate::store::now_unix(),
            quiet_after_secs: 5,
            ended: application.session_ended.clone(),
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (seams, stale_handle) = session::push_seams(
            Arc::clone(&application),
            setup,
            session::PushControl::new(),
            runtime.handle().clone(),
        );
        drop(seams);
        let dead_seams = PushTicket {
            seams: Some(stale_handle),
            ..missing_setup
        };
        assert!(matches!(
            live_ticket_seams(&dead_seams),
            Err(PushRefusalReason::Spent)
        ));
    }

    #[test]
    fn capability_refusal_reason_distinguishes_expiry_from_invalid_proof() {
        let issuer = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
        let foreign_issuer = ed25519_dalek::SigningKey::from_bytes(&[92; 32]);
        let holder_key = ed25519_dalek::SigningKey::from_bytes(&[93; 32]);
        let audience = "votport:push.example.test:8322";
        let requirement = vot_cli::authz::PushRequirement::new(
            "votport",
            vot_cli::authz::key_id_of(&issuer.verifying_key()),
            issuer.verifying_key(),
            audience,
        );
        let challenge = requirement.challenge([94; 32]);
        let binding = vot_transport_api::ChannelBinding::from_bytes([95; 32]);
        let now = 1_700_000_000;
        let root = [96; 32];
        let signed = vot_cli::authz::issue_push(
            "votport",
            audience,
            &issuer,
            holder_key.verifying_key().to_bytes(),
            root,
            97,
            now,
            10,
        )
        .unwrap();
        let holder = vot_cli::authz::Holder::new(signed, holder_key.clone()).unwrap();
        let open = holder.answer(&challenge, binding).unwrap();
        let expired_now = now + 10 + 301;
        let expired = vot_cli::PushPresentation {
            peer: "127.0.0.1:1".parse().unwrap(),
            challenge: &challenge,
            open: &open,
            channel_binding: binding,
            now: expired_now,
        };
        assert_eq!(
            capability_refusal_reason(&requirement, &expired),
            PushRefusalReason::Expired
        );

        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let expired_for_admission = vot_cli::PushPresentation {
            peer: expired.peer,
            challenge: expired.challenge,
            open: expired.open,
            channel_binding: expired.channel_binding,
            now: now + 11,
        };
        assert!(admit_push(
            &application,
            &requirement,
            expired_for_admission,
            runtime.handle()
        )
        .is_none());
        assert_eq!(
            application
                .push_metrics
                .refusals(PushRefusalReason::Expired),
            1
        );
        assert_eq!(
            application.push_metrics.refusals(PushRefusalReason::Spent),
            0
        );

        let foreign_signed = vot_cli::authz::issue_push(
            "votport",
            audience,
            &foreign_issuer,
            holder_key.verifying_key().to_bytes(),
            root,
            97,
            now,
            10,
        )
        .unwrap();
        let foreign_holder = vot_cli::authz::Holder::new(foreign_signed, holder_key).unwrap();
        let foreign_open = foreign_holder.answer(&challenge, binding).unwrap();
        let foreign = vot_cli::PushPresentation {
            open: &foreign_open,
            ..expired
        };
        assert_eq!(
            capability_refusal_reason(&requirement, &foreign),
            PushRefusalReason::Capability
        );

        let wrong_binding = vot_transport_api::ChannelBinding::from_bytes([98; 32]);
        let wrong_binding_presentation = vot_cli::PushPresentation {
            channel_binding: wrong_binding,
            ..expired
        };
        assert_eq!(
            capability_refusal_reason(&requirement, &wrong_binding_presentation),
            PushRefusalReason::Capability
        );
    }

    #[test]
    fn push_ticket_sweep_removes_expired_unconnected_tickets() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(push_config(directory.path())).unwrap();
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let live_control = session::PushControl::new();
        application
            .sessions
            .insert_admitted(
                session::SessionAdmission {
                    id: "live".to_owned(),
                    link_id: "link".to_owned(),
                    tenant: String::new(),
                    reserved_bytes: 0,
                    max_total_bytes: None,
                    max_tenant_sessions: None,
                    max_link_sessions: usize::MAX,
                    max_sessions: usize::MAX,
                    kind: session::SessionKind::Push(live_control.clone()),
                },
                sender,
                || Ok(0),
            )
            .unwrap();
        let now = crate::store::now_unix();
        let expired_control = session::PushControl::new();
        let (expired_sender, _expired_receiver) = tokio::sync::mpsc::channel(1);
        application
            .sessions
            .insert_admitted(
                session::SessionAdmission {
                    id: "expired".to_owned(),
                    link_id: "link".to_owned(),
                    tenant: String::new(),
                    reserved_bytes: 0,
                    max_total_bytes: None,
                    max_tenant_sessions: None,
                    max_link_sessions: usize::MAX,
                    max_sessions: usize::MAX,
                    kind: session::SessionKind::Push(expired_control.clone()),
                },
                expired_sender,
                || Ok(0),
            )
            .unwrap();
        application.push_tickets.lock().unwrap().extend([
            (
                [1; 16],
                PushTicket {
                    session_id: "live".to_owned(),
                    expires_at: now + 60,
                    expected_package: vot_sdk::object::ObjectId {
                        suite: 1,
                        root: [1; 32],
                        length: 1,
                    },
                    directory: directory.path().join("live"),
                    setup: None,
                    seams: None,
                    control: live_control.clone(),
                },
            ),
            (
                [2; 16],
                PushTicket {
                    session_id: "missing".to_owned(),
                    expires_at: now + 60,
                    expected_package: vot_sdk::object::ObjectId {
                        suite: 1,
                        root: [2; 32],
                        length: 1,
                    },
                    directory: directory.path().join("missing"),
                    setup: None,
                    seams: None,
                    control: session::PushControl::new(),
                },
            ),
            (
                [3; 16],
                PushTicket {
                    session_id: "expired".to_owned(),
                    expires_at: now,
                    expected_package: vot_sdk::object::ObjectId {
                        suite: 1,
                        root: [3; 32],
                        length: 1,
                    },
                    directory: directory.path().join("expired"),
                    setup: None,
                    seams: None,
                    control: expired_control.clone(),
                },
            ),
        ]);

        sweep_push_tickets(&application);

        let tickets = application.push_tickets.lock().unwrap();
        assert_eq!(tickets.len(), 1);
        assert!(tickets.contains_key(&[1; 16]));
        assert!(!live_control.is_cancelled());
        assert!(expired_control.is_cancelled());
        assert_eq!(application.sessions.total(), 1);
        assert!(application.sessions.contains_push("live"));
    }

    #[test]
    fn push_ticket_sweep_keeps_expired_connected_tickets() {
        let directory = tempfile::tempdir().unwrap();
        let application = build(push_config(directory.path())).unwrap();
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let control = session::PushControl::new();
        assert!(control.connect());
        application
            .sessions
            .insert_admitted(
                session::SessionAdmission {
                    id: "connected".to_owned(),
                    link_id: "link".to_owned(),
                    tenant: String::new(),
                    reserved_bytes: 0,
                    max_total_bytes: None,
                    max_tenant_sessions: None,
                    max_link_sessions: usize::MAX,
                    max_sessions: usize::MAX,
                    kind: session::SessionKind::Push(control.clone()),
                },
                sender,
                || Ok(0),
            )
            .unwrap();
        application.push_tickets.lock().unwrap().insert(
            [4; 16],
            PushTicket {
                session_id: "connected".to_owned(),
                expires_at: crate::store::now_unix(),
                expected_package: vot_sdk::object::ObjectId {
                    suite: 1,
                    root: [4; 32],
                    length: 1,
                },
                directory: directory.path().join("connected"),
                setup: None,
                seams: None,
                control: control.clone(),
            },
        );

        sweep_push_tickets(&application);

        let tickets = application.push_tickets.lock().unwrap();
        assert!(tickets.contains_key(&[4; 16]));
        assert!(!control.is_cancelled());
    }

    #[test]
    fn managed_credentials_regenerate_when_one_file_is_left_behind() {
        for lone in ["push.crt", "push.key"] {
            let directory = tempfile::tempdir().unwrap();
            let data = directory.path().join("data");
            std::fs::create_dir_all(&data).unwrap();
            std::fs::write(data.join(lone), b"interrupted").unwrap();

            let config = push_config(directory.path());
            push_credentials(&config).unwrap();

            assert!(std::fs::read(data.join("push.crt"))
                .unwrap()
                .starts_with(b"-----BEGIN CERTIFICATE-----"));
            assert!(std::fs::read(data.join("push.key"))
                .unwrap()
                .starts_with(b"-----BEGIN"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn managed_credentials_tighten_existing_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let config = push_config(directory.path());
        std::fs::create_dir_all(&config.data_dir).unwrap();
        let (certificate, key) = push_credentials(&config).unwrap();
        for path in [&certificate, &key] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        push_credentials(&config).unwrap();
        for path in [certificate, key] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn invalid_push_issuer_is_regenerated_and_then_stable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("push-issuer.key");
        std::fs::write(&path, b"interrupted").unwrap();

        let first = load_push_issuer(directory.path()).unwrap();
        let first_bytes = std::fs::read(&path).unwrap();
        assert_eq!(first_bytes.len(), 32);
        let second = load_push_issuer(directory.path()).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(std::fs::read(path).unwrap(), first_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn push_issuer_tightens_an_existing_key() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("push-issuer.key");
        std::fs::write(&path, [9u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        load_push_issuer(directory.path()).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn supplied_credentials_are_strict_and_never_removed() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("supplied.crt");
        let key = directory.path().join("supplied.key");
        std::fs::write(&certificate, b"keep this file").unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.push_bind = Some("127.0.0.1:0".parse().unwrap());
        config.push_certificate = Some(certificate.clone());
        config.push_private_key = Some(key.clone());

        assert!(build(config).is_err());
        assert_eq!(std::fs::read(certificate).unwrap(), b"keep this file");
        assert!(!key.exists());
    }

    #[test]
    fn private_publication_never_overwrites_and_cleans_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let existing = directory.path().join("existing.key");
        std::fs::write(&existing, b"original").unwrap();
        assert!(publish_private(&existing, b"replacement").is_err());
        assert_eq!(std::fs::read(&existing).unwrap(), b"original");

        let created = directory.path().join("created.key");
        publish_private(&created, b"new secret").unwrap();
        assert_eq!(std::fs::read(&created).unwrap(), b"new secret");
        assert!(std::fs::read_dir(directory.path())
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp-")));
    }
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
            .is_some_and(|token| {
                crate::auth::constant_time_eq(token.as_bytes(), expected.as_bytes())
            });
        if !authorized {
            return (StatusCode::UNAUTHORIZED, "metrics token required").into_response();
        }
    }
    let app = Arc::clone(&app);
    let body = match tokio::task::spawn_blocking(move || metrics_text(&app)).await {
        Ok(Ok(body)) => body,
        Ok(Err(error)) => {
            tracing::error!(%error, "metrics read failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "metrics unavailable").into_response();
        }
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

fn metrics_text(app: &App) -> Result<String, String> {
    let usage = app.store.tenant_usage()?;
    let mut body = format!(
        "# TYPE votport_tenants gauge\nvotport_tenants {}\n",
        usage.iter().filter(|row| !row.tenant.is_empty()).count()
    );
    for row in usage {
        let key = if row.tenant.is_empty() {
            "default"
        } else {
            &row.tenant
        };
        let _ = write!(
            body,
            "votport_links{{tenant=\"{key}\"}} {}\nvotport_received_bytes{{tenant=\"{key}\"}} {}\n",
            row.links, row.received_bytes
        );
    }
    let _ = write!(
        body,
        "# TYPE votport_sessions_active gauge\nvotport_sessions_active {}\n",
        app.sessions.total()
    );
    let draining = app
        .store
        .resolved_settings(&app.config)
        .map(|settings| settings.draining)
        .unwrap_or(false);
    let _ = write!(
        body,
        "# TYPE votport_draining gauge\nvotport_draining {}\n",
        u8::from(draining)
    );
    let _ = write!(
        body,
        "# TYPE votport_push_sessions_active gauge\nvotport_push_sessions_active {}\n",
        app.sessions.push_total()
    );
    let _ = write!(
        body,
        "# TYPE votport_push_bytes_total counter\nvotport_push_bytes_total {}\n",
        app.push_metrics.bytes()
    );
    body.push_str("# TYPE votport_push_refused_total counter\n");
    for reason in PushRefusalReason::ALL {
        let _ = writeln!(
            body,
            "votport_push_refused_total{{reason=\"{}\"}} {}",
            reason.label(),
            app.push_metrics.refusals(reason)
        );
    }
    let _ = write!(
        body,
        "# TYPE votport_audit_rows gauge\nvotport_audit_rows {}\n",
        app.store.audit_count()?
    );
    let _ = write!(
        body,
        "# TYPE votport_audit_insert_failures_total counter\nvotport_audit_insert_failures_total {}\n",
        crate::store::AUDIT_INSERT_FAILURES.load(std::sync::atomic::Ordering::Relaxed)
    );
    let _ = write!(
        body,
        "# TYPE votport_upload_bytes_in_flight gauge\nvotport_upload_bytes_in_flight {}\n",
        app.sessions.bytes_in_flight()
    );
    body.push_str("# TYPE votport_disk_free_bytes gauge\n# TYPE votport_disk_total_bytes gauge\n");
    for (volume, root) in [
        ("receive", &app.config.receive_dir),
        ("outbound", &app.config.outbound_dir),
    ] {
        if let Some((free, total)) = crate::api::admin::disk_of(root) {
            let _ = write!(
                body,
                "votport_disk_free_bytes{{volume=\"{volume}\"}} {free}\nvotport_disk_total_bytes{{volume=\"{volume}\"}} {total}\n"
            );
        }
    }
    body.push_str(&TRANSFERS.prometheus());
    body.push_str(&app.request_metrics.prometheus());
    Ok(body)
}

#[cfg(test)]
mod push_metrics_tests {
    use super::*;

    #[test]
    fn push_metrics_keep_fixed_refusal_series() {
        let metrics = PushMetrics::default();
        metrics.add_bytes(7);
        for reason in PushRefusalReason::ALL {
            metrics.refuse(reason);
        }
        assert_eq!(metrics.bytes(), 7);
        assert!(PushRefusalReason::ALL
            .iter()
            .all(|reason| metrics.refusals(*reason) == 1));
        assert_eq!(PushRefusalReason::Rate.label(), "rate");
        assert_eq!(PushRefusalReason::Capability.label(), "capability");
        assert_eq!(PushRefusalReason::Expired.label(), "expired");
        assert_eq!(PushRefusalReason::Spent.label(), "spent");
    }
}

#[cfg(test)]
mod transfer_metrics_tests {
    use super::*;

    #[test]
    fn ended_notifies_only_rejections_and_interrupted_transfers_with_bytes() {
        let event = |outcome: &str, received_bytes: u64| crate::store::SessionEvent {
            at: 2,
            started_at: 1,
            outcome: outcome.to_owned(),
            detail: String::new(),
            received_bytes,
            expected_bytes: 10,
            replayed_chunks: 0,
            rejected_chunks: 0,
        };
        for (outcome, received, expected) in [
            ("rejected", 0, true),
            ("rejected", 5, true),
            ("interrupted", 0, false),
            ("interrupted", 1, true),
            ("cancelled", 5, false),
            ("published", 5, false),
            ("", 5, false),
        ] {
            assert_eq!(
                ended_notifies(&event(outcome, received)),
                expected,
                "{outcome} {received}"
            );
        }
    }

    #[test]
    fn outcome_table_is_fixed() {
        for (index, outcome) in TRANSFER_OUTCOMES.iter().enumerate() {
            assert_eq!(transfer_outcome_index(outcome), Some(index));
        }
        assert_eq!(transfer_outcome_index("exploded"), None);
        assert_eq!(transfer_outcome_index(""), None);
    }

    #[test]
    fn transfer_metrics_keep_fixed_series_and_cumulative_buckets() {
        let metrics = TransferMetrics::new();
        metrics.ended("rejected");
        metrics.ended("interrupted");
        metrics.ended("interrupted");
        metrics.ended("exploded");
        metrics.published(2 << 20, 5);
        metrics.published(3 << 30, 700);
        assert_eq!(metrics.ended_count("published"), 2);
        assert_eq!(metrics.ended_count("rejected"), 1);
        assert_eq!(metrics.ended_count("cancelled"), 0);
        assert_eq!(metrics.ended_count("interrupted"), 2);
        assert_eq!(metrics.ended_count("exploded"), 0);
        let loads = |buckets: &[AtomicU64; 7]| {
            buckets
                .iter()
                .map(|bucket| bucket.load(Ordering::Relaxed))
                .collect::<Vec<_>>()
        };
        assert_eq!(loads(&metrics.bytes_buckets), [0, 1, 1, 1, 2, 2, 2]);
        assert_eq!(loads(&metrics.duration_buckets), [0, 1, 1, 1, 2, 2, 2]);
        let text = metrics.prometheus();
        assert!(text.contains("votport_upload_sessions_ended_total{outcome=\"interrupted\"} 2\n"));
        assert!(text.contains("votport_upload_bytes_bucket{le=\"1048576\"} 0\n"));
        assert!(text.contains("votport_upload_bytes_bucket{le=\"+Inf\"} 2\n"));
        assert!(text.contains(&format!(
            "votport_upload_bytes_sum {}\n",
            (2u64 << 20) + (3 << 30)
        )));
        assert!(text.contains("votport_upload_duration_seconds_count 2\n"));
        assert!(text.contains("votport_upload_duration_seconds_sum 705\n"));
        assert_eq!(text.matches("_bucket{").count(), 14);
    }
}

#[cfg(test)]
mod request_metrics_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::time::Duration;

    #[test]
    fn request_ids_accept_only_bounded_safe_values() {
        let valid = Request::get("/")
            .header("x-request-id", "client.req-1_ok")
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_id(&valid), "client.req-1_ok");
        let too_long = "x".repeat(65);
        for value in ["", "has/slash", "has space", &too_long] {
            let request = Request::get("/")
                .header("x-request-id", value)
                .body(Body::empty())
                .unwrap();
            let generated = request_id(&request);
            assert_eq!(generated.len(), 32);
            assert!(generated
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')));
        }
    }

    #[test]
    fn request_metrics_keep_fixed_status_series_and_cumulative_buckets() {
        let metrics = RequestMetrics::default();
        metrics.observe(StatusCode::OK, Duration::from_millis(5));
        metrics.observe(StatusCode::MOVED_PERMANENTLY, Duration::from_millis(75));
        metrics.observe(StatusCode::BAD_REQUEST, Duration::from_millis(200));
        metrics.observe(
            StatusCode::INTERNAL_SERVER_ERROR,
            Duration::from_millis(2_000),
        );
        metrics.observe(
            StatusCode::from_u16(199).unwrap(),
            Duration::from_millis(6_000),
        );
        let text = metrics.prometheus();
        for class in REQUEST_STATUS_CLASSES {
            assert!(text.contains(&format!(
                "votport_http_requests_total{{status=\"{class}\"}} 1"
            )));
        }
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"0.01\"} 1"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"0.05\"} 1"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"0.1\"} 2"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"0.5\"} 3"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"1\"} 3"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"5\"} 4"));
        assert!(text.contains("votport_http_request_duration_seconds_bucket{le=\"+Inf\"} 5"));
        assert_eq!(
            text.matches("votport_http_request_duration_seconds_bucket{le=\"+Inf\"}")
                .count(),
            1
        );
        assert!(text.contains("votport_http_request_duration_seconds_count 5"));
        assert!(text.contains("votport_http_request_duration_seconds_sum 8.280000000"));
    }

    #[test]
    fn outbound_upload_timing_uses_one_fixed_route_and_histogram() {
        let upload = Request::post("/api/admin/outbound-files?path=project/file.bin")
            .body(Body::empty())
            .unwrap();
        assert!(is_outbound_upload(&upload));
        let other = Request::post("/api/admin/outbound-grants")
            .body(Body::empty())
            .unwrap();
        assert!(!is_outbound_upload(&other));
        let list = Request::get("/api/admin/outbound-files")
            .body(Body::empty())
            .unwrap();
        assert!(!is_outbound_upload(&list));

        let metrics = RequestMetrics::default();
        metrics.observe_outbound_upload(Duration::from_millis(75));
        let text = metrics.prometheus();
        assert!(text.contains(
            "# HELP votport_http_outbound_upload_duration_seconds HTTP time to response headers for outbound library uploads in seconds."
        ));
        assert!(text.contains("votport_http_outbound_upload_duration_seconds_bucket{le=\"0.1\"} 1"));
        assert!(
            text.contains("votport_http_outbound_upload_duration_seconds_bucket{le=\"+Inf\"} 1")
        );
        assert!(text.contains("votport_http_outbound_upload_duration_seconds_count 1"));
        assert!(text.contains("votport_http_outbound_upload_duration_seconds_sum 0.075000000"));
    }

    #[test]
    fn request_metrics_in_flight_returns_to_zero() {
        let metrics = RequestMetrics::default();
        let in_flight = metrics.begin();
        assert!(metrics
            .prometheus()
            .contains("votport_http_requests_in_flight 1"));
        drop(in_flight);
        assert!(metrics
            .prometheus()
            .contains("votport_http_requests_in_flight 0"));
    }

    #[tokio::test]
    async fn request_middleware_sets_valid_or_generated_request_id() {
        use tower::ServiceExt as _;

        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let response = router(app.clone())
            .oneshot(
                Request::get("/healthz")
                    .header("x-request-id", "client.req-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["x-request-id"], "client.req-1");

        let response = router(app)
            .oneshot(
                Request::get("/healthz")
                    .header("x-request-id", "bad/id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let generated = response.headers()["x-request-id"].to_str().unwrap();
        assert_eq!(generated.len(), 32);
        assert!(generated
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')));
    }

    #[tokio::test]
    async fn request_middleware_records_only_outbound_upload_posts() {
        use tower::ServiceExt as _;

        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        router(app.clone())
            .oneshot(
                Request::post("/api/admin/outbound-files?path=x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(app
            .request_metrics
            .prometheus()
            .contains("votport_http_outbound_upload_duration_seconds_count 1"));

        router(app.clone())
            .oneshot(
                Request::get("/api/admin/outbound-files?path=x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(app
            .request_metrics
            .prometheus()
            .contains("votport_http_outbound_upload_duration_seconds_count 1"));
    }
}

async fn expire_link_uploads(app: &App, candidate: crate::store::Link, cutoff: u64) {
    if candidate.legal_hold {
        return;
    }
    let Some(_pin) = app.sessions.try_pin_link(&candidate.id) else {
        return;
    };
    if app.sessions.active_for_link(&candidate.id) > 0 {
        return;
    }
    let link = match app.store.link(&candidate.tenant, &candidate.id) {
        Ok(Some(link)) if !link.legal_hold => link,
        Ok(_) => return,
        Err(error) => {
            tracing::error!(%error, "link re-read failed; skipping retention for link");
            return;
        }
    };
    let mut protected: HashSet<&str> = link
        .uploads
        .iter()
        .filter(|upload| upload.completed_at == 0 || upload.completed_at >= cutoff)
        .flat_map(|upload| &upload.files)
        .filter(|file| !file.deleted)
        .map(|file| file.stored_as.as_str())
        .collect();
    let now = now_unix();
    let active_outbound_files =
        match app
            .store
            .active_outbound_file_keys(&link.tenant, &link.id, now)
        {
            Ok(keys) => keys,
            Err(error) => {
                tracing::error!(%error, "outbound grant read failed; skipping retention for link");
                return;
            }
        };
    let mut active_outbound_files: HashSet<(&str, usize)> = active_outbound_files
        .iter()
        .map(|(upload_id, file_index)| (upload_id.as_str(), *file_index))
        .collect();
    for upload in &link.uploads {
        for (index, file) in upload.files.iter().enumerate() {
            if active_outbound_files.remove(&(upload.id.as_str(), index)) {
                protected.insert(file.stored_as.as_str());
            }
        }
    }
    if !active_outbound_files.is_empty() {
        tracing::error!("outbound grant references a missing file; skipping retention for link");
        return;
    }
    let candidates: HashSet<&str> = link
        .uploads
        .iter()
        .filter(|upload| upload.completed_at > 0 && upload.completed_at < cutoff)
        .flat_map(|upload| &upload.files)
        .filter(|file| !file.deleted && !protected.contains(file.stored_as.as_str()))
        .map(|file| file.stored_as.as_str())
        .collect();
    let mut removed = HashSet::new();
    for stored_as in candidates {
        // Same shape as admin::stored_path: the tenant prefix is not part of
        // stored_as, so omitting it here deletes the default tenant's file at
        // that relative path.
        let mut components = crate::paths::tenant_prefix(&link.tenant);
        components.extend(
            stored_as
                .split('/')
                .filter(|part| !part.is_empty())
                .map(str::to_owned),
        );
        let Ok(path) = crate::paths::join_under(&app.config.receive_dir, &components) else {
            continue;
        };
        let _ = tokio::fs::remove_file(format!("{}.vot-receipt", path.display())).await;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {
                removed.insert(stored_as.to_owned());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                removed.insert(stored_as.to_owned());
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "could not delete expired file");
            }
        }
    }
    if removed.is_empty() {
        return;
    }
    match app.store.tombstone_files(&link.tenant, &link.id, |file| {
        removed.contains(&file.stored_as)
    }) {
        Ok(true) => {
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
        Ok(false) => {
            tracing::warn!(link = %link.id, "expired files removed after link disappeared");
        }
        Err(error) => {
            tracing::error!(link = %link.id, %error, "expired files removed but tombstone failed");
        }
    }
}

/// Discards idle upload sessions and expired audit rows.
fn sweep_push_tickets(app: &App) {
    if app.push.is_none() {
        return;
    }
    let now = crate::store::now_unix();
    let mut cancelled = Vec::new();
    {
        let mut tickets = app.push_tickets.lock().expect("push tickets poisoned");
        tickets.retain(|_, ticket| {
            let connected = ticket.control.is_connected();
            let keep = app.sessions.contains_push(&ticket.session_id)
                && (ticket.expires_at > now || connected);
            if !keep {
                cancelled.push((
                    ticket.session_id.clone(),
                    ticket.control.clone(),
                    ticket.setup.take(),
                    connected,
                ));
            }
            keep
        });
    }
    for (session_id, control, setup, connected) in cancelled {
        control.cancel();
        if !connected {
            app.sessions.remove(&session_id);
        }
        if let Some(setup) = setup {
            session::record_unconnected_push(setup, false);
        }
    }
}

pub async fn session_sweeper(app: Arc<App>) {
    let idle = app.config.session_idle_secs;
    let mut day = tokio::time::interval(std::time::Duration::from_secs(86_400));
    loop {
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                app.sessions.sweep(idle);
                sweep_push_tickets(&app);
            }
            _ = day.tick() => {
                // Skip this tick rather than sweep on guessed settings: a
                // retention sweep deletes, and a wrong answer here deletes
                // the wrong things.
                let settings = match app.store.resolved_settings(&app.config) {
                    Ok(settings) => settings,
                    Err(error) => {
                        tracing::error!(%error, "settings read failed; skipping this sweep");
                        continue;
                    }
                };
                clean_outbound_proofs(&app.config.data_dir, &app.store, crate::store::now_unix());
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
                prune_legacy_snapshots(&backup_dir, cutoff_modified);

                // Received-content lifecycle: delete expired uploads from
                // disk and tombstone their records, per tenant. Only records
                // whose bytes were actually removed are tombstoned; a failed
                // disk delete leaves the record live so the sweep retries.
                if settings.upload_retention_days > 0 {
                    let cutoff = crate::store::now_unix()
                        .saturating_sub(settings.upload_retention_days.saturating_mul(86_400));
                    let links = match app.store.all_links() {
                        Ok(links) => links,
                        Err(error) => {
                            tracing::error!(%error, "link read failed; skipping the retention sweep");
                            continue;
                        }
                    };
                    for link in links {
                        expire_link_uploads(&app, link, cutoff).await;
                    }
                }
            }
        }
    }
}

fn prune_legacy_snapshots(backup_dir: &std::path::Path, cutoff: std::time::SystemTime) {
    let Ok(entries) = std::fs::read_dir(backup_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !crate::backup::owned_legacy_snapshot(name) {
            continue;
        }
        let expired = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .is_ok_and(|modified| modified < cutoff);
        if expired {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;
    use crate::store::{FileRecord, Link, OutboundGrant, SettingWrite, UploadRecord};

    #[test]
    fn legacy_snapshot_pruning_keeps_operator_files() {
        let directory = tempfile::tempdir().unwrap();
        let generated = directory.path().join("votport-1-deadbeef.db");
        let operator = directory.path().join("votport-before-upgrade.db");
        let modified = std::fs::FileTimes::new()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1));
        for path in [&generated, &operator] {
            let file = std::fs::File::create(path).unwrap();
            file.set_times(modified).unwrap();
        }
        prune_legacy_snapshots(
            directory.path(),
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(2),
        );
        assert!(!generated.exists());
        assert!(operator.exists());
    }

    #[tokio::test]
    async fn retention_preserves_protected_files_and_tombstones_expired_files() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let cutoff = crate::store::now_unix();
        app.store
            .put_settings(
                "test",
                &[(
                    "upload_retention_days".to_owned(),
                    SettingWrite::Set("1".to_owned()),
                )],
            )
            .unwrap();
        std::fs::create_dir_all(&app.config.receive_dir).unwrap();
        let held_path = app.config.receive_dir.join("held.txt");
        let expired_path = app.config.receive_dir.join("expired.txt");
        let active_path = app.config.receive_dir.join("active.txt");
        let shared_path = app.config.receive_dir.join("shared.txt");
        let outbound_path = app.config.receive_dir.join("outbound.txt");
        let failed_path = app.config.receive_dir.join("failed.txt");
        std::fs::write(&held_path, b"held").unwrap();
        std::fs::write(&expired_path, b"expired").unwrap();
        std::fs::write(&active_path, b"active").unwrap();
        std::fs::write(&shared_path, b"shared").unwrap();
        std::fs::write(&outbound_path, b"outbound").unwrap();
        std::fs::write(&failed_path, b"failed").unwrap();

        let held = Link {
            id: "held".to_owned(),
            tenant: String::new(),
            label: "held".to_owned(),
            dest: String::new(),
            password_hash: None,
            created_at: 0,
            expires_at: None,
            max_bytes: None,
            active: true,
            legal_hold: true,
            notify_on_upload: false,
            uploads: vec![UploadRecord {
                partial: false,
                log: Vec::new(),
                id: "upload".to_owned(),
                started_at: 0,
                completed_at: 1,
                replayed_chunks: 0,
                rejected_chunks: 0,
                transport: None,
                package_root: "root".to_owned(),
                total_bytes: 4,
                files: vec![FileRecord {
                    path: "held.txt".to_owned(),
                    stored_as: "held.txt".to_owned(),
                    bytes: 4,
                    suite: "blake3".to_owned(),
                    root: "object".to_owned(),
                    receipt: false,
                    deleted: false,
                }],
            }],
            events: Vec::new(),
        };
        let mut expired = held.clone();
        expired.id = "expired".to_owned();
        expired.label = "expired".to_owned();
        expired.legal_hold = false;
        expired.uploads[0].files[0].path = "expired.txt".to_owned();
        expired.uploads[0].files[0].stored_as = "expired.txt".to_owned();
        let mut active = expired.clone();
        active.id = "active".to_owned();
        active.label = "active".to_owned();
        active.uploads[0].files[0].path = "active.txt".to_owned();
        active.uploads[0].files[0].stored_as = "active.txt".to_owned();
        let mut shared = expired.clone();
        shared.id = "shared".to_owned();
        shared.label = "shared".to_owned();
        shared.uploads[0].files[0].path = "shared.txt".to_owned();
        shared.uploads[0].files[0].stored_as = "shared.txt".to_owned();
        shared.uploads.push(shared.uploads[0].clone());
        shared.uploads[1].id = "recent".to_owned();
        shared.uploads[1].completed_at = cutoff;
        let mut failed = expired.clone();
        failed.id = "failed".to_owned();
        failed.label = "failed".to_owned();
        failed.uploads[0].files[0].path = "failed.txt".to_owned();
        failed.uploads[0].files[0].stored_as = "failed.txt".to_owned();
        let mut outbound = expired.clone();
        outbound.id = "outbound".to_owned();
        outbound.label = "outbound".to_owned();
        outbound.uploads[0].files[0].path = "outbound.txt".to_owned();
        outbound.uploads[0].files[0].stored_as = "outbound.txt".to_owned();
        app.store.insert_link(held.clone()).unwrap();
        app.store.insert_link(expired).unwrap();
        app.store.insert_link(active).unwrap();
        app.store.insert_link(shared).unwrap();
        app.store.insert_link(outbound).unwrap();
        app.store.insert_link(failed).unwrap();
        app.store
            .insert_outbound_grant(OutboundGrant {
                id: "grant".to_owned(),
                token_hash: "hash".to_owned(),
                password_hash: None,
                tenant: String::new(),
                link_id: "outbound".to_owned(),
                upload_id: "upload".to_owned(),
                package_root: "root".to_owned(),
                name: "outbound.txt".to_owned(),
                suite: "blake3".to_owned(),
                root: "object".to_owned(),
                file_index: 0,
                bytes: 8,
                label: "outbound".to_owned(),
                created_at: cutoff,
                expires_at: cutoff.saturating_add(86_400),
                revoked_at: None,
                downloads: 0,
                max_downloads: None,
                notify_on_download: false,
                first_download_at: None,
                last_download_at: None,
                files: Vec::new(),
            })
            .unwrap();

        // The candidate came from the first read before an administrator set
        // the hold. The re-read under the lifecycle pin must still preserve it.
        let mut stale_held = held;
        stale_held.legal_hold = false;
        expire_link_uploads(&app, stale_held, cutoff).await;

        let (active_tx, _active_rx) = tokio::sync::mpsc::channel(1);
        app.sessions
            .insert(
                "active-session".to_owned(),
                "active".to_owned(),
                String::new(),
                active_tx,
            )
            .unwrap();
        let active_candidate = app.store.link("", "active").unwrap().unwrap();
        expire_link_uploads(&app, active_candidate, cutoff).await;
        assert!(active_path.exists());

        let shared_candidate = app.store.link("", "shared").unwrap().unwrap();
        expire_link_uploads(&app, shared_candidate, cutoff).await;
        assert!(shared_path.exists());
        assert!(app
            .store
            .link("", "shared")
            .unwrap()
            .unwrap()
            .uploads
            .iter()
            .all(|upload| !upload.files[0].deleted));

        let outbound_candidate = app.store.link("", "outbound").unwrap().unwrap();
        expire_link_uploads(&app, outbound_candidate, cutoff).await;
        assert!(outbound_path.exists());
        assert!(!app.store.link("", "outbound").unwrap().unwrap().uploads[0].files[0].deleted);

        let connection =
            rusqlite::Connection::open(app.config.data_dir.join("votport.db")).unwrap();
        connection
            .execute(
                "UPDATE outbound_grants SET file_index = ?1 WHERE id = ?2",
                rusqlite::params![i64::MAX, "grant"],
            )
            .unwrap();
        let malformed_candidate = app.store.link("", "outbound").unwrap().unwrap();
        expire_link_uploads(&app, malformed_candidate, cutoff).await;
        assert!(outbound_path.exists());
        assert!(!app.store.link("", "outbound").unwrap().unwrap().uploads[0].files[0].deleted);

        connection
            .execute_batch(
                "CREATE TRIGGER fail_link_update BEFORE UPDATE ON links
                 BEGIN SELECT RAISE(FAIL, 'test update failure'); END;",
            )
            .unwrap();
        let failed_candidate = app.store.link("", "failed").unwrap().unwrap();
        expire_link_uploads(&app, failed_candidate, cutoff).await;
        connection
            .execute_batch("DROP TRIGGER fail_link_update")
            .unwrap();
        assert!(!failed_path.exists());
        assert!(!app.store.link("", "failed").unwrap().unwrap().uploads[0].files[0].deleted);
        assert!(app
            .store
            .audit_export("", 0, 0, 100)
            .unwrap()
            .iter()
            .all(|row| row.subject != "failed"));

        let sweeper = tokio::spawn(session_sweeper(Arc::clone(&app)));
        for _ in 0..100 {
            if !expired_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        sweeper.abort();
        let _ = sweeper.await;

        assert!(held_path.exists());
        assert!(!expired_path.exists());
        assert!(active_path.exists());
        assert!(!app.store.link("", "held").unwrap().unwrap().uploads[0].files[0].deleted);
        assert!(app.store.link("", "expired").unwrap().unwrap().uploads[0].files[0].deleted);
        assert!(!app.store.link("", "active").unwrap().unwrap().uploads[0].files[0].deleted);
        assert!(app.sessions.pin_link_for_delete("expired"));
        app.sessions.unpin_link("expired");
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
