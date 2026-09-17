//! Application state and router assembly.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse as _, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use rand::RngCore as _;
use std::fmt::Display;
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

/// A process-local monotonic ceiling for committed-data age retention. The
/// wall anchor is persisted by Store, while elapsed uptime is deliberately
/// kept process-local so a restart cannot manufacture downtime.
pub(crate) struct RetentionClock {
    state: Mutex<RetentionClockState>,
    #[cfg(test)]
    observe_hook: Mutex<Option<RetentionObserveHook>>,
}

struct RetentionClockState {
    trusted_at: Option<u64>,
    anchor_at: u64,
    started_at: Instant,
}

#[cfg(test)]
struct RetentionObserveHook {
    reached: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetentionObservation {
    pub(crate) effective_at: u64,
    pub(crate) allow_age: bool,
}

// GET settings and the monotonic observation run at separate second
// boundaries. This tolerance is display-only; cleanup keeps the exact ceiling.
const RETENTION_CLOCK_DISPLAY_TOLERANCE_SECS: u64 = 2;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum RetentionClockAcknowledgementError {
    FutureObservation,
    Store(String),
}

impl RetentionClock {
    fn open(store: &Store) -> Result<Self, String> {
        let trusted_at = store.retention_clock_anchor()?;
        Ok(Self {
            state: Mutex::new(RetentionClockState {
                anchor_at: trusted_at.unwrap_or(0),
                trusted_at,
                started_at: Instant::now(),
            }),
            #[cfg(test)]
            observe_hook: Mutex::new(None),
        })
    }

    fn observe(&self, store: &Store, raw_wall: u64) -> Result<RetentionObservation, String> {
        let mut state = self.state.lock().expect("retention clock poisoned");
        let elapsed = state.started_at.elapsed();
        self.test_pause_observe();
        Self::observe_locked(store, raw_wall, elapsed, &mut state)
    }

    #[cfg(test)]
    fn observe_with_elapsed(
        &self,
        store: &Store,
        raw_wall: u64,
        elapsed: Duration,
    ) -> Result<RetentionObservation, String> {
        let mut state = self.state.lock().expect("retention clock poisoned");
        self.test_pause_observe();
        Self::observe_locked(store, raw_wall, elapsed, &mut state)
    }

    #[cfg(test)]
    fn test_pause_observe(&self) {
        let hook = self
            .observe_hook
            .lock()
            .expect("retention observe hook poisoned")
            .take();
        if let Some(hook) = hook {
            hook.reached.send(()).unwrap();
            hook.release
                .recv_timeout(Duration::from_secs(2))
                .expect("retention observe hook was not released");
        }
    }

    #[cfg(not(test))]
    fn test_pause_observe(&self) {}

    fn observe_locked(
        store: &Store,
        raw_wall: u64,
        elapsed: Duration,
        state: &mut RetentionClockState,
    ) -> Result<RetentionObservation, String> {
        let Some(trusted_at) = state.trusted_at else {
            return Ok(RetentionObservation {
                effective_at: raw_wall,
                allow_age: false,
            });
        };
        let ceiling = state.anchor_at.saturating_add(elapsed.as_secs());
        let effective_at = raw_wall.min(ceiling);
        let persisted = trusted_at.max(effective_at);
        if persisted > trusted_at {
            store.advance_retention_clock(persisted)?;
            state.trusted_at = Some(persisted);
        }
        Ok(RetentionObservation {
            effective_at,
            allow_age: true,
        })
    }

    fn acknowledge(&self, store: &Store, actor: &str, wall: u64) -> Result<(), String> {
        let mut state = self.state.lock().expect("retention clock poisoned");
        let trusted_at = store.acknowledge_retention_clock(actor, wall)?;
        state.trusted_at = Some(trusted_at);
        state.anchor_at = trusted_at;
        state.started_at = Instant::now();
        Ok(())
    }

    fn status(&self, raw_wall: u64) -> serde_json::Value {
        let state = self.state.lock().expect("retention clock poisoned");
        self.status_at(raw_wall, state.started_at.elapsed(), &state)
    }

    #[cfg(test)]
    fn status_with_elapsed(&self, raw_wall: u64, elapsed: Duration) -> serde_json::Value {
        let state = self.state.lock().expect("retention clock poisoned");
        self.status_at(raw_wall, elapsed, &state)
    }

    fn status_at(
        &self,
        raw_wall: u64,
        elapsed: Duration,
        state: &RetentionClockState,
    ) -> serde_json::Value {
        let Some(trusted_at) = state.trusted_at else {
            return serde_json::json!({
                "held": true,
                "trusted_at": serde_json::Value::Null,
                "effective_at": serde_json::Value::Null,
                "raw_wall_at": raw_wall,
            });
        };
        let ceiling = state.anchor_at.saturating_add(elapsed.as_secs());
        serde_json::json!({
            "held": false,
            "trusted_at": trusted_at,
            "effective_at": raw_wall.min(ceiling),
            "raw_wall_at": raw_wall,
            "capped": raw_wall > ceiling.saturating_add(RETENTION_CLOCK_DISPLAY_TOLERANCE_SECS),
        })
    }
}

pub struct App {
    pub config: Config,
    pub store: Arc<Store>,
    pub(crate) retention_clock: RetentionClock,
    pub sessions: Sessions,
    /// Content hash of the served sender assets, so a page loaded before a
    /// deploy can tell it is stale and reload instead of failing on a changed
    /// contract.
    pub web_build: String,
    pub(crate) asset_versions: Arc<HashMap<String, AssetVersion>>,
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
    /// Failed SCIM bearers per client bucket; a correct bearer resets it.
    pub scim_throttle: crate::auth::IpThrottle,
    /// The same for the replica bearer.
    pub replica_throttle: crate::auth::IpThrottle,
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
    pub outbound_rate: crate::api::session_rate::DownloadRate,
    /// Bounds parsed grant bodies and their preparation lifetime.
    pub outbound_grant_permits: Arc<tokio::sync::Semaphore>,
    /// Per-IP rate limit on automation share creation.
    pub automation_rate: crate::api::session_rate::SessionRate,
    pub automation_read_rate: crate::api::session_rate::SessionRate,
    /// Grants currently preparing or streaming, capped globally and per grant.
    pub outbound_active: Mutex<HashSet<String>>,
    /// Concurrent byte reservations for outbound staging on the data filesystem.
    pub outbound_stage_budget: Arc<crate::api::outbound::StageBudget>,
    pub(crate) admin_status: crate::api::admin::AdminStatusCache,
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
    /// Shared SSO start/callback budget, independent of local password sign-in.
    pub sso_rate: crate::api::session_rate::SessionRate,
    pub desktop_sign_ins: crate::api::sso::DesktopSignIns,
    pub push: Option<PushState>,
    /// The VOT serve listener for Deliver over QUIC, when bound.
    pub serve: Option<crate::api::serve::ServeState>,
    pub serve_rate: crate::api::session_rate::SessionRate,
    pub(crate) serve_metrics: crate::api::serve::ServeMetrics,
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
    /// Process-local, irreversible shutdown state. Persisted draining is a
    /// tenant policy and is deliberately independent of this bit.
    pub stopping: Arc<AtomicBool>,
    shutdown_requested_at: Mutex<Option<std::time::Instant>>,
    pub workflow_ready: tokio::sync::Notify,
    /// Exclusive flock on `<data_dir>/lock`, held for the life of the
    /// process: a second instance over the same data directory (an
    /// active-passive standby started too early) refuses to boot instead of
    /// sharing SQLite and staging with the live one.
    pub(crate) _data_lock: std::fs::File,
    /// This instance's name in the receive-root lease (crate::lease).
    pub lease_holder: String,
    pub receiving: Mutex<Result<Arc<crate::receiving::Active>, String>>,
    pub(crate) receiving_permits: Arc<tokio::sync::Semaphore>,
    pub(crate) receiving_reconfigure: Arc<tokio::sync::Semaphore>,
    /// Set when a heartbeat finds another holder in the lease file; the
    /// process is then shutting down and /readyz reports it.
    pub lease_lost: AtomicBool,
    health: HealthCache,
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
    // The session is not known at refusal time, so like the metric series the
    // row carries only the reason and the peer address.
    app.store.audit(
        "",
        "",
        "push_refused",
        "",
        &serde_json::json!({ "peer": peer.to_string(), "reason": reason.label() }),
    );
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
    client_ip: &str,
    report: &FinishReport,
    runtime: &tokio::runtime::Handle,
) {
    app.workflow_ready.notify_one();
    tracing::info!(
        target: "audit", event = "upload_completed", session = %session_id,
        upload = %report.upload_id,
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
    // Subject is the upload id, the name the UI shows; the tenant falls back
    // to "" only when the link cannot be read (absent, deleted, or a failed
    // read, which the warn above records).
    app.store.audit(
        completed_tenant,
        "",
        "upload_completed",
        &report.upload_id,
        &serde_json::json!({
            "files": report.files.len(),
            "bytes": report.files.iter().map(|file| file.bytes).sum::<u64>(),
            "client_ip": client_ip
        }),
    );
    {
        let application = Arc::clone(app);
        let tenant = completed_tenant.to_owned();
        let upload = report.upload_id.clone();
        runtime.spawn(async move {
            crate::notify::trade_uploaded(&application, &tenant, &upload).await;
        });
    }
    if let Some(link) = link.filter(|link| link.notifications.as_ref().is_some_and(|p| p.enabled()))
    {
        if let Some(completed_at) = app
            .store
            .upload_completed_at(&link.tenant, &link.id, &report.upload_id)
            .inspect_err(|error| {
                tracing::warn!(%error, upload = %report.upload_id, link = %link.id, "completed upload timestamp read failed")
            })
            .ok()
            .flatten()
        {
            let app = Arc::clone(app);
            let report = report.clone();
            runtime.spawn(async move {
                crate::notify::uploaded(
                    app,
                    link.tenant,
                    link.id,
                    link.label,
                    completed_at,
                    report,
                    link.notifications,
                )
                .await;
            });
        } else {
            tracing::warn!(upload = %report.upload_id, link = %link.id, "completed upload timestamp missing for notification");
        }
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
        if ended.notifications.as_ref().is_some_and(|p| p.enabled()) && ended_notifies(&ended.event)
        {
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

const RECEIVING_CHECK_CONCURRENCY: usize = 8;

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
    config.validate()?;
    #[cfg(unix)]
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o022));
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|error| format!("create {}: {error}", config.data_dir.display()))?;
    #[cfg(target_os = "linux")]
    if vot_platform_fs::is_smb_or_nfs(
        &std::fs::File::open(&config.data_dir).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?
    {
        return Err(
            "VOTPORT_DATA_DIR must use local storage; mount the NAS at VOTPORT_RECEIVE_DIR"
                .to_owned(),
        );
    }
    crate::paths::tighten_private_dir(&config.data_dir).map_err(|error| error.to_string())?;
    let data_lock = lock_data_dir(&config.data_dir)?;
    crate::backup::apply_pending_restore(&config.data_dir, crate::store::SCHEMA_VERSION)?;
    let store = Arc::new(Store::open(&config.data_dir)?);
    let orphan_count = crate::backup::sweep_data_dir_orphans(&config.data_dir)?;
    if orphan_count > 0 {
        tracing::info!(
            count = orphan_count,
            "removed interrupted backup and restore scratch"
        );
    }
    match store
        .setting(crate::backup::SETTING_KEY)
        .and_then(|setting| crate::backup::parse_config(setting, &config.data_dir))
        .and_then(|backup| backup.local_root(&config.data_dir))
        .and_then(|root| crate::backup::sweep_backup_root_orphans(&root))
    {
        Ok(Some(count)) if count > 0 => {
            tracing::info!(count, "removed interrupted backup archive stages")
        }
        Ok(None) => tracing::debug!("backup archive stage cleanup deferred while root is busy"),
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, "backup archive stage cleanup skipped"),
    }
    crate::api::serve::sweep_manifests(&store, &config.data_dir);
    // A saved NAS root is never created on a missing mount's local backing directory.
    if crate::receiving::saved_qualification(&store)?.is_none() {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&config.receive_dir)
            .map_err(|e| e.to_string())?;
    }
    std::fs::create_dir_all(&config.outbound_dir).map_err(|e| e.to_string())?;
    let retention_clock = RetentionClock::open(&store)?;
    let boot_retention = retention_clock.observe(&store, now_unix())?;
    let lease_holder = crate::lease::new_holder();
    let mut receiving = match crate::receiving::Destinations::configured(
        &config.receive_dir,
        &store,
    ) {
        Ok(destinations) => Ok(crate::receiving::Active::open(destinations, &lease_holder)?),
        Err(error) => {
            tracing::warn!(%error, "receiving storage needs configuration; admin remains available");
            Err(error)
        }
    };
    clean_outbound_stage(&config.data_dir);
    clean_outbound_proof_stages(&config.data_dir);
    if boot_retention.allow_age {
        clean_outbound_proofs(&config.data_dir, &store, boot_retention.effective_at);
    } else {
        tracing::warn!(
            "automatic retention is held until a platform operator acknowledges the current clock"
        );
        store.audit(
            "",
            "",
            "retention_clock_held",
            "",
            &serde_json::json!({ "raw_wall_at": now_unix() }),
        );
    }
    let secret = crate::auth::load_secret(&config.data_dir)?;
    let signer = Arc::clone(&store.event_signer);
    let sessions = Sessions::new();
    let (session_ended, session_ended_rx) = tokio::sync::mpsc::unbounded_channel();
    if let Ok(active) = &mut receiving {
        resume_upload_sessions(&config, &store, &signer, &sessions, &session_ended, active)?;
    }
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|error| format!("http client: {error}"))?;
    let push = config
        .push_bind
        .map(|address| build_push_state(&config, address))
        .transpose()?;
    let serve = config
        .serve_bind
        .map(|address| build_serve_state(&config, address))
        .transpose()?;
    let (web_build, asset_versions) = web_assets(&config.web_root);
    Ok(Arc::new(App {
        store,
        retention_clock,
        sessions,
        secret,
        web_build,
        asset_versions: Arc::new(asset_versions),
        change_password_throttle: LoginThrottle::new(),
        login_throttle: crate::auth::IpThrottle::new(),
        scim_throttle: crate::auth::IpThrottle::new(),
        replica_throttle: crate::auth::IpThrottle::new(),
        login_permits: Arc::new(tokio::sync::Semaphore::new(VERIFY_PERMITS)),
        link_verify_permits: Arc::new(tokio::sync::Semaphore::new(VERIFY_PERMITS)),
        change_password_permits: Arc::new(tokio::sync::Semaphore::new(VERIFY_PERMITS)),
        link_throttle: crate::auth::IpThrottle::new(),
        session_rate: crate::api::session_rate::SessionRate::new(),
        verify_rate: crate::api::session_rate::SessionRate::new(),
        // Twenty admitted sessions can each use VOT's eight default rails;
        // leave room for refused or retried rails in the same ten-minute window.
        push_rate: crate::api::session_rate::SessionRate::with_limit(200),
        // The same arithmetic as push: twenty fetches at eight rails each.
        serve_rate: crate::api::session_rate::SessionRate::with_limit(200),
        outbound_rate: crate::api::session_rate::DownloadRate::new(),
        outbound_grant_permits: Arc::new(tokio::sync::Semaphore::new(
            crate::api::outbound::LIBRARY_GRANT_CONCURRENCY,
        )),
        automation_rate: crate::api::session_rate::SessionRate::with_limit(60),
        automation_read_rate: crate::api::session_rate::SessionRate::with_limit(6000),
        outbound_active: Mutex::new(HashSet::new()),
        outbound_stage_budget: Arc::new(crate::api::outbound::StageBudget::new()),
        admin_status: crate::api::admin::AdminStatusCache::default(),
        staging_permits: Arc::new(tokio::sync::Semaphore::new(
            crate::api::outbound::STAGING_CONCURRENCY,
        )),
        outbound_upload_locks: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
        signer,
        http,
        sso_config: config.oidc.clone(),
        sso_client: SsoSlot::new(),
        sso_rate: crate::api::session_rate::SessionRate::with_limit(200),
        desktop_sign_ins: crate::api::sso::DesktopSignIns::default(),
        push,
        serve,
        serve_metrics: crate::api::serve::ServeMetrics::default(),
        push_metrics: PushMetrics::default(),
        request_metrics: RequestMetrics::default(),
        session_ended,
        session_ended_rx: Mutex::new(Some(session_ended_rx)),
        push_tickets: Mutex::new(HashMap::new()),
        backup_lock: Arc::new(tokio::sync::Mutex::new(())),
        shutdown: Arc::new(tokio::sync::Notify::new()),
        stopping: Arc::new(AtomicBool::new(false)),
        shutdown_requested_at: Mutex::new(None),
        workflow_ready: tokio::sync::Notify::new(),
        _data_lock: data_lock,
        lease_holder,
        receiving: Mutex::new(receiving.map(Arc::new)),
        receiving_permits: Arc::new(tokio::sync::Semaphore::new(RECEIVING_CHECK_CONCURRENCY)),
        receiving_reconfigure: Arc::new(tokio::sync::Semaphore::new(1)),
        lease_lost: AtomicBool::new(false),
        health: HealthCache::default(),
        config,
    }))
}

impl App {
    pub(crate) fn retention_observation(&self) -> Result<RetentionObservation, String> {
        self.retention_clock.observe(&self.store, now_unix())
    }

    pub(crate) fn retention_clock_status(&self) -> serde_json::Value {
        self.retention_clock.status(now_unix())
    }

    pub(crate) fn acknowledge_retention_clock_at(
        &self,
        actor: &str,
        observed_at: u64,
        current_wall: u64,
    ) -> Result<(), RetentionClockAcknowledgementError> {
        if observed_at > current_wall {
            return Err(RetentionClockAcknowledgementError::FutureObservation);
        }
        self.retention_clock
            .acknowledge(&self.store, actor, observed_at)
            .map_err(RetentionClockAcknowledgementError::Store)
    }

    pub fn receiving_destinations(&self) -> Result<Arc<crate::receiving::Destinations>, String> {
        if self.lease_lost.load(Ordering::Acquire) {
            return Err("receiving storage ownership was lost".to_owned());
        }
        let active = self
            .receiving
            .lock()
            .expect("receiving state poisoned")
            .clone()?;
        active.destinations.check_current()?;
        if self.lease_lost.load(Ordering::Acquire) {
            return Err("receiving storage ownership was lost".to_owned());
        }
        Ok(Arc::clone(&active.destinations))
    }

    pub(crate) async fn receiving_destinations_async(
        self: &Arc<Self>,
    ) -> Result<Arc<crate::receiving::Destinations>, String> {
        let permit = Arc::clone(&self.receiving_permits)
            .acquire_owned()
            .await
            .map_err(|_| "receiving storage is stopped".to_owned())?;
        let app = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            app.receiving_destinations()
        })
        .await
        .map_err(|error| error.to_string())?
    }

    pub(crate) fn resume_receiving(&self, active: &crate::receiving::Active) -> Result<(), String> {
        resume_upload_sessions(
            &self.config,
            &self.store,
            &self.signer,
            &self.sessions,
            &self.session_ended,
            active,
        )?;
        Ok(())
    }

    pub fn request_shutdown(&self) {
        // This short mutex serializes the admission linearization point,
        // timestamp, stopping publication, and notification. No caller can
        // start a fresh budget from a notification that raced its timestamp.
        let mut requested = self
            .shutdown_requested_at
            .lock()
            .expect("shutdown state poisoned");
        let first = self.sessions.close_admission();
        if first {
            *requested = Some(std::time::Instant::now());
        }
        self.stopping.store(true, Ordering::Release);
        self.shutdown.notify_waiters();
    }

    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    /// Waits for the persistent shutdown state without losing a notification
    /// between the check and registration of the waiter.
    pub async fn wait_for_shutdown(&self) {
        loop {
            let notified = self.shutdown.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_stopping() {
                return;
            }
            notified.await;
        }
    }

    pub fn shutdown_deadline(&self, budget: std::time::Duration) -> Option<std::time::Instant> {
        self.shutdown_requested_at
            .lock()
            .expect("shutdown state poisoned")
            .map(|started| started + budget)
    }

    /// Counts work that still owns the drain: setup admissions and live
    /// transport slots. Idle pre-minted tickets are intentionally excluded.
    pub(crate) fn native_active(&self) -> usize {
        let push = self
            .push_tickets
            .lock()
            .expect("push tickets poisoned")
            .values()
            .filter(|ticket| ticket.control.is_connected())
            .count();
        let serve = self
            .serve
            .as_ref()
            .map_or(0, |serve| serve.registry.active_sessions());
        self.sessions.active_admissions() + push + serve
    }

    pub async fn wait_native_drain(&self, deadline: std::time::Instant) {
        while self.native_active() != 0 {
            let now = std::time::Instant::now();
            if now >= deadline {
                tracing::warn!("native drain deadline reached");
                return;
            }
            let next = (deadline - now).min(std::time::Duration::from_millis(25));
            tokio::time::sleep(next).await;
        }
    }
}

/// Suspends every HTTP upload session for a restart: each worker
/// checkpoints and leaves its staging on disk for [`build`] to re-attach.
/// Called once the server has stopped serving, so no handler can reach a
/// session. A worker that does not answer in time is left to the process
/// exit, which is the crash path the checkpoint already covers. The summary
/// counts only sessions whose suspend reply reports a persisted checkpoint;
/// failures are named so an operator can see what a restart inherits.
pub async fn suspend_sessions(app: &App) {
    let senders = app.sessions.take_http();
    let count = senders.len();
    if count == 0 {
        return;
    }
    // Pending tasks retain their senders after the deadline; EOF would discard partial uploads.
    let all = futures_util::future::join_all(senders.into_iter().map(|sender| {
        tokio::spawn(async move {
            let (reply, done) = tokio::sync::oneshot::channel();
            if sender.send(session::Cmd::Suspend { reply }).await.is_ok() {
                done.await.ok()
            } else {
                None
            }
        })
    }));
    match tokio::time::timeout(std::time::Duration::from_secs(30), all).await {
        Ok(replies) => {
            // A joined-but-panicked worker counts as unanswered, like a
            // worker that never sent or replied.
            summarize_suspend(
                replies
                    .into_iter()
                    .map(|joined| joined.unwrap_or(None))
                    .collect(),
            );
        }
        Err(_) => tracing::warn!(count, "suspending upload sessions timed out"),
    }
}

/// Logs the suspend summary from the collected replies: `Ok` replies count
/// toward the suspended total, everything else becomes a named failure.
/// Split from [`suspend_sessions`] so tests can pin the summary without
/// driving real workers.
fn summarize_suspend(replies: Vec<Option<Result<(), String>>>) {
    let mut suspended = 0;
    let mut failures = Vec::new();
    for reply in replies {
        match reply {
            Some(Ok(())) => suspended += 1,
            Some(Err(error)) => failures.push(error),
            None => failures.push("worker did not answer the suspend command".to_owned()),
        }
    }
    if failures.is_empty() {
        tracing::info!(count = suspended, "suspended upload sessions for restart");
    } else {
        tracing::warn!(
            suspended,
            failed = failures.len(),
            "suspended upload sessions with failures: {}",
            failures.join("; ")
        );
    }
}

/// Owns the HTTP server through the bounded native drain and the final
/// checkpoint. `budget` is the production allowance; tests pass a short
/// budget through the same path without adding a runtime configuration knob.
pub async fn drain_and_checkpoint<F, E>(
    application: Arc<App>,
    server: F,
    budget: std::time::Duration,
) -> Result<(), String>
where
    F: Future<Output = Result<(), E>>,
    E: Display,
{
    let mut server = Box::pin(server);
    let drain_app = Arc::clone(&application);
    let mut drain = Box::pin(async move {
        drain_app.wait_for_shutdown().await;
        let deadline = drain_app
            .shutdown_deadline(budget)
            .expect("shutdown state must publish its deadline before waking");
        tokio::time::sleep_until(deadline.into()).await;
    });
    let server_result = tokio::select! {
        result = &mut server => Some(result),
        _ = &mut drain => None,
    };
    if let Some(Err(error)) = server_result {
        return Err(error.to_string());
    }
    if let Some(deadline) = application.shutdown_deadline(budget) {
        application.wait_native_drain(deadline).await;
    }
    // Keep `server` owned until after this checkpoint. In production the
    // process exits immediately afterward, so a blocking native listener
    // cannot be joined by runtime teardown.
    suspend_sessions(&application).await;
    Ok(())
}

/// Waits for the process stop signal used by the real server. API-triggered
/// restarts publish the same `request_shutdown` state directly.
pub async fn shutdown_signal(application: Arc<App>) {
    shutdown_signal_inner(application, None).await;
}

#[cfg(test)]
async fn shutdown_signal_ready(application: Arc<App>, ready: tokio::sync::oneshot::Sender<()>) {
    shutdown_signal_inner(application, Some(ready)).await;
}

async fn shutdown_signal_inner(
    application: Arc<App>,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        terminate.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = async move {
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        std::future::pending::<()>().await
    };
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
        _ = application.wait_for_shutdown() => {},
    }
    application.request_shutdown();
    tracing::info!("shutting down");
}

/// Reattaches recorded uploads and preserves unresolved recovery evidence.
fn resume_upload_sessions(
    config: &Config,
    store: &Arc<Store>,
    signer: &Arc<crate::receipt::ReceiptSigner>,
    sessions: &Sessions,
    ended: &tokio::sync::mpsc::UnboundedSender<session::SessionEnded>,
    active: &crate::receiving::Active,
) -> Result<HashSet<std::path::PathBuf>, String> {
    active
        .during_recovery(|destinations| {
            Ok(restore_upload_sessions(
                config,
                store,
                signer,
                sessions,
                ended,
                destinations,
            ))
        })
        .inspect(|kept| crate::paths::clean_staging(&config.receive_dir, kept))
}

fn restore_upload_sessions(
    config: &Config,
    store: &Arc<Store>,
    signer: &Arc<crate::receipt::ReceiptSigner>,
    sessions: &Sessions,
    ended: &tokio::sync::mpsc::UnboundedSender<session::SessionEnded>,
    destinations: &Arc<crate::receiving::Destinations>,
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
        match resume_upload_session(
            config,
            store,
            signer,
            sessions,
            ended,
            destinations,
            &mut session,
        ) {
            Ok(paths) => {
                if session.committed_upload_id.is_some() {
                    tracing::info!(target: "audit", event = "upload_session_cleaned", session_tag = %session_tag, "cleaned completed upload journals");
                } else {
                    tracing::info!(
                        target: "audit", event = "upload_session_resumed", link = %session.link_id,
                        session_tag = %session_tag, files = session.files.len(),
                        "re-attached upload session after restart"
                    );
                }
                kept.extend(paths);
            }
            Err(error) => {
                match session::permanent_refusal_detail(store, &session) {
                    Some(detail) => {
                        // The link can never accept this session again, so the
                        // evidence is dropped: one final interrupted event, then
                        // the record, staging and journals are removed.
                        session::commit_persisted_interruption(store, ended, &session, &detail);
                        match session::discard_refused_session(store, destinations, &session) {
                            Ok(()) => {
                                tracing::info!(target: "audit", event = "upload_session_discarded", link = %session.link_id, session_tag = %session_tag, %error, "discarded a suspended upload whose link can never accept it again")
                            }
                            Err(cleanup) => {
                                tracing::warn!(session_tag = %session_tag, %error, %cleanup, "discarding a refused suspended upload failed");
                                for file in &session.files {
                                    kept.insert(file.staging_path.clone());
                                    kept.insert(file.journal_path.clone());
                                }
                            }
                        }
                    }
                    None => {
                        tracing::warn!(session_tag = %session_tag, %error, "suspended upload requires recovery");
                        session::commit_persisted_interruption(store, ended, &session, &error);
                        for file in &session.files {
                            kept.insert(file.staging_path.clone());
                            kept.insert(file.journal_path.clone());
                        }
                        if let Some(key) = &session.push_key {
                            // The sweep must not remove a staging directory this
                            // session still needs; its files live inside it.
                            kept.insert(
                                session
                                    .dest_dir
                                    .join(".vot-stage")
                                    .join(format!(".vot-push-{key}")),
                            );
                        }
                    }
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
    destinations: &Arc<crate::receiving::Destinations>,
    session: &mut crate::store::PersistedUploadSession,
) -> Result<Vec<std::path::PathBuf>, String> {
    if session.committed_upload_id.is_some() {
        session::cleanup_committed_session(store, session, destinations)?;
        return Ok(Vec::new());
    }
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
        destinations: Arc::new(
            destinations.child(
                &session
                    .dest_dir
                    .strip_prefix(&config.receive_dir)
                    .map_err(|_| "resume destination is outside receiving storage")?
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>(),
            )?,
        ),
        client_ip: String::new(),
        dest_rel: session.dest_rel.clone(),
        expected_package: session.package.clone(),
        max_total_bytes: session.max_total_bytes.unwrap_or(u64::MAX),
        allow_hidden: config.allow_hidden,
        signer: Arc::clone(signer),
        session_id,
        started_at: session.started_at,
        quiet_after_secs: session::quiet_after_secs(config.session_idle_secs),
        ended: ended.clone(),
        checkpoint_warn: session::CheckpointWarnPacer::new(),
    };
    if let Some(key) = &session.push_key {
        if key.len() != 32 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid push staging key".to_owned());
        }
        let control = session::PushControl::resumable(key.clone(), None);
        let directory = control.staging_dir(&setup);
        // Lock ownership and persisted identity are trusted at boot. Its mtime
        // is wall clock state, so it cannot decide whether this session is idle.
        let _lock = session::lock_push_directory(&directory, setup.destinations.contract())
            .map_err(|error| error.to_string())?;
        let (sender, _) = tokio::sync::mpsc::channel(1);
        sessions
            .insert_admitted(
                session::SessionAdmission {
                    id: session.id.clone(),
                    link_id: session.link_id.clone(),
                    tenant: session.tenant.clone(),
                    reserved_bytes: session.package.length,
                    max_total_bytes: None,
                    max_tenant_sessions: None,
                    max_link_sessions: usize::MAX,
                    max_sessions: usize::MAX,
                    kind: session::SessionKind::Push(control),
                },
                sender,
                || Ok((0, Vec::new())),
            )
            .map_err(|error| format!("register push session: {error:?}"))?;
        // The parked session's native staging and journals live beside the
        // destination, outside the push directory; keep them from any sweep.
        let mut kept_paths = vec![directory];
        for file in &session.files {
            if !file.staging_path.as_os_str().is_empty() {
                kept_paths.push(file.staging_path.clone());
            }
            if !file.journal_path.as_os_str().is_empty() {
                kept_paths.push(file.journal_path.clone());
            }
        }
        return Ok(kept_paths);
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AssetFingerprint {
    len: u64,
    modified: SystemTime,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: u32,
    #[cfg(windows)]
    file_index: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct AssetVersion {
    path: PathBuf,
    stamp: String,
    fingerprint: AssetFingerprint,
}

impl AssetVersion {
    async fn is_current(&self) -> bool {
        tokio::fs::symlink_metadata(&self.path)
            .await
            .ok()
            .and_then(asset_fingerprint_from_metadata)
            .is_some_and(|fingerprint| fingerprint == self.fingerprint)
    }
}

struct AssetFile {
    path: PathBuf,
    relative: PathBuf,
    through_symlink: bool,
}

fn collect_asset_files(
    path: &Path,
    relative: &Path,
    through_symlink: bool,
    files: &mut Vec<AssetFile>,
) {
    let Ok(link_metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if link_metadata.file_type().is_symlink() {
        if relative == Path::new("vendor")
            && std::fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
        {
            let Ok(entries) = std::fs::read_dir(path) else {
                return;
            };
            for entry in entries.flatten() {
                let child_relative = relative.join(entry.file_name());
                collect_asset_files(&entry.path(), &child_relative, true, files);
            }
        } else if std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file()) {
            files.push(AssetFile {
                path: path.to_owned(),
                relative: relative.to_owned(),
                through_symlink: true,
            });
        }
        return;
    }
    if link_metadata.is_dir() {
        if through_symlink {
            return;
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let child_relative = relative.join(entry.file_name());
            collect_asset_files(&entry.path(), &child_relative, false, files);
        }
    } else if link_metadata.is_file() {
        files.push(AssetFile {
            path: path.to_owned(),
            relative: relative.to_owned(),
            through_symlink,
        });
    }
}

fn asset_fingerprint_from_metadata(metadata: std::fs::Metadata) -> Option<AssetFingerprint> {
    if !metadata.file_type().is_file() {
        return None;
    }
    Some(AssetFingerprint {
        len: metadata.len(),
        modified: metadata.modified().ok()?,
        #[cfg(unix)]
        device: std::os::unix::fs::MetadataExt::dev(&metadata),
        #[cfg(unix)]
        inode: std::os::unix::fs::MetadataExt::ino(&metadata),
        #[cfg(windows)]
        volume_serial_number: std::os::windows::fs::MetadataExt::volume_serial_number(&metadata)?,
        #[cfg(windows)]
        file_index: std::os::windows::fs::MetadataExt::file_index(&metadata)?,
    })
}

fn asset_fingerprint(path: &Path) -> Option<AssetFingerprint> {
    asset_fingerprint_from_metadata(std::fs::symlink_metadata(path).ok()?)
}

fn asset_cache_key(relative: &Path) -> Option<String> {
    let mut key = String::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return None;
        };
        key.push('/');
        key.push_str(name.to_str()?);
    }
    (!key.is_empty()).then_some(key)
}

fn is_web_build_asset(relative: &Path) -> bool {
    let depth = relative.components().count();
    (depth == 1 || (depth == 2 && relative.starts_with("vendor")))
        && matches!(
            relative
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("js" | "wasm")
        )
}

fn hash_asset_file(
    path: &Path,
    mut aggregate: Option<&mut sha2::Sha256>,
    aggregate_name: &Path,
) -> Option<String> {
    use sha2::Digest as _;

    let mut file = std::fs::File::open(path).ok()?;
    if let Some(aggregate) = aggregate.as_deref_mut() {
        aggregate.update(aggregate_name.to_string_lossy().as_bytes());
    }
    let mut digest = sha2::Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        if let Some(aggregate) = aggregate.as_deref_mut() {
            aggregate.update(&buffer[..read]);
        }
    }
    let mut stamp = hex::encode(digest.finalize());
    stamp.truncate(16);
    Some(stamp)
}

/// Hashes static files once at startup and retains no asset contents.
fn web_assets(web_root: &Path) -> (String, HashMap<String, AssetVersion>) {
    use sha2::Digest as _;

    let assets = web_root.join("assets");
    let mut files = Vec::new();
    collect_asset_files(&assets, Path::new(""), false, &mut files);
    files.sort_by(|left, right| left.relative.cmp(&right.relative));

    let mut web_build_digest = sha2::Sha256::new();
    let mut web_build_has_files = false;
    let mut versions = HashMap::new();
    for file in files {
        let web_build_asset = is_web_build_asset(&file.relative);
        web_build_has_files |= web_build_asset;
        let fingerprint = (!file.through_symlink)
            .then(|| asset_fingerprint(&file.path))
            .flatten();
        let aggregate_name = Path::new("assets").join(&file.relative);
        let stamp = hash_asset_file(
            &file.path,
            web_build_asset.then_some(&mut web_build_digest),
            &aggregate_name,
        );
        let Some(stamp) = stamp else {
            continue;
        };
        if let (Some(fingerprint), Some(key)) = (fingerprint, asset_cache_key(&file.relative)) {
            if asset_fingerprint(&file.path).is_some_and(|current| current == fingerprint) {
                versions.insert(
                    key,
                    AssetVersion {
                        path: file.path,
                        stamp,
                        fingerprint,
                    },
                );
            }
        }
    }
    let web_build = if web_build_has_files {
        hex::encode(web_build_digest.finalize())[..16].to_owned()
    } else {
        "unknown".to_owned()
    };
    (web_build, versions)
}

/// Takes the single-writer lock. flock is advisory and per open file
/// description, so the returned handle must stay open; it is released by
/// the kernel when the process exits, however it exits.
pub(crate) fn lock_data_dir(data_dir: &std::path::Path) -> Result<std::fs::File, String> {
    let path = data_dir.join("lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options
        .open(&path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    #[cfg(unix)]
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |error| {
            format!(
                "{} is held by another votport process ({error}); only one instance may run on a data directory",
                path.display()
            )
        },
    )?;
    Ok(file)
}

/// Releases ownership for quiescent in-process restart fixtures. Production
/// exits while holding both fences, so blocked work cannot outlive ownership.
pub fn release_data_lock(app: &App) {
    app.lease_lost.store(true, Ordering::Release);
    app.receiving_permits.close();
    app.receiving_reconfigure.close();
    if !app.health.stop() {
        tracing::warn!(
            "health probe still running; retaining storage ownership until process exit"
        );
        return;
    }
    let Ok(mut state) = app.receiving.try_lock() else {
        return;
    };
    if let Ok(active) = state.as_ref() {
        active.destinations.stop();
        if Arc::strong_count(active) != 1 {
            return;
        }
    }
    if app.receiving_reconfigure.available_permits() == 0
        || app.receiving_permits.available_permits() != RECEIVING_CHECK_CONCURRENCY
    {
        return;
    }
    let previous = std::mem::replace(&mut *state, Err("receiving storage released".to_owned()));
    drop(state);
    drop(previous);
    #[cfg(unix)]
    let _ = rustix::fs::flock(&app._data_lock, rustix::fs::FlockOperation::Unlock);
}

/// Any failed ownership check stops receiving before another heartbeat can renew.
pub fn renew_lease(app: &App, now: u64) -> bool {
    if app.lease_lost.load(Ordering::Relaxed) {
        return false;
    }
    let state = app
        .receiving
        .lock()
        .expect("receiving state poisoned")
        .clone();
    let Ok(active) = state else {
        return true;
    };
    match active.renew(now) {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(%error, "receiving storage ownership check failed");
            app.lease_lost.store(true, Ordering::Relaxed);
            false
        }
    }
}

async fn renew_lease_once(app: &Arc<App>) -> bool {
    let app = Arc::clone(app);
    matches!(
        tokio::task::spawn_blocking(move || renew_lease(&app, now_unix())).await,
        Ok(true)
    )
}

/// Heartbeats the lease for the life of the process. A loss is a hard stop:
/// the other instance is re-attaching this one's staging, so a graceful
/// drain that lets in-flight uploads and pre-minted pushes keep writing
/// would be two writers for as long as the longest transfer. Workers
/// checkpoint, then the process exits; the standby resumes from there.
/// Only main spawns this: a test that ran it over a receive root another
/// test takes over would exit the whole test binary.
pub async fn lease_keeper(app: Arc<App>) {
    let mut tick = tokio::time::interval(crate::lease::RENEW_EVERY);
    tick.tick().await;
    loop {
        tick.tick().await;
        if !renew_lease_once(&app).await {
            app.lease_lost.store(true, Ordering::Release);
            suspend_sessions(&app).await;
            std::process::exit(1);
        }
    }
}

/// Remove only VOTPORT-owned outbound staging entries. `symlink_metadata` and
/// per-entry removal keep cleanup from traversing an operator-created link.
/// The sweep runs once per start and covers a bounded directory, so every
/// failure warns with the entry's relative name instead of vanishing.
fn clean_outbound_stage(data_dir: &std::path::Path) {
    let root = data_dir.join("outbound.stage");
    let root_meta = match std::fs::symlink_metadata(&root) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(%error, path = %root.display(), "outbound stage scan failed");
            return;
        }
    };
    if !root_meta.file_type().is_dir() || root_meta.file_type().is_symlink() {
        return;
    }
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(%error, path = %root.display(), "outbound stage scan failed");
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, "outbound stage entry could not be inspected");
                continue;
            }
        };
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(".vot-outbound-") {
            continue;
        }
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) => {
                tracing::warn!(%error, entry = %name, "outbound stage entry could not be inspected");
                continue;
            }
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            if let Err(error) = std::fs::remove_file(&path) {
                tracing::warn!(%error, entry = %name, "outbound stage cleanup failed");
            }
            continue;
        }
        let children = match std::fs::read_dir(&path) {
            Ok(children) => children,
            Err(error) => {
                tracing::warn!(%error, entry = %name, "outbound stage scan failed");
                continue;
            }
        };
        for child in children {
            let child = match child {
                Ok(child) => child,
                Err(error) => {
                    tracing::warn!(%error, entry = %name, "outbound stage entry could not be inspected");
                    continue;
                }
            };
            let child_path = child.path();
            let child_name = child.file_name();
            let Ok(child_meta) = std::fs::symlink_metadata(&child_path) else {
                continue;
            };
            let removal = if child_meta.file_type().is_dir() && !child_meta.file_type().is_symlink()
            {
                std::fs::remove_dir(&child_path)
            } else {
                std::fs::remove_file(&child_path)
            };
            if let Err(error) = removal {
                let child = child_name.to_string_lossy();
                tracing::warn!(%error, entry = %name, child = %child, "outbound stage cleanup failed");
            }
        }
        if let Err(error) = std::fs::remove_dir(&path) {
            tracing::warn!(%error, entry = %name, "outbound stage cleanup failed");
        }
    }
}

/// The stage sweep runs once per start, so every failure warns with the
/// entry's relative name instead of vanishing.
fn clean_outbound_proof_stages(data_dir: &std::path::Path) {
    let root = data_dir.join("outbound.proofs");
    let meta = match std::fs::symlink_metadata(&root) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(%error, path = %root.display(), "outbound catalog stage scan failed");
            return;
        }
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return;
    }
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(%error, path = %root.display(), "outbound catalog stage scan failed");
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, "outbound catalog stage entry could not be inspected");
                continue;
            }
        };
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !owned_catalog_stage_name(&name) {
            continue;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_file() && !meta.file_type().is_symlink() => {
                if let Err(error) = std::fs::remove_file(path) {
                    tracing::warn!(%error, stage = %name, "outbound catalog stage cleanup failed");
                }
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, stage = %name, "outbound catalog stage entry could not be inspected");
            }
        }
    }
}

static UNPARSEABLE_GRANT_WARN: OnceLock<Mutex<crate::api::outbound::ErrorDeduper>> =
    OnceLock::new();

/// Catalog and leaf names for every active outbound object, plus the grants
/// whose suite or root does not parse. An unparseable grant cannot name its
/// files, so its catalogs are missing from the returned keep set; the caller
/// must keep every catalog instead of pruning against a partial set.
fn active_catalog_names(
    keys: Vec<(String, String, String, u64)>,
) -> (HashSet<String>, Vec<(String, String)>) {
    let mut names = HashSet::new();
    let mut unparseable = Vec::new();
    for (grant_id, suite, root, length) in keys {
        let suite = match suite.as_str() {
            "blake3" => 1,
            "sha256" => 2,
            other => {
                unparseable.push((grant_id, format!("unknown suite {other}")));
                continue;
            }
        };
        let root = match hex::decode(&root)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .map(hex::encode)
        {
            Some(root) => root,
            None => {
                unparseable.push((grant_id, "root is not a 32-byte hex digest".to_owned()));
                continue;
            }
        };
        names.insert(format!("{suite}-{root}-{length}.vot-catalog"));
        names.insert(format!("{suite}-{root}-{length}.leaves"));
    }
    (names, unparseable)
}

fn canonical_proof_name(name: &str) -> bool {
    canonical_catalog_name(name) || canonical_leaf_name(name)
}

/// A serve's proof-leaf cache file, `<suite>-<root>-<length>.leaves`.
fn canonical_leaf_name(name: &str) -> bool {
    name.strip_suffix(".leaves")
        .is_some_and(|stem| canonical_catalog_name(&format!("{stem}.vot-catalog")))
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
    canonical_proof_name(catalog)
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
    let (names, unparseable) = match store.active_outbound_object_keys(now) {
        Ok(keys) => active_catalog_names(keys),
        Err(error) => {
            tracing::error!(%error, "outbound catalog references unavailable; skipping prune");
            return;
        }
    };
    // A grant that does not parse cannot contribute its catalogs, so the keep
    // set is incomplete and pruning would delete a live delivery's catalog:
    // keep every file this pass instead.
    for (grant_id, reason) in &unparseable {
        let due = UNPARSEABLE_GRANT_WARN
            .get_or_init(|| {
                Mutex::new(crate::api::outbound::ErrorDeduper::new(
                    "unparseable outbound grant",
                ))
            })
            .lock()
            .expect("unparseable outbound grant warn pacer poisoned")
            .observe(&format!("{grant_id}: {reason}"), std::time::Instant::now());
        if due {
            tracing::warn!(
                grant_id = %grant_id,
                reason = %reason,
                "outbound grant does not parse; keeping every catalog this pass"
            );
        }
    }
    if !unparseable.is_empty() {
        return;
    }
    prune_outbound_proofs(&root, &names);
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
        if !canonical_proof_name(&name) || keys.contains(&name) {
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
        // A leaf cache prunes by the same key as its catalog.
        let active_leaves = format!("1-{active_root}-10.leaves");
        let stale_leaves = format!("2-{}-11.leaves", "11".repeat(32));
        std::fs::write(root.join(&active_leaves), b"leaves").unwrap();
        std::fs::write(root.join(&stale_leaves), b"leaves").unwrap();
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
        // A leaf cache's own stage is also swept.
        let leaf_stage = root.join(format!(".{active_leaves}.stage-{}", "dd".repeat(16)));
        std::fs::write(&leaf_stage, b"leaf-stage").unwrap();
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
        let (keys, unparseable) = active_catalog_names(vec![(
            "grant-1".to_owned(),
            "blake3".to_owned(),
            active_root,
            10,
        )]);
        assert!(unparseable.is_empty());

        prune_outbound_proofs(&root, &keys);

        assert!(root.join(&active).exists());
        assert!(!root.join(stale).exists());
        assert!(
            root.join(&active_leaves).exists(),
            "an active grant's leaves are kept"
        );
        assert!(
            !root.join(&stale_leaves).exists(),
            "a stale grant's leaves are pruned"
        );
        assert!(root.join(foreign).exists());
        assert!(root.join("operator.txt").exists());
        clean_outbound_proof_stages(directory.path());
        assert!(foreign_stage.exists());
        assert!(!owned_stage.exists());
        assert!(!leaf_stage.exists(), "a leaf cache stage is swept");
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
    fn startup_preserves_unreconciled_files_on_shared_storage() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let stage = app.config.outbound_dir.join(".vot-crash.stage");
        std::fs::write(&stage, b"staged").unwrap();
        release_data_lock(&app);
        drop(app);

        let _app = crate::api::testing::build(directory.path());
        assert_eq!(std::fs::read(&stage).unwrap(), b"staged");
    }

    /// Audit finding 222: without write access both sweeps fail their
    /// removals, and each warn must name the item it could not remove.
    #[test]
    fn startup_cleanup_warns_with_entry_names_when_removals_fail() {
        let directory = tempfile::tempdir().unwrap();
        let stage = directory.path().join("outbound.stage");
        let owned = stage.join(".vot-outbound-dead");
        std::fs::create_dir_all(&owned).unwrap();
        std::fs::write(owned.join("part"), b"staged").unwrap();
        let backups = directory.path().join("backups");
        std::fs::create_dir_all(&backups).unwrap();
        let snapshot = backups.join("votport-1-aaaaaaaa.db");
        std::fs::write(&snapshot, b"snapshot").unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o555)).unwrap();

        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            clean_outbound_stage(directory.path());
            // A future cutoff makes the fresh snapshot count as expired.
            prune_legacy_snapshots(
                &backups,
                std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
            );
        });
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o755)).unwrap();

        let text = std::fs::read_to_string(log.path()).unwrap();
        let stage_warn = text
            .lines()
            .find(|line| line.contains("outbound stage cleanup failed"))
            .expect("the stage removal warns");
        assert!(stage_warn.contains(".vot-outbound-dead"), "{stage_warn}");
        let snapshot_warn = text
            .lines()
            .find(|line| line.contains("legacy snapshot removal failed"))
            .expect("the snapshot removal warns");
        assert!(
            snapshot_warn.contains("votport-1-aaaaaaaa.db"),
            "{snapshot_warn}"
        );
    }

    /// Audit finding 223: a grant whose suite does not parse cannot name its
    /// catalogs, so the prune must keep every catalog and warn with the
    /// grant's identity instead of pruning against a partial keep set.
    #[test]
    fn unparseable_grant_keeps_its_catalog_and_warns_with_identity() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let now = crate::store::now_unix();
        app.store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO outbound_grants(id, token_hash, tenant, link_id, upload_id,
                        package_root, name, suite, root, file_index, bytes_hi, bytes_lo,
                        label, created_at, expires_at, downloads)
                     VALUES ('grant-unparseable', 'hash', 'team', 'link', 'upload',
                        'root', 'file.txt', 'md5', 'root', 0, 0, 8,
                        'Delivery', 0, ?1, 0)",
                    rusqlite::params![i64::try_from(now + 3600).unwrap()],
                )
            })
            .unwrap();
        UNPARSEABLE_GRANT_WARN
            .get_or_init(|| {
                Mutex::new(crate::api::outbound::ErrorDeduper::new(
                    "unparseable outbound grant",
                ))
            })
            .lock()
            .unwrap()
            .reset();
        let root = app.config.data_dir.join("outbound.proofs");
        std::fs::create_dir_all(&root).unwrap();
        let stale = format!("2-{}-11.vot-catalog", "11".repeat(32));
        std::fs::write(root.join(&stale), b"stale").unwrap();

        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            clean_outbound_proofs(&app.config.data_dir, &app.store, now);
        });

        assert!(
            root.join(&stale).exists(),
            "conservative retention keeps every catalog when a grant does not parse"
        );
        let text = std::fs::read_to_string(log.path()).unwrap();
        let warn = text
            .lines()
            .find(|line| line.contains("outbound grant does not parse"))
            .expect("the unparseable grant warns");
        assert!(warn.contains("grant-unparseable"), "{warn}");
        assert!(warn.contains("unknown suite md5"), "{warn}");
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

/// The serve twin of [`build_push_state`]: the same certificate, issuer, and
/// audience on a second port, so one identity pins both directions.
fn build_serve_state(
    config: &Config,
    address: std::net::SocketAddr,
) -> Result<crate::api::serve::ServeState, String> {
    let (certificate, key) = push_credentials(config)?;
    let credentials = vot_cli::Credentials::Files { certificate, key };
    let (listener, certificate_digest) = vot_cli::bind_serve_listener(address, &credentials)
        .map_err(|error| format!("bind VOT serve listener: {error:?}"))?;
    let issuer = load_push_issuer(&config.data_dir)?;
    let address = config
        .serve_advertise
        .clone()
        .unwrap_or_else(|| listener.local_address().to_string());
    let audience = push_audience(config.public_url.as_deref(), &address)?;
    tracing::info!(
        address = %listener.local_address(),
        certificate_digest = %hex::encode(certificate_digest),
        "VOT serve listener bound"
    );
    Ok(crate::api::serve::ServeState {
        listener: Mutex::new(listener),
        issuer,
        address,
        audience,
        certificate_digest,
        registry: Arc::new(crate::api::serve::ServeRegistry::default()),
    })
}

/// Starts the process-lifetime VOT serve when Deliver over QUIC is enabled.
pub fn start_serve(app: Arc<App>) {
    if app.serve.is_none() {
        return;
    }
    let runtime = tokio::runtime::Handle::current();
    std::thread::Builder::new()
        .name("votport-serve".to_owned())
        .spawn(move || {
            let serve = app.serve.as_ref().expect("serve state disappeared");
            // Warm the servers for capabilities minted before this restart
            // off the accept thread, so a cold grant's read does not delay
            // the listener; a fetch that arrives first is refused unknown
            // until its server lands.
            let warming = Arc::clone(&app);
            runtime.spawn_blocking(move || {
                let serve = warming.serve.as_ref().expect("serve state disappeared");
                crate::api::serve::warm(&warming, serve);
            });
            let listener = serve.listener.lock().expect("serve listener poisoned");
            if let Err(error) = vot_cli::serve_on(&listener, |presentation| {
                crate::api::serve::admit_fetch(&app, presentation, &runtime)
            }) {
                tracing::error!(?error, "VOT serve stopped");
            }
        })
        .expect("spawn VOT serve");
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
    if app.receiving_destinations().is_err() {
        return None;
    }
    let token_id = capability.token_id;
    // A connected ticket owns the drain already, so later rails may join it.
    // An idle pre-minted ticket must win this fence before connect consumes it.
    let admission = app.sessions.try_admit();
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
            if admission.is_none() {
                return refuse_push(app, PushRefusalReason::Spent, presentation.peer);
            }
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

#[cfg(test)]
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

const HEALTH_TTL: std::time::Duration = std::time::Duration::from_secs(5);
const HEALTH_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Default)]
struct HealthCache {
    state: Mutex<HealthState>,
    stopped: AtomicBool,
    #[cfg(test)]
    probes: AtomicU64,
}

#[derive(Default)]
struct HealthState {
    snapshot: Option<HealthSnapshot>,
    running: bool,
}

#[derive(Clone)]
struct HealthSnapshot {
    started: std::time::Instant,
    generation: u64,
    healthy: bool,
    draining: Option<bool>,
    lease: Option<crate::lease::Lease>,
}

impl HealthSnapshot {
    fn fresh(&self, generation: u64) -> bool {
        self.generation == generation && self.started.elapsed() < HEALTH_TTL
    }
}

impl HealthCache {
    fn stop(&self) -> bool {
        self.stopped.store(true, Ordering::Release);
        self.state.try_lock().is_ok_and(|state| !state.running)
    }
}

async fn health_snapshot(app: &Arc<App>) -> Option<HealthSnapshot> {
    if app.lease_lost.load(Ordering::Relaxed) {
        return None;
    }
    let completed = {
        let mut state = app.health.state.try_lock().ok()?;
        if app.health.stopped.load(Ordering::Acquire) {
            return None;
        }
        let generation = app.store.settings_generation();
        if let Some(snapshot) = state.snapshot.as_ref().filter(|s| s.fresh(generation)) {
            return Some(snapshot.clone());
        }
        if state.running {
            return None;
        }
        state.running = true;
        let started = std::time::Instant::now();
        let app = app.clone();
        let (done, completed) = tokio::sync::oneshot::channel();
        // The completion task owns the claim even if its requesting client leaves.
        tokio::spawn(async move {
            let worker = app.clone();
            let result = tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                worker.health.probes.fetch_add(1, Ordering::Relaxed);
                let health = check_health(&worker);
                if let Err(error) = &health {
                    tracing::error!(%error, "health check failed");
                }
                let draining = worker
                    .store
                    .resolved_settings(&worker.config)
                    .map(|settings| settings.draining)
                    .map_err(|error| tracing::error!(%error, "readiness settings check failed"))
                    .ok();
                let lease = worker
                    .receiving_destinations()
                    .and_then(|root| root.lease_record())
                    .ok()
                    .flatten();
                (health.is_ok(), draining, lease)
            })
            .await;
            let (healthy, draining, lease) = result.unwrap_or_else(|error| {
                tracing::error!(%error, "health probe failed");
                (false, None, None)
            });
            let mut state = app.health.state.lock().expect("health state poisoned");
            state.snapshot = Some(HealthSnapshot {
                started,
                generation,
                healthy,
                draining,
                lease,
            });
            state.running = false;
            drop(state);
            let _ = done.send(());
        });
        completed
    };
    tokio::time::timeout(HEALTH_WAIT, completed)
        .await
        .ok()?
        .ok()?;
    let state = app.health.state.try_lock().ok()?;
    if app.health.stopped.load(Ordering::Acquire) {
        return None;
    }
    state
        .snapshot
        .as_ref()
        .filter(|s| s.fresh(app.store.settings_generation()))
        .cloned()
}

/// Blocking checks for the shared health and readiness snapshot.
pub(crate) fn check_health(app: &App) -> Result<(), String> {
    app.store
        .health_check()
        .and_then(|()| app.receiving_destinations()?.probe())
        .and_then(|()| health_probe(&app.config.outbound_dir, "outbound"))
}

fn health_probe(root: &std::path::Path, label: &str) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(root).map_err(|e| format!("{label}: {e}"))?;
    if !metadata.is_dir() {
        return Err(format!("{label} storage is not a directory"));
    }
    Ok(())
}

async fn healthz(State(app): State<Arc<App>>) -> Response {
    if health_snapshot(&app)
        .await
        .is_some_and(|snapshot| snapshot.healthy)
        && !app.lease_lost.load(Ordering::Relaxed)
    {
        StatusCode::OK.into_response()
    } else {
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}

/// Readiness for failover scripts and orchestrators: 503 while unhealthy or
/// draining, while /healthz keeps reporting the process itself as fine. Not
/// for a single-upstream proxy health check: drain keeps downloads and admin
/// up on purpose (docs/deployment.md, Scaling and availability). The body
/// carries the active upload count so a failover script can wait for zero.
async fn readyz(State(app): State<Arc<App>>) -> Response {
    if app.is_stopping() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ready": false,
                "draining": true,
                "sessions_active": app.sessions.total(),
                "lease": {
                    "holder": serde_json::Value::Null,
                    "mine": false,
                    "age_secs": serde_json::Value::Null,
                    "lost": app.lease_lost.load(Ordering::Relaxed),
                },
            })),
        )
            .into_response();
    }
    let snapshot = health_snapshot(&app).await;
    let lease_lost = app.lease_lost.load(Ordering::Relaxed);
    let (ready, draining) = match snapshot.as_ref() {
        Some(HealthSnapshot {
            healthy: true,
            draining: Some(draining),
            ..
        }) => (!draining && !lease_lost, *draining),
        _ => (false, false),
    };
    let now = now_unix();
    let lease = snapshot
        .and_then(|snapshot| snapshot.lease)
        .filter(|_| !lease_lost);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(serde_json::json!({
            "ready": ready,
            "draining": draining,
            "sessions_active": app.sessions.total(),
            "lease": {
                "holder": lease.as_ref().map(|lease| lease.holder.clone()),
                "mine": lease.as_ref().is_some_and(|lease| lease.holder == app.lease_holder),
                "age_secs": lease.as_ref().map(|lease| lease.age(now)),
                "lost": lease_lost,
            },
        })),
    )
        .into_response()
}

#[cfg(test)]
mod health_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    #[test]
    fn receiving_checks_do_not_hold_ownership_state_or_delay_renewal() {
        use std::time::{Duration, Instant};
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let destinations = app.receiving_destinations().unwrap();
        let pause = crate::receiving::CheckPause::new(&destinations, 1);
        let checking = app.clone();
        let worker = std::thread::spawn(move || checking.receiving_destinations());
        let deadline = Instant::now() + Duration::from_secs(1);
        while pause.entered() == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(pause.entered(), 1);
        let state_available = app.receiving.try_lock().is_ok();
        let renewing = app.clone();
        let (done, completed) = std::sync::mpsc::channel();
        let renewal = std::thread::spawn(move || {
            done.send(renew_lease(&renewing, now_unix())).unwrap();
        });
        let renewed = completed.recv_timeout(Duration::from_millis(500)).ok();
        pause.release();
        worker.join().unwrap().unwrap();
        renewal.join().unwrap();
        assert!(
            state_available,
            "currentness check held the ownership mutex"
        );
        assert_eq!(renewed, Some(true), "currentness check blocked renewal");
    }

    #[tokio::test]
    async fn receiving_checks_keep_their_bound_after_request_cancellation() {
        use std::time::Duration;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let destinations = app.receiving_destinations().unwrap();
        let pause = crate::receiving::CheckPause::new(&destinations, usize::MAX);
        let mut requests = Vec::new();
        for _ in 0..24 {
            let app = app.clone();
            requests.push(tokio::spawn(async move {
                app.receiving_destinations_async().await
            }));
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while pause.entered() < 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(pause.entered(), 8, "only eight checks may reach storage");
        for request in requests {
            request.abort();
            assert!(matches!(request.await, Err(error) if error.is_cancelled()));
        }
        let mut later = Vec::new();
        for _ in 0..12 {
            let app = app.clone();
            later.push(tokio::spawn(async move {
                app.receiving_destinations_async().await
            }));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            pause.entered(),
            8,
            "cancellation must not release running checks"
        );
        assert!(later.iter().all(|request| !request.is_finished()));
        pause.release();
        for request in later {
            tokio::time::timeout(Duration::from_secs(2), request)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.receiving_permits.available_permits() != 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(pause.entered(), 20, "cancelled waiters must never run");
        assert_eq!(app.receiving_permits.available_permits(), 8);
    }

    #[tokio::test]
    async fn receiving_renewal_waits_off_the_executor_and_keeps_ownership() {
        use std::time::{Duration, Instant};
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let destinations = app.receiving_destinations().unwrap();
        let pause = crate::receiving::CheckPause::new(&destinations, 1);
        let worker = app.clone();
        let renewal = tokio::spawn(async move { renew_lease_once(&worker).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while pause.entered() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let started = Instant::now();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!renewal.is_finished());
        assert!(app.receiving.try_lock().is_ok());
        release_data_lock(&app);
        assert!(lock_data_dir(&app.config.data_dir).is_err());
        assert!(crate::lease::Guard::acquire(
            &vot_platform_fs::Directory::open(&app.config.receive_dir).unwrap(),
            "other",
            now_unix()
        )
        .is_err());
        pause.release();
        assert!(!tokio::time::timeout(Duration::from_secs(2), renewal)
            .await
            .unwrap()
            .unwrap());
        assert!(destinations.check_current().is_err());
        release_data_lock(&app);
        assert!(lock_data_dir(&app.config.data_dir).is_ok());
        assert!(crate::lease::Guard::acquire(
            &vot_platform_fs::Directory::open(&app.config.receive_dir).unwrap(),
            "other",
            now_unix()
        )
        .is_ok());
    }

    #[test]
    fn receiving_shutdown_keeps_queued_check_and_reconfiguration_fences() {
        for reconfigure in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let app = crate::api::testing::build(directory.path());
            let permit = if reconfigure {
                &app.receiving_reconfigure
            } else {
                &app.receiving_permits
            }
            .clone()
            .try_acquire_owned()
            .unwrap();
            release_data_lock(&app);
            assert!(lock_data_dir(&app.config.data_dir).is_err());
            assert!(crate::lease::Guard::acquire(
                &vot_platform_fs::Directory::open(&app.config.receive_dir).unwrap(),
                "other",
                now_unix()
            )
            .is_err());
            assert!(app.receiving_permits.is_closed());
            assert!(app.receiving_reconfigure.is_closed());
            drop(permit);
            release_data_lock(&app);
            assert!(lock_data_dir(&app.config.data_dir).is_ok());
            assert!(crate::lease::Guard::acquire(
                &vot_platform_fs::Directory::open(&app.config.receive_dir).unwrap(),
                "other",
                now_unix()
            )
            .is_ok());
        }
    }

    async fn wait_health_idle(app: &App) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while app.health.state.lock().unwrap().running {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    struct PausedHealth {
        release: std::sync::mpsc::Sender<()>,
        holder: Option<std::thread::JoinHandle<()>>,
    }

    impl PausedHealth {
        fn new(app: &Arc<App>, receiving: bool) -> Self {
            let app = app.clone();
            let (entered, waiting) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            let holder = std::thread::spawn(move || {
                let pause = || {
                    entered.send(()).unwrap();
                    let _ = released.recv_timeout(std::time::Duration::from_secs(8));
                };
                if receiving {
                    let _state = app.receiving.lock().unwrap();
                    pause();
                } else {
                    app.store
                        .with(|_| {
                            pause();
                            Ok(())
                        })
                        .unwrap();
                }
            });
            waiting
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            Self {
                release,
                holder: Some(holder),
            }
        }
    }

    impl Drop for PausedHealth {
        fn drop(&mut self) {
            let _ = self.release.send(());
            self.holder.take().unwrap().join().unwrap();
        }
    }

    async fn blocked_health_request(path: &str) {
        use std::time::{Duration, Instant};
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let store = app.store.clone();
        let (entered, waiting) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            store
                .with(|_| {
                    entered.send(()).unwrap();
                    let _ = released.recv_timeout(Duration::from_secs(3));
                    Ok(())
                })
                .unwrap();
        });
        waiting.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        let (response, timer_elapsed) = tokio::join!(
            router(app.clone()).oneshot(Request::get(path).body(Body::empty()).unwrap()),
            async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                started.elapsed()
            },
        );
        let elapsed = started.elapsed();
        let _ = release.send(());
        holder.join().unwrap();
        wait_health_idle(&app).await;
        assert!(
            timer_elapsed < Duration::from_millis(500),
            "{path} blocked the async timer for {timer_elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "{path} waited {elapsed:?}"
        );
        assert_eq!(response.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn health_routes_do_not_block_healthz_on_sqlite() {
        blocked_health_request("/healthz").await;
    }

    #[tokio::test]
    async fn health_routes_do_not_block_readyz_on_sqlite() {
        blocked_health_request("/readyz").await;
    }

    #[tokio::test]
    async fn cancelled_health_requests_leave_only_one_blocking_probe() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let pause = PausedHealth::new(&app, false);
        let request = tokio::spawn(
            router(app.clone()).oneshot(Request::get("/healthz").body(Body::empty()).unwrap()),
        );
        tokio::time::timeout(HEALTH_WAIT, async {
            while app.health.probes.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        tokio::time::sleep(HEALTH_WAIT + std::time::Duration::from_millis(50)).await;
        let mut statuses = Vec::new();
        let started = std::time::Instant::now();
        for index in 0..20 {
            let path = if index % 2 == 0 {
                "/healthz"
            } else {
                "/readyz"
            };
            statuses.push(
                router(app.clone())
                    .oneshot(Request::get(path).body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
            );
        }
        let elapsed = started.elapsed();
        let probes = app.health.probes.load(Ordering::Relaxed);
        drop(pause);
        wait_health_idle(&app).await;
        assert!(statuses
            .iter()
            .all(|status| *status == StatusCode::SERVICE_UNAVAILABLE));
        assert!(elapsed < HEALTH_WAIT, "busy requests waited {elapsed:?}");
        assert_eq!(probes, 1);
        assert!(
            app.health
                .state
                .lock()
                .unwrap()
                .snapshot
                .as_ref()
                .unwrap()
                .healthy
        );
    }

    #[tokio::test]
    async fn shared_health_cache_expires_and_never_refreshes_an_over_age_probe() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        assert!(health_snapshot(&app).await.unwrap().healthy);
        let response = router(app.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 1);
        app.health
            .state
            .lock()
            .unwrap()
            .snapshot
            .as_mut()
            .unwrap()
            .started -= HEALTH_TTL;
        let pause = PausedHealth::new(&app, false);
        let started = std::time::Instant::now();
        assert!(health_snapshot(&app).await.is_none());
        assert!(health_snapshot(&app).await.is_none());
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 2);
        tokio::time::sleep(
            HEALTH_TTL.saturating_sub(started.elapsed()) + std::time::Duration::from_millis(50),
        )
        .await;
        drop(pause);
        wait_health_idle(&app).await;
        assert!(!app
            .health
            .state
            .lock()
            .unwrap()
            .snapshot
            .as_ref()
            .unwrap()
            .fresh(app.store.settings_generation()));
        assert!(health_snapshot(&app).await.unwrap().healthy);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn failed_health_probes_are_cached_and_panics_are_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        std::fs::remove_dir(&app.config.outbound_dir).unwrap();
        assert!(!health_snapshot(&app).await.unwrap().healthy);
        assert!(!health_snapshot(&app).await.unwrap().healthy);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 1);
        std::fs::create_dir(&app.config.outbound_dir).unwrap();
        app.health
            .state
            .lock()
            .unwrap()
            .snapshot
            .as_mut()
            .unwrap()
            .started -= HEALTH_TTL;
        let store = app.store.clone();
        assert!(std::thread::spawn(move || {
            let _ = store.with::<()>(|_| panic!("fixture store poison"));
        })
        .join()
        .is_err());
        assert!(!health_snapshot(&app).await.unwrap().healthy);
        assert!(!health_snapshot(&app).await.unwrap().healthy);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn shutdown_retains_both_fences_until_a_health_probe_finishes() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let pause = PausedHealth::new(&app, true);
        assert!(health_snapshot(&app).await.is_none());
        let started = std::time::Instant::now();
        release_data_lock(&app);
        let elapsed = started.elapsed();
        let data_refused = build(app.config.clone()).is_err();
        let mut standby = app.config.clone();
        standby.data_dir = directory.path().join("standby");
        let receive_refused = build(standby.clone()).is_err();
        let frozen = health_snapshot(&app).await.is_none();
        drop(pause);
        wait_health_idle(&app).await;
        assert!(
            elapsed < HEALTH_WAIT,
            "release waited on a running probe: {elapsed:?}"
        );
        assert!(
            data_refused && receive_refused,
            "both fences must remain held"
        );
        assert!(frozen);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 1);
        assert!(health_snapshot(&app).await.is_none());
        release_data_lock(&app);
        let standby = build(standby).unwrap();
        release_data_lock(&standby);
    }

    #[test]
    fn an_outstanding_health_probe_does_not_delay_process_exit() {
        const ROOT: &str = "VOTPORT_TEST_HEALTH_PROBE_EXIT";
        if let Some(root) = std::env::var_os(ROOT) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let app = crate::api::testing::build(std::path::Path::new(&root));
                let _pause = PausedHealth::new(&app, true);
                assert!(health_snapshot(&app).await.is_none());
                assert!(app.health.state.lock().unwrap().running);
                std::process::exit(0);
            });
            unreachable!();
        }
        let directory = tempfile::tempdir().unwrap();
        let log = std::fs::File::create(directory.path().join("child.log")).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "app::health_tests::an_outstanding_health_probe_does_not_delay_process_exit",
                "--nocapture",
            ])
            .env(ROOT, directory.path())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let outcome = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            outcome.is_some_and(|status| status.success()),
            "probe shutdown failed: {}",
            std::fs::read_to_string(directory.path().join("child.log")).unwrap()
        );
        use std::os::unix::fs::MetadataExt as _;
        let config = crate::api::testing::config(directory.path());
        let record = crate::lease::path(&config.receive_dir);
        let previous: crate::lease::Lease =
            serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
        let lock = record.parent().unwrap().join("writer.lock");
        let inode = std::fs::metadata(&lock).unwrap().ino();
        let app = crate::api::testing::build(directory.path());
        let current: crate::lease::Lease =
            serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
        assert_ne!(previous.holder, current.holder);
        assert_eq!(current.holder, app.lease_holder);
        assert_eq!(std::fs::metadata(&lock).unwrap().ino(), inode);
        release_data_lock(&app);
    }

    #[tokio::test]
    async fn health_settings_generation_tracks_successful_writes_and_resets() {
        use crate::store::SettingWrite;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(false));
        app.store
            .put_settings(
                "fixture",
                &[("draining".into(), SettingWrite::Set("1".into()))],
            )
            .unwrap();
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(true));
        let generation = app.store.settings_generation();
        let probes = app.health.probes.load(Ordering::Relaxed);
        app.store.with(|c| c.execute_batch(
            "CREATE TRIGGER refuse_settings BEFORE INSERT ON settings BEGIN SELECT RAISE(FAIL,'fixture refusal'); END;
             CREATE TRIGGER refuse_reset BEFORE DELETE ON settings BEGIN SELECT RAISE(FAIL,'fixture refusal'); END;"
        )).unwrap();
        assert!(app
            .store
            .put_settings(
                "fixture",
                &[("draining".into(), SettingWrite::Set("0".into()))]
            )
            .is_err());
        assert!(app.store.delete_setting("draining").is_err());
        assert_eq!(app.store.settings_generation(), generation);
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(true));
        assert_eq!(app.health.probes.load(Ordering::Relaxed), probes);
        app.store
            .with(|c| c.execute_batch("DROP TRIGGER refuse_settings; DROP TRIGGER refuse_reset;"))
            .unwrap();
        app.store.delete_setting("draining").unwrap();
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(false));
        app.store
            .put_settings(
                "fixture",
                &[("draining".into(), SettingWrite::Set("1".into()))],
            )
            .unwrap();
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(true));
        app.store
            .put_settings("fixture", &[("draining".into(), SettingWrite::Reset)])
            .unwrap();
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(false));
        assert_eq!(app.health.probes.load(Ordering::Relaxed), probes + 3);
    }

    #[tokio::test]
    async fn settings_changed_during_a_probe_invalidate_its_result() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let pause = PausedHealth::new(&app, true);
        assert!(health_snapshot(&app).await.is_none());
        app.store
            .put_settings(
                "fixture",
                &[(
                    "draining".into(),
                    crate::store::SettingWrite::Set("1".into()),
                )],
            )
            .unwrap();
        drop(pause);
        wait_health_idle(&app).await;
        assert!(!app
            .health
            .state
            .lock()
            .unwrap()
            .snapshot
            .as_ref()
            .unwrap()
            .fresh(app.store.settings_generation()));
        assert_eq!(health_snapshot(&app).await.unwrap().draining, Some(true));
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn cached_readiness_keeps_live_sessions_and_lease_loss() {
        use http_body_util::BodyExt as _;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        assert!(health_snapshot(&app).await.unwrap().healthy);
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        app.sessions
            .insert_resumed("live".into(), "link".into(), String::new(), 0, sender)
            .unwrap();
        let response = router(app.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["sessions_active"], 1);
        app.sessions.remove("live");
        app.lease_lost.store(true, Ordering::Relaxed);
        let response = router(app.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["sessions_active"], 0);
        assert_eq!(json["lease"]["lost"], true);
        assert_eq!(json["lease"]["mine"], false);
        assert!(json["lease"]["holder"].is_null());
        assert!(json["lease"]["age_secs"].is_null());
        let response = router(app.clone())
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(app.health.probes.load(Ordering::Relaxed), 1);
    }

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
    async fn suspension_deadline_includes_a_full_worker_queue() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let (reply, _done) = tokio::sync::oneshot::channel();
        sender.send(session::Cmd::Suspend { reply }).await.unwrap();
        app.sessions
            .insert_resumed("blocked".into(), "link".into(), String::new(), 0, sender)
            .unwrap();
        let (sender, mut healthy) = tokio::sync::mpsc::channel(1);
        app.sessions
            .insert_resumed("healthy".into(), "link".into(), String::new(), 0, sender)
            .unwrap();
        let shutdown = tokio::spawn({
            let app = app.clone();
            async move { suspend_sessions(&app).await }
        });
        let Some(session::Cmd::Suspend { reply }) =
            tokio::time::timeout(std::time::Duration::from_secs(1), healthy.recv())
                .await
                .unwrap()
        else {
            panic!("a blocked worker must not prevent another worker suspending");
        };
        reply.send(Ok(())).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(35), shutdown)
            .await
            .expect("a full worker queue must not bypass the 30-second shutdown deadline")
            .unwrap();
        assert_eq!(receiver.len(), 1);
        assert!(
            !receiver.is_closed(),
            "a timed-out sender must not trigger EOF cleanup of partial files"
        );
        assert_eq!(app.sessions.total(), 0);
        receiver.recv().await.unwrap();
        let Some(session::Cmd::Suspend { reply }) =
            tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                .await
                .unwrap()
        else {
            panic!("the pending suspension must still reach a recovered worker");
        };
        reply.send(Ok(())).unwrap();
    }

    /// Drives `suspend_sessions` against manually answered workers and
    /// returns the log records it emitted, so the summary can be pinned
    /// without asserting on a real NAS checkpoint.
    async fn suspend_summary_records(
        app: std::sync::Arc<App>,
        answers: Vec<Result<(), String>>,
    ) -> Vec<serde_json::Value> {
        use tracing::instrument::WithSubscriber;
        let mut receivers = Vec::new();
        for (index, _) in answers.iter().enumerate() {
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            app.sessions
                .insert_resumed(
                    format!("worker-{index}"),
                    "link".into(),
                    String::new(),
                    0,
                    sender,
                )
                .unwrap();
            receivers.push(receiver);
        }
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        let suspend =
            tokio::spawn(async move { suspend_sessions(&app).await }.with_subscriber(subscriber));
        for (mut receiver, answer) in receivers.into_iter().zip(answers) {
            let Some(session::Cmd::Suspend { reply }) =
                tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                    .await
                    .unwrap()
            else {
                panic!("suspend must reach every worker");
            };
            let _ = reply.send(answer);
        }
        tokio::time::timeout(std::time::Duration::from_secs(35), suspend)
            .await
            .unwrap()
            .unwrap();
        std::fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn suspend_summary_counts_only_persisted_sessions() {
        use tracing::instrument::WithSubscriber;
        let failure = "checkpoint failed; staging kept".to_owned();
        // Mixed through the real path: only the persisted session counts
        // toward the suspended total and the failure is named.
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let records = suspend_summary_records(
            app,
            vec![Ok(()), Err(failure.clone()), Err(failure.clone())],
        )
        .await;
        let summary = records
            .iter()
            .find(|record| {
                record["fields"]["message"].as_str().is_some_and(|message| {
                    message.contains("suspended upload sessions with failures")
                })
            })
            .unwrap_or_else(|| panic!("no suspend summary in {records:?}"));
        assert_eq!(summary["fields"]["suspended"], 1);
        assert_eq!(summary["fields"]["failed"], 2);
        assert!(
            summary["fields"]["message"]
                .as_str()
                .unwrap()
                .contains(&failure),
            "failures must be named: {summary}"
        );
        // All-fail: zero sessions count toward the suspended total.
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        async {
            summarize_suspend(vec![Some(Err(failure.clone())), Some(Err(failure.clone()))]);
        }
        .with_subscriber(subscriber)
        .await;
        let records: Vec<serde_json::Value> = std::fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let summary = records
            .iter()
            .find(|record| {
                record["fields"]["message"].as_str().is_some_and(|message| {
                    message.contains("suspended upload sessions with failures")
                })
            })
            .unwrap_or_else(|| panic!("no suspend summary in {records:?}"));
        assert_eq!(summary["fields"]["suspended"], 0);
        assert_eq!(summary["fields"]["failed"], 2);
        assert!(
            summary["fields"]["message"]
                .as_str()
                .unwrap()
                .contains(&failure),
            "failures must be named: {summary}"
        );
    }

    #[tokio::test]
    async fn readyz_follows_draining_and_healthz_does_not() {
        use http_body_util::BodyExt as _;
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let response = router(app.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ready"], true);
        assert_eq!(json["draining"], false);
        assert_eq!(json["sessions_active"], 0);

        app.store
            .put_settings(
                "test",
                &[(
                    "draining".to_owned(),
                    crate::store::SettingWrite::Set("1".to_owned()),
                )],
            )
            .unwrap();
        let response = router(app.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ready"], false);
        assert_eq!(json["draining"], true);
        let response = router(app)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_reports_process_stop_without_waiting_for_health() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.request_shutdown();
        let response = router(app)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["ready"], false);
        assert_eq!(value["draining"], true);
    }

    #[tokio::test]
    async fn shutdown_waiter_observes_stop_requested_before_it_starts() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.request_shutdown();
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            app.wait_for_shutdown(),
        )
        .await
        .expect("persistent stop state wakes late waiter");
        assert!(app
            .shutdown_deadline(std::time::Duration::from_secs(240))
            .is_some());
        app.request_shutdown();
        assert!(app.is_stopping());
    }

    #[tokio::test]
    async fn readyz_is_unavailable_when_storage_cannot_be_probed() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        std::fs::remove_dir_all(&app.config.receive_dir).unwrap();
        let response = router(app)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_second_instance_on_the_same_receive_root_refuses_to_boot_and_readyz_shows_the_lease()
    {
        use http_body_util::BodyExt as _;
        let directory = tempfile::tempdir().unwrap();
        let first = crate::api::testing::build(directory.path());
        // Its own data directory, so only the receive-root lease can refuse it.
        let mut config = crate::api::testing::config(&directory.path().join("standby"));
        config.receive_dir = first.config.receive_dir.clone();
        let error = match build(config.clone()) {
            Ok(_) => panic!("second instance booted over a live lease"),
            Err(error) => error,
        };
        assert!(error.contains(".votport-lease is held by"), "{error}");
        assert!(error.contains(&first.lease_holder), "{error}");

        let response = router(first.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["lease"]["holder"], first.lease_holder);
        assert_eq!(json["lease"]["mine"], true);
        assert_eq!(json["lease"]["lost"], false);
        assert!(json["lease"]["age_secs"].as_u64().unwrap() < 5);
        let metrics = metrics_text(&first).unwrap();
        assert!(metrics.contains("votport_lease_held 1\n"), "{metrics}");

        // Once the holder is gone and its clock has run out, the standby
        // takes over; the old holder's next heartbeat learns it lost.
        let path = crate::lease::path(&first.config.receive_dir);
        let stale = crate::lease::Lease {
            holder: first.lease_holder.clone(),
            acquired_at: 1,
            renewed_at: 1,
        };
        release_data_lock(&first);
        assert!(!path.exists(), "a clean shutdown yields the lease");
        std::fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
        let standby = build(config).unwrap();
        assert!(!renew_lease(&first, crate::store::now_unix()));
        assert!(first.lease_lost.load(Ordering::Relaxed));
        assert!(!renew_lease(&first, crate::store::now_unix()), "stays lost");
        assert!(renew_lease(&standby, crate::store::now_unix()));
        let response = router(first.clone())
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["lease"]["lost"], true);
        assert_eq!(json["lease"]["mine"], false);
        assert!(json["lease"]["holder"].is_null());
        assert!(metrics_text(&first)
            .unwrap()
            .contains("votport_lease_held 0\n"));
        assert!(metrics_text(&standby)
            .unwrap()
            .contains("votport_lease_held 1\n"));
    }

    #[test]
    fn a_boot_that_fails_after_taking_the_lease_gives_it_back() {
        let directory = tempfile::tempdir().unwrap();
        let config = crate::api::testing::config(directory.path());
        // A directory where the database file belongs makes Store::open
        // fail, which is after the lease is taken.
        std::fs::create_dir_all(config.data_dir.join("votport.db")).unwrap();
        assert!(build(config.clone()).is_err());
        assert!(
            !crate::lease::path(&config.receive_dir).exists(),
            "the failed boot must not leave its lease behind"
        );
        std::fs::remove_dir_all(config.data_dir.join("votport.db")).unwrap();
        build(config).unwrap();
    }

    #[test]
    fn overlapping_storage_roots_fail_before_store_open() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.outbound_dir = config.data_dir.join("library");
        let error = build(config.clone())
            .err()
            .expect("overlapping roots booted");
        assert!(error.contains("VOTPORT_DATA_DIR"), "{error}");
        assert!(error.contains("VOTPORT_OUTBOUND_DIR"), "{error}");
        assert!(!config.data_dir.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let directory = tempfile::tempdir().unwrap();
            let mut config = crate::api::testing::config(directory.path());
            std::fs::create_dir_all(&config.data_dir).unwrap();
            let alias = directory.path().join("received-alias");
            symlink(&config.data_dir, &alias).unwrap();
            config.receive_dir = alias;
            let error = build(config.clone()).err().expect("symlink alias booted");
            assert!(error.contains("VOTPORT_DATA_DIR"), "{error}");
            assert!(error.contains("VOTPORT_RECEIVE_DIR"), "{error}");
            assert!(!config.data_dir.join("votport.db").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_second_instance_on_the_same_data_directory_refuses_to_boot() {
        let directory = tempfile::tempdir().unwrap();
        let first = crate::api::testing::build(directory.path());
        let error = match build(crate::api::testing::config(directory.path())) {
            Ok(_) => panic!("second instance booted over a held data directory"),
            Err(error) => error,
        };
        assert!(error.contains("held by another votport process"), "{error}");
        release_data_lock(&first);
        drop(first);
        crate::api::testing::build(directory.path());
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

    #[test]
    fn metrics_reports_the_maintained_audit_count() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .audit("", "", "metrics_test", "row", &serde_json::json!({}));

        let metrics = metrics_text(&app).unwrap();
        assert!(metrics.contains("votport_audit_rows 1\n"));
        assert!(metrics.contains("votport_delivery_event_chain_failures_total "));
    }
}

#[cfg(test)]
mod shutdown_process_tests {
    use super::*;

    use std::future::IntoFuture;

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;
    use vot_sdk::object::{InMemoryObjectBuilder, Suite};
    use vot_sdk::package::{PackageBuilder, PackageEntry};

    const CHILD_ROOT: &str = "VOTPORT_TEST_SHUTDOWN_CHILD_ROOT";
    const EXPECTED_PREFIX_BYTES: u64 = 64 * 1024;

    async fn send_request(
        application: &Arc<App>,
        request: Request<Body>,
    ) -> axum::response::Response {
        router(Arc::clone(application))
            .oneshot(request)
            .await
            .unwrap()
    }

    fn connect_info(request: &mut Request<Body>) {
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                43210,
            ))));
    }

    async fn child_setup_and_checkpoint(root: &std::path::Path) {
        let application = crate::api::testing::build(root);
        application
            .store
            .insert_link(crate::store::tests::test_link("child"))
            .unwrap();

        let bytes = vec![7u8; 128 * 1024];
        let mut object = InMemoryObjectBuilder::new(
            Suite::Blake3Bao64,
            Some(bytes.len() as u64),
            bytes.len() as u64,
        )
        .unwrap();
        object.update(&bytes).unwrap();
        let prepared = object.finish().unwrap();
        let mut package = PackageBuilder::new().unwrap();
        let entry =
            PackageEntry::direct(vec!["partial.bin".to_owned()], prepared.object_id()).unwrap();
        assert!(package.push(&entry).unwrap().is_none());
        let (summary, final_page, mut finalizer) = package.finish().unwrap().into_parts();
        let page = finalizer.push(final_page).unwrap().into_bytes();
        let seal = finalizer.finish().unwrap().into_bytes();
        let package_id = summary.object_id();

        let mut create = Request::builder()
            .method("POST")
            .uri("/api/r/child/session")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "package": {
                        "suite": "blake3",
                        "root": hex::encode(package_id.root),
                        "length": package_id.length,
                    }
                })
                .to_string(),
            ))
            .unwrap();
        connect_info(&mut create);
        let response = send_request(&application, create).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let session = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["session"]
            .as_str()
            .unwrap()
            .to_owned();

        for (path, body) in [
            (format!("/api/session/{session}/seal"), seal),
            (format!("/api/session/{session}/page"), page),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .body(Body::from(body))
                .unwrap();
            assert_eq!(
                send_request(&application, request).await.status(),
                StatusCode::OK
            );
        }
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/session/{session}/begin"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            send_request(&application, request).await.status(),
            StatusCode::OK
        );

        let proof = prepared.prove(0, EXPECTED_PREFIX_BYTES).unwrap();
        let start = proof.covered_offset() as usize;
        let end = start + proof.covered_length() as usize;
        assert_eq!(start, 0);
        assert_eq!(proof.covered_length(), EXPECTED_PREFIX_BYTES);
        let mut body = proof.proof().to_vec();
        let proof_len = body.len();
        body.extend_from_slice(&bytes[start..end]);
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/session/{session}/chunk?entry=0&offset={start}"
            ))
            .header("x-votport-proof", proof_len.to_string())
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            send_request(&application, request).await.status(),
            StatusCode::OK
        );
        let saved = application.store.load_upload_sessions().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].files[0].prefix_bytes, 0);

        // Hold a real handler so graceful shutdown cannot finish before checkpoint.
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (_release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let entered = Arc::new(tokio::sync::Mutex::new(Some(entered_tx)));
        let release = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
        let held_route = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            get(move || {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                async move {
                    if let Some(sender) = entered.lock().await.take() {
                        let _ = sender.send(());
                    }
                    if let Some(receiver) = release.lock().await.take() {
                        let _ = receiver.await;
                    }
                    StatusCode::OK
                }
            })
        };
        let router = router(Arc::clone(&application)).route("/__test_hold", held_route);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (signal_ready_tx, signal_ready_rx) = tokio::sync::oneshot::channel();
        let server = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal_ready(
            Arc::clone(&application),
            signal_ready_tx,
        ))
        .into_future();
        let mut drain = tokio::spawn(drain_and_checkpoint(
            Arc::clone(&application),
            server,
            std::time::Duration::from_millis(50),
        ));
        let client = reqwest::Client::new();
        let held = tokio::spawn(client.get(format!("http://{address}/__test_hold")).send());
        match tokio::time::timeout(std::time::Duration::from_secs(1), entered_rx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => {
                held.abort();
                drain.abort();
                let _ = held.await;
                let _ = drain.await;
                panic!("held HTTP handler did not start");
            }
        }
        match tokio::time::timeout(std::time::Duration::from_secs(1), signal_ready_rx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => {
                held.abort();
                drain.abort();
                let _ = held.await;
                let _ = drain.await;
                panic!("shutdown signal was not installed");
            }
        }
        // Unix exercises the same SIGTERM waiter as main; other targets use the API path.
        #[cfg(unix)]
        {
            let status = std::process::Command::new("kill")
                .args(["-TERM", &std::process::id().to_string()])
                .status()
                .unwrap();
            assert!(status.success(), "self SIGTERM failed: {status}");
        }
        #[cfg(not(unix))]
        application.request_shutdown();
        if tokio::time::timeout(
            std::time::Duration::from_secs(1),
            application.wait_for_shutdown(),
        )
        .await
        .is_err()
        {
            held.abort();
            drain.abort();
            let _ = held.await;
            let _ = drain.await;
            panic!("SIGTERM did not request shutdown");
        }
        if held.is_finished() {
            held.abort();
            drain.abort();
            let _ = held.await;
            let _ = drain.await;
            panic!("held handler completed before drain");
        }

        let drain_result =
            match tokio::time::timeout(std::time::Duration::from_secs(2), &mut drain).await {
                Ok(result) => result,
                Err(_) => {
                    held.abort();
                    drain.abort();
                    let _ = held.await;
                    let _ = drain.await;
                    panic!("bounded shutdown did not reach checkpoint");
                }
            };
        drain_result
            .expect("shutdown task panicked")
            .expect("shutdown checkpoint failed");
    }

    #[tokio::test]
    async fn child_deadline_checkpoints_and_restart_reattaches_upload() {
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            child_setup_and_checkpoint(std::path::Path::new(&root)).await;
            std::process::exit(0);
        }

        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("child.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "app::shutdown_process_tests::child_deadline_checkpoints_and_restart_reattaches_upload",
                "--nocapture",
            ])
            .env(CHILD_ROOT, directory.path())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            status.is_some_and(|status| status.success()),
            "child shutdown did not complete: {}",
            std::fs::read_to_string(log_path).unwrap()
        );

        let application = crate::api::testing::build(directory.path());
        let sessions = application.store.load_upload_sessions().unwrap();
        assert_eq!(sessions.len(), 1, "checkpoint was not durable");
        assert_eq!(application.sessions.total(), 1, "restart did not reattach");
        assert_eq!(
            sessions[0]
                .files
                .iter()
                .find(|file| file.display_path == "partial.bin")
                .map(|file| file.prefix_bytes),
            Some(EXPECTED_PREFIX_BYTES)
        );
        release_data_lock(&application);
    }
}

#[cfg(test)]
mod asset_cache_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    async fn fetch(path: &str) -> Response {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        request(app, path).await
    }

    async fn request(app: Arc<App>, path: &str) -> Response {
        router(app)
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn unstamped_assets_revalidate_and_stamped_assets_are_immutable() {
        let directory = tempfile::tempdir().unwrap();
        let assets = directory.path().join("web/assets");
        std::fs::create_dir_all(&assets).unwrap();
        std::fs::create_dir(assets.join("subdir")).unwrap();
        std::fs::create_dir(assets.join("vendor")).unwrap();
        std::fs::write(assets.join("app.js"), b"root-script").unwrap();
        std::fs::write(assets.join("vendor/vendor.js"), b"vendor-script").unwrap();
        std::fs::write(assets.join("fonts.css"), b"body {}").unwrap();
        let favicon = assets.join("favicon.png");
        std::fs::write(&favicon, b"fixture").unwrap();
        let app = crate::api::testing::build(directory.path());
        use sha2::Digest as _;
        let mut expected_web_build = sha2::Sha256::new();
        for (name, contents) in [
            ("assets/app.js", &b"root-script"[..]),
            ("assets/vendor/vendor.js", &b"vendor-script"[..]),
        ] {
            expected_web_build.update(name.as_bytes());
            expected_web_build.update(contents);
        }
        let expected_web_build = hex::encode(expected_web_build.finalize());
        assert_eq!(app.web_build, expected_web_build[..16]);
        let favicon_stamp = app.asset_versions["/favicon.png"].stamp.clone();
        let fonts_stamp = app.asset_versions["/fonts.css"].stamp.clone();
        let plain = router(app.clone())
            .oneshot(
                Request::get("/assets/fonts.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(plain.status(), StatusCode::OK);
        assert_eq!(plain.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(plain.headers()[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(
            plain
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            b"body {}"
        );

        let stamped = request(
            app.clone(),
            &format!("/assets/favicon.png?v={favicon_stamp}"),
        )
        .await;
        assert_eq!(stamped.status(), StatusCode::OK);
        assert_eq!(
            stamped.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(stamped.headers()[header::REFERRER_POLICY], "no-referrer");

        for query in [
            "not-a-stamp".to_owned(),
            "0011223344556677".to_owned(),
            "001122334455667A".to_owned(),
            "001122334455667G".to_owned(),
            "001122334455667".to_owned(),
            format!("{favicon_stamp}&v={favicon_stamp}"),
        ] {
            let response = request(app.clone(), &format!("/assets/favicon.png?v={query}")).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
        }

        let wrong_path =
            request(app.clone(), &format!("/assets/fonts.css?v={favicon_stamp}")).await;
        assert_eq!(wrong_path.status(), StatusCode::OK);
        assert_eq!(wrong_path.headers()[header::CACHE_CONTROL], "no-cache");

        let encoded_alias = request(
            app.clone(),
            &format!("/assets/%66avicon.png?v={favicon_stamp}"),
        )
        .await;
        assert_eq!(encoded_alias.status(), StatusCode::OK);
        assert_eq!(encoded_alias.headers()[header::CACHE_CONTROL], "no-cache");

        let dot_alias = request(
            app.clone(),
            &format!("/assets/./favicon.png?v={favicon_stamp}"),
        )
        .await;
        assert_eq!(dot_alias.status(), StatusCode::OK);
        assert_eq!(dot_alias.headers()[header::CACHE_CONTROL], "no-cache");

        std::fs::write(&favicon, b"replacement").unwrap();
        let replaced = request(
            app.clone(),
            &format!("/assets/favicon.png?v={favicon_stamp}"),
        )
        .await;
        assert_eq!(replaced.status(), StatusCode::OK);
        assert_eq!(replaced.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(
            replaced
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            b"replacement"
        );

        let unchanged_other =
            request(app.clone(), &format!("/assets/fonts.css?v={fonts_stamp}")).await;
        assert_eq!(unchanged_other.status(), StatusCode::OK);
        assert_eq!(
            unchanged_other.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );

        let missing = request(app.clone(), "/assets/no-such-file.png?v=0011223344556677").await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(missing.headers()[header::CACHE_CONTROL], "no-cache");
        assert_eq!(
            missing.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        let body = missing.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"asset not found\n");

        for path in ["/assets/subdir", "/assets/subdir/"] {
            let directory_response = router(app.clone())
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(directory_response.status(), StatusCode::NOT_FOUND);
            assert!(directory_response.headers().get(header::LOCATION).is_none());
            assert_eq!(
                directory_response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .as_ref(),
                b"asset not found\n"
            );

            let directory_head = router(app.clone())
                .oneshot(Request::head(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(directory_head.status(), StatusCode::NOT_FOUND);
            assert!(directory_head.headers().get(header::LOCATION).is_none());
            assert!(directory_head
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty());
        }

        let head = router(app)
            .oneshot(
                Request::head("/assets/no-such-file.png")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            head.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert!(head
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());
    }

    #[tokio::test]
    async fn unknown_page_returns_plain_text_not_found_body() {
        let response = fetch("/mistyped-page").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"page not found\n");
    }
}

#[cfg(test)]
mod api_response_tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{HeaderValue, Request};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn api_responses_are_private_and_keep_head_and_method_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());

        let success = router(app.clone())
            .oneshot(
                Request::get("/api/receipt-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(success.status(), StatusCode::OK);
        assert_eq!(success.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(success.headers()[header::CONTENT_TYPE], "application/json");

        let audit = router(app.clone())
            .oneshot(
                Request::get("/api/admin/audit")
                    .header(
                        header::COOKIE,
                        crate::api::admin::test_admin_cookie(
                            &app,
                            &crate::auth::AdminIdentity::local_admin(),
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(audit.status(), StatusCode::OK);
        assert_eq!(audit.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            audit.headers()[header::CONTENT_TYPE],
            "application/x-ndjson; charset=utf-8"
        );
        let _ = audit.into_body().collect().await.unwrap().to_bytes();

        let fallback = router(app.clone())
            .oneshot(
                Request::get("/api/no-such-endpoint")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fallback.status(), StatusCode::NOT_FOUND);
        assert_eq!(fallback.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(fallback.headers()[header::CONTENT_TYPE], "application/json");
        let fallback_body = fallback.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&fallback_body).contains("request does not match"));

        let method_error = router(app.clone())
            .oneshot(
                Request::post("/api/admin/session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(method_error.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(method_error.headers()[header::CACHE_CONTROL], "no-store");
        assert!(method_error
            .headers()
            .get(header::ALLOW)
            .is_some_and(|value| value.as_bytes().windows(3).any(|part| part == b"GET")));
        assert_eq!(
            method_error.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        let body = method_error.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "request_failed");

        let unsupported = router(app.clone())
            .oneshot(
                Request::post("/api/r/missing/verify")
                    .header(header::CONTENT_TYPE, "text/plain")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        8080,
                    ))))
                    .body(Body::from("not json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unsupported.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(unsupported.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            unsupported.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        let unsupported_body = unsupported.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&unsupported_body).contains("request does not match"));

        let invalid_receipt = router(app.clone())
            .oneshot(
                Request::post("/api/verify")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        8080,
                    ))))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid_receipt.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(invalid_receipt.headers()[header::CACHE_CONTROL], "no-store");
        let invalid_receipt_body = invalid_receipt
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let invalid_receipt_body: serde_json::Value =
            serde_json::from_slice(&invalid_receipt_body).unwrap();
        assert_eq!(invalid_receipt_body["error"], "This is not a vot-receipt.");

        let too_large = router(app.clone())
            .oneshot(
                Request::post("/api/verify")
                    .extension(ConnectInfo(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        8080,
                    ))))
                    .body(Body::from(vec![0; 64 * 1024 + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(too_large.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            too_large.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        let too_large_body = too_large.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&too_large_body).contains("request does not match"));

        let head_failure = router(app.clone())
            .oneshot(
                Request::head("/api/no-such-endpoint")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head_failure.status(), StatusCode::NOT_FOUND);
        assert_eq!(head_failure.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            head_failure.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        assert!(head_failure
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());

        let head_fixture = tower::ServiceBuilder::new()
            .layer(axum::middleware::from_fn(api_response_policy))
            .service(tower::service_fn(|_| async {
                Ok::<_, std::convert::Infallible>(
                    (
                        StatusCode::BAD_REQUEST,
                        [(header::CONTENT_TYPE, "text/plain")],
                        Body::from("fixture error"),
                    )
                        .into_response(),
                )
            }));
        let head_fixture_response = head_fixture
            .oneshot(
                Request::head("/api/head-fixture")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head_fixture_response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            head_fixture_response.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        assert!(head_fixture_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());

        let head = router(app)
            .oneshot(
                Request::head("/api/receipt-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers()[header::CACHE_CONTROL], "no-store");
        assert!(head
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty());
    }

    #[tokio::test]
    async fn api_normalization_preserves_non_body_headers() {
        let mut response = (
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::CONTENT_TYPE, "text/plain")],
            Body::from("legacy error"),
        )
            .into_response();
        response
            .headers_mut()
            .append(header::ALLOW, HeaderValue::from_static("GET"));
        response
            .headers_mut()
            .append(header::RETRY_AFTER, HeaderValue::from_static("60"));
        response.headers_mut().append(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=api"),
        );
        response
            .headers_mut()
            .append(header::SET_COOKIE, HeaderValue::from_static("a=1"));
        response
            .headers_mut()
            .append(header::SET_COOKIE, HeaderValue::from_static("b=2"));
        response.extensions_mut().insert(7_u32);

        let normalized = crate::api::normalize_response(response).await;
        assert_eq!(normalized.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(normalized.headers()[header::ALLOW], "GET");
        assert_eq!(normalized.headers()[header::RETRY_AFTER], "60");
        assert_eq!(
            normalized.headers()[header::WWW_AUTHENTICATE],
            "Bearer realm=api"
        );
        assert_eq!(
            normalized
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        assert_eq!(
            normalized.headers()[header::CONTENT_TYPE],
            "application/json"
        );
        assert_eq!(normalized.extensions().get::<u32>(), Some(&7));
        let body = normalized.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("request does not match the API"));

        let scim_body = r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"401","detail":"invalid bearer"}"#;
        let scim = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_TYPE, "Application/SCIM+JSON; charset=utf-8")
            .body(Body::from(scim_body))
            .unwrap();
        let scim = crate::api::normalize_response(scim).await;
        assert_eq!(
            scim.headers()[header::CONTENT_TYPE],
            "Application/SCIM+JSON; charset=utf-8"
        );
        assert_eq!(
            scim.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            scim_body.as_bytes()
        );
    }
}

/// Only an exact startup-approved content stamp gets immutable caching.
async fn asset_cache_control(
    State(app): State<Arc<App>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let is_get = request.method() == Method::GET;
    let path = request.uri().path().to_owned();
    let stamp = request.uri().query().and_then(requested_asset_stamp);
    let version = stamp.and_then(|stamp| {
        app.asset_versions
            .get(&path)
            .filter(|version| version.stamp == stamp)
    });
    let mut response = next.run(request).await;
    let current = match version {
        Some(version) => version.is_current().await,
        None => false,
    };
    if response.status() == StatusCode::NOT_FOUND {
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        if is_get {
            *response.body_mut() = axum::body::Body::from("asset not found\n");
        }
    }
    if current && (response.status().is_success() || response.status() == StatusCode::NOT_MODIFIED)
    {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    }
    response
}

fn requested_asset_stamp(query: &str) -> Option<&str> {
    let mut stamp = None;
    for pair in query.split('&') {
        let Some(value) = pair.strip_prefix("v=") else {
            continue;
        };
        if stamp.is_some()
            || value.len() != 16
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return None;
        }
        stamp = Some(value);
    }
    stamp
}

async fn api_response_policy(request: Request<axum::body::Body>, next: Next) -> Response {
    let is_api =
        matches!(request.uri().path(), "/api") || request.uri().path().starts_with("/api/");
    let is_head = request.method() == Method::HEAD;
    let mut response = next.run(request).await;
    if !is_api {
        return response;
    }
    response = api::normalize_response(response).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    if is_head {
        *response.body_mut() = axum::body::Body::empty();
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
        img-src 'self'; worker-src 'self'; \
        frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    // Request pages carry the secret link token in the URL; never let the
    // browser forward it as a referrer.
    const REFERRER_POLICY: &str = "no-referrer";

    let serve_page = |path: std::path::PathBuf| {
        let app = Arc::clone(&app);
        get(move |headers: HeaderMap| {
            let path = path.clone();
            let app = Arc::clone(&app);
            async move {
                match tokio::fs::read_to_string(&path).await {
                    Ok(mut contents) => {
                        let admin_page = contents.contains("<nav id=\"nav\" class=\"nav\"></nav>");
                        let mut footer_tenant = (!admin_page
                            && matches!(
                                path.file_stem().and_then(|name| name.to_str()),
                                Some("index" | "verify")
                            ))
                        .then(String::new);
                        let page_session = admin_page
                            .then(|| api::admin::admin_page_session(&app, &headers))
                            .flatten();
                        if let Some(session) = &page_session {
                            let session = api::admin::admin_session_view(session);
                            footer_tenant = session["tenant"].as_str().map(str::to_owned);
                            let mut nav = String::new();
                            let self_branding = session["tenant"]
                                .as_str()
                                .is_some_and(|tenant| !tenant.is_empty());
                            if self_branding {
                                contents = contents
                                    .replace(
                                        "<title>VOTPort &middot; Tenants</title>",
                                        "<title>VOTPort &middot; Branding</title>",
                                    )
                                    .replace(
                                        "<h1 id=\"page-title\">Tenant namespaces</h1>",
                                        "<h1 id=\"page-title\">Branding</h1>",
                                    );
                            }
                            for (page, default_label) in [
                                ("receive", "Receive"),
                                ("deliver", "Deliver"),
                                ("workflows", "Workflows"),
                                ("trade-routes", "Trade routes"),
                                ("storage", "Storage"),
                                ("automation", "Automation"),
                                ("notifications", "Notifications"),
                                ("tenants", "Tenants"),
                                ("audit", "Audit"),
                                ("system", "System"),
                            ] {
                                if session["pages"]
                                    .as_array()
                                    .is_some_and(|pages| pages.iter().any(|value| value == page))
                                {
                                    let active = if path.file_stem().and_then(|name| name.to_str())
                                        == Some(page)
                                    {
                                        " class=\"active\" aria-current=\"page\""
                                    } else {
                                        ""
                                    };
                                    let (label, hint): (&str, Option<&str>) = if page == "tenants" {
                                        if self_branding {
                                            (
                                                "Branding",
                                                Some("Set how recipients see this tenant."),
                                            )
                                        } else {
                                            (default_label, Some("Manage separate workspaces, each with its own users and files."))
                                        }
                                    } else {
                                        (default_label, None)
                                    };
                                    let hint = hint.map_or(String::new(), |hint| {
                                        format!(" data-hint=\"{hint}\"")
                                    });
                                    nav.push_str(&format!(
                                        "<a href=\"/{page}\"{active}{hint}>{label}</a>"
                                    ));
                                }
                            }
                            contents = contents.replace(
                                "<nav id=\"nav\" class=\"nav\"></nav>",
                                &format!("<nav id=\"nav\" class=\"nav\">{nav}</nav>"),
                            );
                            let bootstrap = session.to_string().replace('<', "\\u003c");
                            contents = contents.replace("</head>", &format!("<script id=\"admin-session\" type=\"application/json\">{bootstrap}</script></head>"));
                        }
                        if let Some(tenant) = footer_tenant {
                            if let Ok(Some(branding)) = app.store.branding(&tenant) {
                                contents = contents.replace(
                                    "<span class=\"footer-custom\"></span>",
                                    &format!(
                                        "<span class=\"footer-custom\">{}</span>",
                                        api::branding_footer(&branding)
                                    ),
                                );
                            }
                        }
                        (
                            [
                                (axum::http::header::CONTENT_SECURITY_POLICY, CSP),
                                (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                                (axum::http::header::REFERRER_POLICY, REFERRER_POLICY),
                                // Admin pages contain the current identity; shared
                                // caches must never retain them.
                                (
                                    axum::http::header::CACHE_CONTROL,
                                    if admin_page {
                                        "private, no-store"
                                    } else {
                                        "no-cache"
                                    },
                                ),
                            ],
                            Html(contents),
                        )
                            .into_response()
                    }
                    Err(_) => (
                        axum::http::StatusCode::NOT_FOUND,
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "text/plain; charset=utf-8",
                        )],
                        "page not found; is VOTPORT_WEB_ROOT set correctly?",
                    )
                        .into_response(),
                }
            }
        })
    };

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
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
                .fallback_service(
                    ServeDir::new(web_root.join("assets")).append_index_html_on_directories(false),
                )
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
                        .layer(axum::middleware::from_fn_with_state(
                            Arc::clone(&app),
                            asset_cache_control,
                        )),
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
            "/api/admin/receiving-storage",
            get(api::admin::get_receiving_storage).post(api::admin::check_receiving_storage),
        )
        .route(
            "/api/admin/settings",
            get(api::get_settings).put(api::put_settings),
        )
        .route(
            "/api/admin/settings/retention-clock/acknowledge",
            post(api::acknowledge_retention_clock),
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
            get(api::list_outbound_grants).merge(post(api::create_outbound_grant).layer(
                DefaultBodyLimit::max(api::outbound::MAX_GRANT_REQUEST_BYTES),
            )),
        )
        .route(
            "/api/admin/outbound-grants/{id}",
            axum::routing::patch(api::update_outbound_grant).delete(api::delete_outbound_grant),
        )
        .route(
            "/api/admin/outbound-grants/{id}/url",
            get(api::outbound::outbound_grant_url),
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
            get(api::get_link)
                .post(api::update_link)
                .patch(api::update_link)
                .delete(api::delete_link),
        )
        .route("/api/admin/links/{id}/qr", get(api::link_qr))
        .route("/api/admin/links/{id}/uploads", get(api::list_link_uploads))
        .route(
            "/api/admin/links/{id}/uploads/{upload}/files",
            get(api::list_upload_files),
        )
        .route(
            "/api/admin/links/{id}/uploads/{upload}/timeline",
            get(api::export_upload_timeline),
        )
        .route(
            "/api/admin/links/{id}/uploads/{upload}",
            get(api::get_link_upload).delete(api::delete_upload_record),
        )
        .route(
            "/api/admin/links/{id}/uploads/{upload}/files/{index}",
            axum::routing::delete(api::delete_received_file),
        )
        .route("/metrics", axum::routing::get(metrics))
        // Multi-page admin: static shells; authz is enforced per API call.
        .route(
            "/api/automation/notifications",
            get(api::outbound::automation::notification_destinations),
        )
        .route(
            "/api/workflows/jobs/{id}/notifications",
            axum::routing::patch(api::outbound::workflows::update_notifications),
        )
        .route("/trade-routes", serve_page(page("trade-routes")))
        .route("/api/port", get(api::trade::discover))
        .route("/api/port/enroll", post(api::trade::enroll))
        .route("/api/port/status", post(api::trade::status))
        .route("/api/port/rotate", post(api::trade::rotate_remote))
        .route(
            "/api/trade-routes",
            get(api::trade::list).post(api::trade::accept),
        )
        .route(
            "/api/trade-routes/port",
            axum::routing::put(api::trade::settings),
        )
        .route("/api/trade-routes/endpoints", post(api::trade::endpoint))
        .route("/api/trade-routes/invitations", post(api::trade::invite))
        .route("/api/trade-routes/inspect", post(api::trade::inspect))
        .route(
            "/api/trade-routes/{id}",
            axum::routing::put(api::trade::update),
        )
        .route("/api/trade-routes/{id}/test", post(api::trade::test))
        .route("/api/trade-routes/{id}/rotate", post(api::trade::rotate))
        .route(
            "/api/trade-routes/{id}/address",
            axum::routing::put(api::trade::change_address),
        )
        .route("/notifications", serve_page(page("notifications")))
        .route(
            "/api/notifications",
            get(api::notifications::list).post(api::notifications::save),
        )
        .route(
            "/api/notifications/defaults",
            axum::routing::put(api::notifications::defaults),
        )
        .route(
            "/api/notifications/{id}",
            axum::routing::delete(api::notifications::delete),
        )
        .route(
            "/api/notifications/{id}/test",
            post(api::notifications::test),
        )
        .route("/receive", serve_page(page("receive")))
        .route("/deliver", serve_page(page("deliver")))
        .route("/workflows", serve_page(page("workflows")))
        .route("/storage", serve_page(page("storage")))
        .route("/automation", serve_page(page("automation")))
        .route("/links", serve_page(page("receive")))
        .route("/tenants", serve_page(page("tenants")))
        .route("/audit", serve_page(page("audit")))
        .route("/system", serve_page(page("system")))
        // SSO sign-in (phase 3 of docs/multi-tenancy.md).
        .route("/api/admin/sso", get(api::sso_available))
        .route("/api/admin/sso/start", get(api::sso_start))
        .route("/api/admin/sso/exchange", post(api::sso::sso_exchange))
        .route("/api/admin/callback", get(api::sso_callback))
        // Public upload API.
        // SCIM 2.0 provisioning, bearer-authenticated, no cookie or CSRF header.
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(api::scim::service_provider_config),
        )
        .route("/scim/v2/ResourceTypes", get(api::scim::resource_types))
        .route("/scim/v2/ResourceTypes/{id}", get(api::scim::resource_type))
        .route("/scim/v2/Schemas", get(api::scim::schemas))
        .route("/scim/v2/Schemas/{id}", get(api::scim::schema))
        .route(
            "/scim/v2/Groups",
            get(api::scim::list_groups).post(api::scim::create_group),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(api::scim::get_group)
                .put(api::scim::replace_group)
                .patch(api::scim::patch_group)
                .delete(api::scim::delete_group),
        )
        .route(
            "/scim/v2/Users",
            get(api::scim::list_users).post(api::scim::create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(api::scim::get_user)
                .put(api::scim::replace_user)
                .patch(api::scim::patch_user)
                .delete(api::scim::delete_user),
        )
        .route("/api/replica", get(api::replica::replica_archive))
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
        .route(
            "/api/r/{token}/route",
            post(api::outbound::workflows::routes::receive)
                .layer(DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route(
            "/api/route/{id}/revoke",
            post(api::outbound::workflows::routes::revoke)
                .layer(DefaultBodyLimit::max(2 * 1024 * 1024)),
        )
        .route(
            "/api/admin/links/{id}/uploads/{upload}/route",
            get(api::outbound::workflows::routes::evidence),
        )
        .route("/api/s/{token}", get(api::outbound_metadata))
        .route(
            "/api/s/{token}/evidence-challenge",
            post(api::evidence::challenge),
        )
        .route(
            "/api/workflows/projects",
            get(api::outbound::workflows::projects)
                .put(api::outbound::workflows::put_project)
                .layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route(
            "/api/workflows/jobs",
            get(api::outbound::workflows::list)
                .post(api::outbound::workflows::create)
                .layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route(
            "/api/workflows/jobs/{id}",
            get(api::outbound::workflows::get)
                .post(api::outbound::workflows::change)
                .layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/workflows/jobs/{id}/reprocess",
            post(api::outbound::workflows::reprocess).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/workflows/jobs/{id}/evidence",
            get(api::outbound::workflows::evidence),
        )
        .route(
            "/api/workflows/events",
            get(api::outbound::workflows::events),
        )
        .route(
            "/api/workflows/events/export",
            get(api::outbound::workflows::export_events),
        )
        .route(
            "/api/workflows/storage",
            get(api::outbound::workflows::storage::list)
                .put(api::outbound::workflows::storage::put)
                .layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/api/workflows/storage/{id}/test",
            post(api::outbound::workflows::storage::test_connection)
                .layer(DefaultBodyLimit::max(1024)),
        )
        .route(
            "/api/workflows/webhook",
            get(api::outbound::workflows::webhook)
                .put(api::outbound::workflows::put_webhook)
                .layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/workflows/webhook/attempts",
            get(api::outbound::workflows::webhook_attempts),
        )
        .route(
            "/api/workflows/webhook/replay/{id}",
            post(api::outbound::workflows::replay_webhook),
        )
        .route(
            "/api/s/{token}/recipient-challenge",
            post(api::outbound::workflows::recipient_challenge).layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/s/{token}/recipient-verify",
            post(api::outbound::workflows::recipient_verify).layer(DefaultBodyLimit::max(16384)),
        )
        .route(
            "/api/evidence",
            post(api::evidence::submit).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/api/admin/outbound/{id}/evidence",
            get(api::evidence::list),
        )
        .route("/api/s/{token}/logo", get(api::outbound_logo))
        .route("/api/s/{token}/verify", post(api::verify_outbound_password))
        .route("/api/s/{token}/fetch", post(api::serve::mint_fetch))
        .route("/api/s/{token}/bundle", get(api::outbound::outbound_bundle))
        .route("/api/s/{token}/batch", get(api::outbound::outbound_batch))
        .nest(
            "/api/automation",
            Router::new()
                .route("/share", post(api::automation_share))
                .route("/session", get(api::outbound::automation::session))
                .route("/files", get(api::outbound::automation::files))
                .route("/deliveries", get(api::outbound::automation::deliveries))
                .route(
                    "/deliveries/{id}",
                    get(api::outbound::automation::delivery)
                        .delete(api::outbound::automation::revoke),
                )
                .route("/operations/{id}", get(api::outbound::automation::recover)),
        )
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
        .fallback(|| async {
            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "page not found\n",
            )
        })
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
        .layer(axum::middleware::from_fn(api_response_policy))
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
        "serve_address": app.serve.as_ref().map(|serve| serve.address.clone()),
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

    #[tokio::test]
    async fn push_restart_preserves_quota_and_cleanup_waits_for_the_directory_lock() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_link(crate::store::Link {
                id: "resume".to_owned(),
                tenant: String::new(),
                label: "resume".to_owned(),
                dest: String::new(),
                password_hash: None,
                created_at: 0,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,

                notifications: None,
                uploads: Vec::new(),
                events: Vec::new(),
            })
            .unwrap();
        let key = hex::encode([4; 16]);
        let stage = app
            .receiving_destinations()
            .unwrap()
            .push_directory(&key)
            .unwrap();
        std::fs::create_dir_all(stage.join("objects")).unwrap();
        let object_path = stage.join("objects/retained.stage");
        std::fs::write(&object_path, b"staged bytes").unwrap();
        let persisted = crate::store::PersistedUploadSession {
            committed_upload_id: None,
            id: hex::encode([5; 16]),
            push_key: Some(key.clone()),
            link_id: "resume".to_owned(),
            tenant: String::new(),
            dest_dir: app.config.receive_dir.clone(),
            dest_rel: String::new(),
            package: vot_sdk::object::ObjectId {
                suite: 1,
                root: [7; 32],
                length: 12,
            },
            max_total_bytes: Some(12),
            started_at: crate::store::now_unix(),
            files: Vec::new(),
        };
        app.store.insert_upload_session(&persisted).unwrap();
        let kept = resume_upload_sessions(
            &app.config,
            &app.store,
            &app.signer,
            &app.sessions,
            &app.session_ended,
            app.receiving.lock().unwrap().as_mut().unwrap(),
        )
        .unwrap();
        assert!(app.sessions.contains_push_key(&key));
        let (sender, _) = tokio::sync::mpsc::channel(1);
        assert_eq!(
            app.sessions.insert_admitted(
                session::SessionAdmission {
                    id: "extra".to_owned(),
                    link_id: "resume".to_owned(),
                    tenant: String::new(),
                    reserved_bytes: 1,
                    max_total_bytes: Some(12),
                    max_tenant_sessions: None,
                    max_link_sessions: usize::MAX,
                    max_sessions: usize::MAX,
                    kind: session::SessionKind::Http,
                },
                sender,
                || Ok((0, Vec::new()))
            ),
            Err(session::InsertError::ByteQuota)
        );
        crate::paths::clean_staging(&app.config.receive_dir, &kept);
        assert_eq!(std::fs::read(&object_path).unwrap(), b"staged bytes");
        sweep_push_staging(&app);
        assert!(object_path.exists());
        let lock =
            session::lock_push_directory(&stage, vot_sdk_file::NasContract::Unqualified).unwrap();
        app.sessions.sweep(0);
        assert!(!app.sessions.contains_push_key(&key));
        sweep_push_staging(&app);
        assert!(object_path.exists());
        drop(lock);
        sweep_push_staging(&app);
        assert!(!stage.exists());
        assert!(app.store.load_push_sessions().unwrap().is_empty());
        app.store.insert_upload_session(&persisted).unwrap();
        sweep_push_staging(&app);
        assert!(app.store.load_push_sessions().unwrap().is_empty());
    }

    fn push_config(directory: &std::path::Path) -> Config {
        let mut config = crate::api::testing::config(directory);
        config.push_bind = Some("127.0.0.1:0".parse().unwrap());
        config.push_advertise = Some("push.example.test:8322".to_owned());
        config
    }

    #[tokio::test]
    async fn push_staging_lock_failures_warn_paced_and_receiving_relative() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        app.store
            .insert_link(crate::store::tests::test_link("resume"))
            .unwrap();
        let key = hex::encode([4; 16]);
        let persisted = crate::store::PersistedUploadSession {
            committed_upload_id: None,
            id: hex::encode([5; 16]),
            push_key: Some(key.clone()),
            link_id: "resume".to_owned(),
            tenant: String::new(),
            dest_dir: app.config.receive_dir.clone(),
            dest_rel: String::new(),
            package: vot_sdk::object::ObjectId {
                suite: 1,
                root: [7; 32],
                length: 12,
            },
            max_total_bytes: Some(12),
            started_at: crate::store::now_unix(),
            files: Vec::new(),
        };
        app.store.insert_upload_session(&persisted).unwrap();
        // The staging directory opens, but without write access the lock file
        // inside it fails with a non-NotFound error the sweep must report.
        use std::os::unix::fs::PermissionsExt as _;
        let staging = app
            .config
            .receive_dir
            .join(".vot-stage")
            .join(format!(".vot-push-{key}"));
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o555)).unwrap();
        // Other tests sweep staging while a live worker holds its lock, which
        // primes the shared static pacer; clear it so this test starts due.
        PUSH_STAGING_LOCK_WARN
            .get_or_init(|| {
                Mutex::new(crate::api::outbound::ErrorDeduper::new("push staging lock"))
            })
            .lock()
            .unwrap()
            .reset();

        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            sweep_push_staging(&app);
            sweep_push_staging(&app);
        });
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755)).unwrap();
        let warns: Vec<String> = std::fs::read_to_string(log.path())
            .unwrap()
            .lines()
            .filter(|line| line.contains("push staging could not be locked"))
            .map(str::to_owned)
            .collect();
        assert_eq!(warns.len(), 1, "the repeat sweep stays silent: {warns:?}");
        assert!(warns[0].contains(".vot-stage/.vot-push-"), "{}", warns[0]);
        assert!(warns[0].contains(&key[..8]), "{}", warns[0]);
        assert!(
            !warns[0].contains(
                directory
                    .path()
                    .to_string_lossy()
                    .get(..16)
                    .unwrap_or(&directory.path().to_string_lossy())
            ),
            "absolute path leaked: {}",
            warns[0]
        );
        // The staging was skipped, not treated as missing: the record stays.
        assert_eq!(app.store.load_push_sessions().unwrap().len(), 1);
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
        let first_handle = Arc::clone(&first);
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

        release_data_lock(&first_handle);
        drop(first_handle);
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
    fn startup_validation_precedes_filesystem_changes() {
        for invalid in ["idle", "url", "hash"] {
            for push in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let mut config = push_config(directory.path());
                if !push {
                    config.push_bind = None;
                }
                let expected = match invalid {
                    "idle" => {
                        config.session_idle_secs = 0;
                        "VOTPORT_SESSION_IDLE_SECS"
                    }
                    "url" => {
                        config.public_url = Some("https://drop.example.com/base".into());
                        "VOTPORT_PUBLIC_URL"
                    }
                    "hash" => {
                        config.admin_password_hash = "invalid".into();
                        "VOTPORT_ADMIN_PASSWORD_HASH"
                    }
                    _ => unreachable!(),
                };
                let data = config.data_dir.clone();
                assert!(build(config)
                    .err()
                    .expect("invalid configuration was admitted")
                    .contains(expected));
                assert!(
                    !data.exists(),
                    "{invalid}, push={push}: startup created files"
                );
            }
        }
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
            destinations: Arc::new(
                crate::receiving::Destinations::open(
                    directory.path(),
                    vot_sdk_file::NasContract::Unqualified,
                )
                .unwrap()
                .child(&["destination".into()])
                .unwrap(),
            ),
            client_ip: String::new(),
            dest_rel: String::new(),
            expected_package: missing_setup.expected_package.clone(),
            max_total_bytes: 1,
            allow_hidden: false,
            signer: Arc::clone(&application.signer),
            session_id: [79; 16],
            started_at: crate::store::now_unix(),
            quiet_after_secs: 5,
            ended: application.session_ended.clone(),
            checkpoint_warn: session::CheckpointWarnPacer::new(),
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
                || Ok((0, Vec::new())),
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
                || Ok((0, Vec::new())),
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
                || Ok((0, Vec::new())),
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
    let lease = app
        .receiving_destinations()
        .and_then(|root| root.lease_record())
        .ok()
        .flatten();
    let _ = write!(
        body,
        "# TYPE votport_lease_held gauge\nvotport_lease_held {}\n# TYPE votport_lease_age_seconds gauge\nvotport_lease_age_seconds {}\n",
        u8::from(lease.as_ref().is_some_and(|lease| lease.holder == app.lease_holder)
            && !app.lease_lost.load(Ordering::Relaxed)),
        lease.as_ref().map_or(0, |lease| lease.age(now_unix()))
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
    let serving = app
        .serve
        .as_ref()
        .map_or(0, |serve| serve.registry.active_sessions());
    let _ = write!(
        body,
        "# TYPE votport_serve_sessions_active gauge\nvotport_serve_sessions_active {serving}\n# TYPE votport_serve_bytes_total counter\nvotport_serve_bytes_total {}\n# TYPE votport_serve_deliveries_total counter\nvotport_serve_deliveries_total {}\n",
        app.serve_metrics.bytes(),
        app.serve_metrics.deliveries()
    );
    body.push_str("# TYPE votport_serve_refused_total counter\n");
    for reason in crate::api::serve::ServeRefusalReason::ALL {
        let _ = writeln!(
            body,
            "votport_serve_refused_total{{reason=\"{}\"}} {}",
            reason.label(),
            app.serve_metrics.refusals(reason)
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
        "# TYPE votport_delivery_event_chain_failures_total counter\nvotport_delivery_event_chain_failures_total {}\n",
        crate::store::DELIVERY_EVENT_CHAIN_FAILURES
            .load(std::sync::atomic::Ordering::Relaxed)
    );
    let _ = write!(
        body,
        "# TYPE votport_integrity_failures_total counter\nvotport_integrity_failures_total {}\n",
        crate::api::outbound::OUTBOUND_INTEGRITY_FAILURES
            .load(std::sync::atomic::Ordering::Relaxed)
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

async fn expire_link_uploads(
    app: &Arc<App>,
    candidate: crate::store::Link,
    cutoff: u64,
    effective_now: u64,
) -> Option<Result<(), String>> {
    sweep_task(app, "upload retention", move |app| {
        expire_link_uploads_sync(app, candidate, cutoff, effective_now)
    })
    .await
}

fn expire_link_uploads_sync(
    app: &App,
    candidate: crate::store::Link,
    cutoff: u64,
    effective_now: u64,
) -> Result<(), String> {
    app.receiving_destinations()?;
    if candidate.legal_hold {
        return Ok(());
    }
    match app
        .store
        .receive_workflow_pending(&candidate.tenant, &candidate.id)
    {
        Ok(false) => {}
        Ok(true) => return Ok(()),
        Err(error) => {
            tracing::error!(%error, "read incoming workflows; skipping retention");
            return Ok(());
        }
    }
    let Some(_pin) = app.sessions.try_pin_link(&candidate.id) else {
        return Ok(());
    };
    if app.sessions.active_for_link(&candidate.id) > 0 {
        return Ok(());
    }
    let link = match app.store.link(&candidate.tenant, &candidate.id) {
        Ok(Some(link)) if !link.legal_hold => link,
        Ok(_) => return Ok(()),
        Err(error) => {
            tracing::error!(%error, "link re-read failed; skipping retention for link");
            return Ok(());
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
    let active_outbound_files =
        match app
            .store
            .active_outbound_file_keys(&link.tenant, &link.id, effective_now)
        {
            Ok(keys) => keys,
            Err(error) => {
                tracing::error!(%error, "outbound grant read failed; skipping retention for link");
                return Ok(());
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
        return Ok(());
    }
    let candidates: std::collections::HashMap<&str, &crate::store::FileRecord> = link
        .uploads
        .iter()
        .filter(|upload| upload.completed_at > 0 && upload.completed_at < cutoff)
        .flat_map(|upload| &upload.files)
        .filter(|file| !file.deleted && !protected.contains(file.stored_as.as_str()))
        .map(|file| (file.stored_as.as_str(), file))
        .collect();
    let candidates: Vec<_> = candidates.into_values().collect();
    if candidates.is_empty() {
        return Ok(());
    }
    let destinations = app.receiving_destinations()?;
    let removed = (|| -> Result<usize, String> {
        let prepare = |record: &crate::store::FileRecord| {
            let mut components = crate::paths::tenant_prefix(&link.tenant);
            components.extend(record.stored_as.split('/').map(str::to_owned));
            destinations.prepare_received_removal(&components, record, &app.signer)
        };
        // ponytail: verify twice to bound descriptors with one history rewrite.
        // Normalized file records allow one verified deletion per transaction.
        let mut retained: Vec<(String, String)> = Vec::new();
        let eligible: Vec<_> = candidates
            .into_iter()
            .filter(|record| match prepare(record) {
                Ok(_) => true,
                Err(error) => {
                    retained.push((record.stored_as.clone(), error));
                    false
                }
            })
            .collect();
        if let Some((first_path, first_error)) = retained.first() {
            tracing::warn!(
                count = retained.len(),
                path = %first_path,
                error = %first_error,
                "expired file retained before tombstone"
            );
        }
        if eligible.is_empty() {
            return Ok(0);
        }
        let paths: HashSet<_> = eligible
            .iter()
            .map(|file| file.stored_as.as_str())
            .collect();
        if !app.store.tombstone_files(&link.tenant, &link.id, &paths)? {
            return Err("request disappeared before retention; files were retained".into());
        }
        let mut removed = 0;
        let mut retained: Vec<(String, String)> = Vec::new();
        for record in &eligible {
            match prepare(record).and_then(|prepared| prepared.remove(&destinations)) {
                Ok(()) => removed += 1,
                Err(error) => retained.push((record.stored_as.clone(), error)),
            }
        }
        if let Some((first_path, first_error)) = retained.first() {
            tracing::warn!(
                count = retained.len(),
                path = %first_path,
                error = %first_error,
                "expired file retained after tombstone"
            );
        }
        Ok(removed)
    })();
    match removed {
        Ok(0) => {}
        Ok(count) => {
            tracing::info!(target: "audit", event = "uploads_expired", link = %link.id,
                tenant = %link.tenant, files = count, "expired received files deleted");
            app.store.audit(
                &link.tenant,
                "",
                "uploads_expired",
                &link.id,
                &serde_json::json!({"tenant": link.tenant, "files": count}),
            );
        }
        Err(error) => {
            tracing::error!(link = %link.id, %error, "retention failed; files were retained")
        }
    }
    Ok(())
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
        if !connected && !control.park() {
            app.sessions.remove(&session_id);
        }
        if let Some(setup) = setup {
            session::record_unconnected_push(setup, false);
        }
    }
}

static PUSH_STAGING_LOCK_WARN: OnceLock<Mutex<crate::api::outbound::ErrorDeduper>> =
    OnceLock::new();

/// Fixed dedupe key for the staging-lock warn: any non-NotFound locking
/// failure warns once per interval, paced, instead of skipping silently.
const PUSH_STAGING_LOCK_ERROR: &str = "lock failed";

fn sweep_push_staging(app: &App) {
    let Ok(destinations) = app.receiving_destinations() else {
        return;
    };
    let sessions = match app.store.load_push_sessions() {
        Ok(sessions) => sessions,
        Err(error) => {
            tracing::warn!(%error, "load push staging for cleanup");
            return;
        }
    };
    for session in sessions {
        let Some(key) = &session.push_key else {
            continue;
        };
        if app.sessions.contains_push_key(key) || !session.files.is_empty() {
            continue;
        }
        let directory = session
            .dest_dir
            .join(".vot-stage")
            .join(format!(".vot-push-{key}"));
        let _lock = match session::lock_push_directory(&directory, destinations.contract()) {
            Ok(lock) => lock,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !app.sessions.contains_push_key(key) {
                    if let Err(error) = app.store.delete_upload_session(&session.id) {
                        tracing::warn!(%error, "delete missing push staging record");
                    }
                }
                continue;
            }
            Err(_) => {
                // ponytail: static pacer because the sweep owns no state between
                // passes; replace with a per-app pacer if sweeps ever share one.
                let due = PUSH_STAGING_LOCK_WARN
                    .get_or_init(|| {
                        Mutex::new(crate::api::outbound::ErrorDeduper::new("push staging lock"))
                    })
                    .lock()
                    .expect("push staging warn pacer poisoned")
                    .observe(PUSH_STAGING_LOCK_ERROR, std::time::Instant::now());
                if due {
                    tracing::warn!(
                        path = %session::push_staging_log_name(&directory),
                        "push staging could not be locked; it stays for the next sweep"
                    );
                }
                continue;
            }
        };
        if app.sessions.contains_push_key(key) {
            continue;
        }
        if let Err(error) = destinations
            .remove_push_directory(&directory, &_lock)
            .map_err(std::io::Error::other)
            .and_then(|_| {
                app.store
                    .delete_upload_session(&session.id)
                    .map_err(std::io::Error::other)
            })
        {
            tracing::warn!(%error, "remove expired push staging");
        }
    }
}

pub async fn session_sweeper(app: Arc<App>) {
    session_sweeper_with_delays(
        app,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(86_400),
    )
    .await;
}

async fn session_sweeper_with_delays(
    app: Arc<App>,
    short_delay: std::time::Duration,
    daily_delay: std::time::Duration,
) {
    // ponytail: restart resets the daily delay; use calendar scheduling for short-lived deployments.
    tokio::join!(
        async {
            loop {
                tokio::time::sleep(short_delay).await;
                sweep_short(&app).await;
            }
        },
        async {
            loop {
                tokio::time::sleep(daily_delay).await;
                sweep_daily(&app).await;
            }
        },
    );
}

async fn sweep_task<T: Send + 'static>(
    app: &Arc<App>,
    duty: &'static str,
    work: impl FnOnce(&App) -> T + Send + 'static,
) -> Option<T> {
    let app = Arc::clone(app);
    tokio::task::spawn_blocking(move || work(&app))
        .await
        .map_err(|error| tracing::error!(duty, %error, "cleanup duty failed"))
        .ok()
}

const RETENTION_LINK_PAGE_SIZE: usize = 128;

async fn sweep_short(app: &Arc<App>) {
    sweep_task(app, "idle sessions", |app| {
        app.sessions.sweep(app.config.session_idle_secs)
    })
    .await;
    sweep_task(app, "push tickets", sweep_push_tickets).await;
    sweep_task(app, "serve cache", crate::api::serve::prune).await;
    sweep_task(app, "push staging", sweep_push_staging).await;
    sweep_task(app, "library staging", |app| {
        crate::api::outbound::sweep_upload_stages(app, std::time::SystemTime::now());
    })
    .await;
}

async fn sweep_daily(app: &Arc<App>) {
    let retention =
        match sweep_task(app, "retention clock", |app| app.retention_observation()).await {
            Some(Ok(retention)) => retention,
            Some(Err(error)) => {
                tracing::error!(%error, "retention clock read failed; skipping this sweep");
                return;
            }
            None => return,
        };
    sweep_daily_at(app, retention).await;
}

async fn sweep_daily_at(app: &Arc<App>, retention: RetentionObservation) {
    if !retention.allow_age {
        tracing::warn!(
            "automatic retention remains held until a platform operator acknowledges the current clock"
        );
        return;
    }
    let now = retention.effective_at;
    // Destructive cleanup requires current settings; a failed read skips this pass.
    let settings = match sweep_task(app, "retention settings", |app| {
        app.store.resolved_settings(&app.config)
    })
    .await
    {
        Some(Ok(settings)) => settings,
        Some(Err(error)) => {
            tracing::error!(%error, "settings read failed; skipping this sweep");
            return;
        }
        None => return,
    };
    sweep_task(app, "outbound proofs", move |app| {
        clean_outbound_proofs(&app.config.data_dir, &app.store, now);
    })
    .await;
    if settings.audit_retention_days > 0 {
        let cutoff = now.saturating_sub(settings.audit_retention_days.saturating_mul(86_400));
        sweep_task(app, "audit rows", move |app| {
            match app.store.audit_prune(cutoff) {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!(count, "pruned expired audit rows");
                    }
                    // Written after the delete with the current clock, so the
                    // row survives its own cycle and then ages out under the
                    // same retention: at most one row per day per instance.
                    app.store.audit(
                        "",
                        "",
                        "audit_pruned",
                        "",
                        &serde_json::json!({
                            "pruned": count,
                            "retention_days": settings.audit_retention_days,
                            "cutoff": cutoff
                        }),
                    );
                }
                Err(error) => tracing::warn!("audit prune failed: {error}"),
            }
        })
        .await;
    }
    sweep_task(app, "database snapshots", move |app| {
        let backup_dir = app.config.data_dir.join("backups");
        prune_legacy_snapshots_at(&backup_dir, now);
    })
    .await;

    if settings.upload_retention_days > 0 {
        let cutoff = now.saturating_sub(settings.upload_retention_days.saturating_mul(86_400));
        let mut after = None;
        loop {
            let page_after = after.clone();
            let link_ids = match sweep_task(app, "retention link ids", move |app| {
                app.store
                    .retention_link_ids(page_after.as_deref(), RETENTION_LINK_PAGE_SIZE)
            })
            .await
            {
                Some(Ok(link_ids)) => link_ids,
                Some(Err(error)) => {
                    tracing::error!(%error, "link read failed; skipping the retention sweep");
                    return;
                }
                None => return,
            };
            let page_len = link_ids.len();
            for (tenant, id) in link_ids {
                after = Some(id.clone());
                // ponytail: one link's complete history remains the memory ceiling;
                // page link_uploads/files if a single link grows beyond memory.
                let link = match sweep_task(app, "retention link", move |app| {
                    app.store.link(&tenant, &id)
                })
                .await
                {
                    Some(Ok(Some(link))) => link,
                    Some(Ok(None)) => continue,
                    Some(Err(error)) => {
                        tracing::error!(%error, "link read failed; skipping retention for link");
                        continue;
                    }
                    None => return,
                };
                match expire_link_uploads(app, link, cutoff, now).await {
                    Some(Ok(())) => {}
                    Some(Err(error)) => {
                        tracing::error!(%error, "retention stopped; receiving storage unavailable");
                        return;
                    }
                    None => return,
                }
            }
            if page_len < RETENTION_LINK_PAGE_SIZE {
                break;
            }
        }
    }
}

/// One pass per daily sweep over a bounded directory: every failure warns
/// with the snapshot's name instead of vanishing. A missing backup directory
/// is the normal no-snapshots state and stays silent.
fn prune_legacy_snapshots(backup_dir: &std::path::Path, cutoff: std::time::SystemTime) {
    let entries = match std::fs::read_dir(backup_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(%error, path = %backup_dir.display(), "legacy snapshot scan failed");
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, "legacy snapshot entry could not be inspected");
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !crate::backup::owned_legacy_snapshot(name) {
            continue;
        }
        let expired = match entry.metadata().and_then(|meta| meta.modified()) {
            Ok(modified) => modified < cutoff,
            Err(error) => {
                tracing::warn!(%error, snapshot = %name, "legacy snapshot expiry unknown; keeping");
                false
            }
        };
        if expired {
            if let Err(error) = std::fs::remove_file(entry.path()) {
                tracing::warn!(%error, snapshot = %name, "legacy snapshot removal failed");
            }
        }
    }
}

fn prune_legacy_snapshots_at(backup_dir: &std::path::Path, now: u64) {
    let cutoff =
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(now.saturating_sub(30 * 86_400));
    prune_legacy_snapshots(backup_dir, cutoff);
}

#[cfg(test)]
mod retention_tests {
    use super::*;
    use crate::store::{FileRecord, Link, OutboundGrant, SettingWrite, UploadRecord};

    #[test]
    fn retention_clock_seeds_new_database_and_holds_existing_until_ack() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(store.retention_clock_anchor().unwrap().is_some());
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM meta WHERE key = ?1",
                    [crate::store::RETENTION_CLOCK_KEY],
                )
            })
            .unwrap();

        let clock = RetentionClock::open(&store).unwrap();
        let base = 1_800_000_000;
        let future = base + 31 * 86_400;
        assert_eq!(
            clock
                .observe_with_elapsed(&store, future, Duration::ZERO)
                .unwrap(),
            RetentionObservation {
                effective_at: future,
                allow_age: false,
            }
        );

        clock
            .acknowledge(&store, "platform-operator", base)
            .unwrap();
        assert_eq!(
            clock.status_with_elapsed(base + 2, Duration::ZERO)["capped"],
            false,
            "one-second boundary drift does not show a spurious acknowledgement prompt"
        );
        assert_eq!(
            clock.status_with_elapsed(base + 3, Duration::ZERO)["capped"],
            true
        );
        let held_uptime = clock
            .observe_with_elapsed(&store, future, Duration::ZERO)
            .unwrap();
        assert_eq!(held_uptime.effective_at, base);
        assert!(held_uptime.allow_age);
        assert_eq!(
            clock
                .observe_with_elapsed(&store, future, Duration::from_secs(86_400))
                .unwrap()
                .effective_at,
            base + 86_400
        );
        assert_eq!(
            clock
                .observe_with_elapsed(&store, future, Duration::from_secs(86_400))
                .unwrap()
                .effective_at,
            base + 86_400,
            "repeated calls cannot manufacture additional retention age"
        );
        let persisted = store.retention_clock_anchor().unwrap().unwrap();
        assert_eq!(persisted, base + 86_400);

        let reopened = RetentionClock::open(&store).unwrap();
        assert_eq!(
            reopened
                .observe_with_elapsed(&store, future, Duration::ZERO)
                .unwrap()
                .effective_at,
            persisted,
            "a restart starts from persisted effective time"
        );
        assert_eq!(
            reopened
                .observe_with_elapsed(&store, base - 1, Duration::ZERO)
                .unwrap()
                .effective_at,
            base - 1,
            "backward wall time lowers only the current cutoff"
        );
        assert_eq!(store.retention_clock_anchor().unwrap(), Some(persisted));
        reopened
            .acknowledge(&store, "platform-operator", base - 1)
            .unwrap();
        assert_eq!(
            store.retention_clock_anchor().unwrap(),
            Some(persisted),
            "an acknowledgement cannot move trusted time backwards"
        );
        let audit = store.audit_export(None, 0, 0, 10).unwrap();
        assert!(audit
            .iter()
            .any(|row| row.event == "retention_clock_acknowledged"));
    }

    #[test]
    fn retention_observe_and_ack_interleaving_keeps_anchor_atomic() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(directory.path()).unwrap());
        let clock = Arc::new(RetentionClock::open(&store).unwrap());
        let base = store.retention_clock_anchor().unwrap().unwrap();
        let raw = base + 200 * 86_400;
        let acknowledged = base + 100 * 86_400;
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (observe_done_tx, observe_done_rx) = std::sync::mpsc::channel();
        *clock
            .observe_hook
            .lock()
            .expect("retention observe hook poisoned") = Some(RetentionObserveHook {
            reached: reached_tx,
            release: release_rx,
        });

        let observing_clock = Arc::clone(&clock);
        let observing_store = Arc::clone(&store);
        let observer = std::thread::spawn(move || {
            let result = observing_clock.observe_with_elapsed(
                &observing_store,
                raw,
                Duration::from_secs(31 * 86_400),
            );
            observe_done_tx.send(result).unwrap();
        });
        reached_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("observe must reach the forced interleaving");

        let (ack_started_tx, ack_started_rx) = std::sync::mpsc::channel();
        let (ack_done_tx, ack_done_rx) = std::sync::mpsc::channel();
        let acknowledging_clock = Arc::clone(&clock);
        let acknowledging_store = Arc::clone(&store);
        let acknowledger = std::thread::spawn(move || {
            ack_started_tx.send(()).unwrap();
            let result = acknowledging_clock.acknowledge(
                &acknowledging_store,
                "platform-operator",
                acknowledged,
            );
            ack_done_tx.send(result).unwrap();
        });
        ack_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("acknowledgement thread must start");
        let ack_waited = ack_done_rx.recv_timeout(Duration::from_millis(50)).is_err();
        release_tx.send(()).unwrap();
        assert!(
            ack_waited,
            "acknowledgement must wait for the observation clock guard"
        );

        let observation = observe_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("observe must finish after the forced interleaving")
            .unwrap();
        observer.join().unwrap();
        assert_eq!(observation.effective_at, base + 31 * 86_400);
        assert!(ack_done_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .is_ok());
        acknowledger.join().unwrap();
        assert_eq!(store.retention_clock_anchor().unwrap(), Some(acknowledged));
        assert_eq!(
            clock
                .observe_with_elapsed(&store, raw, Duration::ZERO)
                .unwrap()
                .effective_at,
            acknowledged,
            "old uptime cannot be applied to the new acknowledgement anchor"
        );
    }

    #[tokio::test]
    async fn injected_future_runs_real_age_cleanup_and_grant_protection() {
        let directory = tempfile::tempdir().unwrap();
        let config = crate::api::testing::config(directory.path());
        let store = Store::open(&config.data_dir).unwrap();
        store
            .with(|connection| {
                connection.execute(
                    "DELETE FROM meta WHERE key = ?1",
                    [crate::store::RETENTION_CLOCK_KEY],
                )
            })
            .unwrap();
        drop(store);
        let app = crate::app::build(config).unwrap();
        let base = crate::store::now_unix();
        let future = base + 31 * 86_400;
        app.store
            .put_settings(
                "test",
                &[
                    (
                        "audit_retention_days".to_owned(),
                        SettingWrite::Set("7".to_owned()),
                    ),
                    (
                        "upload_retention_days".to_owned(),
                        SettingWrite::Set("1".to_owned()),
                    ),
                ],
            )
            .unwrap();
        std::fs::create_dir_all(&app.config.receive_dir).unwrap();
        let make_link = |id: &str, upload_id: &str, name: &str, completed_at: u64| {
            let path = app.config.receive_dir.join(name);
            let file = crate::receiving::tests::published_file(
                &path,
                name.as_bytes(),
                vot_verifier::Suite::Blake3Bao64,
                &app.signer,
            );
            Link {
                id: id.to_owned(),
                tenant: String::new(),
                label: id.to_owned(),
                dest: String::new(),
                password_hash: None,
                created_at: base,
                expires_at: None,
                max_bytes: None,
                active: true,
                legal_hold: false,
                notifications: None,
                uploads: vec![UploadRecord {
                    partial: false,
                    log: Vec::new(),
                    id: upload_id.to_owned(),
                    started_at: base,
                    completed_at,
                    replayed_chunks: 0,
                    rejected_chunks: 0,
                    transport: None,
                    package_root: "root".to_owned(),
                    total_bytes: file.bytes,
                    files: vec![file],
                }],
                events: Vec::new(),
            }
        };
        let old = make_link("old", "old-upload", "old.txt", base - 8 * 86_400);
        let expired = make_link(
            "expired-future",
            "expired-upload",
            "expired-future.txt",
            future - 2 * 86_400,
        );
        let protected = make_link(
            "protected-future",
            "protected-upload",
            "protected-future.txt",
            future - 2 * 86_400,
        );
        let expired_object = expired.uploads[0].files[0].clone();
        let protected_object = protected.uploads[0].files[0].clone();
        app.store.insert_link(old).unwrap();
        app.store.insert_link(expired).unwrap();
        app.store.insert_link(protected).unwrap();
        let make_grant =
            |id: &str, link_id: &str, upload_id: &str, object: &FileRecord, expires_at: u64| {
                app.store
                    .insert_outbound_grant(OutboundGrant {
                        id: id.to_owned(),
                        token_hash: format!("{id}-hash"),
                        password_hash: None,
                        tenant: String::new(),
                        link_id: link_id.to_owned(),
                        upload_id: upload_id.to_owned(),
                        package_root: "root".to_owned(),
                        name: object.path.clone(),
                        suite: object.suite.clone(),
                        root: object.root.clone(),
                        file_index: 0,
                        bytes: object.bytes,
                        label: id.to_owned(),
                        created_at: base,
                        expires_at,
                        revoked_at: None,
                        downloads: 0,
                        max_downloads: None,
                        notifications: None,
                        first_download_at: None,
                        last_download_at: None,
                        files: Vec::new(),
                    })
                    .unwrap();
            };
        make_grant(
            "expired-grant",
            "expired-future",
            "expired-upload",
            &expired_object,
            future - 3_600,
        );
        make_grant(
            "future-grant",
            "protected-future",
            "protected-upload",
            &protected_object,
            future + 86_400,
        );

        app.store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO audit_log(at,tenant,actor,event,subject,detail)
                     VALUES (?1,'','test','future_audit','subject','{}')",
                    [i64::try_from(base - 8 * 86_400).unwrap()],
                )
            })
            .unwrap();
        let snapshot = app.config.data_dir.join("backups/votport-1-deadbeef.db");
        std::fs::create_dir_all(snapshot.parent().unwrap()).unwrap();
        std::fs::write(&snapshot, b"snapshot").unwrap();
        std::fs::File::open(&snapshot)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(base - 31 * 86_400)),
            )
            .unwrap();
        let proof_dir = app.config.data_dir.join("outbound.proofs");
        std::fs::create_dir_all(&proof_dir).unwrap();
        let expired_proof = proof_dir.join(format!(
            "1-{}-{}.vot-catalog",
            expired_object.root, expired_object.bytes
        ));
        let protected_proof = proof_dir.join(format!(
            "1-{}-{}.vot-catalog",
            protected_object.root, protected_object.bytes
        ));
        std::fs::write(&expired_proof, b"expired proof").unwrap();
        std::fs::write(&protected_proof, b"protected proof").unwrap();

        let held = app.retention_observation().unwrap();
        assert!(!held.allow_age);
        sweep_daily_at(&app, held).await;
        assert!(app.config.receive_dir.join("old.txt").exists());
        assert!(app.config.receive_dir.join("expired-future.txt").exists());
        assert!(snapshot.exists());
        assert!(expired_proof.exists());
        assert!(protected_proof.exists());

        app.acknowledge_retention_clock_at("platform-operator", base, base)
            .unwrap();
        let zero = app
            .retention_clock
            .observe_with_elapsed(&app.store, future, Duration::ZERO)
            .unwrap();
        assert_eq!(zero.effective_at, base);
        sweep_daily_at(&app, zero).await;
        assert!(!app.config.receive_dir.join("old.txt").exists());
        assert!(app.config.receive_dir.join("expired-future.txt").exists());
        assert!(app.config.receive_dir.join("protected-future.txt").exists());
        assert!(!snapshot.exists());
        assert!(expired_proof.exists());
        assert!(protected_proof.exists());

        let one_day = app
            .retention_clock
            .observe_with_elapsed(&app.store, future, Duration::from_secs(86_400))
            .unwrap();
        assert_eq!(one_day.effective_at, base + 86_400);
        sweep_daily_at(&app, one_day).await;
        assert!(app.config.receive_dir.join("expired-future.txt").exists());
        assert!(app.config.receive_dir.join("protected-future.txt").exists());
        assert!(expired_proof.exists());
        assert!(protected_proof.exists());

        let full_age = app
            .retention_clock
            .observe_with_elapsed(&app.store, future, Duration::from_secs(31 * 86_400))
            .unwrap();
        assert_eq!(full_age.effective_at, future);
        sweep_daily_at(&app, full_age).await;
        assert!(!app.config.receive_dir.join("expired-future.txt").exists());
        assert!(app.config.receive_dir.join("protected-future.txt").exists());
        assert!(!expired_proof.exists());
        assert!(protected_proof.exists());
        assert_eq!(
            app.store
                .audit_export(None, 0, 0, 100)
                .unwrap()
                .iter()
                .filter(|row| row.event == "future_audit")
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn poisoned_cleanup_duties_leave_other_work_and_later_passes_running() {
        use std::time::{Duration, SystemTime};

        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::api::testing::config(directory.path());
        config.push_bind = Some("127.0.0.1:0".parse().unwrap());
        config.push_advertise = Some("push.example.test:8322".into());
        let mut app = build(config).unwrap();
        Arc::get_mut(&mut app).unwrap().config.session_idle_secs = 0;
        let poisoned = Arc::clone(&app);
        assert!(std::thread::spawn(move || {
            let _guard = poisoned.push_tickets.lock().unwrap();
            panic!("poison ticket registry");
        })
        .join()
        .is_err());
        assert!(app.push_tickets.is_poisoned());
        let backups = crate::backup::ensure_backups_dir(&app.config.data_dir).unwrap();
        let snapshot = backups.join("votport-1-deadbeef.db");
        let old =
            std::fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1));
        for round in 0..3 {
            if round == 2 {
                let store = Arc::clone(&app.store);
                assert!(std::thread::spawn(move || {
                    let _ = store.with::<()>(|_| panic!("poison store"));
                })
                .join()
                .is_err());
                std::fs::File::create(&snapshot)
                    .unwrap()
                    .set_times(old)
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(5), sweep_daily(&app))
                    .await
                    .expect("failed settings must not terminate or stall the daily pass");
                assert!(
                    snapshot.exists(),
                    "unreadable settings must prevent destructive cleanup"
                );
            }
            let (sender, _receiver) = tokio::sync::mpsc::channel(1);
            app.sessions
                .insert_admitted(
                    session::SessionAdmission {
                        id: format!("expired-{round}"),
                        link_id: "link".into(),
                        tenant: String::new(),
                        reserved_bytes: 0,
                        max_total_bytes: None,
                        max_tenant_sessions: None,
                        max_link_sessions: usize::MAX,
                        max_sessions: usize::MAX,
                        kind: session::SessionKind::Http,
                    },
                    sender,
                    || Ok((0, Vec::new())),
                )
                .unwrap();
            let stage = app
                .config
                .outbound_dir
                .join(format!(".vot-outbound-00-{}.stage", "a".repeat(64)));
            std::fs::File::create(&stage)
                .unwrap()
                .set_times(old)
                .unwrap();
            assert_eq!(app.sessions.total(), 1);
            tokio::time::timeout(Duration::from_secs(5), sweep_short(&app))
                .await
                .expect("one poisoned duty must not stall unrelated cleanup");
            assert_eq!(app.sessions.total(), 0);
            assert!(
                !stage.exists(),
                "library cleanup must run after the failed duty"
            );
            assert!(
                app.push_tickets.is_poisoned(),
                "cleanup must not clear unsafe poisoned state"
            );
        }
    }

    #[tokio::test]
    async fn daily_cleanup_waits_and_does_not_block_idle_session_cleanup() {
        use std::time::{Duration, SystemTime};

        let directory = tempfile::tempdir().unwrap();
        let mut app = build(crate::api::testing::config(directory.path())).unwrap();
        Arc::get_mut(&mut app).unwrap().config.session_idle_secs = 0;
        let backups = crate::backup::ensure_backups_dir(&app.config.data_dir).unwrap();
        let snapshot = backups.join("votport-1-deadbeef.db");
        let add_expired = || {
            let (sender, _receiver) = tokio::sync::mpsc::channel(1);
            app.sessions
                .insert_admitted(
                    session::SessionAdmission {
                        id: "expired".into(),
                        link_id: "link".into(),
                        tenant: String::new(),
                        reserved_bytes: 0,
                        max_total_bytes: None,
                        max_tenant_sessions: None,
                        max_link_sessions: usize::MAX,
                        max_sessions: usize::MAX,
                        kind: session::SessionKind::Http,
                    },
                    sender,
                    || Ok((0, Vec::new())),
                )
                .unwrap();
            std::fs::File::create(&snapshot)
                .unwrap()
                .set_times(
                    std::fs::FileTimes::new()
                        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
                )
                .unwrap();
        };
        add_expired();
        let worker = tokio::spawn(session_sweeper_with_delays(
            Arc::clone(&app),
            Duration::from_millis(5),
            Duration::from_secs(60),
        ));
        let short_ran = tokio::time::timeout(Duration::from_secs(5), async {
            while app.sessions.total() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        worker.abort();
        let _ = worker.await;
        short_ran.expect("short cleanup must run before the first daily deadline");
        assert!(
            snapshot.exists(),
            "daily cleanup must not run immediately at startup"
        );

        add_expired();
        let (locked, ready) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let store = Arc::clone(&app.store);
        let blocker = tokio::task::spawn_blocking(move || {
            store.with(|_| {
                locked.send(()).unwrap();
                released
                    .recv_timeout(Duration::from_secs(10))
                    .expect("test must release retention settings lock");
                Ok(())
            })
        });
        tokio::time::timeout(Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        let worker = tokio::spawn(session_sweeper_with_delays(
            Arc::clone(&app),
            Duration::from_millis(50),
            Duration::from_millis(1),
        ));
        let short_ran = tokio::time::timeout(Duration::from_secs(2), async {
            while app.sessions.total() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        let retained_while_blocked = snapshot.exists();
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), blocker)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let daily_ran = tokio::time::timeout(Duration::from_secs(5), async {
            while snapshot.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        worker.abort();
        let _ = worker.await;
        short_ran.expect("blocked daily cleanup must not stop idle-session expiry");
        assert!(retained_while_blocked);
        daily_ran.expect("daily cleanup must finish after its blocker clears");
    }

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

            notifications: None,
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
        expired.uploads[0].files[0] = crate::receiving::tests::published_file(
            &expired_path,
            b"expired",
            vot_verifier::Suite::Blake3Bao64,
            &app.signer,
        );
        failed.uploads[0].files[0] = crate::receiving::tests::published_file(
            &failed_path,
            b"failed",
            vot_verifier::Suite::Blake3Bao64,
            &app.signer,
        );
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

                notifications: None,
                first_download_at: None,
                last_download_at: None,
                files: Vec::new(),
            })
            .unwrap();

        // The candidate came from the first read before an administrator set
        // the hold. The re-read under the lifecycle pin must still preserve it.
        // An unavailable or replaced receive root must not tombstone live records.
        let receiving = app
            .receiving
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .destinations
            .clone();
        for missing in [false, true] {
            let displaced = directory.path().join("displaced");
            std::fs::rename(&app.config.receive_dir, &displaced).unwrap();
            if !missing {
                std::fs::create_dir(&app.config.receive_dir).unwrap();
                std::fs::write(&expired_path, b"replacement").unwrap();
            }
            let candidate = app.store.link("", "expired").unwrap().unwrap();
            let result = expire_link_uploads(&app, candidate, cutoff, cutoff).await;
            let Some(Err(error)) = result else {
                panic!("unavailable receiving storage must surface a retention error");
            };
            assert!(!error.is_empty());
            assert!(!app.store.link("", "expired").unwrap().unwrap().uploads[0].files[0].deleted);
            assert_eq!(
                std::fs::read(displaced.join("expired.txt")).unwrap(),
                b"expired"
            );
            if !missing {
                assert_eq!(std::fs::read(&expired_path).unwrap(), b"replacement");
                std::fs::remove_dir_all(&app.config.receive_dir).unwrap();
            }
            std::fs::rename(displaced, &app.config.receive_dir).unwrap();
        }
        let daily_displaced = directory.path().join("daily-displaced");
        std::fs::rename(&app.config.receive_dir, &daily_displaced).unwrap();
        use tracing::instrument::WithSubscriber;
        let daily_log = tempfile::NamedTempFile::new().unwrap();
        let daily_writer = daily_log.reopen().unwrap();
        let daily_subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_ansi(false)
            .with_writer(move || daily_writer.try_clone().unwrap())
            .finish();
        sweep_daily_at(
            &app,
            RetentionObservation {
                effective_at: cutoff,
                allow_age: true,
            },
        )
        .with_subscriber(daily_subscriber)
        .await;
        let daily_log = std::fs::read_to_string(daily_log.path()).unwrap();
        assert_eq!(
            daily_log
                .lines()
                .filter(|line| line.contains("retention stopped; receiving storage unavailable"))
                .count(),
            1,
            "{daily_log}"
        );
        assert!(!app.store.link("", "expired").unwrap().unwrap().uploads[0].files[0].deleted);
        assert!(!app.store.link("", "failed").unwrap().unwrap().uploads[0].files[0].deleted);
        assert_eq!(
            std::fs::read(daily_displaced.join("expired.txt")).unwrap(),
            b"expired"
        );
        std::fs::rename(daily_displaced, &app.config.receive_dir).unwrap();
        receiving.check_current().unwrap();
        let mut stale_held = held;
        stale_held.legal_hold = false;
        assert!(matches!(
            expire_link_uploads(&app, stale_held, cutoff, cutoff).await,
            Some(Ok(()))
        ));

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
        assert!(matches!(
            expire_link_uploads(&app, active_candidate, cutoff, cutoff).await,
            Some(Ok(()))
        ));
        assert!(active_path.exists());

        let shared_candidate = app.store.link("", "shared").unwrap().unwrap();
        assert!(matches!(
            expire_link_uploads(&app, shared_candidate, cutoff, cutoff).await,
            Some(Ok(()))
        ));
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
        assert!(matches!(
            expire_link_uploads(&app, outbound_candidate, cutoff, cutoff).await,
            Some(Ok(()))
        ));
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
        assert!(matches!(
            expire_link_uploads(&app, malformed_candidate, cutoff, cutoff).await,
            Some(Ok(()))
        ));
        assert!(outbound_path.exists());
        assert!(!app.store.link("", "outbound").unwrap().unwrap().uploads[0].files[0].deleted);

        connection
            .execute_batch(
                "CREATE TRIGGER fail_link_update BEFORE UPDATE ON files
                 BEGIN SELECT RAISE(FAIL, 'test update failure'); END;",
            )
            .unwrap();
        let failed_candidate = app.store.link("", "failed").unwrap().unwrap();
        assert!(matches!(
            expire_link_uploads(&app, failed_candidate, cutoff, cutoff).await,
            Some(Ok(()))
        ));
        connection
            .execute_batch("DROP TRIGGER fail_link_update")
            .unwrap();
        assert!(failed_path.exists());
        assert!(!app.store.link("", "failed").unwrap().unwrap().uploads[0].files[0].deleted);
        assert!(app
            .store
            .audit_export(None, 0, 0, 100)
            .unwrap()
            .iter()
            .all(|row| row.subject != "failed"));

        let sweep_app = Arc::clone(&app);
        let sweeper = tokio::spawn(async move { sweep_daily(&sweep_app).await });
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
        let mut released = false;
        for _ in 0..100 {
            if app.sessions.pin_link_for_delete("expired") {
                released = true;
                app.sessions.unpin_link("expired");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            released,
            "the blocking deletion must finish and release its pin after sweeper cancellation"
        );
    }
    #[tokio::test]
    async fn audit_pruning_records_a_summary_row_that_outlives_its_own_cycle() {
        let directory = tempfile::tempdir().unwrap();
        let app = crate::api::testing::build(directory.path());
        let base = now_unix();
        app.store
            .put_settings(
                "platform-operator",
                &[(
                    "audit_retention_days".to_owned(),
                    SettingWrite::Set("1".to_owned()),
                )],
            )
            .unwrap();
        // Seed one expired row so the cycle provably prunes something.
        app.store
            .with(|connection| {
                connection.execute(
                    "INSERT INTO audit_log (at, tenant, actor, event, subject, detail)
                     VALUES (?1, '', '', 'expired_audit', '', '{}')",
                    [(base.saturating_sub(2 * 86_400) as i64)],
                )
            })
            .unwrap();
        app.acknowledge_retention_clock_at("platform-operator", base, base)
            .unwrap();
        let observation = app
            .retention_clock
            .observe_with_elapsed(&app.store, base, Duration::ZERO)
            .unwrap();
        assert!(observation.allow_age);

        sweep_daily_at(&app, observation).await;

        let rows = app.store.audit_export(Some(""), 0, 0, 100).unwrap();
        assert!(rows.iter().all(|row| row.event != "expired_audit"));
        let row = rows
            .iter()
            .find(|row| row.event == "audit_pruned")
            .expect("pruning records a summary row");
        assert_eq!(row.detail["pruned"], serde_json::json!(1));
        assert_eq!(row.detail["retention_days"], serde_json::json!(1));
        assert!(row.detail["cutoff"].is_number());
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

#[cfg(test)]
mod audit_observability_tests {
    use super::*;

    #[test]
    fn refused_pushes_leave_an_audit_row_with_reason_and_peer() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        refuse_push(
            &application,
            PushRefusalReason::Spent,
            "10.1.2.3:4".parse().unwrap(),
        );
        let rows = application.store.audit_export(None, 0, 0, 100).unwrap();
        let row = rows
            .iter()
            .find(|row| row.event == "push_refused")
            .expect("the refused push leaves an audit row");
        assert_eq!(row.detail["reason"], "spent");
        assert_eq!(row.detail["peer"], "10.1.2.3:4");
    }

    #[tokio::test]
    async fn completed_uploads_are_recorded_under_the_upload_id() {
        let directory = tempfile::tempdir().unwrap();
        let application = crate::api::testing::build(directory.path());
        application
            .store
            .insert_tenant(crate::store::tests::test_tenant("acme"))
            .unwrap();
        application
            .store
            .insert_link(crate::store::tests::link_in("acme", "link-1"))
            .unwrap();
        let report = crate::session::FinishReport {
            upload_id: "upload-9".to_owned(),
            files: vec![crate::store::FileRecord {
                path: "a.bin".to_owned(),
                stored_as: "a.bin".to_owned(),
                bytes: 5000,
                suite: "blake3".to_owned(),
                root: "00".to_owned(),
                receipt: false,
                deleted: false,
            }],
            received: 5000,
        };
        upload_completed(
            &application,
            "07070707070707070707070707070707",
            Some("link-1".to_owned()),
            "10.0.0.9",
            &report,
            &tokio::runtime::Handle::current(),
        );
        let rows = application
            .store
            .audit_export(Some("acme"), 0, 0, 100)
            .unwrap();
        let row = rows
            .iter()
            .find(|row| row.event == "upload_completed")
            .expect("the completed upload leaves an audit row");
        assert_eq!(row.subject, "upload-9");
        assert_eq!(row.detail["files"], 1);
        assert_eq!(row.detail["bytes"], 5000);
        assert_eq!(row.detail["client_ip"], "10.0.0.9");

        // With the link gone the row still lands, on the default tenant.
        upload_completed(
            &application,
            "07070707070707070707070707070707",
            None,
            "10.0.0.9",
            &report,
            &tokio::runtime::Handle::current(),
        );
        let rows = application.store.audit_export(Some(""), 0, 0, 100).unwrap();
        let row = rows
            .iter()
            .find(|row| row.event == "upload_completed")
            .expect("the completed upload is recorded even without its link");
        assert_eq!(row.subject, "upload-9");
    }
}
