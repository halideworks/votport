//! Application state and router assembly.

mod router;
pub use router::router;

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
use axum::routing::{delete, get, post};
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
    /// Cancellation token per grant with a live download stream; a revocation
    /// cancels it so admitted streams stop at their next frame.
    pub outbound_stream_cancels: Mutex<HashMap<String, tokio_util::sync::CancellationToken>>,
    /// File download leases whose retrieval has been counted, with the
    /// lease expiry. Process-local: after a restart a spent file's lease no
    /// longer passes, the documented limit of resuming across a failover.
    pub counted_leases: Mutex<HashMap<String, u64>>,
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
    /// How often the process lost the receive-root lease. The process exits
    /// on the same heartbeat, so the final log line and the `lease_lost`
    /// audit row carry the value; a scrape rarely observes it live.
    pub lease_lost_total: AtomicU64,
    /// Set with the `mount_disqualified` audit row when the storage was
    /// remounted instead of taken over; /readyz reports it alongside lease.
    pub mount_disqualified: AtomicBool,
    /// Paces the non-NotFound staging-lock warn in `sweep_push_staging`.
    /// Per-instance instead of a process-global static so a rebuilt App
    /// (tests) starts unpaced.
    push_staging_warn: Mutex<crate::api::outbound::ErrorDeduper>,
    /// Reusable verified roots for unchanged outbound library files, backed
    /// by a bounded sidecar under data_dir (outbound.proofs precedent).
    pub(crate) root_cache: crate::api::outbound::RootCache,
    /// In-flight async grant preparations (deliver-page progress handles).
    pub(crate) grant_preparations: Mutex<crate::api::outbound::GrantPreparationRegistry>,
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
    // The duration is the session's own monotonic time in this process, not
    // a wall-clock difference: a resumed session does not charge the server's
    // downtime, and a backwards clock step cannot report an infinite rate.
    let seconds = app
        .sessions
        .remove(session_id)
        .map_or(0, |handle| handle.active_seconds());
    TRANSFERS.published(
        report.files.iter().map(|file| file.bytes).sum::<u64>(),
        seconds,
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
    cooldown: std::time::Duration,
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
            cooldown: SSO_COOLDOWN,
        }
    }

    /// Shortened cooldown for integration tests that exercise re-discovery
    /// without waiting out the production 30 seconds.
    #[cfg(test)]
    pub(crate) fn with_cooldown(cooldown: std::time::Duration) -> Self {
        Self {
            inner: Mutex::new(SsoSlotState::Empty),
            cooldown,
        }
    }

    /// Non-blocking. Healthy only for Ready. Busy lock is not healthy.
    pub fn health_peek(&self) -> bool {
        self.inner
            .try_lock()
            .map(|guard| matches!(*guard, SsoSlotState::Ready(_)))
            .unwrap_or(false)
    }

    /// Drops a Ready client after an id-token verification failure: the usual
    /// cause is the IdP rolling its signing key, which leaves discovery's
    /// cached JWKS unable to verify any new token. The slot re-enters the
    /// same Failed state a failed discovery uses, so the next sign-in after
    /// the cooldown re-discovers. Only a Ready slot flips and an already
    /// Failed slot keeps its timestamp, so the flip is bounded to once per
    /// cooldown and bad tokens cannot force discovery storms.
    pub fn invalidate_ready(&self) {
        let mut guard = self.inner.lock().expect("sso slot poisoned");
        if let SsoSlotState::Ready(_) = &*guard {
            *guard = SsoSlotState::Failed {
                at: std::time::Instant::now(),
            };
        }
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
                SsoSlotState::Failed { at } if at.elapsed() < self.cooldown => return Err(()),
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
    let applied_restore =
        crate::backup::apply_pending_restore(&config.data_dir, crate::store::SCHEMA_VERSION)?;
    let store = Arc::new(Store::open(&config.data_dir)?);
    if let Some(applied) = applied_restore {
        crate::backup::record_applied_restore(&store, &applied);
        // Finding 498: with the rolled-back database installed, records and
        // the receive tree can disagree; stat both before session recovery
        // starts publishing again.
        crate::backup::survey_restored_payloads(&store, &config.receive_dir);
    }
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
        outbound_stream_cancels: Mutex::new(HashMap::new()),
        counted_leases: Mutex::new(HashMap::new()),
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
        lease_lost_total: AtomicU64::new(0),
        mount_disqualified: AtomicBool::new(false),
        push_staging_warn: Mutex::new(crate::api::outbound::ErrorDeduper::new("push staging lock")),
        root_cache: crate::api::outbound::RootCache::new(&config.data_dir),
        grant_preparations: Mutex::default(),
        health: HealthCache::default(),
        config,
    }))
}

impl App {
    /// Audit finding 376: the legal-hold flag lives in a restorable row, so
    /// a restore predating the hold would clear it and the next sweep could
    /// delete held files. This marker lives outside the backup archive, so a
    /// hold stays enforced until an operator releases it explicitly.
    fn legal_holds_dir(&self) -> std::path::PathBuf {
        self.config.data_dir.join("legal-holds")
    }

    fn valid_hold_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 255
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    /// Whether an out-of-database hold marker pins this link. Marker ids come
    /// from the store or the admin route, never from client input.
    pub(crate) fn link_hold_pinned(&self, id: &str) -> bool {
        Self::valid_hold_id(id) && self.legal_holds_dir().join(id).is_file()
    }

    /// Creates or removes the hold marker. Ordered so a failure can only
    /// leave a hold active, never silently dropped.
    pub(crate) fn set_link_hold_pin(&self, id: &str, held: bool) -> std::io::Result<()> {
        if !Self::valid_hold_id(id) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid link id",
            ));
        }
        let marker = self.legal_holds_dir().join(id);
        if !held {
            return match std::fs::remove_file(&marker) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            };
        }
        let dir = self.legal_holds_dir();
        std::fs::create_dir_all(&dir)?;
        crate::paths::tighten_private_dir(&dir)
            .map_err(|error| std::io::Error::other(format!("tighten legal-holds dir: {error}")))?;
        std::fs::File::create_new(&marker)?.sync_all()
    }

    /// Every pinned link id, for exempting their audit rows from pruning.
    pub(crate) fn held_link_ids(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(self.legal_holds_dir()) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| Self::valid_hold_id(name))
            .collect()
    }

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
        verification: link.verification.clone(),
        signer: Arc::clone(signer),
        session_id,
        started_at: session.started_at,
        quiet_after_secs: session::quiet_after_secs(config.session_idle_secs),
        ended: ended.clone(),
        checkpoint_warn: session::CheckpointWarnPacer::new(),
    };
    if let Some(key) = &session.push_key {
        if !crate::auth::valid_hex(key, 32) {
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

/// Any failed ownership check stops receiving before another heartbeat can
/// renew. A lease takeover and a remount of disqualified storage both stop
/// receiving here, but each writes its own audit row and final log line.
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
            app.lease_lost.store(true, Ordering::Relaxed);
            if active.destinations.disqualified() {
                tracing::error!(%error, "receiving storage was remounted with disqualifying options");
                app.mount_disqualified.store(true, Ordering::Release);
                app.store.audit(
                    "",
                    "",
                    "mount_disqualified",
                    "",
                    &serde_json::json!({ "holder": app.lease_holder, "error": error }),
                );
            } else {
                tracing::error!(%error, "receiving storage ownership check failed");
                app.lease_lost_total.fetch_add(1, Ordering::Relaxed);
                app.store.audit(
                    "",
                    "",
                    "lease_lost",
                    "",
                    &serde_json::json!({ "holder": app.lease_holder }),
                );
            }
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
            if app.mount_disqualified.load(Ordering::Relaxed) {
                tracing::error!(
                    "exiting: the receiving mount was remounted with disqualifying options"
                );
            } else {
                tracing::error!(
                    lease_lost_total = app.lease_lost_total.load(Ordering::Relaxed),
                    "exiting: the receive-root lease was lost"
                );
            }
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
    if !crate::auth::valid_hex(root, 64) {
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
    canonical_proof_name(catalog) && crate::auth::valid_hex(token, 32)
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
    let mut body = health_status(&app).await;
    body["sessions_active"] = serde_json::json!(app.sessions.total());
    let ready = body["ready"].as_bool().unwrap_or(false);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}

/// The health and readiness state /healthz and /readyz report, as one
/// document for the admin status strip and the readiness endpoint. One
/// source of truth: the dashboard cannot disagree with the probes.
pub(crate) async fn health_status(app: &Arc<App>) -> serde_json::Value {
    let stopping = app.is_stopping();
    let snapshot = if stopping {
        None
    } else {
        health_snapshot(app).await
    };
    let lease_lost = app.lease_lost.load(Ordering::Relaxed);
    let healthy = snapshot.as_ref().is_some_and(|s| s.healthy) && !lease_lost;
    let (ready, draining) = if stopping {
        (false, true)
    } else {
        match snapshot.as_ref() {
            Some(HealthSnapshot {
                healthy: true,
                draining: Some(draining),
                ..
            }) => (!draining && !lease_lost, *draining),
            _ => (false, false),
        }
    };
    let lease = snapshot
        .and_then(|snapshot| snapshot.lease)
        .filter(|_| !lease_lost);
    let now = now_unix();
    serde_json::json!({
        "healthy": healthy,
        "ready": ready,
        "draining": draining,
        "lease": {
            "holder": lease.as_ref().map(|lease| lease.holder.clone()),
            "mine": lease.as_ref().is_some_and(|lease| lease.holder == app.lease_holder),
            "age_secs": lease.as_ref().map(|lease| lease.age(now)),
            "lost": lease_lost,
        },
        "mount": {
            "disqualified": app.mount_disqualified.load(Ordering::Relaxed),
        },
    })
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

/// Everything the pages and their workers load is same-origin (fonts are
/// self-hosted in /assets/fonts). wasm-unsafe-eval is what lets the browser
/// compile the verification engine; there is no JS eval anywhere. The same
/// policy also rides on the /assets nest: a dedicated worker's policy comes
/// from its own response, so hash-worker.js would otherwise run with none
/// (audit finding 517).
const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
    style-src 'self'; font-src 'self'; connect-src 'self'; \
    img-src 'self'; worker-src 'self'; \
    frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

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

/// True when an enabled backup has failed, never completed, or its last
/// success is overdue by more than two intervals: the worker is stuck or
/// stopped. Sourced from the same status file and config the backups API
/// reports, at scrape time.
fn backup_failing(app: &App, now: u64) -> bool {
    let Ok(setting) = app.store.setting(crate::backup::SETTING_KEY) else {
        return false;
    };
    let Ok(config) = crate::backup::decode_config(setting) else {
        return true;
    };
    if !config.enabled {
        return false;
    }
    let status = crate::backup::read_status(&app.config.data_dir).unwrap_or_default();
    status.last_error.is_some()
        || status
            .last_success_at
            .is_none_or(|at| now.saturating_sub(at) >= config.interval_secs.saturating_mul(2))
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
        "# TYPE votport_retention_sweep_failures_total counter\nvotport_retention_sweep_failures_total {}\n",
        RETENTION_SWEEP_FAILURES.load(std::sync::atomic::Ordering::Relaxed)
    );
    // Every gauge below is read from state another code path already
    // detects: the store rows, the backup and standby status files, and the
    // staged restore marker. No new background work at scrape time.
    let _ = write!(
        body,
        "# TYPE votport_backup_failing gauge\nvotport_backup_failing {}\n",
        u8::from(backup_failing(app, now_unix()))
    );
    let standby_lag = crate::standby::read_status(&app.config.data_dir)
        .and_then(|status| status.last_success_at)
        .map_or(0, |at| now_unix().saturating_sub(at));
    let _ = write!(
        body,
        "# TYPE votport_standby_lag_seconds gauge\nvotport_standby_lag_seconds {standby_lag}\n"
    );
    let _ = write!(
        body,
        "# TYPE votport_notification_destinations_failing gauge\nvotport_notification_destinations_failing {}\n",
        app.store.failing_notification_destinations()?
    );
    let _ = write!(
        body,
        "# TYPE votport_webhook_attempts_dead gauge\nvotport_webhook_attempts_dead {}\n",
        app.store.dead_delivery_webhooks()?
    );
    let _ = write!(
        body,
        "# TYPE votport_trade_routes_unreachable gauge\nvotport_trade_routes_unreachable {}\n",
        app.store.unreachable_trade_routes()?
    );
    let _ = write!(
        body,
        "# TYPE votport_migration_pending gauge\nvotport_migration_pending {}\n",
        u8::from(
            crate::backup::pending_restore_stage(&app.config.data_dir)
                .map(|staged| staged.is_some())
                .unwrap_or(false)
        )
    );
    let _ = write!(
        body,
        "# TYPE votport_lease_lost_total counter\nvotport_lease_lost_total {}\n",
        app.lease_lost_total.load(Ordering::Relaxed)
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

async fn expire_link_uploads(
    app: &Arc<App>,
    candidate: crate::store::Link,
    cutoff: u64,
    effective_now: u64,
) -> Option<Result<(), String>> {
    let result = sweep_task(app, "upload retention", move |app| {
        expire_link_uploads_sync(app, candidate, cutoff, effective_now)
    })
    .await;
    if result.is_none() {
        retention_sweep_failure();
    }
    result
}

fn expire_link_uploads_sync(
    app: &App,
    candidate: crate::store::Link,
    cutoff: u64,
    effective_now: u64,
) -> Result<(), String> {
    app.receiving_destinations()?;
    if candidate.legal_hold || app.link_hold_pinned(&candidate.id) {
        return Ok(());
    }
    match app
        .store
        .receive_workflow_pending(&candidate.tenant, &candidate.id)
    {
        Ok(false) => {}
        Ok(true) => return Ok(()),
        Err(error) => {
            retention_sweep_failure();
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
            retention_sweep_failure();
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
                retention_sweep_failure();
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
        retention_sweep_failure();
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
            retention_sweep_failure();
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
                let due = app
                    .push_staging_warn
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

/// Counts every retention sweep that skipped or failed work. The sweep
/// paths log each occurrence where it happens; this is the scrapeable sum.
static RETENTION_SWEEP_FAILURES: AtomicU64 = AtomicU64::new(0);

fn retention_sweep_failure() {
    RETENTION_SWEEP_FAILURES.fetch_add(1, Ordering::Relaxed);
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
    sweep_task(
        app,
        "revoked download streams",
        crate::api::outbound::cancel_stale_grant_streams,
    )
    .await;
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
                retention_sweep_failure();
                tracing::error!(%error, "retention clock read failed; skipping this sweep");
                return;
            }
            None => {
                retention_sweep_failure();
                return;
            }
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
            retention_sweep_failure();
            tracing::error!(%error, "settings read failed; skipping this sweep");
            return;
        }
        None => return,
    };
    sweep_task(app, "outbound proofs", move |app| {
        clean_outbound_proofs(&app.config.data_dir, &app.store, now);
    })
    .await;
    sweep_task(app, "revoked deliveries", move |app| {
        // Finding 379: a revoked delivery whose expiry has passed keeps its
        // recorded names, roots and receipts alive until this purge removes
        // the grant row and its dependents.
        match app.store.purge_expired_revoked_grants(now) {
            Ok(count) => {
                if count > 0 {
                    tracing::info!(count, "purged expired revoked deliveries");
                }
            }
            Err(error) => {
                retention_sweep_failure();
                tracing::warn!(%error, "revoked delivery purge failed")
            }
        }
    })
    .await;
    if settings.audit_retention_days > 0 {
        let cutoff = now.saturating_sub(settings.audit_retention_days.saturating_mul(86_400));
        sweep_task(app, "audit rows", move |app| {
            // Finding 376: audit rows naming a held link establish who
            // uploaded, so they outlive the retention cutoff until the hold
            // is released.
            let held = app.held_link_ids();
            match app.store.audit_prune(cutoff, &held) {
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
                Err(error) => {
                    retention_sweep_failure();
                    tracing::warn!("audit prune failed: {error}")
                }
            }
        })
        .await;
    }
    sweep_task(app, "database snapshots", move |app| {
        let backup_dir = app.config.data_dir.join("backups");
        prune_legacy_snapshots_at(&backup_dir, now);
    })
    .await;

    // Finding 378: a tenant or link may set its own upload retention even
    // when the platform-wide setting is off, so scope presence alone starts
    // the sweep.
    let scoped_retention = match sweep_task(app, "retention scope", |app| {
        app.store.scoped_retention_exists()
    })
    .await
    {
        Some(Ok(scoped)) => scoped,
        Some(Err(error)) => {
            retention_sweep_failure();
            tracing::error!(%error, "retention scope read failed; skipping the retention sweep");
            return;
        }
        None => return,
    };
    if settings.upload_retention_days > 0 || scoped_retention {
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
                    retention_sweep_failure();
                    tracing::error!(%error, "link read failed; skipping the retention sweep");
                    return;
                }
                None => {
                    retention_sweep_failure();
                    return;
                }
            };
            let page_len = link_ids.len();
            for (tenant, id, tenant_retention) in link_ids {
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
                        retention_sweep_failure();
                        tracing::error!(%error, "link read failed; skipping retention for link");
                        continue;
                    }
                    None => {
                        retention_sweep_failure();
                        return;
                    }
                };
                // The narrowest of the platform, tenant and link windows
                // decides; nothing set (0 = off, None = unset) keeps uploads.
                let Some(days) = narrowest_retention_days(
                    settings.upload_retention_days,
                    tenant_retention,
                    link.retention_days,
                ) else {
                    continue;
                };
                let cutoff = now.saturating_sub(days.saturating_mul(86_400));
                match expire_link_uploads(app, link, cutoff, now).await {
                    Some(Ok(())) => {}
                    Some(Err(error)) => {
                        retention_sweep_failure();
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

/// Finding 378: each link's upload retention is the narrowest positive
/// window set at any level. Zero means "off" at that level, and a missing
/// tenant or link scope does not constrain; when nothing is set the uploads
/// are kept.
fn narrowest_retention_days(
    global_days: u64,
    tenant_days: Option<u64>,
    link_days: Option<u64>,
) -> Option<u64> {
    [Some(global_days), tenant_days, link_days]
        .into_iter()
        .flatten()
        .filter(|days| *days > 0)
        .min()
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
pub(crate) mod tests;
