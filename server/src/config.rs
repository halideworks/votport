//! Environment-driven configuration.

use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Config {
    /// Address the HTTP server binds to.
    pub bind: SocketAddr,
    /// UDP address for native VOT pushes. None leaves the feature off.
    pub push_bind: Option<SocketAddr>,
    /// Certificate and private key presented by the native push listener.
    /// When absent, a persistent self-signed pair is created in `data_dir`.
    pub push_certificate: Option<PathBuf>,
    pub push_private_key: Option<PathBuf>,
    /// Public host and port native senders dial.
    pub push_advertise: Option<String>,
    /// UDP address the VOT serve listener binds; off when unset. Shares the
    /// push certificate and issuer key.
    pub serve_bind: Option<SocketAddr>,
    /// Public host and port VOT fetch clients dial.
    pub serve_advertise: Option<String>,
    /// Directory holding votport state (votport.db, secret).
    pub data_dir: PathBuf,
    /// Root directory received files are published into.
    pub receive_dir: PathBuf,
    /// Root directory for outbound library files and rendered projects.
    pub outbound_dir: PathBuf,
    /// Directory holding the static web assets.
    pub web_root: PathBuf,
    /// Argon2 PHC hash of the admin password.
    pub admin_password_hash: String,
    /// Stable tag for the environment-provided admin credential, bound into
    /// session token MACs so rotating the env password (or env hash) evicts
    /// sessions while a plain restart does not. The argon2 hash above cannot
    /// serve: it is salted fresh each boot.
    pub admin_token_tag: String,
    pub smtp_host: Option<String>,
    /// SMTP port. Default 587. Port 465 uses implicit TLS.
    pub smtp_port: u16,
    /// When true, use STARTTLS on ports other than 465. Default true.
    pub smtp_starttls: bool,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    /// Bearer the SCIM client presents; None disables /scim/v2.
    pub scim_token: Option<String>,
    /// Bearer a standby presents to GET /api/replica; None disables it.
    pub replica_token: Option<String>,
    pub smtp_from: Option<String>,

    /// Public origin (e.g. "https://drop.example.com"); used to render
    /// links in the admin UI and to decide whether cookies are `Secure`.
    pub public_url: Option<String>,
    /// Hard cap on the total bytes of a single upload session.
    pub max_upload_bytes: u64,
    /// Total bytes reserved by retained delivery snapshots.
    pub workflow_snapshot_bytes: u64,
    /// Allow uploaded file names whose components start with a dot.
    pub allow_hidden: bool,
    /// Seconds an upload session may sit idle before it is discarded.
    pub session_idle_secs: u64,
    /// Days to keep audit rows; 0 disables pruning.
    pub audit_retention_days: u64,
    /// Days to keep received files and their records; 0 disables the sweep.
    pub upload_retention_days: u64,
    /// Overlay default quotas: filled into a new tenant when the create
    /// request omits the field, and applied live to the unnamed default
    /// tenant. Named tenants keep the quotas on their row. None is unlimited.
    pub default_max_total_bytes: Option<u64>,
    pub default_max_links: Option<u64>,
    pub default_max_sessions: Option<u64>,
    /// When false, the login page may collapse the local password form if
    /// SSO is offered. The login API itself always stays available.
    pub public_password_login: bool,
    /// Refuse SSO sign-in for subjects with no principal row, so SCIM is the
    /// source of truth for who may enter. Overridable from settings.
    pub require_provisioning: bool,
    /// When set, /metrics requires this bearer token.
    pub metrics_token: Option<String>,
    /// Process-wide cap on concurrent upload sessions across all tenants.
    /// Worst-case queued-body memory rises linearly with it: sessions x 8
    /// in-flight chunks x ~9 MiB.
    pub max_total_sessions: usize,
    /// Cap on concurrent upload sessions per request link.
    pub max_link_sessions: usize,
    /// Lifetime of admin sessions issued through SSO; the settings overlay
    /// can override it live. Local break-glass sessions keep a fixed 7 days.
    pub sso_session_secs: u64,
    /// Peers whose `X-Forwarded-For` is believed, as CIDR blocks. Empty means
    /// the built-in default: loopback plus the private ranges. Naming the
    /// reverse proxy explicitly is what stops anything else that can reach
    /// the port from choosing its own throttle bucket.
    pub trusted_proxies: Vec<IpCidr>,
    /// OIDC single sign-on for the admin dashboard. None when unset.
    pub oidc: Option<OidcConfig>,
}

impl Config {
    pub(crate) fn validate(&self) -> Result<(), String> {
        self.validate_storage_roots()?;
        if let Some(url) = self.public_url.as_deref() {
            validate_public_url(url)?;
        }
        if self.session_idle_secs == 0 {
            return Err("VOTPORT_SESSION_IDLE_SECS must be greater than zero".to_owned());
        }
        if !valid_sso_session_secs(self.sso_session_secs) {
            return Err(format!(
                "VOTPORT_SSO_SESSION_SECS must be between 1 and {MAX_SSO_SESSION_SECS}"
            ));
        }
        validate_admin_password_hash(&self.admin_password_hash)
    }

    pub(crate) fn validate_storage_roots(&self) -> Result<(), String> {
        validate_storage_roots(&self.data_dir, &self.receive_dir, &self.outbound_dir)
    }
}

#[derive(Clone, Debug)]
struct ResolvedStorageRoot {
    path: PathBuf,
    #[cfg(unix)]
    ancestors: Vec<(u64, u64)>,
    #[cfg(unix)]
    anchor: StorageAnchor,
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct StorageAnchor {
    identity: (u64, u64),
    suffix: Vec<std::ffi::OsString>,
}

fn validate_storage_roots(
    data_dir: &Path,
    receive_dir: &Path,
    outbound_dir: &Path,
) -> Result<(), String> {
    let roots = [
        ("VOTPORT_DATA_DIR", data_dir),
        ("VOTPORT_RECEIVE_DIR", receive_dir),
        ("VOTPORT_OUTBOUND_DIR", outbound_dir),
    ];
    let resolved = roots
        .iter()
        .map(|(name, path)| resolve_storage_root(name, path))
        .collect::<Result<Vec<_>, _>>()?;
    // Shared ancestors are valid; only a root matching another root or its ancestor overlaps.
    for (left, right) in [(0, 1), (0, 2), (1, 2)] {
        if storage_paths_overlap(&resolved[left].path, &resolved[right].path)
            || storage_roots_share_physical_directory(&resolved[left], &resolved[right])
        {
            return Err(format!(
                "{} and {} must be separate storage directories",
                roots[left].0, roots[right].0
            ));
        }
    }
    Ok(())
}

fn resolve_storage_root(name: &str, path: &Path) -> Result<ResolvedStorageRoot, String> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        env::current_dir()
            .map_err(|error| format!("{name} cannot resolve its working directory: {error}"))?
            .join(path)
    };
    let mut current = absolute;
    let mut missing = Vec::new();
    let mut symlinks = 0;
    let resolved = loop {
        match std::fs::canonicalize(&current) {
            Ok(path) => {
                let mut resolved = path;
                for component in missing.iter().rev() {
                    if component == OsStr::new(".") {
                        continue;
                    }
                    if component == OsStr::new("..") {
                        resolved.pop();
                    } else {
                        resolved.push(component);
                    }
                }
                match std::fs::canonicalize(&resolved) {
                    Ok(canonical) => break canonical,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if missing
                            .iter()
                            .all(|component| component != OsStr::new(".."))
                        {
                            break resolved;
                        }
                        current = resolved;
                        missing.clear();
                        continue;
                    }
                    Err(error) => return Err(format!("{name} cannot be resolved: {error}")),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Ok(metadata) = std::fs::symlink_metadata(&current) {
                    if metadata.file_type().is_symlink() {
                        symlinks += 1;
                        if symlinks > 40 {
                            return Err(format!("{name} contains too many symlinks"));
                        }
                        let target = std::fs::read_link(&current)
                            .map_err(|error| format!("{name} cannot be resolved: {error}"))?;
                        current = if target.is_absolute() {
                            target
                        } else {
                            current.parent().unwrap_or(Path::new("/")).join(target)
                        };
                        continue;
                    }
                }
                let Some(component) = current.file_name() else {
                    return Err(format!("{name} has no existing parent directory"));
                };
                missing.push(component.to_owned());
                let Some(parent) = current.parent() else {
                    return Err(format!("{name} has no existing parent directory"));
                };
                current = parent.to_owned();
            }
            Err(error) => return Err(format!("{name} cannot be resolved: {error}")),
        }
    };
    match std::fs::metadata(&resolved) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(format!("{name} must be a directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{name} cannot be checked: {error}")),
    }
    #[cfg(unix)]
    let (ancestors, anchor) = storage_root_identities(&resolved, name)?;
    Ok(ResolvedStorageRoot {
        path: resolved,
        #[cfg(unix)]
        ancestors,
        #[cfg(unix)]
        anchor,
    })
}

fn storage_paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

#[cfg(unix)]
fn storage_root_identities(
    path: &Path,
    name: &str,
) -> Result<(Vec<(u64, u64)>, StorageAnchor), String> {
    use std::os::unix::fs::MetadataExt as _;

    let mut ancestors = Vec::new();
    let mut suffix = Vec::new();
    let mut anchor = None;
    let mut current = path;
    loop {
        match std::fs::metadata(current) {
            Ok(metadata) if metadata.is_dir() => {
                let current_identity = (metadata.dev(), metadata.ino());
                if anchor.is_none() {
                    anchor = Some(StorageAnchor {
                        identity: current_identity,
                        suffix: std::mem::take(&mut suffix).into_iter().rev().collect(),
                    });
                }
                ancestors.push(current_identity);
                if current == Path::new("/") {
                    return Ok((ancestors, anchor.expect("root anchor")));
                }
                current = current.parent().unwrap_or(Path::new("/"));
            }
            Ok(_) => return Err(format!("{name} has a non-directory ancestor")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if current == Path::new("/") {
                    return Err(format!("{name} has no existing parent directory"));
                }
                let Some(component) = current.file_name() else {
                    return Err(format!("{name} has no existing parent directory"));
                };
                suffix.push(component.to_owned());
                current = current.parent().unwrap_or(Path::new("/"));
            }
            Err(error) => return Err(format!("{name} cannot be checked: {error}")),
        }
    }
}

#[cfg(unix)]
fn storage_roots_share_physical_directory(
    left: &ResolvedStorageRoot,
    right: &ResolvedStorageRoot,
) -> bool {
    (left.anchor.suffix.is_empty() && right.ancestors.contains(&left.anchor.identity))
        || (right.anchor.suffix.is_empty() && left.ancestors.contains(&right.anchor.identity))
        || (left.anchor.identity == right.anchor.identity
            && (left.anchor.suffix.starts_with(&right.anchor.suffix)
                || right.anchor.suffix.starts_with(&left.anchor.suffix)))
}

#[cfg(not(unix))]
fn storage_roots_share_physical_directory(
    _left: &ResolvedStorageRoot,
    _right: &ResolvedStorageRoot,
) -> bool {
    false
}

/// Identity-provider settings for admin SSO (docs/multi-tenancy.md phase 3).
#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Group whose members sign in as admins; everyone else gets read-only
    /// access. None means every authenticated principal is an admin.
    pub admin_group: Option<String>,
    /// Members of this group get the audit-only role; admin membership
    /// outranks it, everyone else is a viewer.
    pub auditor_group: Option<String>,
    /// Which id-token claim becomes the principal subject. `sub` is the
    /// OIDC default; email or preferred_username lets a SCIM userName match
    /// on providers whose sub is opaque or pairwise (Entra, Okta).
    pub subject_claim: SubjectClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectClaim {
    Sub,
    Email,
    PreferredUsername,
}

impl SubjectClaim {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim() {
            "" | "sub" => Ok(Self::Sub),
            "email" => Ok(Self::Email),
            "preferred_username" => Ok(Self::PreferredUsername),
            other => Err(format!(
                "VOTPORT_OIDC_SUBJECT_CLAIM must be sub, email, or preferred_username, not {other:?}"
            )),
        }
    }
}

const DEFAULT_MAX_UPLOAD_BYTES: u64 = 50 * 1024 * 1024 * 1024; // 50 GiB
const DEFAULT_MAX_TOTAL_SESSIONS: usize = 32;
const DEFAULT_MAX_LINK_SESSIONS: usize = 8;
const DEFAULT_SSO_SESSION_SECS: u64 = 7 * 24 * 3600;
pub(crate) const MAX_SSO_SESSION_SECS: u64 = 365 * 24 * 3600;

pub(crate) fn valid_sso_session_secs(value: u64) -> bool {
    (1..=MAX_SSO_SESSION_SECS).contains(&value)
}

/// Shortest admin password this build accepts. Enforced on anything set
/// through the UI and on `VOTPORT_ADMIN_PASSWORD`, which refuses to start
/// below it. An existing deployment with a shorter one will not boot after
/// upgrading; `VOTPORT_ADMIN_PASSWORD_HASH` is the escape hatch, since a PHC
/// string says nothing about the length of its input.
pub const MIN_ADMIN_PASSWORD_CHARS: usize = 12;

/// Refuses a break-glass password too short to survive guessing. Throttling
/// bounds how fast a guess is checked; it cannot make a short password safe,
/// and this is the credential that still works when the identity provider
/// does not. `VOTPORT_ADMIN_PASSWORD_HASH` is exempt: a PHC string says
/// nothing about the length of its input.
pub fn admit_admin_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_ADMIN_PASSWORD_CHARS {
        return Err(format!(
            "VOTPORT_ADMIN_PASSWORD must be at least {MIN_ADMIN_PASSWORD_CHARS} characters"
        ));
    }
    Ok(())
}

/// One CIDR block: a network address and how many leading bits are fixed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IpCidr {
    network: std::net::IpAddr,
    bits: u8,
}

impl fmt::Display for IpCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.bits)
    }
}

impl IpCidr {
    /// Parses "10.0.0.0/8", "2001:db8::/32", or a bare address (a full-length
    /// prefix). Rejects a prefix longer than the address family allows.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (address, bits) = match text.split_once('/') {
            Some((address, bits)) => {
                let bits: u8 = bits
                    .parse()
                    .map_err(|_| format!("{text:?}: prefix length is not a number"))?;
                (address, Some(bits))
            }
            None => (text, None),
        };
        let network: std::net::IpAddr = address
            .parse()
            .map_err(|_| format!("{text:?}: not an IP address"))?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        let bits = bits.unwrap_or(width);
        if bits > width {
            return Err(format!("{text:?}: prefix longer than the address family"));
        }
        // A v4-mapped network is a v4 network. Peers are compared in their
        // unwrapped form, so leaving this as v6 would build a block that
        // matches nothing, and a dual-stack bind logs peers in the mapped
        // form an operator would copy.
        if let std::net::IpAddr::V6(v6) = network {
            if let Some(v4) = v6.to_ipv4_mapped() {
                if bits >= 96 {
                    return Ok(Self {
                        network: std::net::IpAddr::V4(v4),
                        bits: bits - 96,
                    });
                }
            }
        }
        Ok(Self { network, bits })
    }

    /// Whether `ip` falls inside this block. A v4-mapped address is compared
    /// as v4, matching how the rest of the service reads peers.
    pub fn contains(&self, ip: &std::net::IpAddr) -> bool {
        let ip = match ip {
            std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => std::net::IpAddr::V4(v4),
                None => *ip,
            },
            other => *other,
        };
        match (self.network, ip) {
            (std::net::IpAddr::V4(network), std::net::IpAddr::V4(ip)) => {
                prefix_matches(&network.octets(), &ip.octets(), self.bits)
            }
            (std::net::IpAddr::V6(network), std::net::IpAddr::V6(ip)) => {
                prefix_matches(&network.octets(), &ip.octets(), self.bits)
            }
            _ => false,
        }
    }
}

/// Whether two addresses agree on their first `bits` bits.
fn prefix_matches(network: &[u8], ip: &[u8], bits: u8) -> bool {
    let whole = usize::from(bits / 8);
    let remainder = bits % 8;
    if network[..whole] != ip[..whole] {
        return false;
    }
    if remainder == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remainder);
    network[whole] & mask == ip[whole] & mask
}

const KNOWN_ENVIRONMENT_NAMES: &[&str] = &[
    "VOTPORT_ADMIN_PASSWORD",
    "VOTPORT_ADMIN_PASSWORD_HASH",
    "VOTPORT_ALLOW_HIDDEN",
    "VOTPORT_AUDIT_RETENTION_DAYS",
    "VOTPORT_AUTOMATION_TOKEN",
    "VOTPORT_BIND",
    "VOTPORT_CLAMDSCAN",
    "VOTPORT_DATA_DIR",
    "VOTPORT_DEFAULT_MAX_LINKS",
    "VOTPORT_DEFAULT_MAX_SESSIONS",
    "VOTPORT_DEFAULT_MAX_TOTAL_BYTES",
    "VOTPORT_FFPROBE",
    "VOTPORT_LOG_FORMAT",
    "VOTPORT_MAX_LINK_SESSIONS",
    "VOTPORT_MAX_TOTAL_SESSIONS",
    "VOTPORT_MAX_UPLOAD_BYTES",
    "VOTPORT_METRICS_TOKEN",
    "VOTPORT_NOTIFY_SMTP_FROM",
    "VOTPORT_NOTIFY_SMTP_HOST",
    "VOTPORT_NOTIFY_SMTP_PASSWORD",
    "VOTPORT_NOTIFY_SMTP_PORT",
    "VOTPORT_NOTIFY_SMTP_STARTTLS",
    "VOTPORT_NOTIFY_SMTP_USERNAME",
    "VOTPORT_OIDC_ADMIN_GROUP",
    "VOTPORT_OIDC_AUDITOR_GROUP",
    "VOTPORT_OIDC_CLIENT_ID",
    "VOTPORT_OIDC_CLIENT_SECRET",
    "VOTPORT_OIDC_ISSUER",
    "VOTPORT_OIDC_SUBJECT_CLAIM",
    "VOTPORT_OUTBOUND_DIR",
    "VOTPORT_PUBLIC_PASSWORD_LOGIN",
    "VOTPORT_PUBLIC_URL",
    "VOTPORT_PUSH_ADVERTISE",
    "VOTPORT_PUSH_BIND",
    "VOTPORT_PUSH_CERT",
    "VOTPORT_PUSH_KEY",
    "VOTPORT_RECEIVE_DIR",
    "VOTPORT_REPLICA_TOKEN",
    "VOTPORT_SCIM_REQUIRE_PROVISIONING",
    "VOTPORT_SCIM_TOKEN",
    "VOTPORT_SERVE_ADVERTISE",
    "VOTPORT_SERVE_BIND",
    "VOTPORT_SESSION_IDLE_SECS",
    "VOTPORT_SHARE_PASSWORD",
    "VOTPORT_SSO_SESSION_SECS",
    "VOTPORT_STANDBY_INTERVAL_SECS",
    "VOTPORT_STANDBY_SOURCE",
    "VOTPORT_TRUSTED_PROXIES",
    "VOTPORT_UPLOAD_RETENTION_DAYS",
    "VOTPORT_URL",
    "VOTPORT_WEB_ROOT",
    "VOTPORT_WORKFLOW_SNAPSHOT_BYTES",
];

fn is_known_dynamic_environment_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("VOTPORT_STORAGE_") else {
        return false;
    };
    ["_ACCESS_KEY_ID", "_SECRET_ACCESS_KEY", "_SESSION_TOKEN"]
        .iter()
        .any(|suffix| {
            rest.strip_suffix(suffix).is_some_and(|id| {
                !id.is_empty()
                    && id.len() <= 100
                    && id.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            })
        })
}

fn is_known_environment_name(name: &str) -> bool {
    KNOWN_ENVIRONMENT_NAMES.contains(&name) || is_known_dynamic_environment_name(name)
}

/// Warn about VOTPORT names that have no consumer. Values are intentionally
/// ignored so secrets and invalid Unicode values never enter the log path.
pub fn warn_unknown_environment() {
    for (key, _) in env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("VOTPORT_") && !is_known_environment_name(&name) {
            tracing::warn!(environment = ?name, "unknown environment setting ignored");
        }
    }
}

pub fn from_env() -> Result<Config, String> {
    let bind = env_or("VOTPORT_BIND", "0.0.0.0:8080")
        .parse()
        .map_err(|error| format!("VOTPORT_BIND is not a socket address: {error}"))?;
    let data_dir = PathBuf::from(env_or("VOTPORT_DATA_DIR", "/data"));
    let receive_dir = PathBuf::from(env_or("VOTPORT_RECEIVE_DIR", "/received"));
    let outbound_dir = PathBuf::from(env_or("VOTPORT_OUTBOUND_DIR", "/outbound"));
    let web_root = PathBuf::from(env_or("VOTPORT_WEB_ROOT", "./web"));

    let (admin_password_hash, admin_token_tag) = match env::var("VOTPORT_ADMIN_PASSWORD_HASH") {
        // The env PHC string is stable across restarts and changes on
        // rotation, so it is its own token tag.
        Ok(hash) if !hash.trim().is_empty() => {
            let hash = hash.trim().to_owned();
            let tag = hash.clone();
            (hash, tag)
        }
        _ => match env::var("VOTPORT_ADMIN_PASSWORD") {
            Ok(password) if !password.is_empty() => {
                admit_admin_password(&password)?;
                use sha2::Digest as _;
                let tag = hex::encode(sha2::Sha256::digest(password.as_bytes()));
                let hash = crate::auth::hash_password(&password)
                    .map_err(|error| format!("failed to hash admin password: {error}"))?;
                (hash, tag)
            }
            _ => {
                return Err(
                    "set VOTPORT_ADMIN_PASSWORD (or VOTPORT_ADMIN_PASSWORD_HASH with an \
                     argon2 PHC string) before starting votport"
                        .to_owned(),
                );
            }
        },
    };

    let optional = |name: &str| env::var(name).ok().filter(|value| !value.trim().is_empty());
    let public_url = env::var("VOTPORT_PUBLIC_URL")
        .ok()
        .map(|url| url.trim_end_matches('/').to_owned())
        .filter(|url| !url.is_empty());
    let push_bind = optional("VOTPORT_PUSH_BIND")
        .map(|value| {
            value
                .parse()
                .map_err(|error| format!("VOTPORT_PUSH_BIND is not a socket address: {error}"))
        })
        .transpose()?;
    let (push_certificate, push_private_key) =
        match (optional("VOTPORT_PUSH_CERT"), optional("VOTPORT_PUSH_KEY")) {
            (Some(certificate), Some(key)) => {
                (Some(PathBuf::from(certificate)), Some(PathBuf::from(key)))
            }
            (None, None) => (None, None),
            _ => {
                return Err(
                    "set both VOTPORT_PUSH_CERT and VOTPORT_PUSH_KEY, or neither".to_owned(),
                )
            }
        };
    let push_advertise = push_bind
        .map(|bind| {
            push_address(
                optional("VOTPORT_PUSH_ADVERTISE"),
                public_url.as_deref(),
                bind,
            )
        })
        .transpose()?;
    let serve_bind = optional("VOTPORT_SERVE_BIND")
        .map(|value| {
            value
                .parse()
                .map_err(|error| format!("VOTPORT_SERVE_BIND is not a socket address: {error}"))
        })
        .transpose()?;
    let serve_advertise = serve_bind
        .map(|bind| {
            listener_address(
                "SERVE",
                optional("VOTPORT_SERVE_ADVERTISE"),
                public_url.as_deref(),
                bind,
            )
        })
        .transpose()?;

    let max_upload_bytes = match env::var("VOTPORT_MAX_UPLOAD_BYTES") {
        Ok(value) => {
            parse_bytes(&value).map_err(|error| format!("VOTPORT_MAX_UPLOAD_BYTES: {error}"))?
        }
        Err(_) => DEFAULT_MAX_UPLOAD_BYTES,
    };

    let workflow_snapshot_bytes = match env::var("VOTPORT_WORKFLOW_SNAPSHOT_BYTES") {
        Ok(value) => parse_bytes(&value)
            .map_err(|error| format!("VOTPORT_WORKFLOW_SNAPSHOT_BYTES: {error}"))?,
        Err(_) => max_upload_bytes.saturating_mul(4),
    };
    let allow_hidden = env_bool("VOTPORT_ALLOW_HIDDEN", false)?;

    let upload_retention_days = match env::var("VOTPORT_UPLOAD_RETENTION_DAYS") {
        Ok(value) => value
            .parse()
            .map_err(|error| format!("VOTPORT_UPLOAD_RETENTION_DAYS: {error}"))?,
        Err(_) => 0,
    };
    let metrics_token = optional("VOTPORT_METRICS_TOKEN");
    if metrics_token.is_none() {
        eprintln!(
            "votport: VOTPORT_METRICS_TOKEN is unset; /metrics is unauthenticated and \
             lists tenant keys and per-tenant totals"
        );
    }

    let max_total_sessions = session_cap(
        "VOTPORT_MAX_TOTAL_SESSIONS",
        env::var("VOTPORT_MAX_TOTAL_SESSIONS").ok(),
        DEFAULT_MAX_TOTAL_SESSIONS,
    )?;
    let max_link_sessions = session_cap(
        "VOTPORT_MAX_LINK_SESSIONS",
        env::var("VOTPORT_MAX_LINK_SESSIONS").ok(),
        DEFAULT_MAX_LINK_SESSIONS,
    )?;

    let sso_session_secs = match env::var("VOTPORT_SSO_SESSION_SECS") {
        Ok(value) => {
            let parsed: u64 = value
                .parse()
                .map_err(|error| format!("VOTPORT_SSO_SESSION_SECS: {error}"))?;
            parsed
        }
        Err(_) => DEFAULT_SSO_SESSION_SECS,
    };

    // Read raw, not through `optional`: that helper treats a whitespace-only
    // value as unset, which for this variable means "trust every private
    // peer" rather than the refusal below.
    let trusted_proxies = match env::var("VOTPORT_TRUSTED_PROXIES")
        .ok()
        .filter(|value| !value.is_empty())
    {
        Some(list) => {
            let blocks = list
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(IpCidr::parse)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("VOTPORT_TRUSTED_PROXIES: {error}"))?;
            if blocks.is_empty() {
                // Empty means "use the built-in guess", so a setting that
                // names nothing would quietly widen trust instead of
                // narrowing it. Unset the variable to get the default.
                return Err("VOTPORT_TRUSTED_PROXIES is set but names no address; \
                     unset it to trust loopback and private peers"
                    .to_owned());
            }
            blocks
        }
        None => {
            eprintln!(
                "votport: VOTPORT_TRUSTED_PROXIES is unset; X-Forwarded-For from any \
                 loopback or private peer is believed, so a LAN peer that reaches the \
                 port directly can pick its own per-IP throttle bucket. Name the \
                 reverse proxy before production use (docs/deployment.md)"
            );
            Vec::new()
        }
    };

    let audit_retention_days = match env::var("VOTPORT_AUDIT_RETENTION_DAYS") {
        Ok(value) => value
            .parse()
            .map_err(|error| format!("VOTPORT_AUDIT_RETENTION_DAYS: {error}"))?,
        Err(_) => 400,
    };

    let default_max_total_bytes = optional_positive_u64("VOTPORT_DEFAULT_MAX_TOTAL_BYTES")?;
    let default_max_links = optional_positive_u64("VOTPORT_DEFAULT_MAX_LINKS")?;
    let default_max_sessions = optional_positive_u64("VOTPORT_DEFAULT_MAX_SESSIONS")?;
    let public_password_login = env_bool("VOTPORT_PUBLIC_PASSWORD_LOGIN", true)?;
    let require_provisioning = env_bool("VOTPORT_SCIM_REQUIRE_PROVISIONING", false)?;

    let session_idle_secs = match env::var("VOTPORT_SESSION_IDLE_SECS") {
        Ok(value) => value
            .parse()
            .map_err(|error| format!("VOTPORT_SESSION_IDLE_SECS: {error}"))?,
        Err(_) => 1800,
    };

    let smtp_port = match env::var("VOTPORT_NOTIFY_SMTP_PORT") {
        Ok(value) if !value.trim().is_empty() => {
            let parsed: u16 = value
                .parse()
                .map_err(|error| format!("VOTPORT_NOTIFY_SMTP_PORT: {error}"))?;
            if parsed == 0 {
                return Err("VOTPORT_NOTIFY_SMTP_PORT must be 1..=65535".to_owned());
            }
            parsed
        }
        _ => 587,
    };
    let smtp_starttls = env_bool("VOTPORT_NOTIFY_SMTP_STARTTLS", true)?;

    let oidc = match (
        optional("VOTPORT_OIDC_ISSUER"),
        optional("VOTPORT_OIDC_CLIENT_ID"),
        optional("VOTPORT_OIDC_CLIENT_SECRET"),
    ) {
        (Some(issuer), Some(client_id), Some(client_secret)) => {
            let admin_group = env::var("VOTPORT_OIDC_ADMIN_GROUP")
                .ok()
                .filter(|group| !group.trim().is_empty());
            if admin_group.is_none() {
                eprintln!(
                    "votport: VOTPORT_OIDC_ADMIN_GROUP is unset; every principal your \
                     provider authenticates will have full admin access"
                );
            }
            let auditor_group = env::var("VOTPORT_OIDC_AUDITOR_GROUP")
                .ok()
                .filter(|group| !group.trim().is_empty());
            let subject_claim =
                SubjectClaim::parse(&env::var("VOTPORT_OIDC_SUBJECT_CLAIM").unwrap_or_default())?;
            Some(OidcConfig {
                issuer,
                client_id,
                client_secret,
                admin_group,
                auditor_group,
                subject_claim,
            })
        }
        (None, None, None) => None,
        _ => {
            return Err(
                "set all of VOTPORT_OIDC_ISSUER, VOTPORT_OIDC_CLIENT_ID and \
                 VOTPORT_OIDC_CLIENT_SECRET, or none"
                    .to_owned(),
            )
        }
    };

    let config = Config {
        bind,
        push_bind,
        push_certificate,
        push_private_key,
        push_advertise,
        serve_bind,
        serve_advertise,
        data_dir,
        receive_dir,
        outbound_dir,
        web_root,
        admin_password_hash,
        admin_token_tag,

        smtp_host: optional("VOTPORT_NOTIFY_SMTP_HOST"),
        smtp_port,
        smtp_starttls,
        smtp_username: optional("VOTPORT_NOTIFY_SMTP_USERNAME"),
        smtp_password: optional("VOTPORT_NOTIFY_SMTP_PASSWORD"),
        scim_token: bearer_token(
            "VOTPORT_SCIM_TOKEN",
            optional("VOTPORT_SCIM_TOKEN").as_deref(),
        )?,
        replica_token: bearer_token(
            "VOTPORT_REPLICA_TOKEN",
            optional("VOTPORT_REPLICA_TOKEN").as_deref(),
        )?,
        smtp_from: optional("VOTPORT_NOTIFY_SMTP_FROM"),

        public_url,
        max_upload_bytes,
        workflow_snapshot_bytes,
        allow_hidden,
        session_idle_secs,
        audit_retention_days,
        upload_retention_days,
        default_max_total_bytes,
        default_max_links,
        default_max_sessions,
        public_password_login,
        require_provisioning,
        metrics_token,
        max_total_sessions,
        max_link_sessions,
        sso_session_secs,
        trusted_proxies,
        oidc,
    };
    config.validate()?;
    Ok(config)
}

fn validate_admin_password_hash(phc: &str) -> Result<(), String> {
    use argon2::{password_hash::PasswordHash, Algorithm, Params, Version};

    let invalid =
        || "VOTPORT_ADMIN_PASSWORD_HASH must be a complete supported Argon2 PHC string".to_owned();
    let hash = PasswordHash::new(phc).map_err(|_| invalid())?;
    Algorithm::try_from(hash.algorithm).map_err(|_| invalid())?;
    if let Some(version) = hash.version {
        Version::try_from(version).map_err(|_| invalid())?;
    }
    Params::try_from(&hash).map_err(|_| invalid())?;
    if hash.hash.is_none() {
        return Err(invalid());
    }
    let salt = hash.salt.ok_or_else(invalid)?;
    let mut decoded = [0u8; 64];
    if salt.decode_b64(&mut decoded).map_err(|_| invalid())?.len() < argon2::MIN_SALT_LEN {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn validate_public_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|error| format!("VOTPORT_PUBLIC_URL is not a valid URL: {error}"))?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err("VOTPORT_PUBLIC_URL must use https (or http for loopback)".to_owned());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("VOTPORT_PUBLIC_URL must not contain credentials".to_owned());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("VOTPORT_PUBLIC_URL must not contain a query or fragment".to_owned());
    }
    if parsed.path() != "/" {
        return Err("VOTPORT_PUBLIC_URL must be an origin without a path prefix".to_owned());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "VOTPORT_PUBLIC_URL must include a host".to_owned())?;
    if parsed.scheme() == "http" {
        let ip_host = host.trim_matches(['[', ']']);
        let loopback = host.eq_ignore_ascii_case("localhost")
            || ip_host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        if !loopback {
            return Err("VOTPORT_PUBLIC_URL may use http only for a loopback host".to_owned());
        }
    }
    Ok(())
}

fn push_address(
    explicit: Option<String>,
    public_url: Option<&str>,
    bind: SocketAddr,
) -> Result<String, String> {
    let address = listener_address("PUSH", explicit, public_url, bind)?;
    let loopback = reqwest::Url::parse(&format!("vot://{address}"))
        .ok()
        .and_then(|parsed| parsed.host_str().map(is_loopback_host))
        .unwrap_or(false);
    if loopback && !bind.ip().is_loopback() {
        return Err(format!(
            "VOTPORT_PUSH_ADVERTISE is loopback ({address}) but VOTPORT_PUSH_BIND is not; \
             senders would dial their own machine. Bind push on loopback or advertise a \
             routable address"
        ));
    }
    Ok(address)
}

/// A loopback host literal: `localhost` in any case, or a loopback IP.
/// DNS names are never resolved.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// The env value of a bearer token is always the raw token; the `sha256:`
/// digest form is only how stored tokens are hashed. Accepting a digest here
/// would make every byte comparison fail and silently break replication.
fn bearer_token(name: &str, value: Option<&str>) -> Result<Option<String>, String> {
    match value {
        Some(token) if token.starts_with(crate::api::scim::HASH_PREFIX) => Err(format!(
            "{name} must be the raw bearer token, not a {} digest; the digest form is only for stored values",
            crate::api::scim::HASH_PREFIX
        )),
        token => Ok(token.map(str::to_owned)),
    }
}

/// The advertised address for a UDP listener named by `kind` (`PUSH` or
/// `SERVE`), so an error names the knob the operator set.
fn listener_address(
    kind: &str,
    explicit: Option<String>,
    public_url: Option<&str>,
    bind: SocketAddr,
) -> Result<String, String> {
    if bind.port() == 0 {
        return Err(format!(
            "VOTPORT_{kind}_BIND port must be greater than zero"
        ));
    }
    let address = if let Some(address) = explicit {
        address
    } else {
        let public_url = public_url.ok_or_else(|| {
            format!("set VOTPORT_{kind}_ADVERTISE or VOTPORT_PUBLIC_URL when VOTPORT_{kind}_BIND is set")
        })?;
        let parsed = reqwest::Url::parse(public_url).map_err(|error| {
            format!(
                "VOTPORT_PUBLIC_URL cannot supply the {} address: {error}",
                kind.to_ascii_lowercase()
            )
        })?;
        let host = parsed.host_str().ok_or_else(|| {
            format!("VOTPORT_PUBLIC_URL has no host; set VOTPORT_{kind}_ADVERTISE")
        })?;
        if host.starts_with('[') {
            format!("{host}:{}", bind.port())
        } else if host.contains(':') {
            format!("[{host}]:{}", bind.port())
        } else {
            format!("{host}:{}", bind.port())
        }
    };
    if address.contains(['/', '\\']) {
        return Err(format!("VOTPORT_{kind}_ADVERTISE must be host:port"));
    }
    let parsed = reqwest::Url::parse(&format!("vot://{address}"))
        .map_err(|error| format!("VOTPORT_{kind}_ADVERTISE is not host:port: {error}"))?;
    if parsed.host_str().is_none()
        || parsed.port().is_none_or(|port| port == 0)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || !matches!(parsed.path(), "" | "/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(format!("VOTPORT_{kind}_ADVERTISE must be host:port"));
    }
    Ok(address)
}

fn env_bool(name: &str, default: bool) -> Result<bool, String> {
    let value = match env::var(name) {
        Err(env::VarError::NotPresent) => return Ok(default),
        value => value.map_err(|_| format!("{name} is not valid Unicode"))?,
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("{name} must be 1/0, true/false, yes/no or on/off")),
    }
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn optional_positive_u64(name: &str) -> Result<Option<u64>, String> {
    match env::var(name) {
        Err(_) => Ok(None),
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => {
            let parsed: u64 = value.parse().map_err(|error| format!("{name}: {error}"))?;
            Ok((parsed > 0).then_some(parsed))
        }
    }
}

/// Parses a byte count, optionally suffixed K/KiB/KB, M/MiB/MB, G/GiB/GB or
/// T/TiB/TB (case-insensitive). A bare number stays bytes. All suffix
/// spellings mean x1024^n; the aliases exist so a hand-typed "500G" cannot
/// silently mean 500 bytes or 500000000 by typo.
fn parse_bytes(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    let split_at = trimmed
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii_digit())
        .map_or(trimmed.len(), |(idx, _)| idx);
    let (digits, suffix) = trimmed.split_at(split_at);
    let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1u64,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" => 1024u64 * 1024 * 1024 * 1024,
        other => return Err(format!("unknown size suffix {other:?}")),
    };
    if digits.is_empty() {
        return Err(format!("{value:?} is not a byte count"));
    }
    let bytes = digits
        .parse::<u64>()
        .map_err(|_| format!("{value:?} is out of range"))?
        .saturating_mul(multiplier);
    // A zero cap would silently refuse every upload.
    if bytes == 0 {
        return Err(format!("{value:?} must be greater than zero"));
    }
    Ok(bytes)
}

/// A concurrent-session cap from the environment: unset takes the default,
/// zero is refused because it would deny every upload.
fn session_cap(name: &str, value: Option<String>, default: usize) -> Result<usize, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parsed: usize = value.parse().map_err(|error| format!("{name}: {error}"))?;
    if parsed == 0 {
        return Err(format!("{name} must be at least 1"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod session_cap_tests {
    use super::session_cap;

    #[test]
    fn session_caps_default_and_refuse_zero() {
        assert_eq!(session_cap("X", None, 8), Ok(8));
        assert_eq!(session_cap("X", Some("3".to_owned()), 8), Ok(3));
        assert_eq!(
            session_cap("X", Some("0".to_owned()), 8),
            Err("X must be at least 1".to_owned())
        );
        assert!(session_cap("X", Some("many".to_owned()), 8).is_err());
    }
}

#[cfg(test)]
mod password_tests {
    use super::{admit_admin_password, MIN_ADMIN_PASSWORD_CHARS};

    #[test]
    fn short_break_glass_passwords_are_refused() {
        assert!(admit_admin_password("a-long-enough-passphrase").is_ok());
        // Counted in characters, not bytes. Six two-byte characters is
        // twelve bytes and six characters, so a byte count would admit it.
        let six_two_byte_chars = "\u{e9}".repeat(6);
        assert_eq!(six_two_byte_chars.len(), MIN_ADMIN_PASSWORD_CHARS);
        assert_eq!(six_two_byte_chars.chars().count(), 6);
        assert!(admit_admin_password(&six_two_byte_chars).is_err());
        for short in ["", "short", "elevenchar."] {
            assert!(
                admit_admin_password(short).is_err(),
                "{short:?} was admitted"
            );
        }
        assert_eq!("elevenchar.".chars().count(), MIN_ADMIN_PASSWORD_CHARS - 1);
    }
}

#[cfg(test)]
mod public_url_tests {
    use super::validate_public_url;

    #[test]
    fn public_url_requires_https_except_loopback_http() {
        for valid in [
            "https://drop.example.com",
            "https://drop.example.com/",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(validate_public_url(valid).is_ok(), "{valid} was refused");
        }
        for invalid in [
            "https://drop.example.com/base",
            "https://drop.example.com/base/",
            "https://drop.example.com/%2fbase",
            "http://drop.example.com",
            "ftp://drop.example.com",
            "https://user:pass@drop.example.com",
            "https://drop.example.com/base?tenant=acme",
            "https://drop.example.com/base#fragment",
            "https://",
            "http://192.0.2.1",
        ] {
            assert!(
                validate_public_url(invalid).is_err(),
                "{invalid} was accepted"
            );
        }
    }
}

#[cfg(test)]
mod push_tests {
    use super::{bearer_token, push_address};

    #[test]
    fn loopback_push_advertise_requires_a_loopback_bind() {
        for host in ["127.0.0.1", "localhost", "[::1]"] {
            let advertise = format!("{host}:8322");
            assert_eq!(
                push_address(
                    Some(advertise.clone()),
                    None,
                    "127.0.0.1:8322".parse().unwrap()
                )
                .unwrap(),
                advertise
            );
            let error = push_address(
                Some(advertise.clone()),
                None,
                "0.0.0.0:8322".parse().unwrap(),
            )
            .unwrap_err();
            assert!(error.contains("VOTPORT_PUSH_ADVERTISE"), "{error}");
            assert!(error.contains("VOTPORT_PUSH_BIND"), "{error}");
        }
        // Private non-loopback addresses stay allowed for multi-host LANs.
        assert!(push_address(
            Some("10.0.0.5:8322".to_owned()),
            None,
            "0.0.0.0:8322".parse().unwrap()
        )
        .is_ok());
    }

    #[test]
    fn bearer_token_env_refuses_the_digest_form() {
        for name in ["VOTPORT_SCIM_TOKEN", "VOTPORT_REPLICA_TOKEN"] {
            let error = bearer_token(name, Some("sha256:abc")).unwrap_err();
            assert!(error.contains(name), "{error}");
            assert!(error.contains("raw bearer token"), "{error}");
            assert!(error.contains("stored"), "{error}");
            assert_eq!(
                bearer_token(name, Some("raw-token")).unwrap().as_deref(),
                Some("raw-token")
            );
            assert!(bearer_token(name, None).unwrap().is_none());
        }
    }

    #[test]
    fn push_address_uses_the_public_host_and_udp_port() {
        assert_eq!(
            push_address(
                None,
                Some("https://drop.example.com/base"),
                "0.0.0.0:8322".parse().unwrap()
            )
            .unwrap(),
            "drop.example.com:8322"
        );
        assert_eq!(
            push_address(
                None,
                Some("https://[2001:db8::1]"),
                "[::]:8322".parse().unwrap()
            )
            .unwrap(),
            "[2001:db8::1]:8322"
        );
        assert_eq!(
            push_address(
                Some("push.example.net:9443".to_owned()),
                None,
                "0.0.0.0:8322".parse().unwrap()
            )
            .unwrap(),
            "push.example.net:9443"
        );
        assert!(push_address(None, None, "0.0.0.0:8322".parse().unwrap()).is_err());
        assert!(push_address(
            Some("push.example.net:8322".to_owned()),
            None,
            "127.0.0.1:0".parse().unwrap()
        )
        .is_err());
        for invalid in [
            "push.example.net",
            "push.example.net:0",
            "push.example.net:8322/",
            "push.example.net:9/path",
            "user@host:9",
        ] {
            assert!(
                push_address(
                    Some(invalid.to_owned()),
                    None,
                    "0.0.0.0:8322".parse().unwrap()
                )
                .is_err(),
                "{invalid} was accepted"
            );
        }
    }
}

#[cfg(test)]
mod cidr_tests {
    use super::IpCidr;

    #[test]
    fn blocks_match_only_their_own_range() {
        let single = IpCidr::parse("192.0.2.7/32").unwrap();
        assert!(single.contains(&"192.0.2.7".parse().unwrap()));
        assert!(!single.contains(&"192.0.2.8".parse().unwrap()));
        // The same peer arriving v4-mapped is the same peer.
        assert!(single.contains(&"::ffff:192.0.2.7".parse().unwrap()));

        let private = IpCidr::parse("172.16.0.0/12").unwrap();
        assert!(private.contains(&"172.16.0.1".parse().unwrap()));
        assert!(private.contains(&"172.31.255.255".parse().unwrap()));
        assert!(!private.contains(&"172.32.0.1".parse().unwrap()));
        assert!(!private.contains(&"203.0.113.9".parse().unwrap()));

        // A mapped network matches the unwrapped peer, in both notations.
        let mapped = IpCidr::parse("::ffff:192.0.2.7").unwrap();
        assert!(mapped.contains(&"192.0.2.7".parse().unwrap()));
        assert!(mapped.contains(&"::ffff:192.0.2.7".parse().unwrap()));
        assert!(!mapped.contains(&"192.0.2.8".parse().unwrap()));
        let mapped_block = IpCidr::parse("::ffff:192.0.2.0/120").unwrap();
        assert!(mapped_block.contains(&"192.0.2.9".parse().unwrap()));
        assert!(!mapped_block.contains(&"192.0.3.9".parse().unwrap()));

        let v6 = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(&"2001:db8:1:2::3".parse().unwrap()));
        assert!(!v6.contains(&"2001:db9::1".parse().unwrap()));
        // Families never match across.
        assert!(!v6.contains(&"192.0.2.7".parse().unwrap()));

        // A bare address is a full-length prefix.
        assert!(IpCidr::parse("127.0.0.1")
            .unwrap()
            .contains(&"127.0.0.1".parse().unwrap()));
        for bad in [
            "",
            "not-an-ip",
            "10.0.0.0/33",
            "2001:db8::/129",
            "10.0.0.0/x",
        ] {
            assert!(IpCidr::parse(bad).is_err(), "{bad} parsed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sso_session_bounds_are_explicit() {
        assert_eq!(MAX_SSO_SESSION_SECS, 31_536_000);
        assert!(valid_sso_session_secs(1));
        assert!(valid_sso_session_secs(31_536_000));
        assert!(!valid_sso_session_secs(0));
        assert!(!valid_sso_session_secs(31_536_001));
        assert!(!valid_sso_session_secs(u64::MAX));
    }

    #[test]
    fn known_environment_names_are_explicit() {
        for name in KNOWN_ENVIRONMENT_NAMES {
            assert!(is_known_environment_name(name), "{name}");
        }
        for name in [
            "VOTPORT_STORAGE_MEDIA_ACCESS_KEY_ID",
            "VOTPORT_STORAGE_MEDIA_SECRET_ACCESS_KEY",
            "VOTPORT_STORAGE_MEDIA_SESSION_TOKEN",
        ] {
            assert!(is_known_environment_name(name), "{name}");
        }
        let id_100 = "A".repeat(100);
        assert!(is_known_environment_name(&format!(
            "VOTPORT_STORAGE_{id_100}_ACCESS_KEY_ID"
        )));
        let id_101 = "A".repeat(101);
        assert!(!is_known_environment_name(&format!(
            "VOTPORT_STORAGE_{id_101}_ACCESS_KEY_ID"
        )));
        for name in [
            "VOTPORT_NOTIFY_SMTP_TO",
            "VOTPORT_STORAGE_MEDIA_ACCESS_KEY",
            "VOTPORT_STORAGE__SECRET_ACCESS_KEY",
            "VOTPORT_STORAGE_MEDIA_SESSION_TOKEN_EXTRA",
            "VOTPORT_STORAGE_media_ACCESS_KEY_ID",
            "VOTPORT_STORAGE_MEDIA-ARCHIVE_ACCESS_KEY_ID",
        ] {
            assert!(!is_known_environment_name(name), "{name}");
        }
    }

    fn test_password_hash(algorithm: argon2::Algorithm, version: argon2::Version) -> String {
        use argon2::password_hash::{PasswordHasher as _, SaltString};
        argon2::Argon2::new(
            algorithm,
            version,
            argon2::Params::new(8, 1, 1, Some(16)).unwrap(),
        )
        .hash_password(b"short", &SaltString::encode_b64(b"test salt").unwrap())
        .unwrap()
        .to_string()
    }

    #[test]
    fn startup_environment_refuses_unusable_urls_lifetimes_and_hashes() {
        if let Ok(expected) = env::var("VOTPORT_TEST_CONFIG_CASE") {
            match from_env() {
                Ok(config) => {
                    assert_eq!(expected, "valid", "{expected} was accepted");
                    assert!(crate::auth::verify_password(
                        "short",
                        &config.admin_password_hash
                    ));
                    assert!(config.session_idle_secs > 0);
                }
                Err(error) => assert!(expected != "valid" && error.contains(&expected), "{error}"),
            }
            return;
        }
        let hash = test_password_hash(argon2::Algorithm::Argon2id, argon2::Version::V0x13);
        let mut cases = vec![
            (
                "VOTPORT_PUBLIC_URL",
                "https://drop.example.com/base".to_owned(),
                false,
            ),
            (
                "VOTPORT_PUBLIC_URL",
                "https://drop.example.com/base/".to_owned(),
                false,
            ),
            (
                "VOTPORT_PUBLIC_URL",
                "https://drop.example.com/".to_owned(),
                true,
            ),
            (
                "VOTPORT_PUBLIC_URL",
                "http://127.0.0.1:8080".to_owned(),
                true,
            ),
            ("VOTPORT_SESSION_IDLE_SECS", "0".to_owned(), false),
            ("VOTPORT_SESSION_IDLE_SECS", "1".to_owned(), true),
            (
                "VOTPORT_SSO_SESSION_SECS",
                MAX_SSO_SESSION_SECS.to_string(),
                true,
            ),
            (
                "VOTPORT_SSO_SESSION_SECS",
                (MAX_SSO_SESSION_SECS + 1).to_string(),
                false,
            ),
            ("VOTPORT_SSO_SESSION_SECS", "0".to_owned(), false),
            ("VOTPORT_SSO_SESSION_SECS", u64::MAX.to_string(), false),
            (
                "VOTPORT_ADMIN_PASSWORD_HASH",
                "not-a-password-hash".to_owned(),
                false,
            ),
            ("VOTPORT_ADMIN_PASSWORD_HASH", "$argon2id".to_owned(), false),
            (
                "VOTPORT_ADMIN_PASSWORD_HASH",
                hash.rsplit_once('$').unwrap().0.to_owned(),
                false,
            ),
            (
                "VOTPORT_ADMIN_PASSWORD_HASH",
                hash.replace("argon2id", "scrypt"),
                false,
            ),
            (
                "VOTPORT_ADMIN_PASSWORD_HASH",
                hash.replace("v=19", "v=99"),
                false,
            ),
            (
                "VOTPORT_ADMIN_PASSWORD_HASH",
                hash.replace("$v=19", ""),
                true,
            ),
            (
                "VOTPORT_ADMIN_PASSWORD_HASH",
                hash.replace("m=8", "m=7"),
                false,
            ),
            (
                "VOTPORT_ADMIN_PASSWORD_HASH",
                hash.replace("t=1", "t=0"),
                false,
            ),
            (
                "VOTPORT_ADMIN_PASSWORD_HASH",
                hash.replace("p=1", "p=0"),
                false,
            ),
            ("VOTPORT_ADMIN_PASSWORD_HASH", format!("  {hash}\n"), true),
        ];
        for salt in ["c2FsdA", "abcdefghi"] {
            let mut parts: Vec<_> = hash.split('$').collect();
            parts[4] = salt;
            cases.push(("VOTPORT_ADMIN_PASSWORD_HASH", parts.join("$"), false));
        }
        for algorithm in [
            argon2::Algorithm::Argon2d,
            argon2::Algorithm::Argon2i,
            argon2::Algorithm::Argon2id,
        ] {
            for version in [argon2::Version::V0x10, argon2::Version::V0x13] {
                cases.push((
                    "VOTPORT_ADMIN_PASSWORD_HASH",
                    test_password_hash(algorithm, version),
                    true,
                ));
            }
        }
        let mut failures = Vec::new();
        for (key, value, valid) in cases {
            for push in [false, true] {
                let mut command = std::process::Command::new(env::current_exe().unwrap());
                command.args([
                    "--exact",
                    "config::tests::startup_environment_refuses_unusable_urls_lifetimes_and_hashes",
                    "--nocapture",
                ]);
                for (key, _) in
                    env::vars_os().filter(|(key, _)| key.to_string_lossy().starts_with("VOTPORT_"))
                {
                    command.env_remove(key);
                }
                command
                    .env(
                        "VOTPORT_TEST_CONFIG_CASE",
                        if valid { "valid" } else { key },
                    )
                    .env("VOTPORT_ADMIN_PASSWORD_HASH", &hash)
                    .env("VOTPORT_ADMIN_PASSWORD", "correct-horse-battery")
                    .env(key, &value);
                if push {
                    command
                        .env("VOTPORT_PUSH_BIND", "127.0.0.1:8322")
                        .env("VOTPORT_PUSH_ADVERTISE", "localhost:8322");
                }
                let output = command.output().unwrap();
                if !output.status.success() {
                    failures.push(format!(
                        "{key}, push={push}: {}{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn boolean_environment_settings_are_explicit() {
        const KEYS: [&str; 4] = [
            "VOTPORT_ALLOW_HIDDEN",
            "VOTPORT_PUBLIC_PASSWORD_LOGIN",
            "VOTPORT_SCIM_REQUIRE_PROVISIONING",
            "VOTPORT_NOTIFY_SMTP_STARTTLS",
        ];
        if let Ok(expected) = env::var("VOTPORT_TEST_BOOLEAN_CASE") {
            let config = from_env();
            if let Some(key) = expected.strip_prefix("reject:") {
                assert!(config.unwrap_err().contains(key));
            } else {
                let config = config.unwrap();
                let actual = [
                    config.allow_hidden,
                    config.public_password_login,
                    config.require_provisioning,
                    config.smtp_starttls,
                ];
                assert_eq!(
                    actual,
                    match expected.as_str() {
                        "default" => [false, true, false, true],
                        "true" => [true; 4],
                        "false" => [false; 4],
                        _ => panic!("unexpected boolean test case"),
                    }
                );
            }
            return;
        }
        let hash = test_password_hash(argon2::Algorithm::Argon2id, argon2::Version::V0x13);
        let child = |expected: &str| {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args([
                "--exact",
                "config::tests::boolean_environment_settings_are_explicit",
                "--nocapture",
            ]);
            for (key, _) in
                env::vars_os().filter(|(key, _)| key.to_string_lossy().starts_with("VOTPORT_"))
            {
                command.env_remove(key);
            }
            command
                .env("VOTPORT_TEST_BOOLEAN_CASE", expected)
                .env("VOTPORT_ADMIN_PASSWORD_HASH", &hash);
            command
        };
        let check = |mut command: std::process::Command| {
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        };
        check(child("default"));
        for (value, expected) in [
            ("1", "true"),
            ("true", "true"),
            (" YES ", "true"),
            ("On", "true"),
            ("0", "false"),
            ("false", "false"),
            (" NO ", "false"),
            ("Off", "false"),
        ] {
            let mut command = child(expected);
            for key in KEYS {
                command.env(key, value);
            }
            check(command);
        }
        for key in KEYS {
            for value in ["", " ", "enabled", "2"] {
                let mut command = child(&format!("reject:{key}"));
                command.env(key, value);
                check(command);
            }
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStringExt as _;
                let mut command = child(&format!("reject:{key}"));
                command.env(key, std::ffi::OsString::from_vec(vec![0xff]));
                check(command);
            }
        }
    }

    #[test]
    fn byte_counts_accept_suffixes() {
        assert_eq!(parse_bytes("536870912000").unwrap(), 536_870_912_000);
        assert_eq!(parse_bytes("500G").unwrap(), 500 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("500GB").unwrap(), 500 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("500GiB").unwrap(), 500 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("2mib").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_bytes("10MB").unwrap(), 10 * 1024 * 1024);
        assert_eq!(
            parse_bytes(" 50T ").unwrap(),
            50 * 1024u64 * 1024 * 1024 * 1024
        );
        assert!(parse_bytes("0").is_err());
        assert!(parse_bytes("0G").is_err());
        assert!(parse_bytes("").is_err());
        assert!(parse_bytes("500x").is_err());
        assert!(parse_bytes("-5").is_err());
        assert!(parse_bytes("G").is_err());
    }

    #[test]
    fn storage_roots_reject_nested_paths_and_allow_missing_siblings() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        let receive = directory.path().join("received");
        let outbound = directory.path().join("outbound");
        assert!(validate_storage_roots(&data, &receive, &outbound).is_ok());
        assert!(!data.exists());
        assert!(validate_storage_roots(&data, &receive, &data).is_err());
        assert!(validate_storage_roots(&data, &data.join("received"), &outbound).is_err());
        assert!(!data.exists());
    }

    #[cfg(unix)]
    #[test]
    fn storage_roots_reject_symlink_aliases() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        let alias = directory.path().join("received");
        let outbound = directory.path().join("outbound");
        std::fs::create_dir(&data).unwrap();
        symlink(&data, &alias).unwrap();
        assert!(validate_storage_roots(&data, &alias, &outbound).is_err());

        let future_data = directory.path().join("future-data");
        let future_alias = directory.path().join("future-received");
        symlink(&future_data, &future_alias).unwrap();
        assert!(validate_storage_roots(&future_data, &future_alias, &outbound).is_err());

        let target = directory.path().join("target");
        let target_child = target.join("child");
        let target_data = target.join("data");
        let target_link = directory.path().join("target-link");
        std::fs::create_dir_all(&target_child).unwrap();
        symlink(&target_child, &target_link).unwrap();
        let receive_via_link = target_link.join("../data");
        assert!(!target_data.exists());
        assert!(!receive_via_link.exists());
        let error = validate_storage_roots(&target_data, &receive_via_link, &outbound).unwrap_err();
        assert!(error.contains("VOTPORT_DATA_DIR"), "{error}");
        assert!(error.contains("VOTPORT_RECEIVE_DIR"), "{error}");
        assert!(validate_storage_roots(&target_data, &target.join("received"), &outbound).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn physical_root_projection_rejects_equal_and_nested_missing_aliases() {
        let projected = |identity, suffix: &[&str]| ResolvedStorageRoot {
            path: PathBuf::new(),
            ancestors: Vec::new(),
            anchor: StorageAnchor {
                identity,
                suffix: suffix.iter().map(std::ffi::OsString::from).collect(),
            },
        };
        assert!(storage_roots_share_physical_directory(
            &projected((7, 11), &["data"]),
            &projected((7, 11), &["data"]),
        ));
        assert!(storage_roots_share_physical_directory(
            &projected((7, 11), &["data"]),
            &projected((7, 11), &["data", "child"]),
        ));
        assert!(!storage_roots_share_physical_directory(
            &projected((7, 11), &["data"]),
            &projected((7, 11), &["received"]),
        ));
        assert!(!storage_roots_share_physical_directory(
            &projected((7, 11), &["data"]),
            &projected((7, 12), &["data"]),
        ));
        let existing = ResolvedStorageRoot {
            path: PathBuf::new(),
            ancestors: vec![(7, 11)],
            anchor: StorageAnchor {
                identity: (7, 11),
                suffix: Vec::new(),
            },
        };
        assert!(storage_roots_share_physical_directory(
            &existing,
            &projected((7, 11), &["data"]),
        ));
    }
}
