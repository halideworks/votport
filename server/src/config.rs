//! Environment-driven configuration.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    /// Address the HTTP server binds to.
    pub bind: SocketAddr,
    /// Directory holding votport state (votport.db, secret).
    pub data_dir: PathBuf,
    /// Root directory received files are published into.
    pub receive_dir: PathBuf,
    /// Directory holding the static web assets.
    pub web_root: PathBuf,
    /// Argon2 PHC hash of the admin password.
    pub admin_password_hash: String,
    /// Stable tag for the environment-provided admin credential, bound into
    /// session token MACs so rotating the env password (or env hash) evicts
    /// sessions while a plain restart does not. The argon2 hash above cannot
    /// serve: it is salted fresh each boot.
    pub admin_token_tag: String,
    /// Webhook URL POSTed a JSON summary when an upload completes.
    pub notify_webhook: Option<String>,
    /// ntfy topic URL (e.g. "https://ntfy.sh/mytopic") for upload notices.
    pub notify_ntfy: Option<String>,
    /// Bearer token for the ntfy topic, if it needs one.
    pub notify_ntfy_token: Option<String>,
    /// Pushover application token + user key for upload notices.
    pub notify_pushover: Option<(String, String)>,
    /// SMTP host for upload-complete mail. Assembled with from/to at resolve.
    pub smtp_host: Option<String>,
    /// SMTP port. Default 587. Port 465 uses implicit TLS.
    pub smtp_port: u16,
    /// When true, use STARTTLS on ports other than 465. Default true.
    pub smtp_starttls: bool,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_from: Option<String>,
    /// Comma-separated recipient addresses.
    pub smtp_to: Option<String>,
    /// Public base URL (e.g. "https://drop.example.com"); used to render
    /// links in the admin UI and to decide whether cookies are `Secure`.
    pub public_url: Option<String>,
    /// Hard cap on the total bytes of a single upload session.
    pub max_upload_bytes: u64,
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
    /// When set, /metrics requires this bearer token.
    pub metrics_token: Option<String>,
    /// OIDC single sign-on for the admin dashboard. None when unset.
    pub oidc: Option<OidcConfig>,
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
}

const DEFAULT_MAX_UPLOAD_BYTES: u64 = 50 * 1024 * 1024 * 1024; // 50 GiB

/// Shortest admin password this build considers reasonable. Enforced on
/// anything set through the UI; only warned about for the environment
/// credential, which may predate the check.
pub const MIN_ADMIN_PASSWORD_CHARS: usize = 12;

pub fn from_env() -> Result<Config, String> {
    let bind = env_or("VOTPORT_BIND", "0.0.0.0:8080")
        .parse()
        .map_err(|error| format!("VOTPORT_BIND is not a socket address: {error}"))?;
    let data_dir = PathBuf::from(env_or("VOTPORT_DATA_DIR", "/data"));
    let receive_dir = PathBuf::from(env_or("VOTPORT_RECEIVE_DIR", "/received"));
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
                // Warned, not refused: refusing would strand a deployment
                // whose credential predates this check. admin_change_password
                // enforces the same minimum on anything set through the UI.
                if password.chars().count() < MIN_ADMIN_PASSWORD_CHARS {
                    tracing::warn!(
                        "VOTPORT_ADMIN_PASSWORD is shorter than {MIN_ADMIN_PASSWORD_CHARS} \
                         characters; sign-in throttling bounds guessing but a short \
                         break-glass password is the weakest part of this deployment"
                    );
                }
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

    let public_url = env::var("VOTPORT_PUBLIC_URL")
        .ok()
        .map(|url| url.trim_end_matches('/').to_owned())
        .filter(|url| !url.is_empty());

    let max_upload_bytes = match env::var("VOTPORT_MAX_UPLOAD_BYTES") {
        Ok(value) => {
            parse_bytes(&value).map_err(|error| format!("VOTPORT_MAX_UPLOAD_BYTES: {error}"))?
        }
        Err(_) => DEFAULT_MAX_UPLOAD_BYTES,
    };

    let allow_hidden = env::var("VOTPORT_ALLOW_HIDDEN").is_ok_and(|value| value == "1");

    let optional = |name: &str| env::var(name).ok().filter(|value| !value.trim().is_empty());
    let upload_retention_days = match env::var("VOTPORT_UPLOAD_RETENTION_DAYS") {
        Ok(value) => value
            .parse()
            .map_err(|error| format!("VOTPORT_UPLOAD_RETENTION_DAYS: {error}"))?,
        Err(_) => 0,
    };
    let metrics_token = optional("VOTPORT_METRICS_TOKEN");

    let audit_retention_days = match env::var("VOTPORT_AUDIT_RETENTION_DAYS") {
        Ok(value) => value
            .parse()
            .map_err(|error| format!("VOTPORT_AUDIT_RETENTION_DAYS: {error}"))?,
        Err(_) => 400,
    };

    let default_max_total_bytes = optional_positive_u64("VOTPORT_DEFAULT_MAX_TOTAL_BYTES")?;
    let default_max_links = optional_positive_u64("VOTPORT_DEFAULT_MAX_LINKS")?;
    let default_max_sessions = optional_positive_u64("VOTPORT_DEFAULT_MAX_SESSIONS")?;
    let public_password_login = env::var("VOTPORT_PUBLIC_PASSWORD_LOGIN")
        .ok()
        .is_none_or(|value| value != "0");

    let session_idle_secs = match env::var("VOTPORT_SESSION_IDLE_SECS") {
        Ok(value) => value
            .parse()
            .map_err(|error| format!("VOTPORT_SESSION_IDLE_SECS: {error}"))?,
        Err(_) => 1800,
    };

    let notify_pushover = match (
        optional("VOTPORT_NOTIFY_PUSHOVER_TOKEN"),
        optional("VOTPORT_NOTIFY_PUSHOVER_USER"),
    ) {
        (Some(token), Some(user)) => Some((token, user)),
        (None, None) => None,
        _ => {
            return Err(
                "set both VOTPORT_NOTIFY_PUSHOVER_TOKEN and VOTPORT_NOTIFY_PUSHOVER_USER, \
                 or neither"
                    .to_owned(),
            );
        }
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
    let smtp_starttls = env::var("VOTPORT_NOTIFY_SMTP_STARTTLS")
        .ok()
        .is_none_or(|value| value != "0");

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
            Some(OidcConfig {
                issuer,
                client_id,
                client_secret,
                admin_group,
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

    Ok(Config {
        bind,
        data_dir,
        receive_dir,
        web_root,
        admin_password_hash,
        admin_token_tag,
        notify_webhook: optional("VOTPORT_NOTIFY_WEBHOOK_URL"),
        notify_ntfy: optional("VOTPORT_NOTIFY_NTFY_URL"),
        notify_ntfy_token: optional("VOTPORT_NOTIFY_NTFY_TOKEN"),
        notify_pushover,
        smtp_host: optional("VOTPORT_NOTIFY_SMTP_HOST"),
        smtp_port,
        smtp_starttls,
        smtp_username: optional("VOTPORT_NOTIFY_SMTP_USERNAME"),
        smtp_password: optional("VOTPORT_NOTIFY_SMTP_PASSWORD"),
        smtp_from: optional("VOTPORT_NOTIFY_SMTP_FROM"),
        smtp_to: optional("VOTPORT_NOTIFY_SMTP_TO"),
        public_url,
        max_upload_bytes,
        allow_hidden,
        session_idle_secs,
        audit_retention_days,
        upload_retention_days,
        default_max_total_bytes,
        default_max_links,
        default_max_sessions,
        public_password_login,
        metrics_token,
        oidc,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
