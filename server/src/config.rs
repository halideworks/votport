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
    /// Peers whose `X-Forwarded-For` is believed, as CIDR blocks. Empty means
    /// the built-in default: loopback plus the private ranges. Naming the
    /// reverse proxy explicitly is what stops anything else that can reach
    /// the port from choosing its own throttle bucket.
    pub trusted_proxies: Vec<IpCidr>,
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

    let trusted_proxies = match optional("VOTPORT_TRUSTED_PROXIES") {
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
        None => Vec::new(),
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
        trusted_proxies,
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
