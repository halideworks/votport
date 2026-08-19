//! Environment-driven configuration.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    /// Address the HTTP server binds to.
    pub bind: SocketAddr,
    /// Directory holding votport state (state.json, secret).
    pub data_dir: PathBuf,
    /// Root directory received files are published into.
    pub receive_dir: PathBuf,
    /// Directory holding the static web assets.
    pub web_root: PathBuf,
    /// Argon2 PHC hash of the admin password.
    pub admin_password_hash: String,
    /// Public base URL (e.g. "https://drop.example.com"); used to render
    /// links in the admin UI and to decide whether cookies are `Secure`.
    pub public_url: Option<String>,
    /// Hard cap on the total bytes of a single upload session.
    pub max_upload_bytes: u64,
    /// Allow uploaded file names whose components start with a dot.
    pub allow_hidden: bool,
    /// Seconds an upload session may sit idle before it is discarded.
    pub session_idle_secs: u64,
}

const DEFAULT_MAX_UPLOAD_BYTES: u64 = 50 * 1024 * 1024 * 1024; // 50 GiB

pub fn from_env() -> Result<Config, String> {
    let bind = env_or("VOTPORT_BIND", "0.0.0.0:8080")
        .parse()
        .map_err(|error| format!("VOTPORT_BIND is not a socket address: {error}"))?;
    let data_dir = PathBuf::from(env_or("VOTPORT_DATA_DIR", "/data"));
    let receive_dir = PathBuf::from(env_or("VOTPORT_RECEIVE_DIR", "/received"));
    let web_root = PathBuf::from(env_or("VOTPORT_WEB_ROOT", "./web"));

    let admin_password_hash = match env::var("VOTPORT_ADMIN_PASSWORD_HASH") {
        Ok(hash) if !hash.trim().is_empty() => hash.trim().to_owned(),
        _ => match env::var("VOTPORT_ADMIN_PASSWORD") {
            Ok(password) if !password.is_empty() => crate::auth::hash_password(&password)
                .map_err(|error| format!("failed to hash admin password: {error}"))?,
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
        Ok(value) => value
            .parse()
            .map_err(|error| format!("VOTPORT_MAX_UPLOAD_BYTES: {error}"))?,
        Err(_) => DEFAULT_MAX_UPLOAD_BYTES,
    };

    let allow_hidden = env::var("VOTPORT_ALLOW_HIDDEN").is_ok_and(|value| value == "1");

    let session_idle_secs = match env::var("VOTPORT_SESSION_IDLE_SECS") {
        Ok(value) => value
            .parse()
            .map_err(|error| format!("VOTPORT_SESSION_IDLE_SECS: {error}"))?,
        Err(_) => 1800,
    };

    Ok(Config {
        bind,
        data_dir,
        receive_dir,
        web_root,
        admin_password_hash,
        public_url,
        max_upload_bytes,
        allow_hidden,
        session_idle_secs,
    })
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_owned())
}
