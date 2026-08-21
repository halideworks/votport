//! Passwords (argon2id) and stateless signed admin sessions.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::Argon2;
use hmac::{Hmac, Mac as _};
use rand::RngCore as _;
use sha2::Sha256;

use crate::store::now_unix;

const ADMIN_SESSION_SECS: u64 = 7 * 24 * 3600;
const LOCKOUT_THRESHOLD: u32 = 5;
const LOCKOUT_SECS: u64 = 60;

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| error.to_string())
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Loads or creates the 32-byte cookie-signing secret in the data directory.
pub fn load_secret(data_dir: &std::path::Path) -> Result<[u8; 32], String> {
    let path = data_dir.join("secret");
    match std::fs::read(&path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            Ok(secret)
        }
        Ok(_) => Err(format!("{} is not a 32-byte secret", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut secret = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut secret);
            write_private(&path, &secret).map_err(|error| error.to_string())?;
            Ok(secret)
        }
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
}

/// Creates a file readable only by its owner from the first instant: writing
/// with default permissions and tightening afterwards leaves a window where
/// the secret is world-readable on disk.
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn token_mac(secret: &[u8; 32], context: &[&[u8]], expires: u64, nonce: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts 32-byte keys");
    for part in context {
        mac.update(part);
        mac.update(b"\0");
    }
    mac.update(expires.to_le_bytes().as_slice());
    mac.update(nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn issue_token(secret: &[u8; 32], context: &[&[u8]], lifetime_secs: u64) -> String {
    let expires = now_unix() + lifetime_secs;
    let nonce = random_token();
    let mac = token_mac(secret, context, expires, &nonce);
    format!("{expires}.{nonce}.{mac}")
}

fn verify_token(secret: &[u8; 32], context: &[&[u8]], token: &str) -> bool {
    let mut parts = token.splitn(3, '.');
    let (Some(expires), Some(nonce), Some(mac)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let Ok(expires) = expires.parse::<u64>() else {
        return false;
    };
    if now_unix() >= expires {
        return false;
    }
    let expected = token_mac(secret, context, expires, nonce);
    constant_time_eq(expected.as_bytes(), mac.as_bytes())
}

/// Issues an admin session token: `expires.nonce.mac`. The MAC covers the
/// stored password hash, so changing the password via the UI invalidates
/// every outstanding session. `phc` is the stored hash or empty when the
/// password still comes from the environment; the env-derived hash is salted
/// fresh each boot and would otherwise log the admin out on every restart.
pub fn issue_admin_token(secret: &[u8; 32], phc: &str) -> String {
    issue_token(
        secret,
        &[b"votport-admin", phc.as_bytes()],
        ADMIN_SESSION_SECS,
    )
}

pub fn verify_admin_token(secret: &[u8; 32], phc: &str, token: &str) -> bool {
    verify_token(secret, &[b"votport-admin", phc.as_bytes()], token)
}

const LINK_SESSION_SECS: u64 = 30 * 24 * 3600;

/// Issues a link access token proving the link password was verified once.
/// The MAC covers the link's password hash, so replacing the link (or its
/// password) invalidates outstanding cookies.
pub fn issue_link_token(secret: &[u8; 32], link_id: &str, phc: &str) -> String {
    issue_token(
        secret,
        &[b"votport-link", link_id.as_bytes(), phc.as_bytes()],
        LINK_SESSION_SECS,
    )
}

pub fn verify_link_token(secret: &[u8; 32], link_id: &str, phc: &str, token: &str) -> bool {
    verify_token(
        secret,
        &[b"votport-link", link_id.as_bytes(), phc.as_bytes()],
        token,
    )
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Global login throttle: after repeated failures every login pauses briefly.
pub struct LoginThrottle {
    state: Mutex<(u32, Option<Instant>)>,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self {
            state: Mutex::new((0, None)),
        }
    }

    pub fn locked(&self) -> bool {
        let state = self.state.lock().expect("throttle poisoned");
        state.1.is_some_and(|until| Instant::now() < until)
    }

    pub fn record(&self, success: bool) {
        let mut state = self.state.lock().expect("throttle poisoned");
        if success {
            *state = (0, None);
        } else {
            state.0 += 1;
            if state.0 >= LOCKOUT_THRESHOLD {
                state.1 = Some(Instant::now() + Duration::from_secs(LOCKOUT_SECS));
                state.0 = 0;
            }
        }
    }
}

/// Per-IP throttle for link password checks. The global [`LoginThrottle`]
/// stays admin-only: sharing it with public links let anyone holding a link
/// URL lock the admin out with five bad guesses.
struct IpState {
    failures: u32,
    locked_until: Option<Instant>,
    last_seen: Instant,
}

/// Entries idle this long carry no lockout and stale failure counts; they are
/// evicted when the table needs room.
const IP_ENTRY_TTL_SECS: u64 = 600;
const IP_TABLE_CAP: usize = 4096;

impl IpThrottle {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn locked(&self, ip: &str) -> bool {
        let state = self.state.lock().expect("throttle poisoned");
        state.get(ip).is_some_and(|entry| {
            entry
                .locked_until
                .is_some_and(|until| Instant::now() < until)
        })
    }

    pub fn record(&self, ip: &str, success: bool) {
        let mut state = self.state.lock().expect("throttle poisoned");
        if state.len() >= IP_TABLE_CAP {
            // Evict only dead weight: expired, idle entries. Live lockouts
            // survive, so filling the table cannot reset anyone's penalty.
            let now = Instant::now();
            state.retain(|_, entry| {
                entry.locked_until.is_some_and(|until| now < until)
                    || now.duration_since(entry.last_seen).as_secs() < IP_ENTRY_TTL_SECS
            });
        }
        if success {
            state.remove(ip);
            return;
        }
        let entry = state.entry(ip.to_owned()).or_insert(IpState {
            failures: 0,
            locked_until: None,
            last_seen: Instant::now(),
        });
        entry.last_seen = Instant::now();
        entry.failures += 1;
        if entry.failures >= LOCKOUT_THRESHOLD {
            entry.locked_until = Some(Instant::now() + Duration::from_secs(LOCKOUT_SECS));
            entry.failures = 0;
        }
    }
}

pub struct IpThrottle {
    state: Mutex<std::collections::HashMap<String, IpState>>,
}

impl Default for IpThrottle {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracts a cookie value from a `Cookie` request header.
pub fn cookie_value<'header>(header: &'header str, name: &str) -> Option<&'header str> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}
