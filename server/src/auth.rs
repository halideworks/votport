//! Passwords (argon2id) and stateless signed admin sessions.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::Argon2;
use hmac::{Hmac, Mac as _};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
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

/// One tenant the principal may act in, with its role.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TenantGrant {
    /// "" is the default tenant.
    pub tenant: String,
    /// "admin" (full control) or "viewer" (read-only dashboard).
    pub role: String,
}

fn cv_one() -> u64 {
    1
}

/// The principal an admin session cookie stands for: who, which tenants it
/// may act in, and the one it is currently acting in. Local sign-ins use the
/// default tenant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminIdentity {
    pub subject: String,
    /// The active tenant namespace ("" = default).
    pub tenant: String,
    /// Role within the active tenant ("admin" or "viewer").
    pub role: String,
    /// Every (tenant, role) this principal may switch into.
    #[serde(default)]
    pub grants: Vec<TenantGrant>,
    #[serde(rename = "cv", default = "cv_one")]
    pub credential_version: u64,
}

impl AdminIdentity {
    pub fn local_admin() -> Self {
        Self {
            subject: "local".to_owned(),
            tenant: String::new(),
            role: "admin".to_owned(),
            grants: vec![TenantGrant {
                tenant: String::new(),
                role: "admin".to_owned(),
            }],
            credential_version: 1,
        }
    }
}

fn identity_payload(id: &AdminIdentity) -> String {
    serde_json::to_string(id).expect("AdminIdentity is serde-json")
}

fn admin_mac(secret: &[u8; 32], payload: &str, version: &str, expires: u64, nonce: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts 32-byte keys");
    for part in [
        b"votport-admin-v3".as_slice(),
        payload.as_bytes(),
        version.as_bytes(),
    ] {
        mac.update(part);
        mac.update(b"\0");
    }
    mac.update(expires.to_le_bytes().as_slice());
    mac.update(nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Issues an admin session token bound to the full grant set AND the
/// credential version: changing the password (or rotating the environment
/// credential) invalidates every outstanding session, while SSO identities
/// carry their own subjects, tenants and roles.
pub fn issue_admin_token(secret: &[u8; 32], id: &AdminIdentity, version: &str) -> String {
    let expires = now_unix() + ADMIN_SESSION_SECS;
    let nonce = random_token();
    let payload = identity_payload(id);
    let mac = admin_mac(secret, &payload, version, expires, &nonce);
    format!(
        "{expires}.{}.{}.{}",
        hex::encode(payload.as_bytes()),
        nonce,
        mac
    )
}

/// Verifies an admin token and returns its identity. None when anything at
/// all fails to match: wrong MAC, expired, malformed.
pub fn verify_admin_token(secret: &[u8; 32], version: &str, token: &str) -> Option<AdminIdentity> {
    let parts: Vec<&str> = token.split('.').collect();
    let [expires, payload_hex, nonce, mac] = parts.as_slice() else {
        return None;
    };
    let Ok(expires) = expires.parse::<u64>() else {
        return None;
    };
    if now_unix() >= expires {
        return None;
    }
    let payload = hex::decode(payload_hex).ok()?;
    let payload = String::from_utf8(payload).ok()?;
    let expected = admin_mac(secret, &payload, version, expires, nonce);
    if !constant_time_eq(expected.as_bytes(), mac.as_bytes()) {
        return None;
    }
    serde_json::from_str(&payload).ok()
}

#[cfg(test)]
pub fn issue_admin_token_from_payload(secret: &[u8; 32], payload: &str, version: &str) -> String {
    let expires = now_unix() + ADMIN_SESSION_SECS;
    let nonce = random_token();
    let mac = admin_mac(secret, payload, version, expires, &nonce);
    format!(
        "{expires}.{}.{}.{}",
        hex::encode(payload.as_bytes()),
        nonce,
        mac
    )
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

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    hex::decode(text).ok()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq(a, b)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Global failure counter with a lockout. Its one user is the password-change
/// endpoint, which is reachable only with a valid session, so a global bound
/// there cannot be used to deny anyone. Sign-in deliberately has no counter
/// like this: a global refusal is how the break-glass credential got denied.
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

    /// Claims one attempt, counting it before it is checked. See
    /// [`IpThrottle::claim`]: checking and then recording lets any number of
    /// concurrent attempts through together, which turns the threshold into a
    /// limit per batch the caller can open.
    pub fn claim(&self) -> bool {
        let mut state = self.state.lock().expect("throttle poisoned");
        if state.1.is_some_and(|until| Instant::now() < until) {
            return false;
        }
        state.0 += 1;
        if state.0 >= LOCKOUT_THRESHOLD {
            state.1 = Some(Instant::now() + Duration::from_secs(LOCKOUT_SECS));
            state.0 = 0;
        }
        true
    }

    /// Clears the claims after a correct password.
    pub fn succeeded(&self) {
        *self.state.lock().expect("throttle poisoned") = (0, None);
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

    /// Claims one attempt for `ip`, counting it as a failure up front, and
    /// reports whether it may proceed. Checking `locked` and recording the
    /// outcome afterwards leaves a window where any number of concurrent
    /// attempts pass the check together, so the five-per-window limit becomes
    /// a limit per connection count instead. Call [`Self::succeeded`] to
    /// clear the claim when the password turns out to be right.
    pub fn claim(&self, ip: &str) -> bool {
        let mut state = self.state.lock().expect("throttle poisoned");
        if state.get(ip).is_some_and(|entry| {
            entry
                .locked_until
                .is_some_and(|until| Instant::now() < until)
        }) {
            return false;
        }
        Self::evict_if_full(&mut state, ip);
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
        true
    }

    /// Clears a claim after a correct password.
    pub fn succeeded(&self, ip: &str) {
        self.state.lock().expect("throttle poisoned").remove(ip);
    }

    /// Frees a slot when the table is at cap, so a caller rotating addresses
    /// cannot grow it without bound. Live lockouts are evicted only when
    /// nothing else can be, which costs an attacker a full set of failures.
    fn evict_if_full(state: &mut std::collections::HashMap<String, IpState>, ip: &str) {
        if state.len() >= IP_TABLE_CAP {
            // Evict dead weight first: expired, idle entries. A live lockout
            // is only ever evicted by the fallback below, when every entry
            // holds one and there is nothing else to free.
            let now = Instant::now();
            state.retain(|_, entry| {
                entry.locked_until.is_some_and(|until| now < until)
                    || now.duration_since(entry.last_seen).as_secs() < IP_ENTRY_TTL_SECS
            });
            // A caller rotating addresses keeps every entry fresh, so the
            // sweep above can free nothing. Evict the least recently seen
            // entry that is not serving a lockout, rather than declining to
            // track the new key: not tracking it would turn a full table into
            // a way to switch throttling off for every new address. If every
            // entry holds a live lockout the table is doing its job and the
            // new key waits.
            if state.len() >= IP_TABLE_CAP && !state.contains_key(ip) {
                let now = Instant::now();
                let victim = state
                    .iter()
                    .filter(|(_, entry)| !entry.locked_until.is_some_and(|until| now < until))
                    .min_by_key(|(_, entry)| entry.last_seen)
                    .map(|(key, _)| key.clone());
                let victim = victim.or_else(|| {
                    // Every entry holds a live lockout. Evict the one closest
                    // to expiring rather than declining to track this key:
                    // declining is how a full table becomes a way to switch
                    // throttling off.
                    state
                        .iter()
                        .min_by_key(|(_, entry)| entry.locked_until)
                        .map(|(key, _)| key.clone())
                });
                if let Some(key) = victim {
                    state.remove(&key);
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_global_counter_also_counts_before_it_checks() {
        let throttle = LoginThrottle::new();
        // The password-change endpoint verifies a password for a caller that
        // already holds a session. Counting only on the way out would let one
        // batch of concurrent guesses through per lockout.
        for index in 0..LOCKOUT_THRESHOLD {
            assert!(throttle.claim(), "claim {index} refused early");
        }
        assert!(!throttle.claim(), "the sixth concurrent claim");
        assert!(throttle.locked());
        throttle.succeeded();
        assert!(!throttle.locked());
        assert!(throttle.claim());
    }

    #[test]
    fn concurrent_attempts_cannot_outrun_the_counter() {
        let throttle = IpThrottle::new();
        // Every attempt is counted as it starts, so five claims exhaust the
        // budget whether or not any of them has finished verifying. Checking
        // locked() and recording afterwards would let all of these through.
        for index in 0..LOCKOUT_THRESHOLD {
            assert!(throttle.claim("10.0.0.1"), "claim {index} refused early");
        }
        assert!(!throttle.claim("10.0.0.1"), "the sixth concurrent claim");
        assert!(throttle.locked("10.0.0.1"));
        // A correct password clears the claims it made.
        throttle.succeeded("10.0.0.1");
        assert!(!throttle.locked("10.0.0.1"));
        assert!(throttle.claim("10.0.0.1"));
    }

    #[test]
    fn the_ip_table_stops_growing_and_keeps_live_lockouts() {
        let throttle = IpThrottle::new();
        // Lock one address, then flood with fresh keys the sweep cannot evict.
        for _ in 0..LOCKOUT_THRESHOLD {
            throttle.claim("10.0.0.1");
        }
        assert!(throttle.locked("10.0.0.1"));
        for index in 0..(IP_TABLE_CAP * 2) {
            throttle.claim(&format!("10.9.{}.{}", index / 256, index % 256));
        }
        let size = throttle.state.lock().unwrap().len();
        assert!(size <= IP_TABLE_CAP, "table grew to {size}");
        assert!(throttle.locked("10.0.0.1"), "the live lockout survived");
        // A full table must not switch throttling off for new addresses.
        for _ in 0..LOCKOUT_THRESHOLD {
            throttle.claim("10.0.0.2");
        }
        assert!(
            throttle.locked("10.0.0.2"),
            "a new address is still throttled once the table is full"
        );
    }

    #[test]
    fn payload_without_cv_deserializes_as_one() {
        let secret = [3u8; 32];
        let payload = serde_json::json!({
            "subject": "user@example.com",
            "tenant": "",
            "role": "admin",
            "grants": []
        })
        .to_string();
        let token = issue_admin_token_from_payload(&secret, &payload, "v");
        let identity = verify_admin_token(&secret, "v", &token).unwrap();
        assert_eq!(identity.credential_version, 1);
        assert_eq!(identity.subject, "user@example.com");
        assert!(!payload.contains("cv"));
    }
}
