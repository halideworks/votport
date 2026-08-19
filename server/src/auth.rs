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
            std::fs::write(&path, secret).map_err(|error| error.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            Ok(secret)
        }
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
}

fn admin_mac(secret: &[u8; 32], expires: u64, nonce: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts 32-byte keys");
    mac.update(b"votport-admin\0");
    mac.update(expires.to_le_bytes().as_slice());
    mac.update(nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Issues an admin session token: `expires.nonce.mac`.
pub fn issue_admin_token(secret: &[u8; 32]) -> String {
    let expires = now_unix() + ADMIN_SESSION_SECS;
    let nonce = random_token();
    let mac = admin_mac(secret, expires, &nonce);
    format!("{expires}.{nonce}.{mac}")
}

pub fn verify_admin_token(secret: &[u8; 32], token: &str) -> bool {
    let mut parts = token.splitn(3, '.');
    let (Some(expires), Some(nonce), Some(mac)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Ok(expires) = expires.parse::<u64>() else {
        return false;
    };
    if now_unix() >= expires {
        return false;
    }
    let expected = admin_mac(secret, expires, nonce);
    constant_time_eq(expected.as_bytes(), mac.as_bytes())
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

/// Extracts a cookie value from a `Cookie` request header.
pub fn cookie_value<'header>(header: &'header str, name: &str) -> Option<&'header str> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}
