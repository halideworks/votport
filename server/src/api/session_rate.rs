//! Per-IP rate limit on upload-session creation.
//!
//! Password checks already throttle per IP, but a holder of a no-password
//! link could otherwise churn sessions to the global cap and evict the
//! sessions of legitimate senders. This caps session *creation* per client
//! IP well above human use.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Session creations allowed per IP per window.
const MAX_PER_WINDOW: usize = 20;
const WINDOW: Duration = Duration::from_secs(600);

pub struct SessionRate {
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
}

impl Default for SessionRate {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRate {
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Whether this IP may create another session now. Prunes expired
    /// entries on every call, so abandoned IPs leave no residue.
    pub fn allow(&self, ip: &str) -> bool {
        let mut attempts = self.attempts.lock().expect("session rate poisoned");
        let now = Instant::now();
        let entries = attempts.entry(ip.to_owned()).or_default();
        entries.retain(|at| now.duration_since(*at) < WINDOW);
        if entries.len() >= MAX_PER_WINDOW {
            return false;
        }
        entries.push(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_cap_then_refuses() {
        let rate = SessionRate::new();
        for _ in 0..MAX_PER_WINDOW {
            assert!(rate.allow("10.0.0.1"));
        }
        assert!(!rate.allow("10.0.0.1"));
        // Other IPs are unaffected.
        assert!(rate.allow("10.0.0.2"));
    }

    #[test]
    fn expired_entries_free_budget() {
        let rate = SessionRate::new();
        {
            let mut attempts = rate.attempts.lock().unwrap();
            attempts.insert(
                "10.0.0.1".to_owned(),
                vec![
                    Instant::now() - WINDOW - Duration::from_secs(1),
                    Instant::now() - WINDOW - Duration::from_secs(2),
                ],
            );
        }
        assert!(rate.allow("10.0.0.1"));
        let attempts = rate.attempts.lock().unwrap();
        assert_eq!(attempts.get("10.0.0.1").map(Vec::len), Some(1));
    }
}
