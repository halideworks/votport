//! Per-IP rate limit on upload-session creation.
//!
//! Password checks already throttle per IP, but a holder of a no-password
//! link could otherwise churn sessions to the global cap and evict the
//! sessions of legitimate senders. This caps session *creation* per client
//! IP; a session that finishes hands its budget back, so a sender shipping
//! one file per session is limited only by abandoned sessions.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Session creations allowed per IP per window.
const MAX_PER_WINDOW: usize = 20;
const WINDOW: Duration = Duration::from_secs(600);
/// Distinct IPs tracked before expired entries are swept (~100 bytes each).
const TABLE_CAP: usize = 4096;

pub struct SessionRate {
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
    max_per_window: usize,
}

impl Default for SessionRate {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRate {
    pub fn new() -> Self {
        Self::with_limit(MAX_PER_WINDOW)
    }

    pub fn with_limit(max_per_window: usize) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_per_window,
        }
    }

    /// Whether this IP may create another session now. Prunes this IP's
    /// expired entries on every call; entries for IPs that never return are
    /// dropped when the table hits its cap.
    pub fn allow(&self, ip: &str) -> bool {
        let mut attempts = self.attempts.lock().expect("session rate poisoned");
        let now = Instant::now();
        if attempts.len() >= TABLE_CAP {
            attempts.retain(|_, entries| {
                entries.retain(|at| now.duration_since(*at) < WINDOW);
                !entries.is_empty()
            });
            // A caller rotating addresses keeps every entry live, so the
            // sweep can free nothing. Evict the bucket whose newest attempt
            // is oldest rather than allowing the request untracked: an
            // untracked allow would turn a full table into a way to switch
            // this limit off entirely, which is what it exists to prevent.
            if attempts.len() >= TABLE_CAP && !attempts.contains_key(ip) {
                let victim = attempts
                    .iter()
                    .min_by_key(|(_, entries)| entries.iter().max().copied())
                    .map(|(key, _)| key.clone());
                if let Some(key) = victim {
                    attempts.remove(&key);
                }
            }
        }
        let entries = attempts.entry(ip.to_owned()).or_default();
        entries.retain(|at| now.duration_since(*at) < WINDOW);
        if entries.len() >= self.max_per_window {
            return false;
        }
        entries.push(now);
        true
    }

    /// Hands back one creation: the session finished, so it is no longer
    /// churn against the capacity limit.
    pub fn refund(&self, ip: &str) {
        let mut attempts = self.attempts.lock().expect("session rate poisoned");
        if let Some(entries) = attempts.get_mut(ip) {
            entries.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_cap_then_refuses() {
        let rate = SessionRate::with_limit(2);
        for _ in 0..2 {
            assert!(rate.allow("10.0.0.1"));
        }
        assert!(!rate.allow("10.0.0.1"));
        // Other IPs are unaffected.
        assert!(rate.allow("10.0.0.2"));
    }

    #[test]
    fn a_finished_session_hands_its_budget_back() {
        let rate = SessionRate::with_limit(2);
        for _ in 0..10 {
            assert!(rate.allow("10.0.0.1"));
            rate.refund("10.0.0.1");
        }
        assert!(rate.allow("10.0.0.1"));
        assert!(rate.allow("10.0.0.1"));
        assert!(!rate.allow("10.0.0.1"));
        // Refunding an untracked address is a no-op.
        rate.refund("10.0.0.9");
        assert!(!rate.allow("10.0.0.1"));
    }

    #[test]
    fn the_table_stops_growing_under_address_rotation() {
        let rate = SessionRate::new();
        for index in 0..(TABLE_CAP * 2) {
            assert!(rate.allow(&format!("10.9.{}.{}", index / 256, index % 256)));
        }
        let size = rate.attempts.lock().unwrap().len();
        assert!(size <= TABLE_CAP, "table grew to {size}");
        // A full table must not switch the limit off for new addresses.
        for _ in 0..MAX_PER_WINDOW {
            assert!(rate.allow("10.0.0.1"));
        }
        assert!(!rate.allow("10.0.0.1"), "still capped with a full table");
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
