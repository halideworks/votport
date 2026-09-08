//! Per-IP rate limit on upload-session creation.
//!
//! Password checks already throttle per IP, but a holder of a no-password
//! link could otherwise churn sessions to the global cap and evict the
//! sessions of legitimate senders. This caps session *creation* per client
//! IP; a session that finishes hands its budget back, so a sender shipping
//! drop after drop is limited only by abandoned sessions.

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

/// Per-grant outbound request budget. A whole delivery preparation or a
/// single-file grant costs one full unit; one request for a file in a
/// multi-file grant costs one divided by that grant's file count. The
/// fixed-point bucket keeps that accounting bounded for very large grants.
pub struct DownloadRate {
    buckets: Mutex<HashMap<String, DownloadBucket>>,
}

struct DownloadBucket {
    /// Credits multiplied by `WINDOW_NANOS`, so refills need no floating point.
    tokens: u128,
    last: Instant,
    /// Loaded once for an individual-file grant and reused for every index.
    file_count: Option<usize>,
}

const DOWNLOAD_CAPACITY: u128 = 2_000;
const DOWNLOAD_WINDOW: Duration = Duration::from_secs(600);
const DOWNLOAD_WINDOW_NANOS: u128 = 600_000_000_000;
const DOWNLOAD_SCALE: u128 = 1_000_000;
const DOWNLOAD_TABLE_CAP: usize = 4096;
const DOWNLOAD_MAX_TOKENS: u128 = DOWNLOAD_CAPACITY * DOWNLOAD_SCALE * DOWNLOAD_WINDOW_NANOS;

impl Default for DownloadRate {
    fn default() -> Self {
        Self::new()
    }
}

impl DownloadRate {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Charges one full-grant equivalent, for a legacy file, batch, bundle,
    /// or fetch preparation.
    pub fn allow(&self, key: &str) -> bool {
        self.allow_at(key, DOWNLOAD_SCALE, None, Instant::now())
    }

    /// Charges one divided by the immutable file count. The loader runs only
    /// on a cache miss and outside the bucket mutex; a second lock check in
    /// `allow_at` handles two first requests racing for the same grant.
    pub fn allow_individual<F, E>(&self, key: &str, load_count: F) -> Result<bool, E>
    where
        F: FnOnce() -> Result<usize, E>,
    {
        self.allow_individual_at(key, load_count, Instant::now())
    }

    fn allow_individual_at<F, E>(&self, key: &str, load_count: F, now: Instant) -> Result<bool, E>
    where
        F: FnOnce() -> Result<usize, E>,
    {
        let cached = self
            .buckets
            .lock()
            .expect("download rate poisoned")
            .get(key)
            .and_then(|bucket| bucket.file_count);
        let file_count = match cached {
            Some(count) => count,
            None => load_count()?.max(1),
        };
        let cost = DOWNLOAD_SCALE.div_ceil(file_count as u128);
        Ok(self.allow_at(key, cost, Some(file_count), now))
    }

    fn allow_at(&self, key: &str, cost: u128, file_count: Option<usize>, now: Instant) -> bool {
        let cost = cost.saturating_mul(DOWNLOAD_WINDOW_NANOS);
        let mut buckets = self.buckets.lock().expect("download rate poisoned");
        if !buckets.contains_key(key) {
            buckets
                .retain(|_, bucket| now.saturating_duration_since(bucket.last) < DOWNLOAD_WINDOW);
            if buckets.len() >= DOWNLOAD_TABLE_CAP {
                let victim = buckets
                    .iter()
                    .min_by_key(|(_, bucket)| bucket.last)
                    .map(|(key, _)| key.clone());
                if let Some(victim) = victim {
                    buckets.remove(&victim);
                }
            }
            buckets.insert(
                key.to_owned(),
                DownloadBucket {
                    tokens: DOWNLOAD_MAX_TOKENS,
                    last: now,
                    file_count,
                },
            );
        }
        let bucket = buckets.get_mut(key).expect("download bucket inserted");
        let elapsed = now.saturating_duration_since(bucket.last).as_nanos();
        let refill = elapsed.saturating_mul(DOWNLOAD_CAPACITY * DOWNLOAD_SCALE);
        bucket.tokens = bucket
            .tokens
            .saturating_add(refill)
            .min(DOWNLOAD_MAX_TOKENS);
        bucket.last = bucket.last.max(now);
        if bucket.file_count.is_none() {
            bucket.file_count = file_count;
        }
        if bucket.tokens < cost {
            return false;
        }
        bucket.tokens -= cost;
        true
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

    #[test]
    fn one_hundred_thousand_files_cost_one_full_grant() {
        let rate = DownloadRate::new();
        let now = Instant::now();
        let mut loads = 0;
        for _ in 0..100_000 {
            assert!(rate
                .allow_individual_at(
                    "grant",
                    || {
                        loads += 1;
                        Ok::<_, ()>(100_000)
                    },
                    now,
                )
                .unwrap());
        }
        assert_eq!(loads, 1);
        for _ in 0..(DOWNLOAD_CAPACITY as usize - 1) {
            assert!(rate.allow_at("grant", DOWNLOAD_SCALE, None, now));
        }
        assert!(!rate.allow_at("grant", DOWNLOAD_SCALE, None, now));
    }

    #[test]
    fn single_file_and_batch_costs_exhaust_the_window_budget() {
        let rate = DownloadRate::new();
        let now = Instant::now();
        for _ in 0..DOWNLOAD_CAPACITY {
            assert!(rate.allow_at("single", DOWNLOAD_SCALE, None, now));
        }
        assert!(!rate.allow_at("single", DOWNLOAD_SCALE, None, now));
        for _ in 0..DOWNLOAD_CAPACITY {
            assert!(rate.allow_at("batch", DOWNLOAD_SCALE, None, now));
        }
        assert!(!rate.allow_at("batch", DOWNLOAD_SCALE, None, now));
    }

    #[test]
    fn a_full_window_refills_the_bucket() {
        let rate = DownloadRate::new();
        let now = Instant::now();
        for _ in 0..DOWNLOAD_CAPACITY {
            assert!(rate.allow_at("grant", DOWNLOAD_SCALE, None, now));
        }
        assert!(!rate.allow_at("grant", DOWNLOAD_SCALE, None, now));
        assert!(rate.allow_at("grant", DOWNLOAD_SCALE, None, now + DOWNLOAD_WINDOW));
    }

    #[test]
    fn the_download_table_evicts_the_oldest_key_at_capacity() {
        let rate = DownloadRate::new();
        let now = Instant::now();
        for index in 0..DOWNLOAD_TABLE_CAP {
            let key = format!("grant-{index}");
            assert!(rate.allow_at(
                &key,
                DOWNLOAD_SCALE,
                None,
                now + Duration::from_nanos(index as u64),
            ));
        }
        assert!(rate.allow_at(
            "new-grant",
            DOWNLOAD_SCALE,
            None,
            now + Duration::from_nanos(DOWNLOAD_TABLE_CAP as u64),
        ));
        let buckets = rate.buckets.lock().unwrap();
        assert_eq!(buckets.len(), DOWNLOAD_TABLE_CAP);
        assert!(!buckets.contains_key("grant-0"));
        assert!(buckets.contains_key("new-grant"));
    }

    #[test]
    fn a_slow_file_count_load_cannot_rewind_bucket_clock() {
        let rate = DownloadRate::new();
        let start = Instant::now();
        let newer = start + DOWNLOAD_WINDOW / 2;
        let later = newer + DOWNLOAD_WINDOW / 2;

        assert!(rate
            .allow_individual_at(
                "grant",
                || {
                    // A concurrent request wins the race while this request
                    // is loading the immutable file count.
                    for _ in 0..(DOWNLOAD_CAPACITY as usize - 1) {
                        assert!(rate.allow_at("grant", DOWNLOAD_SCALE, None, newer));
                    }
                    Ok::<_, ()>(2)
                },
                start,
            )
            .unwrap());
        assert_eq!(rate.buckets.lock().unwrap()["grant"].last, newer);

        // With the newer timestamp retained, the half-window refill leaves
        // exactly half the budget for full-unit requests; rewinding would
        // refill the whole window instead.
        assert!(rate
            .allow_individual_at("grant", || Ok::<_, ()>(2), later)
            .unwrap());
        for _ in 0..(DOWNLOAD_CAPACITY / 2) {
            assert!(rate.allow_at("grant", DOWNLOAD_SCALE, None, later));
        }
        assert!(!rate.allow_at("grant", DOWNLOAD_SCALE, None, later));
    }
}
