//! Per-address token bucket for handshake admission
//! (docs/02-security.md, "Limits and hardening"). Used by the server for
//! accepted connections and by an accepting client for inbound ones.

use std::{collections::HashMap, net::IpAddr};

use tokio::time::{Duration, Instant};

/// Buckets idle for this long are forgotten.
const BUCKET_TTL: Duration = Duration::from_secs(600);

/// A rate-limited address is logged at most once per this interval.
pub const WARN_EVERY: Duration = Duration::from_secs(10);

/// One address in the [`RateLimiter`].
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
    /// When this address was last logged as rate limited.
    warned: Option<Instant>,
}

/// Token bucket per address: capacity `rate`, refilled at `rate` per
/// minute. Addresses not seen for ten minutes are forgotten when a new one
/// is added.
#[derive(Debug)]
pub struct RateLimiter {
    rate: u32,
    buckets: HashMap<IpAddr, Bucket>,
}

impl RateLimiter {
    /// `rate` handshakes per minute per address; must be non-zero (callers
    /// treat a zero rate as "no limiter").
    #[must_use]
    pub fn new(rate: u32) -> Self {
        Self {
            rate,
            buckets: HashMap::new(),
        }
    }

    /// Admit a handshake from `ip` at `now`, consuming one token; `false`
    /// when the bucket is empty.
    pub fn check(&mut self, ip: IpAddr, now: Instant) -> bool {
        let capacity = f64::from(self.rate);
        let per_second = capacity / 60.0;
        if !self.buckets.contains_key(&ip) {
            self.buckets
                .retain(|_, b| now.saturating_duration_since(b.last) < BUCKET_TTL);
        }
        let bucket = self.buckets.entry(ip).or_insert(Bucket {
            tokens: capacity,
            last: now,
            warned: None,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * per_second).min(capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// After a rejected [`RateLimiter::check`]: whether to log it (at most
    /// once per [`WARN_EVERY`] per address).
    pub fn should_warn(&mut self, ip: IpAddr, now: Instant) -> bool {
        let Some(bucket) = self.buckets.get_mut(&ip) else {
            return true;
        };
        if bucket
            .warned
            .is_some_and(|at| now.saturating_duration_since(at) < WARN_EVERY)
        {
            return false;
        }
        bucket.warned = Some(now);
        true
    }

    /// Number of addresses currently tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_drains_and_refills() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let other: IpAddr = "::1".parse().unwrap();
        let t0 = Instant::now();
        let mut limiter = RateLimiter::new(3);
        for _ in 0..3 {
            assert!(limiter.check(ip, t0));
        }
        assert!(
            !limiter.check(ip, t0),
            "fourth handshake in the same minute"
        );
        // Other addresses have their own bucket.
        assert!(limiter.check(other, t0));
        // 3/min = one token every 20 s; 10 s in there is only half a token.
        assert!(!limiter.check(ip, t0 + Duration::from_secs(10)));
        assert!(limiter.check(ip, t0 + Duration::from_secs(30)));
        assert!(!limiter.check(ip, t0 + Duration::from_secs(30)));
        // A full minute refills to capacity, never beyond it.
        let t1 = t0 + Duration::from_secs(600);
        for _ in 0..3 {
            assert!(limiter.check(ip, t1));
        }
        assert!(!limiter.check(ip, t1));
    }

    #[test]
    fn warns_once_per_interval_and_prunes() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let t0 = Instant::now();
        let mut limiter = RateLimiter::new(1);
        assert!(limiter.check(ip, t0));
        assert!(!limiter.check(ip, t0));
        assert!(limiter.should_warn(ip, t0));
        assert!(!limiter.should_warn(ip, t0 + Duration::from_secs(9)));
        assert!(limiter.should_warn(ip, t0 + WARN_EVERY));
        assert_eq!(limiter.tracked(), 1);
        // Inserting a new address prunes buckets idle for ten minutes.
        let newcomer: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.check(newcomer, t0 + BUCKET_TTL + Duration::from_secs(1)));
        assert_eq!(limiter.tracked(), 1);
        assert!(limiter.buckets.contains_key(&newcomer));
    }
}
