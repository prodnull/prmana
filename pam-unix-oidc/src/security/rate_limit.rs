//! Rate limiting for brute force protection.
//!
//! This module implements rate limiting to prevent:
//! - Brute force token guessing
//! - Denial of service via repeated auth attempts
//! - Credential stuffing attacks
//!
//! ## Strategy
//!
//! Uses a sliding window counter with exponential backoff:
//! - Track failed attempts per username and per source IP
//! - After N failures, require waiting period before next attempt
//! - Backoff period increases exponentially with consecutive failures
//!
//! ## Configuration
//!
//! Environment variables:
//! - `UNIX_OIDC_RATE_LIMIT_WINDOW`: Window size in seconds (default: 300)
//! - `UNIX_OIDC_RATE_LIMIT_MAX_ATTEMPTS`: Max attempts per window (default: 5)
//! - `UNIX_OIDC_RATE_LIMIT_LOCKOUT`: Initial lockout in seconds (default: 60)

use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Default rate limit window (5 minutes)
const DEFAULT_WINDOW_SECS: u64 = 300;

/// Default maximum attempts per window
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Default initial lockout duration (1 minute)
const DEFAULT_LOCKOUT_SECS: u64 = 60;

/// Maximum lockout duration (1 hour)
const MAX_LOCKOUT_SECS: u64 = 3600;

/// Maximum number of entries (users + IPs) before triggering automatic cleanup.
/// Prevents unbounded memory growth from distributed brute-force attacks.
const MAX_ENTRIES: usize = 100_000;

/// Minimum interval between automatic cleanups (seconds).
const CLEANUP_INTERVAL_SECS: u64 = 60;

/// Minimum allowed max_attempts value.
const MIN_MAX_ATTEMPTS: u32 = 1;

/// Maximum allowed max_attempts value.
const MAX_MAX_ATTEMPTS: u32 = 1000;

/// Rate limit errors
#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded for user '{user}': try again in {retry_after} seconds")]
    UserLimited { user: String, retry_after: u64 },

    #[error("Rate limit exceeded for IP '{ip}': try again in {retry_after} seconds")]
    IpLimited { ip: String, retry_after: u64 },
}

/// Rate limit entry tracking attempts
#[derive(Debug, Clone)]
struct RateLimitEntry {
    /// Timestamps of recent failed attempts
    attempts: Vec<Instant>,
    /// Current lockout end time (if locked out)
    lockout_until: Option<Instant>,
    /// Consecutive failures (for exponential backoff)
    consecutive_failures: u32,
}

impl RateLimitEntry {
    fn new() -> Self {
        Self {
            attempts: Vec::new(),
            lockout_until: None,
            consecutive_failures: 0,
        }
    }
}

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Window size for counting attempts
    pub window: Duration,
    /// Maximum attempts allowed in window
    pub max_attempts: u32,
    /// Initial lockout duration after exceeding limit
    pub initial_lockout: Duration,
    /// Whether to use exponential backoff
    pub exponential_backoff: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(DEFAULT_WINDOW_SECS),
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            initial_lockout: Duration::from_secs(DEFAULT_LOCKOUT_SECS),
            exponential_backoff: true,
        }
    }
}

impl RateLimitConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let window = std::env::var("UNIX_OIDC_RATE_LIMIT_WINDOW")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(DEFAULT_WINDOW_SECS));

        let max_attempts = std::env::var("UNIX_OIDC_RATE_LIMIT_MAX_ATTEMPTS")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .map(|v| {
                let clamped = v.clamp(MIN_MAX_ATTEMPTS, MAX_MAX_ATTEMPTS);
                if clamped != v {
                    tracing::warn!(
                        configured = v,
                        clamped = clamped,
                        min = MIN_MAX_ATTEMPTS,
                        max = MAX_MAX_ATTEMPTS,
                        "UNIX_OIDC_RATE_LIMIT_MAX_ATTEMPTS out of valid range, clamped"
                    );
                }
                clamped
            })
            .unwrap_or(DEFAULT_MAX_ATTEMPTS);

        let initial_lockout = std::env::var("UNIX_OIDC_RATE_LIMIT_LOCKOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(DEFAULT_LOCKOUT_SECS));

        Self {
            window,
            max_attempts,
            initial_lockout,
            exponential_backoff: true,
        }
    }
}

/// Thread-safe rate limiter.
pub struct RateLimiter {
    /// Per-user rate limit tracking
    users: RwLock<HashMap<String, RateLimitEntry>>,
    /// Per-IP rate limit tracking
    ips: RwLock<HashMap<String, RateLimitEntry>>,
    /// Configuration
    config: RateLimitConfig,
    /// Last time automatic cleanup was run
    last_cleanup: RwLock<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter with default configuration.
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Create a rate limiter with custom configuration.
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            ips: RwLock::new(HashMap::new()),
            config,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Create a rate limiter from environment configuration.
    pub fn from_env() -> Self {
        Self::with_config(RateLimitConfig::from_env())
    }

    /// Check if an authentication attempt is allowed.
    ///
    /// Returns Ok(()) if allowed, Err with retry time if rate limited.
    pub fn check_allowed(
        &self,
        username: &str,
        source_ip: Option<&str>,
    ) -> Result<(), RateLimitError> {
        let now = Instant::now();

        // Check user rate limit
        {
            let users = self.users.read();
            if let Some(entry) = users.get(username) {
                if let Some(lockout_until) = entry.lockout_until {
                    if now < lockout_until {
                        let retry_after = lockout_until.duration_since(now).as_secs();
                        return Err(RateLimitError::UserLimited {
                            user: username.to_string(),
                            retry_after,
                        });
                    }
                }
            }
        }

        // Check IP rate limit
        if let Some(ip) = source_ip {
            let ips = self.ips.read();
            if let Some(entry) = ips.get(ip) {
                if let Some(lockout_until) = entry.lockout_until {
                    if now < lockout_until {
                        let retry_after = lockout_until.duration_since(now).as_secs();
                        return Err(RateLimitError::IpLimited {
                            ip: ip.to_string(),
                            retry_after,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Record a failed authentication attempt.
    ///
    /// This increments the failure counter and may trigger a lockout.
    /// Automatically triggers cleanup when capacity is exceeded or enough time has elapsed.
    pub fn record_failure(&self, username: &str, source_ip: Option<&str>) {
        self.maybe_cleanup();

        let now = Instant::now();
        let window_start = now - self.config.window;

        // Record user failure
        {
            let mut users = self.users.write();
            let entry = users
                .entry(username.to_string())
                .or_insert_with(RateLimitEntry::new);

            // Remove old attempts outside window
            entry.attempts.retain(|t| *t > window_start);

            // Add this attempt
            entry.attempts.push(now);
            entry.consecutive_failures += 1;

            // Check if we need to lock out
            if entry.attempts.len() as u32 >= self.config.max_attempts {
                let lockout_duration = self.calculate_lockout(entry.consecutive_failures);
                entry.lockout_until = Some(now + lockout_duration);
            }
        }

        // Record IP failure
        if let Some(ip) = source_ip {
            let mut ips = self.ips.write();
            let entry = ips
                .entry(ip.to_string())
                .or_insert_with(RateLimitEntry::new);

            entry.attempts.retain(|t| *t > window_start);
            entry.attempts.push(now);
            entry.consecutive_failures += 1;

            if entry.attempts.len() as u32 >= self.config.max_attempts {
                let lockout_duration = self.calculate_lockout(entry.consecutive_failures);
                entry.lockout_until = Some(now + lockout_duration);
            }
        }
    }

    /// Record a successful authentication.
    ///
    /// This resets the consecutive failure counter and clears the attempts history.
    /// Clearing attempts is critical: stale attempts from before success would
    /// otherwise count toward the next lockout threshold, causing premature re-lockout.
    pub fn record_success(&self, username: &str, source_ip: Option<&str>) {
        // Reset user consecutive failures and clear attempts
        {
            let mut users = self.users.write();
            if let Some(entry) = users.get_mut(username) {
                entry.consecutive_failures = 0;
                entry.lockout_until = None;
                entry.attempts.clear();
            }
        }

        // Reset IP consecutive failures and clear attempts
        if let Some(ip) = source_ip {
            let mut ips = self.ips.write();
            if let Some(entry) = ips.get_mut(ip) {
                entry.consecutive_failures = 0;
                entry.lockout_until = None;
                entry.attempts.clear();
            }
        }
    }

    /// Calculate lockout duration based on consecutive failures.
    fn calculate_lockout(&self, consecutive_failures: u32) -> Duration {
        if !self.config.exponential_backoff {
            return self.config.initial_lockout;
        }

        // Exponential backoff: initial * 2^(failures-1), capped at max
        let multiplier = 2u64.saturating_pow(consecutive_failures.saturating_sub(1));
        let lockout_secs = self
            .config
            .initial_lockout
            .as_secs()
            .saturating_mul(multiplier);
        let capped_secs = lockout_secs.min(MAX_LOCKOUT_SECS);

        Duration::from_secs(capped_secs)
    }

    /// Get the number of recent failures for a user.
    pub fn user_failure_count(&self, username: &str) -> u32 {
        let now = Instant::now();
        let window_start = now - self.config.window;

        let users = self.users.read();
        users
            .get(username)
            .map(|e| e.attempts.iter().filter(|t| **t > window_start).count() as u32)
            .unwrap_or(0)
    }

    /// Check if a user is currently locked out.
    pub fn is_user_locked_out(&self, username: &str) -> bool {
        let now = Instant::now();
        let users = self.users.read();

        users
            .get(username)
            .and_then(|e| e.lockout_until)
            .map(|until| now < until)
            .unwrap_or(false)
    }

    /// Return total number of tracked entries (users + IPs).
    pub fn total_entries(&self) -> usize {
        self.users.read().len() + self.ips.read().len()
    }

    /// Automatically run cleanup if capacity is exceeded or enough time has elapsed.
    ///
    /// Called from `record_failure()` to prevent unbounded memory growth from
    /// distributed brute-force attacks without requiring an external cleanup timer.
    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let needs_cleanup = {
            let last = self.last_cleanup.read();
            let elapsed = now.duration_since(*last).as_secs() >= CLEANUP_INTERVAL_SECS;
            let over_capacity = self.total_entries() > MAX_ENTRIES;
            elapsed || over_capacity
        };

        if needs_cleanup {
            self.cleanup();
            let mut last = self.last_cleanup.write();
            *last = Instant::now();

            // After cleanup, if still over capacity, log a warning.
            // We do NOT reject auth — that would be a DoS vector.
            if self.total_entries() > MAX_ENTRIES {
                tracing::warn!(
                    total_entries = self.total_entries(),
                    max_entries = MAX_ENTRIES,
                    "Rate limiter still over capacity after cleanup; \
                     possible distributed brute-force attack"
                );
            }
        }
    }

    /// Clean up expired entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window_start = now - self.config.window;

        // Cleanup users
        {
            let mut users = self.users.write();
            users.retain(|_, entry| {
                entry.attempts.retain(|t| *t > window_start);
                !entry.attempts.is_empty() || entry.lockout_until.map(|u| now < u).unwrap_or(false)
            });
        }

        // Cleanup IPs
        {
            let mut ips = self.ips.write();
            ips.retain(|_, entry| {
                entry.attempts.retain(|t| *t > window_start);
                !entry.attempts.is_empty() || entry.lockout_until.map(|u| now < u).unwrap_or(false)
            });
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Global rate limiter instance.
pub fn global_rate_limiter() -> &'static RateLimiter {
    use once_cell::sync::Lazy;
    static LIMITER: Lazy<RateLimiter> = Lazy::new(RateLimiter::from_env);
    &LIMITER
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RateLimitConfig {
        RateLimitConfig {
            window: Duration::from_secs(60),
            max_attempts: 3,
            initial_lockout: Duration::from_secs(10),
            exponential_backoff: false,
        }
    }

    #[test]
    fn test_allows_initial_attempts() {
        let limiter = RateLimiter::with_config(test_config());

        assert!(limiter.check_allowed("alice", None).is_ok());
        assert!(limiter.check_allowed("bob", None).is_ok());
    }

    #[test]
    fn test_locks_out_after_max_attempts() {
        let limiter = RateLimiter::with_config(test_config());

        // Record max_attempts failures
        for _ in 0..3 {
            limiter.record_failure("alice", None);
        }

        // Should now be locked out
        let result = limiter.check_allowed("alice", None);
        assert!(matches!(result, Err(RateLimitError::UserLimited { .. })));
    }

    #[test]
    fn test_different_users_independent() {
        let limiter = RateLimiter::with_config(test_config());

        // Lock out alice
        for _ in 0..3 {
            limiter.record_failure("alice", None);
        }

        // Bob should still be allowed
        assert!(limiter.check_allowed("bob", None).is_ok());
    }

    #[test]
    fn test_ip_rate_limiting() {
        let limiter = RateLimiter::with_config(test_config());

        // Lock out an IP
        for _ in 0..3 {
            limiter.record_failure("alice", Some("192.168.1.100"));
        }

        // Same IP should be locked out even for different user
        let result = limiter.check_allowed("bob", Some("192.168.1.100"));
        assert!(matches!(result, Err(RateLimitError::IpLimited { .. })));

        // Different IP should be allowed
        assert!(limiter.check_allowed("bob", Some("192.168.1.200")).is_ok());
    }

    #[test]
    fn test_success_resets_lockout() {
        let mut config = test_config();
        config.initial_lockout = Duration::from_millis(10);
        let limiter = RateLimiter::with_config(config);

        // Lock out user
        for _ in 0..3 {
            limiter.record_failure("alice", None);
        }

        // Wait for lockout to expire
        std::thread::sleep(Duration::from_millis(20));

        // Authenticate successfully
        limiter.record_success("alice", None);

        // Should no longer be locked out, and attempts must be cleared
        assert!(limiter.check_allowed("alice", None).is_ok());
        assert_eq!(limiter.user_failure_count("alice"), 0); // F-12: attempts cleared on success
    }

    #[test]
    fn test_exponential_backoff() {
        let config = RateLimitConfig {
            window: Duration::from_secs(60),
            max_attempts: 1,
            initial_lockout: Duration::from_secs(10),
            exponential_backoff: true,
        };
        let limiter = RateLimiter::with_config(config);

        // First lockout: 10 seconds
        assert_eq!(limiter.calculate_lockout(1).as_secs(), 10);

        // Second lockout: 20 seconds
        assert_eq!(limiter.calculate_lockout(2).as_secs(), 20);

        // Third lockout: 40 seconds
        assert_eq!(limiter.calculate_lockout(3).as_secs(), 40);

        // Should cap at MAX_LOCKOUT_SECS (1 hour)
        assert_eq!(limiter.calculate_lockout(100).as_secs(), MAX_LOCKOUT_SECS);
    }

    #[test]
    fn test_failure_count() {
        let limiter = RateLimiter::with_config(test_config());

        assert_eq!(limiter.user_failure_count("alice"), 0);

        limiter.record_failure("alice", None);
        assert_eq!(limiter.user_failure_count("alice"), 1);

        limiter.record_failure("alice", None);
        assert_eq!(limiter.user_failure_count("alice"), 2);
    }

    #[test]
    fn test_is_user_locked_out() {
        let limiter = RateLimiter::with_config(test_config());

        assert!(!limiter.is_user_locked_out("alice"));

        for _ in 0..3 {
            limiter.record_failure("alice", None);
        }

        assert!(limiter.is_user_locked_out("alice"));
    }

    /// F-12 positive: after success, user can fail max_attempts - 1 times again
    /// before being locked out (full budget restored).
    #[test]
    fn test_success_clears_attempts_allows_full_budget() {
        let mut config = test_config();
        config.initial_lockout = Duration::from_millis(10);
        let limiter = RateLimiter::with_config(config);

        // Exhaust all attempts to trigger lockout
        for _ in 0..3 {
            limiter.record_failure("alice", None);
        }
        assert!(limiter.is_user_locked_out("alice"));

        // Wait for lockout to expire, then succeed
        std::thread::sleep(Duration::from_millis(20));
        limiter.record_success("alice", None);

        // Failure count must be zero after success
        assert_eq!(limiter.user_failure_count("alice"), 0);

        // User can now fail max_attempts - 1 times without being locked out
        for _ in 0..2 {
            limiter.record_failure("alice", None);
        }
        assert!(
            !limiter.is_user_locked_out("alice"),
            "user must not be locked out with fewer than max_attempts failures after success"
        );

        // The third failure triggers lockout again (full budget was restored)
        limiter.record_failure("alice", None);
        assert!(limiter.is_user_locked_out("alice"));
    }

    /// F-12 negative: a single failure after success does NOT cause immediate re-lockout
    /// (the old bug where stale attempts remained would cause this).
    #[test]
    fn test_single_failure_after_success_does_not_relock() {
        let mut config = test_config();
        config.initial_lockout = Duration::from_millis(10);
        let limiter = RateLimiter::with_config(config);

        // Fill up to max_attempts - 1 failures
        for _ in 0..2 {
            limiter.record_failure("alice", None);
        }

        // Succeed — this must clear all attempts
        limiter.record_success("alice", None);

        // A single new failure must NOT trigger lockout
        limiter.record_failure("alice", None);
        assert!(
            !limiter.is_user_locked_out("alice"),
            "a single failure after success must not trigger lockout"
        );
        assert_eq!(limiter.user_failure_count("alice"), 1);
    }

    /// F-13 positive: after many entries, cleanup removes expired ones.
    #[test]
    fn test_cleanup_removes_expired_entries() {
        let config = RateLimitConfig {
            window: Duration::from_millis(50),
            max_attempts: 100,
            initial_lockout: Duration::from_millis(10),
            exponential_backoff: false,
        };
        let limiter = RateLimiter::with_config(config);

        // Add many entries
        for i in 0..50 {
            limiter.record_failure(&format!("user-{i}"), Some(&format!("10.0.0.{i}")));
        }
        assert!(limiter.total_entries() > 0);

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(60));

        // Cleanup should remove all expired entries
        limiter.cleanup();
        assert_eq!(
            limiter.total_entries(),
            0,
            "all expired entries must be removed after cleanup"
        );
    }

    /// F-13 negative: entries over capacity trigger cleanup via maybe_cleanup.
    #[test]
    fn test_maybe_cleanup_triggered_by_record_failure() {
        let config = RateLimitConfig {
            window: Duration::from_millis(10),
            max_attempts: 100,
            initial_lockout: Duration::from_millis(10),
            exponential_backoff: false,
        };
        let limiter = RateLimiter::with_config(config);

        // Add entries (they'll expire quickly due to 10ms window)
        for i in 0..20 {
            limiter.record_failure(&format!("user-{i}"), None);
        }

        // Wait for entries to expire
        std::thread::sleep(Duration::from_millis(20));

        // Force last_cleanup to be old enough to trigger maybe_cleanup
        {
            let mut last = limiter.last_cleanup.write();
            *last = Instant::now() - Duration::from_secs(CLEANUP_INTERVAL_SECS + 1);
        }

        // record_failure calls maybe_cleanup, which should evict expired entries
        limiter.record_failure("trigger-user", None);

        // Only the trigger-user entry should remain (the 20 expired ones are gone)
        assert!(
            limiter.total_entries() <= 2, // trigger-user in users map (maybe also trigger-user IP=None → not in ips)
            "expired entries must be cleaned up, got {} entries",
            limiter.total_entries()
        );
    }

    /// F-14 positive: valid env value is used as-is.
    #[test]
    fn test_rate_limit_config_valid_max_attempts() {
        std::env::set_var("UNIX_OIDC_RATE_LIMIT_MAX_ATTEMPTS", "50");
        let config = RateLimitConfig::from_env();
        std::env::remove_var("UNIX_OIDC_RATE_LIMIT_MAX_ATTEMPTS");
        assert_eq!(config.max_attempts, 50);
    }

    /// F-14 negative: value of 0 is clamped to 1.
    #[test]
    fn test_rate_limit_config_zero_clamped_to_min() {
        std::env::set_var("UNIX_OIDC_RATE_LIMIT_MAX_ATTEMPTS", "0");
        let config = RateLimitConfig::from_env();
        std::env::remove_var("UNIX_OIDC_RATE_LIMIT_MAX_ATTEMPTS");
        assert_eq!(
            config.max_attempts, 1,
            "max_attempts of 0 must be clamped to MIN_MAX_ATTEMPTS (1)"
        );
    }

    /// F-14 negative: very large value is clamped to 1000.
    #[test]
    fn test_rate_limit_config_large_clamped_to_max() {
        std::env::set_var("UNIX_OIDC_RATE_LIMIT_MAX_ATTEMPTS", "999999");
        let config = RateLimitConfig::from_env();
        std::env::remove_var("UNIX_OIDC_RATE_LIMIT_MAX_ATTEMPTS");
        assert_eq!(
            config.max_attempts, 1000,
            "max_attempts of 999999 must be clamped to MAX_MAX_ATTEMPTS (1000)"
        );
    }
}
