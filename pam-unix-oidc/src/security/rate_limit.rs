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

use std::collections::HashMap;
use std::sync::RwLock;
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
            .and_then(|s| s.parse().ok())
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
            let users = self.users.read().unwrap();
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
            let ips = self.ips.read().unwrap();
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
    pub fn record_failure(&self, username: &str, source_ip: Option<&str>) {
        let now = Instant::now();
        let window_start = now - self.config.window;

        // Record user failure
        {
            let mut users = self.users.write().unwrap();
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
            let mut ips = self.ips.write().unwrap();
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
    /// This resets the consecutive failure counter.
    pub fn record_success(&self, username: &str, source_ip: Option<&str>) {
        // Reset user consecutive failures
        {
            let mut users = self.users.write().unwrap();
            if let Some(entry) = users.get_mut(username) {
                entry.consecutive_failures = 0;
                entry.lockout_until = None;
            }
        }

        // Reset IP consecutive failures
        if let Some(ip) = source_ip {
            let mut ips = self.ips.write().unwrap();
            if let Some(entry) = ips.get_mut(ip) {
                entry.consecutive_failures = 0;
                entry.lockout_until = None;
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

        let users = self.users.read().unwrap();
        users
            .get(username)
            .map(|e| e.attempts.iter().filter(|t| **t > window_start).count() as u32)
            .unwrap_or(0)
    }

    /// Check if a user is currently locked out.
    pub fn is_user_locked_out(&self, username: &str) -> bool {
        let now = Instant::now();
        let users = self.users.read().unwrap();

        users
            .get(username)
            .and_then(|e| e.lockout_until)
            .map(|until| now < until)
            .unwrap_or(false)
    }

    /// Clean up expired entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window_start = now - self.config.window;

        // Cleanup users
        {
            let mut users = self.users.write().unwrap();
            users.retain(|_, entry| {
                entry.attempts.retain(|t| *t > window_start);
                !entry.attempts.is_empty() || entry.lockout_until.map(|u| now < u).unwrap_or(false)
            });
        }

        // Cleanup IPs
        {
            let mut ips = self.ips.write().unwrap();
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

        // Should no longer be locked out
        assert!(limiter.check_allowed("alice", None).is_ok());
        assert_eq!(limiter.user_failure_count("alice"), 3); // Attempts still recorded
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
}
