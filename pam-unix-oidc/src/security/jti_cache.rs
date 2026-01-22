//! JTI (JWT ID) cache for token replay protection.
//!
//! This module prevents token replay attacks by tracking seen JTI values.
//! Each JTI is stored with a TTL matching the token's expiration time.
//!
//! ## Security Properties
//!
//! - Tokens with the same JTI are rejected after first use
//! - Expired entries are automatically cleaned up
//! - Thread-safe for concurrent PAM authentication
//!
//! ## Limitations
//!
//! - In-memory cache is lost on process restart
//! - Single-server only (use Redis for distributed deployments)
//! - Memory grows with number of active tokens (bounded by cleanup)

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Default cleanup interval (5 minutes)
const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

/// Maximum entries before forced cleanup
const MAX_ENTRIES_BEFORE_CLEANUP: usize = 10000;

/// Result of checking a JTI
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JtiCheckResult {
    /// JTI is new (not seen before) - token is valid
    Valid,
    /// JTI was already seen - potential replay attack
    Replay,
    /// JTI is missing from token - cannot enforce replay protection
    Missing,
}

/// Entry in the JTI cache
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct JtiEntry {
    /// When this entry expires (based on token exp)
    expires_at: Instant,
    /// Username associated with this token (for logging)
    username: String,
    /// When the token was first seen
    first_seen: Instant,
}

/// Thread-safe JTI cache for replay protection.
///
/// # Example
///
/// ```
/// use pam_unix_oidc::security::JtiCache;
///
/// let cache = JtiCache::new();
///
/// // First use of a JTI - valid
/// assert!(cache.check_and_record("jti-123", "alice", 300).is_valid());
///
/// // Second use of same JTI - replay detected
/// assert!(cache.check_and_record("jti-123", "alice", 300).is_replay());
/// ```
pub struct JtiCache {
    /// Map of JTI -> entry
    entries: RwLock<HashMap<String, JtiEntry>>,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
    /// Cleanup interval
    cleanup_interval: Duration,
}

impl JtiCache {
    /// Create a new JTI cache with default settings.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            last_cleanup: RwLock::new(Instant::now()),
            cleanup_interval: DEFAULT_CLEANUP_INTERVAL,
        }
    }

    /// Create a JTI cache with custom cleanup interval.
    pub fn with_cleanup_interval(cleanup_interval: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            last_cleanup: RwLock::new(Instant::now()),
            cleanup_interval,
        }
    }

    /// Check if a JTI has been seen and record it if not.
    ///
    /// # Arguments
    ///
    /// * `jti` - The JWT ID claim value (may be None if token lacks jti)
    /// * `username` - Username for logging purposes
    /// * `ttl_seconds` - How long to remember this JTI (should match token lifetime)
    ///
    /// # Returns
    ///
    /// - `JtiCheckResult::Valid` if this is the first time seeing this JTI
    /// - `JtiCheckResult::Replay` if this JTI was already used
    /// - `JtiCheckResult::Missing` if jti is None
    pub fn check_and_record(
        &self,
        jti: Option<&str>,
        username: &str,
        ttl_seconds: u64,
    ) -> JtiCheckResult {
        let jti = match jti {
            Some(j) if !j.is_empty() => j,
            _ => return JtiCheckResult::Missing,
        };

        // Trigger cleanup if needed
        self.maybe_cleanup();

        let now = Instant::now();
        let expires_at = now + Duration::from_secs(ttl_seconds);

        // Try to read first (common case: JTI not seen)
        {
            let entries = self.entries.read().unwrap();
            if let Some(entry) = entries.get(jti) {
                // Entry exists - check if it's still valid
                if entry.expires_at > now {
                    // Not expired, this is a replay
                    return JtiCheckResult::Replay;
                }
                // Entry expired, will be replaced below
            }
        }

        // Need to write - acquire write lock
        {
            let mut entries = self.entries.write().unwrap();

            // Double-check after acquiring write lock
            if let Some(entry) = entries.get(jti) {
                if entry.expires_at > now {
                    return JtiCheckResult::Replay;
                }
            }

            // Insert or replace entry
            entries.insert(
                jti.to_string(),
                JtiEntry {
                    expires_at,
                    username: username.to_string(),
                    first_seen: now,
                },
            );
        }

        JtiCheckResult::Valid
    }

    /// Check if a JTI has been seen (without recording).
    ///
    /// Useful for checking without side effects.
    pub fn is_replay(&self, jti: Option<&str>) -> bool {
        let jti = match jti {
            Some(j) if !j.is_empty() => j,
            _ => return false, // Missing JTI can't be a replay
        };

        let now = Instant::now();
        let entries = self.entries.read().unwrap();

        if let Some(entry) = entries.get(jti) {
            entry.expires_at > now
        } else {
            false
        }
    }

    /// Get the number of active (non-expired) entries.
    pub fn active_count(&self) -> usize {
        let now = Instant::now();
        let entries = self.entries.read().unwrap();
        entries.values().filter(|e| e.expires_at > now).count()
    }

    /// Force cleanup of expired entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut entries = self.entries.write().unwrap();
        entries.retain(|_, entry| entry.expires_at > now);

        let mut last_cleanup = self.last_cleanup.write().unwrap();
        *last_cleanup = now;
    }

    /// Cleanup if interval has passed or too many entries.
    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let last = self.last_cleanup.read().unwrap();
            let entries = self.entries.read().unwrap();
            now.duration_since(*last) > self.cleanup_interval
                || entries.len() > MAX_ENTRIES_BEFORE_CLEANUP
        };

        if should_cleanup {
            self.cleanup();
        }
    }

    /// Clear all entries (for testing).
    #[cfg(test)]
    pub fn clear(&self) {
        let mut entries = self.entries.write().unwrap();
        entries.clear();
    }
}

impl Default for JtiCache {
    fn default() -> Self {
        Self::new()
    }
}

impl JtiCheckResult {
    /// Returns true if the token is valid (not a replay).
    pub fn is_valid(&self) -> bool {
        matches!(self, JtiCheckResult::Valid)
    }

    /// Returns true if this is a replay attack.
    pub fn is_replay(&self) -> bool {
        matches!(self, JtiCheckResult::Replay)
    }

    /// Returns true if JTI was missing.
    pub fn is_missing(&self) -> bool {
        matches!(self, JtiCheckResult::Missing)
    }
}

/// Global JTI cache instance.
///
/// This is used by the PAM module to track JTIs across authentication attempts.
/// Using a global instance ensures JTIs are tracked for the lifetime of the
/// PAM module in memory.
pub fn global_jti_cache() -> &'static JtiCache {
    use once_cell::sync::Lazy;
    static CACHE: Lazy<JtiCache> = Lazy::new(JtiCache::new);
    &CACHE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jti_first_use_is_valid() {
        let cache = JtiCache::new();
        let result = cache.check_and_record(Some("test-jti-1"), "alice", 300);
        assert!(result.is_valid());
    }

    #[test]
    fn test_jti_second_use_is_replay() {
        let cache = JtiCache::new();

        // First use
        let result1 = cache.check_and_record(Some("test-jti-2"), "alice", 300);
        assert!(result1.is_valid());

        // Second use - replay
        let result2 = cache.check_and_record(Some("test-jti-2"), "alice", 300);
        assert!(result2.is_replay());
    }

    #[test]
    fn test_jti_missing_returns_missing() {
        let cache = JtiCache::new();

        let result1 = cache.check_and_record(None, "alice", 300);
        assert!(result1.is_missing());

        let result2 = cache.check_and_record(Some(""), "alice", 300);
        assert!(result2.is_missing());
    }

    #[test]
    fn test_different_jtis_both_valid() {
        let cache = JtiCache::new();

        let result1 = cache.check_and_record(Some("jti-a"), "alice", 300);
        let result2 = cache.check_and_record(Some("jti-b"), "bob", 300);

        assert!(result1.is_valid());
        assert!(result2.is_valid());
    }

    #[test]
    fn test_active_count() {
        let cache = JtiCache::new();

        cache.check_and_record(Some("jti-1"), "alice", 300);
        cache.check_and_record(Some("jti-2"), "bob", 300);
        cache.check_and_record(Some("jti-3"), "charlie", 300);

        assert_eq!(cache.active_count(), 3);
    }

    #[test]
    fn test_is_replay_without_recording() {
        let cache = JtiCache::new();

        // Not seen yet
        assert!(!cache.is_replay(Some("jti-check")));

        // Record it
        cache.check_and_record(Some("jti-check"), "alice", 300);

        // Now it's a replay
        assert!(cache.is_replay(Some("jti-check")));
    }

    #[test]
    fn test_cleanup_removes_expired() {
        let cache = JtiCache::with_cleanup_interval(Duration::from_millis(1));

        // Add entry with very short TTL
        cache.check_and_record(Some("short-lived"), "alice", 0);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        // Cleanup
        cache.cleanup();

        // Entry should be gone - same JTI is now valid again
        let result = cache.check_and_record(Some("short-lived"), "alice", 300);
        assert!(result.is_valid());
    }

    #[test]
    fn test_global_cache_is_singleton() {
        let cache1 = global_jti_cache();
        let cache2 = global_jti_cache();

        // Should be the same instance
        assert!(std::ptr::eq(cache1, cache2));
    }
}
