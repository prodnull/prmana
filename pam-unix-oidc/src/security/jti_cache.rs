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
//! - Cross-fork replay detection via filesystem-backed `FsAtomicStore` (D-06)
//!
//! ## Limitations
//!
//! - In-memory cache is lost on process restart
//! - Single-server only (use Redis for distributed deployments)
//! - Memory grows with number of active tokens (bounded by cleanup)
//!
//! ## References
//!
//! - RFC 9449 §11.1 — JTI uniqueness for DPoP proofs
//! - D-06 (Phase 30 design): strict-mode filesystem failure = hard-reject;
//!   permissive-mode filesystem failure = per-process fallback + LOG_CRIT

use crate::policy::config::EnforcementMode;
use crate::security::fs_store::{AtomicRecordResult, FsAtomicStore};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default cleanup interval (5 minutes)
const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

/// Maximum entries before forced cleanup
const MAX_ENTRIES_BEFORE_CLEANUP: usize = 100_000;

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
/// assert!(cache.check_and_record(Some("jti-123"), "alice", 300).is_valid());
///
/// // Second use of same JTI - replay detected
/// assert!(cache.check_and_record(Some("jti-123"), "alice", 300).is_replay());
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
            let entries = self.entries.read();
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
            let mut entries = self.entries.write();

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
        let entries = self.entries.read();

        if let Some(entry) = entries.get(jti) {
            entry.expires_at > now
        } else {
            false
        }
    }

    /// Get the number of active (non-expired) entries.
    pub fn active_count(&self) -> usize {
        let now = Instant::now();
        let entries = self.entries.read();
        entries.values().filter(|e| e.expires_at > now).count()
    }

    /// Force cleanup of expired entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut entries = self.entries.write();
        entries.retain(|_, entry| entry.expires_at > now);
        drop(entries);

        let mut last_cleanup = self.last_cleanup.write();
        *last_cleanup = now;
    }

    /// Cleanup if interval has passed or too many entries.
    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let last = self.last_cleanup.read();
            let entries = self.entries.read();
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
        let mut entries = self.entries.write();
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
    static CACHE: Lazy<JtiCache> = Lazy::new(JtiCache::new);
    &CACHE
}

// ── Filesystem-backed JTI store (Phase 30, D-06) ──────────────────────────────

/// Global filesystem-based JTI store. Directory: `/run/unix-oidc/jti/`.
///
/// Backed by `FsAtomicStore` with `O_CREAT | O_EXCL` semantics so that all
/// `sshd` worker processes (forked from the same parent) share a single kernel-
/// enforced replay-protection state.
///
/// Override the backing directory with `UNIX_OIDC_JTI_DIR` for testing.
pub fn global_jti_store() -> &'static FsAtomicStore {
    // In test builds, ensure the tempdir env var is set BEFORE the Lazy
    // evaluates. Without this, a parallel test that calls global_jti_store()
    // before setup_test_jti_dir() would initialize the Lazy with the default
    // /run/unix-oidc/jti (which doesn't exist on dev machines), causing all
    // subsequent JTI checks to fail with ReplayDetected.
    // Uses `feature = "test-mode"` (not `#[cfg(test)]`) so integration tests
    // in the `tests/` directory also get the tempdir redirect.
    #[cfg(any(test, feature = "test-mode"))]
    setup_test_jti_dir();

    static STORE: Lazy<FsAtomicStore> =
        Lazy::new(|| FsAtomicStore::new("/run/unix-oidc/jti", "UNIX_OIDC_JTI_DIR"));
    &STORE
}

/// Ensure `UNIX_OIDC_JTI_DIR` points to a per-process tempdir before the
/// `Lazy<FsAtomicStore>` in `global_jti_store()` is first accessed.
///
/// All test modules (auth, dpop, etc.) MUST call this single function
/// instead of setting `UNIX_OIDC_JTI_DIR` independently. The `Lazy` reads
/// the env var exactly once — if two test modules race to set different
/// tempdirs, the `Lazy` captures whichever wins, and the other module's
/// JTIs land in the wrong directory causing spurious `ReplayDetected`.
///
/// This function uses a process-global `OnceLock` so the tempdir is created
/// exactly once and shared by all test modules.
#[cfg(any(test, feature = "test-mode"))]
pub fn setup_test_jti_dir() {
    use std::sync::OnceLock;
    static TEST_JTI_DIR: OnceLock<std::path::PathBuf> = OnceLock::new();
    TEST_JTI_DIR.get_or_init(|| {
        // Use a process-unique subdirectory under the system temp dir.
        // Avoids depending on the `tempfile` crate outside dev-dependencies.
        let dir = std::env::temp_dir().join(format!("unix-oidc-jti-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create JTI test tempdir");
        std::env::set_var("UNIX_OIDC_JTI_DIR", &dir);
        dir
    });
}

/// Check-and-record a JTI with filesystem-based cross-fork replay protection.
///
/// Routes through `FsAtomicStore` (kernel-atomic `O_CREAT | O_EXCL`) for
/// cross-fork state. On filesystem failure the behaviour is governed by
/// `enforcement`:
///
/// - **`Strict`**: `IoError` is treated as a hard-reject (returns
///   `JtiCheckResult::Replay`). Secure-by-default: authentication fails rather
///   than proceeding without replay protection (D-06, CLAUDE.md §Hard-Fail).
///
/// - **`Warn` / `Disabled`**: Falls back to the per-process in-memory
///   `JtiCache`. This restores pre-Phase-30 behaviour for operators running
///   without the `/run/unix-oidc/` tmpfiles directory. A **LOG_CRIT** message
///   is written to syslog (`LOG_AUTH`) so the degradation is SIEM-visible
///   (D-06, RESEARCH Pitfall 5).
///
/// # Arguments
///
/// * `jti` – The JWT ID claim value (may be `None` if the token omits it).
/// * `issuer` – The token's `iss` claim. Used as the cross-issuer isolation
///   scope (D-02): two issuers sharing a JTI value hash to different filenames.
/// * `username` – The authenticating username (for logging and the fallback cache).
/// * `ttl_seconds` – How long to remember this JTI (should match token lifetime).
/// * `enforcement` – Enforcement mode from `SecurityModes.jti_enforcement`.
pub fn check_and_record_fs(
    jti: Option<&str>,
    issuer: &str,
    username: &str,
    ttl_seconds: u64,
    enforcement: EnforcementMode,
) -> JtiCheckResult {
    let jti = match jti {
        Some(j) if !j.is_empty() => j,
        _ => return JtiCheckResult::Missing,
    };

    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(ttl_seconds);

    let store = global_jti_store();

    // Opportunistic sweep (5% probability) — evicts expired entries without a
    // dedicated background thread (D-04).
    store.opportunistic_sweep();

    // `issuer` is the scope so two issuers sharing a JTI value hash to
    // different filenames (D-02, cross-issuer isolation).
    match store.check_and_record(issuer, jti, expires_at) {
        AtomicRecordResult::New => JtiCheckResult::Valid,
        AtomicRecordResult::AlreadyExists => {
            // Cross-fork replay detected: another sshd worker already consumed this JTI.
            // Emit OCSF audit event before returning rejection so the attack is
            // visible in the audit stream regardless of calling code's error handling.
            crate::audit::AuditEvent::jti_replay_detected(
                jti,
                Some(issuer),
                "access_token",
                Some(username),
                None, // source_ip not available in JTI cache layer
            )
            .log();
            JtiCheckResult::Replay
        }
        AtomicRecordResult::IoError(e) => match enforcement {
            EnforcementMode::Strict => {
                // D-06: hard-fail — treat filesystem unavailability as replay
                // so that authentication fails closed rather than open.
                tracing::error!(
                    error = %e,
                    issuer = %issuer,
                    username = %username,
                    "JTI filesystem store unavailable (strict mode) - hard-failing authentication"
                );
                // Emit OCSF audit event: store degraded in strict mode (login rejected).
                crate::audit::AuditEvent::jti_store_degraded(&e.to_string(), "strict", "jti").log();
                JtiCheckResult::Replay
            }
            EnforcementMode::Warn | EnforcementMode::Disabled => {
                // D-06: LOG_CRIT so that the degradation is visible in SIEM
                // dashboards, not just in the application trace log.
                tracing::error!(
                    error = %e,
                    issuer = %issuer,
                    username = %username,
                    "JTI filesystem store unavailable - cross-fork replay protection degraded; \
                     falling back to per-process cache (LOG_CRIT emitted to syslog)"
                );
                emit_syslog_crit(&format!(
                    "unix-oidc: JTI filesystem store unavailable at /run/unix-oidc/jti/ - \
                     cross-fork replay protection degraded for issuer={issuer}; \
                     set jti_enforcement=strict to hard-fail instead"
                ));
                // Emit OCSF audit event: store degraded in permissive mode (fallback active).
                crate::audit::AuditEvent::jti_store_degraded(&e.to_string(), "permissive", "jti")
                    .log();
                // Fallback to per-process cache to preserve v1.x behaviour (D-07).
                global_jti_cache().check_and_record(Some(jti), username, ttl_seconds)
            }
        },
    }
}

/// Emit a LOG_CRIT message to syslog (`LOG_AUTH` facility).
///
/// Modelled after `log_to_syslog` in `audit.rs`. Failures are silently
/// ignored — syslog unavailability must never block authentication.
fn emit_syslog_crit(message: &str) {
    use syslog::{Facility, Formatter3164};

    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTH,
        hostname: None,
        process: "unix-oidc".to_string(),
        pid: std::process::id(),
    };

    if let Ok(mut logger) = syslog::unix(formatter) {
        let _ = logger.crit(message);
    }
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

    // ── Phase 30-05: audit event emission tests ────────────────────────────────

    /// Verify that AuditEvent::jti_replay_detected() constructs and serializes
    /// without panic, exercises enriched_log_json() → OCSF → HMAC chain path.
    #[test]
    fn test_jti_replay_emits_audit_event() {
        // Arrange: construct the event that check_and_record_fs emits on AlreadyExists.
        let event = crate::audit::AuditEvent::jti_replay_detected(
            "test-jti-001",
            Some("https://keycloak.test"),
            "access_token",
            Some("testuser"),
            Some("127.0.0.1"),
        );
        // Act: serialize — exercises enriched_log_json → OCSF → HMAC chain.
        let json = event.enriched_log_json();
        // Assert: required fields present.
        assert!(
            json.contains("JTI_REPLAY_DETECTED"),
            "event name missing: {json}"
        );
        assert!(json.contains("test-jti-001"), "jti field missing: {json}");
        assert!(
            json.contains("keycloak.test"),
            "issuer field missing: {json}"
        );
        assert!(json.contains("testuser"), "user field missing: {json}");
    }

    /// Verify that AuditEvent::jti_store_degraded() constructs correctly for
    /// both enforcement modes used by check_and_record_fs.
    #[test]
    fn test_jti_store_degraded_emits_audit_event() {
        for (enforcement, store_type) in [("strict", "jti"), ("permissive", "nonce")] {
            let event = crate::audit::AuditEvent::jti_store_degraded(
                "No such file or directory",
                enforcement,
                store_type,
            );
            let json = event.enriched_log_json();
            assert!(
                json.contains("JTI_STORE_DEGRADED"),
                "event name missing [{enforcement}]: {json}"
            );
            assert!(
                json.contains(enforcement),
                "enforcement field missing: {json}"
            );
            assert!(
                json.contains(store_type),
                "store_type field missing: {json}"
            );
            // severity_id 5 (Critical) must be present for both enforcement modes.
            assert!(
                json.contains("\"severity_id\":5"),
                "severity_id 5 missing [{enforcement}]: {json}"
            );
        }
    }
}
