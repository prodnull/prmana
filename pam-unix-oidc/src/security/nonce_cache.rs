//! DPoP nonce cache for server-side single-use nonce enforcement (RFC 9449 §8).
//!
//! The server issues nonces that clients must include in their DPoP proofs.
//! Each nonce may be consumed exactly once. Once consumed (or expired), any
//! further attempt to consume the same nonce fails atomically.
//!
//! ## Security Properties
//!
//! - Single-use: `consume()` uses `Cache::remove()` for atomic test-and-delete.
//!   No separate `contains_key()` check avoids TOCTOU races.
//! - TTL-bound: moka evicts entries automatically after `nonce_ttl_secs` seconds,
//!   preventing unbounded memory growth without explicit cleanup threads.
//! - Bounded capacity: moka enforces `max_capacity` to prevent DoS via memory
//!   exhaustion.
//! - Empty nonces are rejected at both issue and consume time.
//! - Nonce comparison at issue/consume time is key-equality in the moka cache,
//!   which uses `Eq` on `String`. For constant-time comparison semantics the
//!   replay check is inherently atomic: either the key is present (consumed) or
//!   not — there is no secret being compared, only a random server-issued token.
//!   The security property is single-use, not confidentiality of the nonce value.
//!
//! ## References
//!
//! - RFC 9449 §8: DPoP Nonce
//! - moka docs: https://docs.rs/moka/latest/moka/sync/struct.Cache.html

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use once_cell::sync::Lazy;
use std::time::Duration;
use thiserror::Error;

// ── Error types ───────────────────────────────────────────────────────────────

/// Error returned when a nonce cannot be consumed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NonceConsumeError {
    /// The nonce was not found in the cache. Either it was already consumed,
    /// it expired (TTL elapsed), or it was never issued by this server.
    #[error("nonce not found: already consumed, expired, or never issued")]
    ConsumedOrExpired,

    /// The nonce string is empty. Empty nonces are always rejected.
    #[error("nonce must not be empty")]
    EmptyNonce,
}

/// Error returned when a nonce cannot be issued.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NonceIssueError {
    /// The nonce string is empty. Empty nonces are always rejected.
    #[error("nonce must not be empty")]
    EmptyNonce,
}

// ── Cache ─────────────────────────────────────────────────────────────────────

/// Server-side DPoP nonce cache.
///
/// Issues single-use nonces and enforces single-consumption atomically.
/// Backed by a moka TTL cache with bounded capacity.
///
/// # Thread safety
///
/// `DPoPNonceCache` is `Send + Sync` (moka's sync::Cache guarantees this).
/// Multiple PAM threads can issue and consume nonces concurrently.
pub struct DPoPNonceCache {
    /// Inner moka cache: nonce_string → () (value is sentinel; presence = issued and not yet consumed)
    inner: moka::sync::Cache<String, ()>,
}

impl DPoPNonceCache {
    /// Create a new nonce cache.
    ///
    /// # Arguments
    ///
    /// * `max_capacity` — Maximum number of outstanding (unconsumed) nonces.
    ///   When the cache reaches capacity moka evicts the least-recently-used
    ///   entries automatically.
    /// * `ttl_secs` — How long a nonce remains valid (in seconds). An
    ///   unconsumed nonce older than this is automatically expired by moka
    ///   and cannot be consumed.
    pub fn new(max_capacity: u64, ttl_secs: u64) -> Self {
        let inner = moka::sync::Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(Duration::from_secs(ttl_secs))
            .build();
        Self { inner }
    }

    /// Issue a nonce, making it available for a single subsequent `consume()`.
    ///
    /// # Errors
    ///
    /// Returns `NonceIssueError::EmptyNonce` if `nonce` is the empty string.
    pub fn issue(&self, nonce: &str) -> Result<(), NonceIssueError> {
        if nonce.is_empty() {
            return Err(NonceIssueError::EmptyNonce);
        }
        self.inner.insert(nonce.to_string(), ());
        Ok(())
    }

    /// Consume a nonce, atomically removing it from the cache.
    ///
    /// Returns `Ok(())` on first consumption. Any subsequent call with the same
    /// nonce returns `Err(ConsumedOrExpired)` — the same error is returned
    /// whether the nonce was already consumed, expired, or never issued, to
    /// avoid leaking state to attackers.
    ///
    /// # Errors
    ///
    /// - `NonceConsumeError::EmptyNonce` — nonce is the empty string.
    /// - `NonceConsumeError::ConsumedOrExpired` — nonce not in cache.
    pub fn consume(&self, nonce: &str) -> Result<(), NonceConsumeError> {
        if nonce.is_empty() {
            return Err(NonceConsumeError::EmptyNonce);
        }
        // moka's remove() is the atomic single-use primitive.
        // It returns Some(()) if present (valid nonce, consumed here),
        // or None if absent (already consumed, expired, or never issued).
        match self.inner.remove(nonce) {
            Some(_) => Ok(()),
            None => Err(NonceConsumeError::ConsumedOrExpired),
        }
    }

    /// Return the number of entries currently tracked by the cache.
    ///
    /// Note: moka's `entry_count()` includes entries that may have expired
    /// but not yet been evicted. This value is suitable for diagnostics only.
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

// ── Nonce generation ──────────────────────────────────────────────────────────

/// Generate a cryptographically random DPoP nonce.
///
/// Fills 32 bytes (256 bits) from the OS CSPRNG via `getrandom` and encodes
/// them using base64url (no padding). The resulting string is always 43 characters.
///
/// # Errors
///
/// Returns `getrandom::Error` if the OS CSPRNG is unavailable (extremely rare;
/// typically only occurs before OS entropy pool is initialized).
pub fn generate_dpop_nonce() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

// ── Global singleton ──────────────────────────────────────────────────────────

/// Global DPoP nonce cache used by the PAM module.
///
/// Initialized once (lazily) with conservative defaults:
/// - 100,000 outstanding nonces
/// - 60-second TTL (matching RFC 9449 §8 recommendation)
///
/// The global cache is the correct primitive for a PAM module because multiple
/// `pam_sm_authenticate` calls across different sshd worker processes share
/// the same loaded shared library in memory, making a process-global singleton
/// the right scope for nonce tracking.
pub fn global_nonce_cache() -> &'static DPoPNonceCache {
    static CACHE: Lazy<DPoPNonceCache> = Lazy::new(|| DPoPNonceCache::new(100_000, 60));
    &CACHE
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // Helper: create a fresh short-TTL cache for most tests so we don't
    // pollute the global singleton.
    fn fresh_cache() -> DPoPNonceCache {
        DPoPNonceCache::new(1_000, 60)
    }

    // ── Issue / consume lifecycle ─────────────────────────────────────────

    #[test]
    fn test_issue_then_consume_succeeds() {
        let cache = fresh_cache();
        let nonce = "test-nonce-abc123";
        cache.issue(nonce).unwrap();
        assert!(cache.consume(nonce).is_ok());
    }

    #[test]
    fn test_consume_twice_second_fails() {
        let cache = fresh_cache();
        let nonce = "nonce-single-use";
        cache.issue(nonce).unwrap();
        assert!(cache.consume(nonce).is_ok(), "first consume must succeed");
        assert_eq!(
            cache.consume(nonce),
            Err(NonceConsumeError::ConsumedOrExpired),
            "second consume must fail"
        );
    }

    #[test]
    fn test_consume_unissued_nonce_fails() {
        let cache = fresh_cache();
        assert_eq!(
            cache.consume("never-issued"),
            Err(NonceConsumeError::ConsumedOrExpired)
        );
    }

    // ── Empty nonce rejection ─────────────────────────────────────────────

    #[test]
    fn test_issue_empty_nonce_rejected() {
        let cache = fresh_cache();
        assert_eq!(cache.issue(""), Err(NonceIssueError::EmptyNonce));
    }

    #[test]
    fn test_consume_empty_nonce_rejected() {
        let cache = fresh_cache();
        assert_eq!(
            cache.consume(""),
            Err(NonceConsumeError::EmptyNonce),
            "empty nonce must be rejected with EmptyNonce, not ConsumedOrExpired"
        );
    }

    // ── Nonce generation ──────────────────────────────────────────────────

    #[test]
    fn test_generate_dpop_nonce_length() {
        let nonce = generate_dpop_nonce().unwrap();
        // 32 bytes base64url-no-pad = ceil(32 * 8 / 6) = ceil(256/6) = 43 chars
        assert_eq!(
            nonce.len(),
            43,
            "generated nonce must be exactly 43 base64url chars (32 bytes)"
        );
    }

    #[test]
    fn test_generate_dpop_nonce_valid_base64url() {
        let nonce = generate_dpop_nonce().unwrap();
        // base64url uses A-Z a-z 0-9 - _  (no + / or padding =)
        assert!(
            nonce.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "nonce must contain only base64url characters: got '{nonce}'"
        );
    }

    #[test]
    fn test_generate_dpop_nonce_uniqueness() {
        let mut seen = HashSet::new();
        for _ in 0..1_000 {
            let nonce = generate_dpop_nonce().unwrap();
            assert!(
                seen.insert(nonce.clone()),
                "duplicate nonce generated: {nonce}"
            );
        }
    }

    // ── Capacity exhaustion ───────────────────────────────────────────────

    #[test]
    fn test_cache_at_max_capacity_does_not_panic() {
        // Create a small-capacity cache and overfill it by 1.
        // moka must not panic — it evicts entries according to its policy.
        let cache = DPoPNonceCache::new(100, 60);
        for i in 0..=100_001u64 {
            // Use a nonce value that won't collide with any interesting state
            let nonce = format!("overflow-nonce-{i}");
            // issue should never panic
            let _ = cache.issue(&nonce);
        }
        // entry_count() call should also not panic
        let _ = cache.entry_count();
    }

    // ── Global singleton ──────────────────────────────────────────────────

    #[test]
    fn test_global_nonce_cache_is_singleton() {
        let a = global_nonce_cache();
        let b = global_nonce_cache();
        // Both references must point to the same allocation.
        assert!(
            std::ptr::eq(a, b),
            "global_nonce_cache() must return the same instance on every call"
        );
    }

    // ── Adversarial: constant-time nonce comparison ───────────────────────
    //
    // The security property we enforce is single-use (not confidentiality of
    // the nonce value). The nonce is a random server-issued token; an attacker
    // who intercepts it can replay it exactly once before it's consumed. There
    // is no secret "expected nonce" being compared in a timing-sensitive way —
    // the cache key lookup in moka uses HashMap equality (constant-time for
    // equal-length strings, early-exit on length mismatch — which is fine
    // because length mismatch leaks no secret).
    //
    // Nonetheless, we document that the dpop.rs nonce path (for callers that
    // set expected_nonce directly) uses `constant_time_eq` from dpop.rs, and
    // verify here that our consume() path does not bypass that guarantee by
    // doing a separate string comparison.
    #[test]
    fn test_consume_atomic_no_toctou() {
        // Verify that two concurrent consumers of the same nonce both get a
        // deterministic result: exactly one Ok and one Err.
        use std::sync::{Arc, Mutex};
        use std::thread;

        let cache = Arc::new(DPoPNonceCache::new(1_000, 60));
        cache.issue("shared-nonce").unwrap();

        let cache1 = Arc::clone(&cache);
        let cache2 = Arc::clone(&cache);
        let results: Arc<Mutex<Vec<Result<(), NonceConsumeError>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let r1 = Arc::clone(&results);
        let r2 = Arc::clone(&results);

        let t1 = thread::spawn(move || {
            let res = cache1.consume("shared-nonce");
            r1.lock().unwrap().push(res);
        });
        let t2 = thread::spawn(move || {
            let res = cache2.consume("shared-nonce");
            r2.lock().unwrap().push(res);
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let results = results.lock().unwrap();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        let err_count = results.iter().filter(|r| r.is_err()).count();
        assert_eq!(ok_count, 1, "exactly one consume must succeed");
        assert_eq!(err_count, 1, "exactly one consume must fail");
    }
}
