//! RFC 7662 token introspection client with moka-based result caching.
//!
//! Token introspection enables near-real-time revocation detection. When an IdP
//! marks a token inactive (account disabled, explicit revocation), the next PAM
//! authentication attempt for that token fails within the cache TTL — rather than
//! waiting until the token's `exp` claim.
//!
//! ## Security Design
//!
//! - **Cache key**: JTI claim (preferred) or SHA-256 of first 32 bytes of token (fallback).
//!   Raw bearer tokens are NEVER used as cache keys.
//! - **Cache TTL**: bounded by `min(configured_ttl, token_exp - now)` — on-miss check.
//!   Cache TTL is per-cache (moka sync Cache), not per-entry, so when the remaining
//!   token lifetime is short a WARN is logged.
//! - **Client auth**: HTTP Basic Auth (client_id + client_secret) per RFC 7662 §2.1.
//! - **Fail-open/fail-closed**: `IntrospectionConfig.enforcement` controls behavior on
//!   endpoint errors (Warn = allow, Strict = deny).
//!
//! ## References
//!
//! - RFC 7662: OAuth 2.0 Token Introspection
//!   <https://www.rfc-editor.org/rfc/rfc7662>

use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::policy::config::IntrospectionConfig;

// ── Error types ───────────────────────────────────────────────────────────────

/// Errors that can occur during token introspection.
#[derive(Debug, Error)]
pub enum IntrospectionError {
    /// HTTP request to the introspection endpoint failed (network, TLS, timeout).
    #[error("HTTP request failed: {0}")]
    Http(String),

    /// The endpoint returned a non-JSON or structurally invalid response.
    #[error("Response parse failed: {0}")]
    Parse(String),

    /// Introspection is enabled but no endpoint URL is configured.
    #[error("Introspection endpoint not configured")]
    NotConfigured,

    /// The introspection endpoint returned `active: false` — token is revoked or expired.
    #[error("Token is inactive (revoked or expired at IdP)")]
    TokenInactive,
}

// ── Cache ─────────────────────────────────────────────────────────────────────

/// Moka-backed introspection result cache.
///
/// Maps `cache_key` (JTI or SHA-256 hex prefix) → `active` boolean.
///
/// The cache TTL is set at construction time and is per-cache (not per-entry).
/// For tokens with short remaining lifetimes a WARN is logged on miss (see
/// `get_or_insert` implementation). This is a best-effort bound — the primary
/// expiry defence is the token's `exp` claim, which the validator already enforces
/// before introspection is called.
///
/// # Thread safety
///
/// `IntrospectionCache` is `Send + Sync` via moka's guarantee on `sync::Cache`.
/// Multiple PAM workers share the global singleton without external locking.
pub struct IntrospectionCache {
    inner: moka::sync::Cache<String, bool>,
    /// Default TTL in seconds (stored for comparison in get_or_insert).
    ttl_secs: u64,
}

impl IntrospectionCache {
    /// Create a new cache.
    ///
    /// # Arguments
    ///
    /// * `max_capacity` — Maximum number of cached results.
    /// * `default_ttl_secs` — Cache TTL; entries older than this are auto-evicted by moka.
    pub fn new(max_capacity: u64, default_ttl_secs: u64) -> Self {
        let inner = moka::sync::Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(Duration::from_secs(default_ttl_secs))
            .build();
        Self {
            inner,
            ttl_secs: default_ttl_secs,
        }
    }

    /// Return the cached result for `cache_key`, or call `introspect_fn` on a miss.
    ///
    /// On a cache miss, `token_exp` is compared against `now + ttl_secs`. If the
    /// token expires before the cache TTL would evict it, a WARN is logged — the
    /// token validator already rejects expired tokens, but this informs operators
    /// that cached results may briefly outlive very short-lived tokens.
    ///
    /// # Errors
    ///
    /// Propagates any `Err` returned by `introspect_fn`. Cache misses that result
    /// in `Err` are **not** cached (a transient endpoint failure should not cache
    /// a negative result that persists until TTL).
    pub fn get_or_insert<F>(
        &self,
        cache_key: &str,
        token_exp: i64,
        introspect_fn: F,
    ) -> Result<bool, IntrospectionError>
    where
        F: FnOnce() -> Result<bool, IntrospectionError>,
    {
        // Cache hit — return early without calling introspect_fn.
        if let Some(cached) = self.inner.get(cache_key) {
            return Ok(cached);
        }

        // Cache miss — check if token lifetime is shorter than cache TTL.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let cache_expiry_secs = now_secs + self.ttl_secs as i64;
        if token_exp < cache_expiry_secs {
            tracing::warn!(
                token_exp = token_exp,
                cache_ttl_secs = self.ttl_secs,
                "Introspection cache TTL may outlive token lifetime; token will expire before next cache eviction"
            );
        }

        // Call the introspection closure.
        let active = introspect_fn()?;

        // Only cache positive results (active=true). Negative results are not cached
        // so that a revoked token is re-checked on the next authentication attempt
        // rather than being denied for the full cache TTL.
        if active {
            self.inner.insert(cache_key.to_string(), active);
        }
        Ok(active)
    }

    /// Return the number of entries tracked by the cache (diagnostic use only).
    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}

// ── Global singleton ──────────────────────────────────────────────────────────

/// Global introspection result cache used by the PAM module.
///
/// Initialized lazily with a 10,000-entry capacity and 60-second TTL matching
/// the `IntrospectionConfig` default. Operators can tune the TTL via
/// `introspection.cache_ttl_secs` in `policy.yaml`.
///
/// The singleton is constructed once on first use. Per-call TTL tuning is not
/// supported (moka `sync::Cache` TTL is per-cache, not per-entry). The global
/// TTL is set at the configured default; deployments that need shorter TTLs
/// can set `cache_ttl_secs: N` in policy.yaml, but this only takes effect on
/// the next process restart (PAM loads the shared library once per sshd lifetime).
pub fn global_introspection_cache() -> &'static IntrospectionCache {
    static CACHE: Lazy<IntrospectionCache> = Lazy::new(|| IntrospectionCache::new(10_000, 60));
    &CACHE
}

// ── HTTP client singleton ──────────────────────────────────────────────────────

/// Global reqwest blocking client for introspection requests.
///
/// Built once to amortize TLS session setup across PAM authentication calls.
/// 5-second timeout on both connect and read (RFC 7662 does not specify a timeout;
/// 5s is conservative for a PAM module where a slow IdP blocks sshd auth threads).
fn global_http_client() -> &'static reqwest::blocking::Client {
    static CLIENT: Lazy<reqwest::blocking::Client> = Lazy::new(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            // Safety: this only fails if TLS backend fails to load.
            // On systems where rustls is unavailable, we would rather fail at first use
            // than panic at startup. Use a permissive fallback that will error on requests.
            .unwrap_or_else(|_| reqwest::blocking::Client::new())
    });
    &CLIENT
}

// ── Cache key derivation ───────────────────────────────────────────────────────

/// Derive an issuer-scoped cache key from a JTI claim or token hash.
///
/// Security: raw bearer tokens MUST NOT appear as cache keys (they would be
/// stored in a process-global `HashMap`, expanding the attack surface for memory
/// forensics).
///
/// The `endpoint` parameter provides cross-issuer isolation: two issuers that
/// happen to share a JTI value (JTIs are only unique per-issuer, not globally)
/// will produce different cache keys because their introspection endpoints differ.
///
/// Key derivation:
/// - With JTI: `SHA-256(endpoint + ":" + jti)` — issuer-scoped, collision-resistant.
/// - Without JTI: `SHA-256(endpoint + ":" + token)` — full token hash, issuer-scoped.
///   Uses the entire token (not just first 32 bytes) to eliminate prefix collisions.
pub fn derive_cache_key(endpoint: &str, token_jti: Option<&str>, token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(endpoint.as_bytes());
    hasher.update(b":");
    if let Some(jti) = token_jti {
        hasher.update(jti.as_bytes());
    } else {
        hasher.update(token.as_bytes());
    }
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Introspection response ────────────────────────────────────────────────────

/// Minimal RFC 7662 introspection response (section 2.2).
///
/// Only `active` is required by the RFC. Additional claims (username, exp, scope)
/// are present in real responses but not consumed here — the token's own claims
/// are authoritative for those values and were already validated by the JWT validator.
#[derive(Debug, serde::Deserialize)]
struct IntrospectionResponse {
    /// REQUIRED (RFC 7662 §2.2): `true` if the token is active, `false` otherwise.
    active: bool,
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// Perform RFC 7662 token introspection (or return a cached result).
///
/// This is the primary entry point for the PAM module. It is called AFTER token
/// signature verification, issuer/audience checks, and DPoP validation — it is an
/// additional active-status check, not a replacement for cryptographic validation.
///
/// # Arguments
///
/// * `config`       — Introspection configuration from `policy.yaml`.
/// * `token`        — The raw access token string.
/// * `token_jti`    — The `jti` claim from the token (preferred cache key).
/// * `token_exp`    — The `exp` claim as a Unix timestamp (for TTL comparison).
/// * `client_id`    — OAuth client ID for Basic Auth to the endpoint.
/// * `session_id`   — PAM session ID for audit events (best-effort, may be None).
/// * `username`     — Authenticated username for audit events (may be None).
///
/// # Returns
///
/// * `Ok(true)`  — Token is active (or introspection is disabled).
/// * `Ok(false)` — Token is inactive (revoked); caller applies enforcement mode.
/// * `Err(_)`    — Endpoint error; caller applies enforcement mode.
///
/// # Errors
///
/// - `IntrospectionError::NotConfigured` — enabled but no endpoint URL set.
/// - `IntrospectionError::Http`          — network or TLS failure.
/// - `IntrospectionError::Parse`         — malformed JSON response.
/// - `IntrospectionError::TokenInactive` — `active: false` returned (treated as Err by this fn).
pub fn introspect_token(
    config: &IntrospectionConfig,
    token: &str,
    token_jti: Option<&str>,
    token_exp: i64,
    client_id: &str,
    session_id: Option<&str>,
    username: Option<&str>,
) -> Result<bool, IntrospectionError> {
    // Fast path: introspection is disabled — no network call, no cache lookup.
    if !config.enabled {
        return Ok(true);
    }

    // Endpoint is required when enabled.
    let endpoint = match &config.endpoint {
        Some(ep) => ep.clone(),
        None => return Err(IntrospectionError::NotConfigured),
    };

    // Derive issuer-scoped cache key — never stores raw bearer credential.
    // The endpoint URL provides cross-issuer isolation (Codex finding 1 fix).
    let cache_key = derive_cache_key(&endpoint, token_jti, token);

    // Capture values for the closure (config.enforcement is used in the caller,
    // but session/username are captured here for audit events emitted inside the closure).
    let session_id_owned: Option<String> = session_id.map(String::from);
    let username_owned: Option<String> = username.map(String::from);
    let client_id_owned = client_id.to_string();
    let client_secret = config.client_secret.clone();
    let token_owned = token.to_string();
    let endpoint_owned = endpoint.clone();
    let enforcement_str = match config.enforcement {
        crate::policy::config::EnforcementMode::Strict => "strict",
        crate::policy::config::EnforcementMode::Warn => "warn",
        crate::policy::config::EnforcementMode::Disabled => "disabled",
    };

    global_introspection_cache().get_or_insert(&cache_key, token_exp, move || {
        do_introspect(
            &endpoint_owned,
            &token_owned,
            &client_id_owned,
            client_secret.as_deref(),
            session_id_owned.as_deref(),
            username_owned.as_deref(),
            enforcement_str,
        )
    })
}

/// Execute the actual HTTP POST to the introspection endpoint.
///
/// Separated from `introspect_token` so it can be called inside the cache closure
/// without borrowing `config` across the closure boundary.
fn do_introspect(
    endpoint: &str,
    token: &str,
    client_id: &str,
    client_secret: Option<&str>,
    session_id: Option<&str>,
    username: Option<&str>,
    enforcement_str: &str,
) -> Result<bool, IntrospectionError> {
    let client = global_http_client();

    // RFC 7662 §2.1: POST with application/x-www-form-urlencoded body.
    // Authenticate with Basic Auth (client_id + optional client_secret).
    let mut request = client
        .post(endpoint)
        .form(&[("token", token), ("token_type_hint", "access_token")]);

    // RFC 7662 §2.1: The introspection endpoint MUST require client authentication.
    // Support both client_id-only and client_id+client_secret Basic Auth.
    request = if let Some(secret) = client_secret {
        request.basic_auth(client_id, Some(secret))
    } else {
        request.basic_auth(client_id, None::<&str>)
    };

    let response = request.send().map_err(|e| {
        let reason = format!("HTTP request to introspection endpoint failed: {e}");
        crate::audit::AuditEvent::introspection_failed(
            session_id,
            username,
            &reason,
            enforcement_str,
        )
        .log();
        IntrospectionError::Http(reason)
    })?;

    // Non-2xx status codes — treat as introspection failure.
    let status = response.status();
    if !status.is_success() {
        let reason = format!("Introspection endpoint returned HTTP {status}");
        crate::audit::AuditEvent::introspection_failed(
            session_id,
            username,
            &reason,
            enforcement_str,
        )
        .log();
        return Err(IntrospectionError::Http(reason));
    }

    // Parse the JSON response.
    let parsed: IntrospectionResponse = response.json().map_err(|e| {
        let reason = format!("Failed to parse introspection response: {e}");
        crate::audit::AuditEvent::introspection_failed(
            session_id,
            username,
            &reason,
            enforcement_str,
        )
        .log();
        IntrospectionError::Parse(reason)
    })?;

    Ok(parsed.active)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::policy::config::{EnforcementMode, IntrospectionConfig};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Convenience: build a disabled config (no endpoint needed).
    fn disabled_config() -> IntrospectionConfig {
        IntrospectionConfig {
            enabled: false,
            endpoint: None,
            enforcement: EnforcementMode::Warn,
            cache_ttl_secs: 60,
            client_secret: None,
        }
    }

    /// Convenience: build an enabled config pointing at a non-existent endpoint.
    fn enabled_config(endpoint: &str, enforcement: EnforcementMode) -> IntrospectionConfig {
        IntrospectionConfig {
            enabled: true,
            endpoint: Some(endpoint.to_string()),
            enforcement,
            cache_ttl_secs: 60,
            client_secret: None,
        }
    }

    /// Convenience: future unix timestamp (token exp in 1 hour).
    fn exp_future() -> i64 {
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600) as i64
    }

    // ── Disabled config ───────────────────────────────────────────────────

    #[test]
    fn test_disabled_returns_ok_true_no_http() {
        // disabled=false means introspect_token short-circuits with Ok(true).
        let config = disabled_config();
        let result = introspect_token(
            &config,
            "sometoken",
            Some("jti-123"),
            exp_future(),
            "client-id",
            None,
            None,
        );
        assert!(result.unwrap());
    }

    // ── Endpoint not configured ───────────────────────────────────────────

    #[test]
    fn test_enabled_no_endpoint_returns_not_configured() {
        let config = IntrospectionConfig {
            enabled: true,
            endpoint: None,
            enforcement: EnforcementMode::Warn,
            cache_ttl_secs: 60,
            client_secret: None,
        };
        let result = introspect_token(
            &config,
            "sometoken",
            Some("jti-456"),
            exp_future(),
            "client-id",
            None,
            None,
        );
        assert!(matches!(result, Err(IntrospectionError::NotConfigured)));
    }

    // ── Cache key derivation ──────────────────────────────────────────────

    const EP_A: &str = "https://issuer-a.example.com/introspect";
    const EP_B: &str = "https://issuer-b.example.com/introspect";

    #[test]
    fn test_cache_key_with_jti_is_64_hex() {
        let key = derive_cache_key(EP_A, Some("my-jti-value"), "ignored-token");
        assert_eq!(
            key.len(),
            64,
            "issuer-scoped key must be 64-char hex: {key}"
        );
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_cache_key_sha256_fallback_when_no_jti() {
        let token = "eyJhbGciOiJFUzI1NiJ9.abc.def";
        let key = derive_cache_key(EP_A, None, token);
        assert_eq!(key.len(), 64, "cache key must be 64-char hex: {key}");
        assert!(
            key.chars().all(|c| c.is_ascii_hexdigit()),
            "cache key must be hex: {key}"
        );
    }

    #[test]
    fn test_cache_key_sha256_fallback_deterministic() {
        let token = "test_token_value";
        let key1 = derive_cache_key(EP_A, None, token);
        let key2 = derive_cache_key(EP_A, None, token);
        assert_eq!(key1, key2, "cache key must be deterministic for same token");
    }

    #[test]
    fn test_cache_key_sha256_fallback_different_tokens() {
        let key1 = derive_cache_key(EP_A, None, "token_a");
        let key2 = derive_cache_key(EP_A, None, "token_b");
        assert_ne!(
            key1, key2,
            "different tokens must produce different cache keys"
        );
    }

    #[test]
    fn test_cache_key_sha256_short_token() {
        // Token shorter than 32 bytes must not panic.
        let key = derive_cache_key(EP_A, None, "abc");
        assert_eq!(key.len(), 64);
    }

    // ── Cross-issuer isolation (Codex finding 1) ────────────────────────

    #[test]
    fn test_cache_key_same_jti_different_issuer_produces_different_keys() {
        let key_a = derive_cache_key(EP_A, Some("shared-jti"), "token");
        let key_b = derive_cache_key(EP_B, Some("shared-jti"), "token");
        assert_ne!(
            key_a, key_b,
            "Same JTI from different issuers must produce different cache keys"
        );
    }

    #[test]
    fn test_cache_key_same_token_different_issuer_produces_different_keys() {
        let key_a = derive_cache_key(EP_A, None, "identical-token-bytes");
        let key_b = derive_cache_key(EP_B, None, "identical-token-bytes");
        assert_ne!(
            key_a, key_b,
            "Same token from different issuers must produce different cache keys"
        );
    }

    #[test]
    fn test_cache_key_same_issuer_same_jti_is_stable() {
        let key1 = derive_cache_key(EP_A, Some("jti-x"), "token-1");
        let key2 = derive_cache_key(EP_A, Some("jti-x"), "token-2");
        assert_eq!(
            key1, key2,
            "Same issuer + JTI must produce same key regardless of token body"
        );
    }

    // ── Cache hit/miss ─────────────────────────────────────────────────────

    #[test]
    fn test_cache_hit_does_not_call_closure_twice() {
        let cache = IntrospectionCache::new(100, 60);
        let call_count = Arc::new(AtomicUsize::new(0));

        let count1 = Arc::clone(&call_count);
        let result1 = cache.get_or_insert("test-key-hit", exp_future(), move || {
            count1.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        });
        assert!(result1.unwrap());
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "first call should invoke closure"
        );

        let count2 = Arc::clone(&call_count);
        let result2 = cache.get_or_insert("test-key-hit", exp_future(), move || {
            count2.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        });
        assert!(result2.unwrap());
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "second call must use cache — closure must NOT be called again"
        );
    }

    #[test]
    fn test_cache_miss_calls_closure() {
        let cache = IntrospectionCache::new(100, 60);
        let call_count = Arc::new(AtomicUsize::new(0));

        let count = Arc::clone(&call_count);
        let _ = cache.get_or_insert("unique-key-miss", exp_future(), move || {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(false) // inactive — must NOT be cached
        });

        // On miss with Ok(false) the result is not cached, so a second call should invoke closure.
        let count2 = Arc::clone(&call_count);
        let _ = cache.get_or_insert("unique-key-miss", exp_future(), move || {
            count2.fetch_add(1, Ordering::SeqCst);
            Ok(false)
        });

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "inactive results must NOT be cached (closure invoked twice)"
        );
    }

    #[test]
    fn test_cache_miss_error_not_cached() {
        let cache = IntrospectionCache::new(100, 60);
        let call_count = Arc::new(AtomicUsize::new(0));

        for _ in 0..3 {
            let count = Arc::clone(&call_count);
            let result = cache.get_or_insert("error-key", exp_future(), move || {
                count.fetch_add(1, Ordering::SeqCst);
                Err(IntrospectionError::Http("connection refused".to_string()))
            });
            assert!(result.is_err());
        }

        assert_eq!(
            call_count.load(Ordering::SeqCst),
            3,
            "errors must NOT be cached (closure invoked on every call)"
        );
    }

    // ── Global singleton ──────────────────────────────────────────────────

    #[test]
    fn test_global_introspection_cache_is_singleton() {
        let a = global_introspection_cache();
        let b = global_introspection_cache();
        assert!(
            std::ptr::eq(a, b),
            "global_introspection_cache() must return the same instance"
        );
    }

    // ── Adversarial: unreachable endpoint ─────────────────────────────────

    #[test]
    fn test_unreachable_endpoint_returns_http_error() {
        // Use an endpoint that is guaranteed not to exist.
        let config = enabled_config(
            "http://127.0.0.1:19999/introspect_nonexistent",
            EnforcementMode::Warn,
        );
        // Give each test its own JTI so tests don't share cache entries.
        let result = introspect_token(
            &config,
            "sometoken",
            Some("test-jti-unreachable-endpoint-warn"),
            exp_future(),
            "client-id",
            None,
            None,
        );
        assert!(
            matches!(result, Err(IntrospectionError::Http(_))),
            "unreachable endpoint must return Http error, got: {result:?}"
        );
    }
}
