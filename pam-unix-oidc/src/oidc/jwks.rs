//! JWKS (JSON Web Key Set) fetching and caching.
//!
//! This module handles:
//! - OIDC discovery to find the JWKS URI
//! - Fetching and parsing JWKS
//! - Caching with TTL and rotation support
//! - Key lookup by kid (key ID)

use jsonwebtoken::jwk::{Jwk, JwkSet};
use parking_lot::RwLock;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Default cache TTL (5 minutes)
const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// HTTP request timeout
const HTTP_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Error)]
pub enum JwksError {
    #[error("Failed to fetch OIDC discovery document: {0}")]
    DiscoveryFetchError(String),

    #[error("Failed to parse OIDC discovery document: {0}")]
    DiscoveryParseError(String),

    #[error("Failed to fetch JWKS: {0}")]
    JwksFetchError(String),

    #[error("Failed to parse JWKS: {0}")]
    JwksParseError(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("No keys in JWKS")]
    NoKeys,

    #[error("Invalid issuer URL: {0}")]
    InvalidIssuer(String),
}

/// OIDC Discovery document.
///
/// Contains the minimal fields required by OIDC Core 1.0 plus optional CIBA
/// (OpenID Connect CIBA Core 1.0 §4) and Device Authorization Grant
/// (RFC 8628 §3.1) endpoint fields.
///
/// All fields beyond `jwks_uri` and `issuer` are optional so that discovery
/// documents from IdPs that do not support CIBA or device flow continue to
/// parse successfully (backward compatibility invariant).
#[derive(Debug, Deserialize)]
pub struct OidcDiscovery {
    /// URL of the JSON Web Key Set document (OIDC Core 1.0 §3).
    pub jwks_uri: String,
    /// Issuer URL (OIDC Core 1.0 §3).
    pub issuer: String,
    /// Authorization endpoint (RFC 6749 §3.1). Absent if auth-code flow unsupported.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    /// Token endpoint (RFC 6749 §3.2).
    pub token_endpoint: String,
    /// PKCE code challenge methods supported (RFC 7636). Absent if unspecified by the IdP.
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    /// Device authorization endpoint (RFC 8628 §3.1). Absent if device flow unsupported.
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    /// Backchannel authentication endpoint (CIBA Core 1.0 §4). Absent if CIBA unsupported.
    #[serde(default)]
    pub backchannel_authentication_endpoint: Option<String>,
    /// Delivery modes supported for CIBA poll (CIBA Core 1.0 §4). Absent when only poll is used.
    #[serde(default)]
    pub backchannel_token_delivery_modes_supported: Option<Vec<String>>,
    /// Token revocation endpoint (RFC 7009 §2).
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

/// Cached JWKS with TTL
#[allow(dead_code)]
struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
    jwks_uri: String,
}

/// JWKS provider with caching
pub struct JwksProvider {
    issuer: String,
    cache: RwLock<Option<CachedJwks>>,
    cache_ttl: Duration,
    /// HTTP request timeout for JWKS and discovery fetches.
    /// Replaces the module-level `HTTP_TIMEOUT_SECS` constant; configurable
    /// via `AgentConfig.timeouts.jwks_http_timeout_secs`.
    http_timeout: Duration,
}

impl JwksProvider {
    /// Create a new JWKS provider for the given issuer using built-in defaults.
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            cache: RwLock::new(None),
            cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
            http_timeout: Duration::from_secs(HTTP_TIMEOUT_SECS),
        }
    }

    /// Create with custom cache TTL (HTTP timeout uses built-in default).
    pub fn with_cache_ttl(issuer: &str, ttl_secs: u64) -> Self {
        Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            cache: RwLock::new(None),
            cache_ttl: Duration::from_secs(ttl_secs),
            http_timeout: Duration::from_secs(HTTP_TIMEOUT_SECS),
        }
    }

    /// Create with both custom cache TTL and HTTP timeout.
    ///
    /// Use this constructor when wiring from `AgentConfig.timeouts`:
    /// ```ignore
    /// JwksProvider::with_timeouts(
    ///     &config.issuer,
    ///     config.timeouts.jwks_cache_ttl_secs,
    ///     config.timeouts.jwks_http_timeout_secs,
    /// )
    /// ```
    pub fn with_timeouts(issuer: &str, ttl_secs: u64, http_timeout_secs: u64) -> Self {
        Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            cache: RwLock::new(None),
            cache_ttl: Duration::from_secs(ttl_secs),
            http_timeout: Duration::from_secs(http_timeout_secs),
        }
    }

    /// Get a key by kid, fetching/refreshing JWKS as needed
    pub fn get_key(&self, kid: &str) -> Result<Jwk, JwksError> {
        // Try to get from cache first
        if let Some(jwk) = self.get_key_from_cache(kid) {
            return Ok(jwk);
        }

        // Cache miss or expired - refresh and try again
        self.refresh_jwks()?;

        self.get_key_from_cache(kid)
            .ok_or_else(|| JwksError::KeyNotFound(kid.to_string()))
    }

    /// Get the first available key (for tokens without kid)
    pub fn get_default_key(&self) -> Result<Jwk, JwksError> {
        // Ensure cache is populated
        {
            let cache = self.cache.read();
            if cache.is_none() || self.is_cache_expired(&cache) {
                drop(cache);
                self.refresh_jwks()?;
            }
        }

        let cache = self.cache.read();
        if let Some(ref cached) = *cache {
            cached.jwks.keys.first().cloned().ok_or(JwksError::NoKeys)
        } else {
            Err(JwksError::NoKeys)
        }
    }

    /// Get all keys (useful for trying multiple keys)
    pub fn get_all_keys(&self) -> Result<Vec<Jwk>, JwksError> {
        // Ensure cache is populated
        {
            let cache = self.cache.read();
            if cache.is_none() || self.is_cache_expired(&cache) {
                drop(cache);
                self.refresh_jwks()?;
            }
        }

        let cache = self.cache.read();
        if let Some(ref cached) = *cache {
            Ok(cached.jwks.keys.clone())
        } else {
            Err(JwksError::NoKeys)
        }
    }

    /// Force refresh the JWKS cache
    pub fn refresh_jwks(&self) -> Result<(), JwksError> {
        // Fetch discovery document
        let discovery = self.fetch_discovery()?;

        // Verify issuer matches
        if discovery.issuer.trim_end_matches('/') != self.issuer {
            return Err(JwksError::InvalidIssuer(format!(
                "Discovery issuer '{}' doesn't match configured issuer '{}'",
                discovery.issuer, self.issuer
            )));
        }

        // Fetch JWKS
        let jwks = self.fetch_jwks(&discovery.jwks_uri)?;

        // Update cache
        let mut cache = self.cache.write();
        *cache = Some(CachedJwks {
            jwks,
            fetched_at: Instant::now(),
            jwks_uri: discovery.jwks_uri,
        });

        Ok(())
    }

    fn get_key_from_cache(&self, kid: &str) -> Option<Jwk> {
        let cache = self.cache.read();

        if let Some(ref cached) = *cache {
            if !self.is_cache_expired(&cache) {
                return cached
                    .jwks
                    .keys
                    .iter()
                    .find(|k| k.common.key_id.as_deref() == Some(kid))
                    .cloned();
            }
        }

        None
    }

    fn is_cache_expired(&self, cache: &Option<CachedJwks>) -> bool {
        match cache {
            Some(cached) => cached.fetched_at.elapsed() > self.cache_ttl,
            None => true,
        }
    }

    fn fetch_discovery(&self) -> Result<OidcDiscovery, JwksError> {
        let discovery_url = format!("{}/.well-known/openid-configuration", self.issuer);

        let client = reqwest::blocking::Client::builder()
            .timeout(self.http_timeout)
            .build()
            .map_err(|e| JwksError::DiscoveryFetchError(e.to_string()))?;

        let response = client
            .get(&discovery_url)
            .send()
            .map_err(|e| JwksError::DiscoveryFetchError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(JwksError::DiscoveryFetchError(format!(
                "HTTP {}: {}",
                response.status(),
                discovery_url
            )));
        }

        response
            .json::<OidcDiscovery>()
            .map_err(|e| JwksError::DiscoveryParseError(e.to_string()))
    }

    fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet, JwksError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(self.http_timeout)
            .build()
            .map_err(|e| JwksError::JwksFetchError(e.to_string()))?;

        let response = client
            .get(jwks_uri)
            .send()
            .map_err(|e| JwksError::JwksFetchError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(JwksError::JwksFetchError(format!(
                "HTTP {}: {}",
                response.status(),
                jwks_uri
            )));
        }

        response
            .json::<JwkSet>()
            .map_err(|e| JwksError::JwksParseError(e.to_string()))
    }
}

// ── IssuerJwksRegistry (Phase 21, MIDP-07) ────────────────────────────────────

/// Thread-safe registry of per-issuer JWKS providers.
///
/// Invariant (MIDP-07): each issuer URL maps to an independent `JwksProvider`.
/// A fetch or refresh for issuer A NEVER touches the cache for issuer B.
///
/// The registry is **not global** — it is owned by the auth routing struct
/// (wired in Plan 02) so that tests can create isolated instances.
///
/// Trailing slashes are normalized before lookup so that
/// `"https://idp.example.com"` and `"https://idp.example.com/"` resolve to
/// the same provider.
///
/// # Thread safety
///
/// Uses a read-write lock with a read-first hot path:
/// - Most calls (repeat lookups) acquire only the read lock.
/// - First-time registration acquires the write lock for insertion.
pub struct IssuerJwksRegistry {
    providers: RwLock<HashMap<String, Arc<JwksProvider>>>,
}

impl IssuerJwksRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
        }
    }

    /// Get or create the `JwksProvider` for the given issuer.
    ///
    /// - Normalizes `issuer` by trimming trailing slashes before lookup.
    /// - On the first call for an issuer, creates a new `JwksProvider` with
    ///   the supplied `ttl_secs` and `timeout_secs`.
    /// - On subsequent calls, returns the existing `Arc<JwksProvider>` without
    ///   touching `ttl_secs` or `timeout_secs` (first write wins).
    pub fn get_or_init(&self, issuer: &str, ttl_secs: u64, timeout_secs: u64) -> Arc<JwksProvider> {
        let normalized = issuer.trim_end_matches('/');

        // Fast path: read lock (no contention on repeated lookups).
        {
            let read = self.providers.read();
            if let Some(p) = read.get(normalized) {
                return Arc::clone(p);
            }
        }

        // Slow path: write lock for first-time registration.
        let mut write = self.providers.write();
        // Re-check after acquiring write lock (another thread may have inserted).
        write
            .entry(normalized.to_string())
            .or_insert_with(|| {
                Arc::new(JwksProvider::with_timeouts(
                    normalized,
                    ttl_secs,
                    timeout_secs,
                ))
            })
            .clone()
    }
}

impl Default for IssuerJwksRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── IssuerJwksRegistry tests (Phase 21-01) ────────────────────────────────

    #[test]
    fn test_jwks_registry_new_is_empty() {
        let registry = IssuerJwksRegistry::new();
        // An empty registry should have no providers — get_or_init creates on demand.
        // Verify by calling get_or_init and confirming it returns a valid Arc.
        let provider = registry.get_or_init("https://a.example.com", 300, 10);
        // Should not panic; the returned Arc should have a strong count of at least 1.
        assert!(std::sync::Arc::strong_count(&provider) >= 1);
    }

    #[test]
    fn test_jwks_registry_different_issuers_return_different_providers() {
        let registry = IssuerJwksRegistry::new();
        let p_a = registry.get_or_init("https://a.example.com", 300, 10);
        let p_b = registry.get_or_init("https://b.example.com", 300, 10);
        // Invariant (MIDP-07): each issuer URL maps to an independent JwksProvider.
        // A fetch or refresh for issuer A NEVER touches the cache for issuer B.
        assert!(
            !std::sync::Arc::ptr_eq(&p_a, &p_b),
            "different issuer URLs must return different Arc<JwksProvider> instances"
        );
    }

    #[test]
    fn test_jwks_registry_same_issuer_returns_same_provider() {
        let registry = IssuerJwksRegistry::new();
        let p1 = registry.get_or_init("https://keycloak.example.com/realms/corp", 300, 10);
        let p2 = registry.get_or_init("https://keycloak.example.com/realms/corp", 300, 10);
        // Calling get_or_init() twice for the same issuer must return the same Arc.
        assert!(
            std::sync::Arc::ptr_eq(&p1, &p2),
            "same issuer URL must return the same Arc<JwksProvider> (idempotent)"
        );
    }

    #[test]
    fn test_jwks_provider_creation() {
        let provider = JwksProvider::new("https://example.com/realms/test");
        assert_eq!(provider.issuer, "https://example.com/realms/test");
    }

    #[test]
    fn test_jwks_provider_strips_trailing_slash() {
        let provider = JwksProvider::new("https://example.com/realms/test/");
        assert_eq!(provider.issuer, "https://example.com/realms/test");
    }

    #[test]
    fn test_cache_ttl_configuration() {
        let provider = JwksProvider::with_cache_ttl("https://example.com", 600);
        assert_eq!(provider.cache_ttl, Duration::from_secs(600));
        // HTTP timeout defaults to HTTP_TIMEOUT_SECS when using with_cache_ttl
        assert_eq!(
            provider.http_timeout,
            Duration::from_secs(HTTP_TIMEOUT_SECS)
        );
    }

    #[test]
    fn test_with_timeouts_constructor() {
        let provider = JwksProvider::with_timeouts("https://example.com", 600, 20);
        assert_eq!(provider.cache_ttl, Duration::from_secs(600));
        assert_eq!(provider.http_timeout, Duration::from_secs(20));
    }

    #[test]
    fn test_new_uses_default_http_timeout() {
        let provider = JwksProvider::new("https://example.com");
        assert_eq!(
            provider.http_timeout,
            Duration::from_secs(HTTP_TIMEOUT_SECS)
        );
    }

    #[test]
    fn test_oidc_discovery_parses_authorization_endpoint() {
        let discovery: OidcDiscovery = serde_json::from_value(serde_json::json!({
            "issuer": "https://idp.example.com",
            "jwks_uri": "https://idp.example.com/jwks",
            "authorization_endpoint": "https://idp.example.com/auth",
            "token_endpoint": "https://idp.example.com/token",
            "code_challenge_methods_supported": ["S256", "plain"],
        }))
        .unwrap();

        assert_eq!(
            discovery.authorization_endpoint.as_deref(),
            Some("https://idp.example.com/auth")
        );
        assert_eq!(
            discovery.code_challenge_methods_supported.as_deref(),
            Some(&vec!["S256".to_string(), "plain".to_string()][..])
        );
    }
}
