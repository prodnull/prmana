//! JWKS (JSON Web Key Set) fetching and caching.
//!
//! This module handles:
//! - OIDC discovery to find the JWKS URI
//! - Fetching and parsing JWKS
//! - Caching with TTL and rotation support
//! - Key lookup by kid (key ID)

use jsonwebtoken::jwk::{Jwk, JwkSet};
use serde::Deserialize;
use std::sync::RwLock;
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

/// OIDC Discovery document (partial)
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
    issuer: String,
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
}

impl JwksProvider {
    /// Create a new JWKS provider for the given issuer
    pub fn new(issuer: &str) -> Self {
        Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            cache: RwLock::new(None),
            cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
        }
    }

    /// Create with custom cache TTL
    pub fn with_cache_ttl(issuer: &str, ttl_secs: u64) -> Self {
        Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            cache: RwLock::new(None),
            cache_ttl: Duration::from_secs(ttl_secs),
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
            let cache = self.cache.read().unwrap();
            if cache.is_none() || self.is_cache_expired(&cache) {
                drop(cache);
                self.refresh_jwks()?;
            }
        }

        let cache = self.cache.read().unwrap();
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
            let cache = self.cache.read().unwrap();
            if cache.is_none() || self.is_cache_expired(&cache) {
                drop(cache);
                self.refresh_jwks()?;
            }
        }

        let cache = self.cache.read().unwrap();
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
        let mut cache = self.cache.write().unwrap();
        *cache = Some(CachedJwks {
            jwks,
            fetched_at: Instant::now(),
            jwks_uri: discovery.jwks_uri,
        });

        Ok(())
    }

    fn get_key_from_cache(&self, kid: &str) -> Option<Jwk> {
        let cache = self.cache.read().unwrap();

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
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
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
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
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

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
