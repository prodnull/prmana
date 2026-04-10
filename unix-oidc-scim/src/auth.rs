//! Bearer token authentication middleware for SCIM endpoints.
//!
//! Validates OAuth 2.0 Bearer tokens against the configured OIDC issuer.
//! The service refuses to start without either a configured `oidc_issuer`
//! (real validation) or the explicit `--insecure-no-auth` flag.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::schema::ScimError;

/// Fetch JWKS from the issuer's OIDC discovery endpoint.
async fn fetch_jwks(issuer: &str) -> Result<jsonwebtoken::jwk::JwkSet, String> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    // Fetch discovery document
    let discovery: serde_json::Value = client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| format!("OIDC discovery fetch failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("OIDC discovery parse failed: {e}"))?;

    let jwks_uri = discovery
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .ok_or("OIDC discovery missing jwks_uri")?;

    // Fetch JWKS
    let jwks: jsonwebtoken::jwk::JwkSet = client
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| format!("JWKS fetch failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("JWKS parse failed: {e}"))?;

    tracing::info!(jwks_uri = jwks_uri, keys = jwks.keys.len(), "JWKS loaded");
    Ok(jwks)
}

#[derive(Debug)]
struct CachedJwks {
    jwks: jsonwebtoken::jwk::JwkSet,
    fetched_at: tokio::time::Instant,
}

/// TTL-based JWKS cache shared across axum handlers.
#[derive(Debug)]
pub struct JwksCache {
    ttl: Duration,
    inner: RwLock<Option<CachedJwks>>,
}

impl JwksCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: RwLock::new(None),
        }
    }

    async fn refresh_locked<F, Fut>(
        &self,
        guard: &mut Option<CachedJwks>,
        fetcher: F,
    ) -> Result<jsonwebtoken::jwk::JwkSet, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<jsonwebtoken::jwk::JwkSet, String>>,
    {
        let jwks = fetcher().await?;
        *guard = Some(CachedJwks {
            jwks: jwks.clone(),
            fetched_at: tokio::time::Instant::now(),
        });
        Ok(jwks)
    }

    async fn get_with_fetch<F, Fut>(&self, fetcher: F) -> Result<jsonwebtoken::jwk::JwkSet, String>
    where
        F: Fn() -> Fut + Clone,
        Fut: Future<Output = Result<jsonwebtoken::jwk::JwkSet, String>>,
    {
        {
            let guard = self.inner.read().await;
            if let Some(cached) = guard.as_ref() {
                if cached.fetched_at.elapsed() < self.ttl {
                    return Ok(cached.jwks.clone());
                }
            }
        }

        let mut guard = self.inner.write().await;
        if let Some(cached) = guard.as_ref() {
            if cached.fetched_at.elapsed() < self.ttl {
                return Ok(cached.jwks.clone());
            }
        }

        self.refresh_locked(&mut guard, fetcher).await
    }

    async fn decoding_key_with_refresh<F, Fut>(
        &self,
        kid: Option<&str>,
        algorithm: Algorithm,
        fetcher: F,
    ) -> Result<Option<DecodingKey>, String>
    where
        F: Fn() -> Fut + Clone,
        Fut: Future<Output = Result<jsonwebtoken::jwk::JwkSet, String>>,
    {
        let jwks = self.get_with_fetch(fetcher.clone()).await?;
        let mut decoding_key = find_decoding_key(&jwks, kid, algorithm);

        if decoding_key.is_none() && kid.is_some() {
            let refreshed = self.refresh_with_fetch(fetcher).await?;
            decoding_key = find_decoding_key(&refreshed, kid, algorithm);
        }

        Ok(decoding_key)
    }

    pub async fn refresh(&self, issuer: &str) -> Result<jsonwebtoken::jwk::JwkSet, String> {
        self.refresh_with_fetch(|| fetch_jwks(issuer)).await
    }

    async fn refresh_with_fetch<F, Fut>(
        &self,
        fetcher: F,
    ) -> Result<jsonwebtoken::jwk::JwkSet, String>
    where
        F: Fn() -> Fut + Clone,
        Fut: Future<Output = Result<jsonwebtoken::jwk::JwkSet, String>>,
    {
        let mut guard = self.inner.write().await;
        self.refresh_locked(&mut guard, fetcher).await
    }

    pub async fn get(&self, issuer: &str) -> Result<jsonwebtoken::jwk::JwkSet, String> {
        self.get_with_fetch(|| fetch_jwks(issuer)).await
    }
}

/// Authentication mode for the SCIM service.
///
/// Determined at startup based on configuration and CLI flags.
/// The service refuses to start without an explicit choice.
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// Full JWT validation with JWKS signature verification against the configured OIDC issuer.
    Validated {
        /// OIDC issuer URL (used for `iss` claim validation and JWKS discovery).
        issuer: String,
        /// Expected audience (`aud` claim).
        audience: String,
        /// Shared TTL-based JWKS cache for this issuer.
        jwks_cache: Arc<JwksCache>,
    },
    /// No-op auth: accept any non-empty Bearer token.
    /// Only reachable via the hidden `--insecure-no-auth` CLI flag.
    Insecure,
}

/// Minimal JWT claims for Bearer token validation.
#[derive(Debug, Deserialize)]
struct BearerClaims {
    // Standard claims validated by jsonwebtoken: iss, aud, exp
}

fn unauthorized(detail: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ScimError {
            schemas: vec![crate::schema::SCHEMA_ERROR.into()],
            status: "401".into(),
            detail: Some(detail.into()),
            scim_type: None,
        }),
    )
        .into_response()
}

/// Extract and validate Bearer token from Authorization header.
///
/// In `Validated` mode, the JWT signature is verified against the issuer's
/// JWKS and standard claims (iss, aud, exp) are enforced. In `Insecure`
/// mode (dev only), any non-empty Bearer token is accepted.
pub async fn auth_middleware(
    State(auth_mode): State<Arc<AuthMode>>,
    request: Request,
    next: Next,
) -> Response {
    let auth_header = request.headers().get("authorization");

    match auth_header {
        Some(value) => {
            let value_str = match value.to_str() {
                Ok(v) => v,
                Err(_) => {
                    return unauthorized("Invalid Authorization header encoding");
                }
            };

            if !value_str.starts_with("Bearer ") {
                return unauthorized("Authorization header must use Bearer scheme");
            }

            let token = &value_str[7..];
            if token.is_empty() {
                return unauthorized("Bearer token is empty");
            }

            match auth_mode.as_ref() {
                AuthMode::Insecure => {
                    // --insecure-no-auth: accept any non-empty Bearer token.
                    // The startup banner already logged a CRITICAL warning.
                    tracing::debug!("Insecure mode: skipping token validation");
                }
                AuthMode::Validated {
                    issuer,
                    audience,
                    jwks_cache,
                } => {
                    // Parse JWT header to determine algorithm and key ID.
                    let header = match decode_header(token) {
                        Ok(h) => h,
                        Err(e) => {
                            tracing::warn!(error = %e, "Bearer token has invalid JWT header");
                            return unauthorized("Invalid token");
                        }
                    };
                    let kid = header.kid.as_deref();

                    // Enforce asymmetric algorithms only — never accept "none" or HMAC.
                    // Algorithm confusion attacks (CVE-2016-5431 class) are blocked here.
                    match header.alg {
                        Algorithm::ES256
                        | Algorithm::ES384
                        | Algorithm::RS256
                        | Algorithm::RS384
                        | Algorithm::RS512
                        | Algorithm::PS256
                        | Algorithm::PS384
                        | Algorithm::PS512
                        | Algorithm::EdDSA => {}
                        other => {
                            tracing::warn!(algorithm = ?other, "Bearer token uses disallowed algorithm");
                            return unauthorized("Invalid token");
                        }
                    }

                    // Fetch JWKS from issuer with TTL-based refresh.
                    let decoding_key = match jwks_cache
                        .decoding_key_with_refresh(kid, header.alg, || fetch_jwks(issuer))
                        .await
                    {
                        Ok(Some(key)) => key,
                        Ok(None) => {
                            tracing::warn!(
                                kid = ?kid,
                                algorithm = ?header.alg,
                                "No matching JWKS key for Bearer token"
                            );
                            return unauthorized("Invalid token");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, issuer = %issuer, "Failed to fetch JWKS");
                            return unauthorized("Authentication service unavailable");
                        }
                    };

                    // Full JWT validation: signature + iss + aud + exp.
                    let mut validation = Validation::new(header.alg);
                    validation.set_issuer(&[issuer]);
                    validation.set_audience(&[audience]);

                    if let Err(e) = decode::<BearerClaims>(token, &decoding_key, &validation) {
                        tracing::warn!(
                            error = %e,
                            issuer = %issuer,
                            "Bearer token validation failed"
                        );
                        return unauthorized("Invalid token");
                    }

                    tracing::debug!(issuer = %issuer, "Bearer token validated (signature + claims)");
                }
            }

            next.run(request).await
        }
        None => unauthorized("Authorization header required"),
    }
}

fn find_decoding_key(
    jwks: &jsonwebtoken::jwk::JwkSet,
    kid: Option<&str>,
    algorithm: Algorithm,
) -> Option<DecodingKey> {
    jwks.keys
        .iter()
        .find(|k| {
            if let (Some(header_kid), Some(key_kid)) = (kid, &k.common.key_id) {
                return header_kid == key_kid;
            }
            k.common
                .key_algorithm
                .map(|ka| format!("{ka:?}") == format!("{algorithm:?}"))
                .unwrap_or(false)
        })
        .and_then(|jwk| DecodingKey::from_jwk(jwk).ok())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    use super::*;

    fn test_jwks_with_kid(kid: &str) -> jsonwebtoken::jwk::JwkSet {
        serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": kid,
                "alg": "RS256",
                "n": "sXchmO7QYj0V8vY4aXK6sA9d7A4L0i2x4g9zJ5R6uV0mU2x9m3q6fJ2k7l8n9p0q1r2s3t4u5v6w7x8y9z0",
                "e": "AQAB"
            }]
        }))
        .unwrap()
    }

    async fn ok_handler() -> &'static str {
        "ok"
    }

    /// Build a test app with insecure auth (accepts any non-empty Bearer).
    fn test_app_insecure() -> Router {
        let auth_mode = Arc::new(AuthMode::Insecure);
        Router::new()
            .route("/test", get(ok_handler))
            .layer(middleware::from_fn_with_state(
                auth_mode.clone(),
                auth_middleware,
            ))
            .with_state(auth_mode)
    }

    #[tokio::test]
    async fn test_missing_auth_header_returns_401() {
        let app = test_app_insecure();
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_non_bearer_scheme_returns_401() {
        let app = test_app_insecure();
        let req = Request::builder()
            .uri("/test")
            .header("authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_empty_bearer_token_returns_401() {
        let app = test_app_insecure();
        let req = Request::builder()
            .uri("/test")
            .header("authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_insecure_mode_accepts_any_token() {
        let app = test_app_insecure();
        let req = Request::builder()
            .uri("/test")
            .header("authorization", "Bearer some-valid-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_validated_mode_rejects_non_jwt() {
        let auth_mode = Arc::new(AuthMode::Validated {
            issuer: "https://idp.example.com".into(),
            audience: "unix-oidc-scim".into(),
            jwks_cache: Arc::new(JwksCache::new(Duration::from_secs(300))),
        });
        let app = Router::new()
            .route("/test", get(ok_handler))
            .layer(middleware::from_fn_with_state(
                auth_mode.clone(),
                auth_middleware,
            ))
            .with_state(auth_mode);

        let req = Request::builder()
            .uri("/test")
            .header("authorization", "Bearer not-a-jwt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwks_cache_reuses_entry_within_ttl() {
        let cache = JwksCache::new(Duration::from_secs(60));
        let fetches = Arc::new(AtomicUsize::new(0));

        let fetcher = {
            let fetches = Arc::clone(&fetches);
            move || {
                let fetches = Arc::clone(&fetches);
                async move {
                    fetches.fetch_add(1, Ordering::SeqCst);
                    Ok(test_jwks_with_kid("kid-1"))
                }
            }
        };

        let _ = cache.get_with_fetch(fetcher.clone()).await.unwrap();
        let _ = cache.get_with_fetch(fetcher).await.unwrap();

        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_jwks_cache_refreshes_after_ttl() {
        let cache = JwksCache::new(Duration::from_millis(1));
        let fetches = Arc::new(AtomicUsize::new(0));

        let fetcher = {
            let fetches = Arc::clone(&fetches);
            move || {
                let fetches = Arc::clone(&fetches);
                async move {
                    fetches.fetch_add(1, Ordering::SeqCst);
                    Ok(test_jwks_with_kid("kid-1"))
                }
            }
        };

        let _ = cache.get_with_fetch(fetcher.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let _ = cache.get_with_fetch(fetcher).await.unwrap();

        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_kid_miss_triggers_immediate_refresh() {
        let cache = JwksCache::new(Duration::from_secs(60));
        let fetches = Arc::new(AtomicUsize::new(0));

        let fetcher = {
            let fetches = Arc::clone(&fetches);
            move || {
                let fetches = Arc::clone(&fetches);
                async move {
                    let call = fetches.fetch_add(1, Ordering::SeqCst);
                    Ok(if call == 0 {
                        test_jwks_with_kid("kid-old")
                    } else {
                        test_jwks_with_kid("kid-new")
                    })
                }
            }
        };

        let decoding_key = cache
            .decoding_key_with_refresh(Some("kid-new"), Algorithm::RS256, fetcher)
            .await
            .unwrap();

        assert!(decoding_key.is_some());
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
    }
}
