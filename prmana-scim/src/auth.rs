//! Bearer token authentication middleware for SCIM endpoints.
//!
//! Validates OAuth 2.0 Bearer tokens against the configured OIDC issuer.
//! The service refuses to start without either a configured `oidc_issuer`
//! (real validation) or the explicit `--insecure-no-auth` flag.

use std::collections::HashMap;
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
        /// Required scope/role value for privileged SCIM operations.
        required_entitlement: String,
        /// Shared TTL-based JWKS cache for this issuer.
        jwks_cache: Arc<JwksCache>,
    },
    /// No-op auth: accept any non-empty Bearer token.
    /// Only reachable via the hidden `--insecure-no-auth` CLI flag.
    Insecure,
}

/// Minimal JWT claims for Bearer token validation.
#[derive(Debug, Deserialize, Default)]
struct BearerClaims {
    #[serde(default)]
    scope: Option<StringOrList>,
    #[serde(default)]
    scp: Option<StringOrList>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    realm_access: Option<RoleList>,
    #[serde(default)]
    resource_access: HashMap<String, RoleList>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringOrList {
    String(String),
    List(Vec<String>),
}

impl StringOrList {
    fn contains(&self, required: &str) -> bool {
        match self {
            Self::String(values) => values.split_whitespace().any(|value| value == required),
            Self::List(values) => values.iter().any(|value| value == required),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct RoleList {
    #[serde(default)]
    roles: Vec<String>,
}

impl BearerClaims {
    fn has_required_entitlement(&self, required: &str, audience: &str) -> bool {
        self.scope
            .as_ref()
            .is_some_and(|scope| scope.contains(required))
            || self.scp.as_ref().is_some_and(|scp| scp.contains(required))
            || self.roles.iter().any(|role| role == required)
            || self
                .realm_access
                .as_ref()
                .is_some_and(|realm| realm.roles.iter().any(|role| role == required))
            || self
                .resource_access
                .get(audience)
                .is_some_and(|resource| resource.roles.iter().any(|role| role == required))
    }
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
                    required_entitlement,
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

                    let claims = match decode::<BearerClaims>(token, &decoding_key, &validation) {
                        Ok(token_data) => token_data.claims,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                issuer = %issuer,
                                "Bearer token validation failed"
                            );
                            return unauthorized("Invalid token");
                        }
                    };

                    if !claims.has_required_entitlement(required_entitlement, audience) {
                        tracing::warn!(
                            issuer = %issuer,
                            audience = %audience,
                            required_entitlement = %required_entitlement,
                            "Bearer token missing required SCIM entitlement"
                        );
                        return unauthorized("Insufficient privileges");
                    }

                    tracing::debug!(
                        issuer = %issuer,
                        required_entitlement = %required_entitlement,
                        "Bearer token validated and authorized"
                    );
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
                .and_then(key_algorithm_to_algorithm)
                .map(|key_alg| key_alg == algorithm)
                .unwrap_or(false)
        })
        .and_then(|jwk| DecodingKey::from_jwk(jwk).ok())
}

fn key_algorithm_to_algorithm(key_algorithm: jsonwebtoken::jwk::KeyAlgorithm) -> Option<Algorithm> {
    use jsonwebtoken::jwk::KeyAlgorithm;

    match key_algorithm {
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;
    use tower::ServiceExt;

    use super::*;

    const TEST_RSA_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQD3FdWl1UmI4wmI
7QYbbGKf9ancLwOsG4L1OMJrDZxxJA+PojeUhRg8A/F+uwdvmDxFR035hHCwLQAO
aM0w7m+83w9wOCs9At9Y0g7C0rqWI7izeDFE0ztixgYY4m2U1V7s2p5S4jQhfkzF
tYykxV2MHhHJ7FqyWJct34JDTPfXtOuwWZv7t9TrOPwozRVDbi+yQN5f9Ea4OFWt
oTd8/MtNielaYgvEXEI8Qmo2jEK6DDQyk1JuYpKOwd996QqtbWQNxaL8YvEP/5wQ
/BuEY9FUf24u8RWky61xoowCx1b0LDf4guVeXUvbMj/5rB1M3iuP2qZhIom3TQ30
R1RG2XOLAgMBAAECggEBAL0IRGLR8ac7Y0ERbVmvqyiLzv84LMwQZDltyjgSurxI
hWszBOiohqjrr2dweTjkNEAgVERwEbKHSwK7JTipQm0yDmKhZlsQBoWydz6P79YL
0DPl4XOxUz63F1UUbheuwifc/cGVc6KoON4NjmNE59PZ8WwVWjIV2ttqowMQMJEi
RU+rY7DWWzjwJWtDplxgTBO8A8qn8bT5wTWB4qFXrW8PUiOrtn/oaUqxR0o2rHqL
ltEWZSAiqquqwwWgkUQnZNK9rRmEgnp1Ot1RsfaVPYPmnt+AlJH4rQNs7j0yH+9U
A04zv7kBdG+YxHoNAC0AZ5Y2YLiWGs5USHSF7cJfA7ECgYEA/mdwwWkw0AnapIX8
FREuLx1bZOGzgyrxxoQltLDyjvmyBc0cAWVVN9i8ZGfu9C5+OPnAMzDyQLj9VH+c
Vo2gnoq4R+VTIod5hkLXy+5mGBhR4Z0nOs2KoLTLPIq1d62NziG9Ispv0jDQXI3H
B3X5glopKCwtaRukGTLuNx+h9kkCgYEA+KKj+tB7JIT/XL/6/NthrtZnRY2xvPna
c/uE/y76jUAyipvXWdMX17+0uHD/7VG7I+1W4aFxLvx3sSMIa0qT/CDHNov95pY/
6hjD8+JbjB/izm277QPCmXVQaWFeF0oSEm/Jwh/q73do+t5Fzvx0It9yPM06lwEd
85zQaNr+SzMCgYA3wD9rgzvZO2+Ywmv9yegPFyXiM7v9MLoPQQJqWKSvRHUI5GwQ
uj40oOCYOFabWFz86259SWqtWFzb2aNPLHZYiBneV5kiZgHxtFBKNpJVEW9QO/pO
3qBUm4o2WEdwVK5Qz//80dQzgdMHlWJadjYZpNyEGzpQYGhTxV+C4QHDUQKBgQDq
7aJLh1oTs6cmGDArY471CJkj2zKqANss4+dSxyzu8k3PMllVAmRw8y7rZ7oqnyNY
WxXQtB6h6uOdeCCoYBtcDAyvua76hdV2eFgOxT8DM822h3EeDoN9RJ/qMpoZH1/c
E8xrpIT0J7wF7qe/YELMAJ2MXc6Sh/epC+7QZLwKiQKBgQCf/F7DCBBcqG6Tt/Fu
fJUOii35XzSg1zwVbLS99x90cxoPgUUKSkTVFAnkKJnBAg46ERs41Q5344Pjk63l
4UGfctqJK/CA3YtTW3oBVFan91IxvhN6g5bOGyOvHYLTVxxrqUs+qOyhjXFL5FnN
3IkQ3oAtqqrQ/P5oguZFR643Ig==
-----END PRIVATE KEY-----"#;

    fn validated_test_jwks() -> jsonwebtoken::jwk::JwkSet {
        serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": "poc-key",
                "alg": "RS256",
                "use": "sig",
                "n": "9xXVpdVJiOMJiO0GG2xin_Wp3C8DrBuC9TjCaw2ccSQPj6I3lIUYPAPxfrsHb5g8RUdN-YRwsC0ADmjNMO5vvN8PcDgrPQLfWNIOwtK6liO4s3gxRNM7YsYGGOJtlNVe7NqeUuI0IX5MxbWMpMVdjB4RyexasliXLd-CQ0z317TrsFmb-7fU6zj8KM0VQ24vskDeX_RGuDhVraE3fPzLTYnpWmILxFxCPEJqNoxCugw0MpNSbmKSjsHffekKrW1kDcWi_GLxD_-cEPwbhGPRVH9uLvEVpMutcaKMAsdW9Cw3-ILlXl1L2zI_-awdTN4rj9qmYSKJt00N9EdURtlziw",
                "e": "AQAB"
            }]
        }))
        .unwrap()
    }

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

    #[test]
    fn test_key_algorithm_mapping_is_explicit() {
        use jsonwebtoken::jwk::KeyAlgorithm;

        assert_eq!(
            key_algorithm_to_algorithm(KeyAlgorithm::RS256),
            Some(Algorithm::RS256)
        );
        assert_eq!(
            key_algorithm_to_algorithm(KeyAlgorithm::ES256),
            Some(Algorithm::ES256)
        );
        assert_eq!(
            key_algorithm_to_algorithm(KeyAlgorithm::EdDSA),
            Some(Algorithm::EdDSA)
        );
        assert_eq!(key_algorithm_to_algorithm(KeyAlgorithm::HS256), None);
    }

    async fn ok_handler() -> &'static str {
        "ok"
    }

    #[derive(Debug, Serialize)]
    struct TestBearerClaims<'a> {
        iss: &'a str,
        aud: &'a str,
        sub: &'a str,
        exp: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<&'a str>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        roles: Vec<&'a str>,
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

    fn test_app_validated(required_entitlement: &str) -> Router {
        let cache = Arc::new(JwksCache::new(Duration::from_secs(300)));
        let mut guard = cache.inner.try_write().unwrap();
        *guard = Some(CachedJwks {
            jwks: validated_test_jwks(),
            fetched_at: tokio::time::Instant::now(),
        });
        drop(guard);

        let auth_mode = Arc::new(AuthMode::Validated {
            issuer: "https://idp.example.com".into(),
            audience: "prmana-scim".into(),
            required_entitlement: required_entitlement.into(),
            jwks_cache: cache,
        });

        Router::new()
            .route("/test", get(ok_handler))
            .layer(middleware::from_fn_with_state(
                auth_mode.clone(),
                auth_middleware,
            ))
            .with_state(auth_mode)
    }

    fn signed_test_token(scope: Option<&str>, roles: &[&str]) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("poc-key".to_string());

        encode(
            &header,
            &TestBearerClaims {
                iss: "https://idp.example.com",
                aud: "prmana-scim",
                sub: "alice",
                exp: 4_102_444_800,
                scope,
                roles: roles.to_vec(),
            },
            &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).unwrap(),
        )
        .unwrap()
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
            audience: "prmana-scim".into(),
            required_entitlement: "scim:provision".into(),
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
    async fn test_validated_mode_rejects_token_missing_required_entitlement() {
        let app = test_app_validated("scim:provision");
        let token = signed_test_token(None, &[]);

        let req = Request::builder()
            .uri("/test")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_validated_mode_accepts_required_scope() {
        let app = test_app_validated("scim:provision");
        let token = signed_test_token(Some("openid profile scim:provision"), &[]);

        let req = Request::builder()
            .uri("/test")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_validated_mode_accepts_required_role() {
        let app = test_app_validated("scim:provision");
        let token = signed_test_token(None, &["scim:provision"]);

        let req = Request::builder()
            .uri("/test")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
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
