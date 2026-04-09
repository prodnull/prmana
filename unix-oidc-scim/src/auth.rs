//! Bearer token authentication middleware for SCIM endpoints.
//!
//! Validates OAuth 2.0 Bearer tokens against the configured OIDC issuer.
//! The service refuses to start without either a configured `oidc_issuer`
//! (real validation) or the explicit `--insecure-no-auth` flag.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::OnceCell;

use crate::schema::ScimError;

/// Cached JWKS keys fetched from the issuer's discovery endpoint.
///
/// Lazily initialized on the first request. The `OnceCell` ensures only
/// one fetch occurs even under concurrent requests.
static JWKS_CACHE: OnceCell<jsonwebtoken::jwk::JwkSet> = OnceCell::const_new();

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
                AuthMode::Validated { issuer, audience } => {
                    // Parse JWT header to determine algorithm and key ID.
                    let header = match decode_header(token) {
                        Ok(h) => h,
                        Err(e) => {
                            tracing::warn!(error = %e, "Bearer token has invalid JWT header");
                            return unauthorized("Invalid token");
                        }
                    };

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

                    // Fetch JWKS from issuer (cached after first request).
                    let issuer_clone = issuer.clone();
                    let jwks = match JWKS_CACHE
                        .get_or_try_init(|| fetch_jwks(&issuer_clone))
                        .await
                    {
                        Ok(j) => j,
                        Err(e) => {
                            tracing::error!(error = %e, issuer = %issuer, "Failed to fetch JWKS");
                            return unauthorized("Authentication service unavailable");
                        }
                    };

                    // Find the matching key by kid (if present in header) or by algorithm.
                    let kid = header.kid.as_deref();
                    let decoding_key = jwks
                        .keys
                        .iter()
                        .find(|k| {
                            // Match by kid if both header and key have it
                            if let (Some(hdr_kid), Some(key_kid)) = (kid, &k.common.key_id) {
                                return hdr_kid == key_kid;
                            }
                            // Fall back to algorithm match
                            k.common
                                .key_algorithm
                                .map(|ka| format!("{ka:?}") == format!("{:?}", header.alg))
                                .unwrap_or(false)
                        })
                        .and_then(|jwk| DecodingKey::from_jwk(jwk).ok());

                    let decoding_key = match decoding_key {
                        Some(k) => k,
                        None => {
                            tracing::warn!(
                                kid = ?kid,
                                algorithm = ?header.alg,
                                "No matching JWKS key for Bearer token"
                            );
                            return unauthorized("Invalid token");
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

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    use super::*;

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
}
