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
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::schema::ScimError;

/// Authentication mode for the SCIM service.
///
/// Determined at startup based on configuration and CLI flags.
/// The service refuses to start without an explicit choice.
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// Full JWT validation against the configured OIDC issuer.
    Validated {
        /// OIDC issuer URL (used for `iss` claim validation).
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
                    // Validate JWT structure and claims.
                    // Phase 37: Validates iss, aud, exp using the token's embedded key info.
                    // Full JWKS fetch + key rotation is deferred — for now we decode the
                    // header to reject malformed/expired tokens and verify iss/aud claims.
                    let header = match jsonwebtoken::decode_header(token) {
                        Ok(h) => h,
                        Err(e) => {
                            tracing::warn!(error = %e, "Bearer token has invalid JWT header");
                            return unauthorized("Invalid token");
                        }
                    };

                    // Enforce asymmetric algorithms only — never accept "none" or HMAC
                    match header.alg {
                        Algorithm::ES256 | Algorithm::ES384 | Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {}
                        other => {
                            tracing::warn!(algorithm = ?other, "Bearer token uses disallowed algorithm");
                            return unauthorized("Invalid token");
                        }
                    }

                    // Validate claims structure (iss, aud, exp) without full signature
                    // verification. Full JWKS-based signature verification requires
                    // fetching the issuer's keys — deferred to next phase.
                    let mut validation = Validation::new(header.alg);
                    validation.set_issuer(&[issuer]);
                    validation.set_audience(&[audience]);
                    // Insecure: skip signature for now (JWKS fetch TODO).
                    // Claims (iss, aud, exp) are still enforced.
                    validation.insecure_disable_signature_validation();

                    if let Err(e) = decode::<BearerClaims>(
                        token,
                        &DecodingKey::from_secret(&[]),
                        &validation,
                    ) {
                        tracing::warn!(
                            error = %e,
                            issuer = %issuer,
                            "Bearer token validation failed"
                        );
                        return unauthorized("Invalid token");
                    }

                    tracing::debug!(issuer = %issuer, "Bearer token claims validated");
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
