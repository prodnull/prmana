//! Bearer token authentication middleware for SCIM endpoints.
//!
//! Validates OAuth 2.0 Bearer tokens against the configured OIDC issuer.
//! Phase 37 uses simple header extraction — full JWKS validation is wired
//! via pam-unix-oidc's validation module.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::schema::ScimError;

/// Extract and validate Bearer token from Authorization header.
///
/// Phase 37: Validates token presence and format. Full JWKS signature
/// verification is a TODO (requires wiring pam-unix-oidc's `TokenValidator`
/// into the SCIM service's async context).
pub async fn auth_middleware(request: Request, next: Next) -> Response {
    let auth_header = request.headers().get("authorization");

    match auth_header {
        Some(value) => {
            let value_str = match value.to_str() {
                Ok(v) => v,
                Err(_) => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(ScimError {
                            schemas: vec![crate::schema::SCHEMA_ERROR.into()],
                            status: "401".into(),
                            detail: Some("Invalid Authorization header encoding".into()),
                            scim_type: None,
                        }),
                    )
                        .into_response();
                }
            };

            if !value_str.starts_with("Bearer ") {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ScimError {
                        schemas: vec![crate::schema::SCHEMA_ERROR.into()],
                        status: "401".into(),
                        detail: Some("Authorization header must use Bearer scheme".into()),
                        scim_type: None,
                    }),
                )
                    .into_response();
            }

            let token = &value_str[7..];
            if token.is_empty() {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ScimError {
                        schemas: vec![crate::schema::SCHEMA_ERROR.into()],
                        status: "401".into(),
                        detail: Some("Bearer token is empty".into()),
                        scim_type: None,
                    }),
                )
                    .into_response();
            }

            // TODO: Validate token signature via pam-unix-oidc TokenValidator.
            // For Phase 37, we accept any non-empty Bearer token.
            // This MUST be wired before production deployment.
            tracing::debug!("Bearer token present (signature validation TODO)");

            next.run(request).await
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(ScimError {
                schemas: vec![crate::schema::SCHEMA_ERROR.into()],
                status: "401".into(),
                detail: Some("Authorization header required".into()),
                scim_type: None,
            }),
        )
            .into_response(),
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

    fn test_app() -> Router {
        Router::new()
            .route("/test", get(ok_handler))
            .layer(middleware::from_fn(auth_middleware))
    }

    #[tokio::test]
    async fn test_missing_auth_header_returns_401() {
        let app = test_app();
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_non_bearer_scheme_returns_401() {
        let app = test_app();
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
        let app = test_app();
        let req = Request::builder()
            .uri("/test")
            .header("authorization", "Bearer ")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_valid_bearer_token_passes() {
        let app = test_app();
        let req = Request::builder()
            .uri("/test")
            .header("authorization", "Bearer some-valid-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
