//! SCIM 2.0 HTTP endpoint handlers (RFC 7644).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;

use crate::provisioner::{ProvisionError, Provisioner};
use crate::schema::*;

/// Application state shared across handlers.
pub type AppState = Arc<Provisioner>;

/// GET /ServiceProviderConfig
pub async fn get_service_provider_config() -> Json<ServiceProviderConfig> {
    Json(default_service_provider_config())
}

/// GET /Schemas — returns supported schema definitions.
pub async fn get_schemas() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "schemas": [SCHEMA_LIST],
        "totalResults": 1,
        "Resources": [
            {
                "id": SCHEMA_USER,
                "name": "User",
                "description": "SCIM 2.0 User Resource"
            }
        ]
    }))
}

/// POST /Users — create a new user.
pub async fn create_user(
    State(provisioner): State<AppState>,
    Json(user): Json<ScimUser>,
) -> impl IntoResponse {
    match provisioner.create_user(user) {
        Ok(created) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(created).unwrap()),
        )
            .into_response(),
        Err(ProvisionError::UserExists(name)) => (
            StatusCode::CONFLICT,
            Json(ScimError {
                schemas: vec![SCHEMA_ERROR.into()],
                status: "409".into(),
                detail: Some(format!("User '{name}' already exists")),
                scim_type: Some("uniqueness".into()),
            }),
        )
            .into_response(),
        Err(ProvisionError::ReservedUsername(name)) => (
            StatusCode::BAD_REQUEST,
            Json(ScimError {
                schemas: vec![SCHEMA_ERROR.into()],
                status: "400".into(),
                detail: Some(format!(
                    "Username '{name}' is reserved and cannot be provisioned"
                )),
                scim_type: None,
            }),
        )
            .into_response(),
        Err(ProvisionError::InvalidUsername(name)) => (
            StatusCode::BAD_REQUEST,
            Json(ScimError {
                schemas: vec![SCHEMA_ERROR.into()],
                status: "400".into(),
                detail: Some(format!("Invalid username '{name}': must match POSIX rules")),
                scim_type: None,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError {
                schemas: vec![SCHEMA_ERROR.into()],
                status: "500".into(),
                detail: Some(e.to_string()),
                scim_type: None,
            }),
        )
            .into_response(),
    }
}

/// GET /Users/:id — read a user.
pub async fn get_user(
    State(provisioner): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match provisioner.get_user(&id) {
        Ok(user) => (StatusCode::OK, Json(serde_json::to_value(user).unwrap())).into_response(),
        Err(ProvisionError::UserNotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(ScimError {
                schemas: vec![SCHEMA_ERROR.into()],
                status: "404".into(),
                detail: Some("User not found".into()),
                scim_type: None,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError {
                schemas: vec![SCHEMA_ERROR.into()],
                status: "500".into(),
                detail: Some(e.to_string()),
                scim_type: None,
            }),
        )
            .into_response(),
    }
}

/// PUT /Users/:id — replace a user.
pub async fn replace_user(
    State(provisioner): State<AppState>,
    Path(id): Path<String>,
    Json(user): Json<ScimUser>,
) -> impl IntoResponse {
    match provisioner.replace_user(&id, user) {
        Ok(updated) => {
            (StatusCode::OK, Json(serde_json::to_value(updated).unwrap())).into_response()
        }
        Err(ProvisionError::UserNotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(ScimError {
                schemas: vec![SCHEMA_ERROR.into()],
                status: "404".into(),
                detail: Some("User not found".into()),
                scim_type: None,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ScimError {
                schemas: vec![SCHEMA_ERROR.into()],
                status: "400".into(),
                detail: Some(e.to_string()),
                scim_type: None,
            }),
        )
            .into_response(),
    }
}

/// DELETE /Users/:id — deactivate/remove a user.
pub async fn delete_user(
    State(provisioner): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match provisioner.delete_user(&id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(ProvisionError::UserNotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(ScimError {
                schemas: vec![SCHEMA_ERROR.into()],
                status: "404".into(),
                detail: Some("User not found".into()),
                scim_type: None,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ScimError {
                schemas: vec![SCHEMA_ERROR.into()],
                status: "500".into(),
                detail: Some(e.to_string()),
                scim_type: None,
            }),
        )
            .into_response(),
    }
}

/// GET /Users — list all users.
pub async fn list_users(State(provisioner): State<AppState>) -> Json<ScimListResponse<ScimUser>> {
    let users = provisioner.list_users();
    let count = users.len();
    Json(ScimListResponse {
        schemas: vec![SCHEMA_LIST.into()],
        total_results: count,
        start_index: 1,
        items_per_page: count,
        resources: users,
    })
}

/// Build the axum Router with all SCIM endpoints.
pub fn build_router(provisioner: AppState, auth_mode: crate::auth::AuthMode) -> axum::Router {
    use axum::middleware;
    use axum::routing::{get, post};

    let auth_state = std::sync::Arc::new(auth_mode);

    axum::Router::new()
        .route("/ServiceProviderConfig", get(get_service_provider_config))
        .route("/Schemas", get(get_schemas))
        .route("/Users", post(create_user).get(list_users))
        .route(
            "/Users/:id",
            get(get_user).put(replace_user).delete(delete_user),
        )
        .layer(middleware::from_fn_with_state(
            auth_state,
            crate::auth::auth_middleware,
        ))
        .with_state(provisioner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_provisioner() -> AppState {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("routes-state.json");
        Arc::new(
            Provisioner::new(crate::config::ScimConfig {
                dry_run: true,
                state_file: state_file.display().to_string(),
                ..crate::config::ScimConfig::default()
            })
            .unwrap(),
        )
    }

    fn test_router() -> axum::Router {
        build_router(test_provisioner(), crate::auth::AuthMode::Insecure)
    }

    fn authed_get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap()
    }

    fn authed_post(uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn authed_put(uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(uri)
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn authed_delete(uri: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("authorization", "Bearer test-token")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_get_service_provider_config() {
        let app = test_router();
        let resp = app
            .oneshot(authed_get("/ServiceProviderConfig"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["schemas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some(SCHEMA_SPC)));
    }

    #[tokio::test]
    async fn test_get_schemas() {
        let app = test_router();
        let resp = app.oneshot(authed_get("/Schemas")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totalResults"], 1);
    }

    #[tokio::test]
    async fn test_create_and_get_user() {
        let app = test_router();
        let create_body = serde_json::json!({
            "schemas": [SCHEMA_USER],
            "userName": "testscim"
        });

        let resp = app
            .clone()
            .oneshot(authed_post("/Users", create_body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let id = created["id"].as_str().unwrap();

        // GET the created user
        let resp = app
            .oneshot(authed_get(&format!("/Users/{id}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let fetched: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(fetched["userName"], "testscim");
    }

    #[tokio::test]
    async fn test_create_reserved_username_rejected() {
        let app = test_router();
        let body = serde_json::json!({
            "schemas": [SCHEMA_USER],
            "userName": "root"
        });
        let resp = app.oneshot(authed_post("/Users", body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_duplicate_returns_409() {
        let app = test_router();
        let body = serde_json::json!({
            "schemas": [SCHEMA_USER],
            "userName": "duproute"
        });
        let resp = app
            .clone()
            .oneshot(authed_post("/Users", body.clone()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = app.oneshot(authed_post("/Users", body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_get_nonexistent_user_returns_404() {
        let app = test_router();
        let resp = app
            .oneshot(authed_get("/Users/nonexistent-id"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_put_user() {
        let app = test_router();
        let create_body = serde_json::json!({
            "schemas": [SCHEMA_USER],
            "userName": "putuser"
        });
        let resp = app
            .clone()
            .oneshot(authed_post("/Users", create_body))
            .await
            .unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let id = created["id"].as_str().unwrap();

        let update_body = serde_json::json!({
            "schemas": [SCHEMA_USER],
            "userName": "putuser",
            "displayName": "Updated"
        });
        let resp = app
            .oneshot(authed_put(&format!("/Users/{id}"), update_body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let updated: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(updated["displayName"], "Updated");
    }

    #[tokio::test]
    async fn test_put_nonexistent_returns_404() {
        let app = test_router();
        let body = serde_json::json!({
            "schemas": [SCHEMA_USER],
            "userName": "ghost"
        });
        let resp = app
            .oneshot(authed_put("/Users/no-such-id", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_user() {
        let app = test_router();
        let create_body = serde_json::json!({
            "schemas": [SCHEMA_USER],
            "userName": "delroute"
        });
        let resp = app
            .clone()
            .oneshot(authed_post("/Users", create_body))
            .await
            .unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let id = created["id"].as_str().unwrap();

        let resp = app
            .clone()
            .oneshot(authed_delete(&format!("/Users/{id}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verify gone
        let resp = app
            .oneshot(authed_get(&format!("/Users/{id}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_nonexistent_returns_404() {
        let app = test_router();
        let resp = app
            .oneshot(authed_delete("/Users/no-such-id"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_users() {
        let app = test_router();

        // Empty list
        let resp = app.clone().oneshot(authed_get("/Users")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(list["totalResults"], 0);

        // Create a user then list
        let create_body = serde_json::json!({
            "schemas": [SCHEMA_USER],
            "userName": "listroute"
        });
        app.clone()
            .oneshot(authed_post("/Users", create_body))
            .await
            .unwrap();

        let resp = app.oneshot(authed_get("/Users")).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(list["totalResults"], 1);
    }

    #[tokio::test]
    async fn test_unauthenticated_request_rejected() {
        let app = test_router();
        let req = Request::builder()
            .uri("/Users")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
