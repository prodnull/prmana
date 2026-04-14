// Control plane HTTP server for the idp-proxy.
//
// Accepts fault injection commands via `POST /fault` (JSON body).
// The control listener MUST bind to loopback (127.0.0.1) in CI — binding
// to a public interface would expose fault injection as a DoS vector against
// the proxied IdP. See README.md security posture section.
//
// Threat T-DT0-03-01: control plane access is mediated by loopback binding.
// Threat T-DT0-03-08: every POST /fault emits a structured audit log event.
use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tracing::info;

use crate::fault::{FaultRequest, SharedFaultState};

/// Run the control plane HTTP server on `addr`.
///
/// The returned future resolves only when the listener fails.
pub async fn run(state: SharedFaultState, addr: SocketAddr) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/fault", post(post_fault))
        .route("/fault", get(get_fault))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(addr = %addr, "control plane listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// `POST /fault` — apply or clear a fault mode.
///
/// Body (JSON): `{ "mode": "503", "duration_secs": 60, "latency_ms": null }`
///
/// Returns `400` if the mode string is unrecognised.
async fn post_fault(
    State(state): State<SharedFaultState>,
    Json(req): Json<FaultRequest>,
) -> (StatusCode, Json<Value>) {
    let duration_secs = req.duration_secs;
    let mode_str = req.mode.clone();

    let mode = match req.into_mode() {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e })),
            );
        }
    };

    let duration = duration_secs.map(Duration::from_secs);

    // Threat T-DT0-03-08: audit every fault injection command so CI logs
    // capture exactly what was injected and when.
    info!(
        mode = %mode_str,
        duration_secs = ?duration_secs,
        "fault_applied"
    );

    state.write().await.apply(mode.clone(), duration);

    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "mode": mode.as_str(),
            "duration_secs": duration_secs
        })),
    )
}

/// `GET /fault` — return the currently active fault mode (for debugging).
async fn get_fault(State(state): State<SharedFaultState>) -> Json<Value> {
    let current = state.read().await.current();
    Json(json!({ "mode": current.as_str() }))
}

// ---------------------------------------------------------------------------
// Unit tests (axum oneshot via tower::ServiceExt)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use crate::fault::{FaultMode, FaultState};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    fn make_state() -> SharedFaultState {
        Arc::new(RwLock::new(FaultState::new()))
    }

    fn make_app(state: SharedFaultState) -> Router {
        Router::new()
            .route("/fault", post(post_fault))
            .route("/fault", get(get_fault))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_post_fault_503_returns_200() {
        let state = make_state();
        let app = make_app(state.clone());

        let req = Request::builder()
            .method(Method::POST)
            .uri("/fault")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"mode":"503","duration_secs":60}"#))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify state was mutated
        let current = state.read().await.current();
        assert_eq!(current, FaultMode::Status503);
    }

    #[tokio::test]
    async fn test_post_fault_unknown_mode_returns_400() {
        let state = make_state();
        let app = make_app(state);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/fault")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"mode":"banana"}"#))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_post_fault_off_clears_state() {
        let state = make_state();
        // Set a fault first
        state
            .write()
            .await
            .apply(FaultMode::Status503, None);

        let app = make_app(state.clone());

        let req = Request::builder()
            .method(Method::POST)
            .uri("/fault")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"mode":"off"}"#))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let current = state.read().await.current();
        assert_eq!(current, FaultMode::Off);
    }

    #[tokio::test]
    async fn test_get_fault_returns_current_mode() {
        let state = make_state();
        state
            .write()
            .await
            .apply(FaultMode::MalformedJwks, None);

        let app = make_app(state);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/fault")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["mode"], "malformed-jwks");
    }
}
