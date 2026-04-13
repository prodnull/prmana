// Integration tests for idp-proxy fault modes.
//
// Each test spins up:
//   1. An in-process upstream stub (tiny axum app with a hit counter)
//   2. The idp-proxy pointing at that stub, with a control plane on a random port
//
// Tests exercise each fault mode by:
//   - Sending a POST /fault to the control plane
//   - Making a request through the proxy
//   - Asserting client-observable behavior matches the fault specification
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use axum::Router;
use reqwest::Url;
use serde_json::json;

// ---------------------------------------------------------------------------
// Upstream stub helpers
// ---------------------------------------------------------------------------

/// Shared hit counter threaded through the stub app.
#[derive(Clone)]
struct UpstreamState {
    hits: Arc<AtomicU32>,
}

/// Bind a tiny upstream stub on a random port and return (URL, hit_counter, shutdown_tx).
async fn spawn_test_upstream() -> (Url, Arc<AtomicU32>, tokio::sync::oneshot::Sender<()>) {
    let hits = Arc::new(AtomicU32::new(0));
    let state = UpstreamState { hits: hits.clone() };

    let app = Router::new()
        .route("/health", get(upstream_health))
        .route(
            "/protocol/openid-connect/certs",
            get(upstream_jwks),
        )
        .route("/.well-known/jwks.json", get(upstream_jwks))
        .route("/jwks", get(upstream_jwks))
        .route("/echo/{path}", get(upstream_echo))
        .route("/count", get(upstream_count))
        .fallback(upstream_fallback)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = Url::parse(&format!("http://{}", addr)).unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async { rx.await.ok(); })
            .await
            .ok();
    });

    (url, hits, tx)
}

async fn upstream_health(State(s): State<UpstreamState>) -> &'static str {
    s.hits.fetch_add(1, Ordering::Relaxed);
    "ok"
}

async fn upstream_jwks(State(s): State<UpstreamState>) -> impl IntoResponse {
    s.hits.fetch_add(1, Ordering::Relaxed);
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        r#"{"keys":[{"kty":"EC","crv":"P-256","x":"stub","y":"stub"}]}"#,
    )
}

async fn upstream_echo(State(s): State<UpstreamState>, Path(p): Path<String>) -> String {
    s.hits.fetch_add(1, Ordering::Relaxed);
    p
}

async fn upstream_count(State(s): State<UpstreamState>) -> Json<serde_json::Value> {
    Json(json!({ "hits": s.hits.load(Ordering::Relaxed) }))
}

async fn upstream_fallback(State(s): State<UpstreamState>) -> Response {
    s.hits.fetch_add(1, Ordering::Relaxed);
    StatusCode::OK.into_response()
}

// ---------------------------------------------------------------------------
// Proxy spawn helper
// ---------------------------------------------------------------------------

/// Spawn the idp-proxy pointing at `upstream_url`.
///
/// Returns (proxy_url, control_url, shutdown_tx).
async fn spawn_test_proxy(
    upstream_url: Url,
) -> (Url, Url, tokio::task::JoinHandle<()>) {
    // Pick two random ports: one for the proxy listener, one for control.
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

    let proxy_addr: SocketAddr = proxy_listener.local_addr().unwrap();
    let control_addr: SocketAddr = control_listener.local_addr().unwrap();

    let proxy_url = Url::parse(&format!("http://{}", proxy_addr)).unwrap();
    let control_url = Url::parse(&format!("http://{}", control_addr)).unwrap();

    // Drop the listeners so proxy::run can bind those ports.
    // There's a small TOCTOU window, but for tests on 127.0.0.1 this is fine.
    drop(proxy_listener);
    drop(control_listener);

    let handle = tokio::spawn(async move {
        idp_proxy::proxy::run(upstream_url, proxy_addr, control_addr)
            .await
            .ok();
    });

    // Give the proxy a moment to bind and start listening.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (proxy_url, control_url, handle)
}

/// Post a fault command to the control plane.
async fn set_fault(
    client: &reqwest::Client,
    control_url: &Url,
    mode: &str,
    duration_secs: Option<u64>,
    latency_ms: Option<u64>,
) {
    let url = control_url.join("/fault").unwrap();
    let body = json!({
        "mode": mode,
        "duration_secs": duration_secs,
        "latency_ms": latency_ms,
    });
    let resp = client.post(url).json(&body).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "set_fault({mode}) should return 200"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_fault_off() {
    let (upstream_url, hits, _upstream_shutdown) = spawn_test_upstream().await;
    let (proxy_url, _control_url, _proxy) = spawn_test_proxy(upstream_url).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let resp = client
        .get(proxy_url.join("/health").unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "ok");
    assert!(hits.load(Ordering::Relaxed) >= 1, "upstream should have been hit");
}

#[tokio::test]
async fn test_fault_503() {
    let (upstream_url, hits, _upstream_shutdown) = spawn_test_upstream().await;
    let (proxy_url, control_url, _proxy) = spawn_test_proxy(upstream_url).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Inject 503 fault for 60 seconds.
    set_fault(&client, &control_url, "503", Some(60), None).await;
    let hits_before = hits.load(Ordering::Relaxed);

    let resp = client
        .get(proxy_url.join("/any-path").unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 503, "proxy should return 503");
    let body = resp.text().await.unwrap();
    assert!(body.contains("service_unavailable"));

    // Upstream must NOT have been contacted.
    let hits_after = hits.load(Ordering::Relaxed);
    assert_eq!(
        hits_before, hits_after,
        "upstream must not be hit during 503 fault"
    );
}

#[tokio::test]
async fn test_fault_slow() {
    let (upstream_url, _hits, _upstream_shutdown) = spawn_test_upstream().await;
    let (proxy_url, control_url, _proxy) = spawn_test_proxy(upstream_url).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    // Inject slow mode with 500 ms latency.
    set_fault(&client, &control_url, "slow", None, Some(500)).await;

    let start = std::time::Instant::now();
    let resp = client
        .get(proxy_url.join("/health").unwrap())
        .send()
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
    assert!(
        elapsed >= Duration::from_millis(450),
        "slow mode should delay at least 500ms, got {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_fault_malformed_jwks() {
    let (upstream_url, _hits, _upstream_shutdown) = spawn_test_upstream().await;
    let (proxy_url, control_url, _proxy) = spawn_test_proxy(upstream_url).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Inject malformed-jwks fault.
    set_fault(&client, &control_url, "malformed-jwks", None, None).await;

    // JWKS path should return malformed JSON.
    let jwks_resp = client
        .get(proxy_url.join("/protocol/openid-connect/certs").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(jwks_resp.status(), 200);
    let jwks_body = jwks_resp.text().await.unwrap();
    assert!(
        serde_json::from_str::<serde_json::Value>(&jwks_body).is_err(),
        "malformed-jwks body should not be valid JSON, got: {}",
        jwks_body
    );

    // Non-JWKS path should pass through untouched.
    let health_resp = client
        .get(proxy_url.join("/health").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(health_resp.status(), 200);
    assert_eq!(health_resp.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn test_fault_drop_connection() {
    let (upstream_url, _hits, _upstream_shutdown) = spawn_test_upstream().await;
    let (proxy_url, control_url, _proxy) = spawn_test_proxy(upstream_url).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Inject drop-connection fault.
    set_fault(&client, &control_url, "drop-connection", None, None).await;

    // Client should observe an error (connection reset / incomplete response).
    let result = client
        .get(proxy_url.join("/health").unwrap())
        .send()
        .await;

    // Either send() errors, or we get a response whose body errors on read.
    match result {
        Err(_) => { /* expected: connection-level error */ }
        Ok(resp) => {
            // Got headers — body read should fail.
            let body_result = resp.bytes().await;
            assert!(
                body_result.is_err(),
                "drop-connection should cause body read error"
            );
        }
    }
}

#[tokio::test]
async fn test_fault_restore() {
    let (upstream_url, hits, _upstream_shutdown) = spawn_test_upstream().await;
    let (proxy_url, control_url, _proxy) = spawn_test_proxy(upstream_url).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Apply 503 fault.
    set_fault(&client, &control_url, "503", None, None).await;
    let resp = client
        .get(proxy_url.join("/health").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);

    // Restore normal operation.
    set_fault(&client, &control_url, "off", None, None).await;

    let hits_before = hits.load(Ordering::Relaxed);
    let resp = client
        .get(proxy_url.join("/health").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
    assert!(
        hits.load(Ordering::Relaxed) > hits_before,
        "upstream should be hit after restoring to off"
    );
}
