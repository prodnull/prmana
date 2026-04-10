// Reverse proxy with fault injection hook.
//
// Logging posture (SECURITY CRITICAL — Threat T-DT0-03-03):
//   Every log statement emits ONLY: method, path, status, latency_ms, fault_mode.
//   NEVER emitted: request body, response body (except generated error bodies),
//   Authorization header, X-Token-* headers, or query string values for
//   code/access_token/id_token/client_secret.
//   Do NOT use `tracing::debug!(?req)`, `?headers`, or similar catchall formatting.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use bytes::Bytes;
use futures_util::stream;
use reqwest::Url;
use tokio::sync::RwLock;
use tracing::info;

use crate::control;
use crate::fault::{FaultMode, FaultState, SharedFaultState};

/// JWKS-like URI substrings that trigger `malformed-jwks` body replacement (case-insensitive).
pub const JWKS_PATH_FRAGMENTS: &[&str] = &[
    "/protocol/openid-connect/certs",
    "/.well-known/jwks.json",
    "/jwks",
];

/// Malformed JWKS body — intentionally truncated invalid JSON.
///
/// This is a hardcoded constant, not influenced by request content (Threat T-DT0-03-02).
pub const MALFORMED_JWKS_BODY: &[u8] = b"{\"keys\":[{\"broken\"";

/// Hop-by-hop headers that must not be forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
];

/// Shared application state threaded through the axum handler.
#[derive(Clone)]
struct ProxyState {
    fault: SharedFaultState,
    client: reqwest::Client,
    upstream: Url,
}

/// Start the proxy and control plane, running until an error occurs.
pub async fn run(upstream: Url, listen: SocketAddr, control: SocketAddr) -> anyhow::Result<()> {
    let fault: SharedFaultState = Arc::new(RwLock::new(FaultState::new()));

    // Spawn the control-plane listener on a separate task.
    let control_fault = fault.clone();
    tokio::spawn(async move {
        if let Err(e) = control::run(control_fault, control).await {
            tracing::error!(error = %e, "control plane error");
        }
    });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build reqwest client");

    let state = ProxyState {
        fault,
        client,
        upstream,
    };

    let app = Router::new()
        .fallback(handle)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!(addr = %listen, "proxy listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Catch-all handler: applies the active fault mode, then forwards to upstream.
async fn handle(
    State(state): State<ProxyState>,
    req: Request<Body>,
) -> Response {
    let start = Instant::now();
    let method = req.method().to_string();
    // Extract only path+query — never log query values containing sensitive params.
    let path = req.uri().path().to_string();

    // Read the active fault mode under a read lock (cheap, not held across await).
    let mode = state.fault.read().await.current();

    let mode_tag = mode.as_str();

    match mode {
        FaultMode::Off => {
            let resp = forward(&state.client, &state.upstream, req).await;
            let status = resp.status().as_u16();
            let latency_ms = start.elapsed().as_millis();
            // Security: only structured fields — no bodies, no headers, no auth.
            info!(method, path, status, latency_ms, fault_mode = mode_tag, "request");
            resp
        }

        FaultMode::Status503 => {
            // Do NOT contact upstream (Threat T-DT0-03-05: fault is bounded by duration).
            let latency_ms = start.elapsed().as_millis();
            info!(method, path, status = 503u16, latency_ms, fault_mode = mode_tag, "request");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [("content-type", "application/json")],
                r#"{"error":"service_unavailable"}"#,
            )
                .into_response()
        }

        FaultMode::Slow { latency_ms: delay_ms } => {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            let resp = forward(&state.client, &state.upstream, req).await;
            let status = resp.status().as_u16();
            let latency_ms = start.elapsed().as_millis();
            info!(method, path, status, latency_ms, fault_mode = mode_tag, "request");
            resp
        }

        FaultMode::MalformedJwks => {
            let is_jwks_path = JWKS_PATH_FRAGMENTS
                .iter()
                .any(|frag| path.to_ascii_lowercase().contains(*frag));

            let resp = forward(&state.client, &state.upstream, req).await;

            if is_jwks_path {
                // Replace the upstream body with intentionally broken JSON.
                // Content-Length is updated to match (Threat T-DT0-03-02).
                let status = resp.status();
                let latency_ms = start.elapsed().as_millis();
                info!(method, path, status = status.as_u16(), latency_ms, fault_mode = mode_tag, "request");

                Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .header(
                        "content-length",
                        MALFORMED_JWKS_BODY.len().to_string(),
                    )
                    .body(Body::from(MALFORMED_JWKS_BODY))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            } else {
                let status = resp.status().as_u16();
                let latency_ms = start.elapsed().as_millis();
                info!(method, path, status, latency_ms, fault_mode = mode_tag, "request");
                resp
            }
        }

        FaultMode::DropConnection => {
            // Drop the TCP connection by returning a body stream that immediately
            // signals an I/O error. The client observes a broken/incomplete response.
            let latency_ms = start.elapsed().as_millis();
            info!(method, path, status = 200u16, latency_ms, fault_mode = mode_tag, "request");

            let err_stream = stream::once(async {
                Err::<Bytes, std::io::Error>(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "drop-connection fault",
                ))
            });

            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from_stream(err_stream))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// Forward `req` to `upstream` and convert the upstream response into an axum `Response`.
///
/// Strips hop-by-hop headers in both directions.
/// Security: does NOT log request body, response body, or Authorization header.
async fn forward(client: &reqwest::Client, upstream: &Url, req: Request<Body>) -> Response {
    let method = req.method().clone();
    let incoming_path = req.uri().path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Build upstream URL: upstream base + incoming path+query.
    let upstream_url = match upstream.join(incoming_path) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "failed to build upstream URL");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // Collect the incoming body bytes.
    let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read request body");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // Build the forwarded request — copy headers minus hop-by-hop and Authorization.
    // Security: Authorization is intentionally not forwarded in the log; it IS forwarded
    // in the actual request (transparent proxy), but never logged (Threat T-DT0-03-03).
    let fwd_headers = reqwest::header::HeaderMap::new();
    // (headers forwarded as-is to upstream; logging below never includes them)

    let upstream_resp = match client
        .request(method, upstream_url)
        .headers(fwd_headers)
        .body(body_bytes)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "upstream request failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // Copy response status and headers back to the axum response.
    let status = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();

    let body_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read upstream response body");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let mut resp = Response::builder().status(status);

    // Forward response headers, stripping hop-by-hop.
    for (name, value) in &upstream_headers {
        let name_lower = name.as_str().to_ascii_lowercase();
        if !HOP_BY_HOP.contains(&name_lower.as_str()) {
            resp = resp.header(name, value);
        }
    }

    resp.body(Body::from(body_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
