// Reverse proxy with fault injection hook.
//
// See Task 2 for full implementation. This module is declared here so the
// crate compiles during Task 1 testing; `run` is a stub that returns Ok(())
// immediately. The integration tests in tests/fault_modes.rs will not pass
// until Task 2 fills in the real implementation.
//
// Logging posture (SECURITY CRITICAL — Threat T-DT0-03-03):
//   Every log statement emits ONLY: method, path, status, latency_ms, fault_mode.
//   NEVER emitted: request body, response body (except generated error bodies),
//   Authorization header, X-Token-* headers, or query string values for
//   code/access_token/id_token/client_secret.
//   Do NOT use `tracing::debug!(?req)`, `?headers`, or similar catchall formatting.
use std::net::SocketAddr;

use reqwest::Url;

/// JWKS-like URI substrings that trigger `malformed-jwks` body replacement.
pub const JWKS_PATH_FRAGMENTS: &[&str] = &[
    "/protocol/openid-connect/certs",
    "/.well-known/jwks.json",
    "/jwks",
];

/// Malformed JWKS body — intentionally truncated invalid JSON.
pub const MALFORMED_JWKS_BODY: &[u8] = b"{\"keys\":[{\"broken\"";

/// Run the proxy (stub — full implementation in Task 2).
#[allow(unused_variables)]
pub async fn run(upstream: Url, listen: SocketAddr, control: SocketAddr) -> anyhow::Result<()> {
    // Stub: real implementation in Task 2.
    Ok(())
}
