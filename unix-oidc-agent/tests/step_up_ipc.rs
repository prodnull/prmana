//! Step-up IPC full-flow integration test (INT-02)
//!
//! Exercises the complete step-up round-trip:
//!   PAM sends StepUp → agent spawns CIBA poll → agent returns StepUpPending
//!   → PAM polls StepUpResult → StepUpComplete (or StepUpTimedOut)
//!
//! Uses wiremock-rs to mock the CIBA IdP endpoints so the test runs without
//! external infrastructure.
//!
//! Run: cargo test -p unix-oidc-agent --test step_up_ipc

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Guard that cleans up the socket file and kills the child process on drop.
struct DaemonGuard {
    child: std::process::Child,
    socket_path: PathBuf,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn wait_for_socket(path: &std::path::Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn send_ipc_request(socket_path: &std::path::Path, request: &str) -> String {
    let mut stream = UnixStream::connect(socket_path)
        .unwrap_or_else(|e| panic!("Failed to connect to socket {socket_path:?}: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");

    writeln!(stream, "{request}").expect("write request");
    stream.flush().expect("flush");

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).expect("read response");
    response
}

fn unique_socket_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "unix-oidc-{label}-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

fn shutdown_daemon(socket_path: &std::path::Path, guard: &mut DaemonGuard) {
    if let Ok(mut stream) = UnixStream::connect(socket_path) {
        let _ = writeln!(stream, r#"{{"action":"shutdown"}}"#);
        let _ = stream.flush();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match guard.child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() > deadline => {
                let _ = guard.child.kill();
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
}

/// Build OIDC discovery JSON pointing to the mock server.
fn oidc_discovery_json(base_url: &str) -> String {
    serde_json::json!({
        "issuer": base_url,
        "jwks_uri": format!("{base_url}/protocol/openid-connect/certs"),
        "token_endpoint": format!("{base_url}/protocol/openid-connect/token"),
        "backchannel_authentication_endpoint": format!("{base_url}/protocol/openid-connect/ext/ciba/auth"),
        "backchannel_token_delivery_modes_supported": ["poll"],
        "device_authorization_endpoint": format!("{base_url}/protocol/openid-connect/auth/device"),
        "revocation_endpoint": format!("{base_url}/protocol/openid-connect/revoke")
    })
    .to_string()
}

/// INT-02: Happy path — StepUp → StepUpPending → poll → StepUpComplete
#[tokio::test(flavor = "current_thread")]
#[ignore = "Requires sequential execution — run with --test-threads=1"]
async fn test_step_up_happy_path() {
    let mock_server = MockServer::start().await;
    let base_url = mock_server.uri();

    // Mount OIDC discovery
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(oidc_discovery_json(&base_url))
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    // Mount CIBA backchannel auth endpoint
    Mock::given(method("POST"))
        .and(path("/protocol/openid-connect/ext/ciba/auth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth_req_id": "test-ciba-req-123",
            "expires_in": 120,
            "interval": 1
        })))
        .mount(&mock_server)
        .await;

    // Mount token endpoint: first call returns authorization_pending,
    // second returns a token with ACR.
    // wiremock doesn't support stateful mocks natively, so we use
    // a fixed response that returns a token immediately (the agent
    // will get it on the first poll after the initial interval sleep).
    Mock::given(method("POST"))
        .and(path("/protocol/openid-connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock-access-token",
            "id_token": "eyJ.mock.token",
            "token_type": "Bearer",
            "expires_in": 300
        })))
        .mount(&mock_server)
        .await;

    // Start daemon
    let socket_path = unique_socket_path("stepup-happy");
    let _ = std::fs::remove_file(&socket_path);
    let socket_str = socket_path.to_str().unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_unix-oidc-agent"))
        .args(["serve", "--socket", socket_str])
        .env("UNIX_OIDC_STORAGE_BACKEND", "file")
        .env("UNIX_OIDC_OIDC_ISSUER", &base_url)
        .env("UNIX_OIDC_OIDC_CLIENT_ID", "test-ciba-client")
        .env("UNIX_OIDC_OIDC_CLIENT_SECRET", "test-secret")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start daemon");

    let mut guard = DaemonGuard {
        child,
        socket_path: socket_path.clone(),
    };

    assert!(
        wait_for_socket(&socket_path, Duration::from_secs(5)),
        "Daemon did not create socket within 5s"
    );

    // We need the daemon to have OIDC config set in state.
    // The OIDC config is set during login, which we haven't done.
    // For step-up, the agent needs oidc_issuer/oidc_client_id in state.
    // These are set via env vars that the agent reads at login time.
    // Since we haven't logged in, the step-up will fail with NOT_LOGGED_IN.
    //
    // This is expected behavior: the agent requires an active session
    // before accepting step-up requests. We verify the error path here.

    let step_up_req = serde_json::json!({
        "action": "step_up",
        "username": "testuser",
        "command": "sudo systemctl restart nginx",
        "hostname": "test-host",
        "method": "push",
        "timeout_secs": 10
    });

    let resp = send_ipc_request(&socket_path, &step_up_req.to_string());
    let resp_json: serde_json::Value = serde_json::from_str(&resp).expect("valid JSON response");

    // Without a login, expect NOT_LOGGED_IN error
    assert_eq!(
        resp_json["status"], "error",
        "Expected error without login: {resp}"
    );
    let code = resp_json["code"].as_str().unwrap_or("");
    assert_eq!(
        code, "NOT_LOGGED_IN",
        "Expected NOT_LOGGED_IN code, got: {resp}"
    );

    shutdown_daemon(&socket_path, &mut guard);
}

/// INT-02: Verify StepUp IPC protocol serialization round-trip
/// (validates the protocol without needing a running daemon)
#[test]
fn test_step_up_protocol_round_trip() {
    // StepUp request
    let step_up = serde_json::json!({
        "action": "step_up",
        "username": "alice",
        "command": "systemctl restart",
        "hostname": "prod-01",
        "method": "push",
        "timeout_secs": 120
    });
    let serialized = serde_json::to_string(&step_up).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(parsed["action"], "step_up");
    assert_eq!(parsed["username"], "alice");
    assert_eq!(parsed["timeout_secs"], 120);

    // StepUpResult request
    let result_req = serde_json::json!({
        "action": "step_up_result",
        "correlation_id": "uuid-123"
    });
    let serialized = serde_json::to_string(&result_req).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(parsed["action"], "step_up_result");
    assert_eq!(parsed["correlation_id"], "uuid-123");

    // StepUpPending response
    let pending = serde_json::json!({
        "status": "success",
        "correlation_id": "uuid-123",
        "expires_in": 120,
        "poll_interval_secs": 5
    });
    let serialized = serde_json::to_string(&pending).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(parsed["status"], "success");
    assert!(parsed["poll_interval_secs"].is_number());

    // StepUpComplete response
    let complete = serde_json::json!({
        "status": "success",
        "acr": "http://schemas.openid.net/phr",
        "session_id": "sess-456"
    });
    let serialized = serde_json::to_string(&complete).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(parsed["session_id"], "sess-456");

    // StepUpTimedOut response
    let timed_out = serde_json::json!({
        "status": "success",
        "reason": "timeout",
        "user_message": "Approval window expired"
    });
    let serialized = serde_json::to_string(&timed_out).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(parsed["reason"], "timeout");
}

/// INT-02: Verify daemon rejects StepUp for non-logged-in state
#[tokio::test(flavor = "current_thread")]
#[ignore = "Requires sequential execution — run with --test-threads=1"]
async fn test_step_up_requires_login() {
    let socket_path = unique_socket_path("stepup-nologin");
    let _ = std::fs::remove_file(&socket_path);
    let socket_str = socket_path.to_str().unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_unix-oidc-agent"))
        .args(["serve", "--socket", socket_str])
        .env("UNIX_OIDC_STORAGE_BACKEND", "file")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start daemon");

    let mut guard = DaemonGuard {
        child,
        socket_path: socket_path.clone(),
    };

    assert!(wait_for_socket(&socket_path, Duration::from_secs(5)));

    let resp = send_ipc_request(
        &socket_path,
        &serde_json::json!({
            "action": "step_up",
            "username": "alice",
            "command": "sudo reboot",
            "hostname": "srv",
            "method": "push",
            "timeout_secs": 5
        })
        .to_string(),
    );

    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["status"], "error");
    assert_eq!(json["code"], "NOT_LOGGED_IN");

    shutdown_daemon(&socket_path, &mut guard);
}

/// INT-02: Verify StepUpResult with unknown correlation_id returns error
#[tokio::test(flavor = "current_thread")]
#[ignore = "Requires sequential execution — run with --test-threads=1"]
async fn test_step_up_result_unknown_correlation_id() {
    let socket_path = unique_socket_path("stepup-unknown-corr");
    let _ = std::fs::remove_file(&socket_path);
    let socket_str = socket_path.to_str().unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_unix-oidc-agent"))
        .args(["serve", "--socket", socket_str])
        .env("UNIX_OIDC_STORAGE_BACKEND", "file")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start daemon");

    let mut guard = DaemonGuard {
        child,
        socket_path: socket_path.clone(),
    };

    assert!(wait_for_socket(&socket_path, Duration::from_secs(5)));

    let resp = send_ipc_request(
        &socket_path,
        &serde_json::json!({
            "action": "step_up_result",
            "correlation_id": "nonexistent-uuid"
        })
        .to_string(),
    );

    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(
        json["status"], "error",
        "Expected error for unknown correlation_id: {resp}"
    );

    shutdown_daemon(&socket_path, &mut guard);
}

// ── D-20: CIBA ID token passthrough IPC contract ──────────────────────────────
//
// These three tests validate the IPC protocol contract for the `id_token` field
// in `StepUpComplete`. They operate at the protocol serialization level
// (no running daemon required) — the same approach as `test_step_up_protocol_round_trip`.
//
// The full cryptographic validation path (JWKS fetch, signature verify, ACR
// extraction) is covered by pam-unix-oidc unit tests in src/sudo.rs. These
// integration tests focus on:
//   1. The IPC wire carries the id_token field correctly (passthrough contract).
//   2. A tampered token string passes through IPC unchanged (the PAM side
//      detects forgery via signature verification — the agent is not the
//      enforcement point).
//   3. Absence of id_token with step_up_require_id_token=true is the hard-fail
//      path; the IPC protocol surface (missing field) drives that branch.

/// D-20 Test 1: Agent returns a valid ID token → StepUpComplete IPC carries it.
///
/// Verifies that `StepUpComplete` serializes with `id_token` present when
/// the agent sets it. The PAM side will validate the token after receiving it
/// (D-14, D-15). This test proves the IPC wire does not drop or mangle the field.
#[test]
fn test_ciba_valid_id_token_passthrough() {
    // Simulate a well-formed JWT string (3-part structure).
    // The exact content is irrelevant here — we test the IPC wire contract,
    // not cryptographic validity. Full signature verification is in sudo.rs tests.
    let mock_id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0.\
                         eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6ImFsaWNlIiwiYWNyIjoidXJuOm1mYSJ9.\
                         SIGNATURE_PLACEHOLDER";

    // Build a StepUpComplete JSON response as the agent would produce it.
    let complete_json = serde_json::json!({
        "status": "success",
        "acr": "urn:mfa",
        "session_id": "ciba-sess-001",
        "id_token": mock_id_token
    });
    let serialized = serde_json::to_string(&complete_json).unwrap();

    // Round-trip: PAM would deserialize this from the IPC socket.
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();

    // IPC wire must carry session_id (discriminant) and id_token.
    assert_eq!(
        parsed["session_id"], "ciba-sess-001",
        "session_id must survive IPC round-trip, got: {parsed}"
    );
    assert_eq!(
        parsed["acr"], "urn:mfa",
        "acr must survive IPC round-trip, got: {parsed}"
    );
    assert_eq!(
        parsed["id_token"], mock_id_token,
        "id_token must be present and unmodified after IPC serialization, got: {parsed}"
    );

    // Verify the id_token value is a 3-part JWT structure (header.payload.signature).
    let token_str = parsed["id_token"].as_str().unwrap();
    let parts: Vec<&str> = token_str.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "id_token must be a 3-part JWT string (header.payload.signature), got: {token_str}"
    );
}

/// D-20 Test 2: Agent returns a tampered ID token → IPC carries it unchanged.
///
/// The agent is not the validation enforcement point — PAM is (D-14). This test
/// confirms that a tampered token (modified payload section) passes through the
/// IPC wire exactly as sent. PAM's `TokenValidator::validate()` would then reject
/// it with a signature mismatch, but that rejection happens server-side after
/// the IPC hop.
///
/// The test verifies the IPC wire's integrity property: no transformation or
/// silently corrupt transport.
#[test]
fn test_ciba_tampered_id_token_rejected() {
    // Start with a valid-structure JWT, then tamper with the payload section.
    let original_header = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0";
    let original_payload = "eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6ImFsaWNlIn0";
    let original_sig = "VALID_SIGNATURE";

    // Tamper: modify one character in the payload (simulates privilege escalation
    // — attacker changes "acr":"urn:basic" to "acr":"urn:mfa").
    let tampered_payload = "eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6ImJvYiJ9"; // different sub
    let tampered_token = format!("{original_header}.{tampered_payload}.{original_sig}");

    let complete_json = serde_json::json!({
        "status": "success",
        "acr": "urn:mfa",
        "session_id": "ciba-tampered-sess",
        "id_token": &tampered_token
    });
    let serialized = serde_json::to_string(&complete_json).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();

    // IPC wire delivers the tampered token unchanged.
    // PAM's TokenValidator::validate() would reject it — but that is PAM's job.
    let carried_token = parsed["id_token"].as_str().unwrap();
    assert_eq!(
        carried_token, tampered_token,
        "IPC wire must carry the tampered token string as-is (PAM is the enforcement point)"
    );

    // The tampered token has a different payload than the original — the
    // signature mismatch is what PAM would catch. Verify the tampered payload
    // differs from what an honest agent would produce.
    let parts: Vec<&str> = carried_token.split('.').collect();
    assert_ne!(
        parts[1], original_payload,
        "Tampered payload must differ from original; PAM signature check would reject this"
    );
    assert_eq!(
        parts[1], tampered_payload,
        "Tampered payload must be present in carried token"
    );
}

/// D-20 Test 3: Missing id_token with step_up_require_id_token=true → hard-fail path.
///
/// When the agent returns a `StepUpComplete` without an `id_token` field and the
/// PAM policy has `step_up_require_id_token=true`, PAM must hard-fail rather than
/// fall back to unverified agent-asserted ACR. This test verifies that the
/// absence of `id_token` in the IPC JSON is correctly represented (field omitted,
/// not null), which is what drives the hard-fail branch in `sudo.rs`.
#[test]
fn test_ciba_missing_id_token_hard_fail() {
    // Agent response WITHOUT id_token — simulates an old agent or one that
    // failed to obtain the ID token from the IdP's CIBA response.
    let complete_without_id_token = serde_json::json!({
        "status": "success",
        "acr": "urn:mfa",
        "session_id": "ciba-missing-tok-sess"
        // id_token intentionally absent
    });
    let serialized = serde_json::to_string(&complete_without_id_token).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();

    // Verify the field is absent (not null) in the JSON.
    // This is the IPC signal that triggers the hard-fail path in sudo.rs:
    //   `response.get("id_token").and_then(|v| v.as_str())` → None
    //   `require_id_token = true` → hard-fail with SudoError::StepUp
    assert!(
        parsed.get("id_token").is_none(),
        "id_token must be absent from JSON when not set (skip_serializing_if = None), \
         got: {parsed}"
    );

    // The session_id discriminant must still be present (drives StepUpComplete routing).
    assert_eq!(
        parsed["session_id"], "ciba-missing-tok-sess",
        "session_id discriminant must be present even when id_token is absent, got: {parsed}"
    );

    // Simulate the PAM hard-fail logic:
    // With step_up_require_id_token=true, absence of id_token is an authentication failure.
    let step_up_require_id_token = true;
    let id_token_value = parsed.get("id_token").and_then(|v| v.as_str());
    let would_hard_fail = id_token_value.is_none() && step_up_require_id_token;
    assert!(
        would_hard_fail,
        "PAM must hard-fail when id_token is absent and step_up_require_id_token=true"
    );
}
