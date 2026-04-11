//! IPC client for communicating with prmana-agent over a Unix domain socket.
//!
//! The protocol is newline-delimited JSON:
//! - Client sends one JSON request line and closes the write half.
//! - Agent responds with one JSON response line and closes the connection.
//!
//! This matches the protocol in `prmana-agent/src/daemon/socket.rs`.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::debug;

use crate::protocol::{AgentRequest, AgentResponse, AgentResponseData};

/// Request a kubectl exec-credential token from prmana-agent.
///
/// # Arguments
/// - `socket_path` — path to the prmana-agent Unix socket
/// - `cluster_id` — cluster identifier; agent forms audience `<cluster_id>.kube.prmana`
///
/// # Returns
/// `(token, expires_at_unix)` on success.
///
/// # Errors
/// Returns a user-friendly error message with remediation hint if the agent
/// is not reachable or returns an error response.
pub async fn get_kubectl_credential(socket_path: &Path, cluster_id: &str) -> Result<(String, i64)> {
    debug!(
        socket = %socket_path.display(),
        cluster_id = %cluster_id,
        "connecting to prmana-agent"
    );

    let mut sock = UnixStream::connect(socket_path).await.map_err(|e| {
        anyhow!(
            "failed to connect to prmana-agent at {}: {}\n\n\
             Is prmana-agent running? Start it with:\n  \
             systemctl --user start prmana-agent.socket\n  \
             or: prmana-agent serve",
            socket_path.display(),
            e
        )
    })?;

    // Build and send request
    let req = AgentRequest::GetKubectlCredential {
        cluster_id: cluster_id.to_string(),
    };
    let req_json = serde_json::to_string(&req).context("serializing IPC request")?;

    debug!(request = %req_json, "sending IPC request");

    sock.write_all(req_json.as_bytes())
        .await
        .context("writing IPC request")?;
    sock.write_all(b"\n")
        .await
        .context("writing IPC request newline")?;

    // Signal end of write so agent starts reading
    sock.shutdown().await.context("shutting down write half")?;

    // Read response
    let mut resp_buf = Vec::new();
    sock.read_to_end(&mut resp_buf)
        .await
        .context("reading IPC response")?;

    if resp_buf.is_empty() {
        return Err(anyhow!(
            "prmana-agent returned an empty response — the agent may have crashed or timed out.\n\
             Check agent logs: journalctl --user -u prmana-agent"
        ));
    }

    debug!(response_len = resp_buf.len(), "received IPC response");

    let resp: AgentResponse =
        serde_json::from_slice(&resp_buf).context("parsing IPC response JSON")?;

    match resp {
        AgentResponse::Success(AgentResponseData::KubectlCredential {
            token,
            expires_at_unix,
        }) => Ok((token, expires_at_unix)),

        AgentResponse::Error { code, message } => Err(anyhow!(
            "prmana-agent returned an error ({}): {}\n\n\
             Hints:\n  \
             - Run `prmana-agent login` if you are not logged in.\n  \
             - Check your cluster_id is correct (used to form audience <cluster_id>.kube.prmana).\n  \
             - Verify your IdP supports RFC 8693 token exchange for this client.",
            code,
            message
        )),

        AgentResponse::Success(other) => Err(anyhow!(
            "prmana-agent returned an unexpected success response type: {other:?}\n\
             This may indicate a version mismatch between prmana-kubectl and prmana-agent."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    /// Test I1: get_kubectl_credential sends correct request and parses response.
    #[tokio::test]
    async fn test_i1_successful_credential_request() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("agent.sock");

        // Spawn a mock agent
        let listener = UnixListener::bind(&socket_path).unwrap();
        let token_str = "eyJ.mock.token".to_string();
        let exp = 1_712_000_000i64;

        let server = {
            let token_str = token_str.clone();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();

                // Validate request
                let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
                assert_eq!(req["action"], "get_kubectl_credential");
                assert_eq!(req["cluster_id"], "prod");

                // Send response
                let resp = serde_json::json!({
                    "status": "success",
                    "token": token_str,
                    "expires_at_unix": exp
                });
                stream.write_all(resp.to_string().as_bytes()).await.unwrap();
            })
        };

        let result = get_kubectl_credential(&socket_path, "prod").await;
        server.await.unwrap();

        let (tok, exp_out) = result.unwrap();
        assert_eq!(tok, token_str);
        assert_eq!(exp_out, exp);
    }

    /// Test I2: missing socket returns user-friendly error with remediation.
    #[tokio::test]
    async fn test_i2_missing_socket_clear_error() {
        let err = get_kubectl_credential(
            std::path::Path::new("/nonexistent/prmana-agent.sock"),
            "prod",
        )
        .await
        .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("prmana-agent"),
            "error must mention prmana-agent: {msg}"
        );
        assert!(
            msg.contains("systemctl") || msg.contains("prmana-agent serve"),
            "error must include remediation hint: {msg}"
        );
    }

    /// Test I3: agent error response propagates with context.
    #[tokio::test]
    async fn test_i3_agent_error_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut _line = String::new();
            reader.read_line(&mut _line).await.unwrap();

            let resp = serde_json::json!({
                "status": "error",
                "code": "NOT_LOGGED_IN",
                "message": "Not logged in — run `prmana-agent login` first"
            });
            stream.write_all(resp.to_string().as_bytes()).await.unwrap();
        });

        let err = get_kubectl_credential(&socket_path, "prod")
            .await
            .unwrap_err();
        server.await.unwrap();

        let msg = err.to_string();
        assert!(
            msg.contains("NOT_LOGGED_IN"),
            "error code must appear: {msg}"
        );
    }
}
