//! Integration tests for prmana-kubectl.
//!
//! Tests C1-C4: CLI subcommand behavior with a mock prmana-agent backend.

use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// Path to the prmana-kubectl binary built in the workspace.
fn binary_path() -> PathBuf {
    // In cargo test, the binary is in target/debug or target/release
    let mut path = std::env::current_exe()
        .unwrap()
        .parent() // deps/
        .unwrap()
        .parent() // debug/ or release/
        .unwrap()
        .to_path_buf();
    path.push("prmana-kubectl");
    path
}

/// Spawn a mock prmana-agent that responds with a KubectlCredential response.
async fn spawn_mock_agent(
    socket_path: &std::path::Path,
    token: &str,
    expires_at_unix: i64,
) -> tokio::task::JoinHandle<()> {
    let listener = UnixListener::bind(socket_path).unwrap();
    let token = token.to_string();

    tokio::spawn(async move {
        // Handle one connection
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap_or(0);

            let resp = serde_json::json!({
                "status": "success",
                "token": token,
                "expires_at_unix": expires_at_unix
            });
            let _ = stream.write_all(resp.to_string().as_bytes()).await;
        }
    })
}

/// Test C1: `prmana-kubectl get-token --cluster-id prod` prints valid ExecCredential JSON.
///
/// Uses `tokio::process::Command` (async) rather than `std::process::Command`
/// (blocking). The mock agent runs on the tokio runtime via `tokio::spawn`;
/// calling `std::process::Command::output()` from an `#[tokio::test]` pins
/// the runtime thread and prevents the spawned mock-agent task from ever
/// being scheduled, so the child process hangs forever waiting for the
/// socket to accept its connection. Using the async command lets the runtime
/// keep scheduling the mock agent.
#[tokio::test]
async fn test_c1_get_token_prints_exec_credential() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("agent.sock");

    let _server = spawn_mock_agent(&socket_path, "eyJ.mock.token", 1_712_000_000).await;

    // Overall-budget guard: if anything still hangs, fail fast rather than
    // letting the CI job time out after 15 minutes.
    let exec = tokio::process::Command::new(binary_path())
        .args(["get-token", "--cluster-id", "prod"])
        .env("PRMANA_SOCKET", socket_path.to_str().unwrap())
        .output();

    let output = match tokio::time::timeout(std::time::Duration::from_secs(30), exec).await {
        Ok(res) => res,
        Err(_) => {
            panic!("prmana-kubectl get-token hung for more than 30s — check agent socket handshake")
        }
    };

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
                .expect(&format!("stdout must be valid JSON: {stdout}"));
            assert_eq!(
                parsed["apiVersion"], "client.authentication.k8s.io/v1",
                "must have correct apiVersion"
            );
            assert_eq!(parsed["kind"], "ExecCredential", "must be ExecCredential");
            assert!(
                !parsed["status"]["token"].is_null(),
                "must have status.token"
            );
            assert!(
                !parsed["status"]["expirationTimestamp"].is_null(),
                "must have expirationTimestamp"
            );
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            panic!("get-token failed: exit={} stderr={}", out.status, stderr);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Binary not built yet — skip in non-build environments
            eprintln!(
                "SKIP: prmana-kubectl binary not found at {:?}",
                binary_path()
            );
        }
        Err(e) => panic!("failed to run binary: {e}"),
    }
}

/// Test C3: `prmana-kubectl --version` prints version string.
#[test]
fn test_c3_version_flag() {
    match std::process::Command::new(binary_path())
        .arg("--version")
        .output()
    {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success(),
                "--version must exit 0: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                stdout.contains("prmana-kubectl"),
                "--version must contain binary name: {stdout}"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("SKIP: binary not found at {:?}", binary_path());
        }
        Err(e) => panic!("failed to run binary: {e}"),
    }
}

/// Test C4: `prmana-kubectl --help` lists both subcommands.
#[test]
fn test_c4_help_lists_subcommands() {
    match std::process::Command::new(binary_path())
        .arg("--help")
        .output()
    {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{stdout}{stderr}");
            assert!(
                combined.contains("get-token"),
                "--help must list get-token: {combined}"
            );
            assert!(
                combined.contains("setup"),
                "--help must list setup: {combined}"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("SKIP: binary not found at {:?}", binary_path());
        }
        Err(e) => panic!("failed to run binary: {e}"),
    }
}

/// Test C2: `prmana-kubectl setup` writes exec stanza to a temp kubeconfig.
#[tokio::test]
async fn test_c2_setup_writes_kubeconfig() {
    let dir = tempfile::tempdir().unwrap();
    let kubeconfig_path = dir.path().join("config");

    match std::process::Command::new(binary_path())
        .args([
            "setup",
            "--cluster-id",
            "test",
            "--server",
            "https://test.example.com:6443",
            "--context",
            "test-ctx",
        ])
        .env("KUBECONFIG", kubeconfig_path.to_str().unwrap())
        .output()
    {
        Ok(out) if out.status.success() => {
            assert!(kubeconfig_path.exists(), "kubeconfig file must be created");
            let content = std::fs::read_to_string(&kubeconfig_path).unwrap();
            assert!(
                content.contains("prmana-kubectl"),
                "kubeconfig must contain exec plugin command: {content}"
            );
            assert!(
                content.contains("test.kube.prmana") || content.contains("cluster-id"),
                "kubeconfig must reference cluster args: {content}"
            );
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            panic!("setup failed: exit={} stderr={}", out.status, stderr);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("SKIP: binary not found at {:?}", binary_path());
        }
        Err(e) => panic!("failed to run binary: {e}"),
    }
}
