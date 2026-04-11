//! Agent daemon lifecycle integration test (TEST-04).
//!
//! Starts the prmana-agent binary, sends IPC commands (Status, GetProof,
//! Shutdown), and validates responses against the protocol defined in
//! `prmana-agent/src/daemon/protocol.rs`.
//!
//! Run: cargo test -p prmana-agent --test daemon_lifecycle
//!
//! CRITICAL: The Shutdown handler calls `std::process::exit(0)` without
//! sending a response. The test must NOT wait for a shutdown response --
//! send the command, drop the stream, and `child.wait()`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Guard that cleans up the socket file and kills the child process on drop.
struct DaemonGuard {
    child: std::process::Child,
    socket_path: PathBuf,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        // Best-effort kill if still running
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Clean up socket file
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Wait for the Unix socket file to appear, polling at 50ms intervals.
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

/// Send a JSON request over a new Unix socket connection and read the response.
fn send_ipc_request(socket_path: &std::path::Path, request: &str) -> String {
    let mut stream = UnixStream::connect(socket_path)
        .unwrap_or_else(|e| panic!("Failed to connect to socket {socket_path:?}: {e}"));
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("Failed to set read timeout");

    writeln!(stream, "{request}").expect("Failed to write request");
    stream.flush().expect("Failed to flush");

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .expect("Failed to read response");
    response
}

#[test]
fn test_daemon_lifecycle() {
    // Unique socket path per test run to avoid collisions
    let socket_path = std::env::temp_dir().join(format!(
        "prmana-test-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let socket_str = socket_path
        .to_str()
        .expect("Socket path must be valid UTF-8");

    // Clean up any stale socket from a previous run
    let _ = std::fs::remove_file(&socket_path);

    // Start the daemon binary. CARGO_BIN_EXE_prmana-agent is set by cargo
    // for integration tests that reference a [[bin]] target.
    // Force file-only storage backend to avoid macOS Keychain prompts
    // (StorageRouter::detect() probes Keychain by default, triggering a system
    // password dialog that blocks headless test runs).
    let child = Command::new(env!("CARGO_BIN_EXE_prmana-agent"))
        .args(["serve", "--socket", socket_str])
        .env("PRMANA_STORAGE_BACKEND", "file")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start prmana-agent daemon");

    let mut guard = DaemonGuard {
        child,
        socket_path: socket_path.clone(),
    };

    // ---------------------------------------------------------------
    // 1. Wait for socket to appear (up to 5 seconds for CI)
    // ---------------------------------------------------------------
    assert!(
        wait_for_socket(&socket_path, Duration::from_secs(5)),
        "Daemon did not create socket at {socket_path:?} within 5 seconds"
    );

    // ---------------------------------------------------------------
    // 2. Status command: fresh daemon should report logged_in=false
    // ---------------------------------------------------------------
    let status_resp = send_ipc_request(&socket_path, r#"{"action":"status"}"#);
    let status_json: serde_json::Value =
        serde_json::from_str(&status_resp).expect("Status response is not valid JSON");

    assert_eq!(
        status_json["status"], "success",
        "Status response should be success, got: {status_resp}"
    );
    assert_eq!(
        status_json["logged_in"], false,
        "Fresh daemon should report logged_in=false, got: {status_resp}"
    );

    // ---------------------------------------------------------------
    // 3. GetProof command: unauthenticated daemon should return error
    // ---------------------------------------------------------------
    let proof_resp = send_ipc_request(
        &socket_path,
        r#"{"action":"get_proof","target":"test.example.com","method":"SSH"}"#,
    );
    let proof_json: serde_json::Value =
        serde_json::from_str(&proof_resp).expect("GetProof response is not valid JSON");

    assert_eq!(
        proof_json["status"], "error",
        "GetProof on unauthenticated daemon should return error, got: {proof_resp}"
    );

    // ---------------------------------------------------------------
    // 4. Shutdown: send command, do NOT read response (process::exit(0)
    //    is called before any response is written)
    // ---------------------------------------------------------------
    {
        let mut stream = UnixStream::connect(&socket_path).expect("Failed to connect for shutdown");
        writeln!(stream, r#"{{"action":"shutdown"}}"#).expect("Failed to write shutdown command");
        let _ = stream.flush();
        // Drop stream immediately -- no response expected
    }

    // Wait for the process to exit (up to 5 seconds)
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match guard.child.try_wait() {
            Ok(Some(_status)) => {
                // Process exited -- success
                break;
            }
            Ok(None) => {
                if Instant::now() > deadline {
                    panic!("Daemon did not exit within 5 seconds after Shutdown");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                panic!("Error waiting for daemon to exit: {e}");
            }
        }
    }

    // Clean up socket (guard Drop will also try)
    let _ = std::fs::remove_file(&socket_path);
}
