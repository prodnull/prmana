//! SSH_ASKPASS handler for PAM keyboard-interactive DPoP nonce challenges.
//!
//! # Overview
//!
//! PAM's keyboard-interactive conversation sends three sequential prompts during
//! DPoP-bound SSH authentication (see `pam-unix-oidc/src/lib.rs`):
//!
//! 1. `DPOP_NONCE:<value>` — server-issued nonce (PROMPT_ECHO_ON)
//! 2. `DPOP_PROOF: ` — waits for a DPoP proof (PROMPT_ECHO_OFF)
//! 3. `OIDC Token: ` — waits for the access token (PROMPT_ECHO_OFF)
//!
//! SSH spawns the `SSH_ASKPASS` binary once per prompt, passing the prompt string
//! as `argv[1]`. Each invocation is a **separate process** with no shared in-process
//! state; state between prompts must be persisted externally.
//!
//! # State persistence across invocations
//!
//! The nonce value from prompt 1 must be available when handling prompt 2.
//! The access token from the GetProof IPC call in prompt 2 must be available
//! in prompt 3.
//!
//! Both pieces of state are stored in tmpfiles keyed by the SSH client's PID
//! (the parent PID of each SSH_ASKPASS invocation):
//!
//! - Nonce tmpfile: `$TMPDIR/.unix-oidc-nonce-{PPID}`
//! - Token tmpfile: `$TMPDIR/.unix-oidc-token-{PPID}`
//!
//! Using PPID (the ssh client process) rather than a fixed path ensures that
//! two concurrent SSH sessions from the same user do not collide.
//!
//! # Security properties
//!
//! - Tmpfiles are created with `0600` permissions (owner-only). Defense-in-depth:
//!   the nonce is a server-generated challenge (not a secret), but the token tmpfile
//!   contains an access token briefly and must be strictly owner-only.
//! - Tmpfiles are deleted immediately after reading (token) or use (nonce).
//! - PPID keying prevents cross-session collision under normal operation.
//!
//! # References
//!
//! - RFC 9449 §4 — DPoP Proof JWT Syntax
//! - SSH `SSH_ASKPASS` / `SSH_ASKPASS_REQUIRE` — OpenSSH manual

use std::fs;
use std::io;
use std::path::PathBuf;

use anyhow::Context;

use unix_oidc_agent::daemon::{AgentClient, AgentResponse, AgentResponseData};

// ── tmpfile path helpers ─────────────────────────────────────────────────────

/// Return the path for the per-session nonce tmpfile.
///
/// Keyed by the parent PID (the ssh client process) so that two simultaneous
/// SSH sessions from the same user do not collide.
fn nonce_tmpfile_path(ppid: u32) -> PathBuf {
    std::env::temp_dir().join(format!(".unix-oidc-nonce-{ppid}"))
}

/// Return the path for the per-session token cache tmpfile.
///
/// Written during the DPOP_PROOF round and read (then deleted) during the
/// OIDC Token round, avoiding a second GetProof IPC call.
fn token_tmpfile_path(ppid: u32) -> PathBuf {
    std::env::temp_dir().join(format!(".unix-oidc-token-{ppid}"))
}

/// Write `contents` to `path` with permissions set to 0600 (owner-only).
///
/// Security: uses `OpenOptions::mode()` to set permissions atomically at file
/// creation, preventing the TOCTOU race where `fs::write()` then
/// `set_permissions()` leaves a window during which the file is world-readable
/// under the default umask. The token tmpfile contains an access token briefly
/// and must be strictly owner-only.
fn write_with_restricted_perms(path: &PathBuf, contents: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, contents)
    }
}

// ── public entry point ───────────────────────────────────────────────────────

/// Handle a single SSH_ASKPASS prompt.
///
/// SSH invokes this function (via the `ssh-askpass` subcommand) once per
/// keyboard-interactive prompt.  The function inspects the prompt string and
/// takes the appropriate action:
///
/// | Prompt prefix     | Action                                        |
/// |-------------------|-----------------------------------------------|
/// | `DPOP_NONCE:`     | Store nonce in tmpfile; print empty line      |
/// | `DPOP_PROOF`      | Read nonce from tmpfile, call GetProof IPC, print dpop_proof |
/// | `OIDC Token`      | Read cached token tmpfile or call GetProof IPC; print token  |
/// | (anything else)   | Print empty line (safe default; SSH receives empty response) |
pub async fn run_ssh_askpass(prompt: String) -> anyhow::Result<()> {
    #[cfg(unix)]
    let ppid = std::os::unix::process::parent_id();
    #[cfg(not(unix))]
    let ppid = std::process::id(); // fallback for non-Unix builds (tests)

    let nonce_path = nonce_tmpfile_path(ppid);
    let token_path = token_tmpfile_path(ppid);

    if let Some(nonce_value) = prompt.strip_prefix("DPOP_NONCE:") {
        // Round 1: PAM has issued a fresh server nonce.
        //
        // Store the nonce for the next invocation (DPOP_PROOF round).
        // The nonce itself is not a secret (it is a server-generated challenge),
        // but we apply 0600 perms as defense-in-depth.
        let nonce = nonce_value.trim();
        write_with_restricted_perms(&nonce_path, nonce)
            .with_context(|| format!("Failed to write nonce tmpfile: {}", nonce_path.display()))?;

        // SSH expects a response on stdout.  For the DPOP_NONCE prompt, the
        // PAM module discards whatever we print; an empty line is the safe default.
        println!();
        return Ok(());
    }

    if prompt.trim_start().starts_with("DPOP_PROOF") {
        // Round 2: PAM is requesting a DPoP proof bound to the earlier nonce.
        //
        // 1. Read the stored nonce (best-effort; None if tmpfile is missing).
        // 2. Delete the nonce tmpfile immediately after reading.
        // 3. Call GetProof IPC with the nonce.
        // 4. Cache the returned access token for round 3.
        // 5. Print the DPoP proof to stdout.

        let nonce = read_and_delete(&nonce_path);

        let target = std::env::var("UNIX_OIDC_TARGET").unwrap_or_default();

        let response: AgentResponse = AgentClient::default()
            .get_proof(&target, "SSH", nonce.as_deref(), None)
            .await
            .context("GetProof IPC failed")?;

        match response {
            AgentResponse::Success(AgentResponseData::Proof {
                token, dpop_proof, ..
            }) => {
                // Cache the token for round 3 (OIDC Token prompt).
                // Failure to cache is non-fatal: round 3 will fall back to another
                // GetProof call rather than failing authentication.
                if let Err(e) = write_with_restricted_perms(&token_path, &token) {
                    eprintln!("Warning: failed to cache token tmpfile: {e}");
                }

                // Print the DPoP proof for PAM to use.
                println!("{dpop_proof}");
                Ok(())
            }
            AgentResponse::Error { message, .. } => {
                eprintln!("Error: GetProof failed: {message}");
                std::process::exit(1);
            }
            other => {
                eprintln!("Error: unexpected GetProof response: {other:?}");
                std::process::exit(1);
            }
        }
    } else if prompt_is_token_request(&prompt) {
        // Round 3: PAM is requesting the OIDC access token.
        //
        // Prefer the cached token from round 2 to avoid an extra IPC call.
        // Fall back to GetProof IPC if the cache is missing (e.g., first-call-only
        // flow or tmpfile cleanup race).
        if let Some(cached) = read_and_delete(&token_path) {
            println!("{cached}");
            return Ok(());
        }

        let target = std::env::var("UNIX_OIDC_TARGET").unwrap_or_default();

        let response: AgentResponse = AgentClient::default()
            .get_proof(&target, "SSH", None, None)
            .await
            .context("GetProof IPC failed (token fallback)")?;

        match response {
            AgentResponse::Success(AgentResponseData::Proof { token, .. }) => {
                println!("{token}");
                Ok(())
            }
            AgentResponse::Error { message, .. } => {
                eprintln!("Error: GetProof failed: {message}");
                std::process::exit(1);
            }
            other => {
                eprintln!("Error: unexpected GetProof response: {other:?}");
                std::process::exit(1);
            }
        }
    } else {
        // Unrecognized prompt: safe default — print an empty line so SSH receives
        // an empty response rather than hanging waiting for input.
        println!();
        Ok(())
    }
}

/// Read file contents (trimmed), then delete the file.
///
/// Returns `None` if the file does not exist or cannot be read.
/// Deletion failures are best-effort (logged to stderr only).
fn read_and_delete(path: &PathBuf) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            if let Err(e) = fs::remove_file(path) {
                eprintln!("Warning: failed to delete tmpfile {}: {e}", path.display());
            }
            Some(contents.trim().to_string())
        }
        Err(_) => None,
    }
}

/// Return true if the prompt is asking for an OIDC access token.
///
/// The PAM module sends `"OIDC Token: "` (with trailing space) from
/// `get_auth_token()`.  We match case-insensitively and allow for minor
/// formatting variations.
fn prompt_is_token_request(prompt: &str) -> bool {
    let lower = prompt.to_lowercase();
    lower.contains("oidc token") || lower.contains("token:")
}

// ── unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_nonce_tmpfile_path_includes_ppid() {
        let path = nonce_tmpfile_path(12345);
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(
            name.contains("12345"),
            "Expected PPID in tmpfile name, got: {name}"
        );
        assert!(name.starts_with(".unix-oidc-nonce-"));
    }

    #[test]
    fn test_token_tmpfile_path_includes_ppid() {
        let path = token_tmpfile_path(12345);
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(
            name.contains("12345"),
            "Expected PPID in token tmpfile name, got: {name}"
        );
        assert!(name.starts_with(".unix-oidc-token-"));
    }

    #[test]
    fn test_two_ppids_produce_different_nonce_paths() {
        let path1 = nonce_tmpfile_path(100);
        let path2 = nonce_tmpfile_path(200);
        assert_ne!(
            path1, path2,
            "Different PPIDs should produce different tmpfile paths"
        );
    }

    #[test]
    fn test_two_ppids_produce_different_token_paths() {
        let path1 = token_tmpfile_path(100);
        let path2 = token_tmpfile_path(200);
        assert_ne!(
            path1, path2,
            "Different PPIDs should produce different token tmpfile paths"
        );
    }

    #[test]
    fn test_write_with_restricted_perms_creates_file() {
        let path =
            std::env::temp_dir().join(format!(".unix-oidc-test-perms-{}", std::process::id()));
        let result = write_with_restricted_perms(&path, "test-content");
        assert!(
            result.is_ok(),
            "write_with_restricted_perms should succeed: {result:?}"
        );

        let content = fs::read_to_string(&path).expect("File should be readable");
        assert_eq!(content, "test-content");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(&path).expect("Metadata should be readable");
            let mode = meta.mode() & 0o777;
            assert_eq!(mode, 0o600, "Expected 0600 permissions, got: {mode:o}");
        }

        let _ = fs::remove_file(&path);
    }

    /// Generate a unique temp path for each test to avoid parallel races.
    fn unique_nonce_path(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            ".unix-oidc-nonce-test-{}-{suffix}",
            std::process::id()
        ))
    }

    #[test]
    fn test_nonce_tmpfile_permissions_are_0600() {
        // Verify that write_with_restricted_perms sets 0600
        let nonce_path = unique_nonce_path("perms");
        let _ = fs::remove_file(&nonce_path);

        write_with_restricted_perms(&nonce_path, "test-nonce").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(&nonce_path).expect("Tmpfile should exist");
            let mode = meta.mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "Expected 0600 permissions on nonce tmpfile, got: {mode:o}"
            );
        }

        let _ = fs::remove_file(&nonce_path);
    }

    #[test]
    fn test_dpop_nonce_prompt_writes_nonce_to_tmpfile() {
        // Simulate DPOP_NONCE:<value> handling (the write-to-tmpfile side,
        // without going through the async entry point).
        let nonce_path = unique_nonce_path("write");
        let _ = fs::remove_file(&nonce_path);

        // Replicate what run_ssh_askpass does for DPOP_NONCE: prompts.
        let prompt = "DPOP_NONCE:abc123";
        if let Some(nonce_value) = prompt.strip_prefix("DPOP_NONCE:") {
            let nonce = nonce_value.trim();
            write_with_restricted_perms(&nonce_path, nonce).unwrap();
        }

        let stored = fs::read_to_string(&nonce_path).expect("Nonce tmpfile should exist");
        assert_eq!(stored.trim(), "abc123");

        let _ = fs::remove_file(&nonce_path);
    }

    #[test]
    fn test_dpop_nonce_prompt_trims_whitespace() {
        let nonce_path = unique_nonce_path("trim");
        let _ = fs::remove_file(&nonce_path);

        let prompt = "DPOP_NONCE:  spaced-nonce  ";
        if let Some(nonce_value) = prompt.strip_prefix("DPOP_NONCE:") {
            write_with_restricted_perms(&nonce_path, nonce_value.trim()).unwrap();
        }

        let stored = fs::read_to_string(&nonce_path).expect("Nonce tmpfile should exist");
        assert_eq!(stored.trim(), "spaced-nonce");

        let _ = fs::remove_file(&nonce_path);
    }

    #[test]
    fn test_read_and_delete_returns_none_when_file_missing() {
        let path = std::env::temp_dir().join(".unix-oidc-nonexistent-99999999");
        let _ = fs::remove_file(&path); // ensure absent
        let result = read_and_delete(&path);
        assert!(result.is_none(), "Expected None for missing file");
    }

    #[test]
    fn test_read_and_delete_returns_contents_and_removes_file() {
        let path = std::env::temp_dir().join(format!(".unix-oidc-rad-test-{}", std::process::id()));
        fs::write(&path, "  hello  ").unwrap();

        let result = read_and_delete(&path);
        assert_eq!(
            result,
            Some("hello".to_string()),
            "Expected trimmed content"
        );
        assert!(
            !path.exists(),
            "File should be deleted after read_and_delete"
        );
    }

    #[test]
    fn test_prompt_is_token_request_matches_oidc_token() {
        assert!(prompt_is_token_request("OIDC Token: "));
        assert!(prompt_is_token_request("oidc token: "));
        assert!(prompt_is_token_request("OIDC Token:"));
        assert!(prompt_is_token_request("Please enter OIDC Token: "));
    }

    #[test]
    fn test_prompt_is_token_request_does_not_match_dpop() {
        assert!(!prompt_is_token_request("DPOP_NONCE:abc"));
        assert!(!prompt_is_token_request("DPOP_PROOF: "));
        assert!(!prompt_is_token_request("Password: "));
    }

    #[test]
    fn test_nonce_and_token_paths_are_in_temp_dir() {
        let nonce_path = nonce_tmpfile_path(42);
        let token_path = token_tmpfile_path(42);
        let temp_dir = std::env::temp_dir();
        assert!(
            nonce_path.starts_with(&temp_dir),
            "Nonce tmpfile should be in temp dir"
        );
        assert!(
            token_path.starts_with(&temp_dir),
            "Token tmpfile should be in temp dir"
        );
    }

    /// F-02 positive: write_with_restricted_perms creates file with 0o600.
    #[cfg(unix)]
    #[test]
    fn test_write_restricted_perms_atomic_0600() {
        use std::os::unix::fs::MetadataExt;

        let path = std::env::temp_dir().join(format!(
            ".unix-oidc-test-atomic-perms-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        write_with_restricted_perms(&path, "atomic-test-content").unwrap();

        let meta = fs::metadata(&path).expect("File should exist");
        let mode = meta.mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "File must be created with 0o600 permissions atomically, got: {mode:o}"
        );

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "atomic-test-content");

        let _ = fs::remove_file(&path);
    }

    /// F-02 negative: file has no group/other permissions even with permissive umask.
    #[cfg(unix)]
    #[test]
    fn test_write_restricted_perms_no_group_other_bits() {
        use std::os::unix::fs::MetadataExt;

        let path = std::env::temp_dir().join(format!(
            ".unix-oidc-test-no-group-other-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        write_with_restricted_perms(&path, "restricted-content").unwrap();

        let meta = fs::metadata(&path).expect("File should exist");
        let mode = meta.mode() & 0o777;

        // No group or other bits should be set regardless of umask.
        assert_eq!(
            mode & 0o077,
            0,
            "File must have no group/other permissions, got: {mode:o}"
        );

        let _ = fs::remove_file(&path);
    }
}
