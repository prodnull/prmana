//! Background session expiry sweep task.
//!
//! The agent daemon holds no long-lived reference to individual session records.
//! Sessions are created by `pam_sm_open_session` (sshd worker A) and removed by
//! `pam_sm_close_session` (sshd worker B via IPC).  If sshd crashes between open
//! and close the record is orphaned in `/run/prmana/sessions/`.
//!
//! This module provides:
//! - `session_expiry_sweep_loop` — Tokio task that calls `sweep_expired_sessions`
//!   on a configurable interval (default 300 s, minimum 60 s).
//! - `sweep_expired_sessions` — synchronous sweep that removes expired (token_exp
//!   in the past) and corrupt (unparseable JSON) session files from a directory.
//!
//! # Graceful race handling
//!
//! The PAM close-session handler may delete a session file between `read_dir` and
//! `remove_file`.  ENOENT from `remove_file` is treated as success (idempotent
//! delete), not an error, per the must-have truth:
//! > "Concurrent delete by PAM (ENOENT) is handled gracefully, not treated as an error"
//!
//! Reference: SES-09 (session expiry sweep requirement).

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::time;
use tracing::{debug, warn};

/// Background loop that periodically sweeps expired session records.
///
/// Skips the first tick so that the sweep does not run immediately at daemon
/// startup (startup I/O is already heavy with credential loading + JWKS prefetch).
/// After the first `interval` elapses the sweep runs on every tick indefinitely.
///
/// This function never returns under normal operation.  It is intended to be
/// spawned via `tokio::spawn` and cancelled implicitly when the daemon exits.
pub async fn session_expiry_sweep_loop(session_dir: PathBuf, interval: Duration) {
    let mut ticker = time::interval(interval);
    // Skip the first (immediate) tick so we don't sweep right at startup.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        debug!(
            session_dir = %session_dir.display(),
            interval_secs = interval.as_secs(),
            "Running session expiry sweep"
        );
        sweep_expired_sessions(&session_dir);
    }
}

/// Synchronously sweep `session_dir`, removing expired and corrupt session files.
///
/// # What is removed
///
/// - Files ending in `.json` whose `token_exp` field (Unix timestamp, i64) is <=
///   the current time — these sessions have expired.
/// - Files ending in `.json` that cannot be parsed as JSON or are missing the
///   `token_exp` field — these are corrupt and will never become valid.
///
/// # What is skipped
///
/// - Files that do not end in `.json` (e.g., lock files, directories).
/// - Files whose `token_exp` is in the future.
/// - Directory listing errors — logged at WARN, no panic.
///
/// # ENOENT on remove_file
///
/// If the file is deleted concurrently by PAM `pam_sm_close_session`, `remove_file`
/// returns `ENOENT`.  This is treated as success (the file is gone — goal achieved).
pub fn sweep_expired_sessions(session_dir: &Path) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let entries = match std::fs::read_dir(session_dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(
                session_dir = %session_dir.display(),
                error = %e,
                "Session sweep: could not read session directory (skipping)"
            );
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "Session sweep: failed to read directory entry (skipping)");
                continue;
            }
        };

        let path = entry.path();

        // Only process .json files; ignore lock files, directories, etc.
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let contents = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Concurrent PAM delete — already gone, nothing to do.
                debug!(path = %path.display(), "Session sweep: file already gone (concurrent delete)");
                continue;
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Session sweep: could not read session file (skipping)");
                continue;
            }
        };

        // Parse as generic JSON Value to extract token_exp without depending on
        // the full SessionRecord type from pam-prmana.  This avoids a circular
        // dependency if the pam crate is not in scope, and is more resilient to
        // schema evolution (extra fields are ignored).
        let token_exp: Option<i64> = serde_json::from_str::<serde_json::Value>(&contents)
            .ok()
            .and_then(|v| v.get("token_exp").and_then(|e| e.as_i64()));

        match token_exp {
            Some(exp) if exp > now => {
                // Session is still valid — leave it alone.
                debug!(
                    path = %path.display(),
                    token_exp = exp,
                    now,
                    "Session sweep: session still valid, skipping"
                );
            }
            Some(_exp) => {
                // token_exp is in the past — remove the expired session file.
                remove_session_file(&path, "expired");
            }
            None => {
                // Cannot extract token_exp — file is corrupt (bad JSON or missing field).
                // Log a warning and remove to prevent accumulation.
                warn!(
                    path = %path.display(),
                    "Session sweep: corrupt or unreadable session file (missing token_exp), removing"
                );
                remove_session_file(&path, "corrupt");
            }
        }
    }
}

/// Remove a session file, handling ENOENT gracefully (concurrent PAM delete).
fn remove_session_file(path: &Path, reason: &str) {
    match std::fs::remove_file(path) {
        Ok(()) => {
            debug!(path = %path.display(), reason, "Session sweep: removed session file");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // PAM close-session already deleted this file — that's fine.
            debug!(
                path = %path.display(),
                reason,
                "Session sweep: file already removed (concurrent PAM delete)"
            );
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                reason,
                error = %e,
                "Session sweep: failed to remove session file"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;

    fn now_epoch() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn write_session(dir: &Path, name: &str, token_exp: i64) {
        let content = serde_json::json!({
            "session_id": name,
            "username": "testuser",
            "token_exp": token_exp,
            "active": true
        })
        .to_string();
        std::fs::write(dir.join(format!("{name}.json")), content).unwrap();
    }

    // Test 1: sweep_interval_secs defaults to 300
    #[test]
    fn test_sweep_interval_default_300() {
        use crate::config::TimeoutsConfig;
        assert_eq!(TimeoutsConfig::default().sweep_interval_secs, 300);
    }

    // Test 2: removes an expired session (token_exp in the past)
    #[test]
    fn test_removes_expired_session() {
        let dir = TempDir::new().unwrap();
        let expired_exp = now_epoch() - 3600; // 1 hour ago
        write_session(dir.path(), "expired-session", expired_exp);

        sweep_expired_sessions(dir.path());

        assert!(
            !dir.path().join("expired-session.json").exists(),
            "Expired session file should have been removed"
        );
    }

    // Test 3: skips a session with token_exp in the future
    #[test]
    fn test_skips_valid_session() {
        let dir = TempDir::new().unwrap();
        let future_exp = now_epoch() + 3600; // 1 hour from now
        write_session(dir.path(), "valid-session", future_exp);

        sweep_expired_sessions(dir.path());

        assert!(
            dir.path().join("valid-session.json").exists(),
            "Valid session file should not have been removed"
        );
    }

    // Test 4: removes a file containing invalid JSON (warn + remove)
    #[test]
    fn test_removes_corrupt_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("corrupt.json");
        std::fs::write(&path, "this is not valid json {{{{").unwrap();

        sweep_expired_sessions(dir.path());

        assert!(
            !path.exists(),
            "Corrupt JSON session file should have been removed"
        );
    }

    // Test 4b: removes a valid JSON file that is missing the token_exp field
    #[test]
    fn test_removes_json_missing_token_exp() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("no-exp.json");
        std::fs::write(
            &path,
            serde_json::json!({"session_id": "x", "username": "user"}).to_string(),
        )
        .unwrap();

        sweep_expired_sessions(dir.path());

        assert!(
            !path.exists(),
            "Session file missing token_exp should have been removed"
        );
    }

    // Test 5: ENOENT on remove_file handled gracefully (simulate concurrent PAM delete)
    #[test]
    fn test_enoent_handled_gracefully() {
        let dir = TempDir::new().unwrap();
        // Write an expired session, then delete it manually before calling sweep.
        let expired_exp = now_epoch() - 1;
        write_session(dir.path(), "already-gone", expired_exp);
        // Pre-delete to simulate concurrent PAM delete during our read_dir scan.
        // We cannot truly race, but we can verify remove_session_file handles ENOENT.
        // Call remove_session_file directly on a non-existent path.
        let ghost_path = dir.path().join("ghost.json");
        // ghost.json does not exist — remove_session_file must not panic.
        remove_session_file(&ghost_path, "expired");
        // No assertion needed — the test passes if no panic occurs.
    }

    // Test 6: non-.json files are ignored
    #[test]
    fn test_ignores_non_json_files() {
        let dir = TempDir::new().unwrap();
        let txt_path = dir.path().join("lockfile.lock");
        std::fs::write(&txt_path, "lock").unwrap();
        let tmp_path = dir.path().join("tempfile.tmp");
        std::fs::write(&tmp_path, "temp").unwrap();

        sweep_expired_sessions(dir.path());

        assert!(txt_path.exists(), "Non-JSON files should not be removed");
        assert!(tmp_path.exists(), "Non-JSON files should not be removed");
    }

    // Test 7: handles missing directory gracefully (warn, not panic)
    #[test]
    fn test_missing_directory_no_panic() {
        let dir = TempDir::new().unwrap();
        let nonexistent = dir.path().join("nonexistent_dir");
        // nonexistent_dir does not exist — sweep must warn and return, not panic.
        sweep_expired_sessions(&nonexistent);
        // Test passes if we reach here without panic.
    }

    // Test 8: env override PRMANA_TIMEOUTS__SWEEP_INTERVAL_SECS works via figment
    #[test]
    fn test_env_override_sweep_interval() {
        use crate::config::AgentConfig;
        use parking_lot::Mutex;
        use tempfile::TempDir;
        static ENV_MUTEX: Mutex<()> = Mutex::new(());
        let _guard = ENV_MUTEX.lock();

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, "issuer: https://idp.example.com\n").unwrap();

        std::env::set_var("PRMANA_TIMEOUTS__SWEEP_INTERVAL_SECS", "120");
        // Clear interfering legacy var
        std::env::remove_var("PRMANA_JWKS_CACHE_TTL");

        let config = AgentConfig::load_from_path(&config_path).unwrap();
        assert_eq!(config.timeouts.sweep_interval_secs, 120);

        std::env::remove_var("PRMANA_TIMEOUTS__SWEEP_INTERVAL_SECS");
    }
}
