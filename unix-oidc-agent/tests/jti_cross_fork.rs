//! Cross-fork JTI replay protection integration tests (D-18, D-19).
//!
//! These tests prove the architectural invariant that two separate OS processes
//! sharing a filesystem directory see the same JTI state. They use real
//! `std::process::Command` process spawning — not threads, not simulated forks —
//! to exercise the kernel `O_CREAT | O_EXCL` atomicity guarantee (D-18).
//!
//! ## Why real processes?
//!
//! PAM authentication runs in separate `sshd` worker processes, not threads. An
//! in-process test using `std::sync::Mutex` would not prove the cross-fork
//! property because mutexes do not cross process boundaries. Only real OS
//! processes can demonstrate that `O_CREAT | O_EXCL` on a shared filesystem
//! directory provides the required atomicity (POSIX `open(2)`, D-01).
//!
//! ## Isolation
//!
//! Each test creates a unique `tempfile::tempdir()` and passes the path via
//! `UNIX_OIDC_JTI_DIR`. Tests do not share any filesystem state (T-30-16).
//!
//! ## No timing sensitivity
//!
//! `O_CREAT | O_EXCL` is synchronous and kernel-atomic: the result is
//! determined by the kernel VFS, not by wall-clock timing. No `sleep` or
//! retry loops are needed (D-22).
//!
//! Run: `cargo test -p unix-oidc-agent --test jti_cross_fork`

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

/// Resolve the path to the test helper binary at compile time.
///
/// `CARGO_BIN_EXE_unix-oidc-jti-helper` is set by `cargo test` for every
/// `[[bin]]` entry in the same crate, so no manual path arithmetic is needed.
fn helper_bin() -> &'static str {
    env!("CARGO_BIN_EXE_unix-oidc-jti-helper")
}

// ── D-19 Scenario 1: Sequential replay ───────────────────────────────────────

/// D-19 Scenario 1: Sequential cross-fork replay detection.
///
/// Process A records a JTI in the shared filesystem store.
/// Process B attempts the same JTI from a separate OS process.
/// B must exit 1 (replay detected) because A already holds the file.
///
/// This is the primary proof that `FsAtomicStore` prevents JTI reuse across
/// a `fork(2)` boundary: the filesystem is the shared state, and
/// `O_CREAT | O_EXCL` is the atomic guard (D-01, D-19).
#[test]
fn test_cross_fork_sequential_replay() {
    let jti_dir = tempfile::tempdir().expect("tempdir");

    // Process A: first use — must succeed.
    let status_a = Command::new(helper_bin())
        .args(["check", "https://idp.example.com", "jti-replay-001"])
        .env("UNIX_OIDC_JTI_DIR", jti_dir.path())
        .status()
        .expect("spawn process A");
    assert!(status_a.success(), "First use must succeed (exit 0), got: {status_a:?}");

    // Process B: replay — must be rejected.
    let status_b = Command::new(helper_bin())
        .args(["check", "https://idp.example.com", "jti-replay-001"])
        .env("UNIX_OIDC_JTI_DIR", jti_dir.path())
        .status()
        .expect("spawn process B");
    assert_eq!(
        status_b.code(),
        Some(1),
        "Replay must be detected by a separate OS process (exit 1), got: {status_b:?}"
    );
}

// ── D-19 Scenario 2: Concurrent race ─────────────────────────────────────────

/// D-19 Scenario 2: Concurrent race — exactly one OS process wins.
///
/// Processes C and D are spawned simultaneously with the same JTI.
/// Due to `O_CREAT | O_EXCL` kernel atomicity, exactly one succeeds
/// (exit 0) and exactly one detects a replay (exit 1).
///
/// This test is the direct proof that the underlying kernel VFS guarantee
/// holds: there is no window between "check" and "create" because the
/// check IS the create (D-01, D-22).
#[test]
fn test_concurrent_race_one_wins() {
    let jti_dir = tempfile::tempdir().expect("tempdir");
    let jti_dir_path = jti_dir.path().to_path_buf();

    // Spawn both processes simultaneously (before either wait call).
    let mut child_c = Command::new(helper_bin())
        .args(["check", "https://idp.example.com", "jti-race-001"])
        .env("UNIX_OIDC_JTI_DIR", &jti_dir_path)
        .spawn()
        .expect("spawn process C");

    let mut child_d = Command::new(helper_bin())
        .args(["check", "https://idp.example.com", "jti-race-001"])
        .env("UNIX_OIDC_JTI_DIR", &jti_dir_path)
        .spawn()
        .expect("spawn process D");

    let status_c = child_c.wait().expect("wait process C");
    let status_d = child_d.wait().expect("wait process D");

    let success_count = [status_c, status_d]
        .iter()
        .filter(|s| s.success())
        .count();
    let replay_count = [status_c, status_d]
        .iter()
        .filter(|s| s.code() == Some(1))
        .count();

    assert_eq!(
        success_count, 1,
        "Exactly one process must win the race (kernel O_CREAT|O_EXCL atomicity), \
         got success_count={success_count}"
    );
    assert_eq!(
        replay_count, 1,
        "Exactly one process must detect replay, got replay_count={replay_count}"
    );
}

// ── D-19 Scenario 3: Different JTIs — no false positives ─────────────────────

/// D-19 Scenario 3: Different JTIs produce no false positives.
///
/// Two processes with distinct JTI values must both succeed independently.
/// The SHA-256 filename hash ensures different JTI values map to different
/// files, so there is no cross-JTI collision (D-02).
#[test]
fn test_different_jtis_no_false_positive() {
    let jti_dir = tempfile::tempdir().expect("tempdir");

    let status_a = Command::new(helper_bin())
        .args(["check", "https://idp.example.com", "jti-unique-aaa"])
        .env("UNIX_OIDC_JTI_DIR", jti_dir.path())
        .status()
        .expect("spawn process A");

    let status_b = Command::new(helper_bin())
        .args(["check", "https://idp.example.com", "jti-unique-bbb"])
        .env("UNIX_OIDC_JTI_DIR", jti_dir.path())
        .status()
        .expect("spawn process B");

    assert!(
        status_a.success(),
        "Process A with unique JTI must succeed (exit 0), got: {status_a:?}"
    );
    assert!(
        status_b.success(),
        "Process B with different JTI must succeed (exit 0), got: {status_b:?}"
    );
}

// ── D-19 Scenario 4: Strict degradation ──────────────────────────────────────

/// D-19 Scenario 4: Strict mode hard-rejects on unwritable JTI directory.
///
/// When the JTI directory is not writable, `FsAtomicStore::check_and_record()`
/// returns `AtomicRecordResult::IoError`. In strict enforcement mode the helper
/// binary exits 2, which the test harness treats as a hard authentication
/// rejection (T-30-03).
///
/// This matches the production path: if `/run/unix-oidc/jti` is misconfigured,
/// PAM must refuse authentication rather than silently skip replay protection.
#[test]
fn test_strict_unwritable_rejects() {
    let jti_dir = tempfile::tempdir().expect("tempdir");

    // Create a sub-directory and remove write permission.
    let dir_path = jti_dir.path().join("jti");
    std::fs::create_dir_all(&dir_path).expect("create jti sub-dir");
    std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o000))
        .expect("set permissions to 000");

    let status = Command::new(helper_bin())
        .args(["check", "https://idp.example.com", "jti-strict-001"])
        .env("UNIX_OIDC_JTI_DIR", &dir_path)
        .status()
        .expect("spawn process");

    // Restore permissions so tempdir can clean up.
    let _ = std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o755));

    assert_eq!(
        status.code(),
        Some(2),
        "Strict mode must hard-reject (exit 2) when JTI directory is unwritable, \
         got: {status:?}"
    );
}

// ── D-19 Scenario 5: Permissive degradation ──────────────────────────────────

/// D-19 Scenario 5: Permissive mode falls back and emits LOG_CRIT on I/O error.
///
/// When the JTI directory is not writable in `check-permissive` mode, the
/// helper binary exits 0 (allow authentication) but prints `LOG_CRIT:` to
/// stderr. This matches the PAM production behavior: `jti_enforcement = warn`
/// allows auth to proceed while alerting operators that cross-fork replay
/// protection is degraded (T-30-03 warn path).
#[test]
fn test_permissive_unwritable_fallback() {
    let jti_dir = tempfile::tempdir().expect("tempdir");

    let dir_path = jti_dir.path().join("jti");
    std::fs::create_dir_all(&dir_path).expect("create jti sub-dir");
    std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o000))
        .expect("set permissions to 000");

    let output = Command::new(helper_bin())
        .args(["check-permissive", "https://idp.example.com", "jti-permissive-001"])
        .env("UNIX_OIDC_JTI_DIR", &dir_path)
        .output()
        .expect("spawn process");

    // Restore permissions so tempdir can clean up.
    let _ = std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o755));

    assert!(
        output.status.success(),
        "Permissive mode must succeed (exit 0) when falling back to per-process cache, \
         got: {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("LOG_CRIT"),
        "Permissive fallback must emit a LOG_CRIT message to stderr so operators \
         know cross-fork protection is degraded; got stderr: {stderr}"
    );
}
