//! Test helper binary for cross-fork JTI replay protection tests (D-18, D-19).
//!
//! This binary is used exclusively by integration tests in
//! `unix-oidc-agent/tests/jti_cross_fork.rs`. It wraps `FsAtomicStore::check_and_record()`
//! and exits with codes the test harness can assert on.
//!
//! # Usage
//!
//! ```text
//! unix-oidc-jti-helper check <issuer> <jti>
//! unix-oidc-jti-helper check-permissive <issuer> <jti>
//! ```
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | JTI was new (first use) — `AtomicRecordResult::New` |
//! | 1    | JTI was already seen (replay detected) — `AtomicRecordResult::AlreadyExists` |
//! | 2    | I/O error in strict mode (filesystem unavailable) — `AtomicRecordResult::IoError` |
//! | 3    | Bad arguments |
//!
//! In `check-permissive` mode, I/O errors fall back to allowing the request
//! (exit 0) but emit a `LOG_CRIT:` line to stderr to signal the fallback.
//!
//! # Environment
//!
//! `UNIX_OIDC_JTI_DIR` — directory for the JTI filesystem store. **Required** for
//! test isolation; each test passes a unique `tempfile::tempdir()` path.

use pam_unix_oidc::security::fs_store::{AtomicRecordResult, FsAtomicStore};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "Usage: {} <check|check-permissive> <issuer> <jti>",
            args[0]
        );
        return ExitCode::from(3);
    }

    let mode = &args[1];
    let issuer = &args[2];
    let jti = &args[3];

    // Validate mode argument early to give a clear error.
    match mode.as_str() {
        "check" | "check-permissive" => {}
        other => {
            eprintln!("Unknown mode: {other}; expected 'check' or 'check-permissive'");
            return ExitCode::from(3);
        }
    }

    // FsAtomicStore reads UNIX_OIDC_JTI_DIR from the environment; each test
    // provides a unique tempdir via that variable for full process isolation.
    let store = FsAtomicStore::new("/run/unix-oidc/jti", "UNIX_OIDC_JTI_DIR");

    // TTL: 5 minutes — plenty for test execution, short enough that expired
    // entries do not accumulate between test runs.
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 300;

    match store.check_and_record(issuer, jti, expires_at) {
        AtomicRecordResult::New => {
            // JTI is new — first use, allow authentication.
            ExitCode::SUCCESS // 0
        }
        AtomicRecordResult::AlreadyExists => {
            // Replay detected — a previous process already recorded this JTI.
            ExitCode::from(1)
        }
        AtomicRecordResult::IoError(e) => {
            eprintln!("I/O error accessing JTI store: {e}");
            match mode.as_str() {
                "check-permissive" => {
                    // Permissive mode: filesystem unavailable → fall back to
                    // per-process in-memory check (allow the request this time)
                    // but emit LOG_CRIT so operators know cross-fork protection
                    // is degraded.
                    eprintln!(
                        "LOG_CRIT: JTI filesystem store unavailable, \
                         falling back to per-process cache (cross-fork \
                         replay protection degraded)"
                    );
                    ExitCode::SUCCESS // 0 — permissive fallback
                }
                _ => {
                    // Strict mode (default): hard-reject when filesystem is
                    // unavailable. This is the T-30-03 enforcement path.
                    ExitCode::from(2)
                }
            }
        }
    }
}
