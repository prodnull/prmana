//! Filesystem-based atomic store for cross-fork replay protection state.
//!
//! `FsAtomicStore` uses `O_CREAT | O_EXCL` (via `OpenOptions::create_new(true)`)
//! to achieve kernel-atomic key creation: exactly one racing writer succeeds.
//! This property is preserved across `fork(2)` because the atomicity is enforced
//! by the kernel VFS layer, not shared process memory.
//!
//! ## Design decisions
//!
//! - **D-01**: `create_new(true)` → `O_CREAT | O_EXCL` — one writer wins
//! - **D-02**: Key filename = `sha256(scope + ":" + value)` hex → 64 chars,
//!   filesystem-safe, cross-issuer-isolated (scope includes the issuer URL)
//! - **D-03**: File contents = `expires_at` as decimal unix timestamp string
//! - **D-04**: Opportunistic sweep (5% probability) removes expired entries
//!   without a dedicated cleanup thread
//! - **D-08**: `consume()` uses `remove_file()` for atomic test-and-delete
//!
//! ## Security properties
//!
//! - Cross-issuer isolation: `scope` embeds the issuer URL, so two issuers with
//!   the same JTI value hash to different filenames (D-02).
//! - Tamper-resistance: directory permissions 0750 root:root (enforced by
//!   `systemd-tmpfiles` — see `contrib/systemd/unix-oidc.tmpfiles.conf`).
//! - DoS protection: opportunistic sweep + `systemd-tmpfiles` age-based cleanup
//!   prevent unbounded directory growth (D-04, T-30-02).
//! - Files contain only expiry timestamps — no tokens, no PII (T-30-05).
//!
//! ## References
//!
//! - RFC 9449 §8 — DPoP Nonce
//! - POSIX `open(2)` — `O_CREAT | O_EXCL` atomicity guarantee

use sha2::Digest;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Result type ───────────────────────────────────────────────────────────────

/// Result of an atomic key creation attempt.
#[derive(Debug)]
pub enum AtomicRecordResult {
    /// Key did not exist; it has been created and will expire at `expires_at_unix`.
    New,
    /// Key already exists (replay detected — file was created by a previous call).
    AlreadyExists,
    /// An unexpected I/O error occurred (directory unwritable, disk full, etc.).
    /// In `jti_enforcement = strict` mode the caller must hard-reject authentication
    /// when this variant is returned (T-30-03).
    IoError(std::io::Error),
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// Filesystem-based atomic store shared across `sshd` worker processes.
///
/// Multiple `sshd` forked processes share the same backing directory.  The
/// kernel's `O_CREAT | O_EXCL` guarantee ensures that exactly one process
/// succeeds in creating a given key file even under concurrent load.
///
/// Construct one instance per store type (JTI store, nonce store) and keep it
/// alive for the lifetime of the PAM module load.
///
/// # Example
///
/// ```rust,no_run
/// use pam_unix_oidc::security::FsAtomicStore;
///
/// let store = FsAtomicStore::new("/run/unix-oidc/jti", "UNIX_OIDC_JTI_DIR");
/// let result = store.check_and_record("https://issuer/", "jti-abc", 3600);
/// ```
pub struct FsAtomicStore {
    dir: PathBuf,
    env_var: &'static str,
}

impl FsAtomicStore {
    /// Create a new `FsAtomicStore`.
    ///
    /// Resolves the backing directory from the environment variable `env_var`
    /// first; falls back to `default_dir` when the variable is unset or empty.
    /// Attempts `create_dir_all()` on construction so the directory exists for
    /// the first `check_and_record()` call.  A `WARN` is logged (and execution
    /// continues) if directory creation fails — the error will surface on the
    /// first write attempt.
    ///
    /// # Arguments
    ///
    /// * `default_dir` — Default directory path (e.g. `/run/unix-oidc/jti`).
    /// * `env_var` — Name of the env var that overrides the directory for testing.
    pub fn new(default_dir: &str, env_var: &'static str) -> Self {
        let dir = std::env::var(env_var)
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(default_dir));

        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::warn!(
                dir = %dir.display(),
                env_var = %env_var,
                error = %e,
                "FsAtomicStore: could not create backing directory"
            );
        }

        Self { dir, env_var }
    }

    /// Compute the full path for the given `scope` and `value`.
    ///
    /// The filename is the lowercase hex encoding of `SHA-256(scope + ":" + value)`,
    /// producing a 64-character filesystem-safe name (D-02).
    ///
    /// The `scope` should include the issuer URL to guarantee cross-issuer
    /// isolation: two issuers sharing a JTI value will hash to different
    /// filenames.
    pub fn key_path(&self, scope: &str, value: &str) -> PathBuf {
        let input = format!("{scope}:{value}");
        let hash = sha2::Sha256::digest(input.as_bytes());
        let hex_name: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(hex_name)
    }

    /// Atomically record a key if it does not already exist.
    ///
    /// Uses `O_CREAT | O_EXCL` semantics (via `create_new(true)`) to guarantee
    /// that at most one concurrent caller succeeds even across `fork(2)`.
    ///
    /// On success the file contains `expires_at_unix` as a decimal string (D-03).
    /// The directory is created if missing (handles fresh installations where
    /// `systemd-tmpfiles` has not yet run).
    ///
    /// # Returns
    ///
    /// - `New` — this call created the entry; caller may proceed.
    /// - `AlreadyExists` — a previous call already recorded this key; caller must
    ///   treat this as a replay.
    /// - `IoError` — unexpected I/O error; caller should log and enforce per
    ///   `jti_enforcement` configuration.
    pub fn check_and_record(&self, scope: &str, value: &str, expires_at_unix: u64) -> AtomicRecordResult {
        let path = self.key_path(scope, value);

        // Ensure the directory exists in case systemd-tmpfiles hasn't run yet
        // or the process restarted after the directory was removed.
        if let Err(e) = std::fs::create_dir_all(&self.dir) {
            tracing::warn!(
                dir = %self.dir.display(),
                error = %e,
                "FsAtomicStore: could not ensure backing directory before write"
            );
            // Not fatal here — the open below will fail with a clearer error.
        }

        match OpenOptions::new()
            .write(true)
            .create_new(true) // O_CREAT | O_EXCL — atomic
            .open(&path)
        {
            Ok(mut file) => {
                // Write the expiry timestamp so opportunistic_sweep can check it
                // without external metadata.
                if let Err(e) = write!(file, "{expires_at_unix}") {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "FsAtomicStore: could not write expiry timestamp to key file"
                    );
                    // The file exists (creation succeeded) — treat as New even if
                    // the timestamp write failed; the sweep will eventually remove
                    // a file with unparseable contents as expired.
                }
                AtomicRecordResult::New
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                AtomicRecordResult::AlreadyExists
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "FsAtomicStore: unexpected I/O error during atomic key creation"
                );
                AtomicRecordResult::IoError(e)
            }
        }
    }

    /// Consume (delete) a key, returning whether it existed.
    ///
    /// Used for single-use nonce enforcement (D-08): after the nonce is
    /// validated, the caller must consume it to prevent replay.
    ///
    /// Returns:
    /// - `Ok(true)` — file existed and was removed.
    /// - `Ok(false)` — file was not found (already consumed or never created).
    /// - `Err(e)` — unexpected I/O error during removal.
    pub fn consume(&self, scope: &str, value: &str) -> std::io::Result<bool> {
        let path = self.key_path(scope, value);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Opportunistically sweep expired entries from the backing directory.
    ///
    /// This method runs with a 5% probability gate (`byte[0] % 20 == 0`) so it
    /// executes roughly once per 20 authentication attempts without a dedicated
    /// cleanup thread (D-04).  `systemd-tmpfiles` provides the deterministic
    /// cleanup for long-running gaps between authentications.
    ///
    /// Files whose content (a decimal unix timestamp) is ≤ `now` are removed.
    /// Files with unparseable contents are removed (treat as expired).
    /// Errors during sweep are logged at WARN and do not propagate — sweep
    /// failures must never block authentication.
    pub fn opportunistic_sweep(&self) {
        // 5% probability gate: read one random byte; sweep when byte % 20 == 0.
        let mut buf = [0u8; 1];
        if getrandom::fill(&mut buf).is_err() {
            // If getrandom fails we skip the sweep rather than blocking auth.
            return;
        }
        if buf[0] % 20 != 0 {
            return;
        }

        self.sweep_expired();
    }

    /// Perform the actual sweep of expired entries (unconditional, for testing).
    ///
    /// Called internally by `opportunistic_sweep` when the probability gate
    /// triggers.  Exposed as a separate method so tests can invoke it directly
    /// without the probability gate.
    pub fn sweep_expired(&self) {
        let now_unix = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(e) => {
                tracing::warn!(error = %e, "FsAtomicStore: system clock before UNIX epoch; skipping sweep");
                return;
            }
        };

        let entries = match std::fs::read_dir(&self.dir) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return, // directory removed
            Err(e) => {
                tracing::warn!(dir = %self.dir.display(), error = %e, "FsAtomicStore: sweep could not read directory");
                return;
            }
        };

        for entry_result in entries {
            let entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(error = %e, "FsAtomicStore: sweep skipping unreadable directory entry");
                    continue;
                }
            };

            let path = entry.path();

            // Read the expiry timestamp from file contents.
            let contents = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "FsAtomicStore: sweep could not read key file; skipping");
                    continue;
                }
            };

            // Parse the timestamp; treat unparseable content as already expired.
            let expires_at: u64 = match contents.trim().parse() {
                Ok(ts) => ts,
                Err(_) => {
                    tracing::warn!(path = %path.display(), "FsAtomicStore: sweep found key file with unparseable timestamp; treating as expired");
                    0 // force deletion
                }
            };

            if expires_at <= now_unix {
                if let Err(e) = std::fs::remove_file(&path) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(path = %path.display(), error = %e, "FsAtomicStore: sweep could not remove expired key file");
                    }
                    // NotFound is fine — another process may have consumed the entry.
                }
            }
        }
    }

    /// Return the backing directory path (for testing and diagnostics).
    #[cfg(test)]
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// Return the env var name used for directory override (for testing).
    #[allow(dead_code)]
    pub fn env_var(&self) -> &'static str {
        self.env_var
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::tempdir;

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_store(dir: &std::path::Path, env_var: &'static str) -> FsAtomicStore {
        // Ensure the env var points to the temp dir for test isolation.
        std::env::set_var(env_var, dir.to_str().unwrap());
        FsAtomicStore::new("/nonexistent-default", env_var)
    }

    #[test]
    fn test_check_and_record_new_key_returns_new() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path(), "UNIX_OIDC_TEST_FS_01");
        let expires = now_unix() + 300;
        let result = store.check_and_record("https://issuer.example.com", "jti-abc", expires);
        assert!(
            matches!(result, AtomicRecordResult::New),
            "First check_and_record should return New"
        );
    }

    #[test]
    fn test_check_and_record_same_key_returns_already_exists() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path(), "UNIX_OIDC_TEST_FS_02");
        let expires = now_unix() + 300;

        let r1 = store.check_and_record("https://issuer.example.com", "jti-abc", expires);
        assert!(matches!(r1, AtomicRecordResult::New));

        let r2 = store.check_and_record("https://issuer.example.com", "jti-abc", expires);
        assert!(
            matches!(r2, AtomicRecordResult::AlreadyExists),
            "Second check_and_record with same key should return AlreadyExists"
        );
    }

    #[test]
    fn test_check_and_record_same_value_different_scope_returns_new() {
        // Cross-issuer isolation: different scope (issuer URL) must hash to
        // a different filename, so the second call returns New (D-02).
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path(), "UNIX_OIDC_TEST_FS_03");
        let expires = now_unix() + 300;

        let r1 = store.check_and_record("https://issuer-a.example.com", "jti-shared", expires);
        assert!(matches!(r1, AtomicRecordResult::New));

        let r2 = store.check_and_record("https://issuer-b.example.com", "jti-shared", expires);
        assert!(
            matches!(r2, AtomicRecordResult::New),
            "Same JTI value under a different scope must return New (cross-issuer isolation)"
        );
    }

    #[test]
    fn test_consume_after_check_and_record_returns_true() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path(), "UNIX_OIDC_TEST_FS_04");
        let expires = now_unix() + 300;

        store.check_and_record("scope", "nonce-x", expires);
        let consumed = store.consume("scope", "nonce-x").unwrap();
        assert!(consumed, "consume() after check_and_record() should return true");
    }

    #[test]
    fn test_consume_twice_returns_false_second_time() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path(), "UNIX_OIDC_TEST_FS_05");
        let expires = now_unix() + 300;

        store.check_and_record("scope", "nonce-y", expires);
        let first = store.consume("scope", "nonce-y").unwrap();
        assert!(first);

        let second = store.consume("scope", "nonce-y").unwrap();
        assert!(!second, "Second consume() on same key must return false");
    }

    #[test]
    fn test_consume_never_created_returns_false() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path(), "UNIX_OIDC_TEST_FS_06");

        let result = store.consume("scope", "nonexistent-key").unwrap();
        assert!(!result, "consume() on non-existent key must return false");
    }

    #[test]
    fn test_check_and_record_unwritable_directory_returns_io_error() {
        // Create a temp dir, then make it read-only.
        let tmp = tempdir().unwrap();
        let ro_dir = tmp.path().join("readonly");
        std::fs::create_dir_all(&ro_dir).unwrap();

        // Set permissions to 0o555 (read + execute, no write).
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        // Create the store pointing directly at the read-only directory.
        let store = FsAtomicStore {
            dir: ro_dir.clone(),
            env_var: "UNIX_OIDC_TEST_FS_07_UNUSED",
        };

        let result = store.check_and_record("scope", "jti-ro", now_unix() + 300);

        // Restore permissions for cleanup.
        let _ = std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o755));

        assert!(
            matches!(result, AtomicRecordResult::IoError(_)),
            "check_and_record on unwritable directory must return IoError"
        );
    }

    #[test]
    fn test_key_path_produces_64_char_hex() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path(), "UNIX_OIDC_TEST_FS_08");

        let path = store.key_path("https://issuer.example.com", "jti-xyz");
        let filename = path.file_name().unwrap().to_str().unwrap();

        assert_eq!(
            filename.len(),
            64,
            "SHA-256 hex filename must be 64 characters; got {filename}"
        );
        assert!(
            filename.chars().all(|c| c.is_ascii_hexdigit()),
            "Filename must contain only hex characters; got {filename}"
        );
    }

    #[test]
    fn test_sweep_expired_deletes_expired_keeps_fresh() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path(), "UNIX_OIDC_TEST_FS_09");

        // Record one entry that has already expired (unix timestamp 1 = far in the past).
        let expired_path = store.key_path("scope", "old-jti");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&expired_path)
                .unwrap();
            write!(f, "1").unwrap(); // timestamp 1 = 1970-01-01, definitely expired
        }

        // Record one entry that expires 1 hour from now.
        let fresh_expires = now_unix() + 3600;
        let r = store.check_and_record("scope", "new-jti", fresh_expires);
        assert!(matches!(r, AtomicRecordResult::New));

        // Run the sweep unconditionally.
        store.sweep_expired();

        // Expired file must be gone.
        assert!(
            !expired_path.exists(),
            "sweep_expired() must delete files with expired timestamps"
        );

        // Fresh file must still exist.
        let fresh_path = store.key_path("scope", "new-jti");
        assert!(
            fresh_path.exists(),
            "sweep_expired() must not delete files with future timestamps"
        );
    }

    #[test]
    fn test_file_contents_contain_expires_at_timestamp() {
        let tmp = tempdir().unwrap();
        let store = make_store(tmp.path(), "UNIX_OIDC_TEST_FS_10");

        let expires = now_unix() + 7200;
        store.check_and_record("scope", "jti-content", expires);

        let path = store.key_path("scope", "jti-content");
        let contents = std::fs::read_to_string(&path).unwrap();
        let stored: u64 = contents.trim().parse().expect("file must contain a u64 timestamp");

        assert_eq!(
            stored, expires,
            "File must contain the exact expires_at unix timestamp"
        );
    }
}
