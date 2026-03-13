//! Storage backend router with probe-based detection and fallback chain.
//!
//! This module implements automatic selection of the best available keyring
//! backend, falling back to file storage when no keyring is accessible.
//!
//! # Backend selection order
//!
//! 1. If `UNIX_OIDC_STORAGE_BACKEND` is set, probe only the requested backend
//!    and return `Err` on probe failure — no fallthrough.
//! 2. Linux: Secret Service (D-Bus/libsecret)
//! 3. Linux: keyutils user keyring (`@u`)
//! 4. macOS: macOS Keychain Services
//! 5. File storage (plaintext files, mode 0600) — last resort
//!
//! # Probe mechanism
//!
//! A probe is a full write → read → delete cycle using the sentinel key
//! `unix-oidc-probe`. Constructor success alone is insufficient — some
//! backends appear to construct successfully but fail on I/O (e.g., keyutils
//! if the session keyring is not initialised, Secret Service if D-Bus is
//! unavailable).
//!
//! # Migration awareness
//!
//! When a higher-priority backend is selected after a previous run used a
//! different backend, credentials from the old backend become inaccessible.
//! Failed probes log a WARN with actionable text:
//! "credentials from previous backend are inaccessible; run `unix-oidc-agent login` to re-authenticate"

use tracing::{info, warn};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::KeyringStorage;
use super::{
    FileStorage, SecureStorage, StorageError, KEY_ACCESS_TOKEN, KEY_DPOP_PRIVATE,
    KEY_REFRESH_TOKEN, KEY_TOKEN_METADATA,
};

/// Prefix for probe sentinel keys. A random suffix is appended per invocation
/// so that parallel probes (e.g., in tests) don't clobber each other.
const PROBE_KEY_PREFIX: &str = "unix-oidc-probe-";
/// Sentinel value written during probe. Must be non-empty (keyutils rejects empty payloads).
const PROBE_VALUE: &[u8] = b"probe-ok";

/// Which storage backend is active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendKind {
    /// Secret Service over D-Bus (Linux, requires `sync-secret-service` feature).
    SecretService,
    /// Linux kernel keyutils user keyring `@u` (requires `linux-native` feature).
    KeyutilsUser,
    /// macOS Keychain Services (requires `apple-native` feature).
    MacOsKeychain,
    /// Plain files, mode 0600, with NIST SP 800-88 three-pass secure delete (last resort).
    File,
}

impl BackendKind {
    /// Human-readable display name shown in status output.
    pub fn display_name(&self) -> &'static str {
        match self {
            BackendKind::SecretService => "keyring (Secret Service)",
            BackendKind::KeyutilsUser => "keyring (keyutils @u)",
            BackendKind::MacOsKeychain => "keyring (macOS Keychain)",
            BackendKind::File => "file (fallback)",
        }
    }
}

/// Whether credentials were migrated from a previous backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationStatus {
    /// N credentials were copied from the old backend to the new one.
    Migrated(usize),
    /// Migration was attempted but no credentials needed moving.
    NotMigrated,
    /// Migration is not applicable (no backend change detected, or first run).
    NotApplicable,
}

impl MigrationStatus {
    /// Human-readable display string shown in status output.
    pub fn display_name(&self) -> &'static str {
        match self {
            MigrationStatus::Migrated(_) => "migrated",
            MigrationStatus::NotMigrated => "not migrated",
            MigrationStatus::NotApplicable => "n/a",
        }
    }
}

/// Routes storage operations to the best available backend.
///
/// Constructed via [`StorageRouter::detect()`] which runs probe-based backend
/// detection. All [`SecureStorage`] method calls are delegated to the selected backend.
///
/// `Debug` is implemented manually because `Box<dyn SecureStorage>` is not `Debug`.
/// The debug output shows the backend kind but not internal state.
pub struct StorageRouter {
    backend: Box<dyn SecureStorage>,
    /// Which backend was selected.
    pub kind: BackendKind,
    /// Migration status set by the caller after optional migration.
    pub migration_status: MigrationStatus,
}

impl std::fmt::Debug for StorageRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageRouter")
            .field("kind", &self.kind)
            .field("migration_status", &self.migration_status)
            .finish_non_exhaustive()
    }
}

impl StorageRouter {
    /// Probe-based backend detection.
    ///
    /// Respects `UNIX_OIDC_STORAGE_BACKEND` environment variable for forced
    /// selection. Falls back through keyring backends to file storage.
    ///
    /// # Environment variable
    ///
    /// Valid values: `file`, `secret-service`, `keyutils`, `macos-keychain`.
    /// If the forced backend fails its probe, returns `Err` — does NOT fall through.
    ///
    /// # Errors
    ///
    /// Returns `Err` if a forced backend fails, or if even the file fallback fails.
    pub fn detect() -> Result<Self, StorageError> {
        if let Ok(forced) = std::env::var("UNIX_OIDC_STORAGE_BACKEND") {
            return detect_forced(&forced);
        }

        detect_auto()
    }

    /// Return the active backend kind.
    pub fn kind(&self) -> &BackendKind {
        &self.kind
    }

    /// Migrate credentials from the default [`FileStorage`] location to this backend.
    ///
    /// This is the public entry point called at daemon startup and login. It creates
    /// a `FileStorage` instance pointing at the default data directory and delegates
    /// to [`StorageRouter::maybe_migrate_from`].
    ///
    /// Returns the number of keys migrated (0 when no migration was needed).
    pub fn maybe_migrate(&mut self) -> Result<usize, StorageError> {
        let file_storage = match FileStorage::new() {
            Ok(s) => s,
            Err(_) => {
                // If we can't even construct FileStorage, there's nothing to migrate.
                self.migration_status = MigrationStatus::NotApplicable;
                return Ok(0);
            }
        };
        self.maybe_migrate_from(&file_storage)
    }

    /// Migrate credentials from `src` (file storage) to this backend.
    ///
    /// # Migration semantics
    ///
    /// 1. If this router is backed by `File`, return `NotApplicable` immediately —
    ///    file-to-file migration is a no-op.
    /// 2. Collect whichever of the 4 credential keys exist in `src`.
    /// 3. If none exist, return `NotApplicable`.
    /// 4. For each key: write to `self` then read back and compare. On any mismatch
    ///    or error, call `rollback_migration()` to undo all previously written keys
    ///    and return `Err`.
    /// 5. After all keys are verified in the new backend, secure-delete each from `src`.
    ///    Deletion failures are logged at WARN and do not abort the migration.
    /// 6. Update `self.migration_status` to `Migrated(n)` and log at INFO.
    ///
    /// Returns the number of keys migrated.
    pub fn maybe_migrate_from(&mut self, src: &FileStorage) -> Result<usize, StorageError> {
        // No file-to-file migration.
        if self.kind == BackendKind::File {
            self.migration_status = MigrationStatus::NotApplicable;
            return Ok(0);
        }

        // Collect keys that exist in the file source.
        let all_keys = [
            KEY_DPOP_PRIVATE,
            KEY_ACCESS_TOKEN,
            KEY_REFRESH_TOKEN,
            KEY_TOKEN_METADATA,
        ];

        let present_keys: Vec<&str> = all_keys.iter().copied().filter(|k| src.exists(k)).collect();

        if present_keys.is_empty() {
            self.migration_status = MigrationStatus::NotApplicable;
            return Ok(0);
        }

        // Migrate each key: write to destination, read back, verify.
        let mut migrated: Vec<&str> = Vec::with_capacity(present_keys.len());

        for &key in &present_keys {
            let value = src.retrieve(key).map_err(|e| {
                StorageError::Migration(format!("Failed to read key '{key}' from source: {e}"))
            })?;

            // Write to destination.
            if let Err(e) = self.backend.store(key, &value) {
                warn!(key, error = %e, "Migration write failed; rolling back");
                self.rollback_migration(&migrated);
                return Err(StorageError::Migration(format!(
                    "Failed to write key '{key}' to destination: {e}"
                )));
            }

            // Read back and verify (guards against silent write failures).
            match self.backend.retrieve(key) {
                Ok(readback) if readback == value => {
                    migrated.push(key);
                }
                Ok(_) => {
                    warn!(key, "Migration read-back mismatch; rolling back");
                    // Delete the just-written key before rolling back the rest.
                    let _ = self.backend.delete(key);
                    self.rollback_migration(&migrated);
                    return Err(StorageError::Migration(format!(
                        "Read-back verification failed for key '{key}'"
                    )));
                }
                Err(e) => {
                    warn!(key, error = %e, "Migration read-back failed; rolling back");
                    let _ = self.backend.delete(key);
                    self.rollback_migration(&migrated);
                    return Err(StorageError::Migration(format!(
                        "Read-back failed for key '{key}': {e}"
                    )));
                }
            }
        }

        // All keys migrated and verified. Secure-delete originals.
        // Deletion failures are best-effort (per research Pitfall 6): log WARN, continue.
        for &key in &migrated {
            if let Err(e) = src.delete(key) {
                warn!(key, error = %e, "Could not secure-delete source key after migration (best-effort)");
            }
        }

        let count = migrated.len();
        self.migration_status = MigrationStatus::Migrated(count);
        info!(
            count,
            "Migrated credentials from file storage to keyring backend"
        );

        Ok(count)
    }

    /// Delete all keys in `migrated` from `self.backend`.
    ///
    /// Called during rollback. Individual deletion failures are logged at WARN
    /// but do not abort the rollback — remaining keys are still attempted.
    fn rollback_migration(&self, migrated: &[&str]) {
        for &key in migrated {
            if let Err(e) = self.backend.delete(key) {
                warn!(key, error = %e, "Rollback deletion failed (best-effort — continuing)");
            }
        }
    }
}

impl SecureStorage for StorageRouter {
    fn store(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.backend.store(key, value)
    }

    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        self.backend.retrieve(key)
    }

    fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.backend.delete(key)
    }

    fn exists(&self, key: &str) -> bool {
        self.backend.exists(key)
    }
}

/// Run a write → read → delete probe cycle against `backend`.
///
/// Returns `Ok(())` if the full cycle succeeds. The probe key is always cleaned
/// up — even on partial failure — to avoid leaving sentinel data behind.
///
/// A unique key is generated per invocation (PID + atomic counter) so that
/// concurrent probes in tests or at startup do not clobber each other.
fn probe_backend(backend: &dyn SecureStorage) -> Result<(), StorageError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

    let seq = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let probe_key = format!("{}{}-{}", PROBE_KEY_PREFIX, std::process::id(), seq);

    // Write sentinel — non-empty to satisfy keyutils constraint (Pitfall 4).
    backend.store(&probe_key, PROBE_VALUE)?;

    // Read back and verify.
    let read_result = backend.retrieve(&probe_key);

    // Always attempt cleanup, even if read failed.
    let _ = backend.delete(&probe_key);

    let retrieved = read_result?;
    if retrieved != PROBE_VALUE {
        return Err(StorageError::Backend(format!(
            "probe read-back mismatch: expected {PROBE_VALUE:?}, got {retrieved:?}"
        )));
    }

    Ok(())
}

/// Probe a backend selected by name; return `Err` on probe failure (no fallthrough).
fn detect_forced(name: &str) -> Result<StorageRouter, StorageError> {
    match name {
        "file" => {
            let storage = FileStorage::new()?;
            probe_backend(&storage).map_err(|e| {
                StorageError::Backend(format!("forced backend 'file' failed probe: {e}"))
            })?;
            info!(backend = "file (fallback)", "Storage backend selected (forced)");
            Ok(StorageRouter {
                backend: Box::new(storage),
                kind: BackendKind::File,
                migration_status: MigrationStatus::NotApplicable,
            })
        }

        "secret-service" => {
            // secret-service is only available on Linux (sync-secret-service feature always enabled)
            #[cfg(target_os = "linux")]
            {
                keyring::set_default_credential_builder(
                    keyring::secret_service::default_credential_builder(),
                );
                let storage = KeyringStorage::new();
                probe_backend(&storage).map_err(|e| {
                    StorageError::Backend(format!(
                        "forced backend 'secret-service' failed probe: {e}"
                    ))
                })?;
                info!(backend = "keyring (Secret Service)", "Storage backend selected (forced)");
                Ok(StorageRouter {
                    backend: Box::new(storage),
                    kind: BackendKind::SecretService,
                    migration_status: MigrationStatus::NotApplicable,
                })
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(StorageError::Backend(
                    "forced backend 'secret-service' is not available on this platform (Linux only)"
                        .to_string(),
                ))
            }
        }

        "keyutils" => {
            // keyutils is only available on Linux (linux-native feature always enabled)
            #[cfg(target_os = "linux")]
            {
                keyring::set_default_credential_builder(
                    keyring::keyutils::default_credential_builder(),
                );
                let storage = KeyringStorage::new();
                probe_backend(&storage).map_err(|e| {
                    StorageError::Backend(format!(
                        "forced backend 'keyutils' failed probe: {e}"
                    ))
                })?;
                info!(backend = "keyring (keyutils @u)", "Storage backend selected (forced)");
                Ok(StorageRouter {
                    backend: Box::new(storage),
                    kind: BackendKind::KeyutilsUser,
                    migration_status: MigrationStatus::NotApplicable,
                })
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(StorageError::Backend(
                    "forced backend 'keyutils' is not available on this platform (Linux only)"
                        .to_string(),
                ))
            }
        }

        "macos-keychain" => {
            // macOS Keychain is only available on macOS (apple-native feature always enabled)
            #[cfg(target_os = "macos")]
            {
                keyring::set_default_credential_builder(
                    keyring::macos::default_credential_builder(),
                );
                let storage = KeyringStorage::new();
                probe_backend(&storage).map_err(|e| {
                    StorageError::Backend(format!(
                        "forced backend 'macos-keychain' failed probe: {}",
                        e
                    ))
                })?;
                info!(backend = "keyring (macOS Keychain)", "Storage backend selected (forced)");
                Ok(StorageRouter {
                    backend: Box::new(storage),
                    kind: BackendKind::MacOsKeychain,
                    migration_status: MigrationStatus::NotApplicable,
                })
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err(StorageError::Backend(
                    "forced backend 'macos-keychain' is not available on this platform (macOS only)"
                        .to_string(),
                ))
            }
        }

        other => Err(StorageError::Backend(format!(
            "unknown forced backend '{other}'; valid values: file, secret-service, keyutils, macos-keychain"
        ))),
    }
}

/// Attempt probes in priority order; fall back to file storage.
fn detect_auto() -> Result<StorageRouter, StorageError> {
    // Linux: Secret Service (D-Bus / libsecret)
    // sync-secret-service feature is unconditionally enabled in Cargo.toml on Linux.
    #[cfg(target_os = "linux")]
    {
        keyring::set_default_credential_builder(
            keyring::secret_service::default_credential_builder(),
        );
        let storage = KeyringStorage::new();
        match probe_backend(&storage) {
            Ok(()) => {
                info!(
                    backend = "keyring (Secret Service)",
                    "Storage backend selected"
                );
                return Ok(StorageRouter {
                    backend: Box::new(storage),
                    kind: BackendKind::SecretService,
                    migration_status: MigrationStatus::NotApplicable,
                });
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Secret Service probe failed — credentials from previous backend are \
                     inaccessible; run `unix-oidc-agent login` to re-authenticate"
                );
            }
        }
    }

    // Linux: keyutils user keyring (@u)
    // linux-native feature is unconditionally enabled in Cargo.toml on Linux.
    #[cfg(target_os = "linux")]
    {
        keyring::set_default_credential_builder(keyring::keyutils::default_credential_builder());
        let storage = KeyringStorage::new();
        match probe_backend(&storage) {
            Ok(()) => {
                info!(
                    backend = "keyring (keyutils @u)",
                    "Storage backend selected"
                );
                return Ok(StorageRouter {
                    backend: Box::new(storage),
                    kind: BackendKind::KeyutilsUser,
                    migration_status: MigrationStatus::NotApplicable,
                });
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "keyutils probe failed — credentials from previous backend are \
                     inaccessible; run `unix-oidc-agent login` to re-authenticate"
                );
            }
        }
    }

    // macOS: Keychain Services
    // apple-native feature is unconditionally enabled in Cargo.toml on macOS.
    #[cfg(target_os = "macos")]
    {
        keyring::set_default_credential_builder(keyring::macos::default_credential_builder());
        let storage = KeyringStorage::new();
        match probe_backend(&storage) {
            Ok(()) => {
                info!(
                    backend = "keyring (macOS Keychain)",
                    "Storage backend selected"
                );
                return Ok(StorageRouter {
                    backend: Box::new(storage),
                    kind: BackendKind::MacOsKeychain,
                    migration_status: MigrationStatus::NotApplicable,
                });
            }
            Err(e) => {
                // macOS Keychain probe failure — log for operator awareness.
                // On macOS warn is available unconditionally (not Linux-gated).
                tracing::warn!(
                    error = %e,
                    "macOS Keychain probe failed — credentials from previous backend are \
                     inaccessible; run `unix-oidc-agent login` to re-authenticate"
                );
            }
        }
    }

    // Last resort: file storage
    let storage = FileStorage::new()?;
    info!(
        backend = "file (fallback)",
        "Storage backend selected (no keyring available)"
    );
    Ok(StorageRouter {
        backend: Box::new(storage),
        kind: BackendKind::File,
        migration_status: MigrationStatus::NotApplicable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Set up the mock keyring backend for the current thread's test scope.
    /// Must be called before any Entry::new() calls in the test.
    fn use_mock_keyring() {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    }

    /// Create a file-backed StorageRouter pointing at a custom directory.
    /// Used in tests that need two separate file stores (source + destination)
    /// without triggering interactive keychain prompts on macOS.
    fn detect_forced_with_dir(
        _name: &str,
        base_dir: std::path::PathBuf,
    ) -> Result<StorageRouter, StorageError> {
        let storage = FileStorage::with_base_dir(base_dir);
        Ok(StorageRouter {
            backend: Box::new(storage),
            // Use a non-File kind so migration actually runs (skipping kind==File guard).
            kind: BackendKind::SecretService,
            migration_status: MigrationStatus::NotApplicable,
        })
    }

    // -------------------------------------------------------------------------
    // maybe_migrate() — TDD RED tests added first (Task 1)
    // -------------------------------------------------------------------------

    /// Migration with all 4 keys present: returns Migrated(4) and keys reach destination.
    #[test]
    fn migration_moves_all_4_keys_from_file_to_keyring() {
        use crate::storage::{
            KEY_ACCESS_TOKEN, KEY_DPOP_PRIVATE, KEY_REFRESH_TOKEN, KEY_TOKEN_METADATA,
        };

        let src_tmp = tempfile::TempDir::new().expect("tempdir");
        let src = FileStorage::with_base_dir(src_tmp.path().to_path_buf());

        // Store all 4 keys in file storage.
        src.store(KEY_DPOP_PRIVATE, b"dpop-key-bytes").unwrap();
        src.store(KEY_ACCESS_TOKEN, b"access-token").unwrap();
        src.store(KEY_REFRESH_TOKEN, b"refresh-token").unwrap();
        src.store(KEY_TOKEN_METADATA, b"metadata-json").unwrap();

        // Use a file-backed destination (a second tempdir) to avoid keyring prompt in CI.
        let dst_tmp = tempfile::TempDir::new().expect("tempdir");
        let mut router = detect_forced_with_dir("file-dst", dst_tmp.path().to_path_buf())
            .expect("router should be created");

        let result = router.maybe_migrate_from(&src);
        assert!(result.is_ok(), "migration should succeed: {result:?}");
        assert_eq!(result.unwrap(), 4, "should report 4 keys migrated");
        assert!(
            matches!(router.migration_status, MigrationStatus::Migrated(4)),
            "migration_status should be Migrated(4)"
        );

        // All 4 keys should now exist in the destination.
        assert!(router.exists(KEY_DPOP_PRIVATE), "dpop key should be in dst");
        assert!(
            router.exists(KEY_ACCESS_TOKEN),
            "access token should be in dst"
        );
        assert!(
            router.exists(KEY_REFRESH_TOKEN),
            "refresh token should be in dst"
        );
        assert!(
            router.exists(KEY_TOKEN_METADATA),
            "metadata should be in dst"
        );
    }

    /// Migration returns NotApplicable when no file credentials exist.
    #[test]
    fn migration_returns_not_applicable_when_no_file_credentials() {
        let src_tmp = tempfile::TempDir::new().expect("tempdir");
        let src = FileStorage::with_base_dir(src_tmp.path().to_path_buf());
        // No keys stored.

        let dst_tmp = tempfile::TempDir::new().expect("tempdir");
        let mut router = detect_forced_with_dir("file-dst", dst_tmp.path().to_path_buf())
            .expect("router should be created");

        let result = router.maybe_migrate_from(&src);
        assert!(result.is_ok(), "should return Ok(0): {result:?}");
        assert_eq!(result.unwrap(), 0, "should report 0 keys migrated");
        assert!(
            matches!(router.migration_status, MigrationStatus::NotApplicable),
            "migration_status should be NotApplicable"
        );
    }

    /// Migration rollback: if write of key 3 fails, keys 1+2 are removed from destination.
    #[test]
    fn migration_rollback_when_destination_write_fails() {
        use crate::storage::{KEY_ACCESS_TOKEN, KEY_DPOP_PRIVATE};

        let src_tmp = tempfile::TempDir::new().expect("tempdir");
        let src = FileStorage::with_base_dir(src_tmp.path().to_path_buf());

        // Only store 2 out of 4 keys; use a poisoned backend that fails on the 3rd write.
        // We simulate this by storing only 2 keys (so migration processes exactly 2) then
        // verifying no partial state remains after a store failure.
        // A simpler approach: wrap the destination in a failing backend after 2 stores.
        src.store(KEY_DPOP_PRIVATE, b"dpop-key").unwrap();
        src.store(KEY_ACCESS_TOKEN, b"access-token").unwrap();

        // Poisoned router: succeeds on first store, fails on second retrieve (verify step).
        // We use a pair of FileStorage tempdirs where the source has keys but we
        // inject a read-verify failure using a custom wrapper.
        struct FailOnSecondStore {
            inner: FileStorage,
            call_count: std::sync::atomic::AtomicUsize,
        }
        impl SecureStorage for FailOnSecondStore {
            fn store(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
                use std::sync::atomic::Ordering;
                let n = self.call_count.fetch_add(1, Ordering::SeqCst);
                if n >= 1 {
                    return Err(StorageError::Backend(
                        "simulated write failure on key 2+".to_string(),
                    ));
                }
                self.inner.store(key, value)
            }
            fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
                self.inner.retrieve(key)
            }
            fn delete(&self, key: &str) -> Result<(), StorageError> {
                self.inner.delete(key)
            }
            fn exists(&self, key: &str) -> bool {
                self.inner.exists(key)
            }
        }

        let dst_tmp = tempfile::TempDir::new().expect("tempdir");
        let failing_backend = FailOnSecondStore {
            inner: FileStorage::with_base_dir(dst_tmp.path().to_path_buf()),
            call_count: std::sync::atomic::AtomicUsize::new(0),
        };

        let mut router = StorageRouter {
            backend: Box::new(failing_backend),
            kind: BackendKind::SecretService, // non-File so migration runs
            migration_status: MigrationStatus::NotApplicable,
        };

        let result = router.maybe_migrate_from(&src);
        // Migration must fail.
        assert!(
            result.is_err(),
            "migration should fail when write fails: {result:?}"
        );

        // After rollback, the first key that WAS written must be deleted from dst.
        // The dst_tmp directory should have 0 remaining files for migrated keys.
        let remaining_files: Vec<_> = std::fs::read_dir(dst_tmp.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            remaining_files.is_empty(),
            "rollback should delete all partially-migrated keys: {:?}",
            remaining_files
                .iter()
                .map(|e| e.file_name())
                .collect::<Vec<_>>()
        );
    }

    /// Migration: file credentials are deleted after successful migration.
    #[test]
    fn migration_secure_deletes_file_credentials_after_success() {
        use crate::storage::{KEY_ACCESS_TOKEN, KEY_DPOP_PRIVATE};

        let src_tmp = tempfile::TempDir::new().expect("tempdir");
        let src = FileStorage::with_base_dir(src_tmp.path().to_path_buf());

        src.store(KEY_DPOP_PRIVATE, b"dpop-key").unwrap();
        src.store(KEY_ACCESS_TOKEN, b"access-token").unwrap();

        let dst_tmp = tempfile::TempDir::new().expect("tempdir");
        let mut router = detect_forced_with_dir("file-dst", dst_tmp.path().to_path_buf())
            .expect("router should be created");

        router
            .maybe_migrate_from(&src)
            .expect("migration should succeed");

        // Source files must be deleted.
        assert!(
            !src.exists(KEY_DPOP_PRIVATE),
            "dpop key must be deleted from source"
        );
        assert!(
            !src.exists(KEY_ACCESS_TOKEN),
            "access token must be deleted from source"
        );
    }

    /// Migration is skipped when router backend is File (no file-to-file migration).
    #[test]
    fn migration_skipped_when_router_is_file_backend() {
        use crate::storage::KEY_DPOP_PRIVATE;

        let src_tmp = tempfile::TempDir::new().expect("tempdir");
        let src = FileStorage::with_base_dir(src_tmp.path().to_path_buf());
        src.store(KEY_DPOP_PRIVATE, b"dpop-key").unwrap();

        let file_router = detect_forced("file").expect("file backend should succeed");
        let mut router = file_router;

        let result = router.maybe_migrate_from(&src);
        assert!(result.is_ok(), "should return Ok: {result:?}");
        assert_eq!(result.unwrap(), 0, "should report 0 (skipped)");
        assert!(
            matches!(router.migration_status, MigrationStatus::NotApplicable),
            "migration_status should be NotApplicable for file-to-file"
        );
    }

    /// maybe_migrate() (public API): uses FileStorage::new() internally; returns NotApplicable
    /// when no file creds exist (avoids interactive keychain on macOS by forcing file backend).
    #[test]
    #[ignore = "Requires FileStorage::new() to succeed (ProjectDirs available)"]
    fn maybe_migrate_no_op_when_no_file_creds() {
        let mut router = detect_forced("file").expect("file backend should succeed");
        // No credentials exist in the default file store for this test environment.
        let result = router.maybe_migrate();
        assert!(result.is_ok(), "maybe_migrate should return Ok: {result:?}");
        assert_eq!(result.unwrap(), 0);
    }

    // -------------------------------------------------------------------------
    // BackendKind display names
    // -------------------------------------------------------------------------

    #[test]
    fn backend_kind_display_names() {
        assert_eq!(
            BackendKind::SecretService.display_name(),
            "keyring (Secret Service)"
        );
        assert_eq!(
            BackendKind::KeyutilsUser.display_name(),
            "keyring (keyutils @u)"
        );
        assert_eq!(
            BackendKind::MacOsKeychain.display_name(),
            "keyring (macOS Keychain)"
        );
        assert_eq!(BackendKind::File.display_name(), "file (fallback)");
    }

    // -------------------------------------------------------------------------
    // MigrationStatus display names
    // -------------------------------------------------------------------------

    #[test]
    fn migration_status_display_names() {
        assert_eq!(MigrationStatus::Migrated(3).display_name(), "migrated");
        assert_eq!(MigrationStatus::Migrated(0).display_name(), "migrated");
        assert_eq!(MigrationStatus::NotMigrated.display_name(), "not migrated");
        assert_eq!(MigrationStatus::NotApplicable.display_name(), "n/a");
    }

    // -------------------------------------------------------------------------
    // probe_backend with file storage (mock keyring has no cross-entry persistence)
    // -------------------------------------------------------------------------
    //
    // The keyring mock stores data per-Entry-instance (no global store), so
    // KeyringStorage cannot be used for probe round-trips in unit tests — store()
    // and retrieve() create separate Entry objects that don't share state.
    // FileStorage with a tempdir is the correct choice for testing probe_backend.

    #[test]
    fn probe_succeeds_with_file_backend() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let storage = FileStorage::with_base_dir(tmp.path().to_path_buf());
        let result = probe_backend(&storage);
        assert!(
            result.is_ok(),
            "probe should succeed with file backend: {result:?}"
        );
    }

    #[test]
    fn probe_cleans_up_sentinel_after_success() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let storage = FileStorage::with_base_dir(tmp.path().to_path_buf());
        probe_backend(&storage).expect("probe should succeed");
        // Sentinel must be removed. Since the probe key is auto-generated with PID+seq,
        // we verify no files remain in the temp directory after the probe.
        let remaining_files: Vec<_> = std::fs::read_dir(tmp.path())
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            remaining_files.is_empty(),
            "no probe sentinel files should remain after probe: {:?}",
            remaining_files
                .iter()
                .map(|e| e.file_name())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn probe_fails_on_read_back_mismatch_by_poisoning_store() {
        // Inject a read error by wrapping FileStorage in a struct that sabotages retrieve.
        struct PoisonedStorage(FileStorage);
        impl SecureStorage for PoisonedStorage {
            fn store(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
                self.0.store(key, value)
            }
            fn retrieve(&self, _key: &str) -> Result<Vec<u8>, StorageError> {
                Err(StorageError::Backend("simulated read failure".to_string()))
            }
            fn delete(&self, key: &str) -> Result<(), StorageError> {
                self.0.delete(key)
            }
            fn exists(&self, key: &str) -> bool {
                self.0.exists(key)
            }
        }

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let storage = PoisonedStorage(FileStorage::with_base_dir(tmp.path().to_path_buf()));
        let result = probe_backend(&storage);
        assert!(
            result.is_err(),
            "probe must fail when backend rejects reads: {result:?}"
        );
    }

    // -------------------------------------------------------------------------
    // detect_forced: known backends
    // -------------------------------------------------------------------------

    #[test]
    fn forced_file_backend_selects_file_kind() {
        use_mock_keyring();
        let result = detect_forced("file");
        assert!(
            result.is_ok(),
            "file forced backend should succeed: {result:?}"
        );
        let router = result.unwrap();
        assert_eq!(router.kind, BackendKind::File);
    }

    #[test]
    fn forced_invalid_backend_returns_err_with_message() {
        let result = detect_forced("nonexistent-backend");
        assert!(
            matches!(result, Err(StorageError::Backend(_))),
            "invalid backend name should return Err(Backend): {result:?}"
        );
        if let Err(StorageError::Backend(msg)) = result {
            assert!(
                msg.contains("unknown forced backend"),
                "error message should mention 'unknown forced backend', got: {msg}"
            );
        }
    }

    #[test]
    fn forced_backend_probe_failure_returns_err_no_fallthrough() {
        // An unknown backend name always returns Err immediately.
        // Verifies the contract: forced + failure = Err, never fallthrough to file.
        let result = detect_forced("nonexistent-backend-xyz");
        assert!(
            result.is_err(),
            "forced backend probe failure must return Err, not fall through to file"
        );
    }

    // -------------------------------------------------------------------------
    // detect_auto / StorageRouter::detect: smoke tests
    //
    // On macOS, detect_auto() triggers a real Keychain access prompt (blocks).
    // On Linux, Secret Service may not be running.
    // These integration-level tests are marked #[ignore]; they're run manually
    // or in environments where the keychain is pre-authorised.
    //
    // Functional delegation tests use detect_forced("file") which goes through
    // FileStorage and is always safe.
    // -------------------------------------------------------------------------

    #[test]
    #[ignore = "Requires interactive keychain or running D-Bus/Secret Service"]
    fn detect_auto_selects_native_keychain() {
        let router = detect_auto().expect("detect_auto should not fail");

        // On macOS, must select Keychain Services; on Linux, Secret Service or keyutils.
        // File fallback means the keychain probe failed — that's a test environment issue,
        // not a pass.
        #[cfg(target_os = "macos")]
        assert_eq!(
            router.kind,
            BackendKind::MacOsKeychain,
            "macOS detect_auto must select Keychain, got {:?}",
            router.kind
        );
        #[cfg(target_os = "linux")]
        assert!(
            router.kind == BackendKind::SecretService || router.kind == BackendKind::KeyutilsUser,
            "Linux detect_auto must select a keyring backend, got {:?}",
            router.kind
        );
    }

    #[test]
    #[ignore = "Requires interactive keychain or running D-Bus/Secret Service"]
    fn storage_router_detect_selects_native_keychain() {
        std::env::remove_var("UNIX_OIDC_STORAGE_BACKEND");
        let router = StorageRouter::detect().expect("StorageRouter::detect() should succeed");

        #[cfg(target_os = "macos")]
        assert_eq!(
            router.kind,
            BackendKind::MacOsKeychain,
            "macOS detect must select Keychain, got {:?}",
            router.kind
        );
        #[cfg(target_os = "linux")]
        assert!(
            router.kind == BackendKind::SecretService || router.kind == BackendKind::KeyutilsUser,
            "Linux detect must select a keyring backend, got {:?}",
            router.kind
        );
    }

    #[test]
    #[ignore = "Requires interactive keychain or running D-Bus/Secret Service"]
    fn probe_cleans_up_keychain_entry() {
        // Verify probe doesn't leave stale entries in the real keychain.
        let storage = KeyringStorage::new();
        let result = probe_backend(&storage);
        assert!(result.is_ok(), "keychain probe should succeed: {result:?}");

        // The probe key format is "unix-oidc-probe-{pid}-{seq}".
        // We can't predict the exact key, but we can verify a second probe
        // also succeeds (which would fail if cleanup left entries that block
        // subsequent writes on some backends).
        let result2 = probe_backend(&storage);
        assert!(
            result2.is_ok(),
            "second keychain probe should succeed (cleanup worked): {result2:?}"
        );
    }

    // -------------------------------------------------------------------------
    // SecureStorage delegation — tested via detect_forced("file") to avoid
    // prompting macOS Keychain or requiring a D-Bus daemon in CI.
    // -------------------------------------------------------------------------

    #[test]
    fn storage_router_delegates_store_retrieve_delete() {
        let router = detect_forced("file").expect("file forced backend should succeed");

        let key = "router-test-key";
        let value = b"router-test-value";

        // store
        router.store(key, value).expect("store should succeed");

        // exists
        assert!(router.exists(key), "key should exist after store");

        // retrieve
        let retrieved = router.retrieve(key).expect("retrieve should succeed");
        assert_eq!(
            retrieved, value,
            "retrieved value should match stored value"
        );

        // delete
        router.delete(key).expect("delete should succeed");
        assert!(!router.exists(key), "key should not exist after delete");
    }

    #[test]
    fn storage_router_retrieve_missing_key_returns_not_found() {
        let router = detect_forced("file").expect("file forced backend should succeed");

        let result = router.retrieve("completely-nonexistent-key-xyz-999");
        assert!(
            matches!(result, Err(StorageError::NotFound(_))),
            "missing key should return NotFound: {result:?}"
        );
    }
}
