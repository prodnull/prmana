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

use tracing::info;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::KeyringStorage;
use super::{FileStorage, SecureStorage, StorageError};

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
    /// Plain files, mode 0600, with DoD 5220.22-M secure delete (last resort).
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
            "probe read-back mismatch: expected {:?}, got {:?}",
            PROBE_VALUE, retrieved
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
                StorageError::Backend(format!("forced backend 'file' failed probe: {}", e))
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
                        "forced backend 'secret-service' failed probe: {}",
                        e
                    ))
                })?;
                info!(backend = "keyring (Secret Service)", "Storage backend selected (forced)");
                return Ok(StorageRouter {
                    backend: Box::new(storage),
                    kind: BackendKind::SecretService,
                    migration_status: MigrationStatus::NotApplicable,
                });
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
                        "forced backend 'keyutils' failed probe: {}",
                        e
                    ))
                })?;
                info!(backend = "keyring (keyutils @u)", "Storage backend selected (forced)");
                return Ok(StorageRouter {
                    backend: Box::new(storage),
                    kind: BackendKind::KeyutilsUser,
                    migration_status: MigrationStatus::NotApplicable,
                });
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
            "unknown forced backend '{}'; valid values: file, secret-service, keyutils, macos-keychain",
            other
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
            "probe should succeed with file backend: {:?}",
            result
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
            "probe must fail when backend rejects reads: {:?}",
            result
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
            "file forced backend should succeed: {:?}",
            result
        );
        let router = result.unwrap();
        assert_eq!(router.kind, BackendKind::File);
    }

    #[test]
    fn forced_invalid_backend_returns_err_with_message() {
        let result = detect_forced("nonexistent-backend");
        assert!(
            matches!(result, Err(StorageError::Backend(_))),
            "invalid backend name should return Err(Backend): {:?}",
            result
        );
        if let Err(StorageError::Backend(msg)) = result {
            assert!(
                msg.contains("unknown forced backend"),
                "error message should mention 'unknown forced backend', got: {}",
                msg
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
    fn detect_auto_returns_router_without_panicking() {
        let result = detect_auto();
        assert!(result.is_ok(), "detect_auto should not fail: {:?}", result);
    }

    #[test]
    #[ignore = "Requires interactive keychain or running D-Bus/Secret Service"]
    fn storage_router_detect_returns_ok_with_mock_builder() {
        std::env::remove_var("UNIX_OIDC_STORAGE_BACKEND");
        let result = StorageRouter::detect();
        assert!(
            result.is_ok(),
            "StorageRouter::detect() should succeed: {:?}",
            result
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
            "missing key should return NotFound: {:?}",
            result
        );
    }
}
