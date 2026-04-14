//! One-time migration of keyring credential key names from `unix-oidc-*` to `prmana-*`.
//!
//! Invoked at agent startup (via `StorageRouter::detect()`) to preserve access and refresh
//! tokens across the prmana rename.
//!
//! # Security contract
//! - Only key NAMES are logged, never credential VALUES.
//! - If write-to-new-name fails, the legacy key is NOT deleted (no lossy partial migration).
//! - Idempotent: safe to run on every startup; no-op when no legacy keys exist.
//!
//! # References
//! - CLAUDE.md storage invariant #11
//! - T-DTA01-01: information disclosure — log key names only
//! - T-DTA01-02: tampering — write-before-delete atomicity
//! - T-DTA01-03: denial of service — migration failure is non-fatal

use super::{SecureStorage, StorageError};

/// Legacy key names used before the prmana rename.
/// These are the only `unix-oidc-*` strings permitted in production code.
pub(crate) const LEGACY_KEY_DPOP_PRIVATE: &str = "unix-oidc-dpop-key";
pub(crate) const LEGACY_KEY_ACCESS_TOKEN: &str = "unix-oidc-access-token";
pub(crate) const LEGACY_KEY_REFRESH_TOKEN: &str = "unix-oidc-refresh-token";
pub(crate) const LEGACY_KEY_TOKEN_METADATA: &str = "unix-oidc-token-metadata";
#[cfg(feature = "pqc")]
pub(crate) const LEGACY_KEY_PQ_SEED: &str = "unix-oidc-pq-seed";

use super::{KEY_ACCESS_TOKEN, KEY_DPOP_PRIVATE, KEY_REFRESH_TOKEN, KEY_TOKEN_METADATA};

/// The set of (legacy, current) key pairs to migrate.
/// Order is deterministic for reproducible logging.
#[cfg(not(feature = "pqc"))]
fn migration_pairs() -> Vec<(&'static str, &'static str)> {
    vec![
        (LEGACY_KEY_DPOP_PRIVATE, KEY_DPOP_PRIVATE),
        (LEGACY_KEY_ACCESS_TOKEN, KEY_ACCESS_TOKEN),
        (LEGACY_KEY_REFRESH_TOKEN, KEY_REFRESH_TOKEN),
        (LEGACY_KEY_TOKEN_METADATA, KEY_TOKEN_METADATA),
    ]
}

/// The set of (legacy, current) key pairs to migrate, including the PQC seed
/// when the `pqc` feature is enabled.
#[cfg(feature = "pqc")]
fn migration_pairs() -> Vec<(&'static str, &'static str)> {
    use super::KEY_PQ_SEED;
    vec![
        (LEGACY_KEY_DPOP_PRIVATE, KEY_DPOP_PRIVATE),
        (LEGACY_KEY_ACCESS_TOKEN, KEY_ACCESS_TOKEN),
        (LEGACY_KEY_REFRESH_TOKEN, KEY_REFRESH_TOKEN),
        (LEGACY_KEY_TOKEN_METADATA, KEY_TOKEN_METADATA),
        (LEGACY_KEY_PQ_SEED, KEY_PQ_SEED),
    ]
}

/// Report from a migration run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// Number of keys successfully renamed.
    pub migrated: usize,
    /// Number of keys skipped because the new-name key already existed.
    pub skipped: usize,
}

/// Migrate legacy `unix-oidc-*` keyring entries to `prmana-*` names.
///
/// For each legacy key:
/// 1. If neither legacy nor current key exists → skip.
/// 2. If only current key exists → nothing to do (skip).
/// 3. If current key already exists and legacy also exists → delete legacy, count as skipped.
/// 4. If only legacy key exists → write to current name, then delete legacy, count as migrated.
///
/// # Errors
/// Returns `Err` only if a `store` (write) call fails. In that case the legacy key is
/// preserved unmodified — no partial credential loss.
pub fn migrate_legacy_key_names(
    store: &dyn SecureStorage,
) -> Result<MigrationReport, StorageError> {
    let mut report = MigrationReport::default();

    for (legacy, current) in migration_pairs() {
        // Check whether the legacy key exists.
        if !store.exists(legacy) {
            // No legacy key — nothing to do for this slot.
            continue;
        }

        // Legacy key exists. Read it.
        let legacy_value = store.retrieve(legacy).map_err(|e| {
            StorageError::Migration(format!("failed to read legacy key '{}': {e}", legacy))
        })?;

        // If new-name key already exists, prefer it; delete legacy only.
        if store.exists(current) {
            tracing::info!(
                legacy_key = %legacy,
                current_key = %current,
                "keyring migration: current key already present, deleting legacy key only"
            );
            if let Err(e) = store.delete(legacy) {
                tracing::warn!(
                    error = %e,
                    legacy_key = %legacy,
                    "keyring migration: failed to delete superseded legacy key — non-fatal"
                );
            }
            report.skipped += 1;
            continue;
        }

        // Write new-name key BEFORE deleting legacy — atomic: no partial loss on write failure.
        // Security: legacy_value is a raw byte slice; tracing never serialises it.
        store.store(current, &legacy_value).map_err(|e| {
            StorageError::Migration(format!("failed to write current key '{}': {e}", current))
        })?;

        // Only after successful write, delete legacy.
        if let Err(e) = store.delete(legacy) {
            tracing::warn!(
                error = %e,
                legacy_key = %legacy,
                current_key = %current,
                "keyring migration: new-name key written, but legacy delete failed — non-fatal"
            );
        }

        tracing::info!(
            legacy_key = %legacy,
            current_key = %current,
            "keyring migration: key renamed"
        );
        report.migrated += 1;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SecureStorage;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // -------------------------------------------------------------------------
    // In-memory mock storage — no real keyring access, purely for migration logic.
    // Security: mock only stores test bytes; never touches a real credential store.
    // -------------------------------------------------------------------------
    struct MockStore(Mutex<HashMap<String, Vec<u8>>>);

    impl MockStore {
        fn new() -> Self {
            Self(Mutex::new(HashMap::new()))
        }

        fn with(keys: &[(&str, &[u8])]) -> Self {
            let s = Self::new();
            let mut g = s.0.lock().unwrap();
            for (k, v) in keys {
                g.insert((*k).to_string(), v.to_vec());
            }
            drop(g);
            s
        }

        /// Read back value by key for assertions.
        fn get(&self, key: &str) -> Option<Vec<u8>> {
            self.0.lock().unwrap().get(key).cloned()
        }
    }

    impl SecureStorage for MockStore {
        fn store(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
            self.0
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_vec());
            Ok(())
        }

        fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
            self.0
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))
        }

        fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }

        fn exists(&self, key: &str) -> bool {
            self.0.lock().unwrap().contains_key(key)
        }
    }

    // -------------------------------------------------------------------------
    // Failing-write mock — write always errors. Used for atomicity test.
    // -------------------------------------------------------------------------
    struct FailingWriteStore {
        inner: MockStore,
    }

    impl FailingWriteStore {
        fn with(keys: &[(&str, &[u8])]) -> Self {
            Self {
                inner: MockStore::with(keys),
            }
        }
        fn get(&self, key: &str) -> Option<Vec<u8>> {
            self.inner.get(key)
        }
    }

    impl SecureStorage for FailingWriteStore {
        fn store(&self, _key: &str, _value: &[u8]) -> Result<(), StorageError> {
            Err(StorageError::Backend("injected write failure".to_string()))
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

    // -------------------------------------------------------------------------
    // Test 1: all 4 base legacy keys present → migrated: 4, skipped: 0
    // -------------------------------------------------------------------------
    #[test]
    fn migrates_all_base_legacy_keys() {
        let store = MockStore::with(&[
            (LEGACY_KEY_DPOP_PRIVATE, b"dpop-bytes"),
            (LEGACY_KEY_ACCESS_TOKEN, b"access-token"),
            (LEGACY_KEY_REFRESH_TOKEN, b"refresh-token"),
            (LEGACY_KEY_TOKEN_METADATA, b"metadata"),
        ]);

        let report = migrate_legacy_key_names(&store).unwrap();

        assert_eq!(report.migrated, 4);
        assert_eq!(report.skipped, 0);

        // New-name keys must now exist with the same bytes.
        assert_eq!(store.get(KEY_DPOP_PRIVATE).unwrap(), b"dpop-bytes".to_vec());
        assert_eq!(
            store.get(KEY_ACCESS_TOKEN).unwrap(),
            b"access-token".to_vec()
        );
        assert_eq!(
            store.get(KEY_REFRESH_TOKEN).unwrap(),
            b"refresh-token".to_vec()
        );
        assert_eq!(store.get(KEY_TOKEN_METADATA).unwrap(), b"metadata".to_vec());

        // Legacy keys must be gone.
        assert!(store.get(LEGACY_KEY_DPOP_PRIVATE).is_none());
        assert!(store.get(LEGACY_KEY_ACCESS_TOKEN).is_none());
        assert!(store.get(LEGACY_KEY_REFRESH_TOKEN).is_none());
        assert!(store.get(LEGACY_KEY_TOKEN_METADATA).is_none());
    }

    // -------------------------------------------------------------------------
    // Test 2: no legacy keys present → no-op (migrated: 0, skipped: 0)
    // -------------------------------------------------------------------------
    #[test]
    fn no_op_when_no_legacy_keys() {
        let store = MockStore::new();
        let report = migrate_legacy_key_names(&store).unwrap();
        assert_eq!(
            report,
            MigrationReport {
                migrated: 0,
                skipped: 0
            }
        );
    }

    // -------------------------------------------------------------------------
    // Test 3: new-name key already exists + legacy also exists → legacy deleted,
    //         new key UNCHANGED, count as skipped: 1
    // -------------------------------------------------------------------------
    #[test]
    fn new_name_wins_when_both_present() {
        let store = MockStore::with(&[
            (LEGACY_KEY_ACCESS_TOKEN, b"OLD"),
            (KEY_ACCESS_TOKEN, b"NEW"),
        ]);

        let report = migrate_legacy_key_names(&store).unwrap();

        assert_eq!(report.migrated, 0, "should not count as migrated");
        assert_eq!(report.skipped, 1, "should count as skipped");

        // New-name key must retain the NEW value (not overwritten).
        assert_eq!(store.get(KEY_ACCESS_TOKEN).unwrap(), b"NEW".to_vec());
        // Legacy key must be gone.
        assert!(store.get(LEGACY_KEY_ACCESS_TOKEN).is_none());
    }

    // -------------------------------------------------------------------------
    // Test 4: write fails → Err returned, legacy key preserved (no data loss)
    // -------------------------------------------------------------------------
    #[test]
    fn write_failure_preserves_legacy_key() {
        let store = FailingWriteStore::with(&[(LEGACY_KEY_ACCESS_TOKEN, b"precious-token")]);

        let result = migrate_legacy_key_names(&store);
        assert!(result.is_err(), "must return Err when write fails");

        // Legacy key must still be present — no partial loss.
        assert_eq!(
            store.get(LEGACY_KEY_ACCESS_TOKEN).unwrap(),
            b"precious-token".to_vec()
        );
    }

    // -------------------------------------------------------------------------
    // Test 5: idempotency — running twice leaves state unchanged after first run
    // -------------------------------------------------------------------------
    #[test]
    fn idempotent_across_runs() {
        let store = MockStore::with(&[(LEGACY_KEY_ACCESS_TOKEN, b"v")]);

        let r1 = migrate_legacy_key_names(&store).unwrap();
        let r2 = migrate_legacy_key_names(&store).unwrap();

        assert_eq!(
            r1,
            MigrationReport {
                migrated: 1,
                skipped: 0
            }
        );
        // Second run: no legacy keys exist, no new-name conflicts → pure no-op.
        assert_eq!(
            r2,
            MigrationReport {
                migrated: 0,
                skipped: 0
            }
        );

        // State: only new-name key, with original value.
        assert_eq!(store.get(KEY_ACCESS_TOKEN).unwrap(), b"v".to_vec());
        assert!(store.get(LEGACY_KEY_ACCESS_TOKEN).is_none());
    }

    // -------------------------------------------------------------------------
    // Test 6 (security): no credential value appears in captured log output.
    //
    // tracing_test captures span/event output. The migration must log only key
    // NAMES (e.g. "prmana-access-token"), never the raw bytes of the credential.
    //
    // We assert that the sentinel byte sequence `SECRETVALUE` does not appear
    // in the captured output even though we inserted it as a credential value.
    // -------------------------------------------------------------------------
    #[test]
    #[tracing_test::traced_test]
    fn no_credential_value_in_logs() {
        let sentinel = b"SECRETVALUE_DO_NOT_LOG";

        let store = MockStore::with(&[(LEGACY_KEY_ACCESS_TOKEN, sentinel)]);
        let _ = migrate_legacy_key_names(&store);

        // tracing_test exposes `logs_contain` via the `traced_test` attribute.
        // We assert the sentinel byte slice string does NOT appear.
        assert!(
            !logs_contain("SECRETVALUE_DO_NOT_LOG"),
            "credential value must not appear in log output"
        );
    }
}
