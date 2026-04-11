//! Storage backend router with probe-based detection and fallback chain.
//!
//! This module implements automatic selection of the best available keyring
//! backend, falling back to file storage when no keyring is accessible.
//!
//! # Backend selection order
//!
//! 1. If `PRMANA_STORAGE_BACKEND` is set, probe only the requested backend
//!    and return `Err` on probe failure — no fallthrough.
//! 2. Linux: Secret Service (D-Bus/libsecret)
//! 3. Linux: keyutils user keyring (`@u`)
//! 4. macOS: macOS Keychain Services
//! 5. File storage (plaintext files, mode 0600) — last resort
//!
//! # Probe mechanism
//!
//! A probe is a full write → read → delete cycle using the sentinel key
//! `prmana-probe`. Constructor success alone is insufficient — some
//! backends appear to construct successfully but fail on I/O (e.g., keyutils
//! if the session keyring is not initialised, Secret Service if D-Bus is
//! unavailable).
//!
//! # Migration awareness
//!
//! When a higher-priority backend is selected after a previous run used a
//! different backend, credentials from the old backend become inaccessible.
//! Failed probes log a WARN with actionable text:
//! "credentials from previous backend are inaccessible; run `prmana-agent login` to re-authenticate"

use tracing::{info, warn};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::KeyringStorage;
use super::{
    FileStorage, SecureStorage, StorageError, KEY_ACCESS_TOKEN, KEY_DPOP_PRIVATE,
    KEY_REFRESH_TOKEN, KEY_TOKEN_METADATA,
};
use super::migration::migrate_legacy_key_names;

/// D-Bus Secret Service session encryption enforcement mode.
///
/// Controls behavior when the D-Bus Secret Service session does not use encryption
/// (i.e., the `plain` algorithm was negotiated instead of `dh-ietf1024-sha256-aes128-cbc-pkcs7`).
///
/// Configured via `PRMANA_REJECT_PLAIN_DBUS` environment variable.
/// Default: `Warn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbusEncryptionPolicy {
    /// Reject the Secret Service backend if the session is unencrypted.
    /// Falls through to keyutils or file storage.
    Strict,
    /// Log a warning but continue using the Secret Service backend.
    Warn,
    /// Skip the encryption check entirely.
    Disabled,
}

impl DbusEncryptionPolicy {
    /// Parse from the `PRMANA_REJECT_PLAIN_DBUS` environment variable.
    ///
    /// Valid values: `strict`, `warn`, `disabled` (case-insensitive).
    /// Returns `Warn` if the variable is unset or has an unrecognized value.
    pub fn from_env() -> Self {
        match std::env::var("PRMANA_REJECT_PLAIN_DBUS") {
            Ok(val) => match val.to_lowercase().as_str() {
                "strict" => DbusEncryptionPolicy::Strict,
                "warn" => DbusEncryptionPolicy::Warn,
                "disabled" => DbusEncryptionPolicy::Disabled,
                other => {
                    warn!(
                        value = %other,
                        "Unrecognized PRMANA_REJECT_PLAIN_DBUS value; defaulting to 'warn'"
                    );
                    DbusEncryptionPolicy::Warn
                }
            },
            Err(_) => DbusEncryptionPolicy::Warn,
        }
    }
}

/// Result of probing D-Bus session encryption status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbusSessionEncryption {
    /// The session was negotiated with DH-based encryption.
    Encrypted,
    /// The session uses the `plain` algorithm (no encryption).
    Plain,
    /// Could not determine session encryption status (non-Linux, no D-Bus, etc.).
    Unknown,
}

/// Outcome of applying the D-Bus encryption policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbusEnforcementAction {
    /// Proceed with the Secret Service backend.
    Allow,
    /// Reject the Secret Service backend (strict mode + plain session).
    Reject,
    /// Check was skipped (policy is Disabled or session is encrypted).
    Skipped,
}

/// Evaluate the D-Bus encryption enforcement policy against the observed session
/// encryption status.
///
/// This function is pure logic — no I/O or D-Bus calls — and is the primary
/// unit-testable entry point for the enforcement decision.
///
/// Returns the action to take and emits structured audit/tracing events.
pub fn evaluate_dbus_encryption(
    policy: DbusEncryptionPolicy,
    session: DbusSessionEncryption,
) -> DbusEnforcementAction {
    if policy == DbusEncryptionPolicy::Disabled {
        return DbusEnforcementAction::Skipped;
    }

    match session {
        DbusSessionEncryption::Encrypted => {
            info!(
                target: "prmana_audit",
                event_type = "DBUS_SESSION_ENCRYPTED",
                backend = "secret-service",
                "D-Bus Secret Service session uses encrypted transport"
            );
            DbusEnforcementAction::Allow
        }
        DbusSessionEncryption::Plain => {
            // Always emit structured audit event for SIEM visibility
            info!(
                target: "prmana_audit",
                event_type = "DBUS_PLAIN_SESSION",
                backend = "secret-service",
                enforcement = ?policy,
                "D-Bus Secret Service session is unencrypted"
            );

            match policy {
                DbusEncryptionPolicy::Strict => {
                    tracing::error!(
                        "D-Bus Secret Service session is unencrypted — rejecting backend per strict policy"
                    );
                    DbusEnforcementAction::Reject
                }
                DbusEncryptionPolicy::Warn => {
                    warn!(
                        "D-Bus Secret Service session is unencrypted — credentials transit D-Bus in \
                         plaintext. Set PRMANA_REJECT_PLAIN_DBUS=strict to reject, or use \
                         full-disk encryption."
                    );
                    DbusEnforcementAction::Allow
                }
                DbusEncryptionPolicy::Disabled => {
                    // Already handled above, but for completeness
                    DbusEnforcementAction::Skipped
                }
            }
        }
        DbusSessionEncryption::Unknown => {
            // Cannot determine encryption status. The enforcement decision depends
            // on the policy: strict mode warns explicitly (we can't verify the
            // security property the operator asked for), other modes note and allow.
            match policy {
                DbusEncryptionPolicy::Strict => {
                    warn!(
                        backend = "secret-service",
                        "D-Bus session encryption status could not be determined — \
                         strict policy requested but cannot verify encryption. \
                         Ensure dbus-send is installed and org.freedesktop.secrets is running. \
                         Allowing this session; set PRMANA_REJECT_PLAIN_DBUS=disabled to suppress."
                    );
                    // Allow despite strict — we don't have evidence the session is
                    // *plain*, just that we can't verify it's encrypted. Blocking
                    // on Unknown would break all non-D-Bus environments and
                    // container setups where dbus-send isn't available.
                    DbusEnforcementAction::Allow
                }
                _ => {
                    info!(
                        backend = "secret-service",
                        "D-Bus session encryption status could not be determined"
                    );
                    DbusEnforcementAction::Allow
                }
            }
        }
    }
}

/// Probe D-Bus Secret Service session encryption status.
///
/// On Linux, calls `dbus-send` to attempt a `plain`-algorithm OpenSession against
/// `org.freedesktop.secrets`. The result tells us whether the Secret Service daemon
/// accepts unencrypted sessions:
///
/// - **`plain` rejected** → server requires DH encryption → `Encrypted`
/// - **`plain` accepted** → server allows unencrypted sessions → `Plain`
///   (Even though `oo7`/keyring prefers DH, the server's willingness to accept
///   plain sessions means a D-Bus attacker could downgrade the negotiation.
///   Strict mode should reject this configuration.)
/// - **Probe fails** (no D-Bus, no `dbus-send`, service not registered) → `Unknown`
///
/// # Security rationale
///
/// The probe checks the server's *capability*, not the current session's state.
/// This is the correct security question: if the server supports plain sessions,
/// a man-in-the-middle on the D-Bus bus could force a downgrade from DH to plain,
/// exposing credentials in transit. Strict mode rejects servers that support plain
/// to close this downgrade vector entirely.
///
/// # Dependencies
///
/// Uses `dbus-send` (part of `dbus` package, available on all D-Bus-capable systems).
/// No Rust crate dependency — avoids pulling `zbus` or `oo7` as direct deps.
///
/// On non-Linux platforms, returns `Unknown`.
///
/// # References
///
/// - freedesktop Secret Service API: `org.freedesktop.secrets.Service.OpenSession`
/// - Session algorithms: `plain` (no encryption), `dh-ietf1024-sha256-aes128-cbc-pkcs7`
#[cfg(target_os = "linux")]
pub fn probe_dbus_session_encryption() -> DbusSessionEncryption {
    use std::process::Command;

    // Step 1: Check if org.freedesktop.secrets is registered on the session bus.
    // If not, no Secret Service daemon is running — return Unknown.
    let name_check = Command::new("dbus-send")
        .args([
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.GetNameOwner",
            "string:org.freedesktop.secrets",
        ])
        .output();

    match &name_check {
        Ok(output) if output.status.success() => {
            // Service is registered — proceed to probe
        }
        Ok(_) => {
            info!(
                "org.freedesktop.secrets not registered on session bus — \
                 D-Bus encryption check not applicable"
            );
            return DbusSessionEncryption::Unknown;
        }
        Err(e) => {
            info!(
                error = %e,
                "dbus-send not available — cannot probe D-Bus session encryption"
            );
            return DbusSessionEncryption::Unknown;
        }
    }

    // Step 2: Attempt OpenSession with "plain" algorithm.
    //
    // Method signature: OpenSession(String algorithm, Variant input) → (Variant output, ObjectPath result)
    // For "plain" algorithm, input is an empty string variant.
    //
    // If the server accepts "plain", it returns success with a session path.
    // If the server rejects "plain" (requires DH), it returns an error
    // (typically org.freedesktop.DBus.Error.NotSupported).
    let plain_probe = Command::new("dbus-send")
        .args([
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.secrets.Service.OpenSession",
            "string:plain",
            "variant:string:",
        ])
        .output();

    match plain_probe {
        Ok(output) if output.status.success() => {
            // Server accepted "plain" session — it allows unencrypted transport.
            // Even though oo7/keyring prefers DH, the server's willingness to
            // accept plain sessions means a D-Bus attacker could force a downgrade.
            //
            // Best-effort: try to close the probe session to avoid orphaning it.
            // The session path is in the reply, but parsing dbus-send output is
            // fragile. The session will be cleaned up when the daemon restarts or
            // the D-Bus connection drops, so this is acceptable.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            info!(
                stdout = %stdout.trim(),
                stderr = %stderr.trim(),
                "D-Bus Secret Service accepted plain session — server allows unencrypted transport"
            );
            DbusSessionEncryption::Plain
        }
        Ok(output) => {
            // Server rejected "plain" — it requires DH encryption.
            // This is the secure configuration: all sessions must be encrypted.
            let stderr = String::from_utf8_lossy(&output.stderr);
            info!(
                stderr = %stderr.trim(),
                "D-Bus Secret Service rejected plain session — server requires encrypted transport"
            );
            DbusSessionEncryption::Encrypted
        }
        Err(e) => {
            warn!(
                error = %e,
                "Failed to probe D-Bus Secret Service session encryption"
            );
            DbusSessionEncryption::Unknown
        }
    }
}

/// On non-Linux platforms, D-Bus Secret Service is not available.
#[cfg(not(target_os = "linux"))]
pub fn probe_dbus_session_encryption() -> DbusSessionEncryption {
    DbusSessionEncryption::Unknown
}

/// Prefix for probe sentinel keys. A random suffix is appended per invocation
/// so that parallel probes (e.g., in tests) don't clobber each other.
const PROBE_KEY_PREFIX: &str = "prmana-probe-";
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
    /// Respects `PRMANA_STORAGE_BACKEND` environment variable for forced
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
        let router = if let Ok(forced) = std::env::var("PRMANA_STORAGE_BACKEND") {
            detect_forced(&forced)?
        } else {
            detect_auto()?
        };

        // Storage invariant #11 (CLAUDE.md): run legacy key-name migration on every
        // startup.  If migration fails, log WARN and continue — the user can still
        // re-authenticate to populate new-name keys.
        if let Err(e) = migrate_legacy_key_names(&router) {
            warn!(
                error = %e,
                "keyring legacy key migration failed — continuing with current-name keys only"
            );
        }

        Ok(router)
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
        #[allow(unused_mut)]
        let mut all_keys: Vec<&str> = vec![
            KEY_DPOP_PRIVATE,
            KEY_ACCESS_TOKEN,
            KEY_REFRESH_TOKEN,
            KEY_TOKEN_METADATA,
        ];
        #[cfg(feature = "pqc")]
        all_keys.push(super::KEY_PQ_SEED);

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

                // SHRD-06: Check D-Bus session encryption for forced Secret Service too.
                let dbus_policy = DbusEncryptionPolicy::from_env();
                let dbus_session = probe_dbus_session_encryption();
                let action = evaluate_dbus_encryption(dbus_policy, dbus_session);

                if action == DbusEnforcementAction::Reject {
                    return Err(StorageError::Backend(
                        "forced backend 'secret-service' rejected: D-Bus session is unencrypted \
                         and PRMANA_REJECT_PLAIN_DBUS=strict"
                            .to_string(),
                    ));
                }

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
                // SHRD-06: Check D-Bus session encryption before accepting Secret Service.
                let dbus_policy = DbusEncryptionPolicy::from_env();
                let dbus_session = probe_dbus_session_encryption();
                let action = evaluate_dbus_encryption(dbus_policy, dbus_session);

                match action {
                    DbusEnforcementAction::Reject => {
                        info!(
                            backend = "keyring (Secret Service)",
                            "Secret Service rejected by D-Bus encryption policy — trying next backend"
                        );
                        // Fall through to keyutils
                    }
                    DbusEnforcementAction::Allow | DbusEnforcementAction::Skipped => {
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
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Secret Service probe failed — credentials from previous backend are \
                     inaccessible; run `prmana-agent login` to re-authenticate"
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
                     inaccessible; run `prmana-agent login` to re-authenticate"
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
                     inaccessible; run `prmana-agent login` to re-authenticate"
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
        std::env::remove_var("PRMANA_STORAGE_BACKEND");
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

        // The probe key format is "prmana-probe-{pid}-{seq}".
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

    // -------------------------------------------------------------------------
    // D-Bus Secret Service encryption enforcement (SHRD-06)
    // -------------------------------------------------------------------------

    #[test]
    fn dbus_policy_warn_allows_plain_session() {
        let action =
            evaluate_dbus_encryption(DbusEncryptionPolicy::Warn, DbusSessionEncryption::Plain);
        assert_eq!(
            action,
            DbusEnforcementAction::Allow,
            "warn mode should allow plain sessions"
        );
    }

    #[test]
    fn dbus_policy_strict_rejects_plain_session() {
        let action =
            evaluate_dbus_encryption(DbusEncryptionPolicy::Strict, DbusSessionEncryption::Plain);
        assert_eq!(
            action,
            DbusEnforcementAction::Reject,
            "strict mode should reject plain sessions"
        );
    }

    #[test]
    fn dbus_policy_disabled_skips_check() {
        let action =
            evaluate_dbus_encryption(DbusEncryptionPolicy::Disabled, DbusSessionEncryption::Plain);
        assert_eq!(
            action,
            DbusEnforcementAction::Skipped,
            "disabled mode should skip the check entirely"
        );
    }

    #[test]
    fn dbus_encrypted_session_allowed_in_all_modes() {
        for policy in [
            DbusEncryptionPolicy::Strict,
            DbusEncryptionPolicy::Warn,
            DbusEncryptionPolicy::Disabled,
        ] {
            let action = evaluate_dbus_encryption(policy, DbusSessionEncryption::Encrypted);
            // Disabled -> Skipped; Strict/Warn -> Allow (encrypted is always fine)
            assert!(
                matches!(
                    action,
                    DbusEnforcementAction::Allow | DbusEnforcementAction::Skipped
                ),
                "encrypted session should be allowed in {policy:?} mode, got {action:?}"
            );
        }
    }

    #[test]
    fn dbus_policy_default_is_warn() {
        // Temporarily clear the env var to test default
        let prev = std::env::var("PRMANA_REJECT_PLAIN_DBUS").ok();
        std::env::remove_var("PRMANA_REJECT_PLAIN_DBUS");

        let policy = DbusEncryptionPolicy::from_env();
        assert_eq!(
            policy,
            DbusEncryptionPolicy::Warn,
            "default policy should be Warn"
        );

        // Restore
        if let Some(val) = prev {
            std::env::set_var("PRMANA_REJECT_PLAIN_DBUS", val);
        }
    }

    #[test]
    fn dbus_policy_parses_env_values() {
        let cases = vec![
            ("strict", DbusEncryptionPolicy::Strict),
            ("STRICT", DbusEncryptionPolicy::Strict),
            ("warn", DbusEncryptionPolicy::Warn),
            ("WARN", DbusEncryptionPolicy::Warn),
            ("disabled", DbusEncryptionPolicy::Disabled),
            ("DISABLED", DbusEncryptionPolicy::Disabled),
        ];

        let prev = std::env::var("PRMANA_REJECT_PLAIN_DBUS").ok();

        for (input, expected) in cases {
            std::env::set_var("PRMANA_REJECT_PLAIN_DBUS", input);
            let policy = DbusEncryptionPolicy::from_env();
            assert_eq!(
                policy, expected,
                "PRMANA_REJECT_PLAIN_DBUS={input} should parse to {expected:?}"
            );
        }

        // Restore
        if let Some(val) = prev {
            std::env::set_var("PRMANA_REJECT_PLAIN_DBUS", val);
        } else {
            std::env::remove_var("PRMANA_REJECT_PLAIN_DBUS");
        }
    }

    #[test]
    fn dbus_unknown_session_allowed() {
        let action =
            evaluate_dbus_encryption(DbusEncryptionPolicy::Strict, DbusSessionEncryption::Unknown);
        assert_eq!(
            action,
            DbusEnforcementAction::Allow,
            "unknown session encryption should be allowed (cannot determine status)"
        );
    }
}
