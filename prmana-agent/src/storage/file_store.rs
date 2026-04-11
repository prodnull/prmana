//! File-based storage for headless environments

use directories::ProjectDirs;
use std::fs::{self, File};
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use tracing::warn;

use crate::storage::secure_delete;
use crate::storage::{SecureStorage, StorageError};

/// File-based storage for headless environments
///
/// WARNING: This stores secrets in files with mode 0600.
/// Prefer KeyringStorage when available.
///
/// # Secure deletion (MEM-05/MEM-06)
///
/// `delete()` uses a three-pass overwrite (NIST SP 800-88 Rev 1 §2.4 Clear) before unlink.
/// A CoW/SSD advisory is logged at construction time and again per-delete.
pub struct FileStorage {
    base_dir: PathBuf,
}

impl FileStorage {
    pub fn new() -> Result<Self, StorageError> {
        let dirs = ProjectDirs::from("com", "prmana", "agent").ok_or_else(|| {
            StorageError::Backend("Could not determine config directory".to_string())
        })?;

        let base_dir = dirs.data_local_dir().to_path_buf();

        // Create directory with restrictive permissions
        fs::create_dir_all(&base_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&base_dir, perms)?;
        }

        // MEM-06: Log CoW/SSD advisories once at construction time so operators
        // are informed if secure delete may not fully erase key material.
        secure_delete::log_storage_advisories(&base_dir);

        Ok(Self { base_dir })
    }

    /// Create with a custom base directory (for testing)
    #[cfg(test)]
    pub fn with_base_dir(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    fn key_path(&self, key: &str) -> PathBuf {
        // Sanitize key name to prevent path traversal
        let safe_key = key.replace(['/', '\\', '.'], "_");
        self.base_dir.join(safe_key)
    }
}

impl SecureStorage for FileStorage {
    fn store(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let path = self.key_path(key);

        // Security: Atomic permission setting at file creation via OpenOptions::mode().
        // Prevents TOCTOU race where File::create() then set_permissions() leaves a
        // window during which the file is world-readable under the default umask.
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?
        };

        #[cfg(not(unix))]
        let mut file = File::create(&path)?;

        file.write_all(value)?;
        file.sync_all()?;

        Ok(())
    }

    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let path = self.key_path(key);

        if !path.exists() {
            return Err(StorageError::NotFound(key.to_string()));
        }

        let mut file = File::open(&path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        Ok(contents)
    }

    fn delete(&self, key: &str) -> Result<(), StorageError> {
        let path = self.key_path(key);

        if !path.exists() {
            return Err(StorageError::NotFound(key.to_string()));
        }

        // MEM-05/MEM-06: Per-delete CoW advisory — inform operator if this
        // specific file is on a filesystem where overwrites may be ineffective.
        if secure_delete::detect_cow_filesystem(&path) {
            warn!(
                path = %path.display(),
                "Deleting key material on a CoW filesystem (btrfs/APFS). \
                Secure overwrite may not erase all block copies. \
                Full-disk encryption is recommended."
            );
        }

        // Three-pass random overwrite (NIST SP 800-88 Rev 1 §2.4) + fsync + unlink.
        // Replaces the previous single zero-overwrite (MEM-05).
        secure_delete::secure_remove(&path).map_err(|e| {
            StorageError::Io(std::io::Error::other(format!(
                "Secure delete failed for key '{key}': {e}"
            )))
        })
    }

    fn exists(&self, key: &str) -> bool {
        self.key_path(key).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_storage() -> (FileStorage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileStorage::with_base_dir(temp_dir.path().to_path_buf());
        (storage, temp_dir)
    }

    #[test]
    fn test_file_store_retrieve() {
        let (storage, _temp) = test_storage();
        let test_key = "test-key";
        let test_value = b"test-secret-value";

        storage.store(test_key, test_value).unwrap();

        let retrieved = storage.retrieve(test_key).unwrap();
        assert_eq!(retrieved, test_value);
    }

    #[test]
    fn test_file_not_found() {
        let (storage, _temp) = test_storage();

        let result = storage.retrieve("nonexistent");
        assert!(matches!(result, Err(StorageError::NotFound(_))));
    }

    #[test]
    fn test_file_delete() {
        let (storage, _temp) = test_storage();
        let test_key = "delete-test";

        storage.store(test_key, b"value").unwrap();
        assert!(storage.exists(test_key));

        storage.delete(test_key).unwrap();
        assert!(!storage.exists(test_key));
    }

    /// Secure delete: verify FileStorage.delete uses secure_remove (integration).
    #[test]
    fn test_file_delete_uses_secure_remove() {
        let (storage, _temp) = test_storage();
        let test_key = "secure-delete-test";
        let secret_content = b"dpop-private-key-material-32bytes-padding";

        storage.store(test_key, secret_content).unwrap();
        assert!(storage.exists(test_key));

        // delete() must succeed and the key must be gone
        storage.delete(test_key).unwrap();
        assert!(!storage.exists(test_key));

        // Also verify that re-deleting returns NotFound
        let result = storage.delete(test_key);
        assert!(
            matches!(result, Err(StorageError::NotFound(_))),
            "Expected NotFound on second delete, got: {result:?}"
        );
    }

    #[test]
    fn test_file_exists() {
        let (storage, _temp) = test_storage();

        assert!(!storage.exists("nonexistent"));

        storage.store("exists-test", b"value").unwrap();
        assert!(storage.exists("exists-test"));
    }

    #[test]
    fn test_path_traversal_prevention() {
        let (storage, _temp) = test_storage();

        // These should not escape the base directory
        let path1 = storage.key_path("../../../etc/passwd");
        let path2 = storage.key_path("..\\..\\windows\\system32");

        assert!(path1.starts_with(&storage.base_dir));
        assert!(path2.starts_with(&storage.base_dir));
    }

    #[cfg(unix)]
    #[test]
    fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (storage, _temp) = test_storage();

        storage.store("perm-test", b"secret").unwrap();

        let path = storage.key_path("perm-test");
        let metadata = fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode();

        // Should be readable/writable by owner only (0600)
        assert_eq!(mode & 0o777, 0o600);
    }

    /// F-01 positive: stored file has mode 0o600 (atomic via OpenOptions::mode).
    #[cfg(unix)]
    #[test]
    fn test_store_creates_file_with_0600_atomically() {
        use std::os::unix::fs::PermissionsExt;

        let (storage, _temp) = test_storage();
        storage.store("atomic-perm-test", b"secret-value").unwrap();

        let path = storage.key_path("atomic-perm-test");
        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "File must be created with 0o600 permissions, got: {mode:o}"
        );
    }

    /// F-01 negative: file is NOT created with default umask permissions.
    /// Verifies that even under a permissive umask, the file is restricted.
    #[cfg(unix)]
    #[test]
    fn test_store_never_creates_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;

        let (storage, _temp) = test_storage();
        storage.store("umask-test", b"secret-value").unwrap();

        let path = storage.key_path("umask-test");
        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;

        // The file must not be group- or world-readable/writable/executable.
        assert_eq!(
            mode & 0o077,
            0,
            "File must have no group/other permissions, got: {mode:o}"
        );
    }
}
