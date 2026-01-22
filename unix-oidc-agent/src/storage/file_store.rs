//! File-based storage for headless environments

use directories::ProjectDirs;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::storage::{SecureStorage, StorageError};

/// File-based storage for headless environments
///
/// WARNING: This stores secrets in files with mode 0600.
/// Prefer KeyringStorage when available.
pub struct FileStorage {
    base_dir: PathBuf,
}

impl FileStorage {
    pub fn new() -> Result<Self, StorageError> {
        let dirs = ProjectDirs::from("com", "unix-oidc", "agent").ok_or_else(|| {
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

        let mut file = File::create(&path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&path, perms)?;
        }

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

        // Overwrite with zeros before deleting (basic secure delete)
        if let Ok(metadata) = fs::metadata(&path) {
            let size = metadata.len() as usize;
            if let Ok(mut file) = File::create(&path) {
                let _ = file.write_all(&vec![0u8; size]);
                let _ = file.sync_all();
            }
        }

        fs::remove_file(&path)?;

        Ok(())
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
}
