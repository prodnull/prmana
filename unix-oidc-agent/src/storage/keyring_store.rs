//! OS keychain storage backend

use base64::{engine::general_purpose::STANDARD, Engine};
use keyring::Entry;

use crate::storage::{SecureStorage, StorageError};

const SERVICE_NAME: &str = "unix-oidc-agent";

/// Storage backend using OS keychain (Keychain on macOS, libsecret on Linux)
pub struct KeyringStorage {
    service: String,
}

impl KeyringStorage {
    pub fn new() -> Self {
        Self {
            service: SERVICE_NAME.to_string(),
        }
    }

    fn get_entry(&self, key: &str) -> Result<Entry, StorageError> {
        Entry::new(&self.service, key).map_err(|e| StorageError::Backend(e.to_string()))
    }
}

impl Default for KeyringStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureStorage for KeyringStorage {
    fn store(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let entry = self.get_entry(key)?;

        // keyring crate expects a string, so we base64 encode binary data
        let encoded = STANDARD.encode(value);

        entry.set_password(&encoded).map_err(|e| match e {
            keyring::Error::NoEntry => StorageError::NotFound(key.to_string()),
            keyring::Error::Ambiguous(_) => StorageError::Backend("Ambiguous entry".to_string()),
            _ => StorageError::Backend(e.to_string()),
        })
    }

    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let entry = self.get_entry(key)?;

        let encoded = entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => StorageError::NotFound(key.to_string()),
            _ => StorageError::Backend(e.to_string()),
        })?;

        STANDARD
            .decode(&encoded)
            .map_err(|e| StorageError::Backend(format!("Base64 decode error: {}", e)))
    }

    fn delete(&self, key: &str) -> Result<(), StorageError> {
        let entry = self.get_entry(key)?;

        entry.delete_password().map_err(|e| match e {
            keyring::Error::NoEntry => StorageError::NotFound(key.to_string()),
            _ => StorageError::Backend(e.to_string()),
        })
    }

    fn exists(&self, key: &str) -> bool {
        self.retrieve(key).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require keychain access and may prompt for permission
    // They're marked ignore by default for CI

    #[test]
    #[ignore = "Requires keychain access"]
    fn test_keyring_store_retrieve() {
        let storage = KeyringStorage::new();
        let test_key = "unix-oidc-test-key";
        let test_value = b"test-secret-value";

        // Clean up any existing key
        let _ = storage.delete(test_key);

        // Store
        storage.store(test_key, test_value).unwrap();

        // Retrieve
        let retrieved = storage.retrieve(test_key).unwrap();
        assert_eq!(retrieved, test_value);

        // Clean up
        storage.delete(test_key).unwrap();
    }

    #[test]
    #[ignore = "Requires keychain access"]
    fn test_keyring_not_found() {
        let storage = KeyringStorage::new();

        let result = storage.retrieve("nonexistent-key-12345");
        assert!(matches!(result, Err(StorageError::NotFound(_))));
    }
}
