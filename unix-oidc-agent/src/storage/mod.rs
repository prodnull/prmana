//! Secure storage for credentials
//!
//! This module provides secure storage backends for:
//! - DPoP private keys
//! - Access and refresh tokens
//! - Token metadata

pub mod file_store;
pub mod keyring_store;

use thiserror::Error;

/// Trait for secure credential storage
pub trait SecureStorage: Send + Sync {
    /// Store a secret
    fn store(&self, key: &str, value: &[u8]) -> Result<(), StorageError>;

    /// Retrieve a secret
    fn retrieve(&self, key: &str) -> Result<Vec<u8>, StorageError>;

    /// Delete a secret
    fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// Check if a key exists
    fn exists(&self, key: &str) -> bool;
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Access denied")]
    AccessDenied,
    #[error("Storage backend error: {0}")]
    Backend(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub use file_store::FileStorage;
pub use keyring_store::KeyringStorage;

/// Storage keys for credentials
pub const KEY_DPOP_PRIVATE: &str = "unix-oidc-dpop-key";
pub const KEY_ACCESS_TOKEN: &str = "unix-oidc-access-token";
pub const KEY_REFRESH_TOKEN: &str = "unix-oidc-refresh-token";
pub const KEY_TOKEN_METADATA: &str = "unix-oidc-token-metadata";
