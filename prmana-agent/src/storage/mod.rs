//! Secure storage for credentials
//!
//! This module provides secure storage backends for:
//! - DPoP private keys
//! - Access and refresh tokens
//! - Token metadata

pub mod file_store;
pub mod keyring_store;
pub mod migration;
pub mod router;
pub mod secure_delete;

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
    /// Error during credential migration between backends.
    /// Carries a human-readable description of which migration step failed.
    #[error("Migration error: {0}")]
    Migration(String),
}

pub use file_store::FileStorage;
pub use keyring_store::KeyringStorage;
pub use router::{BackendKind, MigrationStatus, StorageRouter};

/// Storage keys for credentials
pub const KEY_DPOP_PRIVATE: &str = "prmana-dpop-key";
pub const KEY_ACCESS_TOKEN: &str = "prmana-access-token";
pub const KEY_REFRESH_TOKEN: &str = "prmana-refresh-token";
pub const KEY_TOKEN_METADATA: &str = "prmana-token-metadata";
/// ML-DSA-65 seed for PQC hybrid signer (32 bytes).
/// Only used when `enable_pqc: true` and `--features pqc`.
#[cfg(feature = "pqc")]
pub const KEY_PQ_SEED: &str = "prmana-pq-seed";
