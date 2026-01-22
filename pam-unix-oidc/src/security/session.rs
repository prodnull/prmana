//! Secure session ID generation.
//!
//! Session IDs are used for audit correlation and must be:
//! - Unique across all sessions
//! - Unpredictable (to prevent session prediction attacks)
//! - Suitable for logging and correlation
//!
//! ## Format
//!
//! Session IDs use the format: `{prefix}-{timestamp_hex}-{random_hex}`
//!
//! Example: `unix-oidc-18d4f2a3b4c-a7f3e2d1c0b9a8f7`
//!
//! - `prefix`: Identifies the session type (unix-oidc, sudo, etc.)
//! - `timestamp_hex`: Nanosecond timestamp for ordering and debugging
//! - `random_hex`: 64 bits of cryptographic randomness

use std::time::{SystemTime, UNIX_EPOCH};

/// Generate a cryptographically secure session ID.
///
/// The session ID combines:
/// - A prefix for identification
/// - Timestamp for ordering and debugging
/// - 64 bits of CSPRNG randomness for unpredictability
///
/// # Example
///
/// ```
/// use pam_unix_oidc::security::generate_secure_session_id;
///
/// let session_id = generate_secure_session_id("unix-oidc");
/// assert!(session_id.starts_with("unix-oidc-"));
/// // Example: unix-oidc-18d4f2a3b4c-a7f3e2d1c0b9a8f7
/// ```
pub fn generate_secure_session_id(prefix: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let random_bytes = generate_random_bytes();

    format!("{}-{:x}-{}", prefix, timestamp, hex_encode(&random_bytes))
}

/// Generate a secure session ID for SSH authentication.
pub fn generate_ssh_session_id() -> String {
    generate_secure_session_id("unix-oidc")
}

/// Generate a secure session ID for sudo step-up.
pub fn generate_sudo_session_id() -> String {
    generate_secure_session_id("sudo")
}

/// Generate 8 bytes (64 bits) of cryptographic randomness.
///
/// Uses getrandom for cross-platform CSPRNG access.
///
/// # Panics
///
/// Panics if secure random number generation fails. This is intentional:
/// session IDs are used for security audit correlation, and predictable
/// session IDs could compromise audit integrity. On modern systems,
/// getrandom should never fail, so a failure indicates a severely
/// misconfigured or compromised system where authentication should not proceed.
fn generate_random_bytes() -> [u8; 8] {
    let mut bytes = [0u8; 8];

    // Use getrandom crate for secure random bytes
    // Falls back to /dev/urandom on Linux, CryptGenRandom on Windows
    getrandom::getrandom(&mut bytes).expect(
        "secure random number generation failed - \
         system may be misconfigured or compromised",
    );

    bytes
}

/// Hex encode bytes to string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Validate a session ID format.
///
/// Returns true if the session ID matches the expected format.
pub fn is_valid_session_id(session_id: &str) -> bool {
    let parts: Vec<&str> = session_id.split('-').collect();

    // Must have at least 3 parts: prefix, timestamp, random
    if parts.len() < 3 {
        return false;
    }

    // Last part should be the random hex (16 chars for 8 bytes)
    let random_part = parts.last().unwrap();
    if random_part.len() != 16 {
        return false;
    }

    // Should be valid hex
    random_part.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_session_id_format() {
        let id = generate_secure_session_id("test");
        assert!(id.starts_with("test-"));

        let parts: Vec<&str> = id.split('-').collect();
        assert!(parts.len() >= 3);
    }

    #[test]
    fn test_session_id_uniqueness() {
        let mut ids = HashSet::new();

        // Generate 1000 session IDs
        for _ in 0..1000 {
            let id = generate_secure_session_id("test");
            assert!(ids.insert(id), "Duplicate session ID generated");
        }
    }

    #[test]
    fn test_session_id_has_random_component() {
        let id1 = generate_secure_session_id("test");
        let id2 = generate_secure_session_id("test");

        // Even if generated in same nanosecond, random part should differ
        let parts1: Vec<&str> = id1.split('-').collect();
        let parts2: Vec<&str> = id2.split('-').collect();

        let random1 = parts1.last().unwrap();
        let random2 = parts2.last().unwrap();

        // Very unlikely to be equal with 64 bits of randomness
        assert_ne!(random1, random2);
    }

    #[test]
    fn test_ssh_session_id() {
        let id = generate_ssh_session_id();
        assert!(id.starts_with("unix-oidc-"));
    }

    #[test]
    fn test_sudo_session_id() {
        let id = generate_sudo_session_id();
        assert!(id.starts_with("sudo-"));
    }

    #[test]
    fn test_is_valid_session_id() {
        let valid_id = generate_secure_session_id("test");
        assert!(is_valid_session_id(&valid_id));

        assert!(!is_valid_session_id("invalid"));
        assert!(!is_valid_session_id("test-123"));
        assert!(!is_valid_session_id("test-123-short"));
    }

    #[test]
    fn test_random_bytes_entropy() {
        // Generate multiple sets of random bytes
        let mut all_bytes: Vec<[u8; 8]> = Vec::new();

        for _ in 0..100 {
            let bytes = generate_random_bytes();
            // Check for duplicates
            assert!(
                !all_bytes.contains(&bytes),
                "Duplicate random bytes generated"
            );
            all_bytes.push(bytes);
        }
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xab, 0xcd]), "abcd");
        assert_eq!(hex_encode(&[0x01, 0x23, 0x45, 0x67]), "01234567");
    }
}
