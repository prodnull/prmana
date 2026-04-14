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
//! Example: `prmana-18d4f2a3b4c-a7f3e2d1c0b9a8f7`
//!
//! - `prefix`: Identifies the session type (prmana, sudo, etc.)
//! - `timestamp_hex`: Nanosecond timestamp for ordering and debugging
//! - `random_hex`: 128 bits of cryptographic randomness

use std::time::{SystemTime, UNIX_EPOCH};

/// Generate a cryptographically secure session ID.
///
/// The session ID combines:
/// - A prefix for identification
/// - Timestamp for ordering and debugging
/// - 128 bits of CSPRNG randomness for unpredictability
///
/// 128-bit random component provides a birthday bound of ~2^64, sufficient
/// for high-volume environments per NIST SP 800-63B session identifier guidance.
///
/// Returns an error if the OS CSPRNG is unavailable. Callers in PAM paths
/// must propagate this error rather than panic — a PAM panic can lock users
/// out of their system.
///
/// # Example
///
/// ```
/// use pam_prmana::security::generate_secure_session_id;
///
/// let session_id = generate_secure_session_id("prmana").unwrap();
/// assert!(session_id.starts_with("prmana-"));
/// // Example: prmana-18d4f2a3b4c-a7f3e2d1c0b9a8f7e6d5c4b3a2918070
/// ```
pub fn generate_secure_session_id(prefix: &str) -> Result<String, getrandom::Error> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let random_bytes = generate_random_bytes()?;

    Ok(format!(
        "{}-{:x}-{}",
        prefix,
        timestamp,
        hex_encode(&random_bytes)
    ))
}

/// Generate a secure session ID for SSH authentication.
pub fn generate_ssh_session_id() -> Result<String, getrandom::Error> {
    generate_secure_session_id("prmana")
}

/// Generate a secure session ID for sudo step-up.
pub fn generate_sudo_session_id() -> Result<String, getrandom::Error> {
    generate_secure_session_id("sudo")
}

/// Generate 16 bytes (128 bits) of cryptographic randomness.
///
/// Uses getrandom for cross-platform CSPRNG access.
/// Returns an error if the OS CSPRNG is unavailable rather than panicking,
/// so that PAM paths can propagate the error instead of crashing sshd.
fn generate_random_bytes() -> Result<[u8; 16], getrandom::Error> {
    let mut bytes = [0u8; 16];

    // Use getrandom crate for secure random bytes
    // Falls back to /dev/urandom on Linux, CryptGenRandom on Windows
    // getrandom v0.3 uses fill(), v0.2 uses getrandom()
    getrandom::fill(&mut bytes)?;

    Ok(bytes)
}

/// Hex encode bytes to string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

    // Last part should be the random hex (32 chars for 16 bytes).
    // The guard above guarantees parts.len() >= 3, so last() is always Some.
    let random_part = parts.last().unwrap_or(&"");
    if random_part.len() != 32 {
        return false;
    }

    // Should be valid hex
    random_part.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_session_id_format() {
        let id = generate_secure_session_id("test").unwrap();
        assert!(id.starts_with("test-"));

        let parts: Vec<&str> = id.split('-').collect();
        assert!(parts.len() >= 3);
    }

    #[test]
    fn test_session_id_uniqueness() {
        let mut ids = HashSet::new();

        // Generate 1000 session IDs
        for _ in 0..1000 {
            let id = generate_secure_session_id("test").unwrap();
            assert!(ids.insert(id), "Duplicate session ID generated");
        }
    }

    #[test]
    fn test_session_id_has_random_component() {
        let id1 = generate_secure_session_id("test").unwrap();
        let id2 = generate_secure_session_id("test").unwrap();

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
        let id = generate_ssh_session_id().unwrap();
        assert!(id.starts_with("prmana-"));
    }

    #[test]
    fn test_sudo_session_id() {
        let id = generate_sudo_session_id().unwrap();
        assert!(id.starts_with("sudo-"));
    }

    #[test]
    fn test_is_valid_session_id() {
        let valid_id = generate_secure_session_id("test").unwrap();
        assert!(is_valid_session_id(&valid_id));

        assert!(!is_valid_session_id("invalid"));
        assert!(!is_valid_session_id("test-123"));
        assert!(!is_valid_session_id("test-123-short"));
    }

    #[test]
    fn test_random_bytes_entropy() {
        // Generate multiple sets of random bytes
        let mut all_bytes: Vec<[u8; 16]> = Vec::new();

        for _ in 0..100 {
            let bytes = generate_random_bytes().unwrap();
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
