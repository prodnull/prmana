//! Offline TOTP verification for break-glass authentication (Phase 36-02).
//!
//! Implements RFC 6238 (TOTP) using HMAC-SHA1 for compatibility with standard
//! YubiKey and Google Authenticator enrollments. Seeds are pre-enrolled in
//! `/etc/unix-oidc/break-glass-otp.json` (root-readable only).
//!
//! This module runs ONLY in the break-glass path — never in normal OIDC auth.
//! No network calls; verification is entirely local.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::collections::HashMap;
use std::path::Path;

type HmacSha1 = Hmac<Sha1>;

/// Default TOTP time step (seconds).
const DEFAULT_TIME_STEP: u64 = 30;

/// Default number of digits in the OTP code.
const DEFAULT_DIGITS: u32 = 6;

/// Default clock drift tolerance (±1 step = ±30s).
const DEFAULT_SKEW: i64 = 1;

/// Default path for enrolled OTP seeds.
pub const DEFAULT_OTP_SEEDS_PATH: &str = "/etc/unix-oidc/break-glass-otp.json";

/// Enrolled OTP seed for a break-glass account.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct OtpSeed {
    /// Base32-encoded shared secret (e.g., from YubiKey TOTP enrollment).
    pub secret_base32: String,
    /// TOTP time step in seconds. Default: 30.
    #[serde(default = "default_time_step")]
    pub time_step: u64,
    /// Number of digits. Default: 6.
    #[serde(default = "default_digits")]
    pub digits: u32,
    /// Clock skew tolerance in steps (±N). Default: 1.
    #[serde(default = "default_skew")]
    pub skew: i64,
}

fn default_time_step() -> u64 {
    DEFAULT_TIME_STEP
}
fn default_digits() -> u32 {
    DEFAULT_DIGITS
}
fn default_skew() -> i64 {
    DEFAULT_SKEW
}

/// OTP seed store — maps username to enrolled seed.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct OtpSeedStore {
    #[serde(flatten)]
    pub seeds: HashMap<String, OtpSeed>,
}

/// Errors from OTP verification.
#[derive(Debug, thiserror::Error)]
pub enum OtpError {
    #[error("OTP seed file not found: {0}")]
    SeedFileNotFound(String),
    #[error("OTP seed file read error: {0}")]
    SeedFileRead(String),
    #[error("OTP seed file parse error: {0}")]
    SeedFileParse(String),
    #[error("No OTP seed enrolled for user: {0}")]
    UserNotEnrolled(String),
    #[error("Invalid base32 secret for user: {0}")]
    InvalidSecret(String),
    #[error("OTP code mismatch")]
    CodeMismatch,
}

/// Load enrolled OTP seeds from the configured path.
///
/// Security (Codex MED-2, LOW round 2): validates file via fd-based fstat to
/// close the TOCTOU gap between metadata check and read. Opens with O_NOFOLLOW
/// to reject symlinks atomically at the kernel level.
pub fn load_seeds(path: &Path) -> Result<OtpSeedStore, OtpError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    // Open with O_NOFOLLOW — kernel rejects symlinks atomically (no TOCTOU).
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                OtpError::SeedFileRead(format!(
                    "{}: is a symlink (rejected for security)",
                    path.display()
                ))
            } else if e.kind() == std::io::ErrorKind::NotFound {
                OtpError::SeedFileNotFound(path.display().to_string())
            } else {
                OtpError::SeedFileRead(format!("{}: {e}", path.display()))
            }
        })?;

    // fstat on the fd — no TOCTOU window.
    let meta = file
        .metadata()
        .map_err(|e| OtpError::SeedFileRead(format!("{}: fstat failed: {e}", path.display())))?;

    // Reject non-regular files (FIFOs, devices, etc.).
    if !meta.file_type().is_file() {
        return Err(OtpError::SeedFileRead(format!(
            "{}: not a regular file",
            path.display()
        )));
    }

    // Require root ownership (uid 0).
    if meta.uid() != 0 {
        return Err(OtpError::SeedFileRead(format!(
            "{}: must be owned by root (uid 0), got uid {}",
            path.display(),
            meta.uid()
        )));
    }

    // Reject group/other-readable (mode must be 0600 or 0400).
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(OtpError::SeedFileRead(format!(
            "{}: permissions too open ({:04o}), must be 0600 or 0400",
            path.display(),
            mode
        )));
    }

    // Read from the already-opened fd (same inode we just validated).
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| OtpError::SeedFileRead(format!("{}: {e}", path.display())))?;

    let store: OtpSeedStore = serde_json::from_str(&contents)
        .map_err(|e| OtpError::SeedFileParse(format!("{}: {e}", path.display())))?;
    Ok(store)
}

/// Verify a TOTP code for the given user.
///
/// Returns `Ok(())` if the code matches any time step within the skew window.
/// Returns `Err(OtpError::CodeMismatch)` if the code is invalid.
pub fn verify_totp(username: &str, code: &str, store: &OtpSeedStore) -> Result<(), OtpError> {
    let seed = store
        .seeds
        .get(username)
        .ok_or_else(|| OtpError::UserNotEnrolled(username.to_string()))?;

    let secret = data_encoding::BASE32
        .decode(seed.secret_base32.as_bytes())
        .map_err(|_| OtpError::InvalidSecret(username.to_string()))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let counter = (now / seed.time_step) as i64;

    for offset in -seed.skew..=seed.skew {
        let step = (counter + offset) as u64;
        let expected = generate_totp_code(&secret, step, seed.digits);
        if code == expected {
            return Ok(());
        }
    }

    Err(OtpError::CodeMismatch)
}

/// Generate a TOTP code for a given counter value (RFC 6238 / RFC 4226).
fn generate_totp_code(secret: &[u8], counter: u64, digits: u32) -> String {
    // RFC 4226 §5.3: HMAC-SHA1(secret, counter_bytes)
    let mut mac = match HmacSha1::new_from_slice(secret) {
        Ok(mac) => mac,
        Err(_) => unreachable!("HMAC accepts any key length"),
    };
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 §5.4)
    let offset = (result[19] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);

    let modulus = 10u32.pow(digits);
    format!("{:0>width$}", binary % modulus, width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 test vector: SHA1, time step 30, digits 8.
    /// Seed: "12345678901234567890" (ASCII, not base32).
    /// These are the official TOTP test vectors from RFC 6238 Appendix B.
    #[test]
    fn test_rfc6238_test_vectors() {
        let secret = b"12345678901234567890";

        // Time=59, counter=1 → "94287082" (8 digits)
        assert_eq!(generate_totp_code(secret, 1, 8), "94287082");
        // Time=1111111109, counter=37037036 → "07081804"
        assert_eq!(generate_totp_code(secret, 37037036, 8), "07081804");
        // Time=1111111111, counter=37037037 → "14050471"
        assert_eq!(generate_totp_code(secret, 37037037, 8), "14050471");
        // Time=1234567890, counter=41152263 → "89005924"
        assert_eq!(generate_totp_code(secret, 41152263, 8), "89005924");
        // Time=2000000000, counter=66666666 → "69279037"
        assert_eq!(generate_totp_code(secret, 66666666, 8), "69279037");
        // Time=20000000000, counter=666666666 → "65353130"
        assert_eq!(generate_totp_code(secret, 666666666, 8), "65353130");
    }

    #[test]
    fn test_generate_6_digit_code() {
        let secret = b"12345678901234567890";
        let code = generate_totp_code(secret, 1, 6);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_verify_totp_success() {
        let secret = b"12345678901234567890";
        let secret_b32 = data_encoding::BASE32.encode(secret);

        let store = OtpSeedStore {
            seeds: HashMap::from([(
                "breakglass".to_string(),
                OtpSeed {
                    secret_base32: secret_b32,
                    time_step: 30,
                    digits: 6,
                    skew: 100, // Very wide window for test determinism
                },
            )]),
        };

        // Generate a code for the current counter
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let counter = now / 30;
        let code = generate_totp_code(secret, counter, 6);

        assert!(verify_totp("breakglass", &code, &store).is_ok());
    }

    #[test]
    fn test_verify_totp_wrong_code() {
        let secret = b"12345678901234567890";
        let secret_b32 = data_encoding::BASE32.encode(secret);

        let store = OtpSeedStore {
            seeds: HashMap::from([(
                "breakglass".to_string(),
                OtpSeed {
                    secret_base32: secret_b32,
                    time_step: 30,
                    digits: 6,
                    skew: 1,
                },
            )]),
        };

        let result = verify_totp("breakglass", "000000", &store);
        assert!(matches!(result, Err(OtpError::CodeMismatch)));
    }

    #[test]
    fn test_verify_totp_user_not_enrolled() {
        let store = OtpSeedStore::default();
        let result = verify_totp("unknown", "123456", &store);
        assert!(matches!(result, Err(OtpError::UserNotEnrolled(_))));
    }

    #[test]
    fn test_verify_totp_invalid_base32() {
        let store = OtpSeedStore {
            seeds: HashMap::from([(
                "bad".to_string(),
                OtpSeed {
                    secret_base32: "!!!not-base32!!!".to_string(),
                    time_step: 30,
                    digits: 6,
                    skew: 1,
                },
            )]),
        };

        let result = verify_totp("bad", "123456", &store);
        assert!(matches!(result, Err(OtpError::InvalidSecret(_))));
    }

    #[test]
    fn test_load_seeds_file_not_found() {
        let result = load_seeds(Path::new("/nonexistent/path.json"));
        assert!(matches!(result, Err(OtpError::SeedFileNotFound(_))));
    }

    #[test]
    fn test_otp_seed_store_deserialization() {
        let json = r#"{
            "breakglass": {
                "secret_base32": "JBSWY3DPEHPK3PXP",
                "time_step": 30,
                "digits": 6,
                "skew": 1
            }
        }"#;

        let store: OtpSeedStore = serde_json::from_str(json).unwrap();
        assert!(store.seeds.contains_key("breakglass"));
        let seed = &store.seeds["breakglass"];
        assert_eq!(seed.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(seed.time_step, 30);
        assert_eq!(seed.digits, 6);
    }

    #[test]
    fn test_otp_seed_defaults() {
        let json = r#"{"bg": {"secret_base32": "AAAA"}}"#;
        let store: OtpSeedStore = serde_json::from_str(json).unwrap();
        let seed = &store.seeds["bg"];
        assert_eq!(seed.time_step, 30);
        assert_eq!(seed.digits, 6);
        assert_eq!(seed.skew, 1);
    }
}
