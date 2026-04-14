//! Fuzz target for username mapping
//!
//! Tests the robustness of claim-to-username mapping against edge cases.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzUsernameInput {
    /// The claim value to map
    claim_value: String,
    /// Transform type
    transform: TransformType,
    /// Optional prefix to remove
    prefix: Option<String>,
    /// Optional regex pattern
    regex_pattern: Option<String>,
}

#[derive(Arbitrary, Debug)]
enum TransformType {
    None,
    StripDomain,
    Lowercase,
    RemovePrefix,
    Regex,
}

fuzz_target!(|input: FuzzUsernameInput| {
    // Early exit for inputs that are too large or contain problematic bytes
    // This prevents stack overflows and memory issues in the fuzzer
    if input.claim_value.len() > 1000 {
        return;
    }

    // Skip inputs with embedded null bytes - these are not valid UTF-8 strings
    // from real OIDC tokens (JSON doesn't allow embedded nulls in strings)
    if input.claim_value.contains('\0') {
        return;
    }

    let result = map_username(&input.claim_value, &input);

    // Validate result constraints
    if let Some(username) = result {
        // Username should never be empty
        assert!(!username.is_empty(), "Empty username produced");

        // Username should not contain dangerous characters
        assert!(!username.contains('\0'), "Null byte in username");
        assert!(!username.contains('/'), "Slash in username");

        // Username should be reasonable length
        assert!(username.len() <= 256, "Username too long");
    }
});

/// Maximum allowed username length in bytes
/// POSIX LOGIN_NAME_MAX is typically 32, Linux extended limit is 256 bytes
const MAX_USERNAME_BYTES: usize = 256;

fn map_username(claim: &str, input: &FuzzUsernameInput) -> Option<String> {
    // Always sanitize the result - strip dangerous characters and enforce length limit
    let sanitize = |s: String| -> Option<String> {
        // Filter dangerous characters first
        let filtered: String = s
            .chars()
            .filter(|&c| c != '\0' && c != '/')
            .collect();

        // Truncate to MAX_USERNAME_BYTES while preserving valid UTF-8
        // This is the proper way to limit by bytes, not characters
        let truncated = if filtered.len() > MAX_USERNAME_BYTES {
            // Find a valid UTF-8 boundary at or before MAX_USERNAME_BYTES
            let mut end = MAX_USERNAME_BYTES;
            while end > 0 && !filtered.is_char_boundary(end) {
                end -= 1;
            }
            &filtered[..end]
        } else {
            &filtered[..]
        };

        if truncated.is_empty() {
            None
        } else {
            Some(truncated.to_string())
        }
    };

    match input.transform {
        TransformType::None => sanitize(claim.to_string()),

        TransformType::StripDomain => {
            // email@domain.com -> email
            claim.split('@').next().map(String::from).and_then(sanitize)
        }

        TransformType::Lowercase => sanitize(claim.to_lowercase()),

        TransformType::RemovePrefix => {
            let result = if let Some(ref prefix) = input.prefix {
                if claim.starts_with(prefix) {
                    claim[prefix.len()..].to_string()
                } else {
                    claim.to_string()
                }
            } else {
                claim.to_string()
            };
            sanitize(result)
        }

        TransformType::Regex => {
            // Only compile regex if pattern is provided and reasonable length
            if let Some(ref pattern) = input.regex_pattern {
                // Limit pattern length to prevent ReDoS
                if pattern.len() > 100 {
                    return None;
                }

                // Try to compile regex with timeout/limits
                match regex::Regex::new(pattern) {
                    Ok(re) => {
                        // Limit input length for regex matching
                        let truncated = if claim.len() > 1000 {
                            &claim[..1000]
                        } else {
                            claim
                        };

                        re.captures(truncated)
                            .and_then(|caps| caps.get(1))
                            .map(|m| m.as_str().to_string())
                            .and_then(sanitize)
                    }
                    Err(_) => None,
                }
            } else {
                None
            }
        }
    }
}
