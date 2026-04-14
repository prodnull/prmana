//! Fuzz target for JWT token parsing
//!
//! This fuzzer tests the robustness of token parsing against malformed input.
//! It does NOT test cryptographic validation (that requires valid signatures).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to interpret as UTF-8 (tokens are text)
    if let Ok(token_str) = std::str::from_utf8(data) {
        // Attempt to parse as JWT structure (header.payload.signature)
        let parts: Vec<&str> = token_str.split('.').collect();

        if parts.len() == 3 {
            // Try base64 decoding each part
            for part in parts.iter().take(2) {
                // Header and payload should be base64-decodable
                let _ = base64_decode(part);
            }
        }

        // Also try parsing as a complete token
        // This exercises the full parsing path
        let _ = parse_jwt_structure(token_str);
    }
});

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    // JWT uses base64url encoding
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(input).ok()
}

fn parse_jwt_structure(token: &str) -> Option<(serde_json::Value, serde_json::Value)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let header_bytes = base64_decode(parts[0])?;
    let payload_bytes = base64_decode(parts[1])?;

    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    Some((header, payload))
}
