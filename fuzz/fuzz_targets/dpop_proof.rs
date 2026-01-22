//! Fuzz target for DPoP proof parsing and validation
//!
//! Tests the robustness of DPoP proof parsing against malformed input.
//! Security-critical: DPoP parsing must never panic or consume unbounded resources.

#![no_main]

use base64::Engine;
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzDpopInput {
    /// The DPoP proof JWT
    proof: String,
    /// The HTTP method (GET, POST, etc.)
    http_method: String,
    /// The HTTP URI
    http_uri: String,
    /// Optional access token hash to verify
    access_token: Option<String>,
}

fuzz_target!(|input: FuzzDpopInput| {
    // Test proof structure parsing
    let _ = parse_dpop_proof(&input.proof);

    // Test with various HTTP methods
    let _ = validate_dpop_claims(&input.proof, &input.http_method, &input.http_uri);

    // Test jti extraction (for replay protection)
    let _ = extract_jti(&input.proof);

    // Test ath (access token hash) validation if token provided
    if let Some(ref token) = input.access_token {
        let _ = verify_access_token_hash(&input.proof, token);
    }
});

fn parse_dpop_proof(proof: &str) -> Option<DpopClaims> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode header
    let header_bytes = base64_decode(parts[0])?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;

    // Verify it's a DPoP proof
    if header.get("typ")?.as_str()? != "dpop+jwt" {
        return None;
    }

    // Decode payload
    let payload_bytes = base64_decode(parts[1])?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    Some(DpopClaims {
        jti: payload.get("jti")?.as_str()?.to_string(),
        htm: payload.get("htm")?.as_str()?.to_string(),
        htu: payload.get("htu")?.as_str()?.to_string(),
        iat: payload.get("iat")?.as_u64()?,
        ath: payload.get("ath").and_then(|v| v.as_str()).map(String::from),
    })
}

#[derive(Debug)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: u64,
    ath: Option<String>,
}

fn validate_dpop_claims(proof: &str, expected_method: &str, expected_uri: &str) -> bool {
    if let Some(claims) = parse_dpop_proof(proof) {
        // Case-insensitive method comparison
        if !claims.htm.eq_ignore_ascii_case(expected_method) {
            return false;
        }

        // URI comparison (normalize trailing slashes, etc.)
        let normalized_htu = claims.htu.trim_end_matches('/');
        let normalized_expected = expected_uri.trim_end_matches('/');
        if normalized_htu != normalized_expected {
            return false;
        }

        // Check iat is reasonable (not in future, not too old)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Allow 60 second clock skew
        if claims.iat > now + 60 {
            return false;
        }

        // Reject proofs older than configured max age (e.g., 300 seconds)
        if claims.iat < now.saturating_sub(300) {
            return false;
        }

        true
    } else {
        false
    }
}

fn extract_jti(proof: &str) -> Option<String> {
    parse_dpop_proof(proof).map(|c| c.jti)
}

fn verify_access_token_hash(proof: &str, access_token: &str) -> bool {
    if let Some(claims) = parse_dpop_proof(proof) {
        if let Some(ath) = claims.ath {
            // Compute expected hash
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(access_token.as_bytes());
            let hash = hasher.finalize();
            let expected_ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);

            // Constant-time comparison
            return constant_time_eq(ath.as_bytes(), expected_ath.as_bytes());
        }
    }
    false
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(input).ok()
}
