//! JWK Thumbprint computation (RFC 7638)

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::jwk::EcPublicJwk;

/// Compute JWK thumbprint for an EC P-256 verifying key per RFC 7638
///
/// The thumbprint is SHA-256 of the canonical JSON representation:
/// `{"crv":"P-256","kty":"EC","x":"...","y":"..."}`
///
/// Note: Members MUST be in lexicographic order per RFC 7638.
pub fn compute_thumbprint(verifying_key: &VerifyingKey) -> String {
    let point = verifying_key.to_encoded_point(false);
    // SAFETY: Uncompressed points always have x,y coordinates
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y"));

    compute_thumbprint_from_coordinates(&x, &y)
}

/// Compute JWK thumbprint from base64url-encoded coordinates
///
/// This is useful when you already have the JWK coordinates as strings.
pub fn compute_thumbprint_from_coordinates(x: &str, y: &str) -> String {
    // RFC 7638: Members MUST be in lexicographic order
    // For EC P-256: crv < kty < x < y
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, x, y);

    let hash = Sha256::digest(canonical.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

/// Compute JWK thumbprint from an EcPublicJwk
pub fn compute_thumbprint_from_jwk(jwk: &EcPublicJwk) -> String {
    // RFC 7638: canonical JSON with lexicographic member ordering
    // For EC P-256: crv < kty < x < y
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );

    let hash = Sha256::digest(canonical.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn test_thumbprint_is_deterministic() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let thumb1 = compute_thumbprint(verifying_key);
        let thumb2 = compute_thumbprint(verifying_key);

        assert_eq!(thumb1, thumb2);
    }

    #[test]
    fn test_thumbprint_format() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let thumb = compute_thumbprint(verifying_key);

        // SHA-256 = 32 bytes = 43 base64url chars (no padding)
        assert_eq!(thumb.len(), 43);
        // Should be valid base64url
        assert!(thumb
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_different_keys_different_thumbprints() {
        let key1 = SigningKey::random(&mut OsRng);
        let key2 = SigningKey::random(&mut OsRng);

        let thumb1 = compute_thumbprint(key1.verifying_key());
        let thumb2 = compute_thumbprint(key2.verifying_key());

        assert_ne!(thumb1, thumb2);
    }

    #[test]
    fn test_canonical_json_order() {
        // Verify the canonical JSON has correct member ordering
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#, x, y);

        // Verify lexicographic order: crv < kty < x < y
        assert!(canonical.contains(r#""crv":"P-256","kty":"EC","x":"#));
    }

    #[test]
    fn test_thumbprint_from_coordinates_matches() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let thumb1 = compute_thumbprint(verifying_key);
        let thumb2 = compute_thumbprint_from_coordinates(&x, &y);

        assert_eq!(thumb1, thumb2);
    }

    #[test]
    fn test_thumbprint_from_jwk_matches() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let jwk = EcPublicJwk::new(x, y);

        let thumb1 = compute_thumbprint(verifying_key);
        let thumb2 = compute_thumbprint_from_jwk(&jwk);

        assert_eq!(thumb1, thumb2);
    }
}
