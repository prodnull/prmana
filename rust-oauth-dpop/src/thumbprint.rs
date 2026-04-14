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
    // Security: Hardcode "P-256" and "EC" to prevent attacker-controlled kty/crv
    // from altering the thumbprint. Delegates to compute_thumbprint_from_coordinates
    // which already uses hardcoded canonical values.
    compute_thumbprint_from_coordinates(&jwk.x, &jwk.y)
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

    // ---------------------------------------------------------------
    // F-09: JWK thumbprint uses hardcoded canonical kty/crv
    // ---------------------------------------------------------------

    #[test]
    fn test_f09_thumbprint_from_jwk_equals_coordinates() {
        // Positive: compute_thumbprint_from_jwk delegates to
        // compute_thumbprint_from_coordinates, so results must match.
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let jwk = EcPublicJwk::new(x.clone(), y.clone());

        let from_jwk = compute_thumbprint_from_jwk(&jwk);
        let from_coords = compute_thumbprint_from_coordinates(&x, &y);

        assert_eq!(
            from_jwk, from_coords,
            "JWK-based and coordinate-based thumbprints must be identical"
        );
    }

    #[test]
    fn test_f09_manipulated_kty_crv_ignored_in_thumbprint() {
        // Negative: attacker-supplied kty/crv values in the JWK struct
        // must not alter the computed thumbprint.
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

        let legit = EcPublicJwk::new(x.clone(), y.clone());
        let legit_thumb = compute_thumbprint_from_jwk(&legit);

        // Attacker sets kty to "oct" (symmetric key type)
        let mut attacker_oct = EcPublicJwk::new(x.clone(), y.clone());
        attacker_oct.kty = "oct".to_string();
        assert_eq!(
            legit_thumb,
            compute_thumbprint_from_jwk(&attacker_oct),
            "kty manipulation must not change thumbprint"
        );

        // Attacker sets crv to "P-384"
        let mut attacker_384 = EcPublicJwk::new(x.clone(), y.clone());
        attacker_384.crv = "P-384".to_string();
        assert_eq!(
            legit_thumb,
            compute_thumbprint_from_jwk(&attacker_384),
            "crv manipulation must not change thumbprint"
        );

        // Both kty and crv manipulated
        let mut attacker_both = EcPublicJwk::new(x, y);
        attacker_both.kty = "RSA".to_string();
        attacker_both.crv = "secp256k1".to_string();
        assert_eq!(
            legit_thumb,
            compute_thumbprint_from_jwk(&attacker_both),
            "kty+crv manipulation must not change thumbprint"
        );
    }
}
