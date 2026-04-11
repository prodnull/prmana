//! OAuth client-attestation and proof-of-possession JWT helpers.
//!
//! Implements the header shapes from draft-ietf-oauth-attestation-based-client-auth
//! using the agent's ES256-capable signing key. The long-lived attestation JWT is
//! cached per `(signer thumbprint, client_id, lifetime)`; the short-lived PoP JWT
//! is generated fresh for every request.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use reqwest::RequestBuilder;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::config::ClientAttestationConfig;
use crate::crypto::DPoPError;
use crate::crypto::DPoPSigner;

const ATTESTATION_TYP: &str = "oauth-client-attestation+jwt";
const POP_TYP: &str = "oauth-client-attestation-pop+jwt";
const POP_LIFETIME_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAttestationHeaders {
    pub attestation: String,
    pub pop: String,
}

#[derive(Debug, Clone)]
struct CachedAttestation {
    jwt: String,
    expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    signer_thumbprint: String,
    client_id: String,
    lifetime_secs: u64,
}

fn cache() -> &'static Mutex<HashMap<CacheKey, CachedAttestation>> {
    static CACHE: OnceLock<Mutex<HashMap<CacheKey, CachedAttestation>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, Serialize, Deserialize)]
struct AttestationClaims {
    iss: String,
    sub: String,
    jti: String,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PopClaims {
    iss: String,
    aud: String,
    jti: String,
    iat: u64,
    exp: u64,
}

pub fn build_client_attestation(
    client_id: &str,
    signer: &dyn DPoPSigner,
    lifetime_secs: u64,
) -> Result<String, DPoPError> {
    let now = now_secs()?;
    build_client_attestation_at(client_id, signer, lifetime_secs.max(1), now)
}

fn build_client_attestation_at(
    client_id: &str,
    signer: &dyn DPoPSigner,
    lifetime_secs: u64,
    now: u64,
) -> Result<String, DPoPError> {
    let claims = AttestationClaims {
        iss: client_id.to_string(),
        sub: client_id.to_string(),
        jti: Uuid::new_v4().to_string(),
        iat: now,
        exp: now.saturating_add(lifetime_secs.max(1)),
    };
    let header = json!({
        "typ": ATTESTATION_TYP,
        "alg": "ES256",
        "jwk": signer.client_attestation_jwk()?,
    });
    sign_jwt(&header, &claims, signer)
}

pub fn build_client_attestation_pop(
    client_id: &str,
    audience: &str,
    signer: &dyn DPoPSigner,
) -> Result<String, DPoPError> {
    let now = now_secs()?;
    let claims = PopClaims {
        iss: client_id.to_string(),
        aud: audience.to_string(),
        jti: Uuid::new_v4().to_string(),
        iat: now,
        exp: now.saturating_add(POP_LIFETIME_SECS),
    };
    let header = json!({
        "typ": POP_TYP,
        "alg": "ES256",
    });
    sign_jwt(&header, &claims, signer)
}

pub fn build_client_attestation_headers(
    signer: &dyn DPoPSigner,
    config: Option<&ClientAttestationConfig>,
    client_id: &str,
    token_endpoint: &str,
) -> Result<Option<ClientAttestationHeaders>, DPoPError> {
    let Some(config) = config else {
        return Ok(None);
    };
    if !config.enabled {
        return Ok(None);
    }

    let lifetime_secs = config.lifetime_secs.max(1);
    let attestation = cached_or_build_attestation(client_id, signer, lifetime_secs)?;
    let pop = build_client_attestation_pop(client_id, token_endpoint, signer)?;
    Ok(Some(ClientAttestationHeaders { attestation, pop }))
}

pub fn attach_client_attestation(
    builder: RequestBuilder,
    signer: &dyn DPoPSigner,
    config: Option<&ClientAttestationConfig>,
    client_id: &str,
    token_endpoint: &str,
) -> Result<RequestBuilder, DPoPError> {
    let Some(headers) =
        build_client_attestation_headers(signer, config, client_id, token_endpoint)?
    else {
        return Ok(builder);
    };

    Ok(builder
        .header("OAuth-Client-Attestation", headers.attestation)
        .header("OAuth-Client-Attestation-PoP", headers.pop))
}

fn cached_or_build_attestation(
    client_id: &str,
    signer: &dyn DPoPSigner,
    lifetime_secs: u64,
) -> Result<String, DPoPError> {
    let key = CacheKey {
        signer_thumbprint: signer.thumbprint(),
        client_id: client_id.to_string(),
        lifetime_secs,
    };
    let now = now_secs()?;

    if let Some(jwt) = cache()
        .lock()
        .map_err(|_| DPoPError::HardwareSigner("attestation cache mutex poisoned".to_string()))?
        .get(&key)
        .filter(|cached| cached.expires_at > now)
        .map(|cached| cached.jwt.clone())
    {
        return Ok(jwt);
    }

    let jwt = build_client_attestation_at(client_id, signer, lifetime_secs, now)?;
    let expires_at = extract_exp(&jwt)?;
    cache()
        .lock()
        .map_err(|_| DPoPError::HardwareSigner("attestation cache mutex poisoned".to_string()))?
        .insert(
            key,
            CachedAttestation {
                jwt: jwt.clone(),
                expires_at,
            },
        );
    Ok(jwt)
}

fn sign_jwt<T: Serialize>(
    header: &serde_json::Value,
    claims: &T,
    signer: &dyn DPoPSigner,
) -> Result<String, DPoPError> {
    let encoded_header = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(header).map_err(|e| DPoPError::HardwareSigner(e.to_string()))?);
    let encoded_claims = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(claims).map_err(|e| DPoPError::HardwareSigner(e.to_string()))?);
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = signer.sign_jwt_es256(&signing_input)?;
    let encoded_sig = URL_SAFE_NO_PAD.encode(signature);
    Ok(format!("{signing_input}.{encoded_sig}"))
}

fn now_secs() -> Result<u64, DPoPError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| DPoPError::HardwareSigner(e.to_string()))?
        .as_secs())
}

fn extract_exp(jwt: &str) -> Result<u64, DPoPError> {
    let claims = decode_claims(jwt)?;
    claims
        .get("exp")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| DPoPError::HardwareSigner("client attestation JWT missing exp".to_string()))
}

fn decode_part(jwt: &str, index: usize) -> Result<serde_json::Value, DPoPError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(DPoPError::HardwareSigner("invalid JWT format".to_string()));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(parts[index])
        .map_err(|e| DPoPError::HardwareSigner(e.to_string()))?;
    serde_json::from_slice(&decoded).map_err(|e| DPoPError::HardwareSigner(e.to_string()))
}

fn decode_claims(jwt: &str) -> Result<serde_json::Value, DPoPError> {
    decode_part(jwt, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientAttestationConfig;
    use crate::crypto::SoftwareSigner;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use jsonwebtoken::{decode_header, Algorithm};
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::EncodedPoint;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn verify_with_signer(jwt: &str, signer: &SoftwareSigner) -> Result<(), String> {
        let jwk = signer.public_key_jwk();
        let x = URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().unwrap())
            .map_err(|e| e.to_string())?;
        let y = URL_SAFE_NO_PAD
            .decode(jwk["y"].as_str().unwrap())
            .map_err(|e| e.to_string())?;
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let point = EncodedPoint::from_bytes(&sec1).map_err(|e| e.to_string())?;
        let verifying_key = VerifyingKey::from_encoded_point(&point).map_err(|e| e.to_string())?;
        let parts: Vec<&str> = jwt.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| e.to_string())?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|e| e.to_string())?;
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn test_attestation_jwt_has_expected_claims_and_header() {
        let signer = SoftwareSigner::generate();
        let jwt = build_client_attestation("client-1", &signer, 3600).unwrap();
        let header = decode_header(&jwt).unwrap();
        let claims = decode_claims(&jwt).unwrap();

        assert_eq!(header.typ.as_deref(), Some(ATTESTATION_TYP));
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(claims["iss"], "client-1");
        assert_eq!(claims["sub"], "client-1");
        assert!(claims["jti"].is_string());
        assert!(claims["exp"].as_u64().unwrap() > claims["iat"].as_u64().unwrap());
    }

    #[test]
    fn test_pop_jwt_has_expected_claims_and_header() {
        let signer = SoftwareSigner::generate();
        let jwt = build_client_attestation_pop("client-1", "https://idp/token", &signer).unwrap();
        let header = decode_header(&jwt).unwrap();
        let claims = decode_claims(&jwt).unwrap();

        assert_eq!(header.typ.as_deref(), Some(POP_TYP));
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(claims["iss"], "client-1");
        assert_eq!(claims["aud"], "https://idp/token");
        assert!(claims["jti"].is_string());
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            POP_LIFETIME_SECS
        );
    }

    #[test]
    fn test_pop_jwt_has_no_jwk_in_header() {
        let signer = SoftwareSigner::generate();
        let jwt = build_client_attestation_pop("client-1", "https://idp/token", &signer).unwrap();
        let header = decode_part(&jwt, 0).unwrap();
        assert!(header.get("jwk").is_none());
    }

    #[test]
    fn test_attestation_jwt_lifetime_matches_config() {
        let signer = SoftwareSigner::generate();
        let jwt = build_client_attestation("client-1", &signer, 123).unwrap();
        let claims = decode_claims(&jwt).unwrap();
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            123
        );
    }

    #[test]
    fn test_pop_jwt_is_fresh_per_invocation() {
        let signer = SoftwareSigner::generate();
        let jwt1 = build_client_attestation_pop("client-1", "https://idp/token", &signer).unwrap();
        let jwt2 = build_client_attestation_pop("client-1", "https://idp/token", &signer).unwrap();
        let claims1 = decode_claims(&jwt1).unwrap();
        let claims2 = decode_claims(&jwt2).unwrap();
        assert_ne!(claims1["jti"], claims2["jti"]);
    }

    #[test]
    fn test_attestation_signature_verifies_with_signer_public_key() {
        let signer = SoftwareSigner::generate();
        let jwt = build_client_attestation("client-1", &signer, 3600).unwrap();
        verify_with_signer(&jwt, &signer).unwrap();
        let claims = decode_claims(&jwt).unwrap();
        assert_eq!(claims["iss"], "client-1");
    }

    #[test]
    fn test_pop_signature_verifies_with_signer_public_key() {
        let signer = SoftwareSigner::generate();
        let jwt = build_client_attestation_pop("client-1", "https://idp/token", &signer).unwrap();
        verify_with_signer(&jwt, &signer).unwrap();
        let claims = decode_claims(&jwt).unwrap();
        assert_eq!(claims["aud"], "https://idp/token");
    }

    #[test]
    fn test_attestation_jwk_header_matches_signer_public_key() {
        let signer = SoftwareSigner::generate();
        let jwt = build_client_attestation("client-1", &signer, 3600).unwrap();
        let header = decode_part(&jwt, 0).unwrap();
        assert_eq!(header["jwk"], signer.public_key_jwk());
    }

    #[tokio::test]
    async fn test_attach_client_attestation_adds_both_headers() {
        let signer = SoftwareSigner::generate();
        let config = ClientAttestationConfig {
            enabled: true,
            lifetime_secs: 3600,
        };
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header_exists("OAuth-Client-Attestation"))
            .and(header_exists("OAuth-Client-Attestation-PoP"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let builder = attach_client_attestation(
            client.post(format!("{}/token", server.uri())),
            &signer,
            Some(&config),
            "client-1",
            &format!("{}/token", server.uri()),
        )
        .unwrap();
        builder.send().await.unwrap();
    }

    #[test]
    fn test_cached_attestation_reused_within_lifetime() {
        let signer = SoftwareSigner::generate();
        let config = ClientAttestationConfig {
            enabled: true,
            lifetime_secs: 3600,
        };
        let headers1 = build_client_attestation_headers(
            &signer,
            Some(&config),
            "client-1",
            "https://idp/token",
        )
        .unwrap()
        .unwrap();
        let headers2 = build_client_attestation_headers(
            &signer,
            Some(&config),
            "client-1",
            "https://idp/token",
        )
        .unwrap()
        .unwrap();
        assert_eq!(headers1.attestation, headers2.attestation);
        assert_ne!(headers1.pop, headers2.pop);
    }

    #[test]
    fn test_expired_pop_claims_are_in_past() {
        let claims = PopClaims {
            iss: "client-1".to_string(),
            aud: "https://idp/token".to_string(),
            jti: Uuid::new_v4().to_string(),
            iat: 1,
            exp: 2,
        };
        let now = now_secs().unwrap();
        assert!(claims.exp < now);
        assert!(claims.iat < now);
    }

    #[test]
    fn test_attestation_signed_by_wrong_key_fails_verification() {
        let signer = SoftwareSigner::generate();
        let wrong = SoftwareSigner::generate();
        let jwt = build_client_attestation("client-1", &wrong, 3600).unwrap();
        assert!(verify_with_signer(&jwt, &signer).is_err());
    }

    #[test]
    fn test_empty_client_id_still_produces_valid_jwt_structure() {
        let signer = SoftwareSigner::generate();
        let jwt = build_client_attestation("", &signer, 3600).unwrap();
        assert_eq!(jwt.split('.').count(), 3);
        let claims = decode_claims(&jwt).unwrap();
        assert_eq!(claims["iss"], "");
        assert_eq!(claims["sub"], "");
    }

    #[tokio::test]
    async fn test_attach_client_attestation_disabled_adds_no_headers() {
        let signer = SoftwareSigner::generate();
        let config = ClientAttestationConfig {
            enabled: false,
            lifetime_secs: 3600,
        };
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let request = attach_client_attestation(
            client.post(format!("{}/token", server.uri())),
            &signer,
            Some(&config),
            "client-1",
            &format!("{}/token", server.uri()),
        )
        .unwrap()
        .build()
        .unwrap();

        assert!(request.headers().get("OAuth-Client-Attestation").is_none());
        assert!(request
            .headers()
            .get("OAuth-Client-Attestation-PoP")
            .is_none());
    }

    #[tokio::test]
    async fn test_attach_client_attestation_none_adds_no_headers() {
        let signer = SoftwareSigner::generate();
        let server = MockServer::start().await;
        let client = reqwest::Client::new();
        let request = attach_client_attestation(
            client.post(format!("{}/token", server.uri())),
            &signer,
            None,
            "client-1",
            &format!("{}/token", server.uri()),
        )
        .unwrap()
        .build()
        .unwrap();

        assert!(request.headers().get("OAuth-Client-Attestation").is_none());
        assert!(request
            .headers()
            .get("OAuth-Client-Attestation-PoP")
            .is_none());
    }

    #[test]
    fn test_headers_absent_when_config_disabled_or_absent() {
        let signer = SoftwareSigner::generate();
        let disabled = ClientAttestationConfig {
            enabled: false,
            lifetime_secs: 3600,
        };
        assert!(build_client_attestation_headers(
            &signer,
            Some(&disabled),
            "client",
            "https://idp"
        )
        .unwrap()
        .is_none());
        assert!(
            build_client_attestation_headers(&signer, None, "client", "https://idp")
                .unwrap()
                .is_none()
        );
    }
}
