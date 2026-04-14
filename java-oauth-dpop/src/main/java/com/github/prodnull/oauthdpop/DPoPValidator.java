package com.github.prodnull.oauthdpop;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.collections.api.map.MutableMap;
import org.eclipse.collections.impl.factory.Maps;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.time.Instant;
import java.util.Base64;

/**
 * Server-side DPoP proof validation per RFC 9449.
 *
 * <p>Security features:
 * <ul>
 *   <li>JTI replay protection</li>
 *   <li>Constant-time comparison for cryptographic values</li>
 *   <li>Key parameter validation</li>
 * </ul>
 */
public class DPoPValidator {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Decoder BASE64URL = Base64.getUrlDecoder();
    private static final int P256_COORDINATE_LEN = 32;

    // JTI cache for replay protection (using Eclipse Collections)
    private static final MutableMap<String, Long> jtiCache = Maps.mutable.empty();
    private static volatile long lastCleanup = System.currentTimeMillis();
    private static final Object cacheLock = new Object();

    /**
     * Validate a DPoP proof and return the JWK thumbprint.
     *
     * @param proof  the DPoP proof JWT
     * @param config validation configuration
     * @return the JWK thumbprint
     * @throws DPoPValidationException if validation fails
     */
    public static String validateProof(String proof, DPoPConfig config) {
        String[] parts = proof.split("\\.");
        if (parts.length != 3) {
            throw new DPoPValidationException(
                    DPoPValidationException.INVALID_FORMAT, "Proof must have 3 parts");
        }

        try {
            JsonNode header = MAPPER.readTree(BASE64URL.decode(parts[0]));

            if (!header.has("typ") || !"dpop+jwt".equals(header.get("typ").asText())) {
                throw new DPoPValidationException(
                        DPoPValidationException.INVALID_HEADER, "typ must be dpop+jwt");
            }

            String alg = header.has("alg") ? header.get("alg").asText() : null;
            if (!"ES256".equals(alg)) {
                throw new DPoPValidationException(
                        DPoPValidationException.UNSUPPORTED_ALG, "Unsupported algorithm: " + alg);
            }

            if (!header.has("jwk")) {
                throw new DPoPValidationException(
                        DPoPValidationException.MISSING_JWK, "Missing JWK in header");
            }
            JsonNode jwk = header.get("jwk");

            byte[] sigBytes = BASE64URL.decode(parts[2]);
            ECPublicKey publicKey = jwkToPublicKey(jwk);

            String message = parts[0] + "." + parts[1];
            Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
            sig.initVerify(publicKey);
            sig.update(message.getBytes(StandardCharsets.UTF_8));
            if (!sig.verify(sigBytes)) {
                throw new DPoPValidationException(
                        DPoPValidationException.INVALID_SIGNATURE, "Signature verification failed");
            }

            JsonNode claims = MAPPER.readTree(BASE64URL.decode(parts[1]));

            long now = Instant.now().getEpochSecond();
            long iat = claims.has("iat") ? claims.get("iat").asLong() : 0;
            if (now - iat > config.getMaxProofAgeSecs()) {
                throw new DPoPValidationException(DPoPValidationException.PROOF_EXPIRED,
                        String.format("Proof expired: iat=%d, now=%d", iat, now));
            }
            if (iat > now + 5) {
                throw new DPoPValidationException(DPoPValidationException.PROOF_EXPIRED,
                        String.format("Proof from future: iat=%d, now=%d", iat, now));
            }

            String htm = claims.has("htm") ? claims.get("htm").asText() : null;
            if (!config.getExpectedMethod().equals(htm)) {
                throw new DPoPValidationException(DPoPValidationException.METHOD_MISMATCH,
                        String.format("Expected %s, got %s", config.getExpectedMethod(), htm));
            }

            String htu = claims.has("htu") ? claims.get("htu").asText() : null;
            if (!config.getExpectedTarget().equals(htu)) {
                throw new DPoPValidationException(DPoPValidationException.TARGET_MISMATCH,
                        String.format("Expected %s, got %s", config.getExpectedTarget(), htu));
            }

            if (config.isRequireNonce()) {
                String proofNonce = claims.has("nonce") ? claims.get("nonce").asText() : null;
                if (proofNonce == null) {
                    throw new DPoPValidationException(
                            DPoPValidationException.MISSING_NONCE, "Nonce required but not provided");
                }
                if (config.getExpectedNonce() != null &&
                        !constantTimeEquals(proofNonce, config.getExpectedNonce())) {
                    throw new DPoPValidationException(
                            DPoPValidationException.NONCE_MISMATCH, "Nonce does not match");
                }
            }

            String jti = claims.has("jti") ? claims.get("jti").asText() : "";
            long ttl = config.getMaxProofAgeSecs() + 5;
            if (!checkAndRecordJti(jti, ttl)) {
                throw new DPoPValidationException(
                        DPoPValidationException.REPLAY_DETECTED, "Proof replay detected");
            }

            return Thumbprint.computeFromJwk(
                    jwk.get("kty").asText(), jwk.get("crv").asText(),
                    jwk.get("x").asText(), jwk.get("y").asText());

        } catch (DPoPValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new DPoPValidationException(DPoPValidationException.INVALID_FORMAT,
                    "Failed to parse proof: " + e.getMessage(), e);
        }
    }

    /**
     * Verify that the proof's key matches the token's cnf.jkt claim.
     */
    public static void verifyBinding(String proofThumbprint, String tokenJkt) {
        if (!constantTimeEquals(proofThumbprint, tokenJkt)) {
            throw new DPoPValidationException(DPoPValidationException.THUMBPRINT_MISMATCH,
                    String.format("Token jkt=%s, proof jkt=%s", tokenJkt, proofThumbprint));
        }
    }

    private static ECPublicKey jwkToPublicKey(JsonNode jwk) throws Exception {
        String kty = jwk.has("kty") ? jwk.get("kty").asText() : null;
        String crv = jwk.has("crv") ? jwk.get("crv").asText() : null;

        if (!"EC".equals(kty) || !"P-256".equals(crv)) {
            throw new DPoPValidationException(DPoPValidationException.UNSUPPORTED_ALG,
                    String.format("Unsupported key: kty=%s, crv=%s", kty, crv));
        }

        byte[] xBytes = BASE64URL.decode(jwk.get("x").asText());
        byte[] yBytes = BASE64URL.decode(jwk.get("y").asText());

        if (xBytes.length != P256_COORDINATE_LEN || yBytes.length != P256_COORDINATE_LEN) {
            throw new DPoPValidationException(
                    DPoPValidationException.INVALID_KEY_PARAMS, "Invalid coordinate length");
        }

        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);

        ECPoint point = new ECPoint(x, y);
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return (ECPublicKey) keyFactory.generatePublic(pubSpec);
    }

    private static boolean checkAndRecordJti(String jti, long ttlSeconds) {
        synchronized (cacheLock) {
            long now = System.currentTimeMillis();
            if (now - lastCleanup > 300_000) {
                long currentTime = now;
                jtiCache.removeIf((k, v) -> v < currentTime);
                lastCleanup = now;
            }
            Long expiry = jtiCache.get(jti);
            if (expiry != null && expiry > now) {
                return false;
            }
            jtiCache.put(jti, now + (ttlSeconds * 1000));
            return true;
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
