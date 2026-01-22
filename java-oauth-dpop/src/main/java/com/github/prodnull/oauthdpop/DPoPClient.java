package com.github.prodnull.oauthdpop;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * DPoP client for generating proofs.
 *
 * <p>Example usage:
 * <pre>{@code
 * DPoPClient client = DPoPClient.generate();
 * System.out.println("Thumbprint: " + client.getThumbprint());
 * String proof = client.createProof("POST", "https://api.example.com/token", null);
 * }</pre>
 */
public class DPoPClient {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

    private final KeyPair keyPair;
    private final String thumbprint;

    /**
     * Create a DPoP client from an existing key pair.
     *
     * @param keyPair an EC P-256 key pair
     */
    public DPoPClient(KeyPair keyPair) {
        this.keyPair = keyPair;
        this.thumbprint = Thumbprint.compute((ECPublicKey) keyPair.getPublic());
    }

    /**
     * Generate a new DPoP client with a random P-256 keypair.
     *
     * @return a new DPoPClient
     * @throws DPoPException if key generation fails
     */
    public static DPoPClient generate() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            return new DPoPClient(keyGen.generateKeyPair());
        } catch (Exception e) {
            throw new DPoPException("Failed to generate key pair", e);
        }
    }

    /**
     * Get the JWK thumbprint of this client's public key.
     *
     * @return the base64url-encoded thumbprint
     */
    public String getThumbprint() {
        return thumbprint;
    }

    /**
     * Get the public key.
     *
     * @return the EC public key
     */
    public ECPublicKey getPublicKey() {
        return (ECPublicKey) keyPair.getPublic();
    }

    /**
     * Create a DPoP proof for an HTTP request.
     *
     * @param method HTTP method (e.g., "GET", "POST")
     * @param target target URI
     * @param nonce  optional server-provided nonce
     * @return signed JWT proof
     * @throws DPoPException if proof creation fails
     */
    public String createProof(String method, String target, String nonce) {
        return createProofInternal(method, target, nonce, null);
    }

    /**
     * Create a DPoP proof with an access token hash.
     *
     * @param method      HTTP method
     * @param target      target URI
     * @param nonce       optional server-provided nonce
     * @param accessToken the access token to bind
     * @return signed JWT proof with ath claim
     * @throws DPoPException if proof creation fails
     */
    public String createProofWithAth(String method, String target, String nonce, String accessToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(accessToken.getBytes(StandardCharsets.UTF_8));
            String ath = BASE64URL.encodeToString(hash);
            return createProofInternal(method, target, nonce, ath);
        } catch (NoSuchAlgorithmException e) {
            throw new DPoPException("SHA-256 not available", e);
        }
    }

    private String createProofInternal(String method, String target, String nonce, String ath) {
        try {
            ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

            // Get coordinates (32 bytes each for P-256)
            byte[] xBytes = toUnsignedByteArray(publicKey.getW().getAffineX(), 32);
            byte[] yBytes = toUnsignedByteArray(publicKey.getW().getAffineY(), 32);
            String x = BASE64URL.encodeToString(xBytes);
            String y = BASE64URL.encodeToString(yBytes);

            // Build header
            ObjectNode jwk = MAPPER.createObjectNode()
                    .put("kty", "EC")
                    .put("crv", "P-256")
                    .put("x", x)
                    .put("y", y);

            ObjectNode header = MAPPER.createObjectNode()
                    .put("typ", "dpop+jwt")
                    .put("alg", "ES256")
                    .set("jwk", jwk);

            // Build claims
            ObjectNode claims = MAPPER.createObjectNode()
                    .put("jti", UUID.randomUUID().toString())
                    .put("htm", method)
                    .put("htu", target)
                    .put("iat", Instant.now().getEpochSecond());

            if (nonce != null) {
                claims.put("nonce", nonce);
            }
            if (ath != null) {
                claims.put("ath", ath);
            }

            // Encode
            String headerB64 = BASE64URL.encodeToString(MAPPER.writeValueAsBytes(header));
            String claimsB64 = BASE64URL.encodeToString(MAPPER.writeValueAsBytes(claims));
            String message = headerB64 + "." + claimsB64;

            // Sign with ES256
            Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
            sig.initSign(keyPair.getPrivate());
            sig.update(message.getBytes(StandardCharsets.UTF_8));
            byte[] signature = sig.sign();
            String sigB64 = BASE64URL.encodeToString(signature);

            return message + "." + sigB64;

        } catch (Exception e) {
            throw new DPoPException("Failed to create proof", e);
        }
    }

    /**
     * Convert a BigInteger to a fixed-length unsigned byte array.
     */
    private static byte[] toUnsignedByteArray(java.math.BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        } else if (bytes.length == length + 1 && bytes[0] == 0) {
            // Remove leading zero
            byte[] result = new byte[length];
            System.arraycopy(bytes, 1, result, 0, length);
            return result;
        } else if (bytes.length < length) {
            // Pad with leading zeros
            byte[] result = new byte[length];
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
            return result;
        } else {
            throw new IllegalArgumentException("Value too large for " + length + " bytes");
        }
    }
}
