package com.github.prodnull.oauthdpop;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

/**
 * JWK Thumbprint computation per RFC 7638.
 */
public final class Thumbprint {
    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

    private Thumbprint() {
    }

    /**
     * Compute JWK thumbprint for an EC P-256 public key.
     *
     * @param publicKey the public key
     * @return base64url-encoded thumbprint
     */
    public static String compute(ECPublicKey publicKey) {
        byte[] xBytes = toUnsignedByteArray(publicKey.getW().getAffineX(), 32);
        byte[] yBytes = toUnsignedByteArray(publicKey.getW().getAffineY(), 32);

        String x = BASE64URL.encodeToString(xBytes);
        String y = BASE64URL.encodeToString(yBytes);

        return computeFromCoordinates(x, y);
    }

    /**
     * Compute JWK thumbprint from base64url-encoded coordinates.
     *
     * @param x base64url-encoded x coordinate
     * @param y base64url-encoded y coordinate
     * @return base64url-encoded thumbprint
     */
    public static String computeFromCoordinates(String x, String y) {
        // RFC 7638: canonical JSON with lexicographic member ordering
        // For EC P-256: crv < kty < x < y
        String canonical = String.format(
                "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}", x, y);

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
            return BASE64URL.encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new DPoPException("SHA-256 not available", e);
        }
    }

    /**
     * Compute JWK thumbprint from a JWK.
     *
     * @param kty key type
     * @param crv curve name
     * @param x   base64url-encoded x coordinate
     * @param y   base64url-encoded y coordinate
     * @return base64url-encoded thumbprint
     */
    public static String computeFromJwk(String kty, String crv, String x, String y) {
        // RFC 7638: canonical JSON with lexicographic member ordering
        String canonical = String.format(
                "{\"crv\":\"%s\",\"kty\":\"%s\",\"x\":\"%s\",\"y\":\"%s\"}", crv, kty, x, y);

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
            return BASE64URL.encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new DPoPException("SHA-256 not available", e);
        }
    }

    private static byte[] toUnsignedByteArray(java.math.BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        } else if (bytes.length == length + 1 && bytes[0] == 0) {
            byte[] result = new byte[length];
            System.arraycopy(bytes, 1, result, 0, length);
            return result;
        } else if (bytes.length < length) {
            byte[] result = new byte[length];
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
            return result;
        } else {
            throw new IllegalArgumentException("Value too large for " + length + " bytes");
        }
    }
}
