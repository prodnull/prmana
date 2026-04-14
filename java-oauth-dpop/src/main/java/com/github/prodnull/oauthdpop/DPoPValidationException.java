package com.github.prodnull.oauthdpop;

/**
 * Exception thrown when DPoP proof validation fails.
 */
public class DPoPValidationException extends DPoPException {
    private final String code;

    public DPoPValidationException(String code, String message) {
        super(message);
        this.code = code;
    }

    public DPoPValidationException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    /**
     * Get the error code.
     *
     * @return error code (e.g., "INVALID_FORMAT", "REPLAY_DETECTED")
     */
    public String getCode() {
        return code;
    }

    // Common error codes
    public static final String INVALID_FORMAT = "INVALID_FORMAT";
    public static final String INVALID_HEADER = "INVALID_HEADER";
    public static final String INVALID_SIGNATURE = "INVALID_SIGNATURE";
    public static final String MISSING_JWK = "MISSING_JWK";
    public static final String UNSUPPORTED_ALG = "UNSUPPORTED_ALG";
    public static final String PROOF_EXPIRED = "PROOF_EXPIRED";
    public static final String METHOD_MISMATCH = "METHOD_MISMATCH";
    public static final String TARGET_MISMATCH = "TARGET_MISMATCH";
    public static final String NONCE_MISMATCH = "NONCE_MISMATCH";
    public static final String MISSING_NONCE = "MISSING_NONCE";
    public static final String REPLAY_DETECTED = "REPLAY_DETECTED";
    public static final String INVALID_KEY_PARAMS = "INVALID_KEY_PARAMS";
    public static final String THUMBPRINT_MISMATCH = "THUMBPRINT_MISMATCH";
}
