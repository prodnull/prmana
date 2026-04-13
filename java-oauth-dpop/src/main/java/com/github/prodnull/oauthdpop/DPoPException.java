package com.github.prodnull.oauthdpop;

/**
 * Exception thrown when DPoP operations fail.
 */
public class DPoPException extends RuntimeException {
    public DPoPException(String message) {
        super(message);
    }

    public DPoPException(String message, Throwable cause) {
        super(message, cause);
    }
}
