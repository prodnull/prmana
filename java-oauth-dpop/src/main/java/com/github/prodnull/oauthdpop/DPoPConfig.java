package com.github.prodnull.oauthdpop;

/**
 * Configuration for DPoP proof validation.
 */
public class DPoPConfig {
    private final long maxProofAgeSecs;
    private final boolean requireNonce;
    private final String expectedNonce;
    private final String expectedMethod;
    private final String expectedTarget;

    private DPoPConfig(Builder builder) {
        this.maxProofAgeSecs = builder.maxProofAgeSecs;
        this.requireNonce = builder.requireNonce;
        this.expectedNonce = builder.expectedNonce;
        this.expectedMethod = builder.expectedMethod;
        this.expectedTarget = builder.expectedTarget;
    }

    public long getMaxProofAgeSecs() {
        return maxProofAgeSecs;
    }

    public boolean isRequireNonce() {
        return requireNonce;
    }

    public String getExpectedNonce() {
        return expectedNonce;
    }

    public String getExpectedMethod() {
        return expectedMethod;
    }

    public String getExpectedTarget() {
        return expectedTarget;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private long maxProofAgeSecs = 60;
        private boolean requireNonce = false;
        private String expectedNonce = null;
        private String expectedMethod = "POST";
        private String expectedTarget = "";

        public Builder maxProofAgeSecs(long maxProofAgeSecs) {
            this.maxProofAgeSecs = maxProofAgeSecs;
            return this;
        }

        public Builder requireNonce(boolean requireNonce) {
            this.requireNonce = requireNonce;
            return this;
        }

        public Builder expectedNonce(String expectedNonce) {
            this.expectedNonce = expectedNonce;
            return this;
        }

        public Builder expectedMethod(String expectedMethod) {
            this.expectedMethod = expectedMethod;
            return this;
        }

        public Builder expectedTarget(String expectedTarget) {
            this.expectedTarget = expectedTarget;
            return this;
        }

        public DPoPConfig build() {
            return new DPoPConfig(this);
        }
    }
}
