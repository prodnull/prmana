package com.github.prodnull.oauthdpop;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class DPoPTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Decoder BASE64URL = Base64.getUrlDecoder();

    @Test
    void testClientGeneration() {
        DPoPClient client = DPoPClient.generate();
        assertNotNull(client.getThumbprint());
        assertEquals(43, client.getThumbprint().length()); // SHA-256 = 43 base64url chars
    }

    @Test
    void testProofFormat() {
        DPoPClient client = DPoPClient.generate();
        String proof = client.createProof("POST", "https://example.com/token", null);

        String[] parts = proof.split("\\.");
        assertEquals(3, parts.length);
    }

    @Test
    void testProofHeader() throws Exception {
        DPoPClient client = DPoPClient.generate();
        String proof = client.createProof("GET", "https://api.example.com/resource", null);

        String[] parts = proof.split("\\.");
        JsonNode header = MAPPER.readTree(BASE64URL.decode(parts[0]));

        assertEquals("dpop+jwt", header.get("typ").asText());
        assertEquals("ES256", header.get("alg").asText());
        assertEquals("EC", header.get("jwk").get("kty").asText());
        assertEquals("P-256", header.get("jwk").get("crv").asText());
    }

    @Test
    void testProofClaims() throws Exception {
        DPoPClient client = DPoPClient.generate();
        String proof = client.createProof("POST", "https://api.example.com/token", "server-nonce-123");

        String[] parts = proof.split("\\.");
        JsonNode claims = MAPPER.readTree(BASE64URL.decode(parts[1]));

        assertEquals("POST", claims.get("htm").asText());
        assertEquals("https://api.example.com/token", claims.get("htu").asText());
        assertEquals("server-nonce-123", claims.get("nonce").asText());
        assertNotNull(claims.get("jti").asText());
        assertTrue(claims.get("iat").asLong() > 0);
    }

    @Test
    void testUniqueJti() throws Exception {
        DPoPClient client = DPoPClient.generate();

        String proof1 = client.createProof("GET", "https://example.com", null);
        String proof2 = client.createProof("GET", "https://example.com", null);

        JsonNode claims1 = MAPPER.readTree(BASE64URL.decode(proof1.split("\\.")[1]));
        JsonNode claims2 = MAPPER.readTree(BASE64URL.decode(proof2.split("\\.")[1]));

        assertNotEquals(claims1.get("jti").asText(), claims2.get("jti").asText());
    }

    @Test
    void testProofWithAth() throws Exception {
        DPoPClient client = DPoPClient.generate();
        String accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";

        String proof = client.createProofWithAth("GET", "https://api.example.com/resource", null, accessToken);

        String[] parts = proof.split("\\.");
        JsonNode claims = MAPPER.readTree(BASE64URL.decode(parts[1]));

        assertNotNull(claims.get("ath"));
        assertEquals(43, claims.get("ath").asText().length()); // SHA-256 = 43 base64url chars
    }

    @Test
    void testValidateProof() {
        DPoPClient client = DPoPClient.generate();
        String proof = client.createProof("POST", "https://example.com/token", null);

        DPoPConfig config = DPoPConfig.builder()
                .maxProofAgeSecs(60)
                .expectedMethod("POST")
                .expectedTarget("https://example.com/token")
                .build();

        String thumbprint = DPoPValidator.validateProof(proof, config);
        assertEquals(client.getThumbprint(), thumbprint);
    }

    @Test
    void testValidateProofWithNonce() {
        DPoPClient client = DPoPClient.generate();
        String proof = client.createProof("POST", "https://example.com/token", "abc123");

        DPoPConfig config = DPoPConfig.builder()
                .maxProofAgeSecs(60)
                .requireNonce(true)
                .expectedNonce("abc123")
                .expectedMethod("POST")
                .expectedTarget("https://example.com/token")
                .build();

        String thumbprint = DPoPValidator.validateProof(proof, config);
        assertEquals(client.getThumbprint(), thumbprint);
    }

    @Test
    void testRejectWrongMethod() {
        DPoPClient client = DPoPClient.generate();
        String proof = client.createProof("GET", "https://example.com/token", null);

        DPoPConfig config = DPoPConfig.builder()
                .maxProofAgeSecs(60)
                .expectedMethod("POST")
                .expectedTarget("https://example.com/token")
                .build();

        DPoPValidationException ex = assertThrows(DPoPValidationException.class,
                () -> DPoPValidator.validateProof(proof, config));
        assertEquals(DPoPValidationException.METHOD_MISMATCH, ex.getCode());
    }

    @Test
    void testRejectWrongTarget() {
        DPoPClient client = DPoPClient.generate();
        String proof = client.createProof("POST", "https://other.com/token", null);

        DPoPConfig config = DPoPConfig.builder()
                .maxProofAgeSecs(60)
                .expectedMethod("POST")
                .expectedTarget("https://example.com/token")
                .build();

        DPoPValidationException ex = assertThrows(DPoPValidationException.class,
                () -> DPoPValidator.validateProof(proof, config));
        assertEquals(DPoPValidationException.TARGET_MISMATCH, ex.getCode());
    }

    @Test
    void testRejectWrongNonce() {
        DPoPClient client = DPoPClient.generate();
        String proof = client.createProof("POST", "https://example.com/token", "wrong");

        DPoPConfig config = DPoPConfig.builder()
                .maxProofAgeSecs(60)
                .requireNonce(true)
                .expectedNonce("correct")
                .expectedMethod("POST")
                .expectedTarget("https://example.com/token")
                .build();

        DPoPValidationException ex = assertThrows(DPoPValidationException.class,
                () -> DPoPValidator.validateProof(proof, config));
        assertEquals(DPoPValidationException.NONCE_MISMATCH, ex.getCode());
    }

    @Test
    void testVerifyBinding() {
        DPoPClient client = DPoPClient.generate();
        String proof = client.createProof("POST", "https://example.com/token", null);

        DPoPConfig config = DPoPConfig.builder()
                .maxProofAgeSecs(60)
                .expectedMethod("POST")
                .expectedTarget("https://example.com/token")
                .build();

        String proofThumbprint = DPoPValidator.validateProof(proof, config);

        // Should match
        assertDoesNotThrow(() -> DPoPValidator.verifyBinding(proofThumbprint, client.getThumbprint()));

        // Should not match
        DPoPValidationException ex = assertThrows(DPoPValidationException.class,
                () -> DPoPValidator.verifyBinding(proofThumbprint, "wrong-thumbprint"));
        assertEquals(DPoPValidationException.THUMBPRINT_MISMATCH, ex.getCode());
    }

    @Test
    void testReplayDetection() {
        DPoPClient client = DPoPClient.generate();
        String proof = client.createProof("POST", "https://replay-test.example.com/token", null);

        DPoPConfig config = DPoPConfig.builder()
                .maxProofAgeSecs(60)
                .expectedMethod("POST")
                .expectedTarget("https://replay-test.example.com/token")
                .build();

        // First use should succeed
        DPoPValidator.validateProof(proof, config);

        // Second use should be detected as replay
        DPoPValidationException ex = assertThrows(DPoPValidationException.class,
                () -> DPoPValidator.validateProof(proof, config));
        assertEquals(DPoPValidationException.REPLAY_DETECTED, ex.getCode());
    }

    @Test
    void testThumbprintDeterministic() {
        DPoPClient client = DPoPClient.generate();

        String thumb1 = Thumbprint.compute(client.getPublicKey());
        String thumb2 = Thumbprint.compute(client.getPublicKey());

        assertEquals(thumb1, thumb2);
    }

    @Test
    void testDifferentKeysDifferentThumbprints() {
        DPoPClient client1 = DPoPClient.generate();
        DPoPClient client2 = DPoPClient.generate();

        assertNotEquals(client1.getThumbprint(), client2.getThumbprint());
    }
}
