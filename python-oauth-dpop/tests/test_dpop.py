"""Tests for oauth_dpop package."""

import base64
import json

import pytest

from oauth_dpop import (
    DPoPClient,
    DPoPConfig,
    DPoPValidationError,
    compute_thumbprint,
    validate_proof,
    verify_binding,
)


class TestClient:
    """Tests for DPoPClient."""

    def test_generate(self):
        """Test client generation."""
        client = DPoPClient.generate()
        assert client.thumbprint
        # SHA-256 = 32 bytes = 43 base64url chars
        assert len(client.thumbprint) == 43

    def test_create_proof_format(self):
        """Test proof has correct JWT format."""
        client = DPoPClient.generate()
        proof = client.create_proof("POST", "https://example.com/token")

        parts = proof.split(".")
        assert len(parts) == 3

    def test_proof_header(self):
        """Test proof contains correct header."""
        client = DPoPClient.generate()
        proof = client.create_proof("GET", "https://api.example.com/resource")

        parts = proof.split(".")
        header_bytes = _base64url_decode(parts[0])
        header = json.loads(header_bytes)

        assert header["typ"] == "dpop+jwt"
        assert header["alg"] == "ES256"
        assert header["jwk"]["kty"] == "EC"
        assert header["jwk"]["crv"] == "P-256"

    def test_proof_claims(self):
        """Test proof contains correct claims."""
        client = DPoPClient.generate()
        proof = client.create_proof(
            "POST",
            "https://api.example.com/token",
            nonce="server-nonce-123",
        )

        parts = proof.split(".")
        claims_bytes = _base64url_decode(parts[1])
        claims = json.loads(claims_bytes)

        assert claims["htm"] == "POST"
        assert claims["htu"] == "https://api.example.com/token"
        assert claims["nonce"] == "server-nonce-123"
        assert claims["jti"]
        assert claims["iat"] > 0

    def test_unique_jti(self):
        """Test each proof has unique JTI."""
        client = DPoPClient.generate()

        proof1 = client.create_proof("GET", "https://example.com")
        proof2 = client.create_proof("GET", "https://example.com")

        claims1 = _decode_claims(proof1)
        claims2 = _decode_claims(proof2)

        assert claims1["jti"] != claims2["jti"]

    def test_proof_with_ath(self):
        """Test proof with access token hash."""
        client = DPoPClient.generate()
        access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"

        proof = client.create_proof_with_ath(
            "GET",
            "https://api.example.com/resource",
            access_token,
        )

        claims = _decode_claims(proof)
        assert claims["ath"]
        # SHA-256 = 43 base64url chars
        assert len(claims["ath"]) == 43


class TestServer:
    """Tests for server-side validation."""

    def test_validate_proof(self):
        """Test successful proof validation."""
        client = DPoPClient.generate()
        proof = client.create_proof("POST", "https://example.com/token")

        config = DPoPConfig(
            max_proof_age_secs=60,
            expected_method="POST",
            expected_target="https://example.com/token",
        )

        thumbprint = validate_proof(proof, config)
        assert thumbprint == client.thumbprint

    def test_validate_proof_with_nonce(self):
        """Test validation with nonce."""
        client = DPoPClient.generate()
        proof = client.create_proof("POST", "https://example.com/token", nonce="abc123")

        config = DPoPConfig(
            max_proof_age_secs=60,
            require_nonce=True,
            expected_nonce="abc123",
            expected_method="POST",
            expected_target="https://example.com/token",
        )

        thumbprint = validate_proof(proof, config)
        assert thumbprint == client.thumbprint

    def test_reject_wrong_method(self):
        """Test rejection of wrong method."""
        client = DPoPClient.generate()
        proof = client.create_proof("GET", "https://example.com/token")

        config = DPoPConfig(
            max_proof_age_secs=60,
            expected_method="POST",
            expected_target="https://example.com/token",
        )

        with pytest.raises(DPoPValidationError) as exc:
            validate_proof(proof, config)
        assert exc.value.code == "METHOD_MISMATCH"

    def test_reject_wrong_target(self):
        """Test rejection of wrong target."""
        client = DPoPClient.generate()
        proof = client.create_proof("POST", "https://other.com/token")

        config = DPoPConfig(
            max_proof_age_secs=60,
            expected_method="POST",
            expected_target="https://example.com/token",
        )

        with pytest.raises(DPoPValidationError) as exc:
            validate_proof(proof, config)
        assert exc.value.code == "TARGET_MISMATCH"

    def test_reject_wrong_nonce(self):
        """Test rejection of wrong nonce."""
        client = DPoPClient.generate()
        proof = client.create_proof("POST", "https://example.com/token", nonce="wrong")

        config = DPoPConfig(
            max_proof_age_secs=60,
            require_nonce=True,
            expected_nonce="correct",
            expected_method="POST",
            expected_target="https://example.com/token",
        )

        with pytest.raises(DPoPValidationError) as exc:
            validate_proof(proof, config)
        assert exc.value.code == "NONCE_MISMATCH"

    def test_verify_binding(self):
        """Test binding verification."""
        client = DPoPClient.generate()
        proof = client.create_proof("POST", "https://example.com/token")

        config = DPoPConfig(
            max_proof_age_secs=60,
            expected_method="POST",
            expected_target="https://example.com/token",
        )

        proof_thumbprint = validate_proof(proof, config)

        # Should match
        verify_binding(proof_thumbprint, client.thumbprint)

        # Should not match
        with pytest.raises(DPoPValidationError) as exc:
            verify_binding(proof_thumbprint, "wrong-thumbprint")
        assert exc.value.code == "THUMBPRINT_MISMATCH"

    def test_replay_detection(self):
        """Test replay detection."""
        client = DPoPClient.generate()
        proof = client.create_proof("POST", "https://replay-test.example.com/token")

        config = DPoPConfig(
            max_proof_age_secs=60,
            expected_method="POST",
            expected_target="https://replay-test.example.com/token",
        )

        # First use should succeed
        validate_proof(proof, config)

        # Second use should be detected as replay
        with pytest.raises(DPoPValidationError) as exc:
            validate_proof(proof, config)
        assert exc.value.code == "REPLAY_DETECTED"


class TestThumbprint:
    """Tests for thumbprint computation."""

    def test_thumbprint_is_deterministic(self):
        """Test thumbprint is deterministic for same key."""
        client = DPoPClient.generate()

        thumb1 = compute_thumbprint(client.public_key)
        thumb2 = compute_thumbprint(client.public_key)

        assert thumb1 == thumb2

    def test_different_keys_different_thumbprints(self):
        """Test different keys have different thumbprints."""
        client1 = DPoPClient.generate()
        client2 = DPoPClient.generate()

        assert client1.thumbprint != client2.thumbprint


# Helper functions
def _base64url_decode(data: str) -> bytes:
    """Base64url decode with padding handling."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _decode_claims(proof: str) -> dict:
    """Decode claims from a proof."""
    parts = proof.split(".")
    claims_bytes = _base64url_decode(parts[1])
    return json.loads(claims_bytes)
