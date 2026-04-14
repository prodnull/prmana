"""DPoP client for proof generation."""

import base64
import hashlib
import json
import time
import uuid
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePrivateKey,
    SECP256R1,
)

from .thumbprint import _base64url_encode, _int_to_base64url, compute_thumbprint


class DPoPClient:
    """
    DPoP client for generating proofs.

    Example:
        >>> client = DPoPClient.generate()
        >>> print(f"Thumbprint: {client.thumbprint}")
        >>> proof = client.create_proof("POST", "https://api.example.com/token")
    """

    def __init__(self, private_key: EllipticCurvePrivateKey):
        """
        Create a DPoP client from an existing private key.

        Args:
            private_key: An EC P-256 private key
        """
        self._private_key = private_key
        self._thumbprint = compute_thumbprint(private_key.public_key())

    @classmethod
    def generate(cls) -> "DPoPClient":
        """Generate a new DPoP client with a random P-256 keypair."""
        private_key = ec.generate_private_key(SECP256R1())
        return cls(private_key)

    @property
    def thumbprint(self) -> str:
        """Get the JWK thumbprint of this client's public key."""
        return self._thumbprint

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Get the public key."""
        return self._private_key.public_key()

    def create_proof(
        self,
        method: str,
        target: str,
        nonce: Optional[str] = None,
    ) -> str:
        """
        Create a DPoP proof for an HTTP request.

        Args:
            method: HTTP method (e.g., "GET", "POST")
            target: Target URI (e.g., "https://api.example.com/token")
            nonce: Optional server-provided nonce

        Returns:
            A signed JWT proof
        """
        return self._create_proof_internal(method, target, nonce, None)

    def create_proof_with_ath(
        self,
        method: str,
        target: str,
        access_token: str,
        nonce: Optional[str] = None,
    ) -> str:
        """
        Create a DPoP proof with an access token hash.

        Args:
            method: HTTP method
            target: Target URI
            access_token: The access token to bind
            nonce: Optional server-provided nonce

        Returns:
            A signed JWT proof with ath claim
        """
        hash_bytes = hashlib.sha256(access_token.encode()).digest()
        ath = _base64url_encode(hash_bytes)
        return self._create_proof_internal(method, target, nonce, ath)

    def _create_proof_internal(
        self,
        method: str,
        target: str,
        nonce: Optional[str],
        ath: Optional[str],
    ) -> str:
        """Internal proof generation."""
        public_key = self._private_key.public_key()
        numbers = public_key.public_numbers()

        x = _int_to_base64url(numbers.x, 32)
        y = _int_to_base64url(numbers.y, 32)

        # Build header
        header = {
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": y,
            },
        }

        # Build claims
        claims = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": target,
            "iat": int(time.time()),
        }
        if nonce is not None:
            claims["nonce"] = nonce
        if ath is not None:
            claims["ath"] = ath

        # Encode
        header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())
        claims_b64 = _base64url_encode(json.dumps(claims, separators=(",", ":")).encode())

        # Sign
        message = f"{header_b64}.{claims_b64}"
        signature = self._private_key.sign(message.encode(), ECDSA(hashes.SHA256()))

        # Convert DER signature to raw r||s format (64 bytes)
        sig_b64 = _base64url_encode(_der_to_raw_signature(signature))

        return f"{message}.{sig_b64}"


def _der_to_raw_signature(der_sig: bytes) -> bytes:
    """Convert DER-encoded ECDSA signature to raw r||s format."""
    # Parse DER: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
    if der_sig[0] != 0x30:
        raise ValueError("Invalid DER signature")

    idx = 2  # Skip 0x30 and length

    # Parse r
    if der_sig[idx] != 0x02:
        raise ValueError("Invalid DER signature")
    idx += 1
    r_len = der_sig[idx]
    idx += 1
    r = der_sig[idx : idx + r_len]
    idx += r_len

    # Parse s
    if der_sig[idx] != 0x02:
        raise ValueError("Invalid DER signature")
    idx += 1
    s_len = der_sig[idx]
    idx += 1
    s = der_sig[idx : idx + s_len]

    # Remove leading zeros and pad to 32 bytes
    r = r.lstrip(b"\x00").rjust(32, b"\x00")
    s = s.lstrip(b"\x00").rjust(32, b"\x00")

    return r + s
