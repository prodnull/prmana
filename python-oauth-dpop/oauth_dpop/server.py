"""Server-side DPoP proof validation (RFC 9449)."""

import base64
import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .thumbprint import _base64url_decode, _base64url_encode, compute_thumbprint_from_jwk


class DPoPValidationError(Exception):
    """DPoP validation error."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


# Error constants
INVALID_FORMAT = DPoPValidationError("INVALID_FORMAT", "Invalid proof format")
INVALID_HEADER = DPoPValidationError("INVALID_HEADER", "Invalid header")
INVALID_SIGNATURE = DPoPValidationError("INVALID_SIGNATURE", "Invalid signature")
MISSING_JWK = DPoPValidationError("MISSING_JWK", "Missing JWK in header")
UNSUPPORTED_ALG = DPoPValidationError("UNSUPPORTED_ALG", "Unsupported algorithm")
PROOF_EXPIRED = DPoPValidationError("PROOF_EXPIRED", "Proof expired")
METHOD_MISMATCH = DPoPValidationError("METHOD_MISMATCH", "Method mismatch")
TARGET_MISMATCH = DPoPValidationError("TARGET_MISMATCH", "Target mismatch")
NONCE_MISMATCH = DPoPValidationError("NONCE_MISMATCH", "Nonce mismatch")
MISSING_NONCE = DPoPValidationError("MISSING_NONCE", "Missing nonce")
REPLAY_DETECTED = DPoPValidationError("REPLAY_DETECTED", "Replay detected")
INVALID_KEY_PARAMS = DPoPValidationError("INVALID_KEY_PARAMS", "Invalid key parameters")
THUMBPRINT_MISMATCH = DPoPValidationError("THUMBPRINT_MISMATCH", "Thumbprint mismatch")


@dataclass
class DPoPConfig:
    """DPoP validation configuration."""

    max_proof_age_secs: int = 60
    require_nonce: bool = False
    expected_nonce: Optional[str] = None
    expected_method: str = "POST"
    expected_target: str = ""


# JTI cache for replay protection
_jti_cache: Dict[str, float] = {}
_jti_cache_lock = threading.Lock()
_last_cleanup = time.time()


def _check_and_record_jti(jti: str, ttl_seconds: int) -> bool:
    """Check if JTI is a replay and record it if not."""
    global _last_cleanup

    with _jti_cache_lock:
        now = time.time()

        # Maybe cleanup
        if now - _last_cleanup > 300:
            expired = [k for k, exp in _jti_cache.items() if exp < now]
            for k in expired:
                del _jti_cache[k]
            _last_cleanup = now

        # Check if exists
        if jti in _jti_cache and _jti_cache[jti] > now:
            return False  # Replay

        # Record
        _jti_cache[jti] = now + ttl_seconds
        return True


def _constant_time_eq(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a.encode(), b.encode())


def validate_proof(proof: str, config: DPoPConfig) -> str:
    """
    Validate a DPoP proof and return the JWK thumbprint.

    Args:
        proof: The DPoP proof JWT
        config: Validation configuration

    Returns:
        The JWK thumbprint on success

    Raises:
        DPoPValidationError: If validation fails
    """
    # Split proof
    parts = proof.split(".")
    if len(parts) != 3:
        raise DPoPValidationError("INVALID_FORMAT", "Proof must have 3 parts")

    # Decode header
    try:
        header_bytes = _base64url_decode(parts[0])
        header = json.loads(header_bytes)
    except Exception:
        raise DPoPValidationError("INVALID_HEADER", "Failed to decode header")

    # Verify typ
    if header.get("typ") != "dpop+jwt":
        raise DPoPValidationError("INVALID_HEADER", "typ must be dpop+jwt")

    # Verify alg
    alg = header.get("alg")
    if alg != "ES256":
        raise DPoPValidationError("UNSUPPORTED_ALG", f"Unsupported algorithm: {alg}")

    # Verify JWK present
    jwk = header.get("jwk")
    if not jwk:
        raise DPoPValidationError("MISSING_JWK", "Missing JWK in header")

    # Decode signature
    try:
        sig_bytes = _base64url_decode(parts[2])
    except Exception:
        raise DPoPValidationError("INVALID_SIGNATURE", "Failed to decode signature")

    # Convert JWK to public key
    try:
        public_key = _jwk_to_public_key(jwk)
    except Exception as e:
        raise DPoPValidationError("INVALID_KEY_PARAMS", str(e))

    # Verify signature
    message = f"{parts[0]}.{parts[1]}"
    try:
        # Convert raw signature to DER format for verification
        der_sig = _raw_to_der_signature(sig_bytes)
        public_key.verify(der_sig, message.encode(), ECDSA(hashes.SHA256()))
    except Exception:
        raise DPoPValidationError("INVALID_SIGNATURE", "Signature verification failed")

    # Decode claims
    try:
        claims_bytes = _base64url_decode(parts[1])
        claims = json.loads(claims_bytes)
    except Exception:
        raise DPoPValidationError("INVALID_FORMAT", "Failed to decode claims")

    # Validate iat
    now = int(time.time())
    iat = claims.get("iat", 0)
    if now - iat > config.max_proof_age_secs:
        raise DPoPValidationError("PROOF_EXPIRED", f"Proof expired: iat={iat}, now={now}")
    if iat > now + 5:
        raise DPoPValidationError("PROOF_EXPIRED", f"Proof from future: iat={iat}, now={now}")

    # Validate method
    if claims.get("htm") != config.expected_method:
        raise DPoPValidationError(
            "METHOD_MISMATCH",
            f"Expected {config.expected_method}, got {claims.get('htm')}",
        )

    # Validate target
    if claims.get("htu") != config.expected_target:
        raise DPoPValidationError(
            "TARGET_MISMATCH",
            f"Expected {config.expected_target}, got {claims.get('htu')}",
        )

    # Validate nonce
    if config.require_nonce:
        proof_nonce = claims.get("nonce")
        if proof_nonce is None:
            raise DPoPValidationError("MISSING_NONCE", "Nonce required but not provided")
        if config.expected_nonce and not _constant_time_eq(proof_nonce, config.expected_nonce):
            raise DPoPValidationError("NONCE_MISMATCH", "Nonce does not match")

    # JTI replay protection
    jti = claims.get("jti", "")
    ttl = config.max_proof_age_secs + 5
    if not _check_and_record_jti(jti, ttl):
        raise DPoPValidationError("REPLAY_DETECTED", "Proof replay detected")

    # Compute thumbprint
    return compute_thumbprint_from_jwk(jwk)


def verify_binding(proof_thumbprint: str, token_jkt: str) -> None:
    """
    Verify that the proof's key matches the token's cnf.jkt claim.

    Args:
        proof_thumbprint: Thumbprint from validate_proof
        token_jkt: The cnf.jkt claim from the access token

    Raises:
        DPoPValidationError: If thumbprints don't match
    """
    if not _constant_time_eq(proof_thumbprint, token_jkt):
        raise DPoPValidationError(
            "THUMBPRINT_MISMATCH",
            f"Token jkt={token_jkt}, proof jkt={proof_thumbprint}",
        )


def _jwk_to_public_key(jwk: Dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """Convert JWK to EC public key."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError(f"Unsupported key: kty={jwk.get('kty')}, crv={jwk.get('crv')}")

    x_bytes = _base64url_decode(jwk["x"])
    y_bytes = _base64url_decode(jwk["y"])

    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise ValueError("Invalid coordinate length")

    x = int.from_bytes(x_bytes, "big")
    y = int.from_bytes(y_bytes, "big")

    public_numbers = ec.EllipticCurvePublicNumbers(x, y, SECP256R1())
    return public_numbers.public_key()


def _raw_to_der_signature(raw_sig: bytes) -> bytes:
    """Convert raw r||s signature to DER format."""
    if len(raw_sig) != 64:
        raise ValueError("Raw signature must be 64 bytes")

    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")

    # Encode as DER
    def encode_int(val: int) -> bytes:
        val_bytes = val.to_bytes((val.bit_length() + 7) // 8, "big")
        # Add leading zero if high bit is set
        if val_bytes[0] & 0x80:
            val_bytes = b"\x00" + val_bytes
        return bytes([0x02, len(val_bytes)]) + val_bytes

    r_der = encode_int(r)
    s_der = encode_int(s)
    content = r_der + s_der

    return bytes([0x30, len(content)]) + content
