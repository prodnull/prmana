"""JWK Thumbprint computation (RFC 7638)"""

import base64
import hashlib
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey


def compute_thumbprint(public_key: EllipticCurvePublicKey) -> str:
    """
    Compute JWK thumbprint for an EC P-256 public key per RFC 7638.

    Args:
        public_key: An EC P-256 public key

    Returns:
        Base64url-encoded thumbprint
    """
    numbers = public_key.public_numbers()
    x = _int_to_base64url(numbers.x, 32)
    y = _int_to_base64url(numbers.y, 32)
    return _compute_thumbprint_from_coordinates(x, y)


def compute_thumbprint_from_jwk(jwk: Dict[str, Any]) -> str:
    """
    Compute JWK thumbprint from a JWK dictionary.

    Args:
        jwk: JWK dictionary with kty, crv, x, y

    Returns:
        Base64url-encoded thumbprint
    """
    canonical = f'{{"crv":"{jwk["crv"]}","kty":"{jwk["kty"]}","x":"{jwk["x"]}","y":"{jwk["y"]}"}}'
    hash_bytes = hashlib.sha256(canonical.encode()).digest()
    return _base64url_encode(hash_bytes)


def _compute_thumbprint_from_coordinates(x: str, y: str) -> str:
    """Compute thumbprint from base64url-encoded coordinates."""
    canonical = f'{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}'
    hash_bytes = hashlib.sha256(canonical.encode()).digest()
    return _base64url_encode(hash_bytes)


def _int_to_base64url(value: int, length: int) -> str:
    """Convert an integer to base64url-encoded bytes of fixed length."""
    value_bytes = value.to_bytes(length, byteorder="big")
    return _base64url_encode(value_bytes)


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Base64url decode with padding handling."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)
