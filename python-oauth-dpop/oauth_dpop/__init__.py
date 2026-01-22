"""
OAuth DPoP - Demonstrating Proof of Possession (RFC 9449)

A Python implementation of OAuth 2.0 DPoP for sender-constraining tokens.
"""

from .client import DPoPClient
from .server import (
    DPoPConfig,
    DPoPValidationError,
    validate_proof,
    verify_binding,
)
from .thumbprint import compute_thumbprint, compute_thumbprint_from_jwk

__version__ = "0.1.0"
__all__ = [
    "DPoPClient",
    "DPoPConfig",
    "DPoPValidationError",
    "validate_proof",
    "verify_binding",
    "compute_thumbprint",
    "compute_thumbprint_from_jwk",
]
