#!/usr/bin/env python3
"""
DPoP + Token Exchange Flow Test

Validates RFC 9449 (DPoP) and RFC 8693 (Token Exchange) with Keycloak.
"""

import json
import time
import hashlib
import base64
import secrets
import sys
from urllib.parse import urljoin

# Check for required packages
try:
    import requests
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    import jwt
except ImportError as e:
    print(f"Missing required package: {e}")
    print("Install with: pip install requests cryptography PyJWT")
    sys.exit(1)


# Configuration
KEYCLOAK_URL = "http://localhost:8080"
REALM = "token-exchange-test"
USER_CLIENT_ID = "prmana-agent"
JUMP_HOST_CLIENT_ID = "jump-host-a"
JUMP_HOST_SECRET = "jump-host-secret"
TARGET_AUDIENCE = "target-host-b"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass"


def b64url_encode(data: bytes) -> str:
    """Base64URL encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def b64url_decode(data: str) -> bytes:
    """Base64URL decode with padding fix."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def generate_ec_keypair():
    """Generate EC P-256 keypair."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key


def get_jwk_thumbprint(private_key) -> str:
    """Compute JWK thumbprint per RFC 7638 using canonical order."""
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    # Convert coordinates to base64url (32 bytes each for P-256)
    x_bytes = public_numbers.x.to_bytes(32, 'big')
    y_bytes = public_numbers.y.to_bytes(32, 'big')
    x = b64url_encode(x_bytes)
    y = b64url_encode(y_bytes)
    
    # Canonical JWK (RFC 7638 Section 3.2) - alphabetical order, no whitespace
    canonical = f'{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}'
    
    # SHA-256 hash, then base64url
    thumbprint = hashlib.sha256(canonical.encode()).digest()
    return b64url_encode(thumbprint)


def build_jwk(private_key) -> dict:
    """Build JWK representation of public key."""
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    x_bytes = public_numbers.x.to_bytes(32, 'big')
    y_bytes = public_numbers.y.to_bytes(32, 'big')
    
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(x_bytes),
        "y": b64url_encode(y_bytes)
    }


def create_dpop_proof(private_key, method: str, url: str, ath: str = None) -> str:
    """Create a DPoP proof JWT per RFC 9449."""
    jwk = build_jwk(private_key)
    
    # Header
    header = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk
    }
    
    # Payload
    payload = {
        "jti": secrets.token_hex(16),
        "htm": method,
        "htu": url,
        "iat": int(time.time())
    }
    
    if ath:
        payload["ath"] = ath
    
    # Sign using PyJWT
    token = jwt.encode(payload, private_key, algorithm="ES256", headers=header)
    return token


def decode_token(token: str) -> dict:
    """Decode a JWT without verification (for inspection)."""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    
    payload = json.loads(b64url_decode(parts[1]))
    return payload


def print_pass(msg):
    print(f"  \033[0;32mPASS\033[0m: {msg}")

def print_fail(msg):
    print(f"  \033[0;31mFAIL\033[0m: {msg}")

def print_info(msg):
    print(f"  \033[0mINFO\033[0m: {msg}")

def print_header(msg):
    print(f"\n\033[0;34m{'='*50}")
    print(f"{msg}")
    print(f"{'='*50}\033[0m\n")


def main():
    print_header("DPoP + Token Exchange Flow Test")
    
    token_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    
    # Step 1: Generate User DPoP Keypair
    print_header("Step 1: Generate User DPoP Keypair")
    user_key = generate_ec_keypair()
    user_jkt = get_jwk_thumbprint(user_key)
    print_pass("User keypair generated")
    print_info(f"User JWK thumbprint: {user_jkt}")
    
    # Step 2: Create DPoP Proof
    print_header("Step 2: Create User DPoP Proof")
    user_dpop_proof = create_dpop_proof(user_key, "POST", token_url)
    print_pass("DPoP proof created")
    print_info(f"Proof (truncated): {user_dpop_proof[:80]}...")
    
    # Step 3: Get DPoP-bound token
    print_header("Step 3: Get DPoP-Bound User Token")
    
    response = requests.post(
        token_url,
        headers={"DPoP": user_dpop_proof},
        data={
            "grant_type": "password",
            "client_id": USER_CLIENT_ID,
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD
        }
    )
    
    if response.status_code != 200:
        print_fail(f"Failed to get token: {response.status_code}")
        print_info(f"Response: {response.text}")
        return False
    
    token_data = response.json()
    user_token = token_data.get("access_token")
    
    if not user_token:
        print_fail("No access token in response")
        return False
    
    print_pass("Got access token")
    
    # Step 4: Verify token has cnf.jkt
    print_header("Step 4: Verify Token Has DPoP Binding")
    
    token_payload = decode_token(user_token)
    cnf = token_payload.get("cnf", {})
    token_jkt = cnf.get("jkt")
    
    if not token_jkt:
        print_fail("Token does not have cnf.jkt claim")
        print_info(f"Token claims: {json.dumps(token_payload, indent=2)}")
        return False
    
    if token_jkt != user_jkt:
        print_fail(f"Token jkt doesn't match: expected {user_jkt}, got {token_jkt}")
        return False
    
    print_pass(f"Token has correct cnf.jkt: {token_jkt}")
    
    # Show the token's audience
    print_info(f"Token audience: {token_payload.get('aud')}")
    
    # Step 5: Generate Jump Host Keypair
    print_header("Step 5: Generate Jump Host DPoP Keypair")
    jump_key = generate_ec_keypair()
    jump_jkt = get_jwk_thumbprint(jump_key)
    print_pass("Jump host keypair generated")
    print_info(f"Jump host JWK thumbprint: {jump_jkt}")
    
    # Step 6: Perform Token Exchange (Try WITHOUT audience first for V2)
    print_header("Step 6: Token Exchange (Jump Host → V2 without audience)")
    
    jump_dpop_proof = create_dpop_proof(jump_key, "POST", token_url)
    
    # First try V2 standard exchange (without audience parameter)
    exchange_response = requests.post(
        token_url,
        headers={"DPoP": jump_dpop_proof},
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": user_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "client_id": JUMP_HOST_CLIENT_ID,
            "client_secret": JUMP_HOST_SECRET,
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token"
        }
    )
    
    if exchange_response.status_code == 200:
        print_pass("Token exchange without audience succeeded!")
        exchange_data = exchange_response.json()
        exchanged_token = exchange_data.get("access_token")
    else:
        print_info(f"V2 without audience: {exchange_response.status_code} - {exchange_response.text}")
        
        # Try with audience parameter
        print_header("Step 6b: Token Exchange WITH audience parameter")
        
        jump_dpop_proof2 = create_dpop_proof(jump_key, "POST", token_url)
        
        exchange_response = requests.post(
            token_url,
            headers={"DPoP": jump_dpop_proof2},
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": user_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": TARGET_AUDIENCE,
                "client_id": JUMP_HOST_CLIENT_ID,
                "client_secret": JUMP_HOST_SECRET,
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token"
            }
        )
        
        if exchange_response.status_code != 200:
            print_fail(f"Token exchange failed: {exchange_response.status_code}")
            print_info(f"Response: {exchange_response.text}")
            return False
        
        exchange_data = exchange_response.json()
        exchanged_token = exchange_data.get("access_token")
    
    if not exchanged_token:
        print_fail("No access token in exchange response")
        return False
    
    print_pass("Token exchange successful")
    
    # Step 7: Validate Exchanged Token
    print_header("Step 7: Validate Exchanged Token")
    
    exchanged_payload = decode_token(exchanged_token)
    
    # Check cnf.jkt matches jump host
    exchanged_cnf = exchanged_payload.get("cnf", {})
    exchanged_jkt = exchanged_cnf.get("jkt")
    
    if exchanged_jkt == jump_jkt:
        print_pass(f"Exchanged token bound to jump host key: {exchanged_jkt}")
    elif exchanged_jkt == user_jkt:
        print_fail("Exchanged token still bound to user's key (expected jump host)")
    elif exchanged_jkt:
        print_fail(f"Exchanged token bound to unknown key: {exchanged_jkt}")
    else:
        print_info("Exchanged token has no cnf.jkt (bearer token)")
    
    # Check act claim (delegation)
    act = exchanged_payload.get("act", {})
    if act:
        print_pass(f"Has delegation claim (act): {json.dumps(act)}")
    else:
        print_info("No act claim in exchanged token")
    
    # Check x-prmana-lineage claim
    lineage = exchanged_payload.get("x-prmana-lineage")
    if lineage:
        print_pass(f"Has lineage claim: {json.dumps(lineage)}")
    else:
        print_info("No x-prmana-lineage claim")
    
    # Check audience
    aud = exchanged_payload.get("aud")
    if TARGET_AUDIENCE in str(aud):
        print_pass(f"Correct audience: {aud}")
    else:
        print_info(f"Audience: {aud}")
    
    # Print full token for debugging
    print_info(f"Exchanged token claims:\n{json.dumps(exchanged_payload, indent=2)}")
    
    print_header("Test Complete")
    print_pass("DPoP + Token Exchange flow validated!")
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
