#!/usr/bin/env python3
"""Cross-language DPoP test for Python."""

import json
import sys
from pathlib import Path

# Add parent directory to path for local import
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "python-oauth-dpop"))

from oauth_dpop import DPoPClient, DPoPConfig, validate_proof, verify_binding, DPoPValidationError

METHOD = "POST"
TARGET = "https://cross-test.example.com/token"


def generate(output_file: str):
    """Generate a proof and save to file."""
    client = DPoPClient.generate()
    proof = client.create_proof(METHOD, TARGET)

    data = {
        "proof": proof,
        "thumbprint": client.thumbprint,
        "method": METHOD,
        "target": TARGET,
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Generated proof: {output_file}")


def validate(input_file: str):
    """Validate a proof from file."""
    with open(input_file) as f:
        data = json.load(f)

    config = DPoPConfig(
        max_proof_age_secs=300,  # 5 minutes for cross-language tests
        require_nonce=False,
        expected_method=data["method"],
        expected_target=data["target"],
    )

    try:
        thumbprint = validate_proof(data["proof"], config)
        verify_binding(thumbprint, data["thumbprint"])
        print(f"PASS: {input_file} validated successfully")
        sys.exit(0)
    except DPoPValidationError as e:
        print(f"FAIL: {e.code}: {e.message}", file=sys.stderr)
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <generate|validate> [proof_file]", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]

    if command == "generate":
        output_file = sys.argv[2] if len(sys.argv) > 2 else "python_proof.json"
        generate(output_file)
    elif command == "validate":
        if len(sys.argv) < 3:
            print(f"Usage: {sys.argv[0]} validate <proof_file>", file=sys.stderr)
            sys.exit(1)
        validate(sys.argv[2])
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
