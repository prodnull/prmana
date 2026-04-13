#!/bin/bash
# test/tests/test_get_token.sh
# Test that we can get a valid OIDC token from Keycloak
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOKEN=$("$SCRIPT_DIR/../scripts/get-test-token.sh" testuser testpass)

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "Failed to get token"
    exit 1
fi

# Verify it's a JWT (three parts separated by dots)
if [[ ! "$TOKEN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
    echo "Token doesn't look like a JWT"
    exit 1
fi

echo "Got valid token"
