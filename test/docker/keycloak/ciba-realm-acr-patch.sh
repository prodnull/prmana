#!/usr/bin/env bash
# test/docker/keycloak/ciba-realm-acr-patch.sh
#
# Patch the ciba-test Keycloak realm to add FIDO2 ACR simulation via
# Level-of-Assurance (LoA) mapping.
#
# Purpose: Real FIDO2 hardware is not required in CI. Keycloak LoA levels
# are assigned to phr/phrh ACR values to simulate phishing-resistant and
# hardware-bound authentication for automated testing. The test validates
# ACR claim presence and value, not the underlying authenticator.
#
# ACR mapping:
#   phr  -> LoA 3  (phishing-resistant, simulates FIDO2 AAL3)
#            URI: http://schemas.openid.net/pape/policies/2007/06/phishing-resistant
#   phrh -> LoA 4  (hardware-bound, simulates hardware FIDO2)
#            URI: http://schemas.openid.net/acr/2016/07/phishing-resistant-hardware
#   mfa  -> LoA 2  (standard MFA)
#
# The realm JSON at test/fixtures/keycloak/ciba-test-realm.json already
# includes this mapping under "attributes"."acr.loa.map". This script
# provides a runtime patch path for environments where the realm was
# imported without the LoA mapping (e.g., an older deployment).
#
# Usage: bash test/docker/keycloak/ciba-realm-acr-patch.sh
# Dependencies: curl, jq
# Environment:
#   KEYCLOAK_URL           - defaults to http://localhost:8080
#   KEYCLOAK_ADMIN         - defaults to admin
#   KEYCLOAK_ADMIN_PASSWORD - defaults to admin

set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASS="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM="ciba-test"

echo "Patching realm '${REALM}' at ${KEYCLOAK_URL} with FIDO2 ACR LoA mapping..."

# Obtain master realm admin token
ADMIN_TOKEN=$(curl -sf -X POST \
    "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=${ADMIN_USER}" \
    -d "password=${ADMIN_PASS}" \
    | jq -r '.access_token')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
    echo "ERROR: Failed to obtain admin token from Keycloak at ${KEYCLOAK_URL}" >&2
    exit 1
fi

# Patch realm attributes with ACR LoA mapping
# Keycloak 26.x encodes the mapping as a JSON string within the attributes object.
#   phr  = LoA 3 (phishing-resistant; OpenID EAP ACR Values 1.0 §2.1)
#   phrh = LoA 4 (phishing-resistant hardware; OpenID EAP ACR Values 1.0 §2.2)
#   mfa  = LoA 2 (standard MFA)
HTTP_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X PUT "${KEYCLOAK_URL}/admin/realms/${REALM}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "attributes": {
            "acr.loa.map": "{\"phr\":\"3\",\"phrh\":\"4\",\"mfa\":\"2\",\"default\":\"1\"}",
            "cibaBackchannelTokenDeliveryMode": "poll",
            "cibaAuthRequestedUserHint": "login_hint",
            "cibaInterval": "5",
            "cibaExpiresIn": "120"
        }
    }')

if [ "$HTTP_STATUS" = "204" ] || [ "$HTTP_STATUS" = "200" ]; then
    echo "Realm '${REALM}' patched successfully (HTTP ${HTTP_STATUS})"
    echo "ACR LoA mapping: phr=3 (FIDO2 phishing-resistant), phrh=4 (FIDO2 hardware-bound), mfa=2"
else
    echo "ERROR: Realm patch returned HTTP ${HTTP_STATUS}" >&2
    exit 1
fi
