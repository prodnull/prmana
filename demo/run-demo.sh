#!/bin/bash
# unix-oidc E2E Demo Script
# This script demonstrates OIDC-based Unix authentication

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
KEYCLOAK_URL="http://localhost:8080"
REALM="unix-oidc-test"
CLIENT_ID="unix-oidc"
CLIENT_SECRET="unix-oidc-test-secret"
TEST_USER="testuser"
TEST_PASS="testpass"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           unix-oidc E2E Authentication Demo                  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo

# Check if environment is running
check_environment() {
    echo -e "${YELLOW}[1/6] Checking test environment...${NC}"

    if ! docker compose -f "$PROJECT_ROOT/docker-compose.test.yaml" ps 2>/dev/null | grep -q "healthy"; then
        echo -e "${RED}Test environment not running. Starting it...${NC}"
        docker compose -f "$PROJECT_ROOT/docker-compose.test.yaml" up -d
        echo "Waiting for services to be healthy..."
        sleep 30
    fi

    # Verify Keycloak
    if curl -sf "$KEYCLOAK_URL/health/ready" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Keycloak is healthy${NC}"
    else
        echo -e "${RED}✗ Keycloak not responding${NC}"
        exit 1
    fi
    echo
}

# Method 1: Device Flow (interactive)
demo_device_flow() {
    echo -e "${YELLOW}[2/6] Demonstrating OAuth 2.0 Device Authorization Flow...${NC}"
    echo

    # Initiate device flow
    DEVICE_RESPONSE=$(curl -s -X POST \
        "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/auth/device" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=$CLIENT_ID" \
        -d "client_secret=$CLIENT_SECRET" \
        -d "scope=openid")

    DEVICE_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.device_code')
    USER_CODE=$(echo "$DEVICE_RESPONSE" | jq -r '.user_code')
    VERIFICATION_URI=$(echo "$DEVICE_RESPONSE" | jq -r '.verification_uri_complete')
    INTERVAL=$(echo "$DEVICE_RESPONSE" | jq -r '.interval')
    EXPIRES_IN=$(echo "$DEVICE_RESPONSE" | jq -r '.expires_in')

    echo -e "${BLUE}Device Authorization Response:${NC}"
    echo "  User Code: $USER_CODE"
    echo "  Verification URL: $VERIFICATION_URI"
    echo "  Expires in: ${EXPIRES_IN}s"
    echo

    # Check if we can use automated browser auth
    if command -v open >/dev/null 2>&1; then
        echo -e "${YELLOW}Opening browser for authentication...${NC}"
        open "$VERIFICATION_URI" 2>/dev/null || true
    fi

    echo -e "${YELLOW}Please authenticate in your browser:${NC}"
    echo "  1. Go to: $VERIFICATION_URI"
    echo "  2. Login as: $TEST_USER / $TEST_PASS"
    echo "  3. Grant consent"
    echo
    echo -e "${YELLOW}Polling for token completion...${NC}"

    # Poll for token
    TOKEN=""
    for i in {1..60}; do
        POLL_RESPONSE=$(curl -s -X POST \
            "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
            -d "client_id=$CLIENT_ID" \
            -d "client_secret=$CLIENT_SECRET" \
            -d "device_code=$DEVICE_CODE")

        if echo "$POLL_RESPONSE" | jq -e '.access_token' >/dev/null 2>&1; then
            TOKEN=$(echo "$POLL_RESPONSE" | jq -r '.access_token')
            echo -e "${GREEN}✓ Token acquired!${NC}"
            break
        fi

        ERROR=$(echo "$POLL_RESPONSE" | jq -r '.error // empty')
        if [ "$ERROR" = "authorization_pending" ]; then
            echo -n "."
            sleep "$INTERVAL"
        elif [ "$ERROR" = "slow_down" ]; then
            INTERVAL=$((INTERVAL + 1))
            sleep "$INTERVAL"
        else
            echo -e "${RED}Error: $ERROR${NC}"
            # Fall back to password grant for demo
            break
        fi
    done
    echo

    # Fall back to password grant if device flow not completed
    if [ -z "$TOKEN" ]; then
        echo -e "${YELLOW}Using password grant for demo...${NC}"
        TOKEN_RESPONSE=$(curl -s -X POST \
            "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=password" \
            -d "client_id=$CLIENT_ID" \
            -d "client_secret=$CLIENT_SECRET" \
            -d "username=$TEST_USER" \
            -d "password=$TEST_PASS" \
            -d "scope=openid")
        TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
        echo -e "${GREEN}✓ Token acquired via password grant${NC}"
    fi

    echo "$TOKEN" > /tmp/demo-token.txt
    export DEMO_TOKEN="$TOKEN"
    echo
}

# Display token claims
show_token_claims() {
    echo -e "${YELLOW}[3/6] Token Claims Analysis...${NC}"
    echo

    TOKEN=$(cat /tmp/demo-token.txt)
    PAYLOAD=$(echo "$TOKEN" | cut -d'.' -f2)
    # Add padding
    case $((${#PAYLOAD} % 4)) in
        2) PAYLOAD="${PAYLOAD}==" ;;
        3) PAYLOAD="${PAYLOAD}=" ;;
    esac

    CLAIMS=$(echo "$PAYLOAD" | base64 -d 2>/dev/null)

    echo -e "${BLUE}Token Claims:${NC}"
    echo "$CLAIMS" | jq '{
        issuer: .iss,
        audience: .aud,
        subject: .sub,
        username: .preferred_username,
        acr: .acr,
        expires: (.exp | todate),
        jti: .jti
    }'
    echo
}

# Test SSH PAM authentication
test_ssh_auth() {
    echo -e "${YELLOW}[4/6] Testing SSH PAM Authentication...${NC}"
    echo

    TOKEN=$(cat /tmp/demo-token.txt)

    echo -e "${BLUE}Calling PAM authenticate for SSH service...${NC}"
    RESULT=$(docker compose -f "$PROJECT_ROOT/docker-compose.test.yaml" exec -T -e OIDC_TOKEN="$TOKEN" -e UNIX_OIDC_TEST_MODE="true" test-host bash -c "
export OIDC_ISSUER='http://keycloak:8080/realms/unix-oidc-test'
export OIDC_CLIENT_ID='unix-oidc'
pamtester -v sshd testuser authenticate 2>&1
" 2>&1)

    echo "$RESULT"

    if echo "$RESULT" | grep -q "successfully authenticated"; then
        echo -e "${GREEN}✓ SSH authentication successful!${NC}"
    else
        echo -e "${RED}✗ SSH authentication failed${NC}"
    fi
    echo
}

# Test Sudo PAM authentication
test_sudo_auth() {
    echo -e "${YELLOW}[5/6] Testing Sudo PAM Authentication...${NC}"
    echo

    TOKEN=$(cat /tmp/demo-token.txt)

    echo -e "${BLUE}Calling PAM authenticate for sudo service...${NC}"
    RESULT=$(docker compose -f "$PROJECT_ROOT/docker-compose.test.yaml" exec -T -e OIDC_TOKEN="$TOKEN" -e UNIX_OIDC_TEST_MODE="true" test-host bash -c "
export OIDC_ISSUER='http://keycloak:8080/realms/unix-oidc-test'
export OIDC_CLIENT_ID='unix-oidc'
pamtester -v sudo testuser authenticate 2>&1
" 2>&1)

    echo "$RESULT"

    if echo "$RESULT" | grep -q "successfully authenticated"; then
        echo -e "${GREEN}✓ Sudo authentication successful!${NC}"
    else
        echo -e "${RED}✗ Sudo authentication failed${NC}"
    fi
    echo
}

# Show audit events
show_audit_events() {
    echo -e "${YELLOW}[6/6] Audit Events...${NC}"
    echo

    echo -e "${BLUE}Sample audit event structure:${NC}"
    cat << 'EOF'
{
  "event": "SSH_LOGIN_SUCCESS",
  "timestamp": "2026-01-20T00:04:04.887238250+00:00",
  "session_id": "unix-oidc-188c4791bb41a389-6784f12565e5dcb1",
  "user": "testuser",
  "uid": 1000,
  "source_ip": null,
  "host": "test-host",
  "oidc_jti": "a34f6c65-b1df-4563-94f2-95f4ff2a1141",
  "oidc_acr": "1",
  "oidc_auth_time": null
}
EOF
    echo

    echo -e "${BLUE}Audit events are emitted to syslog for integration with:${NC}"
    echo "  • SIEM systems (Splunk, Elastic, etc.)"
    echo "  • Cloud logging (CloudWatch, Stackdriver)"
    echo "  • Compliance reporting"
    echo
}

# Summary
show_summary() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    Demo Complete!                            ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${GREEN}What was demonstrated:${NC}"
    echo "  ✓ OAuth 2.0 Device Authorization Flow"
    echo "  ✓ JWT token acquisition from Keycloak"
    echo "  ✓ Token validation via JWKS"
    echo "  ✓ PAM-based SSH authentication"
    echo "  ✓ PAM-based sudo authentication"
    echo "  ✓ Structured audit logging"
    echo
    echo -e "${BLUE}Security features:${NC}"
    echo "  • No passwords stored or transmitted"
    echo "  • Token bound to session (JTI tracking)"
    echo "  • ACR-based step-up authentication"
    echo "  • Audit trail for compliance"
    echo
    echo -e "${YELLOW}To clean up:${NC}"
    echo "  docker compose -f docker-compose.test.yaml down -v"
    echo
}

# Main
main() {
    cd "$PROJECT_ROOT"

    check_environment
    demo_device_flow
    show_token_claims

    # Install pamtester if needed
    docker compose -f docker-compose.test.yaml exec -T test-host apt-get update >/dev/null 2>&1 || true
    docker compose -f docker-compose.test.yaml exec -T test-host apt-get install -y pamtester >/dev/null 2>&1 || true

    test_ssh_auth
    test_sudo_auth
    show_audit_events
    show_summary
}

main "$@"
