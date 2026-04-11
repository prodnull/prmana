#!/bin/bash
# test/docker/entrypoint-e2e.sh
# E2E test-host entrypoint — NO TEST_MODE.
set -e

echo "Starting prmana E2E test host (real signature verification)..."

# INFR-03: Sentinel — verify TEST_MODE is NOT set.
if [ -n "${PRMANA_TEST_MODE:-}" ]; then
    echo "FATAL: PRMANA_TEST_MODE is set in E2E environment. This bypasses signature verification."
    echo "E2E tests MUST use real OIDC signature verification. Aborting."
    exit 1
fi

# Wait for LDAP to be ready (with timeout)
MAX_RETRIES=30
RETRY_COUNT=0
until ldapsearch -x -H "$LDAP_URI" -b "$LDAP_BASE" -D "cn=admin,$LDAP_BASE" -w admin > /dev/null 2>&1; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "ERROR: LDAP not available after $MAX_RETRIES attempts"
        exit 1
    fi
    echo "Waiting for LDAP... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 2
done
echo "LDAP is ready"

# Update SSSD config with environment variables
sed -i "s|LDAP_URI|$LDAP_URI|g" /etc/sssd/sssd.conf
sed -i "s|LDAP_BASE|$LDAP_BASE|g" /etc/sssd/sssd.conf

# Start SSSD
sssd -D 2>/dev/null || echo "SSSD started (or already running)"

# Install PAM module if present
if [ -f /opt/prmana/libpam_prmana.so ]; then
    mkdir -p /lib/security
    cp /opt/prmana/libpam_prmana.so /lib/security/pam_prmana.so
    cp /etc/pam.d/sshd.prmana /etc/pam.d/sshd
    if [ -f /etc/pam.d/sudo.prmana ]; then
        cp /etc/pam.d/sudo.prmana /etc/pam.d/sudo
    fi
    echo "testuser ALL=(ALL) ALL" >> /etc/sudoers.d/testuser
    chmod 440 /etc/sudoers.d/testuser
    echo "PAM module installed (SSH + sudo)"
fi

# BFIX-02: Install agent binary on PATH inside the container.
if [ -f /opt/prmana/prmana-agent ]; then
    cp /opt/prmana/prmana-agent /usr/local/bin/prmana-agent
    chmod +x /usr/local/bin/prmana-agent
    echo "prmana-agent installed: $(prmana-agent --version 2>/dev/null || echo 'binary present')"
else
    echo "WARNING: prmana-agent binary not found in /opt/prmana/"
fi

# Create session directory for session lifecycle management
mkdir -p /run/prmana/sessions
chmod 700 /run/prmana

# Export OIDC configuration for PAM module (no TEST_MODE)
export OIDC_ISSUER="${OIDC_ISSUER:-http://localhost:8080/realms/prmana}"
export OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-prmana}"
echo "OIDC_ISSUER=$OIDC_ISSUER"
echo "TEST_MODE: NOT SET (real signature verification)"

# Proxy localhost:8080 → keycloak:8080 so the PAM module can fetch JWKS
# from the issuer URL (http://localhost:8080/...) inside this container.
# KC_HOSTNAME=localhost means token iss = http://localhost:8080/realms/prmana,
# and the PAM module derives the JWKS URL from the issuer.
echo "Starting socat proxy: localhost:8080 → keycloak:8080..."
socat TCP-LISTEN:8080,fork,reuseaddr TCP:keycloak:8080 &

# Start SSH
echo "Starting SSH server..."
exec /usr/sbin/sshd -D
