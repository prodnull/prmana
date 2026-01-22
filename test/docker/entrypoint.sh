#!/bin/bash
# test/docker/entrypoint.sh
set -e

echo "Starting unix-oidc test host..."

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
if [ -f /opt/unix-oidc/libpam_unix_oidc.so ]; then
    mkdir -p /lib/security
    cp /opt/unix-oidc/libpam_unix_oidc.so /lib/security/pam_unix_oidc.so
    cp /etc/pam.d/sshd.unix-oidc /etc/pam.d/sshd
    # Install sudo PAM config for step-up authentication
    if [ -f /etc/pam.d/sudo.unix-oidc ]; then
        cp /etc/pam.d/sudo.unix-oidc /etc/pam.d/sudo
    fi
    # Add testuser to sudoers (requires PAM auth for step-up demo)
    echo "testuser ALL=(ALL) ALL" >> /etc/sudoers.d/testuser
    chmod 440 /etc/sudoers.d/testuser
    echo "PAM module installed (SSH + sudo)"
fi

# Export OIDC configuration for PAM module
# Note: Using localhost because the test-host container accesses Keycloak via localhost mapped port
# For production, use internal DNS: http://keycloak:8080/realms/unix-oidc-test
export OIDC_ISSUER="${OIDC_ISSUER:-http://keycloak:8080/realms/unix-oidc-test}"
export OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-unix-oidc}"
echo "OIDC_ISSUER=$OIDC_ISSUER"

# Start SSH
echo "Starting SSH server..."
exec /usr/sbin/sshd -D
