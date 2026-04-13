#!/bin/bash
# test/scripts/wait-for-healthy-e2e.sh
# Wait for E2E Docker Compose services to become healthy.
# Wraps wait-for-healthy.sh with E2E-specific defaults.

set -e

export COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.e2e.yaml}"
export MAX_WAIT="${MAX_WAIT:-240}"

# E2E stack services
SERVICES="${*:-keycloak openldap test-host-e2e}"

exec "$(dirname "$0")/wait-for-healthy.sh" $SERVICES
