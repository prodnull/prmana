#!/bin/bash
# test/scripts/wait-for-healthy.sh
# Wait for Docker Compose services to become healthy
#
# Usage:
#   ./wait-for-healthy.sh              # Wait for all services
#   ./wait-for-healthy.sh keycloak     # Wait for keycloak only
#   ./wait-for-healthy.sh keycloak openldap  # Wait for specific services

set -e

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.test.yaml}"
MAX_WAIT="${MAX_WAIT:-180}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"

# If no services specified, wait for all defined services
if [ $# -eq 0 ]; then
    SERVICES="keycloak openldap test-host"
else
    SERVICES="$*"
fi

echo "Waiting for services to be healthy: $SERVICES"
echo "Compose file: $COMPOSE_FILE"
echo "Max wait: ${MAX_WAIT}s"

WAITED=0

check_service_health() {
    local service=$1
    # Check if service is healthy using docker compose ps
    docker compose -f "$COMPOSE_FILE" ps "$service" 2>/dev/null | grep -q "(healthy)" && return 0
    return 1
}

get_service_status() {
    local service=$1
    local status
    status=$(docker compose -f "$COMPOSE_FILE" ps "$service" 2>/dev/null | tail -n +2 | awk '{print $NF}' || echo "unknown")
    echo "$status"
}

while [ $WAITED -lt $MAX_WAIT ]; do
    ALL_HEALTHY=true
    STATUS_LINE=""

    for service in $SERVICES; do
        if check_service_health "$service"; then
            STATUS_LINE="$STATUS_LINE $service:✓"
        else
            ALL_HEALTHY=false
            status=$(get_service_status "$service")
            STATUS_LINE="$STATUS_LINE $service:$status"
        fi
    done

    if [ "$ALL_HEALTHY" = true ]; then
        echo ""
        echo "All services healthy!$STATUS_LINE"
        exit 0
    fi

    printf "\rWaiting (%3ds/%3ds)...%s" "$WAITED" "$MAX_WAIT" "$STATUS_LINE"
    sleep "$POLL_INTERVAL"
    WAITED=$((WAITED + POLL_INTERVAL))
done

echo ""
echo "ERROR: Timeout waiting for services after ${MAX_WAIT}s"
echo ""
echo "=== Service Status ==="
docker compose -f "$COMPOSE_FILE" ps
echo ""
echo "=== Service Logs ==="
for service in $SERVICES; do
    echo "--- $service ---"
    docker compose -f "$COMPOSE_FILE" logs --tail=50 "$service" 2>/dev/null || echo "No logs available"
done
exit 1
