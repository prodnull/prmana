#!/bin/bash
# test/tests/test_keycloak_reachable.sh
set -e
curl -sf http://localhost:8080/realms/unix-oidc-test/.well-known/openid-configuration > /dev/null
