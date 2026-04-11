#!/bin/bash
# test/tests/test_keycloak_reachable.sh
set -e
curl -sf http://localhost:8080/realms/prmana-test/.well-known/openid-configuration > /dev/null
