#!/bin/bash
# test/tests/test_sssd_user.sh
set -e
docker compose -f docker-compose.test.yaml exec -T test-host id testuser
