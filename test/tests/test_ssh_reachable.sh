#!/bin/bash
# test/tests/test_ssh_reachable.sh
set -e
nc -z -w 5 localhost 2222
