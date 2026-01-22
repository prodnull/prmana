#!/bin/bash
# test/tests/test_ldap_reachable.sh
set -e
ldapsearch -x -H ldap://localhost:389 -b "dc=test,dc=local" -D "cn=admin,dc=test,dc=local" -w admin "(uid=testuser)" > /dev/null
