# Testing Guide

This guide covers how to test unix-oidc at various levels: unit tests, integration tests, and end-to-end tests.

## Quick Reference

```bash
# Unit tests
cargo test

# Start test environment
make dev-up

# Run integration tests
make test-integration

# Stop test environment
make dev-down
```

## Test Environment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Test Environment                          │
├─────────────────┬─────────────────┬─────────────────────────┤
│    Keycloak     │    OpenLDAP     │      Test Host          │
│    (IdP)        │    (Directory)  │   (SSH + PAM)           │
│    :8080        │    :389         │   :2222                 │
└─────────────────┴─────────────────┴─────────────────────────┘
```

**Components:**
- **Keycloak** - OIDC Identity Provider with test realm
- **OpenLDAP** - User directory (testuser, adminuser)
- **Test Host** - Ubuntu container with SSH, PAM, SSSD

## Unit Tests

Unit tests are in the Rust codebase and test individual components in isolation.

### Running Unit Tests

```bash
# Run all unit tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test policy::

# Run specific test
cargo test test_validate_valid_token
```

### Test Coverage

| Module | Coverage | Description |
|--------|----------|-------------|
| `oidc::token` | Token parsing, claims extraction |
| `oidc::validation` | Token validation (issuer, expiry, ACR, auth_time) |
| `policy::config` | YAML policy parsing, command matching |
| `policy::rules` | Policy evaluation, step-up requirements |
| `device_flow` | Device flow client, error handling |
| `sssd` | User resolution via NSS |
| `audit` | Audit event serialization |
| `sudo` | Sudo context, session ID generation |

## Integration Tests

Integration tests verify components work together with real services.

### Starting the Test Environment

```bash
# Start all services
make dev-up
# Or directly:
docker compose -f docker-compose.test.yaml up -d

# Wait for services to be healthy
./test/scripts/wait-for-healthy.sh

# View service status
docker compose -f docker-compose.test.yaml ps
```

### Running Integration Tests

```bash
# Run all integration tests
make test-integration
# Or directly:
./test/scripts/run-integration-tests.sh
```

### Individual Tests

| Test | Script | Description |
|------|--------|-------------|
| Keycloak reachable | `test_keycloak_reachable.sh` | Verify Keycloak is responding |
| LDAP reachable | `test_ldap_reachable.sh` | Verify OpenLDAP is responding |
| SSH reachable | `test_ssh_reachable.sh` | Verify SSH server is up |
| SSSD user resolution | `test_sssd_user.sh` | Verify testuser exists via SSSD |
| Get OIDC token | `test_get_token.sh` | Get token from Keycloak |
| PAM OIDC auth | `test_ssh_oidc_valid.sh` | Test PAM authentication with token |
| Sudo step-up | `test_sudo_step_up.sh` | Test device flow for sudo |

### Test Credentials

| User | Password | Description |
|------|----------|-------------|
| testuser | testpass | Standard test user |
| adminuser | adminpass | Admin test user |
| admin | admin | Keycloak admin |

### Getting a Test Token

```bash
# Using the helper script
./test/scripts/get-test-token.sh testuser testpass

# Or manually with curl
curl -s -X POST \
  "http://localhost:8080/realms/unix-oidc-test/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=unix-oidc" \
  -d "client_secret=unix-oidc-test-secret" \
  -d "username=testuser" \
  -d "password=testpass" \
  -d "scope=openid" | jq -r '.access_token'
```

## End-to-End Tests

E2E tests verify the complete flow including browser-based authentication.

### Device Flow E2E Test

The device flow requires browser interaction to complete. We provide both manual and automated approaches.

#### Manual Testing

```bash
# Start the E2E test (it will poll in background)
./test/e2e/test-device-flow-e2e.sh &

# Open the verification URL in your browser
# (URL is printed by the script)
# Log in as testuser/testpass
# The script will detect completion and print the token
```

#### Automated Testing with Playwright

When Playwright is available (e.g., via Claude Code MCP):

```bash
# Start device flow
./test/e2e/test-device-flow-e2e.sh &

# In parallel, use Playwright to:
# 1. Navigate to verification_uri_complete
# 2. Fill username: testuser
# 3. Fill password: testpass
# 4. Click login button
# 5. Grant consent if prompted
```

Playwright MCP commands:
```
browser_navigate: http://localhost:8080/realms/unix-oidc-test/device?user_code=XXXX-XXXX
browser_snapshot
browser_type: username field -> testuser
browser_type: password field -> testpass
browser_click: login button
browser_snapshot (capture success)
```

### Testing the Full Sudo Flow

```bash
# 1. SSH into test host
ssh -p 2222 testuser@localhost

# 2. Run sudo command (will trigger step-up)
sudo ls /root

# 3. Complete device flow in browser
# 4. Sudo command should succeed
```

## Test Fixtures

### Keycloak Realm Configuration

`test/fixtures/keycloak/unix-oidc-test-realm.json`

- Client: `unix-oidc` (confidential)
- Device flow enabled (300s timeout, 5s interval)
- Direct access grants enabled (for testing)
- Users: testuser, adminuser

### LDAP Users

`test/fixtures/ldap/01-users.ldif`

- Base DN: `dc=test,dc=local`
- Users: testuser (uid=1001), adminuser (uid=1002)

### Policy Configurations

`test/fixtures/policy/`

- `policy-step-up.yaml` - Requires step-up for sudo
- `policy-no-step-up.yaml` - No step-up required

### PAM Configurations

`test/fixtures/pam/`

- `sshd` - PAM config for SSH with unix-oidc
- `sudo` - PAM config for sudo with unix-oidc

## Troubleshooting

### Keycloak won't start

```bash
# Check logs
docker compose -f docker-compose.test.yaml logs keycloak

# Common issues:
# - Port 8080 already in use
# - Not enough memory (Keycloak needs ~512MB)
```

### SSSD user resolution fails

```bash
# Check SSSD is running in test host
docker compose -f docker-compose.test.yaml exec test-host pgrep sssd

# Check LDAP connectivity
docker compose -f docker-compose.test.yaml exec test-host \
  ldapsearch -x -H ldap://openldap:389 -b "dc=test,dc=local" "(uid=testuser)"
```

### Token validation fails

```bash
# Check token contents
TOKEN=$(./test/scripts/get-test-token.sh testuser testpass)
echo "$TOKEN" | cut -d'.' -f2 | base64 -d | jq '.'

# Verify issuer matches
# Should be: http://keycloak:8080/realms/unix-oidc-test (inside containers)
# Or: http://localhost:8080/realms/unix-oidc-test (from host)
```

### Device flow times out

```bash
# Increase timeout in Keycloak
# Admin console > Clients > unix-oidc > Advanced
# Device Authorization Grant Max Lifespan: 600

# Or check network connectivity to Keycloak
curl http://localhost:8080/health/ready
```

## Writing New Tests

### Unit Test Template

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_name() {
        // Arrange
        let input = ...;

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected);
    }
}
```

### Integration Test Template

```bash
#!/bin/bash
# test/tests/test_new_feature.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test logic here
docker compose -f docker-compose.test.yaml exec -T test-host bash -c "
    # Commands to run inside test container
"

echo "Test passed"
```

## Provider Testing

unix-oidc is tested against real identity providers to ensure compatibility.

### Testing Matrix

| Provider | Discovery | JWKS | Token Acquisition | PAM Validation | Notes |
|----------|-----------|------|-------------------|----------------|-------|
| **Keycloak** | ✅ | ✅ | ✅ | ✅ | Full E2E in CI |
| **Auth0** | ✅ | ✅ | - | - | Cloud endpoints tested |
| **Google** | ✅ | ✅ | - | - | Cloud endpoints tested |
| **Azure AD** | Supported | Supported | - | - | Not in CI (no test tenant) |
| **Okta** | Supported | Supported | - | - | Not in CI (no test tenant) |

### What Each Test Level Validates

**Discovery Tests (Auth0, Google):**
- OIDC `.well-known/openid-configuration` endpoint is reachable
- Required endpoints are present (authorization, token, device_authorization, jwks_uri)
- Response structure matches OpenID Connect specification

**JWKS Tests (Auth0, Google):**
- JWKS endpoint returns valid key set
- Keys have required fields (kty, alg, use, kid)
- Key algorithms are supported (RS256, ES256)

**Token Acquisition (Keycloak only):**
- Direct access grant (password) flow works
- Tokens contain expected claims (sub, iss, aud, exp, iat)
- Token refresh works correctly

**PAM Validation (Keycloak only):**
- PAM module correctly validates JWT signature via JWKS
- Issuer and audience claims are enforced
- User mapping to local Unix accounts works
- Token expiration is enforced

### Why This Testing Approach Is Valid

Our OIDC implementation is **provider-agnostic** by design:

1. **Standard JWT Parsing**: We use the `jsonwebtoken` crate which handles all standard JWT formats
2. **Dynamic JWKS Fetching**: Keys are fetched from the provider's JWKS endpoint at runtime
3. **Standard Claims**: We use only standard OIDC claims (`sub`, `iss`, `aud`, `email`, `preferred_username`)

If the module:
- Correctly fetches JWKS from Auth0/Google (verified in CI)
- Correctly validates JWT signatures (verified with Keycloak tokens)
- Correctly extracts claims (verified with Keycloak tokens)

Then it will work with tokens from any OIDC-compliant provider, because the standards are the same.

### Running Provider Tests Locally

```bash
# Run all provider tests (requires secrets for Auth0)
gh workflow run provider-tests.yml

# Or test specific provider
gh workflow run provider-tests.yml -f provider=keycloak
```

### Adding a New Provider Test

To add tests for a new provider (e.g., Okta):

1. Add secrets to GitHub repository:
   - `OKTA_DOMAIN` - Your Okta domain
   - `OKTA_CLIENT_ID` - Client ID for testing

2. Add job to `.github/workflows/provider-tests.yml`:
   ```yaml
   okta:
     name: Okta Integration
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
       - name: Test Okta Discovery
         env:
           OKTA_DOMAIN: ${{ secrets.OKTA_DOMAIN }}
         run: |
           curl -sf "https://${OKTA_DOMAIN}/.well-known/openid-configuration" | jq .
   ```

## DPoP Testing

DPoP (Demonstrating Proof of Possession) has dedicated tests:

### Unit Tests (87 tests, 8 DPoP-specific)

```bash
cargo test -p pam-unix-oidc -- dpop
```

Tests include:
- Proof generation and parsing
- Signature validation (ES256/P-256)
- JTI uniqueness enforcement
- Constant-time thumbprint comparison
- Clock skew tolerance (60 seconds)

### Cross-Language Interoperability (16/16 combinations)

```bash
cd dpop-cross-language-tests
./run-cross-language-tests.sh
```

Tests all combinations of:
- **Producers**: Rust, Go, Python, Java
- **Validators**: Rust, Go, Python, Java

This ensures a DPoP proof generated by any implementation can be validated by any other.

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo test

  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker compose -f docker-compose.test.yaml up -d
      - run: ./test/scripts/wait-for-healthy.sh
      - run: ./test/scripts/run-integration-tests.sh
      - run: docker compose -f docker-compose.test.yaml down
```

## AWS Platform Testing

For production validation on real cloud infrastructure, we use AWS EC2 instances with native architecture support.

### Architecture Support

| Architecture | Instance Type | Method | Speed |
|--------------|---------------|--------|-------|
| x86_64 (amd64) | GitHub Actions runner | Native | Fast |
| ARM64 (aarch64) | AWS t4g.small (Graviton) | Native | Fast |

ARM64 tests run on native Graviton processors, avoiding slow QEMU emulation.

### AWS Infrastructure

Infrastructure is managed via Terraform in `infra/aws-testing/`:

```bash
cd infra/aws-testing
terraform init
terraform apply -var="budget_email=you@example.com"
```

**Security model:**
- GitHub Actions authenticates via OIDC (no stored AWS credentials)
- Environment protection requires manual approval before AWS resources are created
- Only spot instances allowed (cost control)
- Only specific instance types allowed (t3.micro/small, t4g.micro/small/medium)
- All resources tagged for cost tracking
- Budget alerts at 80% and 100% of $5/month limit

### Running AWS Platform Tests

#### 1. Build ARM64 AMI (monthly or as needed)

```bash
# Trigger via GitHub Actions
gh workflow run build-arm64-ami.yml --field force_rebuild=true
```

This creates an Amazon Linux 2023 ARM64 AMI with:
- Docker and Docker Compose pre-installed
- Test container images pre-pulled (Keycloak, OpenLDAP, Debian)
- Build dependencies (Rust toolchain prerequisites)

AMI lifecycle:
- Auto-builds monthly (1st of each month)
- Skips rebuild if existing AMI is less than 30 days old
- Retains only 2 AMIs (current + previous)
- Sends SNS notification on completion

#### 2. Run ARM64 Integration Tests

```bash
# Trigger via GitHub Actions
gh workflow run integration-arm64-aws.yml --field instance_type=t4g.small
```

Test flow:
1. Launch spot instance from custom AMI
2. Clone repository and checkout specific commit
3. Start test infrastructure (Keycloak, OpenLDAP)
4. Build PAM module natively on ARM64
5. Run unit and integration tests
6. Cleanup and terminate instance

#### 3. Run x86_64 Integration Tests

```bash
gh workflow run integration-x86-aws.yml --field instance_type=t3.small
```

### Cost Estimates

| Operation | Estimated Cost |
|-----------|---------------|
| ARM64 integration test run | ~$0.002 |
| x86_64 integration test run | ~$0.002 |
| AMI storage (2 AMIs) | ~$1/month |
| **Monthly budget** | **$5** |

### Monitoring

- **Budget alerts**: Email notifications at 80% and 100% of budget
- **AMI build notifications**: Email when AMI builds complete
- **Workflow summaries**: GitHub Actions step summaries show costs

### Troubleshooting

#### AMI build fails

```bash
# Check recent runs
gh run list --workflow=build-arm64-ami.yml --limit=5

# View logs
gh run view <run-id> --log-failed
```

Common issues:
- SSM command timeout (increase timeout in workflow)
- Docker pull rate limits (images are pre-pulled in AMI)
- Spot instance capacity (retry or try different AZ)

#### Integration tests fail

```bash
# View test output
gh run view <run-id> --log

# Check SSM command output in logs
# Look for "=== Test Output ===" section
```

Common issues:
- Rust compilation errors (check Cargo.toml dependencies)
- Service startup timeout (increase sleep duration)
- Network connectivity (check security group rules)
