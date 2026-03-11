# Integration Testing Assessment

**Date**: 2026-03-11
**Scope**: Full assessment of unix-oidc integration testing infrastructure, including Phase 10 (CIBA step-up + FIDO2 via ACR delegation) testability.

## Executive Summary

The unix-oidc project has substantial unit test coverage (~473 tests across both crates) and a functional Docker Compose-based integration environment. However, several critical integration gaps exist — most notably, CIBA backchannel authentication has no live IdP test infrastructure (Keycloak realm has `oidc.ciba.grant.enabled: false` in all realm configs), and the end-to-end step-up flow (PAM -> agent daemon IPC -> CIBA poll -> ACR validation) has no automated integration test. The token exchange flow and DPoP binding validation are partially tested with shell scripts but are not wired into CI.

---

## Current Test Infrastructure Inventory

### Unit Tests (cargo test)

| Crate | Test Count | Files with Tests |
|-------|-----------|-----------------|
| pam-unix-oidc | ~313 | 27 source files |
| unix-oidc-agent | ~160 | 17 source files |
| **Total** | **~473** | **44 files** |

Coverage threshold enforced in CI: 55% (target: 80%).

### CI Workflows (`.github/workflows/`)

| Workflow | Trigger | What It Tests |
|----------|---------|---------------|
| `ci.yml` | push/PR to main | fmt, clippy, unit tests, integration (Docker Compose), MSRV, docs, coverage, SBOM, CodeQL |
| `provider-tests.yml` | push/PR + daily cron | Keycloak discovery+token, Auth0 discovery (secrets), Google discovery (public) |
| `platform-tests.yml` | PR (path-filtered) + tags | EC2 instances: Amazon Linux 2023, Ubuntu 22.04, Debian 12, Rocky 9, RHEL 9 |
| `integration-multiarch.yml` | manual only | amd64/arm64 Docker Compose tests (QEMU too slow for CI) |
| `integration-arm64-aws.yml` | manual only | Native ARM64 on Graviton instances |
| `fuzz.yml` | push/PR + nightly | 3 fuzz targets: token_parser, policy_parser, username_mapper |
| `security.yml` | push/PR + weekly | Snyk, cargo-audit, cargo-deny, TruffleHog, OSSF Scorecard |

### Docker Compose Environments

| File | Services | Purpose |
|------|----------|---------|
| `docker-compose.test.yaml` | Keycloak 24.0, OpenLDAP, test-host (Ubuntu 22.04) | Primary integration tests |
| `docker-compose.test-multiarch.yaml` | Same as above | Multi-arch testing |
| `docker-compose.token-exchange.yaml` | Keycloak 26.2 (with token-exchange, admin-fine-grained-authz, dpop features) | Token exchange testing |

### Shell-Based Integration Tests (`test/tests/`)

| Test Script | What It Validates | In CI? |
|-------------|-------------------|--------|
| `test_keycloak_reachable.sh` | OIDC discovery endpoint accessible | Yes |
| `test_ldap_reachable.sh` | OpenLDAP server responds | Yes |
| `test_ssh_reachable.sh` | SSH on test-host:2222 | Yes |
| `test_sssd_user.sh` | SSSD resolves testuser from LDAP | Yes |
| `test_get_token.sh` | Password grant token acquisition from Keycloak | Yes |
| `test_ssh_oidc_valid.sh` | PAM module validates OIDC token via SSH | Yes (skip-safe) |
| `test_sudo_step_up.sh` | Device flow endpoint, polling, policy parse, PAM module presence | Yes (skip-safe) |
| `test_agent_forwarding.sh` | Agent forwarding over SSH | Yes |
| `test_dpop_e2e.sh` | DPoP unit tests, cross-language DPoP, Docker integration | No (manual) |
| `test_token_exchange.sh` | Full DPoP + RFC 8693 token exchange flow | No (untracked) |
| `test_token_exchange.py` | Same as above in Python | No (untracked) |

### Other Test Assets

| Asset | Purpose |
|-------|---------|
| `dpop-cross-language-tests/` | Rust, Go, Python DPoP proof generation + validation (16 cross-language combinations) |
| `fuzz/fuzz_targets/` | 4 fuzz targets (token_parser, policy_parser, username_mapper, dpop_proof) |
| `demo/tests/training-video.spec.ts` | Playwright-based demo recording for device flow |
| `test/fixtures/keycloak/unix-oidc-test-realm.json` | Keycloak realm with unix-oidc client, device flow, ACR mapper, WebAuthn flows |
| `test/fixtures/keycloak/token-exchange-test-realm.json` | Keycloak realm for token exchange with DPoP-bound clients |
| `test/fixtures/policy/policy-step-up.yaml` | Policy requiring step-up for sudo |
| `test/fixtures/policy/policy-no-step-up.yaml` | Policy without step-up |

---

## Testability Assessment by Feature

### Fully Testable (Automated in CI)

| Feature | Unit Tests | Integration Tests | Notes |
|---------|-----------|-------------------|-------|
| Token parsing and claims extraction | 10 tests in `token.rs` | Keycloak provider test | Solid |
| OIDC discovery + JWKS fetch | 3 tests in `jwks.rs` | Provider tests workflow | Keycloak + Auth0 + Google |
| Token signature validation | 13 tests in `validation.rs` | Provider tests (Keycloak) | `cargo test -- jwks validation` in CI |
| DPoP proof generation (agent) | 11 tests in `crypto/dpop.rs` | Cross-language tests (manual) | Unit coverage strong |
| DPoP proof validation (PAM) | 9 tests in `oidc/dpop.rs` | Cross-language tests (manual) | Algorithm enforcement, replay protection |
| JTI replay protection | 8 tests in `jti_cache.rs` | N/A | Size-bounded cache, eviction |
| Policy configuration parsing | 36 tests in `policy/config.rs` | N/A | Comprehensive YAML parsing |
| Policy rule evaluation | 4 tests in `policy/rules.rs` | N/A | |
| Username identity mapping | 20 tests in `identity/mapper.rs` | N/A | Fuzz target exists |
| Identity collision detection | 12 tests in `identity/collision.rs` | N/A | |
| Session management | 14 tests in `session/mod.rs` | N/A | |
| Sudo context parsing | 15 tests in `sudo.rs` | N/A | |
| IPC protocol (agent <-> PAM) | 22 tests in `daemon/protocol.rs` | N/A | Includes StepUp/StepUpResult serde |
| Storage router + migration | 19 tests in `storage/router.rs` | N/A | Probe-based detection, rollback |
| File storage + secure delete | 14 tests in `storage/` | N/A | DoD 5220.22-M three-pass |
| Protected key (mlock, zeroize) | 9 tests in `crypto/protected_key.rs` | N/A | Box-only constructors, export |
| Rate limiting | 8 tests in `security/rate_limit.rs` | N/A | |
| Audit event generation | 18 tests in `audit.rs` | N/A | |
| Metrics collection | 3 tests in `metrics.rs` | N/A | |
| SSSD user/group resolution | 18 tests in `sssd/` | Docker (LDAP) | LDAP-backed SSSD in test-host |

### Partially Testable (Gaps Identified)

| Feature | Unit Tests | Integration Gap | Risk |
|---------|-----------|----------------|------|
| DPoP binding validation (cnf.jkt) | Unit-level proof verification | No live test with DPoP-bound tokens from Keycloak | **High** — the unix-oidc-test realm does not configure `dpop.bound.access.tokens: true`; only the token-exchange-test realm does, but it is not in CI |
| Token exchange (RFC 8693) | N/A (shell/Python scripts only) | `docker-compose.token-exchange.yaml` not wired into any CI workflow; test scripts are untracked | **High** — critical for jump host / agent forwarding scenarios |
| Device flow E2E | Device endpoint reachable test | Browser automation required to complete flow; Playwright scripts exist but require manual Claude Code MCP | **Medium** — endpoint tests are in CI; full flow requires browser |
| Break-glass fallback | N/A | No test verifies PAM falls back to local auth when OIDC is unavailable | **Medium** — deployment invariant from CLAUDE.md |
| End-to-end SSH with OIDC token | `test_ssh_oidc_valid.sh` exists | Test uses UNIX_OIDC_TEST_MODE=true (bypasses signature verification) | **Medium** — real crypto path untested in E2E |

### Not Testable (No Infrastructure Exists)

| Feature | What's Missing | Risk |
|---------|---------------|------|
| **CIBA backchannel authentication** | All Keycloak realm configs have `oidc.ciba.grant.enabled: false`. No CIBA-enabled realm. No backchannel auth endpoint in test infrastructure. | **Critical** — Phase 10 core feature is entirely untested against a real IdP |
| **CIBA step-up full flow (PAM -> agent -> IdP -> ACR validate)** | No integration test exists for the StepUp IPC flow. Unit tests cover serde and parameter building, but no test exercises the async CIBA poll loop in the agent daemon. | **Critical** — the most complex code path in Phase 10 |
| **ACR validation against live tokens** | `satisfies_acr()` and `validate_acr()` have 8 unit tests but no test obtains a token with an actual ACR claim from Keycloak | **High** — ACR claim presence depends on IdP configuration; misconfiguration would be invisible |
| **FIDO2/WebAuthn step-up** | Keycloak realm defines WebAuthn flows and passwordless config, but no FIDO2 authenticator simulator exists in the test environment | **High** — FIDO2 is the security-critical auth method for `ACR_PHRH` |
| **Multi-provider simultaneous** | Auth0 and Google tests only validate discovery, not full token flows. No test validates token from provider A while PAM is configured for provider B (negative test). | **Medium** |
| **Agent daemon lifecycle** | No integration test starts the daemon, sends IPC commands, and validates responses end-to-end | **Medium** — socket tests exist (31 tests) but only unit-level |
| **Token revocation on session close** | SessionClosed IPC protocol tested at serde level only; no test verifies RFC 7009 revocation request is actually sent | **Medium** |
| **Hardware signers (YubiKey, TPM)** | 23 tests in yubikey_signer.rs and tpm_signer.rs, all are mock/stub-based; no real hardware in CI | **Low** — acceptable; hardware CI is impractical |

---

## Priority Recommendations

### P0: CIBA Test Infrastructure (Phase 10 Blocking)

**Problem**: CIBA is the foundation of Phase 10 step-up authentication, but there is zero integration testing against a live CIBA endpoint.

**Actions**:

1. **Create a CIBA-enabled Keycloak realm configuration** (`test/fixtures/keycloak/ciba-test-realm.json`):
   - Set `oidc.ciba.grant.enabled: true` on the unix-oidc client
   - Configure `backchannel_token_delivery_modes_supported: ["poll"]`
   - Set `ciba-authentication-request.expires_in: 120`
   - Configure an authentication flow that maps to ACR values (use Keycloak's built-in ACR LoA mapping)

2. **Add a `docker-compose.ciba.yaml`** (or extend `docker-compose.test.yaml`):
   - Keycloak 26.2 (CIBA support improved significantly in 25+)
   - Enable the `ciba` feature: `start-dev --features=ciba`
   - Include a CIBA test helper service (see below)

3. **Create a CIBA test helper** (`test/scripts/ciba-test-helper.sh` or Python):
   - Initiate backchannel auth request with `login_hint` and `binding_message`
   - Simulate user approval via Keycloak Admin API (`PUT /admin/realms/{realm}/authentication/executions/{id}`)
   - Poll token endpoint with `urn:openid:params:grant-type:ciba` grant type
   - Validate returned token has expected ACR claim

4. **Wire into CI**: Add a `ciba` job to `ci.yml` that runs the CIBA test after the standard integration tests pass.

**Effort**: 2-3 days
**Risk reduction**: Critical (validates the entire Phase 10 architecture)

**Keycloak CIBA limitation**: Keycloak's CIBA implementation requires an external "authentication device" to approve requests. In CI, this can be automated via the Keycloak Admin REST API to directly approve authentication requests. Alternatively, Keycloak's "internal" CIBA authenticator can be configured to auto-approve in test realms.

### P1: Token Exchange in CI

**Problem**: Token exchange tests exist (`test_token_exchange.sh`, `test_token_exchange.py`) but are untracked and not in CI. `docker-compose.token-exchange.yaml` exists but is never used by any workflow.

**Actions**:

1. Track the token exchange test files (`git add test/tests/test_token_exchange.*`)
2. Add a `token-exchange` job to `ci.yml` (or `provider-tests.yml`) that:
   - Starts `docker-compose.token-exchange.yaml`
   - Runs `test/tests/test_token_exchange.sh`
   - Validates DPoP binding transfer (cnf.jkt rebinding)
3. Verify the token-exchange-test realm imports correctly in CI

**Effort**: 0.5 days
**Risk reduction**: High (validates jump host delegation path)

### P2: DPoP-Bound Token E2E Validation

**Problem**: The primary test realm (`unix-oidc-test`) does not enable DPoP binding on access tokens. The `dpop.bound.access.tokens` attribute is absent. DPoP proof validation unit tests pass, but no integration test validates that:
- Keycloak embeds `cnf.jkt` in access tokens when DPoP proof is sent
- PAM module correctly matches `cnf.jkt` against the DPoP proof thumbprint
- Proof replay is rejected in a live multi-request scenario

**Actions**:

1. Add `"dpop.bound.access.tokens": "true"` to the unix-oidc client in `unix-oidc-test-realm.json`
2. Extend `test_dpop_e2e.sh` to:
   - Generate a DPoP proof using openssl
   - Obtain a DPoP-bound token from Keycloak
   - Verify `cnf.jkt` claim is present and matches the proof's JWK thumbprint
   - Attempt to use the token without a DPoP proof (should fail or downgrade to bearer)
3. Add to CI integration test suite

**Effort**: 1 day
**Risk reduction**: High (validates the project's core security differentiator)

### P3: Step-Up IPC Integration Test

**Problem**: The PAM-to-agent StepUp/StepUpResult IPC protocol has comprehensive serde tests (12 tests in `protocol.rs`) but no test exercises the actual async flow: PAM sends `StepUp` -> agent spawns CIBA poll -> agent returns `StepUpPending` -> PAM polls with `StepUpResult` -> agent returns `StepUpComplete`.

**Actions**:

1. Create a Rust integration test (`unix-oidc-agent/tests/step_up_integration.rs`) that:
   - Starts the agent daemon on a Unix socket
   - Sends a `StepUp` request
   - Receives `StepUpPending` with correlation_id
   - Uses a mock HTTP server (e.g., `wiremock-rs`) to simulate CIBA token endpoint responses
   - Polls `StepUpResult` until `StepUpComplete` or timeout
   - Validates ACR claim in the response

2. Add negative tests:
   - CIBA `access_denied` response -> `StepUpTimedOut` with correct reason
   - CIBA `expired_token` response -> `StepUpTimedOut`
   - ACR insufficient (phr when phrh required) -> error propagated

**Effort**: 2 days
**Risk reduction**: High (validates the most complex async code path in the system)

### P4: Break-Glass Fallback Test

**Problem**: CLAUDE.md states break-glass access is MANDATORY, but no test validates the fallback path when OIDC is unavailable.

**Actions**:

1. Add `test_break_glass.sh` that:
   - Configures test-host with a local break-glass account
   - Stops Keycloak while test-host is running
   - Verifies SSH login with break-glass credentials succeeds
   - Verifies OIDC login fails gracefully (not crash/hang)
   - Restarts Keycloak and verifies OIDC recovery

**Effort**: 1 day
**Risk reduction**: Medium-High (deployment safety)

### P5: FIDO2 Authenticator Simulation

**Problem**: Phase 10 specifies FIDO2/WebAuthn as the authentication method for `ACR_PHRH` (hardware-bound phishing-resistant). No FIDO2 authenticator exists in the test environment.

**Actions**:

1. Use Keycloak's built-in virtual authenticator support (available since Keycloak 23+) or a software FIDO2 authenticator like `soft-webauthn` in test infrastructure
2. Register a virtual credential for testuser in the realm config
3. Create a test that triggers CIBA with `acr_values=phrh` and validates the returned token has the correct ACR

**Limitation**: True FIDO2 hardware attestation cannot be tested in CI. The test validates the ACR flow, not hardware binding.

**Effort**: 3-4 days (Keycloak FIDO2 test setup is nontrivial)
**Risk reduction**: High for Phase 10 completeness

### P6: Cross-Language DPoP Tests in CI

**Problem**: The `dpop-cross-language-tests/` directory has Rust, Go, and Python DPoP interop tests, but they are not wired into any CI workflow.

**Actions**:

1. Add a `dpop-interop` job to `ci.yml` that:
   - Installs Go, Python dependencies
   - Runs `dpop-cross-language-tests/run-cross-language-tests.sh`
2. This validates that DPoP proofs generated by any language are accepted by any other language's validator

**Effort**: 0.5 days
**Risk reduction**: Medium (interop assurance for multi-language deployments)

### P7: Agent Daemon Lifecycle Test

**Problem**: No test starts the daemon binary, connects via Unix socket, and validates responses.

**Actions**:

1. Create `test/tests/test_agent_daemon.sh` that:
   - Starts `unix-oidc-agent serve` in background
   - Sends JSON commands to the Unix socket using `socat` or `nc`
   - Validates `Status`, `GetProof`, `Refresh`, `Shutdown` responses
   - Cleans up

**Effort**: 1 day
**Risk reduction**: Medium

---

## Test Infrastructure Summary Matrix

| Feature Area | Unit | Integration (Docker) | E2E (Live IdP) | CI | Priority |
|---|---|---|---|---|---|
| Token parsing | 10 | - | Keycloak | Yes | Done |
| Token validation (sig, exp, iss, aud) | 13 | - | Keycloak | Yes | Done |
| DPoP proof gen/validate | 20 | Cross-lang (manual) | - | Partial | P2, P6 |
| DPoP binding (cnf.jkt) | Unit only | - | - | No | **P2** |
| JWKS cache | 3 | - | Keycloak | Yes | Done |
| Device flow | Endpoint test | - | Browser needed | Partial | Acceptable |
| **CIBA backchannel auth** | **14 (param builder)** | **None** | **None** | **No** | **P0** |
| **Step-up IPC flow** | **12 (serde)** | **None** | **None** | **No** | **P3** |
| **ACR validation (live)** | **8** | **None** | **None** | **No** | **P0** |
| Token exchange (RFC 8693) | Shell/Python | Docker exists | Not in CI | No | **P1** |
| Policy config | 36 | Docker (fixture) | - | Yes | Done |
| Storage backends | 28 | - | - | Yes | Done |
| Memory protection | 9 | - | - | Yes | Done |
| Break-glass fallback | 0 | - | - | No | **P4** |
| FIDO2/WebAuthn | 0 | Realm config exists | - | No | **P5** |
| Multi-provider | Discovery only | - | Auth0/Google | Partial | Low |
| Session lifecycle + revocation | Serde only | - | - | No | P7 |
| Platform matrix | - | - | EC2 (4 distros) | Yes | Done |
| Fuzz testing | 3-4 targets | - | - | Yes | Done |

---

## Keycloak CIBA Configuration Guide (for P0)

To enable CIBA in a Keycloak test realm, the following configuration is required in the realm JSON:

1. **Client attributes**:
   ```json
   "attributes": {
     "oidc.ciba.grant.enabled": "true",
     "ciba.backchannel.token.delivery.mode": "poll",
     "ciba.backchannel.auth.request.expires": "120",
     "ciba.interval": "5"
   }
   ```

2. **Realm-level CIBA settings**: Keycloak 26+ supports CIBA as a first-class authentication channel. The realm must have a CIBA authentication flow configured.

3. **ACR LoA mapping**: Keycloak supports ACR-to-authentication-flow mapping via the `acr-loa-map` realm attribute. Example:
   ```json
   "attributes": {
     "acr-loa-map": "{\"1\":\"urn:keycloak:acr:loa1\",\"2\":\"urn:keycloak:acr:loa2\"}"
   }
   ```

4. **Test automation**: CIBA approval can be automated in tests using Keycloak's Admin REST API to approve pending authentication requests, avoiding the need for a real authenticator device.

---

## Mock Server Strategy (Alternative to Live IdP for CIBA)

For CI environments where Keycloak CIBA setup is too complex, a lightweight mock CIBA server can provide deterministic testing:

1. Use `wiremock-rs` (Rust) or a simple HTTP server that:
   - Accepts backchannel auth requests at `/bc-authorize`
   - Returns `auth_req_id` and `interval`
   - Responds to token poll requests with configurable delays and outcomes
   - Returns tokens with configurable ACR claims

2. This enables testing:
   - Happy path (immediate approval, delayed approval)
   - Error paths (access_denied, expired_token, slow_down)
   - ACR validation (tokens with/without ACR, various ACR values)
   - Timeout behavior

3. **Trade-off**: Mock testing validates the agent's CIBA protocol handling but not IdP-specific behavior (claim formats, error codes, timing). Both mock and live IdP tests are needed for complete assurance.

---

## Conclusion

The project has strong unit test coverage and a well-structured CI pipeline for the features built through Phase 9. The critical gap is Phase 10 integration testing: CIBA backchannel authentication, the step-up IPC flow, and ACR validation against live tokens have no integration test infrastructure. The P0 recommendation (CIBA-enabled Keycloak realm + CI job) is the minimum required to validate that Phase 10 code works end-to-end. Without this, the CIBA implementation is validated only at the parameter-builder and serde level, leaving the full async flow (PAM -> agent -> IdP -> token -> ACR gate) untested.

Secondary priorities (P1-P3) address the DPoP binding and token exchange gaps, which are foundational to the project's security value proposition. These can be addressed incrementally alongside Phase 10 CIBA testing.
