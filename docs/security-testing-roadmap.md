# Security Testing Roadmap

This document outlines the security testing strategy for unix-oidc, including current implementation and future pentest automation plans.

## Current Security Testing

### Static Analysis
- **cargo-audit**: RustSec advisory database scanning (CI)
- **Snyk**: Vulnerability scanning with SARIF upload (CI)
- **cargo-deny**: License and advisory compliance (CI)
- **Clippy**: Rust linting with security-related checks

### Code Coverage
- **cargo-llvm-cov**: Line and branch coverage with Codecov integration
- Current coverage targets: >80% for security-critical modules

### Fuzz Testing
- Parser hardening via cargo-fuzz
- JWT validation fuzzing
- DPoP proof parsing fuzzing

### Integration Tests
- Keycloak-based OIDC flow testing
- Multi-provider validation (Azure AD, Auth0, Google)
- Cross-language DPoP interoperability (16/16 tests)

## Planned: Pentest Automation (Deferred)

### Phase 1: Authentication Attack Surface

**Token Manipulation Tests**
```yaml
tests:
  - name: JWT signature bypass attempts
    vectors:
      - algorithm: none
      - algorithm: HS256 (symmetric with public key)
      - truncated signature
      - embedded null bytes

  - name: DPoP proof manipulation
    vectors:
      - expired proofs
      - replayed JTIs
      - mismatched htu claims
      - invalid jwk thumbprint

  - name: Token injection
    vectors:
      - header injection
      - claim injection
      - unicode normalization attacks
```

**Implementation Tools**
- Custom Rust test harness for JWT/DPoP fuzzing
- Integration with Burp Suite for HTTP-level testing
- AuthMatrix patterns for authorization testing

### Phase 2: PAM Module Security

**Memory Safety Tests**
```yaml
tests:
  - name: Buffer handling
    vectors:
      - oversized tokens
      - malformed UTF-8
      - embedded null bytes in PAM inputs

  - name: Resource exhaustion
    vectors:
      - connection pool exhaustion
      - JTI cache overflow
      - concurrent authentication flood
```

**Implementation Tools**
- AddressSanitizer (ASan) builds
- Memory profiling with Valgrind
- Stress testing framework

### Phase 3: Network Security

**TLS Configuration Tests**
```yaml
tests:
  - name: TLS validation
    vectors:
      - self-signed certificates
      - expired certificates
      - hostname mismatches
      - TLS downgrade attempts

  - name: JWKS endpoint security
    vectors:
      - JWKS fetch timing attacks
      - cache poisoning
      - key rotation handling
```

**Implementation Tools**
- testssl.sh integration
- mitmproxy for MITM testing
- Custom timing attack framework

### Phase 4: Rate Limiting Validation

**Brute Force Resistance**
```yaml
tests:
  - name: Rate limit effectiveness
    scenarios:
      - single IP, multiple users
      - distributed attack simulation
      - rate limit bypass attempts (X-Forwarded-For manipulation)

  - name: Lockout behavior
    scenarios:
      - exponential backoff verification
      - lockout persistence across restarts
      - legitimate user DoS prevention
```

## Implementation Timeline

| Phase | Description | Status | Priority |
|-------|-------------|--------|----------|
| Static Analysis | cargo-audit, Snyk, clippy | ✅ Implemented | P0 |
| Unit Tests | Security control coverage | ✅ Implemented | P0 |
| Integration Tests | E2E flow validation | ✅ Implemented | P0 |
| Fuzz Testing | Parser hardening | ✅ Implemented | P1 |
| Token Manipulation | JWT/DPoP attack testing | ⏳ Planned | P2 |
| PAM Security | Memory safety validation | ⏳ Planned | P2 |
| Network Security | TLS/JWKS testing | ⏳ Planned | P2 |
| Rate Limiting | Brute force resistance | ⏳ Planned | P2 |

## CI Integration (Future)

```yaml
# .github/workflows/pentest.yml (draft)
name: Security Testing

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly
  workflow_dispatch:

jobs:
  token-manipulation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run JWT attack suite
        run: cargo test --features pentest -- jwt_attacks

  memory-safety:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build with ASan
        run: RUSTFLAGS="-Zsanitizer=address" cargo build --release
      - name: Run memory tests
        run: ./scripts/memory-test.sh
```

## External Pentest Coordination

For production deployments, we recommend:

1. **Third-party assessment** before v1.0 release
2. **Bug bounty program** for ongoing vulnerability discovery
3. **Red team exercises** quarterly for mature deployments

## References

- [OWASP Testing Guide v4](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST SP 800-115: Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [RFC 9449 Security Considerations](https://datatracker.ietf.org/doc/html/rfc9449#section-11)
