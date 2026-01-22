# Security Roadmap

This document summarizes the security findings from the research analysis and tracks the implementation status of security hardening measures.

## Current Security Status

### Implemented

| Feature | Status | Notes |
|---------|--------|-------|
| ACR validation | Done | Validates ACR level meets requirements |
| auth_time checking | Done | Prevents stale session reuse |
| Clock skew tolerance | Done | 60 second tolerance |
| Explicit PAM error codes | Done | Never returns PAM_IGNORE on auth failures |
| Username matching | Done | Validates PAM user matches token claim |
| Audit logging | Done | Structured JSON events for security monitoring |
| Modular architecture | Done | Separation of concerns (oidc, sssd, policy) |

### Critical Gaps (Pre-Production)

| Gap | Priority | Status | Description |
|-----|----------|--------|-------------|
| JWT signature verification | P0 | **Done** | Verifies JWT signatures using JWKS from OIDC discovery |
| JWKS caching with rotation | P0 | **Done** | 5-minute TTL cache with automatic refresh on key rotation |

### High Priority Enhancements

| Enhancement | Priority | Status | Description |
|-------------|----------|--------|-------------|
| Session ID entropy | P1 | **Done** | CSPRNG-based session IDs with 64-bit randomness |
| Token replay protection | P1 | **Done** | JTI tracking with TTL-based expiration |
| Rate limiting | P1 | **Done** | Per-user/IP rate limiting with exponential backoff |

## Security Best Practices

### References
- RFC 9700 - OAuth 2.0 Security Best Current Practice (2025)
- RFC 9449 - DPoP (Demonstrating Proof-of-Possession)
- RFC 9470 - OAuth 2.0 Step Up Authentication Challenge Protocol

### Key Principles

1. **Always Fail Closed**: Never return PAM_IGNORE or PAM_SUCCESS on error conditions
2. **Validate Everything**: Token signatures, issuers, audiences, ACR levels, auth_time
3. **Fresh Credentials**: Require fresh authentication for step-up operations
4. **Audit Everything**: Log all authentication events with timestamps and session IDs
5. **Defense in Depth**: Multiple layers of validation and verification

## CVE Lessons Learned

### PAM Module CVEs (2024-2025)

| CVE | Lesson |
|-----|--------|
| CVE-2025-23013 (pam-u2f) | Never return PAM_IGNORE on error conditions |
| CVE-2025-24032 (pam_pkcs11) | Never skip signature verification |
| CVE-2025-24531 (pam_pkcs11) | Never return PAM_IGNORE on memory allocation failure |

### Mitigations Applied
- [x] Return explicit error codes (AUTH_ERR, USER_UNKNOWN, SERVICE_ERR)
- [x] Plan to implement full JWT signature verification
- [x] Graceful error handling for all edge cases

## Competitive Analysis

### Unique Differentiators
- **Step-up authentication for sudo** - No competitor offers this
- **SSSD integration** - Maps to existing users without account provisioning
- **ACR-based host classification** - Granular access control by host type
- **Policy-based command rules** - Per-command step-up requirements

### Feature Comparison

| Feature | unix-oidc | pam-keycloak-oidc | Teleport | Smallstep |
|---------|-----------|-------------------|----------|-----------|
| SSH OIDC auth | Yes | Yes | Enterprise only | Yes |
| Sudo step-up | Yes | No | No | No |
| Device flow | Yes | No | N/A | N/A |
| ACR enforcement | Yes | Basic | No | No |
| SSSD integration | Yes | No | No | No |
| Host classification | Yes | No | Limited | No |

## Implementation Roadmap

### Phase 3: Security Hardening (Complete)

1. **JWT Signature Verification** ✅
   - Fetches JWKS from OIDC discovery endpoint
   - Implements RS256/ES256 verification via `jsonwebtoken` crate
   - Caches JWKS with 5-minute TTL and automatic rotation support
   - Key lookup by `kid` with fallback to default key

2. **Session ID Hardening** ✅
   - Uses `getrandom` crate for CSPRNG
   - Format: `{prefix}-{timestamp_hex}-{random_hex}`
   - 64 bits of cryptographic randomness per session
   - Location: `pam-unix-oidc/src/security/session.rs`

3. **Token Replay Protection** ✅
   - JTI (JWT ID) tracking with in-memory cache
   - TTL matches token expiration for automatic cleanup
   - Global singleton with thread-safe RwLock
   - Configurable via `enforce_jti` flag in ValidationConfig
   - Location: `pam-unix-oidc/src/security/jti_cache.rs`

4. **Rate Limiting** ✅
   - Per-user and per-IP tracking
   - Sliding window with configurable max attempts (default: 5)
   - Exponential backoff on consecutive failures (cap: 1 hour)
   - Configurable via environment variables:
     - `UNIX_OIDC_RATE_LIMIT_WINDOW`: Window size (default: 300s)
     - `UNIX_OIDC_RATE_LIMIT_MAX_ATTEMPTS`: Max attempts (default: 5)
     - `UNIX_OIDC_RATE_LIMIT_LOCKOUT`: Initial lockout (default: 60s)
   - Location: `pam-unix-oidc/src/security/rate_limit.rs`

### Phase 4: Advanced Features (In Progress)

1. **Custom approval workflows** ✅
   - `ApprovalProvider` trait for pluggable approval mechanisms
   - `WebhookApprovalProvider` for HTTP-based approvals
   - Demo webhook server with web UI (`examples/webhook-server/`)
2. Push notification step-up method (Planned)
3. FIDO2/WebAuthn step-up method (Planned)
4. Break-glass with offline YubiKey OTP (Planned)

### Phase 5: Client-Side Agent with DPoP (Implemented)

> **Architecture decision:** [ADR-001: DPoP Proof-of-Possession](adr/001-dpop-proof-of-possession.md)

Reduce blast radius of credential theft using DPoP (RFC 9449) with post-quantum cryptography. Stolen tokens become time-limited and centrally revocable instead of permanent.

**Key features:**
- Per-device ML-DSA-65 + ES256 hybrid keypairs (quantum-resistant)
- Public OIDC client (no secrets to distribute)
- Server nonce binding prevents proof pre-computation
- Zero shared state (no Redis/distributed cache)
- Works with ephemeral cloud instances

**Architecture:**
```
User Machine                          SSH Server
┌─────────────────┐                   ┌─────────────────┐
│ unix-oidc-agent │                   │   PAM Module    │
│ - DPoP keypair  │──token + proof───▶│ - Validate sig  │
│ - Token refresh │                   │ - Check cnf.jkt │
│ - Secure storage│                   │ - Verify nonce  │
└─────────────────┘                   └─────────────────┘
```

**CLI Interface:**
```bash
unix-oidc-agent login      # Browser auth, get DPoP-bound tokens
unix-oidc-agent status     # Show token expiry, key thumbprint
unix-oidc-agent logout     # Revoke tokens, keep keypair
unix-oidc-agent reset      # Delete everything including keypair
unix-oidc-agent serve      # Run daemon (systemd/launchd)
```

**User Experience Goal:**
```bash
$ unix-oidc-agent login          # Once per session (or week with refresh)
$ ssh server.example.com         # Just works, no prompts
$ sudo systemctl restart nginx   # Step-up on phone, command proceeds
```

**Migration path:**
1. Ship agent with `dpop_policy: optional` (both flows work)
2. Monitor adoption via audit logs
3. Enforce with `dpop_policy: required`

#### Custom Approval Workflows

Extensible step-up mechanism supporting enterprise approval patterns beyond standard OAuth flows.

**Use Cases:**
- Mobile approval app (custom enterprise app with approve/deny)
- Webhook notifications (call external system, poll for approval)
- ServiceNow/PagerDuty integration (create ticket, wait for resolution)
- Slack/Teams approval (post message with approve/deny buttons)
- Manager approval chains (escalation workflows)

**Architecture:**

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────┐
│   PAM       │────>│  Approval   │────>│  External       │
│   Module    │     │  Provider   │     │  System         │
└─────────────┘     └──────┬──────┘     └────────┬────────┘
                          │                      │
                    ┌─────┴─────┐          ┌─────┴─────┐
                    │  Poll for │<─────────│  Webhook  │
                    │  result   │          │  callback │
                    └───────────┘          └───────────┘
```

**Configuration:**
```yaml
sudo:
  step_up_required: true
  allowed_methods:
    - device_flow
    - custom_approval

  custom_approval:
    # Provider configuration
    provider: webhook

    # Webhook settings
    webhook:
      initiate_url: "https://approvals.example.com/api/request"
      poll_url: "https://approvals.example.com/api/status/{request_id}"
      # Or use callback instead of polling
      callback_mode: false

    # Display customization
    display:
      title: "Manager Approval Required"
      message: "A request has been sent to your manager for approval."
      show_request_id: true

    # Timeout configuration (per-method overrides)
    timeout_seconds: 600  # 10 minutes for human approval
    poll_interval_seconds: 5

    # Optional: escalation
    escalation:
      after_seconds: 300
      notify: ["oncall@example.com"]
```

**Provider Interface:**
```rust
pub trait ApprovalProvider: Send + Sync {
    /// Initiate an approval request
    fn initiate(&self, ctx: &ApprovalContext) -> Result<ApprovalRequest, ApprovalError>;

    /// Poll for approval status
    fn poll(&self, request_id: &str) -> Result<ApprovalStatus, ApprovalError>;

    /// Cancel a pending request
    fn cancel(&self, request_id: &str) -> Result<(), ApprovalError>;
}

pub enum ApprovalStatus {
    Pending,
    Approved { approver: String, timestamp: i64 },
    Denied { reason: Option<String> },
    Expired,
}
```

**Built-in Providers (planned):**
- `webhook` - Generic HTTP webhook
- `slack` - Slack interactive messages
- `teams` - Microsoft Teams adaptive cards
- `pagerduty` - PagerDuty incidents
- `opsgenie` - Opsgenie alerts

**Terminal Display:**
```
═══════════════════════════════════════════════════════════
  Manager Approval Required

  Request ID: APR-2024-01-17-abc123
  Sent to: manager@example.com

  Waiting for approval... (540s remaining)
═══════════════════════════════════════════════════════════
```

### Phase 5: AI Agent Delegation (Future)

Support for AI agents (Claude Code, Devin, Copilot Workspace, etc.) authenticating on behalf of human users.

**Problem Statement:**
AI agents increasingly need to SSH to servers to perform tasks on behalf of users. The current human-centric authentication model doesn't capture:
- Who is the agent vs who authorized it
- Scoped permissions for delegated access
- Audit trail distinguishing agent actions from human actions
- Step-up auth (agents can't complete interactive flows)

**Token Structure Extensions:**
```json
{
  "sub": "ai-agent-claude-code",
  "act": {
    "sub": "alice@example.com"
  },
  "scope": "ssh:read ssh:execute",
  "azp": "claude-code-client"
}
```

**Implementation Considerations:**

1. **Parse delegation claims** - Extract `act` (actor) and `azp` (authorized party) from tokens
2. **Enrich audit logs** - Distinguish actor vs delegator:
   ```json
   {
     "event": "SSH_LOGIN_SUCCESS",
     "user": "alice",
     "actor": "ai-agent-claude-code",
     "actor_type": "service",
     "delegated": true
   }
   ```
3. **Policy extensions for AI agents:**
   ```yaml
   ai_agents:
     allow_sudo: false
     allowed_commands:
       - "/usr/bin/cat *"
       - "/usr/bin/grep *"
     require_human_approval: true
   ```
4. **Step-up handling options:**
   - AI operations scoped to never require step-up
   - "Pause for human" flow - agent waits for human to complete step-up
   - Pre-authorization windows - human grants elevated access for limited time

**Related Standards:**
- RFC 8693 - OAuth 2.0 Token Exchange
- OpenID Connect token delegation patterns
- SPIFFE/SPIRE for workload identity

**Open Questions:**
- Should AI agents authenticate as service accounts (separate path) or use delegation claims (same path)?
- How to handle "pause for human step-up" UX in headless agent scenarios?
- Rate limiting and abuse prevention for automated access?
- Integration with agent frameworks (Claude Code permissions, etc.)?
