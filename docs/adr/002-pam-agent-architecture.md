# ADR-002: PAM Module and Agent Daemon Separation

## Status

Accepted

## Context

Unix authentication via PAM requires a shared library loaded into security-critical processes (sshd, sudo, login). This creates constraints:

1. **Minimal dependencies**: PAM modules should be lightweight
2. **No network in PAM**: Blocking network calls in PAM cause authentication hangs
3. **Stateless execution**: PAM modules are loaded/unloaded per authentication
4. **Privilege separation**: PAM runs as root; minimize attack surface

However, OIDC authentication requires:
- HTTP client for IdP communication
- Cryptographic operations (DPoP signing)
- State management (tokens, keys, caches)
- Async operations (device flow polling)

These requirements conflict with PAM constraints.

## Decision

We split functionality between two components:

### 1. PAM Module (`pam_prmana.so`)

Library responsible for:
- Reading tokens from PAM conversation
- Validating JWT signatures locally (JWKS fetched and cached in-memory)
- Validating DPoP proofs
- Communicating with agent via Unix socket
- Audit logging
- JWKS fetching from IdP discovery endpoint (in-memory cache with configurable TTL)
- Optional token introspection (RFC 7662)
- Optional webhook-based approval flows
- CIBA step-up authentication support (OpenID CIBA Core)

**Does NOT**:
- Manage persistent state (all caches are in-memory)
- Store credentials to disk

### 2. Agent Daemon (`prmana-agent`)

Long-running user process responsible for:
- OAuth device flow execution
- Token acquisition and refresh
- DPoP key management
- Secure credential storage
- IPC server for PAM module

### Communication

```
┌─────────────────┐     Unix Socket     ┌─────────────────┐
│   PAM Module    │ ←───────────────────→ │   Agent Daemon  │
│ (in sshd/sudo)  │   JSON Protocol     │ (user process)  │
└─────────────────┘                     └─────────────────┘
        │                                       │
        │ JWT Validation + JWKS fetch           │ HTTPS
        │ (in-memory cache, HTTPS on miss)      │
        ↓                                       ↓
   ┌─────────────┐                       ┌─────────────┐
   │  In-memory  │  ──HTTPS on miss──→   │   Identity  │
   │  JWKS cache │                       │   Provider  │
   └─────────────┘                       └─────────────┘
```

### Why this split:

| Concern | PAM Module | Agent Daemon |
|---------|------------|--------------|
| Execution context | Root, in critical service | User, dedicated process |
| Lifetime | Per-auth, short | Long-running |
| Network access | JWKS fetch, introspection, webhooks (in-memory cache) | Full (device flow, token refresh) |
| State | In-memory caches only | Persistent (keyring/file) |
| Crash impact | Auth failure | Token unavailable |
| Attack surface | Moderate (HTTP client for JWKS/introspection) | Contained |

## Consequences

### Positive

- **Security isolation**: Token acquisition and device flow run in user context, not root
- **Reliability**: PAM module's network calls (JWKS, introspection) are timebound and cached; token acquisition flows run in the agent
- **Testability**: Components can be tested independently
- **Flexibility**: Agent can be replaced/upgraded without PAM changes
- **User experience**: Agent handles interactive flows (device auth)

### Negative

- **Deployment complexity**: Two components to install and manage
- **IPC overhead**: Socket communication adds latency (~1ms)
- **Agent dependency**: Auth fails if agent not running
- **Socket security**: Must protect Unix socket permissions

### IPC Protocol

The agent exposes a JSON-over-Unix-socket protocol with these request types:

| Request | Purpose |
|---------|---------|
| `GetProof` | Generate a fresh DPoP proof for a target server |
| `Status` | Check agent health and token state |
| `Metrics` | Retrieve Prometheus-format metrics |
| `Refresh` | Trigger token refresh |
| `Shutdown` | Graceful daemon shutdown |
| `SessionClosed` | Credential cleanup on session end (MEM-03/05) |
| `StepUp` | Initiate CIBA step-up authentication (OpenID CIBA Core) |
| `StepUpResult` | Poll for step-up completion |

### Design decisions within this architecture

1. **JSON over Unix socket**: Human-readable, debuggable, language-agnostic
2. **Synchronous IPC**: PAM is synchronous; agent handles async internally
3. **Socket path**: `$XDG_RUNTIME_DIR/prmana-agent.sock` (user-specific)
4. **Socket permissions**: 0600 (owner only)

### Mitigations

- Clear error messages when agent unavailable
- Socket permission verification before use
- Connection timeout to prevent PAM hangs
- Graceful degradation (status checks before proof requests)

## Alternatives Considered

### Single PAM Module (rejected)

- Would require network in PAM context
- Blocking calls cause sshd hangs
- Large binary with many dependencies
- Complex error handling for network failures

### Systemd Socket Activation (considered)

- Would start agent on-demand
- Added complexity for marginal benefit
- User may want agent always running for device flow

### D-Bus IPC (rejected)

- Additional dependency
- More complex than needed
- Unix socket sufficient for local IPC

## References

- [PAM Module Source](../../pam-prmana/)
- [Agent Daemon Source](../../prmana-agent/)
- [IPC Protocol](../../prmana-agent/src/daemon/protocol.rs)
