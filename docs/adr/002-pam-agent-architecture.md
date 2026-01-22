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

### 1. PAM Module (`pam_unix_oidc.so`)

Minimal, stateless library responsible for:
- Reading tokens from PAM conversation
- Validating JWT signatures locally
- Validating DPoP proofs
- Communicating with agent via Unix socket
- Audit logging

**Does NOT**:
- Make network calls
- Manage persistent state
- Perform OAuth flows
- Store credentials

### 2. Agent Daemon (`unix-oidc-agent`)

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
        │ JWT Validation                        │ HTTPS
        │ (local, no network)                   │
        ↓                                       ↓
   ┌─────────┐                           ┌─────────────┐
   │ Cached  │                           │   Identity  │
   │  JWKS   │                           │   Provider  │
   └─────────┘                           └─────────────┘
```

### Why this split:

| Concern | PAM Module | Agent Daemon |
|---------|------------|--------------|
| Execution context | Root, in critical service | User, dedicated process |
| Lifetime | Per-auth, short | Long-running |
| Network access | None | Full |
| State | Stateless | Stateful |
| Crash impact | Auth failure | Token unavailable |
| Attack surface | Minimal | Contained |

## Consequences

### Positive

- **Security isolation**: Network code runs in user context, not root
- **Reliability**: PAM module never blocks on network
- **Testability**: Components can be tested independently
- **Flexibility**: Agent can be replaced/upgraded without PAM changes
- **User experience**: Agent handles interactive flows (device auth)

### Negative

- **Deployment complexity**: Two components to install and manage
- **IPC overhead**: Socket communication adds latency (~1ms)
- **Agent dependency**: Auth fails if agent not running
- **Socket security**: Must protect Unix socket permissions

### Design decisions within this architecture

1. **JSON over Unix socket**: Human-readable, debuggable, language-agnostic
2. **Synchronous IPC**: PAM is synchronous; agent handles async internally
3. **Socket path**: `$XDG_RUNTIME_DIR/unix-oidc-agent.sock` (user-specific)
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

- [PAM Module Source](../../pam-unix-oidc/)
- [Agent Daemon Source](../../unix-oidc-agent/)
- [IPC Protocol](../../unix-oidc-agent/src/daemon/protocol.rs)
