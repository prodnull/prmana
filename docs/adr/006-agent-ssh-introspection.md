# ADR-006: Agent SSH Config Introspection for Automatic Audience Discovery

## Status

Proposed

## Context

When a user connects through a multi-hop SSH path (e.g., `user → jump-host-a → jump-host-b → target`), the prmana-agent needs to request tokens with the correct audiences for each hop. Currently, the agent only accepts a single `target` parameter and has no knowledge of the full hop chain.

**Problem**: How does the client-side agent know what audiences to include in the initial token?

1. User's initial token includes jump-host-a in audience
2. Jump-host-a exchanges for token with jump-host-b in audience
3. Jump-host-b exchanges for token with target in audience

## Decision

We will implement **SSH config introspection** in prmana-agent to automatically discover the hop chain from `~/.ssh/config` and generate tokens with appropriate audiences.

### SSH Config Format

SSH config supports multi-hop connections via `ProxyJump`:

```ssh-config
Host internal-*
    ProxyJump jump.example.com
    User alice

Host db-prod
    ProxyJump jump-a.example.com,jump-b.example.com
    User dbadmin
```

### Protocol Enhancement (Backward Compatible)

```json
{
    "action": "get_proof",
    "target": "server.example.com",
    "method": "SSH",
    "nonce": "optional-nonce",
    "audience_chain": ["jump-a.example.com", "jump-b.example.com", "server.example.com"],
    "introspect_ssh_config": true
}
```

### New Discover Action

```json
{
    "action": "discover_audiences",
    "target": "db-prod.example.com"
}
```

Response includes discovered hop chain from SSH config.

### Security Considerations

1. Config file permissions validated (not world-writable)
2. Audience strings validated as valid hostnames
3. Maximum chain depth enforced (5 hops)
4. User's own config within trust boundary

### CLI Integration

```bash
# Automatic introspection
prmana-agent get-proof --target db-prod.example.com

# Query what would be discovered
prmana-agent discover-audiences db-prod.example.com
```

## References

- [ssh_config(5) man page](https://man.openbsd.org/ssh_config)
