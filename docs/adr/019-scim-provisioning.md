# ADR-019: SCIM 2.0 Provisioning Architecture

## Status

Accepted

## Context

prmana authenticates users via OIDC but does not create or manage Unix accounts.
Account existence is a prerequisite: if the IdP authenticates a user who has no
corresponding Unix account, PAM authentication succeeds at the OIDC layer but fails
at the system layer ("User not found"). Today, provisioning is a manual process or
handled by an external LDAP/FreeIPA workflow, which creates an operational gap
between identity lifecycle events (hire, role change, departure) and Unix account
state.

SCIM 2.0 (RFC 7643, RFC 7644) is the dominant standard for cross-domain identity
provisioning. All major IdPs (Entra ID, Okta, Google Workspace, Keycloak) support
SCIM push provisioning. Adding a SCIM endpoint to prmana closes the lifecycle
gap: when an IdP provisions or deprovisions a user, the Unix account follows
automatically.

### Design constraints

- **PAM modules must not make outbound provisioning calls.** PAM runs in the
  critical authentication path of sshd. Network calls to provision accounts would
  add latency, introduce failure modes, and expand the attack surface of a
  setuid-equivalent code path.

- **FreeIPA/SSSD remains the group authority** (ADR-008). SCIM group operations
  must reconcile with, not override, the directory.

- **Subprocess-based user management.** Calling `useradd`/`userdel` as subprocesses
  (not libc wrappers) produces audit trail entries in `/var/log/auth.log` and
  integrates with PAM's own `pam_unix` module for account creation hooks. It also
  avoids linking against `libuser` or `libpwquality` whose ABIs vary across
  distributions.

### Options considered

1. **Embed provisioning in the PAM module** — Rejected. PAM is the wrong place for
   account lifecycle operations (latency, privilege scope, failure modes).

2. **Embed provisioning in the agent daemon** — Rejected. The agent runs as the
   authenticating user, not root. User creation requires root privileges.

3. **Standalone SCIM service binary** — Selected. Clean separation of concerns:
   authentication (PAM), credential management (agent), and provisioning (SCIM
   service) are independent processes with independent privilege domains.

4. **Shell script or cron-based reconciliation only** — Rejected. Reconciliation is
   useful as a fallback but does not provide real-time provisioning. IdPs expect a
   SCIM endpoint for push delivery.

## Decision

### Separate binary

A new workspace crate, `prmana-scim`, produces a standalone HTTP service binary.
It is not linked into the PAM module or the agent daemon. The service runs as root
(required for `useradd`/`userdel`) and listens on a configurable address
(default `127.0.0.1:9443`).

### HTTP framework

axum is the HTTP framework. It is the de facto standard async Rust HTTP server,
shares the tokio runtime already used by the agent, and provides tower middleware
for logging, timeouts, and request limits.

### User lifecycle

The SCIM `/Users` endpoint maps to Unix account operations:

| SCIM operation | Unix effect |
|----------------|-------------|
| `POST /Users` | `useradd -m -s /bin/bash -c "{displayName}" {userName}` |
| `GET /Users/{id}` | `getent passwd {userName}` |
| `PUT /Users/{id}` | `usermod` for mutable fields (shell, GECOS) |
| `DELETE /Users/{id}` | `userdel -r {userName}` (configurable: archive vs remove) |

After every provisioning operation, the service calls `getent passwd {userName}` to
confirm the account exists in NSS. This catches silent failures where `useradd`
returns 0 but NSS caching delays visibility.

SCIM `id` is an opaque server-assigned identifier. The service maintains a
`{userName} <-> SCIM id` mapping in a local SQLite database.

### Group lifecycle

The SCIM `/Groups` endpoint maps to `groupadd`/`groupmod`. Per ADR-008, FreeIPA
remains the authoritative group source. SCIM group operations follow a
reconciliation model:

- SCIM group creation creates a local group only if no SSSD-managed group of the
  same name exists.
- SCIM group membership changes trigger `sss_cache -u {userName}` to invalidate
  the SSSD cache, ensuring NSS reflects the latest directory state.
- Group deletion is a no-op if the group is SSSD-managed (log warning, return
  SCIM 409 Conflict).

Group provisioning is deferred from Phase 37 scope (see Scope Limitations below).

### Push and reconciliation

- **Primary**: Webhook push from the IdP. The IdP sends SCIM requests to the
  service endpoint as users are created, modified, or deactivated.
- **Fallback**: Periodic reconciliation poll. The service queries the IdP's SCIM
  client endpoint (if supported) or compares local accounts against a
  known-good user list. Reconciliation catches missed webhook deliveries and
  corrects drift.

Reconciliation is deferred from Phase 37 scope.

### Authentication

The SCIM endpoint authenticates inbound requests using Bearer token validation.
Tokens are validated against the same OIDC issuer configuration used by the PAM
module, reusing the token validation logic from `pam-prmana`. This avoids a
second trust root and ensures that SCIM provisioning requests are authorized by the
same IdP that authenticates users.

A dedicated SCIM scope or role claim (e.g., `scim:provision`) restricts which IdP
principals can invoke provisioning operations. Not every authenticated user can
create accounts.

### Security controls

1. **Username sanitization**: Only POSIX-compliant usernames are accepted:
   `[a-z_][a-z0-9_.-]*`, maximum 32 characters. This is stricter than the 256-byte
   `LOGIN_NAME_MAX` used in PAM validation — SCIM provisioning targets long-lived
   accounts where shorter, conventional names reduce operational risk.

2. **Reserved username denylist**: The same denylist from
   `pam-prmana/src/identity/mapper.rs` (`RESERVED_USERNAMES`: root, daemon, bin,
   sshd, nobody, and 55+ other system accounts) is reused. SCIM requests to
   provision reserved usernames are rejected with SCIM 409 Conflict.

3. **Subprocess execution**: `useradd`, `usermod`, `userdel`, and `groupadd` are
   invoked as subprocesses using `tokio::process::Command`. Arguments are passed as
   separate array elements (never shell-interpolated) to prevent command injection.
   All subprocess calls are logged with full argument lists at INFO level.

4. **Privilege minimization**: Although the service runs as root, it drops
   capabilities after startup to retain only `CAP_DAC_OVERRIDE`, `CAP_CHOWN`,
   `CAP_FOWNER`, and `CAP_SETUID`/`CAP_SETGID` (the minimum set for user
   management). On systems without capability support, the service logs a warning
   and continues as full root.

   > **Superseded by ADR-021 §B (Decision B)** (2026-04-11). The in-process
   > capability dropping described here is not implemented and was found to
   > be fragile under distribution-specific `shadow-utils` and
   > account-management hooks. ADR-021 replaces it with helper-based
   > privilege separation as the target architecture (Decision B) and
   > perimeter hardening of the single-process service as the shipped v1.0
   > posture (Decision A). ADR-021 forbids describing SCIM as
   > privilege-separated until Decision B ships.

5. **Rate limiting**: Tower middleware enforces per-IP rate limits on the SCIM
   endpoint to prevent IdP misconfigurations or compromised tokens from triggering
   mass account creation.

   > **Superseded by ADR-021 §A3** (2026-04-11). The "Tower middleware
   > enforces per-IP rate limits" sentence describes an intended behavior
   > that does not exist in the current code. ADR-021 §A3 replaces it with an
   > explicit layered model (per-IP + per-principal + per-endpoint-class +
   > global + body/header/timeout/concurrency bounds) and calls out that
   > implementation is spec, not code, under phase DT-SCIM.

6. **TLS**: The service requires TLS for non-loopback listeners. Plaintext HTTP is
   permitted only on `127.0.0.1`/`::1` for reverse-proxy deployments.

   > **Superseded by ADR-021 §A1** (2026-04-11). ADR-019's TLS requirement is
   > deployment guidance; ADR-021 §A1 makes it a startup-enforced invariant
   > with a defined bind-target matrix and explicit fail-closed on missing or
   > unreadable key material.

### Phase 37 scope limitations

Phase 37 implements the foundation:

| In scope | Deferred |
|----------|----------|
| SCIM `/Users` CRUD (POST, GET, PUT, DELETE) | SCIM `/Groups` lifecycle |
| `/ServiceProviderConfig` discovery | Bulk operations (RFC 7644 SS3.7) |
| `/Schemas` introspection | PATCH (RFC 7644 SS3.5.2) |
| Bearer token auth for SCIM endpoint | Periodic reconciliation poll |
| Username sanitization + denylist | SCIM filtering/sorting (RFC 7644 SS3.4.2) |
| SQLite state mapping | ETags / conditional requests |

## Consequences

### Positive

- Closes the user lifecycle gap: IdP provisioning events automatically create and
  remove Unix accounts.
- Clean architectural separation: PAM authenticates, agent manages credentials,
  SCIM service manages accounts. Each runs with the minimum required privilege.
- Subprocess-based user management produces native audit trail entries, integrating
  with existing log aggregation and compliance tooling.
- Reusing the PAM crate's token validation avoids a second trust root and keeps
  OIDC issuer configuration in one place.
- Username denylist reuse (from Phase 35) prevents privilege escalation via IdP
  claim manipulation in the provisioning path, consistent with the authentication
  path.

### Negative

- A new long-running service to deploy, monitor, and secure. Adds operational
  surface for teams already managing PAM + agent.
- Running as root is unavoidable for user management but increases the blast radius
  of a service compromise. Capability dropping mitigates but does not eliminate this.
- SQLite state mapping introduces a persistence dependency. Database corruption
  requires reconciliation to recover SCIM ID mappings.
- Subprocess calls to `useradd`/`userdel` are distribution-specific. Behavior
  differences between `shadow-utils` (RHEL) and `adduser` (Debian) require testing
  across the support matrix.

### Future enhancements

- SCIM `/Groups` lifecycle with SSSD reconciliation.
- Periodic reconciliation poll for drift detection and missed-webhook recovery.
- SCIM PATCH support for partial attribute updates.
- Bulk provisioning for large-scale onboarding.
- IdP-mediated deprovisioning confirmation (two-phase delete with grace period).
- Integration with FreeIPA's SCIM bridge when available.

## References

- RFC 7643: System for Cross-domain Identity Management: Core Schema
- RFC 7644: System for Cross-domain Identity Management: Protocol
- RFC 7642: System for Cross-domain Identity Management: Definitions, Overview, Concepts, and Requirements
- ADR-008: SSSD-Only Group Resolution
- ADR-002: PAM Module and Agent Daemon Separation
- NIST SP 800-162: Guide to Attribute Based Access Control Definition and Considerations (provisioning lifecycle context)
