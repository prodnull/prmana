# ADR-021: SCIM Service Hardening and Target-State Privilege Separation

## Status

Accepted (2026-04-11, after second-pass adversarial review)

This ADR supersedes ADR-019's security-control claims around in-process
capability dropping, advisory TLS, and unspecified rate limiting. Decision A
below is required for `v1.0`. Decision B is the selected target architecture,
but it is not a `v1.0` property until it is implemented and tested.

**Review history:**
- 2026-04-11 first-pass review flagged 10+ redlines; ADR was revised to split
  Decision A / Decision B and was re-submitted.
- 2026-04-11 second-pass review found the split architecturally honest,
  requested 13 redlines (implementation status note, TLS fail-closed
  semantics, untrusted-peer behavior, library-choice honesty, audit chain
  integration, `dry_run` decision, 500 vs 503 contract, reconciliation
  specification, Linux-only scope, `PrivateUsers=no` default, `IPAddressDeny`
  fail-closed, ADR-019 inline supersession, new connection-level controls).
- All 13 redlines applied; ADR marked Accepted.

## Context

ADR-019 introduced `prmana-scim` as a standalone SCIM 2.0 provisioning service.
That remains correct. Provisioning does not belong in PAM, and Unix account
lifecycle operations require a different operational boundary than interactive
authentication and credential caching.

The current SCIM implementation is materially less hardened than ADR-019
described:

- The service binds a raw TCP listener directly in-process and does not enforce
  a startup transport policy beyond Bearer token validation.
- The router has authentication middleware but no mandatory request body limit,
  no request timeout, no concurrency bound, and no rate limiting.
- The shipped systemd unit is internally inconsistent with the binary and the
  privilege model: `ExecStart=/usr/bin/prmana-scim serve` references a
  subcommand that does not exist, while `User=prmana` and an empty
  `CapabilityBoundingSet=` cannot successfully run `useradd`/`usermod`/`userdel`.
- The current trust boundary is a single process that performs network I/O, JWT
  parsing, SCIM parsing, state persistence, and privileged account mutation.

Recent hardening work closed the most severe authorization gap by enforcing a
dedicated SCIM entitlement claim and by persisting the `SCIM id <-> userName`
mapping across restarts. Those fixes improve correctness and authorization, but
they do not provide the perimeter controls or privilege separation implied by
ADR-019.

For `v1.0`, prmana needs a SCIM hardening model that is:

- **Deployable**: the service unit and the process privileges must match the
  actual binary behavior.
- **Testable**: the security claims must be enforceable with automated tests.
- **Conservative**: root-equivalent code paths must be kept as small as
  possible.
- **Honest**: documentation and marketing must not claim "privilege separation"
  for SCIM until there is an actual helper boundary in production code.

### Design constraints

- **Provisioning remains a standalone service.** ADR-019 is unchanged on this
  point; PAM and the agent daemon must not absorb provisioning logic.
- **Unix account management remains subprocess-based.** `useradd`, `usermod`,
  `userdel`, and `getent` remain the integration points because they preserve
  native distribution behavior and audit trails.
- **Loopback reverse-proxy deployments remain supported.** Operators may
  terminate TLS in nginx, Envoy, or a load balancer and forward to a loopback
  listener or Unix socket.
- **Transport policy must be enforced by startup checks, not docs.** A public or
  otherwise non-loopback bind must not silently run over plaintext HTTP.
- **Forwarded headers are untrusted by default.** Client IP and scheme are
  derived from the direct peer unless the operator explicitly configures trusted
  proxy CIDRs.
- **Service UIDs must not be reused across unrelated processes.** A future
  helper design depends on a dedicated SCIM service UID distinct from the agent
  UID used in ADR-013.
- **The helper boundary, when implemented, must be narrow and versioned.** Any
  privileged helper must not perform network I/O, JWT validation, or SCIM
  parsing, and its IPC schema must be versioned from day one.
- **Runtime `dry_run` is not a production feature.** A config knob that silently
  suppresses account creation is too dangerous to leave enabled in production
  deployments.

### Alternatives considered

| Option | Pros | Cons |
|--------|------|------|
| **Single-process hardening only** | Lowest implementation churn; fastest path to an honest `v1.0` | Network-facing root process remains the trust boundary; no privilege separation |
| **Single process plus in-process capability dropping** | Superficially preserves ADR-019 language | Fragile, distro-specific, and difficult to prove with `shadow-utils` and account-management hooks |
| **Single-process hardening for `v1.0`, then helper split (chosen)** | Honest about `v1.0`, while selecting a stronger end state | Requires two phases and discipline not to overclaim before phase two lands |
| **Helper split before `v1.0`** | Best immediate privilege story | Higher schedule risk; more moving pieces before `v1.0` |
| **External reverse proxy as the only perimeter control** | Keeps Rust service simpler | Pushes critical controls into deployment folklore; not enforceable by the application |

## Decision

This ADR makes two separable decisions.

### Implementation Status

Decision A is an architectural specification, not shipped code. At the time this
ADR was accepted, none of the Decision A controls existed in `prmana-scim/`:

- `prmana-scim/src/main.rs` binds a raw `TcpListener` with no transport policy
  check.
- `prmana-scim/src/routes.rs` builds a router whose only middleware layer is
  `auth_middleware`; there is no body limit, request timeout, concurrency
  bound, or rate limiter.
- `prmana-scim/src/config.rs` has no TLS, proxy, rate-limit, or audit fields.
- `prmana-scim/src/config.rs` still exposes `dry_run` as a runtime `bool`.
- `contrib/systemd/prmana-scim.service` still points `ExecStart` at a
  nonexistent `serve` subcommand and still declares `User=prmana` with an empty
  `CapabilityBoundingSet=` — a unit that cannot run `useradd`.

This ADR therefore commits the project to implementing Decision A before
tagging `v1.0` or to shipping `v1.0` with an explicit waiver table naming each
missing control. Implementation is tracked under phase `DT-SCIM` (see
`.planning/ROADMAP.md`). No language in the README, marketing, or SECURITY.md
should describe SCIM as hardened in the ways listed below until the phase lands
and its controls are verified in CI.

### Decision A: `v1.0`-blocking hardening of the current single-process service

`v1.0` ships a hardened single-process SCIM service unless and until Decision B
is implemented. That service is **not** described as privilege-separated.

Decision A requires all of the following before `v1.0`:

- startup-enforced transport policy
- mandatory request-shaping middleware
- structured audit events with request correlation
- removal or hard isolation of runtime `dry_run`
- a corrected deployment model and systemd unit that reflects the actual
  executable and privilege model

If `prmana-scim` continues to execute `useradd`/`usermod`/`userdel` in-process
for `v1.0`, then the service unit must run with the privileges required for that
behavior. The currently committed `User=prmana` plus empty capability set is not
a hardening measure; it is a broken deployment.

#### A1. Startup-enforced transport policy

The SCIM service enforces transport policy at startup according to the bind
target:

| Bind target | Plain HTTP allowed | Notes |
|-------------|--------------------|-------|
| `127.0.0.1`, `::1` | Yes | Intended for local reverse proxy deployments |
| Unix domain socket | Yes | Intended for local reverse proxy deployments |
| `0.0.0.0`, `::` | No | Wildcard binds are always treated as non-loopback |
| Any non-loopback unicast address | No | Includes RFC1918, IPv6 ULA, link-local, pod/container IPs, and public IPs |

When plaintext is disallowed, startup fails unless native TLS is configured.
"Native TLS is configured" is defined as: a valid PEM-encoded certificate and
private key, readable by the service user, successfully loaded by rustls at
startup. The service does not proxy, delegate, or silently fall back to
plaintext under any circumstance, including missing, unreadable, or
corrupt key files. In those cases startup fails with a non-zero exit code and
a structured log line naming the cause.

For the native TLS path:

- the service uses `rustls` via `axum-server` (or equivalent rustls-backed
  hyper integration)
- TLS 1.3 is required; older protocol versions are rejected at load time
- cipher suite policy is the rustls default TLS 1.3 suite set; no config knob
  is provided because TLS 1.3 removes most of the tunables that historically
  existed for TLS 1.2 and older
- Bearer token authentication remains the application-layer auth mechanism
- client certificate authentication is not a `v1.0` feature

Operators who need mTLS in `v1.0` must terminate TLS at a reverse proxy on
loopback or a Unix socket. That limitation is explicit.

Certificate rotation in `v1.0` is restart-based. Hot reload is deferred.

#### A2. Trusted proxy model

Forwarded headers are ignored by default.

`v1.0` supports only a conservative proxy model:

- the direct peer IP must match `trusted_proxy_cidrs`
- only `X-Forwarded-For` and `X-Forwarded-Proto` are considered
- only a single directly connected trusted proxy is supported
- `Forwarded:` (RFC 7239) and multi-hop proxy chains are ignored in `v1.0`

Audit events distinguish:

- direct peer address
- derived client address from trusted proxy headers, when used

When a request arrives from a peer that does **not** match `trusted_proxy_cidrs`,
any `X-Forwarded-*` headers are discarded before the request enters the handler.
The request is processed using the direct peer address as the client address;
the audit event includes `forwarded_headers_stripped=true`. Requests are never
rejected for carrying untrusted forwarded headers — reject-on-header is an
operator footgun for internal probes, and strip-and-audit is sufficient for
correlation and abuse detection.

#### A3. Mandatory request-shaping middleware

The single-process SCIM service must apply all of the following layers
simultaneously:

1. global per-process rate limit
2. per-source-IP rate limit regardless of authentication state
3. per-authenticated-principal rate limit keyed by `client_id` or `sub`
4. per-endpoint-class rate limit, separating reads from writes, with
   `/ServiceProviderConfig` and `/Schemas` isolated into a **discovery**
   endpoint class exempt from per-principal limits (Okta/Entra provisioning
   clients re-fetch these every cycle; limiting them trips SCIM clients for
   no abuse-mitigation gain)
5. request body size limit
6. request HTTP header size limit (defense against oversized headers; the
   default tracks hyper's 16 KiB total-header ceiling, but the ADR calls it
   out explicitly so a future hyper upgrade changing the default does not
   regress silently)
7. per-request timeout
8. TCP read-idle timeout separate from the request timeout (slowloris
   mitigation — a trickle attacker staying under `request_timeout_secs`
   still pins a concurrency slot otherwise)
9. keep-alive idle timeout
10. in-flight concurrency limit
11. request ID generation and propagation

**Implementation cost note.** Layers 1–4 require a per-key rate limiter that
understands a composite of (`trusted_proxy_cidrs`-derived client IP,
authenticated principal, endpoint class). No first-party `tower`/`axum`
middleware provides this directly. The canonical choices are `tower-governor`
(built on `governor`) with a custom composite key extractor, or a hand-rolled
`tower::Service` wrapping `governor::RateLimiter`. Either is a multi-day
implementation task, not a middleware bolt-on. The rate-limiter library choice
is a deliberate implementation decision that must be made in phase DT-SCIM,
not deferred to whoever opens the PR.

**Illustrative** baseline defaults for `v1.0` (final values are set against
the provider test matrix — Okta bulk-provisioning burst patterns, Entra ID
delta sync, Keycloak webhook loops — during implementation, not in this ADR):

- `max_body_bytes = 64 KiB` for single-resource routes
- `max_header_bytes = 16 KiB` total request headers
- `request_timeout_secs = 10`
- `tcp_read_idle_secs = 5`
- `keepalive_idle_secs = 30`
- `max_concurrent_requests = 32`
- `global_rate_limit_rps = 100`
- `per_ip_rate_limit_rps = 10`
- `per_principal_read_rps = 50`
- `per_principal_write_rps = 5`

Bulk SCIM routes remain unsupported. If bulk routes are later implemented, they
must get a separate body limit and separate endpoint-class rate limit rather
than inheriting the single-resource defaults.

Read routes and write routes must not share the same bucket. `POST`, `PUT`, and
`DELETE` on `/Users` are materially more expensive than `GET
/ServiceProviderConfig` or `/Schemas`.

The service returns deterministic SCIM-style error responses for:

- `413 Payload Too Large`
- `429 Too Many Requests` — MUST include a `Retry-After` header with a
  jitter-suppressed recommended retry interval
- `503 Service Unavailable` on concurrency-bound rejection — MUST include a
  `Retry-After` header; distinct from the 503 reserved for the Decision B
  helper-unavailable path (`result` distinguishes them in audit)
- request timeout failures (`504 Gateway Timeout` is not used; `500` with
  `result=request_timeout` is consistent with the synchronous failure model
  in §A6)

#### A4. Structured audit events

Every request must emit structured audit fields including:

- `request_id`
- `peer_addr` (always the direct TCP peer, even behind a trusted proxy)
- `client_addr` (authoritative for SIEM correlation when the request came via
  a trusted proxy; equals `peer_addr` when no trusted proxy applied)
- `tls_mode_active`
- `forwarded_headers_stripped` (true when untrusted `X-Forwarded-*` headers
  were discarded per §A2)
- `auth_mechanism`
- `issuer`
- `client_id` or `sub`
- `jwt_jti` when present (requires adding `jti` to the `BearerClaims` struct
  in `prmana-scim/src/auth.rs`; this is a trivial change but is flagged so an
  implementer does not chase a phantom missing field)
- `action`
- `scim_id`
- `user_name`
- `request_bytes`
- `result`
- `failure_reason`
- `latency_ms`

Rejected requests emit audit events as the highest-signal abuse-detection
source. The following `result` values are required:

- `result=rate_limited` for 429 rejections (with which rate-limit layer tripped)
- `result=payload_too_large` for 413 rejections
- `result=header_too_large` for 431 rejections
- `result=concurrency_exceeded` for the v1.0 503 rejection on concurrency
  bound (distinct from the post-v1.0 `result=helper_unavailable`)
- `result=request_timeout` for timeout failures
- `result=read_idle_timeout` for slowloris-class TCP-level timeouts

**Audit stream relationship to ADR-010.** SCIM audit events MUST join the
ADR-010 HMAC audit chain. SCIM is a more privileged code path than
prmana-agent and has a stronger case for tamper evidence, not a weaker one.
The chain sink lives in a workspace-shared audit sink so SCIM, agent, and
(post-v1.0) helper audit records share sequence numbers and HMAC continuity.
An independent second audit stream is rejected: it doubles the SIEM
integration burden without adding forensic value.

Audit correlation must be good enough that a provisioning request can be traced
end to end through the service and, later, through the helper. This is a
deployment requirement, not a nice-to-have.

#### A5. Runtime `dry_run`

**Decision:** `dry_run` is removed from the runtime config surface for `v1.0`.

`prmana-scim/src/provisioner.rs` already defines an `AccountBackend` trait with
a `SystemAccountBackend` production implementation and a `FakeAccountBackend`
test implementation gated behind `#[cfg(test)]`. The production binary does
not need — and must not expose — a runtime flag that silently suppresses
account mutation. All testing that exercises the provisioning logic goes
through `FakeAccountBackend` selected at compile time; production builds have
no code path that skips `useradd` while accepting real SCIM traffic.

The `dry_run: bool` field is deleted from `ScimConfig`. Any tests that
currently set `dry_run: true` on a production `Provisioner` are migrated to
construct a `Provisioner` with `FakeAccountBackend` via
`with_account_backend(...)` instead. The `account_visible` helper that
currently returns `true` when `config.dry_run` is set is deleted along with
the config field.

The service must not silently accept real SCIM traffic while intentionally
skipping account mutation.

#### A6. Failure behavior

For `v1.0`, SCIM operations fail synchronously. There is no internal work queue
and no deferred retry pipeline.

When the service cannot complete a provisioning operation, it returns an error
to the caller immediately. `v1.0` uses the following status-code contract:

- **`500 Internal Server Error`** for state-persistence failures, `useradd`/
  `usermod`/`userdel` non-zero exit, NSS lookup failures after a successful
  subprocess, and any other unexpected operational failure. The SCIM error
  body carries a generic `detail` string; detailed causes stay in audit logs
  per the "generic to user, detailed in logs" policy in CLAUDE.md. IdP clients
  that see `500` surface an administrator-visible error and do not retry
  automatically.
- **`503 Service Unavailable` + `Retry-After`** is **reserved** for two cases
  only: concurrency-bound rejection (§A3) and the Decision B helper-unavailable
  path. `v1.0` does **not** map internal state-store or subprocess failures to
  `503`; doing so would silently invite Okta and Entra retry loops against
  unrecoverable errors.

The architectural principle: `503` is a "try again soon" signal. State-store
corruption and `useradd` failures are not "try again soon" problems; they are
operator-intervention problems. Using `500` for them surfaces the issue in the
IdP admin console where an operator will see it.

### Decision B: target-state privilege separation after `v1.0`

The selected target architecture is:

- an unprivileged SCIM HTTP front-end
- a minimal privileged local helper over a Unix domain socket

This architecture may land after `v1.0`, but it must exist before the project
describes SCIM as privilege-separated.

#### B1. Front-end identity and responsibility

The front-end runs as a dedicated service account `prmana-scim`, distinct from
the agent's service identity and configured with a non-login shell such as
`/usr/sbin/nologin`.

The front-end is responsible for:

- TCP/TLS listener startup and transport enforcement
- Bearer token validation and SCIM entitlement enforcement
- SCIM parsing, schema validation, and username policy
- request-shaping middleware and audit logging
- persistent ownership of the `SCIM id <-> userName` mapping
- reconciliation of persisted mappings against `getent` on startup
- translation of high-level provisioning requests into helper RPCs

NSS remains the source of truth for account existence. The front-end's state
store remains the source of truth for the SCIM identifier mapping. On startup,
the front-end reconciles persisted mappings against `getent` and surfaces
orphaned or missing-account mappings explicitly rather than silently claiming
the system is consistent.

Reconciliation behavior is specified as follows (underspecifying these is how
operators end up with ghost accounts after disaster-recovery restores or
after a `userdel` outside SCIM's control):

- **Orphan mapping (SCIM has a mapping, NSS does not resolve the username).**
  Logged at `WARN` with the mapping's SCIM id and userName. Exposed via a
  non-standard `x-prmana-orphans` field on `/ServiceProviderConfig` for
  operator visibility. Startup continues. The SCIM API returns `404` when
  those mappings are requested (the backing account is genuinely missing).
  Automatic deletion of orphan mappings is **not** performed; the decision to
  delete or re-create is an operator action.

- **Orphan account (NSS resolves a username that SCIM has no mapping for).**
  Never adopted automatically. Logged at `INFO`. This is the correct
  behavior for hosts where prmana-scim coexists with pre-existing local or
  SSSD-provisioned accounts.

- **Reconciliation timeout.** A 50k-user NSS fleet with `getent passwd`
  per-username resolution takes minutes. `startup_reconcile_timeout_secs`
  defaults to 60. Exceeding the timeout is **not** a startup failure; the
  service starts and exposes the degraded state via a
  `x-prmana-reconcile-timeout=true` field on `/ServiceProviderConfig`.
  Incomplete reconciliation is logged at `WARN` with counts of verified and
  unverified mappings.

#### B2. Helper responsibility and peer authentication

The helper's responsibilities are limited to:

- `create_user`
- `replace_user` for explicitly allowed mutable fields
- `delete_user`
- `lookup_user` / `getent` verification

The helper must not:

- listen on TCP
- fetch JWKS or contact an IdP
- parse SCIM JSON
- validate JWTs
- own the SCIM mapping store
- log Bearer tokens or any other auth material from the front-end

The helper authenticates the peer connection using `SO_PEERCRED` on Linux and
checks that the connecting UID is in an explicit allowlist. The default allowlist
contains only the `prmana-scim` service UID.

**Platform scope.** `prmana-scim` is a **Linux-only** service. macOS and
FreeBSD peer-auth primitives (`LOCAL_PEERCRED`, `getpeereid`) return weaker
information than `SO_PEERCRED` (EUID only, no PID, different validity windows)
and are out of scope for the helper trust boundary. `prmana-scim` does **not**
ship launchd or rc.d units. SCIM provisioning is a server-side concern;
developer workstations run `prmana-agent` but not `prmana-scim`.

Socket filesystem permissions are defense in depth only:

- socket path under `/run/prmana/`
- ownership `root:prmana-scim`
- mode `0660`
- Unix-domain-socket listeners on the front-end side (when the front-end
  itself serves SCIM over a Unix socket) MUST refuse to start unless the
  socket path is `chmod 0660` with a restricted owning group; the service
  logs and exits non-zero otherwise.

Filesystem permissions are not treated as the authentication mechanism.

#### B3. Helper RPC contract

The helper RPC protocol is versioned from day one.

`v1` uses:

- `AF_UNIX` stream socket
- one request per connection
- length-prefixed JSON message framing
- explicit `version`
- explicit `request_id`
- explicit operation enum and typed payload
- explicit success/error response envelope

The protocol is intentionally simple and debuggable. There is no request
multiplexing in `v1`.

Mutating helper RPCs are not retried automatically by the front-end. If the
front-end cannot determine whether a mutating RPC completed, it records an audit
outcome that the helper result is unknown and returns a retriable service error
to the caller rather than guessing.

If the front-end disconnects mid-request, the helper completes the current
operation and records its outcome. The helper does not attempt mid-flight
cancellation of account-management subprocesses.

#### B4. Helper failure semantics

There is no internal durable queue between the front-end and the helper.

If the helper is unavailable, overloaded, or times out:

- the front-end returns `503 Service Unavailable`
- the response includes `Retry-After`
- the event is audited with `result=helper_unavailable` or equivalent

This keeps the failure mode explicit and avoids hidden replay storms caused by
internal buffering.

#### B5. Deployment model for helper separation

The helper-separated deployment uses at least three units:

- `prmana-scim-helper.socket`
- `prmana-scim-helper.service`
- `prmana-scim.service`

`prmana-scim.service` depends on the helper socket, not on ad hoc filesystem
creation. The front-end unit must `Require=` and `After=` the helper socket.

The front-end unit should use:

- `User=prmana-scim`
- `NoNewPrivileges=yes`
- empty capability set
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
- `ProtectProc=invisible`
- `PrivateUsers=no` — this is the **default**. `PrivateUsers=yes` creates a
  user namespace that interacts badly with `useradd`'s `setuid`/`setgid` and
  its distribution-specific subuid/subgid requirements. On most distributions
  the package postinst does not configure subuid ranges for the service user,
  and enabling `PrivateUsers=yes` without that host preparation causes silent
  `useradd` failures that do not show up in CI. `PrivateUsers=yes` is allowed
  only on deployments where it has been explicitly verified on the support
  matrix; it is never the default.

The helper unit should use:

- `User=root`
- `RestrictAddressFamilies=AF_UNIX`
- `IPAddressDeny=any` or equivalent no-network policy, with the constraint
  that if the systemd version or kernel cannot **enforce** `IPAddressDeny=`,
  the helper unit MUST fail-closed (refuse to load) rather than silently
  accept a no-enforcement configuration. Silent-accept on pre-eBPF systemd
  (CentOS 7, Debian 10, Ubuntu 18.04) is not acceptable in v1.0 or v1.1.
  The unit MUST use `AssertKernelVersion=` / `ConditionSecurity=ip_filter`
  (or the equivalent effective assertion) to guarantee enforcement.
- only the runtime path needed for the socket as an explicit writable path

The helper unit must be validated on the Linux support matrix before the project
claims aggressive filesystem sandboxing. `useradd` and `userdel` touch
distribution-specific paths under `/etc`, `/var`, home-directory roots, and
distribution hooks. The helper must not claim `ProtectSystem=strict`-style
confinement until that behavior is proven across supported distributions.

## Consequences

### Positive

- `v1.0` gets enforceable perimeter controls instead of advisory-only docs.
- The broken SCIM unit story is replaced by a deployment model that matches the
  actual executable and privilege requirements.
- The target architecture, once implemented, removes network-facing root account
  mutation from the main SCIM process.
- The helper design keeps the privileged ABI narrow, auditable, and testable.

### Negative

- `v1.0` still ships without privilege separation if only Decision A is
  complete.
- The eventual two-process model adds an RPC protocol, more units, and more
  operational complexity.
- The helper protocol becomes a long-lived compatibility surface and must be
  versioned carefully.
- Distro-specific account-management behavior still requires support-matrix
  testing before hardening claims can be generalized.

### Risks

- Reusing the `prmana-scim` UID for unrelated processes would weaken the helper
  trust boundary.
- Rate limits tuned too aggressively can hurt large shared-egress deployments;
  tuned too loosely they provide little abuse resistance.
- Hidden compatibility assumptions in the helper RPC can turn upgrades into
  coordinated rollouts if the protocol is not versioned cleanly from the start.
- Adding any future "insecure public bind" bypass flag would undermine the
  startup transport invariant and would require a separate ADR.

### Effect on ADR-019

ADR-019 remains valid for:

- using a standalone SCIM service
- subprocess-based Unix account management
- Bearer token authentication
- username sanitization and reserved-name denial

This ADR supersedes ADR-019 in three places:

- ADR-019 Security controls §4: helper separation replaces in-process
  capability-dropping as the primary privilege-minimization strategy
- ADR-019 Security controls §5: rate limiting becomes an explicit layered model
  rather than an unspecified future middleware claim
- ADR-019 Security controls §6: TLS becomes a startup-enforced invariant rather
  than deployment guidance

This ADR also requires an **inline edit to ADR-019 itself**: the Security
controls §5 paragraph that asserts "Tower middleware enforces per-IP rate
limits on the SCIM endpoint" is a false statement about the current code and
a false specification of the intended behavior. ADR-019:§5 must carry an
inline "Superseded by ADR-021 §A3" note so grep-auditors of the ADR corpus
do not pull the unsuperseded sentence as still-authoritative.

Until Decision B is implemented, tested, and shipped, project documentation must
describe SCIM as having perimeter hardening and request-shaping controls, not as
privilege-separated.

## References

- ADR-019: SCIM 2.0 Provisioning Architecture
- ADR-013: Same-UID IPC Trust Model
- ADR-010: HMAC Audit Chain Composition
- RFC 7643: System for Cross-domain Identity Management: Core Schema
- RFC 7644: System for Cross-domain Identity Management: Protocol
