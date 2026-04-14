# idp-proxy

A programmable HTTP fault-injection proxy for CI IdP outage simulation.

Sits between the prmana client/PAM module and the upstream Identity Provider
(Keycloak in CI). Enables reproducible "IdP is broken" scenarios by injecting
503 errors, slow responses, malformed JWKS, and connection drops on demand —
from a bash script, without modifying the IdP or the client.

**This tool is CI-only.** It is not intended for production use.

---

## CLI Reference

### `serve` — start the proxy

```
idp-proxy serve \
  --upstream <URL>    # Upstream IdP base URL, e.g. http://keycloak:8080
  --listen <ADDR>     # Address for proxied traffic, e.g. 0.0.0.0:9443
  --control <ADDR>    # Control plane address (loopback only), e.g. 127.0.0.1:9444
```

The proxy starts two listeners:
- **Proxy listener** (`--listen`): forwards all OIDC traffic to `--upstream`
- **Control plane** (`--control`): accepts fault injection commands via HTTP

### `fault` — inject a fault into a running proxy

```
idp-proxy fault \
  --control <URL>       # Control plane URL, e.g. http://127.0.0.1:9444
  --mode <MODE>         # Fault mode (see table below)
  [--duration <DUR>]    # e.g. 60s, 5m; default: permanent until next command
  [--latency <DUR>]     # For slow mode only, e.g. 30s; default: 30s
```

---

## Fault Modes

| Mode | Upstream contacted? | Client-observable behavior |
|------|--------------------|-----------------------------|
| `off` | Yes (pass-through) | Normal response from upstream |
| `503` | No | HTTP 503 with body `{"error":"service_unavailable"}` |
| `slow` | Yes, after delay | Normal response, but delayed by `--latency` |
| `malformed-jwks` | Yes (for non-JWKS paths) | JWKS paths return truncated invalid JSON; other paths pass through |
| `drop-connection` | No | TCP connection dropped; client observes I/O error |

### JWKS path matching (malformed-jwks mode)

The following path substrings are matched case-insensitively:
- `/protocol/openid-connect/certs` (Keycloak)
- `/.well-known/jwks.json` (standard OIDC discovery)
- `/jwks` (short form)

Paths that do not match any of the above are forwarded to upstream unchanged.

---

## Example bash usage

```bash
# Start the proxy
idp-proxy serve \
  --upstream http://keycloak:8080 \
  --listen 0.0.0.0:9443 \
  --control 127.0.0.1:9444 &
PROXY_PID=$!

# Wait for proxy to bind
sleep 1

# Inject a 503 fault for 60 seconds
idp-proxy fault --control http://127.0.0.1:9444 --mode 503 --duration 60s

# ... run fleet test assertions here (clients should observe 503) ...

# Restore normal operation
idp-proxy fault --control http://127.0.0.1:9444 --mode off

# ... assert recovery ...

# Teardown
kill $PROXY_PID
```

### Integration with fleet-test.yml

The `fleet-test.yml` workflow (plan DT-0-04) wires this proxy into CI. The
`if: always()` teardown step issues `--mode off` before killing the process,
ensuring no fault state lingers across test scenarios.

---

## Security Posture

### Control plane MUST bind to loopback

The `--control` address MUST be `127.0.0.1:<port>` (or `::1` for IPv6) in CI.
Binding the control plane to a public interface exposes fault injection as a
remote DoS vector against whatever the proxy fronts.

The `serve` subcommand accepts any `SocketAddr` to allow test environments to
pass loopback addresses. **The operator is responsible for passing a loopback
address.** CI workflows MUST pass `127.0.0.1:9444`, never `0.0.0.0:9444`.

### Logging never emits tokens

The proxy logs exactly four fields per request:
- `method` — HTTP method (GET, POST, …)
- `path` — request path (not the full URI, not query string values)
- `status` — response status code
- `latency_ms` — end-to-end latency in milliseconds
- `fault_mode` — active fault mode at request time

**Never logged:** request body, response body (except generated error bodies),
`Authorization` header, `X-Token-*` headers, or query string parameter values
for `code`, `access_token`, `id_token`, or `client_secret`.

The codebase enforces this by never using `tracing::debug!(?req)`,
`%headers`, or similar catchall formatters. A grep audit is part of the
CI verification step:

```bash
grep -r "?req\|%headers\|Authorization\|access_token" src/ tests/
# Expected: only comments, not log statements
```

### No persistent state

Fault state is held in process memory only. Restarting the proxy unconditionally
clears all faults. There is no configuration file, no database, no inter-process
shared state.

### Unprivileged process

The proxy binds to ports >= 1024 and requires no special capabilities
(`CAP_NET_BIND_SERVICE`, `setuid`, etc.).

---

## Building

```bash
# Development build
cd test/infra/idp-proxy
cargo build

# Release build (used in CI)
cargo build --release

# Run tests
cargo test
cargo test --release

# Lint
cargo clippy -- -D warnings
```

### Log level

Default: `idp_proxy=info` (respects `RUST_LOG` environment variable).

`RUST_LOG=idp_proxy=debug` provides more detail on upstream forwarding but
MUST NOT be used in environments with real OIDC traffic, even though the
structured-field constraints prevent token values from appearing in log output.
