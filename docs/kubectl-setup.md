# prmana-kubectl — Kubernetes SSO Access

prmana-kubectl gives developers transparent SSO access to Kubernetes clusters. Every
kubectl command acquires a short-lived (10 min) OIDC token scoped to a single cluster
audience, issued by the prmana agent after normal SSO login. No long-lived credentials
stored in kubeconfig.

## Architecture

```
Developer machine
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│  kubectl ──── ExecCredential plugin call ────► prmana-kubectl     │
│                                                       │            │
│                                               IPC socket           │
│                                                       │            │
│                                               prmana-agent         │
│                                                       │            │
│                                           RFC 8693 token exchange  │
│                                                       │            │
│                                               IdP (Okta/Entra/    │
│                                               Keycloak/Auth0)      │
└────────────────────────────────────────────────────────────────────┘
         │
         │  Bearer token (aud: prod.kube.prmana)
         │  Authorization: Bearer <token>
         ▼
kube-apiserver ──── JWTAuthenticator ────► validates token against IdP JWKS
```

One identity plane: the same IdP and the same login session that gives you SSH access
to Linux servers also gives you access to Kubernetes clusters. Same policy, same audit
trail.

## Prerequisites

- `prmana-agent` running on your machine (from the `prmana` package)
- `prmana-kubectl` installed (from the `prmana-tools` package)
- `kubectl` 1.26+ (for ExecCredential `client.authentication.k8s.io/v1` support)
- Kubernetes cluster running 1.30+ configured for JWT authentication (see below)

## Quickstart

### 1. Install

```bash
# Debian/Ubuntu
sudo apt install prmana-tools

# Rocky Linux / Amazon Linux 2023
sudo dnf install prmana-tools
```

### 2. Log in once

```bash
prmana-agent login
```

Follow the device-code URL printed in your terminal. On desktops, a browser opens
automatically. On headless servers, copy the URL.

### 3. Configure kubectl for your cluster

```bash
prmana-kubectl setup \
    --cluster-id prod \
    --server https://api.prod.example.com:6443 \
    --context prod
```

This writes an exec stanza into `~/.kube/config`. The cluster is now ready.

### 4. Use kubectl normally

```bash
kubectl --context prod get pods
```

Every command transparently acquires a fresh 10-minute token scoped to audience
`prod.kube.prmana`. No ongoing action required. The token refreshes automatically
before expiry.

## Cluster-side setup (for cluster administrators)

Your kube-apiserver must be configured with a JWTAuthenticator
(`AuthenticationConfiguration` v1beta1, Kubernetes 1.30+).

See [`examples/kubectl/kube-apiserver-auth-config.yaml`](../examples/kubectl/kube-apiserver-auth-config.yaml)
for a reference config.

Key points:
- `audiences` must include `<cluster_id>.kube.prmana` (e.g., `prod.kube.prmana`)
- `issuer.url` must match your IdP's issuer URL (the same one prmana uses for SSH login)
- `claimMappings.username` should be `preferred_username`
- `userValidationRules` must block system accounts and reserved Linux usernames

Apply:
```
kube-apiserver \
    --authentication-config=/etc/kubernetes/pki/prmana-auth-config.yaml \
    ...
```

**Note:** When `--authentication-config` is set, the legacy `--oidc-*` flags are
mutually exclusive. Choose one approach.

## Security model

> **Read this section before deploying.** The security properties of prmana-kubectl
> differ from prmana's SSH/PAM authentication in one important way. Understanding the
> difference lets you make an informed deployment decision.

### Where DPoP protection applies — and where it doesn't

prmana's SSH flow uses DPoP (RFC 9449) end-to-end: the access token on your workstation
has a `cnf.jkt` thumbprint binding it to your agent's private key. The PAM module on the
server verifies a fresh DPoP proof with every authentication. A stolen SSH access token
is useless — the attacker needs the private key to generate a valid proof.

**kubectl tokens work differently.** Here is the full request chain:

```
prmana-agent  ──DPoP-protected exchange──►  IdP
     │                                       │
     │                              issues new token
     │                              (audience: prod.kube.prmana)
     │                                       │
prmana-kubectl ◄─── bearer token ────────────┘
     │
     │  ExecCredential JSON
     ▼
kubectl  ──── Authorization: Bearer <token> ────►  kube-apiserver
```

DPoP is used when the agent exchanges your access token with the IdP — that proves to
the IdP that the exchange is coming from the legitimate key holder, not an attacker who
stole your access token. But the **token the IdP issues back** is a plain bearer token.
kubectl has no mechanism to generate per-request DPoP proofs; it just sends
`Authorization: Bearer <token>`. No party on the kubectl → kube-apiserver leg checks
proof-of-possession.

### The replay risk

**A stolen kubectl bearer token can be replayed.** If an attacker obtains the token
after it has been issued to kubectl — from memory, from a compromised machine, from an
audit log that captured it, or from any point between kubectl and the API server — they
can send it directly to the kube-apiserver and it will be accepted until it expires.

The mitigations in place:

| Mitigation | What it does | Limit |
|-----------|--------------|-------|
| 10-minute TTL | Bounds the replay window | An attacker with 10 min is still dangerous |
| Audience isolation | Stolen kubectl token cannot be used for SSH login | Doesn't prevent k8s API replay |
| IdP-issued, signature-verified | Forgery requires compromising the IdP signing key | Doesn't prevent replay of a legitimately-issued token |
| On-demand issuance | Token is not stored in kubeconfig; it exists only in memory during kubectl execution | A compromised machine still has access during the window |

**This is not a bug or an oversight.** The Kubernetes exec credential API
(`client.authentication.k8s.io/v1`) was designed for bearer tokens. DPoP binding would
require kubectl itself to generate proofs on each request — a capability that doesn't
exist today in any kubectl release. Adding `cnf.jkt` to the token without a verifying
party on the other end would be security theater, not security.

### How this compares to the alternatives

| Credential type | Replay window | Scope | Key binding |
|----------------|---------------|-------|-------------|
| Static kubeconfig service account token | Forever (no expiry) | Cluster-wide | None |
| Long-lived kubeconfig user credential | Until manually rotated | Per-user | None |
| **prmana-kubectl bearer token** | **10 minutes** | **Single cluster audience** | **None on k8s leg** |
| prmana-kubectl with DT-E mTLS (future) | N/A — proof required | Single cluster audience | x509 client cert |

10-minute tokens with IdP-issued audience scoping are a substantial improvement over
static kubeconfig credentials, but they are not equivalent to the DPoP protection
prmana provides for SSH.

### Audience isolation

Tokens issued for kubectl have audience `<cluster_id>.kube.prmana`. This audience is
**hard-rejected** by the prmana PAM/SSH validator (`pam-prmana`). A stolen kubectl
token cannot be used to SSH into a Linux server — that check is a `HARD-FAIL` that
cannot be configured away (see `CLAUDE.md` "kubectl Authentication Invariant").

The reverse also holds: SSH/PAM tokens are rejected by kube-apiserver because the
apiserver's `audiences` config only accepts `<cluster_id>.kube.prmana`.

Audience isolation limits the blast radius of a stolen token but does not prevent replay
within the intended scope.

### Roadmap: DT-E removes the replay risk

Phase DT-E upgrades `prmana-kubectl` to return ephemeral mTLS client certificates
(`clientCertificateData`/`clientKeyData` in ExecCredential). kubectl will present the
certificate on every request; kube-apiserver validates it via `--client-ca-file`. The
private key never leaves the agent. This provides real cryptographic key binding on the
kubectl → kube-apiserver leg — the same guarantee DPoP provides for SSH.

Until DT-E ships, the accurate description of the security model is:
> *Short-lived, IdP-issued, audience-scoped bearer tokens. Replayable within the 10-minute
> TTL. Substantially better than static kubeconfig credentials. Not equivalent to
> DPoP-protected SSH authentication.*

### Audit trail

Every kubectl token issuance is logged as an OCSF-structured `KUBECTL_TOKEN_ISSUED`
event by prmana-agent, including `cluster_id`, full audience, requesting user (`sub`,
`preferred_username`), token expiry (`exp`), and JWT ID (`jti`). Events flow through the
same HMAC-chained audit pipeline as SSH events, giving operators a unified trail for
Linux login and cluster access — but note that audit records show issuance, not usage.
If a token is replayed after issuance, that replay is visible only in kube-apiserver
audit logs, not in prmana's audit trail.

## IdP Support Matrix

| IdP | Status | Token exchange method |
|-----|--------|-----------------------|
| Keycloak | Fully supported | RFC 8693 token exchange with `audience=` parameter |
| Auth0 | Fully supported | `audience` parameter on `/oauth/token` |
| Azure Entra ID | Supported with limitation | Re-authentication with scope parameter; no true RFC 8693 |
| Okta | Supported | RFC 8693 when custom auth server has token-exchange enabled |
| Google Cloud Identity | Supported | Standard OIDC, token exchange via Workforce Identity |

## Troubleshooting

**`prmana-kubectl: failed to connect to prmana-agent`**

The agent is not running. Start it:
```bash
systemctl --user start prmana-agent.socket
# Or run manually in the foreground:
prmana-agent serve
```

**`kubectl error: Unauthorized`**

Check that:
1. The cluster's `audiences` config includes `<cluster_id>.kube.prmana` (exact match)
2. The cluster's `issuer.url` matches your IdP
3. Your kube-apiserver is on Kubernetes 1.30+ (JWTAuthenticator support)
4. `kubectl version --client` shows 1.26+ (ExecCredential v1 support)
5. Your system clock is synchronized (token exp claims are time-sensitive)

**`kubectl error: exec plugin: invalid apiVersion "client.authentication.k8s.io/v1beta1"`**

The kubeconfig was written with the wrong API version. Re-run `prmana-kubectl setup`
to rewrite it with the correct `client.authentication.k8s.io/v1` value.

**`expirationTimestamp is not set`**

You are running an old kubectl (< 1.26). Upgrade to 1.26 or later.

**Token is rejected with "audience mismatch"**

The cluster ID in your kubeconfig does not match the `audiences` configured in the
kube-apiserver auth config. The audience must exactly match:

```yaml
# kube-apiserver config audiences:
- "prod.kube.prmana"

# prmana-kubectl setup --cluster-id must match:
prmana-kubectl setup --cluster-id prod ...
```

## Reference configuration

- [`examples/kubectl/kube-apiserver-auth-config.yaml`](../examples/kubectl/kube-apiserver-auth-config.yaml) — kube-apiserver JWTAuthenticator config
- [`examples/kubectl/kubeconfig-prmana.yaml`](../examples/kubectl/kubeconfig-prmana.yaml) — example kubeconfig with exec stanza
- [`examples/kubectl/kind-cluster.yaml`](../examples/kubectl/kind-cluster.yaml) — local kind cluster for testing
