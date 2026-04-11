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

### Why no DPoP

Tokens issued by `prmana-kubectl` are **bearer tokens with NO `cnf` claim** (no DPoP
binding). This is intentional and not a security weakness in this context.

The Kubernetes exec credential API (`client.authentication.k8s.io/v1`) returns a token
to kubectl and kubectl immediately uses it as `Authorization: Bearer <token>`. kubectl
has no mechanism to inject per-request `DPoP` proof headers between "received
credential" and "sent HTTP request." Adding a `cnf.jkt` thumbprint to the token and
claiming RFC 9449 protection would be **security theater**: no party in the request path
verifies proof-of-possession.

The honest security properties of these tokens are:
- **Short-lived**: 10-minute TTL bounds the exposure window of any stolen token
- **Audience-isolated**: see below
- **Issuer-validated**: kube-apiserver validates the signature against the IdP's JWKS

**Future (Phase DT-E):** The exec plugin will switch to returning ephemeral mTLS client
certificates (`clientCertificateData`/`clientKeyData` in ExecCredential), providing real
cryptographic key binding via native Kubernetes x509 authentication (`--client-ca-file`
on kube-apiserver). This is the "DPoP-equivalent for kubectl" without the theater. Until
DT-E ships, the honest marketing language is: "short-lived, IdP-issued, audience-scoped
tokens — no long-lived kubeconfig credentials."

### Audience isolation

Tokens issued for kubectl have audience `<cluster_id>.kube.prmana`. This audience is
**hard-rejected** by the prmana PAM/SSH validator (`pam-prmana`). A stolen kubectl
token cannot be used to SSH into a Linux server. This is enforced as a
**HARD-FAIL** that cannot be configured away — see `CLAUDE.md` "kubectl Authentication
Invariant (Phase DT-A onwards)."

Conversely, SSH/PAM tokens (audience: hostname) are rejected by kube-apiserver because
the apiserver's `audiences` config only accepts `<cluster_id>.kube.prmana`.

### Audit trail

Every kubectl token issuance is logged as an OCSF-structured `KUBECTL_TOKEN_ISSUED`
event by prmana-agent, including:
- `cluster_id` and full audience
- Requesting user (`sub`, `preferred_username`)
- Token expiry (`exp`)
- JWT ID (`jti`) for replay detection

Events flow through the same HMAC-chained audit pipeline as SSH authentication events,
giving operators a unified audit trail for Linux login AND cluster access.

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
