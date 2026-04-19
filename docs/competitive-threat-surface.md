# Competitive Threat Surface

**Version:** 1.1
**Date:** 2026-04-17 (fact-check pass — see `docs/sub-agents/competitive-audit/audit-report.md`)
**Previous:** 1.0 (2026-04-16)
**Classification:** Public
**Audience:** security architects evaluating `prmana` against alternatives
**Companion to:** [`docs/threat-model.md`](./threat-model.md) (STRIDE model for `prmana` itself)

---

## Purpose

`docs/threat-model.md` is an internal threat model — it describes `prmana`'s trust boundaries and the mitigations applied within them. It does *not* compare `prmana` against alternative ways of solving the same problem.

This document does.

Security buyers evaluate by threat model, not by feature bullets. This document provides a **head-to-head threat-surface comparison** between `prmana` and the realistic alternatives for OIDC-based Linux SSH and privilege-escalation identity.

Adversarial transparency is a trust signal. Where a competitor is fine or better, this document says so.

---

## Threat scenarios

Eight scenarios. Each represents a realistic attacker capability or operational event, not a theoretical edge case.

| ID | Scenario |
|----|----------|
| TS-1 | Attacker intercepts the access credential in transit (mid-session or mid-flow) and attempts to replay it from another machine. |
| TS-2 | Attacker compromises the same machine and same UID as the legitimate user (malware, info-stealer, hostile browser extension). |
| TS-3 | User needs to execute a privileged command via `sudo` after SSH login. What identity/MFA is required at that boundary? |
| TS-4 | The IdP disables the user (off-boarding, incident response). How long until the user's SSH and sudo access actually stops working? |
| TS-5 | An SSH agent is forwarded to a compromised jump host. What can the attacker do with the forwarded agent? |
| TS-6 | The user is operating a host in a cloud the IdP-integrated SSH product doesn't natively cover (multi-cloud / on-prem / edge / CI). |
| TS-7 | The host loses connectivity to the IdP or control plane (airgap, flaky WAN, disaster). Which users can still authenticate, and for how long? |
| TS-8 | The IdP, SSH CA, or control plane itself is compromised. What is the blast radius — one issuer, one CA, the whole fleet? |

---

## Comparator columns

| Column | Product | Mechanism |
|---|---|---|
| **prmana** | `prmana` OSS | PAM-auth + agent + per-request DPoP + sudo step-up + local policy |
| opkssh | OpenPubkey SSH | OIDC → SSH keypair + PK-token, verified via `AuthorizedKeysCommand` |
| pam_oauth2_device | ICS MU PAM module | PAM-auth + OAuth 2.0 Device Grant, bearer token |
| Smallstep | Smallstep SSH / `step-ca` | OIDC → short-lived SSH certificate |
| Vault SSH | Vault SSH secrets engine | OIDC → short-lived SSH certificate via Vault |
| Tailscale SSH | Tailscale SSH | IdP identity in tailnet, enforced by Tailscale daemon |
| Cloud-native | Entra / OS Login / EC2 IC | Provider IAM → ephemeral SSH key or cert |
| Duo Unix | `pam_duo` | PAM MFA second factor (not primary identity) |
| FreeIPA+OIDC | FreeIPA w/ external IdP | OIDC → Kerberos via FreeIPA authentication indicator |
| Cloudflare Access | Cloudflare Access for Infrastructure SSH | IdP SSO → short-lived SSH cert issued post-Access-login; requires Cloudflare tunnel reachability |
| Teleport | Gravitational Teleport | Gateway proxy; IdP SSO → Teleport CA-signed short-lived SSH cert; per-session MFA via IdP-delegated check; native sudo MFA not yet shipped (gravitational/teleport#13258 open) |

---

## Matrix

Cell legend: **✅** = substantively mitigated; **⚠️** = partial / conditional; **❌** = not mitigated / out of scope; **—** = not applicable.

### TS-1. Stolen credential replayed from another machine

| Product | Outcome | Why |
|---|---|---|
| **prmana** | ✅ | DPoP proof signed per request over `htm`/`htu`/`iat`/`jti`. Replay to a different host/URL fails (`htu` mismatch). Without the signing key, a fresh proof cannot be forged. (RFC 9449.) |
| opkssh | ⚠️ | PK token alone is insufficient — sshd still requires the corresponding SSH private key. Attacker with only the PK token: **denied**. Attacker with both PK token + SSH private key: **logs in until the PK-token-backed SSH key expires** (default 24h; configurable to 12h/24h/48h/1week/oidc/oidc-refreshed per opkssh README). |
| pam_oauth2_device | ❌ | Plain bearer token. Interceptor with the token can replay freely within `exp`. |
| Smallstep | ⚠️ | Cert alone is insufficient — sshd requires the private key. Attacker with cert + private key: **logs in until cert expires (typ. 1–4h)**. |
| Vault SSH | ⚠️ | Same as Smallstep. |
| Tailscale SSH | ⚠️ | Tailnet node identity is the credential. Replay requires compromising the target node's WireGuard key. Hard but possible. |
| Cloud-native | ⚠️ | Ephemeral key/cert. Attacker with key + cert: **logs in until expiry**. |
| Duo Unix | — | Duo is a second factor; primary credential is whatever's underneath (password, SSH key). |
| FreeIPA+OIDC | ⚠️ | Kerberos ticket replay requires compromising the session key or keytab. |
| Cloudflare Access | ⚠️ | Short-lived SSH cert issued post-Access-login. Cert alone insufficient — sshd requires the private key. Attacker with cert + private key: logs in until cert expires. No per-request binding. |
| Teleport | ⚠️ | Teleport-CA-signed short-lived SSH cert. Cert + private key until expiry; no per-request DPoP-style binding for the SSH channel itself. Teleport per-session MFA (IdP-delegated) gates session-establishment when configured. |

### TS-2. Same-machine, same-UID compromise

| Product | Outcome | Why |
|---|---|---|
| **prmana** | ⚠️ | [Accepted residual risk](./threat-model.md#tier-3-same-user-malware--credentialsession-abuse). Same-UID malware can invoke the broker via IPC (same trust model as OpenSSH `ssh-agent`). Mitigation: hardware-backed signer makes the key non-exportable — broker becomes a non-exportable signing oracle, attacker gets proofs but not keys. |
| opkssh | ⚠️ | Same-UID attacker reads SSH private key from disk or agent. Hardware key (YubiKey) possible but not core. |
| pam_oauth2_device | ❌ | Token in memory or cache, readable same-UID. |
| Smallstep | ⚠️ | Cert + private key on disk or in ssh-agent. Hardware key possible. |
| Vault SSH | ⚠️ | Same as Smallstep. |
| Tailscale SSH | ⚠️ | Tailscale daemon + node key on disk, protected by OS permissions. |
| Cloud-native | ⚠️ | Cloud-provider key/cert typically in `~/.ssh/` or agent. |
| Duo Unix | ⚠️ | Duo push bypassable by compromise of pushing device, not by same-UID malware on the server directly. |
| FreeIPA+OIDC | ⚠️ | Kerberos credential cache in `/tmp/krb5cc_*`, readable same-UID. |
| Cloudflare Access | ⚠️ | Cert + private key typically in `~/.ssh/` or agent; readable same-UID. Hardware key possible. |
| Teleport | ⚠️ | `tsh` profile + cert + private key typically under `~/.tsh/`; readable same-UID. Hardware key support via PIV exists. |

**Note.** TS-2 is a hard threat for *every* comparator. No OIDC-for-SSH product in this set fully defeats a same-UID attacker on the client. Hardware-backed signing is the strongest available mitigation, and prmana makes it a first-class backend.

### TS-3. Sudo / privilege escalation identity

| Product | Outcome | Why |
|---|---|---|
| **prmana** | ✅ | Ships sudo step-up in OSS: OIDC device flow / CIBA challenge at `sudo` time, local policy (allow / step_up / deny / grace window). Same identity plane as login. |
| opkssh | ❌ | Not in scope. Standard sudo applies (password or NOPASSWD). |
| pam_oauth2_device | ❌ | Auth module only. No sudo story. |
| Smallstep | ❌ | Cert is consumed by sshd only. Standard sudo applies. |
| Vault SSH | ❌ | Same as Smallstep. |
| Tailscale SSH | ❌ | No sudo-boundary step-up. Tailscale SSH "check mode" can require IdP re-auth at SSH-connect time (default 12h re-auth window), but this is not sudo-level. |
| Cloud-native | ❌ | Not in scope; standard sudo. (Entra ID `VM Administrator` role runs sudo without re-auth; Entra `VM User` cannot sudo. AWS EC2 Instance Connect has no native sudo MFA. GCP OS Login 2FA is login-time only.) |
| Duo Unix | ✅ | Supports sudo via PAM MFA push (`pam_duo` in `/etc/pam.d/sudo`). Second factor, not OIDC identity. |
| FreeIPA+OIDC | ⚠️ | FreeIPA sudo rules exist but evaluate FreeIPA-stored policy, not OIDC step-up at the sudo boundary. No per-command IdP re-auth — FreeIPA Authentication Indicators are baked into the Kerberos TGT at login time; sudo PAM can gate on the indicator's presence but cannot re-challenge back to the OIDC IdP at sudo time. See FreeIPA `V4/Authentication_Indicators`. |
| Cloudflare Access | ❌ | No sudo-boundary step-up. Cloudflare Access authenticates the user at SSH connection setup; standard sudo applies on the host. |
| Teleport | ⚠️ | Teleport per-session MFA (IdP-delegated or WebAuthn) gates session-establishment, not sudo. **Native sudo MFA is not yet shipped** — tracked at gravitational/teleport#13258 (feature request still open as of 2026-04-17). |

**Differentiation summary.** Only Duo Unix and prmana handle sudo natively via PAM in this comparator set. Duo is a second factor (not primary identity); prmana uses the *same IdP identity* as SSH login with per-request DPoP binding. Teleport, Cloudflare Access, and the short-lived-cert products (Smallstep, Vault SSH, cloud-native) do login-time step-up only.

### TS-4. Revocation latency after IdP disables user

| Product | Outcome | Latency |
|---|---|---|
| **prmana** | ✅ | Next login / next DPoP-required action: IdP JWKS still validates, but token refresh fails. Effective revocation = token TTL (minutes). JWKS cache TTL is per-issuer configurable. |
| opkssh | ⚠️ | PK token has an `exp`. Access dies at expiry; existing sessions run to completion. |
| pam_oauth2_device | ⚠️ | Token TTL. Existing sessions run. |
| Smallstep | ❌ | Cert lifetime (1–4h typical; step-ca default is 16h for SSH). step-ca supports active revocation via the SSHPOP provisioner (CRL/OCSP at the CA), but OpenSSH-side revocation requires operator-managed KRL distribution (`RevokedKeys` in `sshd_config`) to every host. sshd does not refetch on a schedule; KRL propagation is rarely deployed at scale. Within the cert window, revocation is typically not achievable without out-of-band action. |
| Vault SSH | ⚠️ | Vault's SSH-CA engine issues signed certs that do NOT automatically track revocation leases; operators must manage their own KRL (see vault#3377 / vault#18679 open feature requests for SSH KRL signing). In practice similar to Smallstep. |
| Tailscale SSH | ✅ | Tailscale control-plane removal is near-real-time when SCIM is wired up; otherwise bounded by the check-mode re-auth window (default 12h) or node-key expiry. |
| Cloud-native | ⚠️ | Cert lifetime (Entra ID SSH certs typically 1h; EC2 IC/GCP OS Login similar). Entra ID's Continuous Access Evaluation can revoke the underlying token within ~15 min, but an already-issued SSH cert remains valid until its own expiry. |
| Duo Unix | ✅ | Push denial at next MFA challenge. Primary credential unaffected. |
| FreeIPA+OIDC | ⚠️ | Kerberos ticket lifetime + FreeIPA directory propagation. |
| Cloudflare Access | ⚠️ | Cloudflare can revoke the Access session immediately at the control plane; the already-issued SSH cert remains valid until its own expiry (cert-lifetime-bounded for established sessions, control-plane-bounded for new ones). |
| Teleport | ✅ | Teleport proxy sits in the data path and can terminate active sessions in real time when user is disabled. New connection attempts re-check IdP. |

**Key point.** `prmana`, Tailscale, and Teleport are the three products in this set where revocation latency is bounded by the IdP / control-plane (not cert TTL) for new sessions. Teleport additionally can kill sessions in flight because it sits in the data path. For cert-based products (Smallstep, Vault SSH, cloud-native), the cert lifetime *is* your revocation SLA.

### TS-5. SSH agent forwarding to compromised jump host

| Product | Outcome | Why |
|---|---|---|
| **prmana** | ✅ | DPoP signing key lives in the agent daemon. **Not meant to be forwarded.** Jump-host compromise does not yield a signing key. (Forwarding DPoP keys is an anti-pattern; multi-hop use cases are addressed via token exchange, RFC 8693.) |
| opkssh | ❌ | Standard SSH agent forwarding applies. Compromised jump host can use the forwarded key to log into downstream hosts as the user. |
| pam_oauth2_device | — | Token-based; no SSH key involved in this flow. But token may be forwarded via env/keyboard-interactive. |
| Smallstep | ❌ | Standard SSH agent forwarding. |
| Vault SSH | ❌ | Same as Smallstep. |
| Tailscale SSH | ⚠️ | Tailscale SSH replaces the SSH *authentication* phase with tailnet-identity (via WireGuard), but the SSH *protocol* still runs end-to-end and `ForwardAgent yes` is supported (Tailscale issue #12467 tracks it as a regressible feature). A compromised jump host running Tailscale SSH can abuse a forwarded agent socket exactly as a normal sshd would. No built-in per-hop DPoP-style binding. |
| Cloud-native | ❌ | Standard SSH agent forwarding for key-based flows. |
| Duo Unix | ⚠️ | MFA push at login; once session is established, forwarded agent operates without re-challenge. |
| FreeIPA+OIDC | ⚠️ | GSSAPI credential delegation is the Kerberos equivalent; similar risk if delegation is enabled. |
| Cloudflare Access | ❌ | Standard OpenSSH agent forwarding behavior. Cloudflare Access does not intercept or govern agent forwarding. |
| Teleport | ⚠️ | Teleport controls SSH at the proxy layer, but agent forwarding within the sshd process still behaves as normal OpenSSH; compromised jump host can reach the forwarded agent socket. Per-session MFA does not re-challenge for agent-mediated operations. |

### TS-6. Cross-cloud / hybrid / on-prem coverage

| Product | Outcome | Why |
|---|---|---|
| **prmana** | ✅ | Pure PAM + userspace agent. Runs anywhere with `sshd` + PAM. |
| opkssh | ✅ | PAM + `AuthorizedKeysCommand`. Anywhere. |
| pam_oauth2_device | ✅ | PAM. Anywhere. |
| Smallstep | ✅ | SSH-cert-based; works anywhere you can distribute the CA trust. |
| Vault SSH | ⚠️ | Requires Vault reachability from all hosts. Practical anywhere if networking allows. |
| Tailscale SSH | ⚠️ | Requires tailnet; excludes hosts that cannot run Tailscale. |
| Cloud-native | ⚠️ | AWS EC2 Instance Connect and GCP OS Login are single-cloud. Entra ID SSH (`aadsshlogin`) extends to on-prem and other-cloud hosts via Azure Arc-enrolled servers (GA since mid-2023), but still requires Arc enrollment and Azure connectivity. None offer a truly provider-neutral deployment. |
| Duo Unix | ✅ | PAM. Anywhere. |
| FreeIPA+OIDC | ⚠️ | Requires FreeIPA enrollment. |
| Cloudflare Access | ⚠️ | Requires Cloudflare tunnel reachability from every host. Practical anywhere Cloudflare tunnels can run; a dependency on Cloudflare's control plane. |
| Teleport | ⚠️ | Requires Teleport proxy deployment reachable from every host. Self-hostable. |

---

### TS-7. Offline host / control-plane unreachable

Who keeps working when the IdP or control plane is unreachable (airgap, disaster, WAN outage)?

| Product | Outcome | Why |
|---|---|---|
| **prmana** | ⚠️ | Existing login sessions continue until process exit. Sudo grace window permits reuse (up to operator-configured `grace_period_secs`) without fresh IdP reach. New SSH logins fail at JWKS validation if the cache is stale beyond its TTL. v1.0 has no grace recovery across agent restart — agent restart during an outage forces re-auth. |
| opkssh | ⚠️ | Already-issued PK-token-backed SSH key remains usable until the configured TTL (default 24h). New logins require IdP reachability. |
| pam_oauth2_device | ⚠️ | Access token valid until `exp` (typically minutes). New logins fail without IdP. |
| Smallstep | ✅ | Issued SSH cert is self-contained and valid until expiry (16h default). New cert issuance requires CA reachability, but existing certs work offline — an advantage of the short-lived-cert model. |
| Vault SSH | ✅ | Same as Smallstep. Existing certs work; new issuance requires Vault reachability. |
| Tailscale SSH | ❌ | Requires control-plane (or DERP) reachability for key check mode and identity assertion. Nodes cannot authenticate each other indefinitely offline. |
| Cloud-native | ⚠️ | Already-issued SSH cert works until expiry (typically 1h for Entra). New issuance requires IAM reachability. Entra's Continuous Access Evaluation also fails closed when unreachable. |
| Duo Unix | ⚠️ | Requires Duo service reachability for the MFA push; a bypass codes / offline access feature exists as an operator-opt-in configuration. Without offline config, sudo step-up fails when Duo is unreachable. |
| FreeIPA+OIDC | ❌ | Requires FreeIPA master reachable for new auth. Existing Kerberos TGT stays valid within its lifetime. External OIDC reachability required for initial authn. |
| Cloudflare Access | ❌ | Requires Cloudflare control plane. When unreachable, new SSH is blocked. |
| Teleport | ❌ | Requires Teleport proxy and auth service. Offline operation is not supported. |

**Key point.** Short-lived-cert products (Smallstep, Vault SSH) have the best offline posture for *existing* sessions because the cert is self-contained. Gateway products (Tailscale, Teleport, Cloudflare) have the worst — they require the control plane to authenticate anything. `prmana` sits in the middle: existing sessions + grace-window sudo work offline; new logins do not.

---

### TS-8. Compromised CA / IdP / control plane — blast radius

What is the blast radius if the trust anchor is compromised?

| Product | Outcome | Why |
|---|---|---|
| **prmana** | ⚠️ | OIDC issuer compromise allows an attacker to mint DPoP-bound tokens with attacker-controlled `cnf.jkt` — full SSH and sudo access until the compromise is discovered and JWKS rotated. **Per-issuer isolation bounds the blast radius**: JWKS is issuer-scoped (ADR-013, SU-12, MIDP-07), so a compromise of issuer A does not affect tokens from issuer B. Per-issuer policy supports explicit failover between redundant issuers (ADR-020). Compromise of one issuer does not compromise the SSH CA or the host-local policy. |
| opkssh | ❌ | OIDC IdP compromise lets the attacker forge PK tokens for any user. SSH key signing is IdP-anchored. |
| pam_oauth2_device | ❌ | OIDC IdP compromise lets the attacker issue bearer tokens; no additional trust anchor. |
| Smallstep | ❌ | SSH CA compromise issues arbitrary SSH certs for any user. Full fleet compromise until CA rotation and host-side trust updates. |
| Vault SSH | ❌ | Vault compromise = SSH CA compromise. Same blast radius as Smallstep. |
| Tailscale SSH | ❌ | Tailscale control-plane compromise = full tailnet compromise. Attacker can authorize arbitrary device enrollment and key re-signing. |
| Cloud-native | ❌ | Cloud IAM compromise = all cloud resources in scope. Entra ID compromise affects Entra-Arc-enrolled hosts globally. |
| Duo Unix | ⚠️ | Duo service compromise affects MFA push authorization but does NOT compromise the primary credential (password or SSH key). Primary-factor integrity is retained. |
| FreeIPA+OIDC | ❌ | FreeIPA CA compromise = full Kerberos realm compromise. Plus the external OIDC IdP is a second trust anchor that can be compromised independently. |
| Cloudflare Access | ❌ | Cloudflare control-plane compromise = all Access-protected resources. |
| Teleport | ❌ | Teleport auth service compromise = all Teleport-managed hosts. |

**Key point.** Every IdP-based or CA-based product has a trust-anchor-compromise failure mode that is effectively catastrophic. The differentiator is **isolation**: `prmana`'s issuer-scoped JWKS + per-issuer policy means compromise blast radius is bounded to tokens from that specific issuer. Duo's "second factor" property retains primary-credential integrity under Duo compromise — the only product in this set that genuinely reduces the blast radius rather than just scoping it. The others are essentially single-point-of-failure by design.

---

## Where comparators are fine or better

Adversarial transparency. The matrix above names these cells honestly; this section calls them out explicitly.

1. **Short-lived certs (Smallstep, Vault SSH) vs `prmana`.** Against a "stolen token within the expiry window" threat, a 5-minute SSH cert and a 5-minute DPoP-bound token are *comparable*. prmana wins on per-request binding and on revocation-latency-without-TTL-tail; short-lived-cert products win on **no runtime dependency on the IdP for validation** (once the cert is issued, the IdP can be offline).
2. **Tailscale SSH** gives you **network-level identity and enforcement** that prmana does not. Tailscale SSH is not "worse" — it's solving an overlapping problem with different architectural trade-offs. For orgs fully on Tailscale, Tailscale SSH may be a better fit.
3. **FreeIPA + external OIDC** wins when the fleet is *already* FreeIPA-enrolled and Kerberos is the preferred identity transport. prmana does not provide Kerberos-mediated identity.
4. **Gateway platforms** (Teleport, StrongDM, Boundary, Cloudflare Access for Infrastructure) provide session recording, proxy-level RBAC, broker audit, and (for Teleport) real-time session termination at the proxy boundary — capabilities `prmana` does not provide. The two are complementary: many orgs run both. Caveat on sudo specifically — none of these gateway platforms currently ships native sudo-boundary MFA; Teleport's sudo MFA feature request (gravitational/teleport#13258) is still open as of 2026-04-17.
5. **Duo Unix** is a strong, battle-tested **second factor** for orgs that don't want to replace their primary Linux auth. It's solving a different layer than prmana.

---

## Cross-reference

- `prmana`'s own STRIDE model and residual risks: [`docs/threat-model.md`](./threat-model.md)
- DPoP threat analysis (per-request binding, replay protection, algorithm confusion, thumbprint manipulation, key extraction): [`docs/threat-model.md` §4](./threat-model.md)
- Privilege-escalation assessment (three-tier adversarial review): [`docs/threat-model.md` §8](./threat-model.md)
- Competitive and integration landscape (strategic positioning): internal research artifact, gitignored per CLAUDE.md §"Documentation" (`docs/research/` is a local-only subdirectory).

## Verification

Every ❌ and ⚠️ claim in this matrix was fact-checked against primary sources (vendor documentation, official GitHub repositories, security advisories) on 2026-04-17 before publication. Primary-source citations per claim are retained in the internal audit artifact (gitignored per CLAUDE.md §"Privacy of Deliberations"). If you find a cell that is wrong or outdated, please file a GitHub issue — we treat accuracy of this document as a trust asset and respond quickly to corrections.

---

## Maintenance

This matrix must be revisited when:

- A comparator ships a materially new security property (e.g., opkssh adds per-request binding; Smallstep adds native sudo step-up).
- `prmana` changes its own threat model (new trust boundary, new attack class mitigated, new residual risk).
- A new comparator enters the "OIDC for Linux" category.

*Cells change over time. When a cell improves for a comparator, update the matrix and ship the update. Honesty about shifts in the landscape is the trust asset; freezing the matrix at a convenient moment is how competitive docs lose credibility.*
