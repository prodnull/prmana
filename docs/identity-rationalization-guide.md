# Identity Rationalization Guide

**Deploying prmana alongside FreeIPA and Azure Entra ID**

**Target audience:** Enterprise identity architects and Linux system administrators managing mixed
Active Directory, FreeIPA, and cloud identity (Azure Entra ID, Okta) environments.

**What this guide covers:** How to configure prmana when FreeIPA and Entra coexist, how OIDC
token claims map to Unix UIDs, why groups always come from SSSD, and how to audit and revoke access
when an employee departs.

---

## Table of Contents

1. [The Archaeology Problem: Why Traditional Unix Auth Fails at Offboarding](#1-the-archaeology-problem)
2. [Design Anchor: SSSD is the Source of Truth for Groups](#2-design-anchor-sssd-is-the-source-of-truth-for-groups)
3. [UPN-to-UID Mapping: Worked Examples](#3-upn-to-uid-mapping-worked-examples)
4. [FreeIPA + Entra Coexistence Patterns](#4-freeipa--entra-coexistence-patterns)
5. [Group Sync Strategies](#5-group-sync-strategies)
6. [The Archaeology Problem: Access Audit on Offboarding](#6-access-audit-and-offboarding-procedure)
7. [Troubleshooting Multi-IdP Identity Issues](#7-troubleshooting-multi-idp-identity-issues)
8. [Reference: Complete Configuration Snippets](#8-reference-complete-configuration-snippets)

---

## 1. The Archaeology Problem

When a developer leaves your organization, how do you find all the servers they had SSH access to?

### The Traditional Approach Fails

Traditional Unix SSH relies on `authorized_keys` files — one per user, scattered across every
server:

```
/home/alice/.ssh/authorized_keys  (on web-01)
/home/alice/.ssh/authorized_keys  (on db-01)
/home/alice/.ssh/authorized_keys  (on build-02)
/root/.ssh/authorized_keys        (on web-01, contains alice's key)
/etc/ssh/authorized_keys/alice    (on some servers)
```

To revoke Alice's access you must:
1. Know every server she touched (often requires archaeology in change tickets)
2. SSH into each server and manually remove her key
3. Hope that no one copied her key to another account or a service account
4. Verify the rotation actually propagated everywhere

**Problems with this approach:**
- Keys from departed employees persist for years because no one knows they are there
- Service account SSH keys are often shared between multiple people
- When someone leaves, finding all access requires hunting through tickets, wikis, and change logs
- Compliance audits ("show me who could access production last December") require parsing logs
  from dozens of sources

### The prmana Approach

prmana replaces SSH key authentication with OIDC token authentication:

```
Traditional                               prmana
───────────────────────────────────────   ─────────────────────────────────────────
authorized_keys on every server           Identity Provider (Keycloak/Entra) is the
                                          single source of truth

Manual key rotation                       Token expiration is automatic (≤1 hour TTL)

Revocation = find & delete every key     Revocation = disable account in IdP
                                          (effective within token TTL)

Audit = parse logs on every server        Audit = query structured logs with
                                          username + issuer + session_id
```

**Architecture:**

```
User's Machine                              Linux Server
┌────────────────────────────────┐         ┌──────────────────────────────┐
│  oidc-ssh-agent                │         │  sshd                        │
│  ┌──────────────────────────┐  │         │  ┌──────────────────────┐   │
│  │ OIDC access token        │  │─SSH────▶│  │ PAM (pam_prmana)  │   │
│  │ DPoP proof (per-request) │  │         │  │ Token + DPoP verify  │   │
│  └──────────────────────────┘  │         │  └──────────┬───────────┘   │
│         ▲                      │         │             │               │
│         │ Device Code / ROPC   │         │       SSSD/NSS              │
└─────────┼──────────────────────┘         │  (FreeIPA or Entra sync)   │
          │                                └──────────────────────────────┘
          ▼
┌──────────────────┐
│  Identity Prov.  │
│  (Keycloak/Entra)│
└──────────────────┘
```

**Result:** When Alice leaves, you:
1. Disable her account in the IdP (Keycloak or Entra)
2. Her active tokens expire within their TTL (default ≤ 1 hour)
3. If you need immediate revocation: enable token introspection (see §6.2)
4. Audit log query: `jq 'select(.username=="alice")' /var/log/prmana/audit.log`

No archaeology. No per-server key hunting.

---

## 2. Design Anchor: SSSD is the Source of Truth for Groups

> **Key decision (Phase 8, confirmed Phase 26):** Group membership in prmana is **always**
> resolved from SSSD/NSS. Groups in OIDC token claims are never used for access control decisions.

### Why SSSD, Not Token Claims?

When a user authenticates, the PAM module needs to know their Unix group membership to evaluate
`login_groups` and `sudo_groups` policies in `policy.yaml`. There are two places this information
could come from:

1. **SSSD/NSS** — the local Unix identity subsystem, which aggregates from FreeIPA/LDAP/Active
   Directory via `getgrouplist(3)`.
2. **OIDC token claims** — a `groups` claim that some IdPs include in access tokens.

prmana uses **SSSD/NSS exclusively**. Here is why:

| Concern | Token claims | SSSD/NSS |
|---------|-------------|----------|
| Authoritative source | IdP may not have all Unix groups | FreeIPA/LDAP is the Unix realm |
| Entra group limit | Entra truncates at 200 groups in token | SSSD has no practical limit |
| Group format | Entra emits GUIDs, not group names | SSSD resolves to Unix group names |
| Consistency | Token reflects snapshot at issuance | NSS reflects current membership |
| Trust model | Token issuer decides group membership | Unix realm administrator controls groups |

### Implementation Reference

The `GroupSource` enum in `pam-prmana/src/policy/config.rs` reflects this decision:

```rust
/// Previously included a `TokenClaim` variant, removed in DEBT-03 (Phase 26):
/// groups are always resolved from SSSD/NSS, never from token claims.
pub enum GroupSource {
    /// Resolve groups from NSS/SSSD only. Default and only supported source.
    #[default]
    NssOnly,
}
```

`GroupSource::TokenClaim` was removed as dead code in Phase 26. It is not configurable. If you
see online examples suggesting `source: token_claim` in `group_mapping`, those are outdated.

### What This Means for Your Configuration

Groups referenced in `login_groups` and `sudo_groups` must be Unix group names that exist in
SSSD/NSS. They cannot be Entra object IDs, Keycloak group paths, or token claim values.

**Correct:**
```yaml
issuers:
  - issuer_url: "https://keycloak.example.com/realms/corp"
    client_id: "prmana"
    group_mapping:
      source: nss_only        # default; explicit for clarity

access_policies:
  default_policy:
    login_groups:
      - linux-users           # must exist in FreeIPA/SSSD
    sudo_groups:
      - linux-admins          # must exist in FreeIPA/SSSD
```

**Wrong (will not work):**
```yaml
group_mapping:
  source: token_claim         # not supported — TokenClaim was removed
  claim: groups               # ignored
```

### SSSD Configuration Prerequisite

Before prmana group policies can work, SSSD must be configured and returning group membership
for your users. Verify this with:

```bash
# Verify a user's group membership as seen by the PAM module
id alice

# If SSSD is configured correctly, this shows FreeIPA/LDAP groups:
# uid=12345(alice) gid=12345(alice) groups=12345(alice),5001(linux-users),5002(developers)

# Check SSSD is running and connected to your domain
sssctl domain-status corp.example.com
```

---

## 3. UPN-to-UID Mapping: Worked Examples

The username mapping pipeline is implemented in `pam-prmana/src/identity/mapper.rs`. It extracts
a claim from the OIDC token and applies a sequence of transforms to produce the Unix username.

### 3.1 FreeIPA Native Users (No Mapping Needed)

FreeIPA users have short Unix usernames as their `preferred_username` claim. No transform is
required.

**Scenario:** Keycloak federated to FreeIPA issues tokens where `preferred_username: alice`.

```
Token claim: preferred_username = "alice"
Transforms:  none
Unix user:   alice
```

**Configuration:**

```yaml
issuers:
  - issuer_url: "https://keycloak.corp.example.com/realms/corp"
    client_id: "prmana"
    dpop_enforcement: strict
    # No claim_mapping section — defaults to preferred_username, no transforms
```

**Verify with:**
```bash
# Decode a token and check the preferred_username claim
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .preferred_username
# Expected: "alice"
```

### 3.2 Entra ID UPN Mapping (strip_domain)

Entra ID issues tokens where `preferred_username` is the User Principal Name (UPN) — a fully
qualified identifier like `alice@corp.example.com`. To map this to the local Unix username `alice`,
use the `strip_domain` transform.

**Scenario:** Entra tenant `corp.example.com`, user `alice@corp.example.com`.

```
Token claim: preferred_username = "alice@corp.example.com"
Transform 1: strip_domain       → "alice"
Unix user:   alice
```

Or using the `email` claim with case normalization (recommended for Entra):

```
Token claim: email = "Alice@Corp.onmicrosoft.com"
Transform 1: strip_domain       → "Alice"
Transform 2: lowercase          → "alice"
Unix user:   alice
```

**Configuration:**

```yaml
issuers:
  - issuer_url: "https://login.microsoftonline.com/{TENANT_ID}/v2.0"
    client_id: "your-client-id"
    dpop_enforcement: disabled          # Entra uses SHR, not RFC 9449 DPoP
    allow_unsafe_identity_pipeline: true  # Required for strip_domain on single-tenant Entra
    claim_mapping:
      username_claim: email             # preferred_username also works; email is more reliable
      transforms:
        - strip_domain                  # alice@corp.example.com → alice
        - lowercase                     # normalize case (Entra may capitalize)
```

**Implementation:** `UsernameTransform::StripDomain` in `pam-prmana/src/identity/mapper.rs`
splits on `@` and returns the local part. If the value contains no `@`, it is returned unchanged.

**Important: `allow_unsafe_identity_pipeline`**

`strip_domain` is technically non-injective: two UPNs can have the same local part
(`alice@corp.example.com` and `alice@other.example.com` both map to `alice`). In a multi-tenant
setup this is a security concern. For **single-tenant Entra** (the correct production configuration
— see `docs/entra-setup-guide.md` Step 1), the IdP itself enforces the domain constraint, so this
collision cannot occur. Setting `allow_unsafe_identity_pipeline: true` acknowledges this and
suppresses the hard-fail. A `WARN` is logged at each authentication to make the bypass auditable.

### 3.3 Custom Claim Mapping (email as Username)

When `preferred_username` is not available or unreliable, use the `email` claim:

```yaml
claim_mapping:
  username_claim: email           # use email claim instead of preferred_username
  transforms:
    - strip_domain                # drop @domain.com
    - lowercase                   # normalize
```

**Important:** Add the `email` optional claim to your Entra app registration (Step 5 in
`docs/entra-setup-guide.md`) or ensure Keycloak includes it in access tokens.

### 3.4 Regex Transform for Prefixed Usernames

When IdP usernames follow a pattern that cannot be handled by `strip_domain` alone, use the
`regex` transform:

**Scenario:** Legacy IdP issues usernames like `corp-alice-01`. Extract `alice`.

```
Token claim: preferred_username = "corp-alice-01"
Transform:   regex ^corp-(?P<username>[a-z0-9]+)-\d+$  → "alice"
Unix user:   alice
```

**Configuration:**

```yaml
claim_mapping:
  username_claim: preferred_username
  transforms:
    - type: regex
      pattern: "^corp-(?P<username>[a-z0-9]+)-\\d+$"
```

**Requirements:** The regex pattern must contain a named capture group `(?P<username>...)`.
This is validated at config-load time — a missing capture group causes a hard-fail at startup,
not at authentication time. The regex crate uses a finite automata engine (no backtracking),
so ReDoS attacks are not possible.

### 3.5 Identity Collision Detection

prmana validates at config-load time that the transform pipeline is injective — that no two
IdP identities can map to the same local Unix user. When `strip_domain` is used with
`allow_unsafe_identity_pipeline: false` (the safe default), the following is a hard-fail:

```
alice@corp.example.com  → strip_domain → alice   ← collision!
alice@other.example.com → strip_domain → alice   ← collision!
```

If you configure two issuers where the same local username could result from both, prmana
refuses to start with a `PolicyError::ConfigError` describing the collision.

**Resolution options:**
1. Use `allow_unsafe_identity_pipeline: true` on single-tenant issuers (the IdP guarantees no
   collision within its own domain)
2. Add a `regex` transform that prefixes the local part with a domain-specific identifier:
   ```yaml
   transforms:
     - type: regex
       pattern: "^(?P<username>[^@]+)@corp\\.example\\.com$"
   ```
   This rejects all non-corp.example.com UPNs at the transform level.

---

## 4. FreeIPA + Entra Coexistence Patterns

### 4.1 Pattern A: FreeIPA-Only (Keycloak Federating to FreeIPA)

**Architecture:**

```
User → Keycloak (OIDC IdP)
         └── LDAP federation → FreeIPA
                                 └── SSSD on servers (group membership)
```

Keycloak acts as the OIDC identity broker. Users authenticate to Keycloak using their FreeIPA
credentials. Keycloak issues tokens where `preferred_username` matches the FreeIPA UID. SSSD on
each server resolves group membership directly from FreeIPA via LDAP.

**Use case:** Greenfield deployment, no Microsoft dependency. Maximum consistency — the token
`preferred_username` and the SSSD group resolver use the same FreeIPA backend.

**Configuration:**

```yaml
security_modes:
  jti_enforcement: strict

issuers:
  - issuer_url: "https://keycloak.corp.example.com/realms/corp"
    client_id: "prmana"
    dpop_enforcement: strict
    allowed_algorithms:
      - ES256
    group_mapping:
      source: nss_only

access_policies:
  default_policy:
    login_groups:
      - linux-users
```

**SSSD configuration** (`/etc/sssd/sssd.conf`):
```ini
[sssd]
services = nss, pam
domains = corp.example.com

[domain/corp.example.com]
id_provider = ipa
auth_provider = ipa
ipa_server = ipa01.corp.example.com
ipa_domain = corp.example.com
```

### 4.2 Pattern B: FreeIPA + Entra (Dual-Issuer)

**Architecture:**

```
FreeIPA users → Keycloak → prmana  (issuer 1)
Entra users   → Entra    → prmana  (issuer 2)
                              │
                         SSSD/NSS (group resolution for both)
                         ┌──────────────────────────────┐
                         │ FreeIPA (FreeIPA users)       │
                         │ Entra Domain Services / AD    │
                         │ (Entra users, via SSSD multi) │
                         └──────────────────────────────┘
```

This pattern supports a migration period or permanent coexistence where FreeIPA users and Entra
users both need SSH access to the same Linux servers.

**Critical requirements:**
- FreeIPA UIDs and Entra UIDs must not collide. If `alice` exists in both, prmana cannot
  distinguish which `alice` authenticated. Use domain-namespaced UIDs (e.g., FreeIPA: `alice`,
  Entra: `alice-corp`) or explicit static maps.
- Both sets of users must exist in SSSD/NSS for group policy to work.
- Entra users without SSSD entries can authenticate (token is valid) but group-based policies
  will deny them. This is the correct security behavior.

**Configuration:**

```yaml
security_modes:
  jti_enforcement: warn    # Entra uses uti not jti (RFC 7519 §4.1.7)

issuers:
  # Issuer 1: FreeIPA users via Keycloak
  - issuer_url: "https://keycloak.corp.example.com/realms/corp"
    client_id: "prmana"
    dpop_enforcement: strict
    allowed_algorithms:
      - ES256
    group_mapping:
      source: nss_only

  # Issuer 2: Entra users
  - issuer_url: "https://login.microsoftonline.com/{TENANT_ID}/v2.0"
    client_id: "{ENTRA_CLIENT_ID}"
    dpop_enforcement: disabled          # Entra uses SHR, not RFC 9449 DPoP
    allow_unsafe_identity_pipeline: true
    claim_mapping:
      username_claim: email
      transforms:
        - strip_domain
        - lowercase
    acr_mapping:
      enforcement: warn
    group_mapping:
      source: nss_only

access_policies:
  default_policy:
    login_groups:
      - linux-users           # must exist in SSSD for BOTH FreeIPA and Entra users
```

**SSSD multi-domain configuration:**
```ini
[sssd]
services = nss, pam
domains = corp.example.com, entra.corp.example.com

[domain/corp.example.com]
id_provider = ipa
ipa_server = ipa01.corp.example.com

[domain/entra.corp.example.com]
id_provider = ad
ad_server = dc01.corp.example.com
# Or use Entra Domain Services:
# ad_server = corp.example.com.
```

### 4.3 Pattern C: Entra-Only (No FreeIPA)

**Architecture:**

```
Azure Entra ID users → Entra → prmana
                                    │
                               SSSD (Entra Domain Services or AD sync)
```

For Azure-native enterprises where FreeIPA is not in use. Linux servers join the Azure AD domain
(via Azure AD DS or traditional AD with SSSD) and SSSD resolves users and groups from Entra.

**Configuration:**

```yaml
security_modes:
  jti_enforcement: warn

issuers:
  - issuer_url: "https://login.microsoftonline.com/{TENANT_ID}/v2.0"
    client_id: "{ENTRA_CLIENT_ID}"
    dpop_enforcement: disabled
    allow_unsafe_identity_pipeline: true
    claim_mapping:
      username_claim: email
      transforms:
        - strip_domain
        - lowercase
    group_mapping:
      source: nss_only

access_policies:
  default_policy:
    login_groups:
      - AzureAD\LinuxUsers    # SSSD domain-qualified group name
```

**Note on group names with SSSD + Entra Domain Services:** Depending on your SSSD version and
AD DS configuration, groups may appear as `LinuxUsers@corp.example.com` or `AzureAD\LinuxUsers`
in NSS. Use `getent group` on the target server to determine the exact format expected in
`login_groups`.

---

## 5. Group Sync Strategies

This section compares the strategies for ensuring that Unix group membership (SSSD/NSS) reflects
your IdP's group assignments.

### 5.1 IPA-AD Trust (FreeIPA + Active Directory)

FreeIPA can establish a cross-forest Kerberos trust with Active Directory. After trust setup, AD
users can log in to FreeIPA-enrolled Linux servers, and AD groups appear in FreeIPA/SSSD.

**How it works:**

```
Active Directory           FreeIPA
┌────────────────┐ trust  ┌────────────────────────┐
│ User: alice    │◄──────▶│ External group: AD\corp-│
│ Group: corp-   │        │ admins → IPA group:     │
│   admins       │        │ linux-admins            │
└────────────────┘        └───────────┬─────────────┘
                                      │ LDAP/SSSD
                          Linux server: getgrouplist("alice")
                          → linux-admins
```

**Setup:** See [FreeIPA cross-forest trust documentation](https://www.freeipa.org/page/Trusts).

**Pros:**
- Transparent to prmana — group membership is correct from day one
- Changes to AD group membership appear in SSSD within the cache TTL (typically 5 minutes)
- Supports complex multi-forest enterprise environments

**Cons:**
- Requires domain-level trust setup (Active Directory administrator involvement)
- Complex in multi-forest or multi-domain environments
- Trust failures can block authentication for AD users

**When to use:** Enterprise with established AD + FreeIPA infrastructure already in use. Best
long-term option for permanent FreeIPA/AD coexistence.

### 5.2 SSSD Multi-Domain

SSSD can be configured with multiple `[domain/...]` sections — one for each identity source
(FreeIPA, Entra/AD, etc.). Each domain resolves independently; NSS presents a merged view.

**SSSD multi-domain configuration:**
```ini
[sssd]
services = nss, pam
domains = ipa.corp.example.com, ad.corp.example.com

[domain/ipa.corp.example.com]
id_provider = ipa
auth_provider = ipa
ipa_server = ipa01.corp.example.com

[domain/ad.corp.example.com]
id_provider = ad
ad_server = dc01.corp.example.com
ad_domain = corp.example.com
```

**Pros:**
- No cross-forest trust required
- Works with Entra Domain Services and traditional AD
- Each domain fails independently (FreeIPA outage doesn't block Entra users)

**Cons:**
- Group name conflicts: if both domains have a group named `admins`, SSSD may return one or
  both depending on version. Use domain-qualified names (`admins@ipa.corp.example.com`) in
  `login_groups` for clarity.
- User lookup overhead: SSSD queries each domain in order — more domains = more latency on
  cache miss

**When to use:** Migration period (running FreeIPA and Entra in parallel), or permanent
coexistence where cross-forest trust is not feasible.

### 5.3 Manual Group Sync

A cron job or CI pipeline syncs group membership from the IdP to `/etc/group` or LDAP.

**Example script pattern (Entra → /etc/group):**
```bash
#!/usr/bin/env bash
# Query Entra group membership via Microsoft Graph API
# and update a local group file. Run via cron hourly.

TENANT_ID="..."
CLIENT_ID="..."
CLIENT_SECRET="..."    # stored in vault, not this file

# Acquire token for Microsoft Graph
TOKEN=$(curl -s -X POST \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=https://graph.microsoft.com/.default" \
  | jq -r .access_token)

# Get members of linux-users group
GROUP_ID="..."
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/groups/${GROUP_ID}/members" \
  | jq -r '.value[].userPrincipalName | split("@")[0] | ascii_downcase' \
  > /tmp/linux-users-members

# Update /etc/group entry (example — use proper tools for production)
# ...
```

**Pros:** Simple, no SSSD configuration required, works anywhere.

**Cons:**
- Lag between IdP group change and local group update (up to sync interval)
- Sync failures may leave stale group membership
- Does not handle user deletion gracefully without additional logic
- Scales poorly beyond a few hundred users

**When to use:** Small deployments, testing environments, or when SSSD is not available.

### 5.4 Recommendation Matrix

| Environment | Recommended Strategy | Why |
|-------------|---------------------|-----|
| Greenfield, FreeIPA only | FreeIPA + SSSD | Maximum consistency, simplest config |
| Established AD + FreeIPA | IPA-AD trust | Transparent group sync, existing infrastructure |
| Azure-native, Entra only | SSSD + Azure AD DS | Native cloud integration |
| FreeIPA + Entra migration | SSSD multi-domain | No trust required, each domain independent |
| Entra + no domain services | Manual sync | Pragmatic fallback for simple deployments |
| Testing/CI | Manual sync or mock SSSD | Lowest infrastructure requirement |

---

## 6. Access Audit and Offboarding Procedure

### 6.1 Finding All Access for a Departing User

prmana emits structured audit events for every authentication attempt. Each event includes:

```json
{
  "timestamp": "2026-03-16T10:22:31.411Z",
  "event_type": "AUTH_SUCCESS",
  "username": "alice",
  "issuer": "https://keycloak.corp.example.com/realms/corp",
  "session_id": "sess-8f2a19c3",
  "source_ip": "10.0.1.45",
  "server": "web-01.corp.example.com"
}
```

**Find all authentication events for alice in the last 30 days:**

```bash
# JSON audit log (structured output)
jq 'select(.username == "alice")' /var/log/prmana/audit.log.json \
  | jq 'select(.timestamp > "2026-02-14T00:00:00Z")'

# With date filtering and summary
jq -r 'select(.username == "alice") | [.timestamp, .event_type, .server, .source_ip] | @tsv' \
  /var/log/prmana/audit.log.json \
  | sort

# Count events per server
jq -r 'select(.username == "alice") | .server' /var/log/prmana/audit.log.json \
  | sort | uniq -c | sort -rn
```

**Syslog (fallback if JSON log is not configured):**
```bash
# Search syslog for alice's authentication events
grep 'prmana.*alice' /var/log/auth.log | grep -E 'AUTH_SUCCESS|AUTH_FAILURE|SUDO_STEPUP'

# Across multiple servers (requires log aggregation — see §6.3)
journalctl -u sshd --since "30 days ago" | grep 'prmana.*alice'
```

**Find all sudo step-up events for alice:**
```bash
jq 'select(.username == "alice" and .event_type == "SUDO_STEPUP")' \
  /var/log/prmana/audit.log.json
```

**Verify no sessions remain open after offboarding:**
```bash
# Sessions opened after offboarding timestamp
OFFBOARD_TS="2026-03-15T17:00:00Z"
jq "select(.username == \"alice\" and .event_type == \"AUTH_SUCCESS\" and .timestamp > \"$OFFBOARD_TS\")" \
  /var/log/prmana/audit.log.json
```

### 6.2 Revoking Access

**Step 1: Disable account in IdP (Keycloak or Entra)**

This is the primary revocation mechanism. Active tokens expire within their TTL (default ≤ 1 hour).
No action on individual servers is required.

- **Keycloak:** Administration Console → Users → alice → Enabled → Off
- **Entra:** Entra ID → Users → alice → Account status → Block sign-in

After this point:
- Alice cannot acquire new tokens
- Active tokens remain valid until their `exp` claim (at most 1 hour)
- New SSH connections are denied immediately

**Step 2: If immediate revocation is required**

Configure token introspection to poll the IdP's revocation endpoint:

```yaml
# policy.yaml
issuers:
  - issuer_url: "https://keycloak.corp.example.com/realms/corp"
    client_id: "prmana"
    # token_introspection is planned — see docs/standards-compliance-matrix.md
    # For immediate revocation today: reduce token TTL at IdP level
    jwks_cache_ttl_secs: 60   # Reduces key cache window
```

**Current limitation:** prmana v2.2 does not implement token introspection. The effective
revocation window is the token TTL configured at the IdP level. For high-security environments,
configure the IdP to issue short-lived tokens (5-15 minutes). This is the recommended
configuration for SSH access regardless of revocation requirements.

**Step 3: Remove from SSSD groups**

If Alice's access was granted via group-based policy, remove her from the relevant SSSD group to
prevent re-authentication after her token expires:

- **FreeIPA:** `ipa group-remove-member linux-users --users=alice`
- **Entra:** Remove from the group in the Entra portal (propagates to SSSD via sync)
- **Active Directory:** `Remove-ADGroupMember -Identity "linux-users" -Members "alice"`

**Important limitation:** Group removal takes effect at the SSSD cache TTL boundary (typically
5 minutes). Until the cache expires, alice's next authentication attempt may succeed if she still
has a valid token. To close this window, flush the SSSD cache after group removal:

```bash
sss_cache -G linux-users   # Invalidate group cache for linux-users
sss_cache -u alice         # Invalidate user cache for alice
```

### 6.3 Audit Log Query Examples for SIEM Integration

For log aggregation tools (Splunk, Elastic, Loki), structure queries around the OCSF fields
emitted by prmana:

```
# Find all auth events for alice across all servers
event_type="AUTH_SUCCESS" AND username="alice" AND severity>1

# Find all offboarding-period access (replace timestamp)
username="alice" AND timestamp:[2026-03-15T17:00:00Z TO *]

# Find all sudo escalations in the last 7 days
event_type="SUDO_STEPUP" AND timestamp:[now-7d TO now] | stats count by username, server

# Alert on post-offboarding access
username IN offboarded_users_list AND event_type="AUTH_SUCCESS"
```

The HMAC chain in prmana v2.2 audit logs covers every event field (including OCSF enrichment).
This means the log sequence cannot be tampered with or events deleted without breaking the chain.
See `docs/` for audit verification instructions.

---

## 7. Troubleshooting Multi-IdP Identity Issues

| Symptom | Cause | Resolution |
|---------|-------|------------|
| "User not found" after OIDC auth success | `preferred_username` from IdP does not match local Unix username | Check `claim_mapping` config. For Entra UPNs, add `strip_domain` + `lowercase` transforms. Verify with `id alice` on the target server. |
| Identity collision error at startup | Two Entra UPNs map to the same local username via strip_domain | Add `allow_unsafe_identity_pipeline: true` for single-tenant Entra, or use a regex transform that anchors on the specific domain |
| Group policy denial for Entra user | Login group exists in Entra but not in SSSD/NSS | Sync Entra group to local group via SSSD multi-domain or manual sync. Verify with `getent group linux-users`. |
| "Unknown issuer" for Entra tokens | Tenant ID in issuer URL doesn't match config, or `/v2.0` suffix missing | Decode the token (`echo $TOKEN \| cut -d. -f2 \| base64 -d \| jq .iss`) and match character-for-character with `issuer_url`. Entra v2.0 format: `https://login.microsoftonline.com/{TENANT_ID}/v2.0` |
| DPoP validation failure on Entra tokens | Entra uses SHR (Signed HTTP Requests), not RFC 9449 DPoP | Set `dpop_enforcement: disabled` on the Entra issuer. Entra's SHR is not interoperable with RFC 9449. |
| ACR mismatch between issuers | Keycloak and Entra use different ACR value strings | Use `acr_mapping.mappings` to normalize IdP-specific ACR values. Or set `enforcement: warn` and `required_acr: null` for the Entra issuer if ACR is not enforced there. |
| `preferred_username` missing from Entra token | Optional claim not configured in app registration | Add optional claim in Entra portal → Token configuration → Access token → preferred_username. See `docs/entra-setup-guide.md` Step 5. |
| Token audience mismatch | Entra app configured with Application ID URI (`api://...`) | Set `expected_audience: "api://prmana"` in the Entra issuer config. See `docs/entra-setup-guide.md` §Verify Token Claims. |
| FreeIPA user works but Entra user denied | Two-issuer policy only matching first issuer | Verify `issuer_url` for Entra issuer exactly matches `iss` claim. Check with `jq .iss` on the token. |
| alice@corp.example.com maps to wrong user | Multiple transforms producing unexpected result | Test transform pipeline with `PRMANA_TEST_MODE=1 pam-prmana --dry-run --user alice@corp.example.com` (test-only binary). |
| SSSD returns empty group list | SSSD not joined to domain, or cache not populated | Run `sssctl user-checks alice` and `sssctl domain-status`. Ensure SSSD is enrolled and online. |
| Issuer marked degraded (auth fails) | JWKS endpoint unreachable for 3+ consecutive attempts | Check IdP connectivity from server: `curl -v https://idp.example.com/.well-known/openid-configuration`. Review issuer health files: `ls /run/prmana/issuer-health/`. |

---

## 8. Reference: Complete Configuration Snippets

### Pattern A: FreeIPA-Only (Keycloak)

```yaml
# /etc/prmana/policy.yaml
# Pattern A: FreeIPA users via Keycloak
# Use case: greenfield deployment, no Microsoft dependency

security_modes:
  jti_enforcement: strict

issuers:
  - issuer_url: "https://keycloak.corp.example.com/realms/corp"
    client_id: "prmana"
    dpop_enforcement: strict
    allowed_algorithms:
      - ES256         # ES256 only if Keycloak is configured for EC keys
    jwks_cache_ttl_secs: 300
    http_timeout_secs: 10
    group_mapping:
      source: nss_only

access_policies:
  default_policy:
    login_groups:
      - linux-users
    sudo_groups:
      - linux-admins

break_glass:
  enabled: true
  username: "breakglass"    # local account — must NOT use OIDC auth path
  alert_on_use: true
```

### Pattern B: FreeIPA + Entra (Dual-Issuer)

```yaml
# /etc/prmana/policy.yaml
# Pattern B: FreeIPA users + Entra users, dual-issuer
# Use case: migration period or permanent coexistence

security_modes:
  jti_enforcement: warn     # Entra uses uti not jti

issuers:
  # Issuer 1: FreeIPA users via Keycloak
  - issuer_url: "https://keycloak.corp.example.com/realms/corp"
    client_id: "prmana"
    dpop_enforcement: strict
    allowed_algorithms:
      - ES256
    group_mapping:
      source: nss_only

  # Issuer 2: Entra users (direct)
  - issuer_url: "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0"
    client_id: "YOUR_ENTRA_CLIENT_ID"
    dpop_enforcement: disabled          # Entra uses SHR, not RFC 9449 DPoP
    allow_unsafe_identity_pipeline: true  # single-tenant domain constraint enforced by Entra
    claim_mapping:
      username_claim: email
      transforms:
        - strip_domain                  # alice@corp.example.com → alice
        - lowercase                     # normalize case
    acr_mapping:
      enforcement: warn                 # Entra ACR values differ; normalize or warn
    group_mapping:
      source: nss_only                  # groups must be in SSSD/NSS for Entra users too

access_policies:
  default_policy:
    login_groups:
      - linux-users                     # must exist in SSSD for ALL users
    sudo_groups:
      - linux-admins

break_glass:
  enabled: true
  username: "breakglass"
  alert_on_use: true
```

### Pattern C: Entra-Only

```yaml
# /etc/prmana/policy.yaml
# Pattern C: Entra-only, no FreeIPA
# Use case: Azure-native enterprises

security_modes:
  jti_enforcement: warn

issuers:
  - issuer_url: "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0"
    client_id: "YOUR_ENTRA_CLIENT_ID"
    dpop_enforcement: disabled
    allow_unsafe_identity_pipeline: true
    # expected_audience: "api://prmana"  # uncomment if Application ID URI is set
    claim_mapping:
      username_claim: email
      transforms:
        - strip_domain
        - lowercase
    acr_mapping:
      enforcement: warn
    group_mapping:
      source: nss_only

access_policies:
  default_policy:
    login_groups:
      - linux-users           # synced from Entra via SSSD + Azure AD DS

break_glass:
  enabled: true
  username: "breakglass"
  alert_on_use: true
```

### Implementation File References

The username transform pipeline is implemented across two files:

- **`pam-prmana/src/identity/mapper.rs`** — `UsernameMapper`, `UsernameTransform`
  (StripDomain, Lowercase, Regex), transform application and validation logic

- **`pam-prmana/src/policy/config.rs`** — `IssuerConfig`, `IdentityConfig`,
  `TransformConfig`, `GroupMappingConfig`, `GroupSource` (NssOnly), `AcrMappingConfig`

These files are the authoritative implementation reference. If behavior described in this guide
conflicts with the code, the code takes precedence.

---

*Guide version: 2026-03-16 — reflects prmana v2.2 (Phase 26 SSSD-only group model,
Phase 27 issuer health and audit, Phase 28 identity rationalization DOC-02).*
