# Deployment Patterns

unix-oidc is designed to work with any OIDC-compliant Identity Provider. This guide covers
the most common deployment patterns and helps you choose the right one for your organization.

## Overview

| Pattern | Complexity | Best For |
|---------|------------|----------|
| [A: Direct to Cloud IdP](#pattern-a-direct-to-cloud-idp) | Low | Orgs using a single cloud IdP |
| [B: Self-hosted IdP](#pattern-b-self-hosted-idp) | Medium | Air-gapped, compliance, full control |
| [C: Federated via Broker](#pattern-c-federated-via-broker) | High | Multi-IdP, complex mapping |

---

## Pattern A: Direct to Cloud IdP

**The simplest deployment.** Point unix-oidc directly at your existing cloud IdP.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│ Linux Host  │────>│  unix-oidc  │────>│   Cloud IdP         │
│             │     │  PAM Module │     │ (Azure AD/Auth0/    │
│             │     │             │     │  Google/Okta)       │
└─────────────┘     └─────────────┘     └─────────────────────┘
```

### When to Use

- You already use Azure AD, Auth0, Google, or Okta
- Users have existing accounts in the cloud IdP
- Simple username mapping (email prefix or custom claim)
- No need for on-premises identity federation

### Configuration Examples

#### Azure AD (Microsoft Entra ID)

```bash
# Register an app in Azure Portal
# Enable "Allow public client flows" for Device Code

export OIDC_ISSUER="https://login.microsoftonline.com/<tenant-id>/v2.0"
export OIDC_CLIENT_ID="<application-id>"
```

**Azure AD App Registration:**
1. Azure Portal → App registrations → New registration
2. Name: `unix-oidc`
3. Supported account types: Single tenant (or multi-tenant)
4. Authentication → Advanced → Allow public client flows: **Yes**
5. Token configuration → Add optional claim → `preferred_username`

**Username Mapping:**
```yaml
# /etc/unix-oidc/policy.yaml
username_claim: preferred_username  # or upn, email
username_transform: strip_domain    # alice@corp.com → alice
```

#### Auth0

```bash
export OIDC_ISSUER="https://<your-tenant>.auth0.com/"
export OIDC_CLIENT_ID="<client-id>"
```

**Auth0 Application Setup:**
1. Dashboard → Applications → Create Application
2. Type: Native
3. Settings → Advanced → Grant Types → Enable "Device Code"
4. Connections → Enable your identity sources

#### Google Cloud Identity

```bash
export OIDC_ISSUER="https://accounts.google.com"
export OIDC_CLIENT_ID="<client-id>.apps.googleusercontent.com"
export OIDC_CLIENT_SECRET="<client-secret>"  # Required for Google
```

**Google Cloud Console:**
1. APIs & Services → Credentials → Create OAuth client ID
2. Application type: TVs and Limited Input devices
3. Configure consent screen (Internal for Workspace, External for testing)

#### Okta

```bash
export OIDC_ISSUER="https://<your-org>.okta.com"
export OIDC_CLIENT_ID="<client-id>"
```

**Okta Admin Console:**
1. Applications → Create App Integration
2. OIDC → Native Application
3. Grant type: Device Authorization
4. Assignments: Assign users/groups

### Advantages

- No additional infrastructure to manage
- Leverages existing IdP investment
- Cloud IdP handles MFA, Conditional Access
- Simplest to deploy and maintain

### Considerations

- Requires internet connectivity to IdP (unless using private endpoints)
- Username mapping must be configured carefully
- IdP must support Device Authorization Grant (RFC 8628)

---

## Pattern B: Self-hosted IdP

**Full control over authentication.** Deploy your own OIDC provider.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│ Linux Host  │────>│  unix-oidc  │────>│   Self-hosted IdP   │
│             │     │  PAM Module │     │   (Keycloak/etc)    │
└─────────────┘     └─────────────┘     └──────────┬──────────┘
                                                   │
                                                   v
                                        ┌─────────────────────┐
                                        │   LDAP/AD/FreeIPA   │
                                        │   (User Directory)  │
                                        └─────────────────────┘
```

### When to Use

- Air-gapped or restricted network environments
- Strict compliance requirements (data sovereignty)
- Need full control over authentication policies
- Want to federate multiple user directories
- Already running Keycloak, Authentik, or similar

### Self-hosted IdP Options

| IdP | License | Notes |
|-----|---------|-------|
| [Keycloak](https://www.keycloak.org/) | Apache 2.0 | Full-featured, enterprise-grade |
| [Authentik](https://goauthentik.io/) | MIT | Modern, Python-based |
| [Dex](https://dexidp.io/) | Apache 2.0 | Lightweight, Kubernetes-native |
| [Ory Hydra](https://www.ory.sh/hydra/) | Apache 2.0 | OAuth2/OIDC server only |

### Keycloak Example

**Docker Compose (Production):**
```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:24.0
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${KC_DB_PASSWORD}
      KC_HOSTNAME: auth.example.com
      KC_HTTPS_CERTIFICATE_FILE: /opt/keycloak/conf/cert.pem
      KC_HTTPS_CERTIFICATE_KEY_FILE: /opt/keycloak/conf/key.pem
    command: start
    ports:
      - "8443:8443"
```

**unix-oidc Configuration:**
```bash
export OIDC_ISSUER="https://auth.example.com/realms/your-realm"
export OIDC_CLIENT_ID="unix-oidc"
```

**Keycloak Realm Setup:**
1. Create realm (e.g., `production`)
2. User Federation → Add LDAP provider
3. Clients → Create `unix-oidc` client
   - Client authentication: Off (public client)
   - OAuth 2.0 Device Authorization Grant: On
4. Authentication → Configure step-up flows

### Advantages

- Works in air-gapped environments
- Full control over data and policies
- Can integrate with on-premises directories
- No cloud dependencies

### Considerations

- Requires infrastructure management
- Must handle high availability, backups
- Security patches are your responsibility

---

## Pattern C: Federated via Broker

**Centralized control over multiple IdPs.** Use a broker to federate upstream identity providers.

```
                                        ┌─────────────────────┐
                                   ┌───>│     Azure AD        │
                                   │    └─────────────────────┘
┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐
│ Linux Host  │────>│  unix-oidc  │────>│   Keycloak Broker   │
│             │     │  PAM Module │     │                     │
└─────────────┘     └─────────────┘     └──────────┬──────────┘
                                                   │
                                   ┌───────────────┼───────────────┐
                                   │               │               │
                                   v               v               v
                        ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
                        │    Google    │  │    LDAP      │  │    Okta      │
                        └──────────────┘  └──────────────┘  └──────────────┘
```

### When to Use

- Multiple identity sources that need unification
- Complex username mapping across domains
- Centralized audit logging requirements
- Different MFA policies per user group
- Migration scenarios (old IdP → new IdP)

### How It Works

1. User initiates SSH login
2. unix-oidc contacts Keycloak (the broker)
3. Keycloak shows identity provider selection (or auto-detects via email domain)
4. User authenticates with their home IdP (Azure AD, Google, etc.)
5. Keycloak normalizes claims and issues a token
6. unix-oidc validates the Keycloak token

### Keycloak Identity Brokering Setup

**Add Identity Provider (Azure AD example):**
1. Keycloak Admin → Identity Providers → Add provider → Microsoft
2. Configure:
   - Client ID: (from Azure app registration)
   - Client Secret: (from Azure)
   - Sync mode: Import users

**Username Mapping:**
```
# In Keycloak: Identity Provider Mappers
Mapper Type: Username Template Importer
Template: ${CLAIM.preferred_username | localpart}
```

This transforms `alice@corp.com` → `alice` for all federated users.

**unix-oidc Configuration:**
```bash
# Always point to Keycloak, never to upstream IdPs
export OIDC_ISSUER="https://keycloak.example.com/realms/production"
export OIDC_CLIENT_ID="unix-oidc"
```

### Advantages

- Single point of control for all authentication
- Unified audit logging
- Consistent policies across IdPs
- Handles complex claim transformations
- Graceful IdP migrations

### Considerations

- Additional infrastructure (Keycloak)
- Single point of failure (need HA)
- Latency increase (extra hop)
- More complex troubleshooting

---

## Choosing a Pattern

```
                          ┌──────────────────────────┐
                          │ Do you have an existing  │
                          │ cloud IdP (Azure/Google/ │
                          │ Auth0/Okta)?             │
                          └────────────┬─────────────┘
                                       │
                      ┌────────────────┴────────────────┐
                      │ Yes                             │ No
                      v                                 v
          ┌─────────────────────┐           ┌─────────────────────┐
          │ Do you need to      │           │ Pattern B:          │
          │ federate multiple   │           │ Self-hosted IdP     │
          │ IdPs?               │           └─────────────────────┘
          └──────────┬──────────┘
                     │
        ┌────────────┴────────────┐
        │ Yes                     │ No
        v                         v
┌─────────────────────┐  ┌─────────────────────┐
│ Pattern C:          │  │ Pattern A:          │
│ Federated Broker    │  │ Direct to Cloud IdP │
└─────────────────────┘  └─────────────────────┘
```

## Username Mapping

Regardless of pattern, you need to map OIDC identities to Linux usernames.

### Common Strategies

| Strategy | Example | Configuration |
|----------|---------|---------------|
| Email prefix | `alice@corp.com` → `alice` | `username_transform: strip_domain` |
| Custom claim | `unix_username: alice` | `username_claim: unix_username` |
| UPN | `alice@corp.com` → `alice` | `username_claim: upn`, transform |
| Subject | `sub: abc123` → `abc123` | `username_claim: sub` |

### Configuring in unix-oidc

```yaml
# /etc/unix-oidc/policy.yaml
defaults:
  username_claim: preferred_username
  username_transform: strip_domain

  # Or for custom claim from IdP:
  # username_claim: linux_username
```

### Configuring in IdP

**Azure AD - Custom Claim:**
1. App registrations → Token configuration
2. Add optional claim: `preferred_username`
3. Or create custom claim via Claims mapping policy

**Keycloak - Protocol Mapper:**
1. Clients → unix-oidc → Client scopes
2. Add mapper → User Attribute
3. Name: `linux_username`, Claim: `unix_username`

---

## Security Considerations

### All Patterns

- Enable DPoP for token binding (prevents token theft)
- Use short token lifetimes (5-15 minutes for access tokens)
- Require MFA via IdP policies
- Monitor authentication logs

### Cloud IdP (Pattern A)

- Use Conditional Access / Adaptive MFA
- Restrict to managed devices if possible
- Enable sign-in risk policies

### Self-hosted (Pattern B)

- Deploy in HA configuration
- Regular security updates
- Network segmentation (IdP in secure zone)
- Backup realm configuration

### Federated (Pattern C)

- Audit trust relationships regularly
- Monitor for IdP drift/changes
- Test failover scenarios

---

## Migration Guide

### From Password-only SSH

1. Deploy unix-oidc alongside existing PAM
2. Configure as `sufficient` (falls back to password)
3. Test with pilot users
4. Monitor adoption via audit logs
5. Enforce OIDC-only by changing to `required`

### From One Cloud IdP to Another

1. Set up Pattern C (broker)
2. Add both IdPs to broker
3. Migrate users gradually
4. Disable old IdP when complete
5. Optionally simplify to Pattern A

---

## Next Steps

- [Installation Guide](installation.md) - Install unix-oidc
- [Security Guide](security-guide.md) - Harden your deployment
- [Testing Guide](testing.md) - Validate your configuration
