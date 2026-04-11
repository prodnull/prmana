# prmana Ansible Role

Deploy and configure prmana for OIDC-based Unix authentication.

## Description

This Ansible role installs and configures prmana, enabling OpenID Connect (OIDC) authentication for Unix systems. It supports integration with PAM services like SSH and sudo, allowing users to authenticate using their identity provider credentials.

## Requirements

- Ansible 2.10 or higher
- Target systems must have internet access to download the installer
- Root or sudo privileges on target systems

## Supported Platforms

| Platform | Versions |
|----------|----------|
| Ubuntu | 20.04 LTS (Focal), 22.04 LTS (Jammy), 24.04 LTS (Noble) |
| Debian | 11 (Bullseye), 12 (Bookworm) |
| RHEL | 8, 9 |
| Rocky Linux | 8, 9 |
| AlmaLinux | 8, 9 |

## Role Variables

### Required Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `prmana_issuer` | OIDC issuer URL | `""` (must be set) |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `prmana_version` | Version to install (`latest` or specific version) | `"latest"` |
| `prmana_client_id` | OIDC client ID | `"prmana"` |
| `prmana_install_agent` | Install the user agent | `true` |
| `prmana_enable_dpop` | Enable DPoP for enhanced security | `false` |
| `prmana_pam_services` | List of PAM services to configure | `[]` |
| `prmana_required_acr` | Required Authentication Context Class Reference | `""` |
| `prmana_token_lifetime` | Token lifetime in seconds | `3600` |
| `prmana_allowed_groups` | List of allowed groups for authentication | `[]` |
| `prmana_custom_claims` | Dictionary of custom claims mapping | `{}` |
| `prmana_install_dir` | Installation directory | `"/opt/prmana"` |
| `prmana_config_dir` | Configuration directory | `"/etc/prmana"` |
| `prmana_log_level` | Log level (debug, info, warn, error) | `"info"` |
| `prmana_verify_ssl` | Verify SSL certificates | `true` |

## Dependencies

None.

## Example Playbook

### Basic Installation

```yaml
- hosts: servers
  roles:
    - role: prmana
      vars:
        prmana_issuer: "https://login.microsoftonline.com/your-tenant-id/v2.0"
```

### Full Configuration with PAM Integration

```yaml
- hosts: servers
  roles:
    - role: prmana
      vars:
        prmana_issuer: "https://login.microsoftonline.com/your-tenant-id/v2.0"
        prmana_client_id: "my-app-client-id"
        prmana_enable_dpop: true
        prmana_pam_services:
          - sshd
          - sudo
        prmana_required_acr: "urn:mace:incommon:iap:silver"
        prmana_allowed_groups:
          - "admins"
          - "developers"
        prmana_log_level: "debug"
```

### Using with Keycloak

```yaml
- hosts: servers
  roles:
    - role: prmana
      vars:
        prmana_issuer: "https://keycloak.example.com/realms/myrealm"
        prmana_client_id: "prmana-client"
        prmana_pam_services:
          - sshd
```

### Using with Okta

```yaml
- hosts: servers
  roles:
    - role: prmana
      vars:
        prmana_issuer: "https://your-org.okta.com"
        prmana_client_id: "0oa..."
        prmana_pam_services:
          - sshd
          - sudo
```

## Handlers

The role includes the following handlers:

- `Restart sshd` - Restarts the SSH daemon when PAM configuration changes
- `Restart prmana` - Restarts the prmana service when configuration changes

## Files Created

| Path | Description |
|------|-------------|
| `/etc/prmana/config.env` | Main configuration file |
| `/opt/prmana/` | Installation directory |
| `/etc/pam.d/*` | PAM service configurations (if `prmana_pam_services` is set) |

## Security Considerations

- The configuration file (`/etc/prmana/config.env`) is created with mode `0600` (owner read/write only)
- Enable `prmana_enable_dpop` for enhanced token security
- Use `prmana_required_acr` to enforce specific authentication assurance levels
- Consider using `prmana_allowed_groups` to restrict which users can authenticate

## Troubleshooting

### SSH authentication not working

1. Ensure PAM is enabled in SSH config (`UsePAM yes`)
2. Check that `ChallengeResponseAuthentication` or `KbdInteractiveAuthentication` is enabled
3. Verify the prmana PAM module is loaded: check `/etc/pam.d/sshd`
4. Review logs: `journalctl -u sshd` and check prmana logs

### Token validation failing

1. Verify the issuer URL is correct and accessible
2. Check that the client ID matches your identity provider configuration
3. Ensure the system clock is synchronized (token validation is time-sensitive)

## License

Apache-2.0 OR MIT

## Author Information

prmana project
