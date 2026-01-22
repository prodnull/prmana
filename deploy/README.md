# unix-oidc Deployment

This directory contains comprehensive deployment automation for unix-oidc, supporting everything from quick demos to production infrastructure.

## Quick Start

Choose your path based on available time and goals:

| Path | Time | Prerequisites | Description |
|------|------|---------------|-------------|
| [5-Minute Demo](quickstart/5-minute-demo.md) | 5 min | Docker | Zero setup, self-contained demo |
| [15-Minute Production](quickstart/15-minute-production.md) | 15 min | Linux server, IdP | Real server, real identity provider |

## Deployment Options Overview

| Method | Use Case | Complexity | Best For |
|--------|----------|------------|----------|
| **Installer Scripts** | Single server, manual | Low | Quick setup, testing |
| **Vagrant Images** | Local development, testing | Low | Development, demos |
| **Ansible** | Configuration management | Medium | Existing Ansible shops |
| **Chef** | Configuration management | Medium | Existing Chef shops |
| **Puppet** | Configuration management | Medium | Existing Puppet shops |
| **Terraform** | Infrastructure provisioning | Medium-High | Cloud infrastructure at scale |

## Directory Structure

```
deploy/
├── installer/           # Standalone installer scripts
│   ├── install.sh       # Install unix-oidc
│   ├── uninstall.sh     # Remove unix-oidc
│   └── demo.sh          # Run self-contained demo
├── quickstart/          # Getting started guides
│   ├── 5-minute-demo.md
│   └── 15-minute-production.md
├── idp-templates/       # Identity Provider configurations
│   ├── keycloak/        # Keycloak realm export + guide
│   ├── okta/            # Okta application setup guide
│   ├── azure-ad/        # Azure AD (Entra ID) setup guide
│   └── auth0/           # Auth0 application setup guide
├── terraform/           # Infrastructure as Code
│   ├── modules/         # Reusable Terraform modules
│   ├── aws/             # AWS deployment
│   ├── gcp/             # Google Cloud deployment
│   └── azure/           # Azure deployment
├── ansible/             # Ansible role
│   └── roles/unix_oidc/
├── chef/                # Chef cookbook
│   └── cookbooks/unix_oidc/
├── puppet/              # Puppet module
│   └── modules/unix_oidc/
└── vagrant/             # Vagrant development images
    ├── minimal/         # Minimal testing VM
    └── demo/            # Full demo with Keycloak
```

## Installer Scripts

The installer scripts provide the quickest path to getting unix-oidc running.

### install.sh

Install unix-oidc on a Linux server:

```bash
# Basic installation
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh | bash

# With configuration options
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh | bash -s -- \
  --issuer https://your-idp.example.com \
  --client-id your-client-id

# Dry run (preview what would happen)
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/install.sh | bash -s -- --dry-run
```

### uninstall.sh

Completely remove unix-oidc:

```bash
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/uninstall.sh | bash

# Preview removal
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/uninstall.sh | bash -s -- --dry-run
```

### demo.sh

Run a self-contained demo with Keycloak:

```bash
curl -fsSL https://raw.githubusercontent.com/prodnull/unix-oidc/main/deploy/installer/demo.sh | bash
```

## IdP Templates

Each IdP template includes:
- Step-by-step setup guide with screenshots
- Importable configuration file (where supported)
- Terraform automation (optional)
- CI verification (nightly tested where possible)

| Provider | Status | Documentation |
|----------|--------|---------------|
| [Keycloak](idp-templates/keycloak/) | Verified | Realm export included |
| [Okta](idp-templates/okta/) | Verified | Step-by-step guide |
| [Azure AD](idp-templates/azure-ad/) | Verified | Enterprise setup guide |
| [Auth0](idp-templates/auth0/) | Verified | Developer-friendly setup |

### Which IdP Should I Use?

| Scenario | Recommended IdP |
|----------|-----------------|
| Quick testing/demo | Keycloak (self-hosted) |
| Enterprise with Microsoft | Azure AD (Entra ID) |
| Enterprise with existing Okta | Okta |
| Developer/startup | Auth0 (free tier available) |
| Air-gapped/compliance | Keycloak (self-hosted) |
| Google Workspace users | Google Cloud Identity |

## Terraform Modules

Infrastructure as Code for cloud deployments.

### Shared Module

The `modules/unix-oidc-instance` module provides a cloud-agnostic base:

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/modules/unix-oidc-instance"

  oidc_issuer    = "https://your-idp.example.com"
  oidc_client_id = "unix-oidc"
}
```

### Cloud-Specific Modules

| Cloud | Directory | Features |
|-------|-----------|----------|
| [AWS](terraform/aws/) | `terraform/aws/` | EC2, Security Groups, IAM |
| [GCP](terraform/gcp/) | `terraform/gcp/` | Compute Engine, Firewall, IAM |
| [Azure](terraform/azure/) | `terraform/azure/` | Virtual Machines, NSG, Managed Identity |

### Example: AWS Deployment

```hcl
module "unix_oidc_server" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/aws"

  instance_type  = "t3.medium"
  oidc_issuer    = "https://your-idp.example.com"
  oidc_client_id = "unix-oidc"

  # Optional
  vpc_id    = "vpc-12345678"
  subnet_id = "subnet-12345678"
}
```

See [terraform/aws/README.md](terraform/aws/README.md) for full documentation.

## Configuration Management

### Ansible

The Ansible role installs and configures unix-oidc.

**Requirements:**
- Ansible 2.9+
- Target: Ubuntu 20.04+, Debian 11+, RHEL 8+

**Installation:**

```bash
# Add to requirements.yml
- src: https://github.com/prodnull/unix-oidc
  name: unix_oidc
  path: deploy/ansible/roles

# Or copy directly
cp -r deploy/ansible/roles/unix_oidc /etc/ansible/roles/
```

**Usage:**

```yaml
- hosts: servers
  roles:
    - role: unix_oidc
      vars:
        unix_oidc_issuer: "https://your-idp.example.com"
        unix_oidc_client_id: "unix-oidc"
        unix_oidc_enable_ssh: true
        unix_oidc_enable_sudo: true
```

See [ansible/roles/unix_oidc/README.md](ansible/roles/unix_oidc/README.md) for full documentation.

### Chef

The Chef cookbook installs and configures unix-oidc.

**Requirements:**
- Chef Infra Client 16+
- Target: Ubuntu 20.04+, Debian 11+, RHEL 8+

**Installation:**

```ruby
# In Berksfile
cookbook 'unix_oidc', git: 'https://github.com/prodnull/unix-oidc', rel: 'deploy/chef/cookbooks/unix_oidc'

# Or copy directly
cp -r deploy/chef/cookbooks/unix_oidc /var/chef/cookbooks/
```

**Usage:**

```ruby
# In a recipe
include_recipe 'unix_oidc::default'

# Or with attributes
node.default['unix_oidc']['oidc_issuer'] = 'https://your-idp.example.com'
node.default['unix_oidc']['oidc_client_id'] = 'unix-oidc'
include_recipe 'unix_oidc::default'
```

See [chef/cookbooks/unix_oidc/README.md](chef/cookbooks/unix_oidc/README.md) for full documentation.

### Puppet

The Puppet module installs and configures unix-oidc.

**Requirements:**
- Puppet 6+
- Target: Ubuntu 20.04+, Debian 11+, RHEL 8+

**Installation:**

```bash
# Install from Puppet Forge (future)
puppet module install cbchhaya-unix_oidc

# Or copy directly
cp -r deploy/puppet/modules/unix_oidc /etc/puppetlabs/code/environments/production/modules/
```

**Usage:**

```puppet
class { 'unix_oidc':
  oidc_issuer    => 'https://your-idp.example.com',
  oidc_client_id => 'unix-oidc',
  enable_ssh     => true,
  enable_sudo    => true,
}
```

See [puppet/modules/unix_oidc/README.md](puppet/modules/unix_oidc/README.md) for full documentation.

## Vagrant Images

Vagrant images for local development and testing.

### Minimal Image

A bare-bones Ubuntu VM with unix-oidc pre-installed:

```bash
cd deploy/vagrant/minimal
vagrant up
vagrant ssh
```

Best for: Testing unix-oidc installation on a clean system.

See [vagrant/minimal/README.md](vagrant/minimal/README.md) for details.

### Demo Image

A complete demo environment with Keycloak and test users:

```bash
cd deploy/vagrant/demo
vagrant up
# Access Keycloak at http://localhost:8080
# SSH to demo server: vagrant ssh
```

Best for: Full end-to-end demos, training, development.

See [vagrant/demo/README.md](vagrant/demo/README.md) for details.

## Choosing a Deployment Path

### By Environment

| Environment | Recommended Approach |
|-------------|---------------------|
| **Local development** | Vagrant demo image |
| **Testing/CI** | Docker (5-minute demo) |
| **Single server** | Installer script |
| **Small fleet (<10)** | Ansible/Chef/Puppet |
| **Large fleet (10+)** | Terraform + Config Management |
| **Kubernetes** | Coming soon |

### By Team Experience

| Your Team Uses | Start With |
|----------------|------------|
| Ansible | `ansible/roles/unix_oidc` |
| Chef | `chef/cookbooks/unix_oidc` |
| Puppet | `puppet/modules/unix_oidc` |
| Terraform | `terraform/aws/`, `terraform/gcp/`, or `terraform/azure/` |
| None of the above | Installer script |

### By Time Available

| Time | Path |
|------|------|
| 5 minutes | [5-minute demo](quickstart/5-minute-demo.md) |
| 15 minutes | [15-minute production](quickstart/15-minute-production.md) |
| 1 hour | Terraform module deployment |
| Half day | Full config management integration |

## Production Checklist

Before going to production, ensure you have:

- [ ] **Identity Provider configured** - Using one of our IdP templates
- [ ] **TLS/HTTPS everywhere** - IdP and all communications encrypted
- [ ] **Audit logging enabled** - Sending logs to your SIEM
- [ ] **Fallback authentication** - Break-glass access configured
- [ ] **Monitoring** - Alerting on authentication failures
- [ ] **Backup configuration** - `/etc/unix-oidc/` backed up
- [ ] **Tested failover** - What happens when IdP is unreachable?
- [ ] **Documentation** - Runbooks for your operations team

See [docs/security-guide.md](../docs/security-guide.md) for detailed hardening guidance.

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/prodnull/unix-oidc/issues)
- **Discussions**: [GitHub Discussions](https://github.com/prodnull/unix-oidc/discussions)
- **Security**: See [SECURITY.md](../SECURITY.md) for vulnerability reporting
