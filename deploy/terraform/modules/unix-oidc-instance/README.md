# prmana-instance Terraform Module

A reusable Terraform module for installing and configuring prmana on any cloud instance.

This module uses `null_resource` with `remote-exec` provisioner to install prmana on a target instance via SSH.

## Features

- Downloads and runs the prmana installer script
- Configures `/etc/prmana/config.env` with your OIDC settings
- Optionally enables DPoP token binding
- Validates the installation
- Works with any cloud provider (AWS, Azure, GCP, etc.)

## Usage

### Basic Example

```hcl
module "prmana" {
  source = "./modules/prmana-instance"

  oidc_issuer    = "https://login.example.com/realms/myorg"
  oidc_client_id = "prmana"

  connection = {
    type        = "ssh"
    host        = aws_instance.example.public_ip
    user        = "ubuntu"
    private_key = file("~/.ssh/id_rsa")
  }
}
```

### With DPoP Enabled

```hcl
module "prmana" {
  source = "./modules/prmana-instance"

  oidc_issuer    = "https://login.example.com/realms/myorg"
  oidc_client_id = "prmana"
  enable_dpop    = true

  connection = {
    type        = "ssh"
    host        = aws_instance.example.public_ip
    user        = "ubuntu"
    private_key = file("~/.ssh/id_rsa")
  }
}
```

### With All Options

```hcl
module "prmana" {
  source = "./modules/prmana-instance"

  oidc_issuer       = "https://login.example.com/realms/myorg"
  oidc_client_id    = "prmana"
  prmana_version = "0.1.0"
  install_agent     = true
  enable_dpop       = true
  required_acr      = "urn:example:acr:mfa"
  max_auth_age      = 3600

  connection = {
    type        = "ssh"
    host        = aws_instance.example.public_ip
    user        = "ubuntu"
    private_key = file("~/.ssh/id_rsa")
  }
}
```

### AWS Example

```hcl
resource "aws_instance" "server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  key_name      = aws_key_pair.deployer.key_name

  vpc_security_group_ids = [aws_security_group.allow_ssh.id]
}

module "prmana" {
  source = "github.com/prodnull/prmana//deploy/terraform/modules/prmana-instance"

  oidc_issuer    = var.oidc_issuer
  oidc_client_id = var.oidc_client_id
  enable_dpop    = true

  connection = {
    type        = "ssh"
    host        = aws_instance.server.public_ip
    user        = "ubuntu"
    private_key = tls_private_key.deployer.private_key_pem
  }

  depends_on = [aws_instance.server]
}
```

## Variables

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `oidc_issuer` | OIDC Issuer URL | `string` | n/a | yes |
| `oidc_client_id` | OIDC Client ID | `string` | `"prmana"` | no |
| `install_agent` | Whether to install the prmana-agent | `bool` | `true` | no |
| `enable_dpop` | Enable DPoP token binding | `bool` | `false` | no |
| `connection` | SSH connection details for the target instance | `object` | n/a | yes |
| `prmana_version` | Version of prmana to install | `string` | `"latest"` | no |
| `required_acr` | Required ACR level for authentication | `string` | `""` | no |
| `max_auth_age` | Maximum authentication age in seconds | `number` | `0` | no |
| `installer_url` | URL to the prmana installer script | `string` | (GitHub URL) | no |

### Connection Object

The `connection` variable requires the following attributes:

| Attribute | Description | Type |
|-----------|-------------|------|
| `type` | Connection type (usually `"ssh"`) | `string` |
| `host` | Target host IP or hostname | `string` |
| `user` | SSH username | `string` |
| `private_key` | SSH private key content | `string` |

## Outputs

| Name | Description |
|------|-------------|
| `install_complete` | Indicates that prmana installation is complete |
| `config_path` | Path to the prmana configuration file |
| `pam_module_paths` | Possible paths to the PAM module (depends on OS) |
| `agent_path` | Path to the prmana-agent binary (if installed) |
| `oidc_issuer` | Configured OIDC issuer URL |
| `oidc_client_id` | Configured OIDC client ID |
| `dpop_enabled` | Whether DPoP token binding is enabled |
| `instance_host` | Host address of the configured instance |

## Supported Operating Systems

- Ubuntu 20.04+
- Debian 11+
- RHEL/Rocky/AlmaLinux 8+
- Amazon Linux 2

## Requirements

### Target Instance

- SSH access with sudo privileges
- Outbound internet access (to download installer and packages)
- curl and jq (installed automatically if missing)

### Terraform

- Terraform >= 1.0

## Post-Installation

After the module completes, you need to:

1. Configure PAM to use prmana (copy recommended configs from `/etc/prmana/`)
2. Test authentication with `pamtester`
3. Optionally configure the prmana-agent for your users

See the [prmana documentation](https://github.com/prodnull/prmana) for detailed configuration steps.

## Security Considerations

- The installer runs with `--yes` flag for non-interactive installation
- SSH private keys should be stored securely (use Terraform secrets management)
- Enable DPoP for enhanced security in production environments
- The configuration file is created with `600` permissions (root-only readable)

## License

Apache-2.0 OR MIT
