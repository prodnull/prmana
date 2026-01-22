# unix-oidc-instance Terraform Module

A reusable Terraform module for installing and configuring unix-oidc on any cloud instance.

This module uses `null_resource` with `remote-exec` provisioner to install unix-oidc on a target instance via SSH.

## Features

- Downloads and runs the unix-oidc installer script
- Configures `/etc/unix-oidc/config.env` with your OIDC settings
- Optionally enables DPoP token binding
- Validates the installation
- Works with any cloud provider (AWS, Azure, GCP, etc.)

## Usage

### Basic Example

```hcl
module "unix_oidc" {
  source = "./modules/unix-oidc-instance"

  oidc_issuer    = "https://login.example.com/realms/myorg"
  oidc_client_id = "unix-oidc"

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
module "unix_oidc" {
  source = "./modules/unix-oidc-instance"

  oidc_issuer    = "https://login.example.com/realms/myorg"
  oidc_client_id = "unix-oidc"
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
module "unix_oidc" {
  source = "./modules/unix-oidc-instance"

  oidc_issuer       = "https://login.example.com/realms/myorg"
  oidc_client_id    = "unix-oidc"
  unix_oidc_version = "0.1.0"
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

module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/modules/unix-oidc-instance"

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
| `oidc_client_id` | OIDC Client ID | `string` | `"unix-oidc"` | no |
| `install_agent` | Whether to install the unix-oidc-agent | `bool` | `true` | no |
| `enable_dpop` | Enable DPoP token binding | `bool` | `false` | no |
| `connection` | SSH connection details for the target instance | `object` | n/a | yes |
| `unix_oidc_version` | Version of unix-oidc to install | `string` | `"latest"` | no |
| `required_acr` | Required ACR level for authentication | `string` | `""` | no |
| `max_auth_age` | Maximum authentication age in seconds | `number` | `0` | no |
| `installer_url` | URL to the unix-oidc installer script | `string` | (GitHub URL) | no |

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
| `install_complete` | Indicates that unix-oidc installation is complete |
| `config_path` | Path to the unix-oidc configuration file |
| `pam_module_paths` | Possible paths to the PAM module (depends on OS) |
| `agent_path` | Path to the unix-oidc-agent binary (if installed) |
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

1. Configure PAM to use unix-oidc (copy recommended configs from `/etc/unix-oidc/`)
2. Test authentication with `pamtester`
3. Optionally configure the unix-oidc-agent for your users

See the [unix-oidc documentation](https://github.com/prodnull/unix-oidc) for detailed configuration steps.

## Security Considerations

- The installer runs with `--yes` flag for non-interactive installation
- SSH private keys should be stored securely (use Terraform secrets management)
- Enable DPoP for enhanced security in production environments
- The configuration file is created with `600` permissions (root-only readable)

## License

Apache-2.0 OR MIT
