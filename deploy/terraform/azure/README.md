# unix-oidc Azure Terraform Module

This Terraform module deploys an Azure Linux VM with unix-oidc pre-installed and configured for OIDC-based SSH authentication.

## Features

- Creates an Azure Linux VM with unix-oidc PAM module installed
- Optionally creates a new Resource Group or uses an existing one
- Optionally creates a new VNet/Subnet or uses existing ones
- Configures Network Security Group for SSH access
- Uses Ubuntu 22.04 LTS Gen2 image
- Supports DPoP token binding
- Custom Script Extension for automated installation

## Quick Start

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/azure"

  oidc_issuer          = "https://login.example.com/realms/myorg"
  admin_username       = "azureuser"
  admin_ssh_public_key = file("~/.ssh/id_rsa.pub")
}

output "ssh_command" {
  value = module.unix_oidc.ssh_command
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| azurerm | >= 3.0 |

## Prerequisites

1. Azure CLI authenticated or service principal configured
2. An SSH key pair for VM access
3. An OIDC provider configured with unix-oidc client

## Provider Configuration

```hcl
provider "azurerm" {
  features {}
}
```

## Usage

### Basic Usage (Creates New Resource Group and VNet)

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/azure"

  oidc_issuer          = "https://login.example.com/realms/myorg"
  admin_username       = "azureuser"
  admin_ssh_public_key = file("~/.ssh/id_rsa.pub")
}
```

### Using Existing Resource Group and VNet

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/azure"

  oidc_issuer          = "https://login.example.com/realms/myorg"
  admin_username       = "azureuser"
  admin_ssh_public_key = file("~/.ssh/id_rsa.pub")

  # Use existing resources
  resource_group_name = "my-existing-rg"
  vnet_name           = "my-existing-vnet"
  subnet_name         = "my-existing-subnet"
}
```

### Production Configuration

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/azure"

  # OIDC Configuration
  oidc_issuer    = "https://login.example.com/realms/myorg"
  oidc_client_id = "unix-oidc-prod"
  enable_dpop    = true

  # VM Configuration
  vm_size         = "Standard_B2s"
  vm_name         = "prod-ssh-gateway"
  admin_username  = "adminuser"
  admin_ssh_public_key = file("~/.ssh/prod-key.pub")
  os_disk_size_gb = 50
  os_disk_type    = "Premium_LRS"

  # Network Configuration
  resource_group_name = "prod-resources"
  vnet_name           = "prod-vnet"
  subnet_name         = "ssh-subnet"
  allowed_ssh_cidrs   = ["10.0.0.0/8"]  # Restrict to internal network

  # Tags
  environment = "prod"
  tags = {
    CostCenter = "engineering"
    Owner      = "platform-team"
  }
}
```

### Different Azure Region

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/azure"

  oidc_issuer          = "https://login.example.com/realms/myorg"
  admin_username       = "azureuser"
  admin_ssh_public_key = file("~/.ssh/id_rsa.pub")

  # Deploy to West Europe
  location = "westeurope"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| oidc_issuer | OIDC issuer URL | `string` | n/a | yes |
| admin_username | Admin username for the VM | `string` | n/a | yes |
| admin_ssh_public_key | SSH public key for admin user | `string` | n/a | yes |
| oidc_client_id | OIDC client ID | `string` | `"unix-oidc"` | no |
| install_agent | Install unix-oidc-agent | `bool` | `true` | no |
| enable_dpop | Enable DPoP token binding | `bool` | `true` | no |
| resource_group_name | Existing resource group name | `string` | `""` | no |
| location | Azure region | `string` | `"eastus"` | no |
| vm_size | Azure VM size | `string` | `"Standard_B1s"` | no |
| vm_name | Name for the VM | `string` | `"unix-oidc-server"` | no |
| os_disk_size_gb | OS disk size in GB | `number` | `30` | no |
| os_disk_type | OS disk type | `string` | `"StandardSSD_LRS"` | no |
| vnet_name | Existing VNet name | `string` | `""` | no |
| subnet_name | Existing subnet name | `string` | `""` | no |
| vnet_address_space | Address space for new VNet | `string` | `"10.0.0.0/16"` | no |
| subnet_address_prefix | Address prefix for new subnet | `string` | `"10.0.1.0/24"` | no |
| create_public_ip | Create public IP for VM | `bool` | `true` | no |
| allowed_ssh_cidrs | CIDRs allowed for SSH | `list(string)` | `["0.0.0.0/0"]` | no |
| environment | Environment name | `string` | `"dev"` | no |
| tags | Additional tags | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| vm_id | Azure VM resource ID |
| vm_name | Name of the VM |
| vm_private_ip | Private IP address |
| vm_public_ip | Public IP address (if created) |
| ssh_command | SSH command to connect |
| ssh_host | SSH host for connection |
| admin_username | Admin username for SSH |
| resource_group_name | Resource group name |
| vnet_name | Virtual network name |
| vnet_id | Virtual network ID |
| subnet_id | Subnet ID |
| network_interface_id | Network interface ID |
| network_security_group_id | NSG ID |
| public_ip_id | Public IP resource ID |
| oidc_issuer | Configured OIDC issuer |
| oidc_client_id | Configured OIDC client ID |
| location | Azure region |
| created_resource_group | Whether new RG was created |
| created_vnet | Whether new VNet was created |
| created_public_ip | Whether public IP was created |

## Post-Deployment

After deployment, connect using the unix-oidc agent:

```bash
# Get your OIDC token (varies by IdP)
export OIDC_TOKEN=$(unix-oidc-agent get-token)

# SSH to the VM
ssh -o "SetEnv OIDC_TOKEN=$OIDC_TOKEN" azureuser@<vm-public-ip>
```

Or check the installation logs:

```bash
# SSH with your key first
ssh azureuser@<vm-public-ip>

# Check installation log
sudo cat /var/log/unix-oidc-install.log

# Verify PAM module
pamtester sshd azureuser authenticate
```

## Security Considerations

1. **SSH CIDRs**: The default allows SSH from anywhere (`0.0.0.0/0`). Restrict this in production using `allowed_ssh_cidrs`.
2. **DPoP**: Enabled by default for token binding security. Keep enabled in production.
3. **Public IP**: Consider setting `create_public_ip = false` and using Azure Bastion or VPN for access.
4. **Disk Type**: Use `Premium_LRS` for production workloads.

## Network Security Group Rules

The module creates an NSG with the following rules:

| Rule | Direction | Port | Protocol | Source | Description |
|------|-----------|------|----------|--------|-------------|
| SSH | Inbound | 22 | TCP | allowed_ssh_cidrs | SSH access |
| AllowAllOutbound | Outbound | * | * | * | OIDC provider communication |

## Troubleshooting

### VM not reachable

1. Check NSG rules allow your IP in `allowed_ssh_cidrs`
2. Verify the VM has a public IP or you have VPN/Bastion access
3. Check VM state in Azure Portal
4. Review boot diagnostics in Azure Portal

### unix-oidc not working

1. SSH with your key pair first
2. Check installation log: `sudo cat /var/log/unix-oidc-install.log`
3. Verify PAM config: `cat /etc/pam.d/sshd`
4. Test OIDC issuer: `curl -s $OIDC_ISSUER/.well-known/openid-configuration`

### Custom Script Extension failed

1. Check extension status in Azure Portal
2. Review logs: `sudo cat /var/log/azure/custom-script/handler.log`
3. Check cloud-init logs: `sudo cat /var/log/cloud-init-output.log`

### PAM authentication fails

1. Verify your OIDC token is valid
2. Check that `preferred_username` claim matches your Unix username
3. Review unix-oidc logs: `sudo journalctl -u sshd | grep pam_unix_oidc`

## License

Apache-2.0 OR MIT
