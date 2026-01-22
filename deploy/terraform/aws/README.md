# unix-oidc AWS Terraform Module

This Terraform module deploys an EC2 instance with unix-oidc pre-installed and configured for OIDC-based SSH authentication.

## Features

- Creates an EC2 instance with unix-oidc PAM module installed
- Optionally creates a new VPC or uses an existing one
- Configures security groups for SSH access
- Auto-detects Ubuntu 22.04 LTS AMI
- Supports DPoP token binding
- IMDSv2-only for enhanced security

## Quick Start

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/aws"

  oidc_issuer = "https://login.example.com/realms/myorg"
  key_name    = "my-ssh-key"
}

output "ssh_command" {
  value = module.unix_oidc.ssh_command
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | >= 4.0 |

## Prerequisites

1. AWS credentials configured
2. An SSH key pair created in AWS
3. An OIDC provider configured with unix-oidc client

## Usage

### Basic Usage (Creates New VPC)

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/aws"

  oidc_issuer = "https://login.example.com/realms/myorg"
  key_name    = "my-ssh-key"
}
```

### Using Existing VPC

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/aws"

  oidc_issuer = "https://login.example.com/realms/myorg"
  key_name    = "my-ssh-key"

  # Use existing VPC
  vpc_id    = "vpc-12345678"
  subnet_id = "subnet-12345678"
}
```

### Production Configuration

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/aws"

  # OIDC Configuration
  oidc_issuer    = "https://login.example.com/realms/myorg"
  oidc_client_id = "unix-oidc-prod"
  enable_dpop    = true

  # Instance Configuration
  instance_type    = "t3.small"
  instance_name    = "prod-ssh-gateway"
  root_volume_size = 50
  key_name         = "prod-key"

  # Network Configuration
  vpc_id            = "vpc-12345678"
  subnet_id         = "subnet-12345678"
  allowed_ssh_cidrs = ["10.0.0.0/8"]  # Restrict to internal network
  create_eip        = true

  # Tags
  environment = "prod"
  tags = {
    CostCenter = "engineering"
    Owner      = "platform-team"
  }
}
```

### Custom AMI

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/aws"

  oidc_issuer = "https://login.example.com/realms/myorg"
  key_name    = "my-ssh-key"

  # Use a specific AMI
  ami_id = "ami-0123456789abcdef0"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| oidc_issuer | OIDC issuer URL | `string` | n/a | yes |
| key_name | SSH key pair name | `string` | n/a | yes |
| oidc_client_id | OIDC client ID | `string` | `"unix-oidc"` | no |
| install_agent | Install unix-oidc-agent | `bool` | `true` | no |
| enable_dpop | Enable DPoP token binding | `bool` | `true` | no |
| instance_type | EC2 instance type | `string` | `"t3.micro"` | no |
| ami_id | AMI ID (auto-detects Ubuntu 22.04 if empty) | `string` | `""` | no |
| instance_name | Name tag for the instance | `string` | `"unix-oidc-server"` | no |
| root_volume_size | Root volume size in GB | `number` | `20` | no |
| root_volume_type | Root volume type | `string` | `"gp3"` | no |
| vpc_id | Existing VPC ID | `string` | `""` | no |
| subnet_id | Existing subnet ID | `string` | `""` | no |
| create_vpc | Create new VPC if vpc_id not provided | `bool` | `true` | no |
| vpc_cidr | CIDR for new VPC | `string` | `"10.0.0.0/16"` | no |
| public_subnet_cidrs | CIDRs for public subnets | `list(string)` | `["10.0.1.0/24", "10.0.2.0/24"]` | no |
| availability_zones | AZs for subnets | `list(string)` | `[]` | no |
| allowed_ssh_cidrs | CIDRs allowed for SSH | `list(string)` | `["0.0.0.0/0"]` | no |
| associate_public_ip | Assign public IP | `bool` | `true` | no |
| create_eip | Create Elastic IP | `bool` | `false` | no |
| environment | Environment name | `string` | `"dev"` | no |
| tags | Additional tags | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| instance_id | EC2 instance ID |
| instance_arn | EC2 instance ARN |
| instance_private_ip | Private IP address |
| instance_public_ip | Public IP address |
| instance_public_dns | Public DNS name |
| ssh_command | SSH command to connect |
| ssh_host | SSH host for connection |
| vpc_id | VPC ID |
| subnet_id | Subnet ID |
| security_group_id | Security group ID |
| availability_zone | Instance availability zone |
| oidc_issuer | Configured OIDC issuer |
| oidc_client_id | Configured OIDC client ID |
| ami_id | AMI ID used |
| instance_state | Instance state |
| created_vpc | Whether a new VPC was created |
| created_eip | Whether an EIP was created |

## Post-Deployment

After deployment, connect using the unix-oidc agent:

```bash
# Get your OIDC token (varies by IdP)
export OIDC_TOKEN=$(unix-oidc-agent get-token)

# SSH to the instance
ssh -o "SetEnv OIDC_TOKEN=$OIDC_TOKEN" ubuntu@<instance-ip>
```

Or check the installation logs:

```bash
# SSH with your key first
ssh -i ~/.ssh/your-key.pem ubuntu@<instance-ip>

# Check installation log
sudo cat /var/log/unix-oidc-install.log

# Verify PAM module
pamtester sshd ubuntu authenticate
```

## Security Considerations

1. **SSH CIDRs**: The default allows SSH from anywhere (`0.0.0.0/0`). Restrict this in production.
2. **DPoP**: Enabled by default for token binding security. Keep enabled in production.
3. **IMDSv2**: Instance uses IMDSv2 only to prevent SSRF attacks.
4. **Encrypted Volumes**: Root volume is encrypted by default.

## Troubleshooting

### Instance not reachable

1. Check security group allows your IP
2. Verify the instance has a public IP or you have VPN access
3. Check instance state in AWS console

### unix-oidc not working

1. SSH with your key pair first
2. Check installation log: `sudo cat /var/log/unix-oidc-install.log`
3. Verify PAM config: `cat /etc/pam.d/sshd`
4. Test OIDC issuer: `curl -s $OIDC_ISSUER/.well-known/openid-configuration`

### PAM authentication fails

1. Verify your OIDC token is valid
2. Check that `preferred_username` claim matches your Unix username
3. Review unix-oidc logs: `sudo journalctl -u sshd | grep pam_unix_oidc`

## License

Apache-2.0 OR MIT
