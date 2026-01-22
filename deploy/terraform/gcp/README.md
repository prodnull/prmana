# unix-oidc GCP Terraform Module

This Terraform module deploys a GCE instance with unix-oidc pre-installed and configured for OIDC-based SSH authentication.

## Features

- Creates a GCE instance with unix-oidc PAM module installed
- Optionally creates a new VPC network or uses an existing one
- Configures firewall rules for SSH access and OIDC outbound traffic
- Uses Ubuntu 22.04 LTS by default
- Supports DPoP token binding
- Shielded VM with Secure Boot enabled

## Quick Start

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/gcp"

  project_id     = "my-gcp-project"
  oidc_issuer    = "https://login.example.com/realms/myorg"
  ssh_user       = "ubuntu"
  ssh_public_key = "ssh-rsa AAAA... user@host"
}

output "ssh_command" {
  value = module.unix_oidc.ssh_command
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| google | >= 4.0 |

## Prerequisites

1. GCP credentials configured (`gcloud auth application-default login`)
2. A GCP project with Compute Engine API enabled
3. An SSH key pair for instance access
4. An OIDC provider configured with unix-oidc client

## Usage

### Basic Usage (Creates New VPC)

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/gcp"

  project_id     = "my-gcp-project"
  oidc_issuer    = "https://login.example.com/realms/myorg"
  ssh_user       = "ubuntu"
  ssh_public_key = file("~/.ssh/id_rsa.pub")
}
```

### Using Existing VPC

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/gcp"

  project_id     = "my-gcp-project"
  oidc_issuer    = "https://login.example.com/realms/myorg"
  ssh_user       = "ubuntu"
  ssh_public_key = file("~/.ssh/id_rsa.pub")

  # Use existing VPC
  network    = "projects/my-project/global/networks/my-vpc"
  subnetwork = "projects/my-project/regions/us-central1/subnetworks/my-subnet"
}
```

### Production Configuration

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/gcp"

  # Project Configuration
  project_id = "my-gcp-project"
  region     = "us-central1"
  zone       = "us-central1-a"

  # OIDC Configuration
  oidc_issuer    = "https://login.example.com/realms/myorg"
  oidc_client_id = "unix-oidc-prod"
  enable_dpop    = true

  # Instance Configuration
  machine_type   = "e2-small"
  instance_name  = "prod-ssh-gateway"
  boot_disk_size = 50
  ssh_user       = "admin"
  ssh_public_key = file("~/.ssh/prod_key.pub")

  # Network Configuration
  network           = "projects/my-project/global/networks/prod-vpc"
  subnetwork        = "projects/my-project/regions/us-central1/subnetworks/prod-subnet"
  allowed_ssh_cidrs = ["10.0.0.0/8"]  # Restrict to internal network
  create_static_ip  = true

  # Labels
  environment = "prod"
  labels = {
    cost-center = "engineering"
    owner       = "platform-team"
  }
}
```

### Custom Image

```hcl
module "unix_oidc" {
  source = "github.com/prodnull/unix-oidc//deploy/terraform/gcp"

  project_id     = "my-gcp-project"
  oidc_issuer    = "https://login.example.com/realms/myorg"
  ssh_user       = "ubuntu"
  ssh_public_key = file("~/.ssh/id_rsa.pub")

  # Use a different OS image
  image_family  = "debian-12"
  image_project = "debian-cloud"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| oidc_issuer | OIDC issuer URL | `string` | n/a | yes |
| project_id | GCP project ID | `string` | n/a | yes |
| ssh_user | SSH username | `string` | n/a | yes |
| ssh_public_key | SSH public key | `string` | n/a | yes |
| oidc_client_id | OIDC client ID | `string` | `"unix-oidc"` | no |
| install_agent | Install unix-oidc-agent | `bool` | `true` | no |
| enable_dpop | Enable DPoP token binding | `bool` | `true` | no |
| region | GCP region | `string` | `"us-central1"` | no |
| zone | GCP zone | `string` | `"us-central1-a"` | no |
| machine_type | GCE machine type | `string` | `"e2-micro"` | no |
| image_family | OS image family | `string` | `"ubuntu-2204-lts"` | no |
| image_project | OS image project | `string` | `"ubuntu-os-cloud"` | no |
| instance_name | Instance name | `string` | `"unix-oidc-server"` | no |
| boot_disk_size | Boot disk size in GB | `number` | `20` | no |
| boot_disk_type | Boot disk type | `string` | `"pd-balanced"` | no |
| preemptible | Use preemptible (spot) VM | `bool` | `false` | no |
| network | Existing VPC network | `string` | `""` | no |
| subnetwork | Existing subnetwork | `string` | `""` | no |
| subnet_cidr | CIDR for new subnet | `string` | `"10.0.1.0/24"` | no |
| assign_public_ip | Assign public IP | `bool` | `true` | no |
| create_static_ip | Create static external IP | `bool` | `false` | no |
| allowed_ssh_cidrs | CIDRs allowed for SSH | `list(string)` | `["0.0.0.0/0"]` | no |
| service_account_email | Service account email | `string` | `""` | no |
| service_account_scopes | Service account scopes | `list(string)` | `["https://www.googleapis.com/auth/cloud-platform"]` | no |
| environment | Environment name | `string` | `"dev"` | no |
| labels | Additional labels | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| instance_id | GCE instance ID |
| instance_name | GCE instance name |
| instance_self_link | GCE instance self link |
| instance_private_ip | Private IP address |
| instance_public_ip | Public IP address |
| ssh_command | SSH command to connect |
| ssh_host | SSH host for connection |
| gcloud_ssh_command | gcloud SSH command |
| network | VPC network used |
| subnetwork | Subnetwork used |
| zone | Instance zone |
| firewall_ssh_name | SSH firewall rule name |
| firewall_egress_name | Egress firewall rule name |
| oidc_issuer | Configured OIDC issuer |
| oidc_client_id | Configured OIDC client ID |
| machine_type | Machine type used |
| image | Boot disk image used |
| instance_status | Instance status |
| created_network | Whether a new VPC was created |
| created_static_ip | Whether a static IP was created |
| static_ip_address | Static IP address (if created) |

## Post-Deployment

After deployment, connect using the unix-oidc agent:

```bash
# Get your OIDC token (varies by IdP)
export OIDC_TOKEN=$(unix-oidc-agent get-token)

# SSH to the instance
ssh -o "SetEnv OIDC_TOKEN=$OIDC_TOKEN" ubuntu@<instance-ip>
```

Or use gcloud SSH (with your SSH key):

```bash
# SSH via gcloud
gcloud compute ssh ubuntu@unix-oidc-server --zone=us-central1-a --project=my-project

# Check installation log
sudo cat /var/log/unix-oidc-install.log

# Verify PAM module
pamtester sshd ubuntu authenticate
```

## Security Considerations

1. **SSH CIDRs**: The default allows SSH from anywhere (`0.0.0.0/0`). Restrict this in production.
2. **DPoP**: Enabled by default for token binding security. Keep enabled in production.
3. **Shielded VM**: Instance uses Secure Boot, vTPM, and Integrity Monitoring.
4. **Service Account**: Uses default compute service account. Consider creating a dedicated service account with minimal permissions for production.
5. **VPC Flow Logs**: Enabled by default for new subnets for network monitoring.

## Troubleshooting

### Instance not reachable

1. Check firewall rules allow your IP
2. Verify the instance has a public IP or you have VPN access
3. Check instance status in GCP Console
4. Ensure SSH key is correctly configured

### unix-oidc not working

1. SSH with your key first
2. Check installation log: `sudo cat /var/log/unix-oidc-install.log`
3. Verify PAM config: `cat /etc/pam.d/sshd`
4. Test OIDC issuer: `curl -s $OIDC_ISSUER/.well-known/openid-configuration`

### PAM authentication fails

1. Verify your OIDC token is valid
2. Check that `preferred_username` claim matches your Unix username
3. Review unix-oidc logs: `sudo journalctl -u sshd | grep pam_unix_oidc`

### Startup script issues

```bash
# View startup script logs
sudo journalctl -u google-startup-scripts.service

# Check serial console output
gcloud compute instances get-serial-port-output unix-oidc-server \
  --zone=us-central1-a --project=my-project
```

## License

Apache-2.0 OR MIT
