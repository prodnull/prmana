# unix-oidc-instance module
# Shared Terraform module for installing unix-oidc on any cloud instance
#
# This module uses null_resource with remote-exec provisioner to:
# 1. Download and run the installer script
# 2. Configure /etc/unix-oidc/config.env
# 3. Optionally enable DPoP token binding

terraform {
  required_version = ">= 1.0"

  required_providers {
    null = {
      source  = "hashicorp/null"
      version = ">= 3.0"
    }
  }
}

locals {
  # Build version argument for installer
  version_arg = var.unix_oidc_version != "latest" ? "--version ${var.unix_oidc_version}" : ""

  # Build agent argument
  agent_arg = var.install_agent ? "" : "--no-agent"

  # Build installer command
  installer_args = join(" ", compact([
    "--issuer ${var.oidc_issuer}",
    "--client-id ${var.oidc_client_id}",
    local.version_arg,
    local.agent_arg,
    "--yes"
  ]))
}

# Install unix-oidc on the target instance
resource "null_resource" "unix_oidc_install" {
  connection {
    type        = var.connection.type
    host        = var.connection.host
    user        = var.connection.user
    private_key = var.connection.private_key
  }

  # Download and run the installer
  provisioner "remote-exec" {
    inline = [
      "echo 'Starting unix-oidc installation...'",

      # Install prerequisites if needed
      "if command -v apt-get >/dev/null 2>&1; then",
      "  sudo apt-get update -qq",
      "  sudo apt-get install -y -qq curl jq",
      "elif command -v dnf >/dev/null 2>&1; then",
      "  sudo dnf install -y -q curl jq",
      "elif command -v yum >/dev/null 2>&1; then",
      "  sudo yum install -y -q curl jq",
      "fi",

      # Download and run installer
      "curl -fsSL ${var.installer_url} -o /tmp/unix-oidc-install.sh",
      "chmod +x /tmp/unix-oidc-install.sh",
      "sudo /tmp/unix-oidc-install.sh ${local.installer_args}",

      # Clean up installer
      "rm -f /tmp/unix-oidc-install.sh",

      "echo 'unix-oidc installation complete'"
    ]
  }

  # Trigger reinstall if these values change
  triggers = {
    oidc_issuer       = var.oidc_issuer
    oidc_client_id    = var.oidc_client_id
    unix_oidc_version = var.unix_oidc_version
    install_agent     = var.install_agent
    enable_dpop       = var.enable_dpop
  }
}

# Configure unix-oidc settings
resource "null_resource" "unix_oidc_configure" {
  depends_on = [null_resource.unix_oidc_install]

  connection {
    type        = var.connection.type
    host        = var.connection.host
    user        = var.connection.user
    private_key = var.connection.private_key
  }

  # Update configuration file with all settings
  provisioner "remote-exec" {
    inline = [
      "echo 'Configuring unix-oidc...'",

      # Create/update config.env with all settings
      "sudo tee /etc/unix-oidc/config.env > /dev/null << 'EOFCONFIG'",
      "# unix-oidc configuration",
      "# Managed by Terraform - do not edit manually",
      "",
      "# OIDC Issuer URL (required)",
      "OIDC_ISSUER=${var.oidc_issuer}",
      "",
      "# OIDC Client ID",
      "OIDC_CLIENT_ID=${var.oidc_client_id}",
      "",
      "# DPoP token binding",
      "OIDC_DPOP_REQUIRED=${var.enable_dpop}",
      var.required_acr != "" ? "\n# Required ACR level\nOIDC_REQUIRED_ACR=${var.required_acr}" : "",
      var.max_auth_age > 0 ? "\n# Maximum auth age in seconds\nOIDC_MAX_AUTH_AGE=${var.max_auth_age}" : "",
      "EOFCONFIG",

      # Set proper permissions
      "sudo chmod 600 /etc/unix-oidc/config.env",
      "sudo chown root:root /etc/unix-oidc/config.env",

      "echo 'unix-oidc configuration complete'"
    ]
  }

  # Trigger reconfigure if these values change
  triggers = {
    oidc_issuer    = var.oidc_issuer
    oidc_client_id = var.oidc_client_id
    enable_dpop    = var.enable_dpop
    required_acr   = var.required_acr
    max_auth_age   = var.max_auth_age
  }
}

# Validate the installation
resource "null_resource" "unix_oidc_validate" {
  depends_on = [null_resource.unix_oidc_configure]

  connection {
    type        = var.connection.type
    host        = var.connection.host
    user        = var.connection.user
    private_key = var.connection.private_key
  }

  # Verify installation
  provisioner "remote-exec" {
    inline = [
      "echo 'Validating unix-oidc installation...'",

      # Check PAM module exists
      "if [ -f /lib/security/pam_unix_oidc.so ] || [ -f /lib64/security/pam_unix_oidc.so ]; then",
      "  echo 'PAM module: OK'",
      "else",
      "  echo 'PAM module: NOT FOUND' >&2",
      "  exit 1",
      "fi",

      # Check config exists
      "if [ -f /etc/unix-oidc/config.env ]; then",
      "  echo 'Configuration: OK'",
      "else",
      "  echo 'Configuration: NOT FOUND' >&2",
      "  exit 1",
      "fi",

      # Check agent if installed
      "if [ '${var.install_agent}' = 'true' ]; then",
      "  if [ -f /usr/local/bin/unix-oidc-agent ]; then",
      "    echo 'Agent: OK'",
      "  else",
      "    echo 'Agent: NOT FOUND' >&2",
      "    exit 1",
      "  fi",
      "fi",

      # Test OIDC issuer reachability
      "if curl -fsSL ${var.oidc_issuer}/.well-known/openid-configuration > /dev/null 2>&1; then",
      "  echo 'OIDC Issuer: REACHABLE'",
      "else",
      "  echo 'OIDC Issuer: UNREACHABLE (may be expected in some network configurations)'",
      "fi",

      "echo 'Validation complete'"
    ]
  }
}
