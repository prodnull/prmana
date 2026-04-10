terraform {
  required_version = ">= 1.6"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
}

# Provider configuration: authenticate via Entra workload identity federation.
# The caller (GitHub Actions) must have already run `azure/login@v2` or set
# the following environment variables:
#   ARM_USE_OIDC=true
#   ARM_CLIENT_ID=<service-principal-app-id>
#   ARM_TENANT_ID=<tenant-id>
#   ARM_SUBSCRIPTION_ID=<subscription-id>
#
# No client secrets. Authentication is OIDC-only (RFC 7523 / OIDC Federation).
provider "azurerm" {
  features {}

  # Use Entra workload identity federation — reuses the same federation
  # already configured in .github/workflows/provider-tests.yml for the
  # Entra ROPC OIDC tests. ARM provisioning requires a *separate* service
  # principal with Contributor RBAC (see README.md §Prerequisites).
  use_oidc = true
}
