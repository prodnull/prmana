# azure-fleet Terraform Module

Provisions an N-node Azure Spot VM fleet for prmana-ci integration testing.
Mirrors the `aws-fleet` module's input/output contract so the `fleet-test.yml`
orchestration workflow can treat both clouds uniformly.

## Purpose

prmana validates against Azure for two reasons:

1. **Enterprise fit**: Many target buyers run Azure-first infrastructure.
2. **Entra ID IdP testing**: Azure VMs hosted in the same tenant as the test
   Entra ID application simplify the DPoP/bearer-only E2E test path in
   downstream DT-A scenarios.

## Supported Distro × Arch Matrix

| Distro          | amd64 | arm64 | Notes                                              |
| --------------- | :---: | :---: | -------------------------------------------------- |
| `ubuntu-22.04`  |  ✅   |  ✅   | Canonical official Jammy image                     |
| `ubuntu-24.04`  |  ✅   |  ✅   | Canonical official Noble image                     |
| `debian-12`     |  ✅   |  ✅   | Debian official Bookworm image                     |
| `rocky-9`       |  ✅   |  ✅   | resf (Rocky Enterprise Software Foundation) image  |
| `fedora-40`     |  ✅   |  ❌   | No official arm64 image on Azure Marketplace       |
| `amazon-linux-2023` | ❌ | ❌  | **AWS-only** — not available on Azure Marketplace  |

Unsupported combinations (fedora-40+arm64) are rejected at `terraform plan`
time with a descriptive error. The `terraform apply` step is never reached.

## Module Inputs

| Variable              | Type   | Default             | Description                                              |
| --------------------- | ------ | ------------------- | -------------------------------------------------------- |
| `distro`              | string | —                   | Linux distribution (see matrix above)                    |
| `arch`                | string | —                   | `amd64` or `arm64`                                       |
| `vm_count`            | number | —                   | Number of Spot VMs (1–10)                                |
| `max_instance_minutes`| number | `30`                | VM lifetime in minutes; cloud-init watchdog halts at N   |
| `budget_limit_usd`    | number | `5`                 | Azure Consumption Budget cap per run in USD              |
| `github_run_id`       | string | —                   | GitHub Actions run ID; embedded in all resource names    |
| `azure_location`      | string | `westus2`           | Azure region; must have Spot quota for selected sizes    |
| `vm_size_amd64`       | string | `Standard_B2s`      | Spot-eligible VM size for amd64                          |
| `vm_size_arm64`       | string | `Standard_D2ps_v5`  | Ampere Altra arm64 VM size (Spot-eligible)               |
| `ssh_public_key`      | string | —                   | SSH public key injected onto each VM (sensitive)         |
| `allowed_ssh_cidr`    | string | `0.0.0.0/0`         | CIDR for inbound SSH on the NSG; tighten in production   |

## Module Outputs

| Output                | Type         | Description                                              |
| --------------------- | ------------ | -------------------------------------------------------- |
| `vm_names`            | list(string) | Names of provisioned VMs                                 |
| `public_ips`          | list(string) | Public IPv4 addresses                                    |
| `private_ips`         | list(string) | Private IPv4 addresses (within fleet VNet)               |
| `ssh_user`            | string       | Admin username (ubuntu / rocky / admin / fedora)         |
| `resource_group_name` | string       | Per-run resource group name                              |
| `fleet_tag`           | string       | `prmana-ci-<github_run_id>`                              |
| `region`              | string       | Azure region                                             |

## Example Invocation

```hcl
module "azure_fleet" {
  source = "./test/infra/azure-fleet"

  distro               = "ubuntu-22.04"
  arch                 = "amd64"
  vm_count             = 5
  max_instance_minutes = 30
  budget_limit_usd     = 5
  github_run_id        = var.github_run_id
  ssh_public_key       = var.ssh_public_key
}

output "ips" {
  value = module.azure_fleet.public_ips
}
```

## Prerequisites

### 1. Entra Workload Identity Federation (ARM Provisioning)

This module authenticates to Azure Resource Manager via Entra workload identity
federation (OIDC). This is **separate** from the Entra ROPC credentials used in
`provider-tests.yml` for PAM token testing.

One-time setup (performed by a human with Owner rights on the subscription):

```bash
# 1. Create a new Entra application for ARM provisioning
APP_ID=$(az ad app create --display-name prmana-ci-fleet \
  --query appId -o tsv)

# 2. Create a service principal
az ad sp create --id "${APP_ID}"

# 3. Grant Contributor RBAC on the subscription
az role assignment create \
  --assignee "${APP_ID}" \
  --role Contributor \
  --scope "/subscriptions/${SUBSCRIPTION_ID}"

# 4. Add a federated credential (repo-scoped to refs/heads/main)
az ad app federated-credential create \
  --id "${APP_ID}" \
  --parameters '{
    "name": "prmana-fleet",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:prodnull/prmana:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'

# 5. Add GitHub repository secrets:
#   AZURE_CLIENT_ID       = <APP_ID>
#   AZURE_TENANT_ID       = <TENANT_ID>
#   AZURE_SUBSCRIPTION_ID = <SUBSCRIPTION_ID>
```

These secrets are **distinct** from `ENTRA_CLIENT_ID` and `ENTRA_TENANT_ID`
(used for ROPC PAM token tests). Do not reuse credentials between roles.

The GitHub Actions workflow sets the ARM environment variables used by the
azurerm provider:

```yaml
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
- run: |
    export ARM_USE_OIDC=true
    export ARM_CLIENT_ID=${{ secrets.AZURE_CLIENT_ID }}
    export ARM_TENANT_ID=${{ secrets.AZURE_TENANT_ID }}
    export ARM_SUBSCRIPTION_ID=${{ secrets.AZURE_SUBSCRIPTION_ID }}
    terraform apply -auto-approve
```

### 2. Spot VM Quota

The target Azure region must have Spot VM quota for the selected VM sizes.
Default sizes:

- amd64: `Standard_B2s` (2 vCPU, 4 GB RAM)
- arm64: `Standard_D2ps_v5` (2 vCPU, 8 GB RAM — Ampere Altra)

Request quota via: **Azure Portal → Subscriptions → Usage + quotas → Request
increase**, or:

```bash
az vm list-usage --location westus2 --query "[?name.value == 'StandardBSFamily']"
```

### 3. Marketplace Terms

Some publishers require accepting image terms before first use. Run these
once per subscription:

```bash
# Rocky 9 (resf)
az vm image terms accept \
  --publisher resf --offer rockylinux-x86_64 --plan 9-base
az vm image terms accept \
  --publisher resf --offer rockylinux-aarch64 --plan 9-base

# Fedora 40 (tunnelbiz)
az vm image terms accept \
  --publisher tunnelbiz --offer fedora --plan fedora-40

# Debian 12 and Ubuntu images (Canonical/Debian) do not require terms acceptance.
```

## Cost Model

| Component     | Estimate                                      |
| ------------- | --------------------------------------------- |
| VM pricing    | Azure Spot; ~60–90% discount vs. on-demand    |
| Standard_B2s  | ~$0.04–0.08/hr Spot in westus2                |
| D2ps_v5       | ~$0.07–0.12/hr Spot in westus2                |
| 5 nodes × 30 min | < $0.05 per run                           |
| Budget cap    | $5 per run (10× headroom)                     |

The budget alert fires at 80% of the cap ($4 by default). Workflow teardown
(`terraform destroy`) is the primary cost enforcement; the budget is a backstop.

## Cost Guardrail Layers

1. `vm_count` validation: max 10 VMs (variables.tf precondition)
2. Cloud-init `shutdown -h +N` watchdog in every VM
3. Spot `eviction_policy = Delete`: Azure-reclaimed VMs are fully destroyed,
   not left in stopped-deallocated state (which still incurs disk costs)
4. Azure Consumption Budget alert at 80% of `budget_limit_usd`

## Teardown

All resources are scoped to a single per-run resource group named
`rg-prmana-ci-<github_run_id>`. Destroying the resource group removes
everything atomically:

```bash
terraform destroy -auto-approve
# or directly:
az group delete --name "rg-prmana-ci-${GITHUB_RUN_ID}" --yes --no-wait
```

The `fleet-test.yml` workflow calls `terraform destroy` in an `if: always()`
step to ensure teardown runs even on failure.

## Security Notes

- Password authentication is disabled (`disable_password_authentication = true`).
  SSH key injection is the only login path.
- No client secrets are stored; all authentication is via OIDC federation tokens.
- Managed identity (`SystemAssigned`) is created but granted **no RBAC roles**
  by this module. Downstream phases grant minimum permissions as needed.
- All resources are tagged `Project=prmana-ci` and `GitHubRun=<run_id>` for
  attribution and cost allocation (see also `fleet_tag` output).

## Non-Goals

This module does **not**:

- Install prmana binaries or configure PAM (that is DT-A scope)
- Test SELinux or AppArmor policy (that is DT-B scope)
- Configure Entra ID OIDC application policies
- Provide a persistent Terraform state backend (the caller is responsible)
