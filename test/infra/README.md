# test/infra — DT-0 Deployment Test Harness

Reusable fleet test infrastructure consumed by DT-A (package install), DT-B
(SELinux/AppArmor), and DT-C (rollout safety).  Built once in DT-0; extended
by downstream phases.  This layer is pure scaffolding — it provisions clean
Linux nodes and collects logs.  It does **not** install prmana, configure PAM,
or assert application-layer behaviour.

## Component map

| Directory                        | Purpose                                                   | README                             |
| -------------------------------- | --------------------------------------------------------- | ---------------------------------- |
| `aws-fleet/`                     | Terraform: N-node AWS Spot fleet over distro × arch matrix | [aws-fleet/README.md](aws-fleet/README.md) |
| `azure-fleet/`                   | Terraform: N-node Azure Spot VM fleet                     | [azure-fleet/README.md](azure-fleet/README.md) |
| `idp-proxy/`                     | Rust fault-injection proxy (503, slow, malformed JWKS, drop) | [idp-proxy/README.md](idp-proxy/README.md) |
| `logcollect/`                    | Per-instance log aggregation scripts and CI artifact upload | [logcollect/README.md](logcollect/README.md) |
| `scripts/`                       | Local dev-loop helper and success-criteria verifier        | This file §2–3                     |
| `.github/workflows/fleet-test.yml` | Orchestration entrypoint for all fleet tests              | §3                                 |

**Non-goals (explicit):** Package install assertions → DT-A. SELinux/AppArmor
enforcement → DT-B. Canary/rollout safety gates → DT-C.  RHEL 9 CI
(subscription gap) → community validation.

---

## 1. Architecture

```
Operator / CI
     │
     │  gh workflow run fleet-test.yml \
     │    -f distro=ubuntu-22.04 -f arch=amd64 \
     │    -f count=5 -f scenario=install-smoke -f cloud=aws
     ▼
.github/workflows/fleet-test.yml  (timeout-minutes: 30)
     │
     ├─── Cloud auth (OIDC federation — no long-lived keys)
     │      AWS:   aws-actions/configure-aws-credentials@v4 + AWS_ROLE_ARN
     │      Azure: azure/login@v2 + ARM_USE_OIDC=true
     │
     ├─── Terraform apply
     │      aws-fleet/   → N Spot EC2 instances   ─┐
     │      azure-fleet/ → N Azure Spot VMs        ─┤── SSH public_ips + ssh_user outputs
     │
     ├─── Wait for SSH readiness (up to 5 min)
     │
     ├─── [fault-* scenarios only]
     │      idp-proxy serve --listen 127.0.0.1:9443 &
     │      idp-proxy fault --mode 503 --duration 60s
     │
     ├─── Run scenario (reachability: uname + os-release over SSH)
     │      fault-503: additionally assert proxy returns HTTP 503
     │
     ├─── Collect logs  (if: always())
     │      logcollect/aggregate.sh → fleet-logs/<ip>/…
     │
     ├─── Upload artifact  (if: always())
     │      actions/upload-artifact@v4 → "fleet-logs-<run_id>" (7-day retention)
     │
     └─── Teardown  (all if: always())
            Terraform destroy (AWS or Azure)
            EC2 tag-based safety-net sweep  (GitHubRun=<run_id>)
            Azure RG safety-net sweep       (rg-prmana-ci-<run_id>)
```

The fault-injection path runs the idp-proxy **on the GitHub Actions runner**, not
on the fleet nodes.  In DT-0 the fleet nodes are reachability targets only; full
client-resilience testing against the proxy is DT-A scope.

---

## 2. Dev loop (local)

### Prerequisites

| Tool         | Minimum version | Install                                      |
| ------------ | --------------- | -------------------------------------------- |
| Terraform    | 1.7+            | `brew install terraform` / tfenv             |
| Rust         | 1.75+           | `curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf \| sh` |
| shellcheck   | 0.9+            | `brew install shellcheck`                    |
| Python 3 + PyYAML | any        | `pip install pyyaml`                         |
| yamllint     | any (optional)  | `pip install yamllint`                       |
| AWS CLI      | 2.x             | for live `terraform plan` / `aws ec2` checks |
| Azure CLI    | 2.x             | for live Azure checks                        |

### Step 1 — Run all local validation

```bash
bash test/infra/scripts/local-dev-loop.sh
```

This runs (in sequence, no cloud calls):

1. `terraform validate` + `terraform fmt -check` on `aws-fleet/` and `azure-fleet/`
2. `cargo build` + `cargo test` inside `idp-proxy/`
3. `shellcheck` on `logcollect/*.sh` and `scripts/*.sh`
4. Python YAML parse of `.github/workflows/fleet-test.yml`

Each step prints `PASS` or `FAIL`.  The script exits non-zero if any step fails.
Total runtime: under 60 seconds.

### Step 2 — Optional: live terraform plan (requires creds)

```bash
cd test/infra/aws-fleet
terraform init -backend=false
terraform plan \
  -var="distro=ubuntu-22.04" \
  -var="arch=amd64" \
  -var="instance_count=1" \
  -var="github_run_id=local-dev" \
  -var="ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)"
```

This validates AMI resolution against your real AWS account without applying.

### Step 3 — Exercise idp-proxy fault modes locally

```bash
cd test/infra/idp-proxy
cargo build --release

# Terminal 1: run the proxy
./target/release/idp-proxy serve \
  --upstream http://localhost:8080 \
  --listen 127.0.0.1:9443 \
  --control 127.0.0.1:9444

# Terminal 2: inject a 503 fault for 30 seconds
./target/release/idp-proxy fault \
  --control http://127.0.0.1:9444 \
  --mode 503 \
  --duration 30s

# Verify the fault is active
curl -v http://127.0.0.1:9443/probe   # expect HTTP 503

# Restore normal operation
./target/release/idp-proxy fault \
  --control http://127.0.0.1:9444 \
  --mode off
```

---

## 3. CI loop (GitHub Actions)

### Trigger syntax

```bash
# Single-distro smoke test on AWS (amd64, 5 nodes)
gh workflow run fleet-test.yml \
  -f distro=ubuntu-22.04 \
  -f arch=amd64 \
  -f count=5 \
  -f scenario=install-smoke \
  -f cloud=aws

# Fault injection test on AWS (3 nodes, 60-second 503 window)
gh workflow run fleet-test.yml \
  -f distro=ubuntu-22.04 \
  -f arch=amd64 \
  -f count=3 \
  -f scenario=fault-503 \
  -f cloud=aws \
  -f fault_duration=60s

# Azure parity run
gh workflow run fleet-test.yml \
  -f distro=ubuntu-22.04 \
  -f arch=amd64 \
  -f count=3 \
  -f scenario=install-smoke \
  -f cloud=azure
```

### Scenario × cloud matrix

| Scenario              | Cloud | Expected duration | Typical cost (5 nodes) |
| --------------------- | ----- | ----------------- | ---------------------- |
| `install-smoke`       | aws   | < 15 min          | ~$0.02                 |
| `install-smoke`       | azure | < 15 min          | ~$0.03                 |
| `fault-503`           | aws   | < 15 min          | ~$0.02                 |
| `fault-slow`          | aws   | < 15 min          | ~$0.02                 |
| `fault-malformed-jwks`| aws   | < 15 min          | ~$0.02                 |
| `fault-drop`          | aws   | < 15 min          | ~$0.02                 |

### Monitoring a run

```bash
# List recent runs
gh run list --workflow=fleet-test.yml --limit=5

# Watch a run in real time
gh run watch <run_id>

# View logs after completion
gh run view <run_id> --log
```

### Retrieving log artifacts

```bash
# Download the log bundle (available within 2 minutes of job completion)
gh run download <run_id> --name fleet-logs-<run_id>

# Structure:
# fleet-logs-<run_id>/
#   <ip1>/
#     journalctl.json
#     dmesg.log
#     systemctl-status.txt
#     audit.log
#     metadata.txt
#     uname.txt
#     os-release.txt
#   <ip1>.tar.gz
#   <ip2>/
#     ...

# Search across all instances
grep -r "error" fleet-logs-<run_id>/
```

### Debugging a failed run

| Symptom                                  | Check                                          |
| ---------------------------------------- | ---------------------------------------------- |
| "SSH unreachable after 5 min"            | AMI not found, SG misconfigured, or quota hit  |
| "terraform: no module named aws-fleet"   | Working directory wrong; check `working-directory:` |
| "fault-503 assertion failed: got 000"    | idp-proxy did not start; check cargo build step |
| "az group show: error"                   | Azure credentials not configured; check `AZURE_CLIENT_ID` secret |
| Run cancelled at 30 min                  | Expected for hung-test SC 5 validation         |

### Teardown safety layers

1. **Job timeout** (`timeout-minutes: 30`): GitHub kills the job; `if: always()` steps still run.
2. **`terraform destroy` (if: always())**: primary teardown, removes all resources managed by TF state.
3. **EC2 tag-based sweep**: terminates any instances still tagged `GitHubRun=<run_id>` even if TF state was lost.
4. **Azure RG sweep**: deletes `rg-prmana-ci-<run_id>` if it still exists.
5. **Instance-level watchdog** (`shutdown -h +30` in cloud-init): fires even if the CI runner crashes.
6. **AWS Budget alarm**: SNS notification at 80% of $5 cap if layers 1–5 all fail.

---

## 4. Component reference

### `aws-fleet/` — AWS Spot Fleet Terraform module

Parameterized over distro × arch × count.  Resolves distro-specific AMIs from
verified public owners (Canonical SSM, Debian Marketplace owner, Rocky Linux
official, Fedora Cloud official).  IMDSv2 enforced.  Ephemeral keypair and
security group per run.  Shutdown watchdog via `shutdown -h +N` in user-data.

Full interface: [aws-fleet/README.md](aws-fleet/README.md)

### `azure-fleet/` — Azure Spot VM Terraform module

Mirrors the aws-fleet input/output contract.  All resources in a per-run
resource group (`rg-prmana-ci-<run_id>`).  Spot eviction policy `Delete`
(avoids stopped-deallocated disk costs).  AL2023 is AWS-only and not available
in the Azure Marketplace.

Full interface: [azure-fleet/README.md](azure-fleet/README.md)

### `idp-proxy/` — Rust fault-injection proxy

Thin HTTP reverse proxy with a control-plane REST API.  Supports four fault
modes: `503` (fixed error), `slow` (configurable latency), `malformed-jwks`
(broken JSON), `drop-connection` (TCP reset).  Runs on loopback only.

Full interface: [idp-proxy/README.md](idp-proxy/README.md)

### `logcollect/` — Per-instance log aggregation scripts

`collect.sh` runs on each fleet instance (over SSH) and tarballs
journalctl/dmesg/systemctl/audit.log.  `aggregate.sh` runs on the GitHub
Actions runner, scp-fetches each tarball, and extracts to `fleet-logs/<ip>/`.
Failure is per-instance; one broken instance does not abort collection for the
rest.

Full interface: [logcollect/README.md](logcollect/README.md)

---

## 5. Cost model

### Per-run estimate

| Component             | AWS (t3a.small spot) | Azure (Standard_B2s spot) |
| --------------------- | -------------------- | ------------------------- |
| Spot rate             | ~$0.005–0.01/hr      | ~$0.04–0.08/hr            |
| 5 nodes × 15 min      | ~$0.006–0.01         | ~$0.05                    |
| Ephemeral keypair/SG  | $0.00                | $0.00                     |
| **Per single run**    | **~$0.01–0.02**      | **~$0.05**                |

### Full matrix run estimate

Full matrix: 5 distros × 2 arches × 5 nodes = 50 instances × 15 min each.

| Scenario          | AWS            | Azure          |
| ----------------- | -------------- | -------------- |
| Best case (spot)  | ~$0.25         | ~$0.50         |
| Worst case        | ~$0.50         | ~$1.00         |
| **Budget cap**    | **$5.00 (10×)**| **$5.00 (5×)** |

**SC 4 cost acceptance statement:** The worst-case estimate of ~$1.00 for a full
matrix run (50 instances × 15 min at maximum spot rate) provides 5× headroom
under the $5 cap.  This derivation satisfies design doc §4.5.4.  A live matrix
run is recommended in DT-A where real install work justifies the spend; for
DT-0 the cost model is accepted as sufficient evidence.

### Budget alarm

The AWS Budget (`budget.tf` in aws-fleet) triggers an SNS notification at 80%
of the `budget_limit_usd` default ($5), i.e., at $4.  The alarm **notifies**
but does NOT stop the workflow — that is the timeout's job.  If the alarm fires
consistently, shorten `max_instance_minutes` or reduce `count`.

---

## 6. Success criteria verification

Run the automated checks:

```bash
bash test/infra/scripts/verify-success-criteria.sh
```

This script evaluates all five DT-0 success criteria from design doc §4.5.
Local (automated) checks exit 0 or 1.  Checks requiring a live cloud run print
`[MANUAL]` instructions.

See §7 of the script's output for a final pass/fail summary.

The five criteria:

| SC | Summary                                       | Automated check                         |
| -- | --------------------------------------------- | --------------------------------------- |
| 1  | End-to-end run < 15 min, zero cloud residue   | Workflow YAML structure                 |
| 2  | IdP 503 fault reproducible on demand          | idp-proxy build + cargo test            |
| 3  | Log artifact available < 2 min post-completion| Artifact upload step present in YAML    |
| 4  | Full matrix cost < $5                         | Cost model derivation printed           |
| 5  | Hung test terminated within 30 min            | timeout-minutes + watchdog grep         |

---

## 7. Extending the harness

### DT-A — Package install assertions

Add a new scenario string (`package-install`) to `fleet-test.yml` inputs.  The
scenario step builds and scps the prmana `.deb`/`.rpm` to each node, installs
it, and runs `prmana-ci verify`.  Assert via SSH exit code.  No changes to
`aws-fleet/` or `azure-fleet/` modules.

### DT-B — SELinux/AppArmor enforcement

Add a `selinux-enforce` scenario.  The scenario step sets `SELINUX=enforcing`,
installs the prmana policy module, and runs an SSH login that should be denied.
Assert via `ausearch -m avc` in the collected logs.

### DT-C — Canary/rollout safety

Add a `canary-rollout` scenario.  Use `instance_count=10`, apply a prmana
upgrade to the first 5, assert health, then apply to the remaining 5.  The
workflow orchestrates the two waves within a single `terraform apply` by
targeting instance subsets via `-target`.

---

## 8. Security posture

| Control                      | Detail                                                                 |
| ---------------------------- | ---------------------------------------------------------------------- |
| OIDC federation only         | No long-lived AWS or Azure credentials stored in GitHub secrets.       |
| IMDSv2 enforced (AWS)        | Prevents SSRF-based instance credential theft (T-DT0-01-03).          |
| Ephemeral SSH keypair        | One ed25519 keypair per workflow run; never uploaded as artifact.      |
| Log artifacts                | 7-day retention, private repo visibility. DT-0 logs contain no OIDC tokens or DPoP proofs (prmana not installed). |
| idp-proxy control plane      | Loopback-only (`127.0.0.1:9444`); not reachable from fleet nodes.     |
| Budget alarm                 | SNS at 80% of $5 cap; backstop against runaway fleet costs.           |
| Workflow injection safety    | All `workflow_dispatch` inputs passed via `env:` blocks; never interpolated into `run:` shells (T-DT0-04-07). |
| Tag-based safety-net sweep   | Terminates any orphaned instances/RGs even if Terraform state is lost. |

Detailed threat registers: see `<threat_model>` blocks in DT-0-01 through
DT-0-05 PLAN.md files under `.planning/phases/DT-0-deployment-test-harness/`.
