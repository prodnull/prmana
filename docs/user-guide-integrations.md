# Prmana: Universal Workflow Integration Guide

**Concept:** Prmana is client-agnostic. By leveraging the OpenSSH `SSH_ASKPASS` standard, we provide hardware-rooted evidence across every developer tool without requiring custom CLI wrappers.

---

## 1. Visual Studio Code (Remote-SSH)
Modern developers live in VSCode. Prmana provides a seamless, zero-friction experience for remote development.

- **How it works:** VSCode Remote-SSH uses the system's native `ssh` binary. 
- **Setup:**
  1. Ensure the `prmana-agent` is running locally.
  2. Set `export SSH_ASKPASS="/usr/local/bin/prmana-agent"` in your `.zshrc` or `.bashrc`.
  3. Set `export DISPLAY=":0"` (Required by OpenSSH to trigger the Askpass mechanism).
- **The Experience:** When you click "Connect to Host" in VSCode, Prmana automatically handles the OIDC/DPoP handshake in the background. You are connected instantly with hardware-rooted assurance.

---

## 2. Windows Subsystem for Linux (WSL2)
Prmana bridges the gap between Windows hardware security and Linux development.

- **The Challenge:** WSL2 is a virtualized environment that often lacks direct access to the Windows TPM.
- **The Prmana Solution:** The `prmana-agent` runs on the **Windows Host**, exposing a named pipe or socket to the WSL environment.
- **Benefits:**
  - Use your Windows Hello (Biometrics) or Windows TPM to sign DPoP proofs for your WSL terminal.
  - No need to manage separate keys inside WSL.
- **Setup:** Use the `prmana-agent-bridge` to relay WSL SSH requests to the Windows-native agent.

---

## 3. VDI & Remote Desktop (Citrix / VMware / AWS Workspaces)
Prmana provides high-fidelity evidence even when the user is miles away from the hardware.

### Path A: Seamless (vTPM)
Ideal for standard developer productivity.
- Prmana binds the identity to the **Virtual Machine's TPM**. 
- Ensures the OIDC token cannot be used outside the authorized VDI instance.

### Path B: High-Assurance (Hardware Redirection)
Ideal for Production/DBA access.
- Use a physical **Yubikey** plugged into your home laptop.
- Use **USB Redirection** to pass the Yubikey to the Prmana agent inside the VDI.
- **Result:** Access is granted only if the physical key is in the user's hand, preventing "Cloud-only" credential theft.

---

## 4. Automation & Ansible
Prmana isn't just for humans. It secures your "Agentic" automation.

- **Headless Mode:** Configure the `prmana-agent` to use a TPM-protected "Service Identity" for Ansible controllers.
- **Audit:** Every Ansible play is now attributed to a specific hardware node with a verifiable OCSF audit trail.

---

## 5. Session Recording Compatibility

Prmana uses a direct-to-host architecture — no proxy, no gateway, no terminal multiplexer in the SSH path. This means Prmana does not build session recording. Instead, it is compatible with host-native recording tools that run alongside it on the server.

For regulated environments that require session recording (PCI DSS, HIPAA, SOC 2), deploy one of the following alongside Prmana:

### tlog (SSSD Session Recording)

- Records terminal I/O to the systemd journal or a remote Elasticsearch instance.
- Works with Prmana PAM sessions out of the box — tlog is configured in PAM, same as Prmana.
- Correlation: Prmana's OCSF `session_uid` maps to tlog's recording session ID.
- **Setup:** Install `tlog-rec-session`, add to `/etc/pam.d/sshd` after the Prmana auth line.

### auditd (Linux Audit Framework)

- Kernel-level audit of syscalls, file access, process execution, and network events.
- Always available on enterprise Linux (RHEL, Ubuntu, SLES).
- Correlation: Prmana logs the PAM session ID; auditd tags events with the same `auid` (audit UID).
- **Setup:** Configure audit rules for the session's TTY. No Prmana configuration needed.

### eBPF-Based Observability (Falco, Tetragon, Tracee)

- Kernel-level process and network observability without kernel modules.
- Captures process trees, file access, network connections with full context.
- Best for Kubernetes node enforcement and cloud-native environments.
- Correlation: Prmana's OCSF events include `process.pid` and `session_uid` for cross-tool correlation.
- **Setup:** Deploy as a DaemonSet (K8s) or systemd service. No Prmana configuration needed.

### What Prmana Provides (Identity Layer)

Prmana's OCSF audit trail answers **who** authenticated and **what privilege** was granted:
- IdP identity tied to every SSH login and sudo elevation
- DPoP proof verification status (hardware-bound vs software key)
- CIBA step-up approval events with command context
- Failover events and break-glass usage

The recording tool answers **what happened during the session**. Together, they provide complete compliance evidence without a proxy in the SSH path.
