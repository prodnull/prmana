# Prmana SELinux Policy

This directory contains the SELinux policy for `prmana-agent`.

## Compilation

To compile the policy into a loadable module:

```bash
make build
```

This will produce `prmana.pp`.

## Installation

To install the policy:

```bash
sudo make install
```

## Verification

### Static Verification
Check if the policy allows access to sensitive files like the shadow file (should return nothing):

```bash
sesearch -A -s prmana_agent_t -t shadow_t
```

### Runtime Verification
Run the test script located in `test/mac/test_selinux.sh`.

## Test Coverage

- **Section A (Static Tests):** Verifies the policy structure and rules without requiring a loaded policy. Uses `sesearch`.
- **Section B (Runtime Tests):** Verifies actual enforcement on a live host. Requires the policy to be loaded and SELinux in enforcing mode.
