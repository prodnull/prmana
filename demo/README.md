# unix-oidc Training Video Capture

This directory contains Playwright tests that capture training videos demonstrating
the unix-oidc authentication flows.

## Prerequisites

1. Docker and Docker Compose
2. Node.js 18+

## Setup

```bash
cd demo
npm install
npx playwright install chromium
```

## Recording Videos

### Start the test environment

```bash
cd ..
docker compose -f docker-compose.test.yaml up -d
./test/scripts/wait-for-healthy.sh
```

### Record all demos

```bash
npm run record
```

Videos are saved to `test-results/` directory.

### View report with videos

```bash
npm run show-report
```

## Demo Scenarios

| Demo | Description | Status |
|------|-------------|--------|
| 1. Keycloak Admin Console | Shows realm configuration | ⚠️ Requires HTTPS |
| 2. OIDC Login Flow | Standard OIDC auth code flow | ✅ Working |
| 3. Device Authorization Flow | Sudo step-up authentication | ✅ Working |
| 4. Policy Configuration | Policy YAML walkthrough | ✅ Working |
| 5. Audit Events | Structured audit log demo | ✅ Working |
| 6. Realm Security Settings | Token/session config | ⚠️ Requires HTTPS |

> Note: Admin console demos (1, 6) require Keycloak HTTPS configuration.
> The core client interaction demos (2-5) work with HTTP.

## Output Files

After running demos, videos are saved to:
- `output/demo-2-oidc-login.webm` - OIDC authentication flow
- `output/demo-3-sudo-stepup.webm` - Sudo step-up with device flow
- `output/demo-4-policy-config.webm` - Policy configuration walkthrough
- `output/demo-5-audit-events.webm` - Audit event log demonstration

Raw test artifacts:
- `test-results/*.webm` - Video recordings
- `test-results/*.png` - Screenshots at key moments
- `test-results/trace.zip` - Full Playwright trace for debugging

## Customization

Edit `tests/training-video.spec.ts` to:
- Add new demo scenarios
- Adjust timing for better visibility
- Modify test credentials

## Integration with Terminal Recording

For complete demos, combine with terminal recordings using:

```bash
# Record terminal with asciinema
asciinema rec demo-terminal.cast

# Convert to gif
agg demo-terminal.cast demo-terminal.gif
```
