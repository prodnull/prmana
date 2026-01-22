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

1. **Keycloak Admin Console Overview** - Shows the realm configuration
2. **OIDC Login Flow** - Demonstrates the standard OIDC authorization code flow
3. **Device Authorization Flow** - Shows sudo step-up authentication
4. **User Profile and Token Claims** - Displays user information and claims
5. **Realm Security Settings** - Shows token and session configuration

## Output Files

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
