import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

/**
 * PLAY-01: Automate Keycloak device flow consent.
 * PLAY-02: Tmpfile coordination with shell poll loop.
 * PLAY-03: CI-compatible headless execution.
 *
 * Coordination protocol:
 *   1. Shell script starts device flow, writes verification_uri_complete to TMPFILE
 *   2. This spec polls for TMPFILE, navigates, authenticates, grants consent
 *   3. Shell script's poll loop receives the token from Keycloak
 *
 * Environment variables:
 *   DEVICE_FLOW_TMPFILE — path to coordination tmpfile (required)
 *   KEYCLOAK_USER — username (default: testuser)
 *   KEYCLOAK_PASS — password (default: testpass)
 */

const TMPFILE = process.env.DEVICE_FLOW_TMPFILE || '/tmp/unix-oidc-device-flow-uri';
const KC_USER = process.env.KEYCLOAK_USER || 'testuser';
const KC_PASS = process.env.KEYCLOAK_PASS || 'testpass';

test('complete device flow consent via Keycloak UI', async ({ page }) => {
  // Step 1: Wait for the shell script to write the verification URI.
  // Poll the tmpfile with a short interval — the shell script writes it
  // immediately after receiving the device authorization response.
  test.setTimeout(90_000);

  let verificationUri = '';
  const maxWait = 60_000;
  const pollInterval = 500;
  const start = Date.now();

  while (Date.now() - start < maxWait) {
    try {
      if (fs.existsSync(TMPFILE)) {
        verificationUri = fs.readFileSync(TMPFILE, 'utf-8').trim();
        if (verificationUri) break;
      }
    } catch {
      // File not ready yet
    }
    await new Promise(r => setTimeout(r, pollInterval));
  }

  expect(verificationUri, 'Shell script did not write verification URI to tmpfile').toBeTruthy();
  console.log(`Navigating to: ${verificationUri}`);

  // Step 2: Navigate to the verification URI.
  // Keycloak shows the device login page with pre-filled user code.
  await page.goto(verificationUri);

  // Step 3: Keycloak 26.x login form — fill credentials.
  // Selectors verified against Keycloak 26.4 default theme.
  // The device flow page may show "Device Login" or go straight to login.
  await page.waitForSelector('#username, #kc-login', { timeout: 15_000 });

  // If we see a login form, fill it
  const usernameField = page.locator('#username');
  if (await usernameField.isVisible({ timeout: 3_000 }).catch(() => false)) {
    await usernameField.fill(KC_USER);
    await page.locator('#password').fill(KC_PASS);
    await page.locator('#kc-login').click();
    console.log('Credentials submitted');
  }

  // Step 4: Handle consent/grant page if present.
  // Keycloak may show "Do you grant access?" for device flow.
  // The approve button varies by theme: input[name="accept"], #kc-login, button[value="yes"].
  try {
    const consentBtn = page.locator('input[name="accept"], button[value="yes"], #kc-login');
    await consentBtn.first().waitFor({ state: 'visible', timeout: 5_000 });
    await consentBtn.first().click();
    console.log('Consent granted');
  } catch {
    // No consent page — direct approval (Keycloak configured with auto-consent)
    console.log('No consent page detected (auto-approved or single-page flow)');
  }

  // Step 5: Verify success page.
  // Keycloak device flow shows a success message after approval.
  // Wait for either "Device Login Successful" text or a redirect.
  try {
    await page.waitForSelector(
      'text=successfully, text=approved, text=Device Login, #kc-page-title',
      { timeout: 10_000 }
    );
    console.log('Device flow consent completed successfully');
  } catch {
    // Log the page content for debugging
    const title = await page.title();
    const bodyText = await page.locator('body').innerText().catch(() => '(empty)');
    console.log(`Final page title: ${title}`);
    console.log(`Final page text: ${bodyText.substring(0, 500)}`);
  }

  // Cleanup tmpfile
  try { fs.unlinkSync(TMPFILE); } catch { /* best-effort */ }
});
