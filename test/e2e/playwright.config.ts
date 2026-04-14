import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for prmana E2E device flow automation.
 *
 * Runs headlessly on GitHub Actions ubuntu-latest.
 * Keycloak must already be running (started by docker-compose.e2e.yaml).
 */
export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'html',
  timeout: 120_000,

  use: {
    // Keycloak is accessible via localhost:8080 (mapped from compose).
    baseURL: process.env.KEYCLOAK_URL || 'http://localhost:8080',
    trace: 'on-first-retry',
    video: process.env.CI ? 'off' : 'on',
    screenshot: 'only-on-failure',
    actionTimeout: 15_000,
  },

  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1280, height: 720 },
      },
    },
  ],
});
