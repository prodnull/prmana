import { test, expect, Page, CDPSession } from '@playwright/test';

/**
 * Training Video: unix-oidc Authentication Flows
 *
 * Run with: npm run record
 * Videos saved to: test-results/
 */

const KEYCLOAK_URL = 'http://localhost:8080';
const REALM = 'unix-oidc-test';
const TEST_USER = 'testuser';
const TEST_PASSWORD = 'testpass';

// Helper: Add explanatory text overlay at bottom of screen
async function showCaption(page: Page, text: string, durationMs: number = 3000) {
  await page.evaluate((caption) => {
    // Remove existing caption
    const existing = document.getElementById('demo-caption');
    if (existing) existing.remove();

    // Create caption overlay
    const overlay = document.createElement('div');
    overlay.id = 'demo-caption';
    overlay.style.cssText = `
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      background: rgba(0, 0, 0, 0.9);
      color: white;
      padding: 20px 32px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 18px;
      text-align: center;
      z-index: 999999;
      border-top: 3px solid #4a9eff;
      line-height: 1.4;
    `;
    overlay.textContent = caption;
    document.body.appendChild(overlay);
  }, text);

  await page.waitForTimeout(durationMs);
}

// Helper: Clear caption
async function clearCaption(page: Page) {
  await page.evaluate(() => {
    const existing = document.getElementById('demo-caption');
    if (existing) existing.remove();
  });
}

// Terminal HTML template
const getTerminalHTML = (title: string = 'testuser@prod-server: ~') => `
  <html>
    <head>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          background: #0d1117;
          color: #c9d1d9;
          font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
          font-size: 15px;
          line-height: 1.6;
          padding: 0;
          height: 100vh;
          display: flex;
          flex-direction: column;
        }
        .titlebar {
          background: linear-gradient(#3a3a3a, #2a2a2a);
          padding: 8px 12px;
          display: flex;
          align-items: center;
          gap: 8px;
          border-bottom: 1px solid #1a1a1a;
        }
        .titlebar-btn { width: 12px; height: 12px; border-radius: 50%; }
        .btn-close { background: #ff5f56; }
        .btn-min { background: #ffbd2e; }
        .btn-max { background: #27ca40; }
        .titlebar-title { flex: 1; text-align: center; color: #999; font-size: 13px; }
        .terminal { flex: 1; padding: 20px; overflow: auto; }
        .prompt { color: #58a6ff; }
        .command { color: #c9d1d9; }
        .output { color: #8b949e; }
        .highlight { color: #f0883e; font-weight: bold; }
        .success { color: #3fb950; }
        .error { color: #f85149; }
        .warning { color: #d29922; }
        .box {
          border: 1px solid #30363d;
          border-radius: 6px;
          padding: 16px 20px;
          margin: 16px 0;
          background: #161b22;
        }
        .box-title { color: #f0883e; font-weight: bold; margin-bottom: 12px; font-size: 16px; }
        .code { font-size: 22px; letter-spacing: 3px; color: #58a6ff; font-weight: bold; }
        .cursor {
          display: inline-block;
          width: 10px;
          height: 18px;
          background: #c9d1d9;
          animation: blink 1s step-end infinite;
          vertical-align: middle;
          margin-left: 2px;
        }
        @keyframes blink { 50% { opacity: 0; } }
        .spinner { display: inline-block; animation: spin 1s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        #terminal-content { white-space: pre-wrap; }
        .log-line { margin: 4px 0; font-size: 13px; }
        .log-time { color: #6e7681; }
        .log-level-info { color: #58a6ff; }
        .log-level-warn { color: #d29922; }
        .log-level-audit { color: #a371f7; }
        .json-key { color: #7ee787; }
        .json-string { color: #a5d6ff; }
        .json-number { color: #79c0ff; }
      </style>
    </head>
    <body>
      <div class="titlebar">
        <div class="titlebar-btn btn-close"></div>
        <div class="titlebar-btn btn-min"></div>
        <div class="titlebar-btn btn-max"></div>
        <div class="titlebar-title">${title}</div>
      </div>
      <div class="terminal">
        <div id="terminal-content"></div>
      </div>
    </body>
  </html>
`;

test.describe('unix-oidc Training Videos', () => {
  test.beforeEach(async ({ page }) => {
    page.setDefaultTimeout(60000);
  });

  test('Demo 1: Keycloak Admin Console', async ({ page }) => {
    await page.goto(`${KEYCLOAK_URL}/admin/master/console/`);
    await page.waitForSelector('input[name="username"]');
    await showCaption(page, '🔐 Keycloak Admin Console - Configure OIDC authentication for unix-oidc');

    await page.fill('input[name="username"]', 'admin');
    await page.fill('input[name="password"]', 'admin');
    await page.waitForTimeout(500);
    await page.click('input[type="submit"], button[type="submit"]');

    await page.waitForURL('**/admin/master/console/**');
    await showCaption(page, '✅ Logged in as administrator - Managing identity provider settings');

    await page.click('[data-testid="realmSelectorToggle"]');
    await page.waitForTimeout(500);
    await page.click('text=unix-oidc-test');
    await showCaption(page, '🏢 unix-oidc-test realm - Users, clients, and authentication policies');

    await page.getByRole('link', { name: 'Clients' }).click();
    await showCaption(page, '📋 OIDC Clients - "unix-oidc" client handles SSH and sudo authentication', 4000);

    await clearCaption(page);
  });

  test('Demo 2: OIDC Login Flow', async ({ page }) => {
    await page.goto(`${KEYCLOAK_URL}/realms/${REALM}/account/`);
    await page.waitForSelector('input[name="username"]');
    await showCaption(page, '🌐 OIDC Login - User authenticates with enterprise identity provider');

    await page.fill('input[name="username"]', TEST_USER);
    await showCaption(page, '👤 Username maps to Unix account via SSSD/LDAP integration');

    await page.fill('input[name="password"]', TEST_PASSWORD);
    await showCaption(page, '🔑 In production: Passkeys or push notifications instead of passwords');

    await page.click('input[type="submit"]');
    await page.waitForTimeout(2000);
    await showCaption(page, '✅ Authenticated! Token issued with DPoP binding for SSH session', 4000);

    await clearCaption(page);
  });

  test('Demo 3: Sudo Step-Up with Device Flow', async ({ page }) => {
    test.setTimeout(180000); // 3 minutes for this demo

    // Terminal simulation
    await page.goto('about:blank');
    await page.setContent(getTerminalHTML());
    await page.waitForTimeout(500);

    const addLine = async (html: string) => {
      await page.evaluate((content) => {
        const el = document.getElementById('terminal-content');
        if (el) el.innerHTML += content;
      }, html);
      await page.waitForTimeout(100);
    };

    const typeText = async (text: string) => {
      for (const char of text) {
        await page.evaluate((c) => {
          const el = document.getElementById('terminal-content');
          if (el) {
            const cursor = el.querySelector('.cursor');
            if (cursor) cursor.remove();
            el.innerHTML += `<span class="command">${c}</span>`;
          }
        }, char);
        await page.waitForTimeout(40 + Math.random() * 20);
      }
    };

    // Show prompt
    await addLine('<span class="prompt">testuser@prod-server</span>:<span style="color:#8b949e">~</span>$ ');
    await showCaption(page, '🖥️ User is connected to production server via SSH with OIDC token');

    // Type command
    await typeText('sudo systemctl restart nginx');
    await addLine('<span class="cursor"></span>');
    await showCaption(page, '⌨️ Running privileged command - PAM module will require step-up auth');

    // Execute
    await page.evaluate(() => {
      const el = document.getElementById('terminal-content');
      if (el) {
        const cursor = el.querySelector('.cursor');
        if (cursor) cursor.remove();
        el.innerHTML += '<br>';
      }
    });

    // Step-up box
    await addLine('<br><div class="box">');
    await addLine('<div class="box-title">🔐 Step-up Authentication Required</div>');
    await showCaption(page, '🔒 unix-oidc PAM module intercepts sudo - requires fresh authentication');

    await addLine('<div style="margin: 8px 0;">Privileged command detected. Authenticate to continue:</div>');
    await addLine('<div style="margin: 16px 0;">');

    // Get real device code
    const deviceResponse = await page.request.post(
      `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/auth/device`,
      { form: { client_id: 'unix-oidc', client_secret: 'unix-oidc-test-secret', scope: 'openid' } }
    );
    const deviceData = await deviceResponse.json();
    const userCode = deviceData.user_code;
    const verificationUri = deviceData.verification_uri_complete;

    await addLine(`  <span class="output">URL:</span>   <span class="highlight">https://auth.example.com/device</span><br>`);
    await addLine(`  <span class="output">Code:</span>  <span class="code">${userCode}</span><br>`);
    await addLine('</div>');
    await addLine('<div style="margin-top: 16px;">');
    await addLine('  <span class="spinner">◐</span> <span class="output">Waiting for authentication... (timeout: 5m)</span>');
    await addLine('</div></div>');

    await showCaption(page, `📱 Device code "${userCode}" displayed - User authenticates on phone/browser`, 4000);

    // Browser authentication
    await page.goto(verificationUri);
    await showCaption(page, '🌐 User opens verification URL - Code auto-filled from link');

    const loginForm = page.locator('input[name="username"]');
    if (await loginForm.isVisible()) {
      await showCaption(page, '🔐 Production: FIDO2 passkey (phishing-resistant). Demo: password for simplicity', 4000);
      await page.fill('input[name="username"]', TEST_USER);
      await page.fill('input[name="password"]', TEST_PASSWORD);
      await page.click('input[type="submit"]');
      await page.waitForTimeout(1500);
      await showCaption(page, '🛡️ Passkeys eliminate password theft, phishing, and credential stuffing attacks', 4000);
    }

    await showCaption(page, '✋ Confirm authorization - "Yes, I want to run this sudo command"');

    const yesButton = page.locator('input[type="submit"][value="Yes"], button:has-text("Yes")');
    if (await yesButton.isVisible()) {
      await page.waitForTimeout(1000);
      await yesButton.click();
    }

    await page.waitForTimeout(1500);
    await showCaption(page, '✅ Approved! Returning to terminal...');

    // Success terminal
    await page.setContent(getTerminalHTML());
    await page.waitForTimeout(300);

    await addLine('<span class="prompt">testuser@prod-server</span>:<span style="color:#8b949e">~</span>$ sudo systemctl restart nginx<br>');
    await addLine('<br><div class="box">');
    await addLine('<div class="box-title">🔐 Step-up Authentication Required</div>');
    await addLine(`<div>Code: <span class="code">${userCode}</span></div>`);
    await addLine('<div style="margin-top: 12px;">');
    await addLine('  <span class="success">✓ Authentication successful!</span>');
    await addLine('</div></div><br>');
    await addLine('<span class="success">● nginx.service - A high performance web server</span><br>');
    await addLine('<span class="output">   Loaded: loaded (/lib/systemd/system/nginx.service; enabled)</span><br>');
    await addLine('<span class="success">   Active: active (running) since Mon 2026-01-18 10:15:32 UTC</span><br><br>');
    await addLine('<span class="prompt">testuser@prod-server</span>:<span style="color:#8b949e">~</span>$ <span class="cursor"></span>');

    await showCaption(page, '✅ sudo command completed! nginx restarted with proper authorization', 4000);
    await clearCaption(page);
  });

  test('Demo 4: Policy Configuration', async ({ page }) => {
    test.setTimeout(120000);

    // Pre-rendered policy file content (static HTML for demo - no user input)
    const policyContent = `
<span class="output"># /etc/unix-oidc/policy.yaml</span>
<span class="output"># Step-up authentication configuration for privileged commands</span>

<span class="json-key">host_classification:</span> <span class="json-string">elevated</span>  <span class="output"># production server</span>

<span class="json-key">ssh:</span>
  <span class="json-key">require_oidc:</span> <span class="json-string">true</span>
  <span class="json-key">minimum_acr:</span> <span class="json-string">null</span>  <span class="output"># accept any ACR for login</span>
  <span class="json-key">max_auth_age:</span> <span class="json-number">3600</span>  <span class="output"># 1 hour</span>

<span class="json-key">sudo:</span>
  <span class="json-key">step_up_required:</span> <span class="json-string">true</span>
  <span class="json-key">timeout_seconds:</span> <span class="json-number">300</span>  <span class="output"># 5 minute timeout</span>
  <span class="json-key">required_acr:</span> <span class="json-string">urn:keycloak:acr:loa2</span>  <span class="output"># Require MFA</span>

  <span class="json-key">allowed_methods:</span>
    - <span class="json-string">device_flow</span>  <span class="output"># OAuth 2.0 Device Authorization Grant</span>
    - <span class="json-string">webauthn</span>     <span class="output"># FIDO2/WebAuthn passkey authentication</span>

  <span class="json-key">grace_period_seconds:</span> <span class="json-number">300</span>  <span class="output"># 5 minutes</span>
  <span class="json-key">grace_period_scope:</span> <span class="json-string">command_class</span>

  <span class="json-key">command_classes:</span>
    <span class="json-key">service_management:</span>
      - <span class="json-string">"/usr/bin/systemctl*"</span>
      - <span class="json-string">"/usr/sbin/service*"</span>
    <span class="json-key">package_management:</span>
      - <span class="json-string">"/usr/bin/apt*"</span>
      - <span class="json-string">"/usr/bin/apt-get*"</span>
      - <span class="json-string">"/usr/bin/yum*"</span>
      - <span class="json-string">"/usr/bin/dnf*"</span>
    <span class="json-key">user_management:</span>
      - <span class="json-string">"/usr/sbin/useradd*"</span>
      - <span class="json-string">"/usr/sbin/usermod*"</span>
      - <span class="json-string">"/usr/sbin/userdel*"</span>

  <span class="json-key">commands:</span>  <span class="output"># Per-command overrides (first match wins)</span>
    <span class="output"># System administration - always require step-up</span>
    - <span class="json-key">pattern:</span> <span class="json-string">"/usr/sbin/shutdown*"</span>
      <span class="json-key">step_up_required:</span> <span class="json-string">true</span>
    - <span class="json-key">pattern:</span> <span class="json-string">"/usr/sbin/reboot*"</span>
      <span class="json-key">step_up_required:</span> <span class="json-string">true</span>
    - <span class="json-key">pattern:</span> <span class="json-string">"/usr/bin/systemctl restart*"</span>
      <span class="json-key">step_up_required:</span> <span class="json-string">true</span>
    - <span class="json-key">pattern:</span> <span class="json-string">"/usr/bin/systemctl stop*"</span>
      <span class="json-key">step_up_required:</span> <span class="json-string">true</span>

    <span class="output"># Read-only commands - no step-up needed</span>
    - <span class="json-key">pattern:</span> <span class="json-string">"/usr/bin/systemctl status*"</span>
      <span class="json-key">step_up_required:</span> <span class="json-string">false</span>
    - <span class="json-key">pattern:</span> <span class="json-string">"/bin/cat*"</span>
      <span class="json-key">step_up_required:</span> <span class="json-string">false</span>
    - <span class="json-key">pattern:</span> <span class="json-string">"/usr/bin/less*"</span>
      <span class="json-key">step_up_required:</span> <span class="json-string">false</span>
    - <span class="json-key">pattern:</span> <span class="json-string">"/usr/bin/tail*"</span>
      <span class="json-key">step_up_required:</span> <span class="json-string">false</span>
`.trim();

    await page.goto('about:blank');
    await page.setContent(getTerminalHTML('cat /etc/unix-oidc/policy.yaml'));
    await page.waitForTimeout(500);

    // Set full content immediately (static demo content, not user input)
    await page.evaluate((content) => {
      const el = document.getElementById('terminal-content');
      if (el) {
        const safeContent = content.replace(/\n/g, '<br>');
        el.innerHTML = safeContent;
      }
    }, policyContent);

    await showCaption(page, '📋 Policy Configuration - Define which commands require step-up authentication', 4000);

    // Scroll to show host classification
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 0, behavior: 'smooth' });
    });
    await showCaption(page, '🏢 Host classification: standard (workstation), elevated (staging), critical (production)', 4000);

    // Scroll to show sudo section
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 150, behavior: 'smooth' });
    });
    await showCaption(page, '🔐 Step-up config: Required ACR level (MFA), timeout, allowed auth methods', 4000);

    // Scroll to grace period
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 320, behavior: 'smooth' });
    });
    await showCaption(page, '⏱️ Grace period: Skip re-auth for same command class within 5 minutes', 4000);

    // Scroll to command classes
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 450, behavior: 'smooth' });
    });
    await showCaption(page, '📦 Command classes: Group commands (systemctl, apt, useradd) for grace period scope', 4000);

    // Scroll to per-command rules
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 650, behavior: 'smooth' });
    });
    await showCaption(page, '⚙️ Per-command rules: shutdown/reboot always require auth, status/cat exempt', 5000);

    // Scroll to bottom
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 9999, behavior: 'smooth' });
    });
    await showCaption(page, '✅ Fine-grained control: Dangerous commands locked down, read-only commands flow through', 4000);

    await clearCaption(page);
  });

  test('Demo 5: Audit Events', async ({ page }) => {
    test.setTimeout(120000);

    // Pre-rendered audit log content (static demo content)
    const auditContent = `
<div class="log-line"><span class="log-time">2026-01-18T10:14:28Z</span> <span class="log-level-audit">[AUDIT]</span></div>
<div style="margin-left: 20px; margin-bottom: 16px;">
  {
    <span class="json-key">"event"</span>: <span class="json-string">"ssh_auth_success"</span>,
    <span class="json-key">"user"</span>: <span class="json-string">"testuser"</span>,
    <span class="json-key">"source_ip"</span>: <span class="json-string">"10.0.1.42"</span>,
    <span class="json-key">"idp_subject"</span>: <span class="json-string">"auth0|abc123"</span>,
    <span class="json-key">"acr"</span>: <span class="json-string">"urn:keycloak:acr:loa2"</span>,
    <span class="json-key">"dpop_bound"</span>: <span class="json-number">true</span>,
    <span class="json-key">"session_id"</span>: <span class="json-string">"sess_7f3a9b2c"</span>
  }
</div>

<div class="log-line"><span class="log-time">2026-01-18T10:15:30Z</span> <span class="log-level-audit">[AUDIT]</span></div>
<div style="margin-left: 20px; margin-bottom: 16px;">
  {
    <span class="json-key">"event"</span>: <span class="json-string">"sudo_step_up_required"</span>,
    <span class="json-key">"user"</span>: <span class="json-string">"testuser"</span>,
    <span class="json-key">"command"</span>: <span class="json-string">"systemctl restart nginx"</span>,
    <span class="json-key">"command_class"</span>: <span class="json-string">"service_management"</span>,
    <span class="json-key">"device_code"</span>: <span class="json-string">"ABCD-1234"</span>,
    <span class="json-key">"session_id"</span>: <span class="json-string">"sess_7f3a9b2c"</span>
  }
</div>

<div class="log-line"><span class="log-time">2026-01-18T10:15:45Z</span> <span class="log-level-audit">[AUDIT]</span></div>
<div style="margin-left: 20px; margin-bottom: 16px;">
  {
    <span class="json-key">"event"</span>: <span class="json-string">"sudo_step_up_success"</span>,
    <span class="json-key">"user"</span>: <span class="json-string">"testuser"</span>,
    <span class="json-key">"command"</span>: <span class="json-string">"systemctl restart nginx"</span>,
    <span class="json-key">"auth_method"</span>: <span class="json-string">"device_flow"</span>,
    <span class="json-key">"auth_latency_ms"</span>: <span class="json-number">15234</span>,
    <span class="json-key">"grace_until"</span>: <span class="json-string">"2026-01-18T10:20:45Z"</span>
  }
</div>

<div class="log-line"><span class="log-time">2026-01-18T10:16:12Z</span> <span class="log-level-info">[INFO]</span></div>
<div style="margin-left: 20px; margin-bottom: 16px;">
  {
    <span class="json-key">"event"</span>: <span class="json-string">"sudo_grace_period_used"</span>,
    <span class="json-key">"user"</span>: <span class="json-string">"testuser"</span>,
    <span class="json-key">"command"</span>: <span class="json-string">"systemctl status nginx"</span>,
    <span class="json-key">"command_class"</span>: <span class="json-string">"service_management"</span>,
    <span class="json-key">"grace_remaining_sec"</span>: <span class="json-number">273</span>
  }
</div>

<div class="log-line"><span class="log-time">2026-01-18T10:18:02Z</span> <span class="log-level-warn">[WARN]</span></div>
<div style="margin-left: 20px; margin-bottom: 16px;">
  {
    <span class="json-key">"event"</span>: <span class="json-string">"sudo_step_up_denied"</span>,
    <span class="json-key">"user"</span>: <span class="json-string">"badactor"</span>,
    <span class="json-key">"command"</span>: <span class="json-string">"passwd root"</span>,
    <span class="json-key">"reason"</span>: <span class="json-string">"device_flow_timeout"</span>,
    <span class="json-key">"source_ip"</span>: <span class="json-string">"203.0.113.99"</span>,
    <span class="json-key">"session_id"</span>: <span class="json-string">"sess_9e4f2a1d"</span>
  }
</div>

<div class="log-line"><span class="log-time">2026-01-18T10:21:00Z</span> <span class="log-level-info">[INFO]</span></div>
<div style="margin-left: 20px; margin-bottom: 16px;">
  {
    <span class="json-key">"event"</span>: <span class="json-string">"sudo_grace_period_expired"</span>,
    <span class="json-key">"user"</span>: <span class="json-string">"testuser"</span>,
    <span class="json-key">"command_class"</span>: <span class="json-string">"service_management"</span>,
    <span class="json-key">"session_id"</span>: <span class="json-string">"sess_7f3a9b2c"</span>
  }
</div>
`.trim();

    await page.goto('about:blank');
    await page.setContent(getTerminalHTML('tail -f /var/log/unix-oidc/audit.json | jq'));
    await page.waitForTimeout(500);

    // Set full content immediately (static demo content)
    await page.evaluate((content) => {
      const el = document.getElementById('terminal-content');
      if (el) {
        const safeContent = content.replace(/\n/g, '<br>');
        el.innerHTML = safeContent;
      }
    }, auditContent);

    await showCaption(page, '📊 Audit Log - All authentication events logged as structured JSON for SIEM integration', 4000);

    // Scroll to top - SSH login event
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 0, behavior: 'smooth' });
    });
    await showCaption(page, '🔐 SSH login: User, source IP, IdP subject, ACR level, DPoP binding, session correlation', 5000);

    // Scroll to step-up required event
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 220, behavior: 'smooth' });
    });
    await showCaption(page, '⏳ Step-up initiated: Command, class, device code issued - waiting for user approval', 5000);

    // Scroll to step-up success
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 440, behavior: 'smooth' });
    });
    await showCaption(page, '✅ Step-up success: Auth method, latency measured, grace period window set', 5000);

    // Scroll to grace period used
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 660, behavior: 'smooth' });
    });
    await showCaption(page, '⏱️ Grace period: Same command class within window - no re-auth needed', 5000);

    // Scroll to denied event
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 880, behavior: 'smooth' });
    });
    await showCaption(page, '🚨 Step-up denied: Failed auth attempt logged with reason - incident investigation ready', 5000);

    // Scroll to grace expired
    await page.evaluate(() => {
      document.querySelector('.terminal')?.scrollTo({ top: 9999, behavior: 'smooth' });
    });
    await showCaption(page, '⏰ Grace period expired: Next privileged command will require fresh authentication', 5000);

    await showCaption(page, '📈 All events share session_id for full audit trail - SIEM, Splunk, ELK integration ready', 5000);
    await clearCaption(page);
  });

  test('Demo 6: Realm Security Settings', async ({ page }) => {
    test.setTimeout(120000);

    await page.goto(`${KEYCLOAK_URL}/admin/master/console/`);
    await page.waitForSelector('input[name="username"]');
    await showCaption(page, '⚙️ Keycloak Security Settings - Token lifetimes, sessions, and WebAuthn policies');

    await page.fill('input[name="username"]', 'admin');
    await page.fill('input[name="password"]', 'admin');
    await page.click('input[type="submit"], button[type="submit"]');

    await page.waitForURL('**/admin/master/console/**');
    await page.waitForTimeout(1000);

    await page.click('[data-testid="realmSelectorToggle"]');
    await page.click('text=unix-oidc-test');
    await showCaption(page, '🏢 Configuring unix-oidc-test realm - Security policies for SSH and sudo');

    // Authentication section - WebAuthn policies
    await page.getByRole('link', { name: 'Authentication' }).click();
    await page.waitForTimeout(1000);
    await showCaption(page, '🔐 Authentication Flows - Configure MFA requirements for step-up', 4000);

    // Try to navigate to Policies tab for WebAuthn settings
    const policiesTab = page.getByRole('tab', { name: 'Policies' });
    if (await policiesTab.isVisible()) {
      await policiesTab.click();
      await page.waitForTimeout(1000);
      await showCaption(page, '🔑 WebAuthn Policy - FIDO2 passkeys for phishing-resistant authentication', 5000);
      await showCaption(page, '⚙️ Configure: Signature algorithms (ES256), attestation, user verification', 5000);
    }

    // Realm settings
    await page.getByRole('link', { name: 'Realm settings' }).click();
    await page.waitForTimeout(1000);
    await showCaption(page, '🎛️ Realm Settings - Access token lifespan affects SSH session duration', 4000);

    const tokensTab = page.getByTestId('rs-tokens-tab');
    if (await tokensTab.isVisible()) {
      await tokensTab.click();
      await page.waitForTimeout(1000);
      await showCaption(page, '⏱️ Token Settings - Short access tokens (5min) + refresh for security', 5000);
    }

    const sessionsTab = page.getByTestId('rs-sessions-tab');
    if (await sessionsTab.isVisible()) {
      await sessionsTab.click();
      await page.waitForTimeout(1000);
      await showCaption(page, '🔄 Session Settings - SSO idle timeout determines re-auth frequency', 5000);
    }

    await showCaption(page, '✅ Keycloak provides enterprise-grade security controls for unix-oidc', 4000);
    await clearCaption(page);
  });
});
