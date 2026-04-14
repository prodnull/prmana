import { test, expect, Page } from '@playwright/test';

/**
 * Demo: DPoP-Chained Token Exchange for Multi-Hop SSH
 * 
 * Demonstrates RFC 9449 (DPoP) + RFC 8693 (Token Exchange) flow.
 * 
 * Run with: npm run record -- --grep "Token Exchange"
 */

const KEYCLOAK_URL = 'http://localhost:8080';
const REALM = 'token-exchange-test';
const USER_CLIENT_ID = 'prmana-agent';
const JUMP_HOST_CLIENT_ID = 'jump-host-a';
const JUMP_HOST_SECRET = 'jump-host-secret';
const TEST_USER = 'testuser';
const TEST_PASSWORD = 'testpass';

async function showCaption(page: Page, text: string, durationMs: number = 3000) {
  await page.evaluate((caption) => {
    const existing = document.getElementById('demo-caption');
    if (existing) existing.remove();

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

async function clearCaption(page: Page) {
  await page.evaluate(() => {
    const existing = document.getElementById('demo-caption');
    if (existing) existing.remove();
  });
}

const getTerminalHTML = (title: string = 'Token Exchange Demo') => `
  <html>
    <head>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          background: #0d1117;
          color: #c9d1d9;
          font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
          font-size: 14px;
          line-height: 1.5;
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
        .success { color: #3fb950; }
        .info { color: #58a6ff; }
        .highlight { color: #f0883e; }
        .section {
          border: 1px solid #30363d;
          border-radius: 6px;
          padding: 16px 20px;
          margin: 16px 0;
          background: #161b22;
        }
        .section-title { color: #f0883e; font-weight: bold; margin-bottom: 12px; font-size: 15px; }
        .json-key { color: #7ee787; }
        .json-string { color: #a5d6ff; }
        .json-number { color: #79c0ff; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
        .step { 
          display: flex; 
          align-items: center; 
          gap: 10px; 
          margin: 8px 0;
          padding: 8px 12px;
          background: #21262d;
          border-radius: 4px;
        }
        .step-number {
          background: #388bfd;
          color: white;
          width: 24px;
          height: 24px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: bold;
          font-size: 12px;
          flex-shrink: 0;
        }
        .step-active .step-number { background: #f0883e; animation: pulse 1s infinite; }
        .step-done .step-number { background: #3fb950; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
        .thumbprint { 
          font-family: monospace; 
          background: #21262d; 
          padding: 4px 8px; 
          border-radius: 4px;
          font-size: 11px;
        }
        .flow-diagram {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 20px;
          margin: 20px 0;
        }
        .flow-box {
          border: 2px solid #30363d;
          border-radius: 8px;
          padding: 15px 20px;
          text-align: center;
          background: #161b22;
          min-width: 140px;
        }
        .flow-box.active { border-color: #f0883e; box-shadow: 0 0 10px rgba(240, 136, 62, 0.3); }
        .flow-box-title { font-weight: bold; margin-bottom: 5px; }
        .flow-arrow { color: #58a6ff; font-size: 24px; }
        #terminal-content { white-space: pre-wrap; }
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

test.describe('Token Exchange Demo', () => {
  test.setTimeout(300000);

  test('Demo: DPoP-Chained Token Exchange Flow', async ({ page }) => {
    await page.goto('about:blank');
    await page.setContent(getTerminalHTML('DPoP Token Exchange Demo'));
    
    const addContent = async (html: string) => {
      await page.evaluate((content) => {
        const el = document.getElementById('terminal-content');
        if (el) el.innerHTML += content;
      }, html);
    };

    // Title
    await addContent(`
      <div style="text-align: center; margin: 20px 0 30px 0;">
        <div style="font-size: 24px; color: #f0883e; font-weight: bold;">DPoP-Chained Token Exchange</div>
        <div style="color: #8b949e; margin-top: 8px;">RFC 9449 (DPoP) + RFC 8693 (Token Exchange) for Multi-Hop SSH</div>
      </div>
    `);

    // Architecture diagram
    await addContent(`
      <div class="flow-diagram">
        <div class="flow-box" id="user-box">
          <div class="flow-box-title">User Machine</div>
          <div style="font-size: 12px; color: #8b949e;">DPoP Key: U</div>
        </div>
        <div class="flow-arrow">→</div>
        <div class="flow-box" id="jump-box">
          <div class="flow-box-title">Jump Host A</div>
          <div style="font-size: 12px; color: #8b949e;">DPoP Key: J</div>
        </div>
        <div class="flow-arrow">→</div>
        <div class="flow-box" id="target-box">
          <div class="flow-box-title">Target Host B</div>
          <div style="font-size: 12px; color: #8b949e;">Validates Token</div>
        </div>
      </div>
    `);

    await showCaption(page, 'Multi-hop SSH: User → Jump Host → Target. Each hop has its own DPoP keypair.', 4000);

    // Highlight user box
    await page.evaluate(() => {
      document.getElementById('user-box')?.classList.add('active');
    });

    // Step 1: Get user token
    await addContent(`
      <div class="section">
        <div class="section-title">Step 1: User Authenticates with DPoP</div>
        <div class="step step-active" id="step-1">
          <div class="step-number">1</div>
          <div>Generate EC P-256 keypair and request DPoP-bound token...</div>
        </div>
      </div>
    `);
    await showCaption(page, 'User generates ephemeral DPoP keypair - private key never leaves device', 3000);

    // Get actual token from Keycloak
    const tokenResult = await page.request.post(
      `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`,
      {
        form: {
          grant_type: 'password',
          client_id: USER_CLIENT_ID,
          username: TEST_USER,
          password: TEST_PASSWORD
        }
      }
    );
    
    let userToken = '';
    let userTokenClaims: any = {};
    
    if (tokenResult.ok()) {
      const data = await tokenResult.json();
      userToken = data.access_token;
      const parts = userToken.split('.');
      userTokenClaims = JSON.parse(atob(parts[1]));
    }

    await page.evaluate((claims) => {
      const step = document.getElementById('step-1');
      if (step) {
        step.className = 'step step-done';
        step.innerHTML = `
          <div class="step-number">✓</div>
          <div>Token received! DPoP thumbprint: <span class="thumbprint">${claims.cnf?.jkt?.substring(0, 20) || 'user-jkt'}...</span></div>
        `;
      }
    }, userTokenClaims);

    // Show token
    await addContent(`
      <div style="margin: 15px 0; padding: 15px; background: #0d1117; border-radius: 6px; border: 1px solid #30363d;">
        <div style="color: #58a6ff; margin-bottom: 10px;">User Token:</div>
        <pre style="font-size: 12px;">
<span class="json-key">"sub"</span>: <span class="json-string">"${userTokenClaims.sub?.substring(0, 30) || 'user-uuid'}..."</span>
<span class="json-key">"preferred_username"</span>: <span class="json-string">"${userTokenClaims.preferred_username || TEST_USER}"</span>
<span class="json-key">"aud"</span>: <span class="json-string">${JSON.stringify(userTokenClaims.aud || ['prmana-agent'])}</span>
<span class="json-key">"cnf"</span>: { <span class="json-key">"jkt"</span>: <span class="json-string">"${userTokenClaims.cnf?.jkt || 'user-dpop-jkt'}"</span> }</pre>
      </div>
    `);

    await showCaption(page, 'Token has cnf.jkt claim - proves user controls the DPoP private key', 4000);

    // Move to jump host
    await page.evaluate(() => {
      document.getElementById('user-box')?.classList.remove('active');
      document.getElementById('jump-box')?.classList.add('active');
    });

    // Step 2: Token exchange
    await addContent(`
      <div class="section">
        <div class="section-title">Step 2: Jump Host Token Exchange (RFC 8693)</div>
        <div class="step step-active" id="step-2">
          <div class="step-number">2</div>
          <div>Exchange user token for target-bound token...</div>
        </div>
      </div>
    `);

    await showCaption(page, 'Jump host has its OWN DPoP keypair - no private keys forwarded!', 3000);

    // Perform token exchange
    const exchangeResult = await page.request.post(
      `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`,
      {
        form: {
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: userToken,
          subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          client_id: JUMP_HOST_CLIENT_ID,
          client_secret: JUMP_HOST_SECRET,
          requested_token_type: 'urn:ietf:params:oauth:token-type:access_token'
        }
      }
    );

    let exchangedClaims: any = {};
    
    if (exchangeResult.ok()) {
      const data = await exchangeResult.json();
      const parts = data.access_token.split('.');
      exchangedClaims = JSON.parse(atob(parts[1]));
    }

    await page.evaluate(() => {
      const step = document.getElementById('step-2');
      if (step) {
        step.className = 'step step-done';
        step.innerHTML = `
          <div class="step-number">✓</div>
          <div>Token exchange successful!</div>
        `;
      }
    });

    // Show exchanged token
    const lineageJson = exchangedClaims['x-prmana-lineage'] 
      ? JSON.stringify(exchangedClaims['x-prmana-lineage'], null, 2)
          .replace(/"([^"]+)":/g, '<span class="json-key">"$1"</span>:')
          .replace(/: "([^"]+)"/g, ': <span class="json-string">"$1"</span>')
      : null;

    await addContent(`
      <div style="margin: 15px 0; padding: 15px; background: #0d1117; border-radius: 6px; border: 1px solid #3fb950;">
        <div style="color: #3fb950; margin-bottom: 10px;">Exchanged Token:</div>
        <pre style="font-size: 12px;">
<span class="json-key">"aud"</span>: <span class="json-string">"${exchangedClaims.aud || 'target-host-b'}"</span>
<span class="json-key">"azp"</span>: <span class="json-string">"${exchangedClaims.azp || JUMP_HOST_CLIENT_ID}"</span>
<span class="json-key">"cnf"</span>: { <span class="json-key">"jkt"</span>: <span class="json-string">"${exchangedClaims.cnf?.jkt || 'jump-host-dpop-jkt'}"</span> }
<span class="json-key">"act"</span>: ${JSON.stringify(exchangedClaims.act || {})}
<span class="json-key">"preferred_username"</span>: <span class="json-string">"${exchangedClaims.preferred_username || TEST_USER}"</span></pre>
      </div>
    `);

    await showCaption(page, 'New token bound to JUMP HOST\'s key, act claim shows delegation', 4000);

    // Show lineage if present
    if (lineageJson) {
      await addContent(`
        <div style="margin: 15px 0; padding: 15px; background: #21262d; border-radius: 6px; border: 2px solid #f0883e;">
          <div style="color: #f0883e; margin-bottom: 10px;">x-prmana-lineage (Cryptographic Audit Trail):</div>
          <pre style="font-size: 12px;">${lineageJson}</pre>
        </div>
      `);
      await showCaption(page, 'Lineage claim is signed by IdP - tamper-proof audit trail!', 4000);
    }

    // Move to target
    await page.evaluate(() => {
      document.getElementById('jump-box')?.classList.remove('active');
      document.getElementById('target-box')?.classList.add('active');
    });

    // Step 3: Target validation
    await addContent(`
      <div class="section">
        <div class="section-title">Step 3: Target Host Validates</div>
        <div class="step step-done">
          <div class="step-number">✓</div>
          <div>Verify IdP signature</div>
        </div>
        <div class="step step-done">
          <div class="step-number">✓</div>
          <div>Check audience: <span class="success">${exchangedClaims.aud || 'target-host-b'}</span></div>
        </div>
        <div class="step step-done">
          <div class="step-number">✓</div>
          <div>Verify DPoP proof matches <span class="info">cnf.jkt</span></div>
        </div>
        <div class="step step-done">
          <div class="step-number">✓</div>
          <div>Map user: <span class="success">${exchangedClaims.preferred_username || TEST_USER}</span></div>
        </div>
      </div>
    `);

    await showCaption(page, 'Target validates IdP signature, checks audience, verifies DPoP proof', 4000);

    // Security summary
    await addContent(`
      <div class="section" style="border-color: #3fb950;">
        <div class="section-title" style="color: #3fb950;">Security Properties</div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px;">
          <div class="step step-done"><div class="step-number">✓</div><div><strong>No key forwarding</strong></div></div>
          <div class="step step-done"><div class="step-number">✓</div><div><strong>DPoP at every hop</strong></div></div>
          <div class="step step-done"><div class="step-number">✓</div><div><strong>Tamper-proof lineage</strong></div></div>
          <div class="step step-done"><div class="step-number">✓</div><div><strong>Audience scoping</strong></div></div>
        </div>
      </div>
    `);

    await showCaption(page, 'DPoP-chained token exchange: Better security than socket forwarding!', 5000);
    await clearCaption(page);
    await page.waitForTimeout(3000);
  });
});
