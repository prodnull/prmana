# Extensibility Guide

This guide covers extending and customizing unix-oidc for advanced use cases.

## Table of Contents

- [Plugin Architecture](#plugin-architecture)
- [Custom Claim Mapping](#custom-claim-mapping)
- [Webhook Integration](#webhook-integration)
- [Custom Step-Up Methods](#custom-step-up-methods)
- [API Reference](#api-reference)

---

## Plugin Architecture

unix-oidc is designed with extensibility in mind. Key extension points:

```
┌─────────────────────────────────────────────────────────────────┐
│                        PAM Module                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Token        │  │ Username     │  │ Policy       │          │
│  │ Validators   │  │ Mappers      │  │ Evaluators   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Step-Up      │  │ Audit        │  │ Cache        │          │
│  │ Methods      │  │ Backends     │  │ Providers    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

### Extension Points

| Extension Point | Purpose | Implementation |
|-----------------|---------|----------------|
| Token Validator | Custom token validation | Rust trait |
| Username Mapper | Custom claim → username | Config + Rust |
| Policy Evaluator | Custom authorization logic | Webhook or Rust |
| Step-Up Method | Custom re-auth flow | Webhook |
| Audit Backend | Custom log destination | Rust trait |
| Cache Provider | Custom token/JWKS cache | Rust trait |

---

## Custom Claim Mapping

### Standard Mappings

```yaml
# /etc/unix-oidc/policy.yaml
defaults:
  # Use email claim, strip domain
  username_claim: email
  username_transform: strip_domain

  # Or use a custom claim
  username_claim: unix_username

  # Or use subject with prefix removal
  username_claim: sub
  username_transform: remove_prefix
  username_prefix: "auth0|"
```

### Transform Functions

| Transform | Input | Output |
|-----------|-------|--------|
| `none` | `alice@corp.com` | `alice@corp.com` |
| `strip_domain` | `alice@corp.com` | `alice` |
| `lowercase` | `Alice` | `alice` |
| `remove_prefix` | `auth0\|abc123` | `abc123` |
| `regex` | (configurable) | (configurable) |

### Regex Transform

```yaml
username_transform: regex
username_regex:
  pattern: "^(.+)@example\\.com$"
  replacement: "$1"
```

### Custom Claim Mapper (Rust)

For complex mappings, implement the `UsernameMapper` trait:

```rust
use unix_oidc::auth::UsernameMapper;
use unix_oidc::claims::Claims;

pub struct CustomMapper;

impl UsernameMapper for CustomMapper {
    fn map_username(&self, claims: &Claims) -> Result<String, Error> {
        // Access any claim
        let email = claims.get("email")?;
        let dept = claims.get("department")?;

        // Custom logic
        let username = match dept.as_str() {
            "engineering" => format!("eng_{}", local_part(email)),
            "sales" => format!("sales_{}", local_part(email)),
            _ => local_part(email).to_string(),
        };

        Ok(username)
    }
}
```

---

## Webhook Integration

Webhooks enable external systems to participate in authentication decisions.

### Webhook Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  PAM Module  │────>│   Webhook    │────>│   External   │
│              │     │   (HTTPS)    │     │   System     │
└──────────────┘     └──────────────┘     └──────────────┘
                            │
                            v
                     ┌──────────────┐
                     │   Response   │
                     │  allow/deny  │
                     └──────────────┘
```

### Webhook Request Format

```http
POST /api/unix-oidc/authorize HTTP/1.1
Host: approvals.example.com
Content-Type: application/json
X-Unix-OIDC-Signature: sha256=...

{
  "event": "step_up_request",
  "timestamp": "2026-01-18T10:30:00Z",
  "request_id": "req-abc123",
  "user": {
    "username": "alice",
    "oidc_sub": "auth0|abc123",
    "oidc_email": "alice@example.com"
  },
  "host": {
    "hostname": "prod-web-01",
    "classification": "critical"
  },
  "command": {
    "path": "/usr/bin/systemctl",
    "args": ["restart", "nginx"],
    "cwd": "/home/alice"
  },
  "session": {
    "id": "sess-xyz789",
    "source_ip": "10.1.2.3",
    "acr": "mfa"
  }
}
```

### Webhook Response Format

```json
{
  "decision": "allow",
  "reason": "Approved by manager",
  "approved_by": "bob@example.com",
  "expires_at": "2026-01-18T11:30:00Z",
  "conditions": {
    "max_duration": 3600,
    "audit_level": "verbose"
  }
}
```

### Decision Values

| Decision | Effect |
|----------|--------|
| `allow` | Permit the action |
| `deny` | Reject with reason |
| `pending` | Wait for async approval |
| `challenge` | Request additional auth |

### Configuring Webhooks

```yaml
# /etc/unix-oidc/policy.yaml
webhooks:
  # Global webhook for all step-ups
  step_up:
    url: https://approvals.example.com/api/step-up
    timeout: 30
    retry: 3
    headers:
      Authorization: "Bearer ${WEBHOOK_TOKEN}"
    signature:
      enabled: true
      secret_env: WEBHOOK_SECRET

commands:
  /usr/bin/kubectl:
    webhook:
      url: https://k8s-approvals.example.com/api/authorize
      timeout: 60
      async: true  # Don't block, poll for result
```

### Webhook Security

1. **TLS Required**: All webhooks must use HTTPS
2. **Signature Verification**: HMAC-SHA256 signature in header
3. **Timeout Handling**: Configurable timeout with retry
4. **Secret Management**: Secrets via environment variables

### Signature Verification (Server Side)

```python
import hmac
import hashlib

def verify_signature(payload, signature, secret):
    expected = 'sha256=' + hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

---

## Custom Step-Up Methods

### Built-in Methods

| Method | Description |
|--------|-------------|
| `device_flow` | OAuth 2.0 Device Authorization Grant |
| `webhook` | External approval system |
| `totp` | Time-based OTP (break-glass) |

### Implementing Custom Step-Up

Create a webhook that implements the step-up flow:

```yaml
# /etc/unix-oidc/policy.yaml
step_up:
  methods:
    - name: slack_approval
      type: webhook
      config:
        url: https://internal.example.com/slack-approve
        timeout: 300  # 5 minutes to approve
        message_template: |
          User {{user}} is requesting sudo access on {{host}}
          Command: {{command}}

          React with :white_check_mark: to approve
```

### Step-Up Webhook Protocol

**Request:**
```json
{
  "action": "initiate",
  "request_id": "step-abc123",
  "user": "alice",
  "reason": "sudo systemctl restart nginx",
  "callback_url": "https://unix-oidc.example.com/callback"
}
```

**Async Polling:**
```json
{
  "action": "poll",
  "request_id": "step-abc123"
}
```

**Response:**
```json
{
  "status": "approved",  // or "pending", "denied", "expired"
  "approved_by": "bob",
  "approved_at": "2026-01-18T10:35:00Z"
}
```

---

## API Reference

### PAM Module Arguments

```
auth required pam_unix_oidc.so [options]

Options:
  debug           Enable debug logging
  use_first_pass  Use password from previous module
  try_first_pass  Try previous password, prompt if fails
  config=/path    Custom config file path
  cache_dir=/path Custom cache directory
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OIDC_ISSUER` | OIDC issuer URL | Required |
| `OIDC_CLIENT_ID` | OAuth client ID | Required |
| `OIDC_CLIENT_SECRET` | OAuth client secret | Optional |
| `UNIX_OIDC_CONFIG` | Config file path | `/etc/unix-oidc/policy.yaml` |
| `UNIX_OIDC_CACHE_DIR` | Cache directory | `/var/cache/unix-oidc` |
| `UNIX_OIDC_DEBUG` | Enable debug mode | `0` |
| `UNIX_OIDC_TIMEOUT` | HTTP timeout (seconds) | `30` |

### Rust API

```rust
use unix_oidc::{Config, Authenticator, Claims};

// Load configuration
let config = Config::from_file("/etc/unix-oidc/policy.yaml")?;

// Create authenticator
let auth = Authenticator::new(config)?;

// Validate token
let claims: Claims = auth.validate_token(token)?;

// Check authorization
let decision = auth.authorize(&claims, command, host)?;

// Perform step-up
let result = auth.step_up(&claims, StepUpReason::Sudo)?;
```

### Claims Access

```rust
// Standard OIDC claims
let sub: &str = claims.sub();
let iss: &str = claims.iss();
let aud: &[String] = claims.aud();
let exp: u64 = claims.exp();

// Custom claims
let acr: Option<&str> = claims.get("acr");
let groups: Option<Vec<String>> = claims.get_array("groups");

// DPoP confirmation
let cnf: Option<&Cnf> = claims.cnf();
let jkt: Option<&str> = cnf.and_then(|c| c.jkt.as_deref());
```

---

## Example: Slack Approval Webhook

Complete example of a Slack-based approval webhook:

```python
# webhook_server.py
from flask import Flask, request, jsonify
from slack_sdk import WebClient
import threading
import time

app = Flask(__name__)
slack = WebClient(token=os.environ["SLACK_TOKEN"])
pending_requests = {}

@app.route("/api/step-up", methods=["POST"])
def step_up():
    data = request.json
    request_id = data["request_id"]

    # Post to Slack
    response = slack.chat_postMessage(
        channel="#security-approvals",
        text=f"Step-up request from {data['user']['username']}",
        blocks=[
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Step-up Request*\n"
                           f"User: {data['user']['username']}\n"
                           f"Host: {data['host']['hostname']}\n"
                           f"Command: `{' '.join(data['command']['args'])}`"
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "style": "primary",
                        "action_id": f"approve_{request_id}"
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "style": "danger",
                        "action_id": f"deny_{request_id}"
                    }
                ]
            }
        ]
    )

    pending_requests[request_id] = {
        "status": "pending",
        "slack_ts": response["ts"]
    }

    return jsonify({"status": "pending", "poll_interval": 5})

@app.route("/api/step-up/poll", methods=["POST"])
def poll():
    request_id = request.json["request_id"]
    status = pending_requests.get(request_id, {"status": "expired"})
    return jsonify(status)

@app.route("/slack/actions", methods=["POST"])
def slack_actions():
    payload = json.loads(request.form["payload"])
    action = payload["actions"][0]["action_id"]

    if action.startswith("approve_"):
        request_id = action.replace("approve_", "")
        pending_requests[request_id] = {
            "status": "approved",
            "approved_by": payload["user"]["username"]
        }
    elif action.startswith("deny_"):
        request_id = action.replace("deny_", "")
        pending_requests[request_id] = {
            "status": "denied",
            "denied_by": payload["user"]["username"]
        }

    return "", 200
```

---

## Contributing Extensions

We welcome contributions! See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

When contributing extensions:

1. Follow the existing code style
2. Add comprehensive tests
3. Document the extension
4. Consider security implications
5. Provide example configurations
