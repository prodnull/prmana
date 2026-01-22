# Webhook Approval Server Demo

This is a demo webhook approval server that demonstrates how to integrate custom approval workflows with unix-oidc.

## Quick Start

```bash
# Start the webhook server
cargo run -p webhook-server

# In another terminal, configure unix-oidc to use the webhook
export UNIX_OIDC_WEBHOOK_URL=http://localhost:3000
```

## Web Interface

Open http://localhost:3000 in your browser to see the approval dashboard:

- View pending approval requests
- Approve or deny requests with one click
- See history of recent decisions

## API Endpoints

### Start Approval Request

`POST /approve`

Request body:
```json
{
  "request_id": "apr-abc123",
  "username": "alice",
  "command": "sudo systemctl restart nginx",
  "hostname": "server.example.com",
  "timestamp": 1705400000,
  "timeout_seconds": 300,
  "metadata": {}
}
```

Response:
```json
{
  "request_id": "apr-abc123",
  "status": "pending",
  "message": null,
  "approver": null,
  "decided_at": null
}
```

### Check Status

`GET /approve/{request_id}`

Response:
```json
{
  "request_id": "apr-abc123",
  "status": "approved",
  "message": null,
  "approver": "demo-admin",
  "decided_at": 1705400100
}
```

### Approve Request (Demo UI)

`POST /approve/{request_id}/approve`

### Deny Request (Demo UI)

`POST /approve/{request_id}/deny`

## Status Values

- `pending` - Waiting for decision
- `approved` - Request was approved
- `denied` - Request was denied
- `expired` - Request timed out

## Configuration

The server listens on port 3000 by default.

Configure unix-oidc to use the webhook:

```bash
# Required: Webhook URL
export UNIX_OIDC_WEBHOOK_URL=http://localhost:3000

# Optional: Authorization header
export UNIX_OIDC_WEBHOOK_AUTH="Bearer your-secret-token"

# Optional: Request timeout (default: 10s)
export UNIX_OIDC_WEBHOOK_TIMEOUT=30

# Optional: Disable TLS verification (testing only!)
export UNIX_OIDC_WEBHOOK_INSECURE=true
```

## Building a Production Server

This demo is intentionally simple. For production, consider:

1. **Authentication** - Add bearer token or mutual TLS authentication
2. **Persistence** - Store requests in a database
3. **Notifications** - Send push notifications, emails, or Slack messages
4. **Audit Logging** - Log all approval decisions
5. **Access Control** - Define who can approve which requests
6. **High Availability** - Deploy with redundancy
7. **TLS** - Always use HTTPS in production

## Example: Slack Integration

Here's pseudocode for adding Slack notifications:

```rust
async fn start_approval(request: ApprovalRequest) {
    // Store request
    store_request(&request).await;

    // Send Slack notification
    slack_client.send_message(
        channel: "#sudo-approvals",
        text: format!(
            "🔐 Approval requested\n\
             User: {}\n\
             Command: {}\n\
             <{}/approve/{}/approve|Approve> | <{}/approve/{}/deny|Deny>",
            request.username,
            request.command.unwrap_or("(no command)"),
            WEBHOOK_URL, request.request_id,
            WEBHOOK_URL, request.request_id
        )
    ).await;
}
```

## Example: Email Integration

```rust
async fn start_approval(request: ApprovalRequest) {
    store_request(&request).await;

    email_client.send(Email {
        to: "security-team@example.com",
        subject: format!("Sudo approval needed: {} on {}",
                        request.username, request.hostname),
        body: format!(
            "User {} is requesting sudo access on {}.\n\n\
             Command: {}\n\n\
             Approve: {}/approve/{}/approve\n\
             Deny: {}/approve/{}/deny",
            request.username,
            request.hostname,
            request.command.unwrap_or("(no command)"),
            WEBHOOK_URL, request.request_id,
            WEBHOOK_URL, request.request_id
        ),
    }).await;
}
```
