//! Demo webhook approval server for unix-oidc.
//!
//! This server demonstrates how to implement a custom approval workflow
//! that integrates with unix-oidc's webhook approval provider.
//!
//! ## Usage
//!
//! ```bash
//! # Start the server
//! cargo run -p webhook-server
//!
//! # Configure unix-oidc to use this webhook
//! export UNIX_OIDC_WEBHOOK_URL=http://localhost:3000
//! ```
//!
//! ## API Endpoints
//!
//! - `POST /approve` - Start a new approval request
//! - `GET /approve/{id}` - Check status of a request
//! - `POST /approve/{id}/approve` - Approve a request (for demo UI)
//! - `POST /approve/{id}/deny` - Deny a request (for demo UI)
//! - `GET /` - Web UI showing pending requests

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tracing::{info, warn};

/// Status of an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Incoming approval request from unix-oidc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub username: String,
    pub command: Option<String>,
    pub hostname: String,
    pub timestamp: i64,
    pub timeout_seconds: u64,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Response to unix-oidc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    pub request_id: String,
    pub status: ApprovalStatus,
    pub message: Option<String>,
    pub approver: Option<String>,
    pub decided_at: Option<i64>,
}

/// Stored approval request with state.
#[derive(Debug, Clone)]
struct StoredRequest {
    request: ApprovalRequest,
    status: ApprovalStatus,
    message: Option<String>,
    approver: Option<String>,
    decided_at: Option<i64>,
    created_at: i64,
}

/// Application state.
#[derive(Default)]
struct AppState {
    requests: RwLock<HashMap<String, StoredRequest>>,
}

type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let state = Arc::new(AppState::default());

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/approve", post(start_approval))
        .route("/approve/{id}", get(check_status))
        .route("/approve/{id}/approve", post(approve_request))
        .route("/approve/{id}/deny", post(deny_request))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("Webhook demo server listening on http://0.0.0.0:3000");
    info!("Configure unix-oidc with: UNIX_OIDC_WEBHOOK_URL=http://localhost:3000");

    axum::serve(listener, app).await.unwrap();
}

/// Start a new approval request.
async fn start_approval(
    State(state): State<SharedState>,
    Json(request): Json<ApprovalRequest>,
) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp();

    info!(
        request_id = %request.request_id,
        username = %request.username,
        command = ?request.command,
        hostname = %request.hostname,
        "New approval request"
    );

    let stored = StoredRequest {
        request: request.clone(),
        status: ApprovalStatus::Pending,
        message: None,
        approver: None,
        decided_at: None,
        created_at: now,
    };

    {
        let mut requests = state.requests.write().unwrap();
        requests.insert(request.request_id.clone(), stored);
    }

    let response = ApprovalResponse {
        request_id: request.request_id,
        status: ApprovalStatus::Pending,
        message: None,
        approver: None,
        decided_at: None,
    };

    (StatusCode::OK, Json(response))
}

/// Check the status of an approval request.
async fn check_status(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let requests = state.requests.read().unwrap();

    match requests.get(&id) {
        Some(stored) => {
            // Check if request has expired
            let now = chrono::Utc::now().timestamp();
            let expires_at = stored.request.timestamp + stored.request.timeout_seconds as i64;

            let (status, message) = if stored.status == ApprovalStatus::Pending && now > expires_at
            {
                (
                    ApprovalStatus::Expired,
                    Some("Request timed out".to_string()),
                )
            } else {
                (stored.status.clone(), stored.message.clone())
            };

            let response = ApprovalResponse {
                request_id: id,
                status,
                message,
                approver: stored.approver.clone(),
                decided_at: stored.decided_at,
            };

            (StatusCode::OK, Json(response)).into_response()
        }
        None => {
            warn!(request_id = %id, "Request not found");
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "Request not found" })),
            )
                .into_response()
        }
    }
}

/// Approve a request (demo UI action).
async fn approve_request(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut requests = state.requests.write().unwrap();

    match requests.get_mut(&id) {
        Some(stored) => {
            if stored.status != ApprovalStatus::Pending {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "Request already decided" })),
                )
                    .into_response();
            }

            let now = chrono::Utc::now().timestamp();
            stored.status = ApprovalStatus::Approved;
            stored.approver = Some("demo-admin".to_string());
            stored.decided_at = Some(now);

            info!(request_id = %id, "Request approved");

            let response = ApprovalResponse {
                request_id: id,
                status: ApprovalStatus::Approved,
                message: None,
                approver: Some("demo-admin".to_string()),
                decided_at: Some(now),
            };

            (StatusCode::OK, Json(response)).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Request not found" })),
        )
            .into_response(),
    }
}

/// Deny a request (demo UI action).
async fn deny_request(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut requests = state.requests.write().unwrap();

    match requests.get_mut(&id) {
        Some(stored) => {
            if stored.status != ApprovalStatus::Pending {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "Request already decided" })),
                )
                    .into_response();
            }

            let now = chrono::Utc::now().timestamp();
            stored.status = ApprovalStatus::Denied;
            stored.message = Some("Denied by administrator".to_string());
            stored.decided_at = Some(now);

            info!(request_id = %id, "Request denied");

            let response = ApprovalResponse {
                request_id: id,
                status: ApprovalStatus::Denied,
                message: Some("Denied by administrator".to_string()),
                approver: None,
                decided_at: Some(now),
            };

            (StatusCode::OK, Json(response)).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Request not found" })),
        )
            .into_response(),
    }
}

/// Web UI showing pending requests.
async fn index_handler(State(state): State<SharedState>) -> Html<String> {
    let requests = state.requests.read().unwrap();
    let now = chrono::Utc::now().timestamp();

    let mut html = String::from(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>unix-oidc Webhook Approval Demo</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; }
        h1 { color: #333; }
        .request { border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin: 16px 0; background: #fafafa; }
        .request.pending { border-color: #f0ad4e; background: #fcf8e3; }
        .request.approved { border-color: #5cb85c; background: #dff0d8; }
        .request.denied { border-color: #d9534f; background: #f2dede; }
        .request.expired { border-color: #999; background: #eee; }
        .status { font-weight: bold; text-transform: uppercase; }
        .pending .status { color: #8a6d3b; }
        .approved .status { color: #3c763d; }
        .denied .status { color: #a94442; }
        .expired .status { color: #666; }
        .meta { color: #666; font-size: 0.9em; margin: 8px 0; }
        .command { font-family: monospace; background: #fff; padding: 8px; border-radius: 4px; margin: 8px 0; }
        .actions { margin-top: 12px; }
        button { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; margin-right: 8px; }
        .approve-btn { background: #5cb85c; color: white; }
        .approve-btn:hover { background: #449d44; }
        .deny-btn { background: #d9534f; color: white; }
        .deny-btn:hover { background: #c9302c; }
        .no-requests { color: #666; font-style: italic; padding: 40px; text-align: center; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .refresh { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 unix-oidc Webhook Approval Demo</h1>
        <span class="refresh">Auto-refreshes every 5s</span>
    </div>
"#,
    );

    let mut pending: Vec<_> = requests
        .iter()
        .filter(|(_, r)| r.status == ApprovalStatus::Pending)
        .collect();
    pending.sort_by(|a, b| b.1.created_at.cmp(&a.1.created_at));

    let mut others: Vec<_> = requests
        .iter()
        .filter(|(_, r)| r.status != ApprovalStatus::Pending)
        .collect();
    others.sort_by(|a, b| b.1.decided_at.cmp(&a.1.decided_at));

    if pending.is_empty() && others.is_empty() {
        html.push_str(r#"<div class="no-requests">No approval requests yet. Trigger a sudo step-up to see requests here.</div>"#);
    } else {
        if !pending.is_empty() {
            html.push_str("<h2>Pending Requests</h2>");
            for (id, stored) in &pending {
                let expires_at = stored.request.timestamp + stored.request.timeout_seconds as i64;
                let remaining = expires_at - now;
                let status_class = if remaining <= 0 { "expired" } else { "pending" };

                html.push_str(&format!(
                    r#"<div class="request {status_class}">
                        <div class="status">{}</div>
                        <div class="meta">
                            <strong>User:</strong> {} @ {} |
                            <strong>Request ID:</strong> {} |
                            <strong>Expires:</strong> {}s
                        </div>
                        <div class="command">{}</div>
                        {}
                    </div>"#,
                    if remaining <= 0 { "EXPIRED" } else { "PENDING" },
                    stored.request.username,
                    stored.request.hostname,
                    id,
                    if remaining > 0 {
                        format!("{}", remaining)
                    } else {
                        "expired".to_string()
                    },
                    stored.request.command.as_deref().unwrap_or("(no command)"),
                    if remaining > 0 {
                        format!(
                            r#"<div class="actions">
                                <button class="approve-btn" onclick="approve('{}')">✓ Approve</button>
                                <button class="deny-btn" onclick="deny('{}')">✗ Deny</button>
                            </div>"#,
                            id, id
                        )
                    } else {
                        String::new()
                    }
                ));
            }
        }

        if !others.is_empty() {
            html.push_str("<h2>Recent Decisions</h2>");
            for (id, stored) in others.iter().take(10) {
                let status_class = match stored.status {
                    ApprovalStatus::Approved => "approved",
                    ApprovalStatus::Denied => "denied",
                    ApprovalStatus::Expired => "expired",
                    _ => "pending",
                };
                let status_text = match stored.status {
                    ApprovalStatus::Approved => "APPROVED",
                    ApprovalStatus::Denied => "DENIED",
                    ApprovalStatus::Expired => "EXPIRED",
                    _ => "PENDING",
                };

                html.push_str(&format!(
                    r#"<div class="request {status_class}">
                        <div class="status">{status_text}</div>
                        <div class="meta">
                            <strong>User:</strong> {} @ {} |
                            <strong>Request ID:</strong> {}
                            {}
                        </div>
                        <div class="command">{}</div>
                    </div>"#,
                    stored.request.username,
                    stored.request.hostname,
                    id,
                    stored
                        .approver
                        .as_ref()
                        .map(|a| format!(" | <strong>Approver:</strong> {}", a))
                        .unwrap_or_default(),
                    stored.request.command.as_deref().unwrap_or("(no command)")
                ));
            }
        }
    }

    html.push_str(
        r#"
    <script>
        async function approve(id) {
            await fetch(`/approve/${id}/approve`, { method: 'POST' });
            location.reload();
        }
        async function deny(id) {
            await fetch(`/approve/${id}/deny`, { method: 'POST' });
            location.reload();
        }
    </script>
</body>
</html>"#,
    );

    Html(html)
}
