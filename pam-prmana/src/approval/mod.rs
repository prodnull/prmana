//! Approval providers for step-up authentication.
//!
//! This module provides different mechanisms for approving sudo step-up requests:
//! - Device Flow (OAuth 2.0 Device Authorization Grant) - existing
//! - Webhook (HTTP callback to custom approval service) - new

pub mod provider;
pub mod webhook;

pub use provider::{ApprovalProvider, ApprovalRequest, ApprovalResponse, ApprovalStatus};
pub use webhook::WebhookApprovalProvider;
