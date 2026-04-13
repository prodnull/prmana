//! OAuth 2.0 Device Authorization Grant (RFC 8628) implementation.
//!
//! This module provides a client for the OAuth 2.0 Device Authorization Grant,
//! which allows users to authenticate on devices with limited input capabilities
//! by completing authentication on a secondary device (phone, browser).

pub mod client;
pub mod types;

pub use client::DeviceFlowClient;
pub use types::{DeviceAuthResponse, DeviceFlowError, TokenResponse};
