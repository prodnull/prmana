//! unix-oidc-agent library
//!
//! This library provides the core functionality for the OIDC authentication agent.

pub mod config;
pub mod crypto;
pub mod daemon;
pub mod hardware;
pub mod metrics;
pub mod sanitize;
pub mod security;
pub mod storage;

#[cfg(feature = "spire")]
pub mod spire;
