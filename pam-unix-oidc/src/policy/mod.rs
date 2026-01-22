//! Policy configuration for unix-oidc authentication.
//!
//! This module provides policy configuration for determining authentication
//! requirements based on host classification, action type, and command patterns.

pub mod config;
pub mod rules;

pub use config::{PolicyConfig, PolicyError};
pub use rules::{
    AuthAction, PolicyRules, SshLoginRequirements, StepUpMethod, SudoStepUpRequirements,
};
