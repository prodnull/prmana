// CIBA (Client-Initiated Backchannel Authentication) module.
//
// This module provides the protocol layer for CIBA backchannel authentication:
// - Types and error definitions (types.rs)
// - CibaClient for building request parameters (client.rs)
//
// HTTP execution lives in the agent daemon (Plan 03) to avoid async dependencies
// in the PAM crate.

pub mod client;
pub mod types;

pub use client::CibaClient;
pub use types::{
    satisfies_acr, validate_acr, BackchannelAuthResponse, CibaError, CibaTokenResponse, ACR_PHR,
    ACR_PHRH, CIBA_GRANT_TYPE,
};
