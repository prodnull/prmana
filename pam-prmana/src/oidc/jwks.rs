//! Re-exported from prmana-core. The canonical implementation lives in
//! `prmana_core::oidc::jwks`; this shim preserves backward compatibility
//! for internal consumers that import `pam_prmana::oidc::jwks::*`.

pub use prmana_core::oidc::jwks::*;
