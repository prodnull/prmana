//! SPIFFE/SPIRE integration for JWT-SVID acquisition and DPoP signing.
//!
//! This module provides:
//! - Hand-written protobuf stubs for the SPIRE Workload API (JWT-SVID profile)
//! - `SpireSigner`: a `DPoPSigner` backend that fetches JWT-SVIDs from a local
//!   SPIRE agent and signs DPoP proofs with ephemeral P-256 keys (ADR-016)
//!
//! Requires `--features spire` at build time.

pub mod workload_api;
