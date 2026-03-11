//! Identity mapping — username extraction and transform pipeline.
//!
//! This module bridges OIDC token claims and Unix usernames.  The key types
//! are:
//!
//! - [`UsernameMapper`] — extracts a claim and runs it through a transform pipeline
//! - [`UsernameTransform`] — a single pipeline step (StripDomain, Lowercase, Regex)
//! - [`IdentityError`] — errors from claim extraction or transform execution
//! - [`validate_collision_safety`] — static analysis for non-injective pipelines

pub mod collision;
pub mod mapper;

pub use collision::validate_collision_safety;
pub use mapper::{IdentityError, UsernameMapper, UsernameTransform};
