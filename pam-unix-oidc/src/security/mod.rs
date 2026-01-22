//! Security hardening modules.
//!
//! This module contains security controls beyond basic token validation:
//! - JTI tracking for token replay protection
//! - Session ID generation with cryptographic randomness
//! - Rate limiting for brute force protection

pub mod jti_cache;
pub mod rate_limit;
pub mod session;

pub use jti_cache::JtiCache;
pub use rate_limit::{RateLimitError, RateLimiter};
pub use session::generate_secure_session_id;
