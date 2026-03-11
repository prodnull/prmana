//! Security hardening modules.
//!
//! This module contains security controls beyond basic token validation:
//! - JTI tracking for token replay protection
//! - DPoP nonce cache for single-use nonce enforcement (RFC 9449 §8)
//! - Session ID generation with cryptographic randomness
//! - Rate limiting for brute force protection

pub mod jti_cache;
pub mod nonce_cache;
pub mod rate_limit;
pub mod session;

pub use jti_cache::JtiCache;
pub use nonce_cache::{generate_dpop_nonce, global_nonce_cache, DPoPNonceCache, NonceConsumeError};
pub use rate_limit::{RateLimitError, RateLimiter};
pub use session::generate_secure_session_id;
