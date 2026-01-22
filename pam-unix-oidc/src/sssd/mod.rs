//! SSSD user resolution via NSS.

pub mod user;

pub use user::{get_user_info, user_exists, UserError, UserInfo};
