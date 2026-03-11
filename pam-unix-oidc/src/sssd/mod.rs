//! SSSD user and group resolution via NSS.
//!
//! This module wraps the Unix name service switch (NSS) APIs used to resolve
//! SSSD-enrolled users and groups.  It is the primary bridge between the PAM
//! authentication path and the system identity database.

pub mod groups;
pub mod user;

pub use groups::{check_group_policy, is_group_member, resolve_nss_group_names, GroupPolicyError};
pub use user::{get_user_info, user_exists, UserError, UserInfo};
