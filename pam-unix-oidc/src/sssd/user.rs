//! User resolution via NSS (which queries SSSD).
//!
//! This module provides functions to look up user information from the system's
//! name service switch (NSS), which typically includes SSSD for LDAP-backed users.

use thiserror::Error;
use uzers::os::unix::UserExt;
use uzers::{get_user_by_name, User};

#[derive(Debug, Error)]
pub enum UserError {
    #[error("User not found: {0}")]
    NotFound(String),

    #[error("System error: {0}")]
    SystemError(String),

    #[error("Invalid username")]
    InvalidUsername,
}

/// Information about a resolved user.
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

impl UserInfo {
    fn from_user(user: &User, username: &str) -> Self {
        Self {
            username: username.to_string(),
            uid: user.uid(),
            gid: user.primary_group_id(),
            home: user.home_dir().to_string_lossy().into_owned(),
            shell: user.shell().to_string_lossy().into_owned(),
        }
    }
}

/// Check if a user exists in the system (via NSS/SSSD).
pub fn user_exists(username: &str) -> bool {
    get_user_by_name(username).is_some()
}

/// Get user information from NSS (which queries SSSD).
pub fn get_user_info(username: &str) -> Result<UserInfo, UserError> {
    if username.is_empty() || username.contains('\0') {
        return Err(UserError::InvalidUsername);
    }

    match get_user_by_name(username) {
        Some(user) => Ok(UserInfo::from_user(&user, username)),
        None => Err(UserError::NotFound(username.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_exists_returns_false_for_nonexistent() {
        // This user definitely doesn't exist
        assert!(!user_exists("nonexistent_user_12345"));
    }

    #[test]
    fn test_user_exists_returns_true_for_root() {
        // root always exists on Unix systems
        assert!(user_exists("root"));
    }

    #[test]
    fn test_get_user_info_for_root() {
        let info = get_user_info("root").unwrap();
        assert_eq!(info.uid, 0);
        assert_eq!(info.username, "root");
    }

    #[test]
    fn test_get_user_info_not_found() {
        let result = get_user_info("nonexistent_user_12345");
        assert!(matches!(result, Err(UserError::NotFound(_))));
    }

    #[test]
    fn test_get_user_info_invalid_username() {
        // Empty username is invalid
        let result = get_user_info("");
        assert!(matches!(result, Err(UserError::InvalidUsername)));

        // Username with null byte is invalid
        let result = get_user_info("test\0user");
        assert!(matches!(result, Err(UserError::InvalidUsername)));
    }
}
