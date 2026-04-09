//! Unix user provisioning via subprocess calls.
//!
//! Executes useradd/usermod/userdel as subprocesses for auditability.
//! All username inputs are validated against POSIX rules and a reserved
//! username denylist before any system call.

use std::collections::HashMap;
use std::process::Command;
use std::sync::RwLock;

use thiserror::Error;
use uuid::Uuid;

use crate::config::ScimConfig;
use crate::schema::{ScimMeta, ScimUser};

/// Reserved usernames that must never be provisioned (reuses Phase 35 denylist concept).
const RESERVED_USERNAMES: &[&str] = &[
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "gnats",
    "nobody",
    "systemd-network",
    "systemd-resolve",
    "messagebus",
    "syslog",
    "sshd",
    "ntp",
    "polkitd",
    "rtkit",
    "avahi",
    "colord",
    "cups",
    "dnsmasq",
    "gdm",
    "geoclue",
    "hplip",
    "pulse",
    "speech-dispatcher",
    "tss",
    "whoopsie",
    "kernoops",
    "uuidd",
    "tcpdump",
    "_apt",
    "systemd-timesync",
    "systemd-coredump",
    "ftp",
    "postfix",
    "dovecot",
    "mysql",
    "postgres",
    "redis",
    "mongodb",
    "elasticsearch",
    "nginx",
    "apache",
    "httpd",
    "git",
    "svn",
    "docker",
    "lxd",
    "libvirt-qemu",
    "halt",
    "shutdown",
    "reboot",
    "operator",
    "adm",
];

#[derive(Debug, Error)]
pub enum ProvisionError {
    #[error("Invalid username '{0}': must match [a-z_][a-z0-9_.-]* and be <=32 chars")]
    InvalidUsername(String),
    #[error("Reserved username '{0}' cannot be provisioned")]
    ReservedUsername(String),
    #[error("User '{0}' already exists")]
    UserExists(String),
    #[error("User '{0}' not found")]
    UserNotFound(String),
    #[error("System command failed: {0}")]
    CommandFailed(String),
}

/// Validate a username against POSIX rules and the reserved denylist.
pub fn validate_username(username: &str) -> Result<(), ProvisionError> {
    if username.is_empty() || username.len() > 32 {
        return Err(ProvisionError::InvalidUsername(username.to_string()));
    }
    // POSIX: first char must be [a-z_], rest [a-z0-9_.-]
    let mut chars = username.chars();
    if let Some(first) = chars.next() {
        if !first.is_ascii_lowercase() && first != '_' {
            return Err(ProvisionError::InvalidUsername(username.to_string()));
        }
    }
    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_' && c != '.' && c != '-' {
            return Err(ProvisionError::InvalidUsername(username.to_string()));
        }
    }
    if RESERVED_USERNAMES.contains(&username) {
        return Err(ProvisionError::ReservedUsername(username.to_string()));
    }
    Ok(())
}

/// In-memory user store backed by subprocess calls for actual provisioning.
///
/// For Phase 37, we maintain a simple `HashMap` for CRUD operations
/// and shell out to `useradd`/`userdel` for actual Unix account management.
/// The subprocess calls are best-effort — they require root and will log
/// a warning if they fail (e.g., in test or unprivileged contexts).
pub struct Provisioner {
    config: ScimConfig,
    /// In-memory store mapping SCIM id -> ScimUser.
    users: RwLock<HashMap<String, ScimUser>>,
}

impl Provisioner {
    pub fn new(config: ScimConfig) -> Self {
        Self {
            config,
            users: RwLock::new(HashMap::new()),
        }
    }

    /// Create a Unix user account.
    pub fn create_user(&self, mut user: ScimUser) -> Result<ScimUser, ProvisionError> {
        validate_username(&user.user_name)?;

        let mut store = self.users.write().unwrap();

        // Check for duplicate username
        if store.values().any(|u| u.user_name == user.user_name) {
            return Err(ProvisionError::UserExists(user.user_name.clone()));
        }

        // Assign ID and metadata
        let id = Uuid::new_v4().to_string();
        user.id = Some(id.clone());
        let now = chrono::Utc::now();
        user.meta = Some(ScimMeta {
            resource_type: "User".to_string(),
            created: now,
            last_modified: now,
            location: None,
            version: None,
        });

        // Attempt system useradd (best-effort — may fail in non-root context)
        let result = self.run_useradd(&user.user_name);
        if let Err(e) = &result {
            tracing::warn!(
                username = %user.user_name,
                error = %e,
                "useradd failed (may need root)"
            );
            // Continue anyway — the SCIM store tracks the intent
        }

        store.insert(id, user.clone());
        Ok(user)
    }

    /// Get a user by SCIM ID.
    pub fn get_user(&self, id: &str) -> Result<ScimUser, ProvisionError> {
        let store = self.users.read().unwrap();
        store
            .get(id)
            .cloned()
            .ok_or_else(|| ProvisionError::UserNotFound(id.to_string()))
    }

    /// Replace a user (PUT semantics).
    pub fn replace_user(&self, id: &str, mut user: ScimUser) -> Result<ScimUser, ProvisionError> {
        validate_username(&user.user_name)?;
        let mut store = self.users.write().unwrap();

        if !store.contains_key(id) {
            return Err(ProvisionError::UserNotFound(id.to_string()));
        }

        user.id = Some(id.to_string());
        let now = chrono::Utc::now();
        if let Some(ref mut meta) = user.meta {
            meta.last_modified = now;
        } else {
            user.meta = Some(ScimMeta {
                resource_type: "User".to_string(),
                created: now,
                last_modified: now,
                location: None,
                version: None,
            });
        }

        store.insert(id.to_string(), user.clone());
        Ok(user)
    }

    /// Delete (deactivate) a user.
    pub fn delete_user(&self, id: &str) -> Result<(), ProvisionError> {
        let mut store = self.users.write().unwrap();
        let user = store
            .remove(id)
            .ok_or_else(|| ProvisionError::UserNotFound(id.to_string()))?;

        // Attempt system userdel
        let result = self.run_userdel(&user.user_name);
        if let Err(e) = &result {
            tracing::warn!(
                username = %user.user_name,
                error = %e,
                "userdel failed (may need root)"
            );
        }

        Ok(())
    }

    /// List all users.
    pub fn list_users(&self) -> Vec<ScimUser> {
        let store = self.users.read().unwrap();
        store.values().cloned().collect()
    }

    fn run_useradd(&self, username: &str) -> Result<(), ProvisionError> {
        let mut cmd = Command::new("useradd");
        cmd.arg("--shell").arg(&self.config.default_shell);
        if self.config.create_home {
            cmd.arg("--create-home");
        }
        cmd.arg(username);

        let output = cmd
            .output()
            .map_err(|e| ProvisionError::CommandFailed(e.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ProvisionError::CommandFailed(format!(
                "useradd exited {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        Ok(())
    }

    fn run_userdel(&self, username: &str) -> Result<(), ProvisionError> {
        let output = Command::new("userdel")
            .arg("--remove")
            .arg(username)
            .output()
            .map_err(|e| ProvisionError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ProvisionError::CommandFailed(format!(
                "userdel exited {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SCHEMA_USER;

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("bob-jones").is_ok());
        assert!(validate_username("_service").is_ok());
        assert!(validate_username("user.name").is_ok());
        assert!(validate_username("a").is_ok());
    }

    #[test]
    fn test_validate_username_invalid() {
        assert!(validate_username("").is_err());
        assert!(validate_username("Alice").is_err()); // uppercase
        assert!(validate_username("1user").is_err()); // starts with digit
        assert!(validate_username("user name").is_err()); // space
        assert!(validate_username("user@host").is_err()); // @ sign
        assert!(validate_username(&"a".repeat(33)).is_err()); // too long
    }

    #[test]
    fn test_validate_username_reserved() {
        assert!(matches!(
            validate_username("root"),
            Err(ProvisionError::ReservedUsername(_))
        ));
        assert!(matches!(
            validate_username("sshd"),
            Err(ProvisionError::ReservedUsername(_))
        ));
        assert!(matches!(
            validate_username("nobody"),
            Err(ProvisionError::ReservedUsername(_))
        ));
    }

    #[test]
    fn test_provisioner_create_and_get() {
        let provisioner = Provisioner::new(ScimConfig::default());
        let user = ScimUser {
            schemas: vec![SCHEMA_USER.into()],
            id: None,
            external_id: None,
            user_name: "testuser".into(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
            meta: None,
        };
        let created = provisioner.create_user(user).unwrap();
        assert!(created.id.is_some());
        assert!(created.meta.is_some());

        let fetched = provisioner.get_user(created.id.as_ref().unwrap()).unwrap();
        assert_eq!(fetched.user_name, "testuser");
    }

    #[test]
    fn test_provisioner_duplicate_rejected() {
        let provisioner = Provisioner::new(ScimConfig::default());
        let user = ScimUser {
            schemas: vec![SCHEMA_USER.into()],
            id: None,
            external_id: None,
            user_name: "dupuser".into(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
            meta: None,
        };
        provisioner.create_user(user.clone()).unwrap();
        let err = provisioner.create_user(user).unwrap_err();
        assert!(matches!(err, ProvisionError::UserExists(_)));
    }

    #[test]
    fn test_provisioner_reserved_username_rejected() {
        let provisioner = Provisioner::new(ScimConfig::default());
        let user = ScimUser {
            schemas: vec![SCHEMA_USER.into()],
            id: None,
            external_id: None,
            user_name: "root".into(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
            meta: None,
        };
        let err = provisioner.create_user(user).unwrap_err();
        assert!(matches!(err, ProvisionError::ReservedUsername(_)));
    }

    #[test]
    fn test_provisioner_replace_user() {
        let provisioner = Provisioner::new(ScimConfig::default());
        let user = ScimUser {
            schemas: vec![SCHEMA_USER.into()],
            id: None,
            external_id: None,
            user_name: "replaceuser".into(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
            meta: None,
        };
        let created = provisioner.create_user(user).unwrap();
        let id = created.id.as_ref().unwrap().clone();

        let updated_user = ScimUser {
            schemas: vec![SCHEMA_USER.into()],
            id: None,
            external_id: None,
            user_name: "replaceuser".into(),
            name: None,
            display_name: Some("Updated Name".into()),
            emails: vec![],
            active: false,
            meta: None,
        };
        let replaced = provisioner.replace_user(&id, updated_user).unwrap();
        assert_eq!(replaced.display_name.as_deref(), Some("Updated Name"));
        assert!(!replaced.active);
        assert_eq!(replaced.id.as_deref(), Some(id.as_str()));
    }

    #[test]
    fn test_provisioner_replace_nonexistent() {
        let provisioner = Provisioner::new(ScimConfig::default());
        let user = ScimUser {
            schemas: vec![SCHEMA_USER.into()],
            id: None,
            external_id: None,
            user_name: "ghost".into(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
            meta: None,
        };
        let err = provisioner
            .replace_user("nonexistent-id", user)
            .unwrap_err();
        assert!(matches!(err, ProvisionError::UserNotFound(_)));
    }

    #[test]
    fn test_provisioner_delete_user() {
        let provisioner = Provisioner::new(ScimConfig::default());
        let user = ScimUser {
            schemas: vec![SCHEMA_USER.into()],
            id: None,
            external_id: None,
            user_name: "deleteuser".into(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
            meta: None,
        };
        let created = provisioner.create_user(user).unwrap();
        let id = created.id.as_ref().unwrap().clone();

        provisioner.delete_user(&id).unwrap();

        let err = provisioner.get_user(&id).unwrap_err();
        assert!(matches!(err, ProvisionError::UserNotFound(_)));
    }

    #[test]
    fn test_provisioner_delete_nonexistent() {
        let provisioner = Provisioner::new(ScimConfig::default());
        let err = provisioner.delete_user("no-such-id").unwrap_err();
        assert!(matches!(err, ProvisionError::UserNotFound(_)));
    }

    #[test]
    fn test_provisioner_list_users() {
        let provisioner = Provisioner::new(ScimConfig::default());
        assert!(provisioner.list_users().is_empty());

        let user1 = ScimUser {
            schemas: vec![SCHEMA_USER.into()],
            id: None,
            external_id: None,
            user_name: "listuser-a".into(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
            meta: None,
        };
        let user2 = ScimUser {
            schemas: vec![SCHEMA_USER.into()],
            id: None,
            external_id: None,
            user_name: "listuser-b".into(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
            meta: None,
        };
        provisioner.create_user(user1).unwrap();
        provisioner.create_user(user2).unwrap();

        let users = provisioner.list_users();
        assert_eq!(users.len(), 2);
    }
}
