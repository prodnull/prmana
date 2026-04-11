//! Unix user provisioning with persistent SCIM state.
//!
//! The provisioner keeps the SCIM `{userName} <-> id` mapping on disk so CRUD
//! operations survive service restarts. System account changes are delegated to
//! an account backend so the lifecycle can be tested without touching real users.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
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
    #[error("Changing userName is not supported for managed Unix accounts")]
    UsernameImmutable,
    #[error("System command failed: {0}")]
    CommandFailed(String),
    #[error("SCIM state store failed: {0}")]
    Store(String),
}

/// Validate a username against POSIX rules and the reserved denylist.
pub fn validate_username(username: &str) -> Result<(), ProvisionError> {
    if username.is_empty() || username.len() > 32 {
        return Err(ProvisionError::InvalidUsername(username.to_string()));
    }

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

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedUsers {
    users: HashMap<String, ScimUser>,
}

trait AccountBackend: Send + Sync {
    fn user_exists(&self, username: &str) -> bool;
    fn create_user(
        &self,
        username: &str,
        display_name: Option<&str>,
        default_shell: &str,
        create_home: bool,
    ) -> Result<(), ProvisionError>;
    fn update_user(
        &self,
        username: &str,
        display_name: Option<&str>,
        active: bool,
    ) -> Result<(), ProvisionError>;
    fn delete_user(&self, username: &str) -> Result<(), ProvisionError>;
}

#[derive(Debug, Default)]
struct SystemAccountBackend;

impl SystemAccountBackend {
    fn run_command(&self, command_name: &str, command: &mut Command) -> Result<(), ProvisionError> {
        let output = command
            .output()
            .map_err(|e| ProvisionError::CommandFailed(format!("{command_name}: {e}")))?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(ProvisionError::CommandFailed(format!(
            "{command_name} exited {}: {}",
            output.status,
            stderr.trim()
        )))
    }
}

impl AccountBackend for SystemAccountBackend {
    fn user_exists(&self, username: &str) -> bool {
        uzers::get_user_by_name(username).is_some()
    }

    fn create_user(
        &self,
        username: &str,
        display_name: Option<&str>,
        default_shell: &str,
        create_home: bool,
    ) -> Result<(), ProvisionError> {
        let mut command = Command::new("useradd");
        command.arg("--shell").arg(default_shell);
        if create_home {
            command.arg("--create-home");
        }
        if let Some(display_name) = display_name {
            command.arg("--comment").arg(display_name);
        }
        command.arg(username);
        self.run_command("useradd", &mut command)?;

        if self.user_exists(username) {
            return Ok(());
        }

        Err(ProvisionError::CommandFailed(format!(
            "useradd completed but NSS does not resolve '{username}'"
        )))
    }

    fn update_user(
        &self,
        username: &str,
        display_name: Option<&str>,
        active: bool,
    ) -> Result<(), ProvisionError> {
        if !self.user_exists(username) {
            return Err(ProvisionError::UserNotFound(username.to_string()));
        }

        let mut command = Command::new("usermod");
        command.arg("--comment").arg(display_name.unwrap_or(""));
        if active {
            command.arg("--unlock");
        } else {
            command.arg("--lock");
        }
        command.arg(username);
        self.run_command("usermod", &mut command)
    }

    fn delete_user(&self, username: &str) -> Result<(), ProvisionError> {
        if !self.user_exists(username) {
            return Ok(());
        }

        let mut command = Command::new("userdel");
        command.arg("--remove").arg(username);
        self.run_command("userdel", &mut command)
    }
}

/// Persistent SCIM user store backed by a Unix account backend.
pub struct Provisioner {
    config: ScimConfig,
    state_file: PathBuf,
    users: RwLock<HashMap<String, ScimUser>>,
    accounts: Arc<dyn AccountBackend>,
}

impl Provisioner {
    pub fn new(config: ScimConfig) -> Result<Self, ProvisionError> {
        Self::with_account_backend(config, Arc::new(SystemAccountBackend))
    }

    fn with_account_backend(
        config: ScimConfig,
        accounts: Arc<dyn AccountBackend>,
    ) -> Result<Self, ProvisionError> {
        let state_file = PathBuf::from(&config.state_file);
        let users = Self::load_state(&state_file)?;

        Ok(Self {
            config,
            state_file,
            users: RwLock::new(users),
            accounts,
        })
    }

    fn load_state(path: &Path) -> Result<HashMap<String, ScimUser>, ProvisionError> {
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let content = fs::read_to_string(path)
            .map_err(|e| ProvisionError::Store(format!("reading {}: {e}", path.display())))?;
        let mut persisted: PersistedUsers = serde_json::from_str(&content)
            .map_err(|e| ProvisionError::Store(format!("parsing {}: {e}", path.display())))?;

        for (id, user) in &mut persisted.users {
            match user.id.as_deref() {
                Some(existing) if existing == id => {}
                Some(existing) => {
                    return Err(ProvisionError::Store(format!(
                        "state id mismatch for key {id}: user contains {existing}"
                    )));
                }
                None => user.id = Some(id.clone()),
            }
        }

        Ok(persisted.users)
    }

    fn persist_state(&self, users: &HashMap<String, ScimUser>) -> Result<(), ProvisionError> {
        let parent = self.state_file.parent().ok_or_else(|| {
            ProvisionError::Store(format!(
                "state file {} has no parent directory",
                self.state_file.display()
            ))
        })?;

        fs::create_dir_all(parent)
            .map_err(|e| ProvisionError::Store(format!("creating {}: {e}", parent.display())))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|e| {
                ProvisionError::Store(format!("chmod 0700 {}: {e}", parent.display()))
            })?;
        }

        let tmp_name = format!(
            ".{}.tmp-{}",
            self.state_file
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("scim-users"),
            Uuid::new_v4()
        );
        let tmp_path = parent.join(tmp_name);
        let payload = serde_json::to_vec_pretty(&PersistedUsers {
            users: users.clone(),
        })
        .map_err(|e| ProvisionError::Store(format!("serializing state: {e}")))?;

        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }

        let mut file = options
            .open(&tmp_path)
            .map_err(|e| ProvisionError::Store(format!("creating {}: {e}", tmp_path.display())))?;

        file.write_all(&payload)
            .map_err(|e| ProvisionError::Store(format!("writing {}: {e}", tmp_path.display())))?;
        file.flush()
            .map_err(|e| ProvisionError::Store(format!("flushing {}: {e}", tmp_path.display())))?;

        fs::rename(&tmp_path, &self.state_file).map_err(|e| {
            ProvisionError::Store(format!(
                "renaming {} -> {}: {e}",
                tmp_path.display(),
                self.state_file.display()
            ))
        })?;

        Ok(())
    }

    fn current_user(
        store: &HashMap<String, ScimUser>,
        id: &str,
    ) -> Result<ScimUser, ProvisionError> {
        store
            .get(id)
            .cloned()
            .ok_or_else(|| ProvisionError::UserNotFound(id.to_string()))
    }

    fn system_account_exists(&self, username: &str) -> bool {
        self.accounts.user_exists(username)
    }

    fn account_visible(&self, username: &str) -> bool {
        self.config.dry_run || self.system_account_exists(username)
    }

    /// Create a Unix user account.
    pub fn create_user(&self, mut user: ScimUser) -> Result<ScimUser, ProvisionError> {
        validate_username(&user.user_name)?;

        let mut store = self.users.write().unwrap();
        if store
            .values()
            .any(|existing| existing.user_name == user.user_name)
            || (!self.config.dry_run && self.system_account_exists(&user.user_name))
        {
            return Err(ProvisionError::UserExists(user.user_name.clone()));
        }

        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        user.id = Some(id.clone());
        user.meta = Some(ScimMeta {
            resource_type: "User".to_string(),
            created: now,
            last_modified: now,
            location: None,
            version: None,
        });

        if !self.config.dry_run {
            self.accounts.create_user(
                &user.user_name,
                user.display_name.as_deref(),
                &self.config.default_shell,
                self.config.create_home,
            )?;
        }

        store.insert(id, user.clone());
        self.persist_state(&store)?;
        Ok(user)
    }

    /// Get a user by SCIM ID.
    pub fn get_user(&self, id: &str) -> Result<ScimUser, ProvisionError> {
        let store = self.users.read().unwrap();
        let user = Self::current_user(&store, id)?;
        if self.account_visible(&user.user_name) {
            Ok(user)
        } else {
            Err(ProvisionError::UserNotFound(id.to_string()))
        }
    }

    /// Replace a user (PUT semantics).
    pub fn replace_user(&self, id: &str, mut user: ScimUser) -> Result<ScimUser, ProvisionError> {
        validate_username(&user.user_name)?;

        let mut store = self.users.write().unwrap();
        let current = Self::current_user(&store, id)?;
        if current.user_name != user.user_name {
            return Err(ProvisionError::UsernameImmutable);
        }
        if !self.account_visible(&user.user_name) {
            return Err(ProvisionError::UserNotFound(id.to_string()));
        }

        if !self.config.dry_run {
            self.accounts.update_user(
                &user.user_name,
                user.display_name.as_deref(),
                user.active,
            )?;
        }

        let now = chrono::Utc::now();
        user.id = Some(id.to_string());
        user.meta = Some(ScimMeta {
            resource_type: "User".to_string(),
            created: current
                .meta
                .as_ref()
                .map(|meta| meta.created)
                .unwrap_or(now),
            last_modified: now,
            location: None,
            version: None,
        });

        store.insert(id.to_string(), user.clone());
        self.persist_state(&store)?;
        Ok(user)
    }

    /// Delete (deactivate/remove) a user.
    pub fn delete_user(&self, id: &str) -> Result<(), ProvisionError> {
        let mut store = self.users.write().unwrap();
        let user = Self::current_user(&store, id)?;

        if !self.config.dry_run {
            self.accounts.delete_user(&user.user_name)?;
        }

        store.remove(id);
        self.persist_state(&store)
    }

    /// List all users.
    pub fn list_users(&self) -> Vec<ScimUser> {
        let store = self.users.read().unwrap();
        store
            .values()
            .filter(|user| self.account_visible(&user.user_name))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::schema::SCHEMA_USER;

    #[derive(Debug, Clone)]
    struct FakeAccountState {
        display_name: Option<String>,
        active: bool,
    }

    #[derive(Debug, Default)]
    struct FakeAccountBackend {
        users: RwLock<HashMap<String, FakeAccountState>>,
        create_calls: Mutex<Vec<String>>,
        update_calls: Mutex<Vec<String>>,
        delete_calls: Mutex<Vec<String>>,
    }

    impl FakeAccountBackend {
        fn with_existing_user(username: &str) -> Arc<Self> {
            let backend = Arc::new(Self::default());
            backend.users.write().unwrap().insert(
                username.to_string(),
                FakeAccountState {
                    display_name: None,
                    active: true,
                },
            );
            backend
        }

        fn active_for(&self, username: &str) -> Option<bool> {
            self.users
                .read()
                .unwrap()
                .get(username)
                .map(|user| user.active)
        }

        fn display_name_for(&self, username: &str) -> Option<String> {
            self.users
                .read()
                .unwrap()
                .get(username)
                .and_then(|user| user.display_name.clone())
        }
    }

    impl AccountBackend for FakeAccountBackend {
        fn user_exists(&self, username: &str) -> bool {
            self.users.read().unwrap().contains_key(username)
        }

        fn create_user(
            &self,
            username: &str,
            display_name: Option<&str>,
            _default_shell: &str,
            _create_home: bool,
        ) -> Result<(), ProvisionError> {
            self.create_calls.lock().unwrap().push(username.to_string());
            self.users.write().unwrap().insert(
                username.to_string(),
                FakeAccountState {
                    display_name: display_name.map(str::to_string),
                    active: true,
                },
            );
            Ok(())
        }

        fn update_user(
            &self,
            username: &str,
            display_name: Option<&str>,
            active: bool,
        ) -> Result<(), ProvisionError> {
            self.update_calls.lock().unwrap().push(username.to_string());
            let mut users = self.users.write().unwrap();
            let entry = users
                .get_mut(username)
                .ok_or_else(|| ProvisionError::UserNotFound(username.to_string()))?;
            entry.display_name = display_name.map(str::to_string);
            entry.active = active;
            Ok(())
        }

        fn delete_user(&self, username: &str) -> Result<(), ProvisionError> {
            self.delete_calls.lock().unwrap().push(username.to_string());
            self.users.write().unwrap().remove(username);
            Ok(())
        }
    }

    fn test_user(username: &str) -> ScimUser {
        ScimUser {
            schemas: vec![SCHEMA_USER.into()],
            id: None,
            external_id: None,
            user_name: username.into(),
            name: None,
            display_name: None,
            emails: vec![],
            active: true,
            meta: None,
        }
    }

    fn test_config(state_file: &Path) -> ScimConfig {
        ScimConfig {
            dry_run: false,
            state_file: state_file.display().to_string(),
            ..ScimConfig::default()
        }
    }

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
        assert!(validate_username("Alice").is_err());
        assert!(validate_username("1user").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user@host").is_err());
        assert!(validate_username(&"a".repeat(33)).is_err());
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
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("scim-state.json");
        let backend = Arc::new(FakeAccountBackend::default());
        let provisioner =
            Provisioner::with_account_backend(test_config(&state_file), backend).unwrap();

        let created = provisioner.create_user(test_user("testuser")).unwrap();
        let fetched = provisioner.get_user(created.id.as_ref().unwrap()).unwrap();

        assert_eq!(fetched.user_name, "testuser");
    }

    #[test]
    fn test_provisioner_persists_across_restart() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("scim-state.json");
        let backend = Arc::new(FakeAccountBackend::default());
        let config = test_config(&state_file);

        let created = Provisioner::with_account_backend(config.clone(), backend.clone())
            .unwrap()
            .create_user(test_user("restartuser"))
            .unwrap();

        let restarted = Provisioner::with_account_backend(config, backend).unwrap();
        let fetched = restarted.get_user(created.id.as_ref().unwrap()).unwrap();

        assert_eq!(fetched.user_name, "restartuser");
    }

    #[test]
    fn test_provisioner_duplicate_rejected_for_existing_system_user() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("scim-state.json");
        let backend = FakeAccountBackend::with_existing_user("dupuser");
        let provisioner =
            Provisioner::with_account_backend(test_config(&state_file), backend).unwrap();

        let err = provisioner.create_user(test_user("dupuser")).unwrap_err();
        assert!(matches!(err, ProvisionError::UserExists(_)));
    }

    #[test]
    fn test_provisioner_reserved_username_rejected() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("scim-state.json");
        let backend = Arc::new(FakeAccountBackend::default());
        let provisioner =
            Provisioner::with_account_backend(test_config(&state_file), backend).unwrap();

        let err = provisioner.create_user(test_user("root")).unwrap_err();
        assert!(matches!(err, ProvisionError::ReservedUsername(_)));
    }

    #[test]
    fn test_provisioner_replace_user_updates_backend_and_state() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("scim-state.json");
        let backend = Arc::new(FakeAccountBackend::default());
        let config = test_config(&state_file);
        let provisioner =
            Provisioner::with_account_backend(config.clone(), backend.clone()).unwrap();

        let created = provisioner.create_user(test_user("replaceuser")).unwrap();
        let id = created.id.as_ref().unwrap().clone();

        let mut updated_user = test_user("replaceuser");
        updated_user.display_name = Some("Updated Name".into());
        updated_user.active = false;

        let replaced = provisioner.replace_user(&id, updated_user).unwrap();
        assert_eq!(replaced.display_name.as_deref(), Some("Updated Name"));
        assert!(!replaced.active);
        assert_eq!(
            backend.display_name_for("replaceuser").as_deref(),
            Some("Updated Name")
        );
        assert_eq!(backend.active_for("replaceuser"), Some(false));

        let restarted = Provisioner::with_account_backend(config, backend).unwrap();
        let fetched = restarted.get_user(&id).unwrap();
        assert_eq!(fetched.display_name.as_deref(), Some("Updated Name"));
        assert!(!fetched.active);
    }

    #[test]
    fn test_provisioner_replace_nonexistent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("scim-state.json");
        let backend = Arc::new(FakeAccountBackend::default());
        let provisioner =
            Provisioner::with_account_backend(test_config(&state_file), backend).unwrap();

        let err = provisioner
            .replace_user("nonexistent-id", test_user("ghost"))
            .unwrap_err();
        assert!(matches!(err, ProvisionError::UserNotFound(_)));
    }

    #[test]
    fn test_provisioner_delete_user_after_restart() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("scim-state.json");
        let backend = Arc::new(FakeAccountBackend::default());
        let config = test_config(&state_file);

        let created = Provisioner::with_account_backend(config.clone(), backend.clone())
            .unwrap()
            .create_user(test_user("deleteuser"))
            .unwrap();
        let id = created.id.as_ref().unwrap().clone();

        let restarted = Provisioner::with_account_backend(config, backend.clone()).unwrap();
        restarted.delete_user(&id).unwrap();

        assert!(!backend.user_exists("deleteuser"));
        let err = restarted.get_user(&id).unwrap_err();
        assert!(matches!(err, ProvisionError::UserNotFound(_)));
    }

    #[test]
    fn test_provisioner_delete_nonexistent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("scim-state.json");
        let backend = Arc::new(FakeAccountBackend::default());
        let provisioner =
            Provisioner::with_account_backend(test_config(&state_file), backend).unwrap();

        let err = provisioner.delete_user("no-such-id").unwrap_err();
        assert!(matches!(err, ProvisionError::UserNotFound(_)));
    }

    #[test]
    fn test_provisioner_list_users_filters_missing_accounts() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("scim-state.json");
        let backend = Arc::new(FakeAccountBackend::default());
        let provisioner =
            Provisioner::with_account_backend(test_config(&state_file), backend.clone()).unwrap();

        provisioner.create_user(test_user("listuser-a")).unwrap();
        provisioner.create_user(test_user("listuser-b")).unwrap();
        backend.delete_user("listuser-b").unwrap();

        let users = provisioner.list_users();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].user_name, "listuser-a");
    }

    #[test]
    fn test_dry_run_list_users_keeps_persisted_state() {
        let temp_dir = tempfile::tempdir().unwrap();
        let state_file = temp_dir.path().join("scim-state.json");
        let backend = Arc::new(FakeAccountBackend::default());
        let mut config = test_config(&state_file);
        config.dry_run = true;

        let provisioner = Provisioner::with_account_backend(config, backend).unwrap();
        provisioner.create_user(test_user("dryrun-user")).unwrap();

        let users = provisioner.list_users();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].user_name, "dryrun-user");
    }
}
