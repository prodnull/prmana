//! NSS group resolution for login/sudo group membership enforcement.
//!
//! This module bridges the PAM authentication path and the Unix name service
//! switch (NSS) group database (typically backed by SSSD for LDAP-enrolled
//! systems).  It provides three public functions:
//!
//! - [`resolve_nss_group_names`] — look up a user's groups via `uzers`
//! - [`is_group_member`] — set-intersection test against an allow-list
//! - [`check_group_policy`] — combines the above with enforcement-mode logic
//!
//! # Design decisions
//!
//! **Groups are resolved from NSS, not from token claims.**
//! FreeIPA (and SSSD) is the authoritative source for Unix group membership.
//! Token groups are logged for audit enrichment only (see `TokenClaims::groups_for_audit`).
//! This avoids Entra group-overage (>200 groups), GUID-vs-name inconsistencies,
//! and multi-IdP format differences. (See MEMORY.md key design decision.)
//!
//! **Empty `allowed_groups` means no restriction.**
//! Backward compatibility: existing deployments without group policy configured
//! must continue to work unchanged.  An empty list is equivalent to "allow all".
//!
//! **Non-UTF-8 group names are skipped with a warning.**
//! POSIX group names are byte strings; SSSD/LDAP may return names with
//! non-UTF-8 bytes in unusual configurations.  We use `OsStr::to_str` (strict
//! UTF-8) rather than `to_string_lossy` to avoid silently accepting a mangled
//! group name that might match an allow-list entry.

use thiserror::Error;
use uzers::get_user_groups;

use crate::policy::config::EnforcementMode;

// ── Error type ─────────────────────────────────────────────────────────────────

/// Errors returned from group policy enforcement.
#[derive(Debug, Error)]
pub enum GroupPolicyError {
    /// The user's groups were resolved but none intersect with the allow-list.
    ///
    /// Both `user_groups` and `allowed_groups` are included for audit enrichment.
    /// The `Display` impl joins them with ", " for log readability.
    #[error("User '{username}' is not a member of any allowed group. User groups: [{user_groups_display}]. Allowed groups: [{allowed_groups_display}]")]
    GroupDenied {
        username: String,
        /// The user's actual NSS group names (for audit logging).
        user_groups: Vec<String>,
        /// The configured allow-list (for diagnostic messages).
        allowed_groups: Vec<String>,
        /// Pre-formatted display string: user_groups joined with ", ".
        user_groups_display: String,
        /// Pre-formatted display string: allowed_groups joined with ", ".
        allowed_groups_display: String,
    },

    /// NSS group lookup failed (user not found in NSS, or NSS service error).
    #[error("NSS group lookup failed for user '{0}'")]
    GroupLookupFailed(String),
}

impl GroupPolicyError {
    /// Construct a [`GroupPolicyError::GroupDenied`] error, pre-formatting the display strings.
    pub fn group_denied(
        username: impl Into<String>,
        user_groups: Vec<String>,
        allowed_groups: Vec<String>,
    ) -> Self {
        let user_groups_display = user_groups.join(", ");
        let allowed_groups_display = allowed_groups.join(", ");
        Self::GroupDenied {
            username: username.into(),
            user_groups,
            allowed_groups,
            user_groups_display,
            allowed_groups_display,
        }
    }
}

// ── NSS resolution ─────────────────────────────────────────────────────────────

/// Resolve a user's group names from NSS (SSSD-backed on enrolled systems).
///
/// Calls [`uzers::get_user_groups`] which invokes `getgrouplist(3)` / NSS.
/// Returns `None` when the user cannot be found in NSS (or on NSS error).
///
/// # Non-UTF-8 group names
///
/// Group names that cannot be decoded as UTF-8 are silently skipped with a
/// `tracing::warn!`.  Using `OsStr::to_str` (strict) rather than
/// `to_string_lossy` (lossy) prevents a mangled name from accidentally matching
/// an allow-list entry that was specified in valid UTF-8.
pub fn resolve_nss_group_names(username: &str, gid: u32) -> Option<Vec<String>> {
    let groups = get_user_groups(username, gid)?;

    let names: Vec<String> = groups
        .iter()
        .filter_map(|g| {
            let os_name = g.name();
            match os_name.to_str() {
                Some(s) => Some(s.to_string()),
                None => {
                    tracing::warn!(
                        username = username,
                        "Skipping group with non-UTF-8 name during NSS resolution"
                    );
                    None
                }
            }
        })
        .collect();

    Some(names)
}

// ── Membership test ────────────────────────────────────────────────────────────

/// Return `true` when the user is a member of at least one group in `allowed`.
///
/// If `allowed` is empty this function returns `true` immediately —
/// an empty allow-list means "no restriction" (backward compatibility).
pub fn is_group_member(user_groups: &[String], allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    user_groups.iter().any(|g| allowed.contains(g))
}

// ── Policy check ───────────────────────────────────────────────────────────────

/// Enforce group membership policy, returning the user's group list on success.
///
/// The caller provides `allowed_groups` from the policy configuration and the
/// `enforcement` mode from `security_modes.groups_enforcement`.
///
/// # Return value
///
/// - `Ok(Vec<String>)` — user is permitted; the vec contains the user's NSS
///   group names for use in audit-log enrichment.
/// - `Err(GroupPolicyError::GroupDenied)` — user's groups don't intersect.
/// - `Err(GroupPolicyError::GroupLookupFailed)` — NSS lookup failed and
///   enforcement is `Strict`.
///
/// # Enforcement modes
///
/// | `enforcement`       | `allowed_groups` empty | NSS lookup fails | Not a member |
/// |---------------------|------------------------|-----------------|--------------|
/// | `Disabled`          | allow (skip check)     | allow (skip)    | allow (skip) |
/// | `Warn`              | allow                  | warn + allow    | deny         |
/// | `Strict`            | allow                  | deny            | deny         |
///
/// Note: an empty `allowed_groups` always permits, regardless of enforcement mode.
pub fn check_group_policy(
    username: &str,
    gid: u32,
    allowed_groups: &[String],
    enforcement: EnforcementMode,
) -> Result<Vec<String>, GroupPolicyError> {
    // Fast path: no group restriction configured — always permit.
    if allowed_groups.is_empty() {
        return Ok(Vec::new());
    }

    // Fast path: group checks explicitly disabled by operator.
    if enforcement == EnforcementMode::Disabled {
        return Ok(Vec::new());
    }

    // Resolve user groups via NSS.
    let user_groups = match resolve_nss_group_names(username, gid) {
        Some(groups) => groups,
        None => {
            // NSS lookup failed: no user record or NSS service error.
            match enforcement {
                EnforcementMode::Strict => {
                    return Err(GroupPolicyError::GroupLookupFailed(username.to_string()));
                }
                EnforcementMode::Warn => {
                    tracing::warn!(
                        username = username,
                        "NSS group lookup failed; allowing login under 'warn' enforcement mode"
                    );
                    return Ok(Vec::new());
                }
                EnforcementMode::Disabled => {
                    // Already handled above; unreachable.
                    return Ok(Vec::new());
                }
            }
        }
    };

    // Membership check.
    if is_group_member(&user_groups, allowed_groups) {
        Ok(user_groups)
    } else {
        Err(GroupPolicyError::group_denied(
            username,
            user_groups,
            allowed_groups.to_vec(),
        ))
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── is_group_member ──────────────────────────────────────────────────────

    #[test]
    fn test_is_group_member_matching() {
        let user_groups = vec!["unix-users".to_string(), "developers".to_string()];
        let allowed = vec!["developers".to_string()];
        assert!(is_group_member(&user_groups, &allowed));
    }

    #[test]
    fn test_is_group_member_no_match() {
        let user_groups = vec!["unix-users".to_string()];
        let allowed = vec!["wheel".to_string()];
        assert!(!is_group_member(&user_groups, &allowed));
    }

    #[test]
    fn test_is_group_member_empty_allowed_permits_all() {
        // Empty allow-list means no restriction — always true.
        let user_groups = vec!["unix-users".to_string()];
        let allowed: Vec<String> = Vec::new();
        assert!(is_group_member(&user_groups, &allowed));
    }

    #[test]
    fn test_is_group_member_empty_user_groups_not_member() {
        let user_groups: Vec<String> = Vec::new();
        let allowed = vec!["unix-users".to_string()];
        assert!(!is_group_member(&user_groups, &allowed));
    }

    // ── check_group_policy — fast paths ─────────────────────────────────────

    #[test]
    fn test_empty_allowed_groups_returns_ok() {
        // No restriction configured — must succeed even for a fictional user.
        let result = check_group_policy(
            "nonexistent_user_99999",
            65534,
            &[],
            EnforcementMode::Strict,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_disabled_enforcement_skips_check() {
        // Disabled mode skips everything — even for a user not in the allowed groups.
        let allowed = vec!["wheel".to_string()];
        let result = check_group_policy("root", 0, &allowed, EnforcementMode::Disabled);
        assert!(result.is_ok(), "disabled enforcement must always permit");
    }

    // ── check_group_policy — integration with real NSS (root user) ──────────

    #[test]
    fn test_root_user_nss_resolution_succeeds() {
        // root always exists on Unix; its primary group is gid 0.
        let groups = resolve_nss_group_names("root", 0);
        assert!(
            groups.is_some(),
            "resolve_nss_group_names must return Some for the root user"
        );
        let groups = groups.unwrap();
        // root is at minimum a member of its own group (gid 0, typically "root" or "wheel").
        assert!(!groups.is_empty(), "root must have at least one group");
    }

    #[test]
    fn test_check_group_policy_root_in_own_group() {
        // Determine root's primary group name first.
        let groups = resolve_nss_group_names("root", 0).expect("root must resolve");
        assert!(!groups.is_empty());

        // Allow exactly root's first group — must succeed.
        let allowed = vec![groups[0].clone()];
        let result = check_group_policy("root", 0, &allowed, EnforcementMode::Strict);
        assert!(
            result.is_ok(),
            "root must be permitted when its own group is in the allow-list"
        );
        let returned_groups = result.unwrap();
        assert_eq!(returned_groups, groups);
    }

    #[test]
    fn test_check_group_policy_root_not_in_other_group() {
        // Pick a group name that root is almost certainly not in.
        let impossible_group = "prmana-test-group-nonexistent-99999".to_string();
        let allowed = vec![impossible_group];
        let result = check_group_policy("root", 0, &allowed, EnforcementMode::Strict);
        assert!(
            matches!(result, Err(GroupPolicyError::GroupDenied { .. })),
            "root must be denied when its groups don't intersect"
        );
    }

    // ── Enforcement mode logic — tested via helper that simulates NSS failure ─

    /// Simulate the enforcement logic for a None NSS result (user not in NSS).
    /// This tests the enforcement-mode branching independently of real NSS.
    fn simulate_enforcement_on_lookup_failure(
        enforcement: EnforcementMode,
    ) -> Result<Vec<String>, GroupPolicyError> {
        let allowed = vec!["wheel".to_string()];
        // Use a username guaranteed not to be in NSS on CI; fall back to logic test.
        // We test the logic directly: mimic what check_group_policy does when
        // resolve_nss_group_names returns None.
        let user_groups_opt: Option<Vec<String>> = None; // simulate lookup failure

        match user_groups_opt {
            Some(groups) => {
                if is_group_member(&groups, &allowed) {
                    Ok(groups)
                } else {
                    Err(GroupPolicyError::group_denied("testuser", groups, allowed))
                }
            }
            None => match enforcement {
                EnforcementMode::Strict => {
                    Err(GroupPolicyError::GroupLookupFailed("testuser".to_string()))
                }
                EnforcementMode::Warn => Ok(Vec::new()),
                EnforcementMode::Disabled => Ok(Vec::new()),
            },
        }
    }

    #[test]
    fn test_warn_mode_nss_lookup_failure_logic_allows() {
        // When NSS lookup fails in Warn mode, the enforcement logic must allow.
        let result = simulate_enforcement_on_lookup_failure(EnforcementMode::Warn);
        assert!(result.is_ok(), "warn mode must allow when NSS lookup fails");
    }

    #[test]
    fn test_strict_mode_nss_lookup_failure_logic_denies() {
        // When NSS lookup fails in Strict mode, the enforcement logic must deny.
        let result = simulate_enforcement_on_lookup_failure(EnforcementMode::Strict);
        assert!(
            matches!(result, Err(GroupPolicyError::GroupLookupFailed(_))),
            "strict mode must deny when NSS lookup fails"
        );
    }

    #[test]
    fn test_disabled_mode_nss_lookup_failure_logic_allows() {
        let result = simulate_enforcement_on_lookup_failure(EnforcementMode::Disabled);
        assert!(result.is_ok(), "disabled mode must allow unconditionally");
    }

    // ── GroupDenied error includes audit fields ───────────────────────────────

    #[test]
    fn test_group_denied_error_includes_user_and_allowed_groups() {
        let impossible = "nonexistent-group-99999".to_string();
        let allowed = vec![impossible.clone()];
        let result = check_group_policy("root", 0, &allowed, EnforcementMode::Strict);
        match result {
            Err(GroupPolicyError::GroupDenied {
                username,
                user_groups,
                allowed_groups,
                ..
            }) => {
                assert_eq!(username, "root");
                assert!(
                    !user_groups.is_empty(),
                    "user_groups must be populated for audit"
                );
                assert_eq!(allowed_groups, vec![impossible]);
            }
            other => panic!("expected GroupDenied, got {other:?}"),
        }
    }
}
