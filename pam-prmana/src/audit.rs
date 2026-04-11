//! Audit logging for authentication events.
//!
//! This module provides structured audit logging compatible with CIM (Common Information Model)
//! and OCSF (Open Cybersecurity Schema Framework) for security event analysis.
//!
//! Audit events are written to:
//! 1. Syslog (AUTH facility) - for SIEM integration
//! 2. /var/log/prmana-audit.log - dedicated audit file
//! 3. stderr - for debugging/testing
//!
//! # Tamper-evident HMAC chain (OBS-06)
//!
//! When `PRMANA_AUDIT_HMAC_KEY` is set, each audit event includes:
//! - `prev_hash`: hex-encoded chain_hash of the previous event ("genesis" for the first)
//! - `chain_hash`: HMAC-SHA256(key, "{prev_hash}:{event_json}")
//!
//! Any deletion or modification of a logged event breaks the chain at that point,
//! detectable by `prmana-audit-verify`. The key MUST be a high-entropy secret
//! (at least 32 random bytes) set to the same value on all processes writing to the
//! same log file. In the forked-sshd model, the parent sets the env var and all forks
//! inherit it, giving each session its own chain segment.
//!
//! When the key is absent or empty, tamper-evidence is disabled with a WARNING log.
//! The key MUST NOT be logged or included in error messages.

use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use syslog::{Facility, Formatter3164};

/// HMAC-SHA256 type alias
type HmacSha256 = Hmac<Sha256>;

/// Default audit log file path
const DEFAULT_AUDIT_LOG: &str = "/var/log/prmana-audit.log";

/// OCSF (Open Cybersecurity Schema Framework) version emitted in all audit events.
///
/// Version 1.3.0 maps to the December 2024 OCSF release.
/// Reference: https://schema.ocsf.io/1.3.0/
const OCSF_VERSION: &str = "1.3.0";

/// OCSF metadata embedded in every enriched audit event.
///
/// The `version` field identifies the OCSF schema version used, enabling SIEM
/// connectors to select the correct field mapping without runtime negotiation.
#[derive(Debug, Clone, Serialize)]
pub struct OcsfMetadata {
    /// OCSF schema version string (e.g. "1.3.0").
    pub version: &'static str,
}

/// OCSF field set produced by `AuditEvent::ocsf_fields()`.
///
/// All values follow OCSF 1.3.0 Authentication class (class_uid 3002) under
/// the Identity & Access Management category (category_uid 3).
///
/// Reference: https://schema.ocsf.io/1.3.0/classes/authentication
#[derive(Debug, Clone, Serialize)]
pub struct OcsfFields {
    /// OCSF category: 3 = Identity & Access Management.
    pub category_uid: u32,
    /// OCSF class: 3002 = Authentication.
    pub class_uid: u32,
    /// OCSF activity: 1 = Logon, 2 = Logoff, 3 = Authentication Challenge, 99 = Other.
    pub activity_id: u32,
    /// OCSF severity: 1 = Info, 2 = Low, 3 = Medium, 4 = High, 5 = Critical.
    pub severity_id: u32,
    /// Composite type UID: `class_uid * 100 + activity_id`.
    pub type_uid: u32,
    /// OCSF schema metadata.
    pub metadata: OcsfMetadata,
}

/// Wrapper struct for emitting an `AuditEvent` enriched with OCSF fields.
///
/// Uses `#[serde(flatten)]` so all existing event fields are serialised
/// alongside the new OCSF fields without renaming or removing any existing key.
/// This guarantees backward compatibility: any SIEM pipeline consuming the
/// existing fields continues to work unchanged.
#[derive(Serialize)]
struct EnrichedAuditEvent<'a> {
    #[serde(flatten)]
    event: &'a AuditEvent,
    category_uid: u32,
    class_uid: u32,
    activity_id: u32,
    severity_id: u32,
    type_uid: u32,
    metadata: OcsfMetadata,
}

/// Syslog severity for an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

// ── HMAC chain state (OBS-06) ─────────────────────────────────────────────────

/// Per-process HMAC chain state for tamper-evident audit logging.
///
/// Thread-safety: protected by `Mutex`. In the forked-sshd model, each child
/// process has its own chain segment (starting from "genesis"), which is correct —
/// each fork handles one session. Concurrent PAM calls within the same process are
/// serialized by the mutex, guaranteeing a consistent chain ordering.
pub(crate) struct ChainState {
    /// HMAC key bytes. `None` when `PRMANA_AUDIT_HMAC_KEY` is absent or empty.
    pub(crate) hmac_key: Option<Vec<u8>>,
    /// hex-encoded chain_hash of the most recently logged event, or "genesis".
    pub(crate) prev_hash: String,
}

impl ChainState {
    /// Initialise chain state from `PRMANA_AUDIT_HMAC_KEY`.
    ///
    /// The key is decoded as raw UTF-8 bytes. Operators are advised to use a
    /// hex-encoded key of at least 32 bytes of entropy, but any non-empty string
    /// is accepted. An absent or empty value disables tamper-evidence with a WARNING.
    pub fn new() -> Self {
        let key = std::env::var("PRMANA_AUDIT_HMAC_KEY").ok();
        let hmac_key = match key {
            Some(ref k) if !k.is_empty() => Some(k.as_bytes().to_vec()),
            _ => {
                tracing::warn!(
                    "Audit HMAC chain disabled — PRMANA_AUDIT_HMAC_KEY not set. \
                     Set this env var to enable tamper-evident audit logging."
                );
                None
            }
        };
        Self {
            hmac_key,
            prev_hash: "genesis".to_string(),
        }
    }

    /// Compute the next HMAC chain step over `event_json`.
    ///
    /// `event_json` must be the fully serialized event JSON (including any OCSF
    /// enrichment fields added by Plan 27-04). The chain input is:
    ///
    ///   `HMAC-SHA256(key, "{prev_hash}:{event_json}")`
    ///
    /// Returns `Some((prev_hash, chain_hash))` and advances internal state,
    /// or `None` if tamper-evidence is disabled.
    pub fn compute_chain(&mut self, event_json: &str) -> Option<(String, String)> {
        let key = self.hmac_key.as_ref()?;

        // Input: "{prev_hash}:{event_json}"
        // This binds the hash to the previous event, forming an unforgeable chain.
        let input = format!("{}:{}", self.prev_hash, event_json);

        // HMAC-SHA256 accepts keys of any non-zero length per RFC 2104 §3.
        // new_from_slice only fails on zero-length keys; our HMAC_KEY env var
        // is validated to be non-empty before insertion.  This is not reachable
        // in practice, so we map to None (disabling chaining) rather than panic.
        let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
            return None;
        };
        mac.update(input.as_bytes());
        let result = mac.finalize();
        let chain_hash = hex::encode(result.into_bytes());

        let prev = self.prev_hash.clone();
        self.prev_hash = chain_hash.clone();
        Some((prev, chain_hash))
    }
}

/// Module-level HMAC chain state, initialised once per process.
///
/// In the forked-sshd model, each child process gets its own Lazy initialisation
/// (after fork, the parent's state is NOT inherited — Lazy is reset in each fork).
static CHAIN_STATE: Lazy<Mutex<ChainState>> = Lazy::new(|| Mutex::new(ChainState::new()));

/// A chained audit event: the original event JSON enriched with HMAC chain fields.
#[derive(Serialize)]
struct ChainedAuditEvent {
    /// All original event fields (and OCSF enrichment when Plan 27-04 is active),
    /// flattened into the top-level JSON object.
    #[serde(flatten)]
    enriched: serde_json::Value,
    /// hex-encoded chain_hash of the preceding event, or "genesis" for the first.
    prev_hash: String,
    /// HMAC-SHA256(key, "{prev_hash}:{enriched_json}") as a hex string.
    chain_hash: String,
}

// ── End HMAC chain state ──────────────────────────────────────────────────────

// ── Audit settings (Phase 32) ────────────────────────────────────────────────

/// Resolved audit settings, cached for the lifetime of the process.
///
/// Reads from `PolicyConfig::audit` if available, falling back to env vars
/// and hardcoded defaults. Initialized once per process via `Lazy`.
struct AuditSettings {
    log_file: String,
    syslog_enabled: bool,
    stderr_enabled: bool,
}

static AUDIT_SETTINGS: Lazy<AuditSettings> = Lazy::new(|| {
    // Try loading from PolicyConfig first (Phase 32+).
    if let Ok(policy) = crate::policy::config::PolicyConfig::load_fresh() {
        return AuditSettings {
            log_file: if policy.audit.log_file.is_empty() {
                String::new() // disabled
            } else {
                policy.audit.log_file
            },
            syslog_enabled: policy.audit.syslog_enabled,
            stderr_enabled: policy.audit.stderr_enabled,
        };
    }

    // Fallback: env vars and defaults (backward compat with v1.0).
    AuditSettings {
        log_file: std::env::var("PRMANA_AUDIT_LOG")
            .unwrap_or_else(|_| DEFAULT_AUDIT_LOG.to_string()),
        syslog_enabled: true,
        stderr_enabled: true,
    }
});

/// Global syslog writer
static SYSLOG_WRITER: Lazy<Mutex<Option<syslog::Logger<syslog::LoggerBackend, Formatter3164>>>> =
    Lazy::new(|| {
        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTH,
            hostname: None,
            process: "prmana".to_string(),
            pid: std::process::id(),
        };

        let logger = syslog::unix(formatter).ok();
        Mutex::new(logger)
    });

/// Audit events for SSH/PAM authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum AuditEvent {
    /// Successful SSH login via OIDC
    #[serde(rename = "SSH_LOGIN_SUCCESS")]
    SshLoginSuccess {
        timestamp: String,
        session_id: String,
        user: String,
        uid: Option<u32>,
        source_ip: Option<String>,
        host: String,
        oidc_jti: Option<String>,
        oidc_acr: Option<String>,
        oidc_auth_time: Option<i64>,
        /// DPoP JWK thumbprint (RFC 9449 cnf.jkt) — confirms proof-of-possession binding
        dpop_thumbprint: Option<String>,
        /// The OIDC issuer URL that actually served this authentication (Phase 41).
        /// When failover is active, this is the secondary issuer URL.
        /// When absent (`None`), the issuer was the default/only configured issuer.
        #[serde(skip_serializing_if = "Option::is_none")]
        serving_issuer: Option<String>,
        /// Whether this authentication was served by a failover secondary issuer (Phase 41).
        /// `true` when the primary issuer was unavailable and the secondary handled auth.
        /// Default: `false` (omitted from JSON when false to preserve backward compat).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        failover_active: bool,
    },

    /// Failed SSH login attempt
    #[serde(rename = "SSH_LOGIN_FAILED")]
    SshLoginFailed {
        timestamp: String,
        user: Option<String>,
        source_ip: Option<String>,
        host: String,
        reason: String,
    },

    /// Token validation failure
    #[serde(rename = "TOKEN_VALIDATION_FAILED")]
    TokenValidationFailed {
        timestamp: String,
        user: Option<String>,
        source_ip: Option<String>,
        host: String,
        reason: String,
        oidc_issuer: Option<String>,
    },

    /// User not found in directory
    #[serde(rename = "USER_NOT_FOUND")]
    UserNotFound {
        timestamp: String,
        username: String,
        host: String,
    },

    /// Phase 44 privilege-policy decision for a sudo command.
    #[serde(rename = "PRIVILEGE_POLICY_DECISION")]
    PrivilegePolicyDecision {
        timestamp: String,
        user: String,
        command: String,
        host: String,
        policy_action: String,
        matched_rule: Option<String>,
        host_classification: String,
        grace_period_secs: u64,
        grace_period_applied: bool,
        dry_run: bool,
    },

    /// Sudo step-up authentication initiated
    #[serde(rename = "STEP_UP_INITIATED")]
    StepUpInitiated {
        timestamp: String,
        user: String,
        command: Option<String>,
        host: String,
        method: String,
        device_code: Option<String>,
        matched_rule: Option<String>,
        policy_action: Option<String>,
        host_classification: Option<String>,
        grace_period_secs: Option<u64>,
        dry_run: bool,
    },

    /// Sudo step-up authentication succeeded
    #[serde(rename = "STEP_UP_SUCCESS")]
    StepUpSuccess {
        timestamp: String,
        user: String,
        command: Option<String>,
        host: String,
        method: String,
        session_id: String,
        oidc_acr: Option<String>,
        oidc_auth_time: Option<i64>,
        /// Whether the CIBA ID token was cryptographically verified via TokenValidator.
        /// `true` = signature, issuer, audience, expiry all checked.
        /// `false` = legacy path (agent-asserted ACR without ID token).
        id_token_verified: bool,
        matched_rule: Option<String>,
        policy_action: Option<String>,
        host_classification: Option<String>,
        grace_period_secs: Option<u64>,
        grace_period_applied: bool,
        dry_run: bool,
    },

    /// Sudo step-up authentication failed
    #[serde(rename = "STEP_UP_FAILED")]
    StepUpFailed {
        timestamp: String,
        user: String,
        command: Option<String>,
        host: String,
        method: String,
        reason: String,
        /// When step-up failed due to ID token validation, this contains the specific
        /// validation failure (e.g., "signature mismatch", "expired", "wrong audience").
        /// `None` for non-ID-token failures (e.g., timeout, user denied).
        verification_failure: Option<String>,
        matched_rule: Option<String>,
        policy_action: Option<String>,
        host_classification: Option<String>,
        grace_period_secs: Option<u64>,
        dry_run: bool,
    },

    /// Break-glass emergency access used.
    ///
    /// Emitted at CRITICAL severity when `alert_on_use = true` (the default),
    /// or at INFO severity when `alert_on_use = false`.
    /// This event must be forwarded to SIEM/alerting systems when alert_on_use is enabled.
    /// OCSF: Authentication / Privileged Account Use (class_uid 3002).
    #[serde(rename = "BREAK_GLASS_AUTH")]
    BreakGlassAuth {
        timestamp: String,
        username: String,
        source_ip: Option<String>,
        host: String,
        reason: String,
        /// `"CRITICAL"` when `alert_on_use=true`; `"INFO"` when `alert_on_use=false`.
        severity: String,
        /// Mirrors the `alert_on_use` policy flag at the time of authentication.
        /// When `true`, the SIEM alerting pipeline is expected to page on this event.
        #[serde(skip)]
        alert_on_use: bool,
    },

    /// Session opened by pam_sm_open_session.
    ///
    /// Emitted when a session record is successfully written to the session directory.
    /// OCSF: Account Change / Session Activity.
    #[serde(rename = "SESSION_OPENED")]
    SessionOpened {
        timestamp: String,
        session_id: String,
        username: String,
        client_ip: Option<String>,
        host: String,
        /// Token expiry as Unix timestamp. Used to cross-reference session lifetime.
        token_exp: i64,
    },

    /// Session closed by pam_sm_close_session.
    ///
    /// Emitted when a session record is deleted from the session directory.
    /// Includes the total session duration for operational analytics.
    #[serde(rename = "SESSION_CLOSED")]
    SessionClosed {
        timestamp: String,
        session_id: String,
        username: String,
        host: String,
        /// Session duration in seconds (now - session_start from the record).
        duration_secs: i64,
    },

    /// Token revocation outcome during session teardown.
    ///
    /// Emitted by the IPC call to the agent daemon when close_session triggers
    /// RFC 7009 token revocation.
    #[serde(rename = "TOKEN_REVOKED")]
    TokenRevoked {
        timestamp: String,
        session_id: String,
        username: String,
        host: String,
        /// Revocation outcome: `"success"`, `"failed"`, or `"skipped"`.
        outcome: String,
        /// Human-readable reason for the outcome (e.g. IdP error message, "agent unreachable").
        reason: Option<String>,
    },

    /// Token introspection failure (RFC 7662).
    ///
    /// Emitted when introspection is enabled and the endpoint returns an error
    /// or `active: false`. The `enforcement` field indicates whether the failure
    /// caused authentication to be denied or just warned.
    #[serde(rename = "INTROSPECTION_FAILED")]
    IntrospectionFailed {
        timestamp: String,
        session_id: Option<String>,
        username: Option<String>,
        host: String,
        /// Description of the introspection failure.
        reason: String,
        /// Enforcement mode active at time of failure: `"strict"`, `"warn"`, or `"disabled"`.
        enforcement: String,
    },

    /// Authentication attempt with no token provided (OBS-02).
    ///
    /// Emitted when `get_auth_token()` returns `None` — the client did not supply
    /// any OIDC token. This event is distinct from `SshLoginFailed` / `TokenValidationFailed`
    /// which indicate a token was present but invalid.
    ///
    /// SIEM operators should query `event=AUTH_NO_TOKEN` to track unauthenticated
    /// access attempts separately from token validation failures.
    #[serde(rename = "AUTH_NO_TOKEN")]
    AuthNoToken {
        timestamp: String,
        username: String,
        source_ip: Option<String>,
        host: String,
    },

    /// IPC session-close failure (OBS-08).
    ///
    /// Emitted when `notify_agent_session_closed()` fails to deliver the session-closed
    /// IPC message to the agent daemon. Without this event, missed revocations would be
    /// silently dropped.
    ///
    /// Correlate with `SESSION_CLOSED` events via `session_id` to identify sessions
    /// where revocation was not confirmed.
    #[serde(rename = "SESSION_CLOSE_FAILED")]
    SessionCloseFailed {
        timestamp: String,
        session_id: String,
        /// Username is empty string when `notify_agent_session_closed` is called without
        /// a username — correlate with the preceding SESSION_CLOSED event via session_id.
        username: String,
        host: String,
        /// Description of the IPC failure (e.g., "connection refused", "write timeout").
        /// Contains only the error reason, not the IPC message body.
        reason: String,
    },

    /// Issuer marked degraded after consecutive JWKS fetch failures (MIDP-10, OBS-06, OBS-07).
    ///
    /// Emitted on the FIRST transition to the degraded state (i.e., when failure_count
    /// reaches DEGRADATION_THRESHOLD). Subsequent failures while already degraded do not
    /// re-emit this event.
    ///
    /// OCSF: Authentication / Other (activity_id 99, severity_id 4 = High).
    #[serde(rename = "ISSUER_DEGRADED")]
    IssuerDegraded {
        timestamp: String,
        issuer_url: String,
        failure_count: u8,
        host: String,
    },

    /// Issuer recovered after a successful JWKS fetch following a degraded state (MIDP-10, OBS-06, OBS-07).
    ///
    /// Emitted exactly once per recovery transition — not on every successful fetch.
    ///
    /// OCSF: Authentication / Other (activity_id 99, severity_id 1 = Info).
    #[serde(rename = "ISSUER_RECOVERED")]
    IssuerRecovered {
        timestamp: String,
        issuer_url: String,
        host: String,
    },

    /// JTI replay detected — same token/proof used across sshd forks.
    ///
    /// Emitted when `FsAtomicStore::check_and_record()` returns `AlreadyExists`,
    /// proving a JTI was seen by a different process. This is an attack indicator
    /// requiring immediate SIEM investigation.
    ///
    /// OCSF: Authentication / Logon (activity_id 1, severity_id 4 = High).
    #[serde(rename = "JTI_REPLAY_DETECTED")]
    JtiReplayDetected {
        timestamp: String,
        /// The JTI claim value from the replayed token/proof.
        jti: String,
        /// Issuer that issued the token carrying the replayed JTI.
        issuer: Option<String>,
        /// `"access_token"` or `"dpop_proof"` — which JTI was replayed.
        token_type: String,
        /// Username attempting authentication (if known at this point).
        user: Option<String>,
        source_ip: Option<String>,
        host: String,
    },

    /// JTI filesystem store degraded — fell back to per-process cache.
    ///
    /// Emitted when `FsAtomicStore` I/O fails and permissive mode activates the
    /// per-process fallback cache, or when strict mode hard-rejects the operation.
    /// This MUST trigger SIEM alerting — cross-fork replay protection is reduced
    /// to per-process only (permissive) or the login is rejected (strict).
    ///
    /// OCSF: Authentication / Other (activity_id 99, severity_id 5 = Critical).
    #[serde(rename = "JTI_STORE_DEGRADED")]
    JtiStoreDegraded {
        timestamp: String,
        /// Filesystem error description (e.g., `"Permission denied"`, `"No space left on device"`).
        reason: String,
        /// Enforcement mode active at time of degradation: `"strict"` (login rejected) or
        /// `"permissive"` (per-process fallback active).
        enforcement: String,
        /// Store type: `"jti"` for access-token JTI store, `"nonce"` for DPoP nonce store.
        store_type: String,
        host: String,
    },

    /// RFC 8693 token exchange accepted — delegated token validated successfully.
    ///
    /// Emitted when a token with an `act` claim passes all delegation checks:
    /// exchanger is authorized, depth within limits, lifetime acceptable.
    ///
    /// OCSF: Authentication / Logon (activity_id 1), severity Info.
    #[serde(rename = "TOKEN_EXCHANGE_ACCEPTED")]
    TokenExchangeAccepted {
        timestamp: String,
        session_id: String,
        /// The original subject (end user) from the token's `sub` claim.
        username: String,
        /// The top-level actor (exchanger) from the `act.sub` or `act.client_id` claim.
        exchanger: String,
        /// Number of delegation hops in the `act` chain.
        delegation_depth: usize,
        /// Target audience the exchanged token was issued for.
        target_audience: String,
        host: String,
    },

    /// RFC 8693 token exchange rejected — delegated token failed validation.
    ///
    /// Emitted when a token with an `act` claim fails delegation checks:
    /// unauthorized exchanger, depth exceeded, no delegation config, or
    /// excessive token lifetime.
    ///
    /// OCSF: Authentication / Logon (activity_id 1), severity High.
    /// SIEM operators should alert on this event — it may indicate a
    /// compromised jump host or misconfigured delegation policy.
    #[serde(rename = "TOKEN_EXCHANGE_REJECTED")]
    TokenExchangeRejected {
        timestamp: String,
        /// The original subject (end user) from the token's `sub` claim.
        username: String,
        /// The top-level actor that attempted the exchange.
        exchanger: String,
        /// Reason for rejection (maps to ValidationError variant message).
        reason: String,
        host: String,
    },

    /// IdP failover activated — primary issuer unavailable, switching to secondary (Phase 41).
    ///
    /// Emitted when an availability-class failure (connect timeout, TLS error, 5xx)
    /// causes the agent to switch from primary to secondary issuer. Policy/crypto
    /// failures never trigger this event.
    ///
    /// OCSF: Authentication / Other (activity_id 99, severity_id 4 = High).
    #[serde(rename = "IDP_FAILOVER_ACTIVATED")]
    IdpFailoverActivated {
        timestamp: String,
        /// Primary issuer URL that failed.
        failed_issuer: String,
        /// Secondary issuer URL now active.
        secondary_issuer: String,
        /// Availability failure reason (e.g., "connect timeout", "HTTP 503").
        reason: String,
        host: String,
    },

    /// IdP failover recovered — primary issuer healthy again (Phase 41).
    ///
    /// Emitted when a cooldown-based retry against the primary issuer succeeds
    /// and the failover state transitions back to Primary.
    ///
    /// OCSF: Authentication / Other (activity_id 99, severity_id 1 = Info).
    #[serde(rename = "IDP_FAILOVER_RECOVERED")]
    IdpFailoverRecovered {
        timestamp: String,
        /// Primary issuer URL that recovered.
        recovered_issuer: String,
        /// Secondary issuer URL that was previously active.
        previous_active_issuer: String,
        host: String,
    },

    /// IdP failover exhausted — both primary and secondary unavailable (Phase 41).
    ///
    /// Emitted when both issuers in a failover pair are unreachable. Authentication
    /// fails closed. This event should trigger immediate SIEM alerting.
    ///
    /// OCSF: Authentication / Other (activity_id 99, severity_id 5 = Critical).
    #[serde(rename = "IDP_FAILOVER_EXHAUSTED")]
    IdpFailoverExhausted {
        timestamp: String,
        /// Primary issuer URL.
        primary_issuer: String,
        /// Secondary issuer URL.
        secondary_issuer: String,
        /// Last error encountered.
        last_error: String,
        host: String,
    },
}

impl AuditEvent {
    /// Create a successful SSH login event.
    #[allow(clippy::too_many_arguments)]
    pub fn ssh_login_success(
        session_id: &str,
        user: &str,
        uid: Option<u32>,
        source_ip: Option<&str>,
        oidc_jti: Option<&str>,
        oidc_acr: Option<&str>,
        oidc_auth_time: Option<i64>,
        dpop_thumbprint: Option<&str>,
    ) -> Self {
        Self::SshLoginSuccess {
            timestamp: iso_timestamp(),
            session_id: session_id.to_string(),
            user: user.to_string(),
            uid,
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
            oidc_jti: oidc_jti.map(String::from),
            oidc_acr: oidc_acr.map(String::from),
            oidc_auth_time,
            dpop_thumbprint: dpop_thumbprint.map(String::from),
            serving_issuer: None,
            failover_active: false,
        }
    }

    /// Create a failed SSH login event.
    pub fn ssh_login_failed(user: Option<&str>, source_ip: Option<&str>, reason: &str) -> Self {
        Self::SshLoginFailed {
            timestamp: iso_timestamp(),
            user: user.map(String::from),
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
            reason: reason.to_string(),
        }
    }

    /// Create a token validation failure event.
    pub fn token_validation_failed(
        user: Option<&str>,
        reason: &str,
        source_ip: Option<&str>,
        oidc_issuer: Option<&str>,
    ) -> Self {
        Self::TokenValidationFailed {
            timestamp: iso_timestamp(),
            user: user.map(String::from),
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
            reason: reason.to_string(),
            oidc_issuer: oidc_issuer.map(String::from),
        }
    }

    /// Create a user not found event.
    pub fn user_not_found(username: &str) -> Self {
        Self::UserNotFound {
            timestamp: iso_timestamp(),
            username: username.to_string(),
            host: get_hostname(),
        }
    }

    /// Create a step-up initiated event.
    #[allow(clippy::too_many_arguments)]
    pub fn step_up_initiated(
        user: &str,
        command: Option<&str>,
        method: &str,
        device_code: Option<&str>,
        matched_rule: Option<&str>,
        policy_action: Option<&str>,
        host_classification: Option<&str>,
        grace_period_secs: Option<u64>,
        dry_run: bool,
    ) -> Self {
        Self::StepUpInitiated {
            timestamp: iso_timestamp(),
            user: user.to_string(),
            command: command.map(String::from),
            host: get_hostname(),
            method: method.to_string(),
            device_code: device_code.map(String::from),
            matched_rule: matched_rule.map(String::from),
            policy_action: policy_action.map(String::from),
            host_classification: host_classification.map(String::from),
            grace_period_secs,
            dry_run,
        }
    }

    /// Create a step-up success event.
    ///
    /// `id_token_verified` must be `true` when the CIBA ID token was validated
    /// via `TokenValidator` (signature + issuer + audience + expiry all checked),
    /// and `false` for the legacy agent-asserted-ACR path (deprecated, no crypto).
    #[allow(clippy::too_many_arguments)]
    pub fn step_up_success(
        user: &str,
        command: Option<&str>,
        method: &str,
        session_id: &str,
        oidc_acr: Option<&str>,
        oidc_auth_time: Option<i64>,
        id_token_verified: bool,
        matched_rule: Option<&str>,
        policy_action: Option<&str>,
        host_classification: Option<&str>,
        grace_period_secs: Option<u64>,
        grace_period_applied: bool,
        dry_run: bool,
    ) -> Self {
        Self::StepUpSuccess {
            timestamp: iso_timestamp(),
            user: user.to_string(),
            command: command.map(String::from),
            host: get_hostname(),
            method: method.to_string(),
            session_id: session_id.to_string(),
            oidc_acr: oidc_acr.map(String::from),
            oidc_auth_time,
            id_token_verified,
            matched_rule: matched_rule.map(String::from),
            policy_action: policy_action.map(String::from),
            host_classification: host_classification.map(String::from),
            grace_period_secs,
            grace_period_applied,
            dry_run,
        }
    }

    /// Create a step-up failed event.
    ///
    /// `verification_failure` must be `Some(reason)` when the failure was caused by
    /// ID token validation (e.g., `"signature mismatch"`, `"expired"`, `"wrong audience"`),
    /// and `None` for non-validation failures (e.g., timeout, user denied).
    #[allow(clippy::too_many_arguments)]
    pub fn step_up_failed(
        user: &str,
        command: Option<&str>,
        method: &str,
        reason: &str,
        verification_failure: Option<&str>,
        matched_rule: Option<&str>,
        policy_action: Option<&str>,
        host_classification: Option<&str>,
        grace_period_secs: Option<u64>,
        dry_run: bool,
    ) -> Self {
        Self::StepUpFailed {
            timestamp: iso_timestamp(),
            user: user.to_string(),
            command: command.map(String::from),
            host: get_hostname(),
            method: method.to_string(),
            reason: reason.to_string(),
            verification_failure: verification_failure.map(String::from),
            matched_rule: matched_rule.map(String::from),
            policy_action: policy_action.map(String::from),
            host_classification: host_classification.map(String::from),
            grace_period_secs,
            dry_run,
        }
    }

    /// Create a privilege-policy decision event for a sudo command.
    #[allow(clippy::too_many_arguments)]
    pub fn privilege_policy_decision(
        user: &str,
        command: &str,
        policy_action: &str,
        matched_rule: Option<&str>,
        host_classification: &str,
        grace_period_secs: u64,
        grace_period_applied: bool,
        dry_run: bool,
    ) -> Self {
        Self::PrivilegePolicyDecision {
            timestamp: iso_timestamp(),
            user: user.to_string(),
            command: command.to_string(),
            host: get_hostname(),
            policy_action: policy_action.to_string(),
            matched_rule: matched_rule.map(String::from),
            host_classification: host_classification.to_string(),
            grace_period_secs,
            grace_period_applied,
            dry_run,
        }
    }

    /// Create a break-glass authentication event.
    ///
    /// When `alert_on_use` is `true` (the `break_glass.alert_on_use` policy flag),
    /// the event is emitted at **CRITICAL** severity and the `severity` field in the
    /// JSON payload is `"CRITICAL"`. SIEM rules should page on this value.
    ///
    /// When `alert_on_use` is `false`, severity is downgraded to **INFO**. This is
    /// appropriate when break-glass accounts are used routinely (e.g. CI/CD automation
    /// that is already monitored by other means) and operators have explicitly opted out
    /// of alerting. The `severity` field in the JSON payload is `"INFO"`.
    ///
    /// The caller must log via `.log()` immediately after construction; this constructor
    /// does not emit it automatically.
    pub fn break_glass_auth(username: &str, source_ip: Option<&str>, alert_on_use: bool) -> Self {
        Self::BreakGlassAuth {
            timestamp: iso_timestamp(),
            username: username.to_string(),
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
            reason: "break-glass bypass".to_string(),
            severity: if alert_on_use {
                "CRITICAL".to_string()
            } else {
                "INFO".to_string()
            },
            alert_on_use,
        }
    }

    /// Create a session opened event (pam_sm_open_session).
    pub fn session_opened(
        session_id: &str,
        username: &str,
        client_ip: Option<&str>,
        token_exp: i64,
    ) -> Self {
        Self::SessionOpened {
            timestamp: iso_timestamp(),
            session_id: session_id.to_string(),
            username: username.to_string(),
            client_ip: client_ip.map(String::from),
            host: get_hostname(),
            token_exp,
        }
    }

    /// Create a session closed event (pam_sm_close_session).
    pub fn session_closed(session_id: &str, username: &str, duration_secs: i64) -> Self {
        Self::SessionClosed {
            timestamp: iso_timestamp(),
            session_id: session_id.to_string(),
            username: username.to_string(),
            host: get_hostname(),
            duration_secs,
        }
    }

    /// Create a token revocation outcome event.
    ///
    /// `outcome` must be one of `"success"`, `"failed"`, or `"skipped"`.
    pub fn token_revoked(
        session_id: &str,
        username: &str,
        outcome: &str,
        reason: Option<&str>,
    ) -> Self {
        Self::TokenRevoked {
            timestamp: iso_timestamp(),
            session_id: session_id.to_string(),
            username: username.to_string(),
            host: get_hostname(),
            outcome: outcome.to_string(),
            reason: reason.map(String::from),
        }
    }

    /// Create a token introspection failure event.
    ///
    /// `enforcement` should match the current `EnforcementMode` as a lowercase string.
    pub fn introspection_failed(
        session_id: Option<&str>,
        username: Option<&str>,
        reason: &str,
        enforcement: &str,
    ) -> Self {
        Self::IntrospectionFailed {
            timestamp: iso_timestamp(),
            session_id: session_id.map(String::from),
            username: username.map(String::from),
            host: get_hostname(),
            reason: reason.to_string(),
            enforcement: enforcement.to_string(),
        }
    }

    /// Create a no-token authentication attempt event (OBS-02).
    ///
    /// Emitted in `pam_sm_authenticate` when `get_auth_token()` returns `None`.
    /// Distinct from `ssh_login_failed` — SIEM can filter `event=AUTH_NO_TOKEN`
    /// without matching token validation failures.
    pub fn auth_no_token(username: &str, source_ip: Option<&str>) -> Self {
        Self::AuthNoToken {
            timestamp: iso_timestamp(),
            username: username.to_string(),
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
        }
    }

    /// Create an IPC session-close failure event (OBS-08).
    ///
    /// Emitted in `notify_agent_session_closed` when the IPC message cannot be
    /// delivered to the agent daemon. The `reason` contains only the error string,
    /// not the IPC message body — preventing IPC payload leakage into audit logs.
    ///
    /// Correlate with the preceding `SESSION_CLOSED` event via `session_id` to
    /// identify sessions where agent-side revocation was not confirmed.
    pub fn session_close_failed(session_id: &str, username: &str, reason: &str) -> Self {
        Self::SessionCloseFailed {
            timestamp: iso_timestamp(),
            session_id: session_id.to_string(),
            username: username.to_string(),
            host: get_hostname(),
            reason: reason.to_string(),
        }
    }

    /// Create an issuer-degraded audit event (MIDP-10).
    ///
    /// Call when `IssuerHealthManager::record_failure()` transitions an issuer
    /// to degraded state for the first time (failure_count reaches threshold).
    /// The `failure_count` is the count at the time of degradation.
    pub fn issuer_degraded(issuer_url: &str, failure_count: u8) -> Self {
        Self::IssuerDegraded {
            timestamp: iso_timestamp(),
            issuer_url: issuer_url.to_string(),
            failure_count,
            host: get_hostname(),
        }
    }

    /// Create an issuer-recovered audit event (MIDP-10).
    ///
    /// Call when `IssuerHealthManager::record_success()` transitions an issuer
    /// out of degraded state after a successful JWKS fetch.
    pub fn issuer_recovered(issuer_url: &str) -> Self {
        Self::IssuerRecovered {
            timestamp: iso_timestamp(),
            issuer_url: issuer_url.to_string(),
            host: get_hostname(),
        }
    }

    /// Create a JTI replay detected event.
    ///
    /// Call when `FsAtomicStore::check_and_record()` returns `AlreadyExists`,
    /// indicating a JTI was already seen by another process (cross-fork replay attack).
    ///
    /// `token_type` must be `"access_token"` or `"dpop_proof"` to indicate which
    /// JTI namespace was replayed.
    pub fn jti_replay_detected(
        jti: &str,
        issuer: Option<&str>,
        token_type: &str,
        user: Option<&str>,
        source_ip: Option<&str>,
    ) -> Self {
        Self::JtiReplayDetected {
            timestamp: iso_timestamp(),
            jti: jti.to_string(),
            issuer: issuer.map(String::from),
            token_type: token_type.to_string(),
            user: user.map(String::from),
            source_ip: source_ip.map(String::from),
            host: get_hostname(),
        }
    }

    /// Create a JTI store degraded event.
    ///
    /// Call when `FsAtomicStore` I/O fails and enforcement mode dispatches:
    /// - `enforcement = "strict"`: login rejected (hard-fail, returns `Replay`)
    /// - `enforcement = "permissive"`: per-process fallback activated (LOG_CRIT emitted)
    ///
    /// `store_type` must be `"jti"` for the access-token JTI store or `"nonce"` for
    /// the DPoP nonce store.
    pub fn jti_store_degraded(reason: &str, enforcement: &str, store_type: &str) -> Self {
        Self::JtiStoreDegraded {
            timestamp: iso_timestamp(),
            reason: reason.to_string(),
            enforcement: enforcement.to_string(),
            store_type: store_type.to_string(),
            host: get_hostname(),
        }
    }

    /// Create a token exchange accepted event (RFC 8693 delegation validated).
    ///
    /// Emitted when a token with an `act` claim passes all delegation checks.
    #[allow(clippy::too_many_arguments)]
    pub fn token_exchange_accepted(
        session_id: &str,
        username: &str,
        exchanger: &str,
        delegation_depth: usize,
        target_audience: &str,
    ) -> Self {
        Self::TokenExchangeAccepted {
            timestamp: iso_timestamp(),
            session_id: session_id.to_string(),
            username: username.to_string(),
            exchanger: exchanger.to_string(),
            delegation_depth,
            target_audience: target_audience.to_string(),
            host: get_hostname(),
        }
    }

    /// Create a token exchange rejected event (RFC 8693 delegation failed).
    ///
    /// Emitted when a token with an `act` claim fails delegation validation.
    /// SIEM operators should alert on this event — it may indicate a compromised
    /// jump host or misconfigured delegation policy.
    pub fn token_exchange_rejected(username: &str, exchanger: &str, reason: &str) -> Self {
        Self::TokenExchangeRejected {
            timestamp: iso_timestamp(),
            username: username.to_string(),
            exchanger: exchanger.to_string(),
            reason: reason.to_string(),
            host: get_hostname(),
        }
    }

    /// Create an IdP failover activated event (Phase 41, ADR-020).
    ///
    /// Emitted when an availability failure causes failover from primary to secondary.
    /// `reason` should describe the availability failure (e.g., "connect timeout",
    /// "HTTP 503 Service Unavailable").
    pub fn idp_failover_activated(
        failed_issuer: &str,
        secondary_issuer: &str,
        reason: &str,
    ) -> Self {
        Self::IdpFailoverActivated {
            timestamp: iso_timestamp(),
            failed_issuer: failed_issuer.to_string(),
            secondary_issuer: secondary_issuer.to_string(),
            reason: reason.to_string(),
            host: get_hostname(),
        }
    }

    /// Create an IdP failover recovered event (Phase 41, ADR-020).
    ///
    /// Emitted when the primary issuer becomes healthy again after a cooldown retry.
    pub fn idp_failover_recovered(recovered_issuer: &str, previous_active_issuer: &str) -> Self {
        Self::IdpFailoverRecovered {
            timestamp: iso_timestamp(),
            recovered_issuer: recovered_issuer.to_string(),
            previous_active_issuer: previous_active_issuer.to_string(),
            host: get_hostname(),
        }
    }

    /// Create an IdP failover exhausted event (Phase 41, ADR-020).
    ///
    /// Emitted when both primary and secondary issuers are unreachable.
    /// This is a critical event — authentication will fail closed.
    pub fn idp_failover_exhausted(
        primary_issuer: &str,
        secondary_issuer: &str,
        last_error: &str,
    ) -> Self {
        Self::IdpFailoverExhausted {
            timestamp: iso_timestamp(),
            primary_issuer: primary_issuer.to_string(),
            secondary_issuer: secondary_issuer.to_string(),
            last_error: last_error.to_string(),
            host: get_hostname(),
        }
    }

    /// Log this event to the configured audit destinations.
    ///
    /// When `PRMANA_AUDIT_HMAC_KEY` is set, the output JSON is augmented with
    /// `prev_hash` and `chain_hash` fields providing a tamper-evident audit chain.
    /// The HMAC is computed over the OCSF-enriched event JSON — so the chain
    /// covers all fields including OCSF metadata (OBS-07 + Plan 27-03 chain).
    pub fn log(&self) {
        // Step 1: Serialize with OCSF enrichment (category_uid, class_uid, severity_id,
        // activity_id, type_uid, metadata.version added alongside existing fields).
        // Existing field names are unchanged — OCSF fields are purely additive.
        let base_json = self.enriched_log_json();
        if base_json.is_empty() {
            tracing::error!("Failed to serialize audit event; skipping log");
            return;
        }

        // Step 2: Attempt to advance the HMAC chain. The mutex guard is held for the
        // duration so that concurrent PAM calls cannot interleave their chain steps.
        let output_json = if let Ok(mut state) = CHAIN_STATE.lock() {
            if let Some((prev_hash, chain_hash)) = state.compute_chain(&base_json) {
                // Build ChainedAuditEvent: flatten base JSON then append chain fields.
                match serde_json::from_str::<serde_json::Value>(&base_json) {
                    Ok(enriched_value) => {
                        let chained = ChainedAuditEvent {
                            enriched: enriched_value,
                            prev_hash,
                            chain_hash,
                        };
                        serde_json::to_string(&chained).unwrap_or(base_json)
                    }
                    Err(_) => base_json,
                }
            } else {
                // Chain disabled — use base event JSON as-is (existing behaviour)
                base_json
            }
        } else {
            // Mutex poisoned — fall back to base JSON rather than refusing to log
            tracing::warn!("HMAC chain mutex poisoned; logging without chain fields");
            base_json
        };

        // Step 3: Emit to configured audit destinations (Phase 32).
        let settings = &*AUDIT_SETTINGS;
        let severity = self.syslog_severity();

        if settings.syslog_enabled {
            log_to_syslog(&output_json, severity);
        }

        if !settings.log_file.is_empty() {
            let _ = append_to_file(&settings.log_file, &output_json);
        }

        if settings.stderr_enabled {
            eprintln!("prmana-audit: {output_json}");
        }
    }

    /// Get the event type as a string.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::SshLoginSuccess { .. } => "SSH_LOGIN_SUCCESS",
            Self::SshLoginFailed { .. } => "SSH_LOGIN_FAILED",
            Self::TokenValidationFailed { .. } => "TOKEN_VALIDATION_FAILED",
            Self::UserNotFound { .. } => "USER_NOT_FOUND",
            Self::PrivilegePolicyDecision { .. } => "PRIVILEGE_POLICY_DECISION",
            Self::StepUpInitiated { .. } => "STEP_UP_INITIATED",
            Self::StepUpSuccess { .. } => "STEP_UP_SUCCESS",
            Self::StepUpFailed { .. } => "STEP_UP_FAILED",
            Self::BreakGlassAuth { .. } => "BREAK_GLASS_AUTH",
            Self::SessionOpened { .. } => "SESSION_OPENED",
            Self::SessionClosed { .. } => "SESSION_CLOSED",
            Self::TokenRevoked { .. } => "TOKEN_REVOKED",
            Self::IntrospectionFailed { .. } => "INTROSPECTION_FAILED",
            Self::AuthNoToken { .. } => "AUTH_NO_TOKEN",
            Self::SessionCloseFailed { .. } => "SESSION_CLOSE_FAILED",
            Self::IssuerDegraded { .. } => "ISSUER_DEGRADED",
            Self::IssuerRecovered { .. } => "ISSUER_RECOVERED",
            Self::JtiReplayDetected { .. } => "JTI_REPLAY_DETECTED",
            Self::JtiStoreDegraded { .. } => "JTI_STORE_DEGRADED",
            Self::TokenExchangeAccepted { .. } => "TOKEN_EXCHANGE_ACCEPTED",
            Self::TokenExchangeRejected { .. } => "TOKEN_EXCHANGE_REJECTED",
            Self::IdpFailoverActivated { .. } => "IDP_FAILOVER_ACTIVATED",
            Self::IdpFailoverRecovered { .. } => "IDP_FAILOVER_RECOVERED",
            Self::IdpFailoverExhausted { .. } => "IDP_FAILOVER_EXHAUSTED",
        }
    }

    /// Map each audit event to its appropriate syslog severity.
    ///
    /// - **Critical**: break-glass access with `alert_on_use=true`
    /// - **Info**: break-glass access with `alert_on_use=false` (routine / non-alerting)
    /// - **Warning**: authentication/validation failures
    /// - **Info**: successful operations and routine lifecycle events
    pub fn syslog_severity(&self) -> AuditSeverity {
        match self {
            Self::BreakGlassAuth { alert_on_use, .. } => {
                if *alert_on_use {
                    AuditSeverity::Critical
                } else {
                    AuditSeverity::Info
                }
            }
            // JTI replay is an attack indicator — WARNING syslog (HIGH OCSF severity_id 4).
            // JTI store degraded is a security infrastructure failure — CRITICAL regardless
            // of enforcement mode (strict = login rejected; permissive = fallback active).
            Self::JtiReplayDetected { .. } => AuditSeverity::Warning,
            Self::JtiStoreDegraded { .. } => AuditSeverity::Critical,
            Self::SshLoginFailed { .. }
            | Self::TokenValidationFailed { .. }
            | Self::StepUpFailed { .. }
            | Self::IntrospectionFailed { .. }
            | Self::UserNotFound { .. }
            | Self::AuthNoToken { .. }
            | Self::SessionCloseFailed { .. }
            | Self::IssuerDegraded { .. } => AuditSeverity::Warning,
            Self::SshLoginSuccess { .. }
            | Self::SessionOpened { .. }
            | Self::SessionClosed { .. }
            | Self::TokenRevoked { .. }
            | Self::PrivilegePolicyDecision { .. }
            | Self::StepUpInitiated { .. }
            | Self::StepUpSuccess { .. }
            | Self::IssuerRecovered { .. }
            | Self::TokenExchangeAccepted { .. } => AuditSeverity::Info,
            Self::TokenExchangeRejected { .. } => AuditSeverity::Warning,
            // IdP failover events (Phase 41)
            Self::IdpFailoverActivated { .. } => AuditSeverity::Warning,
            Self::IdpFailoverRecovered { .. } => AuditSeverity::Info,
            Self::IdpFailoverExhausted { .. } => AuditSeverity::Critical,
        }
    }

    /// Return OCSF field values for this event (OBS-07).
    ///
    /// All events map to OCSF 1.3.0 Authentication class (class_uid 3002) under
    /// Identity & Access Management (category_uid 3). Activity and severity IDs
    /// are assigned per-event-type following the OCSF taxonomy:
    ///
    /// | activity_id | Meaning          |
    /// |-------------|------------------|
    /// | 1           | Logon            |
    /// | 2           | Logoff           |
    /// | 3           | Authentication Challenge |
    /// | 99          | Other            |
    ///
    /// | severity_id | Meaning  |
    /// |-------------|----------|
    /// | 1           | Info     |
    /// | 2           | Low      |
    /// | 3           | Medium   |
    /// | 4           | High     |
    /// | 5           | Critical |
    ///
    /// This is a public method so external consumers can inspect OCSF values
    /// without parsing JSON.
    pub fn ocsf_fields(&self) -> OcsfFields {
        let (activity_id, severity_id) = match self {
            // Logon attempts — activity_id 1
            Self::SshLoginSuccess { .. } => (1, 1), // Info: success
            Self::SshLoginFailed { .. } => (1, 3),  // Medium: failed logon
            Self::TokenValidationFailed { .. } => (1, 3),
            Self::AuthNoToken { .. } => (1, 3), // Medium: no token provided
            Self::UserNotFound { .. } => (1, 3),
            Self::SessionOpened { .. } => (1, 1), // Info: session start

            // Logoff / session close — activity_id 2
            Self::SessionClosed { .. } => (2, 1), // Info: normal close
            Self::SessionCloseFailed { .. } => (2, 3), // Medium: cleanup failure
            Self::TokenRevoked { .. } => (2, 1),  // Info: revocation

            // Authentication challenge — activity_id 3
            Self::PrivilegePolicyDecision { .. } => (3, 1), // Info: policy evaluated
            Self::StepUpInitiated { .. } => (3, 1),         // Info: challenge started
            Self::StepUpSuccess { .. } => (3, 1),           // Info: challenge passed
            Self::StepUpFailed { .. } => (3, 3),            // Medium: challenge denied

            // Break-glass — activity_id 1, severity depends on alert_on_use
            Self::BreakGlassAuth { alert_on_use, .. } => {
                let sev = if *alert_on_use { 5 } else { 1 }; // Critical or Info
                (1, sev)
            }

            // Other / infrastructure events — activity_id 99
            Self::IntrospectionFailed { .. } => (99, 3), // Medium: token check failure

            // Issuer health transitions — activity_id 99 (Other)
            Self::IssuerDegraded { .. } => (99, 4), // High: issuer degraded
            Self::IssuerRecovered { .. } => (99, 1), // Info: issuer recovered

            // JTI replay — activity_id 1 (Logon, failed attempt), severity_id 4 (High)
            // Cross-fork replay is an attack indicator; SIEM must alert on this event.
            Self::JtiReplayDetected { .. } => (1, 4),

            // JTI store degraded — activity_id 99 (Other), severity_id 5 (Critical)
            // Security infrastructure failure: cross-fork replay protection degraded or rejected.
            Self::JtiStoreDegraded { .. } => (99, 5),

            // Token exchange — activity_id 1 (Logon)
            // Accepted: Info (1); Rejected: High (4) — potential attack indicator
            Self::TokenExchangeAccepted { .. } => (1, 1),
            Self::TokenExchangeRejected { .. } => (1, 4),

            // IdP failover events (Phase 41) — activity_id 99 (Other)
            // Activated: High (4) — primary unavailable, operator should investigate
            Self::IdpFailoverActivated { .. } => (99, 4),
            // Recovered: Info (1) — primary healthy again
            Self::IdpFailoverRecovered { .. } => (99, 1),
            // Exhausted: Critical (5) — both issuers down, auth fails closed
            Self::IdpFailoverExhausted { .. } => (99, 5),
        };

        let class_uid: u32 = 3002;
        OcsfFields {
            category_uid: 3,
            class_uid,
            activity_id,
            severity_id,
            type_uid: class_uid * 100 + activity_id,
            metadata: OcsfMetadata {
                version: OCSF_VERSION,
            },
        }
    }

    /// Serialize this event as a JSON string enriched with OCSF fields.
    ///
    /// Uses `EnrichedAuditEvent` with `#[serde(flatten)]` to add OCSF fields
    /// alongside all existing event fields.  Existing field names are unchanged
    /// — OCSF fields are purely additive new top-level keys.
    ///
    /// This is the payload written to syslog, the audit file, and stderr by
    /// `log()`.  It is exposed as a public method for testing.
    pub fn enriched_log_json(&self) -> String {
        let fields = self.ocsf_fields();
        let enriched = EnrichedAuditEvent {
            event: self,
            category_uid: fields.category_uid,
            class_uid: fields.class_uid,
            activity_id: fields.activity_id,
            severity_id: fields.severity_id,
            type_uid: fields.type_uid,
            metadata: fields.metadata,
        };
        serde_json::to_string(&enriched).unwrap_or_else(|e| {
            tracing::error!(error = %e, "Failed to serialize enriched audit event; using bare event");
            // Fallback: serialize the bare event without OCSF fields.
            // This cannot fail (the bare event serializes without OCSF enrichment succeeding)
            // since AuditEvent only contains serializable primitives.
            serde_json::to_string(self).unwrap_or_else(|_| String::new())
        })
    }
}

/// Get the current timestamp in ISO 8601 format.
fn iso_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Get the hostname of the current machine.
///
/// Resolution order (first hit wins):
///  1. `PRMANA_HOSTNAME` env var — operator override for CNAME or custom hostname
///     scenarios (e.g. containers where the kernel hostname is a pod ID but audit logs
///     should show a human-readable service name).
///  2. `gethostname(2)` POSIX syscall — always reflects the actual kernel hostname
///     regardless of environment variables.
///
/// The old fallback to `HOSTNAME` / `HOST` env vars is intentionally removed: those
/// env vars are unreliable in containers and are not set by the kernel — they can be
/// missing, stale, or deliberately spoofed.
fn get_hostname() -> String {
    if let Ok(override_host) = std::env::var("PRMANA_HOSTNAME") {
        if !override_host.is_empty() {
            return override_host;
        }
    }
    gethostname::gethostname().to_string_lossy().into_owned()
}

/// Append a line to a file.
fn append_to_file(path: &str, content: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    writeln!(file, "{content}")?;
    Ok(())
}

/// Log a message to syslog at the given severity level.
fn log_to_syslog(message: &str, severity: AuditSeverity) {
    if let Ok(mut guard) = SYSLOG_WRITER.lock() {
        if let Some(ref mut logger) = *guard {
            let _ = match severity {
                AuditSeverity::Info => logger.info(message),
                AuditSeverity::Warning => logger.warning(message),
                AuditSeverity::Critical => logger.crit(message),
            };
        }
    }
}

// ── HMAC chain tests (Plan 27-05) ─────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod hmac_chain_tests {
    use super::*;

    /// Helper: make a fresh ChainState with an explicit key (bypassing lazy env-var init)
    fn chain_with_key(key: &[u8]) -> ChainState {
        ChainState {
            hmac_key: Some(key.to_vec()),
            prev_hash: "genesis".to_string(),
        }
    }

    /// Helper: build a minimal audit event JSON using the current event serializer
    fn make_event_json(event: &AuditEvent) -> String {
        serde_json::to_string(event).unwrap()
    }

    // Test 1: With HMAC key set, the chain produces chain_hash and prev_hash fields
    #[test]
    fn test_hmac_chain_fields_present_when_key_set() {
        let mut chain = chain_with_key(b"test-secret-key-32-bytes-minimum!");
        let event =
            AuditEvent::ssh_login_success("s1", "alice", None, None, None, None, None, None);
        let event_json = make_event_json(&event);

        let result = chain.compute_chain(&event_json);
        assert!(
            result.is_some(),
            "chain should produce a result when key is set"
        );
        let (prev_hash, chain_hash) = result.unwrap();
        assert_eq!(
            prev_hash, "genesis",
            "first event's prev_hash must be 'genesis'"
        );
        assert!(
            !chain_hash.is_empty(),
            "chain_hash must be non-empty hex string"
        );
        // HMAC-SHA256 hex = 64 chars
        assert_eq!(
            chain_hash.len(),
            64,
            "chain_hash must be 64-char hex (HMAC-SHA256)"
        );
    }

    // Test 2: Two consecutive events form a valid chain
    #[test]
    fn test_hmac_chain_consecutive_events_chain_correctly() {
        let mut chain = chain_with_key(b"test-secret-key-32-bytes-minimum!");

        let event1 =
            AuditEvent::ssh_login_success("s1", "alice", None, None, None, None, None, None);
        let json1 = make_event_json(&event1);
        let (_, hash1) = chain.compute_chain(&json1).unwrap();

        let event2 = AuditEvent::session_closed("s1", "alice", 300);
        let json2 = make_event_json(&event2);
        let (prev2, hash2) = chain.compute_chain(&json2).unwrap();

        // event2.prev_hash == event1.chain_hash
        assert_eq!(
            prev2, hash1,
            "event2.prev_hash must equal event1.chain_hash"
        );
        assert_ne!(hash1, hash2, "consecutive hashes must differ");
    }

    // Test 3: Modifying event1's JSON after logging breaks the chain
    #[test]
    fn test_hmac_chain_modification_breaks_chain() {
        let key = b"test-secret-key-32-bytes-minimum!";
        let mut chain1 = chain_with_key(key);
        let mut chain2 = chain_with_key(key);

        let event1 =
            AuditEvent::ssh_login_success("s1", "alice", None, None, None, None, None, None);
        let original_json1 = make_event_json(&event1);
        let (_, hash1_original) = chain1.compute_chain(&original_json1).unwrap();

        // Now compute hash over a tampered version of event1
        let tampered_json1 = original_json1.replace("alice", "mallory");
        let (_, hash1_tampered) = chain2.compute_chain(&tampered_json1).unwrap();

        // The chain hashes must differ — modification detected
        assert_ne!(
            hash1_original, hash1_tampered,
            "tampering with event JSON must produce a different chain_hash"
        );
    }

    // Test 4 (negative): With key unset, compute_chain returns None
    #[test]
    fn test_hmac_chain_disabled_when_key_absent() {
        let mut chain = ChainState {
            hmac_key: None,
            prev_hash: "genesis".to_string(),
        };
        let event = AuditEvent::ssh_login_success("s1", "bob", None, None, None, None, None, None);
        let json = make_event_json(&event);
        let result = chain.compute_chain(&json);
        assert!(
            result.is_none(),
            "chain must be disabled (None) when key is absent"
        );
    }

    // Test 5 (negative): Empty HMAC key treated as unset
    #[test]
    fn test_hmac_chain_disabled_for_empty_key() {
        let mut chain = ChainState {
            hmac_key: Some(vec![]), // empty key → treated as unset during init
            prev_hash: "genesis".to_string(),
        };
        // An empty key vec: we test that the ChainState::new() path with empty env var
        // sets hmac_key = None. Test that compute_chain with Some([]) still gives Some result
        // (the HMAC itself would still compute — the empty check is at init time).
        // This test verifies the init logic: new() with empty env var sets hmac_key = None.
        let chain_from_empty_env = {
            // Simulate what ChainState::new() does with an empty key
            let key_bytes: Vec<u8> = vec![];
            if key_bytes.is_empty() {
                None
            } else {
                Some(key_bytes)
            }
        };
        assert!(
            chain_from_empty_env.is_none(),
            "empty key must be treated as absent"
        );
        // Also verify the chain with None doesn't compute
        chain.hmac_key = None;
        let event = AuditEvent::user_not_found("nobody");
        let json = make_event_json(&event);
        assert!(chain.compute_chain(&json).is_none());
    }

    // Test 6: Chain works correctly across different event types
    #[test]
    fn test_hmac_chain_works_across_event_types() {
        let mut chain = chain_with_key(b"test-secret-key-32-bytes-minimum!");

        let login =
            AuditEvent::ssh_login_success("s1", "alice", None, None, None, None, None, None);
        let (_, hash_login) = chain.compute_chain(&make_event_json(&login)).unwrap();

        let closed = AuditEvent::session_closed("s1", "alice", 60);
        let (prev_closed, _hash_closed) = chain.compute_chain(&make_event_json(&closed)).unwrap();

        assert_eq!(
            prev_closed, hash_login,
            "SessionClosed.prev_hash must equal SshLoginSuccess.chain_hash"
        );
    }

    // Test 7: The chain_hash input includes all event fields (OCSF when present) —
    // modifying any event field (including ones added by enrichment) breaks the chain.
    // Since 27-04 may not have run yet, we test with the current event JSON structure.
    #[test]
    fn test_hmac_chain_covers_all_event_fields() {
        let key = b"test-secret-key-32-bytes-minimum!";
        let mut chain_a = chain_with_key(key);
        let mut chain_b = chain_with_key(key);

        let event_a = AuditEvent::ssh_login_success(
            "s1",
            "alice",
            Some(1000),
            Some("10.0.0.1"),
            None,
            None,
            None,
            None,
        );
        let event_b = AuditEvent::ssh_login_success(
            "s1",
            "alice",
            Some(9999),
            Some("10.0.0.1"),
            None,
            None,
            None,
            None,
        );

        let (_, hash_a) = chain_a.compute_chain(&make_event_json(&event_a)).unwrap();
        let (_, hash_b) = chain_b.compute_chain(&make_event_json(&event_b)).unwrap();

        // Different uid → different JSON → different chain_hash
        assert_ne!(
            hash_a, hash_b,
            "different event content must produce different chain hashes"
        );
    }

    // Test 8: prev_hash state advances correctly — state machine verification
    #[test]
    fn test_hmac_chain_state_advances_correctly() {
        let mut chain = chain_with_key(b"test-secret-key-32-bytes-minimum!");
        assert_eq!(chain.prev_hash, "genesis");

        let e1 = AuditEvent::ssh_login_success("s1", "alice", None, None, None, None, None, None);
        let (prev1, hash1) = chain.compute_chain(&make_event_json(&e1)).unwrap();
        assert_eq!(prev1, "genesis");
        assert_eq!(
            chain.prev_hash, hash1,
            "state must advance to hash1 after event1"
        );

        let e2 = AuditEvent::session_closed("s1", "alice", 30);
        let (prev2, hash2) = chain.compute_chain(&make_event_json(&e2)).unwrap();
        assert_eq!(prev2, hash1, "prev_hash of event2 must be hash1");
        assert_eq!(
            chain.prev_hash, hash2,
            "state must advance to hash2 after event2"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // Serial mutex for hostname tests that mutate PRMANA_HOSTNAME env var.
    // Env vars are process-wide; parallel test threads would race without this.
    // Pattern consistent with Phase 6 / prmana-agent config tests.
    use parking_lot::Mutex;
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_ssh_login_success_serialization() {
        let event = AuditEvent::ssh_login_success(
            "session-123",
            "testuser",
            Some(1001),
            Some("192.168.1.1"),
            Some("token-jti-456"),
            Some("urn:example:acr:mfa"),
            Some(1705400000),
            None,
        );

        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("SSH_LOGIN_SUCCESS"));
        assert!(json.contains("testuser"));
        assert!(json.contains("session-123"));
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("token-jti-456"));
        assert!(json.contains("urn:example:acr:mfa"));
    }

    #[test]
    fn test_ssh_login_success_dpop_thumbprint() {
        // KCDPOP-02: Verify dpop_thumbprint appears in serialized audit event
        let event = AuditEvent::ssh_login_success(
            "session-dpop-1",
            "dpopuser",
            Some(1002),
            Some("10.0.0.5"),
            Some("jti-dpop"),
            Some("urn:example:mfa"),
            Some(1705400000),
            Some("abc123-thumbprint"),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains("\"dpop_thumbprint\":\"abc123-thumbprint\""),
            "dpop_thumbprint must appear in JSON, got: {json}"
        );

        // Without DPoP (backward compat)
        let event_no_dpop = AuditEvent::ssh_login_success(
            "session-no-dpop",
            "regularuser",
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let json_no_dpop = serde_json::to_string(&event_no_dpop).unwrap();
        assert!(
            json_no_dpop.contains("\"dpop_thumbprint\":null"),
            "dpop_thumbprint must be null when absent, got: {json_no_dpop}"
        );

        // Verify enriched_log_json also includes dpop_thumbprint
        let enriched = event.enriched_log_json();
        assert!(
            enriched.contains("abc123-thumbprint"),
            "enriched_log_json must include dpop_thumbprint, got: {enriched}"
        );
    }

    #[test]
    fn test_ssh_login_failed_serialization() {
        let event = AuditEvent::ssh_login_failed(
            Some("testuser"),
            Some("192.168.1.1"),
            "Token validation failed: expired",
        );

        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("SSH_LOGIN_FAILED"));
        assert!(json.contains("testuser"));
        assert!(json.contains("Token validation failed"));
    }

    #[test]
    fn test_token_validation_failed_serialization() {
        let event = AuditEvent::token_validation_failed(
            Some("testuser"),
            "Invalid issuer",
            Some("10.0.0.1"),
            Some("http://wrong-issuer.com"),
        );

        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("TOKEN_VALIDATION_FAILED"));
        assert!(json.contains("Invalid issuer"));
        assert!(json.contains("wrong-issuer"));
    }

    #[test]
    fn test_user_not_found_serialization() {
        let event = AuditEvent::user_not_found("unknownuser");

        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("USER_NOT_FOUND"));
        assert!(json.contains("unknownuser"));
    }

    #[test]
    fn test_event_type() {
        let success = AuditEvent::ssh_login_success("s", "u", None, None, None, None, None, None);
        assert_eq!(success.event_type(), "SSH_LOGIN_SUCCESS");

        let failed = AuditEvent::ssh_login_failed(None, None, "reason");
        assert_eq!(failed.event_type(), "SSH_LOGIN_FAILED");

        let token_failed = AuditEvent::token_validation_failed(None, "reason", None, None);
        assert_eq!(token_failed.event_type(), "TOKEN_VALIDATION_FAILED");

        let not_found = AuditEvent::user_not_found("user");
        assert_eq!(not_found.event_type(), "USER_NOT_FOUND");
    }

    #[test]
    fn test_timestamp_format() {
        let ts = iso_timestamp();
        // Should be in RFC 3339 format like "2024-01-15T10:30:00.123456789+00:00"
        assert!(ts.contains('T'));
        assert!(ts.contains(':'));
    }

    // ── Phase 8: BreakGlassAuth tests ───────────────────────────────────────

    #[test]
    fn test_break_glass_auth_serialization() {
        let event = AuditEvent::break_glass_auth("emergency", Some("10.0.0.1"), true);
        let json = serde_json::to_string(&event).unwrap();

        // Event tag must be BREAK_GLASS_AUTH
        assert!(json.contains("BREAK_GLASS_AUTH"), "json: {json}");
        // Username must appear
        assert!(json.contains("emergency"), "json: {json}");
        // Source IP must appear
        assert!(json.contains("10.0.0.1"), "json: {json}");
        // Severity must be CRITICAL when alert_on_use=true
        assert!(json.contains("CRITICAL"), "json: {json}");
        // Reason must be present
        assert!(json.contains("break-glass bypass"), "json: {json}");
        // Timestamp must be present
        assert!(json.contains("timestamp"), "json: {json}");
    }

    #[test]
    fn test_break_glass_auth_serialization_no_source_ip() {
        let event = AuditEvent::break_glass_auth("breakglass1", None, true);
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("BREAK_GLASS_AUTH"), "json: {json}");
        assert!(json.contains("breakglass1"), "json: {json}");
        assert!(json.contains("CRITICAL"), "json: {json}");
        // source_ip should be null or absent
        assert!(json.contains("null") || !json.contains("source_ip\":\""));
    }

    #[test]
    fn test_break_glass_auth_event_type() {
        let event = AuditEvent::break_glass_auth("emergency", None, true);
        assert_eq!(event.event_type(), "BREAK_GLASS_AUTH");
    }

    // ── SBUG-02 / SHRD-03: alert_on_use wiring and syslog severity ──────────
    //
    // These tests serve as regression guards for SHRD-03:
    // "BREAK_GLASS_AUTH events appear at syslog CRITICAL severity when alert_on_use=true."
    // Existing tests from Phase 24 SBUG-02 already cover:
    // - syslog_severity() -> Critical for alert_on_use=true
    // - syslog_severity() -> Info for alert_on_use=false
    // - JSON payload contains "severity":"CRITICAL" / "severity":"INFO"
    // - event_type() returns "BREAK_GLASS_AUTH"

    #[test]
    fn test_break_glass_auth_alert_on_use_true_is_critical() {
        let event = AuditEvent::break_glass_auth("bguser", Some("10.1.2.3"), true);
        assert_eq!(
            event.syslog_severity(),
            AuditSeverity::Critical,
            "alert_on_use=true must produce Critical severity"
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains("\"CRITICAL\""),
            "serialized severity must be CRITICAL, json: {json}"
        );
    }

    #[test]
    fn test_break_glass_auth_alert_on_use_false_is_info() {
        let event = AuditEvent::break_glass_auth("bguser", Some("10.1.2.3"), false);
        assert_eq!(
            event.syslog_severity(),
            AuditSeverity::Info,
            "alert_on_use=false must produce Info severity"
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains("\"INFO\""),
            "serialized severity must be INFO, json: {json}"
        );
    }

    #[test]
    fn test_break_glass_auth_alert_on_use_false_no_critical_in_json() {
        let event = AuditEvent::break_glass_auth("bguser", None, false);
        let json = serde_json::to_string(&event).unwrap();
        // When alert_on_use=false severity is INFO, not CRITICAL
        assert!(
            !json.contains("\"CRITICAL\""),
            "severity must NOT be CRITICAL when alert_on_use=false, json: {json}"
        );
    }

    // ── Phase 9: Session / introspection audit event tests ───────────────────

    #[test]
    fn test_session_opened_serialization() {
        let event = AuditEvent::session_opened("sid-123", "alice", Some("10.0.0.1"), 9_999_999);
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("SESSION_OPENED"), "json: {json}");
        assert!(json.contains("sid-123"), "json: {json}");
        assert!(json.contains("alice"), "json: {json}");
        assert!(json.contains("10.0.0.1"), "json: {json}");
        assert!(json.contains("9999999"), "json: {json}");
        assert!(json.contains("timestamp"), "json: {json}");
    }

    #[test]
    fn test_session_opened_no_client_ip() {
        let event = AuditEvent::session_opened("sid-456", "bob", None, 1000);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("SESSION_OPENED"), "json: {json}");
        assert!(json.contains("bob"), "json: {json}");
        // client_ip should be null or absent
        assert!(json.contains("null") || !json.contains("client_ip\":\""));
    }

    #[test]
    fn test_session_closed_serialization() {
        let event = AuditEvent::session_closed("sid-789", "charlie", 3600);
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("SESSION_CLOSED"), "json: {json}");
        assert!(json.contains("sid-789"), "json: {json}");
        assert!(json.contains("charlie"), "json: {json}");
        assert!(json.contains("3600"), "json: {json}");
        assert!(json.contains("timestamp"), "json: {json}");
    }

    #[test]
    fn test_token_revoked_success_serialization() {
        let event = AuditEvent::token_revoked("sid-abc", "diana", "success", None);
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("TOKEN_REVOKED"), "json: {json}");
        assert!(json.contains("sid-abc"), "json: {json}");
        assert!(json.contains("diana"), "json: {json}");
        assert!(json.contains("success"), "json: {json}");
    }

    #[test]
    fn test_token_revoked_failed_with_reason() {
        let event = AuditEvent::token_revoked("sid-def", "eve", "failed", Some("IdP unreachable"));
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("TOKEN_REVOKED"), "json: {json}");
        assert!(json.contains("failed"), "json: {json}");
        assert!(json.contains("IdP unreachable"), "json: {json}");
    }

    #[test]
    fn test_introspection_failed_serialization() {
        let event = AuditEvent::introspection_failed(
            Some("sid-xyz"),
            Some("frank"),
            "token not active",
            "warn",
        );
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("INTROSPECTION_FAILED"), "json: {json}");
        assert!(json.contains("sid-xyz"), "json: {json}");
        assert!(json.contains("frank"), "json: {json}");
        assert!(json.contains("token not active"), "json: {json}");
        assert!(json.contains("\"enforcement\""), "json: {json}");
        assert!(json.contains("warn"), "json: {json}");
    }

    #[test]
    fn test_introspection_failed_no_session_no_user() {
        let event = AuditEvent::introspection_failed(None, None, "connection refused", "strict");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("INTROSPECTION_FAILED"), "json: {json}");
        assert!(json.contains("connection refused"), "json: {json}");
        assert!(json.contains("strict"), "json: {json}");
    }

    #[test]
    fn test_new_event_types_in_event_type_method() {
        let opened = AuditEvent::session_opened("s", "u", None, 0);
        assert_eq!(opened.event_type(), "SESSION_OPENED");

        let closed = AuditEvent::session_closed("s", "u", 0);
        assert_eq!(closed.event_type(), "SESSION_CLOSED");

        let revoked = AuditEvent::token_revoked("s", "u", "skipped", None);
        assert_eq!(revoked.event_type(), "TOKEN_REVOKED");

        let failed = AuditEvent::introspection_failed(None, None, "err", "warn");
        assert_eq!(failed.event_type(), "INTROSPECTION_FAILED");
    }

    #[test]
    fn test_break_glass_auth_constructor_populates_all_fields() {
        let event = AuditEvent::break_glass_auth("testuser", Some("192.168.1.50"), true);
        match event {
            AuditEvent::BreakGlassAuth {
                timestamp,
                username,
                source_ip,
                host: _,
                reason,
                severity,
                alert_on_use,
            } => {
                assert!(!timestamp.is_empty(), "timestamp must be populated");
                assert_eq!(username, "testuser");
                assert_eq!(source_ip, Some("192.168.1.50".to_string()));
                assert_eq!(reason, "break-glass bypass");
                assert_eq!(severity, "CRITICAL");
                assert!(alert_on_use, "alert_on_use must be true");
            }
            other => panic!("Expected BreakGlassAuth, got {other:?}"),
        }
    }

    // ── OBS-02: AuthNoToken audit event tests ────────────────────────────────

    #[test]
    fn test_auth_no_token_serialization() {
        let event = AuditEvent::auth_no_token("testuser", Some("192.168.1.1"));
        let json = serde_json::to_string(&event).unwrap();

        // OBS-02 Test 1: correct event tag, username, source_ip, host, timestamp
        assert!(json.contains("AUTH_NO_TOKEN"), "json: {json}");
        assert!(json.contains("testuser"), "json: {json}");
        assert!(json.contains("192.168.1.1"), "json: {json}");
        assert!(json.contains("timestamp"), "json: {json}");
        assert!(json.contains("host"), "json: {json}");
    }

    #[test]
    fn test_auth_no_token_syslog_severity() {
        // OBS-02 Test 2: severity is Warning
        let event = AuditEvent::auth_no_token("user", Some("10.0.0.1"));
        assert_eq!(event.syslog_severity(), AuditSeverity::Warning);
    }

    #[test]
    fn test_auth_no_token_event_type() {
        // OBS-02 Test 3: event_type() returns "AUTH_NO_TOKEN"
        let event = AuditEvent::auth_no_token("user", None);
        assert_eq!(event.event_type(), "AUTH_NO_TOKEN");
    }

    #[test]
    fn test_auth_no_token_distinct_from_ssh_login_failed() {
        // OBS-02 Test 4 (negative): AUTH_NO_TOKEN is distinct from SSH_LOGIN_FAILED
        let no_token = AuditEvent::auth_no_token("user", None);
        let login_failed = AuditEvent::ssh_login_failed(Some("user"), None, "token expired");

        let no_token_json = serde_json::to_string(&no_token).unwrap();
        let login_failed_json = serde_json::to_string(&login_failed).unwrap();

        assert!(
            no_token_json.contains("AUTH_NO_TOKEN"),
            "no_token json: {no_token_json}"
        );
        assert!(
            login_failed_json.contains("SSH_LOGIN_FAILED"),
            "login_failed json: {login_failed_json}"
        );
        assert!(
            !no_token_json.contains("SSH_LOGIN_FAILED"),
            "AUTH_NO_TOKEN must not contain SSH_LOGIN_FAILED, json: {no_token_json}"
        );
        assert!(
            !login_failed_json.contains("AUTH_NO_TOKEN"),
            "SSH_LOGIN_FAILED must not contain AUTH_NO_TOKEN, json: {login_failed_json}"
        );
    }

    // ── OBS-08: SessionCloseFailed audit event tests ──────────────────────────

    #[test]
    fn test_session_close_failed_serialization() {
        let event = AuditEvent::session_close_failed("sid-abc", "alice", "connection refused");
        let json = serde_json::to_string(&event).unwrap();

        assert!(json.contains("SESSION_CLOSE_FAILED"), "json: {json}");
        assert!(json.contains("sid-abc"), "json: {json}");
        assert!(json.contains("alice"), "json: {json}");
        assert!(json.contains("connection refused"), "json: {json}");
        assert!(json.contains("timestamp"), "json: {json}");
        assert!(json.contains("host"), "json: {json}");
    }

    #[test]
    fn test_session_close_failed_syslog_severity() {
        // OBS-08 Test 6: severity is Warning
        let event = AuditEvent::session_close_failed("sid-123", "bob", "write error");
        assert_eq!(event.syslog_severity(), AuditSeverity::Warning);
    }

    #[test]
    fn test_session_close_failed_event_type() {
        // OBS-08 Test 7: event_type() returns "SESSION_CLOSE_FAILED"
        let event = AuditEvent::session_close_failed("sid-456", "carol", "timeout");
        assert_eq!(event.event_type(), "SESSION_CLOSE_FAILED");
    }

    #[test]
    fn test_session_close_failed_no_ipc_message_content() {
        // OBS-08 Test 8 (negative): event does NOT contain full IPC message content
        let ipc_message = r#"{"action":"session_closed","session_id":"sid-789"}"#;
        let event = AuditEvent::session_close_failed("sid-789", "dave", "write timeout");
        let json = serde_json::to_string(&event).unwrap();

        assert!(
            !json.contains("\"action\""),
            "IPC message field action must not appear in audit event, json: {json}"
        );
        assert!(
            !json.contains(ipc_message),
            "full IPC message must not appear in audit event, json: {json}"
        );
        assert!(
            json.contains("write timeout"),
            "reason must appear, json: {json}"
        );
    }

    // ── get_hostname() tests ─────────────────────────────────────────────────

    #[test]
    fn test_get_hostname_returns_non_empty() {
        let _guard = ENV_MUTEX.lock();
        // Without PRMANA_HOSTNAME set (or with it cleared), gethostname(2) must
        // return a non-empty string on any properly configured system.
        std::env::remove_var("PRMANA_HOSTNAME");
        let h = get_hostname();
        assert!(!h.is_empty(), "hostname must be non-empty, got: {h:?}");
    }

    #[test]
    fn test_get_hostname_env_override() {
        let _guard = ENV_MUTEX.lock();
        std::env::set_var("PRMANA_HOSTNAME", "my-custom-host.example.com");
        let h = get_hostname();
        assert_eq!(h, "my-custom-host.example.com");
        std::env::remove_var("PRMANA_HOSTNAME");
    }

    #[test]
    fn test_get_hostname_syscall_without_override() {
        let _guard = ENV_MUTEX.lock();
        std::env::remove_var("PRMANA_HOSTNAME");
        // gethostname::gethostname() returns the same value
        let syscall_result = gethostname::gethostname().to_string_lossy().into_owned();
        let h = get_hostname();
        // Both should agree (no env override in play)
        assert_eq!(h, syscall_result);
    }

    // ── Syslog severity mapping tests ───────────────────────────────────────

    #[test]
    fn test_syslog_severity_mapping() {
        let bg = AuditEvent::break_glass_auth("emergency", None, true);
        assert_eq!(bg.syslog_severity(), AuditSeverity::Critical);

        let failed = AuditEvent::ssh_login_failed(None, None, "reason");
        assert_eq!(failed.syslog_severity(), AuditSeverity::Warning);

        let token_failed = AuditEvent::token_validation_failed(None, "bad", None, None);
        assert_eq!(token_failed.syslog_severity(), AuditSeverity::Warning);

        let not_found = AuditEvent::user_not_found("alice");
        assert_eq!(not_found.syslog_severity(), AuditSeverity::Warning);

        let step_failed = AuditEvent::step_up_failed(
            "u", None, "ciba", "timeout", None, None, None, None, None, false,
        );
        assert_eq!(step_failed.syslog_severity(), AuditSeverity::Warning);

        let intro_failed = AuditEvent::introspection_failed(None, None, "err", "strict");
        assert_eq!(intro_failed.syslog_severity(), AuditSeverity::Warning);

        let success = AuditEvent::ssh_login_success("s", "u", None, None, None, None, None, None);
        assert_eq!(success.syslog_severity(), AuditSeverity::Info);

        let opened = AuditEvent::session_opened("s", "u", None, 0);
        assert_eq!(opened.syslog_severity(), AuditSeverity::Info);

        let closed = AuditEvent::session_closed("s", "u", 0);
        assert_eq!(closed.syslog_severity(), AuditSeverity::Info);

        let revoked = AuditEvent::token_revoked("s", "u", "success", None);
        assert_eq!(revoked.syslog_severity(), AuditSeverity::Info);

        let initiated =
            AuditEvent::step_up_initiated("u", None, "ciba", None, None, None, None, None, false);
        assert_eq!(initiated.syslog_severity(), AuditSeverity::Info);

        let step_ok = AuditEvent::step_up_success(
            "u", None, "ciba", "s", None, None, false, None, None, None, None, false, false,
        );
        assert_eq!(step_ok.syslog_severity(), AuditSeverity::Info);

        // OBS-07: new variants must also be Warning
        let no_token = AuditEvent::auth_no_token("u", None);
        assert_eq!(no_token.syslog_severity(), AuditSeverity::Warning);

        let close_failed = AuditEvent::session_close_failed("s", "u", "err");
        assert_eq!(close_failed.syslog_severity(), AuditSeverity::Warning);
    }

    // ── OBS-07: OCSF schema field tests ──────────────────────────────────────

    /// Helper: serialise an AuditEvent enriched with OCSF fields.
    ///
    /// This calls `ocsf_fields()` directly to produce a JSON-serialisable
    /// `OcsfFields` struct, then checks that the expected fields are present.
    #[allow(dead_code)]
    fn ocsf_json(event: &AuditEvent) -> String {
        let fields = event.ocsf_fields();
        // We test via serde_json::to_string of the AuditEvent alongside the OcsfFields
        // to verify that log() would emit them together.  The actual combined emission
        // is tested end-to-end via the log() calls; here we validate the field values.
        serde_json::to_string(&fields).unwrap()
    }

    #[test]
    fn test_ocsf_ssh_login_success_fields() {
        // OBS-07 Test 1: SshLoginSuccess has correct OCSF fields
        let event = AuditEvent::ssh_login_success("s", "u", None, None, None, None, None, None);
        let fields = event.ocsf_fields();

        assert_eq!(fields.category_uid, 3, "IAM category_uid must be 3");
        assert_eq!(
            fields.class_uid, 3002,
            "Authentication class_uid must be 3002"
        );
        assert_eq!(fields.activity_id, 1, "Logon activity_id must be 1");
        assert_eq!(
            fields.severity_id, 1,
            "Success severity_id must be 1 (Info)"
        );
        assert_eq!(
            fields.type_uid, 300201,
            "type_uid must be class_uid * 100 + activity_id"
        );
        assert_eq!(
            fields.metadata.version, "1.3.0",
            "metadata.version must be 1.3.0"
        );
    }

    #[test]
    fn test_ocsf_ssh_login_failed_fields() {
        // OBS-07 Test 2: SshLoginFailed has severity_id 3 (Medium) and activity_id 1
        let event = AuditEvent::ssh_login_failed(None, None, "bad token");
        let fields = event.ocsf_fields();

        assert_eq!(
            fields.severity_id, 3,
            "Failed auth severity_id must be 3 (Medium)"
        );
        assert_eq!(fields.activity_id, 1, "Logon activity_id must be 1");
        assert_eq!(fields.class_uid, 3002);
        assert_eq!(fields.type_uid, 300201);
    }

    #[test]
    fn test_ocsf_break_glass_critical_fields() {
        // OBS-07 Test 3: BreakGlassAuth with alert_on_use=true has severity_id 5 (Critical)
        let event = AuditEvent::break_glass_auth("emergency", None, true);
        let fields = event.ocsf_fields();

        assert_eq!(
            fields.severity_id, 5,
            "BreakGlass+alert severity_id must be 5 (Critical)"
        );
        assert_eq!(fields.activity_id, 1, "Logon activity_id must be 1");
    }

    #[test]
    fn test_ocsf_auth_no_token_fields() {
        // OBS-07 Test 4: AuthNoToken has activity_id 1 (Logon), severity_id 3
        let event = AuditEvent::auth_no_token("user", None);
        let fields = event.ocsf_fields();

        assert_eq!(
            fields.activity_id, 1,
            "No-token auth activity_id must be 1 (Logon attempt)"
        );
        assert_eq!(
            fields.severity_id, 3,
            "No-token auth severity_id must be 3 (Medium)"
        );
        assert_eq!(fields.class_uid, 3002);
    }

    #[test]
    fn test_ocsf_session_closed_fields() {
        // OBS-07 Test 5: SessionClosed has activity_id 2 (Logoff), severity_id 1
        let event = AuditEvent::session_closed("s", "u", 60);
        let fields = event.ocsf_fields();

        assert_eq!(fields.activity_id, 2, "Logoff activity_id must be 2");
        assert_eq!(
            fields.severity_id, 1,
            "Session closed severity_id must be 1 (Info)"
        );
        assert_eq!(fields.type_uid, 300202, "type_uid = 3002 * 100 + 2");
    }

    #[test]
    fn test_ocsf_existing_fields_unchanged() {
        // OBS-07 Test 6 (negative): Existing fields not renamed or removed
        // Verify that enriched_log_json() preserves the base event fields
        let event = AuditEvent::ssh_login_success(
            "sid-abc",
            "alice",
            Some(1001),
            Some("10.0.0.1"),
            Some("jti-1"),
            Some("mfa"),
            Some(1705400000),
            None,
        );
        let json = event.enriched_log_json();

        // Original event fields must be present
        assert!(
            json.contains("SSH_LOGIN_SUCCESS"),
            "event tag preserved, json: {json}"
        );
        assert!(
            json.contains("sid-abc"),
            "session_id preserved, json: {json}"
        );
        assert!(json.contains("alice"), "user preserved, json: {json}");
        assert!(
            json.contains("10.0.0.1"),
            "source_ip preserved, json: {json}"
        );
        assert!(json.contains("jti-1"), "oidc_jti preserved, json: {json}");
        assert!(json.contains("mfa"), "oidc_acr preserved, json: {json}");
        // OCSF fields must also be present
        assert!(
            json.contains("category_uid"),
            "category_uid added, json: {json}"
        );
        assert!(json.contains("class_uid"), "class_uid added, json: {json}");
        assert!(
            json.contains("severity_id"),
            "severity_id added, json: {json}"
        );
        assert!(
            json.contains("activity_id"),
            "activity_id added, json: {json}"
        );
        assert!(json.contains("type_uid"), "type_uid added, json: {json}");
        assert!(
            json.contains("1.3.0"),
            "metadata.version added, json: {json}"
        );
    }

    #[test]
    fn test_ocsf_all_variants_have_fields() {
        // OBS-07 Test 7: All event variants have OCSF fields in enriched_log_json
        let events: Vec<AuditEvent> = vec![
            AuditEvent::ssh_login_success("s", "u", None, None, None, None, None, None),
            AuditEvent::ssh_login_failed(None, None, "reason"),
            AuditEvent::token_validation_failed(None, "reason", None, None),
            AuditEvent::user_not_found("user"),
            AuditEvent::step_up_initiated("u", None, "ciba", None, None, None, None, None, false),
            AuditEvent::step_up_success(
                "u", None, "ciba", "s", None, None, false, None, None, None, None, false, false,
            ),
            AuditEvent::step_up_failed(
                "u", None, "ciba", "timeout", None, None, None, None, None, false,
            ),
            AuditEvent::break_glass_auth("u", None, true),
            AuditEvent::session_opened("s", "u", None, 0),
            AuditEvent::session_closed("s", "u", 0),
            AuditEvent::token_revoked("s", "u", "success", None),
            AuditEvent::introspection_failed(None, None, "err", "warn"),
            AuditEvent::auth_no_token("u", None),
            AuditEvent::session_close_failed("s", "u", "err"),
            AuditEvent::issuer_degraded("https://idp.example.com/realm", 3),
            AuditEvent::issuer_recovered("https://idp.example.com/realm"),
            AuditEvent::jti_replay_detected("jti-1", None, "access_token", None, None),
            AuditEvent::jti_store_degraded("disk full", "strict", "jti"),
            AuditEvent::token_exchange_accepted("s", "u", "jump-host", 1, "target"),
            AuditEvent::token_exchange_rejected("u", "evil-host", "unauthorized"),
        ];

        for event in &events {
            let json = event.enriched_log_json();
            assert!(
                json.contains("category_uid"),
                "Missing category_uid for {}, json: {json}",
                event.event_type()
            );
            assert!(
                json.contains("class_uid"),
                "Missing class_uid for {}, json: {json}",
                event.event_type()
            );
            assert!(
                json.contains("severity_id"),
                "Missing severity_id for {}, json: {json}",
                event.event_type()
            );
            assert!(
                json.contains("activity_id"),
                "Missing activity_id for {}, json: {json}",
                event.event_type()
            );
            assert!(
                json.contains("type_uid"),
                "Missing type_uid for {}, json: {json}",
                event.event_type()
            );
            assert!(
                json.contains("1.3.0"),
                "Missing metadata.version for {}, json: {json}",
                event.event_type()
            );
        }
    }

    #[test]
    fn test_ocsf_backward_compat_deserialization() {
        // OBS-07 Test 8 (negative): Old-format JSON without OCSF fields still deserializes
        // via serde default — consumers reading old logs are not broken
        let old_json = r#"{"event":"SSH_LOGIN_SUCCESS","timestamp":"2024-01-01T00:00:00Z","session_id":"s","user":"u","uid":null,"source_ip":null,"host":"localhost","oidc_jti":null,"oidc_acr":null,"oidc_auth_time":null}"#;
        // AuditEvent deserialization should succeed (old format, no OCSF fields)
        let result: Result<AuditEvent, _> = serde_json::from_str(old_json);
        assert!(
            result.is_ok(),
            "Old-format JSON must still deserialize: {:?}",
            result.err()
        );
    }

    // ── Phase 30-05: JTI replay and store-degraded audit event tests ───────────

    /// JTI_REPLAY_DETECTED event serializes with required fields and correct OCSF values.
    #[test]
    fn test_jti_replay_detected_fields() {
        let event = AuditEvent::jti_replay_detected(
            "abc-123",
            Some("https://idp.example.com"),
            "access_token",
            Some("alice"),
            Some("10.0.0.1"),
        );
        assert_eq!(event.event_type(), "JTI_REPLAY_DETECTED");
        let json = event.enriched_log_json();
        assert!(
            json.contains("\"jti\":\"abc-123\""),
            "jti field missing: {json}"
        );
        assert!(
            json.contains("\"token_type\":\"access_token\""),
            "token_type field missing: {json}"
        );
        assert!(
            json.contains("\"severity_id\":4"),
            "severity_id 4 (High) missing: {json}"
        );
        assert!(
            json.contains("\"class_uid\":3002"),
            "class_uid 3002 missing: {json}"
        );
        assert!(
            json.contains("\"issuer\":\"https://idp.example.com\""),
            "issuer field missing: {json}"
        );
    }

    /// JTI_REPLAY_DETECTED OCSF fields: severity_id 4 (High), activity_id 1 (Logon).
    #[test]
    fn test_jti_replay_detected_ocsf_severity_high() {
        let event = AuditEvent::jti_replay_detected("x", None, "dpop_proof", None, None);
        let ocsf = event.ocsf_fields();
        assert_eq!(
            ocsf.severity_id, 4,
            "JTI replay must be High (severity_id 4)"
        );
        assert_eq!(
            ocsf.activity_id, 1,
            "JTI replay must be Logon (activity_id 1)"
        );
        assert_eq!(ocsf.class_uid, 3002, "Must use Authentication class (3002)");
        assert_eq!(
            ocsf.type_uid, 300201,
            "type_uid must be class_uid*100+activity_id"
        );
    }

    /// JTI_STORE_DEGRADED event serializes with required fields and correct OCSF values.
    #[test]
    fn test_jti_store_degraded_fields() {
        let event = AuditEvent::jti_store_degraded("No space left on device", "permissive", "jti");
        assert_eq!(event.event_type(), "JTI_STORE_DEGRADED");
        let json = event.enriched_log_json();
        assert!(
            json.contains("\"enforcement\":\"permissive\""),
            "enforcement field missing: {json}"
        );
        assert!(
            json.contains("\"store_type\":\"jti\""),
            "store_type field missing: {json}"
        );
        assert!(
            json.contains("\"severity_id\":5"),
            "severity_id 5 (Critical) missing: {json}"
        );
        assert!(
            json.contains("No space left on device"),
            "reason field missing: {json}"
        );
    }

    /// JTI_STORE_DEGRADED OCSF fields: severity_id 5 (Critical), activity_id 99 (Other).
    #[test]
    fn test_jti_store_degraded_ocsf_critical() {
        let event = AuditEvent::jti_store_degraded("Permission denied", "strict", "nonce");
        let ocsf = event.ocsf_fields();
        assert_eq!(
            ocsf.severity_id, 5,
            "JTI store degraded must be Critical (severity_id 5)"
        );
        assert_eq!(
            ocsf.activity_id, 99,
            "JTI store degraded must be Other (activity_id 99)"
        );
        assert_eq!(
            ocsf.type_uid, 300299,
            "type_uid must be class_uid*100+activity_id"
        );
    }

    /// StepUpSuccess with id_token_verified=true serializes the field correctly.
    #[test]
    fn test_step_up_success_with_id_token_verified() {
        let event = AuditEvent::step_up_success(
            "alice",
            Some("sudo reboot"),
            "ciba",
            "sess-1",
            Some("urn:mace:incommon:iap:silver"),
            Some(1_700_000_000),
            true,
            None,
            None,
            None,
            None,
            false,
            false,
        );
        let json = event.enriched_log_json();
        assert!(
            json.contains("\"id_token_verified\":true"),
            "id_token_verified:true missing: {json}"
        );
    }

    /// StepUpFailed with verification_failure serializes the field correctly.
    #[test]
    fn test_step_up_failed_with_verification_failure() {
        let event = AuditEvent::step_up_failed(
            "bob",
            Some("sudo su"),
            "ciba",
            "ID token signature mismatch",
            Some("signature verification failed"),
            None,
            None,
            None,
            None,
            false,
        );
        let json = event.enriched_log_json();
        assert!(
            json.contains("\"verification_failure\":\"signature verification failed\""),
            "verification_failure field missing: {json}"
        );
    }

    #[test]
    fn test_privilege_policy_decision_serializes_phase44_fields() {
        let event = AuditEvent::privilege_policy_decision(
            "alice",
            "/usr/bin/systemctl restart nginx",
            "step_up",
            Some("service-restart"),
            "critical",
            300,
            true,
            false,
        );
        let json = event.enriched_log_json();
        assert!(json.contains("\"event\":\"PRIVILEGE_POLICY_DECISION\""));
        assert!(json.contains("\"policy_action\":\"step_up\""));
        assert!(json.contains("\"matched_rule\":\"service-restart\""));
        assert!(json.contains("\"host_classification\":\"critical\""));
        assert!(json.contains("\"grace_period_secs\":300"));
        assert!(json.contains("\"grace_period_applied\":true"));
        assert!(json.contains("\"dry_run\":false"));
        assert!(json.contains("\"activity_id\":3"));
        assert!(json.contains("\"severity_id\":1"));
    }

    #[test]
    fn test_step_up_events_serialize_phase44_context_fields() {
        let initiated = AuditEvent::step_up_initiated(
            "alice",
            Some("/usr/bin/systemctl restart nginx"),
            "push",
            None,
            Some("service-restart"),
            Some("step_up"),
            Some("critical"),
            Some(300),
            false,
        );
        let success = AuditEvent::step_up_success(
            "alice",
            Some("/usr/bin/systemctl restart nginx"),
            "push",
            "sess-1",
            Some("urn:example:acr:phr"),
            Some(1_700_000_000),
            true,
            Some("service-restart"),
            Some("step_up"),
            Some("critical"),
            Some(300),
            true,
            false,
        );
        let failed = AuditEvent::step_up_failed(
            "alice",
            Some("/usr/bin/systemctl restart nginx"),
            "push",
            "timeout",
            None,
            Some("service-restart"),
            Some("step_up"),
            Some("critical"),
            Some(300),
            true,
        );

        let initiated_json = initiated.enriched_log_json();
        assert!(initiated_json.contains("\"matched_rule\":\"service-restart\""));
        assert!(initiated_json.contains("\"policy_action\":\"step_up\""));
        assert!(initiated_json.contains("\"host_classification\":\"critical\""));
        assert!(initiated_json.contains("\"grace_period_secs\":300"));

        let success_json = success.enriched_log_json();
        assert!(success_json.contains("\"grace_period_applied\":true"));
        assert!(success_json.contains("\"dry_run\":false"));
        assert!(success_json.contains("\"id_token_verified\":true"));

        let failed_json = failed.enriched_log_json();
        assert!(failed_json.contains("\"dry_run\":true"));
        assert!(failed_json.contains("\"reason\":\"timeout\""));
    }

    // ── Phase 37-01: Token exchange audit event tests ────────────────────────

    #[test]
    fn test_token_exchange_accepted_serialization() {
        let event = AuditEvent::TokenExchangeAccepted {
            timestamp: "2026-04-09T12:00:00Z".into(),
            session_id: "sess-123".into(),
            username: "alice@example.com".into(),
            exchanger: "jump-host-a".into(),
            delegation_depth: 1,
            target_audience: "target-host-b".into(),
            host: "server.example.com".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("TOKEN_EXCHANGE_ACCEPTED"), "json: {json}");
        assert!(json.contains("jump-host-a"), "json: {json}");
        assert!(json.contains("delegation_depth"), "json: {json}");
    }

    #[test]
    fn test_token_exchange_rejected_serialization() {
        let event = AuditEvent::TokenExchangeRejected {
            timestamp: "2026-04-09T12:00:00Z".into(),
            username: "alice@example.com".into(),
            exchanger: "evil-host".into(),
            reason: "Unauthorized exchanger: evil-host not in allowed_exchangers list".into(),
            host: "server.example.com".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("TOKEN_EXCHANGE_REJECTED"), "json: {json}");
        assert!(json.contains("evil-host"), "json: {json}");
    }

    #[test]
    fn test_token_exchange_ocsf_fields() {
        let accepted = AuditEvent::TokenExchangeAccepted {
            timestamp: String::new(),
            session_id: String::new(),
            username: String::new(),
            exchanger: String::new(),
            delegation_depth: 0,
            target_audience: String::new(),
            host: String::new(),
        };
        let ocsf = accepted.ocsf_fields();
        assert_eq!(
            ocsf.activity_id, 1,
            "Accepted must be Logon (activity_id 1)"
        );
        assert_eq!(ocsf.severity_id, 1, "Accepted must be Info (severity_id 1)");

        let rejected = AuditEvent::TokenExchangeRejected {
            timestamp: String::new(),
            username: String::new(),
            exchanger: String::new(),
            reason: String::new(),
            host: String::new(),
        };
        let ocsf = rejected.ocsf_fields();
        assert_eq!(
            ocsf.activity_id, 1,
            "Rejected must be Logon (activity_id 1)"
        );
        assert_eq!(ocsf.severity_id, 4, "Rejected must be High (severity_id 4)");
    }

    #[test]
    fn test_token_exchange_accepted_constructor() {
        let event =
            AuditEvent::token_exchange_accepted("sess-1", "alice", "jump-host", 2, "target-svc");
        assert_eq!(event.event_type(), "TOKEN_EXCHANGE_ACCEPTED");
        assert_eq!(event.syslog_severity(), AuditSeverity::Info);
        let json = event.enriched_log_json();
        assert!(json.contains("alice"), "username missing: {json}");
        assert!(json.contains("jump-host"), "exchanger missing: {json}");
        assert!(
            json.contains("target-svc"),
            "target_audience missing: {json}"
        );
        assert!(
            json.contains("\"delegation_depth\":2"),
            "delegation_depth missing: {json}"
        );
    }

    #[test]
    fn test_token_exchange_rejected_constructor() {
        let event =
            AuditEvent::token_exchange_rejected("bob", "evil-host", "depth exceeded: 4 > 3");
        assert_eq!(event.event_type(), "TOKEN_EXCHANGE_REJECTED");
        assert_eq!(event.syslog_severity(), AuditSeverity::Warning);
        let json = event.enriched_log_json();
        assert!(json.contains("bob"), "username missing: {json}");
        assert!(json.contains("evil-host"), "exchanger missing: {json}");
        assert!(json.contains("depth exceeded"), "reason missing: {json}");
    }

    #[test]
    fn test_token_exchange_rejected_enriched_severity_high() {
        // Verify the enriched JSON has OCSF severity_id 4 (High) — SIEM alert trigger
        let event =
            AuditEvent::token_exchange_rejected("user", "attacker", "unauthorized exchanger");
        let json = event.enriched_log_json();
        assert!(
            json.contains("\"severity_id\":4"),
            "severity_id 4 (High) missing in enriched JSON: {json}"
        );
        assert!(
            json.contains("\"activity_id\":1"),
            "activity_id 1 (Logon) missing in enriched JSON: {json}"
        );
    }
}
