//! Policy configuration types and loading.
//!
//! Uses figment (layered configuration) for YAML + environment-variable overrides.
//! Environment variable override pattern: UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT
//! (double-underscore maps to nested struct fields per figment's `split("__")`).

use figment::{
    providers::{Env, Format, Serialized, Yaml},
    Figment,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use thiserror::Error;

use super::rules::StepUpMethod;
use crate::audit::AuditEvent;

// ── HTTPS URL validation (SHRD-04) ─────────────────────────────────────────

/// Validate that a URL uses the HTTPS scheme.
///
/// Security: All OIDC issuer URLs and device flow verification URIs must use
/// HTTPS to prevent credential interception. HTTP URLs are only permitted
/// in test-mode builds when `allow_insecure_http_for_testing` is true.
///
/// `field_name` is included in the error message for operator clarity.
///
/// Returns `Ok(())` if the URL starts with `https://` and is non-empty.
/// Returns `Err(String)` with a descriptive message otherwise.
pub fn validate_https_url(url: &str, field_name: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err(format!("{field_name}: URL must not be empty"));
    }
    if url.starts_with("https://") {
        Ok(())
    } else if url.starts_with("http://") {
        Err(format!(
            "{field_name}: HTTPS required but got HTTP URL (scheme 'http://'). \
             All OIDC endpoints must use TLS. URL: {url}"
        ))
    } else {
        // Extract the scheme portion for the error message (up to "://")
        let scheme = url.split("://").next().unwrap_or("unknown");
        Err(format!(
            "{field_name}: HTTPS required but got unsupported scheme '{scheme}://'. URL: {url}"
        ))
    }
}

/// Check if test mode is explicitly enabled.
/// Security: Only accepts explicit "true" or "1" values, not just presence of the variable.
fn is_test_mode_enabled() -> bool {
    std::env::var("UNIX_OIDC_TEST_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Failed to read policy file: {0}")]
    ReadError(#[from] std::io::Error),

    /// Returned when the config file cannot be parsed or a field value is invalid.
    /// Changed from `#[from] serde_yaml::Error` to `String` because figment errors
    /// are not serde_yaml errors — figment provides its own error type.
    #[error("Failed to parse policy: {0}")]
    ParseError(String),

    #[error("Policy file not found: {0}")]
    NotFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

// ── Enforcement mode ─────────────────────────────────────────────────────────

/// Enforcement level for configurable security checks (Issue #10).
///
/// - `strict`   — reject the authentication attempt when the check fails
/// - `warn`     — log a warning and allow authentication to proceed (v1.0 default for most checks)
/// - `disabled` — skip the check entirely (not recommended for production)
///
/// Invalid strings cause a [`PolicyError::ParseError`] at config-load time so that
/// operator typos (e.g. `"strct"`) are never silently treated as `warn`.
///
/// Serde impls are hand-rolled (not derived) so that:
/// - `Deserialize` rejects unknown strings with an error rather than falling
///   back silently (no `#[serde(other)]`).
/// - `Serialize` round-trips identically to the lowercase YAML representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    Strict,
    #[default]
    Warn,
    Disabled,
}

impl serde::Serialize for EnforcementMode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            EnforcementMode::Strict => "strict",
            EnforcementMode::Warn => "warn",
            EnforcementMode::Disabled => "disabled",
        })
    }
}

impl<'de> serde::de::Deserialize<'de> for EnforcementMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = EnforcementMode;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(r#"one of "strict", "warn", or "disabled""#)
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<EnforcementMode, E> {
                match v {
                    "strict" => Ok(EnforcementMode::Strict),
                    "warn" => Ok(EnforcementMode::Warn),
                    "disabled" => Ok(EnforcementMode::Disabled),
                    other => Err(E::unknown_variant(other, &["strict", "warn", "disabled"])),
                }
            }
        }
        d.deserialize_str(Visitor)
    }
}

// ── ACR configuration ─────────────────────────────────────────────────────────

/// Authentication Context Reference (ACR) enforcement configuration.
#[derive(Debug, Clone, Serialize)]
#[serde(default)]
pub struct AcrConfig {
    /// How strictly to enforce ACR *presence* (whether the token has any `acr`
    /// claim at all). Default: `Warn` — log if absent but allow authentication.
    /// This does NOT control `required_acr` behavior, which is always hard-fail.
    pub enforcement: EnforcementMode,
    /// Minimum required ACR level string, e.g. `"urn:example:acr:mfa"`. Default: `None`.
    pub minimum_level: Option<String>,
}

impl Default for AcrConfig {
    fn default() -> Self {
        Self {
            enforcement: EnforcementMode::Warn,
            minimum_level: None,
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for AcrConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(default)]
        struct Raw {
            enforcement: EnforcementMode,
            minimum_level: Option<String>,
        }
        impl Default for Raw {
            fn default() -> Self {
                Self {
                    enforcement: EnforcementMode::Warn,
                    minimum_level: None,
                }
            }
        }
        let r = Raw::deserialize(d)?;
        Ok(AcrConfig {
            enforcement: r.enforcement,
            minimum_level: r.minimum_level,
        })
    }
}

// ── Identity configuration ────────────────────────────────────────────────────

/// Transform specification for the username mapping pipeline.
///
/// Supports two deserialization forms:
/// - Shorthand string: `"strip_domain"` or `"lowercase"`
/// - Object form: `{ type: "regex", pattern: "^corp-(?P<username>[a-z0-9]+)" }`
///
/// The object form is required for the `regex` transform to supply the pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransformConfig {
    /// Shorthand form: `"strip_domain"` or `"lowercase"`.
    Simple(String),
    /// Object form for parameterised transforms (currently only `regex`).
    Object {
        #[serde(rename = "type")]
        r#type: String,
        pattern: String,
    },
}

/// Username claim extraction and transform pipeline configuration.
///
/// Deserialised from the `identity:` section of `policy.yaml`.
///
/// ```yaml
/// identity:
///   username_claim: email
///   transforms:
///     - strip_domain
///     - lowercase
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    /// OIDC claim to extract as the raw username. Default: `preferred_username`.
    pub username_claim: String,
    /// Ordered sequence of transforms applied to the raw claim value.
    /// Default: empty (no transforms — use claim value as-is).
    pub transforms: Vec<TransformConfig>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            username_claim: "preferred_username".to_string(),
            transforms: Vec::new(),
        }
    }
}

// ── SPIFFE username mapping (Phase 35) ────────────────────────────────────────

/// SPIFFE ID → Unix username mapping strategy.
///
/// When an issuer is a SPIRE OIDC Discovery Provider and the `sub` claim
/// contains a SPIFFE ID (`spiffe://trust-domain/path/segments`), this config
/// controls how the SPIFFE ID is mapped to a Unix username.
///
/// Three strategies are supported, evaluated in priority order:
/// 1. `static_map` — explicit SPIFFE ID → username table (highest priority)
/// 2. `regex` — regex with `(?P<username>...)` capture group
/// 3. `path_suffix` — last path segment of the SPIFFE ID (default)
///
/// ```yaml
/// issuers:
///   - issuer_url: "https://spire.example.com"
///     spiffe_mapping:
///       strategy: path_suffix          # or "regex" or "static_map"
///       # For regex strategy:
///       # pattern: "spiffe://[^/]+/ns/[^/]+/sa/(?P<username>[a-z0-9-]+)"
///       # For static_map strategy:
///       # mappings:
///       #   "spiffe://td/ns/prod/sa/ml-agent": "ml-agent"
///       #   "spiffe://td/ns/prod/sa/etl-worker": "etl"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SpiffeMappingConfig {
    /// Mapping strategy: `"path_suffix"`, `"regex"`, or `"static_map"`.
    /// Default: `"path_suffix"`.
    pub strategy: String,

    /// Regex pattern with `(?P<username>...)` capture group.
    /// Required when `strategy` is `"regex"`.
    pub pattern: Option<String>,

    /// Explicit SPIFFE ID → username mappings.
    /// Used when `strategy` is `"static_map"`.
    pub mappings: HashMap<String, String>,
}

impl Default for SpiffeMappingConfig {
    fn default() -> Self {
        Self {
            strategy: "path_suffix".to_string(),
            pattern: None,
            mappings: HashMap::new(),
        }
    }
}

// ── Multi-issuer configuration (Phase 21, MIDP-01..05, MIDP-08) ──────────────

/// ACR claim mapping configuration for a specific issuer.
///
/// Maps IdP-specific ACR values to normalized values and specifies enforcement
/// mode for authentication context requirements.
///
/// Used in `IssuerConfig.acr_mapping` (MIDP-03).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AcrMappingConfig {
    /// Map of IdP-specific ACR value → normalized ACR value.
    /// E.g. `{"urn:idp:mfa": "urn:unix-oidc:acr:mfa"}`.
    pub mappings: HashMap<String, String>,
    /// How to enforce ACR *presence* on tokens from this issuer. Default: `Warn`
    /// — log if absent but allow. This does NOT control `required_acr` behavior.
    pub enforcement: EnforcementMode,
    /// The ACR value the operator requires tokens to have (after mapping).
    /// When set, tokens must carry an `acr` claim matching this value
    /// (or an IdP-specific value that maps to it via `mappings`).
    /// **Hard-fail**: tokens without a matching `acr` are always rejected (ADR-012).
    pub required_acr: Option<String>,
}

/// Source of truth for group membership resolution (MIDP-04, ADR-008).
///
/// Only `NssOnly` is supported. Groups are always resolved from NSS/SSSD
/// (FreeIPA/LDAP), never from OIDC token claims. A `TokenClaim` variant
/// existed prior to DEBT-03 (Phase 26) and was removed — deserializing
/// `"token_claim"` is a hard error.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupSource {
    /// Resolve groups from NSS/SSSD only. Default and only supported source.
    #[default]
    NssOnly,
}

/// Group membership mapping configuration for a specific issuer (MIDP-04).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GroupMappingConfig {
    /// Source for group membership. Default: `nss_only`.
    pub source: GroupSource,
    /// Token claim name used for audit enrichment only (see `TokenClaims::groups_for_audit`).
    /// Group authorization always uses NSS/SSSD (ADR-008). Default: `"groups"`.
    #[serde(default = "GroupMappingConfig::default_claim")]
    pub claim: String,
    /// Map of IdP group name → local NSS group name.
    /// Allows renaming/normalizing group names from the IdP.
    pub name_map: HashMap<String, String>,
}

impl GroupMappingConfig {
    fn default_claim() -> String {
        "groups".to_string()
    }
}

fn default_jwks_cache_ttl() -> u64 {
    300
}

fn default_http_timeout() -> u64 {
    10
}

fn default_recovery_interval() -> u64 {
    300
}

/// Per-issuer configuration bundle (MIDP-01, MIDP-02, MIDP-05).
///
/// Each entry in `PolicyConfig.issuers` defines an independent trusted OIDC issuer
/// with its own DPoP enforcement, claim mapping, ACR mapping, and group mapping.
///
/// Missing optional fields fall back to safe defaults (MIDP-08).
///
/// ```yaml
/// issuers:
///   - issuer_url: "https://keycloak.example.com/realms/corp"
///     client_id: "unix-oidc"
///     dpop_enforcement: strict
///   - issuer_url: "https://login.microsoftonline.com/tenant/v2.0"
///     client_id: "unix-oidc-entra"
///     dpop_enforcement: disabled
///     identity:
///       username_claim: email
///       transforms:
///         - strip_domain
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IssuerConfig {
    /// OIDC issuer URL (must match `iss` claim in tokens). Required.
    pub issuer_url: String,
    /// OAuth client ID for this issuer. Default: `"unix-oidc"`.
    pub client_id: String,
    /// OAuth client secret (confidential clients only). Optional.
    pub client_secret: Option<String>,
    /// DPoP (RFC 9449) token binding enforcement. Default: `strict`.
    ///
    /// Security: `strict` is the safe default. Only set to `disabled` for
    /// issuers that do not support DPoP (e.g. Entra ID which uses SHR instead).
    pub dpop_enforcement: EnforcementMode,
    /// Username claim extraction and transform pipeline for this issuer.
    /// Default: `IdentityConfig::default()` (uses `preferred_username`, no transforms).
    pub claim_mapping: IdentityConfig,
    /// ACR claim mapping for this issuer. Default: `None` (no mapping).
    /// When `required_acr` is set within, mismatched tokens are hard-rejected (ADR-012).
    pub acr_mapping: Option<AcrMappingConfig>,
    /// Group membership mapping for this issuer. Default: `None` (NSS-only, WARN logged).
    pub group_mapping: Option<GroupMappingConfig>,
    /// Optional audience URI override. When set, the token `aud` claim is validated against
    /// this value instead of `client_id`. Required when the Entra app registration exposes an
    /// Application ID URI (e.g. `api://unix-oidc`) that differs from the client ID GUID.
    /// Falls back to `client_id` if None (OIDC standard behavior).
    ///
    /// Security: This does not weaken audience validation — it simply allows the operator to
    /// specify the correct audience when IdP uses a different URI scheme than the client_id.
    #[serde(default)]
    pub expected_audience: Option<String>,
    /// When true, bypasses the collision-safety hard-fail for non-injective transform pipelines
    /// (strip_domain, regex). Use for single-tenant IdPs where the domain constraint is enforced
    /// by the IdP itself (e.g. Entra ID single-tenant app). Default: false (safe).
    ///
    /// Security: Setting this to true acknowledges that the transform pipeline is technically
    /// non-injective but safe in the operator's deployment context. A WARN is logged whenever
    /// this bypass is active. Only set this when you understand the injectivity trade-off and
    /// the IdP's domain constraint fully compensates for it.
    #[serde(default)]
    pub allow_unsafe_identity_pipeline: bool,
    /// SPIFFE ID → Unix username mapping for this issuer (Phase 35).
    ///
    /// When set, tokens with a `sub` claim starting with `spiffe://` use this
    /// mapping instead of `claim_mapping`. The SPIRE trust domain must be
    /// registered as a standard OIDC issuer via the SPIRE OIDC Discovery Provider.
    #[serde(default)]
    pub spiffe_mapping: Option<SpiffeMappingConfig>,

    /// Per-issuer algorithm allowlist for JWT validation (SHRD-01/02).
    ///
    /// When present, only these algorithms are accepted from tokens validated
    /// against this issuer's JWKS keys. When absent (`None`), the global
    /// `DEFAULT_ALLOWED_ALGORITHMS` list is used (all asymmetric signing algorithms).
    ///
    /// Values are JOSE algorithm name strings: "RS256", "ES256", "EdDSA", etc.
    /// Symmetric algorithms (HS256/384/512) are never permitted regardless of this setting.
    ///
    /// Example YAML:
    /// ```yaml
    /// issuers:
    ///   - issuer_url: "https://idp.example.com/realms/corp"
    ///     allowed_algorithms:
    ///       - ES256
    ///       - RS256
    /// ```
    #[serde(default)]
    pub allowed_algorithms: Option<Vec<String>>,
    /// JWKS cache TTL in seconds for this issuer (DEBT-05).
    /// Controls how long cached JWKS keys are considered valid before re-fetching.
    /// Default: 300 (5 minutes).
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl_secs: u64,
    /// HTTP timeout in seconds for JWKS endpoint requests for this issuer (DEBT-05).
    /// Default: 10 seconds.
    #[serde(default = "default_http_timeout")]
    pub http_timeout_secs: u64,
    /// Recovery interval in seconds after an issuer is marked degraded (MIDP-10).
    ///
    /// When an issuer has been marked degraded (3+ consecutive JWKS fetch failures),
    /// authentication attempts skip this issuer until `recovery_interval_secs` have
    /// elapsed since the last failure. After the interval, a retry is attempted.
    /// A successful retry clears the degraded flag. Default: 300 (5 minutes).
    #[serde(default = "default_recovery_interval")]
    pub recovery_interval_secs: u64,
    /// Allow HTTP (non-TLS) issuer URLs for local testing only (SHRD-04).
    ///
    /// This field only exists in test-mode builds. When `true`, the HTTPS
    /// check in `load_from()` is skipped for this issuer and a CRITICAL-severity
    /// audit warning is emitted.
    ///
    /// Production binaries (built without `--features test-mode`) cannot parse
    /// this field — it does not exist in the struct.
    #[cfg(any(test, feature = "test-mode"))]
    #[serde(default)]
    pub allow_insecure_http_for_testing: bool,
}

impl Default for IssuerConfig {
    fn default() -> Self {
        Self {
            issuer_url: String::new(),
            client_id: "unix-oidc".to_string(),
            client_secret: None,
            dpop_enforcement: EnforcementMode::Strict,
            claim_mapping: IdentityConfig::default(),
            acr_mapping: None,
            group_mapping: None,
            expected_audience: None,
            allow_unsafe_identity_pipeline: false,
            allowed_algorithms: None,
            jwks_cache_ttl_secs: default_jwks_cache_ttl(),
            http_timeout_secs: default_http_timeout(),
            spiffe_mapping: None,
            recovery_interval_secs: default_recovery_interval(),
            #[cfg(any(test, feature = "test-mode"))]
            allow_insecure_http_for_testing: false,
        }
    }
}

// ── Issuer health monitoring (MIDP-10) ───────────────────────────────────────

/// Health state for a single OIDC issuer.
///
/// Persisted to disk (`/run/unix-oidc/issuer-health/<sha256-prefix>.json`) so that
/// health state survives across forked sshd processes (no shared memory in PAM).
///
/// `degraded` is set when `failure_count >= 3`. `last_failure` records the Unix
/// timestamp of the most recent failure — used to compute whether the recovery
/// interval has elapsed.
///
/// Fields are public so tests can inspect them directly.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IssuerHealthState {
    /// Number of consecutive JWKS fetch failures.
    pub failure_count: u32,
    /// Unix timestamp (seconds since epoch) of the last failure. `None` = no failures yet.
    pub last_failure: Option<i64>,
    /// `true` when `failure_count >= 3`.
    pub degraded: bool,
}

/// Number of consecutive JWKS fetch failures before an issuer is marked degraded.
const DEGRADATION_THRESHOLD: u32 = 3;

/// Manages file-backed health state for each configured OIDC issuer.
///
/// All operations are best-effort: I/O failures are logged at WARN and never
/// block authentication. This is intentional — the health tracking subsystem
/// must not become a second point of failure during IdP outages.
///
/// The health directory is configurable via `UNIX_OIDC_HEALTH_DIR` for testing,
/// defaulting to `/run/unix-oidc/issuer-health/`.
///
/// File naming: SHA-256 of the issuer URL, first 16 hex characters + `.json`.
/// Using a fixed-length hash avoids path issues with URL characters (colons,
/// slashes) while keeping filenames short and deterministic.
pub struct IssuerHealthManager {
    /// Directory where health state files are stored.
    health_dir: PathBuf,
}

impl IssuerHealthManager {
    /// Create a new `IssuerHealthManager`.
    ///
    /// The health directory is resolved from `UNIX_OIDC_HEALTH_DIR` env var
    /// (for testing) or defaults to `/run/unix-oidc/issuer-health/`.
    pub fn new() -> Self {
        let health_dir = std::env::var("UNIX_OIDC_HEALTH_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/run/unix-oidc/issuer-health"));
        Self { health_dir }
    }

    /// Compute the file path for a given issuer URL's health state.
    ///
    /// Uses SHA-256 of the URL, first 16 hex chars, to produce a short
    /// filesystem-safe name.
    pub fn health_file_path(&self, issuer_url: &str) -> PathBuf {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(issuer_url.as_bytes());
        // Format as hex, take first 16 chars (8 bytes).
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        let short = &hex[..16.min(hex.len())];
        self.health_dir.join(format!("{short}.json"))
    }

    /// Load the health state for an issuer from disk.
    ///
    /// Returns a healthy default state on any I/O or parse error.
    /// A WARN is logged when the file exists but cannot be parsed (corrupt file).
    fn load(&self, issuer_url: &str) -> IssuerHealthState {
        let path = self.health_file_path(issuer_url);
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<IssuerHealthState>(&bytes) {
                Ok(state) => state,
                Err(e) => {
                    tracing::warn!(
                        issuer = %issuer_url,
                        path = %path.display(),
                        error = %e,
                        "Corrupt issuer health state file — treating issuer as healthy"
                    );
                    IssuerHealthState::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No state file yet — treat as healthy.
                IssuerHealthState::default()
            }
            Err(e) => {
                tracing::warn!(
                    issuer = %issuer_url,
                    path = %path.display(),
                    error = %e,
                    "Could not read issuer health state file — treating issuer as healthy"
                );
                IssuerHealthState::default()
            }
        }
    }

    /// Persist the health state for an issuer to disk atomically.
    ///
    /// Writes to a temporary file first, then renames to the target path.
    /// On failure, logs WARN and continues — health tracking is best-effort.
    fn save(&self, issuer_url: &str, state: &IssuerHealthState) {
        let path = self.health_file_path(issuer_url);
        // Ensure the directory exists.
        if let Err(e) = std::fs::create_dir_all(&self.health_dir) {
            tracing::warn!(
                dir = %self.health_dir.display(),
                error = %e,
                "Could not create issuer health directory"
            );
            return;
        }
        // Serialize state.
        let json = match serde_json::to_string(state) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(issuer = %issuer_url, error = %e, "Could not serialize issuer health state");
                return;
            }
        };
        // Atomic write: write to tmp file, then rename.
        let tmp_path = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp_path, json.as_bytes()) {
            tracing::warn!(
                issuer = %issuer_url,
                path = %tmp_path.display(),
                error = %e,
                "Could not write issuer health state tmp file"
            );
            return;
        }
        if let Err(e) = std::fs::rename(&tmp_path, &path) {
            tracing::warn!(
                issuer = %issuer_url,
                path = %path.display(),
                error = %e,
                "Could not atomically rename issuer health state file"
            );
            // Best-effort: clean up the tmp file.
            let _ = std::fs::remove_file(&tmp_path);
        }
    }

    /// Record a JWKS fetch failure for an issuer.
    ///
    /// Increments `failure_count` and sets `degraded = true` once the count
    /// reaches `DEGRADATION_THRESHOLD` (3).
    pub fn record_failure(&self, issuer_url: &str) {
        let mut state = self.load(issuer_url);
        state.failure_count = state.failure_count.saturating_add(1);
        state.last_failure = Some(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        );
        let was_degraded = state.degraded;
        if state.failure_count >= DEGRADATION_THRESHOLD {
            state.degraded = true;
        }
        // Emit ISSUER_DEGRADED audit event on the first transition to degraded.
        // Route through AuditEvent::log() so the event receives OCSF enrichment
        // and is included in the HMAC tamper-evidence chain (OBS-06, OBS-07).
        // failure_count is cast to u8; DEGRADATION_THRESHOLD is 3, well within range.
        if state.degraded && !was_degraded {
            #[allow(clippy::cast_possible_truncation)]
            AuditEvent::issuer_degraded(issuer_url, state.failure_count as u8).log();
        }
        tracing::warn!(
            issuer = %issuer_url,
            failure_count = state.failure_count,
            degraded = state.degraded,
            "Recorded JWKS fetch failure for issuer"
        );
        self.save(issuer_url, &state);
    }

    /// Record a successful JWKS fetch for an issuer.
    ///
    /// Resets `failure_count` to 0 and clears the `degraded` flag.
    pub fn record_success(&self, issuer_url: &str) {
        let mut state = self.load(issuer_url);
        let was_degraded = state.degraded;
        state.failure_count = 0;
        state.last_failure = None;
        state.degraded = false;
        // Emit ISSUER_RECOVERED audit event when transitioning from degraded.
        // Route through AuditEvent::log() for OCSF enrichment and HMAC chain
        // coverage (OBS-06, OBS-07). This matches all other 14 audit event types.
        if was_degraded {
            AuditEvent::issuer_recovered(issuer_url).log();
        }
        self.save(issuer_url, &state);
    }

    /// Check whether an issuer is currently degraded and within its recovery interval.
    ///
    /// Returns `true` (degraded, skip this issuer) only when BOTH conditions hold:
    /// 1. `state.degraded == true`
    /// 2. Less than `recovery_interval_secs` have elapsed since `last_failure`
    ///
    /// When the recovery interval has elapsed, returns `false` so the issuer is
    /// retried — a successful retry will call `record_success()` which clears the
    /// degraded state.
    pub fn is_degraded(&self, issuer_url: &str, recovery_interval_secs: u64) -> bool {
        let state = self.load(issuer_url);
        if !state.degraded {
            return false;
        }
        // If recovery_interval_secs == 0, always allow retry.
        if recovery_interval_secs == 0 {
            return false;
        }
        match state.last_failure {
            None => false, // degraded but no timestamp — allow retry
            Some(last_failure_ts) => {
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let elapsed = (now - last_failure_ts).max(0) as u64;
                elapsed < recovery_interval_secs
            }
        }
    }
}

impl Default for IssuerHealthManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Config hot-reload (MIDP-11) ──────────────────────────────────────────────

/// Cached policy configuration with the file mtime used for staleness detection.
struct ConfigCache {
    config: PolicyConfig,
    mtime: SystemTime,
    path: PathBuf,
}

/// Module-level config cache for hot-reload support (MIDP-11).
///
/// Each forked sshd process holds its own cache. On each `pam_sm_authenticate`
/// call, `load_fresh()` stats the config file and re-parses only when the mtime
/// changed. This avoids repeated YAML parses while detecting operator edits
/// without a daemon restart.
///
/// Protected by a `Mutex` because PAM modules can be called from multiple
/// threads within a single process (some SSH implementations use threading).
static CONFIG_CACHE: Lazy<Mutex<Option<ConfigCache>>> = Lazy::new(|| Mutex::new(None));

// ── Security modes ────────────────────────────────────────────────────────────

/// Configurable enforcement modes for security checks (Issue #10).
///
/// When the `security_modes` section is absent from `policy.yaml`, this struct
/// is not instantiated — `PolicyConfig::security_modes` will be `None`.  Call
/// [`PolicyConfig::effective_security_modes`] to get the correct defaults in
/// both the v1.0 and v2.0 cases.
///
/// ## Breaking change in v3.0 (Phase 30)
///
/// `jti_enforcement` default changed from `warn` to `strict` (D-06).
/// Operators who relied on the implicit `warn` default must add an explicit
/// `jti_enforcement: warn` to their `policy.yaml` to preserve the old behavior.
/// Strict mode hard-rejects authentication when the filesystem store returns
/// `IoError` (T-30-03 — disk full maps to authentication failure, not bypass).
#[derive(Debug, Clone, Serialize)]
#[serde(default)]
pub struct SecurityModes {
    /// JTI replay-prevention enforcement. Default: `strict` (D-06).
    ///
    /// **Breaking change from v2.x**: was `warn`; now `strict` for new deployments.
    /// In `strict` mode a missing JTI claim or a filesystem error in the JTI store
    /// causes hard authentication failure.  Set to `warn` to restore the previous
    /// behavior for IdPs that do not issue JTI claims.
    pub jti_enforcement: EnforcementMode,
    /// DPoP token binding enforcement. Default: `strict` (binding is critical).
    pub dpop_required: EnforcementMode,
    /// AMR (Authentication Methods References) claim enforcement. Default: `disabled`.
    pub amr_enforcement: EnforcementMode,
    /// ACR (Authentication Context Reference) configuration.
    pub acr: AcrConfig,
    /// NSS group membership enforcement. Default: `warn`.
    /// - `strict`: deny login if NSS group lookup fails or user not in allowed groups.
    /// - `warn`: log a warning but allow login if NSS lookup fails.
    /// - `disabled`: skip group membership check entirely.
    pub groups_enforcement: EnforcementMode,
    /// Whether CIBA step-up authentication requires a raw ID token for PAM-side
    /// cryptographic validation.  Default: `true` (D-16).
    ///
    /// When `true` the PAM module requires the agent to pass the full signed ID
    /// token so it can verify the signature, ACR, and AMR claims locally.
    ///
    /// When `false` the PAM module falls back to trusting agent-asserted ACR
    /// values without cryptographic verification.  This is a security downgrade —
    /// a `LOG_CRIT` is emitted on every step-up that uses the fallback path.
    /// Set to `false` only when integrating with legacy CIBA agents that cannot
    /// forward the raw ID token.
    pub step_up_require_id_token: bool,
}

/// Helper for serde default: returns `true`.
fn default_true() -> bool {
    true
}

impl Default for SecurityModes {
    fn default() -> Self {
        Self {
            jti_enforcement: EnforcementMode::Strict,
            dpop_required: EnforcementMode::Strict,
            amr_enforcement: EnforcementMode::Disabled,
            acr: AcrConfig::default(),
            groups_enforcement: EnforcementMode::Warn,
            step_up_require_id_token: true,
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for SecurityModes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(default)]
        struct Raw {
            jti_enforcement: EnforcementMode,
            dpop_required: EnforcementMode,
            amr_enforcement: EnforcementMode,
            acr: AcrConfig,
            groups_enforcement: EnforcementMode,
            #[serde(default = "default_true")]
            step_up_require_id_token: bool,
        }
        impl Default for Raw {
            fn default() -> Self {
                let s = SecurityModes::default();
                Self {
                    jti_enforcement: s.jti_enforcement,
                    dpop_required: s.dpop_required,
                    amr_enforcement: s.amr_enforcement,
                    acr: s.acr,
                    groups_enforcement: s.groups_enforcement,
                    step_up_require_id_token: s.step_up_require_id_token,
                }
            }
        }
        let r = Raw::deserialize(d)?;
        Ok(SecurityModes {
            jti_enforcement: r.jti_enforcement,
            dpop_required: r.dpop_required,
            amr_enforcement: r.amr_enforcement,
            acr: r.acr,
            groups_enforcement: r.groups_enforcement,
            step_up_require_id_token: r.step_up_require_id_token,
        })
    }
}

// ── Introspection configuration ───────────────────────────────────────────────

/// Token introspection configuration (RFC 7662).
///
/// When `enabled` is true, the PAM module can verify token validity via the
/// introspection endpoint in addition to (or instead of) local JWT validation.
/// Defaults to disabled — Phase 09 Plan 02 adds the actual introspection client.
///
/// Deserialised from the `introspection:` section of `policy.yaml`.
///
/// ```yaml
/// introspection:
///   enabled: true
///   endpoint: "https://idp.example.com/protocol/openid-connect/token/introspect"
///   enforcement: warn
///   cache_ttl_secs: 30
///   client_secret: "s3cr3t"  # optional; used for Basic Auth per RFC 7662 §2.1
/// ```
#[derive(Debug, Clone, Serialize)]
#[serde(default)]
pub struct IntrospectionConfig {
    /// Enable RFC 7662 token introspection. Default: `false`.
    pub enabled: bool,
    /// Introspection endpoint URL. Required when `enabled = true`.
    pub endpoint: Option<String>,
    /// What to do when introspection returns `active: false` or errors.
    /// - `strict`: deny authentication
    /// - `warn`: log and allow
    /// - `disabled`: skip introspection result (no-op)
    ///   Default: `warn` (Phase 02 will harden to `strict` for new deployments).
    pub enforcement: EnforcementMode,
    /// How long (in seconds) to cache a positive introspection result.
    /// Default: 60 seconds.
    pub cache_ttl_secs: u64,
    /// OAuth client secret for HTTP Basic Auth to the introspection endpoint.
    ///
    /// RFC 7662 §2.1 requires the introspection endpoint to authenticate the caller.
    /// Many IdPs accept client_id-only (public client) or require client_id+client_secret
    /// (confidential client). When absent, only client_id is sent in Basic Auth.
    ///
    /// Security: treat as a secret credential. Do not log this value.
    pub client_secret: Option<String>,
}

impl Default for IntrospectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            enforcement: EnforcementMode::Warn,
            cache_ttl_secs: 60,
            client_secret: None,
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for IntrospectionConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(default)]
        struct Raw {
            enabled: bool,
            endpoint: Option<String>,
            enforcement: EnforcementMode,
            cache_ttl_secs: u64,
            client_secret: Option<String>,
        }
        impl Default for Raw {
            fn default() -> Self {
                let c = IntrospectionConfig::default();
                Self {
                    enabled: c.enabled,
                    endpoint: c.endpoint,
                    enforcement: c.enforcement,
                    cache_ttl_secs: c.cache_ttl_secs,
                    client_secret: c.client_secret,
                }
            }
        }
        let r = Raw::deserialize(d)?;
        Ok(IntrospectionConfig {
            enabled: r.enabled,
            endpoint: r.endpoint,
            enforcement: r.enforcement,
            cache_ttl_secs: r.cache_ttl_secs,
            client_secret: r.client_secret,
        })
    }
}

// ── Session configuration ─────────────────────────────────────────────────────

/// Session lifecycle configuration.
///
/// Controls where session records are written and token-refresh thresholds.
/// Deserialised from the `session:` section of `policy.yaml`.
///
/// ```yaml
/// session:
///   session_dir: "/run/unix-oidc/sessions"
///   token_refresh_threshold_percent: 80
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    /// Filesystem directory where session records are stored.
    /// Should be a tmpfs mount so records are automatically cleared on reboot.
    /// Default: `/run/unix-oidc/sessions`.
    pub session_dir: String,
    /// Percentage of token lifetime at which the agent should attempt token refresh.
    /// E.g. 80 means "refresh when 80% of the token's lifetime has elapsed".
    /// Default: 80 (%).
    pub token_refresh_threshold_percent: u8,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session_dir: "/run/unix-oidc/sessions".to_string(),
            token_refresh_threshold_percent: 80,
        }
    }
}

// ── Cache configuration ───────────────────────────────────────────────────────

/// Operational tuning for caches (JTI replay cache, DPoP nonce cache, etc.).
///
/// Separate from `SecurityModes` because changing cache sizes is operational
/// tuning, not a security-policy change.
#[derive(Debug, Clone, Serialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Maximum number of JTI entries in the replay-prevention cache.
    /// See CLAUDE.md §JWKS Caching Security. Default: 100,000.
    pub jti_max_entries: usize,
    /// How often (in seconds) expired JTI entries are swept from the cache.
    /// Default: 300 seconds (5 minutes).
    pub jti_cleanup_interval_secs: u64,
    /// Maximum number of outstanding (unconsumed) DPoP nonces in the nonce cache.
    /// Each issued nonce occupies one entry until consumed or TTL-expired.
    /// Default: 100,000 (matches RFC 9449 §8 operational guidance).
    pub nonce_max_entries: u64,
    /// Time-to-live for issued DPoP nonces, in seconds.
    /// An unconsumed nonce older than this is automatically expired.
    /// Default: 60 seconds (RFC 9449 §8 recommends short-lived nonces).
    pub nonce_ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            jti_max_entries: 100_000,
            jti_cleanup_interval_secs: 300,
            nonce_max_entries: 100_000,
            nonce_ttl_secs: 60,
        }
    }
}

impl<'de> serde::de::Deserialize<'de> for CacheConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(default)]
        struct Raw {
            jti_max_entries: usize,
            jti_cleanup_interval_secs: u64,
            nonce_max_entries: u64,
            nonce_ttl_secs: u64,
        }
        impl Default for Raw {
            fn default() -> Self {
                let c = CacheConfig::default();
                Self {
                    jti_max_entries: c.jti_max_entries,
                    jti_cleanup_interval_secs: c.jti_cleanup_interval_secs,
                    nonce_max_entries: c.nonce_max_entries,
                    nonce_ttl_secs: c.nonce_ttl_secs,
                }
            }
        }
        let r = Raw::deserialize(d)?;
        Ok(CacheConfig {
            jti_max_entries: r.jti_max_entries,
            jti_cleanup_interval_secs: r.jti_cleanup_interval_secs,
            nonce_max_entries: r.nonce_max_entries,
            nonce_ttl_secs: r.nonce_ttl_secs,
        })
    }
}

// ── Existing config types ─────────────────────────────────────────────────────

/// Host classification for determining authentication requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HostClassification {
    /// Standard hosts with basic MFA requirements
    #[default]
    Standard,
    /// Elevated hosts with stricter requirements
    Elevated,
    /// Critical hosts with maximum security
    Critical,
}

/// SSH login configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SshConfig {
    /// Whether OIDC authentication is required
    pub require_oidc: bool,
    /// Minimum ACR level required
    pub minimum_acr: Option<String>,
    /// Maximum age of auth_time in seconds (re-auth if older)
    pub max_auth_age: Option<i64>,
    /// NSS group names required for SSH login. Empty = no restriction (allow all).
    /// Enforcement behaviour is governed by `security_modes.groups_enforcement`.
    #[serde(default)]
    pub login_groups: Vec<String>,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            require_oidc: true,
            minimum_acr: None,
            max_auth_age: Some(3600), // 1 hour default
            login_groups: Vec::new(),
        }
    }
}

/// Sudo configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SudoConfig {
    /// Whether step-up authentication is required
    pub step_up_required: bool,
    /// Allowed step-up methods
    pub allowed_methods: Vec<StepUpMethod>,
    /// Timeout for step-up challenge in seconds
    pub challenge_timeout: u64,
    /// Command-specific rules
    #[serde(default)]
    pub commands: Vec<CommandRule>,
    /// NSS group names permitted to run sudo. Empty = no restriction (allow all).
    /// Enforcement behaviour is governed by `security_modes.groups_enforcement`.
    #[serde(default)]
    pub sudo_groups: Vec<String>,
}

impl Default for SudoConfig {
    fn default() -> Self {
        Self {
            step_up_required: true,
            allowed_methods: vec![StepUpMethod::DeviceFlow],
            // STP-07: step-up timeout defaults to 120s (covers CIBA poll window
            // with typical IdP push delivery; configurable via policy.yaml).
            challenge_timeout: 120,
            commands: Vec::new(),
            sudo_groups: Vec::new(),
        }
    }
}

/// Rule for specific sudo commands.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandRule {
    /// Glob pattern for matching commands
    pub pattern: String,
    /// Whether step-up is required for this command
    pub step_up_required: bool,
}

/// Break-glass configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BreakGlassConfig {
    /// Whether break-glass is enabled
    pub enabled: bool,
    /// Legacy single-account field (v1.0 backward compat). Use `accounts` for new configs.
    pub local_account: Option<String>,
    /// Authentication method (yubikey_otp)
    pub requires: Option<String>,
    /// Whether to send alerts on break-glass use
    pub alert_on_use: bool,
    /// Break-glass account names (v2.0+). Multiple accounts supported.
    /// If both `local_account` and `accounts` are set, both are honoured.
    /// Default: empty (no break-glass accounts).
    #[serde(default)]
    pub accounts: Vec<String>,
}

impl Default for BreakGlassConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            local_account: None,
            requires: None,
            alert_on_use: true,
            accounts: Vec::new(),
        }
    }
}

/// Host-level configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HostConfig {
    /// Host classification
    pub classification: HostClassification,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            classification: HostClassification::Standard,
        }
    }
}

// ── PamTimeoutsConfig ──────────────────────────────────────────────────────────

/// Clock-skew tolerance values for DPoP proof validation and token staleness checks.
///
/// Loaded from `policy.yaml` under the `timeouts:` key (Phase 14+).
/// Defaults match the previously hardcoded values so v1.0 deployments are
/// unaffected when the section is absent.
///
/// Environment variable override pattern (double-underscore nesting):
/// - `UNIX_OIDC_TIMEOUTS__CLOCK_SKEW_FUTURE_SECS=10`
/// - `UNIX_OIDC_TIMEOUTS__CLOCK_SKEW_STALENESS_SECS=90`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PamTimeoutsConfig {
    /// Maximum number of seconds a DPoP proof is allowed to be issued in the future
    /// (client clock slightly ahead of server). Matches `DPoPAuthConfig::clock_skew_future_secs`.
    /// Default: 5 seconds.
    pub clock_skew_future_secs: u64,
    /// Maximum age of a DPoP proof relative to server clock (proof staleness tolerance).
    /// Also used as `ValidationConfig::clock_skew_tolerance_secs` for ID token expiry checks.
    /// Matches `DPoPAuthConfig::max_proof_age`. Default: 60 seconds.
    pub clock_skew_staleness_secs: u64,
}

impl Default for PamTimeoutsConfig {
    fn default() -> Self {
        Self {
            clock_skew_future_secs: 5,
            clock_skew_staleness_secs: 60,
        }
    }
}

// ── AuditConfig ──────────────────────────────────────────────────────────────

/// Audit logging configuration.
///
/// Controls where audit events are written and how tamper-evidence is configured.
///
/// Environment variable override pattern (double-underscore nesting):
/// - `UNIX_OIDC_AUDIT__LOG_FILE=/var/log/unix-oidc-audit.log`
/// - `UNIX_OIDC_AUDIT__SYSLOG_ENABLED=true`
/// - `UNIX_OIDC_AUDIT__HMAC_KEY_FILE=/etc/unix-oidc/audit-hmac.key`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Path to the dedicated audit log file. JSON-lines format, one event per line.
    /// Set to empty string to disable file logging.
    /// Default: `/var/log/unix-oidc-audit.log`
    pub log_file: String,
    /// Whether to send audit events to syslog (AUTH facility, RFC 3164).
    /// Default: `true`
    pub syslog_enabled: bool,
    /// Path to a file containing the HMAC-SHA256 key for tamper-evident audit chains.
    /// The key is read at startup; the file must be readable by the PAM module.
    /// When empty, falls back to `UNIX_OIDC_AUDIT_HMAC_KEY` environment variable.
    /// Default: empty (env var fallback)
    pub hmac_key_file: String,
    /// Whether to write audit events to stderr (useful for debugging/testing).
    /// Default: `true`
    pub stderr_enabled: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_file: "/var/log/unix-oidc-audit.log".to_string(),
            syslog_enabled: true,
            hmac_key_file: String::new(),
            stderr_enabled: true,
        }
    }
}

// ── PolicyConfig ──────────────────────────────────────────────────────────────

/// Complete policy configuration.
///
/// Loaded via figment from `/etc/unix-oidc/policy.yaml` with optional
/// environment-variable overrides (prefix `UNIX_OIDC_`, double-underscore nesting).
///
/// `security_modes` is `Option<SecurityModes>` so that figment can distinguish
/// between "section absent" (v1.0 file → `None`) and "section present" (v2.0 → `Some`).
/// Use [`Self::effective_security_modes`] to get the correct enforcement config.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct PolicyConfig {
    /// Host-level configuration
    pub host: HostConfig,
    /// SSH login configuration
    pub ssh_login: SshConfig,
    /// Sudo configuration
    pub sudo: SudoConfig,
    /// Break-glass configuration
    pub break_glass: BreakGlassConfig,
    /// Security enforcement modes (v2.0+). Absent in v1.0 files.
    pub security_modes: Option<SecurityModes>,
    /// Cache tuning parameters.
    pub cache: CacheConfig,
    /// Username mapping and transform pipeline configuration.
    #[serde(default)]
    pub identity: IdentityConfig,
    /// RFC 7662 token introspection configuration (Phase 09+).
    #[serde(default)]
    pub introspection: IntrospectionConfig,
    /// Session lifecycle configuration (Phase 09+).
    #[serde(default)]
    pub session: SessionConfig,
    /// Clock-skew tolerance values for DPoP proof validation (Phase 14+).
    /// Absent in v1.0 files — defaults match prior hardcoded values.
    #[serde(default)]
    pub timeouts: PamTimeoutsConfig,
    /// Per-issuer configuration bundles (Phase 21+, MIDP-01..05).
    ///
    /// When non-empty, overrides the legacy single-issuer env-var path.
    /// Use `issuer_by_url()` to look up issuers by their URL.
    ///
    /// Duplicate `issuer_url` values hard-fail at load time (detected by `load_from()`).
    #[serde(default)]
    pub issuers: Vec<IssuerConfig>,
    /// Audit logging configuration (Phase 32+).
    #[serde(default)]
    pub audit: AuditConfig,
}

impl PolicyConfig {
    /// Load policy from the default location.
    pub fn load() -> Result<Self, PolicyError> {
        Self::load_from("/etc/unix-oidc/policy.yaml")
    }

    /// Load policy from a specific path using figment (YAML + env overrides).
    ///
    /// Environment variable override pattern (double-underscore for nesting):
    /// - `UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT=strict`
    /// - `UNIX_OIDC_SECURITY_MODES__DPOP_REQUIRED=warn`
    /// - `UNIX_OIDC_CACHE__JTI_MAX_ENTRIES=50000`
    ///
    /// Only `security_modes`, `cache`, `identity`, `introspection`, `session`,
    /// `timeouts`, and `issuers` env keys are recognized to prevent unrelated
    /// `UNIX_OIDC_*` vars (e.g. `UNIX_OIDC_TEST_MODE`) from causing spurious
    /// config-parse errors.
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(PolicyError::NotFound(path.display().to_string()));
        }

        let config: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::file(path))
            .merge(Env::prefixed("UNIX_OIDC_").split("__").only(&[
                "security_modes",
                "cache",
                "identity",
                "introspection",
                "session",
                "timeouts",
                "issuers",
            ]))
            .extract()
            .map_err(|e| PolicyError::ParseError(e.to_string()))?;

        // Emit v1.0-migration notice so operators know to add the new section.
        if config.security_modes.is_none() {
            tracing::info!(
                "Loaded policy.yaml without security_modes section \
                 — using v1.0 defaults. See docs for v2.0 configuration."
            );
        }

        // MIDP-08: Warn for issuers missing optional fields.
        for issuer in &config.issuers {
            if issuer.acr_mapping.is_none() {
                tracing::warn!(
                    issuer_url = %issuer.issuer_url,
                    "Issuer has no acr_mapping configured — ACR requirements will not be enforced for this issuer"
                );
            }
            if issuer.group_mapping.is_none() {
                tracing::warn!(
                    issuer_url = %issuer.issuer_url,
                    "Issuer has no group_mapping configured — using NSS-only group resolution"
                );
            }
        }

        // Detect duplicate issuer_url values (hard-fail per MIDP design).
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for issuer in &config.issuers {
            let normalized = issuer.issuer_url.trim_end_matches('/').to_string();
            if !seen.insert(normalized.clone()) {
                return Err(PolicyError::ConfigError(format!(
                    "Duplicate issuer_url in issuers[]: '{normalized}'. \
                     Each issuer must have a unique URL."
                )));
            }
        }

        // SHRD-04: Enforce HTTPS for all issuer URLs at config load time.
        // HTTP URLs are a critical misconfiguration: tokens, client credentials, and
        // user codes would be transmitted in the clear.
        for issuer in &config.issuers {
            // In test-mode builds, allow_insecure_http_for_testing bypasses the check.
            #[cfg(any(test, feature = "test-mode"))]
            if issuer.allow_insecure_http_for_testing {
                tracing::error!(
                    issuer_url = %issuer.issuer_url,
                    "INSECURE: HTTP issuer URLs permitted — test mode active. \
                     NEVER use this in production."
                );
                continue;
            }

            if let Err(msg) = validate_https_url(&issuer.issuer_url, "issuer_url") {
                return Err(PolicyError::ParseError(msg));
            }
        }

        Ok(config)
    }

    /// Load policy from environment variables (for testing / runtime override).
    ///
    /// Priority:
    /// 1. `UNIX_OIDC_POLICY_FILE` — path to a YAML file (validated via `load_from`)
    /// 2. `UNIX_OIDC_POLICY_YAML` — inline YAML string (**test-mode only**, Codex finding 4)
    /// 3. `UNIX_OIDC_TEST_MODE=true|1` — return `Default::default()`
    /// 4. Default file location `/etc/unix-oidc/policy.yaml`
    ///
    /// # Security
    ///
    /// `UNIX_OIDC_POLICY_YAML` is restricted to test-mode builds to prevent
    /// environment injection attacks from silently overriding security policy.
    /// Production policy MUST come from the validated file path.
    pub fn from_env() -> Result<Self, PolicyError> {
        // Check for test policy file path — goes through load_from() validation.
        if let Ok(path) = std::env::var("UNIX_OIDC_POLICY_FILE") {
            return Self::load_from(&path);
        }

        // Security (Codex finding 4): Inline YAML config is restricted to test-mode
        // builds. In production, environment injection of UNIX_OIDC_POLICY_YAML cannot
        // override security policy.
        // Note: this path uses figment extraction (type-safe deserialization) but does
        // NOT run the full load_from() validation (e.g. duplicate issuer detection).
        // This is acceptable for test builds; production must use the file path.
        #[cfg(feature = "test-mode")]
        if let Ok(yaml) = std::env::var("UNIX_OIDC_POLICY_YAML") {
            let config: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
                .merge(Yaml::string(&yaml))
                .merge(Env::prefixed("UNIX_OIDC_").split("__").only(&[
                    "security_modes",
                    "cache",
                    "identity",
                    "introspection",
                    "session",
                    "timeouts",
                    "issuers",
                    "audit",
                ]))
                .extract()
                .map_err(|e| PolicyError::ParseError(e.to_string()))?;
            return Ok(config);
        }

        // Return default policy for test mode
        // Security: Requires explicit "true" or "1", not just any value.
        if is_test_mode_enabled() {
            return Ok(Self::default());
        }

        // Try loading from default location
        Self::load()
    }

    /// Load policy with hot-reload support (MIDP-11, ADR-009).
    ///
    /// Applies to the file-backed multi-issuer policy path only. The legacy
    /// single-issuer env-based path (`from_env()`) does not support hot-reload.
    ///
    /// On each call, stats the policy file. If the file mtime has changed since
    /// the last successful load, the file is re-parsed and the cache updated.
    ///
    /// On re-parse failure (bad YAML, missing file), logs a WARNING and returns
    /// the previous valid config from the cache. If no cache exists yet and the
    /// initial load fails, returns the error.
    ///
    /// The config file path is resolved from `UNIX_OIDC_POLICY` env var or
    /// `/etc/unix-oidc/policy.yaml` (same as `from_env()`). The `UNIX_OIDC_POLICY`
    /// var is used (not `UNIX_OIDC_POLICY_FILE`) so tests can set a unique path
    /// per test without conflicting with `from_env()`.
    pub fn load_fresh() -> Result<Self, PolicyError> {
        let config_path: PathBuf = std::env::var("UNIX_OIDC_POLICY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/etc/unix-oidc/policy.yaml"));

        // Acquire the global cache lock. Best-effort: if lock is poisoned, log WARN
        // and fall through to a fresh load.
        let mut cache_guard = match CONFIG_CACHE.lock() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Config cache mutex poisoned — performing fresh load"
                );
                // Return a fresh load without caching.
                return Self::load_from(&config_path);
            }
        };

        // Stat the config file to detect mtime changes.
        let current_mtime = match std::fs::metadata(&config_path) {
            Ok(meta) => meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            Err(e) => {
                // File is missing or unreadable.
                if let Some(ref cached) = *cache_guard {
                    tracing::warn!(
                        path = %config_path.display(),
                        error = %e,
                        "Config file unavailable on reload — using cached config"
                    );
                    return Ok(cached.config.clone());
                }
                // No cache and file unavailable — hard fail.
                return Err(PolicyError::ReadError(e));
            }
        };

        // If the cached path matches and mtime is unchanged, return cache.
        if let Some(ref cached) = *cache_guard {
            if cached.path == config_path && cached.mtime == current_mtime {
                return Ok(cached.config.clone());
            }
        }

        // mtime changed (or no cache) — attempt to re-parse.
        match Self::load_from(&config_path) {
            Ok(new_config) => {
                *cache_guard = Some(ConfigCache {
                    config: new_config.clone(),
                    mtime: current_mtime,
                    path: config_path,
                });
                Ok(new_config)
            }
            Err(e) => {
                // Parse failure — return cached config if available.
                if let Some(ref cached) = *cache_guard {
                    tracing::warn!(
                        path = %config_path.display(),
                        error = %e,
                        "Config reload failed — keeping previous valid config"
                    );
                    Ok(cached.config.clone())
                } else {
                    // No cached config and parse failed — propagate error.
                    Err(e)
                }
            }
        }
    }

    /// Return the effective [`SecurityModes`] for this policy.
    ///
    /// If the `security_modes` section was absent from the YAML (v1.0 file),
    /// returns [`SecurityModes::default()`] which exactly matches v1.0 behavior.
    pub fn effective_security_modes(&self) -> SecurityModes {
        self.security_modes.clone().unwrap_or_default()
    }

    /// Return the effective list of trusted issuers (MIDP-01, legacy compat).
    ///
    /// Resolution order:
    /// Look up an issuer by URL, with trailing-slash normalization on both sides.
    ///
    /// Returns `None` if no matching issuer is found in `issuers[]`.
    pub fn issuer_by_url(&self, iss: &str) -> Option<&IssuerConfig> {
        let normalized_query = iss.trim_end_matches('/');
        self.issuers
            .iter()
            .find(|issuer| issuer.issuer_url.trim_end_matches('/') == normalized_query)
    }

    /// Check if a command matches any pattern that requires step-up.
    pub fn command_requires_step_up(&self, command: &str) -> bool {
        // If no command rules, use the default sudo config
        if self.sudo.commands.is_empty() {
            return self.sudo.step_up_required;
        }

        // Check command rules in order
        for rule in &self.sudo.commands {
            if pattern_matches(&rule.pattern, command) {
                return rule.step_up_required;
            }
        }

        // Default to the sudo config setting
        self.sudo.step_up_required
    }
}

// ── Glob pattern matching ─────────────────────────────────────────────────────

/// Simple glob pattern matching (supports * wildcard).
fn pattern_matches(pattern: &str, text: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('*').collect();

    if pattern_parts.len() == 1 {
        // No wildcards, exact match
        return pattern == text;
    }

    let mut pos = 0;
    for (i, part) in pattern_parts.iter().enumerate() {
        if part.is_empty() {
            // Empty part means * at start or end, or ** - matches anything
            continue;
        }

        if i == 0 {
            // First part must match at start
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == pattern_parts.len() - 1 {
            // Last non-empty part must match at end (if pattern doesn't end with *)
            // But if pattern ends with *, the last part will be empty
            if !text[pos..].ends_with(part) {
                return false;
            }
        } else {
            // Middle parts must be found in order
            if let Some(found_pos) = text[pos..].find(part) {
                pos += found_pos + part.len();
            } else {
                return false;
            }
        }
    }

    // If the last pattern part is empty (pattern ends with *),
    // we've already matched everything we need
    true
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Module-level mutex to serialize tests that manipulate environment variables.
    /// Rust test threads share process memory, so concurrent env-var mutations cause races.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    // ── New-type tests ──────────────────────────────────────────────────────

    #[test]
    fn test_enforcement_mode_defaults() {
        // EnforcementMode::default() must be Warn (v1.0 behavior for JTI)
        assert_eq!(EnforcementMode::default(), EnforcementMode::Warn);
    }

    #[test]
    fn test_security_modes_defaults() {
        // jti_enforcement changed to Strict in v3.0 (D-06 — breaking change).
        let modes = SecurityModes::default();
        assert_eq!(modes.jti_enforcement, EnforcementMode::Strict);
        assert_eq!(modes.dpop_required, EnforcementMode::Strict);
        assert_eq!(modes.amr_enforcement, EnforcementMode::Disabled);
        assert_eq!(modes.acr.enforcement, EnforcementMode::Warn);
        assert!(modes.acr.minimum_level.is_none());
        assert!(modes.step_up_require_id_token, "step_up_require_id_token must default to true (D-16)");
    }

    #[test]
    fn test_cache_config_defaults() {
        let cache = CacheConfig::default();
        assert_eq!(cache.jti_max_entries, 100_000);
        assert_eq!(cache.jti_cleanup_interval_secs, 300);
        assert_eq!(cache.nonce_max_entries, 100_000);
        assert_eq!(cache.nonce_ttl_secs, 60);
    }

    #[test]
    fn test_cache_config_nonce_fields_yaml_override() {
        let yaml = r#"
cache:
  nonce_max_entries: 50000
  nonce_ttl_secs: 30
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("nonce cache yaml should load");

        assert_eq!(policy.cache.nonce_max_entries, 50_000);
        assert_eq!(policy.cache.nonce_ttl_secs, 30);
        // JTI defaults still intact
        assert_eq!(policy.cache.jti_max_entries, 100_000);
    }

    #[test]
    fn test_v1_yaml_loads_with_defaults() {
        // A v1.0 policy.yaml (no security_modes section) must load without error
        // and produce None for security_modes (triggering v1.0-compat path).
        let yaml = r#"
host:
  classification: standard
ssh_login:
  require_oidc: true
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("v1.0 yaml should load");

        assert!(
            policy.security_modes.is_none(),
            "v1.0 yaml must produce security_modes=None"
        );
        // effective_security_modes() must still return correct defaults
        // Note: jti_enforcement default is now Strict (D-06, v3.0 breaking change).
        let modes = policy.effective_security_modes();
        assert_eq!(modes.jti_enforcement, EnforcementMode::Strict);
        assert_eq!(modes.dpop_required, EnforcementMode::Strict);
    }

    #[test]
    fn test_v2_yaml_overrides_security_modes() {
        let yaml = r#"
security_modes:
  jti_enforcement: strict
  dpop_required: warn
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("v2.0 yaml should load");

        let modes = policy.effective_security_modes();
        assert_eq!(modes.jti_enforcement, EnforcementMode::Strict);
        assert_eq!(modes.dpop_required, EnforcementMode::Warn);
    }

    #[test]
    fn test_invalid_enforcement_mode_rejected() {
        let yaml = r#"
security_modes:
  jti_enforcement: strct
"#;
        let result: Result<PolicyConfig, _> =
            Figment::from(Serialized::defaults(PolicyConfig::default()))
                .merge(Yaml::string(yaml))
                .extract();

        assert!(
            result.is_err(),
            "Invalid mode string must cause load failure"
        );
    }

    #[test]
    fn test_cache_section_overrides_defaults() {
        let yaml = r#"
cache:
  jti_max_entries: 50000
  jti_cleanup_interval_secs: 600
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("cache yaml should load");

        assert_eq!(policy.cache.jti_max_entries, 50_000);
        assert_eq!(policy.cache.jti_cleanup_interval_secs, 600);
    }

    #[test]
    fn test_env_var_override_jti_enforcement() {
        // UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT=strict overrides YAML
        let yaml = r#"
security_modes:
  jti_enforcement: warn
"#;
        // Safety: test-only env var manipulation; tests run sequentially within this module
        std::env::set_var("UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT", "strict");
        let result: Result<PolicyConfig, _> =
            Figment::from(Serialized::defaults(PolicyConfig::default()))
                .merge(Yaml::string(yaml))
                .merge(Env::prefixed("UNIX_OIDC_").split("__"))
                .extract();
        std::env::remove_var("UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT");

        let policy = result.expect("env override should succeed");
        assert_eq!(
            policy.effective_security_modes().jti_enforcement,
            EnforcementMode::Strict
        );
    }

    #[test]
    fn test_unknown_env_vars_do_not_break_load() {
        // UNIX_OIDC_TEST_MODE is not a PolicyConfig field — figment must not error.
        // We use `.only()` filter on the env provider to prevent unknown key mapping.
        std::env::set_var("UNIX_OIDC_TEST_MODE", "true");
        let result: Result<PolicyConfig, _> =
            Figment::from(Serialized::defaults(PolicyConfig::default()))
                .merge(Env::prefixed("UNIX_OIDC_").split("__").only(&[
                    "security_modes",
                    "cache",
                    "identity",
                ]))
                .extract();
        std::env::remove_var("UNIX_OIDC_TEST_MODE");

        assert!(
            result.is_ok(),
            "Unknown env vars must not break config load"
        );
    }

    // ── Existing tests (backward compat) ────────────────────────────────────

    #[test]
    fn test_default_policy() {
        let policy = PolicyConfig::default();

        assert_eq!(policy.host.classification, HostClassification::Standard);
        assert!(policy.ssh_login.require_oidc);
        assert!(policy.sudo.step_up_required);
        // STP-07: challenge_timeout default updated to 120s for CIBA step-up support.
        assert_eq!(policy.sudo.challenge_timeout, 120);
    }

    #[test]
    fn test_parse_yaml_policy() {
        let yaml = r#"
host:
  classification: elevated

ssh_login:
  require_oidc: true
  minimum_acr: "urn:example:acr:mfa"
  max_auth_age: 1800

sudo:
  step_up_required: true
  allowed_methods:
    - device_flow
    - fido2
  challenge_timeout: 120
  commands:
    - pattern: "/usr/bin/systemctl restart *"
      step_up_required: true
    - pattern: "/usr/bin/less *"
      step_up_required: false
"#;

        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(policy.host.classification, HostClassification::Elevated);
        assert_eq!(
            policy.ssh_login.minimum_acr,
            Some("urn:example:acr:mfa".into())
        );
        assert_eq!(policy.ssh_login.max_auth_age, Some(1800));
        assert_eq!(policy.sudo.challenge_timeout, 120);
        assert_eq!(policy.sudo.commands.len(), 2);
    }

    #[test]
    fn test_pattern_matching() {
        // Exact match
        assert!(pattern_matches("/usr/bin/less", "/usr/bin/less"));
        assert!(!pattern_matches("/usr/bin/less", "/usr/bin/more"));

        // Trailing wildcard
        assert!(pattern_matches("/usr/bin/less *", "/usr/bin/less foo.txt"));
        assert!(pattern_matches("/usr/bin/less*", "/usr/bin/less")); // No space before *
        assert!(pattern_matches("/usr/bin/less*", "/usr/bin/less foo.txt")); // Also matches with args
        assert!(!pattern_matches("/usr/bin/less *", "/usr/bin/less")); // Space before * requires space in input
        assert!(!pattern_matches("/usr/bin/less *", "/usr/bin/more foo.txt"));

        // Leading wildcard
        assert!(pattern_matches("*.log", "/var/log/syslog.log"));
        assert!(!pattern_matches("*.log", "/var/log/syslog.txt"));

        // Middle wildcard
        assert!(pattern_matches("/usr/*/bin", "/usr/local/bin"));
        assert!(!pattern_matches("/usr/*/bin", "/opt/local/bin"));

        // Complex pattern
        assert!(pattern_matches(
            "/usr/bin/systemctl restart *",
            "/usr/bin/systemctl restart nginx"
        ));
    }

    #[test]
    fn test_command_requires_step_up() {
        let yaml = r#"
sudo:
  step_up_required: true
  commands:
    - pattern: "/usr/bin/systemctl restart *"
      step_up_required: true
    - pattern: "/usr/bin/less *"
      step_up_required: false
"#;

        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();

        // Matched by first rule - requires step-up
        assert!(policy.command_requires_step_up("/usr/bin/systemctl restart nginx"));

        // Matched by second rule - no step-up
        assert!(!policy.command_requires_step_up("/usr/bin/less /var/log/syslog"));

        // Not matched by any rule - uses default
        assert!(policy.command_requires_step_up("/usr/bin/rm -rf /"));
    }

    #[test]
    fn test_host_classification_parsing() {
        let yaml = "classification: critical";
        let host: HostConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(host.classification, HostClassification::Critical);

        let yaml = "classification: standard";
        let host: HostConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(host.classification, HostClassification::Standard);
    }

    // ── Phase 8: Identity config tests ──────────────────────────────────────

    #[test]
    fn test_identity_config_defaults() {
        let config = IdentityConfig::default();
        assert_eq!(config.username_claim, "preferred_username");
        assert!(config.transforms.is_empty());
    }

    #[test]
    fn test_identity_config_yaml_override() {
        let yaml = r#"
identity:
  username_claim: email
  transforms:
    - strip_domain
    - lowercase
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("identity yaml should load");

        assert_eq!(policy.identity.username_claim, "email");
        assert_eq!(policy.identity.transforms.len(), 2);
        // First transform is Simple("strip_domain")
        assert!(
            matches!(&policy.identity.transforms[0], TransformConfig::Simple(s) if s == "strip_domain")
        );
        assert!(
            matches!(&policy.identity.transforms[1], TransformConfig::Simple(s) if s == "lowercase")
        );
    }

    #[test]
    fn test_identity_config_regex_object_form() {
        let yaml = r#"
identity:
  username_claim: email
  transforms:
    - type: regex
      pattern: "^corp-(?P<username>[a-z0-9]+)"
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("identity regex yaml should load");

        assert_eq!(policy.identity.transforms.len(), 1);
        assert!(
            matches!(&policy.identity.transforms[0], TransformConfig::Object { r#type, pattern } if r#type == "regex" && pattern.contains("username"))
        );
    }

    #[test]
    fn test_v1_yaml_loads_without_identity_section() {
        let yaml = r#"
host:
  classification: standard
ssh_login:
  require_oidc: true
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("v1.0 yaml without identity section must load");

        // Should use default identity config
        assert_eq!(policy.identity.username_claim, "preferred_username");
        assert!(policy.identity.transforms.is_empty());
    }

    #[test]
    fn test_ssh_config_login_groups_defaults_to_empty() {
        let config = SshConfig::default();
        assert!(config.login_groups.is_empty());
    }

    #[test]
    fn test_ssh_config_login_groups_yaml_override() {
        let yaml = r#"
ssh_login:
  login_groups:
    - unix-users
    - developers
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("ssh login_groups yaml should load");

        assert_eq!(
            policy.ssh_login.login_groups,
            vec!["unix-users", "developers"]
        );
    }

    #[test]
    fn test_sudo_config_sudo_groups_defaults_to_empty() {
        let config = SudoConfig::default();
        assert!(config.sudo_groups.is_empty());
    }

    #[test]
    fn test_sudo_config_sudo_groups_yaml_override() {
        let yaml = r#"
sudo:
  sudo_groups:
    - wheel
    - admins
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("sudo sudo_groups yaml should load");

        assert_eq!(policy.sudo.sudo_groups, vec!["wheel", "admins"]);
    }

    #[test]
    fn test_break_glass_config_accounts_defaults_to_empty() {
        let config = BreakGlassConfig::default();
        assert!(config.accounts.is_empty());
        // local_account backward compat also None by default
        assert!(config.local_account.is_none());
    }

    #[test]
    fn test_break_glass_config_accounts_yaml_override() {
        let yaml = r#"
break_glass:
  enabled: true
  accounts:
    - breakglass1
    - breakglass2
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("break_glass accounts yaml should load");

        assert!(policy.break_glass.enabled);
        assert_eq!(
            policy.break_glass.accounts,
            vec!["breakglass1", "breakglass2"]
        );
    }

    #[test]
    fn test_break_glass_config_v1_local_account_still_works() {
        // v1.0 backward compat: local_account field must still deserialise
        let yaml = r#"
break_glass:
  enabled: true
  local_account: emergency
  alert_on_use: true
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("v1.0 break_glass with local_account must load");

        assert_eq!(
            policy.break_glass.local_account,
            Some("emergency".to_string())
        );
        assert!(policy.break_glass.accounts.is_empty()); // accounts defaults to empty
    }

    // ── Phase 9: IntrospectionConfig and SessionConfig tests ─────────────────

    #[test]
    fn test_introspection_config_defaults() {
        let config = IntrospectionConfig::default();
        assert!(!config.enabled, "introspection must be disabled by default");
        assert!(
            config.endpoint.is_none(),
            "endpoint must be None by default"
        );
        assert_eq!(config.enforcement, EnforcementMode::Warn);
        assert_eq!(config.cache_ttl_secs, 60);
    }

    #[test]
    fn test_session_config_defaults() {
        let config = SessionConfig::default();
        assert_eq!(config.session_dir, "/run/unix-oidc/sessions");
        assert_eq!(config.token_refresh_threshold_percent, 80);
    }

    #[test]
    fn test_v1_yaml_loads_with_introspection_session_defaults() {
        // A v1.0 policy without introspection/session sections must load correctly
        // and produce the correct defaults.
        let yaml = r#"
host:
  classification: standard
ssh_login:
  require_oidc: true
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("v1.0 yaml must load with introspection/session defaults");

        assert!(!policy.introspection.enabled);
        assert!(policy.introspection.endpoint.is_none());
        assert_eq!(policy.introspection.enforcement, EnforcementMode::Warn);
        assert_eq!(policy.introspection.cache_ttl_secs, 60);
        assert_eq!(policy.session.session_dir, "/run/unix-oidc/sessions");
        assert_eq!(policy.session.token_refresh_threshold_percent, 80);
    }

    #[test]
    fn test_introspection_yaml_override() {
        let yaml = r#"
introspection:
  enabled: true
  endpoint: "https://idp.example.com/token/introspect"
  enforcement: strict
  cache_ttl_secs: 30
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("introspection yaml should load");

        assert!(policy.introspection.enabled);
        assert_eq!(
            policy.introspection.endpoint,
            Some("https://idp.example.com/token/introspect".to_string())
        );
        assert_eq!(policy.introspection.enforcement, EnforcementMode::Strict);
        assert_eq!(policy.introspection.cache_ttl_secs, 30);
    }

    #[test]
    fn test_session_yaml_override() {
        let yaml = r#"
session:
  session_dir: "/tmp/test-sessions"
  token_refresh_threshold_percent: 70
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("session yaml should load");

        assert_eq!(policy.session.session_dir, "/tmp/test-sessions");
        assert_eq!(policy.session.token_refresh_threshold_percent, 70);
    }

    #[test]
    fn test_introspection_enabled_only_override() {
        // Only set enabled=true; other fields should keep defaults.
        let yaml = r#"
introspection:
  enabled: true
  cache_ttl_secs: 30
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("partial introspection yaml should load");

        assert!(policy.introspection.enabled);
        assert_eq!(policy.introspection.cache_ttl_secs, 30);
        // Other fields keep defaults
        assert!(policy.introspection.endpoint.is_none());
        assert_eq!(policy.introspection.enforcement, EnforcementMode::Warn);
    }

    #[test]
    fn test_introspection_invalid_enforcement_rejected() {
        let yaml = r#"
introspection:
  enforcement: invalid_mode
"#;
        let result: Result<PolicyConfig, _> =
            Figment::from(Serialized::defaults(PolicyConfig::default()))
                .merge(Yaml::string(yaml))
                .extract();

        assert!(
            result.is_err(),
            "Invalid introspection enforcement mode must cause parse error"
        );
    }

    #[test]
    fn test_security_modes_groups_enforcement_default_is_warn() {
        let modes = SecurityModes::default();
        assert_eq!(modes.groups_enforcement, EnforcementMode::Warn);
    }

    #[test]
    fn test_security_modes_groups_enforcement_yaml_override() {
        let yaml = r#"
security_modes:
  groups_enforcement: strict
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("groups_enforcement yaml should load");

        let modes = policy.effective_security_modes();
        assert_eq!(modes.groups_enforcement, EnforcementMode::Strict);
    }

    #[test]
    fn test_v1_yaml_without_groups_enforcement_defaults_to_warn() {
        // A v1.0 policy without security_modes must still get groups_enforcement = Warn
        let yaml = r#"
host:
  classification: standard
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("v1.0 yaml should load");

        // security_modes absent (None) → effective_security_modes() returns default
        assert!(policy.security_modes.is_none());
        let modes = policy.effective_security_modes();
        assert_eq!(modes.groups_enforcement, EnforcementMode::Warn);
    }

    // ── PamTimeoutsConfig tests (Phase 14-01) ──────────────────────────────

    #[test]
    fn test_pam_timeouts_defaults() {
        // PamTimeoutsConfig must exist and have clock_skew_future_secs=5, staleness=60 defaults.
        let policy = PolicyConfig::default();
        assert_eq!(policy.timeouts.clock_skew_future_secs, 5);
        assert_eq!(policy.timeouts.clock_skew_staleness_secs, 60);
    }

    #[test]
    fn test_pam_timeouts_custom_yaml() {
        let yaml = r#"
timeouts:
  clock_skew_future_secs: 10
  clock_skew_staleness_secs: 120
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .merge(Env::prefixed("UNIX_OIDC_").split("__").only(&[
                "security_modes",
                "cache",
                "identity",
                "introspection",
                "session",
                "timeouts",
            ]))
            .extract()
            .expect("custom timeouts yaml should load");

        assert_eq!(policy.timeouts.clock_skew_future_secs, 10);
        assert_eq!(policy.timeouts.clock_skew_staleness_secs, 120);
    }

    #[test]
    fn test_pam_timeouts_missing_section_uses_defaults() {
        // A v1.0 policy.yaml without a timeouts section must load successfully.
        let yaml = r#"
host:
  classification: standard
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("v1.0 yaml without timeouts section must load");

        assert_eq!(policy.timeouts.clock_skew_future_secs, 5);
        assert_eq!(policy.timeouts.clock_skew_staleness_secs, 60);
    }

    #[test]
    fn test_pam_timeouts_env_override() {
        // UNIX_OIDC_TIMEOUTS__CLOCK_SKEW_FUTURE_SECS overrides default via figment env provider.
        // Uses bare split("__") (no .only()) to match production load_from() behavior.
        std::env::set_var("UNIX_OIDC_TIMEOUTS__CLOCK_SKEW_FUTURE_SECS", "15");
        let result: Result<PolicyConfig, _> =
            Figment::from(Serialized::defaults(PolicyConfig::default()))
                .merge(Env::prefixed("UNIX_OIDC_").split("__"))
                .extract();
        std::env::remove_var("UNIX_OIDC_TIMEOUTS__CLOCK_SKEW_FUTURE_SECS");

        let policy = result.expect("env override for timeouts should succeed");
        assert_eq!(policy.timeouts.clock_skew_future_secs, 15);
    }

    // ── Phase 21: Multi-issuer config tests (21-01) ───────────────────────────

    /// A YAML with two `issuers[]` entries must deserialize into `PolicyConfig`
    /// with `issuers.len() == 2`.
    #[test]
    fn test_multi_issuer_two_entries_load() {
        let yaml = r#"
issuers:
  - issuer_url: "https://keycloak.example.com/realms/corp"
    client_id: "unix-oidc"
  - issuer_url: "https://login.microsoftonline.com/tenant-id/v2.0"
    client_id: "unix-oidc-entra"
    dpop_enforcement: disabled
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("multi-issuer yaml should load");

        assert_eq!(policy.issuers.len(), 2, "expected 2 issuers");
    }

    /// Duplicate `issuer_url` values in `issuers[]` must cause `load_from()` to
    /// return `Err` with a `ConfigError` variant (MIDP duplicate detection).
    #[test]
    fn test_duplicate_issuer_urls_rejected() {
        let yaml = r#"
issuers:
  - issuer_url: "https://keycloak.example.com/realms/corp"
    client_id: "unix-oidc"
  - issuer_url: "https://keycloak.example.com/realms/corp"
    client_id: "unix-oidc-2"
"#;
        // Write to a temp file so load_from() is exercised (it runs post-parse validation)
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, yaml).expect("write");

        let result = PolicyConfig::load_from(&path);
        assert!(result.is_err(), "duplicate issuer_url must be rejected");
        assert!(
            matches!(result.unwrap_err(), PolicyError::ConfigError(_)),
            "error must be ConfigError"
        );
    }

    /// `issuer_by_url()` returns `Some` for a configured issuer (with trailing-slash
    /// normalization) and `None` for an unknown URL.
    #[test]
    fn test_issuer_by_url_normalization() {
        let yaml = r#"
issuers:
  - issuer_url: "https://keycloak.example.com/realms/corp"
    client_id: "unix-oidc"
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("yaml should load");

        // Exact match
        assert!(policy
            .issuer_by_url("https://keycloak.example.com/realms/corp")
            .is_some());
        // Trailing slash on query side should still match
        assert!(policy
            .issuer_by_url("https://keycloak.example.com/realms/corp/")
            .is_some());
        // Unknown issuer
        assert!(policy.issuer_by_url("https://other.example.com").is_none());
    }

    /// `IssuerConfig` with all optional fields omitted must deserialize with safe defaults:
    /// dpop_enforcement=Strict, claim_mapping=default IdentityConfig, acr/group_mapping=None.
    #[test]
    fn test_issuer_optional_fields_defaults() {
        let yaml = r#"
issuers:
  - issuer_url: "https://keycloak.example.com/realms/corp"
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("minimal issuer yaml should load");

        let issuer = &policy.issuers[0];
        assert_eq!(
            issuer.dpop_enforcement,
            EnforcementMode::Strict,
            "dpop_enforcement must default to Strict"
        );
        assert_eq!(
            issuer.claim_mapping.username_claim, "preferred_username",
            "claim_mapping must default to IdentityConfig default"
        );
        assert!(
            issuer.acr_mapping.is_none(),
            "acr_mapping must default to None"
        );
        assert!(
            issuer.group_mapping.is_none(),
            "group_mapping must default to None"
        );
    }

    // ── SHRD-01/02: Per-issuer allowed_algorithms tests ───────────────────

    /// IssuerConfig with allowed_algorithms field deserializes from YAML correctly.
    #[test]
    fn test_issuer_config_allowed_algorithms_yaml() {
        let yaml = r#"
issuers:
  - issuer_url: "https://idp.example.com/realms/test"
    client_id: "unix-oidc"
    allowed_algorithms:
      - ES256
      - RS256
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("allowed_algorithms yaml should load");

        assert_eq!(policy.issuers.len(), 1);
        let algs = policy.issuers[0].allowed_algorithms.as_ref().unwrap();
        assert_eq!(algs, &["ES256", "RS256"]);
    }

    /// IssuerConfig without allowed_algorithms field uses default (None = global allowlist).
    #[test]
    fn test_issuer_config_no_allowed_algorithms_defaults_to_none() {
        let yaml = r#"
issuers:
  - issuer_url: "https://idp.example.com/realms/test"
    client_id: "unix-oidc"
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("issuer without allowed_algorithms should load");

        assert_eq!(policy.issuers.len(), 1);
        assert!(
            policy.issuers[0].allowed_algorithms.is_none(),
            "allowed_algorithms must default to None (backward compat)"
        );
    }

    // ── SHRD-04: HTTPS enforcement tests ──────────────────────────────────

    #[test]
    fn test_validate_https_url_accepts_https() {
        assert!(validate_https_url("https://idp.example.com/realms/test", "issuer_url").is_ok());
    }

    #[test]
    fn test_validate_https_url_rejects_http() {
        let result = validate_https_url("http://idp.example.com/realms/test", "issuer_url");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("HTTPS required"), "msg: {msg}");
        assert!(msg.contains("issuer_url"), "msg: {msg}");
    }

    #[test]
    fn test_validate_https_url_rejects_ftp() {
        let result = validate_https_url("ftp://idp.example.com", "issuer_url");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("ftp"), "msg: {msg}");
    }

    #[test]
    fn test_validate_https_url_rejects_empty() {
        let result = validate_https_url("", "issuer_url");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("empty"), "msg: {msg}");
    }

    #[test]
    fn test_validate_https_url_rejects_no_scheme() {
        let result = validate_https_url("not-a-url", "issuer_url");
        assert!(result.is_err());
    }

    /// PolicyConfig::load_from with http:// issuer URL must fail at load time.
    #[test]
    fn test_load_from_rejects_http_issuer_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            r#"
issuers:
  - issuer_url: "http://insecure.example.com/realms/test"
    client_id: "unix-oidc"
"#,
        )
        .unwrap();

        let result = PolicyConfig::load_from(&path);
        assert!(
            result.is_err(),
            "HTTP issuer URL must be rejected at load time"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("HTTPS"),
            "Error must mention HTTPS, got: {err_msg}"
        );
    }

    /// PolicyConfig::load_from with https:// issuer URL must succeed.
    #[test]
    fn test_load_from_accepts_https_issuer_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            r#"
issuers:
  - issuer_url: "https://secure.example.com/realms/test"
    client_id: "unix-oidc"
"#,
        )
        .unwrap();

        let result = PolicyConfig::load_from(&path);
        assert!(
            result.is_ok(),
            "HTTPS issuer URL must be accepted: {result:?}"
        );
    }

    /// Test-mode: allow_insecure_http_for_testing=true permits HTTP issuer URLs.
    #[test]
    fn test_load_from_allows_http_with_test_mode_flag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            r#"
issuers:
  - issuer_url: "http://localhost:8080/realms/test"
    client_id: "unix-oidc"
    allow_insecure_http_for_testing: true
"#,
        )
        .unwrap();

        let result = PolicyConfig::load_from(&path);
        assert!(
            result.is_ok(),
            "HTTP issuer URL with allow_insecure_http_for_testing must be accepted: {result:?}"
        );
    }

    // ── DEBT-03/04: Dead code removal regression tests ────────────────────

    /// GroupSource::NssOnly serde round-trip: serialize to YAML and deserialize back.
    /// Guards against regressions after TokenClaim variant removal (DEBT-03).
    #[test]
    fn test_group_source_nss_only_serde_round_trip() {
        // Explicit "nss_only" string deserializes correctly.
        let source: GroupSource =
            serde_yaml::from_str("nss_only").expect("nss_only must deserialize");
        assert_eq!(source, GroupSource::NssOnly);

        // Serialize and round-trip.
        let serialized = serde_yaml::to_string(&source).expect("must serialize");
        let deserialized: GroupSource =
            serde_yaml::from_str(&serialized).expect("round-trip must succeed");
        assert_eq!(deserialized, GroupSource::NssOnly);

        // Default deserialization yields NssOnly.
        assert_eq!(GroupSource::default(), GroupSource::NssOnly);
    }

    /// Deserializing "token_claim" as GroupSource must fail after DEBT-03 removal.
    #[test]
    fn test_group_source_token_claim_rejected() {
        let result: Result<GroupSource, _> = serde_yaml::from_str("token_claim");
        assert!(
            result.is_err(),
            "token_claim must be rejected after variant removal"
        );
    }

    /// issuer_by_url() resolves the correct IssuerConfig from a two-issuer policy.
    /// Guards against regressions after effective_issuers() removal (DEBT-04).
    #[test]
    fn test_issuer_by_url_resolves_correct_config() {
        let yaml = r#"
issuers:
  - issuer_url: "https://issuer-a.example.com"
    client_id: "client-a"
  - issuer_url: "https://issuer-b.example.com"
    client_id: "client-b"
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("two-issuer yaml must load");

        let a = policy
            .issuer_by_url("https://issuer-a.example.com")
            .expect("issuer-a must be found");
        assert_eq!(a.client_id, "client-a");

        let b = policy
            .issuer_by_url("https://issuer-b.example.com")
            .expect("issuer-b must be found");
        assert_eq!(b.client_id, "client-b");

        assert!(
            policy
                .issuer_by_url("https://unknown.example.com")
                .is_none(),
            "unknown issuer must return None"
        );
    }

    /// GroupMappingConfig with source=NssOnly deserializes correctly from YAML.
    /// Confirms SSSD group resolution path is intact after DEBT-03 removal.
    #[test]
    fn test_group_mapping_nss_only_deserializes() {
        let yaml = r#"
issuers:
  - issuer_url: "https://gm-test.example.com"
    client_id: "unix-oidc"
    group_mapping:
      source: nss_only
      claim: "groups"
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("group_mapping yaml must load");

        let gm = policy.issuers[0]
            .group_mapping
            .as_ref()
            .expect("group_mapping must be present");
        assert_eq!(gm.source, GroupSource::NssOnly);
        assert_eq!(gm.claim, "groups");
    }

    // ── Phase 30: FsAtomicStore / SecurityModes extension tests ─────────────

    #[test]
    fn test_step_up_require_id_token_default_true() {
        // D-16: step_up_require_id_token must default to true when absent from YAML.
        let yaml = r#"
host:
  classification: standard
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("minimal yaml must load");

        // If security_modes section absent, effective_security_modes() returns default.
        let modes = policy.effective_security_modes();
        assert!(
            modes.step_up_require_id_token,
            "step_up_require_id_token must default to true when absent from YAML (D-16)"
        );
    }

    #[test]
    fn test_step_up_require_id_token_false_parses_correctly() {
        // Operators can opt out of ID token passthrough (logs LOG_CRIT on use).
        let yaml = r#"
security_modes:
  step_up_require_id_token: false
"#;
        let policy: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::string(yaml))
            .extract()
            .expect("step_up_require_id_token: false must parse");

        let modes = policy.effective_security_modes();
        assert!(
            !modes.step_up_require_id_token,
            "step_up_require_id_token: false must parse and be stored as false"
        );
    }

    #[test]
    fn test_jti_enforcement_default_is_strict() {
        // D-06: jti_enforcement default changed from Warn to Strict in v3.0.
        // This is a breaking change — operators relying on the implicit Warn default
        // must add `jti_enforcement: warn` explicitly.
        let modes = SecurityModes::default();
        assert_eq!(
            modes.jti_enforcement,
            EnforcementMode::Strict,
            "jti_enforcement must default to Strict in v3.0 (D-06)"
        );
    }
}
