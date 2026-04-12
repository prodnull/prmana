//! SCIM 2.0 core schema types (RFC 7643).
//!
//! All types use camelCase JSON serialization as required by the SCIM specification.
//! Schema URIs follow the `urn:ietf:params:scim:schemas:` namespace.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Schema URIs (RFC 7643 §8) ──────────────────────────────────────────────

/// SCIM User schema URI.
pub const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
/// SCIM Group schema URI.
pub const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
/// SCIM ListResponse schema URI.
pub const SCHEMA_LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
/// SCIM Error schema URI.
pub const SCHEMA_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
/// SCIM ServiceProviderConfig schema URI.
pub const SCHEMA_SPC: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

// ── Resource metadata (RFC 7643 §3.1) ──────────────────────────────────────

/// Common resource metadata included in all SCIM resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    /// Resource type name (e.g., "User", "Group").
    pub resource_type: String,
    /// When the resource was created (ISO 8601).
    pub created: DateTime<Utc>,
    /// When the resource was last modified (ISO 8601).
    pub last_modified: DateTime<Utc>,
    /// Resource URI (absolute).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Resource version (ETag).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

// ── User resource (RFC 7643 §4.1) ──────────────────────────────────────────

/// SCIM User name sub-attribute (RFC 7643 §4.1.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    /// Full name, formatted for display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// Family name (last name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Given name (first name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Middle name(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
}

/// SCIM User email sub-attribute (RFC 7643 §4.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimEmail {
    /// Email address value.
    pub value: String,
    /// Email type (e.g., "work", "home").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Whether this is the primary email.
    #[serde(default)]
    pub primary: bool,
}

/// SCIM User resource (RFC 7643 §4.1).
///
/// Represents a provisioned Unix user account. The `user_name` field
/// maps to the Unix login name and must satisfy POSIX username rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    /// SCIM schema URIs.
    #[serde(default = "default_user_schemas")]
    pub schemas: Vec<String>,
    /// Unique resource identifier (assigned by the service provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// External identifier from the IdP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Unix login name (POSIX rules: `[a-z_][a-z0-9_.-]*`, max 32 chars).
    pub user_name: String,
    /// User's name components.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Email addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,
    /// Whether the account is active. Maps to account enabled/disabled.
    #[serde(default = "default_true")]
    pub active: bool,
    /// Resource metadata (set by the server, not the client).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

fn default_user_schemas() -> Vec<String> {
    vec![SCHEMA_USER.to_string()]
}

fn default_true() -> bool {
    true
}

// ── List response (RFC 7644 §3.4.2) ────────────────────────────────────────

/// SCIM list/query response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse<T: Serialize> {
    /// Schema URI for list response.
    #[serde(default = "default_list_schemas")]
    pub schemas: Vec<String>,
    /// Total number of results matching the query.
    pub total_results: usize,
    /// 1-based index of the first result in this page.
    #[serde(default = "default_one")]
    pub start_index: usize,
    /// Number of results per page.
    pub items_per_page: usize,
    /// The resources in this page.
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

fn default_list_schemas() -> Vec<String> {
    vec![SCHEMA_LIST.to_string()]
}

fn default_one() -> usize {
    1
}

// ── Error response (RFC 7644 §3.12) ────────────────────────────────────────

/// SCIM error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimError {
    /// Schema URI for error response.
    #[serde(default = "default_error_schemas")]
    pub schemas: Vec<String>,
    /// HTTP status code as string (e.g., "404", "409").
    pub status: String,
    /// Human-readable error detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// SCIM error type (e.g., "uniqueness", "mutability").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
}

fn default_error_schemas() -> Vec<String> {
    vec![SCHEMA_ERROR.to_string()]
}

// ── ServiceProviderConfig (RFC 7643 §5) ────────────────────────────────────

/// SCIM service provider configuration resource.
///
/// Advertises which SCIM features this server supports.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceProviderConfig {
    /// Schema URIs.
    #[serde(default = "default_spc_schemas")]
    pub schemas: Vec<String>,
    /// Patch operation support.
    pub patch: FeatureSupport,
    /// Bulk operation support.
    pub bulk: BulkSupport,
    /// Filter support.
    pub filter: FilterSupport,
    /// Password change support.
    pub change_password: FeatureSupport,
    /// Sort support.
    pub sort: FeatureSupport,
    /// ETag support.
    pub etag: FeatureSupport,
    /// Authentication schemes.
    pub authentication_schemes: Vec<AuthenticationScheme>,
    /// Resource metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

fn default_spc_schemas() -> Vec<String> {
    vec![SCHEMA_SPC.to_string()]
}

/// Feature support flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSupport {
    pub supported: bool,
}

/// Bulk operation support details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkSupport {
    pub supported: bool,
    pub max_operations: usize,
    pub max_payload_size: usize,
}

/// Filter support details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterSupport {
    pub supported: bool,
    pub max_results: usize,
}

/// Authentication scheme description.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationScheme {
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub auth_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_uri: Option<String>,
    #[serde(default)]
    pub primary: bool,
}

/// Build the default ServiceProviderConfig for this server.
///
/// Phase 37 supports: User CRUD (no PATCH), single operations (no bulk),
/// no filter, no sort, no password change, no ETag. Bearer token auth.
pub fn default_service_provider_config() -> ServiceProviderConfig {
    ServiceProviderConfig {
        schemas: vec![SCHEMA_SPC.to_string()],
        patch: FeatureSupport { supported: false },
        bulk: BulkSupport {
            supported: false,
            max_operations: 0,
            max_payload_size: 0,
        },
        filter: FilterSupport {
            supported: false,
            max_results: 100,
        },
        change_password: FeatureSupport { supported: false },
        sort: FeatureSupport { supported: false },
        etag: FeatureSupport { supported: false },
        authentication_schemes: vec![AuthenticationScheme {
            name: "OAuth Bearer Token".to_string(),
            description: "Authentication scheme using the OAuth 2.0 Bearer Token".to_string(),
            auth_type: "oauthbearertoken".to_string(),
            spec_uri: Some("https://datatracker.ietf.org/doc/html/rfc6750".to_string()),
            documentation_uri: None,
            primary: true,
        }],
        meta: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scim_user_serialization() {
        let user = ScimUser {
            schemas: vec![SCHEMA_USER.into()],
            id: Some("abc-123".into()),
            external_id: Some("alice@corp.example.com".into()),
            user_name: "alice".into(),
            name: Some(ScimName {
                given_name: Some("Alice".into()),
                family_name: Some("Smith".into()),
                ..Default::default()
            }),
            display_name: Some("Alice Smith".into()),
            emails: vec![ScimEmail {
                value: "alice@corp.example.com".into(),
                r#type: Some("work".into()),
                primary: true,
            }],
            active: true,
            meta: None,
        };
        let json = serde_json::to_string_pretty(&user).unwrap();
        assert!(json.contains("urn:ietf:params:scim:schemas:core:2.0:User"));
        assert!(json.contains("\"userName\""));
        assert!(json.contains("alice"));
        assert!(json.contains("familyName")); // camelCase
    }

    #[test]
    fn test_scim_user_deserialization() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "bob",
            "active": false
        }"#;
        let user: ScimUser = serde_json::from_str(json).unwrap();
        assert_eq!(user.user_name, "bob");
        assert!(!user.active);
        assert!(user.id.is_none());
    }

    #[test]
    fn test_scim_list_response() {
        let resp = ScimListResponse {
            schemas: vec![SCHEMA_LIST.into()],
            total_results: 1,
            start_index: 1,
            items_per_page: 10,
            resources: vec![ScimUser {
                schemas: vec![SCHEMA_USER.into()],
                id: Some("1".into()),
                external_id: None,
                user_name: "bob".into(),
                name: None,
                display_name: None,
                emails: vec![],
                active: true,
                meta: None,
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("totalResults"));
        assert!(json.contains("Resources")); // capital R per SCIM spec
        assert!(json.contains("startIndex"));
    }

    #[test]
    fn test_scim_error_response() {
        let err = ScimError {
            schemas: vec![SCHEMA_ERROR.into()],
            status: "404".into(),
            detail: Some("User not found".into()),
            scim_type: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("404"));
        assert!(json.contains("User not found"));
    }

    #[test]
    fn test_service_provider_config() {
        let spc = default_service_provider_config();
        let json = serde_json::to_string_pretty(&spc).unwrap();
        assert!(json.contains("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"));
        assert!(json.contains("oauthbearertoken"));
        assert!(json.contains("\"supported\": false")); // Phase 37: most features unsupported
    }

    #[test]
    fn test_scim_meta_serialization() {
        let meta = ScimMeta {
            resource_type: "User".into(),
            created: Utc::now(),
            last_modified: Utc::now(),
            location: Some("https://scim.example.com/Users/abc".into()),
            version: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("resourceType"));
        assert!(json.contains("lastModified")); // camelCase
    }

    #[test]
    fn test_user_defaults() {
        let json = r#"{"userName": "test"}"#;
        let user: ScimUser = serde_json::from_str(json).unwrap();
        assert!(user.active, "active should default to true");
        assert_eq!(user.schemas, vec![SCHEMA_USER]);
    }
}
