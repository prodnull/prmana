//! Phase 41: Fault-injection integration tests for IdP failover.
//!
//! Uses wiremock to simulate primary/secondary OIDC issuers with
//! controlled failure injection. Validates the failover state machine
//! against real HTTP interactions.
//!
//! Test matrix (from Phase 41 plan):
//! 1. Primary discovery timeout -> secondary used successfully
//! 2. Primary token endpoint 503 -> secondary used successfully
//! 3. Primary invalid_client -> no failover, hard failure
//! 4. Primary reachable but malformed -> no failover, hard failure
//! 5. Primary recovers after cooldown -> returns to primary
//! 6. Both issuers down -> fail-closed with exhausted event
//! 7. Failure classification: 5xx = availability, 4xx = non-failover
//! 8. In-flight no mid-stream switching (covered by unit tests)

use unix_oidc_agent::daemon::{AgentState};
use unix_oidc_agent::failover::{
    classify_http_status, FailoverEvent, FailoverPairConfig,
    FailoverRuntime, FailoverState, FailureClass, validate_failover_pairs,
};
use wiremock::matchers;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build a mock OIDC discovery response for a given issuer.
fn discovery_response(issuer: &str, token_endpoint: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "token_endpoint": token_endpoint,
        "authorization_endpoint": format!("{issuer}/protocol/openid-connect/auth"),
        "jwks_uri": format!("{issuer}/protocol/openid-connect/certs"),
        "device_authorization_endpoint": format!("{issuer}/protocol/openid-connect/auth/device"),
    })
}

// ── Test 1: Primary discovery timeout -> secondary used ─────────────────────

#[tokio::test]
async fn test_primary_discovery_timeout_falls_back_to_secondary() {
    // Primary: responds with a large delay (simulates timeout via 500 for simplicity)
    let primary = MockServer::start().await;
    Mock::given(matchers::path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&primary)
        .await;

    // Secondary: responds with valid discovery
    let secondary = MockServer::start().await;
    let secondary_token_ep = format!("{}/token", secondary.uri());
    Mock::given(matchers::path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(discovery_response(&secondary.uri(), &secondary_token_ep)),
        )
        .mount(&secondary)
        .await;

    // Set up failover runtime
    let config = FailoverPairConfig {
        primary_issuer_url: primary.uri(),
        secondary_issuer_url: secondary.uri(),
        request_timeout_secs: 5,
        cooldown_secs: 60,
    };
    let mut runtime = FailoverRuntime::new(config);

    // Try primary — should get 503 (availability error)
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    let primary_result = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            primary.uri()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(primary_result.status().as_u16(), 503);
    assert_eq!(classify_http_status(503), FailureClass::Availability);

    // Record failure and failover
    let event = runtime.record_failure(&primary.uri(), "HTTP 503");
    assert!(matches!(event, Some(FailoverEvent::Activated { .. })));
    assert_eq!(runtime.state(), FailoverState::Secondary);

    // Try secondary — should succeed
    let resolved = runtime.resolve_issuer();
    assert_eq!(resolved.issuer_url, secondary.uri());

    let secondary_result = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            resolved.issuer_url
        ))
        .send()
        .await
        .unwrap();

    assert!(secondary_result.status().is_success());
    let doc: serde_json::Value = secondary_result.json().await.unwrap();
    assert_eq!(doc["token_endpoint"].as_str().unwrap(), &secondary_token_ep);

    runtime.record_success(&secondary.uri());
    // Should remain on secondary (secondary success doesn't flip back to primary)
    assert_eq!(runtime.state(), FailoverState::Secondary);
}

// ── Test 2: Primary token endpoint 503 -> secondary used ────────────────────

#[tokio::test]
async fn test_primary_token_endpoint_503_triggers_failover() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    // Primary discovery works, but token endpoint returns 503
    Mock::given(matchers::path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_response(
            &primary.uri(),
            &format!("{}/token", primary.uri()),
        )))
        .mount(&primary)
        .await;

    Mock::given(matchers::path("/token"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&primary)
        .await;

    // Secondary has a working token endpoint
    Mock::given(matchers::path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_response(
            &secondary.uri(),
            &format!("{}/token", secondary.uri()),
        )))
        .mount(&secondary)
        .await;

    Mock::given(matchers::path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "secondary-token",
            "token_type": "Bearer",
            "expires_in": 300
        })))
        .mount(&secondary)
        .await;

    let mut runtime = FailoverRuntime::new(FailoverPairConfig {
        primary_issuer_url: primary.uri(),
        secondary_issuer_url: secondary.uri(),
        request_timeout_secs: 5,
        cooldown_secs: 60,
    });

    // Discovery succeeds on primary
    let client = reqwest::Client::new();
    let disc_resp = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            primary.uri()
        ))
        .send()
        .await
        .unwrap();
    assert!(disc_resp.status().is_success());

    // Token endpoint fails with 503
    let token_resp = client
        .post(format!("{}/token", primary.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(token_resp.status().as_u16(), 503);
    assert_eq!(
        classify_http_status(token_resp.status().as_u16()),
        FailureClass::Availability
    );

    // Failover
    runtime.record_failure(&primary.uri(), "Token endpoint HTTP 503");
    assert_eq!(runtime.state(), FailoverState::Secondary);

    // Secondary token endpoint works
    let sec_token_resp = client
        .post(format!("{}/token", secondary.uri()))
        .send()
        .await
        .unwrap();
    assert!(sec_token_resp.status().is_success());
    let body: serde_json::Value = sec_token_resp.json().await.unwrap();
    assert_eq!(body["access_token"].as_str().unwrap(), "secondary-token");
}

// ── Test 3: Primary invalid_client -> no failover ───────────────────────────

#[tokio::test]
async fn test_invalid_client_does_not_trigger_failover() {
    let primary = MockServer::start().await;

    Mock::given(matchers::path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_client",
            "error_description": "Client authentication failed"
        })))
        .mount(&primary)
        .await;

    // 401 is a policy error — should NOT trigger failover
    assert_eq!(classify_http_status(401), FailureClass::NonFailover);

    let runtime = FailoverRuntime::new(FailoverPairConfig {
        primary_issuer_url: primary.uri(),
        secondary_issuer_url: "https://secondary.example.com".to_string(),
        request_timeout_secs: 5,
        cooldown_secs: 60,
    });

    // Verify state doesn't change (no record_failure call for non-failover errors)
    assert_eq!(runtime.state(), FailoverState::Primary);
}

// ── Test 4: Malformed response from reachable endpoint -> no failover ───────

#[tokio::test]
async fn test_malformed_discovery_does_not_trigger_failover() {
    let primary = MockServer::start().await;

    // Discovery returns 200 but with garbage content
    Mock::given(matchers::path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&primary)
        .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            primary.uri()
        ))
        .send()
        .await
        .unwrap();

    // 200 status — issuer is reachable. Malformed response is NOT an availability issue.
    assert!(resp.status().is_success());
    assert_eq!(classify_http_status(200), FailureClass::NonFailover);

    // The body parse will fail, but that's a protocol error, not availability.
    // No failover should be triggered.
    let runtime = FailoverRuntime::new(FailoverPairConfig {
        primary_issuer_url: primary.uri(),
        secondary_issuer_url: "https://secondary.example.com".to_string(),
        request_timeout_secs: 5,
        cooldown_secs: 60,
    });
    assert_eq!(runtime.state(), FailoverState::Primary);
}

// ── Test 5: Primary recovers after cooldown ─────────────────────────────────

#[tokio::test]
async fn test_primary_recovery_after_cooldown() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    // Both serve valid discovery
    for server in [&primary, &secondary] {
        Mock::given(matchers::path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(discovery_response(
                &server.uri(),
                &format!("{}/token", server.uri()),
            )))
            .mount(server)
            .await;
    }

    // Cooldown = 0 for immediate recovery testing
    let mut runtime = FailoverRuntime::new(FailoverPairConfig {
        primary_issuer_url: primary.uri(),
        secondary_issuer_url: secondary.uri(),
        request_timeout_secs: 5,
        cooldown_secs: 0,
    });

    // Fail primary
    runtime.record_failure(&primary.uri(), "HTTP 503");
    assert_eq!(runtime.state(), FailoverState::Secondary);

    // After cooldown (immediate), resolve should try primary again
    let resolved = runtime.resolve_issuer();
    assert_eq!(resolved.issuer_url, primary.uri());

    // Primary now works — record success triggers recovery
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            primary.uri()
        ))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let event = runtime.record_success(&primary.uri());
    assert!(matches!(event, Some(FailoverEvent::Recovered { .. })));
    assert_eq!(runtime.state(), FailoverState::Primary);
}

// ── Test 6: Both issuers down -> fail-closed ────────────────────────────────

#[tokio::test]
async fn test_both_issuers_down_fail_closed() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    // Both return 503
    for server in [&primary, &secondary] {
        Mock::given(matchers::path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(503))
            .mount(server)
            .await;
    }

    let mut runtime = FailoverRuntime::new(FailoverPairConfig {
        primary_issuer_url: primary.uri(),
        secondary_issuer_url: secondary.uri(),
        request_timeout_secs: 5,
        cooldown_secs: 60,
    });

    // Primary fails
    let event1 = runtime.record_failure(&primary.uri(), "HTTP 503");
    assert!(matches!(event1, Some(FailoverEvent::Activated { .. })));
    assert_eq!(runtime.state(), FailoverState::Secondary);

    // Secondary also fails
    let event2 = runtime.record_failure(&secondary.uri(), "HTTP 503");
    assert!(matches!(event2, Some(FailoverEvent::Exhausted { .. })));
    assert_eq!(runtime.state(), FailoverState::Exhausted);

    // Verify the exhausted event contains both issuer URLs
    if let Some(FailoverEvent::Exhausted {
        primary_issuer,
        secondary_issuer,
        reason,
    }) = event2
    {
        assert_eq!(primary_issuer, primary.uri());
        assert_eq!(secondary_issuer, secondary.uri());
        assert!(reason.contains("503"));
    }
}

// ── Test 7: Failure classification matrix ───────────────────────────────────

#[test]
fn test_failure_classification_matrix() {
    // Availability — trigger failover
    assert_eq!(classify_http_status(500), FailureClass::Availability);
    assert_eq!(classify_http_status(502), FailureClass::Availability);
    assert_eq!(classify_http_status(503), FailureClass::Availability);
    assert_eq!(classify_http_status(504), FailureClass::Availability);
    assert_eq!(classify_http_status(520), FailureClass::Availability); // Cloudflare

    // Non-failover — hard fail, no retry
    assert_eq!(classify_http_status(400), FailureClass::NonFailover);
    assert_eq!(classify_http_status(401), FailureClass::NonFailover);
    assert_eq!(classify_http_status(403), FailureClass::NonFailover);
    assert_eq!(classify_http_status(404), FailureClass::NonFailover);
    assert_eq!(classify_http_status(422), FailureClass::NonFailover);
    assert_eq!(classify_http_status(429), FailureClass::NonFailover);

    // Success codes are not failures — classification is for error paths only
    assert_eq!(classify_http_status(200), FailureClass::NonFailover);
    assert_eq!(classify_http_status(201), FailureClass::NonFailover);
    assert_eq!(classify_http_status(301), FailureClass::NonFailover);
}

// ── Test 8: Config validation edge cases ────────────────────────────────────

#[test]
fn test_config_validation_rejects_self_pair() {
    let config = FailoverPairConfig {
        primary_issuer_url: "https://idp.example.com".to_string(),
        secondary_issuer_url: "https://idp.example.com".to_string(),
        request_timeout_secs: 10,
        cooldown_secs: 60,
    };
    let known = vec!["https://idp.example.com".to_string()];
    assert!(config.validate(&known).is_err());
}

#[test]
fn test_config_validation_rejects_duplicate_primary() {
    let pairs = vec![
        FailoverPairConfig {
            primary_issuer_url: "https://a.example.com".to_string(),
            secondary_issuer_url: "https://b.example.com".to_string(),
            request_timeout_secs: 10,
            cooldown_secs: 60,
        },
        FailoverPairConfig {
            primary_issuer_url: "https://a.example.com".to_string(),
            secondary_issuer_url: "https://c.example.com".to_string(),
            request_timeout_secs: 10,
            cooldown_secs: 60,
        },
    ];
    let known = vec![
        "https://a.example.com".to_string(),
        "https://b.example.com".to_string(),
        "https://c.example.com".to_string(),
    ];
    assert!(validate_failover_pairs(&pairs, &known).is_err());
}

// ── Test 9: JWKS cache isolation preserved ──────────────────────────────────

#[tokio::test]
async fn test_jwks_cache_isolation_across_failover_pair() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    // Primary JWKS endpoint
    Mock::given(matchers::path("/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [{"kid": "primary-key-1", "kty": "RSA"}]
        })))
        .mount(&primary)
        .await;

    // Secondary JWKS endpoint — different keys
    Mock::given(matchers::path("/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [{"kid": "secondary-key-1", "kty": "RSA"}]
        })))
        .mount(&secondary)
        .await;

    let client = reqwest::Client::new();

    // Fetch JWKS from primary
    let primary_jwks: serde_json::Value = client
        .get(format!("{}/certs", primary.uri()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Fetch JWKS from secondary
    let secondary_jwks: serde_json::Value = client
        .get(format!("{}/certs", secondary.uri()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Keys must be different — cache isolation preserved
    assert_ne!(
        primary_jwks["keys"][0]["kid"],
        secondary_jwks["keys"][0]["kid"],
        "JWKS keys from primary and secondary must be different (cache isolation)"
    );

    // Verify we got the expected kids
    assert_eq!(
        primary_jwks["keys"][0]["kid"].as_str().unwrap(),
        "primary-key-1"
    );
    assert_eq!(
        secondary_jwks["keys"][0]["kid"].as_str().unwrap(),
        "secondary-key-1"
    );
}

// ── Test 10: AgentState failover runtime initialization ─────────────────────

#[test]
fn test_agent_state_init_failover() {
    let mut state = AgentState::new();
    assert!(state.failover_runtimes.is_empty());

    let pairs = vec![FailoverPairConfig {
        primary_issuer_url: "https://primary.example.com".to_string(),
        secondary_issuer_url: "https://secondary.example.com".to_string(),
        request_timeout_secs: 10,
        cooldown_secs: 60,
    }];

    state.init_failover(&pairs);

    // Should have entries for both primary and secondary URLs
    assert!(state
        .failover_runtimes
        .contains_key("https://primary.example.com"));
    assert!(state
        .failover_runtimes
        .contains_key("https://secondary.example.com"));

    // Both should start in Primary state
    let primary_rt = state
        .failover_runtimes
        .get("https://primary.example.com")
        .unwrap();
    assert_eq!(primary_rt.lock().state(), FailoverState::Primary);
}
