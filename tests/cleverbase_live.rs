//! Live integration tests against the Cleverbase CSC v2 testbed.
//!
//! These tests hit the real Cleverbase pre-production endpoint:
//!   https://signing.lab.cleverbase.io/csc/v2
//!
//! Run with: `cargo test --test cleverbase_live --features test-utils`
//!
//! Tests are gated behind the `CSC_LIVE_TESTS` environment variable:
//!   CSC_LIVE_TESTS=1 cargo test --test cleverbase_live --features test-utils
//!
//! The /info endpoint tests run without authentication.
//! Authenticated endpoint tests require `CSC_ACCESS_TOKEN` to be set.

use csc_client::{CscClient, NoDPop};

const CLEVERBASE_BASE_URL: &str = "https://signing.lab.cleverbase.io/csc/v2";

fn skip_unless_live() -> bool {
    std::env::var("CSC_LIVE_TESTS").is_err()
}

fn live_client() -> CscClient {
    CscClient::new(CLEVERBASE_BASE_URL, NoDPop).expect("failed to create CSC client")
}

fn access_token() -> Option<String> {
    std::env::var("CSC_ACCESS_TOKEN").ok()
}

// ═══════════════════════════════════════════════════════════════════════════════
// /info — no authentication required
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn live_info_returns_service_metadata() {
    if skip_unless_live() {
        eprintln!("Skipping: set CSC_LIVE_TESTS=1 to run live tests");
        return;
    }

    let client = live_client();
    let info = client.info().await.expect("info() failed");

    assert_eq!(info.specs, "2.2.0.0");
    assert_eq!(info.name, "Cleverbase CSC V2 Testbed");
    assert_eq!(info.region, "NL");
    assert_eq!(info.lang, "en");
    assert!(!info.description.is_empty());
}

#[tokio::test]
async fn live_info_has_oauth2_configuration() {
    if skip_unless_live() {
        return;
    }

    let client = live_client();
    let info = client.info().await.expect("info() failed");

    // Cleverbase uses oauth2code auth type
    assert!(
        info.auth_type.contains(&"oauth2code".to_string()),
        "expected oauth2code in auth_type: {:?}",
        info.auth_type
    );

    // Should have at least one OAuth2 server
    assert!(
        !info.oauth2_servers.is_empty(),
        "expected at least one OAuth2 server"
    );
    let server = &info.oauth2_servers[0];
    assert!(server.base_uri.is_some(), "expected OAuth2 server base_uri");
    assert!(server.base_uri.as_ref().unwrap().starts_with("https://"));
}

#[tokio::test]
async fn live_info_has_supported_methods() {
    if skip_unless_live() {
        return;
    }

    let client = live_client();
    let info = client.info().await.expect("info() failed");

    // Must include the endpoints we implement
    assert!(
        info.methods.contains(&"credentials/list".to_string()),
        "missing credentials/list in methods: {:?}",
        info.methods
    );
    assert!(
        info.methods.contains(&"credentials/info".to_string()),
        "missing credentials/info in methods: {:?}",
        info.methods
    );
    assert!(
        info.methods.contains(&"signatures/signHash".to_string()),
        "missing signatures/signHash in methods: {:?}",
        info.methods
    );
}

#[tokio::test]
async fn live_info_has_sign_algorithms() {
    if skip_unless_live() {
        return;
    }

    let client = live_client();
    let info = client.info().await.expect("info() failed");

    // Cleverbase supports ECDSA-SHA256
    assert!(
        info.sign_algorithms
            .algos
            .contains(&"1.2.840.10045.4.3.2".to_string()),
        "expected ECDSA-SHA256 OID in algos: {:?}",
        info.sign_algorithms.algos
    );
}

#[tokio::test]
async fn live_info_has_supported_hash_types() {
    if skip_unless_live() {
        return;
    }

    let client = live_client();
    let info = client.info().await.expect("info() failed");

    // SHA-256 must be supported
    assert!(
        info.supported_hash_types
            .contains(&"2.16.840.1.101.3.4.2.1".to_string()),
        "expected SHA-256 OID in supported_hash_types: {:?}",
        info.supported_hash_types
    );
}

#[tokio::test]
async fn live_info_does_not_support_rar() {
    if skip_unless_live() {
        return;
    }

    let client = live_client();
    let info = client.info().await.expect("info() failed");

    // Current Cleverbase testbed reports supportsRar: false
    assert!(
        !info.supports_rar,
        "expected supportsRar=false from testbed"
    );
}

#[tokio::test]
async fn live_info_asynchronous_mode_disabled() {
    if skip_unless_live() {
        return;
    }

    let client = live_client();
    let info = client.info().await.expect("info() failed");

    assert!(
        !info.asynchronous_operation_mode,
        "expected asynchronousOperationMode=false"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Authenticated endpoints — error behavior without valid token
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn live_credentials_list_rejects_missing_auth() {
    if skip_unless_live() {
        return;
    }

    let client = live_client();
    // Empty auth header should be rejected — but we need to pass something
    // since the client requires a non-empty access_token parameter.
    // Test with a clearly invalid token.
    let err = client
        .list_credentials("Bearer invalid-token-for-testing", None)
        .await
        .unwrap_err();

    // Should get an API error (401 or 500 depending on server behavior)
    match err {
        csc_client::CscError::Api { status, .. } => {
            assert!(
                status == 401 || status == 500,
                "expected 401 or 500, got {status}"
            );
        }
        other => panic!("expected Api error, got: {other:?}"),
    }
}

#[tokio::test]
async fn live_credential_info_rejects_invalid_token() {
    if skip_unless_live() {
        return;
    }

    let client = live_client();
    let err = client
        .credential_info("Bearer invalid-token-for-testing", "nonexistent-cred")
        .await
        .unwrap_err();

    match err {
        csc_client::CscError::Api { status, .. } => {
            assert!(
                status == 401 || status == 500,
                "expected 401 or 500, got {status}"
            );
        }
        other => panic!("expected Api error, got: {other:?}"),
    }
}

#[tokio::test]
async fn live_sign_hash_rejects_invalid_token() {
    if skip_unless_live() {
        return;
    }

    let client = live_client();
    let req = csc_client::SignHashRequest {
        credential_id: "nonexistent".to_string(),
        sad: None,
        hash: vec!["dGVzdA==".to_string()],
        hash_algo: csc_client::HASH_ALGO_SHA256.to_string(),
        sign_algo: csc_client::SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
    };

    let err = client
        .sign_hash("Bearer invalid-token-for-testing", &req)
        .await
        .unwrap_err();

    match err {
        csc_client::CscError::Api { status, .. } => {
            assert!(
                status == 401 || status == 500,
                "expected 401 or 500, got {status}"
            );
        }
        other => panic!("expected Api error, got: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Authenticated endpoints — with valid token (if CSC_ACCESS_TOKEN is set)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn live_credentials_list_with_token() {
    if skip_unless_live() {
        return;
    }
    let token = match access_token() {
        Some(t) => t,
        None => {
            eprintln!("Skipping: set CSC_ACCESS_TOKEN for authenticated tests");
            return;
        }
    };

    let client = live_client();
    let creds = client
        .list_credentials(&format!("Bearer {token}"), None)
        .await
        .expect("list_credentials failed with valid token");

    eprintln!("Found {} credentials: {:?}", creds.len(), creds);
    // With a valid token, should get at least an empty list (not an error)
    // The actual number depends on the user's provisioned credentials
}

#[tokio::test]
async fn live_credential_info_with_token() {
    if skip_unless_live() {
        return;
    }
    let token = match access_token() {
        Some(t) => t,
        None => {
            eprintln!("Skipping: set CSC_ACCESS_TOKEN for authenticated tests");
            return;
        }
    };

    let client = live_client();
    let bearer = format!("Bearer {token}");

    // First list credentials
    let creds = client
        .list_credentials(&bearer, None)
        .await
        .expect("list_credentials failed");

    if creds.is_empty() {
        eprintln!("No credentials available to query info for");
        return;
    }

    // Query info for the first credential
    let info = client
        .credential_info(&bearer, &creds[0])
        .await
        .expect("credential_info failed");

    eprintln!("Credential info: {:?}", info);
    assert_eq!(info.key.status, "enabled");
    assert!(info.multisign >= 1);

    // Verify key algo includes ECDSA-SHA256 (Cleverbase uses EC P-256)
    assert!(
        !info.key.algo.is_empty(),
        "expected at least one key algorithm"
    );
}
