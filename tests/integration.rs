//! Integration tests for the CSC client using wiremock.

use csc_client::{CscClient, NoDPop, SignHashRequest, HASH_ALGO_SHA256, SIGN_ALGO_ECDSA_SHA256};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_client(server: &MockServer) -> CscClient {
    CscClient::new_insecure(&server.uri(), NoDPop).unwrap()
}

#[tokio::test]
async fn list_credentials_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialIDs": ["cred-001", "cred-002"]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let creds = client
        .list_credentials("Bearer test-token", None)
        .await
        .unwrap();

    assert_eq!(creds, vec!["cred-001", "cred-002"]);
}

#[tokio::test]
async fn list_credentials_with_status_filter() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .and(body_json(serde_json::json!({
            "credentialStatus": "enabled"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialIDs": ["cred-001"]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let creds = client
        .list_credentials("Bearer test-token", Some("enabled"))
        .await
        .unwrap();

    assert_eq!(creds, vec!["cred-001"]);
}

#[tokio::test]
async fn credential_info_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "description": "Test signing key",
            "key": {
                "status": "enabled",
                "algo": ["1.2.840.10045.4.3.2"],
                "len": 256,
                "curve": "P-256"
            },
            "cert": {
                "status": "valid",
                "certificates": ["MIIB..."],
                "subjectDN": "CN=Test User",
                "issuerDN": "CN=Test CA",
                "validFrom": "2026-01-01T00:00:00Z",
                "validTo": "2027-01-01T00:00:00Z"
            },
            "auth": {
                "mode": "explicit",
                "expression": "PIN"
            },
            "multisign": 1,
            "status": "enabled",
            "algo": ["1.2.840.10045.4.3.2"]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let info = client
        .credential_info("Bearer test-token", "cred-001")
        .await
        .unwrap();

    assert_eq!(info.description, "Test signing key");
    assert_eq!(info.key.status, "enabled");
    assert_eq!(info.key.curve, Some("P-256".to_string()));
    assert_eq!(
        info.cert.as_ref().unwrap().subject_dn,
        Some("CN=Test User".to_string())
    );
    assert_eq!(info.auth.as_ref().unwrap().mode, "explicit");
    assert_eq!(info.multisign, 1);
}

#[tokio::test]
async fn sign_hash_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/signatures/signHash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signatures": ["MEUCIQD...", "MEUCIBf..."]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let req = SignHashRequest {
        credential_id: "cred-001".to_string(),
        sad: Some("activation-token-123".to_string()),
        hash: vec![
            "dGVzdC1oYXNoLTE=".to_string(),
            "dGVzdC1oYXNoLTI=".to_string(),
        ],
        hash_algo: HASH_ALGO_SHA256.to_string(),
        sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    let sigs = client.sign_hash("Bearer test-token", &req).await.unwrap();
    assert_eq!(sigs.len(), 2);
    assert_eq!(sigs[0], "MEUCIQD...");
}

#[tokio::test]
async fn api_error_response() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_token",
            "error_description": "The access token has expired"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let err = client
        .list_credentials("Bearer expired-token", None)
        .await
        .unwrap_err();

    let err_str = err.to_string();
    assert!(
        err_str.contains("invalid_token"),
        "expected invalid_token in: {err_str}"
    );
    assert!(
        err_str.contains("expired"),
        "expected 'expired' in: {err_str}"
    );
}

#[tokio::test]
async fn dpop_signer_is_called() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .and(header("DPoP", "test-dpop-proof"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialIDs": ["cred-001"]
        })))
        .mount(&server)
        .await;

    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();

    struct TestDPopSigner {
        called: Arc<AtomicBool>,
    }

    impl csc_client::DPopSigner for TestDPopSigner {
        fn sign_dpop(
            &self,
            _http_method: &str,
            _http_url: &str,
            _access_token: Option<&str>,
        ) -> std::result::Result<String, String> {
            self.called.store(true, Ordering::SeqCst);
            Ok("test-dpop-proof".to_string())
        }
    }

    let client = CscClient::new_insecure(
        &server.uri(),
        TestDPopSigner {
            called: called_clone,
        },
    )
    .unwrap();
    let creds = client
        .list_credentials("Bearer test-token", None)
        .await
        .unwrap();

    assert_eq!(creds, vec!["cred-001"]);
    assert!(called.load(Ordering::SeqCst), "DPoP signer was not called");
}
