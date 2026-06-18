//! Conformance tests for CSC API v2.2 against the Cleverbase testbed spec.
//!
//! These tests verify that the csc-client correctly implements the CSC v2.2 wire
//! protocol as defined by the Cleverbase OpenAPI spec at:
//!   https://signing.lab.cleverbase.io/csc/v2/docs/docs.yaml
//!
//! Key areas:
//! - Field name serialization (camelCase → actual CSC v2.2 field names)
//! - `/info` endpoint (not yet implemented — tests marked #[ignore])
//! - Error response parsing for all HTTP status codes
//! - DPoP proof mechanics (method, URL, ath claim pass-through)
//! - Pagination via pageToken
//! - Credential info with all optional fields

use csc_client::{
    CscClient, CscError, DPopSigner, NoDPop, SignHashRequest, HASH_ALGO_SHA256,
    SIGN_ALGO_ECDSA_SHA256,
};
use serde_json::Value;
use std::sync::Arc;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

fn test_client(server: &MockServer) -> CscClient {
    CscClient::new_insecure(&server.uri(), NoDPop).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wire format: SignHashRequest field names
// ═══════════════════════════════════════════════════════════════════════════════
//
// The Cleverbase spec uses:
//   credentialID, SAD, hashes, hashAlgorithmOID, signAlgo, signAlgoParams
//
// The current client serializes with #[serde(rename_all = "camelCase")] which
// produces: credentialId, sad, hash, hashAlgo, signAlgo, signAlgoParams
//
// These tests document the expected wire format per CSC v2.2.

/// Verify SignHashRequest serializes field `credentialID` (not `credentialId`).
#[tokio::test]
async fn sign_hash_request_credential_id_field_name() {
    let server = MockServer::start().await;

    // The spec requires `credentialID` (uppercase ID)
    Mock::given(method("POST"))
        .and(path("/signatures/signHash"))
        .and(body_partial_json(serde_json::json!({
            "credentialID": "cred-001"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signatures": ["MEUCIQD..."]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let req = SignHashRequest {
        credential_id: "cred-001".to_string(),
        sad: None,
        hash: vec!["dGVzdA==".to_string()],
        hash_algo: HASH_ALGO_SHA256.to_string(),
        sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    let result = client.sign_hash("Bearer tok", &req).await;
    // If this fails with a wiremock "no matching mock" error, the field name is wrong
    assert!(
        result.is_ok(),
        "credentialID field name mismatch: {result:?}"
    );
}

/// Verify SignHashRequest serializes `SAD` (all-caps per spec, not `sad`).
#[tokio::test]
async fn sign_hash_request_sad_field_name() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/signatures/signHash"))
        .and(body_partial_json(serde_json::json!({
            "SAD": "activation-data-xyz"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signatures": ["sig1"]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let req = SignHashRequest {
        credential_id: "cred-001".to_string(),
        sad: Some("activation-data-xyz".to_string()),
        hash: vec!["dGVzdA==".to_string()],
        hash_algo: HASH_ALGO_SHA256.to_string(),
        sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    let result = client.sign_hash("Bearer tok", &req).await;
    assert!(result.is_ok(), "SAD field name mismatch: {result:?}");
}

/// Verify SignHashRequest serializes `hashes` (plural per spec, not `hash`).
#[tokio::test]
async fn sign_hash_request_hashes_field_name() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/signatures/signHash"))
        .and(body_partial_json(serde_json::json!({
            "hashes": ["aGFzaDE=", "aGFzaDI="]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signatures": ["sig1", "sig2"]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let req = SignHashRequest {
        credential_id: "cred-001".to_string(),
        sad: None,
        hash: vec!["aGFzaDE=".to_string(), "aGFzaDI=".to_string()],
        hash_algo: HASH_ALGO_SHA256.to_string(),
        sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    let result = client.sign_hash("Bearer tok", &req).await;
    assert!(result.is_ok(), "hashes field name mismatch: {result:?}");
}

/// Verify SignHashRequest serializes `hashAlgorithmOID` (not `hashAlgo`).
#[tokio::test]
async fn sign_hash_request_hash_algorithm_oid_field_name() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/signatures/signHash"))
        .and(body_partial_json(serde_json::json!({
            "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signatures": ["sig1"]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let req = SignHashRequest {
        credential_id: "cred-001".to_string(),
        sad: None,
        hash: vec!["dGVzdA==".to_string()],
        hash_algo: HASH_ALGO_SHA256.to_string(),
        sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    let result = client.sign_hash("Bearer tok", &req).await;
    assert!(
        result.is_ok(),
        "hashAlgorithmOID field name mismatch: {result:?}"
    );
}

/// Verify CredentialsInfoRequest serializes `credentialID` (not `credentialId`).
#[tokio::test]
async fn credential_info_request_credential_id_field_name() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/info"))
        .and(body_partial_json(serde_json::json!({
            "credentialID": "my-cred"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialID": "my-cred",
            "key": { "status": "enabled", "len": 256 },
            "cert": { "status": "valid" },
            "auth": { "mode": "implicit" },
            "multisign": 1
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let result = client.credential_info("Bearer tok", "my-cred").await;
    assert!(
        result.is_ok(),
        "credentialID field name mismatch in info request: {result:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// /info endpoint (CSC v2.2 §8.2.1 — service discovery)
// ═══════════════════════════════════════════════════════════════════════════════

/// Service info returns QTSP metadata including supported algorithms.
#[tokio::test]
async fn info_returns_service_metadata() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "specs": "2.2.0.0",
            "name": "Cleverbase Signing",
            "logo": "https://cleverbase.com/logo.png",
            "region": "EU",
            "lang": "en",
            "description": "Qualified Electronic Signature service",
            "authType": ["oauth2code"],
            "oauth2Servers": [{
                "label": "Cleverbase OAuth",
                "baseUri": "https://auth.cleverbase.io",
                "issuerIdentifier": "https://auth.cleverbase.io",
                "authType": ["oauth2code"],
                "supportsRar": true
            }],
            "supportsRar": true,
            "methods": [
                "credentials/list",
                "credentials/info",
                "signatures/signHash"
            ],
            "signAlgorithms": {
                "algos": ["1.2.840.10045.4.3.2", "1.2.840.113549.1.1.11"],
                "algoParams": []
            },
            "signature_formats": {
                "formats": ["P", "C", "X", "B"],
                "envelope_properties": [],
                "allowMix": false
            }
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let info = client.info().await.unwrap();
    assert_eq!(info.specs, "2.2.0.0");
    assert_eq!(info.name, "Cleverbase Signing");
    assert!(info.supports_rar);
    assert!(info.methods.contains(&"signatures/signHash".to_string()));
    assert_eq!(info.sign_algorithms.algos.len(), 2);
}

/// Service info does NOT require authentication (per CSC v2.2 spec).
#[tokio::test]
async fn info_no_auth_required() {
    let server = MockServer::start().await;

    // Mount without auth header matcher — endpoint is public
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "specs": "2.2.0.0",
            "name": "Test",
            "logo": "",
            "region": "EU",
            "lang": "en",
            "description": "Test service",
            "signAlgorithms": { "algos": [], "algoParams": [] },
            "signature_formats": { "formats": [], "envelope_properties": [], "allowMix": false }
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let info = client.info().await.unwrap();
    assert_eq!(info.specs, "2.2.0.0");
}

/// Info response with null fields (matching actual Cleverbase testbed output).
#[tokio::test]
async fn info_handles_null_fields() {
    let server = MockServer::start().await;

    // Exact response from the live Cleverbase testbed (has nulls)
    Mock::given(method("POST"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "specs": "2.2.0.0",
            "name": "Cleverbase CSC V2 Testbed",
            "logo": "https://cleverbase.com/images/product-card.svg",
            "region": "NL",
            "lang": "en",
            "description": "CSC V2 test service",
            "authType": ["oauth2code"],
            "oauth2Servers": [{
                "label": null,
                "baseUri": "https://signing.lab.cleverbase.io/idp",
                "issuerIdentifier": null,
                "authType": ["oauth2code"],
                "supportsRar": false
            }],
            "oauth2": "https://signing.lab.cleverbase.io/idp",
            "oauth2Issuer": null,
            "supportsRar": false,
            "supportedHashTypes": ["2.16.840.1.101.3.4.2.1"],
            "asynchronousOperationMode": false,
            "methods": ["oauth2/authorize", "oauth2/pushed_authorize",
                        "credentials/list", "credentials/info", "signatures/signHash"],
            "validationInfo": false,
            "signAlgorithms": {"algos": ["1.2.840.10045.4.3.2"], "algoParams": null},
            "documentTypes": null,
            "signature_formats": {"formats": [], "envelope_properties": null, "allowMix": null},
            "conformance_levels": []
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let info = client.info().await.unwrap();
    assert_eq!(info.name, "Cleverbase CSC V2 Testbed");
    assert_eq!(info.region, "NL");
    assert!(!info.supports_rar);
    assert_eq!(
        info.oauth2,
        Some("https://signing.lab.cleverbase.io/idp".to_string())
    );
    assert_eq!(info.oauth2_issuer, None);
    assert_eq!(info.supported_hash_types, vec!["2.16.840.1.101.3.4.2.1"]);
    assert!(!info.asynchronous_operation_mode);
    // OAuth2 server with null label should parse fine
    assert_eq!(info.oauth2_servers[0].label, None);
    assert_eq!(
        info.oauth2_servers[0].base_uri,
        Some("https://signing.lab.cleverbase.io/idp".to_string())
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Error handling: Various HTTP status codes
// ═══════════════════════════════════════════════════════════════════════════════

/// 400 Bad Request returns a text/plain body (per Cleverbase spec).
#[tokio::test]
async fn bad_request_text_plain_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("Invalid value for: body")
                .insert_header("Content-Type", "text/plain"),
        )
        .mount(&server)
        .await;

    let client = test_client(&server);
    let err = client
        .list_credentials("Bearer tok", None)
        .await
        .unwrap_err();

    // The client should handle non-JSON error bodies gracefully
    match err {
        CscError::Api { status, .. } => assert_eq!(status, 400),
        _ => panic!("expected Api error, got: {err:?}"),
    }
}

/// 403 Forbidden when credential access is denied.
#[tokio::test]
async fn forbidden_credential_access() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/info"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "access_denied",
            "error_description": "Credential does not belong to the authenticated user"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let err = client
        .credential_info("Bearer tok", "someone-elses-cred")
        .await
        .unwrap_err();

    match err {
        CscError::Api {
            status,
            ref error,
            ref error_description,
        } => {
            assert_eq!(status, 403);
            assert_eq!(error, "access_denied");
            assert!(error_description.contains("does not belong"));
        }
        _ => panic!("expected Api error, got: {err:?}"),
    }
}

/// 500 Internal Server Error with CSC error body.
#[tokio::test]
async fn server_error_with_csc_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/signatures/signHash"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "error": "server_error",
            "error_description": "Internal HSM communication failure"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let req = SignHashRequest {
        credential_id: "cred-001".to_string(),
        sad: Some("valid-sad".to_string()),
        hash: vec!["dGVzdA==".to_string()],
        hash_algo: HASH_ALGO_SHA256.to_string(),
        sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    let err = client.sign_hash("Bearer tok", &req).await.unwrap_err();
    match err {
        CscError::Api { status, .. } => assert_eq!(status, 500),
        _ => panic!("expected Api error, got: {err:?}"),
    }
}

/// Empty body on error response (malformed server response).
#[tokio::test]
async fn error_response_empty_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let err = client
        .list_credentials("Bearer tok", None)
        .await
        .unwrap_err();

    // Should not panic, should produce a sensible error
    match err {
        CscError::Api { status, .. } => assert_eq!(status, 502),
        _ => panic!("expected Api error with status 502, got: {err:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DPoP proof mechanics
// ═══════════════════════════════════════════════════════════════════════════════

/// DPoP signer receives the correct HTTP method and URL.
#[tokio::test]
async fn dpop_signer_receives_correct_method_and_url() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialIDs": []
        })))
        .mount(&server)
        .await;

    let captured_method = Arc::new(std::sync::Mutex::new(String::new()));
    let captured_url = Arc::new(std::sync::Mutex::new(String::new()));
    let cm = captured_method.clone();
    let cu = captured_url.clone();

    struct CaptureDPopSigner {
        method: Arc<std::sync::Mutex<String>>,
        url: Arc<std::sync::Mutex<String>>,
    }

    impl DPopSigner for CaptureDPopSigner {
        fn sign_dpop(
            &self,
            http_method: &str,
            http_url: &str,
            _access_token: Option<&str>,
        ) -> std::result::Result<String, String> {
            *self.method.lock().unwrap() = http_method.to_string();
            *self.url.lock().unwrap() = http_url.to_string();
            Ok("proof".to_string())
        }
    }

    let client = CscClient::new_insecure(
        &server.uri(),
        CaptureDPopSigner {
            method: cm,
            url: cu,
        },
    )
    .unwrap();

    client
        .list_credentials("Bearer test-token", None)
        .await
        .unwrap();

    assert_eq!(*captured_method.lock().unwrap(), "POST");
    let expected_url = format!("{}/credentials/list", server.uri());
    assert_eq!(*captured_url.lock().unwrap(), expected_url);
}

/// DPoP signer receives the access token (without "Bearer " prefix) for `ath` claim.
#[tokio::test]
async fn dpop_signer_receives_access_token_without_bearer_prefix() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialIDs": []
        })))
        .mount(&server)
        .await;

    let captured_token = Arc::new(std::sync::Mutex::new(String::new()));
    let ct = captured_token.clone();

    struct TokenCaptureSigner {
        token: Arc<std::sync::Mutex<String>>,
    }

    impl DPopSigner for TokenCaptureSigner {
        fn sign_dpop(
            &self,
            _http_method: &str,
            _http_url: &str,
            access_token: Option<&str>,
        ) -> std::result::Result<String, String> {
            *self.token.lock().unwrap() = access_token.unwrap_or("").to_string();
            Ok("proof".to_string())
        }
    }

    let client = CscClient::new_insecure(&server.uri(), TokenCaptureSigner { token: ct }).unwrap();

    client
        .list_credentials("Bearer my-opaque-token-xyz", None)
        .await
        .unwrap();

    // Should strip "Bearer " prefix before passing to signer
    assert_eq!(*captured_token.lock().unwrap(), "my-opaque-token-xyz");
}

/// DPoP signer failure propagates as CscError::DPop.
#[tokio::test]
async fn dpop_signer_failure_propagates() {
    let server = MockServer::start().await;

    // Server won't be hit because DPoP fails first
    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialIDs": []
        })))
        .mount(&server)
        .await;

    struct FailingSigner;

    impl DPopSigner for FailingSigner {
        fn sign_dpop(
            &self,
            _http_method: &str,
            _http_url: &str,
            _access_token: Option<&str>,
        ) -> std::result::Result<String, String> {
            Err("WSCD key unavailable".to_string())
        }
    }

    let client = CscClient::new_insecure(&server.uri(), FailingSigner).unwrap();
    let err = client
        .list_credentials("Bearer tok", None)
        .await
        .unwrap_err();

    match err {
        CscError::DPop(ref msg) => {
            assert!(msg.contains("WSCD key unavailable"), "got: {msg}");
        }
        _ => panic!("expected DPop error, got: {err:?}"),
    }
}

/// When DPoP signer returns empty string, no DPoP header is sent.
#[tokio::test]
async fn no_dpop_header_when_signer_returns_empty() {
    let server = MockServer::start().await;

    // Custom matcher that rejects requests WITH a DPoP header
    struct NoDPopHeader;
    impl Match for NoDPopHeader {
        fn matches(&self, request: &Request) -> bool {
            !request.headers.contains_key("DPoP")
        }
    }

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .and(NoDPopHeader)
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialIDs": ["cred-no-dpop"]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server); // uses NoDPop which returns ""
    let creds = client.list_credentials("Bearer tok", None).await.unwrap();

    assert_eq!(creds, vec!["cred-no-dpop"]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Response parsing edge cases
// ═══════════════════════════════════════════════════════════════════════════════

/// Empty credential list is valid.
#[tokio::test]
async fn list_credentials_empty_list() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialIDs": []
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let creds = client.list_credentials("Bearer tok", None).await.unwrap();

    assert!(creds.is_empty());
}

/// Credential info with minimal fields (only required ones per spec).
#[tokio::test]
async fn credential_info_minimal_response() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialID": "cred-min",
            "key": { "status": "enabled", "len": 256 },
            "cert": {},
            "auth": { "mode": "implicit" },
            "multisign": 5
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let info = client
        .credential_info("Bearer tok", "cred-min")
        .await
        .unwrap();

    assert_eq!(info.key.status, "enabled");
    assert_eq!(info.multisign, 5);
    // Cert fields should default gracefully
    let cert = info.cert.unwrap();
    assert_eq!(cert.certificates.len(), 0);
    assert_eq!(cert.subject_dn, None);
}

/// Credential info response with SCAL and signatureQualifier (extra fields
/// should be tolerated even if not modeled).
#[tokio::test]
async fn credential_info_extra_fields_tolerated() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialID": "cred-qual",
            "description": "Qualified cert",
            "signatureQualifier": "eu_eidas_qes",
            "key": {
                "status": "enabled",
                "algo": ["1.2.840.10045.4.3.2"],
                "len": 256,
                "curve": "P-256"
            },
            "cert": {
                "status": "valid",
                "certificates": ["MIIB...base64..."],
                "subjectDN": "CN=Qualified User,C=NL",
                "issuerDN": "CN=Cleverbase QCA,C=NL",
                "serialNumber": "123456789",
                "validFrom": "20260101000000Z",
                "validTo": "20270101000000Z"
            },
            "auth": {
                "mode": "oauth2code",
                "objects": ["credentials/authorize"]
            },
            "SCAL": "2",
            "multisign": 1,
            "lang": "en"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    // Should NOT fail even though response has fields not in our struct
    let info = client
        .credential_info("Bearer tok", "cred-qual")
        .await
        .unwrap();

    assert_eq!(info.description, "Qualified cert");
    assert_eq!(info.key.curve, Some("P-256".to_string()));
    let cert = info.cert.unwrap();
    assert_eq!(cert.serial_number, Some("123456789".to_string()));
}

/// SignHash with single hash (common case for document signing).
#[tokio::test]
async fn sign_hash_single_document() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/signatures/signHash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signatures": ["MEUCIQCx4..."]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let req = SignHashRequest {
        credential_id: "cred-001".to_string(),
        sad: Some("sad-token".to_string()),
        hash: vec!["47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_string()],
        hash_algo: HASH_ALGO_SHA256.to_string(),
        sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    let sigs = client.sign_hash("Bearer tok", &req).await.unwrap();
    assert_eq!(sigs.len(), 1);
}

/// SignHash without SAD (implicit authorization mode).
/// Verifies that when `sad` is None, the SAD field is not present in the request body.
#[tokio::test]
async fn sign_hash_implicit_auth_no_sad() {
    let server = MockServer::start().await;

    // Custom matcher: verify SAD/sad field is absent from the request body
    struct SadFieldAbsent;
    impl Match for SadFieldAbsent {
        fn matches(&self, request: &Request) -> bool {
            let body: Value = serde_json::from_slice(&request.body).unwrap_or_default();
            // Neither "SAD" nor "sad" should be present
            !body
                .as_object()
                .map_or(false, |o| o.contains_key("SAD") || o.contains_key("sad"))
        }
    }

    Mock::given(method("POST"))
        .and(path("/signatures/signHash"))
        .and(SadFieldAbsent)
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signatures": ["sig-implicit"]
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let req = SignHashRequest {
        credential_id: "cred-implicit".to_string(),
        sad: None,
        hash: vec!["dGVzdA==".to_string()],
        hash_algo: HASH_ALGO_SHA256.to_string(),
        sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    let result = client.sign_hash("Bearer tok", &req).await;
    assert!(
        result.is_ok(),
        "SAD field should be absent when None: {result:?}"
    );
    assert_eq!(result.unwrap(), vec!["sig-implicit"]);
}

/// SignHashResponse with responseID (async operation mode).
#[tokio::test]
async fn sign_hash_response_with_response_id() {
    let server = MockServer::start().await;

    // Cleverbase spec allows responseID in async mode
    Mock::given(method("POST"))
        .and(path("/signatures/signHash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signatures": ["sig1"],
            "responseID": "async-op-12345"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let req = SignHashRequest {
        credential_id: "cred-001".to_string(),
        sad: Some("sad".to_string()),
        hash: vec!["dGVzdA==".to_string()],
        hash_algo: HASH_ALGO_SHA256.to_string(),
        sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    // Should still succeed even with extra responseID field
    let sigs = client.sign_hash("Bearer tok", &req).await.unwrap();
    assert_eq!(sigs, vec!["sig1"]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Request headers
// ═══════════════════════════════════════════════════════════════════════════════

/// Content-Type header is application/json.
#[tokio::test]
async fn request_content_type_is_json() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialIDs": []
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let result = client.list_credentials("Bearer tok", None).await;
    assert!(result.is_ok(), "Content-Type not set: {result:?}");
}

/// Authorization header is forwarded verbatim.
#[tokio::test]
async fn authorization_header_forwarded() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .and(header("Authorization", "DPoP eyJhbGciOiJFUzI1NiJ9.xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialIDs": []
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    // Test with DPoP token type (not just Bearer)
    let result = client
        .list_credentials("DPoP eyJhbGciOiJFUzI1NiJ9.xyz", None)
        .await;
    assert!(result.is_ok(), "Auth header not forwarded: {result:?}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Base URL handling
// ═══════════════════════════════════════════════════════════════════════════════

/// Trailing slash in base URL is normalized.
#[tokio::test]
async fn base_url_trailing_slash_stripped() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialIDs": ["cred-1"]
        })))
        .mount(&server)
        .await;

    // Create client with trailing slash
    let url_with_slash = format!("{}/", server.uri());
    let client = CscClient::new_insecure(&url_with_slash, NoDPop).unwrap();
    let creds = client.list_credentials("Bearer tok", None).await.unwrap();

    assert_eq!(creds, vec!["cred-1"]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Malformed response handling
// ═══════════════════════════════════════════════════════════════════════════════

/// Completely invalid JSON in success response.
#[tokio::test]
async fn invalid_json_in_success_response() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("this is not json")
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&server)
        .await;

    let client = test_client(&server);
    let err = client
        .list_credentials("Bearer tok", None)
        .await
        .unwrap_err();

    match err {
        CscError::InvalidResponse(_) => {} // expected
        _ => panic!("expected InvalidResponse, got: {err:?}"),
    }
}

/// JSON response with unexpected schema (missing required field).
#[tokio::test]
async fn json_response_missing_required_field() {
    let server = MockServer::start().await;

    // Missing `credentialIDs` field entirely
    Mock::given(method("POST"))
        .and(path("/credentials/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "onlyValid": true
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let err = client
        .list_credentials("Bearer tok", None)
        .await
        .unwrap_err();

    match err {
        CscError::InvalidResponse(_) => {} // expected
        _ => panic!("expected InvalidResponse, got: {err:?}"),
    }
}

/// SignHash response with empty signatures array.
#[tokio::test]
async fn sign_hash_empty_signatures() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/signatures/signHash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signatures": []
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let req = SignHashRequest {
        credential_id: "cred-001".to_string(),
        sad: None,
        hash: vec![],
        hash_algo: HASH_ALGO_SHA256.to_string(),
        sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    let sigs = client.sign_hash("Bearer tok", &req).await.unwrap();
    assert!(sigs.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cleverbase-specific: OAuth2 + RAR flow expectations
// ═══════════════════════════════════════════════════════════════════════════════

/// Credential with auth mode "oauth2code" requires RAR-bound access token.
/// The client itself doesn't enforce this, but the test documents the
/// expected error from the server when SAD/authorization is insufficient.
#[tokio::test]
async fn sign_hash_authorization_required_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/signatures/signHash"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_access_token",
            "error_description": "Access token does not contain required authorization_details for this credential"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let req = SignHashRequest {
        credential_id: "cred-qualified".to_string(),
        sad: None,
        hash: vec!["dGVzdA==".to_string()],
        hash_algo: HASH_ALGO_SHA256.to_string(),
        sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    let err = client
        .sign_hash("Bearer insufficient-token", &req)
        .await
        .unwrap_err();
    let err_str = err.to_string();
    assert!(err_str.contains("authorization_details"), "got: {err_str}");
}

/// Cleverbase returns credential with EC P-256 key and ECDSA-SHA256 algo.
#[tokio::test]
async fn credential_info_ec_p256_cleverbase_format() {
    let server = MockServer::start().await;

    // Response shape matching actual Cleverbase testbed output
    Mock::given(method("POST"))
        .and(path("/credentials/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "credentialID": "cleverbase-cred-001",
            "description": "PID-authenticated signing key",
            "signatureQualifier": "eu_eidas_aes",
            "key": {
                "status": "enabled",
                "algo": ["1.2.840.10045.4.3.2"],
                "len": 256,
                "curve": "P-256"
            },
            "cert": {
                "status": "valid",
                "certificates": [
                    "MIICczCCAhmgAwIBAgIUe..."
                ],
                "subjectDN": "CN=Test User,serialNumber=PNOEU-XXYY123456,C=NL",
                "issuerDN": "CN=Cleverbase Lab CA,O=Cleverbase ID B.V.,C=NL",
                "serialNumber": "7B7A8E3F01",
                "validFrom": "20260601120000Z",
                "validTo": "20260901120000Z"
            },
            "auth": {
                "mode": "oauth2code",
                "expression": "",
                "objects": ["credentials/authorize"]
            },
            "SCAL": "2",
            "multisign": 1,
            "lang": "en"
        })))
        .mount(&server)
        .await;

    let client = test_client(&server);
    let info = client
        .credential_info("Bearer tok", "cleverbase-cred-001")
        .await
        .unwrap();

    assert_eq!(info.key.status, "enabled");
    assert_eq!(info.key.len, 256);
    assert_eq!(info.key.curve, Some("P-256".to_string()));
    assert_eq!(info.key.algo, vec!["1.2.840.10045.4.3.2"]);
    let cert = info.cert.unwrap();
    assert!(cert
        .subject_dn
        .as_ref()
        .unwrap()
        .contains("PNOEU-XXYY123456"));
    assert_eq!(info.auth.unwrap().mode, "oauth2code");
}
