//! End-to-end signing flow integration tests against the Cleverbase service stub.
//!
//! These tests exercise the complete OAuth2 → CSC signing flow:
//!   1. OAuth2 authorization code grant (service scope) → Bearer token
//!   2. credentials/list → enumerate available credentials
//!   3. credentials/info → verify key metadata and auth mode
//!   4. OAuth2 authorization code grant (credential scope) → SAD token
//!   5. signatures/signHash with SAD → obtain signature
//!
//! The Cleverbase service stub auto-completes the authorization code flow
//! without user interaction, making this suitable for CI.
//!
//! ## Configuration
//!
//! Set the following environment variables (or create a `.env` file):
//!
//! - `CSC_STUB_CLIENT_ID`     — OAuth2 client ID
//! - `CSC_STUB_CLIENT_SECRET` — OAuth2 client secret
//! - `CSC_STUB_BASE_URL`      — Stub base URL (e.g. `https://trust-driver-stub-hash-signing.cleverbase.com`)
//! - `CSC_STUB_REDIRECT_URI`  — Redirect URI (any URL works for the stub)
//!
//! Run with:
//!   CSC_STUB_TESTS=1 cargo test --test cleverbase_e2e --features test-utils

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use csc_client::{CscClient, CscVersion, NoDPop, SignHashRequest};
use reqwest::redirect::Policy;

// ─── Configuration ──────────────────────────────────────────────────────────

struct StubConfig {
    client_id: String,
    client_secret: String,
    base_url: String,
    redirect_uri: String,
}

impl StubConfig {
    fn load() -> Option<Self> {
        // Load .env if present (ignore errors — CI may set env vars directly)
        let _ = dotenvy::dotenv();

        if std::env::var("CSC_STUB_TESTS").is_err() {
            return None;
        }

        Some(Self {
            client_id: std::env::var("CSC_STUB_CLIENT_ID").expect("CSC_STUB_CLIENT_ID must be set"),
            client_secret: std::env::var("CSC_STUB_CLIENT_SECRET")
                .expect("CSC_STUB_CLIENT_SECRET must be set"),
            base_url: std::env::var("CSC_STUB_BASE_URL").expect("CSC_STUB_BASE_URL must be set"),
            redirect_uri: std::env::var("CSC_STUB_REDIRECT_URI")
                .unwrap_or_else(|_| "https://example.com/callback".to_string()),
        })
    }

    fn csc_base_url(&self) -> String {
        format!("{}/csc/v1", self.base_url)
    }

    fn auth_url(&self) -> String {
        format!("{}/oauth2/auth", self.base_url)
    }

    fn token_url(&self) -> String {
        format!("{}/oauth2/token", self.base_url)
    }
}

// ─── OAuth2 helpers ─────────────────────────────────────────────────────────

/// Perform OAuth2 authorization code flow against the stub.
///
/// The stub auto-redirects with an authorization code (no user interaction).
/// Returns the authorization code extracted from the redirect Location header.
async fn get_auth_code(config: &StubConfig, scope: &str, extra_params: &[(&str, &str)]) -> String {
    let http = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();

    let mut params = vec![
        ("response_type", "code"),
        ("client_id", &config.client_id),
        ("redirect_uri", &config.redirect_uri),
        ("scope", scope),
        ("state", "e2e-test"),
    ];
    params.extend_from_slice(extra_params);

    let resp = http
        .get(&config.auth_url())
        .query(&params)
        .send()
        .await
        .expect("auth request failed");

    let status = resp.status();
    assert!(status.is_redirection(), "expected redirect, got {status}");

    let location = resp
        .headers()
        .get("location")
        .expect("no Location header in redirect")
        .to_str()
        .expect("Location header not valid UTF-8")
        .to_string();

    // Extract code from: https://example.com/callback?code=FhkXf9P269L8g&state=...
    let url = reqwest::Url::parse(&location).expect("invalid redirect URL");
    url.query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("no code parameter in redirect")
}

/// Exchange an authorization code for an access token.
///
/// Returns `(access_token, token_type)`.
async fn exchange_code(config: &StubConfig, code: &str) -> (String, String) {
    let http = reqwest::Client::new();

    let resp = http
        .post(&config.token_url())
        .basic_auth(&config.client_id, Some(&config.client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &config.client_id),
            ("redirect_uri", &config.redirect_uri),
        ])
        .send()
        .await
        .expect("token request failed");

    assert!(
        resp.status().is_success(),
        "token exchange failed: {}",
        resp.status()
    );

    let body: serde_json::Value = resp.json().await.expect("token response not JSON");
    let access_token = body["access_token"]
        .as_str()
        .expect("no access_token in response")
        .to_string();
    let token_type = body["token_type"]
        .as_str()
        .expect("no token_type in response")
        .to_string();

    (access_token, token_type)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Full signing flow: OAuth2 → list → info → authorize → sign
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_full_signing_flow() {
    let config = match StubConfig::load() {
        Some(c) => c,
        None => {
            eprintln!("Skipping: set CSC_STUB_TESTS=1 to run e2e tests");
            return;
        }
    };

    // ── Step 1: Obtain service-scope access token ──────────────────────
    let service_code = get_auth_code(&config, "service", &[]).await;
    let (service_token, service_type) = exchange_code(&config, &service_code).await;

    assert_eq!(
        service_type, "Bearer",
        "service scope should return Bearer token"
    );
    assert!(
        !service_token.is_empty(),
        "service access token should not be empty"
    );

    let bearer = format!("Bearer {service_token}");

    // ── Step 2: Create CSC v1 client and list credentials ──────────────
    let client = CscClient::with_version(&config.csc_base_url(), NoDPop, CscVersion::V1)
        .expect("failed to create CSC client");

    let creds = client
        .list_credentials(&bearer, None)
        .await
        .expect("list_credentials failed");

    assert!(
        !creds.is_empty(),
        "expected at least one credential from stub"
    );
    eprintln!("Found {} credential(s): {:?}", creds.len(), creds);

    // ── Step 3: Get credential info ────────────────────────────────────
    let cred_id = &creds[0];
    let info = client
        .credential_info(&bearer, cred_id)
        .await
        .expect("credential_info failed");

    assert_eq!(info.key.status, "enabled", "key should be enabled");
    assert!(info.key.len > 0, "key length should be > 0");
    assert!(
        !info
            .cert
            .as_ref()
            .map_or(true, |c| c.certificates.is_empty()),
        "expected at least one certificate"
    );

    // Check auth mode via the version-agnostic helper
    let auth_mode = info.effective_auth_mode();
    assert_eq!(
        auth_mode,
        Some("oauth2code"),
        "expected oauth2code auth mode, got {:?}",
        auth_mode
    );
    eprintln!(
        "Credential {cred_id}: key={}/{}-bit, SCAL={:?}, authMode={:?}",
        info.key.status, info.key.len, info.scal, auth_mode
    );

    // ── Step 4: Compute hash of test document ──────────────────────────
    let document = b"Hello, SIROS QES integration test!";
    let hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(document);
        BASE64.encode(hasher.finalize())
    };

    // ── Step 5: Obtain credential-scope SAD via OAuth2 ─────────────────
    let num_signatures = "1";
    let cred_code = get_auth_code(
        &config,
        "credential",
        &[
            ("credentialID", cred_id),
            ("numSignatures", num_signatures),
            ("hash", &hash),
        ],
    )
    .await;
    let (sad_token, sad_type) = exchange_code(&config, &cred_code).await;

    assert_eq!(
        sad_type, "SAD",
        "credential scope should return SAD token type"
    );
    assert!(!sad_token.is_empty(), "SAD token should not be empty");
    eprintln!("Got SAD token (type={sad_type})");

    // ── Step 6: Sign the hash ──────────────────────────────────────────
    let sign_req = SignHashRequest {
        credential_id: cred_id.clone(),
        sad: Some(sad_token),
        hash: vec![hash.clone()],
        hash_algo: "2.16.840.1.101.3.4.2.1".to_string(), // SHA-256
        sign_algo: info
            .key
            .algo
            .first()
            .cloned()
            .unwrap_or_else(|| "1.2.840.113549.1.1.1".to_string()), // RSA PKCS#1
        sign_algo_params: None,
        operation_mode: None,
        validity_period: None,
        response_uri: None,
        client_data: None,
    };

    let signatures = client
        .sign_hash(&bearer, &sign_req)
        .await
        .expect("sign_hash failed");

    assert_eq!(
        signatures.len(),
        1,
        "expected exactly one signature, got {}",
        signatures.len()
    );
    assert!(!signatures[0].is_empty(), "signature should not be empty");

    // Verify the signature is valid base64
    let sig_bytes = BASE64
        .decode(&signatures[0])
        .expect("signature is not valid base64");
    assert!(
        !sig_bytes.is_empty(),
        "decoded signature should not be empty"
    );

    eprintln!(
        "Signature: {} ({} bytes decoded)",
        &signatures[0],
        sig_bytes.len()
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Individual step tests (for debugging specific failures)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_service_token_acquisition() {
    let config = match StubConfig::load() {
        Some(c) => c,
        None => {
            eprintln!("Skipping: set CSC_STUB_TESTS=1");
            return;
        }
    };

    let code = get_auth_code(&config, "service", &[]).await;
    assert!(!code.is_empty(), "auth code should not be empty");

    let (token, token_type) = exchange_code(&config, &code).await;
    assert_eq!(token_type, "Bearer");
    assert!(!token.is_empty());
}

#[tokio::test]
async fn e2e_credential_sad_acquisition() {
    let config = match StubConfig::load() {
        Some(c) => c,
        None => {
            eprintln!("Skipping: set CSC_STUB_TESTS=1");
            return;
        }
    };

    // Need a service token first to get credential IDs
    let service_code = get_auth_code(&config, "service", &[]).await;
    let (service_token, _) = exchange_code(&config, &service_code).await;
    let bearer = format!("Bearer {service_token}");

    let client = CscClient::with_version(&config.csc_base_url(), NoDPop, CscVersion::V1)
        .expect("failed to create client");

    let creds = client
        .list_credentials(&bearer, None)
        .await
        .expect("list failed");
    assert!(!creds.is_empty());

    let hash = BASE64.encode(b"test-hash-for-sad");
    let code = get_auth_code(
        &config,
        "credential",
        &[
            ("credentialID", &creds[0]),
            ("numSignatures", "1"),
            ("hash", &hash),
        ],
    )
    .await;

    let (sad, token_type) = exchange_code(&config, &code).await;
    assert_eq!(token_type, "SAD");
    assert!(!sad.is_empty());
}

#[tokio::test]
async fn e2e_credential_info_v1_auth_mode() {
    let config = match StubConfig::load() {
        Some(c) => c,
        None => {
            eprintln!("Skipping: set CSC_STUB_TESTS=1");
            return;
        }
    };

    let code = get_auth_code(&config, "service", &[]).await;
    let (token, _) = exchange_code(&config, &code).await;
    let bearer = format!("Bearer {token}");

    let client = CscClient::with_version(&config.csc_base_url(), NoDPop, CscVersion::V1)
        .expect("failed to create client");

    let creds = client
        .list_credentials(&bearer, None)
        .await
        .expect("list failed");
    let info = client
        .credential_info(&bearer, &creds[0])
        .await
        .expect("credential_info failed");

    // V1 returns authMode as a flat string
    assert!(
        info.auth_mode.is_some() || info.auth.is_some(),
        "expected either auth or authMode to be present"
    );
    assert_eq!(
        info.effective_auth_mode(),
        Some("oauth2code"),
        "effective auth mode should be oauth2code"
    );
}
