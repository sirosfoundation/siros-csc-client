//! CSC API v2.2 HTTP client.

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;

use crate::error::{CscError, Result};
use crate::types::*;

/// CSC API client for communicating with a QTSP.
///
/// # Usage
///
/// ```ignore
/// let client = CscClient::new("https://qtsp.example.com/csc/v2", dpop_signer);
/// let creds = client.list_credentials("Bearer eyJ...", None).await?;
/// let info = client.credential_info("Bearer eyJ...", &creds[0]).await?;
/// let sigs = client.sign_hash("Bearer eyJ...", &req).await?;
/// ```
pub struct CscClient {
    base_url: String,
    http: Client,
    dpop_signer: Box<dyn DPopSigner>,
}

impl CscClient {
    /// Create a new CSC client.
    ///
    /// - `base_url`: CSC API base URL (e.g. `https://qtsp.example.com/csc/v2`)
    /// - `dpop_signer`: implementation producing DPoP proof JWTs. Use [`NoDPop`]
    ///   if the QTSP doesn't require DPoP.
    pub fn new(
        base_url: impl Into<String>,
        dpop_signer: impl DPopSigner + 'static,
    ) -> Result<Self> {
        let http = Client::builder()
            .https_only(true)
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .user_agent(concat!("csc-client/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| CscError::Http(e.to_string()))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
            dpop_signer: Box::new(dpop_signer),
        })
    }

    /// Create a CSC client that also works over HTTP (for testing only).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_insecure(
        base_url: impl Into<String>,
        dpop_signer: impl DPopSigner + 'static,
    ) -> Result<Self> {
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: Client::new(),
            dpop_signer: Box::new(dpop_signer),
        })
    }

    /// Query service information (no authentication required).
    ///
    /// Returns metadata about the QTSP including supported algorithms,
    /// OAuth2 configuration, and available methods.
    pub async fn info(&self) -> Result<InfoResponse> {
        let url = format!("{}/info", self.base_url);

        let resp = self
            .http
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| CscError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(self.parse_error(resp).await);
        }

        resp.json()
            .await
            .map_err(|e| CscError::InvalidResponse(e.to_string()))
    }

    /// List available signing credentials.
    ///
    /// - `access_token`: Bearer token (e.g. `"Bearer eyJ..."`)
    /// - `filter_status`: optional status filter (e.g. `"enabled"`)
    ///
    /// Note: for paginated listing, use [`list_credentials_paginated`].
    pub async fn list_credentials(
        &self,
        access_token: &str,
        filter_status: Option<&str>,
    ) -> Result<Vec<String>> {
        let url = format!("{}/credentials/list", self.base_url);
        let body = CredentialsListRequest {
            credential_status: filter_status.map(|s| s.to_string()),
            max_results: None,
            page_token: None,
        };

        let resp = self.post_json(&url, access_token, &body).await?;

        if !resp.status().is_success() {
            return Err(self.parse_error(resp).await);
        }

        let result: CredentialsListResponse = resp
            .json()
            .await
            .map_err(|e| CscError::InvalidResponse(e.to_string()))?;

        Ok(result.credential_ids)
    }

    /// List credentials with pagination support.
    ///
    /// Returns the raw response including `next_page_token` for fetching
    /// subsequent pages.
    pub async fn list_credentials_paginated(
        &self,
        access_token: &str,
        filter_status: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> Result<CredentialsListResponse> {
        let url = format!("{}/credentials/list", self.base_url);
        let body = CredentialsListRequest {
            credential_status: filter_status.map(|s| s.to_string()),
            max_results,
            page_token: page_token.map(|s| s.to_string()),
        };

        let resp = self.post_json(&url, access_token, &body).await?;

        if !resp.status().is_success() {
            return Err(self.parse_error(resp).await);
        }

        resp.json()
            .await
            .map_err(|e| CscError::InvalidResponse(e.to_string()))
    }

    /// Get detailed information about a credential.
    ///
    /// - `access_token`: Bearer token
    /// - `credential_id`: ID from `list_credentials`
    pub async fn credential_info(
        &self,
        access_token: &str,
        credential_id: &str,
    ) -> Result<CredentialInfoResponse> {
        let url = format!("{}/credentials/info", self.base_url);
        let body = CredentialInfoRequest {
            credential_id: credential_id.to_string(),
            certificates: Some("chain".to_string()),
            cert_info: Some(true),
            auth_info: Some(true),
        };

        let resp = self.post_json(&url, access_token, &body).await?;

        if !resp.status().is_success() {
            return Err(self.parse_error(resp).await);
        }

        resp.json()
            .await
            .map_err(|e| CscError::InvalidResponse(e.to_string()))
    }

    /// Sign one or more document hashes.
    ///
    /// - `access_token`: Bearer token (must include RFC 9396 authorization_details
    ///   binding the token to the specific document hashes)
    /// - `request`: signing parameters including credential ID, hashes, and algorithms
    ///
    /// Returns base64-encoded signatures (one per input hash).
    pub async fn sign_hash(
        &self,
        access_token: &str,
        request: &SignHashRequest,
    ) -> Result<Vec<String>> {
        let url = format!("{}/signatures/signHash", self.base_url);

        let resp = self.post_json(&url, access_token, request).await?;

        if !resp.status().is_success() {
            return Err(self.parse_error(resp).await);
        }

        let result: SignHashResponse = resp
            .json()
            .await
            .map_err(|e| CscError::InvalidResponse(e.to_string()))?;

        Ok(result.signatures)
    }

    /// Sign hashes with full response (includes async operation fields).
    ///
    /// Use this when `operation_mode` is set to `"A"` (asynchronous) to get
    /// access to the `response_id` for polling.
    pub async fn sign_hash_full(
        &self,
        access_token: &str,
        request: &SignHashRequest,
    ) -> Result<SignHashResponse> {
        let url = format!("{}/signatures/signHash", self.base_url);

        let resp = self.post_json(&url, access_token, request).await?;

        if !resp.status().is_success() {
            return Err(self.parse_error(resp).await);
        }

        resp.json()
            .await
            .map_err(|e| CscError::InvalidResponse(e.to_string()))
    }

    /// Authorize a credential for signing (explicit authorization mode).
    ///
    /// This is required when the credential's `auth.mode` is `"explicit"`.
    /// Returns a SAD (Signature Activation Data) token to pass to `sign_hash`.
    ///
    /// - `access_token`: Bearer token
    /// - `request`: authorization parameters (credential ID, PIN/OTP, hashes)
    pub async fn authorize_credential(
        &self,
        access_token: &str,
        request: &CredentialAuthorizeRequest,
    ) -> Result<CredentialAuthorizeResponse> {
        let url = format!("{}/credentials/authorize", self.base_url);

        let resp = self.post_json(&url, access_token, request).await?;

        if !resp.status().is_success() {
            return Err(self.parse_error(resp).await);
        }

        resp.json()
            .await
            .map_err(|e| CscError::InvalidResponse(e.to_string()))
    }

    /// Trigger OTP delivery for credential authorization.
    ///
    /// Call this before `authorize_credential` when the credential requires
    /// OTP-based authorization. The QTSP will send an OTP to the user via
    /// the configured channel (SMS, email, etc.).
    ///
    /// - `access_token`: Bearer token
    /// - `request`: sendOTP parameters (credential ID)
    pub async fn send_otp(&self, access_token: &str, request: &SendOtpRequest) -> Result<()> {
        let url = format!("{}/credentials/sendOTP", self.base_url);

        let resp = self.post_json(&url, access_token, request).await?;

        if !resp.status().is_success() {
            return Err(self.parse_error(resp).await);
        }

        Ok(())
    }

    // ─── Internal helpers ───────────────────────────────────────────────

    async fn post_json<T: serde::Serialize>(
        &self,
        url: &str,
        access_token: &str,
        body: &T,
    ) -> Result<reqwest::Response> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(access_token)
                .map_err(|e| CscError::Http(format!("invalid access token header: {e}")))?,
        );

        // Attach DPoP proof if the signer produces one
        let dpop = self
            .dpop_signer
            .sign_dpop(
                "POST",
                url,
                Some(access_token.trim_start_matches("Bearer ")),
            )
            .map_err(CscError::DPop)?;
        if !dpop.is_empty() {
            headers.insert(
                "DPoP",
                HeaderValue::from_str(&dpop)
                    .map_err(|e| CscError::DPop(format!("invalid DPoP header: {e}")))?,
            );
        }

        self.http
            .post(url)
            .headers(headers)
            .json(body)
            .send()
            .await
            .map_err(|e| CscError::Http(e.to_string()))
    }

    async fn parse_error(&self, resp: reqwest::Response) -> CscError {
        let status = resp.status().as_u16();
        match resp.json::<CscApiError>().await {
            Ok(api_err) => CscError::Api {
                status,
                error: api_err.error,
                error_description: api_err.error_description,
            },
            Err(_) => CscError::Api {
                status,
                error: "unknown".to_string(),
                error_description: format!("HTTP {status}"),
            },
        }
    }
}
