//! UniFFI bridge for the CSC client.
//!
//! Exposes the CSC client to Swift/Kotlin via FFI using the proc-macro approach.

use crate::client::CscClient;
use crate::error::CscError;
use crate::types::*;

// ─── FFI Error ──────────────────────────────────────────────────────────────

#[derive(Debug, uniffi::Error, thiserror::Error)]
pub enum FfiCscError {
    #[error("HTTP error: {message}")]
    Http { message: String },
    #[error("API error: {message}")]
    Api { message: String },
    #[error("invalid response: {message}")]
    InvalidResponse { message: String },
    #[error("DPoP error: {message}")]
    DPop { message: String },
    #[error("authorization required: {message}")]
    AuthorizationRequired { message: String },
}

impl From<CscError> for FfiCscError {
    fn from(e: CscError) -> Self {
        let msg = e.to_string();
        match e {
            CscError::Http(_) => FfiCscError::Http { message: msg },
            CscError::Api { .. } => FfiCscError::Api { message: msg },
            CscError::InvalidResponse(_) => FfiCscError::InvalidResponse { message: msg },
            CscError::DPop(_) => FfiCscError::DPop { message: msg },
            CscError::AuthorizationRequired(_) => {
                FfiCscError::AuthorizationRequired { message: msg }
            }
        }
    }
}

// ─── FFI types ──────────────────────────────────────────────────────────────

#[derive(uniffi::Record, Clone)]
pub struct FfiCredentialInfo {
    pub description: String,
    pub key_status: String,
    pub key_algo: Vec<String>,
    pub key_curve: Option<String>,
    pub cert_status: Option<String>,
    pub subject_dn: Option<String>,
    pub issuer_dn: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub auth_mode: Option<String>,
    pub status: String,
    pub multisign: u32,
    pub supported_algos: Vec<String>,
}

impl From<crate::types::CredentialInfoResponse> for FfiCredentialInfo {
    fn from(r: crate::types::CredentialInfoResponse) -> Self {
        FfiCredentialInfo {
            description: r.description,
            key_status: r.key.status,
            key_algo: r.key.algo,
            key_curve: r.key.curve,
            cert_status: r.cert.as_ref().map(|c| c.status.clone()),
            subject_dn: r.cert.as_ref().and_then(|c| c.subject_dn.clone()),
            issuer_dn: r.cert.as_ref().and_then(|c| c.issuer_dn.clone()),
            valid_from: r.cert.as_ref().and_then(|c| c.valid_from.clone()),
            valid_to: r.cert.as_ref().and_then(|c| c.valid_to.clone()),
            auth_mode: r.auth.map(|a| a.mode),
            status: r.status,
            multisign: r.multisign,
            supported_algos: r.algo,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiSignHashRequest {
    pub credential_id: String,
    pub sad: Option<String>,
    pub hash: Vec<String>,
    pub hash_algo: String,
    pub sign_algo: String,
}

impl From<&FfiSignHashRequest> for SignHashRequest {
    fn from(r: &FfiSignHashRequest) -> Self {
        SignHashRequest {
            credential_id: r.credential_id.clone(),
            sad: r.sad.clone(),
            hash: r.hash.clone(),
            hash_algo: r.hash_algo.clone(),
            sign_algo: r.sign_algo.clone(),
            sign_algo_params: None,
        }
    }
}

// ─── DPoP callback ─────────────────────────────────────────────────────────

#[uniffi::export(callback_interface)]
pub trait FfiDPopSigner: Send + Sync {
    fn sign_dpop(
        &self,
        http_method: String,
        http_url: String,
        access_token: Option<String>,
    ) -> Result<String, FfiCscError>;
}

/// Bridge from FFI callback → Rust DPopSigner trait.
struct DPopSignerBridge(Box<dyn FfiDPopSigner>);

impl DPopSigner for DPopSignerBridge {
    fn sign_dpop(
        &self,
        http_method: &str,
        http_url: &str,
        access_token: Option<&str>,
    ) -> std::result::Result<String, String> {
        self.0
            .sign_dpop(
                http_method.to_string(),
                http_url.to_string(),
                access_token.map(|s| s.to_string()),
            )
            .map_err(|e| e.to_string())
    }
}

// ─── FfiCscClient ───────────────────────────────────────────────────────────

#[derive(uniffi::Object)]
pub struct FfiCscClient {
    inner: CscClient,
    rt: tokio::runtime::Runtime,
}

#[uniffi::export]
impl FfiCscClient {
    #[uniffi::constructor]
    pub fn new(base_url: String, dpop_signer: Box<dyn FfiDPopSigner>) -> Result<Self, FfiCscError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| FfiCscError::Http { message: format!("failed to create tokio runtime: {e}") })?;
        let inner = CscClient::new(base_url, DPopSignerBridge(dpop_signer))
            .map_err(|e| FfiCscError::Http { message: e.to_string() })?;
        Ok(FfiCscClient { inner, rt })
    }

    /// List available signing credential IDs.
    pub fn list_credentials(
        &self,
        access_token: String,
        filter_status: Option<String>,
    ) -> Result<Vec<String>, FfiCscError> {
        self.rt
            .block_on(
                self.inner
                    .list_credentials(&access_token, filter_status.as_deref()),
            )
            .map_err(|e| e.into())
    }

    /// Get detailed info for a credential.
    pub fn credential_info(
        &self,
        access_token: String,
        credential_id: String,
    ) -> Result<FfiCredentialInfo, FfiCscError> {
        self.rt
            .block_on(self.inner.credential_info(&access_token, &credential_id))
            .map(|r| r.into())
            .map_err(|e| e.into())
    }

    /// Sign document hashes.
    pub fn sign_hash(
        &self,
        access_token: String,
        request: FfiSignHashRequest,
    ) -> Result<Vec<String>, FfiCscError> {
        let req: SignHashRequest = (&request).into();
        self.rt
            .block_on(self.inner.sign_hash(&access_token, &req))
            .map_err(|e| e.into())
    }
}
