//! CSC API v2.2 types (ETSI TS 119 432).

use serde::{Deserialize, Serialize};

// ─── DPoP Signer trait ──────────────────────────────────────────────────────

/// Trait for producing DPoP proof JWTs (RFC 9449).
///
/// Implementations may be backed by any WSCD — software keys, R2PS HSM,
/// FIDO2 authenticator, or platform keychain. The CSC client calls this
/// before each HTTP request to attach a DPoP proof.
pub trait DPopSigner: Send + Sync {
    /// Produce a DPoP proof JWT for the given HTTP method and URL.
    ///
    /// The returned string is a compact JWS (e.g. `eyJ...`).
    /// The `access_token` is provided so the implementation can include
    /// the `ath` (access token hash) claim per RFC 9449 §4.2.
    fn sign_dpop(
        &self,
        http_method: &str,
        http_url: &str,
        access_token: Option<&str>,
    ) -> std::result::Result<String, String>;
}

/// A no-op DPoP signer for QTSPs that don't require DPoP.
pub struct NoDPop;

impl DPopSigner for NoDPop {
    fn sign_dpop(
        &self,
        _http_method: &str,
        _http_url: &str,
        _access_token: Option<&str>,
    ) -> std::result::Result<String, String> {
        Ok(String::new())
    }
}

// ─── CSC API request/response types ─────────────────────────────────────────

/// Request body for `POST /csc/v2/credentials/list`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsListRequest {
    /// Filter by credential status. If omitted, returns all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<String>,
    /// Maximum number of credentials to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_results: Option<u32>,
}

/// Response body for `POST /csc/v2/credentials/list`.
#[derive(Debug, Deserialize)]
pub struct CredentialsListResponse {
    /// List of credential IDs.
    #[serde(rename = "credentialIDs")]
    pub credential_ids: Vec<String>,
}

/// Request body for `POST /csc/v2/credentials/info`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInfoRequest {
    /// The credential ID to query.
    pub credential_id: String,
    /// Whether to include certificate chain details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<String>,
    /// Whether to include authorization info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_info: Option<bool>,
    /// Whether to include auth mode info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_info: Option<bool>,
}

/// Response body for `POST /csc/v2/credentials/info`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInfoResponse {
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Key information.
    pub key: KeyInfo,
    /// Certificate information (if requested).
    pub cert: Option<CertInfo>,
    /// Authorization mode.
    pub auth: Option<AuthInfo>,
    /// Whether multi-sign is supported.
    #[serde(default)]
    pub multisign: u32,
    /// Credential status.
    #[serde(default)]
    pub status: String,
    /// Supported signature algorithms.
    #[serde(default)]
    pub algo: Vec<String>,
}

/// Key metadata within a credential.
#[derive(Debug, Deserialize)]
pub struct KeyInfo {
    /// Key status: `"enabled"` or `"disabled"`.
    pub status: String,
    /// Supported algorithms (e.g. `["1.2.840.10045.4.3.2"]` for ECDSA-SHA256).
    #[serde(default)]
    pub algo: Vec<String>,
    /// Key length in bits.
    #[serde(default)]
    pub len: u32,
    /// Key curve (e.g. `"P-256"`).
    #[serde(default)]
    pub curve: Option<String>,
}

/// Certificate metadata.
#[derive(Debug, Deserialize)]
pub struct CertInfo {
    /// Certificate status.
    #[serde(default)]
    pub status: String,
    /// Base64-encoded X.509 certificates (leaf first).
    #[serde(default)]
    pub certificates: Vec<String>,
    /// Issuer DN.
    #[serde(default, alias = "issuerDN")]
    pub issuer_dn: Option<String>,
    /// Serial number.
    #[serde(default, alias = "serialNumber")]
    pub serial_number: Option<String>,
    /// Subject DN.
    #[serde(default, alias = "subjectDN")]
    pub subject_dn: Option<String>,
    /// Validity start.
    #[serde(default, alias = "validFrom")]
    pub valid_from: Option<String>,
    /// Validity end.
    #[serde(default, alias = "validTo")]
    pub valid_to: Option<String>,
}

/// Authorization mode for the credential.
#[derive(Debug, Deserialize)]
pub struct AuthInfo {
    /// Authorization mode: `"implicit"`, `"explicit"`, `"oauth2code"`.
    #[serde(default)]
    pub mode: String,
    /// Expression combining auth factors (e.g. `"PIN AND OTP"`).
    #[serde(default)]
    pub expression: Option<String>,
}

/// Request body for `POST /csc/v2/signatures/signHash`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignHashRequest {
    /// Credential ID to sign with.
    pub credential_id: String,
    /// Signature Activation Data (for explicit authorization).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sad: Option<String>,
    /// Base64-encoded hash values to sign.
    pub hash: Vec<String>,
    /// Hash algorithm OID (e.g. `"2.16.840.1.101.3.4.2.1"` for SHA-256).
    pub hash_algo: String,
    /// Signature algorithm OID.
    pub sign_algo: String,
    /// Signature format (e.g. `"P"` for PKCS#1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_algo_params: Option<String>,
}

/// Response body for `POST /csc/v2/signatures/signHash`.
#[derive(Debug, Deserialize)]
pub struct SignHashResponse {
    /// Base64-encoded signatures (one per input hash).
    pub signatures: Vec<String>,
}

// ─── CSC API error response ─────────────────────────────────────────────────

/// Error response body from the CSC API.
#[derive(Debug, Deserialize)]
pub struct CscApiError {
    pub error: String,
    #[serde(default)]
    pub error_description: String,
}

// ─── Hash algorithm constants ───────────────────────────────────────────────

/// SHA-256 OID for use in `hash_algo`.
pub const HASH_ALGO_SHA256: &str = "2.16.840.1.101.3.4.2.1";

/// SHA-384 OID.
pub const HASH_ALGO_SHA384: &str = "2.16.840.1.101.3.4.2.2";

/// SHA-512 OID.
pub const HASH_ALGO_SHA512: &str = "2.16.840.1.101.3.4.2.3";

/// ECDSA with SHA-256 signature algorithm OID.
pub const SIGN_ALGO_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

/// RSA PKCS#1 v1.5 with SHA-256 signature algorithm OID.
pub const SIGN_ALGO_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
