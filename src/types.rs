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

/// Response body for `POST /csc/v2/info`.
#[derive(Debug, Deserialize)]
pub struct InfoResponse {
    /// CSC API specification version (e.g. `"2.2.0.0"`).
    pub specs: String,
    /// Service name.
    pub name: String,
    /// Logo URL.
    pub logo: String,
    /// Service region (ISO 3166-1 alpha-2).
    pub region: String,
    /// Language (ISO 639-1).
    pub lang: String,
    /// Human-readable description.
    pub description: String,
    /// Supported authentication types.
    #[serde(default, rename = "authType")]
    pub auth_type: Vec<String>,
    /// OAuth2 server configurations.
    #[serde(default, rename = "oauth2Servers")]
    pub oauth2_servers: Vec<OAuth2ServerInfo>,
    /// OAuth2 base URI (legacy field).
    #[serde(default)]
    pub oauth2: Option<String>,
    /// OAuth2 issuer identifier.
    #[serde(default, rename = "oauth2Issuer")]
    pub oauth2_issuer: Option<String>,
    /// Whether Rich Authorization Requests (RFC 9396) are supported.
    #[serde(default, rename = "supportsRar")]
    pub supports_rar: bool,
    /// Supported hash algorithm OIDs.
    #[serde(default, rename = "supportedHashTypes")]
    pub supported_hash_types: Vec<String>,
    /// Whether asynchronous operation mode is supported.
    #[serde(default, rename = "asynchronousOperationMode")]
    pub asynchronous_operation_mode: bool,
    /// Supported API methods.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Whether validation info is available.
    #[serde(default, rename = "validationInfo")]
    pub validation_info: bool,
    /// Supported signature algorithms.
    #[serde(rename = "signAlgorithms")]
    pub sign_algorithms: SignAlgorithmsInfo,
    /// Supported signature formats.
    #[serde(default)]
    pub signature_formats: Option<SignatureFormatsInfo>,
    /// Conformance levels.
    #[serde(default)]
    pub conformance_levels: Vec<String>,
}

/// OAuth2 server information from the /info response.
#[derive(Debug, Deserialize)]
pub struct OAuth2ServerInfo {
    /// Server label.
    #[serde(default)]
    pub label: Option<String>,
    /// Base URI of the OAuth2 server.
    #[serde(default, rename = "baseUri")]
    pub base_uri: Option<String>,
    /// Issuer identifier.
    #[serde(default, rename = "issuerIdentifier")]
    pub issuer_identifier: Option<String>,
    /// Supported auth types.
    #[serde(default, rename = "authType")]
    pub auth_type: Vec<String>,
    /// Whether RAR is supported.
    #[serde(default, rename = "supportsRar")]
    pub supports_rar: bool,
}

/// Supported signature algorithms from the /info response.
#[derive(Debug, Deserialize)]
pub struct SignAlgorithmsInfo {
    /// Algorithm OIDs.
    #[serde(default)]
    pub algos: Vec<String>,
    /// Algorithm parameters.
    #[serde(default, rename = "algoParams")]
    pub algo_params: Option<Vec<String>>,
}

/// Supported signature formats from the /info response.
#[derive(Debug, Deserialize)]
pub struct SignatureFormatsInfo {
    /// Format identifiers.
    #[serde(default)]
    pub formats: Vec<String>,
    /// Envelope properties.
    #[serde(default)]
    pub envelope_properties: Option<Vec<Vec<String>>>,
    /// Whether mixed formats are allowed.
    #[serde(default, rename = "allowMix")]
    pub allow_mix: Option<bool>,
}

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
    /// Pagination token from a previous response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
}

/// Response body for `POST /csc/v2/credentials/list`.
#[derive(Debug, Deserialize)]
pub struct CredentialsListResponse {
    /// List of credential IDs.
    #[serde(rename = "credentialIDs")]
    pub credential_ids: Vec<String>,
    /// Token for fetching the next page (if more results exist).
    #[serde(default, rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}

/// Request body for `POST /csc/v2/credentials/info`.
#[derive(Debug, Serialize)]
pub struct CredentialInfoRequest {
    /// The credential ID to query.
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    /// Whether to include certificate chain details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<String>,
    /// Whether to include certificate details (issuer, subject, validity).
    #[serde(rename = "certInfo", skip_serializing_if = "Option::is_none")]
    pub cert_info: Option<bool>,
    /// Whether to include authorization mode info.
    #[serde(rename = "authInfo", skip_serializing_if = "Option::is_none")]
    pub auth_info: Option<bool>,
}

/// Response body for `POST /csc/v2/credentials/info`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInfoResponse {
    /// The credential ID (returned by the server).
    #[serde(default, rename = "credentialID")]
    pub credential_id: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Signature qualifier (e.g. `"eu_eidas_qes"`).
    #[serde(default)]
    pub signature_qualifier: Option<String>,
    /// Key information.
    pub key: KeyInfo,
    /// Certificate information (if requested).
    pub cert: Option<CertInfo>,
    /// Authorization mode.
    pub auth: Option<AuthInfo>,
    /// SCAL level.
    #[serde(default, rename = "SCAL")]
    pub scal: Option<String>,
    /// Whether multi-sign is supported.
    #[serde(default)]
    pub multisign: u32,
    /// Credential status.
    #[serde(default)]
    pub status: String,
    /// Supported signature algorithms.
    #[serde(default)]
    pub algo: Vec<String>,
    /// Language.
    #[serde(default)]
    pub lang: Option<String>,
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
    /// Objects/methods used for authorization.
    #[serde(default)]
    pub objects: Vec<String>,
}

/// Request body for `POST /csc/v2/signatures/signHash`.
#[derive(Debug, Serialize)]
pub struct SignHashRequest {
    /// Credential ID to sign with.
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    /// Signature Activation Data (for explicit authorization).
    #[serde(rename = "SAD", skip_serializing_if = "Option::is_none")]
    pub sad: Option<String>,
    /// Base64-encoded hash values to sign.
    #[serde(rename = "hashes")]
    pub hash: Vec<String>,
    /// Hash algorithm OID (e.g. `"2.16.840.1.101.3.4.2.1"` for SHA-256).
    #[serde(rename = "hashAlgorithmOID")]
    pub hash_algo: String,
    /// Signature algorithm OID.
    #[serde(rename = "signAlgo")]
    pub sign_algo: String,
    /// Signature format (e.g. `"P"` for PKCS#1).
    #[serde(rename = "signAlgoParams", skip_serializing_if = "Option::is_none")]
    pub sign_algo_params: Option<String>,
    /// Operation mode: `"S"` (synchronous, default) or `"A"` (asynchronous).
    #[serde(rename = "operationMode", skip_serializing_if = "Option::is_none")]
    pub operation_mode: Option<String>,
    /// Validity period in milliseconds for async mode.
    #[serde(rename = "validityPeriod", skip_serializing_if = "Option::is_none")]
    pub validity_period: Option<u64>,
    /// URI for async callback notification.
    #[serde(rename = "responseURI", skip_serializing_if = "Option::is_none")]
    pub response_uri: Option<String>,
    /// Opaque client data returned unchanged in the response.
    #[serde(rename = "clientData", skip_serializing_if = "Option::is_none")]
    pub client_data: Option<String>,
}

/// Response body for `POST /csc/v2/signatures/signHash`.
#[derive(Debug, Deserialize)]
pub struct SignHashResponse {
    /// Base64-encoded signatures (one per input hash).
    /// Empty in async mode until the operation completes.
    #[serde(default)]
    pub signatures: Vec<String>,
    /// Response ID for async operations (poll with this).
    #[serde(default, rename = "responseID")]
    pub response_id: Option<String>,
}

// ─── Credential authorization types ─────────────────────────────────────────

/// Request body for `POST /csc/v2/credentials/authorize`.
#[derive(Debug, Serialize)]
pub struct CredentialAuthorizeRequest {
    /// Credential ID to authorize.
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    /// Number of signatures to authorize.
    #[serde(rename = "numSignatures")]
    pub num_signatures: u32,
    /// Base64-encoded hashes that will be signed (for binding).
    #[serde(rename = "hashes", skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Vec<String>>,
    /// Hash algorithm OID for the hashes.
    #[serde(rename = "hashAlgorithmOID", skip_serializing_if = "Option::is_none")]
    pub hash_algorithm_oid: Option<String>,
    /// PIN value (for PIN-based authorization).
    #[serde(rename = "PIN", skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// OTP value (for OTP-based authorization).
    #[serde(rename = "OTP", skip_serializing_if = "Option::is_none")]
    pub otp: Option<String>,
    /// Opaque client data returned unchanged in the response.
    #[serde(rename = "clientData", skip_serializing_if = "Option::is_none")]
    pub client_data: Option<String>,
}

/// Response body for `POST /csc/v2/credentials/authorize`.
#[derive(Debug, Deserialize)]
pub struct CredentialAuthorizeResponse {
    /// Signature Activation Data to use in signHash.
    #[serde(rename = "SAD")]
    pub sad: String,
    /// Expiration time of the SAD (ISO 8601 or seconds).
    #[serde(default, rename = "expiresIn")]
    pub expires_in: Option<u64>,
}

/// Request body for `POST /csc/v2/credentials/sendOTP`.
#[derive(Debug, Serialize)]
pub struct SendOtpRequest {
    /// Credential ID to send OTP for.
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    /// Opaque client data returned unchanged in the response.
    #[serde(rename = "clientData", skip_serializing_if = "Option::is_none")]
    pub client_data: Option<String>,
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
