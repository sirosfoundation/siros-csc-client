# siros-csc-client

[![CI](https://github.com/sirosfoundation/siros-csc-client/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-csc-client/actions/workflows/ci.yml)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)

A typed Rust client for the [Cloud Signature Consortium (CSC) API v2.2](https://cloudsignatureconsortium.org/resources/download-api-specifications/) (ETSI TS 119 432), enabling wallet applications to request qualified electronic signatures from remote QTSPs.

## Features

- **`info`** — query QTSP service metadata (unauthenticated)
- **`credentials/list`** — enumerate available signing credentials (with pagination)
- **`credentials/info`** — get metadata for a specific credential (key, cert, auth mode)
- **`credentials/authorize`** — obtain SAD for explicit authorization (PIN/OTP)
- **`credentials/sendOTP`** — trigger OTP delivery
- **`signatures/signHash`** — request hash signing (sync and async modes)
- **DPoP support** — pluggable `DPopSigner` trait for RFC 9449 proof generation
- **UniFFI bindings** — Swift and Kotlin bindings via [UniFFI](https://mozilla.github.io/uniffi-rs/) (optional `ffi` feature)

## Architecture

The CSC client is a **pure HTTP client** — it does NOT:
- Own OAuth flows (receives access tokens from the caller)
- Manage keys (signing keys live in the QTSP's QSCD)
- Render documents (returns metadata; caller decides UX)

The only cryptographic operation it performs is DPoP proof generation via an injected `DPopSigner` trait, which can be backed by any WSCD.

## Usage

```rust
use csc_client::{CscClient, NoDPop, SignHashRequest, HASH_ALGO_SHA256, SIGN_ALGO_ECDSA_SHA256};

// Create client (use your own DPoP signer in production)
let client = CscClient::new("https://qtsp.example.com/csc/v2", NoDPop)?;

// List credentials
let creds = client.list_credentials("Bearer eyJ...", None).await?;

// Get credential info
let info = client.credential_info("Bearer eyJ...", &creds[0]).await?;

// Sign document hash
let req = SignHashRequest {
    credential_id: creds[0].clone(),
    sad: Some("activation-data".to_string()),
    hash: vec!["base64-encoded-sha256-hash".to_string()],
    hash_algo: HASH_ALGO_SHA256.to_string(),
    sign_algo: SIGN_ALGO_ECDSA_SHA256.to_string(),
    sign_algo_params: None,
    operation_mode: None,
    validity_period: None,
    response_uri: None,
    client_data: None,
};
let signatures = client.sign_hash("Bearer eyJ...", &req).await?;
```

## UniFFI Bindings

Generate Swift and Kotlin bindings for mobile integration:

```bash
make bindings          # Both Swift + Kotlin
make bindings-swift    # Swift only
make bindings-kotlin   # Kotlin only
make xcframework       # iOS XCFramework
make aar               # Android AAR
```

## Testing

```bash
cargo test                        # Unit + integration tests (wiremock)
cargo test --features test-utils  # Include test helper utilities
```

### Conformance Testing

The test suite includes conformance tests validated against the [Cleverbase CSC v2 testbed](https://signing.lab.cleverbase.io/csc/v2/docs/):

```bash
cargo test --test cleverbase_conformance
```

## CSC API Compatibility

Tested against:
- [Cleverbase Signing API v2 Beta](https://cleverbase.com/en/dev-docs/signing-v2-beta/) (pre-production)
- CSC API specification v2.2.0.0

## License

[BSD-2-Clause](LICENSE)
