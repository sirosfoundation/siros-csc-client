# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `credentials/authorize` endpoint for explicit credential authorization (SAD).
- `credentials/sendOTP` endpoint to trigger OTP delivery.
- `list_credentials_paginated()` with `pageToken`/`nextPageToken` support.
- `sign_hash_full()` returning full response including async `responseID`.
- Async signing fields: `operationMode`, `validity_period`, `response_uri`, `clientData`.
- UniFFI gated behind optional `ffi` feature flag.
- MSRV policy: Rust 1.75+.
- CI: MSRV check, `RUSTFLAGS=-Dwarnings`, dual feature-flag verification.

### Changed
- UniFFI is now optional (`features = ["ffi"]`); pure-Rust consumers no longer
  pay the proc-macro compilation cost.
- CI checks both `--no-default-features` and `--features ffi`.

## [0.1.0] - 2026-06-18

### Added
- Initial CSC API v2.2 client (ETSI TS 119 432).
- `info` — query QTSP service metadata (unauthenticated).
- `credentials/list` — enumerate signing credentials.
- `credentials/info` — get credential metadata, certs, auth mode.
- `signatures/signHash` — request hash signing.
- DPoP proof support via pluggable `DPopSigner` trait.
- UniFFI bindings for Swift/Kotlin mobile SDKs.
- Production hardening: 30s timeout, 10s connect timeout, user-agent header.
- TLS-only enforcement (`https_only(true)`).
- BSD-2-Clause license.
- Conformance test suite (30 wire-format tests).
- Live integration tests against Cleverbase testbed (12 tests).
- OpenSSF Scorecard workflow.
- Dependabot configuration.

[Unreleased]: https://github.com/sirosfoundation/siros-csc-client/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sirosfoundation/siros-csc-client/releases/tag/v0.1.0
