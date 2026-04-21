# Changelog

All notable changes to the Sigbash SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2025-04-13

### Added
- Initial public release of `@sigbash/sdk`
- `SigbashClient` for key creation, retrieval, and PSBT signing
- Policy definition via `conditionConfigToPoetPolicy()`
- Zero-knowledge proof generation and PSBT signing via WASM
- Built-in support for Bitcoin Signet, Testnet, and Mainnet
- Comprehensive error types and validation
- Full TypeScript support with declaration files
- Complete Node.js and browser environment support
- Integration test suite covering full workflow

### Notes
- Deprecated legacy error class exports (`KmcDecryptionError`, `ProveError`, etc.) — will be removed in v2.0.0. Use `SigbashSDKError` and specific error subclasses instead.
- WASM binary is delivered via CDN (not bundled in npm package) for smaller package size and faster updates.
