# Changelog

All notable changes to the Sigbash SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-04-28

### Breaking
- **`SignPSBTOptions.inputIndex` removed.** The option was passed to the WASM but ignored — `SignPSBTBlind_WASM` always signs every input in the PSBT. Callers passing `inputIndex` should drop it; signing behaviour is unchanged.
- **`VerifyPSBTResult.pathID` renamed to `pathId`** (lowercase `d`) to match `SignPSBTResult.pathId`. Update any consumers reading `verification.pathID`.
- **Error class hierarchy refactored.** `ServerError`, `AuthenticationError`, `NetworkMismatchError`, and `PolicyValidationError` now extend `SigbashSDKError` instead of the legacy `SigbashError`. Their `@deprecated` markers have been removed — they are first-class members of the modern hierarchy. `instanceof SigbashSDKError` now catches every error currently thrown by the SDK. Their constructor signatures and instance fields (`statusCode`, `details`, `expected`, `actual`, `issues`) are unchanged.
- All `'CLIENT_DISPOSED'` errors are now thrown as the new typed `ClientDisposedError` class. Catch via `instanceof ClientDisposedError` (or `SigbashSDKError`); the `'CLIENT_DISPOSED'` `code` string is preserved.

### Added
- `ClientDisposedError` — typed error for operations on a disposed `SigbashClient`.
- `COUNT_BASED_CONSTRAINT.reset_interval` schema widened to expose `'hourly'` and `'custom'` (engine already supported these).
- `COUNT_BASED_CONSTRAINT.reset_interval_seconds` parameter — required when `reset_interval === 'custom'`, range 3600 (1h) to 31_536_000 (1y).

### Docs
- Three-pass audit (grammar / first-time-user accessibility / accuracy) across every doc in `docs/` plus the README. Many edits per doc — highlights below.
- **`docs/nullifiers.md` renamed to `docs/stateful-constraints.md`** (user-facing framing). The doc now opens with troubleshooting guidance for `verifyPSBT` returning `available: false`.
- **`p2trAddress` funding bug fixed in `getting-started.md`, `creating-keys.md`, `server.md`, and `README.md`.** Funding guidance now consistently directs users to import `bip328Xpub` into a descriptor wallet (`tr(<bip328Xpub>/0/*)`) or a `sortedmulti_a(...)` multisig descriptor. `p2trAddress` is documented as a debug artifact, not a fundable address.
- **`docs/server.md` "Admin Operations" rewritten** as four scenario-driven workflows: onboarding a new team member, rotating a policy, recovering a departed user's keys, locking out a compromised user. New endpoint summary table and error-response table added; TOTP endpoints documented; `/setup/credentials` no-write behaviour clarified.
- **`docs/policy-reference.md`**: added table of contents, intro, BIP-443 glossary (with link to bips.dev/443), `OUTPUT_DEST_IS_IN_SETS` descriptor mode, required `selector` parameter on every `REQKEY` example (was missing — examples would fail validation), restructured THRESHOLD example to wrap stateful constraints in nested AND.
- **`docs/policy-overview.md`**: `DERIVED_IS_PAYJOIN_LIKE` row added; `start_date_within` / `end_date_within` added to `TIME_BASED_CONSTRAINT`; canonical condition names used in patterns table; "Common policy patterns" promoted above the reference tables.
- **`docs/stateful-constraints.md`**: `hourly` / `custom` reset intervals documented (with `reset_interval_seconds`); `max_uses` 1–100,000 ceiling surfaced; calendar reset semantics corrected per interval; `end_hour` documented as inclusive; alias relationship between `start_time` and `start_date_within` clarified; troubleshooting section added.
- **`docs/error-handling.md`**: rewritten with full error-code coverage, lifecycle groupings, TOTP error lifecycle, common-scenario try/catch recipes, and a "Server errors" subsection covering `ServerError`/`AuthenticationError`/`NetworkMismatchError`/`PolicyValidationError`. The deprecation note has been dropped.
- **`docs/authentication.md`**: simplified — credential model up top, `Multiple keys per user` content moved to `creating-keys.md`, admin discussion deferred to `admin.md`. Storage warning around credential bundling added.
- **`docs/creating-keys.md`**: gained the `Multiple keys per user` section, a new `Funding the key` section with descriptor templates (single-sig + `sortedmulti_a` for multisig), inline `policy-reference.md` cross-links, and a fix to the inaccurate `listKeys()` "no decryption" claim.
- **`docs/recovery.md`**: triage callout at the top for users who've lost `userSecretKey`; storage warning callout; correction to the "Enable admin recovery" path (self-serve via `POST /api/v2/sdk/admin/settings`, not a sales contact); credential-rotation footgun warning around new `keyId` and on-chain address.
- **`docs/admin.md`**: `apiKey` rotation footgun callout, `revokeUser` next-request invalidation note, server-side `updateable` enforcement clarification, error-table `NOT_UPDATEABLE` removed (not a real `err.code`), correction to admin-recovery enable instructions (self-serve, not sales-gated). Duplicated "Multiple keys" section removed (lives in `creating-keys.md`).
- **`docs/signing.md`**: 2FA setup deferred to `admin.md` as the canonical home; `psbtHex` documented; `verifyPSBT` cross-link added; result fields expanded (`pathId`, `policyRootHex`, `error`).
- **`docs/verifying.md`**: expanded from 15 to ~120 lines — opener, prerequisites, full result-field listing, `nullifierStatus` shape, idempotency note, end-to-end runnable example, honest disclosure that `verifyPSBT` makes one HTTP call to fetch nullifier epoch state.
- **`docs/getting-started.md`**: tightened, integrity-verification rationale expanded (SHA-384 + constant-time comparison + MITM rationale), step ordering fixed.
- **`docs/environments.md` and `docs/security.md` deleted** — content folded into README (runtime support line) and the existing `getting-started.md` / `authentication.md` / `recovery.md` sections.
- **`README.md`**: new "Back up a recovery kit for every key" warning, runtime support line, fixed Quick Start `getKey(keyId)` → `getKey(keyId, { verbose: true })` (default returned `KeySummary` without `kmcJSON` — example would have failed at runtime), `pathId` / `satisfiedClause` shown in the success branch, funding paragraph and admin sentence tightened.

## [0.1.8] — 2026-04-23

### Added
- `listKeys()`, `createKey()`, and `getKey()` responses enriched with `bip328Xpub`, `poetJSON`, and `keyId`.

## [0.1.5] — 2026-04-23

### Changed
- Policy reference rewritten with broader, clearer examples.
- Tightened first-time setup flow vs. returning-user flow guidance.
- Trimmed agent-facing prose for terser LLM output.

## [0.1.4] — 2026-04-23

### Added
- `listKeys()` method on `SigbashClient`.
- `verbose` option on key retrieval to return `kmcJSON`.

### Docs
- Full enumeration of supported logical operators and condition types in agent-facing docs.
- Clarified WITHIN wallclock parameters for time-based constraints.
- Hardened AGENTS.md against common agent failure modes (mandatory rules, port-collision guidance).

## [0.1.3] — 2026-04-22

### Added
- Per-request credential resolution: `X-Sigbash-Api-Key` / `X-Sigbash-User-Key` / `X-Sigbash-Secret-Key` / `X-Sigbash-Server-Url` headers on the HTTP server, layered over `.env` and environment variables.
- AGENTS.md and CLAUDE.md integration guides for agent-driven onboarding.

### Fixed
- `initializeGoRuntime()` is now async with a proper fallback path.
- Server hash verification bug.

### Docs
- New `docs/server.md` HTTP reference.
- Credential privacy and signet-by-default notices; admin recover route documented.

## [0.1.1] — 2026-04-22

### Added
- `generateCredentials()` writes `.env` on first run and returns existing values on subsequent runs.
- `getAuthHash()` returns `authHash` and `apikeyHash` for org identification (e.g. requesting mainnet access) without requiring a dashboard.
- HTTP server: `POST /setup/credentials` and `GET /setup/auth-hash` endpoints.
- `adminRecoverKey()` method.

### Changed
- License switched to Apache-2.0; `NOTICE` and `RUNTIME-NOTICE` merged.
- `publishConfig.access` set to `public`; repository and bug URLs updated.
- `bitcoinjs-lib` moved to devDependencies.

### Fixed
- `policyRoot` TypeScript type error.

### Removed
- `packages/` directory.

### Docs
- `docs/authentication.md` rewritten; `docs/getting-started.md` gains a step 0 for credential setup; README credentials section and quick start updated.

## [0.1.0] — 2026-04-21

### Added
- Initial public release of `@sigbash/sdk`.
- `SigbashClient` for key creation, retrieval, and PSBT signing.
- Policy definition via `conditionConfigToPoetPolicy()`.
- Zero-knowledge proof generation and PSBT signing via WASM.
- Built-in support for Bitcoin Signet, Testnet, and Mainnet.
- Comprehensive error types and validation.
- Full TypeScript support with declaration files.
- Node.js and browser environment support.
- Integration test suite covering full workflow.

### Notes
- Deprecated legacy error class exports (`KmcDecryptionError`, `ProveError`, etc.) — will be removed in v2.0.0. Use `SigbashSDKError` and specific error subclasses instead.
- WASM binary is delivered via CDN (not bundled in npm package) for smaller package size and faster updates.
