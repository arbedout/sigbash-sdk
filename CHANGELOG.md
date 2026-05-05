# Changelog

All notable changes to the Sigbash SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.2] — 2026-05-05

### Fixed

- **`ServerError` now reflects the server's actual error code.**  
  The constructor was hard-coding `'SERVER_ERROR'` regardless of the `code`
  field in the server response payload. Socket-level errors such as
  `NOT_FOUND` are now propagated correctly on `err.code`.

## [0.4.1] — 2026-05-05

### Fixed

- **`updatePolicy()` now propagates server error codes from the KMC update step.**  
  The KMC write preceding the policy PATCH was discarding the server's `code`
  field and always throwing `SigbashSDKError('SERVER_ERROR')`. Errors such as
  `NOT_FOUND` are now forwarded correctly.

## [0.4.0] — 2026-05-05

### Breaking

- **`adminUpdatePolicy()` renamed to `updatePolicy()`.**  
  The method is no longer admin-only: any authenticated user can update the
  policy on their own updateable keys. Only admins can set `updateable: true`
  at key creation time — that restriction is unchanged. Rename all
  `adminUpdatePolicy(...)` calls to `updatePolicy(...)`.

- **Error types from `updatePolicy()` have changed.**  
  Previously `adminUpdatePolicy()` threw `AdminError` for non-admin callers.
  `updatePolicy()` now throws `SigbashSDKError` with code `NOT_UPDATEABLE`
  when the key was not created with `updateable: true`, and `NOT_FOUND` when
  the key index does not exist for the caller.

- **Server route changed.**  
  The underlying endpoint moved from `POST /api/v2/sdk/admin/policy/update`
  to `PATCH /api/v2/sdk/keys/<keyId>/policy`. Only relevant if you are making
  direct HTTP calls instead of using the SDK method.

### Fixed

- **`registerTOTP()` and `confirmTOTP()` now work correctly.**  
  Both methods were sending `auth_hash` in the JSON request body; the server
  reads it only from the `X-Auth-Hash` header. This caused all TOTP setup
  calls to fail with `INVALID_AUTH_HASH`. Fixed by moving `auth_hash` to the
  header in both methods.

- **`SDK_VERSION` constant now matches the package version.**  
  The exported `SDK_VERSION` string was frozen at `0.2.0`; it now reflects
  the actual published version.

## [0.3.2] — 2026-05-05

### Fixed

- `SigbashClient` now authenticates the `/api/v2/sdk` socket at connect time
  by passing `{ auth_hash, apikey_hash }` in the Socket.IO handshake auth
  payload. Previously the socket was created without credentials, so
  `register_key_with_hash` (and all other SDK socket events) failed with
  `auth_hash must be a 64-character lowercase hex string` because the server
  reads `session['credential_id']` set at connect time, not from the event
  payload. Matches the existing pattern used by the `/api/v2/musig2` socket
  since 0.2.2.
- Removed the eager unauthenticated socket creation from the `SigbashClient`
  constructor; the SDK socket is now lazily created on first use (same
  pattern as `_musig2Socket`).

## [0.3.1] — 2026-05-05

### Security

- Admin methods now send credentials via `X-Auth-Hash` header.
- KMC updates require proof of key ownership.

## [0.3.0] — 2026-05-03

### Added
- `SignPSBTOptions.mockedTime?: number` — **test-only** Unix-seconds override for the WASM signing pipeline's wall-clock. Threaded through to the WASM via `SetMockedTimeForTesting`; production WASM registers a no-op stub, so this field has no effect against production servers. Used by SDK e2e tests to drive calendar-reset, `AFTER`, and `WITHIN` time-constraint scenarios.

## [0.2.2] — 2026-05-03

### Fixed
- Intermittent `WebAuthn session not authenticated` errors during rapid sequential `signPSBT()` calls. The SDK now authenticates the signing socket at handshake time, eliminating a session-propagation race that surfaced when several signs ran in close succession.

## [0.2.1] — 2026-05-01

### Breaking
- **`listKeys()` now sends `auth_hash` in the `X-Auth-Hash` request header instead of a URL query parameter.**

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
