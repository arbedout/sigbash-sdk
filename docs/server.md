# Running the HTTP Server

`server.js` is a thin Express wrapper around the SDK. It lets you interact with
Sigbash over plain HTTP — useful for backend integrations, shell scripts, or
any language that can make HTTP requests.

---

## Quickstart

1. **Install and run** the server (`npm install express @sigbash/sdk && node server.js`,
   or `docker run`). See [Running Standalone](#running-standalone) /
   [Running with Docker](#running-with-docker).
2. **Bootstrap credentials** by calling `POST /setup/credentials` — see
   [Bootstrap](#bootstrap-generating-credentials).
3. **Write `.env`** yourself from the values returned in step 2. The endpoint
   does not write any files.
4. **Create a key** via `POST /keys` with your POET policy — see
   [Registering a Key](#registering-a-key). Save the returned `keyId`.
5. **Fund the wallet** by importing the returned `bip328Xpub` into a descriptor
   or multisig wallet of your choice. Do **not** fund the low-level
   `p2trAddress` directly.
6. **Sign a PSBT** via `POST /keys/:keyId/sign` — see
   [Signing a PSBT](#signing-a-psbt).

> **Mainnet.** All keys are signet-only by default. The only setup step
> required to enable mainnet is registering your `apikeyHash` with Sigbash —
> see [Bootstrap](#bootstrap-generating-credentials) for how to obtain it, then
> email [sales@sigbash.com](mailto:sales@sigbash.com).

> **First-call WASM warmup.** The first signing call after server start
> involves cold WASM proof generation and may take noticeably longer than
> subsequent calls. The server has `setTimeout(0)` on the underlying socket so
> it will wait, but raise client-side HTTP timeouts accordingly.

---

## Endpoint summary

| Method | Path | Purpose | Auth |
|---|---|---|---|
| `GET` | `/health` | Liveness probe | none |
| `POST` | `/setup/credentials` | Generate a fresh credential triplet | none |
| `GET` | `/setup/auth-hash` | Return `apikeyHash` / `authHash` for the configured creds | required |
| `GET` | `/keys` | List keys for the caller (slim summary) | required |
| `POST` | `/keys` | Register a new key under a POET policy | required |
| `GET` | `/keys/:keyId` | Get a key (slim by default; `?verbose=true` for `kmcJSON`) | required |
| `POST` | `/keys/:keyId/sign` | Sign a PSBT (consumes a nullifier) | required |
| `POST` | `/keys/:keyId/verify` | Dry-run policy check (no nullifier consumed) | required |
| `POST` | `/keys/:keyId/totp/register` | Begin TOTP enrolment (returns `otpauth://` URI + secret) | required |
| `POST` | `/keys/:keyId/totp/confirm` | Confirm TOTP enrolment with the first 6-digit code | required |
| `GET` | `/keys/:keyId/recovery-kit` | Export a recovery kit | required |
| `POST` | `/recovery` | Self-recover from a kit (caller still has `apiKey`/`userKey`) | required |
| `POST` | `/admin/recover` | Admin-recover a departed user's key | admin |
| `POST` | `/keys/:keyId/update-policy` | Replace the POET policy on an `updateable` key | admin |
| `POST` | `/admin/users` | Pre-register a user | admin |
| `DELETE` | `/admin/users/:userKey` | Revoke a user | admin |

---

## Prerequisites

- Node.js 18+ (or Docker)
- Credentials are optional at startup — see [Bootstrap](#bootstrap-generating-credentials) below

---

## Credential Resolution

The server resolves credentials per request in this order:

1. `.env` file in the working directory
2. Environment variables
3. `X-Sigbash-*` request headers

Because resolution happens on every request, the server can start without
credentials and become fully functional as soon as any of these sources
provides them — no restart required.

The header path is what makes the server multi-tenant: a single running
instance can serve multiple callers simultaneously, each supplying their own
credentials per request via `X-Sigbash-*` headers.

| Source | Keys |
|---|---|
| `.env` / env vars | `SIGBASH_API_KEY`, `SIGBASH_USER_KEY`, `SIGBASH_SECRET_KEY`, `SIGBASH_SERVER_URL` |
| Headers | `X-Sigbash-Api-Key`, `X-Sigbash-User-Key`, `X-Sigbash-Secret-Key`, `X-Sigbash-Server-Url` |

`SIGBASH_SERVER_URL` / `X-Sigbash-Server-Url` defaults to `https://www.sigbash.com` if not provided.

Only `/health` and `/setup/credentials` are accessible without credentials.
All other endpoints return `401` if credentials cannot be resolved.

---

## Running Standalone

```bash
# Install dependencies (express + @sigbash/sdk)
npm install express @sigbash/sdk

node server.js
# → sigbash-http-server listening on :3000
```

Optional environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Port to listen on |
| `SIGBASH_WASM_URL` | `https://www.sigbash.com/sigbash.wasm` | WASM binary URL |

---

## Running with Docker

Build the image (uses the included `Dockerfile`):

```bash
docker build -t sigbash-server .
```

Run without credentials (bootstrap mode):

```bash
docker run --rm -p 3000:3000 sigbash-server
```

Run with credentials via environment:

```bash
docker run --rm -p 3000:3000 \
  -e SIGBASH_API_KEY=<your-api-key> \
  -e SIGBASH_USER_KEY=<your-user-key> \
  -e SIGBASH_SECRET_KEY=<your-user-secret-key> \
  sigbash-server
```

Or with a `.env` file:

```bash
docker run --rm -p 3000:3000 --env-file .env sigbash-server
```

---

## Bootstrap: Generating Credentials

The server starts without credentials. Call `POST /setup/credentials` to
generate a fresh triplet. **The endpoint only returns JSON — it does not write
any files.** You are responsible for placing the values into `.env` (or
exporting them as env vars). Once `.env` is in place, the next request will
pick the new credentials up automatically — no restart required.

```bash
# Generate a fresh credential triplet
curl -s -X POST http://localhost:3000/setup/credentials | python3 -m json.tool
```

```json
{
  "apiKey": "a3f1c8...e8d2",
  "userKey": "7b2e4f...1a9c",
  "userSecretKey": "d4c8a1...3f7e",
  "serverUrl": "https://www.sigbash.com"
}
```

Write these into `.env` yourself:

```
SIGBASH_API_KEY=a3f1c8...e8d2
SIGBASH_USER_KEY=7b2e4f...1a9c
SIGBASH_SECRET_KEY=d4c8a1...3f7e
```

The `userSecretKey` is generated locally and never sent to Sigbash.

To get your org identifier (needed to request mainnet access):

```bash
curl -s http://localhost:3000/setup/auth-hash | python3 -m json.tool
```

```json
{
  "apikeyHash": "e3b0c4...2f8e",
  "authHash": "9a4f2b...7c1d",
  "note": "Share apikeyHash with Sigbash to identify your org (e.g. to request mainnet access)."
}
```

Email [sales@sigbash.com](mailto:sales@sigbash.com) with your `apikeyHash` to
request mainnet access. Beyond registering this hash, no additional setup is
required — the same credentials and endpoints work for mainnet keys once the
org is enabled.

---

## Registering a Key

See [creating-keys.md](creating-keys.md) for the full key-creation model
(policy compilation, `keyIndex`, `updateable`). For a deeper explanation of
the policy JSON below, see [policy-overview.md](policy-overview.md).

```bash
curl -s -X POST http://localhost:3000/keys \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": {
      "version": "1.1",
      "policy": {
        "type": "operator",
        "operator": "AND",
        "children": [{
          "type": "condition",
          "conditionType": "OUTPUT_VALUE",
          "conditionParams": { "selector": "ALL", "operator": "LTE", "value": 10000 }
        }]
      }
    },
    "network": "signet",
    "require2FA": false,
    "verbose": true
  }' | python3 -m json.tool
```

Successful response (`verbose: true`):

```json
{
  "keyId": "key-abc123",
  "keyIndex": 0,
  "policyRoot": "a3f1c8...",
  "p2trAddress": "tb1p...",
  "aggregatePubKeyHex": "02ab12...",
  "bip328Xpub": "[fingerprint]tpub..."
}
```

**Funding the wallet.** Import `bip328Xpub` into a descriptor or multisig
wallet of your choice (e.g. as a singlesig taproot descriptor). Treat
`p2trAddress` as a low-level artifact — it is the first derived address but
not the funding instrument. Always fund via the wallet you imported the xpub
into. This matches the guidance in
[getting-started.md](getting-started.md) and
[creating-keys.md](creating-keys.md).

### Handling `keyIndex` collisions

If you supply an explicit `keyIndex` that is already in use, the server
returns HTTP `409` with a `nextAvailableIndex` field. Retry with that value:

```bash
RESPONSE=$(curl -s -X POST http://localhost:3000/keys \
  -H 'Content-Type: application/json' \
  -d '{ "policy": {...}, "network": "signet", "keyIndex": 0 }')

NEXT=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('nextAvailableIndex',''))" 2>/dev/null)
if [ -n "$NEXT" ]; then
  # Retry with $NEXT as keyIndex
  ...
fi
```

This mirrors the retry pattern documented in `AGENTS.md`.

---

## Listing Keys

`GET /keys` returns lightweight metadata for every key registered by the
caller. No KMC decryption happens, so it's cheap to poll:

```bash
curl -s http://localhost:3000/keys | python3 -m json.tool
```

```json
[
  { "keyId": "0", "network": "signet", "policyRoot": "a3f1c8...", "bip328Xpub": "[fp]tpub..." },
  { "keyId": "1", "network": "signet", "policyRoot": "9c2e4f...", "bip328Xpub": "[fp]tpub..." }
]
```

Use this to:

- Discover the next free `keyIndex` before creating a new key.
- Look up an existing `keyId` to pass to other endpoints (sign, verify,
  recovery-kit, etc.).

---

## Retrieving a Key

`GET /keys/:keyId` returns a slim summary by default. Pass `?verbose=true` to
include the `kmcJSON` required for signing.

**Slim** (`GET /keys/0`):

```json
{
  "keyId": "0",
  "keyIndex": 0,
  "policyRoot": "a3f1c8...",
  "bip328Xpub": "[fingerprint]tpub...",
  "updateable": false
}
```

**Verbose** (`GET /keys/0?verbose=true`):

```json
{
  "keyId": "0",
  "keyIndex": 0,
  "policyRoot": "a3f1c8...",
  "bip328Xpub": "[fingerprint]tpub...",
  "network": "signet",
  "kmcJSON": "{\"...\":\"...\"}",
  "poetJSON": { "version": "1.1", "policy": { "...": "..." } }
}
```

The `kmcJSON` field from the verbose response is required for signing.

---

## Signing a PSBT

```bash
curl -s -X POST http://localhost:3000/keys/key-abc123/sign \
  -H 'Content-Type: application/json' \
  -d '{
    "psbtBase64": "<base64-encoded PSBT>",
    "kmcJSON": "<kmcJSON from getKey>",
    "network": "signet"
  }' | python3 -m json.tool
```

```json
{
  "success": true,
  "txHex": "02000000..."
}
```

---

## Verifying a PSBT (dry run)

Checks whether the PSBT satisfies the policy without consuming a nullifier:

```bash
curl -s -X POST http://localhost:3000/keys/key-abc123/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "psbtBase64": "<base64-encoded PSBT>",
    "kmcJSON": "<kmcJSON from getKey>",
    "network": "signet"
  }' | python3 -m json.tool
```

```json
{
  "success": true,
  "satisfiedPath": "path-0"
}
```

---

## Two-factor authentication

Keys created with `"require2FA": true` reject any signing request that does
not include a current TOTP code. Enrolment is two steps:

```bash
# 1. Begin enrolment — returns an otpauth:// URI and the raw secret
curl -s -X POST http://localhost:3000/keys/key-abc123/totp/register | python3 -m json.tool
```

```json
{
  "uri": "otpauth://totp/Sigbash:key-abc123?secret=JBSWY3DPEHPK3PXP&issuer=Sigbash",
  "secret": "JBSWY3DPEHPK3PXP"
}
```

Render `uri` as a QR code in the user's authenticator app. Optionally store
`secret` as a backup.

```bash
# 2. Confirm with the first 6-digit code from the authenticator app
curl -s -X POST http://localhost:3000/keys/key-abc123/totp/confirm \
  -H 'Content-Type: application/json' \
  -d '{ "totpCode": "123456" }' | python3 -m json.tool
```

```json
{ "ok": true }
```

After confirmation, every signing request must include `totpCode` and
`require2FA: true` in the body. Errors return HTTP `401`:

| Error class | When |
|---|---|
| `TOTPRequiredError` | Key has 2FA but no `totpCode` was supplied |
| `TOTPInvalidError` | Code is wrong, expired, or rate-limit exceeded (5 attempts / 60s) |
| `TOTPSetupIncompleteError` | `confirmTOTP()` was never called for this key |

See [admin.md § 2FA enforcement](admin.md#2fa-enforcement) for the underlying
SDK semantics.

---

## Error responses

The server maps SDK error classes to HTTP status codes:

| HTTP status | Error class | Meaning |
|---|---|---|
| `400` | `SigbashSDKError`, `NetworkError` | Generic SDK / network failure |
| `401` | `TOTPRequiredError`, `TOTPInvalidError` | TOTP missing or invalid |
| `401` | (credential middleware) | Credentials missing for a non-exempt route |
| `403` | `AdminError` | Caller is not the org admin, or operation requires admin |
| `409` | `KeyIndexExistsError` | `keyIndex` already in use; response includes `nextAvailableIndex` |
| `422` | `PolicyCompileError` | POET policy failed to compile; response includes `compilationTrace` |
| `500` | (any other) | Unexpected server error |

---

## Account Recovery

Recovery allows a user (or admin) to regain access to key material after losing
their `userSecretKey`. See [Account Recovery](recovery.md) for full background
on the credential model and how recovery kits work.

### Export a Recovery Kit

Call this **before** the `userSecretKey` is lost, while the triplet is still valid:

```bash
curl -s http://localhost:3000/keys/key-abc123/recovery-kit | python3 -m json.tool
```

```json
{
  "version": "sdk-recovery-v1",
  "keyId": "key-abc123",
  "recoveryKEK": "a3f1c8...e8d2",
  "cekCiphertext": "4a7f3e...",
  "cekNonce": "1b2c8f...",
  "network": "signet",
  "createdAt": 1745000000
}
```

Treat the kit as private-key-equivalent: anyone holding it can decrypt the KMC
for the matching `keyId`.

### Self-Recovery from a Kit

Use this when the user still has access to their `apiKey` and `userKey` but has
lost their `userSecretKey`. The `userSecretKey` field is ignored during recovery
— pass any non-empty string.

```bash
curl -s -X POST http://localhost:3000/recovery \
  -H 'Content-Type: application/json' \
  -d '{
    "version": "sdk-recovery-v1",
    "keyId": "key-abc123",
    "recoveryKEK": "a3f1c8...e8d2",
    "cekCiphertext": "4a7f3e...",
    "cekNonce": "1b2c8f...",
    "network": "signet",
    "createdAt": 1745000000
  }' | python3 -m json.tool
```

Returns a `GetKeyResult` — same shape as `GET /keys/:keyId?verbose=true`,
including `kmcJSON` ready for signing.

### Admin-Initiated Recovery

An org admin can recover a **departed user's** key material using a recovery
kit that was previously exported by that user. Admin-initiated recovery is
**self-serve** — the admin enables it for their own org by calling the admin
settings endpoint:

```bash
curl -s -X POST https://www.sigbash.com/api/v2/sdk/admin/settings \
  -H 'Content-Type: application/json' \
  -d '{
    "auth_hash": "<admin authHash from /setup/auth-hash>",
    "allow_admin_recovery": true
  }'
```

Then perform the recovery via the local server:

```bash
curl -s -X POST http://localhost:3000/admin/recover \
  -H 'Content-Type: application/json' \
  -d '{
    "targetUserKey": "<departed-user-key>",
    "keyId": "key-abc123",
    "recoveryKit": {
      "version": "sdk-recovery-v1",
      "keyId": "key-abc123",
      "recoveryKEK": "a3f1c8...e8d2",
      "cekCiphertext": "4a7f3e...",
      "cekNonce": "1b2c8f...",
      "network": "signet",
      "createdAt": 1745000000
    }
  }' | python3 -m json.tool
```

The server authenticates the request using the **caller's** credentials.
Returns a `GetKeyResult` with the recovered `kmcJSON`.

> **Note:** Without a previously exported recovery kit, admin-initiated
> recovery is not possible. The `recoveryKEK` is derived from the user's
> `userSecretKey`, which Sigbash never receives.

---

## Admin Operations

**The first user to call `POST /keys` within a new org (new `apiKey`) is
automatically promoted to admin.** Admin status is permanent within that org
and tied to the `(apiKey, userKey)` pair. There is no explicit registration
step.

The four operational scenarios below cover the common admin workflows. See
[admin.md](admin.md) for the complete admin model.

### 1. Onboarding a new team member

Pre-authorise a new user so they can create their own keys within the org:

```bash
curl -s -X POST http://localhost:3000/admin/users \
  -H 'Content-Type: application/json' \
  -d '{ "userKey": "<new-user-key>" }' | python3 -m json.tool
```

```json
{ "ok": true }
```

The new member then runs their own bootstrap (`POST /setup/credentials` on
their own machine) and creates keys via `POST /keys`. The member's
`userSecretKey` is generated locally and **never reaches the admin or
Sigbash**.

### 2. Rotating a key's policy

A key's policy is immutable unless it was created with `"updateable": true`:

```bash
curl -s -X POST http://localhost:3000/keys \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": { ... },
    "network": "signet",
    "require2FA": false,
    "updateable": true
  }' | python3 -m json.tool
```

The `updateable` flag is **write-once** — it cannot be set or cleared after
key creation, and only admins can set it (the server silently ignores it for
non-admin callers). The slim `GET /keys/:keyId` summary includes
`"updateable"` so callers can check without fetching the full KMC.

To replace the policy:

```bash
curl -s -X POST http://localhost:3000/keys/key-abc123/update-policy \
  -H 'Content-Type: application/json' \
  -d '{
    "newPolicyJson": "{\"version\":\"1.1\",\"policy\":{\"type\":\"operator\",\"operator\":\"AND\",\"children\":[{\"type\":\"condition\",\"conditionType\":\"OUTPUT_VALUE\",\"conditionParams\":{\"selector\":\"ALL\",\"operator\":\"LTE\",\"value\":50000}}]}}"
  }' | python3 -m json.tool
```

Returns `{ "ok": true }` on success, or HTTP `403` if the key is not marked
`updateable` or the caller is not the admin. The on-chain address and
aggregate key are unchanged — only the stored policy root changes.

### 3. Recovering a departed user's keys

Two prerequisites must both hold:

1. The departing user exported a recovery kit (`GET /keys/:keyId/recovery-kit`)
   **before** they left, and transmitted it to the admin out-of-band.
2. The admin enabled `allow_admin_recovery` for the org via the admin
   settings endpoint:

```bash
curl -s -X POST https://www.sigbash.com/api/v2/sdk/admin/settings \
  -H 'Content-Type: application/json' \
  -d '{
    "auth_hash": "<admin authHash from /setup/auth-hash>",
    "allow_admin_recovery": true
  }'
```

Then call `/admin/recover` as shown in
[Admin-Initiated Recovery](#admin-initiated-recovery) above. Cross-link:
[recovery.md](recovery.md) covers the kit format and threat model.

### 4. Locking out a compromised user

```bash
curl -s -X DELETE http://localhost:3000/admin/users/<userKey> | python3 -m json.tool
```

```json
{ "ok": true }
```

Revocation is enforced **per request**: the next call from that user fails
auth, but there is no push-style invalidation. Importantly, **any kits or
KMCs already exported by the user remain valid** — they were decrypted
locally and Sigbash cannot reach them. To fully contain a compromise, rotate
or admin-recover the affected keys in addition to revoking the user. The
admin cannot revoke their own account.

See [admin.md](admin.md) for the full admin model and SDK-level error
semantics.
