# Running the HTTP Server

`server.js` is a thin Express wrapper around the SDK. It lets you interact with
Sigbash over plain HTTP — useful for backend integrations, shell scripts, or
any language that can make HTTP requests.

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

This means the server starts without credentials and becomes fully functional
as soon as credentials are available by any of these methods. It also means the
same server instance can serve multiple callers with different credentials via headers.

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

The server starts without credentials. Call `/setup/credentials` to generate a
fresh triplet, write the values to `.env`, and subsequent requests will pick
them up automatically — no restart needed.

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

Write these into `.env`:

```
SIGBASH_API_KEY=a3f1c8...e8d2
SIGBASH_USER_KEY=7b2e4f...1a9c
SIGBASH_SECRET_KEY=d4c8a1...3f7e
```

The server picks up `.env` on the next request — no restart needed. The
`userSecretKey` is generated locally and never sent to Sigbash.

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
request mainnet access.

---

## Registering a Key

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
    "require2FA": false
  }' | python3 -m json.tool
```

```json
{
  "keyId": "key-abc123",
  "p2trAddress": "tb1p...",
  "bip328Xpub": "xpub..."
}
```

Fund the returned `p2trAddress` on signet before signing.

---

## Retrieving a Key

By default, `GET /keys/:keyId` returns a slim summary:

```bash
curl -s http://localhost:3000/keys/0 | python3 -m json.tool
```

```json
{
  "keyIndex": 0,
  "policyRoot": "a3f1c8...",
  "bip328Xpub": "[fingerprint]tpub...",
  "poetJSON": { "version": "1.1", "policy": { "..." } }
}
```

To get the full key material including `kmcJSON` (required for signing), pass `?verbose=true`:

```bash
curl -s "http://localhost:3000/keys/0?verbose=true" | python3 -m json.tool
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

Store this kit as securely as a private key. Anyone who holds it can decrypt
the KMC for the matching `keyId`.

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

Returns a `GetKeyResult` — same shape as `GET /keys/:keyId`, including `kmcJSON`
ready for signing.

### Admin-Initiated Recovery

An org admin can recover a **departed user's** key material using a recovery kit
that was previously exported by that user. Admin-initiated recovery must be
enabled for the org (contact [sales@sigbash.com](mailto:sales@sigbash.com)).

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

The server authenticates the request using the **caller's** credentials (from the
environment). Returns a `GetKeyResult` with the recovered `kmcJSON`.

> **Note:** Without a previously exported recovery kit, admin-initiated recovery
> is not possible. The `recoveryKEK` is derived from the user's `userSecretKey`,
> which Sigbash never receives.

---

## Admin Operations

The first user to call `POST /keys` within a new org (new `apiKey`) is
automatically promoted to **admin**. Admins have access to three additional
endpoints. All three require admin credentials to be in scope (`.env`,
environment variables, or `X-Sigbash-*` headers).

### Register a User

Pre-authorise a new user to create keys within this org:

```bash
curl -s -X POST http://localhost:3000/admin/users \
  -H 'Content-Type: application/json' \
  -d '{"userKey": "<new-user-key>"}' | python3 -m json.tool
```

```json
{ "ok": true }
```

### Revoke a User

Remove a user's authorisation. Cannot revoke your own account:

```bash
curl -s -X DELETE http://localhost:3000/admin/users/<userKey> | python3 -m json.tool
```

```json
{ "ok": true }
```

### Update a Key's Policy

Replace the POET policy on a key that was created with `"updateable": true`.
Only the org admin can call this endpoint:

```bash
curl -s -X POST http://localhost:3000/keys/key-abc123/update-policy \
  -H 'Content-Type: application/json' \
  -d '{
    "newPolicyJson": "{\"version\":\"1.1\",\"policy\":{\"type\":\"operator\",\"operator\":\"AND\",\"children\":[{\"type\":\"condition\",\"conditionType\":\"OUTPUT_VALUE\",\"conditionParams\":{\"selector\":\"ALL\",\"operator\":\"LTE\",\"value\":50000}}]}}"
  }' | python3 -m json.tool
```

Returns `{ "ok": true }` on success. Returns HTTP 403 if the key is not
marked `updateable` or the caller is not the admin.

To create an updateable key, include `"updateable": true` in the
`POST /keys` body:

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

The `updateable` flag is write-once — it cannot be set or cleared after
key creation. The slim summary returned by `GET /keys/:keyId` includes
`"updateable"` so callers can check without fetching the full KMC.

See [docs/admin.md](admin.md) for a full description of the admin model.
