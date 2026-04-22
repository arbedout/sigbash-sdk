# Running the HTTP Server

`server.js` is a thin Express wrapper around the SDK. It lets you interact with
Sigbash over plain HTTP — useful for backend integrations, shell scripts, or
any language that can make HTTP requests.

---

## Prerequisites

- Node.js 18+ (or Docker)
- A credential triplet in your environment (see [Authentication](authentication.md))

---

## Running Standalone

```bash
# Install dependencies (express + @sigbash/sdk)
npm install express @sigbash/sdk

# Set required environment variables
export SIGBASH_SERVER_URL=https://www.sigbash.com
export SIGBASH_API_KEY=<your-api-key>
export SIGBASH_USER_KEY=<your-user-key>
export SIGBASH_SECRET_KEY=<your-user-secret-key>

node server.js
# → sigbash-http-server listening on :3000
```

Optional variables:

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

Run it:

```bash
docker run --rm -p 3000:3000 \
  -e SIGBASH_SERVER_URL=https://www.sigbash.com \
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

If you don't have credentials yet, the server can generate them for you.
Start the server with **placeholder** values, call `/setup/credentials`, then
restart with the real values.

```bash
# Generate a fresh credential triplet
curl -s -X POST http://localhost:3000/setup/credentials | jq .
```

```json
{
  "apiKey": "a3f1c8...e8d2",
  "userKey": "7b2e4f...1a9c",
  "userSecretKey": "d4c8a1...3f7e",
  "serverUrl": "https://www.sigbash.com"
}
```

Copy these into your `.env` and restart. The `userSecretKey` is generated
locally — it is never sent to Sigbash.

To get your org identifier (needed to request mainnet access):

```bash
curl -s http://localhost:3000/setup/auth-hash | jq .
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
      "type": "OUTPUT_VALUE",
      "selector": "ALL",
      "operator": "LTE",
      "value": 10000
    },
    "network": "signet",
    "require2FA": false
  }' | jq .
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

```bash
curl -s http://localhost:3000/keys/key-abc123 | jq .
```

```json
{
  "keyId": "key-abc123",
  "policyRoot": "a3f1c8...",
  "network": "signet",
  "require2FA": false,
  "keyIndex": 0,
  "keyMaterial": { "...": "..." },
  "kmcJSON": "{...}"
}
```

The `kmcJSON` field is required for signing.

---

## Signing a PSBT

```bash
curl -s -X POST http://localhost:3000/keys/key-abc123/sign \
  -H 'Content-Type: application/json' \
  -d '{
    "psbtBase64": "<base64-encoded PSBT>",
    "kmcJSON": "<kmcJSON from getKey>",
    "network": "signet"
  }' | jq .
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
  }' | jq .
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
curl -s http://localhost:3000/keys/key-abc123/recovery-kit | jq .
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
  }' | jq .
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
  }' | jq .
```

The server authenticates the request using the **caller's** credentials (from the
environment). Returns a `GetKeyResult` with the recovered `kmcJSON`.

> **Note:** Without a previously exported recovery kit, admin-initiated recovery
> is not possible. The `recoveryKEK` is derived from the user's `userSecretKey`,
> which Sigbash never receives.
