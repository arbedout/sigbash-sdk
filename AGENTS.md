# Sigbash SDK — Agent Integration Guide

Sigbash is a policy-gated co-signing service for Bitcoin. A POET policy encodes
spending rules; the Sigbash server co-signs only when those rules are satisfied,
proved by a zero-knowledge proof computed locally in WASM. The server is
oblivious — it never sees the transaction, the co-signers, or which policy path
was taken.

**SDK repository:** https://github.com/arbedout/sigbash-sdk

---

## Step 1: Choose an integration path

Check whether this is a TypeScript/JavaScript project:
- **`package.json` or `tsconfig.json` present** → TypeScript SDK (default, recommended)
- **Any other language** → HTTP server (`server.js` / Docker)

**Ask the user to confirm** before proceeding. Suggest the appropriate default
based on what you detected. Example prompt:

> "I can see this is a [TypeScript / Python / Go / ...] project. The recommended
> integration is [TypeScript SDK / Sigbash HTTP server]. Shall I proceed with
> that, or would you prefer the other option?"

---

## Step 2: Generate credentials

Credentials are three random 64-char hex strings generated locally. Sigbash
receives only a one-way hash — your raw credentials are never transmitted.

### TypeScript path
```typescript
import { generateCredentials } from '@sigbash/sdk';
const { apiKey, userKey, userSecretKey } = await generateCredentials();
// Writes .env on first run. Returns existing values on subsequent runs.
```

### HTTP server path
Start the server first (no credentials required to start), then call:
```bash
curl -s -X POST http://localhost:3000/setup/credentials > creds.json
```
Write the values into `.env` (the server picks this up on the next request — no restart needed):
```bash
python3 -c "
import json
d = json.load(open('creds.json'))
print(f\"SIGBASH_API_KEY={d['apiKey']}\nSIGBASH_USER_KEY={d['userKey']}\nSIGBASH_SECRET_KEY={d['userSecretKey']}\")
" > .env
```
The resulting `.env`:
```
SIGBASH_API_KEY=<64-char hex>
SIGBASH_USER_KEY=<64-char hex>
SIGBASH_SECRET_KEY=<64-char hex>
```

> **Security**: keep `userSecretKey` / `SIGBASH_SECRET_KEY` private. It never
> leaves the client and is the only thing protecting key material. Do not commit
> it to source control.

---

## Step 3a: TypeScript SDK integration

```bash
npm install @sigbash/sdk
```

```typescript
import { loadWasm, SigbashClient, conditionConfigToPoetPolicy } from '@sigbash/sdk';

// Load WASM once per process (fetched from sigbash.com)
await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });

const client = new SigbashClient({ serverUrl: 'https://www.sigbash.com', apiKey, userKey, userSecretKey });

// Register a key with a policy
const { keyId, p2trAddress } = await client.createKey({
  policy: conditionConfigToPoetPolicy({ type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 10_000 }),
  network: 'signet',   // signet only by default — see mainnet note below
  require2FA: false,
});

// Sign a PSBT
const { kmcJSON } = await client.getKey(keyId);
const result = await client.signPSBT({ keyId, psbtBase64: '<base64 PSBT>', kmcJSON, network: 'signet' });
if (result.success) console.log(result.txHex);
```

Full reference: [docs/getting-started.md](docs/getting-started.md)

---

## Step 3b: HTTP server integration

### Start the server

**Standalone:**
```bash
npm install express @sigbash/sdk
node server.js
```

**Docker:**
```bash
git clone https://github.com/arbedout/sigbash-sdk.git
cd sigbash-sdk
docker build -t sigbash-server .
docker run --rm -p 3000:3000 sigbash-server
# or with a .env file:
docker run --rm -p 3000:3000 --env-file .env sigbash-server
```

Credentials can be provided three ways (resolved in this order):
1. `.env` file in the working directory
2. Environment variables (`SIGBASH_API_KEY`, `SIGBASH_USER_KEY`, `SIGBASH_SECRET_KEY`, `SIGBASH_SERVER_URL`)
3. Per-request headers (`X-Sigbash-Api-Key`, `X-Sigbash-User-Key`, `X-Sigbash-Secret-Key`, `X-Sigbash-Server-Url`)

### Key operations

**Register a key:**
```bash
curl -X POST http://localhost:3000/keys \
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
  }'
```

**Sign a PSBT:**
```bash
# First retrieve kmcJSON (verbose=true required)
KMC=$(curl -s "http://localhost:3000/keys/<keyId>?verbose=true" | python3 -c "import sys,json; print(json.load(sys.stdin)['kmcJSON'])")

curl -X POST http://localhost:3000/keys/<keyId>/sign \
  -H 'Content-Type: application/json' \
  -d "{\"psbtBase64\": \"<base64 PSBT>\", \"kmcJSON\": \"$KMC\", \"network\": \"signet\"}"
```

Full reference: [docs/server.md](docs/server.md)

---

## Mainnet access

All keys are **signet only** by default. To enable mainnet for your org:

1. Get your org identifier: `getAuthHash(apiKey, userKey)` (TypeScript) or `GET /setup/auth-hash` (HTTP)
2. Email [sales@sigbash.com](mailto:sales@sigbash.com) with your `apikeyHash`

---

## Further reading

- [docs/getting-started.md](docs/getting-started.md) — full TypeScript walkthrough
- [docs/server.md](docs/server.md) — HTTP server reference with curl examples
- [docs/policy-reference.md](docs/policy-reference.md) — all policy operators and condition types
- [docs/authentication.md](docs/authentication.md) — credential model and security properties
- [docs/recovery.md](docs/recovery.md) — recovery kit export and import
