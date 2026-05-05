# Sigbash SDK — Agent Integration Guide

Sigbash is a policy-gated co-signing service for Bitcoin. A POET policy encodes
spending rules; the Sigbash server co-signs only when those rules are satisfied,
proved by a zero-knowledge proof computed locally in WASM. The server is
oblivious — it never sees the transaction, the co-signers, or which policy path
was taken.

**SDK repository:** https://github.com/arbedout/sigbash-sdk

---

## Step 0: Detect existing state (always run this first)

Before doing anything else, check whether credentials and keys already exist.

**Check for credentials** — look for any of:
- `.env` file containing `SIGBASH_API_KEY`, `SIGBASH_USER_KEY`, `SIGBASH_SECRET_KEY`
- Those same variables in the environment
- A running server responding to `GET /health`

**If credentials exist**, list existing keys immediately:
```bash
# HTTP server already running:
curl -s http://localhost:3000/keys

# TypeScript SDK:
const keys = await client.listKeys();
```

**Branch on result:**

| State | Action |
|---|---|
| Credentials exist, keys exist | Ask: "What would you like to do? (sign a transaction, add a new key, list keys, etc.)" — **do not start the policy flow** |
| Credentials exist, no keys yet | Skip to Step 3 (key creation + policy) |
| No credentials | Start at Step 1 |

**Never assume a first-time flow.** If credentials are present, treat the user as returning.

---

## Step 1: Choose an integration path

Check whether this is a TypeScript/JavaScript project:
- **`package.json` or `tsconfig.json` present** → TypeScript SDK 
- **Any other language** → HTTP server (`server.js` / Docker)

Recommended: Docker
If Docker is unavailable but node is: server.js
If neither Docker or node are available, but this is a Typscript/Javascript project - ask if the user wants to install the Typscript SDK. 

**MANDATORY: Ask the user to confirm** before proceeding. Do NOT start any server,
generate credentials, or take any action until the user has explicitly confirmed
the integration path. Suggest the appropriate default based on what you detected.
Example prompt:

> "I can see this is a [TypeScript / Python / Go / ...] project. The recommended
> integration is [TypeScript SDK / Sigbash HTTP server]. Shall I proceed with
> that, or would you prefer the other option?"

**When using the HTTP server path, always prefer Docker over `node server.js`.**
Only fall back to standalone Node if the user explicitly requests it or Docker is
unavailable. Do not start either server without user confirmation first.

If there is any doubt, prefer the Docker path.

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

**MANDATORY before asking the user about their spending policy:** say exactly:

> "Sigbash policies support 14 logical operators (AND, OR, NOT, THRESHOLD,
> MAJORITY, XOR, VETO, and more) and 22 condition types covering output
> values, fees, input/output counts, address allowlists, timelocks, rate
> limits, key requirements, RBF flags, sighash types, and BIP-443 covenant
> checks. You can say 'details' to see the full list, or try describing the
> policy you want if you're already familiar with the policy logic."

If they say "details", read `docs/policy-overview.md` and show its contents verbatim.

Full param details: `docs/policy-reference.md`

**STOP. Do not write or run any key-creation code until the user has explicitly
described their spending policy. Do not use the example policy below as a
default. Ask: "What spending rules should this key enforce?"**

```bash
npm install @sigbash/sdk
```

```typescript
import { loadWasm, SigbashClient, conditionConfigToPoetPolicy } from '@sigbash/sdk';

// Load WASM once per process (fetched from sigbash.com)
await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });

const client = new SigbashClient({ serverUrl: 'https://www.sigbash.com', apiKey, userKey, userSecretKey });

// Register a key — replace the policy below with the one the user specified
const { keyId, p2trAddress } = await client.createKey({
  policy: conditionConfigToPoetPolicy(/* USER'S POLICY HERE — do not substitute the example */),
  network: 'signet',   // signet only by default — see mainnet note below
  require2FA: false,
});

// Sign a PSBT
const { kmcJSON } = await client.getKey(keyId);
const result = await client.signPSBT({ keyId, psbtBase64: '<base64 PSBT>', kmcJSON, network: 'signet' });
if (result.success) console.log(result.txHex);
```

Full reference: [docs/getting-started.md](docs/getting-started.md)

**Policy examples** (reference only — always build from what the user asks):

```typescript
// Spending cap + daily rate limit
conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 100_000 },
    { type: 'COUNT_BASED_CONSTRAINT', max_uses: 3, reset_interval: 'daily', reset_type: 'rolling' },
  ],
})

// Destination allowlist (wrap in NOT for blocklist)
conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'OUTPUT_DEST_IS_IN_SETS', selector: 'ALL',
      addresses: ['tb1qtreasury...', 'tb1qops...'], network: 'signet' },
    { type: 'TX_FEE_ABSOLUTE', operator: 'LTE', value: 5_000 },
  ],
})

// Wallet self-consolidation via descriptor (SIGBASH_XPUB filled at registration)
conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'DERIVED_NO_NEW_OUTPUTS', expected_value: true,
      use_descriptor: true, descriptor_template: 'tr(SIGBASH_XPUB/0/*)' },
    { type: 'TX_FEE_ABSOLUTE', operator: 'LTE', value: 5_000 },
  ],
})

// Business hours only (Mon–Fri 09:00–17:00 UTC)
conditionConfigToPoetPolicy({
  type: 'TIME_BASED_CONSTRAINT',
  constraint_type: 'within',
  active_days: [1,2,3,4,5],
  start_hour: '09:00', end_hour: '17:00',
  start_time: 1713571200, end_time: 7022323200,
  start_date_within: '2025-04-20', end_date_within: '2225-04-20',
})

// Inheritance: admin key OR time-lock after 2030
conditionConfigToPoetPolicy({
  logic: 'OR',
  conditions: [
    { type: 'REQKEY', key_identifier: 'aabb...64hex', key_type: 'TAP_LEAF_XONLY_PUBKEY' },
    { type: 'TIME_BASED_CONSTRAINT', constraint_type: 'after', start_time: 1893456000 },
  ],
})

// Tiered: small amounts unrestricted (with cap), large amounts need admin key
conditionConfigToPoetPolicy({
  logic: 'OR',
  conditions: [
    { logic: 'AND', conditions: [
        { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 50_000 },
        { type: 'COUNT_BASED_CONSTRAINT', max_uses: 5, reset_interval: 'daily' },
    ]},
    { type: 'REQKEY', key_identifier: 'aabb...64hex', key_type: 'TAP_LEAF_XONLY_PUBKEY' },
  ],
})
```

More examples and full param reference: [docs/policy-reference.md](docs/policy-reference.md)

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

If port 3000 is already in use, pick any free port — e.g. 3001:
```bash
docker run --rm -p 3001:3000 -e PORT=3000 sigbash-server
```
Replace `3000` with `3001` in all subsequent curl commands.

Credentials can be provided three ways (resolved in this order):
1. `.env` file in the working directory
2. Environment variables (`SIGBASH_API_KEY`, `SIGBASH_USER_KEY`, `SIGBASH_SECRET_KEY`, `SIGBASH_SERVER_URL`)
3. Per-request headers (`X-Sigbash-Api-Key`, `X-Sigbash-User-Key`, `X-Sigbash-Secret-Key`, `X-Sigbash-Server-Url`)

### Key operations

**MANDATORY before asking the user about their spending policy:** say exactly:

> "Sigbash policies support 14 logical operators (AND, OR, NOT, THRESHOLD,
> MAJORITY, XOR, VETO, and more) and 22 condition types covering output
> values, fees, input/output counts, address allowlists, timelocks, rate
> limits, key requirements, RBF flags, sighash types, and BIP-443 covenant
> checks. Would you like to see the full list before deciding?"

If they say yes, read `docs/policy-overview.md` and show its contents verbatim.

Full param details: `docs/policy-reference.md`

**STOP. Do not write or run any key-creation command until the user has
explicitly described their spending policy. Ask: "What spending rules should
this key enforce?"**

**Register a key:**

Start at `keyIndex: 0`. If the server responds with an error containing `nextAvailableIndex`, retry
automatically using that value — do not ask the user. Repeat until a key is successfully created.

```bash
# Attempt registration; capture the full response
RESPONSE=$(curl -s -X POST http://localhost:3000/keys \
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
    "keyIndex": 0
  }')

# If index 0 is taken, the response contains nextAvailableIndex — retry with it
NEXT=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('nextAvailableIndex',''))" 2>/dev/null)
if [ -n "$NEXT" ]; then
  RESPONSE=$(curl -s -X POST http://localhost:3000/keys \
    -H 'Content-Type: application/json' \
    -d "{
      \"policy\": { \"version\": \"1.1\", \"policy\": { \"type\": \"operator\", \"operator\": \"AND\", \"children\": [{ \"type\": \"condition\", \"conditionType\": \"OUTPUT_VALUE\", \"conditionParams\": { \"selector\": \"ALL\", \"operator\": \"LTE\", \"value\": 10000 } }] } },
      \"network\": \"signet\",
      \"require2FA\": false,
      \"keyIndex\": $NEXT
    }")
fi
echo "$RESPONSE"
```

The successful response includes `keyId`, `p2trAddress`, `aggregatePubKeyHex`, and `bip328Xpub`.
Save `keyId` — it is required for all subsequent signing calls.

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

Consult these docs when you need more detail — do not guess at parameter schemas:

| Question / task | Read |
|---|---|
| Full TypeScript SDK walkthrough | [docs/getting-started.md](docs/getting-started.md) |
| HTTP server curl reference | [docs/server.md](docs/server.md) |
| All condition types, operator params, full examples | [docs/policy-reference.md](docs/policy-reference.md) |
| Placeholder values (`SIGBASH_XPUB`, `SIGBASH_OUTPUT_KEY`, index `-1`, `SELF`) | [docs/policy-reference.md § Runtime-resolved placeholders](docs/policy-reference.md#runtime-resolved-placeholders) |
| Credential model, security properties | [docs/authentication.md](docs/authentication.md) |
| Recovery kit export and import | [docs/recovery.md](docs/recovery.md) |
| Rate-limit and time-window semantics (count + time constraints) | [docs/stateful-constraints.md](docs/stateful-constraints.md) |
| Verifying proof bundles | [docs/verifying.md](docs/verifying.md) |
| Admin operations (user mgmt, 2FA, updateable policies, recovery) | [docs/admin.md](docs/admin.md) |
