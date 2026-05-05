# Getting Started

## Installation

```bash
npm install @sigbash/sdk
```

---

## Step 1: Load WASM

Before calling any `SigbashClient` method you must load the Sigbash WASM
module once. The WASM binary is **not** bundled in the npm package — load it
from `sigbash.com`:

```typescript
import { loadWasm } from '@sigbash/sdk';

await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });
```

The `loadWasm` call returns once the WASM runtime is initialised and all
WASM exports are ready. It is safe to call multiple times — subsequent calls
return immediately if WASM is already loaded.

### Integrity verification

In production, always verify the WASM binary hash. The Sigbash JWT auth
response includes a `WasmVersionMetadata` object (fields: `wasm_version`,
`wasm_sha384`, `wasm_path`) that pins the exact binary served by your tier —
see `src/version-metadata.ts`. Pass these into `buildWasmUrl()`:

```typescript
import { loadWasm, buildWasmUrl } from '@sigbash/sdk';

// wasm_version / wasm_sha384 / wasm_path come from the JWT auth response
const { wasm_version, wasm_sha384, wasm_path } = await yourServer.getWasmMetadata();

await loadWasm({
  wasmUrl: buildWasmUrl('https://www.sigbash.com', { wasm_version, wasm_sha384, wasm_path }),
  expectedHash: wasm_sha384,   // SHA-384 — loading fails if hashes don't match
});
```

The SDK computes SHA-384 of the downloaded binary and compares it against
`expectedHash` using a constant-time comparison. A mismatch aborts initialisation
— this is what protects against MITM tampering and server-side WASM substitution.
Always supply `expectedHash` in production.

---

## Step 2: Generate credentials

No dashboard or sign-up required. `generateCredentials()` writes a `.env` file
on first run containing three random 64-char hex strings (`SIGBASH_API_KEY`,
`SIGBASH_USER_KEY`, `SIGBASH_SECRET_KEY`); the server only ever sees a one-way
hash of these.

```typescript
import { generateCredentials } from '@sigbash/sdk';

const { apiKey, userKey, userSecretKey } = await generateCredentials();
// Writes .env on first run. Returns existing values on subsequent runs.
```

Your `.env` will contain:

```
SIGBASH_API_KEY=<64-char hex>
SIGBASH_USER_KEY=<64-char hex>
SIGBASH_SECRET_KEY=<64-char hex>
SIGBASH_SERVER_URL=https://www.sigbash.com
```

Keep `SIGBASH_SECRET_KEY` private — it never leaves your machine and is the
only thing that protects your key material.

---

## Step 3: Quick Start (Node.js)

A complete example: create a client, register a key, and sign a PSBT. The
`loadWasm` call below is a no-op if WASM was already loaded earlier in the
process.

```typescript
import {
  loadWasm,
  SigbashClient,
  conditionConfigToPoetPolicy,
} from '@sigbash/sdk';

// Load WASM (once per process)
await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });

// Create client — supply the three-credential triplet
const client = new SigbashClient({
  serverUrl:     'https://www.sigbash.com',
  apiKey:        process.env.SIGBASH_API_KEY!,     // API key from generateCredentials() — local, no dashboard
  userKey:       process.env.SIGBASH_USER_KEY!,    // User identifier (64-char hex from generateCredentials())
  userSecretKey: process.env.SIGBASH_SECRET_KEY!,  // User-only secret — never sent to server
});

// Define a policy — allow spending only when ALL outputs <= 10,000 sats
const policy = conditionConfigToPoetPolicy({
  type: 'OUTPUT_VALUE',
  selector: 'ALL',
  operator: 'LTE',
  value: 10_000,
});

// Register a key with the policy
const { keyId, bip328Xpub, aggregatePubKeyHex, p2trAddress } = await client.createKey({
  policy,
  network:    'signet',   // 'signet' is the default; mainnet is gated — see AGENTS.md / contact sales
  require2FA: false,      // whether 2FA is required at signing time
});
console.log('BIP-328 xpub:', bip328Xpub);
// Import this xpub into a descriptor or multisig wallet of your choice to fund the key.
// `aggregatePubKeyHex` is also returned for advanced multisig integration.
//
// WARNING: do NOT fund `p2trAddress` directly — it is a single-derivation helper,
// not the funding entry point. Always derive receive addresses from the xpub.

// Retrieve key material (needed for signing). `kmcJSON` is the encrypted
// client-held key-material container; pass it back into `signPSBT()` so WASM
// can reconstruct the local signing share.
const { kmcJSON } = await client.getKey(keyId);

// Sign a PSBT. To produce a signet PSBT, use any descriptor- or multisig-aware
// Bitcoin wallet that can import the xpub above and export an unsigned PSBT —
// see `signing.md` for the end-to-end flow.
const result = await client.signPSBT({
  keyId,
  psbtBase64: '<base64-encoded PSBT>',
  kmcJSON,
  network: 'signet',
});

if (result.success) {
  console.log('Signed tx hex:', result.txHex);
} else {
  console.error('Signing failed:', result.error);
}
```
