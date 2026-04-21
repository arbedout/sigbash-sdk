# Getting Started

## Installation

```bash
npm install @sigbash/sdk
```

---

## Prerequisites: Load WASM

Before calling any `SigbashClient` method you must load the Sigbash WASM
module once.  The WASM binary is **not** bundled in the npm package — load it
from `sigbash.com`:

```typescript
import { loadWasm } from '@sigbash/sdk';

await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });
```

The `loadWasm` call returns once the Go WASM runtime is initialised and all
WASM exports are ready.  It is safe to call multiple times — subsequent calls
return immediately if WASM is already loaded.

### Integrity verification

In production, always verify the WASM binary hash. If your server provides
WASM version metadata (e.g. via an auth endpoint), pin the exact binary:

```typescript
import { loadWasm, buildWasmUrl } from '@sigbash/sdk';

// Your server returns these fields — adapt to your auth flow
const { wasm_version, wasm_sha384, wasm_path } = await yourServer.getWasmMetadata();

await loadWasm({
  wasmUrl: buildWasmUrl('https://www.sigbash.com', { wasm_version, wasm_sha384, wasm_path }),
  expectedHash: wasm_sha384,   // SHA-384 — loading fails if hashes don't match
});
```

---

## Quick Start (Node.js)

A complete example: load WASM, create a client, register a key, and sign a PSBT.

```typescript
import {
  loadWasm,
  SigbashClient,
  conditionConfigToPoetPolicy,
} from '@sigbash/sdk';

// Step 1: Load WASM (once per process)
await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });

// Step 2: Create client — supply the three-credential triplet
const client = new SigbashClient({
  serverUrl:     'https://www.sigbash.com',
  apiKey:        'your-api-key',          // Organisation-level key from dashboard
  userKey:       'alice',                 // User identifier
  userSecretKey: 'super-secret-32bytes',  // User-only secret — never sent to server
});

// Step 3: Define a policy — allow spending only when ALL outputs <= 10,000 sats
const policy = conditionConfigToPoetPolicy({
  type: 'OUTPUT_VALUE',
  selector: 'ALL',
  operator: 'LTE',
  value: 10_000,
});

// Step 4: Register a key with the policy
const { keyId, p2trAddress, bip328Xpub } = await client.createKey({
  policy,
  network:    'signet',
  require2FA: false,
});
console.log('P2TR address:', p2trAddress);  // Fund this address on-chain

// Step 5: Retrieve key material (needed for signing)
const { kmcJSON } = await client.getKey(keyId);

// Step 6: Sign a PSBT
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
