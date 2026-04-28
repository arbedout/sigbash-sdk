# Verifying a PSBT (dry-run)

Every successful `signPSBT` consumes a nullifier session — a one-shot resource
gated by your policy's `max_uses` / `reset_interval` constraints. Calling
`verifyPSBT` first lets you dry-run the full policy and nullifier evaluation
without spending one of those sessions, so you can surface a clean failure
reason to the user before committing.

`verifyPSBT` runs the entire POET policy + nullifier check locally in WASM. It
is **not strictly offline**: it makes one HTTP `GET /api/v2/signing_key` call to
fetch the current nullifier epoch state from the server. No PSBT bytes, no
signing material, and no proof bundle leave the client.

## Prerequisites

- `loadWasm()` must have already been called.
- `kmcJSON` is the decrypted KMC string returned by `await client.getKey(keyId)`.

## Basic usage

```typescript
const verification = await client.verifyPSBT({
  psbtBase64,
  kmcJSON,
  network: 'signet',
});

console.log(verification.passed);          // boolean
console.log(verification.pathId);          // hex ID of the matched policy path
console.log(verification.satisfiedClause); // human-readable clause description
console.log(verification.nullifierStatus); // [{ inputIndex, available, message }]
if (!verification.passed) console.error(verification.error);
```

## `nullifierStatus` shape

`nullifierStatus` is an array with one entry per PSBT input:

```typescript
{ inputIndex: number; available: boolean; message: string }
```

If any entry has `available === false`, a real `signPSBT` would fail at the
nullifier check — the session for that input has already been consumed or is
otherwise unavailable under the current epoch. See
[stateful-constraints.md](stateful-constraints.md) for how `max_uses`,
`reset_interval`, and epoch rollover interact.

## Idempotency

Calling `verifyPSBT` repeatedly on the same PSBT is safe and produces identical
results. It does not mutate server state and does not consume a nullifier.

## Progress callback

Like `signPSBT`, `verifyPSBT` accepts an optional
`progressCallback: (step: string, message: string) => void` for surfacing
WASM evaluation progress to a UI.

## End-to-end example

```typescript
import { loadWasm, SigbashClient, conditionConfigToPoetPolicy } from '@sigbash/sdk';

await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });

const client = new SigbashClient({
  serverUrl: 'https://www.sigbash.com',
  apiKey,
  userKey,
  userSecretKey,
});

// 1. Register a key with a spending policy.
const { keyId, p2trAddress, bip328Xpub } = await client.createKey({
  policy: conditionConfigToPoetPolicy({
    logic: 'AND',
    conditions: [
      { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 100_000 },
      { type: 'COUNT_BASED_CONSTRAINT', max_uses: 3, reset_interval: 'daily', reset_type: 'rolling' },
    ],
  }),
  network: 'signet',
  require2FA: false,
});

// 2. Retrieve the decrypted KMC for local evaluation.
const { kmcJSON } = await client.getKey(keyId, { verbose: true });

// 3. Build a PSBT with any standard PSBT-producing wallet from `bip328Xpub`,
//    spending from `p2trAddress`. Pass the resulting base64 PSBT in:
const psbtBase64 = '<base64 PSBT from your wallet>';

// 4. Dry-run before signing.
const verification = await client.verifyPSBT({
  psbtBase64,
  kmcJSON,
  network: 'signet',
});

if (verification.passed) {
  // Safe to sign — this will consume one nullifier session.
  const result = await client.signPSBT({ keyId, psbtBase64, kmcJSON, network: 'signet' });
  console.log(result.txHex);
} else {
  console.error('Would not sign:', verification.error);
  console.error('Matched path:', verification.pathId, verification.satisfiedClause);
  for (const ns of verification.nullifierStatus) {
    if (!ns.available) {
      console.error(`  input ${ns.inputIndex}: ${ns.message}`);
    }
  }
}
```

## See also

- [signing.md](signing.md) — actually signing a PSBT (consumes a nullifier).
- [stateful-constraints.md](stateful-constraints.md) — `max_uses`,
  `reset_interval`, and how nullifier availability is computed.
