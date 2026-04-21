# @sigbash/sdk

TypeScript SDK for **Sigbash** — policy-gated oblivious Bitcoin signing.

Sigbash is a co-signing service for Bitcoin transactions. You define a POET
(*Policy Operand Evaluation Tree*) that encodes spending rules, and the Sigbash
server will only co-sign when those rules are satisfied. The server is
*oblivious*: it never sees the transaction content, the co-signers, or which
policy path was taken — it learns only that *some* valid path was satisfied,
proved by a zero-knowledge proof computed inside the WASM module.

---

## Installation

```bash
npm install @sigbash/sdk
```

---

## Credentials

You need three values to use the SDK:

| Credential | What it is | How to get it |
|---|---|---|
| `apiKey` | Organisation-level API key | Sign up at [sigbash.com](https://www.sigbash.com) — your API key is on the dashboard |
| `userKey` | Unique identifier for this user | Generate with `SigbashClient.generateUserKey()`, or use any stable string |
| `userSecretKey` | User-only secret for local encryption | Generate with `SigbashClient.generateUserSecretKey()` — **store securely, never share** |

The `apiKey` and `userKey` are sent to the server for authentication. The
`userSecretKey` **never leaves the client** — it is used only to derive the
encryption key for local key material.

> **First user in an org is auto-promoted to admin.** To add more users,
> call `client.registerUser(newUserKey)` from an admin client.

---

## Quick start

```typescript
import { loadWasm, SigbashClient, conditionConfigToPoetPolicy } from '@sigbash/sdk';

// 1. Load WASM (once per process)
await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });

// 2. Create a client
const client = new SigbashClient({
  serverUrl:     'https://www.sigbash.com',
  apiKey:        'your-api-key',                        // from dashboard
  userKey:       SigbashClient.generateUserKey(),        // or any stable identifier
  userSecretKey: SigbashClient.generateUserSecretKey(),  // store this securely
});

// 3. Define a policy — all outputs must be <= 10,000 sats
const policy = conditionConfigToPoetPolicy({
  type: 'OUTPUT_VALUE',
  selector: 'ALL',
  operator: 'LTE',
  value: 10_000,
});

// 4. Register a key with the policy
const { keyId, p2trAddress } = await client.createKey({
  policy,
  network: 'signet',
  require2FA: false,
});
console.log('Fund this address:', p2trAddress);

// 5. Retrieve key material (needed for signing)
const { kmcJSON } = await client.getKey(keyId);

// 6. Sign a PSBT
const result = await client.signPSBT({
  keyId,
  psbtBase64: '<your base64-encoded PSBT>',
  kmcJSON,
  network: 'signet',
});

if (result.success) {
  console.log('Signed tx:', result.txHex);
}
```

---

## Documentation

Read these in order to go from zero to signing:

1. **[Getting Started](docs/getting-started.md)** — WASM loading, integrity verification, full Node.js walkthrough
2. **[Creating Keys](docs/creating-keys.md)** — policy templates, `conditionConfigToPoetPolicy`, raw POET policies
3. **[Policy Reference](docs/policy-reference.md)** — all 14 operators and 27 condition types with examples

Then as needed:

- [Authentication](docs/authentication.md) — three-credential model, KEK derivation
- [Signing a PSBT](docs/signing.md) — `signPSBT` options, TOTP 2FA setup
- [Verifying a PSBT](docs/verifying.md) — dry-run policy checks without consuming a nullifier
- [Stateful Constraints](docs/nullifiers.md) — `COUNT_BASED_CONSTRAINT` and `TIME_BASED_CONSTRAINT`
- [Error Handling](docs/error-handling.md) — error class hierarchy and recovery patterns
- [Security](docs/security.md) — credential model, WASM integrity verification
- [Environment Support](docs/environments.md) — Node.js, browsers, Electron

---

## License

The source code in this repository is licensed under the Apache License, Version 2.0.
See [`LICENSE`](./LICENSE).

## Hosted Sigbash Runtime

This SDK may load a Sigbash-hosted WebAssembly runtime and communicate with
Sigbash-operated services. That hosted runtime and those services are not
licensed under the Apache License by virtue of this repository alone, and may
be subject to separate commercial terms, service terms, or access restrictions.
See [`NOTICE`](./NOTICE).
