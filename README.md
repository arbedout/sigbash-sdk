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

No dashboard or sign-up required. Generate a credential triplet locally:

```typescript
import { generateCredentials } from '@sigbash/sdk';

const { apiKey, userKey, userSecretKey } = await generateCredentials();
// Writes .env on first run. Returns existing values on subsequent runs.
```

> **Your credentials never leave your machine.** `generateCredentials()` produces
> three random hex strings locally. Sigbash only ever receives
> `authHash = DSHA256(apiKey ∥ userKey)` — a one-way hash. Your raw credentials
> are never transmitted.

| Credential | Role | Sent to server? |
|---|---|---|
| `apiKey` | Organisation identifier | No — only its hash |
| `userKey` | User identifier within your organisation | No — only its hash |
| `userSecretKey` | Local encryption key — protects your key material | **Never** |

Keep `userSecretKey` private. The first user to call `createKey()` in a new org
is auto-promoted to admin. Additional users are registered via
`client.registerUser(userKey)`.

> **Signet only by default.** All keys are created on Bitcoin signet. To enable
> mainnet access for your org, email [sales@sigbash.com](mailto:sales@sigbash.com)
> with your `apikeyHash` (run `getAuthHash(apiKey, userKey)` to obtain it).

---

## Quick start

```typescript
import { generateCredentials, loadWasm, SigbashClient, conditionConfigToPoetPolicy } from '@sigbash/sdk';

// 1. Generate (or load) credentials — writes .env on first run
const { apiKey, userKey, userSecretKey } = await generateCredentials();

// 2. Load WASM (once per process)
await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });

// 3. Create a client
const client = new SigbashClient({
  serverUrl: 'https://www.sigbash.com',
  apiKey,
  userKey,
  userSecretKey,
});

// 4. Define a policy — all outputs must be <= 10,000 sats
const policy = conditionConfigToPoetPolicy({
  type: 'OUTPUT_VALUE',
  selector: 'ALL',
  operator: 'LTE',
  value: 10_000,
});

// 5. Register a key with the policy
const { keyId, p2trAddress } = await client.createKey({
  policy,
  network: 'signet',   // signet only by default — email sales@sigbash.com to upgrade
  require2FA: false,
});
console.log('Fund this address:', p2trAddress);

// 6. Retrieve key material (needed for signing)
const { kmcJSON } = await client.getKey(keyId);

// 7. Sign a PSBT
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
- [Running the HTTP Server](docs/server.md) — standalone Node.js, Docker, curl examples

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
