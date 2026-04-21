# Security

## Credential model

- `userSecretKey` is **never transmitted** — it is used only locally for KEK derivation.
- Key material is encrypted with AES-256-GCM using the KEK before being stored server-side.
- The server stores only the encrypted KMC — it cannot decrypt key material without `userSecretKey`.

## WASM integrity

Always supply `expectedHash` to `loadWasm()` in production:

```typescript
await loadWasm({ wasmUrl, expectedHash: 'sha384-...' });
```

The SDK verifies SHA-384 of the downloaded binary before initialisation.  If
the hash does not match, loading fails with an error — protecting against
MITM and server-side WASM substitution attacks.
