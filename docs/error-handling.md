# Error Handling

Every error thrown by the SDK extends `SigbashSDKError`, the canonical base class. Each instance carries a string `code` (e.g. `'CLIENT_DISPOSED'`, `'WASM_ERROR'`, `'POLICY_INVALID'`) and a human-readable `message`. Catching `SigbashSDKError` is sufficient to handle every failure the SDK produces; catch a more specific subclass when you want to react to a particular condition.

Server-failure classes — `ServerError`, `AuthenticationError`, `NetworkMismatchError`, `PolicyValidationError` — are first-class members of this hierarchy. `parseServerError(response)` returns a `SigbashSDKError`, picking the most specific subclass that matches the server payload.

The abstract `SigbashError` base class and the `ErrorCode` enum remain exported for backward compatibility with old consumer code — the SDK itself no longer throws them, and new code should ignore them.

```typescript
import {
  SigbashSDKError,
  KeyIndexExistsError,
  PolicyCompileError,
  TOTPRequiredError,
  TOTPInvalidError,
  MissingOptionError,
  ClientDisposedError,
} from '@sigbash/sdk';

try {
  await client.createKey({ policy, network: 'signet', require2FA: false });
} catch (err) {
  if (err instanceof KeyIndexExistsError) {
    // Key index already used — retry with the next available index
    await client.createKey({
      policy,
      network: 'signet',
      require2FA: false,
      keyIndex: err.nextAvailableIndex,
    });
  } else if (err instanceof PolicyCompileError) {
    // Policy JSON is invalid — compilationTrace shows the error chain
    console.error(err.summary);
    console.error(err.compilationTrace);
  } else if (err instanceof SigbashSDKError) {
    // All other SDK errors — err.code is a string like 'MISSING_OPTION'
    console.error(err.code, err.message);
  }
}
```

## Error class reference

Grouped by lifecycle phase. Every entry below is a subclass of `SigbashSDKError` and is exported from `@sigbash/sdk`.

### Client lifecycle

| Class | Code | When thrown |
|---|---|---|
| `ClientDisposedError` | `CLIENT_DISPOSED` | Any method called after `dispose()` |
| `MissingOptionError` | `MISSING_OPTION` | Required option omitted; `optionName` identifies which (thrown by the `SigbashClient` constructor and `createKey()`) |

### Initialization (constructor / `init`)

| Class / code | When thrown |
|---|---|
| `WASM_NOT_LOADED` | WASM module has not been initialized via `loadWasm()` before constructing the client |
| `WASM_ERROR` | Generic WASM call failure (init, encryption, signing, policy update) |
| `INVALID_PRIVATE_KEY` | The supplied `musig2PrivateKey` is malformed or rejected by WASM |

### `createKey()`

| Class / code | When thrown |
|---|---|
| `KeyIndexExistsError` (`KEY_INDEX_EXISTS`) | Index already registered for this credential; use `nextAvailableIndex` |
| `PolicyCompileError` (`POLICY_COMPILE_FAILED`) | POET policy JSON rejected by the WASM compiler |
| `KEY_GEN_FAILED` | WASM key generation returned an error |
| `KEY_AGG_FAILED` | MuSig2 key aggregation failed |
| `AMBIGUOUS_POLICY` | Both `policy` and `policyJson` were supplied |
| `MISSING_POLICY` | Neither `policy` nor `policyJson` was supplied |
| `INVALID_NETWORK` | The supplied network string is not recognised |
| `NetworkError` (`NETWORK_NOT_ENABLED`) | The requested network is not enabled for this org |

### `signPSBT()`

| Class / code | When thrown |
|---|---|
| `TOTPRequiredError` (`TOTP_REQUIRED`) | 2FA-enabled key, no `totpCode` supplied |
| `TOTPInvalidError` (`TOTP_INVALID`) | Server rejected the supplied TOTP code |
| `TOTPSetupIncompleteError` (`TOTP_SETUP_INCOMPLETE`) | `confirmTOTP()` has not yet been called for this key |
| `WASM_ERROR` | `SigbashWASM_SignPSBTBlind` or related WASM call failed |
| `NO_KEY_MATERIAL` | Server response is missing `encrypted_key_material` |

### Recovery (`exportRecoveryKit` / `importRecoveryKit`)

| Class / code | When thrown |
|---|---|
| `KEY_RESTORE_FAILED` | WASM rejected the recovered key material |
| `RECOVERY_KIT_INVALID` | Recovery kit fields are missing or `recoveryKEK` is not a 32-byte hex string |
| `RECOVERY_KIT_VERSION_MISMATCH` | Recovery kit was produced by an incompatible SDK version |
| `ENC_KEK2_VERSION_MISMATCH` | Migration-only: the server-side `enc_kek2` blob is a legacy `webauthn-v1` shape that this SDK no longer understands. Should not surface in normal flows |

### Admin operations

| Class / code | When thrown |
|---|---|
| `AdminError` (`ADMIN_REQUIRED`) | Server returned 403 / `FORBIDDEN` / `UNAUTHORIZED` for an admin endpoint |
| `ADMIN_RECOVERY_DISABLED` | Admin-mediated recovery is not enabled for this org |

### Server-failure classes (returned by `parseServerError`)

These are full members of the modern hierarchy — extend `SigbashSDKError` directly:

| Class | Code | Notes |
|---|---|---|
| `ServerError` | `SERVER_ERROR` | Generic server failure. `statusCode` reflects HTTP status; `details` preserves the raw response |
| `AuthenticationError` | `AUTH_FAILED` | Credentials rejected. `details` preserves the raw response |
| `NetworkMismatchError` | `NETWORK_MISMATCH` | `expected` and `actual` carry the conflicting network strings |
| `PolicyValidationError` | `POLICY_INVALID` | `issues` is an array of structured `PolicyIssue` records |

### Generic codes (raised via the `SigbashSDKError` base directly)

| Code | When thrown |
|---|---|
| `UNAUTHORIZED` | Server returned a 401-equivalent code on a non-admin endpoint |
| `FORBIDDEN` | Server returned a 403-equivalent code on a non-admin endpoint |
| `UNKNOWN` | Catch-all for unrecognised server payloads |

## TOTP error lifecycle

A 2FA key moves through three states; each maps to a distinct error class so you can route the user appropriately.

```
no totpCode supplied              → TOTPRequiredError
confirmTOTP() not yet called      → TOTPSetupIncompleteError
code mistyped or expired          → TOTPInvalidError
```

```typescript
try {
  await client.signPSBT({ keyId, psbtBase64, kmcJSON, network, totpCode });
} catch (err) {
  if (err instanceof TOTPSetupIncompleteError) {
    // 2FA was enabled but never confirmed — walk the user through enrollment
    await client.confirmTOTP({ keyId, totpCode: enrollmentCode });
  } else if (err instanceof TOTPRequiredError) {
    // Prompt for a code and retry
  } else if (err instanceof TOTPInvalidError) {
    // Code was wrong or expired — let the user retype it
  } else {
    throw err;
  }
}
```

## `PolicyCompileError` shape

`PolicyCompileError` flattens the colon-separated Go error chain returned by the WASM compiler into structured fields:

- `compilationTrace: string[]` — ordered chain, innermost (most specific) segment last, with consecutive duplicates removed.
- `summary: string` — the innermost segment, suitable for surfacing inline.
- `message: string` — multi-line, of the form:
  ```
  Policy compilation failed: <summary>
  Compilation trace:
    1. <segment>
    2. <segment>
    ...
  ```

Use `summary` for UI; log `compilationTrace` (or the full `message`) for diagnostics.

## Common scenarios

### Duplicate `keyIndex`

```typescript
try {
  await client.createKey({ policy, network: 'signet', require2FA: false, keyIndex: 0 });
} catch (err) {
  if (err instanceof KeyIndexExistsError) {
    await client.createKey({
      policy,
      network: 'signet',
      require2FA: false,
      keyIndex: err.nextAvailableIndex,
    });
  } else {
    throw err;
  }
}
```

### TOTP code rejected

```typescript
try {
  await client.signPSBT({ keyId, psbtBase64, kmcJSON, network: 'signet', totpCode });
} catch (err) {
  if (err instanceof TOTPInvalidError) {
    // Surface a "code incorrect — try again" UI affordance
  } else {
    throw err;
  }
}
```

### Use after `dispose()`

```typescript
client.dispose();
try {
  await client.listKeys();
} catch (err) {
  if (err instanceof ClientDisposedError) {
    // Build a fresh client; the old one is permanently retired
  }
}
```

### Recovery kit version mismatch

```typescript
try {
  await client.importRecoveryKit(kit);
} catch (err) {
  if (err instanceof SigbashSDKError && err.code === 'RECOVERY_KIT_VERSION_MISMATCH') {
    // Kit was produced by an incompatible SDK release — surface an upgrade hint
  } else {
    throw err;
  }
}
```

## See also

- [signing.md](signing.md) — TOTP and PSBT signing flows
- [recovery.md](recovery.md) — recovery kit export and import
- [admin.md](admin.md) — admin-gated operations and `AdminError` semantics
- [stateful-constraints.md](stateful-constraints.md) — count- and time-based policy constraints
