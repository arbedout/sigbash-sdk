# Error Handling

All SDK errors extend `SigbashSDKError`.  Catch specific subclasses for targeted recovery:

```typescript
import {
  SigbashSDKError,
  KeyIndexExistsError,
  PolicyCompileError,
  TOTPRequiredError,
  TOTPInvalidError,
  MissingOptionError,
} from '@sigbash/sdk';

try {
  await client.createKey({ policy, network: 'signet', require2FA: false });
} catch (err) {
  if (err instanceof KeyIndexExistsError) {
    // Key index already used — use nextAvailableIndex to create another key
    await client.createKey({ ..., keyIndex: err.nextAvailableIndex });
  } else if (err instanceof PolicyCompileError) {
    // Policy JSON is invalid — compilationTrace shows the error chain
    console.error(err.compilationTrace);
  } else if (err instanceof SigbashSDKError) {
    // All other SDK errors — err.code is a string like 'MISSING_OPTION'
    console.error(err.code, err.message);
  }
}
```

**Error class reference:**

| Class | Code | When thrown |
|---|---|---|
| `KeyIndexExistsError` | `KEY_INDEX_EXISTS` | `createKey()` — index already registered; use `nextAvailableIndex` |
| `PolicyCompileError` | `POLICY_COMPILE_FAILED` | `createKey()` — POET policy JSON rejected by WASM; see `compilationTrace` |
| `MissingOptionError` | `MISSING_OPTION` | Required option omitted; `optionName` identifies which |
| `TOTPRequiredError` | `TOTP_REQUIRED` | `signPSBT()` called on 2FA key without `totpCode` |
| `TOTPInvalidError` | `TOTP_INVALID` | `signPSBT()` TOTP code rejected by server |
| `TOTPSetupIncompleteError` | `TOTP_SETUP_INCOMPLETE` | `confirmTOTP()` not yet called |
| `AdminError` | `ADMIN_REQUIRED` | Operation requires admin credentials |
| `NetworkError` | `NETWORK_NOT_ENABLED` | Requested network unavailable |

> **Legacy errors** (`SigbashError`, `PolicyValidationError`, `WasmError`, etc.) are
> deprecated.  They remain exported for backward compatibility but new code should
> catch `SigbashSDKError` subclasses.
