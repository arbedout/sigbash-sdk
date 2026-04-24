# Admin Operations

## Who is the admin?

The first user to call `createKey()` within a new organisation (identified by
`apiKey`) is **automatically promoted to admin**. No explicit setup is required.
Subsequent users in the same org start as regular users.

Admin status is:
- **Org-scoped** — tied to `(apiKey, userKey)`, not just `userKey`
- **Permanent** — there is no demotion mechanism
- **Self-protecting** — an admin cannot revoke their own access

---

## User management

Admins can pre-register users so they are authorised to create keys within the
org before they make their first request.

```typescript
// Grant access to a new user
await adminClient.registerUser('alice');

// Remove access from an existing user
await adminClient.revokeUser('bob');  // throws AdminError if bob is the caller
```

Both methods throw `AdminError` if the caller is not the org admin.

---

## 2FA enforcement

2FA can be required on a per-key basis by setting `require2FA: true` at
creation time. This flag cannot be changed after the key is created.

### Setup (once per key)

```typescript
// 1. Create the key with 2FA required
const { keyId } = await client.createKey({
  policy,
  network: 'signet',
  require2FA: true,
  verbose: true,
});

// 2. Generate the TOTP secret and get an otpauth:// URI for the authenticator app
const { uri, secret } = await client.registerTOTP(keyId);
// Display `uri` as a QR code. Optionally store `secret` as a backup.

// 3. Confirm with the first code from the authenticator app
await client.confirmTOTP(keyId, '123456');
// TOTP is now active — signing will require a code from this point on.
```

### Signing with 2FA

```typescript
const result = await client.signPSBT({
  keyId,
  psbtBase64,
  kmcJSON,
  network: 'signet',
  require2FA: true,
  totpCode: '654321',  // Current 6-digit code
});
```

### 2FA error codes

| Error class | When |
|---|---|
| `TOTPSetupIncompleteError` | `confirmTOTP()` was never called for this key |
| `TOTPRequiredError` | Key has 2FA but `totpCode` was not supplied |
| `TOTPInvalidError` | Code is incorrect, expired, or rate-limit exceeded (5 attempts / 60s) |

---

## Updateable policies

By default, a key's POET policy is immutable. Marking a key `updateable: true`
at creation time lets the org admin replace the policy later via
`adminUpdatePolicy()`.

Only admins can set the `updateable` flag. For non-admin callers the flag is
silently ignored.

### Creating an updateable key

```typescript
const { keyId } = await adminClient.createKey({
  policy: initialPolicy,
  network: 'signet',
  require2FA: false,
  updateable: true,   // admin-only flag
  verbose: true,
});
```

### Updating the policy

```typescript
import { conditionConfigToPoetPolicy } from '@sigbash/sdk';

const newPolicy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 50_000 },
    { type: 'TX_FEE_ABSOLUTE', operator: 'LTE', value: 5_000 },
  ],
});

await adminClient.adminUpdatePolicy(keyId, JSON.stringify(newPolicy));
// OR: await adminClient.adminUpdatePolicy({ keyId, newPolicyJson: JSON.stringify(newPolicy) });
```

Under the hood:
1. The SDK fetches and decrypts the existing KMC from the server
2. WASM compiles the new policy and updates the KMC in-place
3. The updated KMC is re-encrypted and stored on the server
4. The server updates the stored `policy_root` used for ZK proof verification

Throws `AdminError` (HTTP 403) if the key is not marked `updateable` or the
caller is not the admin.

---

## Admin-initiated key recovery

If a user loses their `userSecretKey`, their keys are normally unrecoverable.
Orgs can opt in to admin-initiated recovery to allow the admin to help departed
users — at the cost of the admin learning the recovered key material.

### Enable admin recovery (opt-in, off by default)

This feature must be explicitly enabled via the server's admin settings endpoint
before `adminRecoverKey()` will succeed. Check your server documentation for
the `POST /api/v2/sdk/admin/settings` endpoint.

### Recovery flow

The target user must have previously exported a recovery kit (see
[recovery.md](recovery.md)).

```typescript
// Admin recovers a departed user's key using their recovery kit
const recovered = await adminClient.adminRecoverKey(
  'departed-user-key',   // targetUserKey — the user's userKey (not their secret)
  keyId,
  recoveryKit,           // SdkRecoveryKit from exportRecoveryKit()
);

// recovered.kmcJSON can now be used to re-register the key under the admin's
// own credentials or a new user account
const result = await adminClient.signPSBT({
  keyId: recovered.keyId,
  psbtBase64,
  kmcJSON: recovered.kmcJSON,
  network: recovered.network,
});
```

Throws:
- `AdminError` — caller is not the org admin
- `SigbashSDKError` with code `ADMIN_RECOVERY_DISABLED` — feature not enabled
- `SigbashSDKError` with code `NOT_FOUND` — target user or key not found
- `CryptoError` — recovery kit KEK is wrong or decryption fails

---

## Key index and multi-key orgs

A user can hold multiple keys within the same org. Each key is assigned a
`keyIndex` (0, 1, 2, …) scoped to the user's credential identifier.

```typescript
// First key — keyIndex defaults to 0
const { keyId: hotKey } = await client.createKey({ policy: hotPolicy, network: 'signet', require2FA: false, verbose: true });

// Second key — provide keyIndex explicitly to avoid collision
const { keyId: coldKey } = await client.createKey({ policy: coldPolicy, network: 'signet', require2FA: false, keyIndex: 1, verbose: true });
```

If the requested `keyIndex` is already taken, the server throws
`KeyIndexExistsError` and includes `nextAvailableIndex` so the caller can retry:

```typescript
import { KeyIndexExistsError } from '@sigbash/sdk';

async function createKeyWithAutoIndex(client, options) {
  let index = options.keyIndex ?? 0;
  while (true) {
    try {
      return await client.createKey({ ...options, keyIndex: index, verbose: true });
    } catch (err) {
      if (err instanceof KeyIndexExistsError) {
        index = err.nextAvailableIndex;
      } else {
        throw err;
      }
    }
  }
}
```

---

## Error reference

| Error class | Code | Cause |
|---|---|---|
| `AdminError` | — | Caller is not the org admin |
| `SigbashSDKError` | `ADMIN_RECOVERY_DISABLED` | `adminRecoverKey()` called but feature not enabled |
| `SigbashSDKError` | `NOT_UPDATEABLE` | `adminUpdatePolicy()` called on a key not marked `updateable` |
| `SigbashSDKError` | `NOT_FOUND` | Target user or key does not exist |
| `SigbashSDKError` | `RECOVERY_KIT_VERSION_MISMATCH` | Recovery kit is from an incompatible SDK version |
| `SigbashSDKError` | `RECOVERY_KIT_INVALID` | Recovery kit is missing required fields |
| `KeyIndexExistsError` | `KEY_INDEX_EXISTS` | Requested `keyIndex` already in use; check `err.nextAvailableIndex` |
