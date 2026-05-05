# Admin Operations

This doc covers admin-only operations: pre-registering users, enforcing 2FA,
updating policies on existing keys, and recovering keys for departed users. All
snippets assume `adminClient` is a `SigbashClient` constructed with the admin's
credentials.

See also: [creating-keys.md](creating-keys.md) for non-admin key creation,
[recovery.md](recovery.md) for user-side recovery kit export.

## Who is the admin?

The first user to call `createKey()` within a new organization (identified by
`apiKey`) is **automatically promoted to admin**. No explicit setup is required.
Subsequent users in the same org start as regular users.

There is no `isAdmin()` helper — the caller's role is implied by their
credentials and revealed by server-side errors when an admin-only operation is
attempted.

Admin status is:
- **Org-scoped** — tied to `(apiKey, userKey)`, not just `userKey`
- **Permanent** — there is no demotion mechanism
- **Self-protecting** — an admin cannot revoke their own access

> **`apiKey` rotation creates a new org.** Admin promotion is scoped to
> `(apiKey, userKey)`. Rotating `apiKey` results in a brand-new org with no
> admin until the first `createKey()` call promotes its caller. Plan rotations
> carefully — and back up the recovery kits before rotating, since the old
> org's keys are unreachable from the new credentials.

---

## User management

Admins can pre-register users so they are authorized to create keys within the
org before they make their first request.

```typescript
// Grant access to a new user
await adminClient.registerUser('alice');

// Remove access from an existing user
await adminClient.revokeUser('bob');  // throws AdminError if the caller is not admin
```

An admin cannot revoke their own access — the server rejects self-revocation.

Revocation takes effect on the next request from that user; existing in-flight
calls are not interrupted. There is no push-style invalidation — the auth check
happens per request, so a revoked user keeps working until their next call to
the server.

Both methods throw `AdminError` if the caller is not the org admin.

---

## 2FA enforcement

2FA can be required on a per-key basis by setting `require2FA: true` at
creation time. This flag cannot be changed after the key is created.

### Setup (once per key)

Until `confirmTOTP()` succeeds, any `signPSBT` call on this key will throw
`TOTPSetupIncompleteError`.

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

> **Backup the TOTP secret.** Store `secret` in a password manager as a backup.
> If the authenticator device is lost and no backup exists, the only recovery
> path is admin-initiated key recovery (see below) or creating a new key.

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
| `TOTPInvalidError` | Code is incorrect, expired, or rate limit exceeded (5 attempts / 60s) |

---

## Updateable policies

By default, a key's POET policy is immutable. Marking a key `updateable: true`
at creation time lets the org admin replace the policy later via
`adminUpdatePolicy()`.

Only admins can set the `updateable` flag. For non-admin callers the flag is
silently ignored. Enforcement is server-side (`/api/v2/sdk/keys` endpoint); the
client always passes the flag through, but the server only honors it for
admins.

The `keyId`, on-chain `p2trAddress`, and aggregate public key are unchanged by
a policy update — only the stored policy root changes.

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

This feature must be explicitly enabled by the admin for their org before
`adminRecoverKey()` will succeed. There is no typed SDK wrapper for this
setting; call the admin settings endpoint directly with the admin's
`authHash` (from `getAuthHash(apiKey, userKey)`):

```typescript
import { getAuthHash } from '@sigbash/sdk';

const { authHash } = await getAuthHash(apiKey, userKey);

await fetch(`${serverUrl}/api/v2/sdk/admin/settings`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    auth_hash: authHash,
    allow_admin_recovery: true,
  }),
});
```

This is self-serve — no contact with Sigbash sales is required.

**Obtaining the kit.** The departing user runs `exportRecoveryKit()` (see
[recovery.md](recovery.md)) and transmits the resulting JSON to the admin
out-of-band — e.g. via an encrypted file share. The kit's `recoveryKEK` is
itself sufficient to unwrap the CEK; transmit the file with the same care as a
private-key backup.

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

## Multi-key orgs

Multi-key orgs and `keyIndex` collisions are covered in
[creating-keys.md § Multiple keys per user](creating-keys.md#multiple-keys-per-user).

---

## Error reference

| Error class | Code | Cause |
|---|---|---|
| `AdminError` | — | Caller is not the org admin, or `adminUpdatePolicy()` was called on a key not marked `updateable` (server message contains "not marked updateable") |
| `SigbashSDKError` | `ADMIN_RECOVERY_DISABLED` | `adminRecoverKey()` called but feature not enabled |
| `SigbashSDKError` | `NOT_FOUND` | Target user or key does not exist |
| `SigbashSDKError` | `RECOVERY_KIT_VERSION_MISMATCH` | Recovery kit is from an incompatible SDK version |
| `SigbashSDKError` | `RECOVERY_KIT_INVALID` | Recovery kit is missing required fields |
| `KeyIndexExistsError` | `KEY_INDEX_EXISTS` | Requested `keyIndex` already in use; check `err.nextAvailableIndex` |
