# Account Recovery

The SDK supports **recovery kit export and import** so that a user who loses their `userSecretKey` can still access their key material container (KMC) and resume signing operations.

---

## Background: Why Recovery Is Needed

The SDK derives encryption keys from the credential triplet:

| Credential | Holder | Sent to server? |
|---|---|---|
| `apiKey` | Admin | No (only `authHash` is sent) |
| `userKey` | Admin | No (only `authHash` is sent) |
| `userSecretKey` | User only | **Never** |

```
authHash    = DSHA256(apiKey ‖ userKey)        — server authentication
credKEK     = HKDF(triplet, salt='sigbash-kmc-v1', …)
recoveryKEK = HKDF(triplet, salt='sigbash-kmc-v1-user-recovery', …)
```

During `createKey()`, the KMC is encrypted under a fresh CEK, which is itself wrapped under both KEKs:

- **auth slot** → CEK wrapped under `credKEK` (normal access path)
- **`enc_kek2`** → CEK wrapped under `recoveryKEK` (recovery path, stored server-side)

If `userSecretKey` is lost, neither KEK can be re-derived, making both slots inaccessible. A recovery kit solves this by **pre-deriving and storing** the `recoveryKEK` before the secret is lost.

---

## Exporting a Recovery Kit

Call `exportRecoveryKit()` while the credential triplet is still valid:

```typescript
const client = new SigbashClient({ apiKey, userKey, userSecretKey, serverUrl });

const kit = await client.exportRecoveryKit(keyId);

// Persist the kit securely — treat it like a private key.
await mySecureStore.save('recovery-kit', JSON.stringify(kit));
```

The returned `SdkRecoveryKit` object looks like:

```json
{
  "version": "sdk-recovery-v1",
  "keyId": "key-abc123",
  "recoveryKEK": "a3f1c8...e8d2",
  "cekCiphertext": "4a7f3e...",
  "cekNonce": "1b2c8f...",
  "network": "mainnet",
  "createdAt": 1745000000,
  "apiKey": "aabbcc...",
  "userKey": "ddeeff..."
}
```

`apiKey` and `userKey` are included so the kit is **fully self-contained**: recovering from it does not require a separately stored `.env` file. They are not secret on their own — signing power requires `recoveryKEK` — but they identify the org and user on the server, so store the kit as a single sensitive unit.

### Security warning

**`recoveryKEK` is as sensitive as a private key.** Anyone who holds the kit
and has access to the server for the matching `keyId` can decrypt the KMC.

Recommended storage:
- Encrypted secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
- Hardware security module (HSM)
- Encrypted offline backup (paper printed and physically secured)

---

## Recovering From a Kit

The `userSecretKey` value does not matter during recovery — it is not used. If the kit includes `apiKey` and `userKey` (all kits exported by this SDK version do), you can reconstruct the client entirely from the kit:

```typescript
const savedKit = JSON.parse(await mySecureStore.load('recovery-kit'));

// apiKey and userKey come from the kit itself — no separate .env needed.
const client = new SigbashClient({
  apiKey:        savedKit.apiKey,
  userKey:       savedKit.userKey,
  userSecretKey: 'placeholder',   // ignored during recoverFromKit()
  serverUrl,
});

const result = await client.recoverFromKit(savedKit);
// result is a GetKeyResult — same shape as getKey()

// Use the recovered KMC for signing:
const signed = await client.signPSBT({
  keyId: result.keyId,
  psbtBase64: '...',
  kmcJSON: result.kmcJSON,
});
```

### What happens internally

1. The SDK authenticates with the server using `authHash = DSHA256(apiKey ‖ userKey)`.
2. The server returns the current encrypted envelope and `enc_kek2`.
3. The kit's `recoveryKEK` hex is decoded to bytes.
4. `unwrapCEK(enc_kek2, recoveryKEKBytes)` → 32-byte CEK.
5. The CEK decrypts the envelope's `ciphertext_package` → KMC.

The `enc_kek2` snapshot embedded in the kit is used as a fallback only if the server returns none; the server copy is always preferred.

---

## Error Codes

| Code | Cause |
|---|---|
| `NO_ENC_KEK2` | Key was registered before `enc_kek2` support — recovery kit cannot be generated |
| `ENC_KEK2_VERSION_MISMATCH` | The server returned a WebAuthn-type `enc_kek2` blob; use the WebAuthn recovery path instead |
| `RECOVERY_KIT_VERSION_MISMATCH` | Kit `version` field is not `'sdk-recovery-v1'` |
| `RECOVERY_KIT_INVALID` | Kit is missing required fields (`keyId`, `recoveryKEK`, `cekCiphertext`, `cekNonce`) or `recoveryKEK` is not valid hex |
| `CryptoError` | `recoveryKEK` is wrong (the CEK unwrap failed); the kit may be for a different key |

---

## Credential Rotation After Recovery

After recovering the KMC you may want to re-wrap it under a new `userSecretKey`:

```typescript
// 1. Recover the KMC.
const recovered = await client.recoverFromKit(kit);

// 2. Create a new key with the recovered policy (requires new userSecretKey).
const freshClient = new SigbashClient({ apiKey, userKey, userSecretKey: newSecret, serverUrl });

// 3. Re-register: call createKey() with the same policy to get a new keyId
//    and fresh KMC wrapped under the new credentials.
//    Note: a full re-key (new musig2 key pair) is the safest approach.
```

---

## FAQ

**Q: Can the server or admin recover the KMC without the recovery kit?**  
No. The server stores `enc_kek2` (CEK encrypted under `recoveryKEK`), but `recoveryKEK` is derived from `userSecretKey` which the server never receives. Without either the full triplet or the pre-derived `recoveryKEK` from the kit, the CEK is unrecoverable.

**Q: What if both `userSecretKey` and the recovery kit are lost?**  
The KMC is permanently inaccessible. There is no server-side recovery mechanism. Export and store recovery kits with the same care as private key backups.

**Q: Should I call `exportRecoveryKit()` after every `createKey()` call?**  
Yes. A new key gets a new CEK and a new `enc_kek2`. Each key has its own recovery kit.

**Q: Does recovering change the on-chain address or policy root?**  
No. Recovery only decrypts the existing KMC — it does not create a new key, modify the policy, or change any on-chain state.
