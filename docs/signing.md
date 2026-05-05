# Signing a PSBT

You've created a key — now use it to sign a PSBT. `keyId` comes from `createKey()`; `kmcJSON` from `getKey(keyId)`.

> **Where does the PSBT come from?** Build the spending wallet from the key's
> `bip328Xpub` (as a descriptor or multisig participant). Never derive the
> spending wallet directly from `p2trAddress` — that address is a single
> aggregate output and won't yield a signable PSBT for the underlying policy.
> See [creating-keys.md](creating-keys.md) for descriptor construction.

```typescript
const result = await client.signPSBT({
  keyId,
  psbtBase64,        // Base64-encoded PSBT string (or use psbtHex)
  kmcJSON,           // From getKey().kmcJSON
  network: 'signet',
  progressCallback: (step, msg) => console.log(step, msg),
});

if (result.success) {
  console.log('txHex:',          result.txHex);            // Ready to broadcast
  console.log('signedPSBT:',     result.signedPSBT);       // For multi-party workflows
  console.log('pathId:',         result.pathId);           // Hex ID of satisfied policy path
  console.log('policyRootHex:',  result.policyRootHex);    // Policy commitment from KMC
  console.log('satisfiedClause:', result.satisfiedClause); // Which policy branch matched
} else {
  console.error(result.error);
}
```

`signPSBT` signs every input in the PSBT in a single call — no per-input loop required.

`psbtHex` is accepted as an alternative to `psbtBase64`; pass whichever encoding
you have. If both are provided, `psbtBase64` wins.

> **Tip — verify before consuming a nullifier.** Each successful sign burns a
> nullifier session. Use [`verifyPSBT()`](verifying.md) for a dry-run that
> checks policy satisfaction without spending one.

## Broadcasting

After `signPSBT` returns successfully, broadcast `result.txHex` to the network.
Any standard Bitcoin transaction broadcaster works — the hex is a fully signed,
network-ready transaction.

---

## With TOTP 2FA

If the key was created with `require2FA: true`, complete TOTP setup once via
`client.registerTOTP()` + `client.confirmTOTP()` — see
[admin.md § 2FA enforcement](admin.md#2fa-enforcement). Then pass `totpCode`
on every `signPSBT` call:

```typescript
const result = await client.signPSBT({
  keyId,
  psbtBase64,
  kmcJSON,
  network: 'signet',
  require2FA: true,
  totpCode: '654321',  // Current 6-digit code from authenticator app
});
```

### Error handling

| Error class | When |
|---|---|
| `TOTPSetupIncompleteError` | `confirmTOTP()` was never called for this key |
| `TOTPRequiredError` | Key has 2FA enabled but `totpCode` was not provided |
| `TOTPInvalidError` | The provided TOTP code is incorrect or expired |

For nullifier-exhausted failures at sign time (max-uses or rate-limit reached),
see [stateful-constraints.md](stateful-constraints.md). For all other error
classes, see [error-handling.md](error-handling.md).
