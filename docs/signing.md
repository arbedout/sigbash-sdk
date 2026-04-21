# Signing a PSBT

```typescript
const result = await client.signPSBT({
  keyId,
  psbtBase64,        // Base64-encoded PSBT string
  kmcJSON,           // From getKey().kmcJSON
  network: 'signet',
  inputIndex: 0,     // Optional — which input to sign (default: 0)
  progressCallback: (step, msg) => console.log(step, msg),
});

if (result.success) {
  console.log('txHex:',          result.txHex);           // Ready to broadcast
  console.log('signedPSBT:',     result.signedPSBT);      // For multi-party workflows
  console.log('satisfiedClause', result.satisfiedClause);  // Which policy branch matched
}
```

---

## With TOTP 2FA

If the key was created with `require2FA: true`, you must register and confirm
a TOTP secret before the first signing attempt.

### Step 1: Register TOTP (once per key)

```typescript
// The SDK generates the secret and registers it with the server.
// You get back an otpauth:// URI to display as a QR code.
const { uri, secret } = await client.registerTOTP(keyId);

// Display `uri` as a QR code for the user to scan in their authenticator app.
// Optionally store `secret` as a backup recovery code.
```

### Step 2: Confirm TOTP (once per key)

```typescript
// The user enters the first 6-digit code from their authenticator app.
await client.confirmTOTP(keyId, '123456');
// TOTP is now active — signing requires a code from this point on.
```

### Step 3: Sign with TOTP code

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
| `TOTPSetupIncompleteError` | `registerTOTP()` or `confirmTOTP()` was not called before signing |
| `TOTPRequiredError` | Key has 2FA enabled but `totpCode` was not provided |
| `TOTPInvalidError` | The provided TOTP code is incorrect or expired |
