# Verifying a PSBT (dry-run)

Check whether a PSBT would be signed without actually signing or consuming a nullifier:

```typescript
const verification = await client.verifyPSBT({
  psbtBase64,
  kmcJSON,
  network: 'signet',
});

console.log(verification.passed);          // true / false
console.log(verification.satisfiedClause); // Which policy branch would match
console.log(verification.nullifierStatus); // Per-input availability
```
