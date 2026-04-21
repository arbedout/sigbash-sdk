# Authentication

`SigbashClient` requires a **three-credential triplet**:

| Credential | Role | Sent to server? |
|---|---|---|
| `apiKey` | Organisation-level key from the Sigbash dashboard | Yes |
| `userKey` | User identifier within your organisation | Yes |
| `userSecretKey` | User-only secret for KEK derivation | **Never** |

The SDK derives `authHash = DSHA256(apiKey ∥ userKey)` for server authentication
and `KEK = HKDF(apiKey ∥ userKey ∥ userSecretKey)` for encrypting key material
locally.  The `userSecretKey` never leaves the client.
