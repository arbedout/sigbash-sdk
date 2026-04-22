# Authentication

`SigbashClient` requires a **three-credential triplet**:

| Credential | Role | Sent to server? |
|---|---|---|
| `apiKey` | Organisation-level key | Yes |
| `userKey` | User identifier within your organisation | Yes |
| `userSecretKey` | User-only secret for KEK derivation | **Never** |

The SDK derives `authHash = DSHA256(apiKey ∥ userKey)` for server authentication
and `KEK = HKDF(apiKey ∥ userKey ∥ userSecretKey)` for encrypting key material
locally.  The `userSecretKey` never leaves the client.

---

## Generating credentials

All three credentials are random hex strings — no dashboard required. Generate
them locally with `generateCredentials()`, which writes a `.env` file and
returns the values. Calling it again on the same file returns the existing
credentials unchanged.

```typescript
import { generateCredentials } from '@sigbash/sdk';

const creds = await generateCredentials();
// → writes .env with SIGBASH_API_KEY, SIGBASH_USER_KEY, SIGBASH_SECRET_KEY
// → subsequent calls return the same values (existed: true)

if (creds.existed) {
  console.log('Using existing credentials from', creds.envPath);
} else {
  console.log('New credentials written to', creds.envPath);
}
```

The generated `.env` looks like:

```
SIGBASH_API_KEY=<64-char hex>
SIGBASH_USER_KEY=<64-char hex>
SIGBASH_SECRET_KEY=<64-char hex>
SIGBASH_SERVER_URL=https://www.sigbash.com
```

Options:

```typescript
// Custom path
await generateCredentials({ envPath: '/path/to/.env' });

// Regenerate and overwrite
await generateCredentials({ force: true });
```

> `generateCredentials()` is **Node.js only** — it writes to the filesystem.
> In browser environments, supply credentials from your own secure storage.

---

## Finding your org identifier

Sigbash identifies organisations by `apikeyHash = DSHA256(apiKey ∥ apiKey)`.
Use `getAuthHash()` to compute it — you'll need it when contacting Sigbash to
upgrade from signet to mainnet or make other org-level changes.

```typescript
import { getAuthHash } from '@sigbash/sdk';

const { apikeyHash, authHash } = await getAuthHash(apiKey, userKey);

console.log('Org identifier (share with Sigbash):', apikeyHash);
// Email sales@sigbash.com with this value to request mainnet access.
```

Neither hash exposes `userSecretKey` or any derived key material.

---

## Security properties

| What admin holds | What admin cannot compute |
|---|---|
| `apiKey`, `userKey` | `userSecretKey` |
| `authHash`, `apikeyHash` | Any KEK or KMC decryption |

The first user to call `createKey()` in a new org is automatically promoted to
admin. Additional users are registered with `client.registerUser(userKey)` from
an admin client.
