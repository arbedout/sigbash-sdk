# Authentication

Sigbash has no signup flow or dashboard. Authentication is fully client-side:
the SDK generates three random credentials locally and uses one-way hashes to
identify your org and user to the server.

`SigbashClient` requires a **three-credential triplet**:

| Credential | Role | Sent to server? |
|---|---|---|
| `apiKey` | Organisation-level key | Yes |
| `userKey` | User identifier within your organisation | Yes |
| `userSecretKey` | User-only secret for KEK derivation | **Never** |

From these, the SDK derives two values: `authHash = DSHA256(apiKey ∥ userKey)`,
sent with every request to identify the user; and
`KEK = HKDF(apiKey ∥ userKey ∥ userSecretKey)`, used only on the client to
encrypt key material. `userSecretKey` never leaves the client. Key material is
encrypted with AES-256-GCM using the KEK before being stored server-side.

---

## Generating credentials

All three credentials are random 64-char hex strings, generated locally.
Generate them with `generateCredentials()`, which writes a `.env` file and
returns the values. Calling it again with the same `envPath` returns the
existing credentials unchanged.

> `generateCredentials()` is **Node.js only** — it writes to the filesystem.
> In browser environments, supply credentials from your own secure storage.

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

---

## Finding your org identifier

An **org** (organisation) is the top-level Sigbash tenant — every credential
triplet belongs to exactly one org, identified by `apiKey`. Sigbash identifies
organisations by `apikeyHash = DSHA256(apiKey ∥ apiKey)`. Use `getAuthHash()`
to compute it — you'll need it when contacting Sigbash to upgrade from signet
to mainnet or make other org-level changes.

```typescript
import { getAuthHash } from '@sigbash/sdk';

const { apikeyHash, authHash } = await getAuthHash(apiKey, userKey);

console.log('Org identifier (share with Sigbash):', apikeyHash);
// Email sales@sigbash.com with this value to request mainnet access.
```

Neither hash exposes `userSecretKey` or any derived key material.

---

## Multiple keys per user

A single triplet can register multiple keys — see
[creating-keys.md § Multiple keys per user](./creating-keys.md#multiple-keys-per-user).

---

## Security properties

| What admin holds | What admin cannot compute |
|---|---|
| `apiKey`, `userKey` | `userSecretKey` |
| `authHash`, `apikeyHash` | Any KEK or KMC decryption |

Org admin promotion and user management are covered in [admin.md](./admin.md).
