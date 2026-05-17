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

---

## Per-request Ed25519 proof-of-possession (PoP)

`authHash` alone is **not** sufficient to authenticate. Every authenticated REST
request and every authenticated Socket.IO event additionally carries an
Ed25519 signature derived from `userSecretKey`. An exfiltrated `authHash`
(from access logs, proxy logs, application logs, header captures, etc.) cannot
be replayed because the attacker also needs the matching private key, which
never leaves the client.

### Key derivation

```
popSeed   = HMAC-SHA256(userSecretKey, "sigbash/sdk-pop-ed25519/v1")[:32]
popKey    = Ed25519 keypair derived from popSeed
popPubkey = popKey.public_key                    (32 bytes, hex-encoded)
```

The keypair is derived deterministically every time the SDK initialises — no
persistent key storage is needed. The public key (`pop_pubkey`) is registered
server-side at user creation time (admin pre-registration includes it; the
first-user auto-register path supplies it in the Socket.IO handshake).

### Wire format

Every authenticated REST call carries:

```
X-Sigbash-Sig: t=<unix-ms>;n=<32-hex-nonce>;v=1;k=<8-hex-pubkey-prefix>;s=<128-hex-ed25519-sig>
```

Every authenticated Socket.IO event payload — and the Socket.IO handshake
`auth` payload — carries the same string in an `_sigbash_sig` field:

```json
{ "auth_hash": "…", "key_id": "0", "_sigbash_sig": "t=…;n=…;v=1;k=…;s=…" }
```

Field summary:

| Field | Length | Meaning |
|---|---|---|
| `t`   | epoch ms      | Server rejects outside ±300s skew. |
| `n`   | 32 hex chars  | 128-bit random nonce. Server rejects replay within 600s. |
| `v=1` | literal       | Protocol version. |
| `k`   | 8 hex chars   | First 8 hex of the registered `pop_pubkey` (supports future rotation). |
| `s`   | 128 hex chars | Ed25519 signature, 64 bytes, hex-encoded. |

### Signed transcript

The signature is over the following 7-line newline-joined bytes (no trailing
newline):

```
SIGBASH-POP-V1
<METHOD>
<path-with-canonical-query>
<sha256-hex of body bytes>
<t>
<n>
<auth_hash>
```

Where:

- **REST** — `METHOD` is the HTTP verb (`GET`, `POST`, `PATCH`, `DELETE`);
  path is the request path with query parameters sorted lexically by
  `(key, value)` and URL-encoded; body sha256 is over the raw request bytes
  (empty body → `sha256("")` = `e3b0c4…b855`).
- **Socket.IO event** — `METHOD` = `WS`, path = `<namespace>#<event_name>`,
  body sha256 is over the canonical-JSON encoding of the payload with the
  `_sigbash_sig` field stripped. Canonical-JSON is the same shape as
  Python's `json.dumps(obj, sort_keys=True, separators=(',', ':'))`.
- **Socket.IO handshake** — `METHOD` = `WS-CONNECT`, path = `<namespace>`,
  body sha256 is over canonical-JSON of the handshake `auth` object with
  `_sigbash_sig` stripped.

Including `auth_hash` in the transcript prevents cross-user substitution;
method + path prevents cross-endpoint replay; the body hash prevents payload
mutation.

### Worked example

Suppose:

- `auth_hash` = `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`
- `pop_pubkey` = `7f4a…3c1b` (first 8 hex: `7f4a3c1b` — used in the `k` field)
- request: `GET /api/v2/sdk/keys`, no body

Transcript bytes (newlines shown as `\n`):

```
SIGBASH-POP-V1\nGET\n/api/v2/sdk/keys\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1715900000000\n9a3f4d7b8e2c1f0a4d6e8b5c2f1a3d4e\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Server header:

```
X-Sigbash-Sig: t=1715900000000;n=9a3f4d7b8e2c1f0a4d6e8b5c2f1a3d4e;v=1;k=7f4a3c1b;s=<128 hex>
```

### Failure codes

| HTTP code | `code` | Cause |
|---|---|---|
| 401 | `AUTH_HASH_REQUIRED`       | `X-Auth-Hash` header missing. |
| 401 | `SIGNATURE_REQUIRED`       | `X-Sigbash-Sig` header / `_sigbash_sig` field missing. |
| 401 | `SIGNATURE_MALFORMED`      | Header parse error or field length wrong. |
| 401 | `SIGNATURE_VERSION_UNSUPPORTED` | `v` is not `1`. |
| 401 | `SIGNATURE_EXPIRED`        | `t` outside ±300s skew window. |
| 401 | `SIGNATURE_REPLAY`         | `(auth_hash, nonce)` seen within 600s. |
| 401 | `SIGNATURE_PUBKEY_UNKNOWN` | No `pop_pubkey` registered for this `auth_hash`. |
| 401 | `SIGNATURE_PUBKEY_MISMATCH`| `k` prefix does not match stored `pop_pubkey`. |
| 401 | `SIGNATURE_INVALID`        | Ed25519 verification failed (wrong key, tampered transcript). |

### What this closes — and what it does not

- **Closes:** bearer-token replay of an exfiltrated `authHash` against any
  authenticated endpoint, including admin operations (user mgmt, mainnet
  toggle, key recovery).
- **Does not close:** compromise of `userSecretKey` itself. That value is
  the root credential — anyone holding it can sign arbitrary requests and
  decrypt KMCs. Treat it as a secret of equivalent sensitivity to a long-
  lived API key. Never commit `.env` to source control; rotate by issuing
  a fresh credential triplet and migrating keys.
