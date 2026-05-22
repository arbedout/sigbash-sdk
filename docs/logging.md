# Audit Logging

The Sigbash SDK records every successful signing operation as an encrypted
audit log entry on the server. Each entry preserves tamper evidence via an
HMAC chain and can optionally be decrypted by the organisation admin for
compliance workflows.

---

## How it works

After every successful `signPSBT()` call, the SDK automatically stores a
signed audit entry containing the **txid**, **satisfied clause**, and
**policy root hash** — the key metadata a compliance team needs — inside an
AES-256-GCM ciphertext. The server sees only the opaque blob; it never has
access to the plaintext audit fields.

Each entry is chained to the previous one with an HMAC-SHA256 computed by the
server using a key never exposed to the client. The client stores the
returned `chain_mac` and `server_seq` to detect server-side deletion or
reordering later.

---

## Configuration

### `privateLogs` option

Pass `privateLogs` to the `SigbashClient` constructor to choose whether the
admin can decrypt audit entries:

```typescript
import { SigbashClient } from '@sigbash/sdk';

// Admin CANNOT decrypt (default). Entries are encrypted with the end-user's
// DEK derived from MasterSeed — only the user can read them.
const client = new SigbashClient({
  serverUrl: 'https://www.sigbash.com',
  apiKey,
  userKey,
  userSecretKey,
});

// Admin CAN decrypt. Entries are encrypted with a key derivable from
// (apiKey + userKey) alone, so any admin who holds the org credentials
// can read every entry across all users.
const client = new SigbashClient({
  serverUrl: 'https://www.sigbash.com',
  apiKey,
  userKey,
  userSecretKey,
  privateLogs: false,
});
```

> **Note:** `privateLogs` is **honoured only on the first admin connect** for
> your organisation. After the admin row is created the value is permanent —
> changing it would orphan every prior entry encrypted under the old key. If
> your org was already created with `privateLogs: true` (the default), you
> cannot switch later. Plan this setting before your first deployment.

### `hasAuditLogAccess` property

After connecting, the client reports whether the server has granted audit log
access to this admin connection:

```typescript
if (!client.hasAuditLogAccess) {
  console.log('Audit log access not granted — contact support');
}
```

This is an optimistic check. The server enforces access on every request
regardless; if the flag is wrong the endpoint will return `403`.

---

## Retrieving logs

### `getAuditLogs()`

```typescript
const logs = await client.getAuditLogs(options?);
```

Fetches encrypted audit log entries for the caller's organisation. The caller
must be an admin with `audit_log_access` enabled; otherwise the call throws.

#### Options

| Field | Type | Default | Description |
|---|---|---|---|
| `limit` | `number` | `100` | Max entries to return (1–1000) |
| `beforeTimestamp` | `number` | — | Unix seconds — only entries older than this timestamp |
| `credentialHash` | `string` | — | Filter to a specific user's credential hash within your org |

#### Return value

Returns an `AuditLogEntry[]` — an array of decrypted or opaque entries
depending on the org's `privateLogs` setting:

```typescript
interface AuditLogEntry {
  // Decrypted signing metadata (present when privateLogs is false)
  txid?: string;
  network: string;
  status: string;
  timestamp: number;
  type?: string;
  satisfiedClause?: string;   // e.g. "AND child 0: TX_VERSION EQ 2 → true"
  policyRootHex?: string;     // hex policy root of the key used
  amountSats?: number;
  recipient?: string;
  notes?: string;

  // Server envelope (always present)
  key_id?: number;
  created_at?: number;
  server_seq?: number;
  chain_mac?: string;         // 64-char hex — HMAC chain link

  [k: string]: unknown;       // forward compatibility
}
```

#### Behaviour by `privateLogs`

| `privateLogs` | What `getAuditLogs()` returns |
|---|---|
| `true` (default) | The server returns raw objects with `encrypted_data` (opaque ciphertext) plus envelope fields. The client returns them as-is — the admin cannot decrypt. |
| `false` | Each entry is decrypted client-side using the admin DEK. Returned objects merge the decrypted fields (`txid`, `status`, `network`, `timestamp`, `type`, `satisfiedClause`, `policyRootHex`, etc.) with the server envelope. The raw `encrypted_data` is replaced by its decrypted contents. |

#### Error handling

```typescript
import { SigbashSDKError } from '@sigbash/sdk';

try {
  const logs = await client.getAuditLogs({ limit: 10 });
  for (const entry of logs) {
    console.log(`[${entry.server_seq}] ${entry.status} — ${entry.txid ?? '(opaque)'}`);
  }
} catch (err) {
  if (err instanceof SigbashSDKError) {
    if (err.code === 'AUDIT_LOG_ACCESS_NOT_ENABLED') {
      // The admin does not have permission — contact Sigbash support
      // to enable audit log access for your organisation.
    }
    // Other error codes are possible (network, server error, etc.)
  }
}
```

#### Pagination

Fetch the latest entries with `limit`, then use `beforeTimestamp` to walk
backwards through history:

```typescript
async function fetchAllLogs(client, pageSize = 100) {
  const all = [];
  let before: number | undefined;
  while (true) {
    const page = await client.getAuditLogs({
      limit: pageSize,
      beforeTimestamp: before,
    });
    if (page.length === 0) break;
    all.push(...page);
    before = page[page.length - 1].created_at;
  }
  return all;
}
```

Entries are returned in descending `created_at` order (newest first).

---

## Auto-logging

Every call to `signPSBT()` that returns `{ success: true }` automatically
stores an audit entry before resolving. The entry includes:

- **`txid`** — SHA-256 of the signed transaction bytes
- **`satisfiedClause`** — string describing which policy rule authorised
  the signing (e.g. `"AND child 0: TX_VERSION EQ 2 → true"`)
- **`policyRootHex`** — the policy root hash for the key used
- **`network`**, **`status`**, **`timestamp`**, **`type`**

Auto-logging is **best-effort** — if the store fails the error is silently
swallowed so signing always succeeds from the caller's perspective.

---

## Client-side helpers

```typescript
import {
  deriveAdminAuditDek,
  encryptAuditEntry,
  decryptAuditEntry,
  verifyReceiptChain,
} from '@sigbash/sdk';
```

| Export | Purpose |
|---|---|
| `deriveAdminAuditDek(apiKey, userKey)` | Derive the 32-byte AES-256 key from org credentials. Used internally when `privateLogs: false`. |
| `encryptAuditEntry(entry, dek)` | Encrypt an `AuditLogEntry` into a JSON blob `{ nonce, ciphertext }`. |
| `decryptAuditEntry(blob, dek)` | Decrypt a blob back into an `AuditLogEntry`. Throws on GCM auth failure (tampered or wrong key). |
| `verifyReceiptChain(receipts)` | Client-side check that an array of `{ server_seq, chain_mac }` forms a monotonically increasing sequence with valid hex MACs. Does **not** verify the HMAC itself (the client doesn't have the server's audit key). |

---

## Receipts and tamper evidence

Every `store_encrypted_log` response includes a receipt with `id`,
`server_seq`, and `chain_mac`. Clients that save receipts locally can later
call `verifyReceiptChain()` to detect whether the server deleted or
reordered entries:

```typescript
const receipts = getStoredReceipts();    // your local storage
const ok = verifyReceiptChain(receipts); // false if gaps or wrong MAC format
```

A missing `server_seq` or a non-hex `chain_mac` indicates tampering.
