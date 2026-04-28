# Creating Keys

`createKey()` registers a new policy-gated key with the Sigbash server and
returns the identifiers you'll need for signing (`keyId`, `bip328Xpub`,
`p2trAddress`). There are three ways to construct the policy passed to it:
a built-in **template**, the structured **`conditionConfigToPoetPolicy`**
helper, or a **raw POET policy** object. All three produce the same kind of
compiled policy — pick whichever matches how much control you need.

Prerequisites: `loadWasm()` has been called once, and you have an authenticated
`SigbashClient` instance. See [getting-started.md](getting-started.md) for
setup, and [policy-overview.md](policy-overview.md) for an overview of what
policies can express.

## Using a template

```typescript
import { buildPolicyFromTemplate, POLICY_TEMPLATES } from '@sigbash/sdk';

// List available templates:
console.log(Object.keys(POLICY_TEMPLATES));

const policy = buildPolicyFromTemplate('weekly-spending-limit', {
  weeklyLimitSats: 500_000,
});

await client.createKey({ policy, network: 'signet', require2FA: false });
```

**Built-in templates:**

| Template ID | Description | Key params |
|---|---|---|
| `weekly-spending-limit` | Max spend per rolling 7-day window | `weeklyLimitSats` |
| `treasury-vault` | IF no admin key THEN restrict amount + destinations | `adminKeyIdentifier`, `hotWalletLimitSats?`, `allowedAddresses?`, `network?` |
| `bitcoin-inheritance` | Funds unlock after a timestamp | `unlockTimestamp?` |
| `blacklist` | Block specific destination addresses | `blockedAddresses`, `network?` (default `"mainnet"`) |
| `business-hours-only` | Transactions only during Mon–Fri business hours (UTC) | `startHourUTC?` (default `"14:00"`), `endHourUTC?` (default `"22:00"`) |
| `no-new-outputs-consolidation` | All outputs must go to input addresses (UTXO consolidation) | *(none)* |

See [policy-reference.md](policy-reference.md) for the underlying condition
types each template compiles to.

---

## Using `conditionConfigToPoetPolicy`

```typescript
import { conditionConfigToPoetPolicy } from '@sigbash/sdk';

// AND of two conditions
const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 100_000 },
    { type: 'COUNT_BASED_CONSTRAINT', max_uses: 3, reset_interval: 'daily', reset_type: 'rolling' },
  ],
});
```

Field definitions for each condition type are in
[policy-reference.md](policy-reference.md).

---

## Using a raw POET policy

```typescript
const policy: POETPolicy = {
  version: '1.1',
  policy: {
    type: 'operator',
    operator: 'AND',
    children: [
      { type: 'condition', conditionType: 'TX_VERSION', conditionParams: { operator: 'EQ', value: 2 } },
      { type: 'condition', conditionType: 'TX_OUTPUT_COUNT', conditionParams: { operator: 'EQ', value: 2 } },
    ],
  },
};
await client.createKey({ policy, network: 'signet', require2FA: false });
```

The full operator and condition vocabulary is documented in
[policy-reference.md](policy-reference.md).

> **Next step:** whichever construction path you used, `createKey()` returns
> a `keyId` and `bip328Xpub`. Use the `keyId` (plus `kmcJSON` from
> `getKey(keyId, { verbose: true })`) for signing — see [signing.md](signing.md).
> Use the `bip328Xpub` for funding the key, covered next.

---

## Funding the key

`createKey()` returns a `bip328Xpub` you can import into a watch-only wallet to
derive receive addresses and fund the key. The canonical single-sig descriptor
is taproot keypath:

```
tr(<bip328Xpub>/0/*)
```

For multisig setups that combine the Sigbash key with other co-signer keys,
use a BIP-386 tapscript multisig descriptor with `sortedmulti_a`:

```
tr(<internal_key>,sortedmulti_a(<k>,<bip328Xpub>/0/*,<cosigner1Xpub>/0/*,<cosigner2Xpub>/0/*))
```

Use `sortedmulti_a` for tapscript (BIP-386); `sortedmulti` is the SegWit-era
equivalent and is not appropriate for taproot outputs.

---

## Next steps

- [signing.md](signing.md) — sign a PSBT with the key you just created.
- [policy-reference.md](policy-reference.md) — full condition and operator reference.
- [stateful-constraints.md](stateful-constraints.md) — rate limits and time windows.

---

## Multiple keys per user

Each policy above produces a single key. To register more than one key under
the same credentials — e.g. a hot/cold split or per-role keys — pass an
explicit `keyIndex` (an integer starting at 0; one per key).

In the snippet below, `hotPolicy`, `coldPolicy`, and `treasuryPolicy` stand in
for compiled POET policies — typically the output of
`conditionConfigToPoetPolicy(...)`, `buildPolicyFromTemplate(...)`, or a raw
`POETPolicy` object (see the sections above).

```typescript
// First key — keyIndex defaults to 0
const hot = await client.createKey({ policy: hotPolicy, network: 'signet', require2FA: false });

// Second key — bump the index
const cold = await client.createKey({ policy: coldPolicy, network: 'signet', require2FA: false, keyIndex: 1 });

// Third key — and so on
const treasury = await client.createKey({ policy: treasuryPolicy, network: 'signet', require2FA: false, keyIndex: 2 });
```

If you call `createKey()` with a `keyIndex` that is already taken, the SDK
throws `KeyIndexExistsError`. The error carries the next free index on
`err.nextAvailableIndex`, so you can retry automatically:

```typescript
import { KeyIndexExistsError, SigbashClient, type CreateKeyOptions, type KeySummary } from '@sigbash/sdk';

async function createWithAutoIndex(
  client: SigbashClient,
  options: CreateKeyOptions,
): Promise<KeySummary> {
  let keyIndex = options.keyIndex ?? 0;
  while (true) {
    try {
      return await client.createKey({ ...options, keyIndex });
    } catch (err) {
      if (err instanceof KeyIndexExistsError) {
        keyIndex = err.nextAvailableIndex;
        continue;
      }
      throw err;
    }
  }
}
```

The HTTP server returns the same information in the JSON response — see
[server.md](server.md) for the curl-driven equivalent.

### Listing your keys

`listKeys()` returns lightweight metadata for every key registered by the
caller.

Each item includes:

- `keyId` (the `keyIndex` value as a string)
- `network`
- `policyRoot`
- `require2FA`
- `createdAt`
- `bip328Xpub`
- `poetJSON` — the parsed policy

The `kmcJSON` field required for signing is **only** returned by
`getKey(keyId, { verbose: true })` (or `GET /keys/:keyId?verbose=true`).

```typescript
const keys = await client.listKeys();

for (const k of keys) {
  console.log(k.keyId, k.network, k.policyRoot, k.bip328Xpub);
}
```

```bash
# HTTP server equivalent
curl -s http://localhost:3000/keys
```
