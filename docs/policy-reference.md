# Policy Reference

## How policies work

A policy is a tree of **operator nodes** and **condition leaves**. Operator nodes
combine children with boolean logic (AND, OR, NOT, etc.). Condition leaves check
one property of the transaction being signed. The policy evaluates to `true` when
the root node is satisfied.

---

## Policy JSON format

All policies — whether passed via the TypeScript SDK or the HTTP server — must
be a versioned `POETPolicy` object with a `version` field and a `policy` tree:

```json
{
  "version": "1.1",
  "policy": {
    "type": "operator",
    "operator": "AND",
    "children": [
      {
        "type": "condition",
        "conditionType": "OUTPUT_VALUE",
        "conditionParams": { "selector": "ALL", "operator": "LTE", "value": 10000 }
      }
    ]
  }
}
```

**Node shapes:**

| Node type | Required fields |
|---|---|
| Operator | `type: "operator"`, `operator` (e.g. `"AND"`), `children: [...]` |
| Condition leaf | `type: "condition"`, `conditionType` (e.g. `"OUTPUT_VALUE"`), `conditionParams: {...}` |

A bare condition at the top level must be wrapped in an `AND` operator node —
the server does not auto-wrap. The TypeScript helper `conditionConfigToPoetPolicy()`
handles this automatically.

---

## TypeScript shorthand

Use `conditionConfigToPoetPolicy()` to build the versioned policy object from a
convenient shorthand rather than writing the tree by hand:

```typescript
import { conditionConfigToPoetPolicy } from '@sigbash/sdk';

// Single condition — auto-wrapped in AND
const policy = conditionConfigToPoetPolicy({
  type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 100_000,
});

// Multiple conditions with explicit logic
const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 100_000 },
    { type: 'TX_OUTPUT_COUNT', operator: 'LTE', value: 3 },
  ],
});
```

---

## Operators

Use these as the `operator` field on operator nodes (or the `logic` shorthand in `conditionConfigToPoetPolicy`):

| Operator | Shorthand | Description |
|---|---|---|
| `AND` | — | All children must be satisfied |
| `OR` | — | At least one child must be satisfied |
| `NOT` | — | Single child must NOT be satisfied |
| `THRESHOLD` | `THRESH` | At least *k* of *n* children satisfied (`operatorParams: { k }`) |
| `WEIGHTED_THRESHOLD` | `WTHRESH` | Weighted sum of satisfied children >= *k* (`operatorParams: { k }`) |
| `MAJORITY` | — | More than half of children satisfied |
| `EXACTLY` | `EXACT` | Exactly *k* children satisfied (`operatorParams: { k }`) |
| `AT_MOST` | `ATMOST` | At most *k* children satisfied (`operatorParams: { k }`) |
| `IMPLIES` | — | If first child satisfied, second child must also be satisfied |
| `IFF` | — | First child satisfied if and only if second child satisfied |
| `VETO` | — | First child is the *trigger*; if trigger is satisfied, the remaining children are **blocked**. Semantics: `NOT(trigger) AND body` |
| `NOR` | — | None of the children may be satisfied |
| `NAND` | — | Not all children may be satisfied simultaneously |
| `XOR` | — | Exactly one child satisfied |

Threshold example:

```typescript
const policy = conditionConfigToPoetPolicy({
  logic: 'THRESHOLD',
  threshold: 2,    // k = 2 of 3
  conditions: [
    { type: 'TX_VERSION', operator: 'EQ', value: 2 },
    { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 50_000 },
    { type: 'COUNT_BASED_CONSTRAINT', max_uses: 1, reset_interval: 'daily' },
  ],
});
```

---

## Selectors

Some conditions check per-input or per-output properties. These conditions accept an optional `selector` field that controls *which* inputs or outputs are checked:

| Selector | Meaning |
|---|---|
| `'ALL'` | Every input/output must satisfy the condition |
| `'ANY'` | At least one input/output must satisfy the condition |
| `{ type: 'INDEX', index: N }` | Only the Nth input/output (zero-based) |

**Default:** When a condition supports a selector but you omit it, the SDK defaults to `'ANY'`.

---

## Comparison operators

Used by value and count conditions (`OUTPUT_VALUE`, `TX_FEE_ABSOLUTE`, `TX_INPUT_COUNT`, etc.):

| Operator | Meaning |
|---|---|
| `'EQ'` | Equal to |
| `'NEQ'` | Not equal to |
| `'LT'` | Less than |
| `'LTE'` | Less than or equal to |
| `'GT'` | Greater than |
| `'GTE'` | Greater than or equal to |

---

## Runtime-resolved placeholders

Some condition parameters cannot be known at policy-registration time. They are
resolved in one of two phases:

### Resolved at key-registration time — `SIGBASH_XPUB`

The `descriptor_template` parameter accepts `SIGBASH_XPUB` as a placeholder
for the BIP-328 extended public key assigned to the key at registration time.
The server substitutes the real xpub and derives the address set once, when
the key is created — **not** at signing time.

Conditions that support descriptor mode (enabled by `use_descriptor: true`):

| Condition | What is derived |
|---|---|
| `INPUT_SOURCE_IS_IN_SETS` | Permitted input source addresses |
| `OUTPUT_DEST_IS_IN_SETS` | Permitted output destination addresses |
| `DERIVED_NO_NEW_OUTPUTS` | Allowed output address set (wallet self-consolidation) |
| `REQKEY` | Key identifier derived from wallet descriptor |

Common descriptor templates:

| Template | Script type |
|---|---|
| `tr(SIGBASH_XPUB/0/*)` | Single-sig P2TR |
| `wpkh(SIGBASH_XPUB/84h/1h/0h/0/*)` | Single-sig P2WPKH (BIP-84) |
| `wsh(multi(2,SIGBASH_XPUB/0/*,COSIGNER_XPUB/0/*))` | 2-of-2 multisig P2WSH |

The optional `derivation_range` parameter (default 1000, range 20–10000)
controls how many addresses are pre-derived for ZK set-membership proofs.

### Resolved at signing time — BIP-443 data placeholders

The `committed_data_hex` field of `OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT` and
the `witness_data_hex` field of `INPUT_COMMITTED_DATA_VERIFY` support special
tokens that are substituted from the PSBT at signing time:

| Token | Resolved to |
|---|---|
| `SIGBASH_INTERNAL_KEY` | The wallet's internal (x-only) public key |
| `SIGBASH_OUTPUT_KEY` | The MuSig2 aggregate output key |
| `SIGBASH_NUMS_KEY` | BIP-341 provably-unspendable NUMS point (keyless contract instances) |
| `SIGBASH_COVENANT_STATE` | Current covenant state fetched from chain |

**Index `-1` (self-reference):** Setting `output_index` or `input_index` to
`-1` means "the same index as the input currently being signed." This lets a
single policy clause apply to any input position.

**`'SELF'` for `script_tree_root`:** The literal string `'SELF'` in
`script_tree_root` means "use the same taptree as the current policy"
(BIP-443 taptree=-1 semantics). Required for self-replicating covenant UTXOs
where the spending script must propagate itself to the output.

---

## Condition types

All 27 condition types are available in the exported `CONDITION_TYPES` constant:

```typescript
import { CONDITION_TYPES } from '@sigbash/sdk';

// Inspect a condition's parameter schema:
console.log(CONDITION_TYPES.OUTPUT_VALUE);

// List all condition type names:
console.log(Object.keys(CONDITION_TYPES));
```

### Value & fee conditions

#### `OUTPUT_VALUE`

Numeric comparison on the satoshi value of one or more outputs.

| Param | Type | Required | Description |
|---|---|---|---|
| `operator` | `ComparisonOperator` | yes | `'LTE'`, `'GTE'`, `'EQ'`, `'LT'`, `'GT'`, `'NEQ'` |
| `value` | `number` | yes | Threshold in satoshis |
| `selector` | `Selector` | no (default `'ANY'`) | Which outputs to check |

```typescript
{ type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 100_000 }
```

#### `INPUT_VALUE`

Numeric comparison on the satoshi value of one or more inputs.

| Param | Type | Required | Description |
|---|---|---|---|
| `operator` | `ComparisonOperator` | yes | `'LTE'`, `'GTE'`, `'EQ'`, `'LT'`, `'GT'`, `'NEQ'` |
| `value` | `number` | yes | Threshold in satoshis |
| `selector` | `Selector` | no (default `'ANY'`) | Which inputs to check |

```typescript
{ type: 'INPUT_VALUE', selector: 'ALL', operator: 'GTE', value: 1_000 }
```

#### `TX_FEE_ABSOLUTE`

Checks the absolute transaction fee in satoshis (sum of inputs minus sum of outputs).

| Param | Type | Required | Description |
|---|---|---|---|
| `operator` | `ComparisonOperator` | yes | Comparison operator |
| `value` | `number` | yes | Fee threshold in satoshis |

```typescript
{ type: 'TX_FEE_ABSOLUTE', operator: 'LTE', value: 5_000 }
```

---

### Transaction structure conditions

#### `TX_VERSION`

Checks the Bitcoin transaction version field (typically 1 or 2).

| Param | Type | Required | Description |
|---|---|---|---|
| `operator` | `ComparisonOperator` | yes | Comparison operator |
| `value` | `number` | yes | Version number (e.g. `2`) |

```typescript
{ type: 'TX_VERSION', operator: 'EQ', value: 2 }
```

#### `TX_LOCKTIME`

Checks the transaction `nLockTime` field. Values < 500,000,000 are block heights; values >= 500,000,000 are UNIX timestamps.

| Param | Type | Required | Description |
|---|---|---|---|
| `operator` | `ComparisonOperator` | yes | Comparison operator |
| `value` | `number` | yes | Block height or UNIX timestamp |

```typescript
{ type: 'TX_LOCKTIME', operator: 'EQ', value: 500_000 }
```

#### `TX_INPUT_COUNT`

Checks the number of transaction inputs.

| Param | Type | Required | Description |
|---|---|---|---|
| `operator` | `ComparisonOperator` | yes | Comparison operator |
| `value` | `number` | yes | Expected input count |

```typescript
{ type: 'TX_INPUT_COUNT', operator: 'EQ', value: 1 }
```

#### `TX_OUTPUT_COUNT`

Checks the number of transaction outputs.

| Param | Type | Required | Description |
|---|---|---|---|
| `operator` | `ComparisonOperator` | yes | Comparison operator |
| `value` | `number` | yes | Expected output count |

```typescript
{ type: 'TX_OUTPUT_COUNT', operator: 'LTE', value: 3 }
```

#### `INPUT_SEQUENCE`

Checks the `nSequence` field of one or more inputs. Useful for RBF signalling (`0xFFFFFFFD`) and relative timelocks.

| Param | Type | Required | Description |
|---|---|---|---|
| `operator` | `ComparisonOperator` | yes | Comparison operator |
| `value` | `number` | yes | Sequence value (e.g. `0xFFFFFFFD` for RBF) |
| `selector` | `Selector` | no (default `'ANY'`) | Which inputs to check |

```typescript
{ type: 'INPUT_SEQUENCE', selector: 'ALL', operator: 'EQ', value: 0xFFFFFFFD }
```

---

### Script & sighash conditions

#### `INPUT_SCRIPT_TYPE`

Requires the spending script type of one or more inputs to match a specific type.

| Param | Type | Required | Valid values |
|---|---|---|---|
| `script_type` | `string` | yes | `'P2PKH'`, `'P2SH'`, `'P2WPKH'`, `'P2WSH'`, `'P2TR'`, `'OP_RETURN'`, `'UNKNOWN'` |
| `selector` | `Selector` | no (default `'ANY'`) | Which inputs to check |

```typescript
{ type: 'INPUT_SCRIPT_TYPE', selector: 'ALL', script_type: 'P2TR' }
```

#### `OUTPUT_SCRIPT_TYPE`

Requires the `scriptPubKey` type of one or more outputs to match a specific type.

| Param | Type | Required | Valid values |
|---|---|---|---|
| `script_type` | `string` | yes | `'P2PKH'`, `'P2SH'`, `'P2WPKH'`, `'P2WSH'`, `'P2TR'`, `'OP_RETURN'`, `'UNKNOWN'` |
| `selector` | `Selector` | no (default `'ANY'`) | Which outputs to check |

```typescript
{ type: 'OUTPUT_SCRIPT_TYPE', selector: 'ALL', script_type: 'P2TR' }
```

#### `INPUT_SIGHASH_TYPE`

Enforces a specific sighash type on one or more inputs.

| Param | Type | Required | Valid values |
|---|---|---|---|
| `sighash_type` | `string` | yes | `'SIGHASH_ALL'`, `'SIGHASH_NONE'`, `'SIGHASH_SINGLE'`, `'SIGHASH_ANYONECANPAY_ALL'`, `'SIGHASH_ANYONECANPAY_NONE'`, `'SIGHASH_ANYONECANPAY_SINGLE'` |
| `selector` | `Selector` | no (default `'ANY'`) | Which inputs to check |

```typescript
{ type: 'INPUT_SIGHASH_TYPE', selector: 'ALL', sighash_type: 'SIGHASH_ALL' }
```

---

### Address set conditions

#### `OUTPUT_DEST_IS_IN_SETS`

Checks that the destination address(es) of one or more outputs are in an approved set. Wrap in `NOT()` for a blocklist.

| Param | Type | Required | Description |
|---|---|---|---|
| `addresses` | `string[]` | yes | Array of permitted Bitcoin addresses |
| `network` | `string` | yes | `'mainnet'`, `'testnet'`, or `'signet'` |
| `selector` | `Selector` | no (default `'ANY'`) | Which outputs to check |
| `require_change_to_input_addresses` | `boolean` | no (default `false`) | When `true`, change outputs must send back to an input address |

```typescript
{ type: 'OUTPUT_DEST_IS_IN_SETS', selector: 'ALL',
  addresses: ['tb1qexample1...', 'tb1qexample2...'], network: 'signet' }
```

#### `INPUT_SOURCE_IS_IN_SETS`

Checks that the source address(es) of one or more inputs are in a permitted set.

| Param | Type | Required | Description |
|---|---|---|---|
| `addresses` | `string[]` | conditional | Array of permitted source addresses. Required unless `use_descriptor` is `true` |
| `network` | `string` | yes | `'mainnet'`, `'testnet'`, or `'signet'` |
| `selector` | `Selector` | no (default `'ANY'`) | Which inputs to check |
| `descriptor_template` | `string` | no | BIP-328 descriptor template with `SIGBASH_XPUB` placeholder |
| `use_descriptor` | `boolean` | no | When `true`, derive addresses from `descriptor_template` at key-request time |

```typescript
// Explicit address list
{ type: 'INPUT_SOURCE_IS_IN_SETS', selector: 'ANY',
  addresses: ['tb1qexample...'], network: 'signet' }

// Descriptor-based (addresses derived automatically)
{ type: 'INPUT_SOURCE_IS_IN_SETS',
  descriptor_template: 'wpkh(SIGBASH_XPUB/84h/1h/0h/0/*)',
  use_descriptor: true, network: 'signet' }
```

---

### Key requirement

#### `REQKEY`

Proves that a specific key is present in the tapscript spending path, using a zero-knowledge set-membership proof. The signer cannot determine which key was required.

| Param | Type | Required | Description |
|---|---|---|---|
| `key_identifier` | `string` | conditional | 64-char hex x-only public key (32 bytes). Required when `use_descriptor` is `false` |
| `key_type` | `string` | yes | `'TAP_LEAF_XONLY_PUBKEY'` or `'TAP_KEYPATH_OUTPUTKEY'` |
| `use_descriptor` | `boolean` | no (default `false`) | When `true`, derive the key from `descriptor_template` instead of using a fixed `key_identifier` |
| `descriptor_template` | `string` | conditional | BIP-328 descriptor with `SIGBASH_XPUB` placeholder. Required when `use_descriptor` is `true`. Resolved at key-registration time |

```typescript
// Fixed key (most common)
{ type: 'REQKEY',
  key_identifier: 'aabbccdd...64hexchars',
  key_type: 'TAP_LEAF_XONLY_PUBKEY' }

// Descriptor-derived key
{ type: 'REQKEY',
  key_type: 'TAP_LEAF_XONLY_PUBKEY',
  use_descriptor: true, descriptor_template: 'tr(SIGBASH_XPUB/0/*)' }
```

---

### Usage limit conditions

#### `COUNT_BASED_CONSTRAINT`

Rate-limits signing sessions using a server-side nullifier counter. When `max_uses` is reached in the current interval, further signing attempts fail until the interval resets.

| Param | Type | Required | Description |
|---|---|---|---|
| `max_uses` | `number` | yes | Maximum signing sessions per interval |
| `reset_interval` | `string` | yes | `'never'`, `'daily'`, `'weekly'`, or `'monthly'` |
| `reset_type` | `string` | no (default `'rolling'`) | `'rolling'` (relative to first use) or `'calendar'` (midnight UTC) |

```typescript
{ type: 'COUNT_BASED_CONSTRAINT', max_uses: 5, reset_interval: 'daily', reset_type: 'rolling' }
```

#### `TIME_BASED_CONSTRAINT`

Restricts signing to a wall-clock time window. Three modes are available:

- **`'after'`** — signing allowed only after a UNIX timestamp (unlock-after / inheritance)
- **`'before'`** — signing allowed only before a UNIX timestamp (expiry / time-limited keys)
- **`'within'`** — signing allowed only during specific hours on specific days of the week

**`'after'` and `'before'`**

| Param | Type | Required | Description |
|---|---|---|---|
| `constraint_type` | `string` | yes | `'after'` or `'before'` |
| `start_time` | `number` | conditional | UNIX timestamp (seconds). Required when `constraint_type` is `'after'` |
| `end_time` | `number` | conditional | UNIX timestamp (seconds). Required when `constraint_type` is `'before'` |

```typescript
// Signing allowed only after Jan 1 2030
{ type: 'TIME_BASED_CONSTRAINT', constraint_type: 'after', start_time: 1893456000 }

// Signing expires after Dec 31 2025
{ type: 'TIME_BASED_CONSTRAINT', constraint_type: 'before', end_time: 1767225600 }
```

**`'within'` — recurring time window with day-of-week filter**

Restricts signing to a daily time range on selected days of the week. `active_days`
accepts any subset of days — use it for business hours, Fridays only, weekends, or
any other recurring schedule.

| Param | Type | Required | Description |
|---|---|---|---|
| `constraint_type` | `'within'` | yes | |
| `active_days` | `number[]` | yes | Days of week: 1 = Mon, 2 = Tue, …, 6 = Sat, 7 = Sun |
| `start_hour` | `string` | yes | Start of daily window, `"HH:MM"` UTC |
| `end_hour` | `string` | yes | End of daily window, `"HH:MM"` UTC |
| `start_time` | `number` | yes | UNIX timestamp — earliest date the rule is active |
| `end_time` | `number` | yes | UNIX timestamp — latest date the rule is active |
| `start_date_within` | `string` | yes | ISO date `"YYYY-MM-DD"` (human-readable alias for `start_time`) |
| `end_date_within` | `string` | yes | ISO date `"YYYY-MM-DD"` (human-readable alias for `end_time`) |

```typescript
// Weekdays only, 9 AM–5 PM EST (14:00–22:00 UTC)
{
  type: 'TIME_BASED_CONSTRAINT',
  constraint_type: 'within',
  active_days: [1, 2, 3, 4, 5],   // Mon–Fri
  start_hour: '14:00',
  end_hour: '22:00',
  start_time: 1713571200,
  end_time: 7022323200,
  start_date_within: '2025-04-20',
  end_date_within: '2225-04-20',
}

// Fridays only, any hour
{
  type: 'TIME_BASED_CONSTRAINT',
  constraint_type: 'within',
  active_days: [5],                // Friday only
  start_hour: '00:00',
  end_hour: '23:59',
  start_time: 1713571200,
  end_time: 7022323200,
  start_date_within: '2025-04-20',
  end_date_within: '2225-04-20',
}

// Weekends only
{
  type: 'TIME_BASED_CONSTRAINT',
  constraint_type: 'within',
  active_days: [6, 7],             // Sat + Sun
  start_hour: '00:00',
  end_hour: '23:59',
  start_time: 1713571200,
  end_time: 7022323200,
  start_date_within: '2025-04-20',
  end_date_within: '2225-04-20',
}
```

> **Tip:** The `business-hours-only` template generates `within` boilerplate for
> weekday business hours — see [Creating Keys](./creating-keys.md).

---

### Output checks

#### `OUTPUT_OP_RETURN`

Checks that an OP_RETURN output is present in the transaction.

| Param | Type | Required | Description |
|---|---|---|---|
| `selector` | `Selector` | no (default `'ANY'`) | Which outputs to check |

```typescript
{ type: 'OUTPUT_OP_RETURN', selector: 'ANY' }
```

---

### Derived (boolean) conditions

These conditions derive a boolean property from the overall transaction structure. Set `expected_value` to `true` to require the property, or `false` to forbid it. The SDK automatically converts the boolean to the internal numeric form.

#### `DERIVED_IS_CONSOLIDATION`

True when the transaction has more inputs than outputs (UTXO consolidation pattern).

```typescript
{ type: 'DERIVED_IS_CONSOLIDATION', expected_value: true }
```

#### `DERIVED_IS_COINJOIN_LIKE`

True when the transaction resembles a CoinJoin: multiple inputs from different addresses and multiple equal-value outputs.

```typescript
{ type: 'DERIVED_IS_COINJOIN_LIKE', expected_value: false }
```

#### `DERIVED_IS_PAYJOIN_LIKE`

True when the transaction resembles a PayJoin: the recipient contributes at least one input.

```typescript
{ type: 'DERIVED_IS_PAYJOIN_LIKE', expected_value: false }
```

#### `DERIVED_RBF_ENABLED`

True when at least one input signals Replace-By-Fee (`nSequence < 0xFFFFFFFE`).

```typescript
{ type: 'DERIVED_RBF_ENABLED', expected_value: true }
```

#### `DERIVED_NO_NEW_OUTPUTS`

True when every output address was already seen as an input address (self-consolidation mode),
or — when `use_descriptor` is `true` — when every output address falls within the wallet's
derived address set.

| Param | Type | Required | Description |
|---|---|---|---|
| `expected_value` | `boolean` | yes | `true` to require no new outputs, `false` to require at least one new output |
| `use_descriptor` | `boolean` | no (default `false`) | When `true`, validate against wallet descriptor instead of input addresses |
| `descriptor_template` | `string` | conditional | BIP-328 descriptor with `SIGBASH_XPUB` placeholder. Required when `use_descriptor` is `true`. Resolved at key-registration time |
| `derivation_range` | `number` | no (default `1000`) | Number of addresses to pre-derive (gap limit, 20–10000) |

```typescript
// Self-consolidation mode: outputs must match input addresses
{ type: 'DERIVED_NO_NEW_OUTPUTS', expected_value: true }

// Descriptor mode: outputs must be within the wallet's own address set
{ type: 'DERIVED_NO_NEW_OUTPUTS', expected_value: true,
  use_descriptor: true, descriptor_template: 'tr(SIGBASH_XPUB/0/*)' }
```

#### `DERIVED_SIGHASH_TYPE`

Checks the derived/effective sighash type for the transaction.

| Param | Type | Required | Valid values |
|---|---|---|---|
| `sighash_type` | `string` | yes | `'SIGHASH_ALL'`, `'SIGHASH_NONE'`, `'SIGHASH_SINGLE'`, `'SIGHASH_ANYONECANPAY_ALL'`, `'SIGHASH_ANYONECANPAY_NONE'`, `'SIGHASH_ANYONECANPAY_SINGLE'` |

```typescript
{ type: 'DERIVED_SIGHASH_TYPE', sighash_type: 'SIGHASH_ALL' }
```

---

### Template hash

#### `TX_TEMPLATE_HASH_MATCHES`

Checks that the transaction matches a pre-committed template hash covering version, locktime, input sequences, and outputs. Any deviation fails.

| Param | Type | Required | Description |
|---|---|---|---|
| `template_hash` | `string` | yes | Hex-encoded 32-byte template hash |
| `input_index` | `number` | no (default `0`) | Zero-based input index this template applies to |

```typescript
{ type: 'TX_TEMPLATE_HASH_MATCHES', template_hash: 'aabbccdd...64hexchars', input_index: 0 }
```

---

### BIP-443 covenant conditions

These conditions enforce covenant semantics via the oblivious signer — not Bitcoin
consensus. They are checked against the PSBT at signing time. For the full set of
runtime-substituted placeholders available in data fields, see [Runtime-resolved
placeholders](#runtime-resolved-placeholders).

#### `OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT`

Validates that an output's `scriptPubKey` matches a BIP-443 covenant commitment.
Use this to enforce state-carrying UTXOs (vaults, counters, state machines).

| Param | Type | Required | Description |
|---|---|---|---|
| `output_index` | `number` | yes | Zero-based output index. Use `-1` for self-reference (maps to current input index) |
| `committed_data_hex` | `string` | yes | Hex data to commit (max 1 KB). Accepts placeholders: `SIGBASH_INTERNAL_KEY`, `SIGBASH_OUTPUT_KEY`, `SIGBASH_NUMS_KEY`, `SIGBASH_COVENANT_STATE` |
| `script_tree_root` | `string` | yes | 32-byte hex taptree root. Use `'SELF'` for taptree self-reference (same script tree as current policy) |
| `validation_mode` | `string` | yes | `'bip443_covenant'` (full), `'simple_data_tweak'` (taptweak + data), `'taptweak_only'` (basic taproot tweak) |
| `amount_mode` | `string` | no (default `'ignore'`) | CCV amount semantics: `'ignore'` (CCV mode 1, default), `'preserve'` (CCV mode 0, accumulate input to output minimum), `'deduct'` (CCV mode 2, subtract output from input residual) |

```typescript
// Enforce a self-replicating vault output (same taptree, same key, state carried forward)
{
  type: 'OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT',
  output_index: -1,             // same index as the input being signed
  committed_data_hex: 'SIGBASH_OUTPUT_KEY',  // substituted at signing time
  script_tree_root: 'SELF',     // taptree self-reference
  validation_mode: 'bip443_covenant',
  amount_mode: 'preserve',
}
```

#### `INPUT_COMMITTED_DATA_VERIFY`

Verifies that an input's witness data matches expected BIP-443 committed data. Use this
to read and validate the previous covenant state before authorising a state transition.

| Param | Type | Required | Description |
|---|---|---|---|
| `input_index` | `number` | yes | Zero-based input index. Use `-1` for self-reference (current input being signed) |
| `witness_data_hex` | `string` | yes | Expected witness data hex (max 1 KB). Accepts placeholders: `SIGBASH_INTERNAL_KEY`, `SIGBASH_OUTPUT_KEY`, `SIGBASH_NUMS_KEY`, `SIGBASH_COVENANT_STATE` |
| `script_tree_root` | `string` | yes | 32-byte hex taptree root. Use `'SELF'` for taptree self-reference |
| `expected_data_length` | `number` | no | Expected byte length of the data (optional extra validation) |
| `validation_pattern` | `string` | no | Hex pattern for partial matching; `*` is a wildcard (e.g. `'deadbeef****'`) |

```typescript
// Verify the previous state embedded in the input witness
{
  type: 'INPUT_COMMITTED_DATA_VERIFY',
  input_index: -1,             // self-reference: current input being signed
  witness_data_hex: 'SIGBASH_COVENANT_STATE',  // substituted at signing time
  script_tree_root: 'SELF',
}

// Verify with a partial pattern (first 4 bytes must match, rest ignored)
{
  type: 'INPUT_COMMITTED_DATA_VERIFY',
  input_index: 0,
  witness_data_hex: 'deadbeef',
  script_tree_root: 'abc123...64hexchars',
  validation_pattern: 'deadbeef****',
}
```

---

## Enums reference

### Script types

Available as the `SCRIPT_TYPES` export:

`P2PKH` | `P2SH` | `P2WPKH` | `P2WSH` | `P2TR` | `OP_RETURN` | `UNKNOWN`

### Sighash types

Available as the `SIGHASH_TYPES` export:

`SIGHASH_ALL` | `SIGHASH_NONE` | `SIGHASH_SINGLE` | `SIGHASH_ANYONECANPAY_ALL` | `SIGHASH_ANYONECANPAY_NONE` | `SIGHASH_ANYONECANPAY_SINGLE`

---

## Complete examples

### Allowlist: only send to approved addresses, max 3 per day

```typescript
const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'OUTPUT_DEST_IS_IN_SETS', selector: 'ALL',
      addresses: ['tb1qtreasury...', 'tb1qops...'], network: 'signet' },
    { type: 'COUNT_BASED_CONSTRAINT', max_uses: 3, reset_interval: 'daily' },
  ],
});
```

### Spending cap with fee limit

```typescript
const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 50_000 },
    { type: 'TX_FEE_ABSOLUTE', operator: 'LTE', value: 2_000 },
  ],
});
```

### Admin override: unrestricted if admin key present, otherwise capped

```typescript
const policy = conditionConfigToPoetPolicy({
  logic: 'IMPLIES',
  conditions: [
    // If admin key is NOT present...
    { logic: 'NOT', child: { type: 'REQKEY',
        key_identifier: 'aabb...64hex', key_type: 'TAP_LEAF_XONLY_PUBKEY' } },
    // ...then enforce spending cap
    { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 10_000 },
  ],
});
```

### Consolidation-only: no new output addresses

```typescript
const policy = conditionConfigToPoetPolicy({
  type: 'DERIVED_NO_NEW_OUTPUTS', expected_value: true,
});
```

### Business hours only with daily cap

```typescript
const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    {
      type: 'TIME_BASED_CONSTRAINT',
      constraint_type: 'within',
      active_days: [1, 2, 3, 4, 5],   // Mon–Fri
      start_hour: '09:00',
      end_hour: '17:00',
      start_time: 1713571200,
      end_time: 7022323200,
      start_date_within: '2025-04-20',
      end_date_within: '2225-04-20',
    },
    { type: 'COUNT_BASED_CONSTRAINT', max_uses: 10, reset_interval: 'daily', reset_type: 'calendar' },
  ],
});
```

### Inheritance unlock: admin key OR time-lock

```typescript
const policy = conditionConfigToPoetPolicy({
  logic: 'OR',
  conditions: [
    // Admin can always sign
    { type: 'REQKEY', key_identifier: 'aabb...64hex', key_type: 'TAP_LEAF_XONLY_PUBKEY' },
    // Anyone can sign after 2030-01-01 (Unix: 1893456000)
    { type: 'TIME_BASED_CONSTRAINT', constraint_type: 'after', start_time: 1893456000 },
  ],
});
```

### Wallet self-consolidation using descriptor

Outputs must go to wallet-owned addresses only, derived from the key's BIP-328 xpub
at registration time — no hardcoded address list required:

```typescript
const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    {
      type: 'DERIVED_NO_NEW_OUTPUTS',
      expected_value: true,
      use_descriptor: true,
      descriptor_template: 'tr(SIGBASH_XPUB/0/*)',  // SIGBASH_XPUB filled in at registration
    },
    { type: 'TX_FEE_ABSOLUTE', operator: 'LTE', value: 5_000 },
  ],
});
```

### Tiered spending: small amounts always OK, large amounts require admin key

```typescript
const policy = conditionConfigToPoetPolicy({
  logic: 'OR',
  conditions: [
    // Tier 1: any output ≤ 50k sats, max 5 per day
    {
      logic: 'AND',
      conditions: [
        { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 50_000 },
        { type: 'COUNT_BASED_CONSTRAINT', max_uses: 5, reset_interval: 'daily' },
      ],
    },
    // Tier 2: admin key overrides all limits
    { type: 'REQKEY', key_identifier: 'aabb...64hex', key_type: 'TAP_LEAF_XONLY_PUBKEY' },
  ],
});
```

### Input allowlist: only spend from wallet-owned UTXOs (descriptor mode)

```typescript
const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    {
      type: 'INPUT_SOURCE_IS_IN_SETS',
      selector: 'ALL',
      use_descriptor: true,
      descriptor_template: 'wpkh(SIGBASH_XPUB/84h/1h/0h/0/*)',
      network: 'signet',
    },
    { type: 'TX_FEE_ABSOLUTE', operator: 'LTE', value: 10_000 },
  ],
});
```

### Weekly spending limit

Reset every Monday at midnight UTC, max 10 signing sessions, each output capped at 50k sats:

```typescript
const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    { type: 'COUNT_BASED_CONSTRAINT', max_uses: 10, reset_interval: 'weekly', reset_type: 'calendar' },
    { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 50_000 },
    { type: 'TX_FEE_ABSOLUTE', operator: 'LTE', value: 5_000 },
  ],
});
```

Use `reset_type: 'rolling'` instead to count 7 days from the first use rather than resetting on a fixed calendar day.

---

### Blacklist: block known-bad output addresses

Wrap `OUTPUT_DEST_IS_IN_SETS` in `NOT` to turn an allowlist into a blocklist. Any transaction
sending to a blacklisted address will be rejected regardless of other conditions:

```typescript
const BLACKLISTED_ADDRESSES = [
  'tb1qsuspect1...',
  'tb1qsuspect2...',
  'tb1qmixer...',
];

const policy = conditionConfigToPoetPolicy({
  logic: 'AND',
  conditions: [
    // Block outputs to any blacklisted address
    {
      logic: 'NOT',
      child: {
        type: 'OUTPUT_DEST_IS_IN_SETS',
        selector: 'ANY',
        addresses: BLACKLISTED_ADDRESSES,
        network: 'signet',
      },
    },
    // Optional: also block inputs from tainted sources
    {
      logic: 'NOT',
      child: {
        type: 'INPUT_SOURCE_IS_IN_SETS',
        selector: 'ANY',
        addresses: BLACKLISTED_ADDRESSES,
        network: 'signet',
      },
    },
  ],
});
```

---

### Inheritance: owner always, heir after time-lock

The owner key can sign at any time. After a specified date (e.g. 2 years from now), a
designated heir key can also sign — but only within a monthly rate limit and per-transaction
spending cap, preventing a single large sweep:

```typescript
const OWNER_KEY  = 'aabbccdd...64hex';  // owner x-only pubkey
const HEIR_KEY   = '11223344...64hex';  // heir x-only pubkey
const UNLOCK_AT  = 1956528000;          // Unix ts: ~2032-01-01

const policy = conditionConfigToPoetPolicy({
  logic: 'OR',
  conditions: [
    // Owner — unrestricted, always valid
    { type: 'REQKEY', key_identifier: OWNER_KEY, key_type: 'TAP_LEAF_XONLY_PUBKEY' },

    // Heir — only after unlock date, rate-limited, capped per transaction
    {
      logic: 'AND',
      conditions: [
        { type: 'REQKEY', key_identifier: HEIR_KEY, key_type: 'TAP_LEAF_XONLY_PUBKEY' },
        { type: 'TIME_BASED_CONSTRAINT', constraint_type: 'after', start_time: UNLOCK_AT },
        { type: 'COUNT_BASED_CONSTRAINT', max_uses: 4, reset_interval: 'monthly', reset_type: 'calendar' },
        { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 10_000_000 },
      ],
    },
  ],
});
```

---

### BIP-443 two-step vault

Emulates Salvatore Ingala's OP_VAULT design without a soft fork. Enforced today via the
oblivious cosigner's ZK policy predicate. The vault UTXO carries a committed state value;
the policy enforces valid state transitions.

**Two signing paths:**

- **Trigger (TX1)**: input carries initial state `d0` (32 zero bytes) → output carries `d1`
  (`5120 ‖ outputKey`, a P2TR witness program). The server stores `d1` after the block
  confirms.
- **Complete (TX2)**: input carries `d1` (resolved from server-stored covenant state) →
  funds released to any destination.

A plain UTXO cannot satisfy `INPUT_COMMITTED_DATA_VERIFY` because its scriptPubKey does not
encode the expected state commitment — the attack path demonstrated in the demo is rejected at
the proof stage, before the cosigner is even contacted.

```typescript
// Replace with the actual 32-byte taptree merkle root of the vault script
const VAULT_SCRIPT_TREE_ROOT = 'aaaa...64hexchars';

// d0: initial vault state — 32 zero bytes
const D0 = '00'.repeat(32);

const policy = conditionConfigToPoetPolicy({
  logic: 'OR',
  conditions: [
    // ── Path 1: Trigger (TX1) ────────────────────────────────────────────────
    // Input must carry d0; output must carry d1 (the key commitment).
    // After this transaction confirms, the server stores d1 as SIGBASH_COVENANT_STATE.
    {
      logic: 'AND',
      conditions: [
        {
          type: 'INPUT_COMMITTED_DATA_VERIFY',
          input_index: 0,
          witness_data_hex: D0,                    // must match deposited state
          script_tree_root: VAULT_SCRIPT_TREE_ROOT,
          validation_mode: 'bip443_covenant',
        },
        {
          type: 'OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT',
          output_index: 0,
          committed_data_hex: '5120SIGBASH_OUTPUT_KEY',  // d1: P2TR witness program, resolved at signing
          script_tree_root: VAULT_SCRIPT_TREE_ROOT,
          validation_mode: 'bip443_covenant',
        },
      ],
    },

    // ── Path 2: Complete (TX2) ───────────────────────────────────────────────
    // Input must carry d1, fetched from server-stored covenant state.
    // Satisfied only after TX1 has confirmed and d1 has been stored.
    {
      type: 'INPUT_COMMITTED_DATA_VERIFY',
      input_index: 0,
      witness_data_hex: 'SIGBASH_COVENANT_STATE',   // resolved at signing time from server
      script_tree_root: VAULT_SCRIPT_TREE_ROOT,
      validation_mode: 'bip443_covenant',
    },
  ],
});
```

See [`demos/bip443-vault-demo.js`](../demos/bip443-vault-demo.js) for a runnable end-to-end
example including deposit, trigger, completion, and a failed attack attempt.
