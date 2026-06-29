# Ark Labs Integration

This doc covers Sigbash integration with **Ark Labs** — the `@arkade-os/sdk` wallet
and `arkd` operator implementation. The four `MATCH_ARK_*` policy atoms are specific to
the Ark Labs PSBT structure and register-intent protocol; they are not generic to
other Ark implementations.

In the Ark Labs model, a virtual UTXO (vtxo) lives in a shared output tree managed
by the operator (Arkade Service). Funds move cooperatively inside the tree without
touching the blockchain; a CSV-gated tapscript leaf lets users exit unilaterally
after the operator's timeout expires, without needing operator cooperation.

Sigbash adds a policy-gated co-signing layer on top: your Ark Labs wallet can only
move funds when the transaction satisfies the conditions you chose at key-registration
time. The operator never sees your policy; the Sigbash server never sees the transaction.

This doc covers the canonical "operator-only" setup — a key that may only transact within
the Ark Labs network (cooperative sends and exits) — and walks through the full
TypeScript SDK integration using `@arkade-os/sdk`.

---

## How Ark Labs transactions map to policy atoms

Four Sigbash condition types cover every PSBT shape an Ark Labs wallet produces:

| Atom | PSBT shape | When it fires |
|---|---|---|
| `MATCH_ARK_INTENT` | vtxo spend (1 or more inputs spending vtxo tapscript leaves) | `wallet.send()` — the main cooperative send |
| `MATCH_ARK_CHECKPOINT` | 1-in / 2-out, output[1] is P2A anchor | Intermediate checkpoint tx produced automatically during `wallet.send()` |
| `MATCH_ARK_FORFEIT` | 2-in / 2-out (vtxo tapscript + connector keyspend) | Operator-initiated forfeit during settlement |
| `MATCH_ARK_COLLABORATIVE_EXIT` | vtxo spend with exit-intent RegisterMessage | `ramps.offboard()` — cooperative onchain exit |

**The OR requirement.** A single `wallet.send()` call triggers two policy-gated co-signs:
first the intent spend (`MATCH_ARK_INTENT`) and then the intermediate checkpoint tx
(`MATCH_ARK_CHECKPOINT`). The `ArkadeContext` is single-use and is consumed by the
intent sign, so the checkpoint sign runs without context. The policy must cover both
shapes via OR, or the checkpoint co-sign will be rejected.

Similarly, `ramps.offboard()` produces an exit spend (`MATCH_ARK_COLLABORATIVE_EXIT`)
followed by a forfeit-shaped settlement tx (`MATCH_ARK_FORFEIT`).

**Unilateral exit.** After the operator's CSV timeout the user can sweep vtxos onchain via
the tapscript unilateral-exit leaf. This is Ark-protocol-level and requires no
Sigbash co-signing; no policy atom is needed to allow it.

---

## Policy composition

Two common compositions:

**Sends only** — allows cooperative sends within Ark; does not co-sign offboard exits.
```
OR(MATCH_ARK_INTENT, MATCH_ARK_CHECKPOINT, MATCH_ARK_FORFEIT)
```

**Full lifecycle** — allows sends and cooperative onchain exits.
```
OR(MATCH_ARK_INTENT, MATCH_ARK_CHECKPOINT, MATCH_ARK_FORFEIT, MATCH_ARK_COLLABORATIVE_EXIT)
```

---

## Step 1: Fetch operator parameters

Before registering a key you need three values from the arkd `GET /v1/info` endpoint:

```typescript
const operatorInfo = await fetch('https://your-arkade-service.example/v1/info').then(r => r.json());

const OPERATOR_PUBKEY      = operatorInfo.signerPubkey;    // 33-byte compressed pubkey hex (66 chars)
const FORFEIT_PUBKEY  = operatorInfo.forfeitPubkey;   // used in MATCH_ARK_CHECKPOINT
const FORFEIT_ADDRESS = operatorInfo.forfeitAddress;  // bech32m P2TR; convert to scriptPubKey for MATCH_ARK_FORFEIT
const CHECKPOINT_TAPSCRIPT = operatorInfo.checkpointTapscript; // raw hex of server-unroll leaf
```

**Decoding `csv_timeout`.** The `MATCH_ARK_CHECKPOINT` atom requires the raw BIP-68
sequence number, not a human-readable duration. Decode it from the leading CScriptNum
push in `checkpointTapscript`:

```typescript
function decodeCsvTimeout(tapscriptHex: string): number {
  const b = Buffer.from(tapscriptHex, 'hex');
  const op = b[0];
  if (op === 0x00) return 0;
  if (op >= 0x51 && op <= 0x60) return op - 0x50; // OP_1..OP_16
  if (op <= 0x4b) {
    let v = 0;
    for (let i = 0; i < op; i++) v += b[1 + i] * (2 ** (8 * i)); // little-endian
    return v;
  }
  throw new Error(`unexpected CScriptNum opcode 0x${op.toString(16)}`);
}
const CSV_TIMEOUT = decodeCsvTimeout(CHECKPOINT_TAPSCRIPT);
```

**Converting `forfeitAddress` to a scriptPubKey hex string.** The `MATCH_ARK_FORFEIT`
atom compares against a raw scriptPubKey, not a bech32m address. Decode the address:

```typescript
import { bech32, bech32m } from '@scure/base';

function addressToScriptPubKey(address: string): string {
  // Try bech32m first (P2TR / segwit v1+), fall back to bech32 (P2WPKH/P2WSH / segwit v0).
  let words: number[];
  let fromWords: (words: number[]) => Uint8Array;
  try {
    ({ words } = bech32m.decode(address));
    fromWords = bech32m.fromWords;
  } catch {
    ({ words } = bech32.decode(address));
    fromWords = bech32.fromWords;
  }
  const witnessVersion = words[0];
  const program = fromWords(words.slice(1));
  // segwit v0 → OP_0 (0x00); segwit v1..v16 → OP_1..OP_16 (0x51..0x60)
  const versionOpcode = witnessVersion === 0 ? 0x00 : 0x50 + witnessVersion;
  return Buffer.from([versionOpcode, program.length, ...program]).toString('hex');
}
const FORFEIT_SPK = addressToScriptPubKey(FORFEIT_ADDRESS);
```

---

## Step 2: Build the policy

```typescript
import { conditionConfigToPoetPolicy } from '@sigbash/sdk';

const policy = conditionConfigToPoetPolicy({
  logic: 'OR',
  conditions: [
    {
      type: 'MATCH_ARK_INTENT',
      // The operator's 33-byte compressed pubkey — verified in every vtxo taptree the wallet builds.
      operator_pubkey: OPERATOR_PUBKEY,
      // How long a RegisterMessage stays valid (seconds). Match the operator's window.
      max_validity_duration_secs: 7200,
      // Output destinations this key may pay. SIGBASH_ARK_SELF_VTXO resolves at
      // signing time to the signer's own change vtxo (requires exit_delay_seconds).
      // Add the scriptPubKey hex of any additional permitted recipients.
      allowed_destinations: ['SIGBASH_ARK_SELF_VTXO'],
      // Must match the operator's vtxo exit delay (seconds). Required when
      // SIGBASH_ARK_SELF_VTXO is in allowed_destinations.
      exit_delay_seconds: 512,
      // Sats bounds applied to every non-self output in the vtxo tree.
      min_receiver_value: 1000,
      max_receiver_value: 1_000_000,
    },
    {
      type: 'MATCH_ARK_CHECKPOINT',
      // The forfeit/checkpoint key — may differ from OPERATOR_PUBKEY; use forfeitPubkey.
      operator_pubkey: FORFEIT_PUBKEY,
      // Raw BIP-68 sequence from the server-unroll leaf (decoded above).
      csv_timeout: CSV_TIMEOUT,
      // Absolute fee cap for the checkpoint tx (sats).
      max_fee: 5000,
    },
    {
      type: 'MATCH_ARK_FORFEIT',
      operator_pubkey: OPERATOR_PUBKEY,
      // The operator's forfeit P2TR as a scriptPubKey hex string (converted above).
      forfeit_script_pubkey: FORFEIT_SPK,
      // Absolute fee cap for the forfeit tx (sats).
      max_fee: 5000,
    },
    // Remove this arm if you do not want cooperative onchain exits.
    {
      type: 'MATCH_ARK_COLLABORATIVE_EXIT',
      operator_pubkey: OPERATOR_PUBKEY,
      max_validity_duration_secs: 7200,
      // Permitted onchain exit destinations as scriptPubKey hex strings.
      // These are the addresses the user may exit to.
      allowed_destinations: ['5120...your_onchain_destination_scriptpubkey_hex...'],
      // Sats bounds on the total exit value.
      min_exit_value: 1000,
      max_exit_value: 10_000_000,
    },
  ],
});
```

> To allow a specific onchain destination: encode the P2TR (or P2WPKH, P2WSH)
> scriptPubKey as a lowercase hex string. Use the same `addressToScriptPubKey`
> helper from Step 1. If you want to allow *any* destination, widen
> `min_exit_value` / `max_exit_value` to cover the expected range — the atom does
> not support an unrestricted wildcard.

---

## Step 3: Register the key

```typescript
import { loadWasm, SigbashClient } from '@sigbash/sdk';

await loadWasm({ wasmUrl: 'https://www.sigbash.com/sigbash.wasm' });

const client = new SigbashClient({
  serverUrl:     'https://www.sigbash.com',
  apiKey:        process.env.SIGBASH_API_KEY!,
  userKey:       process.env.SIGBASH_USER_KEY!,
  userSecretKey: process.env.SIGBASH_SECRET_KEY!,
});

const { keyId, aggregatePubKeyHex } = await client.createKey({
  policy,
  network: 'signet',   // 'signet' by default; see AGENTS.md for mainnet access
  require2FA: false,
});

const { kmcJSON } = await client.getKey(keyId);
```

`aggregatePubKeyHex` is the 32-byte x-only aggregate key. When constructing
`SigbashArkadeIdentity` (Step 4), you need the 33-byte *compressed* form. Extract
it from the KMC's `internal_public_key` field:

```typescript
const kmcData = JSON.parse(kmcJSON) as { internal_public_key?: string };
// internal_public_key is 33-byte compressed hex (02/03 prefix).
// Fall back to a 02-prefix prepend if absent (older KMC versions).
const aggregatePubkeyCompressed = Buffer.from(
  kmcData.internal_public_key ?? ('02' + aggregatePubKeyHex),
  'hex',
);
```

---

## Step 4: Construct SigbashArkadeIdentity

`SigbashArkadeIdentity` wraps a `SigbashClient` key as an Ark-compatible signing
identity. Pass it as `identity` to `Wallet.create()`.

```typescript
import { SigbashArkadeIdentity } from '@sigbash/sdk';
import {
  Wallet, Transaction, SingleKey,
  InMemoryWalletRepository, InMemoryContractRepository, EsploraProvider,
} from '@arkade-os/sdk';

const identity = new SigbashArkadeIdentity(
  client,
  keyId,
  kmcJSON,
  aggregatePubkeyCompressed,          // 33-byte compressed aggregate key
  'signet',
  () => SingleKey.fromRandomBytes().signerSession(),  // MuSig2 tree signer session factory
  (bytes) => Transaction.fromPSBT(bytes),
);

const wallet = await Wallet.create({
  identity,
  arkServerUrl: 'https://your-arkade-service.example',
  onchainProvider: new EsploraProvider('https://your-esplora.example'),
  storage: {
    walletRepository: new InMemoryWalletRepository(),
    contractRepository: new InMemoryContractRepository(),
  },
});
```

---

## Step 5: Sign with context

For `MATCH_ARK_INTENT` and `MATCH_ARK_COLLABORATIVE_EXIT`, the WASM evaluator
requires a `RegisterMessage` from the operator and the vtxo taptree paths of the inputs
being spent. Inject this before each wallet operation:

```typescript
// Retrieve the vtxos the wallet will spend.
const vtxos = await wallet.getVtxos();

// Build the context. vtxoTaprootTrees is a per-input array of tapscript leaf
// hex strings (the intent/exit branch of each vtxo's taptree).
await identity.setArkadeContext({
  // The JSON-encoded RegisterMessage returned by the operator during send/exit setup.
  // In the ts-sdk this is produced internally; expose it via the Intent API or
  // capture it from the wallet's register-intent flow.
  registerMessageJson: JSON.stringify({
    type: 'register',
    onchain_output_indexes: [],
    valid_at:  Math.floor(Date.now() / 1000),
    expire_at: Math.floor(Date.now() / 1000) + 3600,
    cosigners_public_keys: [OPERATOR_PUBKEY],  // 33-byte compressed pubkey hex (same as operator_pubkey above)
  }),
  // One entry per input: the raw tapscript bytes (no version suffix) as hex.
  vtxoTaprootTrees: vtxos.map(v =>
    [Buffer.from(v.intentTapLeafScript[1].subarray(0, v.intentTapLeafScript[1].length - 1)).toString('hex')]
  ),
});

// Now send. The identity signs the intent spend (consuming the context) and
// then the checkpoint tx (context gone, covered by MATCH_ARK_CHECKPOINT).
await wallet.send({ address: recipientArkAddress, amount: 50_000 });
```

The context is single-use and is consumed automatically after the first real
(non-intent-proof) sign. Background vtxo-renewal register-intent proofs do not
consume the context.

For `ramps.offboard()` the flow is identical, but set the context with the exit
RegisterMessage and supply the exit vtxo's `forfeitTapLeafScript` instead.

---

## Parameter reference

### MATCH_ARK_INTENT

| Parameter | Type | Required | Description |
|---|---|---|---|
| `operator_pubkey` | string (compressed pubkey hex, 66 chars) | yes | The operator's pubkey. Verified against every vtxo taptree. |
| `max_validity_duration_secs` | number | yes | Maximum age of a RegisterMessage in seconds. |
| `allowed_destinations` | string[] | yes | scriptPubKey hex strings of permitted outputs. `SIGBASH_ARK_SELF_VTXO` resolves to the signer's own vtxo change output. |
| `exit_delay_seconds` | number | if `SIGBASH_ARK_SELF_VTXO` in destinations | The operator's vtxo exit delay in seconds; used to derive the self-vtxo scriptPubKey. |
| `min_receiver_value` | number | yes | Minimum sats for any non-self vtxo output. |
| `max_receiver_value` | number | yes | Maximum sats for any non-self vtxo output. |

### MATCH_ARK_CHECKPOINT

| Parameter | Type | Required | Description |
|---|---|---|---|
| `operator_pubkey` | string (compressed pubkey hex, 66 chars) | yes | The operator's forfeit/checkpoint key (`forfeitPubkey` from `/v1/info`). |
| `csv_timeout` | number | yes | Raw BIP-68 sequence from the server-unroll leaf (decode with `decodeCsvTimeout` above — not seconds). |
| `max_fee` | number | yes | Absolute fee cap in sats. |

### MATCH_ARK_FORFEIT

| Parameter | Type | Required | Description |
|---|---|---|---|
| `operator_pubkey` | string (compressed pubkey hex, 66 chars) | yes | The operator's pubkey. |
| `forfeit_script_pubkey` | string (hex) | yes | The operator's forfeit output scriptPubKey hex (`forfeitAddress` converted with `addressToScriptPubKey`). |
| `max_fee` | number | yes | Absolute fee cap in sats. |

### MATCH_ARK_COLLABORATIVE_EXIT

| Parameter | Type | Required | Description |
|---|---|---|---|
| `operator_pubkey` | string (compressed pubkey hex, 66 chars) | yes | The operator's pubkey. |
| `max_validity_duration_secs` | number | yes | Maximum age of the exit RegisterMessage in seconds. |
| `allowed_destinations` | string[] | yes | Permitted onchain exit destinations as scriptPubKey hex strings. |
| `min_exit_value` | number | yes | Minimum total exit value in sats. |
| `max_exit_value` | number | yes | Maximum total exit value in sats. |

---

## Common errors

| Error | Cause |
|---|---|
| Policy not satisfied — no intent context | `setArkadeContext()` was not called before `wallet.send()`. |
| Policy not satisfied — output destination not allowed | A vtxo output scriptPubKey is not in `allowed_destinations`. Add the destination or use `SIGBASH_ARK_SELF_VTXO` for change. |
| Policy not satisfied — operator key not found in vtxo taptree | `operator_pubkey` does not match the key present in the vtxo's tapscript leaves. Verify against `/v1/info`. |
| Policy not satisfied — receiver value out of range | A vtxo output is outside `[min_receiver_value, max_receiver_value]`. Widen the bounds or check the amount. |
| Policy not satisfied — csv_timeout mismatch | `csv_timeout` does not match the sequence in the checkpoint output taptree. Redecode from `checkpointTapscript`. |
| Policy not satisfied — no forfeit script match | `forfeit_script_pubkey` does not match the forfeit output. Re-derive from `forfeitAddress`. |

---

## Further reading

| Topic | Reference |
|---|---|
| Credential setup, WASM loading | [getting-started.md](./getting-started.md) |
| Full policy operator and condition reference | [policy-reference.md](./policy-reference.md) |
| Stateful rate limits (COUNT_BASED_CONSTRAINT) | [stateful-constraints.md](./stateful-constraints.md) |
| Dry-run policy checking without consuming nullifiers | [verifying.md](./verifying.md) |
