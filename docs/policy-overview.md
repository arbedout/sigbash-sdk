# Sigbash Policy — Operators & Conditions Quick Reference

## Operators

`k` = integer param; aliases accepted by `conditionConfigToPoetPolicy` (TypeScript) and the policy JSON (HTTP):

| Operator | Alias | Params | Meaning |
|---|---|---|---|
| `AND` | — | — | All children satisfied |
| `OR` | — | — | At least one child satisfied |
| `NOT` | — | — | Child must NOT be satisfied |
| `IMPLIES` | — | — | If child[0] satisfied → child[1] must be too |
| `IFF` | — | — | child[0] ↔ child[1] |
| `VETO` | — | — | If child[0] (trigger) satisfied, rest are blocked |
| `NOR` | — | — | None of the children satisfied |
| `NAND` | — | — | Not all children satisfied simultaneously |
| `XOR` | — | — | Exactly one child satisfied |
| `THRESHOLD` | `THRESH` | `k` | At least k of n children satisfied |
| `WEIGHTED_THRESHOLD` | `WTHRESH` | `k` | Weighted sum of satisfied children ≥ k |
| `MAJORITY` | — | — | More than half of children satisfied |
| `EXACTLY` | `EXACT` | `k` | Exactly k children satisfied |
| `AT_MOST` | `ATMOST` | `k` | At most k children satisfied |

## Conditions

`selector`: `ALL` | `ANY` | `{type:'INDEX',index:N}` — `operator`: `EQ` `NEQ` `LT` `LTE` `GT` `GTE`

| Condition | Key params | Description |
|---|---|---|
| `OUTPUT_VALUE` | `selector`, `operator`, `value` (sats) | Output satoshi value |
| `INPUT_VALUE` | `selector`, `operator`, `value` (sats) | Input satoshi value |
| `TX_FEE_ABSOLUTE` | `operator`, `value` (sats) | Absolute fee (inputs − outputs) |
| `TX_VERSION` | `operator`, `value` | Transaction version field |
| `TX_LOCKTIME` | `operator`, `value` | nLockTime (<500 M = block height, ≥500 M = UNIX ts) |
| `TX_INPUT_COUNT` | `operator`, `value` | Number of inputs |
| `TX_OUTPUT_COUNT` | `operator`, `value` | Number of outputs |
| `INPUT_SEQUENCE` | `selector`, `operator`, `value` | nSequence (e.g. `0xFFFFFFFD` = RBF) |
| `INPUT_SIGHASH_TYPE` | `selector`, `sighash_type` | Sighash type (`SIGHASH_ALL` `SIGHASH_NONE` `SIGHASH_SINGLE` + `ANYONECANPAY_*` variants) |
| `OUTPUT_DEST_IS_IN_SETS` | `addresses[]`, `network`, `selector` | Output destination in approved address set; wrap in NOT for blocklist |
| `INPUT_SOURCE_IS_IN_SETS` | `addresses[]` or `descriptor_template`+`use_descriptor`, `network`, `selector` | Input source in permitted address set |
| `REQKEY` | `key_identifier` (64-hex x-only pubkey), `key_type` (`TAP_LEAF_XONLY_PUBKEY` \| `TAP_KEYPATH_OUTPUTKEY`) | Key present in tapscript path (ZK set-membership, signer-oblivious) |
| `COUNT_BASED_CONSTRAINT` | `max_uses`, `reset_interval` (`never` `daily` `weekly` `monthly`), `reset_type` (`rolling` \| `calendar`) | Rate-limit signing sessions via nullifier counter |
| `TIME_BASED_CONSTRAINT` | `constraint_type` (`after` \| `before` \| `within`); for `within`: `active_days[]` (1=Mon…7=Sun), `start_hour`, `end_hour`, `start_time`, `end_time` | Wall-clock window restriction |
| `OUTPUT_OP_RETURN` | `selector` | OP_RETURN output present |
| `DERIVED_IS_CONSOLIDATION` | `expected_value` (bool) | More inputs than outputs |
| `DERIVED_RBF_ENABLED` | `expected_value` (bool) | At least one input signals RBF |
| `DERIVED_NO_NEW_OUTPUTS` | `expected_value` (bool); optional `use_descriptor`+`descriptor_template` | All outputs go to known addresses (self-consolidation or wallet descriptor) |
| `DERIVED_SIGHASH_TYPE` | `sighash_type` | Derived/effective sighash type for the transaction |
| `TX_TEMPLATE_HASH_MATCHES` | `template_hash` (64-hex), `input_index` | Tx matches pre-committed template (version, locktime, sequences, outputs) |
| `INPUT_COMMITTED_DATA_VERIFY` | `input_index` (`-1`=self), `witness_data_hex` (hex+placeholders), `script_tree_root` (`'SELF'`=same taptree), `validation_pattern` | BIP-443 input witness data check |
| `OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT` | `output_index` (`-1`=self), `committed_data_hex` (hex+placeholders), `script_tree_root` (`'SELF'`=same taptree), `validation_mode`, `amount_mode` | BIP-443 output scriptPubKey commitment |

## Policy placeholders

Some parameter values are not available at policy-registration time and are resolved later:

**At key-registration** — `SIGBASH_XPUB` in `descriptor_template` is replaced with the key's BIP-328 xpub. Conditions that accept `use_descriptor: true`: `INPUT_SOURCE_IS_IN_SETS`, `OUTPUT_DEST_IS_IN_SETS`, `DERIVED_NO_NEW_OUTPUTS`, `REQKEY`. Example templates: `tr(SIGBASH_XPUB/0/*)`, `wpkh(SIGBASH_XPUB/84h/1h/0h/0/*)`.

**At signing time** (PSBT-derived) — in BIP-443 data fields: `SIGBASH_INTERNAL_KEY`, `SIGBASH_OUTPUT_KEY`, `SIGBASH_NUMS_KEY`, `SIGBASH_COVENANT_STATE`. Index `-1` = same index as the input being signed. `script_tree_root: 'SELF'` = same taptree as current policy.

Full param details: [policy-reference.md](./policy-reference.md)
