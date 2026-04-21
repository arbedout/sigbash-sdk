/**
 * Machine-readable catalog of all condition types supported by the Sigbash
 * POET v1.1 runtime.  Use this catalog to discover valid `conditionType`
 * strings and the `conditionParams` schema for each condition.
 *
 * All 25 condition types are listed.  The SDK's `SigbashClient` normalises
 * params (e.g. boolean `expected_value`, sighash strings, script type strings)
 * before handing them to the WASM evaluator — you can use the human-friendly
 * forms shown here.
 *
 * @example
 * ```typescript
 * import { CONDITION_TYPES } from '@sigbash/sdk';
 *
 * // Discover parameters required by OUTPUT_VALUE:
 * console.log(CONDITION_TYPES.OUTPUT_VALUE.params);
 *
 * // List all condition types:
 * console.log(Object.keys(CONDITION_TYPES));
 * ```
 */

/** Parameter specification for a single condition param. */
export interface ConditionParamSpec {
  /** JavaScript type of the parameter value. */
  type: 'number' | 'string' | 'boolean' | 'string[]' | 'Selector' | 'ComparisonOperator';
  /** Human-readable description. */
  description: string;
  /** Whether this parameter must be supplied. */
  required: boolean;
  /** Exhaustive list of valid string values, when applicable. */
  enum?: readonly string[];
  /** Default value when omitted. */
  default?: unknown;
}

/** Full specification for one condition type. */
export interface ConditionTypeSpec {
  /** Human-readable description of what this condition checks. */
  description: string;
  /**
   * Whether a `selector` param is required.
   * When `true`, pass `selector: 'ALL' | 'ANY' | { type: 'INDEX', index: N }`.
   * The SDK defaults to `'ANY'` when the selector is omitted.
   */
  requiresSelector: boolean;
  /** Parameter schema. */
  params: Record<string, ConditionParamSpec>;
  /** Minimal usage example. */
  example: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Condition type catalog
// ---------------------------------------------------------------------------

/**
 * Complete catalog of all Sigbash POET v1.1 condition types.
 *
 * Grouped by category:
 *  - **Value conditions** — numeric comparisons on output/input satoshi amounts
 *  - **Transaction structure** — version, locktime, input/output count, fees
 *  - **Script & sighash** — script type and sighash type enforcement
 *  - **Address sets** — allowlist / blocklist for destinations or sources
 *  - **Key requirements** — REQKEY for proving key membership in tapscript
 *  - **Usage limits** — COUNT_BASED_CONSTRAINT (rate limiting), TIME_BASED_CONSTRAINT
 *  - **Derived properties** — boolean flags computed from the transaction structure
 *  - **Template hashes** — OP_TEMPLATEHASH commitment for pre-authorised tx shapes
 *  - **BIP-443 commitments** — committed data and scriptPubKey matching
 */
export const CONDITION_TYPES: Record<string, ConditionTypeSpec> = {

  // -------------------------------------------------------------------------
  // Value conditions
  // -------------------------------------------------------------------------

  OUTPUT_VALUE: {
    description: 'Enforces a numeric comparison on the satoshi value of one or more outputs.',
    requiresSelector: true,
    params: {
      operator: {
        type: 'ComparisonOperator',
        description: 'Comparison operator.',
        required: true,
        enum: ['LTE', 'GTE', 'EQ', 'LT', 'GT', 'NEQ'],
      },
      value: {
        type: 'number',
        description: 'Threshold value in satoshis.',
        required: true,
      },
      selector: {
        type: 'Selector',
        description: "Which outputs to check. Defaults to 'ANY' if omitted.",
        required: false,
        default: 'ANY',
      },
    },
    example: { type: 'OUTPUT_VALUE', selector: 'ALL', operator: 'LTE', value: 100000 },
  },

  INPUT_VALUE: {
    description: 'Enforces a numeric comparison on the satoshi value of one or more inputs.',
    requiresSelector: true,
    params: {
      operator: {
        type: 'ComparisonOperator',
        description: 'Comparison operator.',
        required: true,
        enum: ['LTE', 'GTE', 'EQ', 'LT', 'GT', 'NEQ'],
      },
      value: {
        type: 'number',
        description: 'Threshold value in satoshis.',
        required: true,
      },
      selector: {
        type: 'Selector',
        description: "Which inputs to check. Defaults to 'ANY' if omitted.",
        required: false,
        default: 'ANY',
      },
    },
    example: { type: 'INPUT_VALUE', selector: 'ALL', operator: 'GTE', value: 1000 },
  },

  // -------------------------------------------------------------------------
  // Transaction structure
  // -------------------------------------------------------------------------

  TX_VERSION: {
    description: 'Checks the Bitcoin transaction version field (typically 1 or 2).',
    requiresSelector: false,
    params: {
      operator: {
        type: 'ComparisonOperator',
        description: 'Comparison operator.',
        required: true,
        enum: ['EQ', 'NEQ', 'GTE', 'LTE', 'GT', 'LT'],
      },
      value: {
        type: 'number',
        description: 'Transaction version number (e.g. 2).',
        required: true,
      },
    },
    example: { type: 'TX_VERSION', operator: 'EQ', value: 2 },
  },

  TX_LOCKTIME: {
    description:
      'Checks the transaction nLockTime field. Values < 500,000,000 are block heights; values >= 500,000,000 are UNIX timestamps.',
    requiresSelector: false,
    params: {
      operator: {
        type: 'ComparisonOperator',
        description: 'Comparison operator.',
        required: true,
        enum: ['EQ', 'NEQ', 'GTE', 'LTE', 'GT', 'LT'],
      },
      value: {
        type: 'number',
        description: 'Locktime value (block height or UNIX timestamp).',
        required: true,
      },
    },
    example: { type: 'TX_LOCKTIME', operator: 'EQ', value: 500000 },
  },

  TX_INPUT_COUNT: {
    description: 'Checks the number of transaction inputs.',
    requiresSelector: false,
    params: {
      operator: {
        type: 'ComparisonOperator',
        description: 'Comparison operator.',
        required: true,
        enum: ['EQ', 'NEQ', 'GTE', 'LTE', 'GT', 'LT'],
      },
      value: {
        type: 'number',
        description: 'Expected input count.',
        required: true,
      },
    },
    example: { type: 'TX_INPUT_COUNT', operator: 'EQ', value: 1 },
  },

  TX_OUTPUT_COUNT: {
    description: 'Checks the number of transaction outputs.',
    requiresSelector: false,
    params: {
      operator: {
        type: 'ComparisonOperator',
        description: 'Comparison operator.',
        required: true,
        enum: ['EQ', 'NEQ', 'GTE', 'LTE', 'GT', 'LT'],
      },
      value: {
        type: 'number',
        description: 'Expected output count.',
        required: true,
      },
    },
    example: { type: 'TX_OUTPUT_COUNT', operator: 'EQ', value: 2 },
  },

  TX_FEE_ABSOLUTE: {
    description: 'Checks the absolute transaction fee in satoshis (sum of inputs minus sum of outputs).',
    requiresSelector: false,
    params: {
      operator: {
        type: 'ComparisonOperator',
        description: 'Comparison operator.',
        required: true,
        enum: ['EQ', 'NEQ', 'GTE', 'LTE', 'GT', 'LT'],
      },
      value: {
        type: 'number',
        description: 'Fee threshold in satoshis.',
        required: true,
      },
    },
    example: { type: 'TX_FEE_ABSOLUTE', operator: 'LTE', value: 5000 },
  },

  INPUT_SEQUENCE: {
    description:
      'Checks the nSequence field of one or more inputs. Used for RBF signalling (0xFFFFFFFD) and relative timelocks.',
    requiresSelector: true,
    params: {
      operator: {
        type: 'ComparisonOperator',
        description: 'Comparison operator.',
        required: true,
        enum: ['EQ', 'NEQ', 'GTE', 'LTE', 'GT', 'LT'],
      },
      value: {
        type: 'number',
        description: 'Expected sequence value (e.g. 0xFFFFFFFD for RBF).',
        required: true,
      },
      selector: {
        type: 'Selector',
        description: "Which inputs to check. Defaults to 'ANY' if omitted.",
        required: false,
        default: 'ANY',
      },
    },
    example: { type: 'INPUT_SEQUENCE', selector: 'ALL', operator: 'EQ', value: 0xFFFFFFFD },
  },

  // -------------------------------------------------------------------------
  // Script & sighash conditions
  // -------------------------------------------------------------------------

  INPUT_SCRIPT_TYPE: {
    description: 'Requires the spending script type of one or more inputs to match a specific script type.',
    requiresSelector: true,
    params: {
      script_type: {
        type: 'string',
        description: 'Required script type. The SDK converts this string to a numeric enum automatically.',
        required: true,
        enum: ['P2PKH', 'P2SH', 'P2WPKH', 'P2WSH', 'P2TR', 'OP_RETURN', 'UNKNOWN'],
      },
      selector: {
        type: 'Selector',
        description: "Which inputs to check. Defaults to 'ANY' if omitted.",
        required: false,
        default: 'ANY',
      },
    },
    example: { type: 'INPUT_SCRIPT_TYPE', selector: 'ALL', script_type: 'P2TR' },
  },

  OUTPUT_SCRIPT_TYPE: {
    description: 'Requires the scriptPubKey type of one or more outputs to match a specific script type.',
    requiresSelector: true,
    params: {
      script_type: {
        type: 'string',
        description: 'Required script type. The SDK converts this string to a numeric enum automatically.',
        required: true,
        enum: ['P2PKH', 'P2SH', 'P2WPKH', 'P2WSH', 'P2TR', 'OP_RETURN', 'UNKNOWN'],
      },
      selector: {
        type: 'Selector',
        description: "Which outputs to check. Defaults to 'ANY' if omitted.",
        required: false,
        default: 'ANY',
      },
    },
    example: { type: 'OUTPUT_SCRIPT_TYPE', selector: 'ALL', script_type: 'P2TR' },
  },

  INPUT_SIGHASH_TYPE: {
    description: 'Enforces a specific sighash type on one or more inputs.',
    requiresSelector: true,
    params: {
      sighash_type: {
        type: 'string',
        description: 'Required sighash type. The SDK converts this string to numeric form automatically.',
        required: true,
        enum: [
          'SIGHASH_ALL',
          'SIGHASH_NONE',
          'SIGHASH_SINGLE',
          'SIGHASH_ANYONECANPAY_ALL',
          'SIGHASH_ANYONECANPAY_NONE',
          'SIGHASH_ANYONECANPAY_SINGLE',
        ],
      },
      selector: {
        type: 'Selector',
        description: "Which inputs to check. Defaults to 'ANY' if omitted.",
        required: false,
        default: 'ANY',
      },
    },
    example: { type: 'INPUT_SIGHASH_TYPE', selector: 'ALL', sighash_type: 'SIGHASH_ALL' },
  },

  // -------------------------------------------------------------------------
  // Address set conditions
  // -------------------------------------------------------------------------

  OUTPUT_DEST_IS_IN_SETS: {
    description:
      'Checks that the destination address(es) of one or more outputs are in an approved set. ' +
      'Use NOT(OUTPUT_DEST_IS_IN_SETS) for a blocklist.',
    requiresSelector: true,
    params: {
      addresses: {
        type: 'string[]',
        description: 'Array of permitted Bitcoin addresses.',
        required: true,
      },
      network: {
        type: 'string',
        description: "Bitcoin network for address validation ('mainnet', 'testnet', 'signet').",
        required: true,
        enum: ['mainnet', 'testnet', 'signet'],
      },
      selector: {
        type: 'Selector',
        description: "Which outputs to check. Defaults to 'ANY' if omitted.",
        required: false,
        default: 'ANY',
      },
      require_change_to_input_addresses: {
        type: 'boolean',
        description: 'When true, any change output must send back to one of the input addresses.',
        required: false,
        default: false,
      },
    },
    example: {
      type: 'OUTPUT_DEST_IS_IN_SETS',
      selector: { type: 'ALL' },
      addresses: ['tb1qexample...'],
      network: 'signet',
    },
  },

  INPUT_SOURCE_IS_IN_SETS: {
    description: 'Checks that the source address(es) of one or more inputs are in a permitted set.',
    requiresSelector: true,
    params: {
      addresses: {
        type: 'string[]',
        description: 'Array of permitted source Bitcoin addresses. Not required when use_descriptor is true.',
        required: false,
      },
      network: {
        type: 'string',
        description: "Bitcoin network for address validation.",
        required: true,
        enum: ['mainnet', 'testnet', 'signet'],
      },
      selector: {
        type: 'Selector',
        description: "Which inputs to check. Defaults to 'ANY' if omitted.",
        required: false,
        default: 'ANY',
      },
      descriptor_template: {
        type: 'string',
        description: 'BIP-328 descriptor template with SIGBASH_XPUB placeholder for address derivation at key request time.',
        required: false,
      },
      use_descriptor: {
        type: 'boolean',
        description: 'When true, addresses are derived from descriptor_template at key request time.',
        required: false,
      },
    },
    example: {
      type: 'INPUT_SOURCE_IS_IN_SETS',
      selector: 'ANY',
      addresses: ['tb1qexample...'],
      network: 'signet',
    },
  },

  // INPUT_TXID_IS_IN_SETS removed in T73 — TxidList polynomial slot removed.

  // -------------------------------------------------------------------------
  // Key requirement
  // -------------------------------------------------------------------------

  REQKEY: {
    description:
      'Proves that a specific key is present in the tapscript spending path, using a zero-knowledge ' +
      'set-membership proof (IPA). The signer cannot determine which specific key was required.',
    requiresSelector: false,
    params: {
      key_identifier: {
        type: 'string',
        description: '64-char hex x-only public key (32 bytes). Use TAP_LEAF_XONLY_PUBKEY for Taproot.',
        required: true,
      },
      key_type: {
        type: 'string',
        description: 'Key domain — determines how the key is extracted from the spending path.',
        required: true,
        enum: ['TAP_LEAF_XONLY_PUBKEY', 'TAP_LEAF_SCRIPT_HASH'],
      },
    },
    example: {
      type: 'REQKEY',
      parameters: {
        key_identifier: 'aabbcc...64hexchars',
        key_type: 'TAP_LEAF_XONLY_PUBKEY',
      },
    },
  },

  // -------------------------------------------------------------------------
  // Usage limits
  // -------------------------------------------------------------------------

  COUNT_BASED_CONSTRAINT: {
    description:
      'Rate-limits signing sessions using a server-side nullifier counter. ' +
      'When max_uses is reached in the current interval, further signing attempts fail ' +
      'until the interval resets.',
    requiresSelector: false,
    params: {
      max_uses: {
        type: 'number',
        description: 'Maximum number of signing sessions allowed per interval.',
        required: true,
      },
      reset_interval: {
        type: 'string',
        description: 'How often the counter resets.',
        required: true,
        enum: ['never', 'daily', 'weekly', 'monthly'],
      },
      reset_type: {
        type: 'string',
        description:
          "'rolling' resets relative to the first use; 'calendar' resets at the start of the calendar period (midnight UTC).",
        required: false,
        default: 'rolling',
        enum: ['rolling', 'calendar'],
      },
    },
    example: {
      type: 'COUNT_BASED_CONSTRAINT',
      max_uses: 5,
      reset_interval: 'daily',
      reset_type: 'rolling',
    },
  },

  TIME_BASED_CONSTRAINT: {
    description:
      'Restricts signing to a wall-clock time window. Use constraint_type "after" for unlock-after, ' +
      '"before" for expiry, or combine both in an AND node for a window.',
    requiresSelector: false,
    params: {
      constraint_type: {
        type: 'string',
        description: '"after" — signing allowed after start_time; "before" — signing allowed before end_time.',
        required: true,
        enum: ['after', 'before'],
      },
      start_time: {
        type: 'number',
        description: 'UNIX timestamp (seconds). Required when constraint_type is "after".',
        required: false,
      },
      end_time: {
        type: 'number',
        description: 'UNIX timestamp (seconds). Required when constraint_type is "before".',
        required: false,
      },
    },
    example: {
      type: 'TIME_BASED_CONSTRAINT',
      constraint_type: 'after',
      start_time: 1893456000,
    },
  },

  // -------------------------------------------------------------------------
  // Output checks
  // -------------------------------------------------------------------------

  OUTPUT_OP_RETURN: {
    description: 'Checks that an OP_RETURN output is present (or absent) in the transaction.',
    requiresSelector: true,
    params: {
      selector: {
        type: 'Selector',
        description: "Which outputs to check. Defaults to 'ANY' if omitted.",
        required: false,
        default: 'ANY',
      },
    },
    example: { type: 'OUTPUT_OP_RETURN', selector: 'ANY' },
  },

  // -------------------------------------------------------------------------
  // Derived (boolean) conditions
  // -------------------------------------------------------------------------

  DERIVED_IS_CONSOLIDATION: {
    description:
      'True when the transaction has more inputs than outputs — a typical UTXO consolidation pattern.',
    requiresSelector: false,
    params: {
      expected_value: {
        type: 'boolean',
        description: 'true to require consolidation; false to require it is NOT a consolidation.',
        required: true,
      },
    },
    example: { type: 'DERIVED_IS_CONSOLIDATION', expected_value: true },
  },

  DERIVED_IS_COINJOIN_LIKE: {
    description:
      'True when the transaction resembles a CoinJoin: multiple inputs from different addresses ' +
      'and multiple equal-value outputs.',
    requiresSelector: false,
    params: {
      expected_value: {
        type: 'boolean',
        description: 'true to require CoinJoin-like; false to require it is NOT CoinJoin-like.',
        required: true,
      },
    },
    example: { type: 'DERIVED_IS_COINJOIN_LIKE', expected_value: false },
  },

  DERIVED_IS_PAYJOIN_LIKE: {
    description:
      'True when the transaction resembles a PayJoin: the recipient contributes at least one input.',
    requiresSelector: false,
    params: {
      expected_value: {
        type: 'boolean',
        description: 'true to require PayJoin-like; false to require it is NOT PayJoin-like.',
        required: true,
      },
    },
    example: { type: 'DERIVED_IS_PAYJOIN_LIKE', expected_value: false },
  },

  DERIVED_RBF_ENABLED: {
    description: 'True when at least one input signals Replace-By-Fee (nSequence < 0xFFFFFFFE).',
    requiresSelector: false,
    params: {
      expected_value: {
        type: 'boolean',
        description: 'true to require RBF enabled; false to require RBF disabled.',
        required: true,
      },
    },
    example: { type: 'DERIVED_RBF_ENABLED', expected_value: true },
  },

  DERIVED_NO_NEW_OUTPUTS: {
    description:
      'True when every output address was already seen as an input address — no new addresses introduced.',
    requiresSelector: false,
    params: {
      expected_value: {
        type: 'boolean',
        description: 'true to require no new outputs; false to allow new output addresses.',
        required: true,
      },
    },
    example: { type: 'DERIVED_NO_NEW_OUTPUTS', expected_value: true },
  },

  DERIVED_SIGHASH_TYPE: {
    description: 'Checks the derived/effective sighash type for the transaction.',
    requiresSelector: false,
    params: {
      sighash_type: {
        type: 'string',
        description: 'Required sighash type.',
        required: true,
        enum: [
          'SIGHASH_ALL',
          'SIGHASH_NONE',
          'SIGHASH_SINGLE',
          'SIGHASH_ANYONECANPAY_ALL',
          'SIGHASH_ANYONECANPAY_NONE',
          'SIGHASH_ANYONECANPAY_SINGLE',
        ],
      },
    },
    example: { type: 'DERIVED_SIGHASH_TYPE', sighash_type: 'SIGHASH_ALL' },
  },

  // -------------------------------------------------------------------------
  // Template hash (OP_TEMPLATEHASH — BIP-119 family)
  // -------------------------------------------------------------------------

  TX_TEMPLATE_HASH_MATCHES: {
    description:
      'Checks that the transaction matches a pre-committed template hash. ' +
      'The template covers: version, locktime, input sequences, and outputs. ' +
      'Any deviation (different amount, address, or sequence) will fail.',
    requiresSelector: false,
    params: {
      template_hash: {
        type: 'string',
        description: 'Hex-encoded 32-byte template hash pre-computed by the policy author.',
        required: true,
      },
      input_index: {
        type: 'number',
        description: 'Zero-based input index this template applies to (default: 0).',
        required: false,
        default: 0,
      },
    },
    example: {
      type: 'TX_TEMPLATE_HASH_MATCHES',
      template_hash: 'aabbccdd...64hexchars',
      input_index: 0,
    },
  },

  // -------------------------------------------------------------------------
  // BIP-443 committed data conditions
  // -------------------------------------------------------------------------

  INPUT_COMMITTED_DATA_VERIFY: {
    description:
      'Verifies that the input contains a specific committed data value (BIP-443 annex commitment). ' +
      'Used in chained tapscript state machines.',
    requiresSelector: false,
    params: {
      committed_data: {
        type: 'string',
        description: 'Hex-encoded committed data blob expected in the input annex.',
        required: true,
      },
    },
    example: {
      type: 'INPUT_COMMITTED_DATA_VERIFY',
      committed_data: 'deadbeef',
    },
  },

  OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT: {
    description:
      'Verifies that an output scriptPubKey matches a pre-committed value (BIP-443 output commitment). ' +
      'Used to enforce exact output scripts in chained state machines.',
    requiresSelector: false,
    params: {
      commitment: {
        type: 'string',
        description: 'Hex-encoded expected scriptPubKey.',
        required: true,
      },
    },
    example: {
      type: 'OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT',
      commitment: '5120aabbcc...66hexchars',
    },
  },
};
