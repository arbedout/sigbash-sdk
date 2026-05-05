/**
 * Public enum maps extracted from SigbashClient internals.
 *
 * These constants document the valid string values that the SDK normalises
 * before passing to the WASM constraint evaluator.  Pass these strings in
 * your `conditionParams` — the SDK converts them to numeric form automatically.
 */

/**
 * Valid sighash type strings for `INPUT_SIGHASH_TYPE` conditions.
 *
 * @example
 * ```typescript
 * import { SIGHASH_TYPES } from '@sigbash/sdk';
 *
 * const condition = {
 *   type: 'INPUT_SIGHASH_TYPE',
 *   selector: 'ALL',
 *   sighash_type: SIGHASH_TYPES.SIGHASH_ALL,
 * };
 * ```
 */
export const SIGHASH_TYPES = {
  SIGHASH_ALL:               'SIGHASH_ALL',
  SIGHASH_NONE:              'SIGHASH_NONE',
  SIGHASH_SINGLE:            'SIGHASH_SINGLE',
  SIGHASH_ANYONECANPAY_ALL:  'SIGHASH_ANYONECANPAY_ALL',
  SIGHASH_ANYONECANPAY_NONE: 'SIGHASH_ANYONECANPAY_NONE',
  SIGHASH_ANYONECANPAY_SINGLE: 'SIGHASH_ANYONECANPAY_SINGLE',
} as const;

export type SighashType = keyof typeof SIGHASH_TYPES;

/**
 * Valid script type strings for `INPUT_SCRIPT_TYPE` and `OUTPUT_SCRIPT_TYPE` conditions.
 *
 * @example
 * ```typescript
 * import { SCRIPT_TYPES } from '@sigbash/sdk';
 *
 * const condition = {
 *   type: 'OUTPUT_SCRIPT_TYPE',
 *   selector: 'ALL',
 *   script_type: SCRIPT_TYPES.P2TR,
 * };
 * ```
 */
export const SCRIPT_TYPES = {
  P2PKH:     'P2PKH',
  P2SH:      'P2SH',
  P2WPKH:    'P2WPKH',
  P2WSH:     'P2WSH',
  P2TR:      'P2TR',
  OP_RETURN: 'OP_RETURN',
  UNKNOWN:   'UNKNOWN',
} as const;

export type ScriptType = keyof typeof SCRIPT_TYPES;
