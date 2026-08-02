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

/**
 * Valid delegation mode strings for `MATCH_ARK_FORFEIT` conditions.
 *
 * Controls whether the delegated (ANYONECANPAY) forfeit flow is permitted
 * alongside or instead of the standard 2-input SIGHASH_DEFAULT flow.
 *
 * @example
 * ```typescript
 * import { FORFEIT_DELEGATION } from '@sigbash/sdk';
 *
 * const condition = {
 *   type: 'MATCH_ARK_FORFEIT',
 *   operator_pubkey: '03...',
 *   forfeit_script_pubkey: '0014...',
 *   max_fee: 1000,
 *   delegation: FORFEIT_DELEGATION.ALLOW,
 * };
 * ```
 */
export const FORFEIT_DELEGATION = {
  /** Default — direct 2-input SIGHASH_DEFAULT forfeit only. */
  DISALLOW: 'disallow',
  /** Accept both direct (SIGHASH_DEFAULT) and delegated (SIGHASH_ALL|ANYONECANPAY). */
  ALLOW: 'allow',
  /** Delegated 1-input SIGHASH_ALL|ANYONECANPAY forfeit only. */
  REQUIRE: 'require',
} as const;

export type ForfeitDelegation = typeof FORFEIT_DELEGATION[keyof typeof FORFEIT_DELEGATION];
