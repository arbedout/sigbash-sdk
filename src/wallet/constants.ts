/**
 * Institutional wallet format constants.
 *
 * Every value here is a wallet-format constant shared with the canonical
 * builder implementation in the WASM lane. No constant may be changed or
 * added without a golden-vector fixture asserting the new value end to end:
 * the fixture is the mirror discipline, never a silent hand copy.
 */

import { MAX_SIGNERS_PER_LEAF } from '../contracts/walletDescriptor';

export { MAX_SIGNERS_PER_LEAF };

/** BIP-341 provably unspendable NUMS x-only internal key (format constant). */
export const WALLET_NUMS_INTERNAL_KEY_HEX =
  '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';

/** Receive is /0/i, change is /1/i. */
export const WALLET_BRANCH_RECEIVE = 0;
export const WALLET_BRANCH_CHANGE = 1;

/**
 * Per-branch child index ceiling. The descriptor-mode REQKEY gadget commits
 * exactly 256 receive + 256 change candidate output keys, so derivation
 * outside 0..255 on either branch is never permitted.
 */
export const WALLET_MAX_DERIVATION_INDEX = 255;
export const WALLET_CANDIDATES_PER_BRANCH = WALLET_MAX_DERIVATION_INDEX + 1;
export const WALLET_REQKEY_CANDIDATE_COUNT = 2 * WALLET_CANDIDATES_PER_BRANCH;

/** Marks a descriptor_template value as a wallet-ownership REQKEY payload. */
export const WALLET_REQKEY_TEMPLATE_PREFIX = 'sigbashwd1:';

/** Sentinel occupying the single Sigbash signer's xpub in a REQKEY payload. */
export const WALLET_REQKEY_PLACEHOLDER_XPUB = 'SIGBASH_XPUB';

/** Decay block count T bounds (OP_CSV / BIP-68 per-output semantics). */
export const WALLET_DECAY_BLOCKS_MIN = 1;
export const WALLET_DECAY_BLOCKS_MAX = 65535;

/** Maximum distinct allowed signer sets (tapscript leaf count) per wallet. */
export const WALLET_MAX_ALLOWED_SIGNER_SETS = 255;

/** Maximum signer roots per wallet. */
export const WALLET_MAX_SIGNERS = 255;

/** Merkle depth bound keeping control blocks within the consensus limit. */
export const WALLET_TAPTREE_MAX_DEPTH = 128;

/** BIP-32 depth field bound for supplied origin paths. */
export const WALLET_ORIGIN_PATH_MAX_COMPONENTS = 255;

/** Hardened key start (BIP-32). */
export const BIP32_HARDENED_KEY_START = 0x80000000;

/** Tapscript leaf version for all wallet leaves. */
export const TAP_LEAF_VERSION = 0xc0;

export type WalletNetwork = 'signet' | 'mainnet' | 'testnet';

export const WALLET_NETWORKS: readonly WalletNetwork[] = ['signet', 'mainnet', 'testnet'];

export interface WalletNetworkParams {
  /** BIP-32 public extended key version bytes (xpub / tpub-class). */
  hdPublicKeyVersion: number;
  /** BIP-32 private extended key version bytes, accepted only to reject. */
  hdPrivateKeyVersion: number;
  /** Bech32m human-readable part for P2TR addresses. */
  hrp: string;
}

/**
 * Signet and testnet share the tpub-class version bytes; the wallet's
 * explicit network property, never key version bytes, disambiguates them.
 */
export const WALLET_NETWORK_PARAMS: Record<WalletNetwork, WalletNetworkParams> = {
  signet: { hdPublicKeyVersion: 0x043587cf, hdPrivateKeyVersion: 0x04358394, hrp: 'tb' },
  testnet: { hdPublicKeyVersion: 0x043587cf, hdPrivateKeyVersion: 0x04358394, hrp: 'tb' },
  mainnet: { hdPublicKeyVersion: 0x0488b21e, hdPrivateKeyVersion: 0x0488ade4, hrp: 'bc' },
};

/**
 * Protocol input cap enforced server-side; a signing session above it can
 * never prove, so the client fails closed before spending a proof attempt.
 */
export const MAX_BATCH_INPUTS = 64;

/** Maximum encoded wallet-ownership REQKEY template payload (fail-closed guard). */
export const WALLET_REQKEY_TEMPLATE_MAX_CANONICAL_BYTES = 60 * 1024;
