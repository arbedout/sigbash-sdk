/**
 * Client-only wallet identity: the wallet fingerprint and the canonical
 * address derivation facade.
 *
 * The fingerprint is the deterministic client-only identity of a wallet. It
 * is derived exclusively from canonical wallet material and network and is
 * never used as a public sync identifier; server-facing encrypted-object
 * records keep random opaque IDs.
 *
 * FINGERPRINT-ORDER PIN: the fingerprint is defined over the canonical
 * descriptor TEXT with leaves in tree-faithful TapLeaf-hash ascending order,
 * evaluated at the branch's reference derivation (branch, index 0). That
 * anchor makes the text order index-independent, so one wallet keeps one
 * stable fingerprint while the text still reproduces the index-0 output key
 * through third-party tr() tooling. The text order is wallet identity: any
 * change to it moves every wallet_id and is therefore a format-version
 * change, never a bugfix.
 *
 * ORIGIN DECORATION PIN: origin metadata is PSBT/hardware interoperability
 * decoration, never spend identity — derivation consumes only the xpub. The
 * fingerprint therefore commits the origin-less canonical text.
 */

import { bytesToHex, taggedHash } from '../contracts/encoding';
import { fingerprintPreimageBytes } from './canonicalText';
import type { InstitutionalWallet } from './walletBuilder';
import { buildWalletTapTree, type WalletTapTree } from './taptree';
import type { DescriptorBranch } from './canonicalText';

/** Wallet fingerprint domain tag; any change is an identity format change. */
export const WALLET_FINGERPRINT_DOMAIN_TAG = 'SIGBASH/WALLET/V1';

/** Returns the wallet's deterministic 32-byte client-only identity. */
export function walletFingerprint(wallet: InstitutionalWallet): Uint8Array {
  return taggedHash(WALLET_FINGERPRINT_DOMAIN_TAG, fingerprintPreimageBytes(wallet));
}

/** Returns the wallet fingerprint as lowercase hex. */
export function walletFingerprintHex(wallet: InstitutionalWallet): string {
  return bytesToHex(walletFingerprint(wallet));
}

/**
 * Derives the wallet's P2TR address at one canonical branch/index. Receive
 * is branch 0, change is branch 1; the same child index is applied to every
 * signer root. All tree, tweak, and bound rules are the canonical TapTree
 * builder's — this facade adds no derivation logic of its own.
 */
export function deriveWalletAddress(
  wallet: InstitutionalWallet,
  branch: DescriptorBranch,
  index: number
): string {
  return buildWalletTapTree(wallet, branch, index).address;
}

/**
 * Derives the full spend metadata for one branch/index: address, output
 * key, scriptPubKey, and per-leaf scripts/paths/control blocks for PSBT
 * construction.
 */
export function deriveWalletSpendMetadata(
  wallet: InstitutionalWallet,
  branch: DescriptorBranch,
  index: number
): WalletTapTree {
  return buildWalletTapTree(wallet, branch, index);
}
