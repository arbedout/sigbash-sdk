/**
 * Canonical descriptor text view over a built institutional wallet.
 *
 * The text is a view, never an independent source. Leaf order is
 * tree-faithful: leaves appear in the raw TapLeaf-hash ascending order the
 * deterministic tree builder produces, evaluated at the branch's reference
 * derivation (branch, index 0), so one wallet has exactly one canonical
 * text per branch and the text reproduces the wallet's index-0 output key
 * through third-party tr() tooling. This same ordering commits into the
 * wallet fingerprint (in its origin-less form), so changing the text order
 * is a wallet-identity format change. Scripts never depend on how key
 * expressions are rendered, so placeholder and origin modes share the
 * order.
 */

import { bytesToHex, concatBytes, taggedHash, utf8 } from '../contracts/encoding';
import { TAP_LEAF_VERSION, WALLET_NUMS_INTERNAL_KEY_HEX } from './constants';
import { WalletDescriptorError } from './errors';
import { decayScript, pkScript, sortedMultiAScript } from './taptree';
import { deriveWalletChildKey, parseExtendedPublicKey } from './xpubImport';
import type { InstitutionalWallet } from './walletBuilder';

export type DescriptorBranch = 0 | 1;

const DESCRIPTOR_INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const CHECKSUM_MASK = (1n << 41n) - 1n;
const CHECKSUM_POLY_MASKS = [
  0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn,
];

function descPolymod(c: bigint, val: number): bigint {
  const c0 = c >> 35n;
  let out = ((c & CHECKSUM_MASK) << 5n) ^ BigInt(val);
  for (let i = 0; i < 5; i++) {
    if ((c0 >> BigInt(i)) & 1n) {
      out ^= CHECKSUM_POLY_MASKS[i];
    }
  }
  return out;
}

/** Bitcoin Core descriptor checksum (8 bech32 characters after '#'). */
export function descriptorChecksum(descriptor: string): string {
  let c = 1n;
  let cls = 0;
  let clscount = 0;
  for (const ch of descriptor) {
    const pos = DESCRIPTOR_INPUT_CHARSET.indexOf(ch);
    if (pos === -1) {
      throw new WalletDescriptorError('character outside the descriptor charset');
    }
    c = descPolymod(c, pos & 31);
    cls = cls * 3 + (pos >>> 5);
    clscount += 1;
    if (clscount === 3) {
      c = descPolymod(c, cls);
      cls = 0;
      clscount = 0;
    }
  }
  if (clscount > 0) {
    c = descPolymod(c, cls);
  }
  for (let i = 0; i < 8; i++) {
    c = descPolymod(c, 0);
  }
  c ^= 1n;
  let out = '';
  for (let j = 0; j < 8; j++) {
    out += BECH32_CHARSET[Number((c >> BigInt(5 * (7 - j))) & 31n)];
  }
  return out;
}

function originPrefix(origin: { masterFingerprint: Uint8Array; path: number[] }): string {
  let out = '[' + bytesToHex(origin.masterFingerprint);
  for (const idx of origin.path) {
    if (idx >= 0x80000000) {
      out += `/${idx - 0x80000000}h`;
    } else {
      out += `/${idx}`;
    }
  }
  return out + ']';
}

function walletKeyExpression(
  wallet: InstitutionalWallet,
  signerIndex: number,
  branch: DescriptorBranch,
  sigbashPlaceholder: boolean,
  omitOrigin: boolean
): string {
  const signer = wallet.signers[signerIndex];
  let out = '';
  if (signer.origin !== undefined && !omitOrigin) {
    out += originPrefix(signer.origin);
  }
  if (sigbashPlaceholder && signer.kind === 'sigbash_policy_key') {
    out += 'SIGBASH_XPUB';
  } else {
    out += signer.xpub;
  }
  return `${out}/${branch}/*`;
}

export interface CanonicalTextOptions {
  /** Renders the single Sigbash signer as the placeholder (exactly-one rule). */
  sigbashPlaceholder?: boolean;
  /** Omits origin decoration (the fingerprint-committed form). */
  omitOrigin?: boolean;
}

/**
 * Renders the canonical descriptor text for one branch. Network is not part
 * of the descriptor text itself; the network rides the wallet record.
 */
export function canonicalWalletDescriptorText(
  wallet: InstitutionalWallet,
  branch: DescriptorBranch,
  options: CanonicalTextOptions = {}
): string {
  const { sigbashPlaceholder = false, omitOrigin = false } = options;
  if (branch !== 0 && branch !== 1) {
    throw new WalletDescriptorError('branch must be 0 (receive) or 1 (change)');
  }
  const sigbashCount = wallet.signers.filter((s) => s.kind === 'sigbash_policy_key').length;
  if (sigbashPlaceholder && sigbashCount !== 1) {
    throw new WalletDescriptorError(
      `placeholder descriptor text requires exactly one Sigbash signer, wallet carries ${sigbashCount}`
    );
  }

  // Tree-faithful ordering: leaf scripts come from the same construction
  // the tree builder consumes, evaluated at the branch's reference
  // derivation (branch, index 0), and the text presents them in raw
  // TapLeaf-hash ascending order. Two identical leaf hashes would make the
  // tree ambiguous, so they fail closed exactly as the builder does.
  const walletLeafHash = (script: Uint8Array): Uint8Array =>
    taggedHash('TapLeaf', concatBytes(new Uint8Array([TAP_LEAF_VERSION, script.length]), script));

  const leaves: { leafHash: Uint8Array; text: string }[] = [];
  for (const set of wallet.allowedSignerSets) {
    const childKeys = set.map((idx) => {
      const { hd } = parseExtendedPublicKey(wallet.network, wallet.signers[idx].xpub, 'signer xpub');
      return deriveWalletChildKey(hd, branch, 0).slice(1);
    });
    const exprs = set.map((idx) =>
      walletKeyExpression(wallet, idx, branch, sigbashPlaceholder, omitOrigin)
    );
    leaves.push({
      leafHash: walletLeafHash(sortedMultiAScript(childKeys)),
      text: `sortedmulti_a(${exprs.length},${exprs.join(',')})`,
    });
  }
  if (wallet.recovery !== undefined) {
    const keyHex = bytesToHex(wallet.recovery.recoveryKeyXOnly);
    const key = wallet.recovery.recoveryKeyXOnly;
    if (wallet.recovery.alwaysSpendable) {
      leaves.push({ leafHash: walletLeafHash(pkScript(key)), text: `pk(${keyHex})` });
    }
    if (wallet.recovery.decay) {
      leaves.push({
        leafHash: walletLeafHash(decayScript(key, wallet.recovery.decayBlocks)),
        text: `and_v(v:older(${wallet.recovery.decayBlocks}),pk(${keyHex}))`,
      });
    }
  }
  leaves.sort((a, b) => {
    for (let i = 0; i < 32; i++) {
      if (a.leafHash[i] !== b.leafHash[i]) {
        return a.leafHash[i] - b.leafHash[i];
      }
    }
    return 0;
  });
  for (let i = 1; i < leaves.length; i++) {
    if (bytesToHex(leaves[i].leafHash) === bytesToHex(leaves[i - 1].leafHash)) {
      throw new WalletDescriptorError('two leaves share a TapLeaf hash; the tree would be ambiguous');
    }
  }

  const inner =
    leaves.length === 1 ? leaves[0].text : `{${leaves.map((l) => l.text).join(',')}}`;
  return `tr(${WALLET_NUMS_INTERNAL_KEY_HEX},${inner})`;
}

/** Canonical text with its '#' checksum. */
export function canonicalWalletDescriptorTextWithChecksum(
  wallet: InstitutionalWallet,
  branch: DescriptorBranch,
  options: CanonicalTextOptions = {}
): string {
  const text = canonicalWalletDescriptorText(wallet, branch, options);
  return `${text}#${descriptorChecksum(text)}`;
}

/**
 * The origin-less canonical descriptor texts (receive then change) with the
 * network byte prepended exactly as the wallet fingerprint preimage
 * requires. Internal helper for the fingerprint.
 */
export function walletFingerprintPreimageTexts(
  wallet: InstitutionalWallet
): { network: Uint8Array; receive: Uint8Array; change: Uint8Array } {
  return {
    network: utf8(wallet.network),
    receive: utf8(canonicalWalletDescriptorText(wallet, 0, { omitOrigin: true })),
    change: utf8(canonicalWalletDescriptorText(wallet, 1, { omitOrigin: true })),
  };
}

export function fingerprintPreimageBytes(wallet: InstitutionalWallet): Uint8Array {
  const parts = walletFingerprintPreimageTexts(wallet);
  return concatBytes(parts.network, new Uint8Array([0x00]), parts.receive, new Uint8Array([0x00]), parts.change);
}
