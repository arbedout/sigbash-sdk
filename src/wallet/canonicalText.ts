/**
 * Canonical descriptor text view over a built institutional wallet.
 *
 * The text is a view, never an independent source. Leaf order is fixed and
 * index-independent: sortedmulti_a leaves by ascending signer-index tuple,
 * then the always-spendable recovery leaf, then the decay leaf. This same
 * ordering commits into the wallet fingerprint (in its origin-less form),
 * so changing the text order is a wallet-identity format change.
 */

import { bytesToHex, concatBytes, utf8 } from '../contracts/encoding';
import { WALLET_NUMS_INTERNAL_KEY_HEX } from './constants';
import { WalletDescriptorError } from './errors';
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

  const leaves: { orderKey: number[]; text: string }[] = [];
  for (const set of wallet.allowedSignerSets) {
    const exprs = set.map((idx) =>
      walletKeyExpression(wallet, idx, branch, sigbashPlaceholder, omitOrigin)
    );
    leaves.push({
      orderKey: [0x00, ...set],
      text: `sortedmulti_a(${exprs.length},${exprs.join(',')})`,
    });
  }
  if (wallet.recovery !== undefined) {
    const keyHex = bytesToHex(wallet.recovery.recoveryKeyXOnly);
    if (wallet.recovery.alwaysSpendable) {
      leaves.push({ orderKey: [0x01, 0x00], text: `pk(${keyHex})` });
    }
    if (wallet.recovery.decay) {
      leaves.push({
        orderKey: [0x01, 0x01],
        text: `and_v(v:older(${wallet.recovery.decayBlocks}),pk(${keyHex}))`,
      });
    }
  }
  leaves.sort((a, b) => {
    for (let i = 0; i < Math.min(a.orderKey.length, b.orderKey.length); i++) {
      if (a.orderKey[i] !== b.orderKey[i]) {
        return a.orderKey[i] - b.orderKey[i];
      }
    }
    return a.orderKey.length - b.orderKey.length;
  });

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
