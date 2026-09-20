/**
 * Deterministic multi-leaf TapTree construction over the BIP-341 NUMS
 * internal key — the TypeScript mirror of the canonical WASM-lane builder.
 *
 * Invariants:
 *  - The internal key is always the NUMS constant; there is no key-path
 *    spend and no key-path material anywhere in the output.
 *  - Leaf scripts sort their derived x-only keys once; canonical signer
 *    ordering drives subset enumeration, never script-key ordering.
 *  - Leaves are ordered by raw 32-byte TapLeaf hash ascending and the tree
 *    is the balanced split of that ordered list at ceil(len/2).
 *  - The branch contract is /0/i and /1/i with index 0..255 on both
 *    branches; anything else fails closed before any derivation happens.
 */

import { bech32m } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1.js';

import { bytesToHex, concatBytes, hexToBytes, taggedHash } from '../contracts/encoding';
import {
  TAP_LEAF_VERSION,
  WALLET_BRANCH_CHANGE,
  WALLET_BRANCH_RECEIVE,
  WALLET_CANDIDATES_PER_BRANCH,
  WALLET_MAX_DERIVATION_INDEX,
  WALLET_NETWORK_PARAMS,
  WALLET_NUMS_INTERNAL_KEY_HEX,
  WALLET_REQKEY_CANDIDATE_COUNT,
  WALLET_TAPTREE_MAX_DEPTH,
} from './constants';
import { WalletDescriptorError } from './errors';
import {
  canonicalWalletDescriptorText,
  type DescriptorBranch,
} from './canonicalText';
import type { InstitutionalWallet } from './walletBuilder';
import { deriveWalletChildKey, parseExtendedPublicKey } from './xpubImport';

const P = 2n ** 256n - 2n ** 32n - 977n;

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) {
      result = (result * b) % mod;
    }
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

/** BIP-340 lift_x: the even-y point with the given x-coordinate. */
export function liftX(xBytes: Uint8Array): { x: bigint; y: bigint } {
  if (xBytes.length !== 32) {
    throw new WalletDescriptorError('x-only key must be 32 bytes');
  }
  let x = 0n;
  for (const b of xBytes) {
    x = (x << 8n) | BigInt(b);
  }
  if (x >= P) {
    throw new WalletDescriptorError('x-only key is not a valid curve point');
  }
  const c = (x * x * x + 7n) % P;
  const y = modPow(c, (P + 1n) / 4n, P);
  if ((y * y) % P !== c) {
    throw new WalletDescriptorError('x-only key is not a valid curve point');
  }
  return { x, y: y % 2n === 0n ? y : P - y };
}

function numberToBytes32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function pointToXOnly(point: { x: bigint }): Uint8Array {
  return numberToBytes32(point.x);
}

function tapLeafHash(script: Uint8Array): Uint8Array {
  return taggedHash('TapLeaf', concatBytes(new Uint8Array([TAP_LEAF_VERSION, script.length]), script));
}

/** BIP-341 lexicographic TapBranch hashing. */
export function tapBranchHash(a: Uint8Array, b: Uint8Array): Uint8Array {
  let aFirst = false;
  for (let i = 0; i < 32; i++) {
    if (a[i] !== b[i]) {
      aFirst = a[i] < b[i];
      break;
    }
  }
  const lo = aFirst ? a : b;
  const hi = aFirst ? b : a;
  return taggedHash('TapBranch', concatBytes(lo, hi));
}

function tapTweak(internal: Uint8Array, root: Uint8Array): Uint8Array {
  return taggedHash('TapTweak', concatBytes(internal, root));
}

function scriptNumMinimal(value: number): Uint8Array {
  if (value === 0) {
    return new Uint8Array(0);
  }
  const out: number[] = [];
  let v = value;
  while (v > 0) {
    out.push(v & 0xff);
    v >>= 8;
  }
  if (out[out.length - 1] & 0x80) {
    out.push(0);
  }
  return new Uint8Array(out);
}

const OP_CHECKSIG = 0xac;
const OP_CHECKSIGADD = 0xba;
const OP_CHECKSEQUENCEVERIFY = 0xb2;
const OP_VERIFY = 0x69;
const OP_NUMEQUAL = 0x9c;

/** All-keys-required sortedmulti_a over pre-sorted x-only keys. */
export function sortedMultiAScript(xOnlyKeys: Uint8Array[]): Uint8Array {
  const keys = [...xOnlyKeys].sort((a, b) => {
    for (let i = 0; i < 32; i++) {
      if (a[i] !== b[i]) {
        return a[i] - b[i];
      }
    }
    return 0;
  });
  const parts: Uint8Array[] = [];
  for (let i = 0; i < keys.length; i++) {
    parts.push(new Uint8Array([0x20]), keys[i], new Uint8Array([i === 0 ? OP_CHECKSIG : OP_CHECKSIGADD]));
  }
  parts.push(new Uint8Array([0x50 + keys.length, OP_NUMEQUAL]));
  return concatBytes(...parts);
}

export function pkScript(key: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([0x20]), key, new Uint8Array([OP_CHECKSIG]));
}

/** and_v(v:older(T),pk(KEY)) with minimal CScriptNum T. */
export function decayScript(key: Uint8Array, blocks: number): Uint8Array {
  const num = scriptNumMinimal(blocks);
  return concatBytes(
    new Uint8Array([num.length]),
    num,
    new Uint8Array([OP_CHECKSEQUENCEVERIFY, OP_VERIFY]),
    new Uint8Array([0x20]),
    key,
    new Uint8Array([OP_CHECKSIG])
  );
}

export type WalletTapLeafKind = 'sortedmulti' | 'recovery_always_spendable' | 'recovery_decay';

export interface WalletTapLeaf {
  kind: WalletTapLeafKind;
  /** Ascending signer-index tuple for sortedmulti_a leaves; absent for recovery leaves. */
  set?: number[];
  script: Uint8Array;
  tapLeafHash: Uint8Array;
  /** Sibling node hashes leaf-to-root, each 32 bytes. */
  merklePath: Uint8Array[];
  controlBlock: Uint8Array;
  /** CSV block count for the decay leaf; absent otherwise. */
  decayBlocks?: number;
}

export interface WalletTapTree {
  branch: DescriptorBranch;
  index: number;
  merkleRoot: Uint8Array;
  outputKeyXOnly: Uint8Array;
  outputKeyYIsOdd: boolean;
  scriptPubKey: Uint8Array;
  address: string;
  leaves: WalletTapLeaf[];
  descriptorText: string;
}

function outputPoint(internal: Uint8Array, root: Uint8Array): { xOnly: Uint8Array; yIsOdd: boolean } {
  const t = BigInt('0x' + bytesToHex(tapTweak(internal, root)));
  if (t >= secp256k1.Point.Fn.ORDER) {
    throw new WalletDescriptorError('tap tweak exceeds the group order');
  }
  const { x, y } = liftX(internal);
  const q = secp256k1.Point.fromAffine({ x, y }).add(secp256k1.Point.BASE.multiply(t));
  if (q.is0()) {
    throw new WalletDescriptorError('tweaked output key is the point at infinity');
  }
  const aff = q.toAffine();
  return { xOnly: pointToXOnly(aff), yIsOdd: aff.y % 2n === 1n };
}

function p2trAddress(network: InstitutionalWallet['network'], outputKey: Uint8Array): string {
  const hrp = WALLET_NETWORK_PARAMS[network].hrp;
  return bech32m.encode(hrp, [1, ...bech32m.toWords(outputKey)]);
}

function buildLeaves(wallet: InstitutionalWallet, branch: DescriptorBranch, index: number): WalletTapLeaf[] {
  // Allowed-set indices bind to the canonical signer order; a reordered
  // signer list is construction-time drift and fails closed here.
  for (let i = 1; i < wallet.signers.length; i++) {
    const a = wallet.signers[i - 1];
    const b = wallet.signers[i];
    const kindRank = (s: typeof a) => (s.kind === 'sigbash_policy_key' ? 1 : 2);
    if (
      kindRank(a) > kindRank(b) ||
      (kindRank(a) === kindRank(b) && (a.xpub > b.xpub || (a.xpub === b.xpub && (a.policyKeyId ?? '') > (b.policyKeyId ?? ''))))
    ) {
      throw new WalletDescriptorError('wallet signers are not in canonical order; the descriptor was mutated after construction');
    }
  }

  const childKeys: Uint8Array[] = wallet.signers.map((signer, i) => {
    const { hd } = parseExtendedPublicKey(wallet.network, signer.xpub, 'signer xpub');
    let compressed: Uint8Array;
    try {
      compressed = deriveWalletChildKey(hd, branch, index);
    } catch {
      throw new WalletDescriptorError(`signer ${i} has an unparseable extended public key or cannot derive at the branch/index`);
    }
    return compressed.slice(1);
  });

  const leaves: WalletTapLeaf[] = [];
  for (const set of wallet.allowedSignerSets) {
    const keys = set.map((idx) => childKeys[idx]);
    const sorted = [...keys].sort((a, b) => {
      for (let i = 0; i < 32; i++) {
        if (a[i] !== b[i]) {
          return a[i] - b[i];
        }
      }
      return 0;
    });
    for (let k = 1; k < sorted.length; k++) {
      if (bytesToHex(sorted[k - 1]) === bytesToHex(sorted[k])) {
        throw new WalletDescriptorError('allowed signer set derives a duplicated child key at this index');
      }
    }
    leaves.push({
      kind: 'sortedmulti',
      set: [...set],
      script: sortedMultiAScript(sorted),
      tapLeafHash: new Uint8Array(0),
      merklePath: [],
      controlBlock: new Uint8Array(0),
    });
  }
  if (wallet.recovery !== undefined) {
    const key = wallet.recovery.recoveryKeyXOnly;
    if (wallet.recovery.alwaysSpendable) {
      leaves.push({
        kind: 'recovery_always_spendable',
        script: pkScript(key),
        tapLeafHash: new Uint8Array(0),
        merklePath: [],
        controlBlock: new Uint8Array(0),
      });
    }
    if (wallet.recovery.decay) {
      leaves.push({
        kind: 'recovery_decay',
        script: decayScript(key, wallet.recovery.decayBlocks),
        tapLeafHash: new Uint8Array(0),
        merklePath: [],
        controlBlock: new Uint8Array(0),
        decayBlocks: wallet.recovery.decayBlocks,
      });
    }
  }
  for (const leaf of leaves) {
    leaf.tapLeafHash = tapLeafHash(leaf.script);
  }
  return leaves;
}

/**
 * Derives the deterministic multi-leaf TapTree for the wallet at
 * branch/index. Revalidates canonical order, derives every signer child,
 * builds one leaf per allowed signer set plus the recovery/decay leaves,
 * orders by TapLeaf hash, and tweaks the NUMS internal key by the balanced
 * split tree root.
 */
export function buildWalletTapTree(
  wallet: InstitutionalWallet,
  branch: DescriptorBranch,
  index: number
): WalletTapTree {
  if (branch !== WALLET_BRANCH_RECEIVE && branch !== WALLET_BRANCH_CHANGE) {
    throw new WalletDescriptorError('branch must be 0 (receive) or 1 (change)');
  }
  if (!Number.isInteger(index) || index < 0 || index > WALLET_MAX_DERIVATION_INDEX) {
    throw new WalletDescriptorError(
      `derivation index ${index} outside the 0..${WALLET_MAX_DERIVATION_INDEX} branch contract`
    );
  }

  const leaves = buildLeaves(wallet, branch, index);

  // Hash-ascending leaf order; identical hashes fail closed (ambiguous
  // sibling-side assignment).
  leaves.sort((a, b) => {
    for (let i = 0; i < 32; i++) {
      if (a.tapLeafHash[i] !== b.tapLeafHash[i]) {
        return a.tapLeafHash[i] - b.tapLeafHash[i];
      }
    }
    return 0;
  });
  for (let i = 1; i < leaves.length; i++) {
    if (bytesToHex(leaves[i].tapLeafHash) === bytesToHex(leaves[i - 1].tapLeafHash)) {
      throw new WalletDescriptorError('two leaves share a TapLeaf hash; the tree would be ambiguous');
    }
  }

  // Balanced tree via ceil(len/2) splits; sibling hashes recorded
  // leaf-to-root as the recursion unwinds.
  let root: Uint8Array;
  if (leaves.length === 1) {
    root = leaves[0].tapLeafHash;
  } else {
    const split = (lo: number, hi: number, depth: number): Uint8Array => {
      if (depth > WALLET_TAPTREE_MAX_DEPTH) {
        throw new WalletDescriptorError('tap tree exceeds the consensus Merkle depth bound');
      }
      if (hi - lo === 1) {
        return leaves[lo].tapLeafHash;
      }
      const mid = lo + Math.ceil((hi - lo) / 2);
      const left = split(lo, mid, depth + 1);
      const right = split(mid, hi, depth + 1);
      for (let i = lo; i < mid; i++) {
        leaves[i].merklePath.push(right);
      }
      for (let i = mid; i < hi; i++) {
        leaves[i].merklePath.push(left);
      }
      return tapBranchHash(left, right);
    };
    root = split(0, leaves.length, 0);
  }

  const numsKey = hexToBytes(WALLET_NUMS_INTERNAL_KEY_HEX);
  const { xOnly: outputKeyXOnly, yIsOdd } = outputPoint(numsKey, root);
  const scriptPubKey = concatBytes(new Uint8Array([0x51]), outputKeyXOnly);
  const address = p2trAddress(wallet.network, outputKeyXOnly);

  for (const leaf of leaves) {
    const proof = concatBytes(...leaf.merklePath);
    leaf.controlBlock = concatBytes(
      new Uint8Array([TAP_LEAF_VERSION | (yIsOdd ? 1 : 0)]),
      numsKey,
      proof
    );
  }

  return {
    branch,
    index,
    merkleRoot: root,
    outputKeyXOnly,
    outputKeyYIsOdd: yIsOdd,
    scriptPubKey,
    address,
    leaves,
    descriptorText: canonicalWalletDescriptorText(wallet, branch),
  };
}

/**
 * One slot of the committed REQKEY candidate universe: i below
 * WALLET_CANDIDATES_PER_BRANCH is receive /0/i, the rest are change
 * /1/(i-256). The committed candidate set and every derived address share
 * the single canonical tree algorithm. Anything outside the committed
 * universe is a hard error, never a silent broadening.
 */
export function deriveWalletReqkeyCandidate(wallet: InstitutionalWallet, candidateIndex: number): Uint8Array {
  if (candidateIndex < 0 || candidateIndex >= WALLET_REQKEY_CANDIDATE_COUNT) {
    throw new WalletDescriptorError(
      `candidate index ${candidateIndex} is outside the committed 0..${WALLET_REQKEY_CANDIDATE_COUNT - 1} wallet universe`
    );
  }
  const branch: DescriptorBranch = candidateIndex < WALLET_CANDIDATES_PER_BRANCH ? 0 : 1;
  const index = candidateIndex < WALLET_CANDIDATES_PER_BRANCH ? candidateIndex : candidateIndex - WALLET_CANDIDATES_PER_BRANCH;
  return buildWalletTapTree(wallet, branch, index).outputKeyXOnly;
}
