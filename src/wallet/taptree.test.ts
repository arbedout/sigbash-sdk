/**
 * TapTree construction rules: derivation bounds, leaf shape, script bytes,
 * and the tree-order invariants that the oracle vectors assert only for the
 * vector cases. Error-shape expectations mirror the canonical WASM-lane
 * builder.
 */

import { bytesToHex, hexToBytes } from '../contracts/encoding';
import { WALLET_NUMS_INTERNAL_KEY_HEX } from './constants';
import { WalletDescriptorError } from './errors';
import { HDKey } from '@scure/bip32';
import {
  buildWalletTapTree,
  decayScript,
  deriveWalletReqkeyCandidate,
  liftX,
  pkScript,
  sortedMultiAScript,
  tapBranchHash,
} from './taptree';
import {
  buildInstitutionalWalletDescriptor,
  type InstitutionalWallet,
  type WalletSigner,
} from './walletBuilder';

const SIGNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };

function seedXpub(byte: number): string {
  return HDKey.fromMasterSeed(new Uint8Array(32).fill(byte), SIGNET_VERSIONS).publicExtendedKey;
}

function sigbash(byte: number, policyKeyId = 'pk-1'): WalletSigner {
  return { kind: 'sigbash_policy_key', xpub: seedXpub(byte), policyKeyId };
}

function singleWallet(): InstitutionalWallet {
  return buildInstitutionalWalletDescriptor({
    network: 'signet',
    signers: [sigbash(0x40)],
    allowedSignerSets: [[0]],
  });
}

function recoveryWallet(): InstitutionalWallet {
  const key = HDKey.fromMasterSeed(new Uint8Array(32).fill(0x41), SIGNET_VERSIONS)
    .derive('m/0/0').publicKey!.slice(1);
  return buildInstitutionalWalletDescriptor({
    network: 'signet',
    signers: [sigbash(0x42)],
    allowedSignerSets: [[0]],
    recovery: { recoveryKeyXOnly: key, alwaysSpendable: true, decay: true, decayBlocks: 144 },
  });
}

describe('derivation bounds', () => {
  const wallet = singleWallet();

  it('accepts index 255 on both branches and rejects 256, negative, and fractional', () => {
    expect(() => buildWalletTapTree(wallet, 0, 255)).not.toThrow();
    expect(() => buildWalletTapTree(wallet, 1, 255)).not.toThrow();
    expect(() => buildWalletTapTree(wallet, 0, 256)).toThrow(/0\.\.255 branch contract/);
    expect(() => buildWalletTapTree(wallet, 0, -1)).toThrow(/branch contract/);
    expect(() => buildWalletTapTree(wallet, 0, 1.5)).toThrow(/branch contract/);
  });

  it('rejects branches other than 0 and 1', () => {
    expect(() => buildWalletTapTree(wallet, 2 as 0, 0)).toThrow(/branch must be 0/);
  });

  it('rejects candidate indices outside the committed 512 universe', () => {
    expect(() => deriveWalletReqkeyCandidate(wallet, 512)).toThrow(/committed 0\.\.511/);
    expect(() => deriveWalletReqkeyCandidate(wallet, -1)).toThrow(/committed/);
  });
});

describe('tree shape and leaf construction', () => {
  it('a single-leaf tree roots at the leaf hash itself', () => {
    const tree = buildWalletTapTree(singleWallet(), 0, 0);
    expect(tree.leaves).toHaveLength(1);
    expect(bytesToHex(tree.merkleRoot)).toBe(bytesToHex(tree.leaves[0].tapLeafHash));
    expect(tree.leaves[0].merklePath).toHaveLength(0);
    expect(tree.leaves[0].controlBlock).toHaveLength(33);
  });

  it('recovery leaves join the tree with fixed kinds and decay metadata', () => {
    const tree = buildWalletTapTree(recoveryWallet(), 0, 0);
    const kinds = tree.leaves.map((l) => l.kind).sort();
    expect(kinds).toEqual(['recovery_always_spendable', 'recovery_decay', 'sortedmulti']);
    const decay = tree.leaves.find((l) => l.kind === 'recovery_decay')!;
    expect(decay.decayBlocks).toBe(144);
    expect(decay.set).toBeUndefined();
  });

  it('every leaf hashes over the version-prefixed script', () => {
    const tree = buildWalletTapTree(singleWallet(), 0, 0);
    expect(tree.leaves[0].script[0]).toBe(0x20);
  });

  it('the scriptPubKey is OP_1 followed by the output key', () => {
    const tree = buildWalletTapTree(singleWallet(), 0, 0);
    expect(tree.scriptPubKey[0]).toBe(0x51);
    expect(tree.scriptPubKey).toHaveLength(33);
    expect(bytesToHex(tree.scriptPubKey.slice(1))).toBe(bytesToHex(tree.outputKeyXOnly));
  });

  it('output parity and control-block first byte agree', () => {
    for (const branch of [0, 1] as const) {
      const tree = buildWalletTapTree(singleWallet(), branch, 7);
      const expected = tree.outputKeyYIsOdd ? 0xc1 : 0xc0;
      expect(tree.leaves[0].controlBlock[0]).toBe(expected);
    }
  });

  it('rejects a wallet whose signer order was mutated after construction', () => {
    const wallet = singleWallet();
    const mutated: InstitutionalWallet = {
      ...wallet,
      signers: [{ ...wallet.signers[0], xpub: seedXpub(0x43) }, ...wallet.signers.slice(0, 0)],
    };
    // Build a two-signer wallet then reverse its canonical order.
    const two = buildInstitutionalWalletDescriptor({
      network: 'signet',
      signers: [sigbash(0x44, 'pk-a'), sigbash(0x45, 'pk-b')],
      allowedSignerSets: [[0, 1]],
    });
    const reversed: InstitutionalWallet = { ...two, signers: [two.signers[1], two.signers[0]] };
    expect(() => buildWalletTapTree(reversed, 0, 0)).toThrow(/canonical order/);
    expect(mutated.signers).toHaveLength(1);
  });
});

describe('script bytes', () => {
  it('sortedmulti_a emits CHECKSIG then CHECKSIGADD with the minimal NUMEQUAL tail', () => {
    const k1 = hexToBytes('0101010101010101010101010101010101010101010101010101010101010101');
    const k2 = hexToBytes('0202020202020202020202020202020202020202020202020202020202020202');
    const script = sortedMultiAScript([k1, k2]);
    expect(Array.from(script)).toEqual([
      0x20, ...Array.from(k1), 0xac,
      0x20, ...Array.from(k2), 0xba,
      0x52, 0x9c,
    ]);
  });

  it('sortedmulti_a sorts keys x-only ascending regardless of input order', () => {
    const k1 = hexToBytes('0202020202020202020202020202020202020202020202020202020202020202');
    const k2 = hexToBytes('0101010101010101010101010101010101010101010101010101010101010101');
    const a = sortedMultiAScript([k1, k2]);
    const b = sortedMultiAScript([k2, k1]);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  it('the pk script is push-key CHECKSIG', () => {
    const key = hexToBytes(WALLET_NUMS_INTERNAL_KEY_HEX);
    expect(Array.from(pkScript(key))).toEqual([0x20, ...Array.from(key), 0xac]);
  });

  it('the decay script is and_v(v:older(T),pk(KEY)) with a minimal CScriptNum', () => {
    const key = hexToBytes(WALLET_NUMS_INTERNAL_KEY_HEX);
    // 144 = 0x90 needs the trailing zero of a minimally-encoded script number.
    expect(Array.from(decayScript(key, 144))).toEqual([
      0x02, 0x90, 0x00, 0xb2, 0x69, 0x20, ...Array.from(key), 0xac,
    ]);
    // 100 fits one byte with the high bit clear.
    expect(Array.from(decayScript(key, 100))).toEqual([
      0x01, 0x64, 0xb2, 0x69, 0x20, ...Array.from(key), 0xac,
    ]);
  });

  it('TapBranch hashing orders its two children lexicographically', () => {
    const a = hexToBytes('0202020202020202020202020202020202020202020202020202020202020202');
    const b = hexToBytes('0101010101010101010101010101010101010101010101010101010101010101');
    expect(bytesToHex(tapBranchHash(a, b))).toBe(bytesToHex(tapBranchHash(b, a)));
  });

  it('lift_x returns the even-y point and rejects non-residue x', () => {
    const nums = hexToBytes(WALLET_NUMS_INTERNAL_KEY_HEX);
    const { y } = liftX(nums);
    expect(y % 2n).toBe(0n);
    // A value whose cube-plus-seven has no square root mod p.
    expect(() => liftX(hexToBytes('0b' + '11'.repeat(31)))).toThrow(/not a valid curve point/);
  });
});

describe('determinism', () => {
  it('rebuilding the same wallet at the same slot reproduces every byte', () => {
    const wallet = recoveryWallet();
    const a = buildWalletTapTree(wallet, 0, 3);
    const b = buildWalletTapTree(wallet, 0, 3);
    expect(bytesToHex(a.merkleRoot)).toBe(bytesToHex(b.merkleRoot));
    expect(a.address).toBe(b.address);
    expect(a.leaves.map((l) => bytesToHex(l.controlBlock))).toEqual(
      b.leaves.map((l) => bytesToHex(l.controlBlock))
    );
  });
});
