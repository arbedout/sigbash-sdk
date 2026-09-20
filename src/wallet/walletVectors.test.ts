/**
 * Golden-vector parity tests: every derived value asserted here comes from
 * the independent Python oracle (stdlib-only secp256k1/BIP-32/BIP-341/
 * bech32m/checksum implementation, separately validated against btcd), never
 * from the code under test. These vectors are the drift guard between this
 * TypeScript mirror and the canonical WASM-lane builder, whose own native
 * tests re-derive the same values Go-side.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { tapBranchHash } from './taptree';
import {
  buildInstitutionalWalletDescriptor,
  type InstitutionalWallet,
  type WalletRecoveryBranches,
  type WalletSigner,
} from './walletBuilder';
import { buildWalletTapTree } from './taptree';
import { canonicalWalletDescriptorText, canonicalWalletDescriptorTextWithChecksum, descriptorChecksum } from './canonicalText';
import { walletFingerprintHex } from './walletIdentity';
import { deriveWalletReqkeyCandidate } from './taptree';
import vectors from '../contracts/vectors/wallet-descriptor-v1.json';

interface OracleCase {
  name: string;
  network: string;
  xpubs: string[];
  branch: number;
  index: number;
  leaf_scripts_hex: string[];
  merkle_root: string;
  output_key: string;
  output_key_y_is_odd: boolean;
  script_pub_key_hex: string;
  address: string;
  fingerprint: string;
  receive_text_with_checksum: string;
  change_text_with_checksum: string;
  receive_text_originless: string;
  change_text_originless: string;
  recovery: { key: string; always: boolean; decay: boolean; decay_blocks: number } | null;
}

/** Allowed signer sets per oracle case, in the generator's recorded order. */
const CASE_SETS: Record<string, number[][]> = {
  'one-sigbash': [[0]],
  'sigbash-native-2-of-3': [
    [0, 1],
    [0, 2],
    [1, 2],
  ],
  'sigbash-native-3-of-5': [
    [0, 1, 2],
    [0, 1, 3],
    [0, 1, 4],
    [0, 2, 3],
    [0, 2, 4],
    [0, 3, 4],
    [1, 2, 3],
    [1, 2, 4],
    [1, 3, 4],
    [2, 3, 4],
  ],
  'mixed-1-plus-2-of-4': [
    [0, 1, 2],
    [0, 1, 3],
    [0, 1, 4],
    [0, 2, 3],
    [0, 2, 4],
    [0, 3, 4],
  ],
  'recovery-decay': [[0]],
  'sparrow-importable': [[0]],
};

const ALL_SIGBASH = new Set([
  'one-sigbash',
  'sigbash-native-2-of-3',
  'sigbash-native-3-of-5',
  'recovery-decay',
  'sparrow-importable',
]);

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function buildOracleWallet(c: OracleCase): InstitutionalWallet {
  const signers: WalletSigner[] = c.xpubs.map((xpub, i) => {
    const sigbash = ALL_SIGBASH.has(c.name) || i === 0;
    const origin =
      c.name === 'sparrow-importable' && i === 0
        ? {
            masterFingerprint: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
            path: [84 + 0x80000000, 0x80000000, 0x80000000],
          }
        : undefined;
    return {
      kind: sigbash ? ('sigbash_policy_key' as const) : ('external_xpub' as const),
      xpub,
      ...(sigbash ? { policyKeyId: `pk-${i}` } : {}),
      ...(origin ? { origin } : {}),
    };
  });
  const recovery: WalletRecoveryBranches | undefined = c.recovery
    ? {
        recoveryKeyXOnly: new Uint8Array(Buffer.from(c.recovery.key, 'hex')),
        alwaysSpendable: c.recovery.always,
        decay: c.recovery.decay,
        decayBlocks: c.recovery.decay_blocks,
      }
    : undefined;
  return buildInstitutionalWalletDescriptor({
    network: c.network as InstitutionalWallet['network'],
    signers,
    allowedSignerSets: CASE_SETS[c.name],
    ...(recovery ? { recovery } : {}),
  });
}

describe('wallet descriptor oracle vectors', () => {
  const cases = vectors.cases as unknown as OracleCase[];

  it.each(cases.map((c) => [c.name, c] as const))('case %s matches byte-for-byte', (_, c) => {
    const wallet = buildOracleWallet(c);

    expect(canonicalWalletDescriptorText(wallet, 0, { omitOrigin: true })).toBe(c.receive_text_originless);
    expect(canonicalWalletDescriptorText(wallet, 1, { omitOrigin: true })).toBe(c.change_text_originless);
    expect(canonicalWalletDescriptorTextWithChecksum(wallet, 0)).toBe(c.receive_text_with_checksum);
    expect(canonicalWalletDescriptorTextWithChecksum(wallet, 1)).toBe(c.change_text_with_checksum);
    expect(walletFingerprintHex(wallet)).toBe(c.fingerprint);

    const tree = buildWalletTapTree(wallet, c.branch as 0 | 1, c.index);
    expect(toHex(tree.merkleRoot)).toBe(c.merkle_root);
    expect(toHex(tree.outputKeyXOnly)).toBe(c.output_key);
    expect(tree.outputKeyYIsOdd).toBe(c.output_key_y_is_odd);
    expect(tree.address).toBe(c.address);
    expect(toHex(tree.scriptPubKey)).toBe(c.script_pub_key_hex);
    expect(tree.leaves.map((l) => toHex(l.script))).toEqual(c.leaf_scripts_hex);
  });

  it('pins the Bitcoin Core descriptor checksum reference pair', () => {
    expect('raw(deadbeef)#' + descriptorChecksum('raw(deadbeef)')).toBe('raw(deadbeef)#89f8spxm');
  });

  it('control blocks fold back to the Merkle root independently of the builder', () => {
    for (const c of cases) {
      const wallet = buildOracleWallet(c);
      const tree = buildWalletTapTree(wallet, c.branch as 0 | 1, c.index);
      const firstByte = 0xc0 | (tree.outputKeyYIsOdd ? 1 : 0);
      for (const leaf of tree.leaves) {
        let acc = new Uint8Array(leaf.tapLeafHash);
        for (const sibling of leaf.merklePath) {
          acc = tapBranchHash(acc, sibling);
        }
        expect(toHex(acc)).toBe(c.merkle_root);
        expect(leaf.controlBlock.length).toBe(33 + 32 * leaf.merklePath.length);
        expect(leaf.controlBlock[0]).toBe(firstByte);
        expect(toHex(leaf.controlBlock.slice(1, 33))).toBe(
          '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
        );
      }
    }
  });
});

describe('cross-implementation sync fixture (pinned by the native builder tests)', () => {
  const fixtureXpubs = [
    'tpubD6NzVbkrYhZ4Wgf68pWWfTRzdXMoepBvepfiAKtNoE7RvbAbWVfWzQxH1jbkfNk3iJ9zR65Yw6u3B2QZzpkMSTN4y8Lfm1t44HbpZX7efhZ',
    'tpubD6NzVbkrYhZ4XAhKE5b3VVtF4kipaPAEwhcF7e54zMkPoGh5C5rZFnpV4PMfB8gHhgqEK6hQZynZWbQWLiR2hhMohdfoBSzxG6NfD8F58rE',
    'tpubD6NzVbkrYhZ4Y3qD9tjwWFRv4AdyPdscx4wKXiywhgTXUeytmGtsEMiSJaXs9kqyYdPaKQv9tir5J2cDg2Fm3vaudETvLADYLLY4Vb7kMU4',
  ];

  function fixtureWallet(): InstitutionalWallet {
    return buildInstitutionalWalletDescriptor({
      network: 'signet',
      signers: fixtureXpubs.map((xpub, i) => ({
        kind: 'sigbash_policy_key' as const,
        xpub,
        policyKeyId: `pk-sync-${i}`,
      })),
      allowedSignerSets: [
        [0, 1],
        [0, 2],
        [1, 2],
      ],
    });
  }

  it('reproduces the pinned wallet fingerprint', () => {
    expect(walletFingerprintHex(fixtureWallet())).toBe(
      'f2dad558c741b1aa3b95c4deef9189db627147304f17cd1e2607f729f78a7a57'
    );
  });

  it('reproduces the pinned receive/change addresses at several indices', () => {
    const wallet = fixtureWallet();
    expect(buildWalletTapTree(wallet, 0, 0).address).toBe(
      'tb1pmcvjlxgervv4artga2etngejm9fwncq8am45sd487sscmyh9yk2q2wf6ex'
    );
    expect(buildWalletTapTree(wallet, 1, 0).address).toBe(
      'tb1pwhzde0d5p0snggmedgyvn48pst7dqehv44eem709qcjwdkpumevslvukk3'
    );
    expect(buildWalletTapTree(wallet, 0, 15).address).toBe(
      'tb1purq2phqg5muxm4afv89va3qglf5z3auqw6ajnruqpqrczqz34g8slryruy'
    );
  });

  it('maps REQKEY candidates receive-then-change with a genuine branch boundary', () => {
    const wallet = fixtureWallet();
    expect(toHex(deriveWalletReqkeyCandidate(wallet, 0))).toBe(
      toHex(buildWalletTapTree(wallet, 0, 0).outputKeyXOnly)
    );
    expect(toHex(deriveWalletReqkeyCandidate(wallet, 255))).toBe(
      toHex(buildWalletTapTree(wallet, 0, 255).outputKeyXOnly)
    );
    expect(toHex(deriveWalletReqkeyCandidate(wallet, 256))).toBe(
      toHex(buildWalletTapTree(wallet, 1, 0).outputKeyXOnly)
    );
    expect(toHex(deriveWalletReqkeyCandidate(wallet, 511))).toBe(
      toHex(buildWalletTapTree(wallet, 1, 255).outputKeyXOnly)
    );
    expect(toHex(deriveWalletReqkeyCandidate(wallet, 255))).not.toBe(
      toHex(deriveWalletReqkeyCandidate(wallet, 256))
    );
  });
});

describe('vector fixture integrity', () => {
  it('the fixture file lives beside the other golden vectors', () => {
    const raw = readFileSync(join(__dirname, '../contracts/vectors/wallet-descriptor-v1.json'), 'utf8');
    const doc = JSON.parse(raw);
    expect(doc.generator).toContain('wallet_vector_reference_generator.py');
    expect(doc.cases).toHaveLength(6);
  });
});
