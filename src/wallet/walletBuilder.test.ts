/**
 * Canonical wallet construction: normalization determinism and the
 * fail-closed validation matrix. Error-shape expectations mirror the
 * canonical WASM-lane builder's rules (every ambiguity fails closed).
 */

import { HDKey } from '@scure/bip32';

import {
  WALLET_DECAY_BLOCKS_MAX,
  WALLET_DECAY_BLOCKS_MIN,
  WALLET_NUMS_INTERNAL_KEY_HEX,
} from './constants';
import { WalletDescriptorError, WalletXpubError } from './errors';
import {
  buildInstitutionalWalletDescriptor,
  buildSigbashNativeMultisigWallet,
  buildSigbashPlusExternalWallet,
  buildSingleSigbashWallet,
  enumerateWalletSubsets,
  institutionalWalletFromContractRecord,
  type WalletSigner,
} from './walletBuilder';
import { parseWalletSignerOrigin, validateWalletXpubImport } from './xpubImport';
import { walletFingerprintHex } from './walletIdentity';

const SIGNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };

export function seedXpub(byte: number, network: 'signet' | 'mainnet' | 'testnet' = 'signet'): string {
  const versions =
    network === 'mainnet'
      ? { private: 0x0488ade4, public: 0x0488b21e }
      : SIGNET_VERSIONS;
  return HDKey.fromMasterSeed(new Uint8Array(32).fill(byte), versions).publicExtendedKey;
}

function sigbash(byte: number, policyKeyId = 'pk-1'): WalletSigner {
  return { kind: 'sigbash_policy_key', xpub: seedXpub(byte), policyKeyId };
}

function external(byte: number): WalletSigner {
  return { kind: 'external_xpub', xpub: seedXpub(byte) };
}

function recoveryKey(byte: number): Uint8Array {
  return HDKey.fromMasterSeed(new Uint8Array(32).fill(byte), SIGNET_VERSIONS)
    .derive('m/0/0').publicKey!.slice(1);
}

describe('canonical construction', () => {
  it('builds the single-Sigbash wallet and derives both canonical sets', () => {
    const wallet = buildSingleSigbashWallet('signet', sigbash(0x10));
    expect(wallet.signers).toHaveLength(1);
    expect(wallet.allowedSignerSets).toEqual([[0]]);
    expect(wallet.recovery).toBeUndefined();
  });

  it('normalizes signer and set ordering deterministically', () => {
    const a = sigbash(0x11, 'pk-a');
    const b = sigbash(0x12, 'pk-b');
    const c = sigbash(0x13, 'pk-c');
    const forward = buildInstitutionalWalletDescriptor({
      network: 'signet',
      signers: [a, b, c],
      allowedSignerSets: [[1, 2], [0, 1], [0, 2]],
    });
    const reversed = buildInstitutionalWalletDescriptor({
      network: 'signet',
      signers: [c, b, a],
      allowedSignerSets: [[0, 2], [1, 2], [0, 1]],
    });
    expect(forward.signers.map((s) => s.xpub)).toEqual(reversed.signers.map((s) => s.xpub));
    expect(forward.allowedSignerSets).toEqual([[0, 1], [0, 2], [1, 2]]);
    expect(walletFingerprintHex(forward)).toBe(walletFingerprintHex(reversed));
  });

  it('accepts a one-Sigbash wallet as valid', () => {
    expect(() => buildSingleSigbashWallet('signet', sigbash(0x14))).not.toThrow();
  });

  it('Sigbash-native M-of-N enumerates every exact subset (3-of-5 gives ten)', () => {
    const wallet = buildSigbashNativeMultisigWallet(
      'signet',
      [sigbash(0x15, 'a'), sigbash(0x16, 'b'), sigbash(0x17, 'c'), sigbash(0x18, 'd'), sigbash(0x19, 'e')],
      3
    );
    expect(wallet.allowedSignerSets).toHaveLength(10);
  });

  it('Sigbash-native rejects N>5 and M>3', () => {
    const six = [1, 2, 3, 4, 5, 6].map((b) => sigbash(b, `pk-${b}`));
    expect(() => buildSigbashNativeMultisigWallet('signet', six, 3)).toThrow(WalletDescriptorError);
    const five = [1, 2, 3, 4, 5].map((b) => sigbash(b, `pk-${b}`));
    expect(() => buildSigbashNativeMultisigWallet('signet', five, 4)).toThrow(WalletDescriptorError);
  });

  it('mixed template pairs the Sigbash signer with external subsets', () => {
    const wallet = buildSigbashPlusExternalWallet(
      'signet',
      sigbash(0x1a),
      [external(0x1b), external(0x1c), external(0x1d)],
      2
    );
    expect(wallet.signers[0].kind).toBe('sigbash_policy_key');
    expect(wallet.allowedSignerSets).toEqual([[0, 1, 2], [0, 1, 3], [0, 2, 3]]);
  });

  it('enumerateWalletSubsets covers every exact k-subset lexicographically', () => {
    expect(enumerateWalletSubsets(4, 2)).toEqual([[0, 1], [0, 2], [0, 3], [1, 2], [1, 3], [2, 3]]);
    expect(enumerateWalletSubsets(3, 0)).toEqual([[]]);
  });
});

describe('fail-closed construction matrix', () => {
  const base = { network: 'signet' as const };

  it('rejects unknown, empty, and regtest-style networks', () => {
    expect(() => buildInstitutionalWalletDescriptor({ ...base, network: '' as never, signers: [sigbash(0x20)], allowedSignerSets: [[0]] })).toThrow(/explicit/);
    expect(() => buildInstitutionalWalletDescriptor({ ...base, network: 'regtest' as never, signers: [sigbash(0x20)], allowedSignerSets: [[0]] })).toThrow(/unsupported wallet network/);
  });

  it('rejects private extended keys outright', () => {
    const xprv = HDKey.fromMasterSeed(new Uint8Array(32).fill(0x21), SIGNET_VERSIONS).privateExtendedKey;
    expect(() =>
      buildInstitutionalWalletDescriptor({
        ...base,
        signers: [{ kind: 'sigbash_policy_key', xpub: xprv, policyKeyId: 'pk' }],
        allowedSignerSets: [[0]],
      })
    ).toThrow(WalletXpubError);
  });

  it('rejects network-incompatible version bytes (mainnet xpub in a signet wallet)', () => {
    const mainnet = seedXpub(0x22, 'mainnet');
    expect(() =>
      buildInstitutionalWalletDescriptor({
        ...base,
        signers: [{ kind: 'sigbash_policy_key', xpub: mainnet, policyKeyId: 'pk' }],
        allowedSignerSets: [[0]],
      })
    ).toThrow(WalletXpubError);
  });

  it('resolves tpub-class ambiguity from the explicit wallet network, never by guessing', () => {
    // The same tpub-class key is valid for both signet and testnet wallets.
    const tpub = seedXpub(0x23);
    for (const network of ['signet', 'testnet'] as const) {
      expect(() => validateWalletXpubImport(network, tpub)).not.toThrow();
    }
    expect(() => validateWalletXpubImport('mainnet', tpub)).toThrow(/version|valid public extended key/);
  });

  it('rejects duplicate signer xpubs and duplicate policy key references', () => {
    const dup = sigbash(0x24, 'pk-a');
    expect(() =>
      buildInstitutionalWalletDescriptor({
        ...base,
        signers: [dup, { kind: 'sigbash_policy_key', xpub: dup.xpub, policyKeyId: 'pk-b' }],
        allowedSignerSets: [[0]],
      })
    ).toThrow(/duplicate signer xpub/);
    expect(() =>
      buildInstitutionalWalletDescriptor({
        ...base,
        signers: [sigbash(0x25, 'pk-same'), sigbash(0x26, 'pk-same')],
        allowedSignerSets: [[0]],
      })
    ).toThrow(/duplicate Sigbash policy key reference/);
  });

  it('enforces the kind/policyKeyId coherence in both directions', () => {
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: [{ kind: 'sigbash_policy_key', xpub: seedXpub(0x27) }], allowedSignerSets: [[0]] })
    ).toThrow(/policy key reference/);
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: [{ kind: 'external_xpub', xpub: seedXpub(0x28), policyKeyId: 'x' }], allowedSignerSets: [[0]] })
    ).toThrow(/must not carry a policy key reference/);
  });

  it('rejects Sigbash-free, oversized, out-of-range, and repeated signer sets', () => {
    const ext = [external(0x29), external(0x2a)];
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: ext, allowedSignerSets: [[0, 1]] })
    ).toThrow(/no Sigbash policy-bound signer/);
    const sig = sigbash(0x2b);
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: [sig, external(0x2c), external(0x2d), external(0x2e)], allowedSignerSets: [[0, 1, 2, 3]] })
    ).toThrow(/1\.\.3 keys/);
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: [sig], allowedSignerSets: [[1]] })
    ).toThrow(/outside the signer set/);
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: [sig, external(0x2f)], allowedSignerSets: [[0, 1], [0, 1]] })
    ).toThrow(/duplicate allowed signer set/);
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: [sig], allowedSignerSets: [[0], [0]] })
    ).toThrow(/duplicate allowed signer set/);
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: [sig], allowedSignerSets: [] })
    ).toThrow(/at least one allowed signer set/);
  });

  it('rejects a recovery block with no branch, out-of-range decay, or an invalid key', () => {
    const key = recoveryKey(0x30);
    const sig = [sigbash(0x31)];
    const sets = [[0]];
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: sig, allowedSignerSets: sets, recovery: { recoveryKeyXOnly: key, alwaysSpendable: false, decay: false, decayBlocks: 0 } })
    ).toThrow(/neither an always-spendable nor a decay branch/);
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: sig, allowedSignerSets: sets, recovery: { recoveryKeyXOnly: key, alwaysSpendable: true, decay: true, decayBlocks: WALLET_DECAY_BLOCKS_MAX + 1 } })
    ).toThrow(/decay block count/);
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: sig, allowedSignerSets: sets, recovery: { recoveryKeyXOnly: key, alwaysSpendable: true, decay: true, decayBlocks: WALLET_DECAY_BLOCKS_MIN - 1 } })
    ).toThrow(/decay block count/);
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: sig, allowedSignerSets: sets, recovery: { recoveryKeyXOnly: new Uint8Array(32), alwaysSpendable: true, decay: false, decayBlocks: 0 } })
    ).toThrow(/not a valid x-only public key/);
    // The upper bound itself (65534) is valid; 0xffff is the reserved
    // record-form null marker and can never be a decay count.
    expect(() =>
      buildInstitutionalWalletDescriptor({ ...base, signers: sig, allowedSignerSets: sets, recovery: { recoveryKeyXOnly: key, alwaysSpendable: true, decay: true, decayBlocks: WALLET_DECAY_BLOCKS_MAX } })
    ).not.toThrow();
  });
});

describe('xpub import and origin metadata', () => {
  it('accepts a naked signet tpub and rejects malformed base58 and bad checksums', () => {
    const xpub = seedXpub(0x32);
    expect(() => validateWalletXpubImport('signet', xpub)).not.toThrow();
    expect(() => validateWalletXpubImport('signet', xpub.slice(0, -2) + 'zz')).toThrow(WalletXpubError);
    expect(() => validateWalletXpubImport('signet', 'notAnExtendedKey')).toThrow(WalletXpubError);
  });

  it('rejects SLIP-132 ypub-class keys instead of guessing the network', () => {
    // A real ypub (P2WPKH-in-P2SH account key, mainnet) is never a wallet root.
    const ypub =
      'ypub6Ww33ife7438DC9Wpp6vBzjzpx6jP9jjMbDDBbME5JC7tLyPjSUrxHm#invalid';
    expect(() => validateWalletXpubImport('mainnet', ypub)).toThrow(WalletXpubError);
  });

  it('parses origin metadata verbatim with hardened markers and rejects bad input', () => {
    const origin = parseWalletSignerOrigin('deadbeef', "m/84'/0'/0'");
    expect(Array.from(origin.masterFingerprint)).toEqual([0xde, 0xad, 0xbe, 0xef]);
    expect(origin.path).toEqual([84 + 0x80000000, 0x80000000, 0x80000000]);
    expect(parseWalletSignerOrigin('deadbeef', '').path).toEqual([]);
    expect(parseWalletSignerOrigin('deadbeef', '1h/2H/3\'').path).toEqual([
      1 + 0x80000000,
      2 + 0x80000000,
      3 + 0x80000000,
    ]);
    expect(() => parseWalletSignerOrigin('abc', '')).toThrow(/8 hex characters/);
    expect(() => parseWalletSignerOrigin('zzzzzzzz', '')).toThrow(/not valid hex/);
    expect(() => parseWalletSignerOrigin('deadbeef', "2147483648'")).toThrow(/already encodes a hardened index/);
    expect(() => parseWalletSignerOrigin('deadbeef', 'm//1')).toThrow(/malformed/);
    expect(() => parseWalletSignerOrigin('deadbeef', `1/${'0/'.repeat(255)}0`)).toThrow(/components/);
  });
});

describe('contract record conversion', () => {
  it('builds a canonical wallet from a versioned wallet record', () => {
    const wallet = institutionalWalletFromContractRecord({
      network: 'signet',
      walletMode: 'sigbash_native',
      signers: [sigbash(0x33, 'pk-one'), sigbash(0x34, 'pk-two'), sigbash(0x35, 'pk-three')],
      allowedSignerSets: [{ signerIndexes: [0, 1] }, { signerIndexes: [0, 2] }, { signerIndexes: [1, 2] }],
    });
    expect(wallet.allowedSignerSets).toHaveLength(3);
  });

  it('rejects a sigbash_native record carrying external roots', () => {
    expect(() =>
      institutionalWalletFromContractRecord({
        network: 'signet',
        walletMode: 'sigbash_native',
        signers: [sigbash(0x36), external(0x37)],
        allowedSignerSets: [{ signerIndexes: [0, 1] }],
      })
    ).toThrow(/carries external signer roots/);
  });

  it('maps a recovery block; the record form cannot express a 65535-block decay', () => {
    const wallet = institutionalWalletFromContractRecord({
      network: 'signet',
      walletMode: 'sigbash_native',
      signers: [sigbash(0x38)],
      allowedSignerSets: [{ signerIndexes: [0] }],
      recovery: { recoveryKeyXOnly: recoveryKey(0x39), decayBlocks: 144 },
    });
    expect(wallet.recovery).toEqual({
      recoveryKeyXOnly: recoveryKey(0x39),
      alwaysSpendable: true,
      decay: true,
      decayBlocks: 144,
    });
  });
});

describe('format constants', () => {
  it('pins the NUMS internal key to the BIP-341 test-vector value', () => {
    expect(WALLET_NUMS_INTERNAL_KEY_HEX).toBe(
      '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
    );
  });
});
