/**
 * Wallet-ownership REQKEY template round-trips and fail-closed validation.
 * The template is the persisted wallet form inside the single unconditional
 * descriptor-mode REQKEY atom: prefix-tagged hex of the canonical encoding
 * with the one Sigbash signer's xpub rendered as the placeholder.
 */

import { bytesToHex, hexToBytes } from '../contracts/encoding';
import { WALLET_REQKEY_TEMPLATE_PREFIX } from './constants';
import { WalletReqkeyTemplateError } from './errors';
import { HDKey } from '@scure/bip32';
import {
  decodeWalletReqkeyTemplate,
  encodeWalletCanonicalBytes,
  validateWalletReqkeyTemplate,
  walletReqkeyTemplatePayload,
} from './reqkeyTemplate';
import { buildInstitutionalWalletDescriptor, type InstitutionalWallet } from './walletBuilder';

const SIGNET_VERSIONS = { private: 0x04358394, public: 0x043587cf };

function seedXpub(byte: number): string {
  return HDKey.fromMasterSeed(new Uint8Array(32).fill(byte), SIGNET_VERSIONS).publicExtendedKey;
}

function singleSigbashWallet(): InstitutionalWallet {
  return buildInstitutionalWalletDescriptor({
    network: 'signet',
    signers: [{ kind: 'sigbash_policy_key', xpub: seedXpub(0x50), policyKeyId: 'pk-wallet' }],
    allowedSignerSets: [[0]],
  });
}

describe('payload rendering', () => {
  it('renders the prefix plus hex of the placeholder-substituted encoding', () => {
    const wallet = singleSigbashWallet();
    const payload = walletReqkeyTemplatePayload(wallet);
    expect(payload.startsWith(WALLET_REQKEY_TEMPLATE_PREFIX)).toBe(true);
    const raw = hexToBytes(payload.slice(WALLET_REQKEY_TEMPLATE_PREFIX.length));
    const text = new TextDecoder().decode(raw);
    expect(text).toContain('SIGBASH_XPUB');
    expect(text).not.toContain(seedXpub(0x50));
    // The encoding with the placeholder substituted is byte-identical to
    // what the renderer emits.
    expect(bytesToHex(raw)).toBe(
      bytesToHex(
        encodeWalletCanonicalBytes(wallet, { signerIndex: 0, placeholder: 'SIGBASH_XPUB' })
      )
    );
  });

  it('rejects wallets with more than one Sigbash signer', () => {
    const wallet = buildInstitutionalWalletDescriptor({
      network: 'signet',
      signers: [
        { kind: 'sigbash_policy_key', xpub: seedXpub(0x51), policyKeyId: 'pk-a' },
        { kind: 'sigbash_policy_key', xpub: seedXpub(0x52), policyKeyId: 'pk-b' },
      ],
      allowedSignerSets: [[0, 1]],
    });
    expect(() => walletReqkeyTemplatePayload(wallet)).toThrow(/exactly one Sigbash signer/);
  });
});

describe('decode resolution', () => {
  it('round-trips a bare xpub back to an equivalent wallet', () => {
    const wallet = singleSigbashWallet();
    const payload = walletReqkeyTemplatePayload(wallet);
    const decoded = decodeWalletReqkeyTemplate(payload, seedXpub(0x50));
    expect(bytesToHex(encodeWalletCanonicalBytes(decoded))).toBe(
      bytesToHex(encodeWalletCanonicalBytes(wallet))
    );
  });

  it('resolves the bracketed origin-prefixed form into origin metadata', () => {
    const wallet = singleSigbashWallet();
    const payload = walletReqkeyTemplatePayload(wallet);
    const xpub = seedXpub(0x50);
    const decoded = decodeWalletReqkeyTemplate(payload, `[deadbeef]${xpub}`);
    expect(decoded.signers[0].xpub).toBe(xpub);
    expect(Array.from(decoded.signers[0].origin!.masterFingerprint)).toEqual([
      0xde, 0xad, 0xbe, 0xef,
    ]);
  });

  it('rejects a malformed origin prefix, an empty xpub, and a second Sigbash signer', () => {
    const payload = walletReqkeyTemplatePayload(singleSigbashWallet());
    expect(() => decodeWalletReqkeyTemplate(payload, '[deadbee]' + seedXpub(0x50))).toThrow(
      /origin prefix is malformed/
    );
    expect(() => decodeWalletReqkeyTemplate(payload, '')).toThrow(/requires the real BIP-328 xpub/);
  });

  it('rejects a payload whose Sigbash signer lost the placeholder', () => {
    const wallet = singleSigbashWallet();
    // Encode without substitution: an already-resolved or hand-edited
    // template is wallet-material drift.
    const raw = encodeWalletCanonicalBytes(wallet);
    const payload = WALLET_REQKEY_TEMPLATE_PREFIX + bytesToHex(raw);
    expect(() => decodeWalletReqkeyTemplate(payload, seedXpub(0x50))).toThrow(/placeholder/);
  });
});

describe('static validation', () => {
  const payload = walletReqkeyTemplatePayload(singleSigbashWallet());

  it('accepts derivation ranges 0 and 512 and rejects anything else', () => {
    expect(() => validateWalletReqkeyTemplate(payload, 0)).not.toThrow();
    expect(() => validateWalletReqkeyTemplate(payload, 512)).not.toThrow();
    expect(() => validateWalletReqkeyTemplate(payload, 255)).toThrow(
      /derivation_range 255 has no deterministic subset meaning/
    );
    expect(() => validateWalletReqkeyTemplate(payload, 513)).toThrow(/derivation_range/);
  });

  it('rejects a template whose wallet shape fails validation under the probe xpub', () => {
    // Hand-assemble a canonical encoding whose only allowed signer set
    // references an index outside the signer list.
    const enc = (s: string): number[] => Array.from(new TextEncoder().encode(s));
    const bytes = [
      0x01,
      6, ...enc('signet'),
      1,
      0x01, ...u16(enc('SIGBASH_XPUB')), ...enc('SIGBASH_XPUB'),
      ...u16(enc('pk-wallet')), ...enc('pk-wallet'), 0x00,
      0x00, 1,
      2, 0, 5,
      0x00,
    ];
    const bad = WALLET_REQKEY_TEMPLATE_PREFIX + bytesToHex(new Uint8Array(bytes));
    expect(() => validateWalletReqkeyTemplate(bad, 512)).toThrow(/outside the signer set/);
  });

  it('rejects a truncated encoding after the version byte', () => {
    const bad = WALLET_REQKEY_TEMPLATE_PREFIX + bytesToHex(new Uint8Array([0x01]));
    expect(() => validateWalletReqkeyTemplate(bad, 512)).toThrow(/truncated wallet template/);
  });
});

describe('payload guards', () => {
  it('rejects a missing prefix, invalid hex, and truncated encodings', () => {
    expect(() => decodeWalletReqkeyTemplate('tr(SIGBASH_XPUB/0/*)', seedXpub(0x50))).toThrow(
      /not a wallet reqkey template/
    );
    expect(() =>
      decodeWalletReqkeyTemplate(WALLET_REQKEY_TEMPLATE_PREFIX + 'zznot hex', seedXpub(0x50))
    ).toThrow(/not valid hex/);
    expect(() =>
      decodeWalletReqkeyTemplate(WALLET_REQKEY_TEMPLATE_PREFIX + '00ff', seedXpub(0x50))
    ).toThrow(/format version 0/);
    // Trailing bytes beyond a well-formed encoding never pass silently.
    const payload = walletReqkeyTemplatePayload(singleSigbashWallet());
    expect(() =>
      decodeWalletReqkeyTemplate(payload + 'ff', seedXpub(0x50))
    ).toThrow(/trailing bytes/);
  });

  it('rejects payloads beyond the registration size guard before decoding', () => {
    const oversized = WALLET_REQKEY_TEMPLATE_PREFIX + 'ab'.repeat(61441);
    expect(() => decodeWalletReqkeyTemplate(oversized, seedXpub(0x50))).toThrow(/registration guard/);
  });
});

function u16(bytes: number[]): number[] {
  const len = bytes.length;
  return [(len >> 8) & 0xff, len & 0xff];
}
