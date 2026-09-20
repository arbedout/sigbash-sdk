/**
 * Wallet-ownership REQKEY template: the persisted form of the institutional
 * wallet inside the single unconditional descriptor-mode REQKEY system atom.
 *
 * The template carries the wallet's canonical encoding with the one Sigbash
 * signer's xpub replaced by the SIGBASH_XPUB placeholder, so the committed
 * clause never embeds BIP-328 key material and the real xpub is resolved
 * once at post-aggregation rebuild (and again at signing time from the same
 * stored template). Both descriptor branches live in this one payload: the
 * depth-9 gadget's 512-candidate universe maps deterministically as
 * candidate i < 256 -> (receive, i), otherwise (change, i - 256). The
 * sole-atom gate forbids a second descriptor atom, so both branches share
 * this single persisted string.
 *
 * The legacy descriptor-template mode ("tr(SIGBASH_XPUB/0/*)", the webapp
 * flow) keeps its own shape and semantics untouched; the prefix is what
 * separates the two. Any string without the prefix is never interpreted as
 * a wallet template, and a malformed wallet template is always a hard error.
 */

import { bytesToHex, concatBytes, hexToBytes, u16be, utf8 } from '../contracts/encoding';
import {
  WALLET_MAX_ALLOWED_SIGNER_SETS,
  WALLET_NETWORK_PARAMS,
  WALLET_NETWORKS,
  WALLET_REQKEY_CANDIDATE_COUNT,
  WALLET_REQKEY_TEMPLATE_MAX_CANONICAL_BYTES,
  WALLET_REQKEY_TEMPLATE_PREFIX,
  WALLET_REQKEY_PLACEHOLDER_XPUB,
  type WalletNetwork,
} from './constants';
import { WalletReqkeyTemplateError } from './errors';
import { HDKey } from '@scure/bip32';
import {
  buildInstitutionalWalletDescriptor,
  type InstitutionalWallet,
  type WalletRecoveryBranches,
  type WalletSigner,
} from './walletBuilder';
import { parseWalletSignerOrigin, type WalletSignerOrigin } from './xpubImport';

const WALLET_FORMAT_VERSION = 0x01;

interface WalletCanonicalParts {
  network: WalletNetwork;
  signers: WalletSigner[];
  allowedSignerSets: number[][];
  recovery?: WalletRecoveryBranches;
}

class ByteWriter {
  private parts: Uint8Array[] = [];
  writeByte(value: number): void {
    this.parts.push(new Uint8Array([value]));
  }
  writeBytes(bytes: Uint8Array): void {
    this.parts.push(bytes);
  }
  writeU16(value: number): void {
    this.parts.push(u16be(value));
  }
  writeString(text: string): void {
    const raw = utf8(text);
    this.writeBytes(raw);
  }
  toBytes(): Uint8Array {
    return concatBytes(...this.parts);
  }
}

class ByteReader {
  offset = 0;
  constructor(private readonly data: Uint8Array) {}
  readByte(field: string): number {
    if (this.offset >= this.data.length) {
      throw new WalletReqkeyTemplateError(`${field}: truncated wallet template`);
    }
    return this.data[this.offset++];
  }
  readBytes(n: number, field: string): Uint8Array {
    if (this.offset + n > this.data.length) {
      throw new WalletReqkeyTemplateError(`${field}: truncated wallet template`);
    }
    const out = this.data.slice(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }
  readU16(field: string): number {
    return (this.readByte(field) << 8) | this.readByte(field);
  }
  readU32(field: string): number {
    return (
      ((this.readByte(field) << 24) | (this.readByte(field) << 16) | (this.readByte(field) << 8) | this.readByte(field)) >>> 0
    );
  }
  readLenByteString(field: string): string {
    const len = this.readByte(field);
    return new TextDecoder().decode(this.readBytes(len, field));
  }
  readU16String(field: string): string {
    const len = this.readU16(field);
    return new TextDecoder().decode(this.readBytes(len, field));
  }
  remaining(): number {
    return this.data.length - this.offset;
  }
}

function encodeOrigin(writer: ByteWriter, origin?: WalletSignerOrigin): void {
  if (origin === undefined) {
    writer.writeByte(0x00);
    return;
  }
  writer.writeByte(0x01);
  writer.writeBytes(origin.masterFingerprint);
  writer.writeByte(origin.path.length);
  for (const idx of origin.path) {
    writer.writeBytes(
      new Uint8Array([(idx >>> 24) & 0xff, (idx >>> 16) & 0xff, (idx >>> 8) & 0xff, idx & 0xff])
    );
  }
}

/**
 * Encodes the canonical wallet spend-identity form. Layout (big-endian):
 * version byte, u8 network length + ascii bytes, u8 signer count, per
 * signer (kind, u16 xpub, u16 policy key id, origin), u16 set count with
 * per-set size + indices, recovery flag block. The NUMS internal key is a
 * format constant and is not serialized. When substituteSignerXpub is set,
 * that signer's xpub renders as the SIGBASH_XPUB placeholder and the caller
 * must already have validated the underlying wallet.
 */
export function encodeWalletCanonicalBytes(
  wallet: InstitutionalWallet,
  substituteSignerXpub?: { signerIndex: number; placeholder: string }
): Uint8Array {
  const writer = new ByteWriter();
  writer.writeByte(WALLET_FORMAT_VERSION);
  const network = utf8(wallet.network);
  writer.writeByte(network.length);
  writer.writeBytes(network);
  writer.writeByte(wallet.signers.length);
  for (let i = 0; i < wallet.signers.length; i++) {
    const signer = wallet.signers[i];
    writer.writeByte(signer.kind === 'sigbash_policy_key' ? 0x01 : 0x02);
    const xpub =
      substituteSignerXpub !== undefined && substituteSignerXpub.signerIndex === i
        ? substituteSignerXpub.placeholder
        : signer.xpub;
    const xpubRaw = utf8(xpub);
    writer.writeU16(xpubRaw.length);
    writer.writeBytes(xpubRaw);
    const policyRaw = utf8(signer.policyKeyId ?? '');
    writer.writeU16(policyRaw.length);
    writer.writeBytes(policyRaw);
    encodeOrigin(writer, signer.origin);
  }
  writer.writeU16(wallet.allowedSignerSets.length);
  for (const set of wallet.allowedSignerSets) {
    writer.writeByte(set.length);
    for (const idx of set) {
      writer.writeByte(idx);
    }
  }
  if (wallet.recovery === undefined) {
    writer.writeByte(0x00);
  } else {
    writer.writeByte(0x01);
    let flags = 0;
    if (wallet.recovery.alwaysSpendable) {
      flags |= 0x01;
    }
    if (wallet.recovery.decay) {
      flags |= 0x02;
    }
    writer.writeByte(flags);
    writer.writeU16(wallet.recovery.decay ? wallet.recovery.decayBlocks : 0);
    writer.writeBytes(wallet.recovery.recoveryKeyXOnly);
  }
  return writer.toBytes();
}

function parseCanonicalParts(data: Uint8Array): WalletCanonicalParts {
  const r = new ByteReader(data);
  const version = r.readByte('version');
  if (version !== WALLET_FORMAT_VERSION) {
    throw new WalletReqkeyTemplateError(`unsupported wallet descriptor format version ${version}`);
  }
  const network = r.readLenByteString('network');
  if (!WALLET_NETWORKS.includes(network as WalletNetwork)) {
    throw new WalletReqkeyTemplateError(`unsupported wallet network '${network}'`);
  }
  const signerCount = r.readByte('signer count');
  if (signerCount === 0) {
    throw new WalletReqkeyTemplateError('wallet descriptor requires at least one signer');
  }
  const signers: WalletSigner[] = [];
  for (let i = 0; i < signerCount; i++) {
    const kindByte = r.readByte('signer kind');
    const kind = kindByte === 0x01 ? 'sigbash_policy_key' : kindByte === 0x02 ? 'external_xpub' : undefined;
    if (kind === undefined) {
      throw new WalletReqkeyTemplateError(`unknown signer kind ${kindByte}`);
    }
    const xpub = r.readU16String('signer xpub');
    const policyKeyId = r.readU16String('signer policy key id');
    const originFlag = r.readByte('origin flag');
    let origin: WalletSignerOrigin | undefined;
    if (originFlag === 0x01) {
      const fingerprint = r.readBytes(4, 'origin fingerprint');
      const pathLen = r.readByte('origin path length');
      const path: number[] = [];
      for (let j = 0; j < pathLen; j++) {
        path.push(r.readU32('origin path index'));
      }
      origin = { masterFingerprint: fingerprint, path };
    } else if (originFlag !== 0x00) {
      throw new WalletReqkeyTemplateError(`unknown origin flag ${originFlag}`);
    }
    signers.push({
      kind,
      xpub,
      ...(policyKeyId.length > 0 ? { policyKeyId } : {}),
      ...(origin !== undefined ? { origin } : {}),
    });
  }
  const setCount = r.readU16('allowed signer set count');
  if (setCount === 0) {
    throw new WalletReqkeyTemplateError('wallet descriptor requires at least one allowed signer set');
  }
  if (setCount > WALLET_MAX_ALLOWED_SIGNER_SETS) {
    throw new WalletReqkeyTemplateError(`wallet descriptor supports at most ${WALLET_MAX_ALLOWED_SIGNER_SETS} allowed signer sets`);
  }
  const allowedSignerSets: number[][] = [];
  for (let i = 0; i < setCount; i++) {
    const size = r.readByte('allowed signer set size');
    const set: number[] = [];
    for (let j = 0; j < size; j++) {
      set.push(r.readByte('allowed signer index'));
    }
    allowedSignerSets.push(set);
  }
  const recoveryFlag = r.readByte('recovery flag');
  let recovery: WalletRecoveryBranches | undefined;
  if (recoveryFlag === 0x01) {
    const flags = r.readByte('recovery flags');
    if ((flags & ~0x03) !== 0) {
      throw new WalletReqkeyTemplateError(`unknown recovery branch flags 0x${flags.toString(16)}`);
    }
    const decayBlocks = r.readU16('recovery decay blocks');
    const key = r.readBytes(32, 'recovery key');
    recovery = {
      recoveryKeyXOnly: key,
      alwaysSpendable: (flags & 0x01) !== 0,
      decay: (flags & 0x02) !== 0,
      decayBlocks,
    };
  } else if (recoveryFlag !== 0x00) {
    throw new WalletReqkeyTemplateError(`unknown recovery flag ${recoveryFlag}`);
  }
  if (r.remaining() !== 0) {
    throw new WalletReqkeyTemplateError(`wallet template carries ${r.remaining()} trailing bytes`);
  }
  return { network: network as WalletNetwork, signers, allowedSignerSets, ...(recovery !== undefined ? { recovery } : {}) };
}

function countSigbashSigners(signers: WalletSigner[]): number {
  return signers.filter((s) => s.kind === 'sigbash_policy_key').length;
}

/**
 * Renders the wallet as a wallet-ownership REQKEY template payload: the
 * canonical encoding with the single Sigbash signer's xpub rendered as the
 * placeholder. A wallet with more than one Sigbash signer has no single
 * placeholder substitution and is rejected — the placeholder form is defined
 * only for exactly one Sigbash signer, so all-Sigbash M-of-N wallets cannot
 * register through this path until a real-xpub template mode exists.
 */
export function walletReqkeyTemplatePayload(wallet: InstitutionalWallet): string {
  if (countSigbashSigners(wallet.signers) !== 1) {
    throw new WalletReqkeyTemplateError(
      `wallet reqkey template requires exactly one Sigbash signer, wallet carries ${countSigbashSigners(wallet.signers)}`
    );
  }
  const sigbashIndex = wallet.signers.findIndex((s) => s.kind === 'sigbash_policy_key');
  const raw = encodeWalletCanonicalBytes(wallet, {
    signerIndex: sigbashIndex,
    placeholder: WALLET_REQKEY_PLACEHOLDER_XPUB,
  });
  if (raw.length > WALLET_REQKEY_TEMPLATE_MAX_CANONICAL_BYTES) {
    throw new WalletReqkeyTemplateError(
      `wallet reqkey template encoding is ${raw.length} bytes, beyond the ${WALLET_REQKEY_TEMPLATE_MAX_CANONICAL_BYTES} byte registration guard`
    );
  }
  return WALLET_REQKEY_TEMPLATE_PREFIX + bytesToHex(raw);
}

function decodeTemplateBytes(payload: string): Uint8Array {
  if (!payload.startsWith(WALLET_REQKEY_TEMPLATE_PREFIX)) {
    throw new WalletReqkeyTemplateError(
      `payload is not a wallet reqkey template (missing "${WALLET_REQKEY_TEMPLATE_PREFIX}" prefix)`
    );
  }
  const hexText = payload.slice(WALLET_REQKEY_TEMPLATE_PREFIX.length);
  if (hexText.length > 2 * WALLET_REQKEY_TEMPLATE_MAX_CANONICAL_BYTES) {
    throw new WalletReqkeyTemplateError(
      `wallet reqkey template payload is beyond the ${WALLET_REQKEY_TEMPLATE_MAX_CANONICAL_BYTES} byte registration guard`
    );
  }
  let raw: Uint8Array;
  try {
    raw = hexToBytes(hexText);
  } catch {
    throw new WalletReqkeyTemplateError('wallet reqkey template payload is not valid hex');
  }
  if (raw.length > WALLET_REQKEY_TEMPLATE_MAX_CANONICAL_BYTES) {
    throw new WalletReqkeyTemplateError(
      `wallet reqkey template payload is ${raw.length} bytes, beyond the ${WALLET_REQKEY_TEMPLATE_MAX_CANONICAL_BYTES} byte registration guard`
    );
  }
  return raw;
}

/**
 * Parses a wallet-ownership REQKEY template payload and resolves its single
 * Sigbash placeholder to actualXpub, re-running the full builder validation
 * against the resolved key material. actualXpub may carry the credential's
 * descriptor origin prefix ("[fingerprint]xpub", the form the key-material
 * container stores): the bracketed prefix is parsed into the Sigbash
 * signer's origin metadata and the bare base58 key drives derivation. Every
 * ambiguity fails closed: a missing prefix, malformed hex, a payload
 * without the placeholder (an already-resolved or hand-edited template is
 * wallet-material drift), a second Sigbash signer, or an empty actualXpub
 * are all errors.
 */
export function decodeWalletReqkeyTemplate(payload: string, actualXpub: string): InstitutionalWallet {
  const parts = parseCanonicalParts(decodeTemplateBytes(payload));
  if (actualXpub === '') {
    throw new WalletReqkeyTemplateError('wallet reqkey template resolution requires the real BIP-328 xpub');
  }
  let bareXpub = actualXpub;
  let origin: WalletSignerOrigin | undefined;
  if (bareXpub.startsWith('[')) {
    const end = bareXpub.indexOf(']');
    if (end !== 9) {
      throw new WalletReqkeyTemplateError('wallet reqkey template resolution xpub origin prefix is malformed');
    }
    origin = parseWalletSignerOrigin(bareXpub.slice(1, end), '');
    bareXpub = bareXpub.slice(end + 1);
  }
  const resolved = parts.signers.map((signer) => ({ ...signer }));
  let placeholderSeen = false;
  let sigbashCount = 0;
  for (const signer of resolved) {
    if (signer.kind !== 'sigbash_policy_key') {
      continue;
    }
    sigbashCount++;
    if (signer.xpub === WALLET_REQKEY_PLACEHOLDER_XPUB) {
      placeholderSeen = true;
      signer.xpub = bareXpub;
      if (origin !== undefined) {
        signer.origin = origin;
      }
    }
  }
  if (sigbashCount !== 1 || !placeholderSeen) {
    throw new WalletReqkeyTemplateError(
      `wallet reqkey template must carry the placeholder on exactly one Sigbash signer (found ${sigbashCount} Sigbash signers, placeholder present: ${placeholderSeen})`
    );
  }
  return buildInstitutionalWalletDescriptor({
    network: parts.network,
    signers: resolved,
    allowedSignerSets: parts.allowedSignerSets,
    ...(parts.recovery !== undefined ? { recovery: parts.recovery } : {}),
  });
}

/**
 * Fixed, network-correct probe xpub used only to shape-validate a template
 * whose Sigbash signer still carries the placeholder. The same fixed seed
 * always yields the same probe per network, so validation is deterministic
 * and the probe never reaches any committed value.
 */
function walletReqkeyTemplateProbeXpub(network: WalletNetwork): string {
  const params = WALLET_NETWORK_PARAMS[network];
  const master = HDKey.fromMasterSeed(new Uint8Array(16).fill(0x77), {
    private: params.hdPrivateKeyVersion,
    public: params.hdPublicKeyVersion,
  });
  return master.publicExtendedKey;
}

/**
 * Statically validates a wallet-ownership REQKEY template the way
 * compile-time REQKEY validation runs it: structure, network, placeholder
 * placement, and the derivation-range contract are checked without a real
 * BIP-328 xpub. The Sigbash signer's remaining shape (policy key reference,
 * set membership, tree shape) is validated by substituting a
 * network-correct probe xpub for the placeholder; the resolved template is
 * re-validated in full with the real xpub at post-aggregation rebuild and
 * at signing time.
 */
export function validateWalletReqkeyTemplate(payload: string, derivRange: number): void {
  const parts = parseCanonicalParts(decodeTemplateBytes(payload));
  if (derivRange !== 0 && derivRange !== WALLET_REQKEY_CANDIDATE_COUNT) {
    throw new WalletReqkeyTemplateError(
      `wallet reqkey template commits the full ${WALLET_REQKEY_CANDIDATE_COUNT}-candidate universe; derivation_range ${derivRange} has no deterministic subset meaning`
    );
  }
  let placeholderSeen = false;
  const sigbashCount = countSigbashSigners(parts.signers);
  for (const signer of parts.signers) {
    if (signer.kind === 'sigbash_policy_key' && signer.xpub === WALLET_REQKEY_PLACEHOLDER_XPUB) {
      placeholderSeen = true;
    }
  }
  if (sigbashCount !== 1 || !placeholderSeen) {
    throw new WalletReqkeyTemplateError(
      `wallet reqkey template must carry the placeholder on exactly one Sigbash signer (found ${sigbashCount} Sigbash signers, placeholder present: ${placeholderSeen})`
    );
  }
  const probeXpub = walletReqkeyTemplateProbeXpub(parts.network);
  const probed = parts.signers.map((signer) =>
    signer.kind === 'sigbash_policy_key' && signer.xpub === WALLET_REQKEY_PLACEHOLDER_XPUB
      ? { ...signer, xpub: probeXpub }
      : signer
  );
  buildInstitutionalWalletDescriptor({
    network: parts.network,
    signers: probed,
    allowedSignerSets: parts.allowedSignerSets,
    ...(parts.recovery !== undefined ? { recovery: parts.recovery } : {}),
  });
}
