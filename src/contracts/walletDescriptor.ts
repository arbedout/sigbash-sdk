/**
 * WalletDescriptorV1 — the canonical wallet spend identity.
 *
 * Signer-type agnostic: a signer root is either a policy-bound Sigbash
 * BIP-328 xpub or an external account xpub. The canonical representation
 * is an ordered signer-root list plus an exact list of allowed signer
 * subsets; every subset becomes one sortedmulti_a tapscript leaf with all
 * keys required. The BIP-341 NUMS internal key is implied by the
 * descriptor text and is never a spendable key path.
 *
 * Future wallet modes (silent-payment receive, threshold organization-side
 * signers) enter through a new version of this contract, never by
 * overloading the V1 fields. They are deliberately NOT modeled here.
 */

import { ContractVersionError, assertFixedLength, bytesToHex, concatBytes, contractHeader, Decoder, expectExhausted, hexToBytes, lengthDelimited, readContractHeader, readLengthDelimited, readU16, readU8, u16be, u8be, utf8 } from './encoding';
import { decodeNetworkId, encodeNetworkId, NetworkId } from './network';

export const WALLET_DESCRIPTOR_CONTRACT_ID = 0x01;
export const WALLET_DESCRIPTOR_VERSION = 1;
export const SUPPORTED_WALLET_DESCRIPTOR_VERSIONS = [WALLET_DESCRIPTOR_VERSION] as const;

export const MAX_SIGNERS_PER_LEAF = 3;
export const MAX_XPUB_LENGTH = 512;
export const MAX_DESCRIPTOR_LENGTH = 4096;

export type WalletSignerKind = 'sigbash_policy_key' | 'external_xpub';

export const WALLET_SIGNER_KIND_CODES = {
  sigbash_policy_key: 0x01,
  external_xpub: 0x02,
} as const satisfies Record<WalletSignerKind, number>;

const CODE_TO_WALLET_SIGNER_KIND: Record<number, WalletSignerKind> = {
  [WALLET_SIGNER_KIND_CODES.sigbash_policy_key]: 'sigbash_policy_key',
  [WALLET_SIGNER_KIND_CODES.external_xpub]: 'external_xpub',
};

export type WalletMode = 'sigbash_native' | 'mixed';

export const WALLET_MODE_CODES = {
  sigbash_native: 0x01,
  mixed: 0x02,
} as const satisfies Record<WalletMode, number>;

const CODE_TO_WALLET_MODE: Record<number, WalletMode> = {
  [WALLET_MODE_CODES.sigbash_native]: 'sigbash_native',
  [WALLET_MODE_CODES.mixed]: 'mixed',
};

export interface WalletSignerRootV1 {
  kind: WalletSignerKind;
  /** Canonical extended public key text (account root for the wallet). */
  xpub: string;
  /** Required for sigbash_policy_key; the encrypted-state policy reference. */
  policyKeyId?: string;
}

export interface AllowedSignerSetV1 {
  /** Indexes into the ordered signer list, ascending, size 1..3. */
  signerIndexes: number[];
}

export interface RecoveryBranchV1 {
  /** Fixed customer-held x-only recovery key; never Sigbash material. */
  recoveryKeyXOnly: Uint8Array;
  /** Decay blocks 1..65535, or null for an always-spendable branch only. */
  decayBlocks: number | null;
}

export interface WalletDescriptorV1 {
  version: typeof WALLET_DESCRIPTOR_VERSION;
  network: NetworkId;
  walletMode: WalletMode;
  signers: WalletSignerRootV1[];
  allowedSignerSets: AllowedSignerSetV1[];
  /** Canonical receive descriptor text without checksum, /0/* branch. */
  receiveDescriptor: string;
  /** Canonical change descriptor text without checksum, /1/* branch. */
  changeDescriptor: string;
  /** At most one recovery branch object; both branch styles share one key. */
  recovery?: RecoveryBranchV1;
}

function encodeSigner(signer: WalletSignerRootV1): Uint8Array {
  const kindCode = WALLET_SIGNER_KIND_CODES[signer.kind];
  const policyKeyId = signer.policyKeyId ?? '';
  if (signer.kind === 'sigbash_policy_key' && !signer.policyKeyId) {
    throw new Error('sigbash_policy_key signer requires policyKeyId');
  }
  if (signer.kind !== 'sigbash_policy_key' && signer.policyKeyId) {
    throw new Error('external_xpub signer must not carry policyKeyId');
  }
  return concatBytes(
    u8be(kindCode),
    lengthDelimited(utf8(signer.xpub)),
    lengthDelimited(utf8(policyKeyId)),
  );
}

function encodeRecovery(recovery: RecoveryBranchV1 | undefined): Uint8Array {
  if (!recovery) {
    return u8be(0x00);
  }
  assertFixedLength(recovery.recoveryKeyXOnly, 32, 'recoveryKeyXOnly');
  const decay = recovery.decayBlocks === null ? 0xffff : recovery.decayBlocks;
  if (recovery.decayBlocks !== null && (recovery.decayBlocks < 1 || recovery.decayBlocks > 0xfffe)) {
    throw new RangeError('decayBlocks must be 1..65534, or null for no decay branch');
  }
  return concatBytes(u8be(0x01), lengthDelimited(recovery.recoveryKeyXOnly), u16be(decay));
}

export function encodeWalletDescriptorV1(descriptor: WalletDescriptorV1): Uint8Array {
  if (descriptor.version !== WALLET_DESCRIPTOR_VERSION) {
    throw new ContractVersionError(`WalletDescriptorV1: unsupported version ${descriptor.version}`);
  }
  if (descriptor.signers.length === 0 || descriptor.signers.length > 0xffff) {
    throw new Error('wallet requires between 1 and 65535 signers');
  }
  for (const set of descriptor.allowedSignerSets) {
    if (set.signerIndexes.length < 1 || set.signerIndexes.length > MAX_SIGNERS_PER_LEAF) {
      throw new Error(`allowed signer subsets must contain 1..${MAX_SIGNERS_PER_LEAF} signers`);
    }
    let sorted = true;
    for (let i = 0; i < set.signerIndexes.length; i++) {
      if (set.signerIndexes[i] < 0 || set.signerIndexes[i] >= descriptor.signers.length) {
        throw new Error('allowed signer subset index out of range');
      }
      if (i > 0 && set.signerIndexes[i] <= set.signerIndexes[i - 1]) {
        sorted = false;
      }
    }
    if (!sorted) {
      throw new Error('allowed signer subset indexes must be strictly ascending');
    }
  }
  if (descriptor.receiveDescriptor.length > MAX_DESCRIPTOR_LENGTH || descriptor.changeDescriptor.length > MAX_DESCRIPTOR_LENGTH) {
    throw new Error('descriptor text exceeds maximum length');
  }

  const parts: Uint8Array[] = [
    contractHeader(WALLET_DESCRIPTOR_CONTRACT_ID, WALLET_DESCRIPTOR_VERSION),
    u8be(encodeNetworkId(descriptor.network)),
    u8be(WALLET_MODE_CODES[descriptor.walletMode]),
    u16be(descriptor.signers.length),
  ];
  for (const signer of descriptor.signers) {
    parts.push(encodeSigner(signer));
  }
  parts.push(u16be(descriptor.allowedSignerSets.length));
  for (const set of descriptor.allowedSignerSets) {
    parts.push(u8be(set.signerIndexes.length));
    for (const index of set.signerIndexes) {
      parts.push(u8be(index));
    }
  }
  parts.push(lengthDelimited(utf8(descriptor.receiveDescriptor)));
  parts.push(lengthDelimited(utf8(descriptor.changeDescriptor)));
  parts.push(encodeRecovery(descriptor.recovery));
  return concatBytes(...parts);
}

function decodeSigner(d: Decoder): WalletSignerRootV1 {
  const kindCode = readU8(d, 'signer.kind');
  const kind = CODE_TO_WALLET_SIGNER_KIND[kindCode];
  if (kind === undefined) {
    throw new ContractVersionError(`WalletDescriptorV1: unknown signer kind 0x${kindCode.toString(16)}`);
  }
  const xpubBytes = readLengthDelimited(d, 'signer.xpub');
  if (xpubBytes.length === 0 || xpubBytes.length > MAX_XPUB_LENGTH) {
    throw new Error('signer xpub length out of range');
  }
  const policyKeyIdBytes = readLengthDelimited(d, 'signer.policyKeyId');
  const xpub = new TextDecoder().decode(xpubBytes);
  const policyKeyId = new TextDecoder().decode(policyKeyIdBytes);
  if (kind === 'sigbash_policy_key' && policyKeyId.length === 0) {
    throw new Error('sigbash_policy_key signer requires policyKeyId');
  }
  if (kind !== 'sigbash_policy_key' && policyKeyId.length > 0) {
    throw new Error('external_xpub signer must not carry policyKeyId');
  }
  return { kind, xpub, ...(policyKeyId.length > 0 ? { policyKeyId } : {}) };
}

function decodeRecovery(d: Decoder): RecoveryBranchV1 | undefined {
  const flag = readU8(d, 'recovery.flag');
  if (flag === 0x00) {
    return undefined;
  }
  if (flag !== 0x01) {
    throw new ContractVersionError(`WalletDescriptorV1: unknown recovery flag 0x${flag.toString(16)}`);
  }
  const key = new Uint8Array(readLengthDelimited(d, 'recovery.key'));
  assertFixedLength(key, 32, 'recoveryKeyXOnly');
  const decay = readU16(d, 'recovery.decayBlocks');
  return {
    recoveryKeyXOnly: key,
    decayBlocks: decay === 0xffff ? null : decay,
  };
}

export function decodeWalletDescriptorV1(bytes: Uint8Array): WalletDescriptorV1 {
  const d: Decoder = { data: bytes, offset: 0 };
  const version = readContractHeader(d, WALLET_DESCRIPTOR_CONTRACT_ID, SUPPORTED_WALLET_DESCRIPTOR_VERSIONS, 'WalletDescriptorV1');
  const network = decodeNetworkId(readU8(d, 'network'));
  const modeCode = readU8(d, 'walletMode');
  const walletMode = CODE_TO_WALLET_MODE[modeCode];
  if (walletMode === undefined) {
    throw new ContractVersionError(`WalletDescriptorV1: unknown wallet mode 0x${modeCode.toString(16)}`);
  }

  const signerCount = readU16(d, 'signers.count');
  if (signerCount === 0) {
    throw new Error('wallet requires at least one signer');
  }
  const signers: WalletSignerRootV1[] = [];
  for (let i = 0; i < signerCount; i++) {
    signers.push(decodeSigner(d));
  }

  const setCount = readU16(d, 'allowedSignerSets.count');
  const allowedSignerSets: AllowedSignerSetV1[] = [];
  for (let i = 0; i < setCount; i++) {
    const size = readU8(d, 'allowedSignerSets.size');
    if (size < 1 || size > MAX_SIGNERS_PER_LEAF) {
      throw new Error(`allowed signer subsets must contain 1..${MAX_SIGNERS_PER_LEAF} signers`);
    }
    const indexes: number[] = [];
    for (let j = 0; j < size; j++) {
      const index = readU8(d, 'allowedSignerSets.index');
      if (index >= signerCount) {
        throw new Error('allowed signer subset index out of range');
      }
      if (indexes.length > 0 && index <= indexes[indexes.length - 1]) {
        throw new Error('allowed signer subset indexes must be strictly ascending');
      }
      indexes.push(index);
    }
    allowedSignerSets.push({ signerIndexes: indexes });
  }

  const receiveDescriptor = new TextDecoder().decode(readLengthDelimited(d, 'receiveDescriptor'));
  const changeDescriptor = new TextDecoder().decode(readLengthDelimited(d, 'changeDescriptor'));
  if (receiveDescriptor.length === 0 || changeDescriptor.length === 0) {
    throw new Error('wallet requires both receive and change descriptors');
  }
  const recovery = decodeRecovery(d);
  expectExhausted(d, 'WalletDescriptorV1');

  return {
    version: version as typeof WALLET_DESCRIPTOR_VERSION,
    network,
    walletMode,
    signers,
    allowedSignerSets,
    receiveDescriptor,
    changeDescriptor,
    ...(recovery ? { recovery } : {}),
  };
}

/** Hex helper for golden vectors and logs of already-public encodings. */
export function walletDescriptorToHex(descriptor: WalletDescriptorV1): string {
  return bytesToHex(encodeWalletDescriptorV1(descriptor));
}

export function walletDescriptorFromHex(hex: string): WalletDescriptorV1 {
  return decodeWalletDescriptorV1(hexToBytes(hex));
}
