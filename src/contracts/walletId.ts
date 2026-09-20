/**
 * WalletId — the client-only deterministic wallet fingerprint.
 *
 * Derived from the canonical descriptor pair exactly as specified:
 *
 *   WalletId = TaggedHash(
 *     "SIGBASH/WALLET/V1",
 *     network_ascii_name || 0x00 ||
 *     canonical_receive_descriptor_without_checksum ||
 *     0x00 || canonical_change_descriptor_without_checksum
 *   )
 *
 * The network enters the preimage as its ASCII name bytes ("signet" /
 * "mainnet"), matching the canonical Go reference construction — not as a
 * numeric wire code. Wire codes are reserved for binary contract encodings.
 *
 * The wallet id is used for client-side identity and encrypted-state
 * references. It is never a public sync identifier; server-facing
 * encrypted-object ids stay random.
 */

import { bytesToHex, concatBytes, hexToBytes, taggedHash, u8be, utf8 } from './encoding';
import { NetworkId } from './network';

export const WALLET_ID_VERSION = 1;
export const WALLET_ID_TAG = 'SIGBASH/WALLET/V1';
export const WALLET_ID_LENGTH = 32;

export type WalletId = Uint8Array;

function assertCanonicalDescriptorText(descriptor: string, field: string): void {
  if (descriptor.length === 0) {
    throw new Error(`${field} descriptor must not be empty`);
  }
  if (/\s/.test(descriptor)) {
    throw new Error(`${field} descriptor must be canonical (whitespace-free) and checksum-free`);
  }
  if (/#/.test(descriptor)) {
    throw new Error(`${field} descriptor must not include a checksum`);
  }
}

export function computeWalletId(params: {
  network: NetworkId;
  receiveDescriptor: string;
  changeDescriptor: string;
}): WalletId {
  assertCanonicalDescriptorText(params.receiveDescriptor, 'receive');
  assertCanonicalDescriptorText(params.changeDescriptor, 'change');
  const preimage = concatBytes(
    utf8(params.network),
    u8be(0x00),
    utf8(params.receiveDescriptor),
    u8be(0x00),
    utf8(params.changeDescriptor),
  );
  return taggedHash(WALLET_ID_TAG, preimage);
}

export function walletIdToHex(walletId: WalletId): string {
  if (walletId.length !== WALLET_ID_LENGTH) {
    throw new Error(`wallet id must be ${WALLET_ID_LENGTH} bytes`);
  }
  return bytesToHex(walletId);
}

export function walletIdFromHex(hex: string): WalletId {
  const bytes = hexToBytes(hex);
  if (bytes.length !== WALLET_ID_LENGTH) {
    throw new Error(`wallet id must be ${WALLET_ID_LENGTH} bytes`);
  }
  return bytes;
}
