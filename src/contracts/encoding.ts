/**
 * Canonical binary encoding primitives for the cross-component contracts.
 *
 * Every binary contract encoding is big-endian, length-delimited where a
 * field has variable size, and opens with a two-byte header:
 *   [contract_id (u8), contract_version (u8)]
 * Decoders reject unknown contract ids and unsupported versions (fail
 * closed) and reject trailing bytes. One canonical definition per contract
 * lives under src/contracts; the Flask mirror in the application backend
 * re-implements only what it must verify and cross-checks against the
 * golden vectors.
 */

import { sha256 } from '@noble/hashes/sha256';
import { SigbashSDKError } from '../errors';

export class ContractVersionError extends SigbashSDKError {
  constructor(message: string) {
    super(message, 'CONTRACT_VERSION_UNSUPPORTED');
    this.name = 'ContractVersionError';
    Object.setPrototypeOf(this, ContractVersionError.prototype);
  }
}

export function u8be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new RangeError(`u8 out of range: ${value}`);
  }
  return new Uint8Array([value]);
}

export function u16be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError(`u16 out of range: ${value}`);
  }
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, false);
  return out;
}

export function u32be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError(`u32 out of range: ${value}`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

export function u64be(value: bigint | number): Uint8Array {
  const v = typeof value === 'bigint' ? value : BigInt(Math.trunc(value));
  if (v < 0n || v > 0xffffffffffffffffn) {
    throw new RangeError(`u64 out of range: ${value}`);
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, false);
  return out;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Length-delimited field: u32be byte length followed by the raw bytes. */
export function lengthDelimited(payload: Uint8Array): Uint8Array {
  if (payload.length > 0xffffffff) {
    throw new RangeError('length-delimited field too large');
  }
  return concatBytes(u32be(payload.length), payload);
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/**
 * BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
 * Mirrors wasm computeTaggedHash exactly.
 */
export function taggedHash(tag: string, msg: Uint8Array): Uint8Array {
  const tagHash = sha256(utf8(tag));
  return sha256(concatBytes(tagHash, tagHash, msg));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new Error('invalid hex encoding');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function assertFixedLength(bytes: Uint8Array, length: number, field: string): void {
  if (bytes.length !== length) {
    throw new Error(`${field} must be exactly ${length} bytes, got ${bytes.length}`);
  }
}

export interface Decoder {
  data: Uint8Array;
  offset: number;
}

export function readBytes(d: Decoder, n: number, field: string): Uint8Array {
  if (d.offset + n > d.data.length) {
    throw new Error(`${field}: truncated input`);
  }
  const out = d.data.subarray(d.offset, d.offset + n);
  d.offset += n;
  return out;
}

export function readU8(d: Decoder, field: string): number {
  return readBytes(d, 1, field)[0];
}

export function readU16(d: Decoder, field: string): number {
  const bytes = readBytes(d, 2, field);
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(0, false);
}

export function readU32(d: Decoder, field: string): number {
  const bytes = readBytes(d, 4, field);
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
}

export function readU64(d: Decoder, field: string): bigint {
  const bytes = readBytes(d, 8, field);
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, false);
}

export function readLengthDelimited(d: Decoder, field: string): Uint8Array {
  const len = readU32(d, `${field}.length`);
  return readBytes(d, len, field);
}

export function expectExhausted(d: Decoder, contract: string): void {
  if (d.offset !== d.data.length) {
    throw new Error(`${contract}: trailing bytes after final field`);
  }
}

/**
 * Read and validate the two-byte contract header. Fail closed on an
 * unknown contract id or an unsupported version.
 */
export function readContractHeader(
  d: Decoder,
  expectedContractId: number,
  supportedVersions: readonly number[],
  contractName: string,
): number {
  const id = readU8(d, `${contractName}.contract_id`);
  if (id !== expectedContractId) {
    throw new ContractVersionError(`${contractName}: unknown contract id 0x${id.toString(16)}`);
  }
  const version = readU8(d, `${contractName}.version`);
  if (!supportedVersions.includes(version)) {
    throw new ContractVersionError(
      `${contractName}: unsupported version ${version} (supported: ${supportedVersions.join(', ')})`,
    );
  }
  return version;
}

export function contractHeader(contractId: number, version: number): Uint8Array {
  return concatBytes(u8be(contractId), u8be(version));
}
