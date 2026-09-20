/**
 * Minimal PSBT input-count scan.
 *
 * The protocol enforces a hard input cap per signing session server-side; a
 * session above the cap can never prove, so the client fails closed before
 * spending a proof attempt. This scanner reads only what the count needs:
 * the PSBT global map and the unsigned transaction's input count. It never
 * parses or validates full transaction structure.
 */

import { PsbtParseError } from './errors';

const PSBT_MAGIC = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]);

function decodePsbtBytes(psbt: string): Uint8Array {
  if (psbt === '') {
    throw new PsbtParseError('PSBT is required');
  }
  const hexRe = /^(?:[0-9a-fA-F]{2})+$/;
  if (hexRe.test(psbt)) {
    const out = new Uint8Array(psbt.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(psbt.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
  const normalized = psbt.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
  let raw: string;
  try {
    raw = atob(normalized);
  } catch {
    throw new PsbtParseError('PSBT is neither valid base64 nor valid hex');
  }
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

/**
 * Bitcoin CompactSize: a value below 0xfd is one byte; the 0xfd/0xfe/0xff
 * prefixes announce a fixed 2/4/8-byte little-endian value. This is not a
 * continuation-bit varint — every byte of a short value is data, high bit
 * included.
 */
function readVarint(data: Uint8Array, offset: number, field: string): { value: number; next: number } {
  if (offset >= data.length) {
    throw new PsbtParseError(`PSBT is truncated in ${field}`);
  }
  const prefix = data[offset++];
  let value: number;
  if (prefix < 0xfd) {
    value = prefix;
  } else if (prefix === 0xfd) {
    if (offset + 2 > data.length) {
      throw new PsbtParseError(`PSBT is truncated in ${field}`);
    }
    value = data[offset] | (data[offset + 1] << 8);
    offset += 2;
  } else if (prefix === 0xfe) {
    if (offset + 4 > data.length) {
      throw new PsbtParseError(`PSBT is truncated in ${field}`);
    }
    value =
      (data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0;
    offset += 4;
  } else {
    if (offset + 8 > data.length) {
      throw new PsbtParseError(`PSBT is truncated in ${field}`);
    }
    let acc = 0n;
    for (let i = 7; i >= 0; i--) {
      acc = (acc << 8n) | BigInt(data[offset + i]);
    }
    offset += 8;
    if (acc > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new PsbtParseError(`PSBT ${field} varint is out of range`);
    }
    value = Number(acc);
  }
  return { value, next: offset };
}

/**
 * Counts the inputs of the PSBT's global unsigned transaction. Fail-closed
 * on any structural deviation: missing magic, truncated global map, missing
 * unsigned-tx record, or a malformed transaction header.
 */
export function parsePsbtInputCount(psbt: string): number {
  const data = decodePsbtBytes(psbt);
  if (data.length < PSBT_MAGIC.length) {
    throw new PsbtParseError('PSBT is truncated');
  }
  for (let i = 0; i < PSBT_MAGIC.length; i++) {
    if (data[i] !== PSBT_MAGIC[i]) {
      throw new PsbtParseError('PSBT magic bytes are missing');
    }
  }
  let pos = PSBT_MAGIC.length;
  let txBytes: Uint8Array | undefined;
  for (;;) {
    if (pos >= data.length) {
      throw new PsbtParseError('PSBT global map is truncated');
    }
    const keyLen = readVarint(data, pos, 'global key length');
    pos = keyLen.next;
    if (keyLen.value === 0) {
      break; // global map separator
    }
    const key = data.slice(pos, pos + keyLen.value);
    if (key.length !== keyLen.value) {
      throw new PsbtParseError('PSBT global map is truncated');
    }
    pos += keyLen.value;
    const valueLen = readVarint(data, pos, 'global value length');
    pos = valueLen.next;
    const value = data.slice(pos, pos + valueLen.value);
    if (value.length !== valueLen.value) {
      throw new PsbtParseError('PSBT global map is truncated');
    }
    pos += valueLen.value;
    if (key.length === 1 && key[0] === 0x00) {
      if (txBytes !== undefined) {
        throw new PsbtParseError('PSBT carries a duplicated unsigned transaction record');
      }
      txBytes = value;
    }
  }
  if (txBytes === undefined) {
    throw new PsbtParseError('PSBT global map carries no unsigned transaction');
  }
  return countTxInputs(txBytes);
}

function countTxInputs(tx: Uint8Array): number {
  if (tx.length < 5) {
    throw new PsbtParseError('unsigned transaction is truncated');
  }
  let pos = 4; // version
  // BIP-144 marker/flag (0x00 0x01) may appear in serialized transactions;
  // the PSBT global unsigned transaction must be non-witness, but decoding
  // tolerates the flag pair rather than miscounting if one slips through.
  if (tx[pos] === 0x00 && tx[pos + 1] === 0x01) {
    pos += 2;
  }
  const { value } = readVarint(tx, pos, 'input count');
  return value;
}
