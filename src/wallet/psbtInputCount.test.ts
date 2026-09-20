/**
 * Minimal PSBT input-count scan. The scanner reads only the global map and
 * the unsigned transaction's input-count varint; every structural deviation
 * fails closed with a typed parse error.
 */

import { PsbtParseError } from './errors';
import { parsePsbtInputCount } from './psbtInputCount';

const PSBT_MAGIC_HEX = '70736274ff';

function varint(value: number): number[] {
  if (value < 0xfd) {
    return [value];
  }
  if (value <= 0xffff) {
    return [0xfd, value & 0xff, (value >> 8) & 0xff];
  }
  return [0xfe, value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >>> 24) & 0xff];
}

function unsignedTx(inputCount: number, options: { segwitFlag?: boolean } = {}): number[] {
  const bytes: number[] = [0x02, 0x00, 0x00, 0x00]; // version
  if (options.segwitFlag) {
    bytes.push(0x00, 0x01);
  }
  bytes.push(...varint(inputCount));
  for (let i = 0; i < Math.min(inputCount, 3); i++) {
    // prevout txid + vout, empty script, sequence (only shape matters here)
    bytes.push(...new Array(32).fill(i + 1), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  }
  return bytes;
}

function psbt(inputCount: number, options: { segwitFlag?: boolean } = {}): string {
  const tx = unsignedTx(inputCount, options);
  const bytes = [
    ...hexToBytes(PSBT_MAGIC_HEX),
    0x01, 0x00,
    ...varint(tx.length),
    ...tx,
    0x00, // global map separator
  ];
  return bytesToHex(new Uint8Array(bytes));
}

function hexToBytes(hex: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    out.push(parseInt(hex.substring(i, i + 2), 16));
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('parsePsbtInputCount', () => {
  it('counts inputs at and around the batch cap', () => {
    expect(parsePsbtInputCount(psbt(1))).toBe(1);
    expect(parsePsbtInputCount(psbt(64))).toBe(64);
    expect(parsePsbtInputCount(psbt(65))).toBe(65);
  });

  it('reads multi-byte varint input counts across every CompactSize width', () => {
    expect(parsePsbtInputCount(psbt(200))).toBe(200);
    expect(parsePsbtInputCount(psbt(253))).toBe(253);
    expect(parsePsbtInputCount(psbt(0x10000))).toBe(0x10000);
  });

  it('counts a base64-encoded PSBT identically to its hex form', () => {
    const raw = new Uint8Array(hexToBytes(psbt(3)));
    const base64 = Buffer.from(raw).toString('base64');
    expect(parsePsbtInputCount(base64)).toBe(3);
  });

  it('tolerates a BIP-144 marker/flag pair without miscounting', () => {
    expect(parsePsbtInputCount(psbt(2, { segwitFlag: true }))).toBe(2);
  });

  it('rejects empty, non-decodable, and magic-less payloads', () => {
    expect(() => parsePsbtInputCount('')).toThrow(PsbtParseError);
    expect(() => parsePsbtInputCount('!!not base64!!')).toThrow(/neither valid base64 nor valid hex/);
    expect(() => parsePsbtInputCount(bytesToHex(new Uint8Array(20)))).toThrow(/magic bytes/);
    expect(() => parsePsbtInputCount(PSBT_MAGIC_HEX)).toThrow(/truncated/);
  });

  it('rejects a global map without an unsigned transaction', () => {
    const bytes = [...hexToBytes(PSBT_MAGIC_HEX), 0x00];
    expect(() => parsePsbtInputCount(bytesToHex(new Uint8Array(bytes)))).toThrow(
      /no unsigned transaction/
    );
  });

  it('rejects a global map truncated before the separator', () => {
    const tx = unsignedTx(1);
    const bytes = [
      ...hexToBytes(PSBT_MAGIC_HEX),
      0x01, 0x00,
      ...varint(tx.length + 4), // value length lies beyond the data
      ...tx,
    ];
    expect(() => parsePsbtInputCount(bytesToHex(new Uint8Array(bytes)))).toThrow(/truncated/);
  });

  it('rejects a duplicated unsigned-transaction record', () => {
    const tx = unsignedTx(1);
    const bytes = [
      ...hexToBytes(PSBT_MAGIC_HEX),
      0x01, 0x00, ...varint(tx.length), ...tx,
      0x01, 0x00, ...varint(tx.length), ...tx,
      0x00,
    ];
    expect(() => parsePsbtInputCount(bytesToHex(new Uint8Array(bytes)))).toThrow(
      /duplicated unsigned transaction/
    );
  });

  it('rejects a truncated transaction header', () => {
    const bytes = [...hexToBytes(PSBT_MAGIC_HEX), 0x01, 0x00, 0x02, 0x01, 0x00, 0x00];
    expect(() => parsePsbtInputCount(bytesToHex(new Uint8Array(bytes)))).toThrow(
      /transaction is truncated/
    );
  });
});
