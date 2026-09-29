/**
 * A minimal BIP-174 (PSBT) reader for the authorization lane's subject
 * adapter. The adapter needs only: the unsigned transaction, each input's
 * utxo (witness or non-witness), the declared sighash type, and tapscript
 * leaf scripts with their control blocks — enough to re-derive the lane's
 * sighash per the envelope's posture disclosure. Everything else is skipped
 * (forward-compatible per BIP-174's unknown-key rule).
 *
 * This is a READER, not a serializer or a validator beyond structure: it
 * never mutates, never signs, and refuses any structure it cannot walk
 * deterministically (fail closed, never skip a section it cannot parse).
 */

import { taggedHash } from '../contracts/encoding';
import { compactSize } from '../contracts/authorizationSubject';

export const PSBT_MAGIC = Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff]);

/** BIP-174 key types the adapter consumes. */
export const PSBT_GLOBAL_UNSIGNED_TX = 0x00;
export const PSBT_GLOBAL_VERSION = 0xfb;
export const PSBT_IN_NON_WITNESS_UTXO = 0x00;
export const PSBT_IN_WITNESS_UTXO = 0x01;
export const PSBT_IN_SIGHASH_TYPE = 0x03;
export const PSBT_IN_TAP_LEAF_SCRIPT = 0x15;

/** BIP-341 tapscript leaf version for a standard tapscript leaf. */
export const TAPSCRIPT_LEAF_VERSION = 0xc0;

export class PsbtParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PsbtParseError';
    Object.setPrototypeOf(this, PsbtParseError.prototype);
  }
}

function fail(message: string): never {
  throw new PsbtParseError(message);
}

export interface ParsedTxInput {
  /** Prevout hash in wire (serialized) byte order. */
  txid: Uint8Array;
  vout: number;
  scriptSig: Uint8Array;
  sequence: number;
}

export interface ParsedTxOutput {
  value: number;
  scriptPubKey: Uint8Array;
}

export interface ParsedTx {
  version: number;
  inputs: ParsedTxInput[];
  outputs: ParsedTxOutput[];
  lockTime: number;
}

export interface ParsedWitnessUtxo {
  value: number;
  scriptPubKey: Uint8Array;
}

export interface ParsedTapLeafScript {
  /** The control block as the PSBT key data carries it. */
  controlBlock: Uint8Array;
  /** The tapscript body (without its leaf-version byte). */
  script: Uint8Array;
  leafVersion: number;
}

export interface ParsedPsbtInput {
  witnessUtxo?: ParsedWitnessUtxo;
  nonWitnessUtxo?: Uint8Array;
  sighashType?: number;
  tapLeafScripts: ParsedTapLeafScript[];
}

export interface ParsedPsbt {
  unsignedTx: ParsedTx;
  inputs: ParsedPsbtInput[];
  raw: Uint8Array;
}

interface Cursor {
  data: Uint8Array;
  offset: number;
}

function readBytes(c: Cursor, n: number, what: string): Uint8Array {
  if (c.offset + n > c.data.length) {
    fail(`truncated PSBT: ${what} needs ${n} bytes at offset ${c.offset}`);
  }
  const out = c.data.subarray(c.offset, c.offset + n);
  c.offset += n;
  return out;
}

function readVarInt(c: Cursor, what: string): number {
  const first = readBytes(c, 1, what)[0];
  if (first < 0xfd) return first;
  const width = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
  const bytes = readBytes(c, width, what);
  let v = 0n;
  for (let i = width - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail(`${what} length exceeds the addressable range`);
  }
  return Number(v);
}

function readLe32(c: Cursor, what: string): number {
  const b = readBytes(c, 4, what);
  // Plain arithmetic, not bitwise OR — the OR form sign-truncates through
  // int32 and turns sequences ≥ 0x80000000 negative.
  return b[0] + b[1] * 0x100 + b[2] * 0x10000 + b[3] * 0x1000000;
}

function readLe64(c: Cursor, what: string): number {
  const b = readBytes(c, 8, what);
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail(`${what} value exceeds the addressable range`);
  }
  return Number(v);
}

/** Parse a serialized Bitcoin transaction (the unsigned-tx shape). */
export function parseTransaction(tx: Uint8Array): ParsedTx {
  const c: Cursor = { data: tx, offset: 0 };
  const version = readLe32(c, 'tx version');
  const inputCount = readVarInt(c, 'input count');
  const inputs: ParsedTxInput[] = [];
  for (let i = 0; i < inputCount; i++) {
    inputs.push({
      txid: Uint8Array.from(readBytes(c, 32, 'prevout hash')),
      vout: readLe32(c, 'prevout index'),
      scriptSig: Uint8Array.from(readBytes(c, readVarInt(c, 'scriptSig length'), 'scriptSig')),
      sequence: readLe32(c, 'sequence'),
    });
  }
  const outputCount = readVarInt(c, 'output count');
  const outputs: ParsedTxOutput[] = [];
  for (let i = 0; i < outputCount; i++) {
    outputs.push({
      value: readLe64(c, 'output value'),
      scriptPubKey: Uint8Array.from(
        readBytes(c, readVarInt(c, 'scriptPubKey length'), 'scriptPubKey')),
    });
  }
  const lockTime = readLe32(c, 'locktime');
  if (c.offset !== tx.length) {
    fail('trailing bytes after the transaction body');
  }
  return { version, inputs, outputs, lockTime };
}

interface SectionEntry {
  key: Uint8Array;
  value: Uint8Array;
}

function readSection(c: Cursor, what: string): SectionEntry[] {
  const entries: SectionEntry[] = [];
  for (;;) {
    const keyLength = readVarInt(c, `${what} key length`);
    if (keyLength === 0) break; // separator
    const key = readBytes(c, keyLength, `${what} key`);
    const valueLength = readVarInt(c, `${what} value length`);
    const value = readBytes(c, valueLength, `${what} value`);
    entries.push({ key, value });
  }
  return entries;
}

/**
 * Parse a base64-encoded PSBT into the structures the subject adapter
 * needs. Unknown global/input key types are skipped per BIP-174; anything
 * malformed fails closed.
 */
export function parsePsbt(psbtBase64: string): ParsedPsbt {
  const decoded = Uint8Array.from(atob(psbtBase64), ch => ch.charCodeAt(0));
  return parsePsbtBytes(decoded);
}

/** Parse raw PSBT bytes (the exact received subject bytes). */
export function parsePsbtBytes(decoded: Uint8Array): ParsedPsbt {
  if (decoded.length < PSBT_MAGIC.length ||
      PSBT_MAGIC.some((b, i) => decoded[i] !== b)) {
    fail('not a PSBT: magic bytes missing');
  }
  const c: Cursor = { data: decoded, offset: PSBT_MAGIC.length };
  let unsignedTx: ParsedTx | undefined;
  let psbtVersion = 0;
  for (const { key, value } of readSection(c, 'global')) {
    const keyType = key[0];
    if (keyType === PSBT_GLOBAL_UNSIGNED_TX) {
      if (key.length !== 1) fail('global unsigned-tx key carries key data');
      unsignedTx = parseTransaction(value);
    } else if (keyType === PSBT_GLOBAL_VERSION) {
      if (value.length !== 4) fail('global version must be LE32');
      psbtVersion = value[0] + value[1] * 0x100 + value[2] * 0x10000 + value[3] * 0x1000000;
    }
    // Other global keys (proprietary, xpub) are not consumed.
  }
  if (psbtVersion !== 0) {
    fail(`unsupported PSBT version ${psbtVersion} — the lane consumes BIP-174 v0 only`);
  }
  if (!unsignedTx) fail('global map carries no unsigned transaction');

  const inputs: ParsedPsbtInput[] = [];
  for (let i = 0; i < unsignedTx.inputs.length; i++) {
    const input: ParsedPsbtInput = { tapLeafScripts: [] };
    for (const { key, value } of readSection(c, `input ${i}`)) {
      const keyType = key[0];
      const keyData = key.subarray(1);
      if (keyType === PSBT_IN_WITNESS_UTXO) {
        if (key.length !== 1) fail('witness-utxo key carries key data');
        const vc: Cursor = { data: value, offset: 0 };
        input.witnessUtxo = {
          value: readLe64(vc, 'witness utxo value'),
          scriptPubKey: Uint8Array.from(
            readBytes(vc, readVarInt(vc, 'witness utxo script length'), 'witness utxo script')),
        };
        if (vc.offset !== value.length) fail('trailing bytes in the witness utxo');
      } else if (keyType === PSBT_IN_NON_WITNESS_UTXO) {
        if (key.length !== 1) fail('non-witness-utxo key carries key data');
        input.nonWitnessUtxo = value;
      } else if (keyType === PSBT_IN_SIGHASH_TYPE) {
        if (key.length !== 1) fail('sighash-type key carries key data');
        if (value.length !== 4) fail('sighash type must be LE32');
        input.sighashType =
          value[0] + value[1] * 0x100 + value[2] * 0x10000 + value[3] * 0x1000000;
      } else if (keyType === PSBT_IN_TAP_LEAF_SCRIPT) {
        if (keyData.length === 0) fail('tap-leaf-script key carries no control block');
        if (value.length < 2) fail('tap-leaf-script value too short for a script and version');
        input.tapLeafScripts.push({
          controlBlock: Uint8Array.from(keyData),
          script: Uint8Array.from(value.subarray(0, value.length - 1)),
          leafVersion: value[value.length - 1],
        });
      }
    }
    inputs.push(input);
  }

  // The output maps are not consumed; walk them so a malformed trailing
  // section still fails closed. BIP-174 ends after the output maps — the
  // fee is computed from the inputs and outputs, never encoded.
  for (let i = 0; i < unsignedTx.outputs.length; i++) {
    readSection(c, `output ${i}`);
  }
  if (c.offset !== decoded.length) fail('trailing bytes after the PSBT output maps');

  return { unsignedTx, inputs, raw: decoded };
}

/**
 * The BIP-341 tapleaf hash: tagged "TapLeaf" over
 * leafVersion || compactSize(len(script)) || script.
 */
export function tapLeafHash(leaf: ParsedTapLeafScript): Uint8Array {
  return taggedHash('TapLeaf', new Uint8Array([
    ...[leaf.leafVersion],
    ...compactSize(leaf.script.length),
    ...leaf.script,
  ]));
}
