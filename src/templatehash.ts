/**
 * TX_TEMPLATE_HASH_MATCHES commitment computation.
 *
 * TX220 replaced the original BIP-446-tagged-SHA256 semantic (which the
 * in-circuit gate never actually enforced against — see the wasm-side
 * TX220 task file for the full root-cause trail) with a zero-SHA256-block
 * GF(2^128) algebraic polynomial commitment over the same six preimage
 * fields: nVersion, nLockTime, sha_sequences, sha_outputs, annex_present,
 * input_index. The unified circuit sits at a hard, zero-slack 64/64
 * SHA256-block budget — a real in-circuit BIP-446 hash would cost 2 more
 * blocks and roughly double proof cost for every signing operation.
 * TX_TEMPLATE_HASH_MATCHES is Sigbash-internal POET enforcement only
 * (BIP-446/OP_TEMPLATEHASH is not a real, consensus-active Bitcoin opcode),
 * so bit-for-bit compatibility with the literal BIP-446 tagged hash is not
 * required.
 *
 * This mirrors wasm/longfellow_templatehash_poly_commit.go exactly (same
 * GF(2^128) field, modulus x^128+x^7+x^2+x+1, same per-field encoding) —
 * cross-checked byte-for-byte against the Go implementation for multiple
 * random inputs before landing. Users/wallets must NOT be asked to
 * hand-compute this themselves; this module (or the equivalent WASM export,
 * SigbashWASM_ComputeTemplateHashCommitment) is the single source of truth.
 */

function circuitConstant(tag: string): bigint {
  // Lazily require crypto so this module works in both Node and any
  // bundler target that polyfills it; avoids a top-level Node-only import
  // breaking browser bundling of unrelated SDK entry points.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const crypto = require('crypto');
  const digest: Buffer = crypto.createHash('sha256').update(tag).digest();
  return bytesToBigIntLE(digest.subarray(0, 16));
}

function bytesToBigIntLE(buf: Uint8Array): bigint {
  let v = 0n;
  for (let i = buf.length - 1; i >= 0; i--) {
    v = (v << 8n) | BigInt(buf[i]);
  }
  return v;
}

let cachedBeta: bigint | null = null;
let cachedGamma: bigint | null = null;
function templateHashPolyBeta(): bigint {
  if (cachedBeta === null) cachedBeta = circuitConstant('EMZA_TEMPLATEHASH_POLY_BETA_V1');
  return cachedBeta;
}
function templateHashFieldGamma(): bigint {
  if (cachedGamma === null) cachedGamma = circuitConstant('EMZA_TEMPLATEHASH_FIELD_GAMMA_V1');
  return cachedGamma;
}

/**
 * GF(2^128) multiplication modulo x^128+x^7+x^2+x+1 (the same modulus
 * GCM/GHASH uses). Carry-less multiply via shift-and-XOR, then reduce using
 * x^128 = x^7+x^2+x+1 (constant term 0x87).
 */
function gf128Mul(a: bigint, b: bigint): bigint {
  let result = 0n;
  for (let i = 0n; i < 128n; i++) {
    if ((b >> i) & 1n) {
      result ^= a << i;
    }
  }
  for (let i = 254n; i >= 128n; i--) {
    if ((result >> i) & 1n) {
      result ^= 1n << i;
      result ^= 0x87n << (i - 128n);
    }
  }
  return result;
}

function u32le(v: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v >>> 0, true);
  return b;
}

function elemFromField(buf: Uint8Array): bigint {
  const padLen = Math.ceil(buf.length / 8) * 8;
  const padded = new Uint8Array(padLen);
  padded.set(buf);
  const n = padLen / 8;
  const chunks: bigint[] = [];
  for (let c = 0; c < n; c++) {
    chunks.push(bytesToBigIntLE(padded.subarray(c * 8, (c + 1) * 8)));
  }
  let acc = chunks[n - 1];
  for (let i = n - 2; i >= 0; i--) {
    acc = gf128Mul(acc, templateHashFieldGamma()) ^ chunks[i];
  }
  return acc;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 === 0 ? hex : `0${hex}`;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

function bytesToHex(buf: Uint8Array): string {
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export interface TemplateHashRawFields {
  /** Transaction version */
  nVersion: number;
  /** Transaction locktime */
  nLockTime: number;
  /** 64-hex-char SHA256 of all input nSequence values (BIP-341 sha_sequences) */
  shaSequences: string;
  /** 64-hex-char SHA256 of all CTxOut-serialized outputs (BIP-341 sha_outputs) */
  shaOutputs: string;
  /** Whether an annex is present (default false — annex support not implemented) */
  annexPresent?: boolean;
  /** Index of the input this template applies to */
  inputIndex: number;
}

/**
 * Computes TX_TEMPLATE_HASH_MATCHES's committed "value": the packed
 * GF(2^128) polynomial commitment P over the six raw BIP-446 preimage
 * fields (bytes 0..15 = P little-endian, bytes 16..31 = zero padding —
 * matches wasm/longfellow_templatehash_poly_commit.go's
 * lfTemplateHashPolyCommitBytes exactly). This is what
 * ConditionParams.expected_template_hash must be set to.
 */
export function computeTemplateHashCommitment(fields: TemplateHashRawFields): string {
  const shaSeq = hexToBytes(fields.shaSequences);
  const shaOut = hexToBytes(fields.shaOutputs);
  if (shaSeq.length !== 32) throw new Error('shaSequences must be 64 hex characters (32 bytes)');
  if (shaOut.length !== 32) throw new Error('shaOutputs must be 64 hex characters (32 bytes)');

  const elems = [
    elemFromField(u32le(fields.nVersion)),
    elemFromField(u32le(fields.nLockTime)),
    elemFromField(shaSeq),
    elemFromField(shaOut),
    elemFromField(new Uint8Array([fields.annexPresent ? 1 : 0])),
    elemFromField(u32le(fields.inputIndex)),
  ];

  let p = templateHashPolyBeta() ^ elems[0];
  for (let i = 1; i < elems.length; i++) {
    p = gf128Mul(p, templateHashPolyBeta() ^ elems[i]);
  }

  const lo = p & ((1n << 64n) - 1n);
  const hi = p >> 64n;
  const out = new Uint8Array(32);
  const dv = new DataView(out.buffer);
  dv.setBigUint64(0, lo, true);
  dv.setBigUint64(8, hi, true);
  return bytesToHex(out);
}
