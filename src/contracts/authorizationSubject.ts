/**
 * Authorization subject binding — the SDK's TypeScript mirror of the lane's
 * cryptographic constructions (wasm/authorization_envelope.go, Flask mirror
 * api/contracts.py).
 *
 * The authorization lane binds an action through the pins the proof circuit
 * already exposes; per position, e_hat = SHA256_BIP340("BIP0340/challenge",
 * R'_x || Q_x || sighash) + beta (mod 2^256), with beta =
 * SHA256_compression(sighash_state, "SIGBASH_BETA_V1\0" || sigma || pad).
 * THE LANE NEVER SIGNS: e' is a hash ingredient inside e_hat only, which is
 * why Q is the position's prevout output key rather than a wallet key.
 *
 * Every function here asserts the committed golden vectors in
 * contracts/vectors/contracts-v1.json (harvested from the wasm suite's
 * golden log), so a mirror drift fails a test, never a proof.
 */

import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { taggedHash, utf8, concatBytes, bytesToHex, hexToBytes } from './encoding';

export const AUTHZ_RNONCE_TAG = 'SIGBASH.AUTHZ.RNONCE.V1';
export const AUTHZ_QKEY_TAG = 'SIGBASH.AUTHZ.QKEY.V1';
export const AUTHZ_PINAGG_TAG = 'SIGBASH.AUTHZ.PINAGG.V1';
export const AUTHZ_BURNSET_TAG = 'SIGBASH.AUTHZ.BURNSET.V1';
export const AUTHZ_SCOPE_TAG = 'SIGBASH.AUTHZ.SCOPE.V1';
export const AUTHZ_ACTIONKEY_TAG = 'SIGBASH.AUTHZ.ACTIONKEY.V1';

export const BIP0340_CHALLENGE_TAG = 'BIP0340/challenge';
export const TAPSIGHASH_TAG = 'TapSighash';
export const TAPLEAF_TAG = 'TapLeaf';

/** The beta derivation block's domain tag and padding length word. */
export const AUTHZ_BETA_BLOCK_TAG = utf8('SIGBASH_BETA_V1\0');
export const AUTHZ_BETA_BLOCK_LENGTH = 0x180;

/** One transaction input as the preimage builders consume it. `txid` is in
 * wire (serialized) byte order. */
export interface AuthzTxInput {
  txid: Uint8Array;
  vout: number;
  sequence: number;
  amount: number;
  scriptPubKey: Uint8Array;
}

/** One transaction output as the preimage builders consume it. */
export interface AuthzTxOutput {
  value: number;
  scriptPubKey: Uint8Array;
}

/**
 * One raw SHA-256 compression: 8-word state in, 8-word state out. `state`
 * and the return value are 32-byte big-endian renderings of the eight state
 * words, matching the compression-call convention the beta derivation uses.
 */
export function sha256Compress(state: Uint8Array, block: Uint8Array): Uint8Array {
  if (state.length !== 32 || block.length !== 64) {
    throw new Error('sha256Compress requires a 32-byte state and a 64-byte block');
  }
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const dv = new DataView(block.buffer, block.byteOffset, block.byteLength);
  const w = new Array<number>(64);
  for (let i = 0; i < 16; i++) w[i] = dv.getUint32(i * 4, false);
  for (let i = 16; i < 64; i++) {
    const x = w[i - 15];
    const y = w[i - 2];
    const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
    w[i] = (w[i - 16] + (s0 >>> 0) + w[i - 7] + (s1 >>> 0)) >>> 0;
  }
  const sv = new DataView(state.buffer, state.byteOffset, state.byteLength);
  let a = sv.getUint32(0, false);
  let b = sv.getUint32(4, false);
  let c = sv.getUint32(8, false);
  let d = sv.getUint32(12, false);
  let e = sv.getUint32(16, false);
  let f = sv.getUint32(20, false);
  let g = sv.getUint32(24, false);
  let h = sv.getUint32(28, false);
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + (S1 >>> 0) + (ch >>> 0) + K[i] + w[i]) >>> 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = ((S0 >>> 0) + (maj >>> 0)) >>> 0;
    h = g; g = f; f = e; e = (d + t1) >>> 0;
    d = c; c = b; b = a; a = (t1 + t2) >>> 0;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, (a + sv.getUint32(0, false)) >>> 0, false);
  ov.setUint32(4, (b + sv.getUint32(4, false)) >>> 0, false);
  ov.setUint32(8, (c + sv.getUint32(8, false)) >>> 0, false);
  ov.setUint32(12, (d + sv.getUint32(12, false)) >>> 0, false);
  ov.setUint32(16, (e + sv.getUint32(16, false)) >>> 0, false);
  ov.setUint32(20, (f + sv.getUint32(20, false)) >>> 0, false);
  ov.setUint32(24, (g + sv.getUint32(24, false)) >>> 0, false);
  ov.setUint32(28, (h + sv.getUint32(28, false)) >>> 0, false);
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function bigIntToBytes32(v: bigint): Uint8Array {
  const hex = v.toString(16).padStart(64, '0');
  return hexToBytes(hex);
}

/** Bitcoin compact-size serialization of a length. */
export function compactSize(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0) throw new RangeError(`compactSize: ${n}`);
  if (n < 253) return Uint8Array.from([n]);
  if (n <= 0xffff) {
    const out = new Uint8Array(3);
    out[0] = 0xfd;
    out[1] = n & 0xff;
    out[2] = (n >>> 8) & 0xff;
    return out;
  }
  if (n <= 0xffffffff) {
    const out = new Uint8Array(5);
    out[0] = 0xfe;
    for (let i = 0; i < 4; i++) out[1 + i] = (n >>> (8 * i)) & 0xff;
    return out;
  }
  const out = new Uint8Array(9);
  out[0] = 0xff;
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    out[1 + i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * R'_x = (SHA256(tag || salt || session_id) mod n) * G, x-only.
 *
 * The salt is the existing client-held policy salt; the derivation is
 * deterministic so the client-side adapter can re-derive e_hat. A zero
 * scalar rehashes with a counter suffix, mirroring the wasm derivation.
 */
export function authzDeriveRNonceX(salt: Uint8Array, sessionId: Uint8Array): Uint8Array {
  if (salt.length !== 32 || sessionId.length !== 32) {
    throw new Error('authzDeriveRNonceX requires 32-byte salt and session id');
  }
  const tagBytes = utf8(AUTHZ_RNONCE_TAG);
  const order = secp256k1.Point.Fn.ORDER;
  for (let attempt = 0; attempt < 256; attempt++) {
    const msg = attempt > 0
      ? concatBytes(tagBytes, salt, sessionId, Uint8Array.from([attempt]))
      : concatBytes(tagBytes, salt, sessionId);
    const scalarMod = bytesToBigInt(sha256(msg)) % order;
    if (scalarMod === 0n) continue;
    const affine = secp256k1.Point.BASE.multiply(scalarMod).toAffine();
    return bigIntToBytes32(affine.x);
  }
  throw new Error('r-nonce derivation exhausted its attempts');
}

/**
 * The Q ingredient: the prevout's output key. A 34-byte P2TR prevout uses
 * its x-only output key directly; any other script shape uses a tagged
 * digest of the prevout scriptPubKey.
 */
export function authzPrevoutQ(scriptPubKey: Uint8Array): Uint8Array {
  if (
    scriptPubKey.length === 34 &&
    scriptPubKey[0] === 0x51 && scriptPubKey[1] === 0x20
  ) {
    return scriptPubKey.slice(2, 34);
  }
  return sha256(
    concatBytes(utf8(AUTHZ_QKEY_TAG), compactSize(scriptPubKey.length), scriptPubKey),
  );
}

function sha256d(...chunks: Uint8Array[]): Uint8Array {
  return sha256(concatBytes(...chunks));
}

function assertFixed32(bytes: Uint8Array, field: string): void {
  if (bytes.length !== 32) {
    throw new Error(`${field} must be exactly 32 bytes, got ${bytes.length}`);
  }
}

function le32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) out[i] = (n >>> (8 * i)) & 0xff;
  return out;
}

function le64(n: number): Uint8Array {
  const out = new Uint8Array(8);
  let v = BigInt(Math.trunc(n));
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function hashInputAmounts(inputs: AuthzTxInput[]): Uint8Array {
  return sha256(concatBytes(...inputs.map(i => le64(i.amount))));
}

function hashInputScripts(inputs: AuthzTxInput[]): Uint8Array {
  return sha256(
    concatBytes(...inputs.map(i => concatBytes(compactSize(i.scriptPubKey.length), i.scriptPubKey))),
  );
}

function hashOutputsRaw(outputs: AuthzTxOutput[]): Uint8Array {
  return concatBytes(
    ...outputs.map(o => concatBytes(le64(o.value), compactSize(o.scriptPubKey.length), o.scriptPubKey)),
  );
}

function keyPathPreimage(
  inputs: AuthzTxInput[],
  outputs: AuthzTxOutput[],
  inputIndex: number,
  spendType: number,
  version: number,
  lockTime: number,
): Uint8Array {
  const prevouts = concatBytes(...inputs.map(i => concatBytes(i.txid, le32(i.vout))));
  const sequences = concatBytes(...inputs.map(i => le32(i.sequence)));
  return concatBytes(
    Uint8Array.from([0x00]),       // epoch
    Uint8Array.from([0x00]),       // hash_type normalized to SIGHASH_DEFAULT
    le32(version),
    le32(lockTime),
    sha256(prevouts),
    hashInputAmounts(inputs),
    hashInputScripts(inputs),
    sha256(sequences),
    sha256(hashOutputsRaw(outputs)),
    Uint8Array.from([spendType]),
    le32(inputIndex),
  );
}

function acpPreimage(
  inputs: AuthzTxInput[],
  outputs: AuthzTxOutput[],
  inputIndex: number,
  spendType: number,
  version: number,
  lockTime: number,
): Uint8Array {
  const src = inputs[inputIndex];
  if (src.scriptPubKey.length !== 34) {
    throw new Error('the ACP encoding is P2TR-shaped');
  }
  return concatBytes(
    Uint8Array.from([0x00]),
    Uint8Array.from([0x81]),
    le32(version),
    le32(lockTime),
    sha256(hashOutputsRaw(outputs)),
    Uint8Array.from([spendType]),
    src.txid,
    le32(src.vout),
    le64(src.amount),
    Uint8Array.from([0x22]),       // the 34-byte script's fixed length byte
    src.scriptPubKey,
    le32(src.sequence),
  );
}

/** The tapscript extension: leaf hash, key version, code-separator position. */
export function tapscriptExtension(
  leafHash: Uint8Array,
  keyVersion = 0,
  codesepPos = 0xffffffff,
): Uint8Array {
  return concatBytes(leafHash, Uint8Array.from([keyVersion]), le32(codesepPos));
}

/** The lane's canonical sighash for a non-ACP position (key-path shape). */
export function authzSighashKeyPath(
  inputs: AuthzTxInput[],
  outputs: AuthzTxOutput[],
  inputIndex: number,
  version = 2,
  lockTime = 0,
): Uint8Array {
  return taggedHash(TAPSIGHASH_TAG, keyPathPreimage(inputs, outputs, inputIndex, 0x00, version, lockTime));
}

/** The lane's canonical sighash for an ANYONECANPAY position (126-byte preimage). */
export function authzSighashAcpKeyPath(
  inputs: AuthzTxInput[],
  outputs: AuthzTxOutput[],
  inputIndex: number,
  version = 2,
  lockTime = 0,
): Uint8Array {
  const preimage = acpPreimage(inputs, outputs, inputIndex, 0x00, version, lockTime);
  if (preimage.length !== 126) {
    throw new Error(`ACP preimage must be 126 bytes, got ${preimage.length}`);
  }
  return taggedHash(TAPSIGHASH_TAG, preimage);
}

/** The lane's canonical sighash for a non-ACP tapscript position (212-byte preimage). */
export function authzSighashTapscriptKeyPath(
  inputs: AuthzTxInput[],
  outputs: AuthzTxOutput[],
  inputIndex: number,
  leafHash: Uint8Array,
  version = 2,
  lockTime = 0,
): Uint8Array {
  const preimage = concatBytes(
    keyPathPreimage(inputs, outputs, inputIndex, 0x02, version, lockTime),
    tapscriptExtension(leafHash),
  );
  if (preimage.length !== 212) {
    throw new Error(`tapscript preimage must be 212 bytes, got ${preimage.length}`);
  }
  return taggedHash(TAPSIGHASH_TAG, preimage);
}

/** The lane's canonical sighash for an ACP tapscript position (163-byte preimage). */
export function authzSighashAcpTapscript(
  inputs: AuthzTxInput[],
  outputs: AuthzTxOutput[],
  inputIndex: number,
  leafHash: Uint8Array,
  version = 2,
  lockTime = 0,
): Uint8Array {
  const preimage = concatBytes(
    acpPreimage(inputs, outputs, inputIndex, 0x02, version, lockTime),
    tapscriptExtension(leafHash),
  );
  if (preimage.length !== 163) {
    throw new Error(`ACP tapscript preimage must be 163 bytes, got ${preimage.length}`);
  }
  return taggedHash(TAPSIGHASH_TAG, preimage);
}

/** beta = SHA256_compression(sighash_state, tag || sigma || pad). */
export function authzBeta(sighash: Uint8Array, sigma: Uint8Array): Uint8Array {
  if (sighash.length !== 32 || sigma.length !== 32) {
    throw new Error('authzBeta requires 32-byte sighash and sigma');
  }
  const block = new Uint8Array(64);
  block.set(AUTHZ_BETA_BLOCK_TAG, 0);
  block.set(sigma, 16);
  block[48] = 0x80;
  const dv = new DataView(block.buffer);
  dv.setUint32(60, AUTHZ_BETA_BLOCK_LENGTH, false);
  return sha256Compress(sighash, block);
}

/** e' = SHA256_BIP340("BIP0340/challenge", R'_x || Q_x || sighash). */
export function authzEPrime(rX: Uint8Array, qX: Uint8Array, sighash: Uint8Array): Uint8Array {
  return taggedHash(BIP0340_CHALLENGE_TAG, concatBytes(rX, qX, sighash));
}

/** e_hat = e' + beta (mod 2^256), matching the in-circuit adder. */
export function authzEHat(rX: Uint8Array, qX: Uint8Array, sighash: Uint8Array, sigma: Uint8Array): Uint8Array {
  const total = bytesToBigInt(authzEPrime(rX, qX, sighash)) + bytesToBigInt(authzBeta(sighash, sigma));
  const wrapped = total & ((1n << 256n) - 1n);
  return bigIntToBytes32(wrapped);
}

export interface AuthzPinEntry {
  /** The pinned BlindedChallengeE (32 bytes). */
  eHat: Uint8Array;
  /** The GKR-verified mode pin (0 = SIGNED, 1 = COORDINATION). */
  positionMode: number;
}

export interface AuthzChunkEntry {
  hashOutputsBlindedCommit: Uint8Array;
  covenantWriteCommit: Uint8Array;
}

export interface AuthzCompletingPins {
  hashOutputsBlindedCommitUnified: Uint8Array;
  hinBlindedCommitUnified: Uint8Array;
  saltBlindedCommitUnified: Uint8Array;
  polyCoeffsBlindedCommitUnified: Uint8Array;
  inputSetPolyProduct: Uint8Array;
}

/**
 * The subject-identity pin aggregate the issuer binds into the artifact:
 * SHA256(tag || sessionID || positionCount LE32 || completingPosition LE32 ||
 * per position e_hat || mode || chunkCount LE32 || per chunk pins ||
 * the five unified completing pins). The authorization lane computes it over
 * ONE entry — the completing bundle's own pins with CompletingPosition = 0.
 */
export function authzPinAggregate(
  sessionId: Uint8Array,
  completingPosition: number,
  positions: AuthzPinEntry[],
  chunks: AuthzChunkEntry[],
  completing: AuthzCompletingPins,
): Uint8Array {
  const msg: Uint8Array[] = [utf8(AUTHZ_PINAGG_TAG), sessionId, le32(positions.length), le32(completingPosition)];
  for (const p of positions) {
    msg.push(p.eHat, Uint8Array.from([p.positionMode]));
  }
  msg.push(le32(chunks.length));
  for (const c of chunks) {
    assertFixed32(c.hashOutputsBlindedCommit, 'hashOutputsBlindedCommit');
    if (c.covenantWriteCommit.length !== 16) {
      throw new Error('covenantWriteCommit must be exactly 16 bytes');
    }
    msg.push(c.hashOutputsBlindedCommit, c.covenantWriteCommit);
  }
  assertFixed32(completing.hashOutputsBlindedCommitUnified, 'hashOutputsBlindedCommitUnified');
  assertFixed32(completing.hinBlindedCommitUnified, 'hinBlindedCommitUnified');
  assertFixed32(completing.saltBlindedCommitUnified, 'saltBlindedCommitUnified');
  assertFixed32(completing.polyCoeffsBlindedCommitUnified, 'polyCoeffsBlindedCommitUnified');
  if (completing.inputSetPolyProduct.length !== 16) {
    throw new Error('inputSetPolyProduct must be exactly 16 bytes');
  }
  msg.push(
    completing.hashOutputsBlindedCommitUnified,
    completing.hinBlindedCommitUnified,
    completing.saltBlindedCommitUnified,
    completing.polyCoeffsBlindedCommitUnified,
    completing.inputSetPolyProduct,
  );
  return sha256d(...msg);
}

export interface AuthzBurnEntry {
  positionIndex: number;
  n0: Uint8Array;
  n1: Uint8Array;
}

/**
 * The aggregate over the session's VERIFIED burn set — the per-position N0/N1
 * commitments the server echoes verbatim at issuance; the backend burns only
 * the echoed set, never a client-declared claim.
 */
export function authzBurnSetAggregate(
  sessionId: Uint8Array,
  entries: AuthzBurnEntry[],
): Uint8Array {
  const msg: Uint8Array[] = [utf8(AUTHZ_BURNSET_TAG), sessionId, le32(entries.length)];
  for (const e of entries) {
    msg.push(le32(e.positionIndex), e.n0, e.n1);
  }
  return sha256d(...msg);
}

/**
 * The action-stable lookup key for one authorized action: SHA-256 over the
 * domain tag and the ordered N_USE (N0) nullifiers of the verified burn
 * echo. The N0 values sit at the even indices of the echoed set.
 */
export function authzActionKey(n0s: Uint8Array[]): Uint8Array {
  return sha256(concatBytes(utf8(AUTHZ_ACTIONKEY_TAG), ...n0s));
}

/** Action key from the echoed burn pair [N0, N1] (N0 at the even index). */
export function authzActionKeyFromBurnPair(burnPair: readonly [string, string]): Uint8Array {
  return authzActionKey([hexToBytes(burnPair[0])]);
}

/**
 * The scope digest the server derives at issuance: SHA256(tag || 0x00 ||
 * credential identifier UTF-8 || key index LE32). Scope is SERVER-DERIVED,
 * never client-asserted — the verifier recomputes it only to compare against
 * the artifact's signed value.
 */
export function authzScope(credentialIdentifier: string, keyIndex: number): Uint8Array {
  return sha256(
    concatBytes(utf8(AUTHZ_SCOPE_TAG), Uint8Array.from([0x00]), utf8(credentialIdentifier), le32(keyIndex)),
  );
}

export { bytesToHex, hexToBytes };
