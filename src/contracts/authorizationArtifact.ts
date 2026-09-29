/**
 * AuthorizationArtifact — the issuer-signed artifact the authorization lane
 * returns at issuance and every enforcer verifies offline.
 *
 * Canonical definition of the artifact's binary encoding, mirroring the
 * Moon-side encoder field for field: a fixed ASCII prefix, then a
 * little-endian version word, three length-prefixed strings, three 32-byte
 * commitments, three little-endian 64-bit numbers, a 32-byte nonce, two more
 * length-prefixed strings, and the burn-set aggregate as the final field.
 *
 * Endianness note: every other contract under src/contracts is big-endian by
 * convention. This encoding is deliberately little-endian because it is the
 * Moon service's wire contract (its encoder and the little-endian
 * authorization wire data elsewhere in the stack pin the byte layout); the
 * Flask contract mirror re-implements it and cross-checks the golden
 * vectors, so a re-encode here is byte-comparable on both sides.
 *
 * A verifier MUST re-encode a decoded artifact and compare bytes before
 * accepting it: the issuer signs the canonical encoding, so any
 * non-canonical variant (trailing bytes, non-minimal strings) is a
 * different message than the one signed. Decode therefore re-encodes
 * internally and refuses divergence.
 */

import { utf8 } from './encoding';

export const AUTHORIZATION_ARTIFACT_VERSION = 1;
export const AUTHORIZATION_ARTIFACT_ENCODING_PREFIX = 'SIGBASH.AUTHZ.ARTIFACT.V1';

/** Largest string a 2-byte length prefix can address. */
export const AUTHORIZATION_ARTIFACT_MAX_LENGTH_PREFIXED_BYTES = 0xffff;

export const AUTHORIZATION_SUBJECT_KIND_BITCOIN_PSBT = 'bitcoin_psbt';
export const AUTHORIZATION_PROTOCOL_BITCOIN = 'bitcoin';
export const AUTHORIZATION_STRENGTH_SOFTWARE_ENFORCED = 'software_enforced';

/** The artifact's signed field set, signature excluded. */
export interface AuthorizationArtifactFields {
  version: number;
  subjectKind: string;
  protocol: string;
  network: string;
  subjectCommitment: Uint8Array;
  policyRoot: Uint8Array;
  scope: Uint8Array;
  maxUses: number | bigint;
  issuedAt: number;
  expiresAt: number;
  artifactNonce: Uint8Array;
  issuerKid: string;
  strength: string;
  burnSetAggregate: Uint8Array;
}

/** The artifact as an enforcer receives it: encoded bytes plus the signature. */
export interface EncodedAuthorizationArtifact {
  /** Canonical encoded artifact bytes (the signed message). */
  raw: Uint8Array;
  /** Issuer Ed25519 signature over `raw`. */
  signature: Uint8Array;
}

export type AuthorizationArtifactDecodeFailure =
  | 'AUTHORIZATION_NON_CANONICAL'
  | 'AUTHORIZATION_UNKNOWN_VERSION';

/**
 * Decode-side failure with a stable reason the verifier surfaces verbatim.
 * The reason is deliberately one of the verifier checklist's codes so a
 * malformed artifact can never fall through to an acceptance.
 */
export class AuthorizationArtifactFormatError extends Error {
  readonly reason: AuthorizationArtifactDecodeFailure;

  constructor(message: string, reason: AuthorizationArtifactDecodeFailure) {
    super(message);
    this.name = 'AuthorizationArtifactFormatError';
    Object.setPrototypeOf(this, AuthorizationArtifactFormatError.prototype);
    this.reason = reason;
  }
}

function u16le(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError(`u16 out of range: ${value}`);
  }
  const out = new Uint8Array(2);
  out[0] = value & 0xff;
  out[1] = (value >>> 8) & 0xff;
  return out;
}

function u64le(value: number | bigint): Uint8Array {
  const v = typeof value === 'bigint' ? value : BigInt(Math.trunc(value));
  if (v < 0n || v > 0xffffffffffffffffn) {
    throw new RangeError(`u64 out of range: ${v}`);
  }
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    out[i] = Number((v >> BigInt(i * 8)) & 0xffn);
  }
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function appendLengthPrefixed(dst: Uint8Array, value: string): Uint8Array {
  const bytes = utf8(value);
  if (bytes.length > AUTHORIZATION_ARTIFACT_MAX_LENGTH_PREFIXED_BYTES) {
    throw new RangeError(
      `field length ${bytes.length} exceeds the ` +
      `${AUTHORIZATION_ARTIFACT_MAX_LENGTH_PREFIXED_BYTES}-byte length-prefix limit`,
    );
  }
  return concat(dst, u16le(bytes.length), bytes);
}

function assertFixed32(bytes: Uint8Array, field: string): void {
  if (bytes.length !== 32) {
    throw new Error(`${field} must be exactly 32 bytes, got ${bytes.length}`);
  }
}

/**
 * Encode the artifact field set to the canonical byte form (signature
 * excluded). Field order and widths are fixed by the wire contract.
 */
export function encodeAuthorizationArtifactV1(fields: AuthorizationArtifactFields): Uint8Array {
  if (fields.version !== AUTHORIZATION_ARTIFACT_VERSION) {
    throw new AuthorizationArtifactFormatError(
      `unsupported artifact version ${fields.version}`,
      'AUTHORIZATION_UNKNOWN_VERSION',
    );
  }
  assertFixed32(fields.subjectCommitment, 'subjectCommitment');
  assertFixed32(fields.policyRoot, 'policyRoot');
  assertFixed32(fields.scope, 'scope');
  assertFixed32(fields.artifactNonce, 'artifactNonce');
  assertFixed32(fields.burnSetAggregate, 'burnSetAggregate');

  let buf = concat(utf8(AUTHORIZATION_ARTIFACT_ENCODING_PREFIX), u16le(fields.version));
  buf = appendLengthPrefixed(buf, fields.subjectKind);
  buf = appendLengthPrefixed(buf, fields.protocol);
  buf = appendLengthPrefixed(buf, fields.network);
  buf = concat(
    buf,
    fields.subjectCommitment,
    fields.policyRoot,
    fields.scope,
    u64le(fields.maxUses),
    u64le(fields.issuedAt),
    u64le(fields.expiresAt),
    fields.artifactNonce,
  );
  buf = appendLengthPrefixed(buf, fields.issuerKid);
  buf = appendLengthPrefixed(buf, fields.strength);
  return concat(buf, fields.burnSetAggregate);
}

interface Reader {
  data: Uint8Array;
  offset: number;
}

function readBytes(d: Reader, n: number, field: string): Uint8Array {
  if (d.offset + n > d.data.length) {
    throw new AuthorizationArtifactFormatError(
      `${field}: truncated input`,
      'AUTHORIZATION_NON_CANONICAL',
    );
  }
  const out = d.data.subarray(d.offset, d.offset + n);
  d.offset += n;
  return out;
}

function readU16le(d: Reader, field: string): number {
  const b = readBytes(d, 2, field);
  return b[0] | (b[1] << 8);
}

function readU64le(d: Reader, field: string): bigint {
  const b = readBytes(d, 8, field);
  let v = 0n;
  for (let i = 7; i >= 0; i--) {
    v = (v << 8n) | BigInt(b[i]);
  }
  return v;
}

function readLengthPrefixed(d: Reader, field: string): string {
  const len = readU16le(d, `${field}.length`);
  const bytes = readBytes(d, len, field);
  return new TextDecoder().decode(bytes);
}

/**
 * Decode a canonical artifact encoding. Strict: rejects truncation, any
 * trailing byte after the final field, and any version this module does not
 * implement; then re-encodes the decoded fields and refuses byte divergence
 * so only the canonical encoding of a field set can ever decode.
 */
export function decodeAuthorizationArtifactV1(input: Uint8Array): AuthorizationArtifactFields {
  const d: Reader = { data: input, offset: 0 };
  const prefix = readBytes(
    d, AUTHORIZATION_ARTIFACT_ENCODING_PREFIX.length, 'encoding_prefix',
  );
  if (new TextDecoder().decode(prefix) !== AUTHORIZATION_ARTIFACT_ENCODING_PREFIX) {
    throw new AuthorizationArtifactFormatError(
      'encoding prefix mismatch', 'AUTHORIZATION_NON_CANONICAL',
    );
  }
  const version = readU16le(d, 'version');
  if (version !== AUTHORIZATION_ARTIFACT_VERSION) {
    throw new AuthorizationArtifactFormatError(
      `unsupported artifact version ${version}`, 'AUTHORIZATION_UNKNOWN_VERSION',
    );
  }
  const subjectKind = readLengthPrefixed(d, 'subjectKind');
  const protocol = readLengthPrefixed(d, 'protocol');
  const network = readLengthPrefixed(d, 'network');
  const fields: AuthorizationArtifactFields = {
    version,
    subjectKind,
    protocol,
    network,
    subjectCommitment: Uint8Array.from(readBytes(d, 32, 'subjectCommitment')),
    policyRoot: Uint8Array.from(readBytes(d, 32, 'policyRoot')),
    scope: Uint8Array.from(readBytes(d, 32, 'scope')),
    maxUses: readU64le(d, 'maxUses'),
    issuedAt: Number(readU64le(d, 'issuedAt')),
    expiresAt: Number(readU64le(d, 'expiresAt')),
    artifactNonce: Uint8Array.from(readBytes(d, 32, 'artifactNonce')),
    issuerKid: readLengthPrefixed(d, 'issuerKid'),
    strength: readLengthPrefixed(d, 'strength'),
    burnSetAggregate: Uint8Array.from(readBytes(d, 32, 'burnSetAggregate')),
  };
  if (d.offset !== input.length) {
    throw new AuthorizationArtifactFormatError(
      'trailing bytes after final field', 'AUTHORIZATION_NON_CANONICAL',
    );
  }
  const reencoded = encodeAuthorizationArtifactV1(fields);
  if (reencoded.length !== input.length || reencoded.some((b, i) => b !== input[i])) {
    throw new AuthorizationArtifactFormatError(
      're-encoded bytes diverge from the input — encoding is not canonical',
      'AUTHORIZATION_NON_CANONICAL',
    );
  }
  return fields;
}

/**
 * Extract the issuer kid from a canonical encoding by walking the
 * length-prefixed fields from the front — the same front-walk the Moon
 * verifier uses, usable even where a full decode is not attempted. Returns
 * '' when the walk cannot reach the kid field.
 */
export function issuerKidFromEncoding(input: Uint8Array): string {
  let cursor = AUTHORIZATION_ARTIFACT_ENCODING_PREFIX.length + 2;
  const readLenPrefixed = (): string | null => {
    if (cursor + 2 > input.length) return null;
    const n = input[cursor] | (input[cursor + 1] << 8);
    cursor += 2;
    if (cursor + n > input.length) return null;
    const value = new TextDecoder().decode(input.subarray(cursor, cursor + n));
    cursor += n;
    return value;
  };
  if (readLenPrefixed() === null) return ''; // subjectKind
  if (readLenPrefixed() === null) return ''; // protocol
  if (readLenPrefixed() === null) return ''; // network
  cursor += 32 + 32 + 32; // subjectCommitment, policyRoot, scope
  cursor += 8 + 8 + 8;    // maxUses, issuedAt, expiresAt
  cursor += 32;           // artifactNonce
  return readLenPrefixed() ?? '';
}

/** Decode an artifact together with its signature (raw bytes preserved). */
export function decodeSignedAuthorizationArtifact(
  raw: Uint8Array,
  signature: Uint8Array,
): { fields: AuthorizationArtifactFields; encoded: EncodedAuthorizationArtifact } {
  if (signature.length !== 64) {
    throw new AuthorizationArtifactFormatError(
      `artifact signature must be 64 bytes, got ${signature.length}`,
      'AUTHORIZATION_NON_CANONICAL',
    );
  }
  return {
    fields: decodeAuthorizationArtifactV1(raw),
    encoded: { raw, signature },
  };
}
