/**
 * The authorization artifact codec is asserted against the committed
 * golden vector — the same bytes the Moon encoder (the canonical side)
 * and the Flask mirror both produce. Any drift here fails a test, never a
 * proof.
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import {
  AuthorizationArtifactFormatError,
  AuthorizationArtifactFields,
  decodeAuthorizationArtifactV1,
  encodeAuthorizationArtifactV1,
  issuerKidFromEncoding,
} from './authorizationArtifact';
import { hexToBytes, bytesToHex } from './encoding';

const VECTORS = JSON.parse(
  readFileSync(join(__dirname, 'vectors', 'contracts-v1.json'), 'utf8'),
).authorization_artifact_v1 as {
  fields: {
    version: number;
    subject_kind: string;
    protocol: string;
    network: string;
    subject_commitment_hex: string;
    policy_root_hex: string;
    scope_hex: string;
    max_uses: number;
    issued_at: number;
    expires_at: number;
    artifact_nonce_hex: string;
    issuer_kid: string;
    strength: string;
    burn_set_aggregate_hex: string;
  };
  encoding_hex: string;
  encoding_zero_burn_set_hex: string;
};

function fixtureFields(burnSet: Uint8Array): AuthorizationArtifactFields {
  const f = VECTORS.fields;
  return {
    version: f.version,
    subjectKind: f.subject_kind,
    protocol: f.protocol,
    network: f.network,
    subjectCommitment: hexToBytes(f.subject_commitment_hex),
    policyRoot: hexToBytes(f.policy_root_hex),
    scope: hexToBytes(f.scope_hex),
    maxUses: BigInt(f.max_uses),
    issuedAt: f.issued_at,
    expiresAt: f.expires_at,
    artifactNonce: hexToBytes(f.artifact_nonce_hex),
    issuerKid: f.issuer_kid,
    strength: f.strength,
    burnSetAggregate: burnSet,
  };
}

describe('authorization artifact codec', () => {
  it('encodes the committed golden vector byte-exactly', () => {
    const encoded = encodeAuthorizationArtifactV1(
      fixtureFields(hexToBytes(VECTORS.fields.burn_set_aggregate_hex)),
    );
    expect(bytesToHex(encoded)).toBe(VECTORS.encoding_hex);
  });

  it('keeps the encoding before the burn-set aggregate independent of its value', () => {
    const zeroed = encodeAuthorizationArtifactV1(fixtureFields(new Uint8Array(32)));
    expect(bytesToHex(zeroed)).toBe(VECTORS.encoding_zero_burn_set_hex);
    const full = hexToBytes(VECTORS.encoding_hex);
    expect(zeroed.slice(0, zeroed.length - 32)).toEqual(full.slice(0, full.length - 32));
  });

  it('decodes the golden vector back to the same fields and rejects trailing bytes', () => {
    const raw = hexToBytes(VECTORS.encoding_hex);
    const fields = decodeAuthorizationArtifactV1(raw);
    expect(fields.issuerKid).toBe(VECTORS.fields.issuer_kid);
    expect(fields.subjectKind).toBe(VECTORS.fields.subject_kind);
    expect(fields.maxUses).toBe(BigInt(VECTORS.fields.max_uses));
    expect(fields.issuedAt).toBe(VECTORS.fields.issued_at);
    expect(issuerKidFromEncoding(raw)).toBe(VECTORS.fields.issuer_kid);

    expect(() => decodeAuthorizationArtifactV1(new Uint8Array([...raw, 0x00])))
      .toThrow(AuthorizationArtifactFormatError);
    try {
      decodeAuthorizationArtifactV1(new Uint8Array([...raw, 0x00]));
    } catch (err) {
      expect((err as AuthorizationArtifactFormatError).reason).toBe('AUTHORIZATION_NON_CANONICAL');
    }
  });

  it('refuses an unsupported version before any field is accepted', () => {
    const mutated = Uint8Array.from(hexToBytes(VECTORS.encoding_hex));
    mutated[25] = 0x02; // the version word's low byte, right after the 25-char prefix
    expect(() => decodeAuthorizationArtifactV1(mutated)).toThrow(AuthorizationArtifactFormatError);
    try {
      decodeAuthorizationArtifactV1(mutated);
    } catch (err) {
      expect((err as AuthorizationArtifactFormatError).reason).toBe('AUTHORIZATION_UNKNOWN_VERSION');
    }
  });

  it('refuses a truncated encoding and a wrong prefix', () => {
    const raw = hexToBytes(VECTORS.encoding_hex);
    expect(() => decodeAuthorizationArtifactV1(raw.slice(0, raw.length - 1)))
      .toThrow(AuthorizationArtifactFormatError);
    const wrongPrefix = Uint8Array.from(raw);
    wrongPrefix[0] = 0x58; // 'X' — breaks the canonical prefix
    try {
      decodeAuthorizationArtifactV1(wrongPrefix);
    } catch (err) {
      expect((err as AuthorizationArtifactFormatError).reason).toBe('AUTHORIZATION_NON_CANONICAL');
    }
  });

  it('round-trips encode then decode exactly', () => {
    const fields = fixtureFields(hexToBytes(VECTORS.fields.burn_set_aggregate_hex));
    const decoded = decodeAuthorizationArtifactV1(encodeAuthorizationArtifactV1(fields));
    expect(decoded).toEqual(fields);
  });
});
