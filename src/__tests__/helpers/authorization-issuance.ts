/**
 * Shared synthetic-issuance builder for the authorization lane's unit
 * suites. Self-consistent by construction: the envelope's pins are the
 * honest adapter re-derivation of the fixture PSBT under the fixture salt,
 * so every suite can tamper any single field and expect a refusal at a
 * stated checklist step. No server, no WASM.
 */

import { etc, sign as ed25519Sign } from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import {
  bytesToHex,
  hexToBytes,
  authzDeriveRNonceX,
  authzEHat,
  authzPrevoutQ,
  authzScope,
  authzSighashKeyPath,
} from '../../contracts/authorizationSubject';
import {
  AUTHORIZATION_ARTIFACT_VERSION,
  AuthorizationArtifactFields,
  encodeAuthorizationArtifactV1,
} from '../../contracts/authorizationArtifact';
import {
  authorizationBurnSetAggregateFromEnvelope,
  authorizationPinAggregateFromEnvelope,
} from '../../authorization/adapterRegistry';
import { parseAuthorizationEnvelope } from '../../authorization/envelope';

// The sync noble/ed25519 API needs an explicit SHA-512 injection; the
// async API (used by the production verify path) needs none.
etc.sha512Sync = (...m: Uint8Array[]) => sha512(etc.concatBytes(...m));

export const SALT = hexToBytes('0fd7fb7e35fc36a086af14e3493ada3ad9136f6259c5b2a053db3c83b75decb9');
export const SESSION_ID = hexToBytes('751f88e619bd040df69324d60dc9d20a24a8781d75a060b85615844be4081e0e');
export const TXID = hexToBytes('aec97b6b57e5ac54912a6c9478d4e647216e39e4ffac99a5d2541ce447001926');
export const P2TR_PREVOUT = hexToBytes('5120' + '212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4');
export const P2TR_DESTINATION = hexToBytes('5120' + '9b8c8d2f22a3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9');
export const PREVOUT_VALUE = 25000;
export const OUTPUT_VALUE = 20000;
export const SEQUENCE = 0xfffffffe;
export const CREDENTIAL_ID = '66a8f924913890fcd36345619c1a56b66deb85ebd853a0c6d80e5fb141370a6b';
export const ISSUER_SEED = hexToBytes('7c1e8a44d2b93f60a5c8e17b3d9f24a6c0e5b81d7f3a92c64e08b5d1a7c3f902');
export const ISSUER_KID = 'authz-ed25519-v1.1';
export const ISSUED_AT = 1790000000;
export const EXPIRES_AT = 1790000900;
export const NULLIFIER_N0 = sha256('authz-n0');
export const NULLIFIER_N1 = sha256('authz-n1');

export const digest = (label: string) => sha256(label);

export { bytesToHex };

export const toInts = (b: Uint8Array): number[] => Array.from(b);

function le32(v: number): Uint8Array {
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) out[i] = (v >>> (i * 8)) & 0xff;
  return out;
}

function le64(v: number): Uint8Array {
  const out = new Uint8Array(8);
  let big = BigInt(v);
  for (let i = 0; i < 8; i++) { out[i] = Number(big & 0xffn); big >>= 8n; }
  return out;
}

function varint(v: number): Uint8Array {
  return Uint8Array.from([v]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/** A one-input, one-output taproot PSBT with a witness utxo and posture 0x00. */
export function buildPsbtBytes(): Uint8Array {
  const unsignedTx = concat(
    le32(2),
    varint(1),
    TXID, le32(0), varint(0), le32(SEQUENCE),
    varint(1),
    le64(OUTPUT_VALUE), varint(P2TR_DESTINATION.length), P2TR_DESTINATION,
    le32(0),
  );
  const witnessUtxoValue = concat(le64(PREVOUT_VALUE), varint(P2TR_PREVOUT.length), P2TR_PREVOUT);
  return concat(
    Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff]),
    // global map: the unsigned tx
    varint(1), Uint8Array.from([0x00]),
    varint(unsignedTx.length), unsignedTx,
    Uint8Array.from([0x00]),
    // input map: witness utxo + declared sighash posture 0x00
    varint(1), Uint8Array.from([0x01]), varint(witnessUtxoValue.length), witnessUtxoValue,
    varint(1), Uint8Array.from([0x03]), varint(4), le32(0x00),
    Uint8Array.from([0x00]),
    // output map, empty (BIP-174 ends here — the fee is never encoded)
    Uint8Array.from([0x00]),
  );
}

export function buildEnvelopeJson(challengeE: Uint8Array): object {
  return {
    version: 1,
    session_id: toInts(SESSION_ID),
    completing_position: 0,
    positions: [{
      posture: { hash_type: 0x00, is_acp: false, mux_branch: 'key_path' },
      position_mode: 0,
      bundle: {
        proof_session_id: toInts(SESSION_ID),
        output_chunk_proofs: [{
          is_final_chunk: true,
          covenant_write_commit: toInts(digest('covenant-write').slice(0, 16)),
        }],
        public_inputs: {
          challenge_e: toInts(challengeE),
          path_id: toInts(digest('path')),
          session_seed: toInts(digest('seed')),
          nullifier_n0: toInts(NULLIFIER_N0),
          nullifier_n1: toInts(NULLIFIER_N1),
          hash_outputs_blinded_commit: toInts(digest('hobc')),
          hash_outputs_blinded_commit_unified: toInts(digest('hobc-unified')),
          hin_blinded_commit_unified: toInts(digest('hin')),
          salt_blinded_commit_unified: toInts(digest('saltcommit')),
          poly_coeffs_blinded_commit_unified: toInts(digest('poly')),
          input_set_poly_product: toInts(concat(Uint8Array.from([1]), new Uint8Array(15))),
          position_mode: 0,
        },
      },
    }],
  };
}

/** The completing e_hat the honest adapter re-derives from the fixture PSBT. */
export function honestEHat(): Uint8Array {
  const inputs = [{
    txid: TXID, vout: 0, sequence: SEQUENCE,
    amount: PREVOUT_VALUE, scriptPubKey: P2TR_PREVOUT,
  }];
  const outputs = [{ value: OUTPUT_VALUE, scriptPubKey: P2TR_DESTINATION }];
  const sighash = authzSighashKeyPath(inputs, outputs, 0);
  const q = authzPrevoutQ(P2TR_PREVOUT);
  const rX = authzDeriveRNonceX(SALT, SESSION_ID);
  return authzEHat(rX, q, sighash, new Uint8Array(32));
}

export function parseEnvelopeJSON(envelopeJSON: string) {
  return parseAuthorizationEnvelope(JSON.parse(envelopeJSON));
}

/** The envelope JSON of an honest issuance for the fixture PSBT and salt. */
export function honestEnvelopeJSON(): string {
  return JSON.stringify(buildEnvelopeJson(honestEHat()));
}

/** The stage-1 pin aggregate of an honest issuance (the subject commitment). */
export function honestSubjectCommitment(): Uint8Array {
  return authorizationPinAggregateFromEnvelope(parseEnvelopeJSON(honestEnvelopeJSON()));
}

/** The burn-set aggregate of an honest issuance (the artifact's final field). */
export function honestBurnSetAggregate(): Uint8Array {
  return authorizationBurnSetAggregateFromEnvelope(parseEnvelopeJSON(honestEnvelopeJSON()));
}

/** The scope digest the server would derive for the fixture credential. */
export function honestScope(): Uint8Array {
  return authzScope(CREDENTIAL_ID, 0);
}

export interface SignedIssuance {
  rawArtifact: Uint8Array;
  rawSignature: Uint8Array;
  envelopeJSON: string;
  fields: AuthorizationArtifactFields;
}

export interface IssueOverrides {
  scope?: Uint8Array;
  expiresAt?: number;
  issuedAt?: number;
  kid?: string;
  challengeE?: Uint8Array;
  policyRoot?: Uint8Array;
}

/**
 * A complete signed issuance: canonical artifact encoding, Ed25519
 * signature by the fixture issuer key, and the matching envelope JSON.
 */
export function issue(overrides?: IssueOverrides): SignedIssuance {
  const envelopeJSON = JSON.stringify(
    buildEnvelopeJson(overrides?.challengeE ?? honestEHat()));
  const envelope = parseEnvelopeJSON(envelopeJSON);
  const fields: AuthorizationArtifactFields = {
    version: AUTHORIZATION_ARTIFACT_VERSION,
    subjectKind: 'bitcoin_psbt',
    protocol: 'bitcoin',
    network: 'signet',
    subjectCommitment: authorizationPinAggregateFromEnvelope(envelope),
    policyRoot: overrides?.policyRoot ?? digest('policy-root'),
    scope: overrides?.scope ?? honestScope(),
    maxUses: 1n,
    issuedAt: overrides?.issuedAt ?? ISSUED_AT,
    expiresAt: overrides?.expiresAt ?? EXPIRES_AT,
    artifactNonce: digest('nonce'),
    issuerKid: overrides?.kid ?? ISSUER_KID,
    strength: 'software_enforced',
    burnSetAggregate: authorizationBurnSetAggregateFromEnvelope(envelope),
  };
  const rawArtifact = encodeAuthorizationArtifactV1(fields);
  return {
    rawArtifact,
    rawSignature: ed25519Sign(rawArtifact, ISSUER_SEED),
    envelopeJSON,
    fields,
  };
}

/** The export object SigbashWASM_AuthorizePSBT resolves with on success. */
export function wasmExportSuccess(envelopeJSON: string): Record<string, unknown> {
  const envelope = parseEnvelopeJSON(envelopeJSON);
  // The export carries the completing position's BARE bundle JSON alongside
  // the envelope — the same fields the envelope embeds under
  // positions[completing_position].bundle, with the proof session id at the
  // top level. The issuance proof_bundle the client forwards is this bare
  // serialization, not the envelope.
  const envelopeRecord = JSON.parse(envelopeJSON) as {
    completing_position: number;
    positions: Array<{ bundle: unknown }>;
  };
  const completingBundleJSON = JSON.stringify(
    envelopeRecord.positions[envelopeRecord.completing_position].bundle
  );
  return {
    success: true,
    envelope_json: envelopeJSON,
    bundle_json: completingBundleJSON,
    subject_commitment_hex: bytesToHex(authorizationPinAggregateFromEnvelope(envelope)),
    policy_root: bytesToHex(digest('policy-root')),
    lifetime_seconds: 900,
    session_id_hex: bytesToHex(SESSION_ID),
    burn_commitments: [bytesToHex(NULLIFIER_N0), bytesToHex(NULLIFIER_N1)],
    path_id: bytesToHex(digest('path')),
    satisfied_clause: 'clause-0',
    nullifier_status: [],
  };
}
