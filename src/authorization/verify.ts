/**
 * Offline authorization verification as an executable
 * checklist. Given the artifact, its signature, the issuer key set, the raw
 * subject, the proof envelope, and the credential context, an enforcer can
 * accept or refuse an authorization WITHOUT the server.
 *
 * The checklist order is the contract; it is stated here so any audit can
 * replay it step by step, and the implementation follows it exactly:
 *
 *   1. Issuer key set present ......................... ISSUER_UNKNOWN
 *   2. Decode + canonical re-encode + version gate .... AUTHORIZATION_NON_CANONICAL /
 *                                                      AUTHORIZATION_UNKNOWN_VERSION
 *      (trailing-garbage and non-canonical rejection happen HERE, before any
 *      acceptance can occur)
 *   3. Issuer kid selection + Ed25519 over the EXACT received bytes ... ISSUER_UNKNOWN /
 *                                                      AUTHORIZATION_BAD_SIGNATURE
 *   4. Validity window against the caller's clock ..... AUTHORIZATION_NOT_YET_VALID /
 *                                                      AUTHORIZATION_EXPIRED
 *   5. Protocol / network match ....................... SUBJECT_MISMATCH /
 *                                                      NETWORK_MISMATCH
 *   6. Two-stage subject check ........................ SUBJECT_MISMATCH /
 *                                                      SUBJECT_CHECK_UNAVAILABLE
 *      stage 1: re-aggregate the envelope's completing-bundle pins and
 *               compare to the signed subjectCommitment (no secrets);
 *      stage 2: re-derive the completing e_hat from the RAW subject and the
 *               client salt, compare to the pinned challenge_e.
 *   7. Scope (when credential context is supplied) .... SCOPE_MISMATCH
 *   8. Policy-root pin (optional) ..................... POLICY_ROOT_MISMATCH
 *   9. Strength acceptance ............................ STRENGTH_REJECTED
 *
 * Failure is exhaustive: every step either passes or returns
 * { valid: false, reason } — there is no path that accepts on missing
 * inputs. A missing key set, envelope, subject, or salt stops the checklist
 * at ISSUER_UNKNOWN or SUBJECT_CHECK_UNAVAILABLE respectively; a verifier
 * that cannot check scope says so in the result detail rather than staying
 * silent.
 */

import { verifyAsync } from '@noble/ed25519';
import { decodeAuthorizationArtifactV1 } from '../contracts/authorizationArtifact';
import {
  authzScope,
  hexToBytes,
  bytesToHex,
} from '../contracts/authorizationSubject';
import { AUTHORIZATION_PROTOCOL_BITCOIN } from '../contracts/authorizationArtifact';
import {
  AuthorizationEnvelope,
  parseAuthorizationEnvelope,
} from './envelope';
import {
  authorizationPinAggregateFromEnvelope,
  getAuthorizationAdapter,
} from './adapterRegistry';
import { LoadedIssuerKeySet, issuerKeyForKid } from './issuerKeySet';

export const AUTHORIZATION_STRENGTH_ACCEPTED_DEFAULT = 'software_enforced';

/** The credential context that lets the verifier check scope. */
export interface AuthorizationCredentialContext {
  /** The credential's registration identifier (the auth hash). */
  credentialIdentifier: string;
  /** The key's registration index; falls back to the KMC's key_index. */
  keyIndex?: number;
  /** A KMC JSON string to read key_index from when keyIndex is omitted. */
  kmcJSON?: string;
}

export interface VerifyAuthorizationOptions {
  /** The artifact as received: exact encoded bytes plus the 64-byte signature. */
  authorization: {
    rawArtifact: Uint8Array;
    rawSignature: Uint8Array;
  };
  /** The network the enforcer is about to execute the subject on. */
  network: string;
  /** The pinned issuer key set (step 1). */
  issuerKeySet?: LoadedIssuerKeySet;
  /** The raw subject bytes (for 'bitcoin_psbt': the PSBT bytes). */
  subject?: Uint8Array;
  /** The proof envelope JSON (or parsed) that carries the GKR-pinned pins. */
  envelope?: AuthorizationEnvelope | string;
  /** The client-held policy salt; stage 2 needs it. */
  salt?: Uint8Array;
  /** Scope context: the precomputed expected digest, or the credential
   * context to recompute it from. With neither, the scope check is skipped
   * and the result detail says so. */
  expectedScope?: Uint8Array;
  credential?: AuthorizationCredentialContext;
  /** The policy root the enforcer requires (hex or bytes). */
  expectedPolicyRoot?: Uint8Array | string;
  /** The enforcer's clock, unix seconds (default: current time). */
  now?: number;
  /** The artifact strengths this enforcer accepts. */
  acceptedStrengths?: string[];
}

export interface VerifyAuthorizationResult {
  valid: boolean;
  /** The checklist's refusal code when invalid. */
  reason?: string;
  /** Human- and machine-readable context for the outcome. */
  detail?: Record<string, string>;
}

function asBytes(value: Uint8Array | string): Uint8Array {
  return typeof value === 'string' ? hexToBytes(value) : value;
}

/**
 * Run the verification checklist in its stated order. Never throws for a
 * verification outcome — a thrown error is an adapter/parser defect and is
 * surfaced as SUBJECT_MISMATCH only for subject-shape refusals, everything
 * else returns a structured result.
 */
export async function verifyAuthorization(
  options: VerifyAuthorizationOptions,
): Promise<VerifyAuthorizationResult> {
  const detail: Record<string, string> = {};

  // Step 1: the issuer key set must already be loaded and pinned by the caller.
  const keySet = options.issuerKeySet;
  if (!keySet) {
    return { valid: false, reason: 'ISSUER_UNKNOWN', detail: { step: '1', cause: 'no issuer key set supplied' } };
  }

  // Step 2: decode, version-gate, and re-encode-compare BEFORE any acceptance.
  let fields;
  try {
    fields = decodeAuthorizationArtifactV1(options.authorization.rawArtifact);
  } catch (err) {
    return {
      valid: false,
      reason: (err as { reason?: string }).reason ?? 'AUTHORIZATION_NON_CANONICAL',
      detail: { step: '2', cause: String((err as Error).message ?? err) },
    };
  }
  detail.subjectKind = fields.subjectKind;
  detail.issuerKid = fields.issuerKid;

  // Step 3: issuer kid selection and signature over the EXACT received bytes.
  const issuerKey = issuerKeyForKid(keySet, fields.issuerKid);
  if (!issuerKey) {
    return { valid: false, reason: 'ISSUER_UNKNOWN', detail: { step: '3', issuerKid: fields.issuerKid } };
  }
  let signatureValid = false;
  try {
    signatureValid = await verifyAsync(
      options.authorization.rawSignature,
      options.authorization.rawArtifact,
      hexToBytes(issuerKey.publicKeyHex),
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    return { valid: false, reason: 'AUTHORIZATION_BAD_SIGNATURE', detail: { step: '3', issuerKid: fields.issuerKid } };
  }

  // Step 4: validity window against the caller's clock.
  const now = options.now ?? Math.floor(Date.now() / 1000);
  if (now < fields.issuedAt) {
    return { valid: false, reason: 'AUTHORIZATION_NOT_YET_VALID', detail: { step: '4', now: String(now), issuedAt: String(fields.issuedAt) } };
  }
  if (now > fields.expiresAt) {
    return { valid: false, reason: 'AUTHORIZATION_EXPIRED', detail: { step: '4', now: String(now), expiresAt: String(fields.expiresAt) } };
  }

  // Step 5: protocol and network match between artifact and enforcer.
  if (fields.protocol !== AUTHORIZATION_PROTOCOL_BITCOIN) {
    return { valid: false, reason: 'SUBJECT_MISMATCH', detail: { step: '5', protocol: fields.protocol } };
  }
  if (fields.network !== options.network) {
    return { valid: false, reason: 'NETWORK_MISMATCH', detail: { step: '5', artifactNetwork: fields.network, enforcerNetwork: options.network } };
  }

  // Step 6: the two-stage subject check. Both stages need the envelope;
  // stage 2 additionally needs the raw subject and the client salt.
  if (!options.envelope) {
    return { valid: false, reason: 'SUBJECT_CHECK_UNAVAILABLE', detail: { step: '6', cause: 'no proof envelope supplied' } };
  }
  const envelope = typeof options.envelope === 'string'
    ? parseAuthorizationEnvelope(options.envelope)
    : options.envelope;
  if (bytesToHex(authorizationPinAggregateFromEnvelope(envelope)) !== bytesToHex(fields.subjectCommitment)) {
    return { valid: false, reason: 'SUBJECT_MISMATCH', detail: { step: '6', stage: '1', cause: 'pin aggregate does not match the signed subject commitment' } };
  }
  if (!options.subject || !options.salt) {
    return { valid: false, reason: 'SUBJECT_CHECK_UNAVAILABLE', detail: { step: '6', stage: '2', cause: options.subject ? 'no client salt supplied' : 'no raw subject supplied' } };
  }
  const adapter = getAuthorizationAdapter(fields.subjectKind);
  if (!adapter) {
    return { valid: false, reason: 'SUBJECT_KIND_UNKNOWN', detail: { step: '6', subjectKind: fields.subjectKind } };
  }
  let derivedEHat: Uint8Array;
  try {
    adapter.checkVerifiable(options.subject, options.network);
    derivedEHat = adapter.rederiveCompletingEHat(options.subject, envelope, options.salt);
  } catch (err) {
    return { valid: false, reason: 'SUBJECT_MISMATCH', detail: { step: '6', stage: '2', cause: String((err as Error).message ?? err) } };
  }
  if (bytesToHex(derivedEHat) !== bytesToHex(envelope.positions[envelope.completingPosition].bundle.publicInputs.challengeE)) {
    return { valid: false, reason: 'SUBJECT_MISMATCH', detail: { step: '6', stage: '2', cause: 're-derived e_hat does not match the pinned challenge' } };
  }

  // Step 7: scope — runs when the enforcer's credential context is
  // available; a verifier without it says so explicitly.
  if (options.expectedScope !== undefined) {
    if (bytesToHex(asBytes(options.expectedScope)) !== bytesToHex(fields.scope)) {
      return { valid: false, reason: 'SCOPE_MISMATCH', detail: { step: '7' } };
    }
    detail.scope = 'checked against the supplied expected digest';
  } else if (options.credential?.credentialIdentifier !== undefined) {
    const keyIndex = options.credential.keyIndex ?? readKmcKeyIndex(options.credential.kmcJSON);
    if (keyIndex === undefined) {
      return { valid: false, reason: 'SCOPE_MISMATCH', detail: { step: '7', cause: 'no key index resolvable for the scope recompute' } };
    }
    const expected = authzScope(options.credential.credentialIdentifier, keyIndex);
    if (bytesToHex(expected) !== bytesToHex(fields.scope)) {
      return { valid: false, reason: 'SCOPE_MISMATCH', detail: { step: '7', credential: options.credential.credentialIdentifier, keyIndex: String(keyIndex) } };
    }
    detail.scope = `recomputed for key index ${keyIndex}`;
  } else {
    detail.scope = 'NOT CHECKED — no credential context was supplied; the artifact scope was not verified';
  }

  // Step 8: the optional policy-root pin.
  if (options.expectedPolicyRoot !== undefined) {
    if (bytesToHex(asBytes(options.expectedPolicyRoot)) !== bytesToHex(fields.policyRoot)) {
      return { valid: false, reason: 'POLICY_ROOT_MISMATCH', detail: { step: '8' } };
    }
    detail.policyRoot = 'matches the enforcer pin';
  } else {
    detail.policyRoot = bytesToHex(fields.policyRoot);
  }

  // Step 9: strength acceptance.
  const accepted = options.acceptedStrengths ?? [AUTHORIZATION_STRENGTH_ACCEPTED_DEFAULT];
  if (!accepted.includes(fields.strength)) {
    return { valid: false, reason: 'STRENGTH_REJECTED', detail: { step: '9', strength: fields.strength } };
  }
  detail.strength = fields.strength;

  return { valid: true, detail };
}

function readKmcKeyIndex(kmcJSON?: string): number | undefined {
  if (!kmcJSON) return undefined;
  try {
    const parsed = JSON.parse(kmcJSON) as { key_index?: unknown };
    const index = parsed.key_index;
    return typeof index === 'number' && Number.isInteger(index) ? index : undefined;
  } catch {
    return undefined;
  }
}
