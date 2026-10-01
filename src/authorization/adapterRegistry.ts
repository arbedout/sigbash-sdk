/**
 * The authorization subject-adapter registry: one adapter per subject kind,
 * registered under the artifact's subjectKind string. An enforcer looks its
 * subject kind up here; an unknown kind is a refusal (SUBJECT_KIND_UNKNOWN),
 * never a fallback path.
 *
 * The registry also carries the two subject-kind-agnostic derivations every
 * enforcer needs: the stage-1 pin aggregate over an envelope's completing
 * bundle, and the burn-set aggregate over its pinned nullifiers.
 */

import {
  authzActionKey,
  authzBurnSetAggregate,
  authzPinAggregate,
  hexToBytes,
} from '../contracts/authorizationSubject';
import {
  AuthorizationBundle,
  AuthorizationEnvelope,
  completingPositionOf,
  selectCovenantWriteCommit,
} from './envelope';

export interface AuthorizationSubjectAdapter {
  /** The artifact subjectKind string this adapter verifies. */
  subjectKind: string;
  /**
   * Refuse any subject this adapter cannot verify, before any acceptance.
   * Throws with the reason the verifier surfaces (fail closed — there is no
   * adapter path that accepts an unverifiable subject).
   */
  checkVerifiable(rawSubject: Uint8Array, network: string): void;
  /**
   * Stage 2 of the subject check: re-derive the completing position's
   * e_hat from the RAW subject bytes and the client-held salt, so the
   * verifier can compare it against the GKR-pinned challenge_e.
   */
  rederiveCompletingEHat(
    rawSubject: Uint8Array,
    envelope: AuthorizationEnvelope,
    salt: Uint8Array,
  ): Uint8Array;
}

const registry = new Map<string, AuthorizationSubjectAdapter>();

/** Register an adapter. A duplicate subject kind is refused, not replaced. */
export function registerAuthorizationAdapter(adapter: AuthorizationSubjectAdapter): void {
  if (registry.has(adapter.subjectKind)) {
    throw new Error(`authorization subject adapter already registered for '${adapter.subjectKind}'`);
  }
  registry.set(adapter.subjectKind, adapter);
}

/** The adapter for a subject kind, or undefined for an unregistered kind. */
export function getAuthorizationAdapter(subjectKind: string): AuthorizationSubjectAdapter | undefined {
  return registry.get(subjectKind);
}

/** All registered subject kinds (diagnostics only). */
export function registeredAuthorizationSubjects(): string[] {
  return Array.from(registry.keys());
}

/**
 * Stage 1 of the subject check, subject-kind agnostic: re-aggregate the
 * completing bundle's own pins exactly as the WASM export and the Sigbash
 * server's verifier do — ONE position entry, ONE chunk entry, CompletingPosition = 0.
 * No secrets, no transaction: only the envelope's GKR-pinned public inputs.
 */
export function authorizationPinAggregateFromEnvelope(
  envelope: AuthorizationEnvelope,
): Uint8Array {
  const bundle = completingPositionOf(envelope).bundle;
  return authzPinAggregate(
    envelope.sessionId,
    0,
    [{
      eHat: bundle.publicInputs.challengeE,
      positionMode: bundle.publicInputs.positionMode,
    }],
    [{
      hashOutputsBlindedCommit: bundle.publicInputs.hashOutputsBlindedCommit,
      covenantWriteCommit: selectCovenantWriteCommit(bundle),
    }],
    {
      hashOutputsBlindedCommitUnified: bundle.publicInputs.hashOutputsBlindedCommitUnified,
      hinBlindedCommitUnified: bundle.publicInputs.hinBlindedCommitUnified,
      saltBlindedCommitUnified: bundle.publicInputs.saltBlindedCommitUnified,
      polyCoeffsBlindedCommitUnified: bundle.publicInputs.polyCoeffsBlindedCommitUnified,
      inputSetPolyProduct: bundle.publicInputs.inputSetPolyProduct,
    },
  );
}

/**
 * The burn-set aggregate over the completing bundle's own pinned nullifiers
 * (the same single-entry set the server echoes verbatim at issuance).
 */
export function authorizationBurnSetAggregateFromEnvelope(
  envelope: AuthorizationEnvelope,
): Uint8Array {
  const bundle: AuthorizationBundle = completingPositionOf(envelope).bundle;
  return authzBurnSetAggregate(envelope.sessionId, [{
    positionIndex: 0,
    n0: bundle.publicInputs.nullifierN0,
    n1: bundle.publicInputs.nullifierN1,
  }]);
}

/** The action key for an echoed burn pair [N0hex, N1hex] (N0 at the even index). */
export function authorizationActionKeyFromBurnPair(
  burnPair: readonly [string, string],
): Uint8Array {
  return authzActionKey([hexToBytes(burnPair[0])]);
}
