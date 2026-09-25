/**
 * Signing-session shared-store wire contracts: the protocol metadata a
 * shared session registry carries for one signing session.
 *
 * Session rows carry protocol metadata only — session ids, counts,
 * modes — never wallet plaintext. The session keeps its protocol
 * identity: the session id minted at nonce exchange, scoped by
 * (credential_id, key_index). The input count is pinned once at first
 * sight and restated on every later request; a mismatch rejects. A
 * position mode arriving with no live session row fails the release
 * check closed — absence is a lockstep anomaly.
 *
 * Each participating PolicyKey owns its session identity, its nonce set,
 * and its single-session enforcement; one key's session failure never
 * poisons another's. The per-credential in-flight cap applies per
 * principal credential.
 *
 * These are JSON message shapes without a binary codec. If a server lane
 * needs to parse or validate one, the shape promotes into this module
 * (with the application-backend mirror added in the same release) rather
 * than being restated elsewhere — one canonical definition per contract.
 */

import { ContractVersionError } from './encoding';

export const SIGNING_SESSION_VERSION = 1;
export const SIGNING_SESSION_STATE_VERSION = 1;

export type SigningSessionState = 'active' | 'completed' | 'abandoned';

/**
 * Wire codes for session state. Codes are explicitly assigned and never
 * contiguous-by-convention; unknown codes fail closed.
 */
export const SIGNING_SESSION_STATE_CODES = {
  active: 0x01,
  completed: 0x02,
  abandoned: 0x03,
} as const satisfies Record<SigningSessionState, number>;

const CODE_TO_SESSION_STATE: Record<number, SigningSessionState> = Object.fromEntries(
  Object.entries(SIGNING_SESSION_STATE_CODES).map(([state, code]) => [code, state as SigningSessionState]),
);

/**
 * The shared-store wire shape for one signing session. Position modes
 * map string input indices to integer modes, exactly as the registry
 * records them. Timestamp fields are server-owned clock fields and
 * travel as strings; the server owns all TTL and expiry semantics.
 */
export interface SigningSessionWireV1 {
  readonly session_id: string;
  readonly credential_id: string;
  readonly key_index: number;
  readonly input_count: number;
  readonly position_modes: Readonly<Record<string, number>>;
  readonly current_input_index: number;
  readonly state: SigningSessionState;
  readonly inflight_since: string | null;
  readonly created_at: string;
  readonly expires_at: string;
  readonly completing_released_at: string | null;
}

/**
 * The per-PolicyKey session descriptor: the scope one PolicyKey's
 * independent session keys on. Each descriptor participates in the same
 * transaction orchestration without sharing session identity with any
 * other key's session.
 */
export interface PerPolicyKeySessionDescriptorV1 {
  readonly policy_key_id: string;
  readonly key_index: number;
  readonly session_id: string;
}

export function encodeSigningSessionState(state: SigningSessionState): number {
  return SIGNING_SESSION_STATE_CODES[state];
}

/** Fail closed on unknown session-state codes. */
export function decodeSigningSessionState(code: number): SigningSessionState {
  const state = CODE_TO_SESSION_STATE[code];
  if (state === undefined) {
    throw new ContractVersionError(`SigningSessionState: unknown code 0x${code.toString(16)}`);
  }
  return state;
}
