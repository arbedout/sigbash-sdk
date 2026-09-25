/**
 * Protocol authority contracts: the non-human authority credential, its
 * rotation, and the atomic policy mutation it authenticates.
 *
 * The authority is a credential, not an account: a client-generated
 * protocol keypair whose auth hash is the identifier. It has no email,
 * no password, no TOTP secret, no app session — nothing to phish. Humans
 * reach it only through capability material wrapped to a dedicated
 * capability epoch; the server can never mint an authority.
 *
 * The admin_generation identifies the authority incarnation. Rotation
 * produces generation N+1 and a new current admin auth hash; every
 * authority-authenticated request carries the generation it observed and
 * a stale incarnation fails closed. Stale-incarnation checks read the
 * row's current state, never the request's claims, so an old authority
 * cannot restore itself.
 *
 * AtomicPolicyMutationV1 is the only institutional mutation path. It
 * replaces the encrypted KMC and the policy root together in one commit,
 * so no window exists where new policy state lacks the signing freeze.
 * Rotation and mutation are idempotent by key: a retried idempotency key
 * returns the recorded outcome without re-executing.
 *
 * Authority operations reuse the governing account-layer step-up
 * mechanism (a recent-login freshness window satisfies step-up on first
 * publication only). The window length and the session stamp are server
 * state, not contract values.
 *
 * These are JSON message shapes without a binary codec. If a server lane
 * needs to parse or validate one, the shape promotes into this module
 * (with the application-backend mirror added in the same release) rather
 * than being restated elsewhere — one canonical definition per contract.
 */

import { ContractVersionError } from './encoding';

export const PROTOCOL_AUTHORITY_VERSION = 1;
export const PROTOCOL_AUTHORITY_STATUS_VERSION = 1;
export const ATOMIC_POLICY_MUTATION_VERSION = 1;

export type ProtocolAuthorityStatus = 'active' | 'rotating' | 'retired';

/**
 * Wire codes for authority status. Codes are explicitly assigned and
 * never contiguous-by-convention; unknown codes fail closed.
 */
export const PROTOCOL_AUTHORITY_STATUS_CODES = {
  active: 0x01,
  rotating: 0x02,
  retired: 0x03,
} as const satisfies Record<ProtocolAuthorityStatus, number>;

const CODE_TO_AUTHORITY_STATUS: Record<number, ProtocolAuthorityStatus> = Object.fromEntries(
  Object.entries(PROTOCOL_AUTHORITY_STATUS_CODES).map(([status, code]) => [code, status as ProtocolAuthorityStatus]),
);

/** The authority state view an authorized client observes for one org. */
export interface ProtocolAuthorityStateViewV1 {
  readonly admin_generation: number;
  readonly current_admin_auth_hash: string;
  readonly status: ProtocolAuthorityStatus;
}

/**
 * Rotation request: install the next authority incarnation. Neither
 * private key — old or new — ever reaches the server; the new
 * incarnation's private key is wrapped client-side before submission.
 */
export interface ProtocolAuthorityRotationRequestV1 {
  readonly new_authority_public_key: string;
  readonly expected_admin_generation: number;
  readonly idempotency_key: string;
}

/**
 * The single institutional policy-mutation message. The expected
 * generation and expected old policy root make the swap compare-and-swap;
 * the immutable client-key commitments are validated unchanged, so a
 * policy update never touches Bitcoin identity.
 */
export interface AtomicPolicyMutationV1 {
  readonly policy_key_id: string;
  readonly expected_generation: number;
  readonly expected_old_policy_root: string;
  readonly new_policy_root: string;
  readonly new_encrypted_kmc: string;
  readonly compiled_policy_digest: string;
  readonly idempotency_key: string;
  readonly protocol_authority_proof: string;
}

export function encodeProtocolAuthorityStatus(status: ProtocolAuthorityStatus): number {
  return PROTOCOL_AUTHORITY_STATUS_CODES[status];
}

/** Fail closed on unknown authority-status codes. */
export function decodeProtocolAuthorityStatus(code: number): ProtocolAuthorityStatus {
  const status = CODE_TO_AUTHORITY_STATUS[code];
  if (status === undefined) {
    throw new ContractVersionError(`ProtocolAuthorityStatus: unknown code 0x${code.toString(16)}`);
  }
  return status;
}
