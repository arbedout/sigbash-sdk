/**
 * PolicyKeyAccess contracts: revocable pseudonymous principal access to a
 * PolicyKey.
 *
 * A principal is a non-human protocol identity; the principal auth hash
 * (a hash of the principal public key and the organization id) is the
 * only server-visible principal identifier. It never resolves to a named
 * application user, and any principal-to-named-user join is a violation.
 * Authorization to a specific PolicyKey is a row in PolicyKeyAccess,
 * never a property of the key material.
 *
 * A stale access_generation fails closed — authorization is checked
 * against the row's current state, never the request's claims. Grant and
 * revoke each install the row change and the generation increment in one
 * transaction; a revoked principal gets no future fetch, no future
 * signing, and no future session. Possession of previously fetched
 * plaintext is honestly not recoverable; revocation guarantees no future
 * access.
 *
 * Account-layer step-up on grant and revoke ceremonies reuses the
 * governing recent-login freshness mechanism (a recent login satisfies
 * step-up on first publication only; replacement demands a fresh code).
 * The window length and the session stamp are server state, not contract
 * values.
 *
 * These are JSON message shapes without a binary codec. If a server lane
 * needs to parse or validate one, the shape promotes into this module
 * (with the application-backend mirror added in the same release) rather
 * than being restated elsewhere — one canonical definition per contract.
 */

import { ContractVersionError } from './encoding';

export const POLICY_KEY_ACCESS_VERSION = 1;
export const POLICY_KEY_ACCESS_STATUS_VERSION = 1;

export type PolicyKeyAccessStatus = 'active' | 'revoked';

/**
 * Wire codes for access-row status. Codes are explicitly assigned and
 * never contiguous-by-convention; unknown codes fail closed.
 */
export const POLICY_KEY_ACCESS_STATUS_CODES = {
  active: 0x01,
  revoked: 0x02,
} as const satisfies Record<PolicyKeyAccessStatus, number>;

const CODE_TO_ACCESS_STATUS: Record<number, PolicyKeyAccessStatus> = Object.fromEntries(
  Object.entries(POLICY_KEY_ACCESS_STATUS_CODES).map(([status, code]) => [code, status as PolicyKeyAccessStatus]),
);

/** Grant payload: installs an active access row for one principal. */
export interface PolicyKeyAccessGrantV1 {
  readonly policy_key_id: string;
  readonly principal_auth_hash: string;
  readonly access_generation: number;
}

/** Revoke payload: marks the access row revoked and bumps the generation. */
export interface PolicyKeyAccessRevokeV1 {
  readonly policy_key_id: string;
  readonly principal_auth_hash: string;
  readonly access_generation: number;
}

/** Status query carrying the generation the client last observed. */
export interface PolicyKeyAccessStatusQueryV1 {
  readonly policy_key_id: string;
  readonly principal_auth_hash: string;
  readonly observed_access_generation: number;
}

/** Status view returned for one principal's access to one PolicyKey. */
export interface PolicyKeyAccessStatusV1 {
  readonly policy_key_id: string;
  readonly principal_auth_hash: string;
  readonly status: PolicyKeyAccessStatus;
  readonly access_generation: number;
}

export function encodePolicyKeyAccessStatus(status: PolicyKeyAccessStatus): number {
  return POLICY_KEY_ACCESS_STATUS_CODES[status];
}

/** Fail closed on unknown access-status codes. */
export function decodePolicyKeyAccessStatus(code: number): PolicyKeyAccessStatus {
  const status = CODE_TO_ACCESS_STATUS[code];
  if (status === undefined) {
    throw new ContractVersionError(`PolicyKeyAccessStatus: unknown code 0x${code.toString(16)}`);
  }
  return status;
}
