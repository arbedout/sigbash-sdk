/**
 * Staged signer provisioning lifecycle contracts: the states a Sigbash
 * signer reservation walks from intent to a sign-capable PolicyKey.
 *
 * Lifecycle: reserve → assemble descriptor → compile policy + REQKEY per
 * signer → seal → activate. Each staged signer is an independent
 * PolicyKey participating in the canonical wallet's sortedmulti_a leaves;
 * assembly derives the canonical descriptor over the reserved PolicyKeys
 * and introduces no new descriptor algebra.
 *
 * An expired or un-activated reservation leaves no usable signer: it
 * cannot sign, cannot register envelopes, and is reaped without
 * descriptor or policy residue. Re-sealing a fresh reservation for
 * identical intent yields an identical descriptor — provisioning is
 * deterministic.
 *
 * These are JSON message shapes without a binary codec. If a server lane
 * needs to parse or validate one, the shape promotes into this module
 * (with the application-backend mirror added in the same release) rather
 * than being restated elsewhere — one canonical definition per contract.
 */

import { ContractVersionError, invertCodeMap } from './encoding';
import type { PerPolicyKeySessionDescriptorV1 } from './signingSession';

export const SIGNER_PROVISIONING_VERSION = 1;
export const SIGNER_PROVISIONING_STATE_VERSION = 1;

export type SignerProvisioningState =
  | 'RESERVED'
  | 'ASSEMBLED'
  | 'COMPILED'
  | 'SEALED'
  | 'ACTIVATED'
  | 'EXPIRED';

/**
 * Wire codes for provisioning states. Codes are explicitly assigned and
 * never contiguous-by-convention; unknown codes fail closed.
 */
export const SIGNER_PROVISIONING_STATE_CODES = {
  RESERVED: 0x01,
  ASSEMBLED: 0x02,
  COMPILED: 0x03,
  SEALED: 0x04,
  ACTIVATED: 0x05,
  EXPIRED: 0x06,
} as const satisfies Record<SignerProvisioningState, number>;

const CODE_TO_PROVISIONING_STATE: Record<number, SignerProvisioningState> = /*#__PURE__*/ invertCodeMap(
  SIGNER_PROVISIONING_STATE_CODES,
);

/**
 * One staged signer reservation: the per-PolicyKey session descriptor
 * scope the reservation will seal into a sign-capable key. No field here
 * ever carries wallet plaintext — sealing commits roots and digests only.
 */
export interface SignerReservationV1 {
  readonly reservation_id: string;
  readonly descriptor: PerPolicyKeySessionDescriptorV1;
  readonly state: SignerProvisioningState;
}

export function encodeSignerProvisioningState(state: SignerProvisioningState): number {
  return SIGNER_PROVISIONING_STATE_CODES[state];
}

/** Fail closed on unknown provisioning-state codes. */
export function decodeSignerProvisioningState(code: number): SignerProvisioningState {
  const state = CODE_TO_PROVISIONING_STATE[code];
  if (state === undefined) {
    throw new ContractVersionError(`SignerProvisioningState: unknown code 0x${code.toString(16)}`);
  }
  return state;
}
