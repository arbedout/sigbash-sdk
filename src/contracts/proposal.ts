/**
 * Transaction proposal and signing-attempt identity and state contracts.
 *
 * The proposal state machine is deterministic and matches the workflow
 * specification exactly: DRAFT may mutate freely and holds no valid
 * approvals; PROPOSED fixes the approval commitment and the selected
 * signer/tapleaf plan; a semantic mutation creates a new proposal and
 * marks the old one SUPERSEDED; a fresh cryptographic signing attempt for
 * unchanged proposal semantics preserves approvals; a session-terminal
 * failure moves the attempt to TERMINAL_FAILED and the proposal to
 * SESSION_RESTART_REQUIRED. Identity ids are random client UUIDs; only
 * the id formats are versioned here.
 */

import { ContractVersionError } from './encoding';

export const PROPOSAL_ID_VERSION = 1;
export const SIGNING_ATTEMPT_ID_VERSION = 1;

export const TRANSACTION_PROPOSAL_STATE_VERSION = 1;
export const SIGNING_ATTEMPT_STATE_VERSION = 1;

export type TransactionProposalState =
  | 'DRAFT'
  | 'PROPOSED'
  | 'AWAITING_APPROVALS'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXPIRED'
  | 'CANCELLED'
  | 'SUPERSEDED'
  | 'SIGNING'
  | 'SESSION_RESTART_REQUIRED'
  | 'FINALIZED'
  | 'BROADCAST'
  | 'BROADCAST_FAILED'
  | 'CONFIRMED';

/**
 * Wire codes for the proposal states. Codes are explicitly assigned and
 * never contiguous-by-convention; unknown codes fail closed.
 */
export const TRANSACTION_PROPOSAL_STATE_CODES = {
  DRAFT: 0x01,
  PROPOSED: 0x02,
  AWAITING_APPROVALS: 0x03,
  APPROVED: 0x04,
  REJECTED: 0x05,
  EXPIRED: 0x06,
  CANCELLED: 0x07,
  SUPERSEDED: 0x08,
  SIGNING: 0x09,
  SESSION_RESTART_REQUIRED: 0x0a,
  FINALIZED: 0x0b,
  BROADCAST: 0x0c,
  BROADCAST_FAILED: 0x0d,
  CONFIRMED: 0x0e,
} as const satisfies Record<TransactionProposalState, number>;

const CODE_TO_PROPOSAL_STATE: Record<number, TransactionProposalState> = Object.fromEntries(
  Object.entries(TRANSACTION_PROPOSAL_STATE_CODES).map(([state, code]) => [code, state as TransactionProposalState]),
);

export type SigningAttemptState =
  | 'PENDING'
  | 'NONCES_ISSUED'
  | 'PROOF_VERIFIED'
  | 'PARTIALLY_SIGNED'
  | 'COMPLETED'
  | 'TERMINAL_FAILED';

export const SIGNING_ATTEMPT_STATE_CODES = {
  PENDING: 0x01,
  NONCES_ISSUED: 0x02,
  PROOF_VERIFIED: 0x03,
  PARTIALLY_SIGNED: 0x04,
  COMPLETED: 0x05,
  TERMINAL_FAILED: 0x06,
} as const satisfies Record<SigningAttemptState, number>;

const CODE_TO_ATTEMPT_STATE: Record<number, SigningAttemptState> = Object.fromEntries(
  Object.entries(SIGNING_ATTEMPT_STATE_CODES).map(([state, code]) => [code, state as SigningAttemptState]),
);

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parseProposalId(value: string): string {
  if (!UUID_PATTERN.test(value)) {
    throw new ContractVersionError(`ProposalId: expected UUID, got "${value}"`);
  }
  return value.toLowerCase();
}

export function parseSigningAttemptId(value: string): string {
  if (!UUID_PATTERN.test(value)) {
    throw new ContractVersionError(`SigningAttemptId: expected UUID, got "${value}"`);
  }
  return value.toLowerCase();
}

export function encodeTransactionProposalState(state: TransactionProposalState): number {
  return TRANSACTION_PROPOSAL_STATE_CODES[state];
}

/** Fail closed on unknown state codes. */
export function decodeTransactionProposalState(code: number): TransactionProposalState {
  const state = CODE_TO_PROPOSAL_STATE[code];
  if (state === undefined) {
    throw new ContractVersionError(`TransactionProposalState: unknown code 0x${code.toString(16)}`);
  }
  return state;
}

export function encodeSigningAttemptState(state: SigningAttemptState): number {
  return SIGNING_ATTEMPT_STATE_CODES[state];
}

/** Fail closed on unknown state codes. */
export function decodeSigningAttemptState(code: number): SigningAttemptState {
  const state = CODE_TO_ATTEMPT_STATE[code];
  if (state === undefined) {
    throw new ContractVersionError(`SigningAttemptState: unknown code 0x${code.toString(16)}`);
  }
  return state;
}

/**
 * Proposals in these states can never progress in the official client;
 * the transition out is supersession or a new proposal.
 */
export function isProposalTerminal(state: TransactionProposalState): boolean {
  return (
    state === 'REJECTED' ||
    state === 'EXPIRED' ||
    state === 'CANCELLED' ||
    state === 'SUPERSEDED' ||
    state === 'CONFIRMED'
  );
}
