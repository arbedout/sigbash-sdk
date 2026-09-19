/**
 * Policy version identity and enforcement-class contracts.
 *
 * Every policy version is an immutable client-side record. The version id
 * is a random client UUID; the enforcement class states which layer
 * enforces a policy rule — hard cryptographic/state enforcement, a
 * governance-only application rule, or a disabled condition excluded from
 * hard institutional claims. The design-partner milestone uses immutable
 * policy keys only: an approved revision goes to replacement-key/wallet
 * migration rather than in-place mutation.
 */

import { ContractVersionError } from './encoding';

export const POLICY_VERSION_ID_VERSION = 1;
export const POLICY_ENFORCEMENT_CLASS_VERSION = 1;
export const POLICY_VERSION_STATE_VERSION = 1;

export type PolicyEnforcementClass = 'hard_cryptographic' | 'governance_only' | 'disabled_unsound';

export const POLICY_ENFORCEMENT_CLASS_CODES = {
  hard_cryptographic: 0x01,
  governance_only: 0x02,
  disabled_unsound: 0x03,
} as const satisfies Record<PolicyEnforcementClass, number>;

const CODE_TO_ENFORCEMENT_CLASS: Record<number, PolicyEnforcementClass> = {
  [POLICY_ENFORCEMENT_CLASS_CODES.hard_cryptographic]: 'hard_cryptographic',
  [POLICY_ENFORCEMENT_CLASS_CODES.governance_only]: 'governance_only',
  [POLICY_ENFORCEMENT_CLASS_CODES.disabled_unsound]: 'disabled_unsound',
};

export type PolicyVersionState =
  | 'DRAFT'
  | 'PROPOSED'
  | 'AWAITING_APPROVALS'
  | 'APPROVED'
  | 'MIGRATION_REQUIRED'
  | 'SUBMITTED'
  | 'COOLING_OFF'
  | 'ACTIVE'
  | 'REJECTED'
  | 'CANCELLED'
  | 'SUPERSEDED';

export const POLICY_VERSION_STATE_CODES = {
  DRAFT: 0x01,
  PROPOSED: 0x02,
  AWAITING_APPROVALS: 0x03,
  APPROVED: 0x04,
  MIGRATION_REQUIRED: 0x05,
  SUBMITTED: 0x06,
  COOLING_OFF: 0x07,
  ACTIVE: 0x08,
  REJECTED: 0x09,
  CANCELLED: 0x0a,
  SUPERSEDED: 0x0b,
} as const satisfies Record<PolicyVersionState, number>;

const CODE_TO_POLICY_VERSION_STATE: Record<number, PolicyVersionState> = Object.fromEntries(
  Object.entries(POLICY_VERSION_STATE_CODES).map(([state, code]) => [code, state as PolicyVersionState]),
);

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function parsePolicyVersionId(value: string): string {
  if (!UUID_PATTERN.test(value)) {
    throw new ContractVersionError(`PolicyVersionId: expected UUID, got "${value}"`);
  }
  return value.toLowerCase();
}

export function encodePolicyEnforcementClass(clazz: PolicyEnforcementClass): number {
  return POLICY_ENFORCEMENT_CLASS_CODES[clazz];
}

/** Fail closed on unknown enforcement-class codes. */
export function decodePolicyEnforcementClass(code: number): PolicyEnforcementClass {
  const clazz = CODE_TO_ENFORCEMENT_CLASS[code];
  if (clazz === undefined) {
    throw new ContractVersionError(`PolicyEnforcementClass: unknown code 0x${code.toString(16)}`);
  }
  return clazz;
}

export function encodePolicyVersionState(state: PolicyVersionState): number {
  return POLICY_VERSION_STATE_CODES[state];
}

/** Fail closed on unknown policy-version state codes. */
export function decodePolicyVersionState(code: number): PolicyVersionState {
  const state = CODE_TO_POLICY_VERSION_STATE[code];
  if (state === undefined) {
    throw new ContractVersionError(`PolicyVersionState: unknown code 0x${code.toString(16)}`);
  }
  return state;
}
