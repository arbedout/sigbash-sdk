/**
 * Signing API error-code contract: terminal vs retryable, V1.
 *
 * The set is exhaustive for the V1 signing surface and extracted from the
 * signing API's real failure paths. Codes are stable strings; the set
 * itself is versioned, and additions require a version bump — never an
 * unversioned extension.
 *
 * Terminal means the cryptographic signing attempt identity is dead: the
 * nonce/proof/session state is consumed or unrecoverable, or the request
 * can never succeed as posed. The client destroys attempt-local state and
 * creates a fresh attempt for the same immutable proposal; approvals are
 * preserved because proposal semantics are unchanged.
 *
 * Retryable means the same attempt may be retried after the stated
 * condition clears (transport recovery, cooldown expiry, key-info
 * availability). A retryable code never masks a consumed nonce.
 */

export const SIGNING_ERROR_CODESET_VERSION = 1;

export const SIGNING_API_ERROR_CODES = [
  // Request-validation failures; no session exists to preserve.
  'MISSING_NETWORK',
  'INVALID_NETWORK',
  'NETWORK_NOT_ENABLED_FOR_ORG',
  'PROOF_BUNDLE_MALFORMED',
  'MISSING_REQUIRED_FIELD',
  'INVALID_FIELD_FORMAT',
  'INPUT_COUNT_OUT_OF_RANGE',
  // Identity/policy-binding rejections; the attempt cannot proceed.
  'CREDENTIAL_BINDING_REQUIRED',
  'CREDENTIAL_NOT_REGISTERED',
  'POLICY_ROOT_MISMATCH',
  'KEY_COMMITMENT_NOT_FOUND',
  'TOTP_PREFLIGHT_REQUIRED',
  'POLICY_COOLDOWN',
  // Session-state failures; nonce/session identity is consumed or broken.
  'SESSION_STATE_UNKNOWN',
  'SESSION_NOT_FOUND',
  'INPUT_COUNT_MISMATCH',
  'INPUT_INDEX_OUT_OF_RANGE',
  'INPUT_PHASE_MISMATCH',
  'PROOF_REJECTED',
  'PROOF_SESSION_ID_MISMATCH',
  'EQUATION_DEBIT_FAILED',
  'SIGNING_SERVICE_LOCKSTEP',
  // Transport/service availability; same attempt may be retried.
  'SIGNING_SERVICE_TIMEOUT',
  'SIGNING_SERVICE_UNREACHABLE',
  'SIGNING_KEY_INFO_UNAVAILABLE',
] as const;

export type SigningApiErrorCode = (typeof SIGNING_API_ERROR_CODES)[number];

export type SigningFailureClass = 'terminal' | 'retryable';

export const SIGNING_ERROR_CLASSES = {
  MISSING_NETWORK: 'terminal',
  INVALID_NETWORK: 'terminal',
  NETWORK_NOT_ENABLED_FOR_ORG: 'terminal',
  PROOF_BUNDLE_MALFORMED: 'terminal',
  MISSING_REQUIRED_FIELD: 'terminal',
  INVALID_FIELD_FORMAT: 'terminal',
  INPUT_COUNT_OUT_OF_RANGE: 'terminal',
  CREDENTIAL_BINDING_REQUIRED: 'terminal',
  CREDENTIAL_NOT_REGISTERED: 'terminal',
  POLICY_ROOT_MISMATCH: 'terminal',
  KEY_COMMITMENT_NOT_FOUND: 'terminal',
  TOTP_PREFLIGHT_REQUIRED: 'terminal',
  POLICY_COOLDOWN: 'retryable',
  SESSION_STATE_UNKNOWN: 'terminal',
  SESSION_NOT_FOUND: 'terminal',
  INPUT_COUNT_MISMATCH: 'terminal',
  INPUT_INDEX_OUT_OF_RANGE: 'terminal',
  INPUT_PHASE_MISMATCH: 'terminal',
  PROOF_REJECTED: 'terminal',
  PROOF_SESSION_ID_MISMATCH: 'terminal',
  EQUATION_DEBIT_FAILED: 'terminal',
  SIGNING_SERVICE_LOCKSTEP: 'terminal',
  SIGNING_SERVICE_TIMEOUT: 'retryable',
  SIGNING_SERVICE_UNREACHABLE: 'retryable',
  SIGNING_KEY_INFO_UNAVAILABLE: 'retryable',
} as const satisfies Record<SigningApiErrorCode, SigningFailureClass>;

/** Exhaustive classification; unknown codes fail closed. */
export function signingFailureClass(code: string): SigningFailureClass {
  if (!Object.prototype.hasOwnProperty.call(SIGNING_ERROR_CLASSES, code)) {
    throw new Error(`SigningApiErrorCode: unknown code "${code}"`);
  }
  return SIGNING_ERROR_CLASSES[code as SigningApiErrorCode];
}

/**
 * True when the client must destroy attempt-local nonce/proof/session
 * state and start a fresh signing attempt. Retryable failures keep the
 * attempt identity alive.
 */
export function isSigningSessionTerminal(code: string): boolean {
  return signingFailureClass(code) === 'terminal';
}
