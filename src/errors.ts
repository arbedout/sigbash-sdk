/**
 * Error classes for Sigbash SDK
 */

import { ErrorCode, PolicyIssue } from './types';

/**
 * Base error class for all SDK errors.
 *
 * @deprecated Use {@link SigbashSDKError} subclasses instead.
 * New code should catch `SigbashSDKError` (or its specific subclasses such as
 * `KeyIndexExistsError`, `PolicyCompileError`, `TOTPRequiredError`, etc.).
 */
export class SigbashError extends Error {
  public readonly code: ErrorCode;
  public readonly details?: any;

  constructor(message: string, code: ErrorCode = ErrorCode.UNKNOWN, details?: any) {
    super(message);
    this.name = 'SigbashError';
    this.code = code;
    this.details = details;

    // Maintain proper prototype chain
    Object.setPrototypeOf(this, SigbashError.prototype);
  }
}

/**
 * Policy validation error with structured issues.
 *
 * @deprecated Use {@link PolicyCompileError} instead.
 */
export class PolicyValidationError extends SigbashError {
  public readonly issues: PolicyIssue[];

  constructor(message: string, issues: PolicyIssue[]) {
    super(message, ErrorCode.INVALID_POLICY, { issues });
    this.name = 'PolicyValidationError';
    this.issues = issues;

    Object.setPrototypeOf(this, PolicyValidationError.prototype);
  }
}

/**
 * Authentication error.
 *
 * @deprecated Use {@link SigbashSDKError} with code `'AUTH_FAILED'` instead.
 */
export class AuthenticationError extends SigbashError {
  constructor(message: string, details?: any) {
    super(message, ErrorCode.AUTH_FAILED, details);
    this.name = 'AuthenticationError';

    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

/**
 * WASM loading/initialization error.
 *
 * @deprecated Use {@link SigbashSDKError} with code `'WASM_NOT_LOADED'` instead.
 */
export class WasmError extends SigbashError {
  constructor(message: string, details?: any) {
    super(message, ErrorCode.WASM_NOT_LOADED, details);
    this.name = 'WasmError';

    Object.setPrototypeOf(this, WasmError.prototype);
  }
}

/**
 * Network mismatch error.
 *
 * @deprecated Use {@link NetworkError} instead.
 */
export class NetworkMismatchError extends SigbashError {
  constructor(expected: string, actual: string) {
    super(
      `Network mismatch: expected ${expected}, got ${actual}`,
      ErrorCode.NETWORK_MISMATCH,
      { expected, actual }
    );
    this.name = 'NetworkMismatchError';

    Object.setPrototypeOf(this, NetworkMismatchError.prototype);
  }
}

/**
 * Encryption/decryption error.
 *
 * @deprecated Use {@link SigbashSDKError} with code `'ENCRYPTION_FAILED'` or `'DECRYPTION_FAILED'` instead.
 */
export class CryptoError extends SigbashError {
  constructor(message: string, isEncryption: boolean = true) {
    super(
      message,
      isEncryption ? ErrorCode.ENCRYPTION_FAILED : ErrorCode.DECRYPTION_FAILED
    );
    this.name = 'CryptoError';

    Object.setPrototypeOf(this, CryptoError.prototype);
  }
}

/**
 * Server communication error.
 *
 * @deprecated Use {@link SigbashSDKError} with code `'SERVER_ERROR'` instead.
 */
export class ServerError extends SigbashError {
  public readonly statusCode?: number;

  constructor(message: string, statusCode?: number, details?: any) {
    super(message, ErrorCode.SERVER_ERROR, details);
    this.name = 'ServerError';
    this.statusCode = statusCode;

    Object.setPrototypeOf(this, ServerError.prototype);
  }
}

/**
 * Operation timeout error.
 *
 * @deprecated Use {@link SigbashSDKError} with code `'TIMEOUT'` instead.
 */
export class TimeoutError extends SigbashError {
  constructor(operation: string, timeoutMs: number) {
    super(
      `Operation '${operation}' timed out after ${timeoutMs}ms`,
      ErrorCode.TIMEOUT,
      { operation, timeoutMs }
    );
    this.name = 'TimeoutError';

    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

// ---------------------------------------------------------------------------
// SDK-specific error base class (string codes instead of ErrorCode enum)
// ---------------------------------------------------------------------------

/**
 * Base error class for SDK-specific errors that use string codes.
 * New error classes (KeyIndexExistsError, MissingOptionError, etc.) extend this.
 */
export class SigbashSDKError extends Error {
  public readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'SigbashSDKError';
    this.code = code;
    Object.setPrototypeOf(this, SigbashSDKError.prototype);
  }
}

/**
 * Thrown when createKey() is called with a key_index that is already registered
 * for this credential. Use `nextAvailableIndex` to create an additional key, or
 * call `getKey(keyId)` to retrieve the existing one.
 */
export class KeyIndexExistsError extends SigbashSDKError {
  public readonly requestedIndex: number;
  public readonly nextAvailableIndex: number;

  constructor(requestedIndex: number, nextAvailableIndex: number) {
    super(
      `Key index ${requestedIndex} is already registered for this user. ` +
      `To create an additional key pass { keyIndex: ${nextAvailableIndex} } to createKey(). ` +
      `To retrieve the existing key call getKey() with the keyId returned at creation time.`,
      'KEY_INDEX_EXISTS'
    );
    this.name = 'KeyIndexExistsError';
    this.requestedIndex = requestedIndex;
    this.nextAvailableIndex = nextAvailableIndex;
    Object.setPrototypeOf(this, KeyIndexExistsError.prototype);
  }
}

/**
 * Parse a colon-separated Go error chain into an ordered array of segments,
 * de-duplicating repeated leading prefixes (e.g. two "POET policy compilation failed").
 */
function parseErrorChain(raw: string): string[] {
  const segments = raw.split(': ').map(s => s.trim()).filter(Boolean);
  // De-duplicate consecutive identical segments
  const deduped: string[] = [];
  for (const seg of segments) {
    if (deduped.length === 0 || deduped[deduped.length - 1] !== seg) {
      deduped.push(seg);
    }
  }
  return deduped;
}

/**
 * Thrown when POET policy compilation fails inside createKey().
 * Provides a structured `compilationTrace` array (innermost error last)
 * and a readable multi-line `message` so developers can pinpoint the cause
 * without wading through a flat colon-separated Go error chain.
 */
export class PolicyCompileError extends SigbashSDKError {
  /** Ordered error chain, innermost (most specific) segment last. */
  public readonly compilationTrace: string[];
  /** The most specific segment of the error chain. */
  public readonly summary: string;

  constructor(rawError: string) {
    const trace = parseErrorChain(rawError);
    const summary = trace[trace.length - 1] ?? rawError;
    const traceLines = trace.map((s, i) => `  ${i + 1}. ${s}`).join('\n');
    super(
      `Policy compilation failed: ${summary}\nCompilation trace:\n${traceLines}`,
      'POLICY_COMPILE_FAILED'
    );
    this.name = 'PolicyCompileError';
    this.compilationTrace = trace;
    this.summary = summary;
    Object.setPrototypeOf(this, PolicyCompileError.prototype);
  }
}

/**
 * Thrown when a required option is missing from a method call.
 * The `optionName` property identifies which option was missing.
 */
export class MissingOptionError extends SigbashSDKError {
  public readonly optionName: string;

  constructor(optionName: string) {
    super(`Required option '${optionName}' was not provided`, 'MISSING_OPTION');
    this.name = 'MissingOptionError';
    this.optionName = optionName;
    Object.setPrototypeOf(this, MissingOptionError.prototype);
  }
}

/**
 * Thrown when an operation requires admin privileges but the caller is not an admin.
 */
export class AdminError extends SigbashSDKError {
  constructor(message: string = 'Admin privileges required') {
    super(message, 'ADMIN_REQUIRED');
    this.name = 'AdminError';
    Object.setPrototypeOf(this, AdminError.prototype);
  }
}

/**
 * Thrown when a signing call is made against a 2FA-enabled key without providing a TOTP code.
 */
export class TOTPRequiredError extends SigbashSDKError {
  constructor() {
    super('TOTP code required for 2FA-enabled key', 'TOTP_REQUIRED');
    this.name = 'TOTPRequiredError';
    Object.setPrototypeOf(this, TOTPRequiredError.prototype);
  }
}

/**
 * Thrown when a provided TOTP code is rejected by the server.
 */
export class TOTPInvalidError extends SigbashSDKError {
  constructor() {
    super('Invalid TOTP code', 'TOTP_INVALID');
    this.name = 'TOTPInvalidError';
    Object.setPrototypeOf(this, TOTPInvalidError.prototype);
  }
}

/**
 * Thrown when signing is attempted on a 2FA-enabled key before confirmTOTP() has been called.
 */
export class TOTPSetupIncompleteError extends SigbashSDKError {
  constructor() {
    super('TOTP setup not confirmed. Call confirmTOTP() first.', 'TOTP_SETUP_INCOMPLETE');
    this.name = 'TOTPSetupIncompleteError';
    Object.setPrototypeOf(this, TOTPSetupIncompleteError.prototype);
  }
}

/**
 * Thrown when the requested network is not enabled or is unsupported.
 */
export class NetworkError extends SigbashSDKError {
  constructor(message: string = 'Network not enabled or unsupported') {
    super(message, 'NETWORK_NOT_ENABLED');
    this.name = 'NetworkError';
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

// ---------------------------------------------------------------------------
// Server error parser
// ---------------------------------------------------------------------------

/**
 * Parse server error response into appropriate error class
 */
export function parseServerError(response: any): SigbashError {
  const code = response.code as ErrorCode || ErrorCode.UNKNOWN;
  const message = response.message || 'Unknown server error';

  // Check for policy validation errors
  if (code === ErrorCode.INVALID_POLICY && response.issues) {
    return new PolicyValidationError(message, response.issues);
  }

  // Check for authentication errors
  if (code === ErrorCode.AUTH_FAILED) {
    return new AuthenticationError(message, response);
  }

  // Check for network mismatch
  if (code === ErrorCode.NETWORK_MISMATCH && response.expected && response.actual) {
    return new NetworkMismatchError(response.expected, response.actual);
  }

  // Generic server error
  return new ServerError(message, response.statusCode, response);
}
