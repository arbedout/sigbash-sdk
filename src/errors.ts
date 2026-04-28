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
 * Policy validation error with structured issues.
 *
 * Returned by `parseServerError` when the server rejects a policy with
 * structured issues. First-class member of the modern `SigbashSDKError`
 * hierarchy — catch via `instanceof SigbashSDKError` or `PolicyValidationError`.
 */
export class PolicyValidationError extends SigbashSDKError {
  public readonly issues: PolicyIssue[];
  public readonly details?: any;

  constructor(message: string, issues: PolicyIssue[]) {
    super(message, 'POLICY_INVALID');
    this.name = 'PolicyValidationError';
    this.issues = issues;
    this.details = { issues };

    Object.setPrototypeOf(this, PolicyValidationError.prototype);
  }
}

/**
 * Authentication error.
 *
 * Returned by `parseServerError` when the server rejects credentials.
 * First-class member of the modern `SigbashSDKError` hierarchy.
 */
export class AuthenticationError extends SigbashSDKError {
  public readonly details?: any;

  constructor(message: string, details?: any) {
    super(message, 'AUTH_FAILED');
    this.name = 'AuthenticationError';
    this.details = details;

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
 * Returned by `parseServerError` when the server's expected network does not
 * match the network supplied in the request. First-class member of the modern
 * `SigbashSDKError` hierarchy.
 */
export class NetworkMismatchError extends SigbashSDKError {
  public readonly expected: string;
  public readonly actual: string;
  public readonly details?: any;

  constructor(expected: string, actual: string) {
    super(
      `Network mismatch: expected ${expected}, got ${actual}`,
      'NETWORK_MISMATCH'
    );
    this.name = 'NetworkMismatchError';
    this.expected = expected;
    this.actual = actual;
    this.details = { expected, actual };

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
 * Returned by `parseServerError` for generic server failures that do not match
 * a more specific class. First-class member of the modern `SigbashSDKError`
 * hierarchy. The `statusCode` (when present) reflects the HTTP status; the raw
 * server response is preserved in `details`.
 */
export class ServerError extends SigbashSDKError {
  public readonly statusCode?: number;
  public readonly details?: any;

  constructor(message: string, statusCode?: number, details?: any) {
    super(message, 'SERVER_ERROR');
    this.name = 'ServerError';
    this.statusCode = statusCode;
    this.details = details;

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
 * Thrown when an operation is attempted on a `SigbashClient` instance that has
 * already been disposed via `dispose()`. Once disposed, the client cannot be
 * reused — create a new instance instead.
 */
export class ClientDisposedError extends SigbashSDKError {
  constructor(message: string = 'SigbashClient has been disposed') {
    super(message, 'CLIENT_DISPOSED');
    this.name = 'ClientDisposedError';
    Object.setPrototypeOf(this, ClientDisposedError.prototype);
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
export function parseServerError(response: any): SigbashSDKError {
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
