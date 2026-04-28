/**
 * Sigbash SDK — TypeScript SDK for the Sigbash oblivious signing platform.
 *
 * @packageDocumentation
 */

// Ensure Node.js libuv thread pool is large enough for parallel WebCrypto
// hashing across multiple prove workers. Must be set before any crypto.subtle
// call triggers thread pool initialization (pool size is fixed at first use).
// Default is 4 threads; parallel proving with 2 workers dispatching 8+ hashes
// each can saturate the pool and cause 10-100x hash latency regression.
if (typeof process !== 'undefined' && process.env && !process.env.UV_THREADPOOL_SIZE) {
  process.env.UV_THREADPOOL_SIZE = '16';
}

// WASM loading utilities
export { loadWasm, detectEnvironment, isWasmReady, waitForWasm, getProveWorkerManager } from './wasm-loader';
export type { WasmLoaderOptions, WasmLoaderResult, Environment, ProveWorkerManager, ProveRequest, ProveWorkerManagerStatus } from './wasm-loader';

// Main client class
export { SigbashClient } from './SigbashClient';

// Auth utilities
export { doubleSha256, validateAuthHash } from './auth';

// Credential generation and identity
export { generateCredentials, getAuthHash } from './credentials';
export type { GenerateCredentialsOptions, GeneratedCredentials, AuthHashResult } from './credentials';

// Crypto utilities
export { deriveKEK, encryptKMC, decryptKMC } from './crypto';

// Policy templates
export {
  buildPolicyFromTemplate,
  POLICY_TEMPLATES,
} from './templates';
export type { PolicyTemplate, TemplateParam } from './templates';

// Policy builder — converts conditionConfig to POET v1.1 policy
export { conditionConfigToPoetPolicy } from './policy-builder';
export type {
  ConditionConfig,
  LeafConditionConfig,
  BinaryConditionConfig,
  UnaryConditionConfig,
  ExplicitOperatorConfig,
  ConditionsArrayConfig,
  OperatorAlias,
  ConditionConfigOperator,
} from './policy-builder';

// Socket abstraction
export { SigbashSocket } from './socket';

// TOTP utilities
export { generateTOTPSecret, buildTOTPUri } from './totp';

// Enums — exported string constants for condition params
export { SIGHASH_TYPES, SCRIPT_TYPES } from './enums';
export type { SighashType, ScriptType } from './enums';

// Condition type catalog — machine-readable reference for all 25 condition types
export { CONDITION_TYPES } from './conditions';
export type { ConditionTypeSpec, ConditionParamSpec } from './conditions';

// TypeScript types
export type {
  SigbashConfig,
  Network,
  POETPolicy,
  PolicyNode,
  OperatorNode,
  ConditionNode,
  PolicyIssue,
  OperatorType,
  OperatorParams,
  // Primitive helpers
  Selector,
  SelectorShorthand,
  SelectorObject,
  ComparisonOperator,
  SigbashClientOptions,
  CreateKeyOptions,
  CreateKeyResult,
  GetKeyResult,
  KeySummary,
  KeyListItem,
  SignPSBTOptions,
  SignPSBTResult,
  NullifierCheckResult,
  VerifyPSBTOptions,
  VerifyPSBTResult,
} from './types';

/** @deprecated Use string codes on {@link SigbashSDKError} subclasses instead. */
export { ErrorCode } from './types';

// Error classes
export {
  // Modern error hierarchy (all extend SigbashSDKError)
  SigbashSDKError,
  ClientDisposedError,
  KeyIndexExistsError,
  PolicyCompileError,
  MissingOptionError,
  AdminError,
  TOTPRequiredError,
  TOTPInvalidError,
  TOTPSetupIncompleteError,
  NetworkError,
  // Server-failure classes — first-class members of the modern hierarchy.
  PolicyValidationError,
  AuthenticationError,
  NetworkMismatchError,
  ServerError,
  parseServerError,
  // Backward-compat surface — kept for old consumer code only.
  // The SDK itself no longer throws these.
  SigbashError,
  WasmError,
  CryptoError,
  TimeoutError,
} from './errors';

// Version metadata
export type { WasmVersionMetadata } from './version-metadata';
export { buildWasmUrl, sha384ToBase64, formatSRIHash } from './version-metadata';

// SDK version
export const SDK_VERSION = '0.2.0';
