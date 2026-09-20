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

// TX_TEMPLATE_HASH_MATCHES commitment computation (normally invoked
// automatically by conditionConfigToPoetPolicy — exported directly for
// callers who need the raw committed value, e.g. to embed in a
// precomputed-hash test fixture).
export { computeTemplateHashCommitment } from './templatehash';
export type { TemplateHashRawFields } from './templatehash';
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

// COUNT_BASED_CONSTRAINT helper with arbitrary reset periods (SDK-only surface)
export { nUse } from './n-use';
export type { NUseOptions, NUsePeriod } from './n-use';

// Socket abstraction
export { SigbashSocket } from './socket';

// TOTP utilities
export { generateTOTPSecret, buildTOTPUri } from './totp';

// Enums — exported string constants for condition params
export { SIGHASH_TYPES, SCRIPT_TYPES, FORFEIT_DELEGATION } from './enums';
export type { SighashType, ScriptType, ForfeitDelegation } from './enums';

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
  // Audit log types
  AuditLogEntry,
  AuditLogsOptions,
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
  WeakSecretError,
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
export const SDK_VERSION = '0.8.3';

// Arkade integration — @arkade-os/ts-sdk Identity bridge
export {
  SigbashArkadeIdentity,
  SigbashArkadeSigningError,
} from './SigbashArkadeIdentity';
export type {
  ArkadeContext,
  ArkadeTransaction,
  ArkadeSignerSession,
} from './SigbashArkadeIdentity';

// Audit log
export {
  AUDIT_LOG_KEY_LABEL,
  deriveAdminAuditDek,
  encryptAuditEntry,
  decryptAuditEntry,
  verifyReceiptChain,
} from './audit-log';

// Cross-component contracts — versioned source of truth for lane-boundary
// structures (wallet descriptor, wallet id, approval commitment, sync
// envelope/event header, capability groups, proposal/attempt states,
// policy versions, recovery envelope, signing error codes).
export {
  ContractVersionError,
  NETWORK_ID_VERSION,
  NETWORK_CODES,
  encodeNetworkId,
  decodeNetworkId,
  parseNetworkId,
  WALLET_DESCRIPTOR_CONTRACT_ID,
  WALLET_DESCRIPTOR_VERSION,
  WALLET_SIGNER_KIND_CODES,
  WALLET_MODE_CODES,
  MAX_SIGNERS_PER_LEAF,
  encodeWalletDescriptorV1,
  decodeWalletDescriptorV1,
  walletDescriptorToHex,
  walletDescriptorFromHex,
  WALLET_ID_VERSION,
  WALLET_ID_TAG,
  WALLET_ID_LENGTH,
  computeWalletId,
  walletIdToHex,
  walletIdFromHex,
  APPROVAL_COMMITMENT_CONTRACT_ID,
  APPROVAL_COMMITMENT_VERSION,
  APPROVAL_COMMITMENT_TAG,
  APPROVAL_COMMITMENT_LENGTH,
  encodeApprovalCommitmentV1,
  decodeApprovalCommitmentV1,
  computeApprovalCommitment,
  approvalCommitmentToHex,
  hexField,
  SYNC_ENVELOPE_CONTRACT_ID,
  EVENT_HEADER_CONTRACT_ID,
  ENCRYPTED_SYNC_ENVELOPE_VERSION,
  ENCRYPTED_EVENT_HEADER_VERSION,
  encodeEncryptedEventHeaderV1,
  decodeEncryptedEventHeaderV1,
  CAPABILITY_EPOCH_VERSION,
  CAPABILITY_GROUP_ORG_COMMON,
  CAPABILITY_GROUP_POLICY_GOVERNANCE,
  CAPABILITY_GROUP_AUDIT,
  CAPABILITY_GROUP_SECURITY_RECOVERY,
  CAPABILITY_GROUP_WALLET_PREFIX,
  walletCapabilityGroupId,
  parseCapabilityGroupId,
  encodeCapabilityEpoch,
  PROPOSAL_ID_VERSION,
  SIGNING_ATTEMPT_ID_VERSION,
  TRANSACTION_PROPOSAL_STATE_VERSION,
  SIGNING_ATTEMPT_STATE_VERSION,
  TRANSACTION_PROPOSAL_STATE_CODES,
  SIGNING_ATTEMPT_STATE_CODES,
  parseProposalId,
  parseSigningAttemptId,
  encodeTransactionProposalState,
  decodeTransactionProposalState,
  encodeSigningAttemptState,
  decodeSigningAttemptState,
  isProposalTerminal,
  POLICY_VERSION_ID_VERSION,
  POLICY_ENFORCEMENT_CLASS_VERSION,
  POLICY_VERSION_STATE_VERSION,
  POLICY_ENFORCEMENT_CLASS_CODES,
  POLICY_VERSION_STATE_CODES,
  parsePolicyVersionId,
  encodePolicyEnforcementClass,
  decodePolicyEnforcementClass,
  encodePolicyVersionState,
  decodePolicyVersionState,
  RECOVERY_ENVELOPE_CONTRACT_ID,
  RECOVERY_ENVELOPE_VERSION,
  RECOVERY_QR_FORMAT_VERSION,
  encodeRecoveryEnvelopeVersion,
  decodeRecoveryEnvelopeVersion,
  SIGNING_ERROR_CODESET_VERSION,
  SIGNING_API_ERROR_CODES,
  SIGNING_ERROR_CLASSES,
  signingFailureClass,
  isSigningSessionTerminal,
} from './contracts';
export type {
  NetworkId,
  WalletDescriptorV1,
  WalletSignerKind,
  WalletSignerRootV1,
  WalletMode,
  AllowedSignerSetV1,
  RecoveryBranchV1,
  WalletId,
  ApprovalCommitmentFieldsV1,
  ApprovalCommitmentInputV1,
  ApprovalCommitmentOutputV1,
  EncryptedEventHeaderV1,
  TransactionProposalState,
  SigningAttemptState,
  PolicyEnforcementClass,
  PolicyVersionState,
  SigningApiErrorCode,
  SigningFailureClass,
} from './contracts';

// Institutional wallet helpers — canonical construction, canonical text +
// fingerprint, TapTree derivation, and the wallet-ownership REQKEY template.
// The contracts lane above carries the sync-contract codec; this lane carries
// the canonical spend-identity form the proof system binds against. The two
// share the WalletSignerKind union, exported once from contracts.
export * from './wallet';
