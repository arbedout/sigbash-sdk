/**
 * TypeScript type definitions for Sigbash SDK
 */

/**
 * Bitcoin network for signing operations.
 */
export type Network = 'mainnet' | 'testnet' | 'signet';

/**
 * Legacy SDK configuration (for backward compatibility with wasm-loader usage).
 */
export interface SigbashConfig {
  /** Partner API key (from Sigbash dashboard) */
  apiKey: string;
  /** Server URL for Socket.IO connection */
  serverUrl: string;
  /** Bitcoin network to use */
  network: Network;
  /** Optional custom WASM binary URL */
  wasmUrl?: string;
  /** Expected SHA-256 hash of WASM binary for integrity verification */
  wasmHash?: string;
}

// ---------------------------------------------------------------------------
// Shared primitive types
// ---------------------------------------------------------------------------

/**
 * Selects which inputs or outputs a condition applies to.
 *
 * - `'ALL'` — every input/output must satisfy the condition.
 * - `'ANY'` — at least one input/output must satisfy the condition.
 * - `'INDEX'` — only the input/output at the specified zero-based `index`.
 *
 * Can also be passed as an object: `{ type: 'INDEX', index: 0 }`.
 */
export type SelectorShorthand = 'ALL' | 'ANY' | 'INDEX';

export interface SelectorObject {
  type: 'ALL' | 'ANY' | 'INDEX';
  /** Zero-based index — required when `type === 'INDEX'`. */
  index?: number;
}

/** Selector for which inputs/outputs a condition applies to. */
export type Selector = SelectorShorthand | SelectorObject;

/**
 * Comparison operators for value-based conditions such as
 * `OUTPUT_VALUE`, `INPUT_VALUE`, `TX_VERSION`, etc.
 */
export type ComparisonOperator = 'LTE' | 'GTE' | 'EQ' | 'LT' | 'GT' | 'NEQ';

// ---------------------------------------------------------------------------
// POET policy types
// ---------------------------------------------------------------------------

/** POET policy structure (v1.1 format) */
export interface POETPolicy {
  version: string;
  policy: PolicyNode;
}

/** Policy tree node (operator or condition) */
export type PolicyNode = OperatorNode | ConditionNode;

/** All operator types supported by the POET v1.1 runtime */
export type OperatorType =
  | 'AND' | 'OR' | 'NOT'
  | 'IMPLIES' | 'IFF'
  | 'THRESHOLD' | 'WEIGHTED_THRESHOLD' | 'MAJORITY'
  | 'EXACTLY' | 'AT_MOST'
  | 'VETO' | 'NOR' | 'NAND' | 'XOR';

/** Parameters for threshold-style operators */
export interface OperatorParams {
  /** Threshold value k (THRESHOLD, EXACTLY, AT_MOST, WEIGHTED_THRESHOLD) */
  k?: number;
  /** Per-child weights (WEIGHTED_THRESHOLD) */
  weights?: number[];
}

/** Operator node */
export interface OperatorNode {
  type: 'operator';
  operator: OperatorType;
  /** Structured operator parameters — preferred over top-level threshold */
  operatorParams?: OperatorParams;
  /** @deprecated Use operatorParams.k. Kept for backward compatibility. */
  threshold?: number;
  children: PolicyNode[];
  /** Per-node weight when this node is a child of WEIGHTED_THRESHOLD */
  weight?: number;
  description?: string;
}

/** Condition node (leaf node with specific constraint) */
export interface ConditionNode {
  type: 'condition';
  conditionType: string;
  conditionParams: Record<string, unknown>;
  /** Per-node weight when this node is a child of WEIGHTED_THRESHOLD */
  weight?: number;
  description?: string;
}

// ---------------------------------------------------------------------------
// SDK client types
// ---------------------------------------------------------------------------

/**
 * Options for constructing a SigbashClient instance.
 *
 * Admin holds apiKey and userKey; userSecretKey is user-only and never shared.
 * The SDK derives authHash = DSHA256(apiKey || userKey) and
 * KEK = HKDF(apiKey || userKey || userSecretKey, ...) from these three values.
 */
export interface SigbashClientOptions {
  /** Organisation-level API key from the Sigbash dashboard. */
  apiKey: string;
  /** Admin-assigned user identifier. */
  userKey: string;
  /** User-only secret key for KEK derivation — never sent to the server. */
  userSecretKey: string;
  /** Sigbash server URL (e.g. 'https://api.example.com'). */
  serverUrl: string;
  /**
   * BYO MuSig2 private key (32 bytes). If omitted, WASM generates a fresh key during createKey().
   * Prefer Uint8Array over hex string — strings cannot be securely wiped from memory.
   * When supplied as string: immediately copied to Uint8Array, string reference discarded.
   */
  musig2PrivateKey?: string | Uint8Array;
}

/**
 * Options for the createKey() SDK method.
 *
 * Exactly one of `template`/`templateParams` or `policy` must be provided.
 * Both `require2FA` and `network` are mandatory — omitting either throws MissingOptionError.
 */
export interface CreateKeyOptions {
  /**
   * Policy template ID (e.g. 'daily-cap', 'allowlist').
   * Mutually exclusive with `policy`.
   */
  template?: string;

  /**
   * Parameters for the selected template.
   */
  templateParams?: Record<string, unknown>;

  /**
   * Raw POET v1.1 policy object.
   * Mutually exclusive with `template`.
   */
  policy?: POETPolicy;

  /**
   * Bitcoin network for the key.
   * Mandatory — throws MissingOptionError if undefined.
   */
  network: Network;

  /**
   * Whether this key requires TOTP 2FA for signing.
   * Mandatory — throws MissingOptionError if undefined.
   */
  require2FA: boolean;

  /**
   * Key index for multiple keys per credential pair (default 0 server-side).
   * Throws KeyIndexExistsError with nextAvailableIndex if the index is taken.
   */
  keyIndex?: number;

  /**
   * Client MuSig2 public keys (hex-encoded compressed pubkeys).
   */
  clientKeys?: string[];
}

/**
 * Result returned by createKey().
 */
export interface CreateKeyResult {
  /** Server-assigned unique key identifier. */
  keyId: string;
  /** Policy root hash (hex). */
  policyRoot: string;
  /** Bitcoin network. */
  network: Network;
  /** Server's co-signer public key (if returned by server). */
  serverPubkey?: string;
  /** Whether 2FA is required for this key. */
  require2FA: boolean;
  /** Key index assigned to this key. */
  keyIndex: number;
  /**
   * Taproot-tweaked aggregate public key (x-only, 32 bytes hex).
   * This is the on-chain key controlling the P2TR output.
   * Populated by SigbashWASM_AggregateAndBuildKMC after key creation.
   */
  aggregatePubKeyHex?: string;
  /**
   * Bech32 P2TR address derived from the BIP-328 xpub child 0.
   * Populated by SigbashWASM_AggregateAndBuildKMC after key creation.
   */
  p2trAddress?: string;
  /**
   * BIP-328 xpub derived from the untweaked aggregate internal key.
   * Suitable for tr(xpub/0/*) wallet descriptors.
   * Populated by SigbashWASM_AggregateAndBuildKMC after key creation.
   */
  bip328Xpub?: string;
}

/**
 * Result returned by getKey().
 */
export interface GetKeyResult {
  /** Key identifier. */
  keyId: string;
  /** Policy root hash (hex). */
  policyRoot: string;
  /** Bitcoin network. */
  network: Network;
  /** Whether 2FA is required for this key. */
  require2FA: boolean;
  /** Key index. */
  keyIndex: number;
  /** Decrypted key material container (JSON object). */
  keyMaterial: Record<string, unknown>;
  /** Raw decrypted KMC as JSON string (for passing to WASM). */
  kmcJSON: string;
}

/**
 * Options for the signPSBT() SDK method.
 *
 * The signing pipeline runs entirely inside the Go WASM binary
 * (SigbashWASM_SignPSBTBlind) which communicates with the server on the
 * /api/v2/musig2 Socket.IO namespace.  The SDK wires up the socket before
 * invoking WASM and tears it down on completion.
 */
export interface SignPSBTOptions {
  /** Key identifier to use for signing. */
  keyId: string;
  /** Base64-encoded PSBT. */
  psbtBase64: string;
  /** Hex-encoded PSBT (alternative to psbtBase64). */
  psbtHex?: string;
  /**
   * Decrypted KMC as a JSON string — as returned by getKey().kmcJSON.
   * Required: the WASM needs the full key material container to perform
   * blind MuSig2 signing.
   */
  kmcJSON: string;
  /**
   * PSBT input index to sign (0-based).
   * Defaults to 0 (first input) when omitted.
   */
  inputIndex?: number;
  /**
   * Bitcoin network — must match the network stored in the KMC.
   * Defaults to 'signet' when omitted.
   */
  network?: Network;
  /**
   * Optional progress callback invoked by the WASM during signing.
   * Receives (step: string, message: string) pairs.
   */
  progressCallback?: (step: string, message: string) => void;
  /** TOTP code — required if the key has require2FA: true. */
  totpCode?: string;
  /**
   * Whether this key requires TOTP 2FA. If true and totpCode is absent, a
   * TOTPRequiredError is thrown before the network call.
   */
  require2FA?: boolean;
}

/**
 * Result returned by signPSBT().
 *
 * Fields are populated from the Go WASM result object returned by
 * SigbashWASM_SignPSBTBlind.  The Go binary uses snake_case keys;
 * the SDK maps them to camelCase here.
 */
export interface SignPSBTResult {
  /** Whether signing completed successfully. */
  success: boolean;
  /** Fully signed transaction as hex (ready to broadcast). */
  txHex?: string;
  /** Signed PSBT in base64 (for multi-party workflows). */
  signedPSBT?: string;
  /** Policy path ID of the satisfied clause (hex). */
  pathId?: string;
  /** Human-readable description of the satisfied POET policy clause. */
  satisfiedClause?: string;
  /** Policy root hash from the KMC (hex). */
  policyRootHex?: string;
  /** Error message if signing failed. */
  error?: string;
}

/**
 * Per-input nullifier availability status.
 */
export interface NullifierCheckResult {
  /** PSBT input index. */
  inputIndex: number;
  /** Whether the nullifier is available (not exhausted). */
  available: boolean;
  /** Human-readable status message. */
  message: string;
}

/**
 * Options for the verifyPSBT() SDK method.
 */
export interface VerifyPSBTOptions {
  /** Base64-encoded PSBT to verify. */
  psbtBase64: string;
  /** Decrypted KMC as a JSON string (from getKey().kmcJSON). */
  kmcJSON: string;
  /** Bitcoin network. */
  network: Network;
  /** Optional progress callback invoked during WASM evaluation. */
  progressCallback?: (step: string, message: string) => void;
}

/**
 * Result returned by verifyPSBT().
 *
 * This is a dry-run — no signing occurs and no nullifier is consumed.
 */
export interface VerifyPSBTResult {
  /** Whether the PSBT passes all policy + nullifier checks. */
  passed: boolean;
  /** Policy path ID that would be satisfied. */
  pathID: string;
  /** Human-readable description of the satisfied clause. */
  satisfiedClause: string;
  /** Per-input nullifier availability. */
  nullifierStatus: NullifierCheckResult[];
  /** Error message if the check failed. */
  error?: string;
}

// ---------------------------------------------------------------------------
// Error codes (legacy enum — new errors use string codes in SigbashSDKError)
// ---------------------------------------------------------------------------

/**
 * SDK error codes.
 *
 * @deprecated New errors extend {@link SigbashSDKError} and use string codes directly.
 */
export enum ErrorCode {
  INVALID_POLICY = 'INVALID_POLICY',
  AUTH_FAILED = 'AUTH_FAILED',
  NETWORK_MISMATCH = 'NETWORK_MISMATCH',
  INSUFFICIENT_FUNDS = 'INSUFFICIENT_FUNDS',
  POLICY_VIOLATION = 'POLICY_VIOLATION',
  WASM_NOT_LOADED = 'WASM_NOT_LOADED',
  INVALID_PARAMETERS = 'INVALID_PARAMETERS',
  ENCRYPTION_FAILED = 'ENCRYPTION_FAILED',
  DECRYPTION_FAILED = 'DECRYPTION_FAILED',
  SERVER_ERROR = 'SERVER_ERROR',
  TIMEOUT = 'TIMEOUT',
  UNKNOWN = 'UNKNOWN',
}

/** Policy validation issue */
export interface PolicyIssue {
  path: string;
  code: string;
  message: string;
}

// ---------------------------------------------------------------------------
// Account recovery types
// ---------------------------------------------------------------------------

/**
 * A recovery kit exported from exportRecoveryKit().
 *
 * Contains the pre-derived userRecoveryKEK so that the KMC can be decrypted
 * even if userSecretKey is later lost (the KEK is already computed here).
 *
 * Security note: treat `recoveryKEK` like a private key.  Anyone who holds
 * this value and has access to the server's enc_kek2 for the matching keyId
 * can decrypt the key material container.  Store offline, encrypted, or in a
 * hardware-backed secret store.
 */
export interface SdkRecoveryKit {
  /** Always 'sdk-recovery-v1'. Used to reject kits from incompatible versions. */
  version: 'sdk-recovery-v1';
  /** Server-assigned key identifier. */
  keyId: string;
  /**
   * Hex-encoded pre-derived userRecoveryKEK.
   * HKDF-SHA256(apiKey ∥ userKey ∥ userSecretKey,
   *             salt='sigbash-kmc-v1-user-recovery', info='kmc-encryption-recovery').
   */
  recoveryKEK: string;
  /**
   * Hex-encoded ciphertext of the CEK wrapped under recoveryKEK (AES-256-GCM).
   * Snapshot of enc_kek2.ciphertext at export time.
   * The server copy is preferred during recoverFromKit(); this is a fallback
   * for offline or air-gapped recovery.
   */
  cekCiphertext: string;
  /**
   * Hex-encoded AES-GCM nonce used when wrapping the CEK under recoveryKEK.
   * Snapshot of enc_kek2.nonce at export time.
   */
  cekNonce: string;
  /** Bitcoin network this key belongs to. */
  network: string;
  /** Unix timestamp (seconds) when this kit was generated. */
  createdAt: number;
}
