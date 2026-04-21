/**
 * SigbashClient — Main SDK client class.
 *
 * Credential triplet auth model:
 *   apiKey        — org-level key (admin holds)
 *   userKey       — user identifier (admin holds)
 *   userSecretKey — user-only secret (never shared with admin/server)
 *
 *   authHash  = DSHA256(apiKey || userKey)
 *   apikeyHash = DSHA256(apiKey || apiKey)   — org-scoped identifier
 *   KEK       = HKDF(apiKey || userKey || userSecretKey, ...)
 *
 * Admin can compute authHash and apikeyHash, but cannot derive KEK
 * without userSecretKey — so KMCs remain opaque to the server/admin.
 */

import type {
  SigbashClientOptions,
  CreateKeyOptions,
  CreateKeyResult,
  GetKeyResult,
  SignPSBTOptions,
  SignPSBTResult,
  VerifyPSBTOptions,
  VerifyPSBTResult,
  POETPolicy,
  SdkRecoveryKit,
} from './types';

import {
  AdminError,
  KeyIndexExistsError,
  PolicyCompileError,
  MissingOptionError,
  NetworkError,
  ServerError,
  SigbashSDKError,
  TOTPInvalidError,
  TOTPRequiredError,
  TOTPSetupIncompleteError,
} from './errors';

import { generateTOTPSecret, buildTOTPUri } from './totp';

import { doubleSha256 } from './auth';
import {
  deriveUserRecoveryKEK,
  buildKMCEnvelope,
  decryptKMCEnvelope,
  decryptKMCFromRecoveryKEK,
  derivePolicySalt,
  parseEncKek2,
} from './crypto';
import type { KMCEnvelope, WrappedKey } from './crypto';
import { buildPolicyFromTemplate } from './templates';
import { SigbashSocket } from './socket';
import { getProveWorkerManager } from './prove-worker-manager';

// ---------------------------------------------------------------------------
// Internal types for server responses
// ---------------------------------------------------------------------------

interface RegisterKeyResponse {
  success: boolean;
  key_id: string;
}

interface GetKMCResponse {
  success: boolean;
  encrypted_key_material: string;   // KMC envelope JSON string (new format)
  enc_kek2: string;
  client_key_commitment_h1: string;
  client_key_hash: string;
  policy_root: string;
  network: string;
  require_2fa: boolean;
  key_index?: number;
}

// WasmSignResult is the JS object shape returned by SigbashWASM_SignPSBTBlind.
// Go uses snake_case keys.
interface WasmSignResult {
  success?: boolean;
  signed_tx_hex?: string;
  signed_psbt_base64?: string;
  policy_root_hex?: string;
  path_id?: string;
  satisfied_clause?: string;
  error?: string;
}

// WASM verify result shape as returned by Go WASM export
interface WasmVerifyResult {
  success?: boolean;
  passed?: boolean;
  pathID?: string;
  satisfiedClause?: string;
  nullifierStatus?: Array<{
    inputIndex: number;
    available: boolean;
    message: string;
  }>;
  error?: string;
}

// ---------------------------------------------------------------------------
// Policy normalisation helpers
// ---------------------------------------------------------------------------

const BOOLEAN_DERIVED_CONDITIONS = new Set([
  'DERIVED_IS_CONSOLIDATION',
  'DERIVED_IS_COINJOIN_LIKE',
  'DERIVED_IS_PAYJOIN_LIKE',
  'DERIVED_RBF_ENABLED',
  'DERIVED_NO_NEW_OUTPUTS',
]);

// Conditions that require a selector — default to 'ANY' when omitted,
// mirroring the web UI's default dropdown value.
const SELECTOR_REQUIRED_CONDITIONS = new Set([
  'INPUT_VALUE',
  'INPUT_SEQUENCE',
  'INPUT_SCRIPT_TYPE',
  'INPUT_SIGHASH_TYPE',
  'OUTPUT_VALUE',
  'OUTPUT_SCRIPT_TYPE',
]);

const SIGHASH_TYPE_MAP: Record<string, number> = {
  'SIGHASH_ALL':               0x01,
  'SIGHASH_NONE':              0x02,
  'SIGHASH_SINGLE':            0x03,
  'SIGHASH_ANYONECANPAY_ALL':  0x81,
  'SIGHASH_ANYONECANPAY_NONE': 0x82,
  'SIGHASH_ANYONECANPAY_SINGLE': 0x83,
};

const SCRIPT_TYPE_MAP: Record<string, number> = {
  'P2PKH':     0x00,
  'P2SH':      0x01,
  'P2WPKH':    0x02,
  'P2WSH':     0x03,
  'P2TR':      0x04,
  'OP_RETURN': 0x06,
  'UNKNOWN':   0xFF,
};

/**
 * Walk a POET policy tree and normalise conditionParams so that SDK callers can
 * use intuitive string/boolean values and have them converted to the numeric
 * forms the WASM constraint evaluator requires.
 *
 * Conversions performed (matching condition-modal.js convertEnumParametersToNumeric):
 *
 * 1. Boolean-derived conditions — `expected_value: boolean` → `{ operator: 'EQ', value: 0|1 }`
 * 2. INPUT_SIGHASH_TYPE — `sighash_type: string` → `{ min, max }` numeric
 * 3. INPUT_SCRIPT_TYPE / OUTPUT_SCRIPT_TYPE — `script_type: string` → `{ min, max }` numeric
 * 4. Default selector — adds `selector: 'ANY'` for SELECTOR_REQUIRED conditions when absent
 */
function normalisePolicy(node: unknown): unknown {
  if (!node || typeof node !== 'object') return node;
  const n = node as Record<string, unknown>;

  if (n['type'] === 'condition') {
    const ct = n['conditionType'] as string | undefined;
    const cp = n['conditionParams'];
    if (ct && cp && typeof cp === 'object') {
      const params = cp as Record<string, unknown>;

      // 1. Boolean-derived conditions: expected_value boolean → operator/value integer
      if (BOOLEAN_DERIVED_CONDITIONS.has(ct) && 'expected_value' in params) {
        const ev = params['expected_value'];
        if (!('operator' in params)) params['operator'] = 'EQ';
        params['value'] = (ev === true || ev === 1 || ev === '1') ? 1 : 0;
        delete params['expected_value'];
      }

      // 2. INPUT_SIGHASH_TYPE: sighash_type string → min/max numeric
      if (ct === 'INPUT_SIGHASH_TYPE' && typeof params['sighash_type'] === 'string') {
        const enumValue = SIGHASH_TYPE_MAP[params['sighash_type'] as string];
        if (enumValue !== undefined) {
          params['min'] = enumValue;
          params['max'] = enumValue;
        }
        delete params['sighash_type'];
      }

      // 3. INPUT_SCRIPT_TYPE / OUTPUT_SCRIPT_TYPE: script_type string → min/max numeric
      if ((ct === 'INPUT_SCRIPT_TYPE' || ct === 'OUTPUT_SCRIPT_TYPE') &&
          typeof params['script_type'] === 'string') {
        const enumValue = SCRIPT_TYPE_MAP[params['script_type'] as string];
        if (enumValue !== undefined) {
          params['min'] = enumValue;
          params['max'] = enumValue;
        }
        delete params['script_type'];
      }

      // 4. Default selector for SELECTOR_REQUIRED conditions when absent
      if (SELECTOR_REQUIRED_CONDITIONS.has(ct) && !params['selector']) {
        params['selector'] = 'ANY';
      }

      // 5. Reject empty address lists for set-membership conditions — but only
      // when no descriptor template is configured.  When use_descriptor is true
      // the addresses are derived from the descriptor at key-request time, so an
      // empty explicit list is expected and valid.
      if (ct === 'INPUT_SOURCE_IS_IN_SETS' || ct === 'OUTPUT_DEST_IS_IN_SETS') {
        const addrs = params['addresses'];
        const hasDescriptor = params['use_descriptor'] === true && params['descriptor_template'];
        if (Array.isArray(addrs) && addrs.length === 0 && !hasDescriptor) {
          throw new PolicyCompileError(
            `${ct} requires at least one address — empty address list is not permitted (or set use_descriptor with a descriptor_template)`
          );
        }
      }
    }
  }

  if (Array.isArray(n['children'])) {
    n['children'] = (n['children'] as unknown[]).map(normalisePolicy);
  }
  return n;
}


// ---------------------------------------------------------------------------
// SigbashClient
// ---------------------------------------------------------------------------

/**
 * Main SDK client for the Sigbash oblivious signing platform.
 *
 * @example
 * ```typescript
 * const client = new SigbashClient({
 *   apiKey: 'org-api-key',
 *   userKey: 'user-key',
 *   userSecretKey: SigbashClient.generateUserSecretKey(),
 *   serverUrl: 'https://www.sigbash.com',
 * });
 *
 * const key = await client.createKey({
 *   template: 'daily-cap',
 *   templateParams: { dailyLimitSats: 1_000_000 },
 *   network: 'signet',
 *   require2FA: false,
 * });
 * ```
 */
export class SigbashClient {
  private readonly _apiKey: string;
  private readonly _userKey: string;
  private readonly _userSecretKey: string;
  private readonly _serverUrl: string;

  /**
   * Promise resolving to the user's auth hash: DSHA256(apiKey || userKey).
   * Computed eagerly in the constructor; all methods await it before use.
   */
  private readonly _authHash: Promise<string>;

  /**
   * Promise resolving to the org-level hash: DSHA256(apiKey || apiKey).
   * Used as apikey_hash in server payloads to scope the org without exposing the raw key.
   */
  private readonly _apikeyHash: Promise<string>;

  private _socket: SigbashSocket | null = null;

  /**
   * Dedicated Socket.IO connection to /api/v2/musig2.
   * Lazily created on first signPSBT() call.  Go WASM reads
   * globalThis.sharedMusigSocket to use this connection for blind MuSig2.
   */
  private _musig2Socket: SigbashSocket | null = null;

  // MuSig2 client key material (native JS private fields — inaccessible at runtime)
  #musig2PrivateKey: Uint8Array = new Uint8Array(32);
  #commitmentH1: string = '';
  #keyHash: string = '';
  #disposed = false;

  constructor(options: SigbashClientOptions) {
    if (!options.apiKey) throw new MissingOptionError('apiKey');
    if (!options.userKey) throw new MissingOptionError('userKey');
    // Explicit length check: empty string passes the falsy guard but breaks the
    // security property — HKDF IKM would then equal HKDF(apiKey || userKey),
    // which the admin can compute without userSecretKey.
    if (!options.userSecretKey || options.userSecretKey.length === 0) {
      throw new MissingOptionError('userSecretKey');
    }
    if (!options.serverUrl) throw new MissingOptionError('serverUrl');

    this._apiKey = options.apiKey;
    this._userKey = options.userKey;
    this._userSecretKey = options.userSecretKey;
    this._serverUrl = options.serverUrl;

    // Kick off async hash computations immediately
    this._authHash = doubleSha256(this._apiKey, this._userKey);
    this._apikeyHash = doubleSha256(this._apiKey, this._apiKey);

    // Eagerly initialize the Socket.IO connection
    this._socket = new SigbashSocket(this._serverUrl);

    // BYO key path: validate immediately via WASM and pre-compute commitments
    const raw = options.musig2PrivateKey;
    if (raw !== undefined && raw !== null) {
      if (typeof raw === 'string') {
        if (typeof process !== 'undefined' && process.env?.NODE_ENV !== 'production') {
          console.warn(
            '[SigbashClient] musig2PrivateKey supplied as string — ' +
              'string values cannot be securely wiped. Prefer Uint8Array.'
          );
        }
      }
      const privHex =
        typeof raw === 'string'
          ? raw
          : Array.from(raw)
              .map(b => b.toString(16).padStart(2, '0'))
              .join('');

      const wasmFn = (globalThis as Record<string, unknown>)[
        'SigbashWASM_GenerateClientKeyMaterial'
      ] as ((input: string) => string) | undefined;
      if (typeof wasmFn !== 'function') {
        throw new SigbashSDKError(
          'WASM not loaded — call loadWasm() before constructing SigbashClient with a BYO musig2PrivateKey',
          'WASM_NOT_LOADED'
        );
      }

      const kmResult = JSON.parse(wasmFn(JSON.stringify({ private_key_hex: privHex }))) as {
        private_key_hex?: string;
        public_key_hex?: string;
        xonly_pubkey_hex?: string;
        h1_hex?: string;
        key_hash_hex?: string;
        error?: string;
      };

      if (kmResult.error) {
        throw new SigbashSDKError(`Invalid musig2PrivateKey: ${kmResult.error}`, 'INVALID_PRIVATE_KEY');
      }

      const fromHex = (s: string) => Uint8Array.from(s.match(/.{2}/g)!.map(b => parseInt(b, 16)));
      this.#musig2PrivateKey = fromHex(kmResult.private_key_hex!);
      this.#commitmentH1 = kmResult.h1_hex!;
      this.#keyHash = kmResult.key_hash_hex!;
    }
    // else: fields stay zeroed; populated by createKey() (auto-gen → 'api') or getKey()
  }

  // -------------------------------------------------------------------------
  // Static generators
  // -------------------------------------------------------------------------

  /**
   * Generate a random 32-byte hex string suitable for use as a userKey.
   */
  static generateUserKey(): string {
    return Array.from(crypto.getRandomValues(new Uint8Array(32)))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Generate a random 32-byte hex string suitable for use as a userSecretKey.
   * Uses the same entropy source as generateUserKey() but fulfils a different role.
   */
  static generateUserSecretKey(): string {
    return SigbashClient.generateUserKey();
  }

  // -------------------------------------------------------------------------
  // Admin methods
  // -------------------------------------------------------------------------

  /**
   * Pre-register a new user within the caller's organisation.
   *
   * Only an admin can call this. The server auto-promotes the first user in an
   * org to admin; subsequent users must be explicitly registered by an existing admin.
   *
   * @throws AdminError if the caller is not an admin
   */
  async registerUser(userKey: string): Promise<void> {
    const callerAuthHash = await this._authHash;
    const newUserAuthHash = await doubleSha256(this._apiKey, userKey);

    const response = await fetch(
      `${this._serverUrl.replace(/\/$/, '')}/api/v2/sdk/admin/users`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          auth_hash: callerAuthHash,
          new_user_auth_hash: newUserAuthHash,
        }),
      }
    );

    const data = (await response.json()) as { success?: boolean; code?: string; message?: string };

    if (!response.ok || data.success !== true) {
      const code = data.code ?? '';
      if (code === 'FORBIDDEN' || code === 'UNAUTHORIZED' || response.status === 403) {
        throw new AdminError(data.message ?? 'Admin access required');
      }
      throw new SigbashSDKError(
        data.message ?? `registerUser failed (HTTP ${response.status})`,
        code || 'SERVER_ERROR'
      );
    }
  }

  /**
   * Revoke a user's access within the caller's organisation.
   *
   * Only an admin can call this.
   *
   * @throws AdminError if the caller is not an admin
   */
  async revokeUser(userKey: string): Promise<void> {
    const callerAuthHash = await this._authHash;
    const targetAuthHash = await doubleSha256(this._apiKey, userKey);

    const response = await fetch(
      `${this._serverUrl.replace(/\/$/, '')}/api/v2/sdk/admin/users/${targetAuthHash}`,
      {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auth_hash: callerAuthHash }),
      }
    );

    const data = (await response.json()) as { success?: boolean; code?: string; message?: string };

    if (!response.ok || data.success !== true) {
      const code = data.code ?? '';
      if (code === 'FORBIDDEN' || code === 'UNAUTHORIZED' || response.status === 403) {
        throw new AdminError(data.message ?? 'Admin access required');
      }
      throw new SigbashSDKError(
        data.message ?? `revokeUser failed (HTTP ${response.status})`,
        code || 'SERVER_ERROR'
      );
    }
  }

  // -------------------------------------------------------------------------
  // Core methods
  // -------------------------------------------------------------------------

  /**
   * Create a new policy-bound key and register it with the server.
   *
   * Exactly one of `options.template`/`options.templateParams` or `options.policy`
   * must be provided. Both `require2FA` and `network` are mandatory.
   *
   * @throws MissingOptionError if require2FA or network is undefined
   * @throws KeyIndexExistsError if the requested keyIndex is already in use
   * @throws NetworkError if the network is not enabled on the server
   */
  async createKey(options: CreateKeyOptions): Promise<CreateKeyResult> {
    if (this.#disposed) {
      throw new SigbashSDKError('SigbashClient has been disposed', 'CLIENT_DISPOSED');
    }

    // Mandatory field validation — must throw before any network call
    if ((options as Partial<CreateKeyOptions>).require2FA === undefined) {
      throw new MissingOptionError('require2FA');
    }
    if ((options as Partial<CreateKeyOptions>).network === undefined) {
      throw new MissingOptionError('network');
    }

    // Policy validation: exactly one of template or policy
    const hasTemplate = options.template !== undefined;
    const hasPolicy = options.policy !== undefined;
    if (!hasTemplate && !hasPolicy) {
      throw new SigbashSDKError(
        "createKey requires either 'template' or 'policy'",
        'MISSING_POLICY'
      );
    }
    if (hasTemplate && hasPolicy) {
      throw new SigbashSDKError(
        "createKey requires exactly one of 'template' or 'policy', not both",
        'AMBIGUOUS_POLICY'
      );
    }

    // Build POET policy
    let poetPolicy: POETPolicy;
    if (hasTemplate) {
      poetPolicy = buildPolicyFromTemplate(
        options.template as string,
        (options.templateParams ?? {}) as Record<string, unknown>
      );
    } else {
      poetPolicy = options.policy as POETPolicy;
    }

    // Normalise conditionParams — convert string enums, booleans, and selectors
    // to the numeric/object forms the WASM constraint evaluator requires.
    normalisePolicy(poetPolicy?.policy);

    // ---------------------------------------------------------------------------
    // Step 1 — Ensure client MuSig2 keypair is initialised.
    // For the auto-gen path (no BYO key) call SigbashWASM_GenerateClientKeyMaterial
    // to produce a fresh random key and compute commitment fields.
    // ---------------------------------------------------------------------------
    if (this.#commitmentH1 === '') {
      const wasmKeyFn = (globalThis as Record<string, unknown>)[
        'SigbashWASM_GenerateClientKeyMaterial'
      ] as ((input: string) => string) | undefined;
      if (typeof wasmKeyFn !== 'function') {
        throw new SigbashSDKError(
          'WASM not loaded — call loadWasm() before createKey()',
          'WASM_NOT_LOADED'
        );
      }
      const kmResult = JSON.parse(wasmKeyFn('{}')) as {
        private_key_hex?: string;
        public_key_hex?: string;
        xonly_pubkey_hex?: string;
        h1_hex?: string;
        key_hash_hex?: string;
        error?: string;
      };
      if (kmResult.error) {
        throw new SigbashSDKError(`Key generation failed: ${kmResult.error}`, 'KEY_GEN_FAILED');
      }
      const fromHex = (s: string) => Uint8Array.from(s.match(/.{2}/g)!.map(b => parseInt(b, 16)));
      this.#musig2PrivateKey = fromHex(kmResult.private_key_hex!);
      this.#commitmentH1 = kmResult.h1_hex!;
      this.#keyHash = kmResult.key_hash_hex!;
    }

    const authHash = await this._authHash;
    const apikeyHash = await this._apikeyHash;

    const privateKeyHex = Array.from(this.#musig2PrivateKey)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // ---------------------------------------------------------------------------
    // Step 2 — Fetch the server's partial public key via submit_key_request.
    // This mirrors the web frontend's startKeyRequest → processKeyResponse flow.
    // The musig2 socket is established here and kept for subsequent signPSBT calls.
    //
    // NOTE: The server emits 'key_request_response' (not 'submit_key_request_response'),
    // so we must listen on the raw socket directly rather than using the generic
    // request() helper which auto-generates '{event}_response' from the event name.
    // ---------------------------------------------------------------------------
    const musig2Socket = this._requireMusig2Socket();

    // Expose the socket on globalThis so Go WASM can reach it during signing.
    (globalThis as Record<string, unknown>)['sharedMusigSocket'] = musig2Socket.rawSocket;

    interface KeyRequestResponse {
      success?: boolean;
      data?: {
        partial_pub_key?: unknown;
        credential_id?: string;
        network?: string;
      };
      message?: string;
    }

    let keyRequestResp: KeyRequestResponse;
    try {
      keyRequestResp = await new Promise<KeyRequestResponse>((resolve, reject) => {
        const rawSocket = musig2Socket.rawSocket;
        const TIMEOUT_MS = 30_000;

        const onResponse = (payload: KeyRequestResponse): void => {
          clearTimeout(timer);
          rawSocket.off('key_request_response', onResponse);
          resolve(payload);
        };

        const timer = setTimeout(() => {
          rawSocket.off('key_request_response', onResponse);
          reject(new Error(`submit_key_request timed out after ${TIMEOUT_MS}ms`));
        }, TIMEOUT_MS);

        rawSocket.once('key_request_response', onResponse);
        rawSocket.emit('submit_key_request', {
          credential_id: authHash,
          credential_type: 'api',
          network: options.network,
        });
      });
    } catch (err) {
      throw new SigbashSDKError(
        `submit_key_request failed: ${String(err)}`,
        'SERVER_ERROR'
      );
    }

    if (!keyRequestResp?.data?.partial_pub_key) {
      const serverMsg = keyRequestResp?.message ? `: ${keyRequestResp.message}` : '';
      throw new SigbashSDKError(
        `submit_key_request: server response missing partial_pub_key${serverMsg}`,
        'SERVER_ERROR'
      );
    }

    // The partial_pub_key is a JSON array of PartialKey objects (candidate_key + id).
    // Serialise it to a JSON string for the WASM aggregation function.
    const serverPartialPubKeyJSON = JSON.stringify(keyRequestResp.data.partial_pub_key);

    // ---------------------------------------------------------------------------
    // Step 3 — Compile the POET policy via Go WASM (same as the web frontend).
    // Ensures POET validation errors surface here and that the policy_root stored
    // on the server is identical regardless of credential type.
    // ---------------------------------------------------------------------------
    const compileFn = (globalThis as Record<string, unknown>)[
      'SigbashWASM_CompilePOETPolicy'
    ] as ((input: string) => string) | undefined;
    if (typeof compileFn !== 'function') {
      throw new SigbashSDKError(
        'WASM not loaded — call loadWasm() before createKey()',
        'WASM_NOT_LOADED'
      );
    }

    // Derive a deterministic 32-byte seed for the WASM SeedManager.
    // HKDF(apiKey || userKey || userSecretKey, salt='sigbash-policy-salt-v1',
    //      info='poet-policy-compilation-salt') — stable per credential triplet.
    const seedHex = await derivePolicySalt(this._apiKey, this._userKey, this._userSecretKey);

    const compileResult = JSON.parse(
      compileFn(JSON.stringify({
        policy: JSON.stringify(poetPolicy),
        network: options.network,
        seed_hex: seedHex,
      }))
    ) as { policy_root?: string; compiled_policy_json?: string; error?: string };

    if (compileResult.error) {
      throw new PolicyCompileError(compileResult.error);
    }

    let policyRoot = compileResult.policy_root!;
    // Use the processed policy JSON produced by the Go compiler (nullifier configs
    // and address data have been extracted and normalised).
    const compiledPolicyJSON = compileResult.compiled_policy_json ?? JSON.stringify(poetPolicy);

    // ---------------------------------------------------------------------------
    // Step 4 — Aggregate keys and build the full KMC via Go WASM.
    // SigbashWASM_AggregateAndBuildKMC calls the same internal Go functions as
    // processKeyResponse in key_request.go: it derives server participant keys from
    // the descriptor, combines them with the client key, computes the Taproot-tweaked
    // aggregate key, BIP-328 xpub, P2TR address, and populates PolicyCommitment
    // (including TseitinCNF) so that SignPSBTBlind_WASM can consume the KMC.
    // ---------------------------------------------------------------------------
    const aggregateFn = (globalThis as Record<string, unknown>)[
      'SigbashWASM_AggregateAndBuildKMC'
    ] as ((input: string) => string) | undefined;
    if (typeof aggregateFn !== 'function') {
      throw new SigbashSDKError(
        'SigbashWASM_AggregateAndBuildKMC is not available. Ensure the WASM binary is up to date.',
        'WASM_NOT_LOADED'
      );
    }

    const aggregateResult = JSON.parse(
      aggregateFn(JSON.stringify({
        client_private_key_hex: privateKeyHex,
        server_partial_pub_key_json: serverPartialPubKeyJSON,
        compiled_policy_json: compiledPolicyJSON,
        policy_root_hex: policyRoot,
        network: options.network,
        seed_hex: seedHex,
        credential_id: authHash,
        key_index: options.keyIndex ?? 0,
      }))
    ) as {
      kmc_json?: string;
      aggregate_public_key_hex?: string;
      internal_public_key_hex?: string;
      p2tr_address?: string;
      bip328_xpub?: string;
      client_key_commitment_h1?: string;
      client_key_hash?: string;
      policy_root_hex?: string;
      error?: string;
    };

    if (aggregateResult.error) {
      throw new SigbashSDKError(
        `Key aggregation failed: ${aggregateResult.error}`,
        'KEY_AGG_FAILED'
      );
    }

    const kmcJSON = aggregateResult.kmc_json!;
    const kmc = JSON.parse(kmcJSON) as object;

    // Sync policy root — descriptor-mode conditions (ISIS/DNNO) rebuild PathLeafs
    // after the BIP-328 xpub is available, which recomputes the PolicyRoot.  The
    // post-rebuild root must be used for server registration and all subsequent ops.
    if (aggregateResult.policy_root_hex) {
      policyRoot = aggregateResult.policy_root_hex;
    }

    // Update in-memory commitment fields with the WASM-computed values (these are
    // derived from the client participant stored in the KMC, so they agree with Step 1,
    // but we sync them here for correctness in subsequent signPSBT calls).
    if (aggregateResult.client_key_commitment_h1) {
      this.#commitmentH1 = aggregateResult.client_key_commitment_h1;
    }
    if (aggregateResult.client_key_hash) {
      this.#keyHash = aggregateResult.client_key_hash;
    }

    // ---------------------------------------------------------------------------
    // Step 5 — Encrypt the Go-produced KMC into a KMCEnvelope.
    // buildKMCEnvelope accepts an arbitrary JS object — kmc is parsed from the JSON
    // string returned by WASM and passed in directly.
    // ---------------------------------------------------------------------------
    const userRecoveryKEK = await deriveUserRecoveryKEK(
      this._apiKey,
      this._userKey,
      this._userSecretKey
    );
    const { envelope, enc_kek2 } = await buildKMCEnvelope(kmc, {
      apiKey: this._apiKey,
      userKey: this._userKey,
      userSecretKey: this._userSecretKey,
      userRecoveryKEK,
      authHash,
      network: options.network,
    });

    // ---------------------------------------------------------------------------
    // Step 6 — Register the key with the server on /api/v2/sdk.
    // client_keys carries the Taproot-tweaked aggregate public key hex so that
    // the MuSig2 signing pipeline can identify this key during blind_signing_request.
    // ---------------------------------------------------------------------------
    const socket = this._requireSocket();

    let response: RegisterKeyResponse;
    try {
      response = await socket.request<RegisterKeyResponse>('register_key_with_hash', {
        auth_hash: authHash,
        apikey_hash: apikeyHash,
        encrypted_key_material: JSON.stringify(envelope),
        policy_root: policyRoot,
        network: options.network,
        client_keys: [aggregateResult.aggregate_public_key_hex ?? ''],
        key_index: options.keyIndex ?? 0,
        require_2fa: options.require2FA,
        client_key_commitment_h1: this.#commitmentH1,
        client_key_hash: this.#keyHash,
        enc_kek2,
      });
    } catch (err) {
      // Map well-known server error codes
      if (err instanceof Error) {
        const details = (err as { details?: { code?: string; nextAvailableIndex?: number } }).details;
        const code = details?.code;
        if (code === 'KEY_INDEX_EXISTS') {
          const requested = options.keyIndex ?? 0;
          throw new KeyIndexExistsError(requested, details?.nextAvailableIndex ?? requested + 1);
        }
        if (code === 'NETWORK_NOT_ENABLED' || code === 'INVALID_NETWORK') {
          throw new NetworkError((err as Error).message);
        }
      }
      throw err;
    }

    return {
      keyId: response.key_id,
      policyRoot,
      network: options.network,
      require2FA: options.require2FA,
      keyIndex: options.keyIndex ?? 0,
      p2trAddress: aggregateResult.p2tr_address,
      aggregatePubKeyHex: aggregateResult.aggregate_public_key_hex,
      bip328Xpub: aggregateResult.bip328_xpub,
    };
  }

  /**
   * Retrieve and decrypt a key's material container from the server.
   *
   * @param keyId - The key identifier returned by createKey()
   * @param opts.keyIndex - Optional key index (default 0)
   */
  async getKey(
    keyId: string,
    opts?: { keyIndex?: number }
  ): Promise<GetKeyResult> {
    if (this.#disposed) {
      throw new SigbashSDKError('SigbashClient has been disposed', 'CLIENT_DISPOSED');
    }

    const authHash = await this._authHash;
    const socket = this._requireSocket();

    const response = await socket.request<GetKMCResponse>('get_encrypted_kmc', {
      auth_hash: authHash,
      key_id: keyId,
      key_index: opts?.keyIndex ?? 0,
    });

    if (!response.encrypted_key_material) {
      throw new SigbashSDKError('No encrypted_key_material in server response', 'NO_KEY_MATERIAL');
    }

    // enc_kek2 is server-stored for admin recovery; the SDK does not use it to
    // decrypt the KMC (decryption uses the credential-triplet KEK via the auth
    // slot in the envelope).  However, we validate the version tag here so that
    // a WebAuthn-path blob (version 'webauthn-v1') cannot silently be returned
    // to an SDK api-credential caller — it would fail cryptographically anyway,
    // but an explicit version check surfaces the mismatch immediately.
    if (response.enc_kek2) {
      parseEncKek2(response.enc_kek2); // throws SigbashSDKError with code ENC_KEK2_VERSION_MISMATCH if wrong type
    }

    const envelope = JSON.parse(response.encrypted_key_material) as KMCEnvelope;
    const kmc = await decryptKMCEnvelope(envelope, this._apiKey, this._userKey, this._userSecretKey);
    const kmcJSON = JSON.stringify(kmc);

    // Restore #musig2PrivateKey from the decrypted KMC participants array.
    // This enables: new SigbashClient(opts) → getKey(id) → signPSBT(...)
    // across sessions without re-supplying the BYO key.
    if (this.#commitmentH1 === '') {
      const participants = (kmc as { participants?: Array<{ source: string; key?: string; private_key_hex?: string }> }).participants;
      const clientParticipant = participants?.find(p => p.source === 'client');
      if (clientParticipant?.private_key_hex) {
        const wasmFn = (globalThis as Record<string, unknown>)[
          'SigbashWASM_GenerateClientKeyMaterial'
        ] as ((input: string) => string) | undefined;
        if (typeof wasmFn === 'function') {
          const kmResult = JSON.parse(
            wasmFn(JSON.stringify({ private_key_hex: clientParticipant.private_key_hex }))
          ) as {
            private_key_hex?: string;
            public_key_hex?: string;
            h1_hex?: string;
            key_hash_hex?: string;
            error?: string;
          };
          if (kmResult.error) {
            throw new SigbashSDKError(
              `Failed to restore MuSig2 key from KMC: ${kmResult.error}`,
              'KEY_RESTORE_FAILED'
            );
          }
          const fromHex = (s: string) => Uint8Array.from(s.match(/.{2}/g)!.map(b => parseInt(b, 16)));
          this.#musig2PrivateKey = fromHex(kmResult.private_key_hex!);
          this.#commitmentH1 = kmResult.h1_hex!;
          this.#keyHash = kmResult.key_hash_hex!;
        }
      }
    }

    const network = (response.network as GetKeyResult['network']) ?? 'signet';

    return {
      keyId,
      policyRoot: response.policy_root,
      network,
      require2FA: response.require_2fa,
      keyIndex: response.key_index ?? opts?.keyIndex ?? 0,
      keyMaterial: kmc as Record<string, unknown>,
      kmcJSON,
    };
  }

  /**
   * Sign a PSBT using blind MuSig2 with the specified key.
   *
   * The full signing pipeline runs inside the Go WASM binary
   * (SigbashWASM_SignPSBTBlind).  Before calling it, the SDK establishes a
   * Socket.IO connection to /api/v2/musig2 and registers it as
   * globalThis.sharedMusigSocket so the Go code can reach the server.
   *
   * Required options:
   *   - psbtBase64  — the PSBT to sign (base64)
   *   - kmcJSON     — decrypted KMC string from getKey().kmcJSON
   *
   * If the key has `require2FA: true`, `totpCode` is mandatory.
   *
   * @throws SigbashSDKError with code WASM_NOT_LOADED if WASM is not initialised
   * @throws TOTPRequiredError if the key requires TOTP and totpCode is absent
   * @throws TOTPInvalidError if the provided TOTP code is rejected
   */
  async signPSBT(options: SignPSBTOptions): Promise<SignPSBTResult> {
    if (this.#disposed) {
      throw new SigbashSDKError('SigbashClient has been disposed', 'CLIENT_DISPOSED');
    }

    if ((options as SignPSBTOptions & { require2FA?: boolean }).require2FA === true && options.totpCode === undefined) {
      throw new TOTPRequiredError();
    }

    // Validate the WASM function is loaded before doing any network work.
    const wasmFn = (globalThis as Record<string, unknown>)[
      'SigbashWASM_SignPSBTBlind'
    ] as ((
      psbtBase64: string,
      kmcJSON: string,
      inputIndex: number,
      network: string,
      progressCallback: ((step: string, message: string) => void) | null,
      seedHex: string
    ) => Promise<WasmSignResult>) | undefined;

    if (typeof wasmFn !== 'function') {
      throw new SigbashSDKError(
        'SigbashWASM_SignPSBTBlind is not available. ' +
          'Ensure the WASM binary has been loaded via loadWasm() before calling signPSBT().',
        'WASM_NOT_LOADED'
      );
    }

    // The Go WASM signing pipeline (requestServerNonces, requestServerUBPoint,
    // requestServerSignatureCommitmentBased) reads js.Global().Get("sharedMusigSocket")
    // to emit/receive socket events on /api/v2/musig2.  We must set this up
    // before invoking the WASM function.
    const musig2Socket = this._requireMusig2Socket();

    // Register the raw socket.io Socket on globalThis so the Go WASM can find it.
    // Go calls js.Global().Get("sharedMusigSocket") and then .emit() / .on() on it.
    (globalThis as Record<string, unknown>)['sharedMusigSocket'] = musig2Socket.rawSocket;

    // Tell the WASM which namespace to use (idempotent — safe to call repeatedly).
    const setNsFn = (globalThis as Record<string, unknown>)['setSocketNamespace'] as
      | ((ns: string) => void)
      | undefined;
    if (typeof setNsFn === 'function') {
      setNsFn('/api/v2/musig2');
    }

    const psbtBase64 = options.psbtBase64 ?? options.psbtHex ?? '';
    const inputIndex = options.inputIndex ?? 0;
    const network = options.network ?? 'signet';
    const progressCallback = options.progressCallback ?? null;

    // Pre-flight: validate auth + TOTP on the SDK namespace before invoking WASM.
    // The server checks credentials and TOTP here so we can surface typed errors
    // (TOTPRequiredError, TOTPInvalidError, TOTPSetupIncompleteError) before the
    // blind MuSig2 pipeline starts.
    const sdkSocket = this._requireSocket();
    const authHash = await this._authHash;
    try {
      await sdkSocket.request('sign_with_hash_auth', {
        auth_hash: authHash,
        key_id: options.keyId,
        psbt_hex: psbtBase64,
        totp_code: options.totpCode ?? null,
      });
    } catch (err) {
      if (err instanceof ServerError) {
        const serverCode = (err.details as { code?: string } | undefined)?.code;
        if (serverCode === 'TOTP_INVALID') throw new TOTPInvalidError();
        if (serverCode === 'TOTP_SETUP_INCOMPLETE') throw new TOTPSetupIncompleteError();
        if (serverCode === 'TOTP_REQUIRED') throw new TOTPRequiredError();
      }
      throw err;
    }

    // Pre-fetch covenant state so SIGBASH_COVENANT_STATE resolves in SDK context (Option C).
    // This sets globalThis.sigbashPreFetchedCovenantState before WASM runs so the
    // new requestCovenantState implementation can read it synchronously.
    await this._prefetchCovenantState(options.kmcJSON, psbtBase64, authHash);

    // The WASM uses relative URLs (e.g. /api/v2/signing_key) which resolve
    // automatically in a browser but fail in Node.js (no base URL).
    // • Set sigbashBaseUrl so getAPIBaseURL() (proof_bundle_generator_helpers.go)
    //   can construct absolute URLs without touching window.location.
    // • Wrap globalThis.fetch to prepend the server origin for any remaining
    //   relative-path fetch calls.
    // Both are restored in the finally block.
    const serverBase = this._serverUrl.replace(/\/$/, '');
    (globalThis as Record<string, unknown>)['sigbashBaseUrl'] = serverBase;
    const baseFetch = (globalThis as Record<string, unknown>)['fetch'] as typeof fetch;
    (globalThis as Record<string, unknown>)['fetch'] = (
      input: Parameters<typeof fetch>[0],
      init?: Parameters<typeof fetch>[1]
    ) => {
      const isRelative = typeof input === 'string' && input.startsWith('/');
      const url = isRelative ? `${serverBase}${input}` : input;
      if (!isRelative) {
        return baseFetch(url as Parameters<typeof fetch>[0], init);
      }
      // Inject X-Sigbash-Auth so Flask can forward credential_id to Moon for
      // ProofSessionToken tracking (Wagner k=1 invariant). Without this header,
      // the HTTP request carries no session cookie (no browser session in Node.js)
      // and Moon never registers a token for this credential, causing
      // "Session token superseded" on the WebSocket blind signing request.
      const existingHeaders = (init?.headers ?? {}) as Record<string, string>;
      return baseFetch(url as Parameters<typeof fetch>[0], {
        ...init,
        headers: { ...existingHeaders, 'X-Sigbash-Auth': authHash },
      });
    };

    // Derive the policy seed so the WASM can initialize the global SeedManager.
    // The same seed is used in createKey; passing it here ensures signing works
    // in both same-session (after createKey) and cross-session (after getKey) flows.
    const seedHex = await derivePolicySalt(this._apiKey, this._userKey, this._userSecretKey);

    // Ensure prove workers are initialized before checking status.  Without
    // this await, the first signPSBT call in a session may find workers not
    // yet ready and fall back to inline proving (serializing chunk + unified
    // proves instead of running them in parallel on separate workers).
    const workerMgr = getProveWorkerManager();
    await workerMgr.init();
    // Fire-and-forget: tell workers to prefetch circuit binaries in the
    // background while the main thread does nonce exchange + witness build.
    // sigbashBaseUrl is already set (line above), so fetches resolve correctly.
    workerMgr.warmCircuits();
    const workerStatus = workerMgr.getStatus();
    if (workerStatus.ready && workerStatus.workerCount > 0) {
      (globalThis as Record<string, unknown>)['_sigbashProveAsync'] = (
        circuitType: string,
        witnessBytes: Uint8Array,
        paramsJSON: string,
        policyRoot: string,
        sessionBind: string,
        publicInputsJSON: string,
      ) => workerMgr.proveAsync({
        circuitType: circuitType as 'unified' | 'output_chunk' | 'output_chunk_final',
        witnessBytes,
        paramsJSON,
        policyRoot,
        sessionBind,
        publicInputsJSON,
      });

      // T92: Register witness+prove dispatcher so output chunk proves run on
      // workers instead of blocking the main Go WASM thread.  Without this,
      // the chunk prove runs inline and serializes with the unified prove.
      (globalThis as Record<string, unknown>)['_sigbashWitnessAndProveAsync'] = (
        circuitType: string,
        witnessInputsJSON: string,
        paramsJSON: string,
        policyRoot: string,
        sessionBind: string,
        publicInputsJSON: string,
      ) => workerMgr.witnessAndProveAsync({
        circuitType: circuitType as 'output_chunk' | 'output_chunk_final',
        witnessInputsJSON,
        paramsJSON,
        policyRoot,
        sessionBind,
        publicInputsJSON,
      });
    }

    let result: WasmSignResult;
    try {
      result = await wasmFn(psbtBase64, options.kmcJSON, inputIndex, network, progressCallback, seedHex);
    } catch (err) {
      // wasmErrorResult() returns a Go map {error: "msg"} which becomes a JS object.
      // String(obj) gives "[object Object]", so extract the .error property directly.
      let errMsg: string;
      if (err !== null && typeof err === 'object') {
        const o = err as Record<string, unknown>;
        errMsg = typeof o['error'] === 'string' ? o['error']
               : typeof o['message'] === 'string' ? o['message']
               : JSON.stringify(err);
      } else {
        errMsg = String(err);
      }
      // Policy evaluation failures are expected outcomes (the PSBT does not satisfy
      // the policy) — return { success: false } so callers can inspect the result
      // without try/catch. Only hard infrastructure errors (PSBT parse failure,
      // WASM crash, etc.) propagate as exceptions.
      const isSoftPolicyFailure =
        errMsg.includes('policy evaluation failed') ||
        errMsg.includes('Policy not satisfied') ||
        errMsg.includes('nullifier constraint validation failed') ||
        errMsg.includes('max uses exhausted') ||
        errMsg.includes('failed to extract constraints from PathLeaf');
      if (isSoftPolicyFailure) {
        return { success: false, error: errMsg };
      }
      throw new SigbashSDKError(`SigbashWASM_SignPSBTBlind failed: ${errMsg}`, 'WASM_ERROR');
    } finally {
      (globalThis as Record<string, unknown>)['fetch'] = baseFetch;
      delete (globalThis as Record<string, unknown>)['sigbashBaseUrl'];
      delete (globalThis as Record<string, unknown>)['sigbashPreFetchedCovenantState'];
      delete (globalThis as Record<string, unknown>)['_sigbashProveAsync'];
      delete (globalThis as Record<string, unknown>)['_sigbashWitnessAndProveAsync'];
    }

    if (!result.success) {
      // WASM returned success=false without throwing — treat as a soft policy failure.
      return { success: false, error: result.error ?? 'Policy not satisfied' };
    }

    return {
      success: true,
      txHex: result.signed_tx_hex,
      signedPSBT: result.signed_psbt_base64,
      pathId: result.path_id,
      satisfiedClause: result.satisfied_clause,
      policyRootHex: result.policy_root_hex,
    };
  }

  /**
   * Register a TOTP secret for a 2FA-enabled key.
   *
   * Generates a fresh TOTP secret, sends it (encrypted in transit via TLS) to the server
   * for storage, and returns the otpauth URI for the user to scan with an authenticator app.
   *
   * Call confirmTOTP() with the first generated code to activate 2FA.
   *
   * @param keyId - The key identifier returned by createKey()
   * @returns { uri, secret } — URI for QR scan; secret as backup
   */
  async registerTOTP(keyId: string): Promise<{ uri: string; secret: string }> {
    const authHash = await this._authHash;
    const secret = generateTOTPSecret();

    const response = await fetch(
      `${this._serverUrl.replace(/\/$/, '')}/api/v2/sdk/totp/register`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          auth_hash: authHash,
          key_id: keyId,
          totp_secret: secret,
        }),
      }
    );

    const data = (await response.json()) as { success?: boolean; code?: string; message?: string };

    if (!response.ok || data.success !== true) {
      const code = data.code ?? '';
      throw new SigbashSDKError(
        data.message ?? `registerTOTP failed (HTTP ${response.status})`,
        code || 'SERVER_ERROR'
      );
    }

    const uri = buildTOTPUri(secret, this._userKey);
    return { uri, secret };
  }

  /**
   * Confirm TOTP setup by providing the first code from the authenticator app.
   *
   * Must be called after registerTOTP() and before signing with a 2FA-enabled key.
   * Marks the TOTP secret as verified on the server.
   *
   * @param keyId    - The key identifier returned by createKey()
   * @param totpCode - 6-digit TOTP code from the authenticator app
   * @throws TOTPInvalidError if the provided code is incorrect
   */
  async confirmTOTP(keyId: string, totpCode: string): Promise<void> {
    const authHash = await this._authHash;

    const response = await fetch(
      `${this._serverUrl.replace(/\/$/, '')}/api/v2/sdk/totp/verify-setup`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          auth_hash: authHash,
          key_id: keyId,
          totp_code: totpCode,
        }),
      }
    );

    const data = (await response.json()) as {
      success?: boolean;
      code?: string;
      message?: string;
      error?: boolean;
    };

    if (!response.ok || data.success !== true) {
      const code = data.code ?? '';
      if (code === 'TOTP_INVALID') {
        throw new TOTPInvalidError();
      }
      throw new SigbashSDKError(
        data.message ?? `confirmTOTP failed (HTTP ${response.status})`,
        code || 'SERVER_ERROR'
      );
    }
  }

  /**
   * Dry-run policy evaluation and nullifier check against a PSBT.
   *
   * This is a **local WASM operation** — no signing occurs and no nullifier is consumed.
   * Calling this twice on the same PSBT produces identical results (idempotent).
   *
   * @param options.psbtBase64  - Base64-encoded PSBT
   * @param options.kmcJSON     - Decrypted KMC JSON string (from getKey().kmcJSON)
   * @param options.network     - Bitcoin network
   * @param options.progressCallback - Optional WASM progress callback
   *
   * @throws SigbashSDKError if the WASM function is not available or returns an error
   */
  async verifyPSBT(options: VerifyPSBTOptions): Promise<VerifyPSBTResult> {
    const wasmFn = (globalThis as Record<string, unknown>)[
      'SigbashWASM_VerifyPSBTAgainstPolicy'
    ] as ((
      psbt: string,
      kmc: string,
      network: string,
      cb: ((step: string, msg: string) => void) | null
    ) => Promise<WasmVerifyResult>) | undefined;

    if (typeof wasmFn !== 'function') {
      throw new SigbashSDKError(
        'SigbashWASM_VerifyPSBTAgainstPolicy is not available. ' +
          'Ensure the WASM binary has been loaded via loadWasm() before calling verifyPSBT().',
        'WASM_NOT_LOADED'
      );
    }

    // The WASM fetches /api/v2/signing_key (relative URL) for the server
    // timestamp needed by nullifier epoch derivation.  In Node.js there is no
    // base URL, so wrap globalThis.fetch exactly as signPSBT does.
    const serverBase = this._serverUrl.replace(/\/$/, '');
    (globalThis as Record<string, unknown>)['sigbashBaseUrl'] = serverBase;
    const baseFetch = (globalThis as Record<string, unknown>)['fetch'] as typeof fetch;
    (globalThis as Record<string, unknown>)['fetch'] = (
      input: Parameters<typeof fetch>[0],
      init?: Parameters<typeof fetch>[1]
    ) => {
      const isRelative = typeof input === 'string' && input.startsWith('/');
      const url = isRelative ? `${serverBase}${input}` : input;
      return baseFetch(url as Parameters<typeof fetch>[0], init);
    };

    let result: WasmVerifyResult;
    try {
      result = await wasmFn(
        options.psbtBase64,
        options.kmcJSON,
        options.network,
        options.progressCallback ?? null
      );
    } catch (err) {
      throw new SigbashSDKError(
        `WASM VerifyPSBTAgainstPolicy failed: ${String(err)}`,
        'WASM_ERROR'
      );
    } finally {
      (globalThis as Record<string, unknown>)['fetch'] = baseFetch;
      delete (globalThis as Record<string, unknown>)['sigbashBaseUrl'];
    }

    const passed = result.success ?? result.passed ?? false;

    return {
      passed,
      pathID: result.pathID ?? '',
      satisfiedClause: result.satisfiedClause ?? '',
      nullifierStatus: (result.nullifierStatus ?? []).map(ns => ({
        inputIndex: ns.inputIndex,
        available: ns.available,
        message: ns.message,
      })),
      error: result.error,
    };
  }

  // -------------------------------------------------------------------------
  // Cleanup
  // -------------------------------------------------------------------------

  /**
   * Disconnect all Socket.IO connections and release resources.
   */
  disconnect(): void {
    if (this._socket !== null) {
      this._socket.disconnect();
      this._socket = null;
    }
    if (this._musig2Socket !== null) {
      this._musig2Socket.disconnect();
      this._musig2Socket = null;
    }
    // Clear the globalThis reference so the WASM socket handle is released.
    if ((globalThis as Record<string, unknown>)['sharedMusigSocket'] !== undefined) {
      delete (globalThis as Record<string, unknown>)['sharedMusigSocket'];
    }
  }

  /**
   * Returns a safe JSON representation — private key material is excluded.
   */
  toJSON(): Record<string, unknown> {
    return { serverUrl: this._serverUrl };
  }

  /**
   * Control Node.js util.inspect / console.log output to prevent key leaks in server logs.
   */
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `SigbashClient { serverUrl: '${this._serverUrl}', [private key hidden] }`;
  }

  /**
   * Overwrite the in-memory private key with random bytes and mark this instance as disposed.
   * Call this when the SigbashClient is no longer needed.
   */
  dispose(): void {
    if (this.#disposed) return;
    crypto.getRandomValues(this.#musig2PrivateKey);
    // Overwrite the userSecretKey reference — string can't be zeroed in JS but
    // removing the reference makes the original value eligible for GC sooner.
    (this as unknown as { _userSecretKey: string })._userSecretKey = '';
    this.#disposed = true;
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private _requireSocket(): SigbashSocket {
    if (this._socket === null) {
      this._socket = new SigbashSocket(this._serverUrl);
    }
    return this._socket;
  }

  /**
   * Return (lazily creating) a Socket.IO connection to /api/v2/musig2.
   *
   * The Go WASM signing pipeline communicates with the server exclusively on
   * this namespace (request_server_nonces, compute_server_ub,
   * blind_signing_request / blind_signing_response events).
   *
   * A separate connection is used so that the SDK namespace (/api/v2/sdk)
   * and the musig2 namespace (/api/v2/musig2) remain independent.
   */
  private _requireMusig2Socket(): SigbashSocket {
    if (this._musig2Socket === null) {
      this._musig2Socket = new SigbashSocket(this._serverUrl, '/api/v2/musig2');
    }
    return this._musig2Socket;
  }

  /**
   * Decrypt a single AES-256-GCM encrypted covenant state value.
   * Format: hex(12-byte-nonce || ciphertext || 16-byte-GCM-tag)
   */
  private async _decryptCovenantState(encryptedHex: string, encKeyHex: string): Promise<string> {
    if (!encryptedHex || encryptedHex.length % 2 !== 0 || !encKeyHex || encKeyHex.length !== 64) {
      throw new Error('_decryptCovenantState: invalid input lengths');
    }
    const encryptedBytes = Uint8Array.from(
      encryptedHex.match(/.{2}/g)!.map(b => parseInt(b, 16))
    );
    const encKeyBytes = Uint8Array.from(
      encKeyHex.match(/.{2}/g)!.map(b => parseInt(b, 16))
    );
    const nonce = encryptedBytes.slice(0, 12);
    const ciphertextWithTag = encryptedBytes.slice(12);
    const key = await crypto.subtle.importKey(
      'raw', encKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']
    );
    const decryptedBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce }, key, ciphertextWithTag
    );
    return new TextDecoder().decode(decryptedBytes);
  }

  /**
   * Pre-fetch and decrypt covenant state for all PSBT inputs, storing the results
   * in globalThis.sigbashPreFetchedCovenantState so WASM can read them synchronously.
   * Always sets the global (even as {}) so WASM skips any WebSocket fallback.
   */
  private async _prefetchCovenantState(
    kmcJSON: string,
    psbtBase64: string,
    authHash: string,
  ): Promise<void> {
    // Always set the marker so WASM skips WebSocket fallback in SDK context.
    (globalThis as Record<string, unknown>)['sigbashPreFetchedCovenantState'] = {};

    const keysFn = (globalThis as Record<string, unknown>)[
      'SigbashWASM_ComputeCovenantBlindedKeys'
    ] as ((psbt: string, kmc: string) => string) | undefined;
    if (typeof keysFn !== 'function') return;

    let keysResult: { success?: boolean; blinded_keys?: string[]; enc_keys?: string[]; error?: string };
    try {
      keysResult = JSON.parse(keysFn(psbtBase64, kmcJSON));
    } catch {
      return;
    }
    if (!keysResult.success || !keysResult.blinded_keys?.length) return;

    // Fetch encrypted state from server using SDK auth.
    let covenantStateMap: Record<string, string> = {};
    try {
      const sdkSocket = this._requireSocket();
      const resp = await sdkSocket.request<{
        success: boolean;
        data?: { covenant_state_map?: Record<string, string> };
      }>('fetch_covenant_state_with_hash', {
        auth_hash: authHash,
        keys: keysResult.blinded_keys,
      });
      covenantStateMap = resp?.data?.covenant_state_map ?? {};
    } catch {
      return; // Non-fatal — WASM proceeds with empty map.
    }

    // Decrypt each value using AES-256-GCM and the corresponding enc key.
    const decryptedMap: Record<string, string> = {};
    const encKeyHexes = keysResult.enc_keys ?? [];
    for (let i = 0; i < keysResult.blinded_keys.length; i++) {
      const blindedKeyHex = keysResult.blinded_keys[i];
      const encryptedHex = covenantStateMap[blindedKeyHex];
      if (!encryptedHex) continue;
      try {
        decryptedMap[blindedKeyHex] = await this._decryptCovenantState(encryptedHex, encKeyHexes[i]);
      } catch {
        // Skip undecryptable entries.
      }
    }

    (globalThis as Record<string, unknown>)['sigbashPreFetchedCovenantState'] = decryptedMap;
  }

  // ---------------------------------------------------------------------------
  // Account recovery
  // ---------------------------------------------------------------------------

  /**
   * Export a recovery kit for the given key.
   *
   * The kit contains the pre-derived `userRecoveryKEK` (hex), which acts as an
   * out-of-band decryption key for the server-stored `enc_kek2`.  If the user
   * later loses their `userSecretKey` they can still recover their KMC as long
   * as the kit is available — the kit's `recoveryKEK` substitutes for the
   * missing secret.
   *
   * Must be called while the credential triplet is valid (normal authentication
   * must succeed, since the method fetches the current `enc_kek2` from the
   * server to embed in the kit).
   *
   * **Security**: treat the returned kit like a private key.  Anyone who has
   * the kit and access to the server for the matching `keyId` can decrypt the
   * key material container.  Store offline, encrypted, or in a
   * hardware-backed secret store.  Print to paper only if physically secured.
   *
   * @param keyId - The key identifier returned by createKey()
   * @param opts.keyIndex - Optional key index (default 0)
   * @returns SdkRecoveryKit — save this value securely offline
   */
  async exportRecoveryKit(
    keyId: string,
    opts?: { keyIndex?: number }
  ): Promise<SdkRecoveryKit> {
    if (this.#disposed) {
      throw new SigbashSDKError('SigbashClient has been disposed', 'CLIENT_DISPOSED');
    }

    const authHash = await this._authHash;
    const socket = this._requireSocket();

    // Fetch the current envelope and enc_kek2 from the server.
    const response = await socket.request<GetKMCResponse>('get_encrypted_kmc', {
      auth_hash: authHash,
      key_id: keyId,
      key_index: opts?.keyIndex ?? 0,
    });

    if (!response.encrypted_key_material) {
      throw new SigbashSDKError('No encrypted_key_material in server response', 'NO_KEY_MATERIAL');
    }
    if (!response.enc_kek2) {
      throw new SigbashSDKError(
        'Server did not return enc_kek2 for this key — recovery kit cannot be generated',
        'NO_ENC_KEK2'
      );
    }

    // Parse and version-validate enc_kek2 — throws ENC_KEK2_VERSION_MISMATCH if webauthn-v1.
    const parsedEncKek2 = parseEncKek2(response.enc_kek2);

    // Derive the user recovery KEK from the credential triplet and encode as hex.
    const recoveryKEKBytes = await deriveUserRecoveryKEK(
      this._apiKey,
      this._userKey,
      this._userSecretKey
    );
    const recoveryKEKHex = Array.from(recoveryKEKBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    return {
      version: 'sdk-recovery-v1',
      keyId,
      recoveryKEK: recoveryKEKHex,
      cekCiphertext: parsedEncKek2.ciphertext,
      cekNonce: parsedEncKek2.nonce,
      network: response.network,
      createdAt: Math.floor(Date.now() / 1000),
    };
  }

  /**
   * Recover access to a key using a previously exported recovery kit.
   *
   * Uses the kit's `recoveryKEK` to decrypt the KMC via the `enc_kek2`
   * (recovery-path CEK wrapping) rather than the credential auth slot.
   * This means `userSecretKey` is **not required** to be correct — the
   * kit's pre-derived KEK substitutes for it.
   *
   * The `SigbashClient` instance must still have a valid `apiKey` and
   * `userKey` (the `authHash` is used to authenticate the server request to
   * fetch the current envelope).
   *
   * The method prefers the server-fetched `enc_kek2` (authoritative) and
   * falls back to the snapshot stored in the kit if the server returns none.
   *
   * @param recoveryKit - Kit previously returned by exportRecoveryKit()
   * @returns GetKeyResult — same shape as getKey(); use kmcJSON for signing
   * @throws SigbashSDKError  if the kit version or fields are invalid
   * @throws SigbashSDKError  with code ENC_KEK2_VERSION_MISMATCH if enc_kek2 is a webauthn blob
   * @throws CryptoError      if the recoveryKEK is wrong or decryption fails
   */
  async recoverFromKit(recoveryKit: SdkRecoveryKit): Promise<GetKeyResult> {
    if (this.#disposed) {
      throw new SigbashSDKError('SigbashClient has been disposed', 'CLIENT_DISPOSED');
    }

    // Validate kit shape.
    if (recoveryKit?.version !== 'sdk-recovery-v1') {
      throw new SigbashSDKError(
        `Unsupported recovery kit version: '${recoveryKit?.version}'. Expected 'sdk-recovery-v1'.`,
        'RECOVERY_KIT_VERSION_MISMATCH'
      );
    }
    if (!recoveryKit.keyId || !recoveryKit.recoveryKEK || !recoveryKit.cekCiphertext || !recoveryKit.cekNonce) {
      throw new SigbashSDKError(
        'Recovery kit is missing required fields (keyId, recoveryKEK, cekCiphertext, cekNonce)',
        'RECOVERY_KIT_INVALID'
      );
    }

    const authHash = await this._authHash;
    const socket = this._requireSocket();

    // Fetch the current envelope and enc_kek2 from the server.
    const response = await socket.request<GetKMCResponse>('get_encrypted_kmc', {
      auth_hash: authHash,
      key_id: recoveryKit.keyId,
      key_index: 0,
    });

    if (!response.encrypted_key_material) {
      throw new SigbashSDKError('No encrypted_key_material in server response', 'NO_KEY_MATERIAL');
    }

    // Build the WrappedKey to use for CEK unwrapping.
    // Prefer the server-fetched enc_kek2 (it may have been rotated since the
    // kit was exported).  Fall back to the kit's snapshot if the server returns none.
    let wrappedCEK: WrappedKey;
    if (response.enc_kek2) {
      // Validate server copy; throws ENC_KEK2_VERSION_MISMATCH if webauthn blob.
      wrappedCEK = parseEncKek2(response.enc_kek2) as WrappedKey;
    } else {
      // Use the flat ciphertext/nonce fields stored in the kit.
      wrappedCEK = { ciphertext: recoveryKit.cekCiphertext, nonce: recoveryKit.cekNonce };
    }

    // Decode the recovery KEK from hex.
    const hexStr = recoveryKit.recoveryKEK;
    if (hexStr.length !== 64 || !/^[0-9a-f]+$/i.test(hexStr)) {
      throw new SigbashSDKError('Recovery kit recoveryKEK is not a valid 32-byte hex string', 'RECOVERY_KIT_INVALID');
    }
    const recoveryKEKBytes = Uint8Array.from(
      hexStr.match(/.{2}/g)!.map(b => parseInt(b, 16))
    );

    // Decrypt the KMC using the recovery KEK path.
    const envelope = JSON.parse(response.encrypted_key_material) as KMCEnvelope;
    const kmc = await decryptKMCFromRecoveryKEK(envelope, wrappedCEK, recoveryKEKBytes);
    const kmcJSON = JSON.stringify(kmc);

    const network = (response.network as GetKeyResult['network']) ?? 'signet';

    return {
      keyId: recoveryKit.keyId,
      policyRoot: response.policy_root,
      network,
      require2FA: response.require_2fa,
      keyIndex: response.key_index ?? 0,
      keyMaterial: kmc as Record<string, unknown>,
      kmcJSON,
    };
  }

}
