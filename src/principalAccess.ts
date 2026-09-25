/**
 * Principal access lifecycle: the client halves of the revocable-principal
 * grant, revoke, and recovery-rebind ceremonies on the mainnet signing
 * path.
 *
 * A principal replaces the shared-executor credential model: authorization
 * to a PolicyKey is a server-side access row plus a KMC auth slot sealed
 * to the principal's slot key, and revocation works against a copied
 * credential because the row flip, the generation bump, and the envelope
 * re-wrap are all protocol events the old credential cannot ride past.
 *
 * Ceremony division. This module composes protocol halves the server
 * surfaces already own:
 *
 * 1. Registration — the grantor pre-registers the principal's
 *    proof-of-possession row (the existing org-admin users route), so the
 *    credential can authenticate before its first use.
 * 2. Access row — the grant route installs the active row and bumps the
 *    key's access generation in one transaction; the revoke route flips
 *    the row (revoking an already-revoked principal is a no-op success).
 * 3. Envelope — the WASM slot-add seals the content-encryption key to the
 *    new principal's slot key without disturbing the other slots' bytes;
 *    the re-wrap ceremony rotates to a fresh content key and drops the
 *    removed principal's slot entirely. The replacement envelope uploads
 *    through the rewrap route, which replaces key material only.
 * 4. Delivery — the grant returns the serialized credential as an opaque
 *    delivery payload. Sealing it into the grantee's capability envelope
 *    and depositing it through the key-envelope mailbox is the caller's
 *    vault-side concern: the transport that carries mailbox rows is an
 *    application-plane session this module deliberately never holds.
 *
 * Privacy posture. Every request body this module emits carries only
 * opaque values — auth hashes, envelope JSON, commitment hex — never the
 * credential secret, the slot private key, or any content-encryption key
 * material. The transport-capture tests pin that property. No descriptor,
 * Bitcoin key, or policy root changes: a principal change mutates access
 * state only.
 */

import type { PolicyKeyAccessStatusV1 } from './contracts';
import {
  generatePrincipalCredential,
  principalAuthHash,
  principalPopPublicKeyHex,
  principalSlotCredentialId,
  derivePrincipalSlotKey,
  serializePrincipalCredential,
  type PrincipalCredentialV1,
} from './wallet/principalCredential';
import { AdminError, SigbashSDKError, WasmError } from './errors';

// ---------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------

/**
 * The authenticated REST transport the ceremonies ride. SigbashClient
 * binds its PoP-signing fetch here; tests substitute a capturing fake.
 */
export interface PrincipalAccessTransport {
  authedFetch(
    input: string,
    init?: RequestInit & { body?: string | Uint8Array | undefined },
  ): Promise<Response>;
}

/** Grantor identity opening the envelope: the slot the grantor holds. */
export interface PrincipalGrantorAuth {
  /** Envelope auth mode of the grantor's slot (e.g. 'api' or 'principal'). */
  readonly selectedAuthMode: string;
  /** Credential id of the grantor's slot inside the envelope. */
  readonly credentialId: string;
  /** The grantor's slot secret — used locally, never sent. */
  readonly authSecret: string;
}

/** The WASM seam: the two envelope ceremonies the grant and revoke need. */
export interface PrincipalAccessWasm {
  /** Seal the envelope's content key into a new principal slot. */
  addPrincipalSlot(request: {
    envelopeJson: string;
    selectedAuthMode: string;
    credentialId: string;
    authSecret: string;
    principalPublicKeyHex: string;
    newCredentialId: string;
  }): Promise<string>;
  /** Rotate to a fresh content key, dropping the named slots. */
  rewrapEnvelope(request: {
    envelopeJson: string;
    selectedAuthMode: string;
    credentialId: string;
    authSecret: string;
    removeCredentialIds: readonly string[];
  }): Promise<string>;
}

type WasmCeremonyResult = {
  success?: boolean;
  envelopeJSON?: string;
  envelopeID?: string;
  error?: string;
};

function ceremonyEnvelope(result: WasmCeremonyResult, ceremony: string): string {
  if (result.error || result.success === false || !result.envelopeJSON) {
    throw new WasmError(`${ceremony} failed: ${result.error ?? 'no envelope returned'}`);
  }
  return result.envelopeJSON;
}

function globalWasmFn(name: string): (arg: string) => unknown {
  const fn = (globalThis as Record<string, unknown>)[name] as
    | ((arg: string) => unknown)
    | undefined;
  if (typeof fn !== 'function') {
    throw new WasmError(
      `WASM not loaded — ${name} is unavailable. Call loadWasm() before running principal ceremonies.`,
    );
  }
  return fn;
}

/**
 * The production seam over the loaded WASM binary's principal-slot
 * ceremonies. Both exports answer on the promise medium and carry their
 * failure in an `error` field of the resolved value.
 */
export function defaultPrincipalAccessWasm(): PrincipalAccessWasm {
  const run = (name: string, payload: Record<string, unknown>): Promise<WasmCeremonyResult> =>
    Promise.resolve(globalWasmFn(name)(JSON.stringify(payload)) as WasmCeremonyResult);
  return {
    async addPrincipalSlot(request) {
      return ceremonyEnvelope(
        await run('SigbashWASM_AddKMCPrincipalSlot', {
          envelope_json: request.envelopeJson,
          selected_auth_mode: request.selectedAuthMode,
          credential_id: request.credentialId,
          auth_secret: request.authSecret,
          principal_public_key: request.principalPublicKeyHex,
          new_credential_id: request.newCredentialId,
        }),
        'principal slot add',
      );
    },
    async rewrapEnvelope(request) {
      return ceremonyEnvelope(
        await run('SigbashWASM_RewrapKMCEnvelope', {
          envelope_json: request.envelopeJson,
          selected_auth_mode: request.selectedAuthMode,
          credential_id: request.credentialId,
          auth_secret: request.authSecret,
          remove_credentials: [...request.removeCredentialIds],
        }),
        'envelope re-wrap',
      );
    },
  };
}

// ---------------------------------------------------------------------------
// Options and results
// ---------------------------------------------------------------------------

/** Client-key commitments proving the replacement envelope's lineage. */
export interface PrincipalKeyCommitments {
  readonly clientKeyCommitmentH1?: string;
  readonly clientKeyHash?: string;
}

export interface PrincipalGrantOptions extends PrincipalKeyCommitments {
  /** The key's numeric id as a string — the client-visible key handle. */
  readonly policyKeyId: string;
  /** The current KMC envelope JSON (the grantor holds it decrypt-capable). */
  readonly envelopeJson: string;
  readonly grantor: PrincipalGrantorAuth;
  /**
   * Pre-register the principal's proof-of-possession row before granting
   * (default true). The grantor must hold org-admin authority either way.
   */
  readonly register?: boolean;
  /** The access generation the caller last observed; sent as a staleness guard. */
  readonly observedAccessGeneration?: number;
}

export interface PrincipalGrantResult {
  /** The provisioned credential — store it in the capability vault. */
  readonly credential: PrincipalCredentialV1;
  /** The server-visible principal identifier. */
  readonly authHash: string;
  /** The slot public key the content key was sealed to. */
  readonly slotPublicKeyHex: string;
  /** The slot address a revoke re-wrap names to drop. */
  readonly slotCredentialId: string;
  /**
   * Opaque delivery payload for the grantee's mailbox: the canonical
   * credential serialization. The caller seals it into the grantee's
   * capability envelope before depositing it.
   */
  readonly delivery: Uint8Array;
  /** The access state the grant installed. */
  readonly status: PolicyKeyAccessStatusV1;
  /** The key's generation after the replacement envelope upload. */
  readonly accessGeneration: number;
}

export interface PrincipalRevokeOptions extends PrincipalKeyCommitments {
  readonly policyKeyId: string;
  /** The principal auth hash whose row is revoked. */
  readonly principalAuthHash: string;
  /** The slot address to drop in the re-wrap. */
  readonly slotCredentialId: string;
  readonly envelopeJson: string;
  readonly grantor: PrincipalGrantorAuth;
  readonly observedAccessGeneration?: number;
}

export interface PrincipalRevokeResult {
  /** The access state after the revoke. */
  readonly status: PolicyKeyAccessStatusV1;
  /** The key's generation after the replacement envelope upload. */
  readonly accessGeneration: number;
}

export interface PrincipalRebindOptions extends PrincipalKeyCommitments {
  /** Every key the recovered principal should hold access to. */
  readonly policyKeyIds: readonly string[];
  /** Per-key grantor envelopes: key id → the current envelope JSON. */
  readonly envelopes: Readonly<Record<string, string>>;
  readonly grantor: PrincipalGrantorAuth;
  /** The principal being replaced (its rows are revoked after the grants). */
  readonly previousPrincipal: {
    readonly authHash: string;
    readonly slotCredentialId: string;
  };
  readonly observedAccessGeneration?: number;
}

export interface PrincipalRebindResult {
  /** One fresh credential provisioned for all the listed keys. */
  readonly credential: PrincipalCredentialV1;
  readonly authHash: string;
  readonly delivery: Uint8Array;
  /** Grants in options order; each carries its key's status view. */
  readonly grants: readonly PrincipalGrantResult[];
  /** Revocations of the replaced principal, in options order. */
  readonly revokes: readonly PrincipalRevokeResult[];
}

// ---------------------------------------------------------------------------
// Response handling
// ---------------------------------------------------------------------------

interface AccessStatusBody {
  policy_key_id?: string;
  principal_auth_hash?: string;
  status?: string;
  access_generation?: number | string;
}

interface ErrorBody {
  success?: boolean;
  code?: string;
  message?: string;
}

const WIRE_ACCESS_STATUSES: readonly string[] = ['active', 'revoked'];

function statusView(body: AccessStatusBody): PolicyKeyAccessStatusV1 {
  if (
    typeof body.policy_key_id !== 'string' ||
    typeof body.principal_auth_hash !== 'string' ||
    typeof body.status !== 'string' ||
    !WIRE_ACCESS_STATUSES.includes(body.status)
  ) {
    throw new SigbashSDKError('Malformed principal access status response', 'SERVER_ERROR');
  }
  const generation = Number(body.access_generation);
  if (!Number.isInteger(generation) || generation < 0) {
    throw new SigbashSDKError('Malformed access generation in status response', 'SERVER_ERROR');
  }
  return {
    policy_key_id: body.policy_key_id,
    principal_auth_hash: body.principal_auth_hash,
    status: body.status as PolicyKeyAccessStatusV1['status'],
    access_generation: generation,
  };
}

function assertOk(response: Response, data: ErrorBody, action: string): void {
  if (response.ok && data.success !== false) {
    return;
  }
  const code = data.code ?? '';
  const message = data.message ?? `${action} failed (HTTP ${response.status})`;
  if (code === 'FORBIDDEN' || code === 'UNAUTHORIZED' || response.status === 403) {
    throw new AdminError(message);
  }
  // The server's typed rejection code is the error identity: stale
  // generation, commitment mismatch, atomic-mutation requirement, posture
  // gate, and rate limiting each surface as its own catchable code.
  throw new SigbashSDKError(message, code || 'SERVER_ERROR');
}

async function readJson<T>(response: Response): Promise<T> {
  try {
    return (await response.json()) as T;
  } catch {
    throw new SigbashSDKError(
      `Unreadable response from the principal access surface (HTTP ${response.status})`,
      'SERVER_ERROR',
    );
  }
}

// ---------------------------------------------------------------------------
// Lifecycle API
// ---------------------------------------------------------------------------

export class PrincipalAccessApi {
  constructor(
    private readonly _transport: PrincipalAccessTransport,
    private readonly _orgApiKey: string,
    private readonly _wasm: PrincipalAccessWasm = defaultPrincipalAccessWasm(),
  ) {}

  /**
   * Run the grant ceremony for one new principal on one key: provision the
   * credential, register its proof-of-possession row, seal a new envelope
   * slot, install the access row, and upload the replacement envelope.
   */
  async grant(options: PrincipalGrantOptions): Promise<PrincipalGrantResult> {
    const credential = generatePrincipalCredential(this._orgApiKey);
    const authHash = await principalAuthHash(this._orgApiKey, credential.userKey);
    if (options.register !== false) {
      await this._registerPrincipal(credential, authHash);
    }
    return this._grantOnKey(credential, authHash, options);
  }

  /**
   * Run the revoke ceremony for one principal on one key: read the access
   * state first (the client-side guard — the server's row check is the
   * gate), flip the row, rotate the envelope to a fresh content key with
   * the revoked principal's slot dropped, and upload the replacement.
   */
  async revoke(options: PrincipalRevokeOptions): Promise<PrincipalRevokeResult> {
    // Status before revoke: fails fast on an unknown key or posture
    // denial, and records the state the caller started from.
    await this.status(options.policyKeyId, options.principalAuthHash);

    const revokeResponse = await this._transport.authedFetch(
      `/api/v2/sdk/keys/${encodeURIComponent(options.policyKeyId)}/access/${options.principalAuthHash}`,
      { method: 'DELETE' },
    );
    const revokeData = await readJson<ErrorBody & AccessStatusBody>(revokeResponse);
    assertOk(revokeResponse, revokeData, 'principal access revoke');

    const envelopeJson = await this._wasm.rewrapEnvelope({
      envelopeJson: options.envelopeJson,
      selectedAuthMode: options.grantor.selectedAuthMode,
      credentialId: options.grantor.credentialId,
      authSecret: options.grantor.authSecret,
      removeCredentialIds: [options.slotCredentialId],
    });

    const upload = await this._uploadEnvelope(
      options.policyKeyId,
      envelopeJson,
      options.observedAccessGeneration,
      options,
    );
    return { status: statusView(revokeData), accessGeneration: upload.accessGeneration };
  }

  /**
   * Recovery rebind: one fresh credential granted on every listed key
   * (grants first, so the organization never loses a working principal),
   * then the replaced principal's rows revoked and its slots re-wrapped
   * away. Exactly one registration and one credential cover all keys.
   */
  async rebind(options: PrincipalRebindOptions): Promise<PrincipalRebindResult> {
    if (options.policyKeyIds.length === 0) {
      throw new SigbashSDKError('rebind requires at least one key', 'INVALID_ARGUMENT');
    }
    const credential = generatePrincipalCredential(this._orgApiKey);
    const authHash = await principalAuthHash(this._orgApiKey, credential.userKey);
    await this._registerPrincipal(credential, authHash);

    const grants: PrincipalGrantResult[] = [];
    for (const policyKeyId of options.policyKeyIds) {
      const envelopeJson = options.envelopes[policyKeyId];
      if (typeof envelopeJson !== 'string') {
        throw new SigbashSDKError(
          `rebind requires an envelope for key ${policyKeyId}`,
          'INVALID_ARGUMENT',
        );
      }
      grants.push(await this._grantOnKey(credential, authHash, { ...options, policyKeyId, envelopeJson }));
    }

    const revokes: PrincipalRevokeResult[] = [];
    for (const policyKeyId of options.policyKeyIds) {
      const envelopeJson = options.envelopes[policyKeyId] as string;
      revokes.push(
        await this.revoke({
          policyKeyId,
          principalAuthHash: options.previousPrincipal.authHash,
          slotCredentialId: options.previousPrincipal.slotCredentialId,
          envelopeJson,
          grantor: options.grantor,
          clientKeyCommitmentH1: options.clientKeyCommitmentH1,
          clientKeyHash: options.clientKeyHash,
          observedAccessGeneration: options.observedAccessGeneration,
        }),
      );
    }

    return {
      credential,
      authHash,
      delivery: serializePrincipalCredential(credential),
      grants,
      revokes,
    };
  }

  /** One principal's current access state for one key. */
  async status(
    policyKeyId: string,
    principalAuthHashValue: string,
  ): Promise<PolicyKeyAccessStatusV1> {
    const response = await this._transport.authedFetch(
      `/api/v2/sdk/keys/${encodeURIComponent(policyKeyId)}/access/${principalAuthHashValue}`,
    );
    const data = await readJson<ErrorBody & AccessStatusBody>(response);
    assertOk(response, data, 'principal access status');
    return statusView(data);
  }

  /** Every access row on one key — auth hashes and states only. */
  async list(policyKeyId: string): Promise<PolicyKeyAccessStatusV1[]> {
    const response = await this._transport.authedFetch(
      `/api/v2/sdk/keys/${encodeURIComponent(policyKeyId)}/access`,
    );
    const data = await readJson<ErrorBody & AccessStatusBody[]>(response);
    assertOk(response, data, 'principal access list');
    if (!Array.isArray(data)) {
      throw new SigbashSDKError('Malformed principal access list response', 'SERVER_ERROR');
    }
    return data.map(statusView);
  }

  private async _registerPrincipal(
    credential: PrincipalCredentialV1,
    authHash: string,
  ): Promise<void> {
    const popPubkey = await principalPopPublicKeyHex(credential);
    const response = await this._transport.authedFetch('/api/v2/sdk/admin/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        new_user_auth_hash: authHash,
        new_user_pop_pubkey: popPubkey,
      }),
    });
    assertOk(response, await readJson<ErrorBody>(response), 'principal registration');
  }

  /**
   * Grant one already-provisioned credential on one key. This is the
   * per-key half of the ceremony; grant() wraps it with provisioning and
   * registration, rebind() calls it once per key for one credential.
   */
  private async _grantOnKey(
    credential: PrincipalCredentialV1,
    authHash: string,
    options: PrincipalGrantOptions,
  ): Promise<PrincipalGrantResult> {
    const slotKey = derivePrincipalSlotKey(this._orgApiKey, credential.userSecretKey);
    const slotCredentialId = principalSlotCredentialId(credential);

    const envelopeJson = await this._wasm.addPrincipalSlot({
      envelopeJson: options.envelopeJson,
      selectedAuthMode: options.grantor.selectedAuthMode,
      credentialId: options.grantor.credentialId,
      authSecret: options.grantor.authSecret,
      principalPublicKeyHex: slotKey.publicKeyHex,
      newCredentialId: slotCredentialId,
    });

    const grantBody: Record<string, unknown> = { principal_auth_hash: authHash };
    if (options.observedAccessGeneration !== undefined) {
      grantBody['access_generation'] = options.observedAccessGeneration;
    }
    const grantResponse = await this._transport.authedFetch(
      `/api/v2/sdk/keys/${encodeURIComponent(options.policyKeyId)}/access`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(grantBody),
      },
    );
    const grantData = await readJson<ErrorBody & AccessStatusBody>(grantResponse);
    assertOk(grantResponse, grantData, 'principal access grant');

    const upload = await this._uploadEnvelope(
      options.policyKeyId,
      envelopeJson,
      options.observedAccessGeneration,
      options,
    );

    return {
      credential,
      authHash,
      slotPublicKeyHex: slotKey.publicKeyHex,
      slotCredentialId,
      delivery: serializePrincipalCredential(credential),
      status: statusView(grantData),
      accessGeneration: upload.accessGeneration,
    };
  }

  private async _uploadEnvelope(
    policyKeyId: string,
    envelopeJson: string,
    observedAccessGeneration: number | undefined,
    commitments: PrincipalKeyCommitments,
  ): Promise<{ accessGeneration: number }> {
    const body: Record<string, unknown> = { encrypted_kmc: envelopeJson };
    if (commitments.clientKeyCommitmentH1 !== undefined) {
      body['client_key_commitment_h1'] = commitments.clientKeyCommitmentH1;
    }
    if (commitments.clientKeyHash !== undefined) {
      body['client_key_hash'] = commitments.clientKeyHash;
    }
    if (observedAccessGeneration !== undefined) {
      body['access_generation'] = observedAccessGeneration;
    }
    const response = await this._transport.authedFetch(
      `/api/v2/sdk/keys/${encodeURIComponent(policyKeyId)}/kmc/rewrap`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
    );
    const data = await readJson<ErrorBody & { access_generation?: number | string }>(response);
    assertOk(response, data, 'envelope upload');
    const generation = Number(data.access_generation);
    if (!Number.isInteger(generation) || generation < 0) {
      throw new SigbashSDKError('Malformed generation in envelope upload response', 'SERVER_ERROR');
    }
    return { accessGeneration: generation };
  }
}
