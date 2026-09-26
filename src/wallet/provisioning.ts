/**
 * Staged multi-signer wallet provisioning: the client half of the
 * reserve → assemble → compile → seal → activate lifecycle.
 *
 * Assembly is pure and deterministic: the canonical wallet descriptor and
 * its fingerprint digest are a function of the committed signer roots and
 * allowed signer sets alone, so two assemblies of the identical committed
 * intent produce the identical digest no matter the submission order.
 * Origin metadata never enters the digest — the fingerprint commits the
 * origin-less canonical text — so interoperability decoration cannot move
 * a sealed wallet's identity.
 *
 * Multi-Sigbash refusal: the lifecycle machinery is signer-kind agnostic,
 * but a staged intent carrying more than one policy-bound Sigbash signer
 * is refused before any reservation exists (pre-flight) — multi-Sigbash
 * execution is an owner-gated capability. The server refuses the same
 * intent again at seal time, so a pre-flight bypass can never turn a
 * multi-Sigbash intent into sign-capable keys.
 *
 * Privacy posture: requests carry committed signer roots, index tuples,
 * and hex digests only — never wallet plaintext, never key material.
 * The per-signer binding tokens returned by the reservation create are
 * opaque handles each signer's key submission must present once.
 */

import { SigbashSDKError } from '../errors';
import {
  buildInstitutionalWalletDescriptor,
  type InstitutionalWallet,
  type WalletSigner,
} from './walletBuilder';
import { walletFingerprintHex } from './walletIdentity';
import type { WalletNetwork } from './constants';

/** The stable seal-time/pre-flight refusal code for multi-Sigbash intent. */
export const MULTI_SIGBASH_UNSUPPORTED = 'MULTI_SIGBASH_UNSUPPORTED';

/** One staged signer-set intent: exactly what the server commits. */
export interface StagedSignerIntent {
  readonly network: WalletNetwork;
  readonly signers: readonly WalletSigner[];
  readonly allowedSignerSets: readonly (readonly number[])[];
}

/** The pure assembly result: the canonical wallet plus its digest. */
export interface StagedAssemblyV1 {
  readonly wallet: InstitutionalWallet;
  /** The wallet fingerprint hex — the committed descriptor digest. */
  readonly descriptorDigest: string;
}

/** One signer slot handed out at reservation create. */
export interface StagedSignerSlotHandleV1 {
  readonly slot_index: number;
  readonly kind: string;
  readonly slot_token: string;
}

/** The server's create view of a reservation. */
export interface StagedReservationCreatedV1 {
  readonly reservation_id: string;
  readonly state: string;
  readonly network: string;
  readonly expires_at: string;
  readonly slots: readonly StagedSignerSlotHandleV1[];
}

/** One signer's compiled per-signer digests. */
export interface StagedSignerCompilationV1 {
  readonly slot_index: number;
  readonly policy_root: string;
  readonly reqkey_digest: string;
}

/**
 * Refuse a staged intent the surface must not provision. The only intent
 * shape the machinery accepts today carries at most one policy-bound
 * Sigbash signer; multi-Sigbash composition stays an owner-gated
 * capability until its execution orchestration lands.
 */
export function preflightStagedSignerIntent(intent: StagedSignerIntent): void {
  const sigbashCount = intent.signers.filter(
    (signer) => signer.kind === 'sigbash_policy_key',
  ).length;
  if (sigbashCount > 1) {
    throw new SigbashSDKError(
      'Staged provisioning supports at most one policy-bound Sigbash signer; '
      + 'multi-Sigbash intent is refused',
      MULTI_SIGBASH_UNSUPPORTED,
    );
  }
}

/**
 * Pure deterministic assembly: the canonical descriptor built from the
 * committed intent plus its digest. Throws the builder's fail-closed
 * errors on any invalid intent and the multi-Sigbash refusal on a
 * multi-Sigbash intent.
 */
export function assembleStagedWalletDescriptor(
  intent: StagedSignerIntent,
): StagedAssemblyV1 {
  preflightStagedSignerIntent(intent);
  const wallet = buildInstitutionalWalletDescriptor({
    network: intent.network,
    signers: [...intent.signers],
    allowedSignerSets: intent.allowedSignerSets.map((set) => [...set]),
  });
  return { wallet, descriptorDigest: walletFingerprintHex(wallet) };
}

/** The authenticated REST transport the lifecycle rides. */
export interface StagedProvisioningTransport {
  authedFetch(
    input: string,
    init?: RequestInit & { body?: string | Uint8Array | undefined },
  ): Promise<Response>;
}

/**
 * The server's create contract for one signer: {kind, signer_root,
 * policy_key_id?}. The commitment is origin-less by design — origin
 * decoration never crosses the wire, and the SDK's `xpub` field maps to
 * the server's `signer_root` here so the client shape stays ergonomic
 * while the server schema stays authoritative.
 */
function toWireSigner(signer: WalletSigner): Record<string, string> {
  const wire: Record<string, string> = {
    kind: signer.kind,
    signer_root: signer.xpub,
  };
  if (signer.kind === 'sigbash_policy_key' && signer.policyKeyId) {
    wire.policy_key_id = signer.policyKeyId;
  }
  return wire;
}

interface ErrorBody {
  readonly error?: boolean;
  readonly code?: string;
  readonly message?: string;
}

function assertOk(response: Response, data: ErrorBody, action: string): void {
  if (response.ok && data.error !== true) {
    return;
  }
  const message = data.message ?? `${action} failed (HTTP ${response.status})`;
  throw new SigbashSDKError(message, data.code ?? 'SERVER_ERROR');
}

async function readJson<T extends object>(response: Response): Promise<T> {
  try {
    return (await response.json()) as T;
  } catch {
    throw new SigbashSDKError(
      `Unreadable response from the provisioning surface (HTTP ${response.status})`,
      'SERVER_ERROR',
    );
  }
}

/**
 * The reservation lifecycle client: one class per organization session,
 * riding the SigbashClient's PoP-signed transport. Every method surfaces
 * server rejections as typed SigbashSDKError codes.
 */
export class StagedProvisioningApi {
  constructor(private readonly _transport: StagedProvisioningTransport) {}

  /** Reserve the signer-set intent; returns each signer's binding token. */
  async createReservation(intent: StagedSignerIntent): Promise<StagedReservationCreatedV1> {
    preflightStagedSignerIntent(intent);
    const response = await this._transport.authedFetch(
      '/api/v2/sdk/wallet/provisioning/reservations',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          network: intent.network,
          signers: intent.signers.map(toWireSigner),
          allowed_signer_sets: intent.allowedSignerSets,
        }),
      },
    );
    const data = await readJson<ErrorBody & StagedReservationCreatedV1>(response);
    assertOk(response, data, 'reservation create');
    return data;
  }

  /** Read one reservation's lifecycle state. */
  async getReservation(reservationId: string): Promise<ErrorBody & Record<string, unknown>> {
    const response = await this._transport.authedFetch(
      `/api/v2/sdk/wallet/provisioning/reservations/${encodeURIComponent(reservationId)}`,
    );
    const data = await readJson<ErrorBody & Record<string, unknown>>(response);
    assertOk(response, data, 'reservation read');
    return data;
  }

  /** Commit the assembled canonical descriptor's digest. */
  async assemble(reservationId: string, descriptorDigest: string): Promise<void> {
    const response = await this._transport.authedFetch(
      `/api/v2/sdk/wallet/provisioning/reservations/${encodeURIComponent(reservationId)}/assemble`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ descriptor_digest: descriptorDigest }),
      },
    );
    const data = await readJson<ErrorBody>(response);
    assertOk(response, data, 'reservation assemble');
  }

  /** Record every signer's compiled policy root and REQKEY digest. */
  async compile(
    reservationId: string,
    perSigner: readonly StagedSignerCompilationV1[],
  ): Promise<void> {
    const response = await this._transport.authedFetch(
      `/api/v2/sdk/wallet/provisioning/reservations/${encodeURIComponent(reservationId)}/compile`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ per_signer: perSigner }),
      },
    );
    const data = await readJson<ErrorBody>(response);
    assertOk(response, data, 'reservation compile');
  }

  /** Seal the wallet: freeze the committed intent and digest. */
  async seal(reservationId: string): Promise<void> {
    const response = await this._transport.authedFetch(
      `/api/v2/sdk/wallet/provisioning/reservations/${encodeURIComponent(reservationId)}/seal`,
      { method: 'POST' },
    );
    const data = await readJson<ErrorBody>(response);
    assertOk(response, data, 'reservation seal');
  }

  /** Activate the sealed wallet: every bound signer becomes sign-capable. */
  async activate(reservationId: string): Promise<void> {
    const response = await this._transport.authedFetch(
      `/api/v2/sdk/wallet/provisioning/reservations/${encodeURIComponent(reservationId)}/activate`,
      { method: 'POST' },
    );
    const data = await readJson<ErrorBody>(response);
    assertOk(response, data, 'reservation activate');
  }

  /** Abandon a live reservation; nothing bound to it can ever activate. */
  async abandon(reservationId: string): Promise<void> {
    const response = await this._transport.authedFetch(
      `/api/v2/sdk/wallet/provisioning/reservations/${encodeURIComponent(reservationId)}`,
      { method: 'DELETE' },
    );
    const data = await readJson<ErrorBody>(response);
    assertOk(response, data, 'reservation abandon');
  }
}
