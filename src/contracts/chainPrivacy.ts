/**
 * Chain-data privacy contracts: the configurable chain endpoint record
 * and the broadcast result shapes.
 *
 * The browser is the only component that sends addresses, txids, and raw
 * transactions to the chain provider. The default provider origin is
 * fixed and the UI discloses that the provider observes queried
 * addresses, network metadata, and broadcast transactions; the same
 * disclosure extends to a user-configured endpoint.
 *
 * The endpoint scope is per-org — the owner-ruled scope for configurable
 * endpoints. The scope field is the extension point: adding another scope
 * value is a version-bumped contract change, not an unversioned option.
 * A configured endpoint accepts only exact validated origins and fails
 * closed when unconfigured or invalid; an unconfigured organization uses
 * the fixed default origin byte-identically.
 *
 * A broadcast result is the transaction id only. Rebroadcast is
 * idempotent, and a downloaded-but-not-broadcast transaction is never
 * shown as sent — broadcast state follows the transaction proposal state
 * machine, never this result alone.
 *
 * These are JSON message shapes without a binary codec. If a server lane
 * needs to parse or validate one, the shape promotes into this module
 * (with the application-backend mirror added in the same release) rather
 * than being restated elsewhere — one canonical definition per contract.
 */

import { ContractVersionError } from './encoding';

export const CHAIN_ENDPOINT_CONFIG_VERSION = 1;
export const BROADCAST_VARIANT_VERSION = 1;

/**
 * The scope a configured endpoint binds to. Per-org is the ruled scope;
 * the union stays a single member until a ruled extension arrives, and
 * any extension is a version bump.
 */
export type ChainEndpointScope = 'org';

export const CHAIN_ENDPOINT_SCOPE_CODES = {
  org: 0x01,
} as const satisfies Record<ChainEndpointScope, number>;

const CODE_TO_ENDPOINT_SCOPE: Record<number, ChainEndpointScope> = Object.fromEntries(
  Object.entries(CHAIN_ENDPOINT_SCOPE_CODES).map(([scope, code]) => [code, scope as ChainEndpointScope]),
);

/**
 * The configured chain endpoint record for one organization. The origin
 * is an exact validated origin — never a URL prefix or wildcard; the
 * disclosure acknowledgement records that the operator accepted the
 * provider-observation disclosure for this endpoint.
 */
export interface ChainEndpointConfigV1 {
  readonly scope: ChainEndpointScope;
  readonly org_id: string;
  readonly endpoint_origin: string;
  readonly disclosure_acknowledged: boolean;
}

export type BroadcastVariant = 'default_endpoint' | 'operator_configured_endpoint' | 'download_self_broadcast';

/**
 * Wire codes for broadcast variants. Codes are explicitly assigned and
 * never contiguous-by-convention; unknown codes fail closed.
 */
export const BROADCAST_VARIANT_CODES = {
  default_endpoint: 0x01,
  operator_configured_endpoint: 0x02,
  download_self_broadcast: 0x03,
} as const satisfies Record<BroadcastVariant, number>;

const CODE_TO_BROADCAST_VARIANT: Record<number, BroadcastVariant> = Object.fromEntries(
  Object.entries(BROADCAST_VARIANT_CODES).map(([variant, code]) => [code, variant as BroadcastVariant]),
);

/**
 * The result of one broadcast attempt: the transaction id of the
 * accepted broadcast. Downloader self-broadcast surfaces the same shape
 * after the user's own successful submission.
 */
export interface BroadcastResultV1 {
  readonly txid: string;
}

export function encodeChainEndpointScope(scope: ChainEndpointScope): number {
  return CHAIN_ENDPOINT_SCOPE_CODES[scope];
}

/** Fail closed on unknown endpoint-scope codes. */
export function decodeChainEndpointScope(code: number): ChainEndpointScope {
  const scope = CODE_TO_ENDPOINT_SCOPE[code];
  if (scope === undefined) {
    throw new ContractVersionError(`ChainEndpointScope: unknown code 0x${code.toString(16)}`);
  }
  return scope;
}

export function encodeBroadcastVariant(variant: BroadcastVariant): number {
  return BROADCAST_VARIANT_CODES[variant];
}

/** Fail closed on unknown broadcast-variant codes. */
export function decodeBroadcastVariant(code: number): BroadcastVariant {
  const variant = CODE_TO_BROADCAST_VARIANT[code];
  if (variant === undefined) {
    throw new ContractVersionError(`BroadcastVariant: unknown code 0x${code.toString(16)}`);
  }
  return variant;
}
