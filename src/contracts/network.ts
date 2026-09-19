/**
 * NetworkId — the explicit Bitcoin network property of every wallet.
 *
 * Network is never inferred from extended-key version bytes or address
 * prefixes (ADR section 14: Signet and mainnet are explicit wallet
 * properties). The only supported networks are signet and mainnet; testnet
 * exists only when explicitly enabled by a later reviewed change.
 */

import { ContractVersionError } from './encoding';

export const NETWORK_ID_VERSION = 1;

export type NetworkId = 'signet' | 'mainnet';

/** Explicit wire codes; no numeric adjacency carries any meaning. */
export const NETWORK_CODES = {
  signet: 0x01,
  mainnet: 0x02,
} as const satisfies Record<NetworkId, number>;

const CODE_TO_NETWORK: Record<number, NetworkId> = {
  [NETWORK_CODES.signet]: 'signet',
  [NETWORK_CODES.mainnet]: 'mainnet',
};

export function encodeNetworkId(network: NetworkId): number {
  return NETWORK_CODES[network];
}

/**
 * Decode a network code. Throws on any value that is not an exact,
 * explicitly assigned network code — ambiguous networks fail closed.
 */
export function decodeNetworkId(code: number): NetworkId {
  const network = CODE_TO_NETWORK[code];
  if (network === undefined) {
    throw new ContractVersionError(`NetworkId: unknown network code 0x${code.toString(16)}`);
  }
  return network;
}

/** Strict textual parse for API/UI surfaces. No aliases, no fallback. */
export function parseNetworkId(value: string): NetworkId {
  if (value === 'signet' || value === 'mainnet') {
    return value;
  }
  throw new ContractVersionError(`NetworkId: unknown network "${value}"`);
}
