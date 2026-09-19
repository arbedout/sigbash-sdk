/**
 * Capability-group identifiers and encryption epochs.
 *
 * Capability domains are the minimum set required by the organization
 * encryption model. A group identifier is a canonical UTF-8 string; the
 * wallet-scoped group embeds the opaque client wallet id chosen at wallet
 * creation (never the deterministic wallet fingerprint). Each group
 * carries a monotonically increasing epoch; removal of a member advances
 * every epoch that member possessed.
 */

import { ContractVersionError, concatBytes, u64be, utf8 } from './encoding';

export const CAPABILITY_EPOCH_VERSION = 1;

export const CAPABILITY_GROUP_ORG_COMMON = 'org-common';
export const CAPABILITY_GROUP_POLICY_GOVERNANCE = 'policy-governance';
export const CAPABILITY_GROUP_AUDIT = 'audit';
export const CAPABILITY_GROUP_SECURITY_RECOVERY = 'security-recovery';

export const CAPABILITY_GROUP_WALLET_PREFIX = 'wallet:';

export type CapabilityGroupId =
  | typeof CAPABILITY_GROUP_ORG_COMMON
  | typeof CAPABILITY_GROUP_POLICY_GOVERNANCE
  | typeof CAPABILITY_GROUP_AUDIT
  | typeof CAPABILITY_GROUP_SECURITY_RECOVERY
  | (typeof CAPABILITY_GROUP_WALLET_PREFIX & { readonly walletScope: unique symbol });

/**
 * Build the canonical identifier for a wallet-scoped capability group.
 * The wallet client id is an opaque random UUID string from encrypted
 * state; it is never the deterministic wallet fingerprint.
 */
export function walletCapabilityGroupId(walletClientId: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(walletClientId)) {
    throw new Error('wallet capability group requires a UUID wallet client id');
  }
  return `${CAPABILITY_GROUP_WALLET_PREFIX}${walletClientId.toLowerCase()}`;
}

/** Strict parse; unknown group shapes fail closed. */
export function parseCapabilityGroupId(value: string): string {
  if (
    value === CAPABILITY_GROUP_ORG_COMMON ||
    value === CAPABILITY_GROUP_POLICY_GOVERNANCE ||
    value === CAPABILITY_GROUP_AUDIT ||
    value === CAPABILITY_GROUP_SECURITY_RECOVERY
  ) {
    return value;
  }
  if (value.startsWith(CAPABILITY_GROUP_WALLET_PREFIX)) {
    const walletClientId = value.substring(CAPABILITY_GROUP_WALLET_PREFIX.length);
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(walletClientId)) {
      return value;
    }
  }
  throw new ContractVersionError(`CapabilityGroupId: unknown group identifier "${value}"`);
}

/** Epoch wire encoding: capability group UTF-8 bytes || u64be epoch. */
export function encodeCapabilityEpoch(groupId: string, epoch: number): Uint8Array {
  parseCapabilityGroupId(groupId);
  if (!Number.isInteger(epoch) || epoch < 1 || epoch > 0xffffffffffffffff) {
    throw new RangeError('capability epoch must be a positive 64-bit integer');
  }
  return concatBytes(utf8(groupId), u64be(epoch));
}
