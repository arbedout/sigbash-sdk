/**
 * Locked system policy — the wallet-ownership clause every institutional
 * wallet enforces, structurally separate from the editable user policy.
 *
 *   FINAL_POLICY = AND(SYSTEM_WALLET_OWNERSHIP_REQKEY, USER_POLICY)
 *
 * The system clause is a descriptor-mode REQKEY atom: candidate signing
 * keys are derived from the SIGBASH_XPUB placeholder template at key
 * registration, and the WASM post-aggregation rebuild commits the depth-9
 * Merkle root over that candidate set (bound to the wallet's canonical
 * WalletDescriptorV1) into every relevant PathLeaf/PolicyRoot. Raw editing
 * operates on the user fragment only, and composition happens in this
 * module — no editor or UI path can reach the compiler without the AND
 * weld, so raw POET editing can never remove or weaken the system clause.
 *
 * The fragment is deeply frozen: immutable by construction, never part of
 * user-editable text.
 */

import type { PolicyNode, ConditionNode } from '../types';
import { ContractVersionError, u8be, concatBytes, utf8, taggedHash } from './encoding';
import { canonicalizePolicyRoot, type CanonicalPolicyAstV1 } from './policyAst';
import { computePolicyAstDigest, policyAstDigestToHex } from './policyEncoding';
import { WALLET_DESCRIPTOR_VERSION, type WalletDescriptorV1 } from './walletDescriptor';

export const SYSTEM_POLICY_VERSION = 1;

/**
 * Descriptor template carried by the system REQKEY atom. The placeholder
 * is replaced by the resolved Sigbash BIP-328 xpub at post-aggregation
 * rebuild; candidate keys are derived over the fixed range below.
 * MUST stay byte-identical to the template the WASM rebuild gadget and
 * signing-time sibling-path search expect — it is the shared derivation
 * input on both sides.
 */
export const SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE = 'tr(SIGBASH_XPUB/0/*)';

/** Matches the depth-9 REQKEY descriptor Merkle gadget's hard capacity. */
export const SYSTEM_REQKEY_DERIVATION_RANGE = 512;

export const SYSTEM_POLICY_TAG = 'SIGBASH/SYSTEM_POLICY/V1';

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const entry of Object.values(value as Record<string, unknown>)) {
      deepFreeze(entry);
    }
    Object.freeze(value);
  }
  return value;
}

/**
 * The locked wallet-ownership fragment for a canonical wallet. The POET
 * atom itself is wallet-invariant (the descriptor binding happens at
 * rebuild time on the WASM side); the descriptor argument asserts that the
 * wallet's canonical descriptor text carries the SIGBASH_XPUB placeholder
 * the rebuild resolves.
 */
export function systemWalletOwnershipFragment(descriptor: WalletDescriptorV1): ConditionNode {
  if (descriptor.version !== WALLET_DESCRIPTOR_VERSION) {
    throw new ContractVersionError(`system policy: unsupported wallet descriptor version ${descriptor.version}`);
  }
  if (!descriptor.receiveDescriptor.includes('SIGBASH_XPUB') || !descriptor.changeDescriptor.includes('SIGBASH_XPUB')) {
    throw new Error('system policy: wallet descriptors must carry the SIGBASH_XPUB placeholder');
  }
  return deepFreeze({
    type: 'condition',
    conditionType: 'REQKEY',
    conditionParams: {
      use_descriptor: true,
      descriptor_template: SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE,
      derivation_range: SYSTEM_REQKEY_DERIVATION_RANGE,
    },
  }) as ConditionNode;
}

/** The system clause as a canonical AST (digest target for version records). */
export function systemPolicyAst(descriptor: WalletDescriptorV1): CanonicalPolicyAstV1 {
  return canonicalizePolicyRoot(systemWalletOwnershipFragment(descriptor));
}

/**
 * Single canonical composition path: AND(system, user) with the system
 * clause as the first child. The user fragment must not carry its own
 * REQKEY condition — wallet ownership is exclusively a system clause, and
 * the condition vocabulary permits at most one descriptor-mode REQKEY per
 * policy with no other REQKEY beside it.
 */
export function composeEffectivePolicy(
  system: CanonicalPolicyAstV1,
  user: CanonicalPolicyAstV1,
): CanonicalPolicyAstV1 {
  assertNoUserReqkey(user.root);
  return canonicalizePolicyRoot({
    type: 'operator',
    operator: 'AND',
    children: [system.root, user.root],
  });
}

function assertNoUserReqkey(node: PolicyNode): void {
  if (node.type === 'condition') {
    if (node.conditionType === 'REQKEY') {
      throw new Error('user policy must not carry REQKEY conditions; wallet ownership is a system clause');
    }
    return;
  }
  for (const child of node.children) assertNoUserReqkey(child);
}

/** Digest of the locked system clause for the policy version record. */
export function computeSystemPolicyDigest(descriptor: WalletDescriptorV1): Uint8Array {
  return computePolicyAstDigest(systemPolicyAst(descriptor));
}

export function systemPolicyDigestHex(descriptor: WalletDescriptorV1): string {
  return policyAstDigestToHex(computeSystemPolicyDigest(descriptor));
}

/**
 * Digest of the effective combined policy AND(system, user) — the
 * commitment the compiled key material ultimately answers to.
 */
export function computeEffectivePolicyDigest(
  system: CanonicalPolicyAstV1,
  user: CanonicalPolicyAstV1,
): Uint8Array {
  return computePolicyAstDigest(composeEffectivePolicy(system, user));
}

export function effectivePolicyDigestHex(system: CanonicalPolicyAstV1, user: CanonicalPolicyAstV1): string {
  return policyAstDigestToHex(computeEffectivePolicyDigest(system, user));
}

/**
 * Standalone system-policy identity digest over the clause shape alone
 * (independent of any wallet), for registry/telemetry use where no wallet
 * descriptor exists yet.
 */
export function systemClauseIdentityDigestHex(): string {
  const preimage = concatBytes(u8be(SYSTEM_POLICY_VERSION), utf8(SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE));
  return policyAstDigestToHex(taggedHash(SYSTEM_POLICY_TAG, preimage));
}
