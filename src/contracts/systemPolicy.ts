/**
 * Locked system policy — the wallet-ownership clause every institutional
 * wallet enforces, structurally separate from the editable user policy.
 *
 *   FINAL_POLICY = AND(SYSTEM_WALLET_OWNERSHIP_REQKEY, USER_POLICY)
 *
 * The system clause is a descriptor-mode REQKEY atom carrying the
 * wallet-ownership REQKEY template payload (the "sigbashwd1:" form): the
 * wallet's canonical encoding with the single Sigbash signer's xpub
 * replaced by the SIGBASH_XPUB placeholder. The WASM post-aggregation
 * rebuild resolves the placeholder and commits the depth-9 Merkle root
 * over the full 256-receive + 256-change candidate universe — the
 * derivation range below — into every relevant PathLeaf/PolicyRoot. Raw
 * editing operates on the user fragment only, and composition happens in
 * this module — no editor or UI path can reach the compiler without the
 * AND weld, so raw POET editing can never remove or weaken the system
 * clause.
 *
 * The fragment is deeply frozen: immutable by construction, never part of
 * user-editable text. The legacy "tr(SIGBASH_XPUB/0/*)" descriptor
 * template stays valid for the webapp flow's own policies, but it is
 * never a valid system clause: it commits a single unbounded receive
 * branch, which would exclude every change index and make receive indices
 * beyond the wallet universe provable. Composition rejects any system
 * atom that does not carry the wallet-template payload over the full
 * derivation universe.
 */

import type { PolicyNode, ConditionNode } from '../types';
import { u8be, u32be, concatBytes, utf8, taggedHash } from './encoding';
import { canonicalizePolicyRoot, type CanonicalPolicyAstV1 } from './policyAst';
import { computePolicyAstDigest, policyAstDigestToHex } from './policyEncoding';

export const SYSTEM_POLICY_VERSION = 1;

/**
 * Descriptor template of the legacy webapp REQKEY mode. Kept exported
 * only as the rejection anchor for the composed system clause: a system
 * atom carrying this template commits a single unbounded receive branch
 * and is rejected by composition.
 */
export const SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE = 'tr(SIGBASH_XPUB/0/*)';

/** Matches the depth-9 REQKEY descriptor Merkle gadget's hard capacity. */
export const SYSTEM_REQKEY_DERIVATION_RANGE = 512;

/**
 * Marks a descriptor_template value as a wallet-ownership REQKEY payload.
 * Byte-shared with the WASM lane, which dispatches on this exact prefix;
 * the canonical TypeScript home is here because composition must tell the
 * wallet-template mode apart from the legacy descriptor form fail-closed.
 */
export const WALLET_REQKEY_TEMPLATE_PREFIX = 'sigbashwd1:';

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
 * The locked wallet-ownership fragment: a descriptor-mode REQKEY atom over
 * the wallet-ownership REQKEY template payload. The payload is produced by
 * the wallet lane's system-policy template builder, which shape-validates
 * the template against this clause's derivation-range contract before any
 * registration can commit it.
 */
export function systemWalletOwnershipFragment(reqkeyTemplatePayload: string): ConditionNode {
  if (reqkeyTemplatePayload.length === 0) {
    throw new Error('system policy: the wallet-ownership REQKEY template payload is required');
  }
  if (!reqkeyTemplatePayload.startsWith(WALLET_REQKEY_TEMPLATE_PREFIX)) {
    throw new Error('system policy: the system clause carries the wallet-ownership REQKEY template payload, never the legacy descriptor form');
  }
  // Structural payload sanity only: the canonical encoding is prefix-tagged
  // hex. Full shape validation (placeholder placement, signer sets,
  // derivation-range contract) belongs to the wallet lane's template
  // validator, which runs at rebuild and at signing time.
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(reqkeyTemplatePayload.slice(WALLET_REQKEY_TEMPLATE_PREFIX.length))) {
    throw new Error('system policy: the wallet-ownership REQKEY template payload body must be hex of the canonical wallet encoding');
  }
  return deepFreeze({
    type: 'condition',
    conditionType: 'REQKEY',
    conditionParams: {
      use_descriptor: true,
      descriptor_template: reqkeyTemplatePayload,
      derivation_range: SYSTEM_REQKEY_DERIVATION_RANGE,
    },
  }) as ConditionNode;
}

/** The system clause as a canonical AST (digest target for version records). */
export function systemPolicyAst(reqkeyTemplatePayload: string): CanonicalPolicyAstV1 {
  return canonicalizePolicyRoot(systemWalletOwnershipFragment(reqkeyTemplatePayload));
}

function assertSystemReqkeyAtom(node: PolicyNode): void {
  if (node.type !== 'condition' || node.conditionType !== 'REQKEY') {
    throw new Error('system policy: the system clause is the wallet-ownership REQKEY atom, alone and unconditional');
  }
  const params = node.conditionParams as Record<string, unknown>;
  const template = params['descriptor_template'];
  if (typeof template !== 'string' || !template.startsWith(WALLET_REQKEY_TEMPLATE_PREFIX)) {
    throw new Error('system policy: the system REQKEY atom must carry the wallet-ownership template payload, never the legacy descriptor form');
  }
  if (params['derivation_range'] !== SYSTEM_REQKEY_DERIVATION_RANGE) {
    throw new Error(`system policy: the wallet template commits the full ${SYSTEM_REQKEY_DERIVATION_RANGE}-candidate universe; no other derivation range has deterministic meaning`);
  }
}

/**
 * Single canonical composition path: AND(system, user) with the system
 * clause as the first child. The system clause must be the wallet-template
 * REQKEY atom over the full derivation universe, and the user fragment
 * must not carry its own REQKEY condition — wallet ownership is
 * exclusively a system clause, and the condition vocabulary permits at
 * most one descriptor-mode REQKEY per policy with no other REQKEY beside
 * it.
 */
export function composeEffectivePolicy(
  system: CanonicalPolicyAstV1,
  user: CanonicalPolicyAstV1,
): CanonicalPolicyAstV1 {
  assertSystemReqkeyAtom(system.root);
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
export function computeSystemPolicyDigest(reqkeyTemplatePayload: string): Uint8Array {
  return computePolicyAstDigest(systemPolicyAst(reqkeyTemplatePayload));
}

export function systemPolicyDigestHex(reqkeyTemplatePayload: string): string {
  return policyAstDigestToHex(computeSystemPolicyDigest(reqkeyTemplatePayload));
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
 * template exists yet: the wallet-template REQKEY atom over the full
 * derivation universe.
 */
export function systemClauseIdentityDigestHex(): string {
  const preimage = concatBytes(
    u8be(SYSTEM_POLICY_VERSION),
    utf8(WALLET_REQKEY_TEMPLATE_PREFIX),
    u32be(SYSTEM_REQKEY_DERIVATION_RANGE),
  );
  return policyAstDigestToHex(taggedHash(SYSTEM_POLICY_TAG, preimage));
}
