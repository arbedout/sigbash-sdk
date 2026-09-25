/**
 * Managed-organization relationship contracts: the server-readable
 * parent/child administrative relationship between organizations.
 *
 * The relationship records handles and chosen labels only — never wallet
 * plaintext. Parent membership is never a master decryption or signing
 * key; a parent gains wallet visibility or operational capability in a
 * child only by receiving explicit membership and capability grants into
 * that child. The server never creates a plaintext cross-child balance
 * or transaction index, and the relationship carries nothing about child
 * descriptors, balances, proposals, policy text, or audit contents.
 *
 * A child may be detached from the relationship without rotating its
 * Bitcoin wallet keys; any parent principals holding child capability
 * keys are offboarded by the child's normal capability-epoch rotation.
 *
 * These are JSON message shapes without a binary codec. If a server lane
 * needs to parse or validate one, the shape promotes into this module
 * (with the application-backend mirror added in the same release) rather
 * than being restated elsewhere — one canonical definition per contract.
 */

export const MANAGED_ORG_VIEW_VERSION = 1;

/** One child organization the parent administers. Labels are optional,
 * explicitly chosen administrative labels — never wallet names by
 * inference. */
export interface ManagedChildOrgEntryV1 {
  readonly child_org_id: string;
  readonly label?: string;
}

/**
 * The managed-organization relationship view: which children the parent
 * has been granted administration over, by handle. Aggregated views over
 * child wallets, where offered, are computed client-side from children
 * the logged-in user can independently decrypt.
 */
export interface ManagedOrgRelationshipViewV1 {
  readonly parent_org_id: string;
  readonly granted_children: readonly ManagedChildOrgEntryV1[];
}
