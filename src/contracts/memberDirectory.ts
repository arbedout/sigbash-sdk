/**
 * Member-directory contracts: the server-readable membership facts of one
 * organization's active roster.
 *
 * The directory is the ADR-acknowledged server-visible membership
 * inventory: user id, normalized account email, the two org-global role
 * flags the membership row carries, and the membership status. It is an
 * authorization-scoped read, not a privacy surface — and it is also a
 * closed inventory: no key material, no session fact, no mailbox or
 * recovery pointer, and no wallet- or workflow-scoped role ever appears.
 * Wallet-scoped presets live inside encrypted organization state; the
 * server cannot express them and this shape cannot carry them.
 *
 * Only active members enumerate. Departed members are outside the
 * directory's purpose (grant delivery and the live roster); removal
 * history is a separate surface decision.
 *
 * These are JSON message shapes without a binary codec. If a server lane
 * needs to parse or validate one, the shape promotes into this module
 * (with the application-backend mirror added in the same release) rather
 * than being restated elsewhere — one canonical definition per contract.
 */

export const MEMBER_DIRECTORY_VIEW_VERSION = 1;

/** One active member of an organization, by handle and server-known
 * membership facts. The email is the account's normalized address, the
 * same fact the invitation list carries; the flags are the only
 * server-known role surface. */
export interface OrgMemberEntryV1 {
  readonly user_id: string;
  readonly email: string;
  readonly is_owner: boolean;
  readonly is_security_admin: boolean;
  readonly status: 'active';
}

/**
 * The member-directory view: who is in the organization, for the
 * capability-holding caller. Grant delivery resolves recipients from the
 * `user_id` handles; human-facing surfaces correlate the invitation list
 * through `email`.
 */
export interface OrgMemberDirectoryViewV1 {
  readonly org_id: string;
  readonly members: readonly OrgMemberEntryV1[];
}
