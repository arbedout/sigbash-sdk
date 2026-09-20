/**
 * Role presets and capability actions.
 *
 * Role presets are the assignment and display vocabulary; capability
 * actions are what authorization resolves. No runtime code branches on a
 * preset name for an authorization decision — a principal holds capability
 * actions, and the preset tables below are data, not control flow.
 *
 * Two currencies, deliberately separate:
 * - Capability groups (`./capability.ts`) are the encryption/possession
 *   currency. Possession of a group's epoch key is what lets a principal
 *   read or write that domain's ciphertext.
 * - Capability actions are the workflow permissions. A wallet-scoped or
 *   signing-scope action additionally requires possession of the mapped
 *   capability group, so a preset assignment alone never grants access to
 *   a wallet's plaintext — the grant event that delivers the epoch keys
 *   does.
 *
 * One human may hold multiple presets. Preset assignments live inside
 * encrypted organization state; the server never learns which wallet- or
 * workflow-scoped presets a member holds. The only server-known roles are
 * the org-global flags on the membership row (owner, security admin),
 * which the capability table in the application backend maps to org-global
 * actions — those two flags and no others are the server-visible role
 * surface.
 *
 * Preset assignments are JSON records inside encrypted state (the keyring
 * record precedent), validated by `parsePresetAssignment`. The org
 * governance settings record (`parseOrgGovernanceSettings`) carries the
 * explicit self-approval opt-in; a missing record parses to the default,
 * which denies self-approval.
 */

import {
  CAPABILITY_GROUP_AUDIT,
  CAPABILITY_GROUP_ORG_COMMON,
  CAPABILITY_GROUP_POLICY_GOVERNANCE,
  CAPABILITY_GROUP_SECURITY_RECOVERY,
  walletCapabilityGroupId,
} from './capability';
import { ContractVersionError } from './encoding';

export const ROLE_PRESET_VERSION = 1;
export const CAPABILITY_ACTION_VERSION = 1;

// ---------------------------------------------------------------------------
// Role presets
// ---------------------------------------------------------------------------

/** Org-global presets (ADR RBAC §org-global). */
export const ROLE_PRESET_ORG_OWNER = 'org-owner';
export const ROLE_PRESET_SECURITY_ADMIN = 'security-admin';
export const ROLE_PRESET_MANAGED_ORG_ADMIN = 'managed-org-admin';

/** Wallet-scoped and workflow presets (ADR RBAC §wallet-scoped). */
export const ROLE_PRESET_WALLET_ADMIN = 'wallet-admin';
export const ROLE_PRESET_POLICY_EDITOR = 'policy-editor';
export const ROLE_PRESET_POLICY_APPROVER = 'policy-approver';
export const ROLE_PRESET_TREASURY_OPERATOR = 'treasury-operator';
export const ROLE_PRESET_TX_APPROVER = 'tx-approver';
export const ROLE_PRESET_SIGNER = 'signer';
export const ROLE_PRESET_AUDITOR = 'auditor';

/** Narrow automation identity. Explicit grants only; confers no human approval. */
export const ROLE_PRESET_SERVICE_USER = 'service-user';

export const ROLE_PRESETS = [
  ROLE_PRESET_ORG_OWNER,
  ROLE_PRESET_SECURITY_ADMIN,
  ROLE_PRESET_MANAGED_ORG_ADMIN,
  ROLE_PRESET_WALLET_ADMIN,
  ROLE_PRESET_POLICY_EDITOR,
  ROLE_PRESET_POLICY_APPROVER,
  ROLE_PRESET_TREASURY_OPERATOR,
  ROLE_PRESET_TX_APPROVER,
  ROLE_PRESET_SIGNER,
  ROLE_PRESET_AUDITOR,
  ROLE_PRESET_SERVICE_USER,
] as const;

export type RolePreset = (typeof ROLE_PRESETS)[number];

/** Strict parse; unknown preset identifiers fail closed. */
export function parseRolePreset(value: string): RolePreset {
  if ((ROLE_PRESETS as readonly string[]).includes(value)) {
    return value as RolePreset;
  }
  throw new ContractVersionError(`RolePreset: unknown preset identifier "${value}"`);
}

// ---------------------------------------------------------------------------
// Capability actions
// ---------------------------------------------------------------------------

export const CAPABILITY_ORG_MEMBER_INVITE = 'org.member-invite';
export const CAPABILITY_ORG_MEMBER_REMOVE = 'org.member-remove';
export const CAPABILITY_ORG_ROLE_ASSIGN = 'org.role-assign';
export const CAPABILITY_ORG_SETTINGS_WRITE = 'org.settings-write';
export const CAPABILITY_ORG_SECURITY_SETTINGS_WRITE = 'org.security-settings-write';
export const CAPABILITY_ORG_RECOVERY_ASSIST = 'org.recovery-assist';
export const CAPABILITY_ORG_SYNC_ROTATE = 'org.sync-rotate';
export const CAPABILITY_ORG_MANAGED_PROVISION = 'org.managed-provision';

export const CAPABILITY_WALLET_CREATE = 'wallet.create';
export const CAPABILITY_WALLET_SIGNER_ADD = 'wallet.signer-add';
export const CAPABILITY_WALLET_ARCHIVE = 'wallet.archive';
export const CAPABILITY_WALLET_MIGRATE = 'wallet.migrate';
export const CAPABILITY_POLICY_DRAFT = 'policy.draft';
export const CAPABILITY_POLICY_APPROVE = 'policy.approve';
export const CAPABILITY_TX_PROPOSE = 'tx.propose';
export const CAPABILITY_TX_APPROVE = 'tx.approve';
export const CAPABILITY_AUDIT_READ = 'audit.read';

export const CAPABILITY_TX_SIGN = 'tx.sign';

export const CAPABILITY_ACTIONS = [
  CAPABILITY_ORG_MEMBER_INVITE,
  CAPABILITY_ORG_MEMBER_REMOVE,
  CAPABILITY_ORG_ROLE_ASSIGN,
  CAPABILITY_ORG_SETTINGS_WRITE,
  CAPABILITY_ORG_SECURITY_SETTINGS_WRITE,
  CAPABILITY_ORG_RECOVERY_ASSIST,
  CAPABILITY_ORG_SYNC_ROTATE,
  CAPABILITY_ORG_MANAGED_PROVISION,
  CAPABILITY_WALLET_CREATE,
  CAPABILITY_WALLET_SIGNER_ADD,
  CAPABILITY_WALLET_ARCHIVE,
  CAPABILITY_WALLET_MIGRATE,
  CAPABILITY_POLICY_DRAFT,
  CAPABILITY_POLICY_APPROVE,
  CAPABILITY_TX_PROPOSE,
  CAPABILITY_TX_APPROVE,
  CAPABILITY_AUDIT_READ,
  CAPABILITY_TX_SIGN,
] as const;

export type CapabilityActionId = (typeof CAPABILITY_ACTIONS)[number];

/**
 * Where an action is enforced. `org-global` actions resolve through the
 * server-known membership flags; `wallet-scoped` and `signing-scope`
 * actions resolve through capability-group possession inside encrypted
 * state, never through a server answer — the server holds no plaintext
 * semantics to answer with. The signing scope is its own class because the
 * binding enforcement for a signature is the wallet's signer plan and
 * selected tapleaf, not application possession alone.
 */
export type CapabilityActionScope = 'org-global' | 'wallet-scoped' | 'signing-scope';

export const CAPABILITY_ACTION_SCOPES: Readonly<
  Record<CapabilityActionId, CapabilityActionScope>
> = Object.freeze({
  [CAPABILITY_ORG_MEMBER_INVITE]: 'org-global',
  [CAPABILITY_ORG_MEMBER_REMOVE]: 'org-global',
  [CAPABILITY_ORG_ROLE_ASSIGN]: 'org-global',
  [CAPABILITY_ORG_SETTINGS_WRITE]: 'org-global',
  [CAPABILITY_ORG_SECURITY_SETTINGS_WRITE]: 'org-global',
  [CAPABILITY_ORG_RECOVERY_ASSIST]: 'org-global',
  [CAPABILITY_ORG_SYNC_ROTATE]: 'org-global',
  [CAPABILITY_ORG_MANAGED_PROVISION]: 'org-global',
  [CAPABILITY_WALLET_CREATE]: 'wallet-scoped',
  [CAPABILITY_WALLET_SIGNER_ADD]: 'wallet-scoped',
  [CAPABILITY_WALLET_ARCHIVE]: 'wallet-scoped',
  [CAPABILITY_WALLET_MIGRATE]: 'wallet-scoped',
  [CAPABILITY_POLICY_DRAFT]: 'wallet-scoped',
  [CAPABILITY_POLICY_APPROVE]: 'wallet-scoped',
  [CAPABILITY_TX_PROPOSE]: 'wallet-scoped',
  [CAPABILITY_TX_APPROVE]: 'wallet-scoped',
  [CAPABILITY_AUDIT_READ]: 'wallet-scoped',
  [CAPABILITY_TX_SIGN]: 'signing-scope',
});

/**
 * Actions that satisfy a human approval requirement. A service principal
 * is denied these by default, with no opt-in.
 */
export const HUMAN_APPROVAL_ACTIONS: readonly CapabilityActionId[] = Object.freeze([
  CAPABILITY_TX_APPROVE,
  CAPABILITY_POLICY_APPROVE,
]);

// ---------------------------------------------------------------------------
// Preset-to-capability mapping
// ---------------------------------------------------------------------------

/**
 * The preset-to-action table. This is the authoritative capability source;
 * every preset's set is exactly its ADR preset bullet list, and no preset
 * implies another's actions. The non-implication invariants (approver vs
 * signer, security admin vs spending, owner vs wallet-scoped work) hold in
 * this data and are asserted by the contract tests.
 */
export const PRESET_CAPABILITIES: Readonly<Record<RolePreset, readonly CapabilityActionId[]>> =
  Object.freeze({
    [ROLE_PRESET_ORG_OWNER]: [
      CAPABILITY_ORG_MEMBER_INVITE,
      CAPABILITY_ORG_MEMBER_REMOVE,
      CAPABILITY_ORG_ROLE_ASSIGN,
      CAPABILITY_ORG_SETTINGS_WRITE,
      CAPABILITY_ORG_SYNC_ROTATE,
    ],
    [ROLE_PRESET_SECURITY_ADMIN]: [
      CAPABILITY_ORG_SECURITY_SETTINGS_WRITE,
      CAPABILITY_ORG_RECOVERY_ASSIST,
      CAPABILITY_ORG_SYNC_ROTATE,
    ],
    // Enforcement surface is the managed-organization lane's: this preset
    // carries parent-level administration actions only, and every
    // wallet-scoped action stays out of its set — child grants are
    // explicit, never inherited from the parent relationship.
    [ROLE_PRESET_MANAGED_ORG_ADMIN]: [
      CAPABILITY_ORG_MANAGED_PROVISION,
      CAPABILITY_ORG_MEMBER_INVITE,
      CAPABILITY_ORG_ROLE_ASSIGN,
    ],
    [ROLE_PRESET_WALLET_ADMIN]: [
      CAPABILITY_WALLET_CREATE,
      CAPABILITY_WALLET_SIGNER_ADD,
      CAPABILITY_WALLET_ARCHIVE,
      CAPABILITY_WALLET_MIGRATE,
    ],
    [ROLE_PRESET_POLICY_EDITOR]: [CAPABILITY_POLICY_DRAFT],
    [ROLE_PRESET_POLICY_APPROVER]: [CAPABILITY_POLICY_APPROVE],
    [ROLE_PRESET_TREASURY_OPERATOR]: [CAPABILITY_TX_PROPOSE],
    [ROLE_PRESET_TX_APPROVER]: [CAPABILITY_TX_APPROVE],
    [ROLE_PRESET_SIGNER]: [CAPABILITY_TX_SIGN],
    [ROLE_PRESET_AUDITOR]: [CAPABILITY_AUDIT_READ],
    // Narrow automation: the preset alone confers no action. Automation
    // capabilities attach only through explicit capability grants, and the
    // human-approval actions are denied to service principals regardless
    // of grants.
    [ROLE_PRESET_SERVICE_USER]: [],
  });

// ---------------------------------------------------------------------------
// Preset-to-capability-group mapping
// ---------------------------------------------------------------------------

/**
 * The org-level capability groups each preset receives at grant time.
 * These are the groups wrapped to the member when the assignment is made;
 * a wallet-scoped assignment adds that wallet's group on top. Groups are
 * the possession currency: this table decides what a member can decrypt,
 * never what they may do — the action table above decides that.
 *
 * The org owner receives org-common and nothing else: no automatic wallet
 * decryption, no audit bypass. The service user receives nothing here —
 * every group a service principal holds is an explicit grant.
 */
export const PRESET_ORG_GROUPS: Readonly<Record<RolePreset, readonly string[]>> = Object.freeze({
  [ROLE_PRESET_ORG_OWNER]: [CAPABILITY_GROUP_ORG_COMMON],
  [ROLE_PRESET_SECURITY_ADMIN]: [CAPABILITY_GROUP_ORG_COMMON, CAPABILITY_GROUP_SECURITY_RECOVERY],
  [ROLE_PRESET_MANAGED_ORG_ADMIN]: [CAPABILITY_GROUP_ORG_COMMON],
  [ROLE_PRESET_WALLET_ADMIN]: [CAPABILITY_GROUP_ORG_COMMON],
  [ROLE_PRESET_POLICY_EDITOR]: [CAPABILITY_GROUP_ORG_COMMON, CAPABILITY_GROUP_POLICY_GOVERNANCE],
  [ROLE_PRESET_POLICY_APPROVER]: [
    CAPABILITY_GROUP_ORG_COMMON,
    CAPABILITY_GROUP_POLICY_GOVERNANCE,
  ],
  [ROLE_PRESET_TREASURY_OPERATOR]: [CAPABILITY_GROUP_ORG_COMMON],
  [ROLE_PRESET_TX_APPROVER]: [CAPABILITY_GROUP_ORG_COMMON],
  [ROLE_PRESET_SIGNER]: [CAPABILITY_GROUP_ORG_COMMON],
  [ROLE_PRESET_AUDITOR]: [CAPABILITY_GROUP_ORG_COMMON, CAPABILITY_GROUP_AUDIT],
  [ROLE_PRESET_SERVICE_USER]: [],
});

/** Assignment scope of one preset: the whole organization or one wallet. */
export type PresetScope = { readonly kind: 'org' } | { readonly kind: 'wallet'; readonly walletClientId: string };

/**
 * Resolve the capability groups one preset assignment wraps to its
 * subject: the preset's org-level groups plus, for a wallet-scoped
 * assignment, that wallet's group. This function is the single canonical
 * source of the preset-to-group mapping; grant flows import it and never
 * re-declare their own table. Parent-level or org-scope assignments never
 * imply any wallet group — wallet groups arrive only through a
 * wallet-scoped assignment or an explicit grant.
 */
export function capabilityGroupsForPreset(preset: RolePreset, scope: PresetScope): string[] {
  parseRolePreset(preset);
  const groups = new Set(PRESET_ORG_GROUPS[preset]);
  if (scope.kind === 'wallet') {
    groups.add(walletCapabilityGroupId(scope.walletClientId));
  }
  return [...groups].sort();
}

// ---------------------------------------------------------------------------
// Preset assignment records (encrypted state)
// ---------------------------------------------------------------------------

/** One preset assignment record, stored inside encrypted organization state. */
export interface PresetAssignment {
  readonly preset: RolePreset;
  readonly scope: PresetScope;
  /** Subject user id (32-byte hex, the client user id). */
  readonly subjectUserId: string;
  /** Assigning user id, or null for the founding owner assignment. */
  readonly assignedByUserId: string | null;
  readonly assignedAtMs: number;
}

const USER_ID_PATTERN = /^[0-9a-f]{32}$/;

function parseUserId(value: unknown, field: string): string {
  if (typeof value !== 'string' || !USER_ID_PATTERN.test(value)) {
    throw new ContractVersionError(`PresetAssignment: ${field} is not a user id`);
  }
  return value;
}

/**
 * Strict parse of one assignment record. Structural faults fail closed:
 * an assignment this parser rejects cannot silently become an authorization.
 */
export function parsePresetAssignment(value: unknown): PresetAssignment {
  if (typeof value !== 'object' || value === null) {
    throw new ContractVersionError('PresetAssignment: record is not an object');
  }
  const record = value as Record<string, unknown>;
  const preset = parseRolePreset(record['preset'] as string);
  const rawScope = record['scope'];
  let scope: PresetScope;
  if (
    typeof rawScope === 'object' &&
    rawScope !== null &&
    (rawScope as Record<string, unknown>)['kind'] === 'wallet'
  ) {
    const walletClientId = (rawScope as Record<string, unknown>)['walletClientId'];
    if (
      typeof walletClientId !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(walletClientId)
    ) {
      throw new ContractVersionError('PresetAssignment: wallet scope is not a wallet client id');
    }
    scope = { kind: 'wallet', walletClientId: walletClientId.toLowerCase() };
  } else if (
    typeof rawScope === 'object' &&
    rawScope !== null &&
    (rawScope as Record<string, unknown>)['kind'] === 'org'
  ) {
    scope = { kind: 'org' };
  } else {
    throw new ContractVersionError('PresetAssignment: unknown scope kind');
  }
  const assignedBy = record['assignedByUserId'];
  if (assignedBy !== null && assignedBy !== undefined) {
    parseUserId(assignedBy, 'assignedByUserId');
  }
  if (
    typeof record['assignedAtMs'] !== 'number' ||
    !Number.isSafeInteger(record['assignedAtMs']) ||
    record['assignedAtMs'] < 0
  ) {
    throw new ContractVersionError('PresetAssignment: assignedAtMs is not a safe timestamp');
  }
  return {
    preset,
    scope,
    subjectUserId: parseUserId(record['subjectUserId'], 'subjectUserId'),
    assignedByUserId: assignedBy == null ? null : (assignedBy as string),
    assignedAtMs: record['assignedAtMs'] as number,
  };
}

// ---------------------------------------------------------------------------
// Organization governance settings (encrypted state)
// ---------------------------------------------------------------------------

/**
 * The organization's governance settings, stored inside encrypted
 * organization state. `selfApprovalExplicitlyEnabled` is the single
 * explicit opt-in that permits a proposer to satisfy their own approval
 * requirement (single-person mode). It is never inferred from member
 * count and never leaves the encrypted state — the server never sees this
 * record.
 */
export interface OrgGovernanceSettings {
  readonly selfApprovalExplicitlyEnabled: boolean;
}

/** The fail-closed default: self-approval is denied until explicitly enabled. */
export const DEFAULT_ORG_GOVERNANCE_SETTINGS: OrgGovernanceSettings = Object.freeze({
  selfApprovalExplicitlyEnabled: false,
});

/**
 * Strict parse of the governance settings record. A missing record parses
 * to the default (deny); an invalid record fails closed with the default's
 * decision rather than trusting unknown fields.
 */
export function parseOrgGovernanceSettings(value: unknown): OrgGovernanceSettings {
  if (value === undefined || value === null) {
    return DEFAULT_ORG_GOVERNANCE_SETTINGS;
  }
  if (typeof value !== 'object') {
    return DEFAULT_ORG_GOVERNANCE_SETTINGS;
  }
  const record = value as Record<string, unknown>;
  if (typeof record['selfApprovalExplicitlyEnabled'] !== 'boolean') {
    throw new ContractVersionError('OrgGovernanceSettings: selfApprovalExplicitlyEnabled is not a boolean');
  }
  return Object.freeze({
    selfApprovalExplicitlyEnabled: record['selfApprovalExplicitlyEnabled'],
  });
}
