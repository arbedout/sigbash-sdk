/**
 * Policy template catalogue with enforcement-class metadata.
 *
 * Design partners configure policy through templates, never raw POET, and
 * every template states which layer enforces it: hard cryptographic/state
 * enforcement committed into the policy AST, or an organization workflow
 * rule that produces no POET atoms at all. A governance rule that looks
 * like a chain guarantee is exactly the confusion that loses funds, so the
 * class is machine-readable metadata bound to the exact canonical output
 * each template produces.
 *
 * The catalogue is bounded by the soundness condition census
 * (docs/soundness_condition_census_summary.md, row-level verdicts in
 * docs/soundness_condition_census.tsv). The census table below is asserted
 * row-for-row against that document by the test suite, and the module-init
 * invariant rejects any template that would grade a NOT SOUND or disabled
 * condition as hard enforcement. Condition types graded NOT SOUND at the
 * census head — most notably OUTPUT_VALUE, whose per-output comparator
 * semantics do not mean "maximum external spend" — cannot appear in a hard
 * template, and no template wording implies per-output semantics equal
 * external-spend-total semantics. A descriptor-aware hard spend limit is a
 * separately audited future condition, not a template here.
 *
 * The negated destination-blocklist construction uses the remediated
 * in-circuit set negation: at most one negated condition family per
 * policy, a family slot never mixes positive and negated content, and
 * negated membership is placed fail-closed. The template negates an
 * ANY-selector atom — "no output is in the banned set" — because negating
 * an ALL-selector atom would only require one clean output and would let a
 * transaction carry a banned destination beside it.
 */

import type { ConditionNode, PolicyNode } from '../types';
import { ContractVersionError } from './encoding';
import { parseNetworkId, type NetworkId } from './network';
import { canonicalizePolicyRoot, canonicalJson, type CanonicalPolicyAstV1 } from './policyAst';
import { canonicalPolicyAstToHex, policyAstDigestHex } from './policyEncoding';
import type { PolicyEnforcementClass } from './policy';

/** Version of the catalogue metadata contract itself. */
export const POLICY_TEMPLATE_CATALOGUE_VERSION = 1;

/**
 * Verdicts exactly as the soundness census grades them. Ungraded
 * conditions are not listed here; they live in DISABLED_CONDITION_TYPES or
 * are unknown constructs.
 */
export type SoundnessCensusVerdict = 'sound' | 'sound_with_conditions' | 'not_sound' | 'removed';

export interface CensusVerdictRecord {
  verdict: SoundnessCensusVerdict;
  /** One-line census basis, without workflow provenance identifiers. */
  basis: string;
  /**
   * Present only when a condition graded NOT SOUND still has a
   * specifically reviewed usable form after remediation. Names those
   * forms; the selection gate enforces them shape-exactly. A census row
   * without this field is unusable as hard enforcement in any form.
   */
  hardAllowedForms?: string;
}

/**
 * The census verdict table, one row per graded condition. The test suite
 * asserts this row-for-row against the census summary document; when the
 * census updates, this table and the catalogue templates must be reviewed
 * together in the same change.
 */
export const SOUNDNESS_CENSUS_VERDICTS: Readonly<Record<string, CensusVerdictRecord>> = Object.freeze({
  TX_VERSION: { verdict: 'sound', basis: 'Derivation-bound and tamper-tested.' },
  TX_LOCKTIME: { verdict: 'sound', basis: 'Derivation-bound and tamper-tested.' },
  TX_INPUT_COUNT: {
    verdict: 'sound_with_conditions',
    basis: 'Aggregate-gap conditions inherited; per-assignment distinct-bound gate added.',
  },
  TX_OUTPUT_COUNT: {
    verdict: 'sound_with_conditions',
    basis: 'Aggregate-gap conditions inherited; per-assignment distinct-bound gate added.',
  },
  TX_FEE_ABSOLUTE: {
    verdict: 'sound_with_conditions',
    basis: 'Aggregate-gap conditions inherited; per-assignment distinct-bound gate added.',
  },
  DERIVED_NO_NEW_OUTPUTS: {
    verdict: 'sound_with_conditions',
    basis: 'The EQ-0 direction is unenforceable; only requiring the condition true is sound.',
  },
  REQKEY: {
    verdict: 'sound_with_conditions',
    basis: 'Residuals from the key-request chain; wallet ownership is the locked system clause and user policies must not carry it.',
  },
  INPUT_VALUE: {
    verdict: 'sound_with_conditions',
    basis: 'INDEX selector target pinning is host-only; multi-instance per-input range slots collapse last-write-wins.',
  },
  INPUT_SEQUENCE: {
    verdict: 'sound_with_conditions',
    basis: 'Same multi-instance per-input slot-collapse class as INPUT_VALUE.',
  },
  INPUT_SOURCE_IS_IN_SETS: {
    verdict: 'not_sound',
    basis: 'Negated form vacuous at census head (one-directional atom anchoring); remediated in-circuit negation now covers the family.',
  },
  OUTPUT_VALUE: {
    verdict: 'not_sound',
    basis: 'Chunk comparator thresholds are steerable through a witness-only salt pad; per-output semantics never equal external-spend-total semantics. Amounts themselves remain soundly bound.',
  },
  OUTPUT_DEST_IS_IN_SETS: {
    verdict: 'not_sound',
    basis: 'Negated form vacuous at census head; positive form sound after the remediation chain, and the remediated in-circuit negation is the enforced blocklist construction.',
    hardAllowedForms:
      'Positive-form set membership (any selector) and the remediated negated blocklist: NOT over an ANY-selector atom, one negated family per policy, no positive/negated mixing, fail-closed placement.',
  },
  OUTPUT_OP_RETURN: {
    verdict: 'not_sound',
    basis: 'Negated form vacuous at census head; positive form sound.',
  },
  OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT: {
    verdict: 'not_sound',
    basis: 'BIP-443 sentinel fail-open; the halt stands at census head.',
  },
  INPUT_COMMITTED_DATA_VERIFY: {
    verdict: 'not_sound',
    basis: 'Same BIP-443 registration halt, symmetric side.',
  },
  TX_TEMPLATE_HASH_MATCHES: {
    verdict: 'sound_with_conditions',
    basis: 'Prior commitment gap does not reproduce at census head; the NOT direction is unenforceable.',
  },
  COUNT_BASED_CONSTRAINT: {
    verdict: 'sound_with_conditions',
    basis: 'Bound in-circuit with the spend state server-authoritative; the forge check is unforgeable under the hostile-client model.',
  },
  TIME_BASED_CONSTRAINT: {
    verdict: 'sound_with_conditions',
    basis: 'Holds when the host runs the honest client build; drift gates bound clock error, not window honesty.',
  },
  MATCH_ARK_INTENT: {
    verdict: 'removed',
    basis: 'Condition withdrawn; no longer authorable.',
  },
  MATCH_ARK_CHECKPOINT: {
    verdict: 'sound_with_conditions',
    basis: 'Anchor union dropped on both sides in lockstep; committed set is the static-ledger intersection and the swap-at-first-output shape fails membership.',
  },
  MATCH_ARK_FORFEIT: {
    verdict: 'sound_with_conditions',
    basis: 'Destination gate fails closed; value pins and live-path tamper legs are tracked census drift.',
  },
});

/** Number of condition rows the census graded. */
export const CENSUS_GRADED_CONDITION_COUNT = 21;

/**
 * Condition types present in the authoring registry but excluded from
 * grading — disabled slots with no enforced preimage. They are never
 * selectable as hard enforcement.
 */
export const DISABLED_CONDITION_TYPES: readonly string[] = Object.freeze([
  'DERIVED_SIGHASH_TYPE',
  'DERIVED_RBF_ENABLED',
  'DERIVED_IS_COINJOIN_LIKE',
  'DERIVED_IS_PAYJOIN_LIKE',
  'DERIVED_IS_CONSOLIDATION',
  'INPUT_SCRIPT_TYPE',
  'INPUT_SIGHASH_TYPE',
  'OUTPUT_SCRIPT_TYPE',
]);

/** Condition families that carry a negated form in the engine. */
const NEGATABLE_FAMILIES: Readonly<Record<string, string>> = Object.freeze({
  INPUT_SOURCE_IS_IN_SETS: 'input_source_sets',
  OUTPUT_DEST_IS_IN_SETS: 'output_dest_sets',
  OUTPUT_OP_RETURN: 'op_return',
  REQKEY: 'reqkey',
});

// ---------------------------------------------------------------------------
// Template descriptors
// ---------------------------------------------------------------------------

export interface PolicyTemplateParamSpecV1 {
  name: string;
  type: 'number' | 'number[]' | 'string' | 'string[]' | 'boolean' | 'object';
  description: string;
  required: boolean;
}

interface PolicyTemplateCommonV1 {
  /** Stable template slug used in selections and version records. */
  templateId: string;
  templateVersion: number;
  title: string;
  summary: string;
  /** UI tier: advanced templates carry extra explanation obligations. */
  tier: 'standard' | 'advanced';
  /** Exact condition types the template emits; empty for governance. */
  conditionTypes: readonly string[];
  /** Census linkage per emitted condition type, quoted from the census table. */
  censusBasis: Readonly<Record<string, CensusVerdictRecord>>;
  /** Trust-model and semantics notes shown beside the enforcement badge. */
  notes: readonly string[];
  params: readonly PolicyTemplateParamSpecV1[];
}

export interface HardPolicyTemplateDescriptorV1 extends PolicyTemplateCommonV1 {
  enforcementClass: 'hard_cryptographic';
  buildAst: (params: Record<string, unknown>) => PolicyNode;
}

export interface GovernancePolicyTemplateDescriptorV1 extends PolicyTemplateCommonV1 {
  enforcementClass: 'governance_only';
  buildFact: (params: Record<string, unknown>) => GovernanceWorkflowFactV1;
}

export type PolicyTemplateDescriptorV1 =
  | HardPolicyTemplateDescriptorV1
  | GovernancePolicyTemplateDescriptorV1;

/**
 * Organization workflow facts. These never enter the policy AST and never
 * reach the compiler; they are workflow-layer requirements evaluated by
 * the governance lane against proposal data.
 */
export type GovernanceWorkflowFactV1 =
  | {
      kind: 'approval_amount_band';
      /** Ascending spend thresholds, each with extra approvals required. */
      thresholds: ReadonlyArray<{ amount_sats: number; additional_approvals_required: number }>;
    }
  | { kind: 'human_approval_quorum'; quorum: number }
  | { kind: 'required_approver'; approver_kind: 'role' | 'person'; approver_id: string }
  | { kind: 'proposal_expiration'; expires_after_seconds: number };

// ---------------------------------------------------------------------------
// Parameter validation helpers
// ---------------------------------------------------------------------------

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertNonNegativeSafeInt(value: unknown, where: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${where} must be a non-negative safe integer`);
  }
  return value;
}

function assertPositiveSafeInt(value: unknown, where: string, max?: number): number {
  const n = assertNonNegativeSafeInt(value, where);
  if (n <= 0) throw new Error(`${where} must be positive`);
  if (max !== undefined && n > max) throw new Error(`${where} must be at most ${max}`);
  return n;
}

function assertString(value: unknown, where: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${where} must be a non-empty string`);
  }
  return value;
}

function assertAddressList(value: unknown, where: string): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${where} must be a non-empty array of addresses`);
  }
  const seen = new Set<string>();
  for (const entry of value) {
    if (typeof entry !== 'string' || entry.length < 14 || entry.length > 90 || /\s/.test(entry)) {
      throw new Error(`${where} entries must be address strings without whitespace`);
    }
    seen.add(entry);
  }
  if (seen.size !== value.length) {
    throw new Error(`${where} must not contain duplicate addresses`);
  }
  return [...value];
}

function assertNetwork(value: unknown, where: string): NetworkId {
  return parseNetworkId(assertString(value, where));
}

const HOUR_PATTERN = /^([01]\d|2[0-3]):[0-5]\d$/;
const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const DAY_MIN = 1;
const DAY_MAX = 7;

function assertActiveDays(value: unknown, where: string): number[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${where} must be a non-empty array of day numbers`);
  }
  const seen = new Set<number>();
  for (const day of value) {
    if (typeof day !== 'number' || !Number.isSafeInteger(day) || day < DAY_MIN || day > DAY_MAX) {
      throw new Error(`${where} entries must be integers ${DAY_MIN} (Mon) through ${DAY_MAX} (Sun)`);
    }
    seen.add(day);
  }
  return [...seen].sort((a, b) => a - b);
}

function assertHour(value: unknown, where: string): string {
  const hour = assertString(value, where);
  if (!HOUR_PATTERN.test(hour)) {
    throw new Error(`${where} must be "HH:MM" in UTC`);
  }
  return hour;
}

function assertIsoDate(value: unknown, where: string): string {
  const date = assertString(value, where);
  if (!ISO_DATE_PATTERN.test(date) || Number.isNaN(Date.parse(`${date}T00:00:00Z`))) {
    throw new Error(`${where} must be an ISO date "YYYY-MM-DD"`);
  }
  return date;
}

const NAMED_RESET_INTERVALS: ReadonlySet<string> = new Set([
  'never', 'hourly', 'daily', 'weekly', 'monthly',
]);
const DURATION_PATTERN = /^(\d+)(s|m|h|d|w)$/;
const RESET_INTERVAL_SECONDS_MIN = 60;
const RESET_INTERVAL_SECONDS_MAX = 315_360_000;

function validateResetInterval(
  params: Record<string, unknown>,
  where: string,
): { reset_interval: string; reset_interval_seconds?: number } {
  const interval = assertString(params['resetInterval'], `${where}.resetInterval`);
  const seconds = params['resetIntervalSeconds'];
  if (NAMED_RESET_INTERVALS.has(interval) || DURATION_PATTERN.test(interval)) {
    if (seconds !== undefined) {
      throw new Error(`${where}: a named or duration reset interval cannot be combined with resetIntervalSeconds`);
    }
    return { reset_interval: interval };
  }
  if (interval === 'custom') {
    const custom = assertPositiveSafeInt(
      seconds,
      `${where}.resetIntervalSeconds`,
      RESET_INTERVAL_SECONDS_MAX,
    );
    if (custom < RESET_INTERVAL_SECONDS_MIN) {
      throw new Error(`${where}.resetIntervalSeconds must be at least ${RESET_INTERVAL_SECONDS_MIN}`);
    }
    return { reset_interval: 'custom', reset_interval_seconds: custom };
  }
  throw new Error(`${where}.resetInterval must be a named interval, a duration string, or "custom"`);
}

/** Reads one typed param object from loosely typed input, strictly. */
function readParams(params: unknown, where: string): Record<string, unknown> {
  if (!isPlainObject(params)) {
    throw new Error(`${where} requires a params object`);
  }
  return params;
}

// ---------------------------------------------------------------------------
// Hard template builders — pure AST constructors
// ---------------------------------------------------------------------------

const SELECTOR_ALL = { type: 'ALL' } as const;
const SELECTOR_ANY = { type: 'ANY' } as const;

function destinationSetCondition(params: Record<string, unknown>, selector: unknown): ConditionNode {
  const where = 'destination set template';
  const addresses = assertAddressList(params['addresses'], `${where} addresses`);
  const network = assertNetwork(params['network'], `${where} network`);
  const conditionParams: Record<string, unknown> = {
    selector,
    addresses,
    network,
  };
  if (params['requireChangeToInputAddresses'] !== undefined) {
    if (typeof params['requireChangeToInputAddresses'] !== 'boolean') {
      throw new Error(`${where} requireChangeToInputAddresses must be a boolean`);
    }
    conditionParams['require_change_to_input_addresses'] = params['requireChangeToInputAddresses'];
  }
  return { type: 'condition', conditionType: 'OUTPUT_DEST_IS_IN_SETS', conditionParams };
}

function buildDestinationAllowlistAst(params: Record<string, unknown>): PolicyNode {
  return destinationSetCondition(readParams(params, 'destination allowlist'), SELECTOR_ALL);
}

function buildDestinationBlocklistAst(params: Record<string, unknown>): PolicyNode {
  const inner = destinationSetCondition(readParams(params, 'destination blocklist'), SELECTOR_ANY);
  return { type: 'operator', operator: 'NOT', children: [inner] };
}

function buildFeeCeilingAst(params: Record<string, unknown>): PolicyNode {
  const where = 'fee ceiling template';
  const maxFeeSats = assertPositiveSafeInt(
    readParams(params, where)['maxFeeSats'],
    `${where} maxFeeSats`,
    2_100_000_000_000_000,
  );
  return {
    type: 'condition',
    conditionType: 'TX_FEE_ABSOLUTE',
    conditionParams: { operator: 'LTE', value: maxFeeSats },
  };
}

function buildTimeWindowAst(params: Record<string, unknown>): PolicyNode {
  const where = 'time window template';
  const input = readParams(params, where);
  const mode = assertString(input['mode'], `${where} mode`);
  if (mode === 'after') {
    const start = assertPositiveSafeInt(input['startUnixSeconds'], `${where} startUnixSeconds`);
    return {
      type: 'condition',
      conditionType: 'TIME_BASED_CONSTRAINT',
      conditionParams: { constraint_type: 'after', start_time: start },
    };
  }
  if (mode === 'within') {
    const start = assertPositiveSafeInt(input['startUnixSeconds'], `${where} startUnixSeconds`);
    const end = assertPositiveSafeInt(input['endUnixSeconds'], `${where} endUnixSeconds`);
    if (end <= start) {
      throw new Error(`${where} endUnixSeconds must be after startUnixSeconds`);
    }
    const startHour = assertHour(input['startHourUtc'], `${where} startHourUtc`);
    const endHour = assertHour(input['endHourUtc'], `${where} endHourUtc`);
    const toMinutes = (h: string): number => Number(h.slice(0, 2)) * 60 + Number(h.slice(3, 5));
    if (toMinutes(endHour) <= toMinutes(startHour)) {
      throw new Error(`${where} endHourUtc must be after startHourUtc`);
    }
    return {
      type: 'condition',
      conditionType: 'TIME_BASED_CONSTRAINT',
      conditionParams: {
        constraint_type: 'within',
        active_days: assertActiveDays(input['activeDays'], `${where} activeDays`),
        start_hour: startHour,
        end_hour: endHour,
        start_date_within: assertIsoDate(input['startDate'], `${where} startDate`),
        end_date_within: assertIsoDate(input['endDate'], `${where} endDate`),
        start_time: start,
        end_time: end,
      },
    };
  }
  throw new Error(`${where} mode must be "after" or "within"`);
}

function buildUsageVelocityAst(params: Record<string, unknown>): PolicyNode {
  const where = 'usage velocity template';
  const input = readParams(params, where);
  const maxUses = assertPositiveSafeInt(input['maxUses'], `${where} maxUses`, 100_000);
  const interval = validateResetInterval(input, where);
  const conditionParams: Record<string, unknown> = { max_uses: maxUses, ...interval };
  const resetType = input['resetType'];
  if (resetType !== undefined) {
    if (resetType !== 'rolling' && resetType !== 'calendar') {
      throw new Error(`${where} resetType must be "rolling" or "calendar"`);
    }
    conditionParams['reset_type'] = resetType;
  }
  return { type: 'condition', conditionType: 'COUNT_BASED_CONSTRAINT', conditionParams };
}

function buildConsolidationOnlyAst(_params: Record<string, unknown>): PolicyNode {
  if (isPlainObject(_params) && Object.keys(_params).length > 0) {
    throw new Error('consolidation template takes no parameters');
  }
  return {
    type: 'condition',
    conditionType: 'DERIVED_NO_NEW_OUTPUTS',
    conditionParams: { expected_value: true },
  };
}

// ---------------------------------------------------------------------------
// Governance fact builders — organization workflow, zero POET atoms
// ---------------------------------------------------------------------------

const GOVERNANCE_NOT_ON_CHAIN_NOTE =
  'Organization workflow rule: evaluated by the application governance flow, never compiled into the policy AST and never enforced on-chain.';

function buildAmountBandFact(params: Record<string, unknown>): GovernanceWorkflowFactV1 {
  const where = 'amount band template';
  const input = readParams(params, where);
  const raw = input['thresholds'];
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error(`${where} thresholds must be a non-empty array`);
  }
  let previous = -1;
  const thresholds = raw.map((entry) => {
    if (!isPlainObject(entry)) {
      throw new Error(`${where} thresholds entries must be objects`);
    }
    const amount = assertPositiveSafeInt(entry['amountSats'], `${where} amountSats`);
    const approvals = assertPositiveSafeInt(
      entry['additionalApprovals'],
      `${where} additionalApprovals`,
    );
    if (amount <= previous) {
      throw new Error(`${where} thresholds must be strictly ascending by amountSats`);
    }
    previous = amount;
    return { amount_sats: amount, additional_approvals_required: approvals };
  });
  return { kind: 'approval_amount_band', thresholds };
}

function buildQuorumFact(params: Record<string, unknown>): GovernanceWorkflowFactV1 {
  const where = 'approval quorum template';
  const quorum = assertPositiveSafeInt(
    readParams(params, where)['quorum'],
    `${where} quorum`,
    100,
  );
  return { kind: 'human_approval_quorum', quorum };
}

function buildRequiredApproverFact(params: Record<string, unknown>): GovernanceWorkflowFactV1 {
  const where = 'required approver template';
  const input = readParams(params, where);
  const approverKind = assertString(input['approverKind'], `${where} approverKind`);
  if (approverKind !== 'role' && approverKind !== 'person') {
    throw new Error(`${where} approverKind must be "role" or "person"`);
  }
  const approverId = assertString(input['approverId'], `${where} approverId`);
  return { kind: 'required_approver', approver_kind: approverKind, approver_id: approverId };
}

function buildProposalExpirationFact(params: Record<string, unknown>): GovernanceWorkflowFactV1 {
  const where = 'proposal expiration template';
  const seconds = assertPositiveSafeInt(
    readParams(params, where)['expiresInSeconds'],
    `${where} expiresInSeconds`,
  );
  return { kind: 'proposal_expiration', expires_after_seconds: seconds };
}

// ---------------------------------------------------------------------------
// The catalogue
// ---------------------------------------------------------------------------

const TIME_DRIFT_NOTE =
  'Clock trust model: Moon-bounded drift gates reject proof submissions when client and Moon timestamps drift beyond fixed limits; drift gates bound clock error, and window honesty relies on the host running the honest client build (census sound-with-conditions basis).';

const BLOCKLIST_NEGATION_NOTE =
  'Negated-form construction: the census graded the negated set family NOT SOUND at census head; this template uses the remediated in-circuit negation, which enforces at most one negated condition family per policy, never mixes positive and negated content in a family slot, and places negated membership fail-closed. The negation wraps an ANY-selector atom, so the policy requires that no output is in the banned set.';

const HARD_POLICY_TEMPLATES: readonly HardPolicyTemplateDescriptorV1[] = Object.freeze([
  {
    templateId: 'destination-allowlist',
    templateVersion: 1,
    title: 'Destination allowlist',
    summary: 'Every transaction output must go to an approved address.',
    tier: 'standard',
    enforcementClass: 'hard_cryptographic',
    conditionTypes: ['OUTPUT_DEST_IS_IN_SETS'],
    censusBasis: { OUTPUT_DEST_IS_IN_SETS: SOUNDNESS_CENSUS_VERDICTS['OUTPUT_DEST_IS_IN_SETS'] } as Readonly<Record<string, CensusVerdictRecord>>,
    notes: [
      'Positive-form set membership, enforced in-circuit; change outputs can be required to return to input addresses.',
    ],
    params: [
      { name: 'addresses', type: 'string[]', description: 'Approved destination addresses.', required: true },
      { name: 'network', type: 'string', description: 'Wallet network (signet or mainnet).', required: true },
      {
        name: 'requireChangeToInputAddresses',
        type: 'boolean',
        description: 'Require change outputs to return to input addresses.',
        required: false,
      },
    ],
    buildAst: buildDestinationAllowlistAst,
  },
  {
    templateId: 'destination-blocklist',
    templateVersion: 1,
    title: 'Destination blocklist',
    summary: 'No transaction output may go to a banned address.',
    tier: 'standard',
    enforcementClass: 'hard_cryptographic',
    conditionTypes: ['OUTPUT_DEST_IS_IN_SETS'],
    censusBasis: { OUTPUT_DEST_IS_IN_SETS: SOUNDNESS_CENSUS_VERDICTS['OUTPUT_DEST_IS_IN_SETS'] } as Readonly<Record<string, CensusVerdictRecord>>,
    notes: [BLOCKLIST_NEGATION_NOTE],
    params: [
      { name: 'addresses', type: 'string[]', description: 'Banned destination addresses.', required: true },
      { name: 'network', type: 'string', description: 'Wallet network (signet or mainnet).', required: true },
    ],
    buildAst: buildDestinationBlocklistAst,
  },
  {
    templateId: 'fee-ceiling',
    templateVersion: 1,
    title: 'Absolute fee ceiling',
    summary: 'The transaction fee (inputs minus outputs) must stay at or below the ceiling.',
    tier: 'standard',
    enforcementClass: 'hard_cryptographic',
    conditionTypes: ['TX_FEE_ABSOLUTE'],
    censusBasis: { TX_FEE_ABSOLUTE: SOUNDNESS_CENSUS_VERDICTS['TX_FEE_ABSOLUTE'] } as Readonly<Record<string, CensusVerdictRecord>>,
    notes: ['Bound on the transaction fee, not on spend amounts.'],
    params: [
      { name: 'maxFeeSats', type: 'number', description: 'Maximum fee in satoshis.', required: true },
    ],
    buildAst: buildFeeCeilingAst,
  },
  {
    templateId: 'time-window',
    templateVersion: 1,
    title: 'Time window',
    summary: 'Restrict signing to an unlock time or to a recurring daily window on selected weekdays.',
    tier: 'standard',
    enforcementClass: 'hard_cryptographic',
    conditionTypes: ['TIME_BASED_CONSTRAINT'],
    censusBasis: { TIME_BASED_CONSTRAINT: SOUNDNESS_CENSUS_VERDICTS['TIME_BASED_CONSTRAINT'] } as Readonly<Record<string, CensusVerdictRecord>>,
    notes: [TIME_DRIFT_NOTE],
    params: [
      { name: 'mode', type: 'string', description: '"after" (unlock at a time) or "within" (daily window).', required: true },
      { name: 'startUnixSeconds', type: 'number', description: 'Window start, UNIX seconds. Required for both modes.', required: true },
      { name: 'endUnixSeconds', type: 'number', description: 'Window end, UNIX seconds. Required for "within".', required: false },
      { name: 'activeDays', type: 'number[]', description: 'Days 1 (Mon) through 7 (Sun). Required for "within".', required: false },
      { name: 'startHourUtc', type: 'string', description: 'Daily window start "HH:MM" UTC. Required for "within".', required: false },
      { name: 'endHourUtc', type: 'string', description: 'Daily window end "HH:MM" UTC. Required for "within".', required: false },
      { name: 'startDate', type: 'string', description: 'ISO start date "YYYY-MM-DD". Required for "within".', required: false },
      { name: 'endDate', type: 'string', description: 'ISO end date "YYYY-MM-DD". Required for "within".', required: false },
    ],
    buildAst: buildTimeWindowAst,
  },
  {
    templateId: 'usage-velocity',
    templateVersion: 1,
    title: 'Usage velocity',
    summary: 'Limit how many signing sessions the wallet allows per interval.',
    tier: 'standard',
    enforcementClass: 'hard_cryptographic',
    conditionTypes: ['COUNT_BASED_CONSTRAINT'],
    censusBasis: { COUNT_BASED_CONSTRAINT: SOUNDNESS_CENSUS_VERDICTS['COUNT_BASED_CONSTRAINT'] } as Readonly<Record<string, CensusVerdictRecord>>,
    notes: [
      'Backed by the server-authoritative nullifier/spend-state layer with the use bound committed in-circuit; the forge check is unforgeable under the hostile-client model per the census.',
    ],
    params: [
      { name: 'maxUses', type: 'number', description: 'Maximum signing sessions per interval (1-100000).', required: true },
      { name: 'resetInterval', type: 'string', description: 'Named interval, duration string ("6h", "3d", "2w"), or "custom".', required: true },
      { name: 'resetIntervalSeconds', type: 'number', description: 'Custom interval seconds (60-31536000); only with "custom".', required: false },
      { name: 'resetType', type: 'string', description: '"rolling" (from first use) or "calendar" (UTC period start).', required: false },
    ],
    buildAst: buildUsageVelocityAst,
  },
  {
    templateId: 'consolidation-only',
    templateVersion: 1,
    title: 'No new outputs (consolidation-only)',
    summary: 'Every output address must already appear among the input addresses — consolidation-style flows only.',
    tier: 'advanced',
    enforcementClass: 'hard_cryptographic',
    conditionTypes: ['DERIVED_NO_NEW_OUTPUTS'],
    censusBasis: { DERIVED_NO_NEW_OUTPUTS: SOUNDNESS_CENSUS_VERDICTS['DERIVED_NO_NEW_OUTPUTS'] } as Readonly<Record<string, CensusVerdictRecord>>,
    notes: [
      'Advanced template: with this active, the wallet cannot send to any address that is not already an input address. Only the "condition true" direction is enforced; the opposite direction is not enforceable in-circuit.',
      'This bounds where outputs may go relative to the inputs of one transaction; it is not a destination allowlist and not a spend limit.',
    ],
    params: [],
    buildAst: buildConsolidationOnlyAst,
  },
]);

const GOVERNANCE_POLICY_TEMPLATES: readonly GovernancePolicyTemplateDescriptorV1[] = Object.freeze([
  {
    templateId: 'approval-amount-band',
    templateVersion: 1,
    title: 'Amount bands with additional approvals',
    summary: 'Spends at or above configured amounts require extra human approvals.',
    tier: 'standard',
    enforcementClass: 'governance_only',
    conditionTypes: [],
    censusBasis: {},
    notes: [
      GOVERNANCE_NOT_ON_CHAIN_NOTE,
      'The band is checked by the organization workflow against the proposal’s computed external-spend total (outputs excluding recognized change). This is a workflow check, not an on-chain guarantee; it is not the per-output value comparator and never implies on-chain spend-limit enforcement.',
    ],
    params: [
      {
        name: 'thresholds',
        type: 'object',
        description: 'Ascending list of { amountSats, additionalApprovals } bands.',
        required: true,
      },
    ],
    buildFact: buildAmountBandFact,
  },
  {
    templateId: 'human-approval-quorum',
    templateVersion: 1,
    title: 'Human approval quorum',
    summary: 'Proposals need a minimum number of distinct human approvals.',
    tier: 'standard',
    enforcementClass: 'governance_only',
    conditionTypes: [],
    censusBasis: {},
    notes: [GOVERNANCE_NOT_ON_CHAIN_NOTE],
    params: [{ name: 'quorum', type: 'number', description: 'Required approval count (1-100).', required: true }],
    buildFact: buildQuorumFact,
  },
  {
    templateId: 'required-approver',
    templateVersion: 1,
    title: 'Required approver role or person',
    summary: 'Proposals need an approval from a specific role or named person.',
    tier: 'standard',
    enforcementClass: 'governance_only',
    conditionTypes: [],
    censusBasis: {},
    notes: [GOVERNANCE_NOT_ON_CHAIN_NOTE],
    params: [
      { name: 'approverKind', type: 'string', description: '"role" or "person".', required: true },
      { name: 'approverId', type: 'string', description: 'Role identifier or person identifier.', required: true },
    ],
    buildFact: buildRequiredApproverFact,
  },
  {
    templateId: 'proposal-expiration',
    templateVersion: 1,
    title: 'Proposal expiration',
    summary: 'Unapproved proposals expire after the configured interval.',
    tier: 'standard',
    enforcementClass: 'governance_only',
    conditionTypes: [],
    censusBasis: {},
    notes: [GOVERNANCE_NOT_ON_CHAIN_NOTE],
    params: [{ name: 'expiresInSeconds', type: 'number', description: 'Expiration interval in seconds.', required: true }],
    buildFact: buildProposalExpirationFact,
  },
]);

/** All catalogue templates, hard first. */
export const POLICY_TEMPLATES: readonly PolicyTemplateDescriptorV1[] = Object.freeze([
  ...HARD_POLICY_TEMPLATES,
  ...GOVERNANCE_POLICY_TEMPLATES,
]);

const TEMPLATES_BY_ID: ReadonlyMap<string, PolicyTemplateDescriptorV1> = new Map(
  POLICY_TEMPLATES.map((template) => [template.templateId, template]),
);

// ---------------------------------------------------------------------------
// Module-init invariant — the reviewed catalogue discipline
// ---------------------------------------------------------------------------

/**
 * Re-checks the catalogue discipline: every hard template emits only
 * census-graded sound or sound-with-conditions conditions, quotes the
 * census verdict for each of them, quotes nothing else, and every
 * governance template emits no condition types at all. Runs at module
 * init; a future catalogue editor that violates the census cannot import.
 */
export function assertCatalogueInvariant(
  templates: readonly PolicyTemplateDescriptorV1[] = POLICY_TEMPLATES,
): void {
  for (const template of templates) {
    if (template.templateVersion !== 1) {
      throw new Error(`template ${template.templateId}: unsupported template version`);
    }
    const basisKeys = Object.keys(template.censusBasis).sort();
    const conditionKeys = [...template.conditionTypes].sort();
    if (basisKeys.length !== conditionKeys.length || basisKeys.some((k, i) => k !== conditionKeys[i])) {
      throw new Error(`template ${template.templateId}: census basis must quote exactly its condition types`);
    }
    if (template.enforcementClass === 'hard_cryptographic') {
      if (conditionKeys.length === 0) {
        throw new Error(`template ${template.templateId}: hard template must emit at least one condition`);
      }
      for (const conditionType of conditionKeys) {
        const census = SOUNDNESS_CENSUS_VERDICTS[conditionType];
        if (census === undefined) {
          throw new Error(`template ${template.templateId}: condition ${conditionType} is not census-graded`);
        }
        if (template.censusBasis[conditionType].verdict !== census.verdict) {
          throw new Error(`template ${template.templateId}: census basis for ${conditionType} does not match the census`);
        }
        const usable =
          census.verdict === 'sound' ||
          census.verdict === 'sound_with_conditions' ||
          (census.verdict === 'not_sound' && census.hardAllowedForms !== undefined);
        if (!usable) {
          throw new Error(`template ${template.templateId}: condition ${conditionType} is not sound for hard enforcement`);
        }
        if (DISABLED_CONDITION_TYPES.includes(conditionType)) {
          throw new Error(`template ${template.templateId}: condition ${conditionType} is a disabled registry slot`);
        }
      }
    } else if (conditionKeys.length > 0) {
      throw new Error(`template ${template.templateId}: governance template must not emit conditions`);
    }
  }
}

assertCatalogueInvariant();

// ---------------------------------------------------------------------------
// Template lookups and deterministic compile
// ---------------------------------------------------------------------------

export function getPolicyTemplate(templateId: string): PolicyTemplateDescriptorV1 {
  const template = TEMPLATES_BY_ID.get(templateId);
  if (template === undefined) {
    throw new ContractVersionError(`PolicyTemplate: unknown template id "${templateId}"`);
  }
  return template;
}

export interface PolicyTemplateAstOutputV1 {
  ast: CanonicalPolicyAstV1;
  canonicalJson: string;
  encodingHex: string;
  digestHex: string;
}

/**
 * Builds a hard template's user-policy AST fragment and its canonical
 * encoding: canonical binary bytes (contract 0x07) and the
 * SIGBASH/POLICY/V1 digest. Equivalent configurations with reordered
 * parameter keys or commutatively reordered children produce identical
 * bytes and digests.
 */
export function buildPolicyTemplateAst(templateId: string, params: Record<string, unknown>): PolicyTemplateAstOutputV1 {
  const template = getPolicyTemplate(templateId);
  if (template.enforcementClass !== 'hard_cryptographic') {
    throw new Error(`template ${templateId} is a governance template and produces no policy AST`);
  }
  const ast = canonicalizePolicyRoot(template.buildAst(params));
  return {
    ast,
    canonicalJson: canonicalJson(ast.root),
    encodingHex: canonicalPolicyAstToHex(ast),
    digestHex: policyAstDigestHex(ast),
  };
}

/** Builds a governance template's workflow fact. Throws for hard templates. */
export function buildGovernanceTemplateFact(templateId: string, params: Record<string, unknown>): GovernanceWorkflowFactV1 {
  const template = getPolicyTemplate(templateId);
  if (template.enforcementClass !== 'governance_only') {
    throw new Error(`template ${templateId} is a hard template and produces a policy AST, not a workflow fact`);
  }
  return template.buildFact(params);
}

// ---------------------------------------------------------------------------
// Fail-closed selection gate
// ---------------------------------------------------------------------------

export interface PolicyConditionGateOptions {
  /**
   * Unknown condition types (not census-graded, not disabled) are
   * retained as advanced constructs by default. When the caller
   * represents the normal template path, set this false so anything
   * outside the graded vocabulary fails closed.
   */
  allowUnknownConditionTypes?: boolean;
}

interface NegationScan {
  negatedFamilies: Set<string>;
  positiveFamilies: Set<string>;
}

function rejectCondition(conditionType: string, path: string): string | undefined {
  const census = SOUNDNESS_CENSUS_VERDICTS[conditionType];
  if (census?.hardAllowedForms !== undefined) {
    // A NOT SOUND row with reviewed usable forms: the direction-specific
    // checks below enforce exactly those shapes (positive form, or the
    // exact remediated blocklist negation).
    return undefined;
  }
  if (census !== undefined && census.verdict !== 'sound' && census.verdict !== 'sound_with_conditions') {
    return `${path}: condition ${conditionType} is ${census.verdict.replace('_', ' ')} per the soundness census and cannot be hard enforcement`;
  }
  if (DISABLED_CONDITION_TYPES.includes(conditionType)) {
    return `${path}: condition ${conditionType} is a disabled registry slot and cannot be hard enforcement`;
  }
  return undefined;
}

/**
 * Fail-closed gate over a policy AST (raw parsed node tree). Rejects:
 * census NOT SOUND or removed conditions, disabled registry slots, REQKEY
 * outside the locked system clause, any negation outside the exact
 * remediated destination-blocklist shape, more than one negated family,
 * and positive/negated mixing inside one family. Unknown condition types
 * pass through by default (advanced constructs are retained, never
 * rewritten); pass allowUnknownConditionTypes: false for the normal
 * template path.
 */
export function validatePolicySelectionAst(root: unknown, options: PolicyConditionGateOptions = {}): void {
  const allowUnknown = options.allowUnknownConditionTypes !== false;
  const scan: NegationScan = { negatedFamilies: new Set(), positiveFamilies: new Set() };

  const walk = (node: unknown, path: string, negated: boolean): void => {
    if (!isPlainObject(node)) {
      throw new Error(`${path}: policy node must be an object`);
    }
    if (node['type'] === 'condition') {
      const conditionType = node['conditionType'];
      if (typeof conditionType !== 'string' || conditionType.length === 0) {
        throw new Error(`${path}: condition node requires a conditionType`);
      }
      const family = NEGATABLE_FAMILIES[conditionType];
      if (family !== undefined) {
        if (conditionType === 'REQKEY') {
          throw new Error(`${path}: REQKEY belongs to the locked system clause and never appears in a user policy`);
        }
        if (negated) {
          if (scan.negatedFamilies.has(family)) {
            throw new Error(`${path}: at most one negated condition per family is enforced (${family})`);
          }
          scan.negatedFamilies.add(family);
        } else {
          scan.positiveFamilies.add(family);
        }
      }
      if (negated) {
        assertExactBlocklistShape(node, path);
      }
      const rejection = rejectCondition(conditionType, path);
      if (rejection !== undefined) throw new Error(rejection);
      if (censusGraded(conditionType) || DISABLED_CONDITION_TYPES.includes(conditionType)) {
        return;
      }
      if (!allowUnknown) {
        throw new Error(`${path}: condition ${conditionType} is outside the supported template vocabulary`);
      }
      return;
    }
    if (node['type'] === 'operator') {
      const operator = node['operator'];
      if (typeof operator !== 'string') {
        throw new Error(`${path}: operator node requires an operator`);
      }
      const children = node['children'];
      if (!Array.isArray(children)) {
        throw new Error(`${path}: operator node requires children`);
      }
      if (operator === 'NOT') {
        if (children.length !== 1) {
          throw new Error(`${path}: NOT takes exactly one child`);
        }
        walk(children[0], `${path}.0`, true);
        return;
      }
      children.forEach((child, i) => walk(child, `${path}.${i}`, negated));
      return;
    }
    throw new Error(`${path}: unknown node type`);
  };

  walk(root, 'n', false);

  for (const family of scan.negatedFamilies) {
    if (scan.positiveFamilies.has(family)) {
      throw new Error(`family ${family} mixes positive and negated content; a family slot carries one direction only`);
    }
  }
  if (scan.negatedFamilies.size > 1) {
    throw new Error('at most one condition family per policy may carry a negation');
  }
}

function censusGraded(conditionType: string): boolean {
  return SOUNDNESS_CENSUS_VERDICTS[conditionType] !== undefined;
}

/** The only negation the gate accepts: NOT over a positive ANY-selector destination set. */
function assertExactBlocklistShape(node: Record<string, unknown>, path: string): void {
  if (node['conditionType'] !== 'OUTPUT_DEST_IS_IN_SETS') {
    throw new Error(`${path}: the only enforced negation is the remediated destination blocklist; this negated shape is not supported`);
  }
  const params = node['conditionParams'];
  if (!isPlainObject(params)) {
    throw new Error(`${path}: blocklist condition requires parameters`);
  }
  const selector = params['selector'];
  const selectorType = typeof selector === 'string' ? selector : isPlainObject(selector) ? selector['type'] : undefined;
  if (selectorType !== 'ANY') {
    throw new Error(`${path}: the blocklist negation must wrap an ANY-selector atom; negating an ALL-selector atom would let a transaction carry one banned destination beside a clean one`);
  }
  if (!Array.isArray(params['addresses']) || params['addresses'].length === 0) {
    throw new Error(`${path}: blocklist requires a non-empty banned address set`);
  }
  if (typeof params['network'] !== 'string') {
    throw new Error(`${path}: blocklist requires an explicit network`);
  }
}

// ---------------------------------------------------------------------------
// Selection records — enforcement class bound to exact output
// ---------------------------------------------------------------------------

export interface PolicyTemplateSelectionV1 {
  catalogueVersion: number;
  templateId: string;
  templateVersion: number;
  enforcementClass: PolicyEnforcementClass;
  /** Hard templates: digest of the produced canonical AST (hex). */
  astDigestHex?: string;
  /** Governance templates: the workflow fact. */
  workflowFact?: GovernanceWorkflowFactV1;
  /** Template parameters the selection was built from. */
  params: Record<string, unknown>;
}

/** Builds a validated selection record for a template with its parameters. */
export function createPolicyTemplateSelection(templateId: string, params: Record<string, unknown>): PolicyTemplateSelectionV1 {
  const template = getPolicyTemplate(templateId);
  if (template.enforcementClass === 'hard_cryptographic') {
    const output = buildPolicyTemplateAst(templateId, params);
    return {
      catalogueVersion: POLICY_TEMPLATE_CATALOGUE_VERSION,
      templateId,
      templateVersion: template.templateVersion,
      enforcementClass: template.enforcementClass,
      astDigestHex: output.digestHex,
      params,
    };
  }
  return {
    catalogueVersion: POLICY_TEMPLATE_CATALOGUE_VERSION,
    templateId,
    templateVersion: template.templateVersion,
    enforcementClass: template.enforcementClass,
    workflowFact: buildGovernanceTemplateFact(templateId, params),
    params,
  };
}

/**
 * Validates a stored selection record, including stale configurations:
 * the catalogue version, template version, and enforcement class must
 * match the current catalogue, and the enforcement class must be bound to
 * the exact output — hard selections re-digest their parameters, and
 * governance selections must carry the exact recomputed workflow fact.
 * Any mismatch fails closed.
 */
export function validatePolicyTemplateSelection(selection: unknown): void {
  if (!isPlainObject(selection)) {
    throw new Error('policy template selection must be an object');
  }
  if (selection['catalogueVersion'] !== POLICY_TEMPLATE_CATALOGUE_VERSION) {
    throw new ContractVersionError(
      `PolicyTemplateSelection: unsupported catalogue version ${JSON.stringify(selection['catalogueVersion'])}`,
    );
  }
  const template = getPolicyTemplate(assertString(selection['templateId'], 'selection templateId'));
  if (selection['templateVersion'] !== template.templateVersion) {
    throw new Error(`selection template version ${JSON.stringify(selection['templateVersion'])} does not match catalogue version ${template.templateVersion}`);
  }
  if (selection['enforcementClass'] !== template.enforcementClass) {
    throw new Error(`selection enforcement class ${JSON.stringify(selection['enforcementClass'])} does not match template class ${template.enforcementClass}`);
  }
  const params = selection['params'];
  if (!isPlainObject(params)) {
    throw new Error('selection params must be an object');
  }
  if (template.enforcementClass === 'hard_cryptographic') {
    const output = buildPolicyTemplateAst(template.templateId, params);
    if (selection['astDigestHex'] !== output.digestHex) {
      throw new Error('selection AST digest does not match the digest of its parameters; the record is stale or tampered');
    }
    validatePolicySelectionAst(output.ast.root, { allowUnknownConditionTypes: false });
  } else {
    const fact = buildGovernanceTemplateFact(template.templateId, params);
    if (canonicalJson(selection['workflowFact']) !== canonicalJson(fact)) {
      throw new Error('selection workflow fact does not match the fact of its parameters; the record is stale or tampered');
    }
  }
}
