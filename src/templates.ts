/**
 * Policy template system for Sigbash SDK.
 *
 * Templates generate POET v1.1 policy JSON from simple parameters.
 * Use templates instead of raw POET JSON for common use cases.
 *
 * The registry is bounded by the soundness condition census: every
 * template emits only census-graded condition types in their reviewed
 * forms, the only negation is the remediated destination blocklist (NOT
 * over an ANY-selector atom), and no template reads the wall clock —
 * time constraints take explicit timestamps, dates, and hours. As a
 * census-per-output-comparator consequence no template expresses a
 * spend-amount cap; amount bands live in the governance workflow lane.
 *
 * Every policy returned by buildPolicyFromTemplate is re-checked against
 * the fail-closed selection gate from the contracts catalogue, so a
 * registry entry that drifts outside the census cannot return a policy.
 */

import type { POETPolicy } from './types';
import { validatePolicySelectionAst } from './contracts/policyTemplates';
import { parseNetworkId } from './contracts/network';

/** Template parameter specification */
export interface TemplateParam {
  name: string;
  type: 'number' | 'number[]' | 'string' | 'string[]' | 'boolean';
  description: string;
  required: boolean;
}

/** Template definition */
export interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  params: TemplateParam[];
  build: (params: Record<string, unknown>) => POETPolicy;
}

// ---------------------------------------------------------------------------
// Parameter validation — same shapes the contracts catalogue builders use
// ---------------------------------------------------------------------------

function assertPositiveSafeInt(value: unknown, where: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${where} must be a positive safe integer`);
  }
  return value;
}

const HOUR_PATTERN = /^([01]\d|2[0-3]):[0-5]\d$/;
const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const DAY_MIN = 1;
const DAY_MAX = 7;

function assertHour(value: unknown, where: string): string {
  if (typeof value !== 'string' || !HOUR_PATTERN.test(value)) {
    throw new Error(`${where} must be "HH:MM" in UTC`);
  }
  return value;
}

function assertIsoDate(value: unknown, where: string): string {
  if (typeof value !== 'string' || !ISO_DATE_PATTERN.test(value) || Number.isNaN(Date.parse(`${value}T00:00:00Z`))) {
    throw new Error(`${where} must be an ISO date "YYYY-MM-DD"`);
  }
  return value;
}

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

function assertNetwork(value: unknown, where: string): string {
  if (typeof value !== 'string') {
    throw new Error(`${where} must be a network string`);
  }
  return parseNetworkId(value);
}

// ---------------------------------------------------------------------------
// Template: BitcoinInheritanceTemplate
// ---------------------------------------------------------------------------

/** Parameters for BitcoinInheritanceTemplate */
export interface BitcoinInheritanceParams {
  /** UNIX timestamp (seconds) after which beneficiaries may spend */
  startUnixSeconds: number;
}

const BitcoinInheritanceTemplate: PolicyTemplate = {
  id: 'bitcoin-inheritance',
  name: 'Bitcoin Inheritance Policy',
  description:
    'Time-locked inheritance. Funds unlock for beneficiaries after the configured unlock time.',
  params: [
    {
      name: 'startUnixSeconds',
      type: 'number',
      description: 'UNIX timestamp (seconds) after which beneficiaries can spend',
      required: true,
    },
  ],
  build(params: Record<string, unknown>): POETPolicy {
    const startUnixSeconds = assertPositiveSafeInt(
      params['startUnixSeconds'],
      'BitcoinInheritanceTemplate: startUnixSeconds'
    );

    return {
      version: '1.1',
      policy: {
        type: 'condition',
        conditionType: 'TIME_BASED_CONSTRAINT',
        conditionParams: { constraint_type: 'after', start_time: startUnixSeconds },
        description: `Beneficiaries can access funds after UNIX ${startUnixSeconds}`,
      },
    };
  },
};

// ---------------------------------------------------------------------------
// Template: BlacklistTemplate
// ---------------------------------------------------------------------------

/** Parameters for BlacklistTemplate */
export interface BlacklistParams {
  /** Banned addresses */
  blockedAddresses: string[];
  /** Bitcoin network (signet or mainnet) */
  network: string;
}

const BlacklistTemplate: PolicyTemplate = {
  id: 'blacklist',
  name: 'Address Blacklist',
  description: 'Prevents sending Bitcoin to specific banned addresses.',
  params: [
    {
      name: 'blockedAddresses',
      type: 'string[]',
      description: 'Array of banned Bitcoin addresses',
      required: true,
    },
    {
      name: 'network',
      type: 'string',
      description: 'Bitcoin network (signet or mainnet)',
      required: true,
    },
  ],
  build(params: Record<string, unknown>): POETPolicy {
    const blockedAddresses = assertAddressList(
      params['blockedAddresses'],
      'BlacklistTemplate: blockedAddresses'
    );
    const network = assertNetwork(params['network'], 'BlacklistTemplate: network');

    // The remediated blocklist negation: the NOT wraps an ANY-selector
    // atom, so the policy requires that no output is in the banned set.
    // Negating an ALL-selector atom would only require one clean output
    // and would let a transaction carry a banned destination beside it.
    return {
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'NOT',
        children: [
          {
            type: 'condition',
            conditionType: 'OUTPUT_DEST_IS_IN_SETS',
            conditionParams: {
              selector: { type: 'ANY' },
              addresses: blockedAddresses,
              network,
            },
            description: `No output may go to any of ${blockedAddresses.length} banned address(es)`,
          },
        ],
      } as POETPolicy['policy'],
    };
  },
};

// ---------------------------------------------------------------------------
// Template: BusinessHoursOnlyTemplate
// ---------------------------------------------------------------------------

/** Parameters for BusinessHoursOnlyTemplate */
export interface BusinessHoursOnlyParams {
  /** Days 1 (Mon) through 7 (Sun) the window applies to */
  activeDays: number[];
  /** Daily window start "HH:MM" in UTC */
  startHourUtc: string;
  /** Daily window end "HH:MM" in UTC, after startHourUtc */
  endHourUtc: string;
  /** Window start date "YYYY-MM-DD" */
  startDate: string;
  /** Window end date "YYYY-MM-DD", after startDate */
  endDate: string;
  /** Window start, UNIX seconds */
  startUnixSeconds: number;
  /** Window end, UNIX seconds, after startUnixSeconds */
  endUnixSeconds: number;
}

const BusinessHoursOnlyTemplate: PolicyTemplate = {
  id: 'business-hours-only',
  name: 'Business Hours Only',
  description:
    'Signing restricted to a recurring daily window on selected days. ' +
    'The window is fully explicit — hours in UTC, dates as ISO days, ' +
    'bounds as UNIX seconds.',
  params: [
    {
      name: 'activeDays',
      type: 'number[]',
      description: 'Days 1 (Mon) through 7 (Sun) the window applies to',
      required: true,
    },
    {
      name: 'startHourUtc',
      type: 'string',
      description: 'Daily window start "HH:MM" in UTC',
      required: true,
    },
    {
      name: 'endHourUtc',
      type: 'string',
      description: 'Daily window end "HH:MM" in UTC, after startHourUtc',
      required: true,
    },
    {
      name: 'startDate',
      type: 'string',
      description: 'Window start date "YYYY-MM-DD"',
      required: true,
    },
    {
      name: 'endDate',
      type: 'string',
      description: 'Window end date "YYYY-MM-DD", after startDate',
      required: true,
    },
    {
      name: 'startUnixSeconds',
      type: 'number',
      description: 'Window start, UNIX seconds',
      required: true,
    },
    {
      name: 'endUnixSeconds',
      type: 'number',
      description: 'Window end, UNIX seconds, after startUnixSeconds',
      required: true,
    },
  ],
  build(params: Record<string, unknown>): POETPolicy {
    const where = 'BusinessHoursOnlyTemplate';
    const activeDays = assertActiveDays(params['activeDays'], `${where}: activeDays`);
    const startHour = assertHour(params['startHourUtc'], `${where}: startHourUtc`);
    const endHour = assertHour(params['endHourUtc'], `${where}: endHourUtc`);
    const startDate = assertIsoDate(params['startDate'], `${where}: startDate`);
    const endDate = assertIsoDate(params['endDate'], `${where}: endDate`);
    const startUnixSeconds = assertPositiveSafeInt(
      params['startUnixSeconds'],
      `${where}: startUnixSeconds`
    );
    const endUnixSeconds = assertPositiveSafeInt(
      params['endUnixSeconds'],
      `${where}: endUnixSeconds`
    );
    if (endDate <= startDate) {
      throw new Error(`${where}: endDate must be after startDate`);
    }
    if (endUnixSeconds <= startUnixSeconds) {
      throw new Error(`${where}: endUnixSeconds must be after startUnixSeconds`);
    }
    const toMinutes = (h: string): number => Number(h.slice(0, 2)) * 60 + Number(h.slice(3, 5));
    if (toMinutes(endHour) <= toMinutes(startHour)) {
      throw new Error(`${where}: endHourUtc must be after startHourUtc`);
    }

    return {
      version: '1.1',
      policy: {
        type: 'condition',
        conditionType: 'TIME_BASED_CONSTRAINT',
        conditionParams: {
          constraint_type: 'within',
          active_days: activeDays,
          start_hour: startHour,
          end_hour: endHour,
          start_date_within: startDate,
          end_date_within: endDate,
          start_time: startUnixSeconds,
          end_time: endUnixSeconds,
        },
        description: `Only during ${activeDays.join(', ')} ${startHour}–${endHour} UTC`,
      },
    };
  },
};

// ---------------------------------------------------------------------------
// Template: NoNewOutputsConsolidationTemplate
// ---------------------------------------------------------------------------

const NoNewOutputsConsolidationTemplate: PolicyTemplate = {
  id: 'no-new-outputs-consolidation',
  name: 'No New Outputs (Consolidation-Only)',
  description:
    'Safe UTXO consolidation — prevents sending to external addresses. ' +
    'All outputs must be to addresses already present in the transaction inputs.',
  params: [],
  build(params: Record<string, unknown>): POETPolicy {
    if (params !== undefined && typeof params === 'object' && !Array.isArray(params) && Object.keys(params).length > 0) {
      throw new Error('NoNewOutputsConsolidationTemplate: takes no parameters');
    }
    return {
      version: '1.1',
      policy: {
        type: 'condition',
        conditionType: 'DERIVED_NO_NEW_OUTPUTS',
        conditionParams: {
          expected_value: true,
        },
        description: 'All outputs must be to addresses from transaction inputs (consolidation only)',
      },
    };
  },
};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/** Registry of all built-in policy templates. */
export const POLICY_TEMPLATES: Record<string, PolicyTemplate> = {
  [BitcoinInheritanceTemplate.id]: BitcoinInheritanceTemplate,
  [BlacklistTemplate.id]: BlacklistTemplate,
  [BusinessHoursOnlyTemplate.id]: BusinessHoursOnlyTemplate,
  [NoNewOutputsConsolidationTemplate.id]: NoNewOutputsConsolidationTemplate,
};

/**
 * Build a POET policy from a template ID and parameters.
 *
 * Every returned policy passes the fail-closed selection gate: census
 * NOT SOUND or removed condition types, disabled registry slots, REQKEY,
 * and every negation outside the remediated blocklist shape are
 * rejected, so a template that drifts outside the census cannot return.
 *
 * @param templateId - Template identifier (e.g. 'bitcoin-inheritance')
 * @param params - Template-specific parameters
 * @returns Compiled POETPolicy object
 * @throws Error if template not found, params invalid, or the built policy is outside the census vocabulary
 */
export function buildPolicyFromTemplate(
  templateId: string,
  params: Record<string, unknown>
): POETPolicy {
  const template = POLICY_TEMPLATES[templateId];
  if (!template) {
    const available = Object.keys(POLICY_TEMPLATES).join(', ');
    throw new Error(
      `Unknown policy template '${templateId}'. Available: ${available}`
    );
  }

  // Check required params
  for (const spec of template.params) {
    if (spec.required && params[spec.name] === undefined) {
      throw new Error(`Template '${templateId}' missing required param: '${spec.name}'`);
    }
  }

  const policy = template.build(params);
  validatePolicySelectionAst(policy.policy, { allowUnknownConditionTypes: false });
  return policy;
}
