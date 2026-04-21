/**
 * Policy template system for Sigbash SDK.
 *
 * Templates generate POET v1.1 policy JSON from simple parameters.
 * Use templates instead of raw POET JSON for common use cases.
 */

import type { POETPolicy } from './types';

/** Template parameter specification */
export interface TemplateParam {
  name: string;
  type: 'number' | 'string' | 'string[]' | 'boolean';
  description: string;
  required: boolean;
  default?: unknown;
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
// Template: WeeklySpendingLimitTemplate
// ---------------------------------------------------------------------------

/** Parameters for WeeklySpendingLimitTemplate */
export interface WeeklySpendingLimitParams {
  /** Maximum satoshis per rolling 7-day window */
  weeklyLimitSats: number;
}

const WeeklySpendingLimitTemplate: PolicyTemplate = {
  id: 'weekly-spending-limit',
  name: 'Weekly Spending Limit',
  description: 'Limits spending to one transaction per week with a maximum amount cap.',
  params: [
    {
      name: 'weeklyLimitSats',
      type: 'number',
      description: 'Maximum satoshis allowed per rolling 7-day period',
      required: true,
      default: 1000000,
    },
  ],
  build(params: Record<string, unknown>): POETPolicy {
    const weeklyLimitSats = params['weeklyLimitSats'] as number;
    if (typeof weeklyLimitSats !== 'number' || weeklyLimitSats <= 0) {
      throw new Error('WeeklySpendingLimitTemplate: weeklyLimitSats must be a positive number');
    }

    return {
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'AND',
        children: [
          {
            type: 'condition',
            conditionType: 'OUTPUT_VALUE',
            conditionParams: {
              selector: { type: 'ALL' },
              operator: 'LTE',
              value: weeklyLimitSats,
            },
            description: `Amount must be <= ${weeklyLimitSats} sats`,
          },
          {
            type: 'condition',
            conditionType: 'COUNT_BASED_CONSTRAINT',
            conditionParams: {
              max_uses: 1,
              reset_interval: 'weekly',
              reset_type: 'rolling',
            },
            description: 'Can only use once per week (rolling 7-day window)',
          },
        ],
      } as POETPolicy['policy'],
    };
  },
};

// ---------------------------------------------------------------------------
// Template: TreasuryVaultTemplate
// ---------------------------------------------------------------------------

/** Parameters for TreasuryVaultTemplate */
export interface TreasuryVaultParams {
  /** Admin override key identifier (64-char xonly hex pubkey) */
  adminKeyIdentifier: string;
  /** Hot-wallet limit in satoshis */
  hotWalletLimitSats?: number;
  /** Allowed destination addresses for hot-wallet withdrawals */
  allowedAddresses?: string[];
  /** Bitcoin network */
  network?: string;
}

const TreasuryVaultTemplate: PolicyTemplate = {
  id: 'treasury-vault',
  name: 'Treasury Vault',
  description:
    'Conditional spending limits: IF admin key NOT present, THEN restrict destinations and amounts.',
  params: [
    {
      name: 'adminKeyIdentifier',
      type: 'string',
      description: '64-char xonly hex pubkey for the admin override key',
      required: true,
    },
    {
      name: 'hotWalletLimitSats',
      type: 'number',
      description: 'Hot-wallet withdrawal limit in satoshis (default: 100000)',
      required: false,
      default: 100000,
    },
    {
      name: 'allowedAddresses',
      type: 'string[]',
      description: 'Whitelisted destination addresses for hot-wallet withdrawals',
      required: false,
      default: [],
    },
    {
      name: 'network',
      type: 'string',
      description: 'Bitcoin network (default: signet)',
      required: false,
      default: 'signet',
    },
  ],
  build(params: Record<string, unknown>): POETPolicy {
    const adminKey = params['adminKeyIdentifier'] as string;
    if (typeof adminKey !== 'string' || (adminKey.length !== 64 && adminKey.length !== 66)) {
      throw new Error(
        'TreasuryVaultTemplate: adminKeyIdentifier must be a 64 or 66 char hex string'
      );
    }
    const limitSats =
      typeof params['hotWalletLimitSats'] === 'number' ? params['hotWalletLimitSats'] : 100000;
    const addresses = Array.isArray(params['allowedAddresses'])
      ? (params['allowedAddresses'] as string[])
      : [];
    const network = typeof params['network'] === 'string' ? params['network'] : 'signet';

    return {
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'IMPLIES',
        children: [
          {
            type: 'operator',
            operator: 'NOT',
            children: [
              {
                type: 'condition',
                conditionType: 'REQKEY',
                conditionParams: {
                  key_identifier: adminKey,
                  key_type: 'TAP_LEAF_XONLY_PUBKEY',
                },
                description: 'Admin override key',
              },
            ],
            description: 'IF admin key is NOT in signing set',
          },
          {
            type: 'operator',
            operator: 'AND',
            children: [
              {
                type: 'condition',
                conditionType: 'OUTPUT_VALUE',
                conditionParams: {
                  selector: { type: 'ALL' },
                  operator: 'LTE',
                  value: limitSats,
                },
                description: `Amount must be <= ${limitSats} sats`,
              },
              {
                type: 'condition',
                conditionType: 'OUTPUT_DEST_IS_IN_SETS',
                conditionParams: {
                  selector: { type: 'ALL' },
                  addresses,
                  network,
                  require_change_to_input_addresses: true,
                },
                description: 'Destination must be in approved whitelist',
              },
              {
                type: 'condition',
                conditionType: 'COUNT_BASED_CONSTRAINT',
                conditionParams: {
                  max_uses: 1,
                  reset_interval: 'daily',
                  reset_type: 'rolling',
                },
                description: 'Once per 24 hours (rolling window)',
              },
            ],
          },
        ],
      } as POETPolicy['policy'],
    };
  },
};

// ---------------------------------------------------------------------------
// Template: BitcoinInheritanceTemplate
// ---------------------------------------------------------------------------

/** Parameters for BitcoinInheritanceTemplate */
export interface BitcoinInheritanceParams {
  /** UNIX timestamp after which beneficiaries may spend */
  unlockTimestamp?: number;
}

const BitcoinInheritanceTemplate: PolicyTemplate = {
  id: 'bitcoin-inheritance',
  name: 'Bitcoin Inheritance Policy',
  description:
    'Time-locked inheritance. Funds automatically unlock for beneficiaries after a predetermined date.',
  params: [
    {
      name: 'unlockTimestamp',
      type: 'number',
      description:
        'UNIX timestamp (seconds) after which beneficiaries can spend (default: 10 years from now)',
      required: false,
    },
  ],
  build(params: Record<string, unknown>): POETPolicy {
    const tenYearsFromNow = Math.floor(Date.now() / 1000) + Math.round(10 * 365.25 * 24 * 3600);
    const unlockTimestamp =
      typeof params['unlockTimestamp'] === 'number' ? params['unlockTimestamp'] : tenYearsFromNow;

    return {
      version: '1.1',
      policy: {
        type: 'condition',
        conditionType: 'TIME_BASED_CONSTRAINT',
        conditionParams: { constraint_type: 'after', start_time: unlockTimestamp },
        description: `Beneficiaries can access funds after UNIX ${unlockTimestamp}`,
      },
    };
  },
};

// ---------------------------------------------------------------------------
// Template: BlacklistTemplate
// ---------------------------------------------------------------------------

/** Parameters for BlacklistTemplate */
export interface BlacklistParams {
  /** Blocked addresses */
  blockedAddresses: string[];
  /** Bitcoin network */
  network?: string;
}

const BlacklistTemplate: PolicyTemplate = {
  id: 'blacklist',
  name: 'Address Blacklist',
  description: 'Prevents sending Bitcoin to specific blocked addresses.',
  params: [
    {
      name: 'blockedAddresses',
      type: 'string[]',
      description: 'Array of blocked Bitcoin addresses',
      required: true,
    },
    {
      name: 'network',
      type: 'string',
      description: 'Bitcoin network (default: mainnet)',
      required: false,
      default: 'mainnet',
    },
  ],
  build(params: Record<string, unknown>): POETPolicy {
    const blockedAddresses = params['blockedAddresses'] as string[];
    if (!Array.isArray(blockedAddresses) || blockedAddresses.length === 0) {
      throw new Error('BlacklistTemplate: blockedAddresses must be a non-empty array');
    }
    const network = typeof params['network'] === 'string' ? params['network'] : 'mainnet';

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
              selector: { type: 'ALL' },
              addresses: blockedAddresses,
              network,
            },
            description: `Block ${blockedAddresses.length} address(es)`,
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
  /**
   * Start of allowed window in UTC, "HH:MM" format.
   * Default: "14:00" (9 AM EST = 14:00 UTC)
   */
  startHourUTC?: string;
  /**
   * End of allowed window in UTC, "HH:MM" format.
   * Default: "22:00" (5 PM EST = 22:00 UTC)
   */
  endHourUTC?: string;
}

const BusinessHoursOnlyTemplate: PolicyTemplate = {
  id: 'business-hours-only',
  name: 'Business Hours Only',
  description:
    'Transactions only allowed during business hours (Monday–Friday). ' +
    'Prevents after-hours or weekend activity. Hours expressed in UTC.',
  params: [
    {
      name: 'startHourUTC',
      type: 'string',
      description: 'Start of allowed window in UTC, "HH:MM" format (default: "14:00" = 9 AM EST)',
      required: false,
      default: '14:00',
    },
    {
      name: 'endHourUTC',
      type: 'string',
      description: 'End of allowed window in UTC, "HH:MM" format (default: "22:00" = 5 PM EST)',
      required: false,
      default: '22:00',
    },
  ],
  build(params: Record<string, unknown>): POETPolicy {
    const startHourUTC =
      typeof params['startHourUTC'] === 'string' ? params['startHourUTC'] : '14:00';
    const endHourUTC =
      typeof params['endHourUTC'] === 'string' ? params['endHourUTC'] : '22:00';

    const hourPattern = /^\d{2}:\d{2}$/;
    if (!hourPattern.test(startHourUTC)) {
      throw new Error('BusinessHoursOnlyTemplate: startHourUTC must be "HH:MM" format');
    }
    if (!hourPattern.test(endHourUTC)) {
      throw new Error('BusinessHoursOnlyTemplate: endHourUTC must be "HH:MM" format');
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const twoHundredYearsSec = 200 * 365 * 24 * 3600;
    const startTimestamp = nowSec;
    const endTimestamp = nowSec + twoHundredYearsSec;

    const startDateISO = new Date(startTimestamp * 1000).toISOString().slice(0, 10);
    const endDateISO = new Date(endTimestamp * 1000).toISOString().slice(0, 10);

    return {
      version: '1.1',
      policy: {
        type: 'condition',
        conditionType: 'TIME_BASED_CONSTRAINT',
        conditionParams: {
          constraint_type: 'within',
          active_days: [1, 2, 3, 4, 5],  // Monday–Friday
          start_date_within: startDateISO,
          end_date_within: endDateISO,
          start_hour: startHourUTC,
          end_hour: endHourUTC,
          start_time: startTimestamp,
          end_time: endTimestamp,
        },
        description: `Only during business hours: Mon–Fri, ${startHourUTC}–${endHourUTC} UTC`,
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
  build(_params: Record<string, unknown>): POETPolicy {
    return {
      version: '1.1',
      policy: {
        type: 'condition',
        conditionType: 'DERIVED_NO_NEW_OUTPUTS',
        conditionParams: {
          expected_value: 1,
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
  [WeeklySpendingLimitTemplate.id]: WeeklySpendingLimitTemplate,
  [TreasuryVaultTemplate.id]: TreasuryVaultTemplate,
  [BitcoinInheritanceTemplate.id]: BitcoinInheritanceTemplate,
  [BlacklistTemplate.id]: BlacklistTemplate,
  [BusinessHoursOnlyTemplate.id]: BusinessHoursOnlyTemplate,
  [NoNewOutputsConsolidationTemplate.id]: NoNewOutputsConsolidationTemplate,
};

/**
 * Build a POET policy from a template ID and parameters.
 *
 * @param templateId - Template identifier (e.g. 'weekly-spending-limit')
 * @param params - Template-specific parameters
 * @returns Compiled POETPolicy object
 * @throws Error if template not found or params invalid
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

  return template.build(params);
}
