/**
 * Unit tests for buildPolicyFromTemplate (templates.ts)
 *
 * The registry is bounded by the soundness condition census: every
 * template emits only census-graded conditions in their reviewed forms,
 * the only negation is the remediated destination blocklist shape, and
 * no template reads the wall clock. Each test builds through the same
 * fail-closed selection gate the contracts catalogue uses.
 */

import { buildPolicyFromTemplate, POLICY_TEMPLATES } from './templates';
import { validatePolicySelectionAst } from './contracts/policyTemplates';
import type { POETPolicy, PolicyNode } from './types';

const AVAILABLE_IDS = Object.keys(POLICY_TEMPLATES).sort().join(', ');

const businessHoursParams = {
  activeDays: [1, 2, 3, 4, 5],
  startHourUtc: '14:00',
  endHourUtc: '22:00',
  startDate: '2026-10-01',
  endDate: '2027-10-01',
  startUnixSeconds: 1790000000,
  endUnixSeconds: 1820000000,
};

function conditionTypes(policy: PolicyNode): string[] {
  const found: string[] = [];
  const walk = (node: PolicyNode): void => {
    if (node.type === 'condition') {
      found.push(node.conditionType);
      return;
    }
    node.children.forEach(walk);
  };
  walk(policy);
  return found;
}

describe('buildPolicyFromTemplate', () => {
  // ---------------------------------------------------------------------------
  // Registry-wide census discipline
  // ---------------------------------------------------------------------------
  it('registry offers exactly the conformant templates', () => {
    expect(AVAILABLE_IDS).toBe(
      'bitcoin-inheritance, blacklist, business-hours-only, no-new-outputs-consolidation'
    );
  });

  it('no template emits a census NOT SOUND condition type, REQKEY, or a disabled slot', () => {
    const forbidden = ['OUTPUT_VALUE', 'REQKEY', 'INPUT_SOURCE_IS_IN_SETS', 'OUTPUT_OP_RETURN'];
    for (const [id, template] of Object.entries(POLICY_TEMPLATES)) {
      const built = buildPolicyFromTemplate(id, sampleParams(id));
      for (const conditionType of conditionTypes(built.policy)) {
        expect(forbidden).not.toContain(conditionType);
      }
      expect(template.params.every((p) => p.required)).toBe(true);
    }
  });

  it('every template output passes the fail-closed census gate', () => {
    for (const id of Object.keys(POLICY_TEMPLATES)) {
      const built = buildPolicyFromTemplate(id, sampleParams(id));
      expect(() =>
        validatePolicySelectionAst(built.policy, { allowUnknownConditionTypes: false })
      ).not.toThrow();
    }
  });

  it('the census gate rejects a hand-built spend-cap policy, so the gate really binds', () => {
    const spendCap = {
      type: 'condition',
      conditionType: 'OUTPUT_VALUE',
      conditionParams: { selector: { type: 'ALL' }, operator: 'LTE', value: 1000 },
    };
    expect(() =>
      validatePolicySelectionAst(spendCap, { allowUnknownConditionTypes: false })
    ).toThrow('not sound');
  });

  it('building is deterministic — same params produce identical output', () => {
    for (const id of Object.keys(POLICY_TEMPLATES)) {
      const first = buildPolicyFromTemplate(id, sampleParams(id));
      const second = buildPolicyFromTemplate(id, sampleParams(id));
      expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    }
  });

  // ---------------------------------------------------------------------------
  // Unknown template ID
  // ---------------------------------------------------------------------------
  it('unknown template ID throws with list of available templates', () => {
    expect(() => buildPolicyFromTemplate('no-such-template', {})).toThrow(
      `Unknown policy template 'no-such-template'. Available: ${AVAILABLE_IDS}`
    );
  });

  it('removed templates fail through the unknown-template path', () => {
    for (const removedId of ['weekly-spending-limit', 'treasury-vault']) {
      expect(() => buildPolicyFromTemplate(removedId, {})).toThrow(
        `Unknown policy template '${removedId}'`
      );
    }
  });

  it('missing required param throws naming the param', () => {
    expect(() => buildPolicyFromTemplate('blacklist', {})).toThrow(
      "Template 'blacklist' missing required param: 'blockedAddresses'"
    );
  });

  // ---------------------------------------------------------------------------
  // bitcoin-inheritance — explicit unlock time, no wall-clock default
  // ---------------------------------------------------------------------------
  it('bitcoin-inheritance with explicit startUnixSeconds returns TIME_BASED_CONSTRAINT after', () => {
    const result = buildPolicyFromTemplate('bitcoin-inheritance', { startUnixSeconds: 9999999999 });
    expect(result).toMatchObject({
      version: '1.1',
      policy: {
        type: 'condition',
        conditionType: 'TIME_BASED_CONSTRAINT',
        conditionParams: {
          constraint_type: 'after',
          start_time: 9999999999,
        },
      },
    });
  });

  it('bitcoin-inheritance requires the unlock time — no default is invented', () => {
    expect(() => buildPolicyFromTemplate('bitcoin-inheritance', {})).toThrow(
      "Template 'bitcoin-inheritance' missing required param: 'startUnixSeconds'"
    );
  });

  it.each([0, -5, 1.5, Number.MAX_SAFE_INTEGER + 1, '1800000000'])(
    'bitcoin-inheritance rejects non-positive-safe-integer startUnixSeconds (%p)',
    (bad) => {
      expect(() => buildPolicyFromTemplate('bitcoin-inheritance', { startUnixSeconds: bad })).toThrow(
        'startUnixSeconds must be a positive safe integer'
      );
    }
  );

  // ---------------------------------------------------------------------------
  // blacklist — remediated blocklist negation (NOT over ANY-selector atom)
  // ---------------------------------------------------------------------------
  it('blacklist returns NOT over an ANY-selector OUTPUT_DEST_IS_IN_SETS atom', () => {
    const result = buildPolicyFromTemplate('blacklist', {
      blockedAddresses: ['bc1qbadaddress000000'],
      network: 'mainnet',
    });
    expect(result).toMatchObject({
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
              addresses: ['bc1qbadaddress000000'],
              network: 'mainnet',
            },
          },
        ],
      },
    });
  });

  it('blacklist with multiple addresses includes all in the banned set', () => {
    const addrs = ['bc1qaddr1000000000000', 'bc1qaddr2000000000000', 'bc1qaddr3000000000000'];
    const result = buildPolicyFromTemplate('blacklist', { blockedAddresses: addrs, network: 'mainnet' });
    const child = (
      result.policy as { children: Array<{ conditionParams: { addresses: string[] } }> }
    ).children[0];
    expect(child.conditionParams.addresses).toEqual(addrs);
  });

  it('blacklist requires an explicit supported network', () => {
    expect(() =>
      buildPolicyFromTemplate('blacklist', { blockedAddresses: ['bc1qaddr1000000000000'] })
    ).toThrow("Template 'blacklist' missing required param: 'network'");
    expect(() =>
      buildPolicyFromTemplate('blacklist', {
        blockedAddresses: ['bc1qaddr1000000000000'],
        network: 'testnet',
      })
    ).toThrow('unknown network "testnet"');
  });

  it('blacklist rejects empty, duplicated, or malformed address lists', () => {
    expect(() =>
      buildPolicyFromTemplate('blacklist', { blockedAddresses: [], network: 'mainnet' })
    ).toThrow('blockedAddresses must be a non-empty array of addresses');
    expect(() =>
      buildPolicyFromTemplate('blacklist', {
        blockedAddresses: ['bc1qaddr1000000000000', 'bc1qaddr1000000000000'],
        network: 'mainnet',
      })
    ).toThrow('must not contain duplicate addresses');
    expect(() =>
      buildPolicyFromTemplate('blacklist', { blockedAddresses: ['short'], network: 'mainnet' })
    ).toThrow('must be address strings without whitespace');
  });

  // ---------------------------------------------------------------------------
  // business-hours-only — fully explicit window, no wall-clock reads
  // ---------------------------------------------------------------------------
  it('business-hours-only returns the explicit within-window condition', () => {
    const result = buildPolicyFromTemplate('business-hours-only', businessHoursParams);
    expect(result).toMatchObject({
      version: '1.1',
      policy: {
        type: 'condition',
        conditionType: 'TIME_BASED_CONSTRAINT',
        conditionParams: {
          constraint_type: 'within',
          active_days: [1, 2, 3, 4, 5],
          start_hour: '14:00',
          end_hour: '22:00',
          start_date_within: '2026-10-01',
          end_date_within: '2027-10-01',
          start_time: 1790000000,
          end_time: 1820000000,
        },
      },
    });
  });

  it('every business-hours-only field is required — no defaults, no clock reads', () => {
    for (const name of Object.keys(businessHoursParams)) {
      const partial: Record<string, unknown> = { ...businessHoursParams };
      delete partial[name];
      expect(() => buildPolicyFromTemplate('business-hours-only', partial)).toThrow(
        `Template 'business-hours-only' missing required param: '${name}'`
      );
    }
  });

  it('business-hours-only rejects malformed hours, dates, days, and inverted windows', () => {
    const bad: Array<[Record<string, unknown>, string]> = [
      [{ ...businessHoursParams, startHourUtc: '9:00' }, 'startHourUtc must be "HH:MM" in UTC'],
      [{ ...businessHoursParams, endHourUtc: '24:00' }, 'endHourUtc must be "HH:MM" in UTC'],
      [{ ...businessHoursParams, startDate: '2026-13-01' }, 'startDate must be an ISO date "YYYY-MM-DD"'],
      [{ ...businessHoursParams, activeDays: [] }, 'activeDays must be a non-empty array of day numbers'],
      [{ ...businessHoursParams, activeDays: [0, 8] }, 'entries must be integers 1 (Mon) through 7 (Sun)'],
      [{ ...businessHoursParams, endDate: '2026-10-01' }, 'endDate must be after startDate'],
      [{ ...businessHoursParams, endUnixSeconds: 1790000000 }, 'endUnixSeconds must be after startUnixSeconds'],
      [{ ...businessHoursParams, endHourUtc: '14:00' }, 'endHourUtc must be after startHourUtc'],
      [{ ...businessHoursParams, startUnixSeconds: 0 }, 'startUnixSeconds must be a positive safe integer'],
    ];
    for (const [params, message] of bad) {
      expect(() => buildPolicyFromTemplate('business-hours-only', params)).toThrow(message);
    }
  });

  // ---------------------------------------------------------------------------
  // no-new-outputs-consolidation
  // ---------------------------------------------------------------------------
  it('no-new-outputs-consolidation returns DERIVED_NO_NEW_OUTPUTS with expected_value true', () => {
    const result = buildPolicyFromTemplate('no-new-outputs-consolidation', {});
    expect(result).toMatchObject({
      version: '1.1',
      policy: {
        type: 'condition',
        conditionType: 'DERIVED_NO_NEW_OUTPUTS',
        conditionParams: { expected_value: true },
      },
    });
  });

  it('no-new-outputs-consolidation takes no parameters', () => {
    expect(() =>
      buildPolicyFromTemplate('no-new-outputs-consolidation', { unexpected: 1 })
    ).toThrow('takes no parameters');
  });
});

/** One valid parameter set per registry template, keyed by template ID. */
function sampleParams(templateId: string): Record<string, unknown> {
  switch (templateId) {
    case 'bitcoin-inheritance':
      return { startUnixSeconds: 1800000000 };
    case 'blacklist':
      return { blockedAddresses: ['bc1qsamplebannedaddr00'], network: 'signet' };
    case 'business-hours-only':
      return { ...businessHoursParams };
    case 'no-new-outputs-consolidation':
      return {};
    default:
      throw new Error(`no sample params registered for template '${templateId}'`);
  }
}

describe('buildPolicyFromTemplate sample params stay in sync with the registry', () => {
  it('every template has sample params and every sample set builds', () => {
    expect(Object.keys(POLICY_TEMPLATES).sort()).toEqual(
      ['bitcoin-inheritance', 'blacklist', 'business-hours-only', 'no-new-outputs-consolidation']
    );
    for (const id of Object.keys(POLICY_TEMPLATES)) {
      const built: POETPolicy = buildPolicyFromTemplate(id, sampleParams(id));
      expect(built.version).toBe('1.1');
    }
  });
});
