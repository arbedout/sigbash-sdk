/**
 * Unit tests for buildPolicyFromTemplate (templates.ts)
 *
 * Tests the four production templates synced from web/js/template-definitions.js:
 *   weekly-spending-limit, treasury-vault, bitcoin-inheritance, blacklist
 */

import { buildPolicyFromTemplate } from './templates';

describe('buildPolicyFromTemplate', () => {
  // ---------------------------------------------------------------------------
  // Scenario 1 – Unknown template ID
  // ---------------------------------------------------------------------------
  it('1: unknown template ID throws with list of available templates', () => {
    expect(() => buildPolicyFromTemplate('no-such-template', {})).toThrow(
      "Unknown policy template 'no-such-template'. Available: weekly-spending-limit, treasury-vault, bitcoin-inheritance, blacklist"
    );
  });

  // ---------------------------------------------------------------------------
  // Scenario 2 – Missing required param (generic check via weekly-spending-limit)
  // ---------------------------------------------------------------------------
  it('2: missing required param throws naming the param', () => {
    expect(() => buildPolicyFromTemplate('weekly-spending-limit', {})).toThrow(
      "Template 'weekly-spending-limit' missing required param: 'weeklyLimitSats'"
    );
  });

  // ---------------------------------------------------------------------------
  // weekly-spending-limit
  // ---------------------------------------------------------------------------
  it('3: weekly-spending-limit with weeklyLimitSats=1_000_000 returns correct policy', () => {
    const result = buildPolicyFromTemplate('weekly-spending-limit', { weeklyLimitSats: 1_000_000 });
    expect(result).toMatchObject({
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
              value: 1_000_000,
            },
          },
          {
            type: 'condition',
            conditionType: 'COUNT_BASED_CONSTRAINT',
            conditionParams: {
              max_uses: 1,
              reset_interval: 'weekly',
              reset_type: 'rolling',
            },
          },
        ],
      },
    });
  });

  it('4: weekly-spending-limit with weeklyLimitSats=1 (minimum valid) succeeds', () => {
    const result = buildPolicyFromTemplate('weekly-spending-limit', { weeklyLimitSats: 1 });
    expect(result.version).toBe('1.1');
    const policy = result.policy as { children: Array<{ conditionType: string }> };
    expect(policy.children[0].conditionType).toBe('OUTPUT_VALUE');
    expect(policy.children[1].conditionType).toBe('COUNT_BASED_CONSTRAINT');
  });

  it('5: weekly-spending-limit policy has exactly 2 children', () => {
    const result = buildPolicyFromTemplate('weekly-spending-limit', { weeklyLimitSats: 500_000 });
    expect((result.policy as { children: unknown[] }).children).toHaveLength(2);
  });

  it('6: weekly-spending-limit with weeklyLimitSats=0 throws', () => {
    expect(() =>
      buildPolicyFromTemplate('weekly-spending-limit', { weeklyLimitSats: 0 })
    ).toThrow('WeeklySpendingLimitTemplate: weeklyLimitSats must be a positive number');
  });

  it('7: weekly-spending-limit with weeklyLimitSats=-100 throws', () => {
    expect(() =>
      buildPolicyFromTemplate('weekly-spending-limit', { weeklyLimitSats: -100 })
    ).toThrow('WeeklySpendingLimitTemplate: weeklyLimitSats must be a positive number');
  });

  // ---------------------------------------------------------------------------
  // bitcoin-inheritance
  // ---------------------------------------------------------------------------
  it('8: bitcoin-inheritance with explicit unlockTimestamp returns TIME_BASED_CONSTRAINT after', () => {
    const result = buildPolicyFromTemplate('bitcoin-inheritance', { unlockTimestamp: 9999999999 });
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

  it('9: bitcoin-inheritance without unlockTimestamp defaults to ~10 years from now', () => {
    const before = Math.floor(Date.now() / 1000);
    const result = buildPolicyFromTemplate('bitcoin-inheritance', {});
    const after = Math.floor(Date.now() / 1000);
    const params = (result.policy as { conditionParams: { start_time: number } }).conditionParams;
    const tenYearsSeconds = 10 * 365.25 * 24 * 3600;
    expect(params.start_time).toBeGreaterThanOrEqual(before + tenYearsSeconds - 1);
    expect(params.start_time).toBeLessThanOrEqual(after + tenYearsSeconds + 1);
  });

  it('10: bitcoin-inheritance conditionType is TIME_BASED_CONSTRAINT', () => {
    const result = buildPolicyFromTemplate('bitcoin-inheritance', { unlockTimestamp: 1800000000 });
    expect((result.policy as { conditionType: string }).conditionType).toBe('TIME_BASED_CONSTRAINT');
  });

  // ---------------------------------------------------------------------------
  // blacklist
  // ---------------------------------------------------------------------------
  it('11: blacklist with single address returns NOT(OUTPUT_DEST_IS_IN_SETS)', () => {
    const result = buildPolicyFromTemplate('blacklist', {
      blockedAddresses: ['bc1qbadaddress'],
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
              selector: { type: 'ALL' },
              addresses: ['bc1qbadaddress'],
              network: 'mainnet',
            },
          },
        ],
      },
    });
  });

  it('12: blacklist with multiple addresses includes all in OUTPUT_DEST_IS_IN_SETS', () => {
    const addrs = ['bc1qaddr1', 'bc1qaddr2', 'bc1qaddr3'];
    const result = buildPolicyFromTemplate('blacklist', { blockedAddresses: addrs });
    const child = (result.policy as { children: Array<{ conditionParams: { addresses: string[] } }> })
      .children[0];
    expect(child.conditionParams.addresses).toEqual(addrs);
  });

  it('13: blacklist with custom network uses that network', () => {
    const result = buildPolicyFromTemplate('blacklist', {
      blockedAddresses: ['addr1'],
      network: 'signet',
    });
    const child = (result.policy as { children: Array<{ conditionParams: { network: string } }> })
      .children[0];
    expect(child.conditionParams.network).toBe('signet');
  });

  it('14: blacklist with empty array throws', () => {
    expect(() => buildPolicyFromTemplate('blacklist', { blockedAddresses: [] })).toThrow(
      'BlacklistTemplate: blockedAddresses must be a non-empty array'
    );
  });

  it('15: blacklist missing blockedAddresses param throws', () => {
    expect(() => buildPolicyFromTemplate('blacklist', {})).toThrow(
      "Template 'blacklist' missing required param: 'blockedAddresses'"
    );
  });

  // ---------------------------------------------------------------------------
  // treasury-vault
  // ---------------------------------------------------------------------------
  it('16: treasury-vault missing adminKeyIdentifier throws', () => {
    expect(() => buildPolicyFromTemplate('treasury-vault', {})).toThrow(
      "Template 'treasury-vault' missing required param: 'adminKeyIdentifier'"
    );
  });

  it('17: treasury-vault with invalid key length throws', () => {
    expect(() =>
      buildPolicyFromTemplate('treasury-vault', {
        adminKeyIdentifier: 'tooshort',
      })
    ).toThrow('TreasuryVaultTemplate: adminKeyIdentifier must be a 64 or 66 char hex string');
  });

  it('18: treasury-vault with valid 64-char key returns IMPLIES policy', () => {
    const adminKey = '0'.repeat(64);
    const result = buildPolicyFromTemplate('treasury-vault', { adminKeyIdentifier: adminKey });
    expect(result.version).toBe('1.1');
    expect((result.policy as { operator: string }).operator).toBe('IMPLIES');
  });

  it('19: treasury-vault IMPLIES has NOT left child and AND right child', () => {
    const adminKey = 'a'.repeat(64);
    const result = buildPolicyFromTemplate('treasury-vault', { adminKeyIdentifier: adminKey });
    const children = (result.policy as { children: Array<{ operator?: string; type: string }> }).children;
    expect(children).toHaveLength(2);
    expect(children[0]).toMatchObject({ type: 'operator', operator: 'NOT' });
    expect(children[1]).toMatchObject({ type: 'operator', operator: 'AND' });
  });

  it('20: treasury-vault NOT child contains REQKEY with correct adminKey', () => {
    const adminKey = 'b'.repeat(64);
    const result = buildPolicyFromTemplate('treasury-vault', { adminKeyIdentifier: adminKey });
    const notNode = (result.policy as {
      children: Array<{ children: Array<{ conditionParams: { key_identifier: string } }> }>;
    }).children[0];
    expect(notNode.children[0].conditionParams.key_identifier).toBe(adminKey);
  });

  it('21: treasury-vault AND child has OUTPUT_VALUE, OUTPUT_DEST_IS_IN_SETS, COUNT_BASED_CONSTRAINT', () => {
    const adminKey = 'c'.repeat(64);
    const result = buildPolicyFromTemplate('treasury-vault', { adminKeyIdentifier: adminKey });
    const andNode = (result.policy as {
      children: Array<{ children: Array<{ conditionType: string }> }>;
    }).children[1];
    const types = andNode.children.map((c) => c.conditionType);
    expect(types).toContain('OUTPUT_VALUE');
    expect(types).toContain('OUTPUT_DEST_IS_IN_SETS');
    expect(types).toContain('COUNT_BASED_CONSTRAINT');
  });

  it('22: treasury-vault respects custom hotWalletLimitSats', () => {
    const adminKey = 'd'.repeat(64);
    const result = buildPolicyFromTemplate('treasury-vault', {
      adminKeyIdentifier: adminKey,
      hotWalletLimitSats: 50_000,
    });
    const andNode = (result.policy as {
      children: Array<{ children: Array<{ conditionType: string; conditionParams: Record<string, unknown> }> }>;
    }).children[1];
    const valueNode = andNode.children.find((c) => c.conditionType === 'OUTPUT_VALUE');
    expect(valueNode?.conditionParams['value']).toBe(50_000);
  });

  it('23: treasury-vault respects custom allowedAddresses', () => {
    const adminKey = 'e'.repeat(64);
    const addrs = ['tb1qfoo', 'tb1qbar'];
    const result = buildPolicyFromTemplate('treasury-vault', {
      adminKeyIdentifier: adminKey,
      allowedAddresses: addrs,
    });
    const andNode = (result.policy as {
      children: Array<{ children: Array<{ conditionType: string; conditionParams: Record<string, unknown> }> }>;
    }).children[1];
    const destNode = andNode.children.find((c) => c.conditionType === 'OUTPUT_DEST_IS_IN_SETS');
    expect(destNode?.conditionParams['addresses']).toEqual(addrs);
  });

  it('24: treasury-vault accepts 66-char compressed pubkey as adminKeyIdentifier', () => {
    const adminKey = '02' + 'a'.repeat(64);  // 66 chars (compressed pubkey prefix + 64)
    const result = buildPolicyFromTemplate('treasury-vault', { adminKeyIdentifier: adminKey });
    expect((result.policy as { operator: string }).operator).toBe('IMPLIES');
  });

  it('25: treasury-vault default network is signet in OUTPUT_DEST_IS_IN_SETS', () => {
    const adminKey = 'f'.repeat(64);
    const result = buildPolicyFromTemplate('treasury-vault', { adminKeyIdentifier: adminKey });
    const andNode = (result.policy as {
      children: Array<{ children: Array<{ conditionType: string; conditionParams: Record<string, unknown> }> }>;
    }).children[1];
    const destNode = andNode.children.find((c) => c.conditionType === 'OUTPUT_DEST_IS_IN_SETS');
    expect(destNode?.conditionParams['network']).toBe('signet');
  });
});
