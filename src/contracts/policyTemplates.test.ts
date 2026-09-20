/**
 * Policy template catalogue tests: the census row-for-row assertion,
 * the module-init catalogue invariant, golden AST vectors per template,
 * determinism, the fail-closed selection gate, parameter bounds, and
 * enforcement-class-to-output binding for stored selections.
 */

import {
  CENSUS_GRADED_CONDITION_COUNT,
  DISABLED_CONDITION_TYPES,
  POLICY_TEMPLATE_CATALOGUE_VERSION,
  POLICY_TEMPLATES,
  SOUNDNESS_CENSUS_VERDICTS,
  assertCatalogueInvariant,
  buildGovernanceTemplateFact,
  buildPolicyTemplateAst,
  canonicalPolicyAstFromHex,
  canonicalPolicyAstToHex,
  canonicalizePolicyRoot,
  createPolicyTemplateSelection,
  validatePolicySelectionAst,
  validatePolicyTemplateSelection,
  ContractVersionError,
} from './index';
import vectors from './vectors/policy-templates-v1.json';

/**
 * Transcribed from docs/soundness_condition_census_summary.md (per-row
 * verdict table). The embedded census table must match this row for row;
 * when the census updates, update this transcript and review every
 * template that references a changed row in the same change.
 */
const CENSUS_TRANSCRIPT: Readonly<Record<string, string>> = {
  TX_VERSION: 'sound',
  TX_LOCKTIME: 'sound',
  TX_INPUT_COUNT: 'sound_with_conditions',
  TX_OUTPUT_COUNT: 'sound_with_conditions',
  TX_FEE_ABSOLUTE: 'sound_with_conditions',
  DERIVED_NO_NEW_OUTPUTS: 'sound_with_conditions',
  REQKEY: 'sound_with_conditions',
  INPUT_VALUE: 'sound_with_conditions',
  INPUT_SEQUENCE: 'sound_with_conditions',
  INPUT_SOURCE_IS_IN_SETS: 'not_sound',
  OUTPUT_VALUE: 'not_sound',
  OUTPUT_DEST_IS_IN_SETS: 'not_sound',
  OUTPUT_OP_RETURN: 'not_sound',
  OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT: 'not_sound',
  INPUT_COMMITTED_DATA_VERIFY: 'not_sound',
  TX_TEMPLATE_HASH_MATCHES: 'sound_with_conditions',
  COUNT_BASED_CONSTRAINT: 'sound_with_conditions',
  TIME_BASED_CONSTRAINT: 'sound_with_conditions',
  MATCH_ARK_INTENT: 'removed',
  MATCH_ARK_CHECKPOINT: 'sound_with_conditions',
  MATCH_ARK_FORFEIT: 'sound_with_conditions',
};

describe('Census verdict table', () => {
  it('matches the census summary row for row', () => {
    const embedded = Object.keys(SOUNDNESS_CENSUS_VERDICTS).sort();
    const transcript = Object.keys(CENSUS_TRANSCRIPT).sort();
    expect(embedded).toEqual(transcript);
    for (const [conditionType, verdict] of Object.entries(CENSUS_TRANSCRIPT)) {
      expect(SOUNDNESS_CENSUS_VERDICTS[conditionType].verdict).toBe(verdict);
    }
    expect(Object.keys(SOUNDNESS_CENSUS_VERDICTS)).toHaveLength(CENSUS_GRADED_CONDITION_COUNT);
  });

  it('carries a remediated-form carve-out for exactly the rows the census bounds that way', () => {
    const carvedOut = Object.entries(SOUNDNESS_CENSUS_VERDICTS)
      .filter(([, record]) => record.hardAllowedForms !== undefined)
      .map(([conditionType]) => conditionType);
    expect(carvedOut).toEqual(['OUTPUT_DEST_IS_IN_SETS']);
  });

  it('lists exactly the registry-disabled condition slots', () => {
    expect([...DISABLED_CONDITION_TYPES].sort()).toEqual(
      [
        'DERIVED_SIGHASH_TYPE',
        'DERIVED_RBF_ENABLED',
        'DERIVED_IS_COINJOIN_LIKE',
        'DERIVED_IS_PAYJOIN_LIKE',
        'DERIVED_IS_CONSOLIDATION',
        'INPUT_SCRIPT_TYPE',
        'INPUT_SIGHASH_TYPE',
        'OUTPUT_SCRIPT_TYPE',
      ].sort(),
    );
  });
});

describe('Catalogue invariant', () => {
  it('holds at module init and on explicit re-check', () => {
    expect(() => assertCatalogueInvariant()).not.toThrow();
  });

  it('separates the two enforcement tiers', () => {
    const hard = POLICY_TEMPLATES.filter((t) => t.enforcementClass === 'hard_cryptographic');
    const governance = POLICY_TEMPLATES.filter((t) => t.enforcementClass === 'governance_only');
    expect(hard.map((t) => t.templateId).sort()).toEqual(
      [
        'consolidation-only',
        'destination-allowlist',
        'destination-blocklist',
        'fee-ceiling',
        'time-window',
        'usage-velocity',
      ].sort(),
    );
    expect(governance.map((t) => t.templateId).sort()).toEqual(
      ['approval-amount-band', 'human-approval-quorum', 'proposal-expiration', 'required-approver'].sort(),
    );
    for (const template of governance) {
      expect(template.conditionTypes).toHaveLength(0);
    }
  });

  it('rejects a hard template that grades an unsafe condition as hard enforcement', () => {
    const hard = POLICY_TEMPLATES.find((t) => t.templateId === 'fee-ceiling') as Extract<
      (typeof POLICY_TEMPLATES)[number],
      { enforcementClass: 'hard_cryptographic' }
    >;
    expect(() =>
      assertCatalogueInvariant([
        {
          ...hard,
          conditionTypes: ['OUTPUT_VALUE'],
          censusBasis: { OUTPUT_VALUE: SOUNDNESS_CENSUS_VERDICTS['OUTPUT_VALUE'] },
        },
      ]),
    ).toThrow(/not sound/);
    expect(() =>
      assertCatalogueInvariant([
        {
          ...hard,
          conditionTypes: ['DERIVED_SIGHASH_TYPE'],
          censusBasis: { DERIVED_SIGHASH_TYPE: { verdict: 'sound_with_conditions', basis: 'fabricated' } },
        },
      ]),
    ).toThrow(/not census-graded/);
    expect(() =>
      assertCatalogueInvariant([
        {
          ...hard,
          conditionTypes: ['OUTPUT_VALUE'],
          censusBasis: {
            OUTPUT_VALUE: { verdict: 'sound_with_conditions', basis: 'fabricated, contradicting the census' },
          },
        },
      ]),
    ).toThrow(/does not match the census/);
  });
});

describe('Hard template golden vectors', () => {
  it.each(vectors.hard_templates.map((entry) => [entry.template_id, entry] as const))(
    '%s builds the committed canonical output',
    (_id, entry) => {
      const output = buildPolicyTemplateAst(entry.template_id, entry.params);
      expect(output.canonicalJson).toBe(entry.canonical_json);
      expect(output.encodingHex).toBe(entry.encoding_hex);
      expect(output.digestHex).toBe(entry.digest_hex);
    },
  );

  it('round-trips every template AST through the binary encoding', () => {
    for (const entry of vectors.hard_templates) {
      const output = buildPolicyTemplateAst(entry.template_id, entry.params);
      const decoded = canonicalPolicyAstFromHex(output.encodingHex);
      expect(canonicalPolicyAstToHex(decoded)).toBe(entry.encoding_hex);
      expect(decoded.root).toEqual(output.ast.root);
    }
  });

  it('is deterministic across parameter key order and commutative child order', () => {
    const a = buildPolicyTemplateAst('destination-allowlist', {
      addresses: ['tb1qexampleaddress0000000000000000000000000aa', 'tb1qexampleaddress0000000000000000000000000bb'],
      network: 'signet',
    });
    const b = buildPolicyTemplateAst('destination-allowlist', {
      network: 'signet',
      addresses: ['tb1qexampleaddress0000000000000000000000000aa', 'tb1qexampleaddress0000000000000000000000000bb'],
    });
    expect(a.digestHex).toBe(b.digestHex);
    expect(a.encodingHex).toBe(b.encodingHex);
  });

  it('produces distinct digests for distinct configurations', () => {
    const a = buildPolicyTemplateAst('fee-ceiling', { maxFeeSats: 50000 });
    const b = buildPolicyTemplateAst('fee-ceiling', { maxFeeSats: 60000 });
    expect(a.digestHex).not.toBe(b.digestHex);
  });
});

describe('Hard template parameter bounds', () => {
  it('rejects malformed destination sets', () => {
    expect(() => buildPolicyTemplateAst('destination-allowlist', { addresses: [], network: 'signet' })).toThrow(/non-empty/);
    expect(() => buildPolicyTemplateAst('destination-allowlist', { addresses: ['tb1qexampleaddress0000000000000000000000000aa'], network: 'fauxnet' })).toThrow();
    expect(() =>
      buildPolicyTemplateAst('destination-allowlist', {
        addresses: ['tb1qexampleaddress0000000000000000000000000aa', 'tb1qexampleaddress0000000000000000000000000aa'],
        network: 'signet',
      }),
    ).toThrow(/duplicate/);
  });

  it('pins the fee ceiling to a positive LTE bound within the supply cap', () => {
    expect(() => buildPolicyTemplateAst('fee-ceiling', { maxFeeSats: 0 })).toThrow(/positive/);
    expect(() => buildPolicyTemplateAst('fee-ceiling', { maxFeeSats: 2_100_000_000_000_001 })).toThrow(/at most/);
    const output = buildPolicyTemplateAst('fee-ceiling', { maxFeeSats: 50000 });
    expect(output.canonicalJson).toContain('"operator":"LTE"');
  });

  it('requires explicit time-window parameters and rejects internal contradictions', () => {
    expect(() => buildPolicyTemplateAst('time-window', { mode: 'within', startUnixSeconds: 1 })).toThrow();
    expect(() =>
      buildPolicyTemplateAst('time-window', {
        mode: 'within',
        activeDays: [0, 8],
        startHourUtc: '09:00',
        endHourUtc: '17:00',
        startDate: '2027-01-15',
        endDate: '2030-03-20',
        startUnixSeconds: 100,
        endUnixSeconds: 200,
      }),
    ).toThrow(/integers 1 \(Mon\) through 7 \(Sun\)/);
    expect(() =>
      buildPolicyTemplateAst('time-window', {
        mode: 'within',
        activeDays: [1],
        startHourUtc: '17:00',
        endHourUtc: '09:00',
        startDate: '2027-01-15',
        endDate: '2030-03-20',
        startUnixSeconds: 100,
        endUnixSeconds: 200,
      }),
    ).toThrow(/endHourUtc/);
    expect(() =>
      buildPolicyTemplateAst('time-window', {
        mode: 'after',
        startUnixSeconds: 100,
      }),
    ).not.toThrow();
  });

  it('bounds usage velocity and validates reset intervals', () => {
    expect(() => buildPolicyTemplateAst('usage-velocity', { maxUses: 0, resetInterval: 'daily' })).toThrow(/positive/);
    expect(() => buildPolicyTemplateAst('usage-velocity', { maxUses: 100_001, resetInterval: 'daily' })).toThrow(/at most/);
    expect(() => buildPolicyTemplateAst('usage-velocity', { maxUses: 1, resetInterval: 'daily', resetIntervalSeconds: 600 })).toThrow(/cannot be combined/);
    expect(() => buildPolicyTemplateAst('usage-velocity', { maxUses: 1, resetInterval: 'custom' })).toThrow();
    expect(() => buildPolicyTemplateAst('usage-velocity', { maxUses: 1, resetInterval: 'custom', resetIntervalSeconds: 59 })).toThrow(/at least 60/);
  });

  it('takes no parameters for consolidation and never emits the unenforceable direction', () => {
    expect(() => buildPolicyTemplateAst('consolidation-only', { unexpected: true })).toThrow(/no parameters/);
    const output = buildPolicyTemplateAst('consolidation-only', {});
    expect(output.canonicalJson).toContain('"expected_value":true');
  });
});

describe('Fail-closed selection gate', () => {
  const blocklist = buildPolicyTemplateAst('destination-blocklist', {
    addresses: ['tb1qexamplebannedaddress0000000000000000000cc'],
    network: 'signet',
  });
  const allowlist = buildPolicyTemplateAst('destination-allowlist', {
    addresses: ['tb1qexampleaddress0000000000000000000000000aa'],
    network: 'signet',
  });

  const condition = (conditionType: string, conditionParams: Record<string, unknown> = {}): Record<string, unknown> => ({
    type: 'condition',
    conditionType,
    conditionParams,
  });
  const not = (child: Record<string, unknown>): Record<string, unknown> => ({
    type: 'operator',
    operator: 'NOT',
    children: [child],
  });
  const and = (...children: Record<string, unknown>[]): Record<string, unknown> => ({
    type: 'operator',
    operator: 'AND',
    children,
  });

  it('accepts every catalogue template output', () => {
    for (const entry of vectors.hard_templates) {
      const output = buildPolicyTemplateAst(entry.template_id, entry.params);
      expect(() => validatePolicySelectionAst(output.ast.root, { allowUnknownConditionTypes: false })).not.toThrow();
    }
  });

  it('rejects OUTPUT_VALUE as hard enforcement in any form', () => {
    expect(() =>
      validatePolicySelectionAst(condition('OUTPUT_VALUE', { selector: 'ALL', operator: 'LTE', value: 1000 })),
    ).toThrow(/OUTPUT_VALUE/);
    expect(() => validatePolicySelectionAst(not(condition('OUTPUT_VALUE', { selector: 'ALL', operator: 'LTE', value: 1000 })))).toThrow(
      /not supported/,
    );
  });

  it('accepts the exact remediated blocklist shape and only that shape', () => {
    expect(() => validatePolicySelectionAst(blocklist.ast.root)).not.toThrow();
    expect(() => validatePolicySelectionAst(blocklist.ast.root, { allowUnknownConditionTypes: false })).not.toThrow();
    // Negating an ALL-selector atom would allow one banned output beside a clean one.
    expect(() =>
      validatePolicySelectionAst(
        not(condition('OUTPUT_DEST_IS_IN_SETS', { selector: 'ALL', addresses: ['tb1qexamplebannedaddress0000000000000000000cc'], network: 'signet' })),
      ),
    ).toThrow(/ANY-selector/);
    // Negating other families stays out: the census vacuity has no remediated shape here.
    expect(() =>
      validatePolicySelectionAst(
        not(condition('INPUT_SOURCE_IS_IN_SETS', { selector: 'ANY', addresses: ['tb1qexampleaddress0000000000000000000000000aa'], network: 'signet' })),
      ),
    ).toThrow(/not supported/);
    expect(() =>
      validatePolicySelectionAst(
        not(condition('OUTPUT_OP_RETURN', { selector: 'ANY', data_patterns: ['X'] })),
      ),
    ).toThrow(/not supported/);
  });

  it('enforces one negated family per policy and no positive/negated mixing', () => {
    expect(() =>
      validatePolicySelectionAst(and(blocklist.ast.root, blocklist.ast.root)),
    ).toThrow(/at most one negated condition per family/);
    expect(() => validatePolicySelectionAst(and(allowlist.ast.root, blocklist.ast.root))).toThrow(/mixes positive and negated/);
  });

  it('rejects census NOT SOUND conditions, removed conditions, and disabled slots', () => {
    expect(() => validatePolicySelectionAst(condition('OUTPUT_SCRIPTPUBKEY_MATCHES_COMMITMENT', {}))).toThrow(/not sound/);
    expect(() => validatePolicySelectionAst(condition('INPUT_COMMITTED_DATA_VERIFY', {}))).toThrow(/not sound/);
    expect(() => validatePolicySelectionAst(condition('MATCH_ARK_INTENT', {}))).toThrow(/removed/);
    expect(() => validatePolicySelectionAst(condition('DERIVED_SIGHASH_TYPE', { sighash_type: 'SIGHASH_ALL' }))).toThrow(/disabled registry slot/);
    expect(() => validatePolicySelectionAst(condition('INPUT_SIGHASH_TYPE', { selector: 'ALL', sighash_type: 'SIGHASH_ALL' }))).toThrow(/disabled registry slot/);
  });

  it('rejects REQKEY anywhere in a user policy', () => {
    expect(() =>
      validatePolicySelectionAst(condition('REQKEY', { use_descriptor: true, descriptor_template: 'tr(SIGBASH_XPUB/0/*)', derivation_range: 512 })),
    ).toThrow(/system clause/);
    expect(() =>
      validatePolicySelectionAst(
        not(condition('REQKEY', { key_identifier: 'a'.repeat(64), key_type: 'TAP_LEAF_XONLY_PUBKEY' })),
      ),
    ).toThrow(/system clause/);
  });

  it('retains unknown constructs by default and fails closed for the normal path', () => {
    const unknown = condition('ORG_CUSTOM_ATTESTATION', { quorum_note: 'x' });
    expect(() => validatePolicySelectionAst(unknown)).not.toThrow();
    expect(() => validatePolicySelectionAst(unknown, { allowUnknownConditionTypes: false })).toThrow(/template vocabulary/);
  });
});

describe('Governance templates', () => {
  it.each(vectors.governance_facts.map((entry) => [entry.template_id, entry] as const))(
    '%s builds the committed workflow fact',
    (_id, entry) => {
      expect(buildGovernanceTemplateFact(entry.template_id, entry.params)).toEqual(entry.workflow_fact);
    },
  );

  it('emits no POET atoms', () => {
    for (const entry of vectors.governance_facts) {
      const fact = buildGovernanceTemplateFact(entry.template_id, entry.params);
      const serialized = JSON.stringify(fact);
      expect(serialized).not.toContain('conditionType');
      expect(serialized).not.toContain('"operator"');
    }
  });

  it('validates governance parameter bounds', () => {
    expect(() =>
      buildGovernanceTemplateFact('approval-amount-band', {
        thresholds: [
          { amountSats: 100, additionalApprovals: 1 },
          { amountSats: 100, additionalApprovals: 2 },
        ],
      }),
    ).toThrow(/strictly ascending/);
    expect(() => buildGovernanceTemplateFact('human-approval-quorum', { quorum: 0 })).toThrow(/positive/);
    expect(() => buildGovernanceTemplateFact('human-approval-quorum', { quorum: 101 })).toThrow(/at most/);
    expect(() => buildGovernanceTemplateFact('required-approver', { approverKind: 'committee', approverId: 'x' })).toThrow(/role.*person/);
    expect(() => buildGovernanceTemplateFact('proposal-expiration', { expiresInSeconds: 0 })).toThrow(/positive/);
  });
});

describe('Selection records', () => {
  it('binds the enforcement class to the exact output and detects stale records', () => {
    const params = { maxFeeSats: 12345 };
    const selection = createPolicyTemplateSelection('fee-ceiling', params);
    expect(selection.catalogueVersion).toBe(POLICY_TEMPLATE_CATALOGUE_VERSION);
    expect(selection.enforcementClass).toBe('hard_cryptographic');
    expect(() => validatePolicyTemplateSelection(selection)).not.toThrow();

    const stale = { ...selection, astDigestHex: '0'.repeat(64) };
    expect(() => validatePolicyTemplateSelection(stale)).toThrow(/stale or tampered/);

    const tamperedParams = { ...selection, params: { maxFeeSats: 54321 } };
    expect(() => validatePolicyTemplateSelection(tamperedParams)).toThrow(/stale or tampered/);

    const wrongClass = { ...selection, enforcementClass: 'governance_only' };
    expect(() => validatePolicyTemplateSelection(wrongClass)).toThrow(/does not match template class/);

    const wrongVersion = { ...selection, templateVersion: 2 };
    expect(() => validatePolicyTemplateSelection(wrongVersion)).toThrow(/does not match catalogue version/);

    const wrongCatalogue = { ...selection, catalogueVersion: 99 };
    expect(() => validatePolicyTemplateSelection(wrongCatalogue)).toThrow(ContractVersionError);
  });

  it('binds governance selections to the exact workflow fact', () => {
    const selection = createPolicyTemplateSelection('human-approval-quorum', { quorum: 3 });
    expect(selection.enforcementClass).toBe('governance_only');
    expect(() => validatePolicyTemplateSelection(selection)).not.toThrow();
    const tampered = { ...selection, workflowFact: { kind: 'human_approval_quorum', quorum: 4 } };
    expect(() => validatePolicyTemplateSelection(tampered)).toThrow(/stale or tampered/);
  });

  it('revalidates the template output through the fail-closed gate', () => {
    const selection = createPolicyTemplateSelection('destination-blocklist', {
      addresses: ['tb1qexamplebannedaddress0000000000000000000cc'],
      network: 'signet',
    });
    expect(() => validatePolicyTemplateSelection(selection)).not.toThrow();
  });
});

describe('Binary round-trip of composed template output', () => {
  it('keeps template-equivalent configurations identical through canonicalization', () => {
    const direct = buildPolicyTemplateAst('usage-velocity', { maxUses: 2, resetInterval: 'daily' });
    const canonicalized = canonicalizePolicyRoot(direct.ast.root);
    expect(direct.digestHex).toBe(buildPolicyTemplateAst('usage-velocity', { resetInterval: 'daily', maxUses: 2 }).digestHex);
    expect(canonicalized.root).toEqual(direct.ast.root);
  });
});
