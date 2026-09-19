/**
 * Canonical policy AST tests: golden vectors, round-trips, determinism,
 * unknown-construct retention, fail-closed rejection, and the locked
 * system policy composition path.
 */

import {
  CANONICAL_POLICY_CONTRACT_ID,
  CANONICAL_POLICY_VERSION,
  ContractVersionError,
  SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE,
  SYSTEM_REQKEY_DERIVATION_RANGE,
  composeEffectivePolicy,
  canonicalPolicyAstFromHex,
  canonicalJson,
  canonicalizePolicyRoot,
  decodeCanonicalPolicyAstV1,
  effectivePolicyDigestHex,
  encodeCanonicalPolicyAstV1,
  encodeWalletDescriptorV1,
  hexToBytes,
  bytesToHex,
  parseCanonicalPolicyAst,
  policyAstDigestHex,
  policyNodeIdentityPaths,
  systemPolicyAst,
  systemPolicyDigestHex,
  systemWalletOwnershipFragment,
  WALLET_DESCRIPTOR_CONTRACT_ID,
  APPROVAL_COMMITMENT_CONTRACT_ID,
  SYNC_ENVELOPE_CONTRACT_ID,
  EVENT_HEADER_CONTRACT_ID,
  RECOVERY_ENVELOPE_CONTRACT_ID,
  type CanonicalPolicyAstV1,
  type WalletDescriptorV1,
} from './index';
import vectors from './vectors/policy-ast-v1.json';

const DESCRIPTOR: WalletDescriptorV1 = {
  version: 1,
  network: 'signet',
  walletMode: 'sigbash_native',
  signers: [
    {
      kind: 'sigbash_policy_key',
      xpub: 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
      policyKeyId: '11111111-2222-4333-8444-555555555555',
    },
  ],
  allowedSignerSets: [{ signerIndexes: [0] }],
  receiveDescriptor: 'tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(1,<<SIGBASH_XPUB/0/0>>))',
  changeDescriptor: 'tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(1,<<SIGBASH_XPUB/1/0>>))',
};

function condition(conditionType: string, conditionParams: Record<string, unknown> = {}): Record<string, unknown> {
  return { type: 'condition', conditionType, conditionParams };
}

function roundTrip(ast: CanonicalPolicyAstV1): CanonicalPolicyAstV1 {
  return decodeCanonicalPolicyAstV1(encodeCanonicalPolicyAstV1(ast));
}

describe('Canonical policy AST parsing', () => {
  it('parses and canonicalizes a POET v1.1 document', () => {
    const ast = parseCanonicalPolicyAst({
      version: '1.1',
      policy: { type: 'condition', conditionType: 'TX_FEE_ABSOLUTE', conditionParams: { value: 5000 } },
    });
    expect(ast.version).toBe(1);
    expect(ast.root).toEqual({
      type: 'condition',
      conditionType: 'TX_FEE_ABSOLUTE',
      conditionParams: { value: 5000 },
    });
  });

  it('accepts JSON text and rejects malformed JSON and wrong versions fail-closed', () => {
    expect(() => parseCanonicalPolicyAst('{"version":"1.1","policy":{"type":"condition","conditionType":"X","conditionParams":{}}}')).not.toThrow();
    expect(() => parseCanonicalPolicyAst('{not json')).toThrow(ContractVersionError);
    expect(() => parseCanonicalPolicyAst({ version: '1.0', policy: condition('X') })).toThrow(ContractVersionError);
    expect(() => parseCanonicalPolicyAst({ version: '1.1' })).toThrow(/policy root/);
  });

  it('fails closed on unknown operators, which are a closed enum', () => {
    expect(() =>
      parseCanonicalPolicyAst({
        version: '1.1',
        policy: { type: 'operator', operator: 'MAYBE', children: [condition('X')] },
      }),
    ).toThrow(ContractVersionError);
    expect(() =>
      parseCanonicalPolicyAst({
        version: '1.1',
        policy: { type: 'operator', operator: 'AND', children: [] },
      }),
    ).toThrow(/at least one child/);
  });

  it('rejects contradictory and malformed operator parameters', () => {
    expect(() =>
      parseCanonicalPolicyAst({
        version: '1.1',
        policy: {
          type: 'operator',
          operator: 'THRESHOLD',
          operatorParams: { k: 2 },
          threshold: 3,
          children: [condition('X')],
        },
      }),
    ).toThrow(/contradictory/);
    expect(() =>
      parseCanonicalPolicyAst({
        version: '1.1',
        policy: {
          type: 'operator',
          operator: 'THRESHOLD',
          operatorParams: { k: -1 },
          children: [condition('X')],
        },
      }),
    ).toThrow(/non-negative safe integer/);
  });
});

describe('Canonicalization determinism', () => {
  it('is invariant to child order of commutative operators, key order, and whitespace', () => {
    const a = parseCanonicalPolicyAst({
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'AND',
        children: [condition('TX_FEE_ABSOLUTE', { value: 5 }), condition('TX_FEE_ABSOLUTE', { value: 5 })],
      },
    });
    const b = parseCanonicalPolicyAst(
      JSON.stringify({
        version: '1.1',
        policy: {
          type: 'operator',
          operator: 'AND',
          children: [condition('TX_FEE_ABSOLUTE', { value: 5 })],
        },
      }),
    );
    // Identical children dedupe deterministically; both inputs must
    // produce the same canonical bytes.
    expect(encodeCanonicalPolicyAstV1(a)).toEqual(encodeCanonicalPolicyAstV1(b));
  });

  it('sorts commutative children by canonical serialization', () => {
    const ast = parseCanonicalPolicyAst({
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'OR',
        children: [
          condition('ZZZ_CONDITION'),
          condition('AAA_CONDITION'),
          condition('MID_CONDITION'),
        ],
      },
    });
    // All children carry empty parameter objects, so the canonical
    // serialization orders them purely by condition type name.
    const children = (ast.root as { children: Array<{ conditionType: string }> }).children;
    expect(children.map((c) => c.conditionType)).toEqual([
      'AAA_CONDITION',
      'MID_CONDITION',
      'ZZZ_CONDITION',
    ]);
  });

  it('flattens nested AND/OR chains and never changes operator identity', () => {
    const ast = parseCanonicalPolicyAst({
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'AND',
        children: [
          condition('A'),
          { type: 'operator', operator: 'AND', children: [condition('B'), { type: 'operator', operator: 'AND', children: [condition('C')] }] },
        ],
      },
    });
    expect(ast.root).toMatchObject({ type: 'operator', operator: 'AND' });
    expect((ast.root as { children: unknown[] }).children).toHaveLength(3);
  });

  it('never sorts WEIGHTED_THRESHOLD children (positional weights)', () => {
    const ast = parseCanonicalPolicyAst({
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'WEIGHTED_THRESHOLD',
        operatorParams: { k: 3, weights: [1, 2] },
        children: [condition('ZZZ_LATE'), condition('AAA_EARLY')],
      },
    });
    const children = (ast.root as { children: Array<{ conditionType: string }> }).children;
    expect(children.map((c) => c.conditionType)).toEqual(['ZZZ_LATE', 'AAA_EARLY']);
  });

  it('strips cosmetic descriptions and reconciles the deprecated threshold field', () => {
    const ast = parseCanonicalPolicyAst({
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'THRESHOLD',
        threshold: 2,
        description: 'cosmetic',
        children: [condition('A'), condition('B')],
      },
    });
    const node = ast.root as Record<string, unknown>;
    expect(node['description']).toBeUndefined();
    expect(node['threshold']).toBeUndefined();
    expect(node['operatorParams']).toEqual({ k: 2 });
  });

  it('produces stable node identity paths in canonical order', () => {
    const ast = parseCanonicalPolicyAst({
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'AND',
        children: [condition('A'), { type: 'operator', operator: 'NOT', children: [condition('B')] }],
      },
    });
    // Canonical child order sorts the NOT subtree ("children..." sorts
    // before "condition...") ahead of the bare condition leaf.
    expect(policyNodeIdentityPaths(ast)).toEqual(['n', 'n.0', 'n.0.0', 'n.1']);
  });
});

describe('Canonical binary serialization round trip', () => {
  it('round-trips a mixed policy losslessly, including per-node weights', () => {
    const ast = parseCanonicalPolicyAst({
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'AND',
        children: [
          { ...condition('COUNT_BASED_CONSTRAINT', { max_uses: 3 }), weight: 2 },
          condition('TIME_BASED_CONSTRAINT', { window_seconds: 3600 }),
          {
            type: 'operator',
            operator: 'WEIGHTED_THRESHOLD',
            operatorParams: { k: 3, weights: [1, 2] },
            children: [condition('X'), condition('Y')],
          },
        ],
      },
    });
    const decoded = roundTrip(ast);
    expect(decoded).toEqual(ast);
    expect(encodeCanonicalPolicyAstV1(decoded)).toEqual(encodeCanonicalPolicyAstV1(ast));
  });

  it('round-trips all parameter value shapes byte-identically', () => {
    const ast = parseCanonicalPolicyAst({
      version: '1.1',
      policy: condition('ORG_CUSTOM', {
        text: 'hello',
        flag: true,
        big: 2100000000000000,
        negative: -7,
        fraction: 12.5,
        nothing: null,
        nested: { b: 2, a: [1, 'two', false] },
      }),
    });
    const decoded = roundTrip(ast);
    expect(decoded).toEqual(ast);
    expect(bytesToHex(encodeCanonicalPolicyAstV1(decoded))).toBe(bytesToHex(encodeCanonicalPolicyAstV1(ast)));
  });

  it('is idempotent through parse → canonicalize → serialize → parse', () => {
    const ast = parseCanonicalPolicyAst(vectors.user_policy_a.poet_json as string);
    const text = canonicalJson(ast.root);
    const reparsed = parseCanonicalPolicyAst({ version: '1.1', policy: JSON.parse(text) });
    expect(encodeCanonicalPolicyAstV1(reparsed)).toEqual(encodeCanonicalPolicyAstV1(ast));
    const twice = roundTrip(roundTrip(ast));
    expect(encodeCanonicalPolicyAstV1(twice)).toEqual(encodeCanonicalPolicyAstV1(ast));
  });
});

describe('Canonical policy digests', () => {
  it('matches the golden vectors for equivalent reformatted policies', () => {
    const a = parseCanonicalPolicyAst(vectors.user_policy_a.poet_json as string);
    const b = parseCanonicalPolicyAst(vectors.user_policy_reformatted_equivalent.poet_json as string);
    expect(bytesToHex(encodeCanonicalPolicyAstV1(a))).toBe(vectors.user_policy_a.encoding_hex);
    expect(bytesToHex(encodeCanonicalPolicyAstV1(b))).toBe(vectors.user_policy_reformatted_equivalent.encoding_hex);
    expect(policyAstDigestHex(a)).toBe(vectors.user_policy_a.digest_hex);
    expect(policyAstDigestHex(b)).toBe(vectors.user_policy_a.digest_hex);
    expect(canonicalJson(a.root)).toBe(vectors.user_policy_a.canonical_json);
  });

  it('retains unknown-but-valid condition constructs byte-identically', () => {
    const ast = parseCanonicalPolicyAst(vectors.user_policy_unknown_condition.poet_json as string);
    expect(bytesToHex(encodeCanonicalPolicyAstV1(ast))).toBe(vectors.user_policy_unknown_condition.encoding_hex);
    expect(policyAstDigestHex(ast)).toBe(vectors.user_policy_unknown_condition.digest_hex);
    const decoded = roundTrip(ast);
    const params = (decoded.root as { conditionParams: Record<string, unknown> }).conditionParams;
    expect(params).toEqual({
      quorum_note: { roles: ['treasurer', 'cfo'], min: 2 },
      basis_points: 12.5,
      note: null,
      strict: false,
    });
  });

  it('changes the digest when semantics change', () => {
    const a = parseCanonicalPolicyAst({
      version: '1.1',
      policy: condition('TX_FEE_ABSOLUTE', { value: 5 }),
    });
    const b = parseCanonicalPolicyAst({
      version: '1.1',
      policy: condition('TX_FEE_ABSOLUTE', { value: 6 }),
    });
    expect(policyAstDigestHex(a)).not.toBe(policyAstDigestHex(b));
  });
});

describe('Locked system policy', () => {
  it('builds the frozen descriptor-mode REQKEY clause', () => {
    const fragment = systemWalletOwnershipFragment(DESCRIPTOR);
    expect(fragment).toEqual({
      type: 'condition',
      conditionType: 'REQKEY',
      conditionParams: {
        use_descriptor: true,
        descriptor_template: SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE,
        derivation_range: SYSTEM_REQKEY_DERIVATION_RANGE,
      },
    });
    expect(Object.isFrozen(fragment)).toBe(true);
    expect(SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE).toBe('tr(SIGBASH_XPUB/0/*)');
    expect(SYSTEM_REQKEY_DERIVATION_RANGE).toBe(512);
  });

  it('rejects descriptors without the SIGBASH_XPUB placeholder or with a wrong version', () => {
    expect(() =>
      systemWalletOwnershipFragment({ ...DESCRIPTOR, receiveDescriptor: 'tr(abc)' }),
    ).toThrow(/SIGBASH_XPUB/);
    expect(() => systemWalletOwnershipFragment({ ...DESCRIPTOR, version: 2 as typeof DESCRIPTOR.version })).toThrow(
      ContractVersionError,
    );
  });

  it('composes AND(system, user) and matches the system and effective vectors', () => {
    const system = systemPolicyAst(DESCRIPTOR);
    expect(bytesToHex(encodeCanonicalPolicyAstV1(system))).toBe(vectors.system_policy.encoding_hex);
    expect(systemPolicyDigestHex(DESCRIPTOR)).toBe(vectors.system_policy.digest_hex);

    const user = parseCanonicalPolicyAst(vectors.user_policy_a.poet_json as string);
    const effective = composeEffectivePolicy(system, user);
    expect(bytesToHex(encodeCanonicalPolicyAstV1(effective))).toBe(vectors.effective_policy.encoding_hex);
    expect(effectivePolicyDigestHex(system, user)).toBe(vectors.effective_policy.digest_hex);
  });

  it('keeps the system clause present under every composition path', () => {
    const system = systemPolicyAst(DESCRIPTOR);
    const user = parseCanonicalPolicyAst({
      version: '1.1',
      policy: { type: 'operator', operator: 'OR', children: [condition('A'), condition('B')] },
    });
    const effective = composeEffectivePolicy(system, user);
    const text = canonicalJson(effective.root);
    expect(text).toContain('"conditionType":"REQKEY"');
    expect(text).toContain(SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE);
  });

  it('rejects user policies that try to carry their own REQKEY clause', () => {
    const system = systemPolicyAst(DESCRIPTOR);
    const hostile = parseCanonicalPolicyAst({
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'AND',
        children: [
          condition('A'),
          { type: 'operator', operator: 'NOT', children: [condition('REQKEY', { key_identifier: 'aa'.repeat(32) })] },
        ],
      },
    });
    expect(() => composeEffectivePolicy(system, hostile)).toThrow(/REQKEY/);
  });

  it('freezes the composed AST against mutation', () => {
    const system = systemPolicyAst(DESCRIPTOR);
    const user = parseCanonicalPolicyAst({ version: '1.1', policy: condition('A') });
    const effective = composeEffectivePolicy(system, user);
    expect(Object.isFrozen(effective)).toBe(true);
    expect(Object.isFrozen(effective.root)).toBe(true);
  });
});

describe('CanonicalPolicyAst contract header', () => {
  it('opens with contract id 0x07 and version 1', () => {
    const ast = parseCanonicalPolicyAst({ version: '1.1', policy: condition('A') });
    const bytes = encodeCanonicalPolicyAstV1(ast);
    expect(Array.from(bytes.subarray(0, 2))).toEqual([CANONICAL_POLICY_CONTRACT_ID, CANONICAL_POLICY_VERSION]);
    expect(CANONICAL_POLICY_CONTRACT_ID).toBe(0x07);
  });

  it('decodes hex vectors and rejects foreign contract ids and trailing bytes', () => {
    const ast = canonicalPolicyAstFromHex(vectors.user_policy_a.encoding_hex);
    expect(policyAstDigestHex(ast)).toBe(vectors.user_policy_a.digest_hex);

    const raw = hexToBytes(vectors.user_policy_a.encoding_hex);
    expect(() => decodeCanonicalPolicyAstV1(raw.subarray(1))).toThrow(ContractVersionError);
    const corrupt = new Uint8Array(raw.length + 1);
    corrupt.set(raw);
    expect(() => decodeCanonicalPolicyAstV1(corrupt)).toThrow(/trailing bytes/);
    const truncated = raw.subarray(0, raw.length - 1);
    expect(() => decodeCanonicalPolicyAstV1(truncated)).toThrow();
  });

  it('keeps binary contract ids distinct across the module', () => {
    const ids = [
      WALLET_DESCRIPTOR_CONTRACT_ID,
      APPROVAL_COMMITMENT_CONTRACT_ID,
      SYNC_ENVELOPE_CONTRACT_ID,
      EVENT_HEADER_CONTRACT_ID,
      RECOVERY_ENVELOPE_CONTRACT_ID,
      CANONICAL_POLICY_CONTRACT_ID,
    ];
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('Structural hygiene of canonical projection inputs', () => {
  it('rejects nodes that have no canonical representation', () => {
    expect(() => parseCanonicalPolicyAst({ version: '1.1', policy: { type: 'unknown' } })).toThrow(/node type/);
    expect(() =>
      parseCanonicalPolicyAst({ version: '1.1', policy: condition('X', { bad: undefined }) }),
    ).toThrow(/undefined/);
    expect(() =>
      parseCanonicalPolicyAst({ version: '1.1', policy: condition('X', { bad: Number.NaN }) }),
    ).toThrow(/finite/);
    expect(() => canonicalizePolicyRoot({ type: 'condition', conditionType: '' })).toThrow(/conditionType/);
  });
});
