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
  WALLET_REQKEY_TEMPLATE_PREFIX,
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
} from './index';
import { HDKey } from '@scure/bip32';
import { buildInstitutionalWalletDescriptor } from '../wallet/walletBuilder';
import { systemPolicyReqkeyTemplatePayload, validateWalletReqkeyTemplate } from '../wallet/reqkeyTemplate';
import vectors from './vectors/policy-ast-v1.json';

const SIGNET_HD_VERSIONS = { private: 0x04358394, public: 0x043587cf };

/**
 * Deterministic wallet-ownership REQKEY template payload for the system
 * clause: the same fixed seed always yields the same network-correct
 * Sigbash xpub, so the committed atom (and its golden vectors) is stable.
 */
function walletReqkeyPayload(): string {
  const xpub = HDKey.fromMasterSeed(new Uint8Array(32).fill(0x50), SIGNET_HD_VERSIONS).publicExtendedKey;
  const wallet = buildInstitutionalWalletDescriptor({
    network: 'signet',
    signers: [{ kind: 'sigbash_policy_key', xpub, policyKeyId: '11111111-2222-4333-8444-555555555555' }],
    allowedSignerSets: [[0]],
  });
  return systemPolicyReqkeyTemplatePayload(wallet);
}

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

describe('Multiplicity-semantic commutative operators', () => {
  it('preserves duplicate children for XOR, where multiplicity is the semantics', () => {
    const doubled = parseCanonicalPolicyAst({
      version: '1.1',
      policy: { type: 'operator', operator: 'XOR', children: [condition('A'), condition('A')] },
    });
    const single = parseCanonicalPolicyAst({
      version: '1.1',
      policy: { type: 'operator', operator: 'XOR', children: [condition('A')] },
    });
    expect((doubled.root as { children: unknown[] }).children).toHaveLength(2);
    expect(policyAstDigestHex(doubled)).not.toBe(policyAstDigestHex(single));
  });

  it('preserves duplicate children for THRESHOLD, EXACTLY, AT_MOST, and MAJORITY', () => {
    for (const operator of ['THRESHOLD', 'EXACTLY', 'AT_MOST', 'MAJORITY'] as const) {
      const params = operator === 'THRESHOLD' || operator === 'EXACTLY' ? { k: 2 } : {};
      const doubled = parseCanonicalPolicyAst({
        version: '1.1',
        policy: {
          type: 'operator',
          operator,
          ...(Object.keys(params).length > 0 ? { operatorParams: params } : {}),
          children: [condition('A'), condition('A'), condition('B')],
        },
      });
      const deduped = parseCanonicalPolicyAst({
        version: '1.1',
        policy: {
          type: 'operator',
          operator,
          ...(Object.keys(params).length > 0 ? { operatorParams: params } : {}),
          children: [condition('A'), condition('B')],
        },
      });
      expect(`${operator}: ${(doubled.root as { children: unknown[] }).children.length}`).toBe(`${operator}: 3`);
      expect(policyAstDigestHex(doubled)).not.toBe(policyAstDigestHex(deduped));
    }
  });

  it('still removes duplicate children for AND, OR, NAND, and NOR', () => {
    for (const operator of ['AND', 'OR', 'NAND', 'NOR'] as const) {
      const ast = parseCanonicalPolicyAst({
        version: '1.1',
        policy: { type: 'operator', operator, children: [condition('A'), condition('A')] },
      });
      expect(`${operator}: ${(ast.root as { children: unknown[] }).children.length}`).toBe(`${operator}: 1`);
    }
  });

  it('is idempotent when child multiplicity is preserved', () => {
    const ast = parseCanonicalPolicyAst({
      version: '1.1',
      policy: {
        type: 'operator',
        operator: 'THRESHOLD',
        operatorParams: { k: 2 },
        children: [condition('A'), condition('A'), condition('B')],
      },
    });
    const text = canonicalJson(ast.root);
    const reparsed = parseCanonicalPolicyAst({ version: '1.1', policy: JSON.parse(text) });
    expect(encodeCanonicalPolicyAstV1(reparsed)).toEqual(encodeCanonicalPolicyAstV1(ast));
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
  it('builds the frozen wallet-template REQKEY clause over the full derivation universe', () => {
    const payload = walletReqkeyPayload();
    const fragment = systemWalletOwnershipFragment(payload);
    expect(fragment).toEqual({
      type: 'condition',
      conditionType: 'REQKEY',
      conditionParams: {
        use_descriptor: true,
        descriptor_template: payload,
        derivation_range: SYSTEM_REQKEY_DERIVATION_RANGE,
      },
    });
    expect(Object.isFrozen(fragment)).toBe(true);
    expect(payload.startsWith(WALLET_REQKEY_TEMPLATE_PREFIX)).toBe(true);
    expect(SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE).toBe('tr(SIGBASH_XPUB/0/*)');
    expect(SYSTEM_REQKEY_DERIVATION_RANGE).toBe(512);
  });

  it('rejects fragment inputs that are not the wallet-ownership template payload', () => {
    expect(() => systemWalletOwnershipFragment('')).toThrow(/required/);
    expect(() => systemWalletOwnershipFragment(SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE)).toThrow(
      /wallet-ownership REQKEY template payload/,
    );
    expect(() => systemWalletOwnershipFragment('sigbashwd1:zz')).toThrow(/must be hex/);
    expect(() => systemWalletOwnershipFragment('not-a-template')).toThrow(
      /wallet-ownership REQKEY template payload/,
    );
  });

  it('binds the template to the full receive-then-change candidate universe, never a subset', () => {
    const payload = walletReqkeyPayload();
    // The wallet-template mode commits receive 0..255 then change 0..255 —
    // the 512-candidate universe the depth-9 gadget holds. The legacy form
    // would instead commit one unbounded receive branch: change indices
    // would fail membership and receive indices beyond the wallet universe
    // would become provable.
    expect(() => validateWalletReqkeyTemplate(payload, SYSTEM_REQKEY_DERIVATION_RANGE)).not.toThrow();
    expect(() => validateWalletReqkeyTemplate(payload, 256)).toThrow(/no deterministic subset meaning/);
  });

  it('composes AND(system, user) and matches the system and effective vectors', () => {
    const system = systemPolicyAst(walletReqkeyPayload());
    expect(bytesToHex(encodeCanonicalPolicyAstV1(system))).toBe(vectors.system_policy.encoding_hex);
    expect(systemPolicyDigestHex(walletReqkeyPayload())).toBe(vectors.system_policy.digest_hex);

    const user = parseCanonicalPolicyAst(vectors.user_policy_a.poet_json as string);
    const effective = composeEffectivePolicy(system, user);
    expect(bytesToHex(encodeCanonicalPolicyAstV1(effective))).toBe(vectors.effective_policy.encoding_hex);
    expect(effectivePolicyDigestHex(system, user)).toBe(vectors.effective_policy.digest_hex);
  });

  it('keeps the system clause present under every composition path', () => {
    const system = systemPolicyAst(walletReqkeyPayload());
    const user = parseCanonicalPolicyAst({
      version: '1.1',
      policy: { type: 'operator', operator: 'OR', children: [condition('A'), condition('B')] },
    });
    const effective = composeEffectivePolicy(system, user);
    const text = canonicalJson(effective.root);
    expect(text).toContain('"conditionType":"REQKEY"');
    expect(text).toContain(WALLET_REQKEY_TEMPLATE_PREFIX);
  });

  it('rejects composition of a system clause in the legacy unbounded descriptor form', () => {
    const user = parseCanonicalPolicyAst({ version: '1.1', policy: condition('A') });
    const legacyAtom = canonicalizePolicyRoot({
      type: 'condition',
      conditionType: 'REQKEY',
      conditionParams: {
        use_descriptor: true,
        descriptor_template: SYSTEM_REQKEY_DESCRIPTOR_TEMPLATE,
        derivation_range: SYSTEM_REQKEY_DERIVATION_RANGE,
      },
    });
    expect(() => composeEffectivePolicy(legacyAtom, user)).toThrow(/legacy descriptor form/);
  });

  it('rejects a system atom that is not the sole unconditional REQKEY atom', () => {
    const user = parseCanonicalPolicyAst({ version: '1.1', policy: condition('A') });
    const weldedAtom = canonicalizePolicyRoot({
      type: 'operator',
      operator: 'AND',
      children: [
        {
          type: 'condition',
          conditionType: 'REQKEY',
          conditionParams: {
            use_descriptor: true,
            descriptor_template: walletReqkeyPayload(),
            derivation_range: SYSTEM_REQKEY_DERIVATION_RANGE,
          },
        },
        condition('A'),
      ],
    });
    expect(() => composeEffectivePolicy(weldedAtom, user)).toThrow(/alone and unconditional/);
  });

  it('rejects a wallet-template atom whose derivation range commits another domain', () => {
    const user = parseCanonicalPolicyAst({ version: '1.1', policy: condition('A') });
    const foreignRangeAtom = canonicalizePolicyRoot({
      type: 'condition',
      conditionType: 'REQKEY',
      conditionParams: {
        use_descriptor: true,
        descriptor_template: walletReqkeyPayload(),
        derivation_range: 1000,
      },
    });
    expect(() => composeEffectivePolicy(foreignRangeAtom, user)).toThrow(/no other derivation range/);
  });

  it('rejects user policies that try to carry their own REQKEY clause', () => {
    const system = systemPolicyAst(walletReqkeyPayload());
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
    const system = systemPolicyAst(walletReqkeyPayload());
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
