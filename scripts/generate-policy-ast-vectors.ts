/**
 * Generates the deterministic golden vectors for the canonical policy AST
 * contract (0x07). Run from the sdk directory after a temporary CommonJS
 * build of this script plus src/contracts:
 *
 *   npx tsc scripts/generate-policy-ast-vectors.ts src/contracts/index.ts \
 *     --outDir /tmp/policyvecgen --module commonjs --moduleResolution node \
 *     --target es2020 --esModuleInterop --skipLibCheck
 *   node /tmp/policyvecgen/scripts/generate-policy-ast-vectors.js
 *
 * The output file src/contracts/vectors/policy-ast-v1.json is committed.
 * There is deliberately no application-backend mirror of these vectors:
 * the server sees policy digests only, never plaintext policy semantics.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  bytesToHex,
  canonicalJson,
  canonicalPolicyAstToHex,
  encodeWalletDescriptorV1,
  parseCanonicalPolicyAst,
  policyAstDigestHex,
  systemPolicyAst,
  composeEffectivePolicy,
  type WalletDescriptorV1,
} from '../src/contracts/index';

const DESCRIPTOR: WalletDescriptorV1 = {
  version: 1,
  network: 'signet',
  walletMode: 'sigbash_native',
  signers: [
    { kind: 'sigbash_policy_key', xpub: 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB', policyKeyId: '11111111-2222-4333-8444-555555555555' },
  ],
  allowedSignerSets: [{ signerIndexes: [0] }],
  receiveDescriptor: 'tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(1,<<SIGBASH_XPUB/0/0>>))',
  changeDescriptor: 'tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(1,<<SIGBASH_XPUB/1/0>>))',
};

// User policy A: a threshold of a fee ceiling and two destination rules.
const USER_POLICY_A_DOC = {
  version: '1.1',
  policy: {
    type: 'operator',
    operator: 'THRESHOLD',
    operatorParams: { k: 2 },
    children: [
      { type: 'condition', conditionType: 'TX_FEE_ABSOLUTE', conditionParams: { max_fee_sats: 50000 } },
      { type: 'condition', conditionType: 'OUTPUT_DEST_IS_IN_SETS', conditionParams: { addresses: [], use_descriptor: true } },
      { type: 'condition', conditionType: 'TIME_BASED_CONSTRAINT', conditionParams: { window_seconds: 3600 } },
    ],
  },
};

// User policy B: the same policy reformatted — children permuted, parameter
// keys reordered, deprecated top-level threshold instead of operatorParams,
// and cosmetic descriptions. Must canonicalize to the exact same bytes and
// digest as A.
const USER_POLICY_B_DOC = {
  policy: {
    type: 'operator',
    operator: 'THRESHOLD',
    threshold: 2,
    children: [
      {
        type: 'condition',
        conditionType: 'TIME_BASED_CONSTRAINT',
        description: 'business hours',
        conditionParams: { window_seconds: 3600 },
      },
      { type: 'condition', conditionType: 'TX_FEE_ABSOLUTE', conditionParams: { max_fee_sats: 50000 } },
      { type: 'condition', conditionType: 'OUTPUT_DEST_IS_IN_SETS', conditionParams: { use_descriptor: true, addresses: [] } },
    ],
  },
  version: '1.1',
};

// Unknown-but-valid condition type with exotic parameters — retained
// verbatim by the canonical projection.
const USER_POLICY_UNKNOWN_DOC = {
  version: '1.1',
  policy: {
    type: 'condition',
    conditionType: 'ORG_CUSTOM_ATTESTATION',
    conditionParams: {
      quorum_note: { roles: ['treasurer', 'cfo'], min: 2 },
      basis_points: 12.5,
      note: null,
      strict: false,
    },
  },
};

const USER_A = parseCanonicalPolicyAst(USER_POLICY_A_DOC);
const USER_B = parseCanonicalPolicyAst(USER_POLICY_B_DOC);
const USER_UNKNOWN = parseCanonicalPolicyAst(USER_POLICY_UNKNOWN_DOC);
const SYSTEM = systemPolicyAst(DESCRIPTOR);
const EFFECTIVE = composeEffectivePolicy(SYSTEM, USER_A);

const entry = (poetDoc: unknown, ast: ReturnType<typeof parseCanonicalPolicyAst>) => ({
  poet_json: poetDoc === null ? null : JSON.stringify(poetDoc),
  canonical_json: canonicalJson(ast.root),
  encoding_hex: canonicalPolicyAstToHex(ast),
  digest_hex: policyAstDigestHex(ast),
});

const VECTORS = {
  wallet_descriptor_v1: {
    fields: DESCRIPTOR,
    encoding_hex: '',
  },
  user_policy_a: entry(USER_POLICY_A_DOC, USER_A),
  user_policy_reformatted_equivalent: entry(USER_POLICY_B_DOC, USER_B),
  user_policy_unknown_condition: entry(USER_POLICY_UNKNOWN_DOC, USER_UNKNOWN),
  system_policy: entry(null, SYSTEM),
  effective_policy: entry(null, EFFECTIVE),
};

VECTORS.wallet_descriptor_v1.encoding_hex = bytesToHex(encodeWalletDescriptorV1(DESCRIPTOR));

const outPath = join(__dirname, '..', 'src', 'contracts', 'vectors', 'policy-ast-v1.json');
writeFileSync(outPath, JSON.stringify(VECTORS, null, 2) + '\n');
console.log(`wrote ${outPath}`);
