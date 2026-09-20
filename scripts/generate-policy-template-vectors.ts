/**
 * Generates the deterministic golden vectors for the policy template
 * catalogue. Run from the sdk directory after a temporary CommonJS build
 * of this script plus src/contracts (the sdk package is ESM, so the temp
 * output needs a CommonJS package marker, and __dirname-relative output
 * needs the vectors directory to exist before the run):
 *
 *   npx tsc scripts/generate-policy-template-vectors.ts src/contracts/index.ts \
 *     --outDir .tmp-vecgen --module commonjs --moduleResolution node \
 *     --target es2020 --esModuleInterop --skipLibCheck
 *   echo '{"type":"commonjs"}' > .tmp-vecgen/package.json
 *   mkdir -p .tmp-vecgen/src/contracts/vectors
 *   node .tmp-vecgen/scripts/generate-policy-template-vectors.js
 *   cp .tmp-vecgen/src/contracts/vectors/policy-templates-v1.json \
 *      src/contracts/vectors/policy-templates-v1.json
 *   rm -rf .tmp-vecgen
 *
 * The output file src/contracts/vectors/policy-templates-v1.json is
 * committed. There is deliberately no application-backend mirror of these
 * vectors: templates are compiled browser-side only and the server sees
 * policy digests only, never plaintext policy semantics.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  POLICY_TEMPLATE_CATALOGUE_VERSION,
  buildGovernanceTemplateFact,
  buildPolicyTemplateAst,
  createPolicyTemplateSelection,
} from '../src/contracts/index';

const HARD_SAMPLES: ReadonlyArray<{ template_id: string; params: Record<string, unknown> }> = [
  {
    template_id: 'destination-allowlist',
    params: {
      network: 'signet',
      requireChangeToInputAddresses: true,
      addresses: [
        'tb1qexampleaddress0000000000000000000000000aa',
        'tb1qexampleaddress0000000000000000000000000bb',
      ],
    },
  },
  {
    template_id: 'destination-blocklist',
    params: {
      network: 'signet',
      addresses: ['tb1qexamplebannedaddress0000000000000000000cc'],
    },
  },
  {
    template_id: 'fee-ceiling',
    params: { maxFeeSats: 50000 },
  },
  {
    template_id: 'time-window',
    params: {
      mode: 'within',
      activeDays: [3, 1, 2],
      startHourUtc: '09:00',
      endHourUtc: '17:00',
      startDate: '2027-01-15',
      endDate: '2030-03-20',
      startUnixSeconds: 1800000000,
      endUnixSeconds: 1900000000,
    },
  },
  {
    template_id: 'time-window',
    params: { mode: 'after', startUnixSeconds: 1893456000 },
  },
  {
    template_id: 'usage-velocity',
    params: { maxUses: 5, resetInterval: '6h', resetType: 'rolling' },
  },
  {
    template_id: 'consolidation-only',
    params: {},
  },
];

const GOVERNANCE_SAMPLES: ReadonlyArray<{ template_id: string; params: Record<string, unknown> }> = [
  {
    template_id: 'approval-amount-band',
    params: {
      thresholds: [
        { amountSats: 1000000, additionalApprovals: 1 },
        { amountSats: 100000000, additionalApprovals: 2 },
      ],
    },
  },
  { template_id: 'human-approval-quorum', params: { quorum: 2 } },
  { template_id: 'required-approver', params: { approverKind: 'role', approverId: 'treasurer' } },
  { template_id: 'proposal-expiration', params: { expiresInSeconds: 86400 } },
];

const VECTORS = {
  catalogue_version: POLICY_TEMPLATE_CATALOGUE_VERSION,
  hard_templates: HARD_SAMPLES.map((sample) => {
    const output = buildPolicyTemplateAst(sample.template_id, sample.params);
    return {
      template_id: sample.template_id,
      params: sample.params,
      canonical_json: output.canonicalJson,
      encoding_hex: output.encodingHex,
      digest_hex: output.digestHex,
    };
  }),
  governance_facts: GOVERNANCE_SAMPLES.map((sample) => ({
    template_id: sample.template_id,
    params: sample.params,
    workflow_fact: buildGovernanceTemplateFact(sample.template_id, sample.params),
  })),
  selection_example: createPolicyTemplateSelection('destination-allowlist', {
    network: 'signet',
    addresses: ['tb1qexampleaddress0000000000000000000000000aa'],
  }),
};

const outPath = join(__dirname, '..', 'src', 'contracts', 'vectors', 'policy-templates-v1.json');
writeFileSync(outPath, JSON.stringify(VECTORS, null, 2) + '\n');
console.log(`wrote ${outPath}`);
