/**
 * Generates the deterministic golden vectors for the cross-component
 * contracts. Run from the sdk directory after a temporary CommonJS build
 * of this script plus src/contracts:
 *
 *   npx tsc scripts/generate-contract-vectors.ts src/contracts/index.ts \
 *     --outDir /tmp/vecgen --module commonjs --moduleResolution node \
 *     --target es2020 --esModuleInterop --skipLibCheck
 *   node /tmp/vecgen/scripts/generate-contract-vectors.js
 *
 * The output file src/contracts/vectors/contracts-v1.json is committed.
 * The Flask mirror re-encodes these vectors byte-for-byte; any change to
 * a contract regenerates this file in the same change.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  encodeWalletDescriptorV1,
  computeWalletId,
  encodeApprovalCommitmentV1,
  computeApprovalCommitment,
  encodeEncryptedEventHeaderV1,
  encodeCapabilityEpoch,
  encodeRecoveryEnvelopeVersion,
  bytesToHex,
  hexToBytes,
} from '../src/contracts/index';

const VECTORS = {
  wallet_descriptor_v1: {
    fields: {
      network: 'signet',
      wallet_mode: 'mixed',
      signers: [
        { kind: 'sigbash_policy_key', xpub: 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB', policy_key_id: '11111111-2222-4333-8444-555555555555' },
        { kind: 'external_xpub', xpub: 'xpub661MyMwAqRbcFtXgS5sYJABqqy9CpwBsGA4hMCmsv3nAjfMD3MfDDtqR8zZGDzBTXTtbcc6KkbpXjhBXTQeSCbhDdq9nJpLksFjSyb3Tiyx' },
      ],
      allowed_signer_sets: [{ signer_indexes: [0] }, { signer_indexes: [0, 1] }],
      receive_descriptor: 'tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(1,<<SIGBASH_XPUB/0/0>>,<<EXTERNAL_XPUB/0/0>>))',
      change_descriptor: 'tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(1,<<SIGBASH_XPUB/1/0>>,<<EXTERNAL_XPUB/1/0>>))',
    },
    encoding_hex: '',
  },
  wallet_id_v1: {
    network: 'mainnet',
    receive_descriptor: 'tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(1,<<KEY/0/0>>))',
    change_descriptor: 'tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(1,<<KEY/1/0>>))',
    wallet_id_hex: '',
  },
  approval_commitment_v1: {
    fields: {
      network: 'signet',
      wallet_id_hex: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      policy_version_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      selected_tapleaf_hash_hex: '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
      selected_customer_signer_ids: ['external-xpub-fingerprint-a1b2'],
      unsigned_tx_version: 2,
      unsigned_tx_locktime: 650000,
      ordered_inputs: [
        {
          outpoint_txid_hex: '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f',
          outpoint_vout: 1,
          sequence: 0xfffffffd,
          prevout_amount: 90000,
          prevout_script_pubkey_hex: '5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          sighash_type: 0x81,
        },
      ],
      ordered_outputs: [
        { amount: 45000, script_pubkey_hex: '5120bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' },
        { amount: 40000, script_pubkey_hex: '5120cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' },
      ],
    },
    encoding_hex: '',
    commitment_hex: '',
  },
  encrypted_event_header_v1: {
    fields: {
      schema_version: 1,
      event_id_hex: '000102030405060708090a0b0c0d0e0f',
      event_type: 'transaction.proposal.created',
      org_client_id_hex: '101112131415161718191a1b1c1d1e1f',
      wallet_client_id_hex: '202122232425262728292a2b2c2d2e2f',
      subject_id_hex: null,
      actor_user_id_hex: '303132333435363738393a3b3c3d3e3f',
      client_timestamp_ms: 1726740000000,
      parent_event_hashes_hex: ['404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'],
      semantic_commitment_hex: '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f',
      actor_signature_hex: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf',
    },
    encoding_hex: '',
  },
  capability_epoch_v1: [
    { group_id: 'org-common', epoch: 1, encoding_hex: '' },
    { group_id: 'wallet:6f9619ff-8b86-4d01-b42d-00cf4fc964ff', epoch: 7, encoding_hex: '' },
  ],
  recovery_envelope_v1: {
    version_prefix_hex: '',
  },
};

const wdFields = VECTORS.wallet_descriptor_v1.fields;
const wdEncoding = encodeWalletDescriptorV1({
  version: 1,
  network: wdFields.network as 'signet',
  walletMode: wdFields.wallet_mode as 'mixed',
  signers: wdFields.signers.map((s) => ({
    kind: s.kind as 'sigbash_policy_key' | 'external_xpub',
    xpub: s.xpub,
    ...(s.policy_key_id ? { policyKeyId: s.policy_key_id } : {}),
  })),
  allowedSignerSets: wdFields.allowed_signer_sets.map((set) => ({ signerIndexes: set.signer_indexes })),
  receiveDescriptor: wdFields.receive_descriptor,
  changeDescriptor: wdFields.change_descriptor,
});
VECTORS.wallet_descriptor_v1.encoding_hex = bytesToHex(wdEncoding);
VECTORS.wallet_id_v1.wallet_id_hex = bytesToHex(
  computeWalletId({
    network: VECTORS.wallet_id_v1.network as 'mainnet',
    receiveDescriptor: VECTORS.wallet_id_v1.receive_descriptor,
    changeDescriptor: VECTORS.wallet_id_v1.change_descriptor,
  }),
);

const acFields = VECTORS.approval_commitment_v1.fields;
const acEncoding = encodeApprovalCommitmentV1({
  network: acFields.network as 'signet',
  walletId: hexToBytes(acFields.wallet_id_hex),
  policyVersionId: acFields.policy_version_id,
  selectedTapleafHash: hexToBytes(acFields.selected_tapleaf_hash_hex),
  selectedCustomerSignerIds: acFields.selected_customer_signer_ids,
  unsignedTxVersion: acFields.unsigned_tx_version,
  unsignedTxLocktime: acFields.unsigned_tx_locktime,
  orderedInputs: acFields.ordered_inputs.map((i) => ({
    outpointTxid: hexToBytes(i.outpoint_txid_hex),
    outpointVout: i.outpoint_vout,
    sequence: i.sequence,
    prevoutAmount: i.prevout_amount,
    prevoutScriptPubkey: hexToBytes(i.prevout_script_pubkey_hex),
    sighashType: i.sighash_type,
  })),
  orderedOutputs: acFields.ordered_outputs.map((o) => ({
    amount: o.amount,
    scriptPubkey: hexToBytes(o.script_pubkey_hex),
  })),
});
VECTORS.approval_commitment_v1.encoding_hex = bytesToHex(acEncoding);
VECTORS.approval_commitment_v1.commitment_hex = bytesToHex(computeApprovalCommitment({
  network: acFields.network as 'signet',
  walletId: hexToBytes(acFields.wallet_id_hex),
  policyVersionId: acFields.policy_version_id,
  selectedTapleafHash: hexToBytes(acFields.selected_tapleaf_hash_hex),
  selectedCustomerSignerIds: acFields.selected_customer_signer_ids,
  unsignedTxVersion: acFields.unsigned_tx_version,
  unsignedTxLocktime: acFields.unsigned_tx_locktime,
  orderedInputs: acFields.ordered_inputs.map((i) => ({
    outpointTxid: hexToBytes(i.outpoint_txid_hex),
    outpointVout: i.outpoint_vout,
    sequence: i.sequence,
    prevoutAmount: i.prevout_amount,
    prevoutScriptPubkey: hexToBytes(i.prevout_script_pubkey_hex),
    sighashType: i.sighash_type,
  })),
  orderedOutputs: acFields.ordered_outputs.map((o) => ({
    amount: o.amount,
    scriptPubkey: hexToBytes(o.script_pubkey_hex),
  })),
}));

const ehFields = VECTORS.encrypted_event_header_v1.fields;
VECTORS.encrypted_event_header_v1.encoding_hex = bytesToHex(
  encodeEncryptedEventHeaderV1({
    schemaVersion: ehFields.schema_version,
    eventId: hexToBytes(ehFields.event_id_hex),
    eventType: ehFields.event_type,
    orgClientId: hexToBytes(ehFields.org_client_id_hex),
    walletClientId: ehFields.wallet_client_id_hex ? hexToBytes(ehFields.wallet_client_id_hex) : undefined,
    ...(ehFields.subject_id_hex ? { subjectId: hexToBytes(ehFields.subject_id_hex) } : {}),
    actorUserId: hexToBytes(ehFields.actor_user_id_hex),
    clientTimestampMs: BigInt(ehFields.client_timestamp_ms),
    parentEventHashes: ehFields.parent_event_hashes_hex.map((h) => hexToBytes(h)),
    ...(ehFields.semantic_commitment_hex ? { semanticCommitment: hexToBytes(ehFields.semantic_commitment_hex) } : {}),
    actorSignature: hexToBytes(ehFields.actor_signature_hex),
  }),
);

for (const entry of VECTORS.capability_epoch_v1) {
  entry.encoding_hex = bytesToHex(encodeCapabilityEpoch(entry.group_id, entry.epoch));
}

VECTORS.recovery_envelope_v1.version_prefix_hex = bytesToHex(encodeRecoveryEnvelopeVersion());

// Resolved relative to the process working directory; run from the sdk root.
const outPath = join('src', 'contracts', 'vectors', 'contracts-v1.json');
writeFileSync(outPath, JSON.stringify(VECTORS, null, 2) + '\n');
console.log(`wrote ${outPath}`);
