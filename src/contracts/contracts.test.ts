/**
 * Cross-component contract tests: canonical encodings, golden vectors,
 * and fail-closed version rejection for every contract.
 */

import {
  APPROVAL_COMMITMENT_CONTRACT_ID,
  APPROVAL_COMMITMENT_TAG,
  ENCRYPTED_EVENT_HEADER_VERSION,
  ENCRYPTED_SYNC_ENVELOPE_VERSION,
  ContractVersionError,
  SIGNING_API_ERROR_CODES,
  SUPPORTED_APPROVAL_COMMITMENT_VERSIONS,
  SUPPORTED_EVENT_HEADER_VERSIONS,
  SUPPORTED_RECOVERY_ENVELOPE_VERSIONS,
  SUPPORTED_SYNC_ENVELOPE_VERSIONS,
  SUPPORTED_WALLET_DESCRIPTOR_VERSIONS,
  RECOVERY_ENVELOPE_CONTRACT_ID,
  SYNC_ENVELOPE_CONTRACT_ID,
  EVENT_HEADER_CONTRACT_ID,
  WALLET_DESCRIPTOR_CONTRACT_ID,
  WALLET_ID_TAG,
  decodeApprovalCommitmentV1,
  decodeEncryptedEventHeaderV1,
  decodeNetworkId,
  decodePolicyEnforcementClass,
  decodePolicyVersionState,
  decodeRecoveryEnvelopeVersion,
  decodeSigningAttemptState,
  decodeTransactionProposalState,
  decodeWalletDescriptorV1,
  encodeApprovalCommitmentV1,
  encodeEncryptedEventHeaderV1,
  encodeWalletDescriptorV1,
  computeApprovalCommitment,
  computeWalletId,
  encodeCapabilityEpoch,
  encodeRecoveryEnvelopeVersion,
  isSigningSessionTerminal,
  parseCapabilityGroupId,
  parseNetworkId,
  parsePolicyVersionId,
  parseProposalId,
  signingFailureClass,
  taggedHash,
  utf8,
  bytesToHex,
  hexToBytes,
  walletIdFromHex,
} from './index';
import type {
  ApprovalCommitmentFieldsV1,
  EncryptedEventHeaderV1,
  WalletDescriptorV1,
} from './index';
import vectors from './vectors/contracts-v1.json';

function expectContractVersionError(fn: () => unknown): void {
  expect(fn).toThrow(ContractVersionError);
}

describe('NetworkId', () => {
  it('parses the exact supported networks and nothing else', () => {
    expect(parseNetworkId('signet')).toBe('signet');
    expect(parseNetworkId('mainnet')).toBe('mainnet');
    expect(() => parseNetworkId('testnet')).toThrow(ContractVersionError);
    expect(() => parseNetworkId('Signet')).toThrow(ContractVersionError);
    expect(() => parseNetworkId('')).toThrow(ContractVersionError);
  });

  it('decodes only explicitly assigned wire codes', () => {
    expect(decodeNetworkId(0x01)).toBe('signet');
    expect(decodeNetworkId(0x02)).toBe('mainnet');
    expect(() => decodeNetworkId(0x00)).toThrow(ContractVersionError);
    expect(() => decodeNetworkId(0x03)).toThrow(ContractVersionError);
    expect(() => decodeNetworkId(0xff)).toThrow(ContractVersionError);
  });
});

describe('WalletDescriptorV1', () => {
  const fields = vectors.wallet_descriptor_v1.fields;
  const descriptor: WalletDescriptorV1 = {
    version: 1,
    network: 'signet',
    walletMode: 'mixed',
    signers: [
      { kind: 'sigbash_policy_key', xpub: fields.signers[0].xpub, policyKeyId: fields.signers[0].policy_key_id },
      { kind: 'external_xpub', xpub: fields.signers[1].xpub },
    ],
    allowedSignerSets: [{ signerIndexes: [0] }, { signerIndexes: [0, 1] }],
    receiveDescriptor: fields.receive_descriptor,
    changeDescriptor: fields.change_descriptor,
  };

  it('encodes to the golden vector bytes', () => {
    expect(bytesToHex(encodeWalletDescriptorV1(descriptor))).toBe(vectors.wallet_descriptor_v1.encoding_hex);
  });

  it('round-trips through the golden vector encoding', () => {
    const decoded = decodeWalletDescriptorV1(hexToBytes(vectors.wallet_descriptor_v1.encoding_hex));
    expect(decoded.version).toBe(1);
    expect(decoded.network).toBe('signet');
    expect(decoded.walletMode).toBe('mixed');
    expect(decoded.signers).toEqual([
      { kind: 'sigbash_policy_key', xpub: fields.signers[0].xpub, policyKeyId: fields.signers[0].policy_key_id },
      { kind: 'external_xpub', xpub: fields.signers[1].xpub },
    ]);
    expect(decoded.allowedSignerSets).toEqual([{ signerIndexes: [0] }, { signerIndexes: [0, 1] }]);
    expect(decoded.receiveDescriptor).toBe(fields.receive_descriptor);
    expect(decoded.changeDescriptor).toBe(fields.change_descriptor);
    expect(decoded.recovery).toBeUndefined();
  });

  it('rejects unknown versions and unknown contract ids', () => {
    const bytes = hexToBytes(vectors.wallet_descriptor_v1.encoding_hex);
    const badVersion = Uint8Array.from(bytes);
    badVersion[1] = 0x02;
    expectContractVersionError(() => decodeWalletDescriptorV1(badVersion));
    const badId = Uint8Array.from(bytes);
    badId[0] = 0x7f;
    expectContractVersionError(() => decodeWalletDescriptorV1(badId));
    expect(SUPPORTED_WALLET_DESCRIPTOR_VERSIONS).toEqual([1]);
  });

  it('rejects trailing bytes, bad subsets, and bad signer shapes', () => {
    const bytes = hexToBytes(vectors.wallet_descriptor_v1.encoding_hex);
    expect(() => decodeWalletDescriptorV1(Uint8Array.from([...bytes, 0x00]))).toThrow(/trailing bytes/);
    expect(() =>
      encodeWalletDescriptorV1({ ...descriptor, allowedSignerSets: [{ signerIndexes: [1, 1] }] }),
    ).toThrow(/strictly ascending/);
    expect(() =>
      encodeWalletDescriptorV1({ ...descriptor, allowedSignerSets: [{ signerIndexes: [0, 1, 2] }] }),
    ).toThrow(/out of range/);
    const fourSigners: WalletDescriptorV1 = {
      ...descriptor,
      signers: [...descriptor.signers, { kind: 'external_xpub', xpub: fields.signers[1].xpub }, { kind: 'external_xpub', xpub: fields.signers[1].xpub }],
    };
    expect(() => encodeWalletDescriptorV1({ ...fourSigners, allowedSignerSets: [{ signerIndexes: [0, 1, 2, 3] }] })).toThrow(/1\.\.3/);
    expect(() =>
      encodeWalletDescriptorV1({ ...descriptor, signers: [{ kind: 'sigbash_policy_key', xpub: 'xpubX' }], allowedSignerSets: [{ signerIndexes: [0] }] }),
    ).toThrow(/policyKeyId/);
    expect(() =>
      encodeWalletDescriptorV1({ ...descriptor, signers: [{ kind: 'external_xpub', xpub: 'xpubX', policyKeyId: 'x' }], allowedSignerSets: [{ signerIndexes: [0] }] }),
    ).toThrow(/must not carry policyKeyId/);
  });
});

describe('WalletId', () => {
  it('derives the golden fingerprint with the exact tagged-hash construction', () => {
    const v = vectors.wallet_id_v1;
    const expected = taggedHash(
      WALLET_ID_TAG,
      Uint8Array.from([
        0x02, 0x00,
        ...Array.from(utf8(v.receive_descriptor)),
        0x00,
        ...Array.from(utf8(v.change_descriptor)),
      ]),
    );
    const walletId = computeWalletId({
      network: 'mainnet',
      receiveDescriptor: v.receive_descriptor,
      changeDescriptor: v.change_descriptor,
    });
    expect(bytesToHex(walletId)).toBe(v.wallet_id_hex);
    expect(bytesToHex(walletId)).toBe(bytesToHex(expected));
    expect(bytesToHex(walletIdFromHex(v.wallet_id_hex))).toBe(v.wallet_id_hex);
  });

  it('rejects non-canonical descriptor text', () => {
    expect(() =>
      computeWalletId({ network: 'signet', receiveDescriptor: ' tr(a)', changeDescriptor: 'tr(b)' }),
    ).toThrow(/canonical/);
    expect(() =>
      computeWalletId({ network: 'signet', receiveDescriptor: 'tr(a)#checksum', changeDescriptor: 'tr(b)' }),
    ).toThrow(/checksum/);
    expect(() => computeWalletId({ network: 'signet', receiveDescriptor: '', changeDescriptor: 'tr(b)' })).toThrow();
  });
});

describe('ApprovalCommitmentV1', () => {
  const f = vectors.approval_commitment_v1.fields;
  const fields: ApprovalCommitmentFieldsV1 = {
    network: 'signet',
    walletId: hexToBytes(f.wallet_id_hex),
    policyVersionId: f.policy_version_id,
    selectedTapleafHash: hexToBytes(f.selected_tapleaf_hash_hex),
    selectedCustomerSignerIds: f.selected_customer_signer_ids,
    unsignedTxVersion: f.unsigned_tx_version,
    unsignedTxLocktime: f.unsigned_tx_locktime,
    orderedInputs: f.ordered_inputs.map((i) => ({
      outpointTxid: hexToBytes(i.outpoint_txid_hex),
      outpointVout: i.outpoint_vout,
      sequence: i.sequence,
      prevoutAmount: BigInt(i.prevout_amount),
      prevoutScriptPubkey: hexToBytes(i.prevout_script_pubkey_hex),
      sighashType: i.sighash_type,
    })),
    orderedOutputs: f.ordered_outputs.map((o) => ({
      amount: BigInt(o.amount),
      scriptPubkey: hexToBytes(o.script_pubkey_hex),
    })),
  };

  it('encodes to the golden vector bytes', () => {
    expect(bytesToHex(encodeApprovalCommitmentV1(fields))).toBe(vectors.approval_commitment_v1.encoding_hex);
  });

  it('commits via the approval tagged hash to the golden digest', () => {
    expect(APPROVAL_COMMITMENT_TAG).toBe('SIGBASH/APPROVAL/V1');
    expect(bytesToHex(computeApprovalCommitment(fields))).toBe(vectors.approval_commitment_v1.commitment_hex);
  });

  it('decodes the golden encoding back to identical fields', () => {
    expect(decodeApprovalCommitmentV1(hexToBytes(vectors.approval_commitment_v1.encoding_hex))).toEqual(fields);
  });

  it('rejects unknown versions and trailing bytes', () => {
    const bytes = hexToBytes(vectors.approval_commitment_v1.encoding_hex);
    const badVersion = Uint8Array.from(bytes);
    badVersion[1] = 0x63;
    expectContractVersionError(() => decodeApprovalCommitmentV1(badVersion));
    expect(SUPPORTED_APPROVAL_COMMITMENT_VERSIONS).toEqual([1]);
    expect(() => decodeApprovalCommitmentV1(Uint8Array.from([...bytes, 0x00]))).toThrow(/trailing bytes/);
  });

  it('rejects empty signer-id lists and malformed field widths', () => {
    expect(() => encodeApprovalCommitmentV1({ ...fields, selectedCustomerSignerIds: [] })).toThrow(/must not be empty/);
    expect(() => encodeApprovalCommitmentV1({ ...fields, walletId: hexToBytes('aabb') })).toThrow(/32 bytes/);
    expect(() => encodeApprovalCommitmentV1({ ...fields, orderedInputs: [] })).not.toThrow();
  });

  it('binds input and output order', () => {
    const swapped: ApprovalCommitmentFieldsV1 = {
      ...fields,
      orderedOutputs: [...fields.orderedOutputs].reverse(),
    };
    expect(bytesToHex(computeApprovalCommitment(swapped))).not.toBe(vectors.approval_commitment_v1.commitment_hex);
  });
});

describe('EncryptedEventHeaderV1', () => {
  const f = vectors.encrypted_event_header_v1.fields;
  const header: EncryptedEventHeaderV1 = {
    schemaVersion: f.schema_version,
    eventId: hexToBytes(f.event_id_hex),
    eventType: f.event_type,
    orgClientId: hexToBytes(f.org_client_id_hex),
    walletClientId: hexToBytes(f.wallet_client_id_hex),
    actorUserId: hexToBytes(f.actor_user_id_hex),
    clientTimestampMs: BigInt(f.client_timestamp_ms),
    parentEventHashes: f.parent_event_hashes_hex.map((h) => hexToBytes(h)),
    semanticCommitment: hexToBytes(f.semantic_commitment_hex),
    actorSignature: hexToBytes(f.actor_signature_hex),
  };

  it('encodes to the golden vector bytes and decodes back identically', () => {
    expect(bytesToHex(encodeEncryptedEventHeaderV1(header))).toBe(vectors.encrypted_event_header_v1.encoding_hex);
    const decoded = decodeEncryptedEventHeaderV1(hexToBytes(vectors.encrypted_event_header_v1.encoding_hex));
    expect(decoded).toEqual(header);
  });

  it('rejects unknown versions and bad optional flags', () => {
    const bytes = hexToBytes(vectors.encrypted_event_header_v1.encoding_hex);
    const badVersion = Uint8Array.from(bytes);
    badVersion[1] = 0x02;
    expectContractVersionError(() => decodeEncryptedEventHeaderV1(badVersion));
    expect(SUPPORTED_EVENT_HEADER_VERSIONS).toEqual([ENCRYPTED_EVENT_HEADER_VERSION]);
    expect(SUPPORTED_SYNC_ENVELOPE_VERSIONS).toEqual([ENCRYPTED_SYNC_ENVELOPE_VERSION]);
    const badFlag = Uint8Array.from(bytes);
    // wallet_client_id optional flag sits after the fixed org id block.
    const fixedPrefix = 2 + 1 + 16 + 4 + f.event_type.length + 16;
    badFlag[fixedPrefix] = 0x7f;
    expectContractVersionError(() => decodeEncryptedEventHeaderV1(badFlag));
  });
});

describe('Capability groups and epochs', () => {
  it('encodes the golden epoch bindings', () => {
    for (const entry of vectors.capability_epoch_v1) {
      expect(bytesToHex(encodeCapabilityEpoch(entry.group_id, entry.epoch))).toBe(entry.encoding_hex);
    }
  });

  it('parses known groups and fails closed on unknown shapes', () => {
    expect(parseCapabilityGroupId('org-common')).toBe('org-common');
    expect(parseCapabilityGroupId('policy-governance')).toBe('policy-governance');
    expect(parseCapabilityGroupId('audit')).toBe('audit');
    expect(parseCapabilityGroupId('security-recovery')).toBe('security-recovery');
    expect(parseCapabilityGroupId('wallet:6f9619ff-8b86-4d01-b42d-00cf4fc964ff')).toBe(
      'wallet:6f9619ff-8b86-4d01-b42d-00cf4fc964ff',
    );
    expect(() => parseCapabilityGroupId('everything')).toThrow(ContractVersionError);
    expect(() => parseCapabilityGroupId('wallet:not-a-uuid')).toThrow(ContractVersionError);
    expect(() => parseCapabilityGroupId('')).toThrow(ContractVersionError);
  });

  it('rejects zero epochs and non-integer epochs', () => {
    expect(() => encodeCapabilityEpoch('org-common', 0)).toThrow(RangeError);
    expect(() => encodeCapabilityEpoch('org-common', 1.5)).toThrow(RangeError);
  });
});

describe('Proposal and signing-attempt states', () => {
  it('round-trips every proposal and attempt state code', () => {
    const proposalStates = [
      'DRAFT', 'PROPOSED', 'AWAITING_APPROVALS', 'APPROVED', 'REJECTED', 'EXPIRED',
      'CANCELLED', 'SUPERSEDED', 'SIGNING', 'SESSION_RESTART_REQUIRED', 'FINALIZED',
      'BROADCAST', 'BROADCAST_FAILED', 'CONFIRMED',
    ] as const;
    for (const state of proposalStates) {
      const code = 0x01 + proposalStates.indexOf(state);
      expect(decodeTransactionProposalState(code)).toBe(state);
    }
    const attemptStates = ['PENDING', 'NONCES_ISSUED', 'PROOF_VERIFIED', 'PARTIALLY_SIGNED', 'COMPLETED', 'TERMINAL_FAILED'] as const;
    for (const state of attemptStates) {
      expect(decodeSigningAttemptState(0x01 + attemptStates.indexOf(state))).toBe(state);
    }
  });

  it('fails closed on unknown state codes', () => {
    expect(() => decodeTransactionProposalState(0x00)).toThrow(ContractVersionError);
    expect(() => decodeTransactionProposalState(0x0f)).toThrow(ContractVersionError);
    expect(() => decodeSigningAttemptState(0x07)).toThrow(ContractVersionError);
  });

  it('validates identity id formats', () => {
    expect(parseProposalId('6f9619ff-8b86-4d01-b42d-00cf4fc964ff')).toBe('6f9619ff-8b86-4d01-b42d-00cf4fc964ff');
    expect(parsePolicyVersionId('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee')).toBe('aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee');
    expect(() => parseProposalId('not-a-uuid')).toThrow(ContractVersionError);
    expect(() => parseProposalId('6F9619FF-8B86-4D01-B42D-00CF4FC964FF')).not.toThrow();
  });
});

describe('Policy version and enforcement class', () => {
  it('round-trips enforcement classes and version states', () => {
    expect(decodePolicyEnforcementClass(0x01)).toBe('hard_cryptographic');
    expect(decodePolicyEnforcementClass(0x02)).toBe('governance_only');
    expect(decodePolicyEnforcementClass(0x03)).toBe('disabled_unsound');
    expect(() => decodePolicyEnforcementClass(0x04)).toThrow(ContractVersionError);
    expect(decodePolicyVersionState(0x01)).toBe('DRAFT');
    expect(decodePolicyVersionState(0x08)).toBe('ACTIVE');
    expect(decodePolicyVersionState(0x0b)).toBe('SUPERSEDED');
    expect(() => decodePolicyVersionState(0x0c)).toThrow(ContractVersionError);
  });
});

describe('Recovery envelope version', () => {
  it('matches the golden version prefix and fails closed on unknowns', () => {
    expect(bytesToHex(encodeRecoveryEnvelopeVersion())).toBe(vectors.recovery_envelope_v1.version_prefix_hex);
    expect(decodeRecoveryEnvelopeVersion(hexToBytes(vectors.recovery_envelope_v1.version_prefix_hex))).toBe(1);
    expect(SUPPORTED_RECOVERY_ENVELOPE_VERSIONS).toEqual([1]);
    expectContractVersionError(() => decodeRecoveryEnvelopeVersion(new Uint8Array([0x06, 0x02])));
    expectContractVersionError(() => decodeRecoveryEnvelopeVersion(new Uint8Array([0x07, 0x01])));
    expectContractVersionError(() => decodeRecoveryEnvelopeVersion(new Uint8Array([0x06])));
  });
});

describe('Signing API error codes', () => {
  it('classifies every code as exactly terminal or retryable', () => {
    for (const code of SIGNING_API_ERROR_CODES) {
      const classification = signingFailureClass(code);
      expect(['terminal', 'retryable']).toContain(classification);
      expect(isSigningSessionTerminal(code)).toBe(classification === 'terminal');
    }
  });

  it('keeps consumed-nonce and transport failures on the correct sides', () => {
    expect(signingFailureClass('SESSION_STATE_UNKNOWN')).toBe('terminal');
    expect(signingFailureClass('PROOF_REJECTED')).toBe('terminal');
    expect(signingFailureClass('SIGNING_SERVICE_LOCKSTEP')).toBe('terminal');
    expect(signingFailureClass('POLICY_COOLDOWN')).toBe('retryable');
    expect(signingFailureClass('SIGNING_SERVICE_TIMEOUT')).toBe('retryable');
    expect(signingFailureClass('SIGNING_SERVICE_UNREACHABLE')).toBe('retryable');
    expect(signingFailureClass('SIGNING_KEY_INFO_UNAVAILABLE')).toBe('retryable');
  });

  it('fails closed on unknown codes', () => {
    expect(() => signingFailureClass('MADE_UP_CODE')).toThrow(/unknown code/);
  });
});

describe('Contract id allocation', () => {
  it('assigns distinct contract ids across binary contracts', () => {
    const ids = [
      WALLET_DESCRIPTOR_CONTRACT_ID,
      APPROVAL_COMMITMENT_CONTRACT_ID,
      SYNC_ENVELOPE_CONTRACT_ID,
      EVENT_HEADER_CONTRACT_ID,
      RECOVERY_ENVELOPE_CONTRACT_ID,
    ];
    expect(new Set(ids).size).toBe(ids.length);
    expect(ENCRYPTED_SYNC_ENVELOPE_VERSION).toBe(1);
    expect(ENCRYPTED_EVENT_HEADER_VERSION).toBe(1);
  });
});
