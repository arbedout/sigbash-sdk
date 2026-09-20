/**
 * ApprovalCommitmentV1 — the exact immutable transaction semantic commitment.
 *
 * The canonical encoding is binary and length-delimited; JSON is never
 * hashed as the protocol definition. Field order below is normative:
 *
 *   network                         u8
 *   wallet_id                       32 bytes
 *   policy_version_id               length-delimited UTF-8
 *   selected_tapleaf_hash           32 bytes
 *   selected_customer_signer_ids    u16 count, then length-delimited UTF-8 ids
 *   unsigned_tx_version             u32
 *   unsigned_tx_locktime            u32
 *   ordered_inputs                  u16 count, then per input:
 *     outpoint_txid                 32 bytes
 *     outpoint_vout                 u32
 *     sequence                      u32
 *     prevout_amount                u64 (satoshis)
 *     prevout_script_pubkey         length-delimited bytes
 *     sighash_type                  u32
 *   ordered_outputs                 u16 count, then per output:
 *     amount                        u64 (satoshis)
 *     script_pubkey                 length-delimited bytes
 *
 * Input and output order is committed. Prevout amounts and scriptPubKeys
 * are committed because the unsigned transaction serialization does not
 * fully represent them. Partial signatures, labels, notes, UI formatting,
 * and PSBT proprietary fields are excluded. The full governance-side
 * encoder integration is owned by the governance task; this module is the
 * versioned contract, the codec, and its vectors.
 */

import { bytesToHex, concatBytes, contractHeader, ContractVersionError, Decoder, expectExhausted, hexToBytes, lengthDelimited, readBytes, readContractHeader, readLengthDelimited, readU16, readU32, readU64, readU8, u16be, u32be, u64be, u8be, utf8, taggedHash } from './encoding';
import { decodeNetworkId, encodeNetworkId, NetworkId } from './network';
import { SigbashSDKError } from '../errors';

/**
 * Typed rejection of any malformed commitment encoding: truncated input,
 * length prefixes that overrun the buffer, invalid UTF-8, or trailing
 * bytes. Decode never silently reinterpret bytes; every structural fault
 * surfaces as this class (version faults stay ContractVersionError).
 */
export class ApprovalCommitmentDecodeError extends SigbashSDKError {
  constructor(message: string) {
    super(message, 'CONTRACT_DECODE_INVALID');
    this.name = 'ApprovalCommitmentDecodeError';
    Object.setPrototypeOf(this, ApprovalCommitmentDecodeError.prototype);
  }
}

export const APPROVAL_COMMITMENT_CONTRACT_ID = 0x03;
export const APPROVAL_COMMITMENT_VERSION = 1;
export const SUPPORTED_APPROVAL_COMMITMENT_VERSIONS = [APPROVAL_COMMITMENT_VERSION] as const;

export const APPROVAL_COMMITMENT_TAG = 'SIGBASH/APPROVAL/V1';
export const APPROVAL_COMMITMENT_LENGTH = 32;

export interface ApprovalCommitmentInputV1 {
  outpointTxid: Uint8Array;
  outpointVout: number;
  sequence: number;
  prevoutAmount: bigint | number;
  prevoutScriptPubkey: Uint8Array;
  sighashType: number;
}

export interface ApprovalCommitmentOutputV1 {
  amount: bigint | number;
  scriptPubkey: Uint8Array;
}

export interface ApprovalCommitmentFieldsV1 {
  network: NetworkId;
  walletId: Uint8Array;
  policyVersionId: string;
  selectedTapleafHash: Uint8Array;
  /** Ordered, non-empty customer signer ids for the selected leaf plan. */
  selectedCustomerSignerIds: string[];
  unsignedTxVersion: number;
  unsignedTxLocktime: number;
  orderedInputs: ApprovalCommitmentInputV1[];
  orderedOutputs: ApprovalCommitmentOutputV1[];
}

export function encodeApprovalCommitmentV1(fields: ApprovalCommitmentFieldsV1): Uint8Array {
  if (fields.walletId.length !== 32) {
    throw new Error('wallet_id must be 32 bytes');
  }
  if (fields.selectedTapleafHash.length !== 32) {
    throw new Error('selected_tapleaf_hash must be 32 bytes');
  }
  if (fields.policyVersionId.length === 0) {
    throw new Error('policy_version_id must not be empty');
  }
  if (fields.selectedCustomerSignerIds.length === 0) {
    throw new Error('selected_customer_signer_ids must not be empty');
  }
  for (const input of fields.orderedInputs) {
    if (input.outpointTxid.length !== 32) {
      throw new Error('outpoint_txid must be 32 bytes');
    }
  }
  return concatBytes(
    contractHeader(APPROVAL_COMMITMENT_CONTRACT_ID, APPROVAL_COMMITMENT_VERSION),
    u8be(encodeNetworkId(fields.network)),
    fields.walletId,
    lengthDelimited(utf8(fields.policyVersionId)),
    fields.selectedTapleafHash,
    u16be(fields.selectedCustomerSignerIds.length),
    ...fields.selectedCustomerSignerIds.map((id) => lengthDelimited(utf8(id))),
    u32be(fields.unsignedTxVersion),
    u32be(fields.unsignedTxLocktime),
    u16be(fields.orderedInputs.length),
    ...fields.orderedInputs.map((input) =>
      concatBytes(
        input.outpointTxid,
        u32be(input.outpointVout),
        u32be(input.sequence),
        u64be(input.prevoutAmount),
        lengthDelimited(input.prevoutScriptPubkey),
        u32be(input.sighashType),
      ),
    ),
    u16be(fields.orderedOutputs.length),
    ...fields.orderedOutputs.map((output) =>
      concatBytes(u64be(output.amount), lengthDelimited(output.scriptPubkey)),
    ),
  );
}

export function decodeApprovalCommitmentV1(bytes: Uint8Array): ApprovalCommitmentFieldsV1 {
  try {
    return decodeApprovalCommitmentV1Bytes(bytes);
  } catch (error) {
    if (error instanceof ApprovalCommitmentDecodeError || error instanceof ContractVersionError) {
      throw error;
    }
    throw new ApprovalCommitmentDecodeError(error instanceof Error ? error.message : String(error));
  }
}

function decodeApprovalCommitmentV1Bytes(bytes: Uint8Array): ApprovalCommitmentFieldsV1 {
  const d: Decoder = { data: bytes, offset: 0 };
  readContractHeader(d, APPROVAL_COMMITMENT_CONTRACT_ID, SUPPORTED_APPROVAL_COMMITMENT_VERSIONS, 'ApprovalCommitmentV1');
  const networkCode = readU8(d, 'network');
  const network = decodeNetworkId(networkCode);
  const walletId = new Uint8Array(readBytes32(d, 'wallet_id'));
  const policyVersionId = new TextDecoder().decode(readLengthDelimited(d, 'policy_version_id'));
  const selectedTapleafHash = new Uint8Array(readBytes32(d, 'selected_tapleaf_hash'));

  const signerIdCount = readU16(d, 'selected_customer_signer_ids.count');
  if (signerIdCount === 0) {
    throw new Error('selected_customer_signer_ids must not be empty');
  }
  const selectedCustomerSignerIds: string[] = [];
  for (let i = 0; i < signerIdCount; i++) {
    selectedCustomerSignerIds.push(new TextDecoder().decode(readLengthDelimited(d, 'selected_customer_signer_ids[]')));
  }

  const unsignedTxVersion = readU32(d, 'unsigned_tx_version');
  const unsignedTxLocktime = readU32(d, 'unsigned_tx_locktime');

  const inputCount = readU16(d, 'ordered_inputs.count');
  const orderedInputs: ApprovalCommitmentInputV1[] = [];
  for (let i = 0; i < inputCount; i++) {
    orderedInputs.push({
      outpointTxid: new Uint8Array(readBytes32(d, 'outpoint_txid')),
      outpointVout: readU32(d, 'outpoint_vout'),
      sequence: readU32(d, 'sequence'),
      prevoutAmount: readU64(d, 'prevout_amount'),
      prevoutScriptPubkey: new Uint8Array(readLengthDelimited(d, 'prevout_script_pubkey')),
      sighashType: readU32(d, 'sighash_type'),
    });
  }

  const outputCount = readU16(d, 'ordered_outputs.count');
  const orderedOutputs: ApprovalCommitmentOutputV1[] = [];
  for (let i = 0; i < outputCount; i++) {
    orderedOutputs.push({
      amount: readU64(d, 'amount'),
      scriptPubkey: new Uint8Array(readLengthDelimited(d, 'script_pubkey')),
    });
  }
  expectExhausted(d, 'ApprovalCommitmentV1');

  return {
    network,
    walletId,
    policyVersionId,
    selectedTapleafHash,
    selectedCustomerSignerIds,
    unsignedTxVersion,
    unsignedTxLocktime,
    orderedInputs,
    orderedOutputs,
  };
}

function readBytes32(d: Decoder, field: string): Uint8Array {
  const bytes = readBytes(d, 32, field);
  return bytes;
}

/** ApprovalCommitmentV1 = TaggedHash("SIGBASH/APPROVAL/V1", canonical encoding). */
export function computeApprovalCommitment(fields: ApprovalCommitmentFieldsV1): Uint8Array {
  return taggedHash(APPROVAL_COMMITMENT_TAG, encodeApprovalCommitmentV1(fields));
}

export function approvalCommitmentToHex(fields: ApprovalCommitmentFieldsV1): string {
  return bytesToHex(computeApprovalCommitment(fields));
}

export function hexField(hex: string): Uint8Array {
  return hexToBytes(hex);
}
