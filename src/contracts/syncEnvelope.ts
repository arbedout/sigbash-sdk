/**
 * Encrypted sync envelope and encrypted event header contracts.
 *
 * The sync backend stores opaque ciphertext objects only; it never sees
 * event semantics, wallet identifiers, or actor identity in the clear.
 * The outer envelope version (what the server persists) and the inner
 * event header version (what clients sign and decrypt) are versioned
 * separately and both fail closed on unknown versions.
 *
 * Inner signed event header field order is normative:
 *   schema_version        u8
 *   event_id              16 bytes (random, client-generated)
 *   event_type            length-delimited UTF-8
 *   org_client_id         16 bytes
 *   wallet_client_id      optional: 0x00 absent / 0x01 + 16 bytes
 *   subject_id            optional: 0x00 absent / 0x01 + 16 bytes
 *   actor_user_id         16 bytes
 *   client_timestamp      u64 (milliseconds since Unix epoch)
 *   parent_event_hashes   u16 count, then 32 bytes each
 *   semantic_commitment   optional: 0x00 absent / 0x01 + 32 bytes
 *   actor_signature       length-delimited bytes over all preceding fields
 */

import { ContractVersionError, concatBytes, contractHeader, Decoder, expectExhausted, lengthDelimited, readBytes, readContractHeader, readLengthDelimited, readU16, readU64, readU8, u16be, u64be, u8be, utf8 } from './encoding';

export const SYNC_ENVELOPE_CONTRACT_ID = 0x04;
export const EVENT_HEADER_CONTRACT_ID = 0x05;
export const ENCRYPTED_SYNC_ENVELOPE_VERSION = 1;
export const ENCRYPTED_EVENT_HEADER_VERSION = 1;
export const SUPPORTED_SYNC_ENVELOPE_VERSIONS = [ENCRYPTED_SYNC_ENVELOPE_VERSION] as const;
export const SUPPORTED_EVENT_HEADER_VERSIONS = [ENCRYPTED_EVENT_HEADER_VERSION] as const;

export const CLIENT_EVENT_ID_LENGTH = 16;
export const CLIENT_ORG_ID_LENGTH = 16;
export const CLIENT_USER_ID_LENGTH = 16;

export interface EncryptedEventHeaderV1 {
  schemaVersion: number;
  eventId: Uint8Array;
  eventType: string;
  orgClientId: Uint8Array;
  walletClientId?: Uint8Array;
  subjectId?: Uint8Array;
  actorUserId: Uint8Array;
  clientTimestampMs: bigint;
  parentEventHashes: Uint8Array[];
  semanticCommitment?: Uint8Array;
  actorSignature: Uint8Array;
}

function readOptionalId(d: Decoder, field: string): Uint8Array | undefined {
  const flag = readU8(d, `${field}.flag`);
  if (flag === 0x00) {
    return undefined;
  }
  if (flag !== 0x01) {
    throw new ContractVersionError(`EncryptedEventHeaderV1: unknown ${field} flag 0x${flag.toString(16)}`);
  }
  return new Uint8Array(readBytes(d, CLIENT_EVENT_ID_LENGTH, field));
}

function readOptionalHash32(d: Decoder, field: string): Uint8Array | undefined {
  const flag = readU8(d, `${field}.flag`);
  if (flag === 0x00) {
    return undefined;
  }
  if (flag !== 0x01) {
    throw new ContractVersionError(`EncryptedEventHeaderV1: unknown ${field} flag 0x${flag.toString(16)}`);
  }
  return new Uint8Array(readBytes(d, 32, field));
}

export function encodeEncryptedEventHeaderV1(header: EncryptedEventHeaderV1): Uint8Array {
  if (header.eventId.length !== CLIENT_EVENT_ID_LENGTH) {
    throw new Error(`event_id must be ${CLIENT_EVENT_ID_LENGTH} bytes`);
  }
  if (header.orgClientId.length !== CLIENT_ORG_ID_LENGTH) {
    throw new Error(`org_client_id must be ${CLIENT_ORG_ID_LENGTH} bytes`);
  }
  if (header.actorUserId.length !== CLIENT_USER_ID_LENGTH) {
    throw new Error(`actor_user_id must be ${CLIENT_USER_ID_LENGTH} bytes`);
  }
  if (header.eventType.length === 0) {
    throw new Error('event_type must not be empty');
  }
  return concatBytes(
    contractHeader(EVENT_HEADER_CONTRACT_ID, ENCRYPTED_EVENT_HEADER_VERSION),
    u8be(header.schemaVersion),
    header.eventId,
    lengthDelimited(utf8(header.eventType)),
    header.orgClientId,
    header.walletClientId ? concatBytes(u8be(0x01), header.walletClientId) : u8be(0x00),
    header.subjectId ? concatBytes(u8be(0x01), header.subjectId) : u8be(0x00),
    header.actorUserId,
    u64be(header.clientTimestampMs),
    u16be(header.parentEventHashes.length),
    ...header.parentEventHashes,
    header.semanticCommitment ? concatBytes(u8be(0x01), header.semanticCommitment) : u8be(0x00),
    lengthDelimited(header.actorSignature),
  );
}

export function decodeEncryptedEventHeaderV1(bytes: Uint8Array): EncryptedEventHeaderV1 {
  const d: Decoder = { data: bytes, offset: 0 };
  readContractHeader(d, EVENT_HEADER_CONTRACT_ID, SUPPORTED_EVENT_HEADER_VERSIONS, 'EncryptedEventHeaderV1');
  const schemaVersion = readU8(d, 'schema_version');
  const eventId = new Uint8Array(readBytes(d, CLIENT_EVENT_ID_LENGTH, 'event_id'));
  const eventType = new TextDecoder().decode(readLengthDelimited(d, 'event_type'));
  const orgClientId = new Uint8Array(readBytes(d, CLIENT_ORG_ID_LENGTH, 'org_client_id'));
  const walletClientId = readOptionalId(d, 'wallet_client_id');
  const subjectId = readOptionalId(d, 'subject_id');
  const actorUserId = new Uint8Array(readBytes(d, CLIENT_USER_ID_LENGTH, 'actor_user_id'));
  const clientTimestampMs = readU64(d, 'client_timestamp');
  const parentCount = readU16(d, 'parent_event_hashes.count');
  const parentEventHashes: Uint8Array[] = [];
  for (let i = 0; i < parentCount; i++) {
    parentEventHashes.push(new Uint8Array(readBytes(d, 32, 'parent_event_hash')));
  }
  const semanticCommitment = readOptionalHash32(d, 'semantic_commitment');
  const actorSignature = new Uint8Array(readLengthDelimited(d, 'actor_signature'));
  expectExhausted(d, 'EncryptedEventHeaderV1');
  return {
    schemaVersion,
    eventId,
    eventType,
    orgClientId,
    ...(walletClientId ? { walletClientId } : {}),
    ...(subjectId ? { subjectId } : {}),
    actorUserId,
    clientTimestampMs,
    parentEventHashes,
    ...(semanticCommitment ? { semanticCommitment } : {}),
    actorSignature,
  };
}
