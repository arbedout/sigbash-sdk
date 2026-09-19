/**
 * Recovery envelope version contract.
 *
 * Application recovery is envelope-based: a random recovery KEK encrypts
 * the user root into a UserRecoveryEnvelope; only the ciphertext and
 * envelope id are stored server-side; the QR carries the envelope id, the
 * KEK, and this version. Email alone can never restore cryptographic
 * material. The legacy encrypted_kmc-in-QR validation path is superseded;
 * only the envelope schema below is supported.
 */

import { ContractVersionError } from './encoding';

export const RECOVERY_ENVELOPE_CONTRACT_ID = 0x06;
export const RECOVERY_ENVELOPE_VERSION = 1;
export const SUPPORTED_RECOVERY_ENVELOPE_VERSIONS = [RECOVERY_ENVELOPE_VERSION] as const;

/** Wire format of the recovery QR: envelope version byte prefix. */
export const RECOVERY_QR_FORMAT_VERSION = 1;

export function encodeRecoveryEnvelopeVersion(): Uint8Array {
  return new Uint8Array([RECOVERY_ENVELOPE_CONTRACT_ID, RECOVERY_ENVELOPE_VERSION]);
}

/** Fail closed on unknown recovery envelope versions. */
export function decodeRecoveryEnvelopeVersion(bytes: Uint8Array): number {
  if (bytes.length < 2) {
    throw new ContractVersionError('RecoveryEnvelope: truncated version header');
  }
  if (bytes[0] !== RECOVERY_ENVELOPE_CONTRACT_ID) {
    throw new ContractVersionError(`RecoveryEnvelope: unknown contract id 0x${bytes[0].toString(16)}`);
  }
  const version = bytes[1];
  if (!SUPPORTED_RECOVERY_ENVELOPE_VERSIONS.includes(version as typeof RECOVERY_ENVELOPE_VERSION)) {
    throw new ContractVersionError(`RecoveryEnvelope: unsupported version ${version}`);
  }
  return version;
}
