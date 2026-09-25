/**
 * Revocable principal credential: one non-human protocol identity per
 * (organization, device-embedded root), generated fresh inside an
 * authorized client and provisioned into the wallet security-capability
 * vault — the same envelope model that holds the beta execution
 * credential. Replacing the beta credential changes WHAT is provisioned,
 * never WHERE it lives.
 *
 * Composition. Every principal secret derives from one random 32-byte
 * `userSecretKey` generated at provisioning time — never from a password,
 * email, or any human-chosen material:
 *
 * - `userKey` — a second random 32-byte identifier; together with the org
 *   protocol apiKey it forms the credential auth hash, the only
 *   server-visible principal identifier (DSHA256(orgApiKey || userKey),
 *   the same identity shape every SDK principal already carries, so the
 *   proof-of-possession registry resolves a principal exactly as it
 *   resolves any credential).
 * - PoP key — the Ed25519 request-signing key, derived from
 *   `userSecretKey` exactly as for any SDK credential.
 * - KMC slot key — a secp256k1 keypair under the `sigbash.principal.v1`
 *   label space, derived from `userSecretKey` with the org protocol apiKey
 *   bound as the HKDF salt. Its compressed public key is what a grantor
 *   seals the KMC content-encryption key to (the envelope's principal
 *   auth slot); its private key is what the grantee's client opens that
 *   slot with. One secret per credential, so a vault copy provisions the
 *   whole identity and nothing else can.
 *
 * A principal is domain-bound by access rows, never by key material: one
 * credential may hold access to several PolicyKeys in one organization,
 * each independently revocable. Revocation of a copied credential is the
 * protocol surface's job (access rows plus envelope re-wrap); this module
 * only makes the identity itself well-formed and transportable.
 *
 * Key-schedule registry. HKDF info labels live under the
 * `sigbash.principal.v1` prefix, disjoint from the wallet execution
 * credential (`sigbash.executioncredential.v1/*`), org protocol key
 * (`sigbash.orgprotocol.v1`), user-root (`sigbash.userroot.v1.*`),
 * capability (`sigbash.capability.v1.*`), and PoP
 * (`sigbash/sdk-pop-ed25519/v1`) label spaces; the disjointness is pinned
 * by the test suite.
 *
 * Canonical serialization. Self-identifying magic prefix whose letters sit
 * outside the hexadecimal alphabet, so the token cannot occur in the hex
 * encoding of unrelated ciphertext and is safe as a prohibited-plaintext
 * scan marker on byte surfaces. Every parse deviation fails closed.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { doubleSha256 } from '../auth';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  utf8,
} from '../contracts/encoding';
import { SigbashSDKError } from '../errors';
import { derivePopKey } from '../pop';

/** Wire/format version of the canonical in-memory serialization. */
export const PRINCIPAL_CREDENTIAL_FORMAT_VERSION = 1;

/**
 * Self-identifying magic prefix of the canonical serialization. None of
 * its bytes occur in the lowercase hexadecimal alphabet, so the token
 * cannot occur in the hex encoding of unrelated ciphertext.
 */
export const PRINCIPAL_CREDENTIAL_MAGIC = 'SIGPRINC';

/** HKDF info prefix for the principal slot-key family. */
export const PRINCIPAL_CREDENTIAL_HKDF_PREFIX = 'sigbash.principal.v1';

const SLOT_KEY_HKDF_INFO = utf8(`${PRINCIPAL_CREDENTIAL_HKDF_PREFIX}/slot-key`);

const HEX_64 = /^[0-9a-f]{64}$/;

/** Typed failure codes for every parse and derivation deviation. */
export type PrincipalCredentialErrorCode =
  | 'credential-malformed'
  | 'format-unsupported'
  | 'field-malformed';

/** Fail-closed error for every malformed principal credential surface. */
export class PrincipalCredentialError extends SigbashSDKError {
  constructor(code: PrincipalCredentialErrorCode) {
    super(`principal credential: ${code}`, code);
    this.name = 'PrincipalCredentialError';
    Object.setPrototypeOf(this, PrincipalCredentialError.prototype);
  }
}

/** One generated principal credential for one organization domain. */
export interface PrincipalCredentialV1 {
  readonly formatVersion: number;
  /** Organization protocol apiKey; every SDK principal of the org shares it. */
  readonly orgApiKey: string;
  /** Principal identifier half of the auth hash (64 lowercase hex chars). */
  readonly userKey: string;
  /** The credential's only secret (64 lowercase hex chars). */
  readonly userSecretKey: string;
}

function randomHex32(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

function assertOrgApiKey(value: string): void {
  if (!HEX_64.test(value)) {
    throw new PrincipalCredentialError('field-malformed');
  }
}

/**
 * Generate a fresh principal credential. The caller runs this inside an
 * authorized client's unlocked session and provisions the returned record
 * into the wallet security-capability vault; nothing here touches a
 * network.
 */
export function generatePrincipalCredential(orgApiKey: string): PrincipalCredentialV1 {
  assertOrgApiKey(orgApiKey);
  return {
    formatVersion: PRINCIPAL_CREDENTIAL_FORMAT_VERSION,
    orgApiKey,
    userKey: randomHex32(),
    userSecretKey: randomHex32(),
  };
}

/**
 * The principal auth hash — DSHA256(orgApiKey || userKey), the same
 * server-visible identity shape every SDK credential carries. This
 * realizes the principal identifier contract: the server sees and stores
 * this hash and nothing else about the principal.
 */
export function principalAuthHash(orgApiKey: string, userKey: string): Promise<string> {
  if (!HEX_64.test(orgApiKey) || !HEX_64.test(userKey)) {
    throw new PrincipalCredentialError('field-malformed');
  }
  return doubleSha256(orgApiKey, userKey);
}

/** The secp256k1 KMC slot keypair a principal credential opens slots with. */
export interface PrincipalSlotKey {
  /** 32-byte private key, hex — never leaves the unlocked client. */
  readonly privateKeyHex: string;
  /** 33-byte compressed public key, hex — what the grantor seals to. */
  readonly publicKeyHex: string;
}

/**
 * Derive the secp256k1 slot key from the credential's single secret with
 * the org protocol apiKey as the HKDF salt, so the same secret never
 * produces the same slot key in two organizations. The compressed public
 * key is the grant ceremony's `principal_public_key`; the private key is
 * the grantee's slot-opening `auth_secret`.
 */
export function derivePrincipalSlotKey(
  orgApiKey: string,
  userSecretKey: string,
): PrincipalSlotKey {
  assertOrgApiKey(orgApiKey);
  if (!HEX_64.test(userSecretKey)) {
    throw new PrincipalCredentialError('field-malformed');
  }
  const secretBytes = hexToBytes(userSecretKey);
  const salt = utf8(orgApiKey);
  // Rejection sampling on the derived scalar: an HKDF output outside the
  // group order is astronomically unlikely, but the derivation retries
  // with a counter suffix rather than ever emitting an unusable key.
  for (let attempt = 0; ; attempt++) {
    const info = attempt === 0
      ? SLOT_KEY_HKDF_INFO
      : concatBytes(SLOT_KEY_HKDF_INFO, utf8(`/${attempt}`));
    const candidate = hkdf(sha256, secretBytes, salt, info, 32);
    try {
      const publicKeyHex = bytesToHex(secp256k1.getPublicKey(candidate, true));
      return { privateKeyHex: bytesToHex(candidate), publicKeyHex };
    } catch {
      if (attempt > 64) {
        throw new PrincipalCredentialError('credential-malformed');
      }
    }
  }
}

/**
 * The deterministic slot address a grant records for this credential: the
 * KMC principal auth slot is created with the credential's `userKey` as
 * its caller-supplied credential id, so a revoke re-wrap names the slot
 * to drop without any side table.
 */
export function principalSlotCredentialId(credential: PrincipalCredentialV1): string {
  return credential.userKey;
}

/**
 * Canonical serialization: magic, format version, then the three 32-byte
 * fields in fixed order. Fixed width keeps the parse total and the scan
 * marker meaningful.
 */
export function serializePrincipalCredential(credential: PrincipalCredentialV1): Uint8Array {
  if (credential.formatVersion !== PRINCIPAL_CREDENTIAL_FORMAT_VERSION) {
    throw new PrincipalCredentialError('format-unsupported');
  }
  assertOrgApiKey(credential.orgApiKey);
  if (!HEX_64.test(credential.userKey) || !HEX_64.test(credential.userSecretKey)) {
    throw new PrincipalCredentialError('credential-malformed');
  }
  return concatBytes(
    utf8(PRINCIPAL_CREDENTIAL_MAGIC),
    new Uint8Array([PRINCIPAL_CREDENTIAL_FORMAT_VERSION]),
    hexToBytes(credential.orgApiKey),
    hexToBytes(credential.userKey),
    hexToBytes(credential.userSecretKey),
  );
}

/**
 * Parse a canonical serialization. Every deviation — wrong magic, unknown
 * format version, wrong length — fails closed with a typed error and no
 * partial record.
 */
export function parsePrincipalCredential(bytes: Uint8Array): PrincipalCredentialV1 {
  const magic = utf8(PRINCIPAL_CREDENTIAL_MAGIC);
  const totalLength = magic.length + 1 + 32 + 32 + 32;
  if (bytes.length !== totalLength) {
    throw new PrincipalCredentialError('credential-malformed');
  }
  for (let i = 0; i < magic.length; i++) {
    if (bytes[i] !== magic[i]) {
      throw new PrincipalCredentialError('credential-malformed');
    }
  }
  let offset = magic.length;
  const formatVersion = bytes[offset++];
  if (formatVersion !== PRINCIPAL_CREDENTIAL_FORMAT_VERSION) {
    throw new PrincipalCredentialError('format-unsupported');
  }
  const orgApiKey = bytesToHex(bytes.slice(offset, offset + 32));
  offset += 32;
  const userKey = bytesToHex(bytes.slice(offset, offset + 32));
  offset += 32;
  const userSecretKey = bytesToHex(bytes.slice(offset, offset + 32));
  assertOrgApiKey(orgApiKey);
  if (!HEX_64.test(userKey) || !HEX_64.test(userSecretKey)) {
    throw new PrincipalCredentialError('credential-malformed');
  }
  return { formatVersion, orgApiKey, userKey, userSecretKey };
}

/** Byte-identity helper for callers comparing two provisioning runs. */
export function principalCredentialsEqual(
  a: PrincipalCredentialV1,
  b: PrincipalCredentialV1,
): boolean {
  const left = serializePrincipalCredential(a);
  const right = serializePrincipalCredential(b);
  if (left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) {
      return false;
    }
  }
  return true;
}

/** Convenience: the credential's Ed25519 PoP public key (request signing). */
export async function principalPopPublicKeyHex(credential: PrincipalCredentialV1): Promise<string> {
  return (await derivePopKey(credential.userSecretKey)).publicKeyHex;
}
